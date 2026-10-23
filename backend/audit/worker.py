"""The background audit coordinator.

Runs are serialized for durable SQLite ownership.  A Planner-led run freezes a project
map, then one Planner revises a cross-file task frontier while bounded worker slots
claim ready tasks concurrently.  Historical unit-queue runs remain readable.  The
coordinator never expands the frozen source scope, and cancellation interrupts both
planning and in-flight worker passes.
"""
from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone

from .agent import _parse_evidence, audit_unit, plan_audit_frontier, pursue_planner_task, pursue_task_work
from .config import ModelConfig, Settings
from .db import WITHDRAWN_FINDING_DISPOSITIONS, Store
from .events import EventBus
from .evidence import fingerprint, seen_ranges, title_for, validate_evidence
from .finding_policy import is_vulnerability_finding
from .health import ModelHealth
from .poc import PocPolicy, PocVerifier
from .project_findings import canonical_fingerprint, ledger_record
from .prompts import system_prompt
from .source import SourceRepository
from .runtime import AgentPolicy, StopAudit, allowed_paths_for_run, policy_from_snapshot
from .execution_state import CURRENT_EXECUTION, execution_context, execution_role
from .poc_readiness import normalize_poc_mode
from .schemas import Check

# Two model-level failures in a row mean the endpoint itself is down; grinding
# through the rest of the queue would only burn budget.
MODEL_ERROR_ABORT_AFTER = 2
MODEL_FAILURE_REASONS = frozenset(("model_error", "request_timeout"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalise_task_findings(outcome: dict) -> dict:
    """Keep source observations in the attempt without treating them as vulnerabilities.

    The host repeats this boundary even when an integration bypasses the model schema,
    including older workers which returned safe data-flow facts as achieved findings.
    A malformed vulnerability stays a finding so it fails validation rather than being
    quietly re-labelled as a safe observation.
    """
    result = dict(outcome.get("result") or {})
    payloads = result.get("findings")
    if not isinstance(payloads, list):
        payloads = []
    else:
        payloads = list(payloads)
    legacy = result.get("finding")
    if isinstance(legacy, dict) and legacy not in payloads:
        payloads.insert(0, legacy)
    observations = list(result.get("observations") or [])
    findings = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        kind = str(payload.get("kind") or payload.get("finding_kind") or "source_observation").strip().casefold()
        if kind in {"source_observation", "data_flow", "security_boundary"}:
            observations.append({
                "title": str(payload.get("title") or "源码观察"),
                "kind": kind,
                "summary": str(payload.get("summary") or ""),
                "evidence": str(payload.get("evidence") or ""),
            })
        else:
            findings.append(payload)
    result.update(finding=findings[0] if findings else None, findings=findings, observations=observations)
    if outcome.get("outcome") == "achieved" and not findings and observations:
        result.update(outcome="no_evidence", terminal_reason="source_observations_only")
        # Preserve the model call's successful terminal reason for health accounting.
        return {**outcome, "outcome": "no_evidence", "result": result}
    return {**outcome, "result": result}


class AuditWorker:
    def __init__(
        self,
        *,
        settings: Settings,
        store: Store,
        repository: SourceRepository,
        bus: EventBus,
        health: ModelHealth,
        resolve_model_profile: Callable[[dict], ModelConfig | None] | None = None,
    ):
        self.settings = settings
        self.store = store
        self.repository = repository
        self.bus = bus
        self.health = health
        self._resolve_model_profile = resolve_model_profile
        self._wake = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._current: asyncio.Task | None = None
        self._run_id: str | None = None
        self._stopping = False
        self._cancel_reason = "user_cancelled"
        # Per-run cooperative pause flags, keyed by run id while that run is executing.
        # A pause has to be observed from inside the run (between attempts, between
        # rounds) rather than by cancelling it, so the flag lives beside the task that
        # reads it; `_loop` clears the entry when the run stops.
        self._pauses: dict[str, asyncio.Event] = {}

    # --- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping = False
        self.store.interrupt_stale_runs()
        self._task = asyncio.create_task(self._loop(), name="audit-worker")

    async def stop(self) -> None:
        self._stopping = True
        self._cancel_reason = "server_shutdown"
        self._wake.set()
        if self._current is not None:
            self._current.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._current
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    def notify(self) -> None:
        self._wake.set()

    def cancel(self, run_id: str, *, reason: str = "user_cancelled") -> None:
        if self._run_id == run_id and self._current is not None:
            self._cancel_reason = reason
            self._current.cancel()
        self.notify()

    def pause(self, run_id: str) -> None:
        """Ask a running run to stop at its next boundary, keeping its frontier.

        Cooperative by construction: the flag is read between attempts and between
        rounds, so an attempt already in flight finishes and its result is committed.
        That is the whole difference from ``cancel``, which interrupts the request and
        settles the run -- a pause has to leave something worth resuming.  The store
        owns the status; this only tells the executing run to look at it.
        """
        event = self._pauses.get(run_id)
        if event is not None:
            event.set()
        self.notify()

    @property
    def status(self) -> dict:
        return {"name": self.settings.worker, "current_run": self._run_id,
                "busy": self._current is not None, "alive": self._task is not None and not self._task.done()}

    def _model_for_run(self, run: dict) -> ModelConfig:
        """Resolve the exact public provider identity frozen with a run.

        New records identify a profile and freeze its model/endpoint.  Credential
        lookup is deliberately separate and happens through that profile id so a
        restart cannot use whichever profile happens to be selected then.  Historic
        records have no snapshot and retain their previous current-config fallback.
        """
        snapshot = run.get("model_profile")
        if isinstance(snapshot, dict) and snapshot:
            profile_id = str(snapshot.get("profile_id") or "").strip()
            model = str(snapshot.get("model") or "").strip()
            base_url = str(snapshot.get("base_url") or "").strip().rstrip("/")
            if profile_id:
                if not (model and base_url):
                    raise RuntimeError("Frozen model profile snapshot is incomplete")
                if self._resolve_model_profile is not None:
                    config = self._resolve_model_profile(snapshot)
                    if config is None:
                        raise RuntimeError(f"Frozen model profile is unavailable: {profile_id}")
                    return config
                raise RuntimeError("Frozen model profile resolver is unavailable")
            if model or base_url:
                return replace(
                    self.settings.model,
                    model=model or self.settings.model.model,
                    base_url=base_url or self.settings.model.base_url,
                )

        name = str(run.get("model") or "").strip()
        return replace(self.settings.model, model=name) if name else self.settings.model

    # --- main loop ---------------------------------------------------------

    async def _loop(self) -> None:
        while not self._stopping:
            run = self.store.claim_next_run()
            if run is None:
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass
                continue
            self._run_id = run["id"]
            # A fresh flag per claim: a pause requested against the previous execution of
            # this run must not arrive already set, which would stop the resumed run at
            # its first boundary for no reason the user can see.
            self._pauses[run["id"]] = asyncio.Event()
            self._current = asyncio.create_task(self._execute(run), name=f"run-{run['id']}")
            try:
                await self._current
            except asyncio.CancelledError:
                status = "interrupted" if self._stopping else "cancelled"
                self.store.update_run(run["id"], status=status, finished_at=_now(), error=self._cancel_reason)
                self.bus.emit(run["id"], None, f"run_{status}", {"reason": self._cancel_reason})
                if self._stopping:
                    raise
            except Exception as exc:  # a worker crash must not strand a run
                self.store.update_run(
                    run["id"], status="failed", finished_at=_now(), error=f"{type(exc).__name__}: {exc}"[:600]
                )
                self.bus.emit(run["id"], None, "run_failed", {"error": f"{type(exc).__name__}: {exc}"[:600]})
            finally:
                self._current = None
                self._run_id = None
                self._pauses.pop(run["id"], None)

    # --- one run -----------------------------------------------------------

    async def _execute(self, run: dict) -> None:
        run_id = run["id"]
        summary = self.store.execution_summary(run_id)
        if not summary or not summary.get("claim_epoch"):
            with self.store._lock:
                self.store._claim_execution_tx(run_id)
            run = self.store.get_run(run_id) or run
            summary = self.store.execution_summary(run_id)
        epoch = summary["claim_epoch"]
        async def execute_body():
            with execution_context(self.store, run_id, epoch):
                await self._execute_body(run)
        body = asyncio.create_task(execute_body())
        try:
            while not body.done():
                await asyncio.wait({body}, timeout=0.2)
                if not body.done():
                    try:
                        self.store.admit_execution(run_id, epoch, None)
                    except StopAudit as exc:
                        if exc.reason == "run_budget_exhausted":
                            state = self.store.execution_summary(run_id)
                            self.store.terminate_execution(run_id, "inconclusive", state["stop_reason"], epoch=epoch)
                            body.cancel()
                            break
                        if (self.store.get_run(run_id) or {}).get("status") in ("cancelled", "interrupted"):
                            body.cancel()
                            break
            if body.done():
                await body
        except StopAudit as exc:
            reason = (self.store.execution_summary(run_id) or {}).get("stop_reason")
            self.store.terminate_execution(run_id, "inconclusive", reason or {"code": exc.reason, "message": str(exc)}, epoch=epoch)
        except asyncio.CancelledError:
            status = "interrupted" if self._stopping else "cancelled"
            self.store.terminate_execution(run_id, status, {"code": "interrupted" if self._stopping else "user_cancelled", "message": self._cancel_reason}, epoch=epoch)
            body.cancel()
            raise
        except Exception as exc:
            self.store.terminate_execution(run_id, "failed", {"code": "worker_exit_without_terminal", "message": f"{type(exc).__name__}: {str(exc)[:400]}"}, epoch=epoch)
            raise
        finally:
            # Fence threads before giving ownership back; cancellation cannot kill an
            # interpreter thread that has already entered a tool.
            current = self.store.get_run(run_id)
            if current and current["status"] == "running":
                self.store.terminate_execution(run_id, "failed", {"code": "worker_exit_without_terminal", "message": "执行者退出但未提交终态"}, epoch=epoch)
            elif current and current["status"] not in ("paused", "pending") and not self.store.get_final_summary(run_id):
                self.store.terminate_execution(run_id, current["status"], {"code": "interrupted", "message": current.get("error") or "执行已结束"}, epoch=epoch)
            self.store.quiesce_execution(run_id)
            body.cancel()
            with contextlib.suppress(asyncio.CancelledError, StopAudit):
                await body

    async def _execute_body(self, run: dict) -> None:
        if run.get("task_spec"):
            await self._execute_planner_task(run)
            return
        await self._execute_legacy(run)

    async def _execute_legacy(self, run: dict) -> None:
        run_id = run["id"]
        model_config = self._model_for_run(run)
        if self.health.is_open():
            error = "模型熔断窗口尚未结束；未发起新的模型请求"
            self.store.abandon_pending_units(run_id, error)
            self.store.update_run(run_id, status="failed", finished_at=_now(), error=error)
            self.bus.emit(run_id, None, "run_failed", {"reason": "model_unavailable", "error": error})
            return
        # A resumed run has already announced its beginning (see the Planner path below);
        # a second `run_started` would read in the timeline as a run that began twice.
        if not self.store.has_event(run_id, "run_started"):
            self.bus.emit(
                run_id,
                None,
                "run_started",
                {
                    "snapshot_id": run["snapshot_id"],
                    "scope": run["scope"],
                    "prompt_id": run["prompt_id"],
                    "model": run["model"],
                    "model_profile": run.get("model_profile") or {},
                    "budgets": run["budgets"],
                    "total_units": run["total_units"],
                },
            )
        consecutive_errors = 0

        while True:
            current = self.store.get_run(run_id)
            if current is not None and current["status"] == "paused":
                # Parked between units, not cancelled: the remaining queue stays pending
                # and `resume` returns the run to `pending`, where the same claim picks it
                # up again.  The unit that was in flight when the pause landed is settled,
                # which is what "pause at a boundary" has to mean for a durable queue.
                self.bus.emit(run_id, None, "run_paused", {"reason": "pause requested"})
                return
            if current is not None and current["status"] == "pending":
                # Resumed mid-pass, same as the Planner path above: the queue is durable, so
                # handing the run back loses nothing and cancelling it would lose everything.
                return
            if current is None or current["status"] != "running":
                self.store.abandon_pending_units(run_id, "Run is no longer running")
                self.bus.emit(run_id, None, "run_cancelled", {"reason": "cancel requested"})
                return
            unit = self.store.next_pending_unit(run_id)
            if unit is None:
                self.store.update_run(run_id, status="completed", finished_at=_now())
                self.bus.emit(run_id, None, "run_completed", {"completed_units": current["completed_units"]})
                return

            self.store.mark_unit_running(run_id, unit["unit_id"])
            invocation_id = uuid.uuid4().hex
            self.bus.emit(
                run_id,
                unit["unit_id"],
                "unit_started",
                {
                    "file_path": unit["file_path"],
                    "symbol": unit["symbol"],
                    "start_line": unit["start_line"],
                    "end_line": unit["end_line"],
                    "priority": unit["priority"],
                    "agent_invocation_id": invocation_id, "request_index": 0,
                },
            )

            saved_categories: set[str] = set()
            checkpoint = {"result": None, "usage": None, "seen": []}

            def record(event: dict) -> None:
                # Synchronous callback: the durable event is committed before the
                # model advances to another graph node or receives another tool result.
                kind = event.get("kind", "agent_event")
                payload = {key: value for key, value in event.items() if key != "kind"}
                payload.setdefault("agent_invocation_id", invocation_id)
                payload.setdefault("request_index", 0)
                self.bus.emit(run_id, unit["unit_id"], kind, payload)
                for key in checkpoint:
                    if key in event:
                        checkpoint[key] = event[key]
                if any(key in event for key in checkpoint):
                    self.store.checkpoint_unit(run_id, unit["unit_id"], **checkpoint)
                if kind == "unit_checkpoint" and event.get("result"):
                    completed = {
                        name: Check.model_validate(check)
                        for name, check in event["result"].get("checks", {}).items()
                        if name not in saved_categories
                    }
                    self._store_findings(run, unit, {"checks": completed, "seen": checkpoint["seen"], "seen_exact": True})
                    saved_categories.update(completed)

            outcome = await audit_unit(
                repository=self.repository,
                snapshot_id=run["snapshot_id"],
                snapshot_name=run["snapshot_name"],
                unit=unit,
                prompt_text=system_prompt(run["prompt_text"]),
                config=model_config,
                budgets=run["budgets"],
                policy=policy_from_snapshot(run["agent_policy"]) if run.get("agent_policy", {}).get("version") == "whitebox-2" else AgentPolicy(),
                on_event=record,
                agent_invocation_id=invocation_id,
            )

            remaining_checks = {name: check for name, check in outcome.get("checks", {}).items() if name not in saved_categories}
            if remaining_checks:
                self._store_findings(run, unit, {**outcome, "checks": remaining_checks})

            if outcome["analysis"] is None:
                model_failure = outcome["incomplete"] in MODEL_FAILURE_REASONS
                status = "failed" if model_failure or outcome["incomplete"] == "internal_error" else "incomplete"
                # Settlement judges one category per call, so it can get part of the way and
                # then time out on the next one. Those settled categories are real work and
                # are kept in the record even though the unit as a whole stays unfinished —
                # the status is what the statistics read, and it must not claim a verdict the
                # unit never reached. Dropping them entirely is how a single slow response
                # erased two already-decided categories.
                settled = outcome.get("verdicts") or {}
                partial = {name: check.conclusion for name, check in settled.items()}
                self.store.finish_unit(
                    run_id, unit["unit_id"], status, usage=outcome["usage"], seen=outcome["seen"],
                    error=outcome["error"],
                    result=outcome.get("result") or ({"conclusions": partial, "settlement": "partial"} if partial else None),
                )
                self.bus.emit(
                    run_id,
                    unit["unit_id"],
                    "unit_incomplete",
                    {"reason": outcome["incomplete"], "error": outcome["error"], "usage": outcome["usage"],
                     "settled_categories": partial, "agent_invocation_id": invocation_id,
                     "request_index": outcome["usage"].get("model_attempts", outcome["usage"].get("requests", 0))},
                )
                # A request-level timeout means the provider did not produce an answer.
                # It must count toward the same breaker as connection/HTTP failures;
                # otherwise a dead endpoint makes us exhaust every queued unit.
                if model_failure:
                    self.health.trip(outcome["error"] or "model error", status=outcome.get("status"))
                    consecutive_errors += 1
                else:
                    consecutive_errors = 0
                if consecutive_errors >= MODEL_ERROR_ABORT_AFTER or self.health.is_open():
                    message = f"模型熔断或连续失败阈值触发（本次 {consecutive_errors} 次），运行中止：{outcome['error']}"
                    self.store.abandon_pending_units(run_id, message)
                    self.store.update_run(run_id, status="failed", finished_at=_now(), error=message)
                    self.bus.emit(run_id, None, "run_failed", {"error": message})
                    return
                continue

            self.health.pass_()
            consecutive_errors = 0
            stored = self._store_findings(run, unit, outcome) if "checks" not in outcome else []
            # Exploration can run out of budget and still be settled into an answer. That
            # answer stands — its evidence passed the same validation as any other — but
            # the unit is not a clean one: less code was read than the model asked for, so
            # the report lists it with the unfinished units instead of letting a
            # budget-truncated "no_candidate" pass as a confident negative.
            partial = outcome.get("exploration_incomplete")
            self.store.finish_unit(
                run_id, unit["unit_id"], "completed",
                result=outcome.get("result") or {
                    "summary": outcome["analysis"].summary,
                    "conclusions": {
                        name: check.conclusion for name, check in outcome["analysis"].by_category().items()
                    },
                    "exploration_incomplete": partial,
                },
                usage=outcome["usage"],
                seen=outcome["seen"],
            )
            self.bus.emit(
                run_id,
                unit["unit_id"],
                "unit_completed",
                {
                    "summary": outcome["analysis"].summary,
                    "conclusions": {
                        name: check.conclusion for name, check in outcome["analysis"].by_category().items()
                    },
                    "usage": outcome["usage"],
                    "findings": stored,
                    "exploration_incomplete": partial,
                    "agent_invocation_id": invocation_id,
                    "request_index": outcome["usage"].get("model_attempts", outcome["usage"].get("requests", 0)),
                },
            )

    def _policy_for_run(self, run: dict) -> AgentPolicy:
        policy = run.get("agent_policy") or {}
        return policy_from_snapshot(policy) if policy.get("version") == "whitebox-2" else AgentPolicy()

    async def _execute_planner_task(self, run: dict) -> None:
        """Run ARTEX-style Planner rounds over a durable, dynamic task frontier.

        One Planner owns task creation and graph changes; many bounded workers only
        claim ready tasks.  A worker never decides that the project goal is impossible.
        Its evidence-bound summary becomes input for the next serialized Planner round.
        """
        run_id = run["id"]
        model_config = self._model_for_run(run)
        task_spec = run["task_spec"]
        # A scenario run is "find every reachable instance of one class", not "find the
        # first one".  ``stop_on_achieved`` must therefore be off so a first finding does
        # not hold the remaining directions back; the host's exhaustion gate in
        # ``Store.finalize_goal`` is what closes the run once the frontier is settled.
        if task_spec.get("scenario"):
            task_spec = {**task_spec, "stop_on_achieved": False}
        if self.health.is_open():
            error = "模型熔断窗口尚未结束；未发起新的 Planner 或 worker 请求"
            self.store.abandon_planner_tasks(run_id, error)
            self.store.update_run(run_id, status="failed", finished_at=_now(), error=error)
            self.bus.emit(run_id, None, "run_failed", {"reason": "model_unavailable", "error": error})
            return

        goal = self.store.get_task_goal(run_id)
        session = self.store.get_planner_session(run_id)
        project_map = self.store.get_project_map(run_id)
        if goal is None or session is None or project_map is None:
            raise RuntimeError("Planner run is missing its durable goal, session, or project map")
        policy = self._policy_for_run(run)
        stop = asyncio.Event()
        # The run's pause flag, set from outside by ``AuditWorker.pause`` and read at the
        # boundaries -- a slot that has not claimed a task yet, and each pass of the
        # reconcile loop -- so a pause never cuts an attempt in half.  ``_loop`` registers
        # a fresh one per claim; the fallback covers a run driven directly (a test, or any
        # later entry path) so that pausing it is not silently a no-op.
        pause = self._pauses.setdefault(run_id, asyncio.Event())
        coordinator = asyncio.Lock()
        failure_message: str | None = None
        consecutive_errors = 0
        # Consecutive rounds that produced no usable decision.  One bad structured output
        # used to end the whole run; the host now re-plans, then falls back to the durable
        # frontier, and only then settles the goal.
        stalled_rounds = 0
        # The state the last pre-closure review round was run against.  A review that changes
        # nothing has already had its say, so the host closes instead of reviewing again.
        reviewed_for: tuple | None = None
        # (finding id, revision) pairs this process has already given the Planner a chance
        # to cross-check.  Kept apart from ``reviewed_for`` because a review round is not a
        # frontier review: one asks the Planner to read the verdicts, the other asks it to
        # confirm the frontier is finished.
        reviewed_reviews_for: tuple = ()
        repaired_blockers: set[tuple] = set()
        # Set when a worker produces a conclusion the host would close the run on and
        # ``stop_on_achieved`` says to stop queued work.  It withholds the directions that
        # have not started yet -- the run is about to be over, so starting them would spend
        # attempts on work nobody asked for -- without closing the run, which is what lets
        # the review round below look at the frontier before the host settles on it.
        closing = False
        # How many task proposals and frontier updates the last Planner round committed.
        # ``continue`` covers both "I looked and the conclusion stands" and "run what is
        # still on the frontier", and only the decision itself tells the two apart.
        round_mutations = 0
        # ``project_finding_id`` -> revision already sent to the POC agent this process.
        # Verification happens at the closure boundary, where every standing conclusion is
        # known and the next Planner round is the closure review that should see it.
        verified_for: dict[str, int] = {}
        poc_verifier = PocVerifier(store=self.store, bus=self.bus, settings=self.settings)
        project_mode = str(run.get("project_mode") or "legacy") == "project"
        # POC verification is the layer this closure gate belongs to.  When it is off for
        # this run (no runner, policy disabled) there is no verdict for anyone to
        # cross-check, so the gate stays inert and a plain source run closes as before.
        poc_review_required = bool(
            PocPolicy.from_run(run, self.settings).enabled
            or normalize_poc_mode(run)[0] != "off"
        )

        # A run that was paused and resumed re-enters here with its session, its round
        # number and its frontier exactly as they were.  The two events below describe a
        # beginning, and this run has already had one; ``run_resumed`` (emitted where the
        # transition was requested) is the event that belongs to this re-entry.
        if not self.store.has_event(run_id, "run_started"):
            self.bus.emit(
                run_id,
                None,
                "run_started",
                {
                    "snapshot_id": run["snapshot_id"],
                    "scope": run["scope"],
                    "model": run["model"],
                    "model_profile": run.get("model_profile") or {},
                    "budgets": run["budgets"],
                    "mode": "planner_v2",
                    "task": task_spec,
                    "project_map": {"stats": project_map.get("stats"), "entrypoints": project_map.get("entrypoints", [])[:12]},
                },
            )
            self.bus.emit(
                run_id,
                None,
                "planner_session_started",
                {
                    "goal_id": goal["id"],
                    "session_id": session["session_id"],
                    "objective": goal["objective"],
                    "success_criteria": goal["success_criteria"],
                    "max_planner_rounds": session["max_rounds"],
                    "max_total_attempts": goal["max_total_attempts"],
                    "max_workers": task_spec["max_workers"],
                    "project_map_stats": project_map.get("stats") or {},
                },
            )

        async def abort(message: str) -> None:
            nonlocal failure_message
            async with coordinator:
                if failure_message is not None:
                    return
                failure_message = message
                stop.set()
                self.store.abandon_planner_tasks(run_id, message)
                self.store.update_run(run_id, status="failed", finished_at=_now(), error=message)
                self.bus.emit(run_id, None, "run_failed", {"error": message})

        async def account_model_result(outcome: dict, role: str) -> str | None:
            """Keep provider-health behaviour identical for Planner and worker calls."""
            nonlocal consecutive_errors
            reason = outcome.get("terminal_reason")
            if reason in MODEL_FAILURE_REASONS:
                async with coordinator:
                    self.health.trip(outcome.get("error") or f"{role} model error", status=outcome.get("status"))
                    consecutive_errors += 1
                    if consecutive_errors >= MODEL_ERROR_ABORT_AFTER or self.health.is_open():
                        return (
                            f"模型熔断或连续失败阈值触发（{role}，本次 {consecutive_errors} 次）："
                            f"{outcome.get('error') or reason}"
                        )
            elif reason == "completed":
                async with coordinator:
                    self.health.pass_()
                    consecutive_errors = 0
            return None

        async def finish_goal(state: str, basis: str, missing: list[str] | None = None) -> bool:
            """Persist a host-verified terminal goal and its public run state."""
            try:
                queue_now = self.store.task_queue_state(run_id)
                session_now = self.store.get_planner_session(run_id) or {}
                goal_now = self.store.get_task_goal(run_id) or {}
                code = "goal_met" if state == "met" else (
                    "worker_attempt_limit" if int(goal_now.get("attempts", 0)) >= int(goal_now.get("max_total_attempts", 1)) else
                    "planner_round_limit" if int(session_now.get("current_round", 0)) >= int(session_now.get("max_rounds", 1)) else
                    "unresolved_blockers" if queue_now["blocked"] else
                    "environment_unavailable" if normalize_poc_mode(run)[0] == "required" and not (self.store.execution_summary(run_id) or {}).get("poc", {}).get("available", False) else
                    "invalid_output_limit"
                )
                if state == "met":
                    record_carried()
                settled = self.store.finalize_goal(
                    run_id, state, basis, missing,
                    # Strict mode: the run may only close on a finding the isolated POC
                    # runner actually reproduced, not on a static conclusion.
                    require_verified=normalize_poc_mode(run)[0] == "required",
                    # Whenever POC verification is active at all, the Planner has to have
                    # read the captured observations before a verified conclusion can
                    # carry the closure: one agent's verdict, cross-checked by another.
                    require_reviewed=poc_review_required,
                    stop_reason={"code": code, "message": basis},
                )
            except ValueError as exc:
                self.bus.emit(run_id, None, "planner_terminal_deferred", {
                    "state": state, "reason": str(exc), "basis_summary": basis,
                })
                return False
            status_map = {"met": ("completed", "run_completed"), "unreachable": ("unreachable", "goal_unreachable"), "inconclusive": ("inconclusive", "goal_inconclusive")}
            run_status, event_kind = status_map[state]
            if state == "met":
                # The POC agent rejected these, the Planner chose not to retract them, and
                # the host still excluded them from what the goal stands on.  Keep that
                # divergence visible instead of silently dropping the conclusions.
                kept_rejected = [
                    item for item in self.store.list_findings(run_id)
                    if item.get("validation_state") == "candidate"
                    and is_vulnerability_finding(item)
                    and str(item.get("disposition") or "open") not in WITHDRAWN_FINDING_DISPOSITIONS
                    and str(item.get("verification_status") or "") == "rejected"
                ]
                if kept_rejected:
                    self.bus.emit(run_id, None, "planner_kept_rejected_finding", {
                        "finding_ids": [item["id"] for item in kept_rejected][:32],
                        "count": len(kept_rejected),
                        "note": "自动验证未通过，但 Planner 没有撤回；这些结论不支撑目标达成。",
                    })
            self.bus.emit(run_id, None, event_kind, {
                "goal_id": settled["id"],
                "goal_status": state,
                "reason": settled.get("terminal_reason"),
                "attempts": settled["attempts"],
            })
            stop.set()
            return True

        async def run_planner_round() -> str:
            """Reserve, execute and commit one Planner revision."""
            nonlocal round_mutations
            owner = CURRENT_EXECUTION.get()
            if owner is not None:
                owner.admit("work")
            round_mutations = 0
            plan = self.store.begin_planner_round(run_id, session["session_id"])
            if plan is None:
                return "no_round"
            invocation_id = uuid.uuid4().hex
            self.bus.emit(run_id, None, "planner_round_started", {
                "plan_id": plan["id"], "round": plan["round_no"], "revision": plan["revision"],
                "session_id": session["session_id"],
                "agent_invocation_id": invocation_id, "request_index": 0,
            })

            def record(event: dict) -> None:
                kind = event.get("kind", "planner_agent_event")
                payload = {key: value for key, value in event.items() if key != "kind"}
                # Reconnaissance runs inside a Planner round but is its own role, so its
                # events must not be presented as Planner activity.  An event that names
                # no role is Planner activity, which is the historical default.
                payload.update({
                    "plan_id": plan["id"],
                    "session_id": session["session_id"],
                    "role": str(event.get("role") or "planner"),
                    "planner_round": plan["round_no"],
                    "revision": plan["revision"],
                })
                payload.setdefault("agent_invocation_id", invocation_id)
                payload.setdefault("request_index", 0)
                self.bus.emit(run_id, None, kind, payload)

            context = self.store.list_planner_context(run_id, project_map=project_map)
            outcome = await plan_audit_frontier(
                project_map=project_map,
                run_context=context,
                context_reader=lambda: self.store.list_planner_context(run_id, project_map=project_map),
                task=task_spec,
                round_no=int(plan["round_no"]),
                config=model_config,
                budgets=run["budgets"],
                policy=policy,
                repository=self.repository,
                snapshot_id=run["snapshot_id"],
                allowed_paths=allowed_paths_for_run(run),
                # What this run has already had answered, so a later round reuses an
                # earlier round's reconnaissance, listings and searches instead of
                # paying for them again.
                pins=self.store,
                run_id=run_id,
                plan_id=plan["id"],
                agent_invocation_id=invocation_id,
                on_event=record,
            )
            failed = await account_model_result(outcome, "Planner")
            if failed:
                self.store.finish_planner_round(
                    run_id, plan["id"], goal_state="inconclusive", basis_summary=failed,
                    usage=outcome.get("usage"), error=outcome.get("error") or failed,
                )
                await abort(failed)
                return "failed"
            decision = outcome.get("decision")
            if not isinstance(decision, dict):
                message = outcome.get("error") or "Planner 未返回可验证的任务决策"
                self.store.finish_planner_round(
                    run_id, plan["id"], goal_state="inconclusive", basis_summary=message,
                    usage=outcome.get("usage"), error=message,
                )
                # The round is recorded honestly as a failed draft, but the run does not
                # end here: the caller decides between a fresh round and the durable
                # frontier.  Settling the goal from inside a single bad decision threw
                # away a run whose workers had simply not been dispatched yet.
                self.bus.emit(run_id, None, "planner_round_failed", {
                    "plan_id": plan["id"],
                    "round": plan["round_no"],
                    "revision": plan["revision"],
                    "terminal_reason": str(outcome.get("terminal_reason") or "invalid_output"),
                    "error": message,
                })
                return "failed"
            tasks = list(decision.get("tasks") or [])
            updates = list(decision.get("updates") or [])
            narrative = decision.get("report") if isinstance(decision.get("report"), dict) else None
            committed = self.store.finish_planner_round(
                run_id,
                plan["id"],
                goal_state=str(decision.get("goal_state") or "continue"),
                basis_summary=str(decision.get("basis_summary") or "Planner 已提交任务图更新。"),
                next_action=str(decision.get("next_action") or ""),
                missing_context=list(decision.get("missing_context") or []),
                tasks=tasks,
                updates=updates,
                usage=outcome.get("usage"),
                # A revision extends the attempt allowance instead of spending it; the store
                # applies this to both the task's own cap and the goal-wide one.
                reopen_attempts=int(policy.reopen_attempts),
                narrative=narrative,
            )
            if narrative:
                self.bus.emit(run_id, None, "report_narrative_committed", {
                    "plan_id": plan["id"],
                    "round": plan["round_no"],
                    "revision": plan["revision"],
                    "summary": str(narrative.get("summary") or "")[:300],
                    "limitations": len(narrative.get("limitations") or []),
                })
            queue = self.store.task_queue_state(run_id)
            # Project-ledger dispositions are applied after the round commits: they are not
            # part of the task graph transaction, and a ledger write must not be able to
            # roll back an otherwise valid frontier update.
            project_updates = list(decision.get("project_updates") or [])
            applied_projects = 0
            for update in project_updates:
                project_finding_id = str(update.get("project_finding_id") or "")
                action = str(update.get("action") or "")
                try:
                    updated = self.store.set_project_finding_disposition(
                        project_finding_id,
                        action,
                        str(update.get("rationale_summary") or ""),
                        run_id=run_id,
                    )
                except ValueError:
                    updated = None
                if updated is None or str(updated.get("project_id")) != str(run.get("project_id") or ""):
                    self.bus.emit(run_id, None, "project_finding_update_rejected", {
                        "project_finding_id": project_finding_id,
                        "action": action,
                        "reason": "not in this run's project or unsupported action",
                    })
                    continue
                applied_projects += 1
                self.bus.emit(run_id, None, {
                    "retract": "project_finding_retracted",
                    "duplicate": "project_finding_duplicate",
                    "reopen": "project_finding_reopened",
                }.get(action, "project_finding_disposition_changed"), {
                    "project_finding_id": project_finding_id,
                    "action": action,
                    "disposition": updated.get("disposition"),
                    "revision": int(updated.get("revision") or 1),
                    "reason": update.get("rationale_summary"),
                })
            # The round's own reading of the automatic verdicts.  Stored per revision, so a
            # conclusion that is later corrected has to be read again rather than inheriting
            # the old sign-off.  Deliberately not counted as a frontier mutation: reviewing a
            # verdict is not a reason to release directions the host is withholding.
            reviews = [item for item in (decision.get("verification_reviews") or []) if isinstance(item, dict)]
            applied_reviews = self.store.record_verification_reviews(
                run_id, reviews, plan_id=plan["id"]
            )
            if applied_reviews:
                self.bus.emit(run_id, None, "verification_reviews_recorded", {
                    "plan_id": plan["id"],
                    "round": plan["round_no"],
                    "confirmed": sum(1 for item in applied_reviews if item["decision"] == "confirmed"),
                    "contested": sum(1 for item in applied_reviews if item["decision"] == "contested"),
                    "finding_ids": [item["finding_id"] for item in applied_reviews][:32],
                })
            round_mutations = len(tasks) + len(updates) + applied_projects
            self.bus.emit(run_id, None, "planner_round_committed", {
                "plan_id": plan["id"],
                "round": plan["round_no"],
                "revision": plan["revision"],
                "goal_state": decision.get("goal_state"),
                "basis_summary": decision.get("basis_summary"),
                "next_action": decision.get("next_action"),
                "task_count": len(tasks),
                "updates": updates,
                "project_updates": project_updates,
                "queue": queue,
            })
            # A correction is worth its own event: it is the moment the run decided an earlier
            # conclusion was wrong, and it is the only place the attempt count and the
            # revision count can be read side by side.
            for update in updates:
                action = str(update.get("action"))
                if action == "reopen":
                    task = next(
                        (item for item in committed if item.get("task_key") == update.get("task_key")), None,
                    )
                    self.bus.emit(run_id, task["id"] if task else None, "planner_task_reopened", {
                        "task_key": update.get("task_key"),
                        "state": task.get("state") if task else None,
                        "revisions": int(task.get("revisions") or 0) if task else None,
                        "attempts": int(task.get("attempts") or 0) if task else None,
                        "max_attempts": int(task.get("max_attempts") or 0) if task else None,
                        "reason": str(update.get("rationale_summary") or ""),
                    })
                elif action in {"retract", "duplicate"}:
                    # What was asked for and what was written can differ (retract and
                    # duplicate are normalized in the store), so the event is read back
                    # off the row instead of being assumed from the action.
                    finding = self.store.get_finding(str(update.get("finding_key") or ""))
                    if finding is None:
                        continue
                    disposition = str(finding.get("disposition") or "")
                    self.bus.emit(run_id, finding["unit_id"], {
                        "retracted": "finding_retracted",
                        "duplicate": "finding_duplicate",
                        "contested": "finding_contested",
                    }.get(disposition, "finding_disposition_changed"), {
                        "finding_id": finding["id"],
                        "task_key": update.get("task_key"),
                        "requested_action": action,
                        "disposition": disposition,
                        "reason": finding.get("disposition_reason"),
                        "by": finding.get("disposition_by"),
                        "verdict": finding.get("verdict"),
                        "related_finding_id": finding.get("derived_from_finding_id"),
                        "validation_state": finding.get("validation_state"),
                    })
            requested_state = decision.get("goal_state")
            if requested_state in {"met", "unreachable", "inconclusive"}:
                if requested_state == "inconclusive" and queue["active"]:
                    self.bus.emit(run_id, None, "planner_terminal_deferred", {
                        "state": requested_state,
                        "reason": "仍有已派发任务正在等待或执行，先收集 worker 反馈",
                        "basis_summary": decision.get("basis_summary"),
                    })
                    return "committed"
                # A suggested terminal state is advisory. The store checks candidates,
                # outstanding tasks and blocked context before it permits closure.
                closed = await finish_goal(
                    str(requested_state),
                    str(decision.get("basis_summary") or "Planner requested goal closure."),
                    list(decision.get("missing_context") or []),
                )
                if closed:
                    return "closed"
            return "committed"

        async def execute_slot(slot: int) -> None:
            nonlocal closing
            worker_id = f"{self.settings.worker}:{run_id[:8]}:{slot}"
            try:
                while not stop.is_set() and not pause.is_set():
                    # Held back by a sibling's conclusion under stop_on_achieved: the run is
                    # about to close and this direction has not started, so it is not started.
                    if closing:
                        return
                    current = self.store.get_run(run_id)
                    current_goal = self.store.get_task_goal(run_id)
                    if current is None or current["status"] != "running" or current_goal is None or current_goal["status"] != "open":
                        return
                    owner = CURRENT_EXECUTION.get()
                    if owner is not None:
                        owner.admit("work")
                    planner_task = self.store.claim_ready_task(run_id, worker_id)
                    if planner_task is None:
                        return
                    attempt = int(planner_task["attempts"]) + 1
                    task_id = planner_task["id"]
                    invocation_id = uuid.uuid4().hex
                    self.bus.emit(run_id, task_id, "planner_task_started", {
                        "task_id": task_id,
                        "task_key": planner_task["task_key"],
                        "title": planner_task["title"],
                        "objective": planner_task["objective"],
                        "acceptance_criteria": planner_task["acceptance_criteria"],
                        "worker_id": worker_id,
                        "attempt": attempt,
                        "max_attempts": planner_task["max_attempts"],
                        "dependencies": planner_task["dependencies"],
                        "context_spec": planner_task["context_spec"],
                        "agent_invocation_id": invocation_id, "request_index": 0,
                    })

                    def record(event: dict) -> None:
                        kind = event.get("kind", "planner_worker_event")
                        payload = {key: value for key, value in event.items() if key != "kind"}
                        payload.update({
                            "task_id": task_id,
                            "task_key": planner_task["task_key"],
                            "worker_id": worker_id,
                            "attempt": attempt,
                            "role": "worker",
                        })
                        payload.setdefault("agent_invocation_id", invocation_id)
                        payload.setdefault("request_index", 0)
                        self.bus.emit(run_id, task_id, kind, payload)

                    # ARTEX lets a worker build on other workers' durable activity.
                    # For white-box review we narrow that to source-safe handoffs:
                    # dependency summaries plus bounded public tool/assessment traces.
                    # The agent still has to read original snapshot lines before it can
                    # attach an evidence reference to a finding.
                    dependency_handoffs = self.store.get_planner_dependency_handoffs(task_id)

                    def search_peer_traces(query: str) -> list[dict]:
                        return self.store.search_planner_worker_traces(
                            run_id,
                            exclude_task_id=task_id,
                            query=query,
                        )

                    def get_peer_trace(task_key: str, event_ids: list[int] | None = None) -> list[dict]:
                        return self.store.get_planner_worker_trace(
                            run_id,
                            exclude_task_id=task_id,
                            task_key=task_key,
                            event_ids=event_ids,
                        )

                    with execution_role("worker", task_id):
                        outcome = await pursue_planner_task(
                            repository=self.repository,
                            snapshot_id=run["snapshot_id"],
                            snapshot_name=run["snapshot_name"],
                            planner_task=planner_task,
                            run_task=task_spec,
                            attempt=attempt,
                            agent_invocation_id=invocation_id,
                            allowed_paths=allowed_paths_for_run(run),
                            dependency_handoffs=dependency_handoffs,
                            known_findings=list((run.get("project_baseline") or [])[:8]),
                            peer_trace_search=search_peer_traces,
                            peer_trace_read=get_peer_trace,
                            config=model_config,
                            budgets=run["budgets"],
                            policy=policy,
                            on_event=record,
                        )
                    outcome = _normalise_task_findings(outcome)
                    prepared_findings: list[dict] = []
                    if outcome["outcome"] == "achieved":
                        prepared_findings = self._build_planner_findings(run, planner_task, outcome)
                        if not any(item["candidate"] for item in prepared_findings):
                            message = "Planner worker 未提交风险等级明确且通过证据校验的漏洞，不能满足目标"
                            outcome = {
                                **outcome,
                                "outcome": "blocked",
                                "error": message,
                                "result": {
                                    **outcome["result"], "outcome": "blocked", "terminal_reason": "evidence_rejected",
                                    "finding": None, "findings": [], "missing_context": [message],
                                },
                            }

                    resolved = self.store.resolve_task_attempt(
                        task_id,
                        worker_id,
                        outcome=outcome["outcome"],
                        result=outcome["result"],
                        usage=outcome.get("usage"),
                        seen=outcome.get("seen"),
                        error=outcome.get("error"),
                        terminal_reason=outcome.get("terminal_reason"),
                    )
                    if resolved is None:
                        return
                    for prepared in prepared_findings:
                        self._record_finding(
                            run_id, task_id, prepared,
                            extra={"task_id": task_id, "task_key": planner_task["task_key"]},
                        )
                    state_kind = {
                        "ready": "planner_task_requeued",
                        "completed": "planner_task_completed",
                        "exhausted": "planner_task_exhausted",
                        "blocked": "planner_task_blocked",
                        "cancelled": "planner_task_cancelled",
                    }.get(resolved["state"], "planner_task_settled")
                    self.bus.emit(run_id, task_id, state_kind, {
                        "task_id": task_id,
                        "task_key": planner_task["task_key"],
                        "worker_id": worker_id,
                        "state": resolved["state"],
                        "outcome": outcome["outcome"],
                        "attempt": resolved["attempts"],
                        "max_attempts": resolved["max_attempts"],
                        "summary": (outcome.get("result") or {}).get("summary", ""),
                        "terminal_reason": outcome.get("terminal_reason"),
                    })
                    failed = await account_model_result(outcome, "worker")
                    if failed:
                        await abort(failed)
                        return
                    if outcome["outcome"] == "achieved" and any(item["candidate"] for item in prepared_findings):
                        if task_spec.get("stop_on_achieved", True):
                            # Stop queued work; do not close the run here.  A worker producing the
                            # conclusion the goal asked for used to end the run on the spot, which
                            # meant the directions dispatched alongside it were cancelled unseen
                            # and -- because a Planner round only runs when the frontier is quiet --
                            # the conclusion itself was never shown to the Planner for review.  The
                            # host now closes from the reconcile loop, after that review.
                            closing = True
            except asyncio.CancelledError:
                raise
            except StopAudit:
                raise
            except Exception as exc:
                await abort(f"Planner worker {slot} failure: {type(exc).__name__}: {str(exc)[:400]}")

        def standing_conclusions() -> list[dict]:
            """The conclusions this run's goal is satisfied by, counted the way the host counts them.

            The same filter ``Store.finalize_goal`` applies: evidence that survived validation,
            that no Planner round has taken back, and that the POC agent did not reject.
            Rejected citations and a retracted or duplicated conclusion are all things the
            run must not be closed on.
            """
            return [
                item
                for item in self.store.list_findings(run_id)
                if item.get("validation_state") == "candidate"
                and is_vulnerability_finding(item)
                and str(item.get("disposition") or "open") not in WITHDRAWN_FINDING_DISPOSITIONS
                and str(item.get("verification_status") or "") != "rejected"
            ]

        def standing_baseline() -> list[dict]:
            """Verified project conclusions this run inherited rather than re-discovered.

            Frozen at run start, so a sibling run cannot move this run's goalposts.  Only
            ``verified`` rows count: an unverified project finding is a lead, not a
            conclusion, and a run may not close on it without doing any work.
            """
            run_row = self.store.get_run(run_id) or {}
            return [
                item
                for item in run_row.get("project_baseline") or []
                if str(item.get("disposition") or "open") == "open"
                and str(item.get("verification_status") or "") == "verified"
            ]

        def record_carried() -> None:
            """Mark the project conclusions this run reused without re-finding them."""
            run_row = self.store.get_run(run_id) or {}
            project_id = str(run_row.get("project_id") or "")
            if not project_id:
                return
            try:
                count = self.store.record_carried_findings(project_id, run_id)
            except Exception as exc:  # pragma: no cover - reporting only
                self.bus.emit(run_id, None, "carried_findings_failed", {
                    "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                })
                return
            if count:
                self.bus.emit(run_id, None, "carried_findings_recorded", {
                    "project_id": project_id,
                    "count": count,
                })

        def conclusion_state() -> tuple:
            """What a review round would be looking at: the settled frontier and every conclusion.

            Compared before the host closes.  A review that leaves this unchanged already had
            its chance and did not use it, so the host closes rather than reviewing again --
            which is what keeps the review costing one round per closure point and not two.
            """
            queue_state = self.store.task_queue_state(run_id)
            return (
                queue_state["total"],
                queue_state["terminal"],
                tuple(
                    sorted(
                        (str(item["id"]), int(item["revision"] or 1), str(item["disposition"] or "open"))
                        for item in self.store.list_findings(run_id)
                    )
                ),
            )

        async def run_worker_wave() -> None:
            workers = [
                asyncio.create_task(execute_slot(slot), name=f"planner-{run_id[:8]}-{slot}")
                for slot in range(1, max(1, int(task_spec["max_workers"])) + 1)
            ]
            try:
                await asyncio.gather(*workers)
            finally:
                for worker in workers:
                    worker.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

        while not stop.is_set():
            current = self.store.get_run(run_id)
            goal = self.store.get_task_goal(run_id)
            session_state = self.store.get_planner_session(run_id)
            if current is not None and current["status"] == "paused":
                # A pause is observed here, at the one place every pass goes through, and
                # it returns without abandoning anything.  Nothing below this point has
                # run yet: the frontier is exactly as the last committed round left it and
                # the session keeps its round number, so `resume` continues the run rather
                # than re-planning it.  Treating this as "no longer running" was the bug
                # that would have made pause indistinguishable from cancel.
                self.bus.emit(run_id, None, "run_paused", {
                    "round": (session_state or {}).get("current_round"),
                    "reason": "pause requested",
                })
                return
            if current is not None and current["status"] == "pending":
                # The user resumed before this pass reached its boundary: `resume` returns a
                # paused run to the claim queue, and the attempt that was in flight is
                # allowed to finish.  Reading that `pending` as "no longer running" would
                # abandon the frontier and cancel a run the user had just restarted, so the
                # pass hands the run back instead -- the claim loop takes it straight away
                # and continues from the frontier this pass committed.
                return
            if current is None or current["status"] != "running":
                self.store.abandon_planner_tasks(run_id, "Run is no longer running")
                self.bus.emit(run_id, None, "run_cancelled", {"reason": "cancel requested"})
                return
            if goal is None or session_state is None:
                raise RuntimeError("Planner goal/session disappeared during execution")
            if goal["status"] != "open":
                await finish_goal(goal["status"], goal.get("terminal_reason") or "Goal already settled")
                return
            queue = self.store.task_queue_state(run_id)
            blockers = tuple(sorted({
                (str(item.get("error") or ""), str((item.get("result") or {}).get("missing_context") or []),
                 str((item.get("context_spec") or {}).get("source_refs") or []))
                for item in self.store.list_tasks(run_id, include_attempts=False)
                if item["state"] == "blocked"
            }))
            if blockers and not queue["ready"] and not queue["running"]:
                if blockers in repaired_blockers:
                    await finish_goal("inconclusive", "一次修复规划后阻塞原因仍未改变，停止重复规划。")
                    return
                repaired_blockers.add(blockers)
            # The conclusions the host would close this run on, asked once per pass: they decide
            # both whether a worker may start another direction and whether the host reviews
            # before it closes.  The hold is only meaningful while one of them exists.
            standing = standing_conclusions()
            inherited = standing_baseline()
            if closing and not (standing or inherited):
                closing = False
            if (queue["ready"] or queue["running"]) and not closing:
                await run_worker_wave()
                continue
            # The run is about to satisfy its own completion condition: no direction is being
            # worked on and at least one conclusion survived validation and is still standing.
            # The host's closure is unchanged -- ``finalize_goal`` still checks the same thing --
            # but it does not get to make it before the Planner has seen the conclusion it is
            # being closed on.  A Planner round otherwise only ever runs at the moment the run
            # closes, so without this the corrections a round is allowed to make (reopen a
            # direction, retract a conclusion, call one a duplicate) would be unreachable for
            # exactly the conclusions that matter.  Costs one model call per closure point; a
            # review that changes nothing closes the run on the next pass instead of repeating.
            if (standing or inherited) and (closing or not queue["active"]):
                # Automatic verification runs here rather than after every worker wave: it
                # is the one point where every standing conclusion is already known and the
                # next round is the closure review that should read the verdicts.  A verdict
                # can remove a conclusion from the standing set, so both sets are re-read.
                if project_mode and standing and not stop.is_set():
                    await poc_verifier.verify_standing(
                        run_id,
                        standing,
                        verified_for,
                        model_config=model_config,
                        should_stop=stop.is_set,
                    )
                    standing = standing_conclusions()
                    inherited = standing_baseline()
                    if closing and not (standing or inherited):
                        closing = False
                    if not (standing or inherited):
                        # Every conclusion the host would have closed on was executed and
                        # not reproduced.  Nothing is left to review or close on, so go back
                        # to planning instead of deferring ``met`` forever.
                        continue
                signature = conclusion_state()
                # One agent produced the verdict; a different one has to read the
                # observations before the host may close on it.  This round is that
                # reading, and the closure gate refuses a verified conclusion nobody
                # cross-checked -- so the request is made while rounds remain, not after
                # the run has already decided to close.
                pending_reviews = self.store.unreviewed_verified_findings(run_id)
                review_key = tuple(sorted(
                    (str(item.get("id")), int(item.get("revision") or 1))
                    for item in pending_reviews
                ))
                if (
                    review_key
                    and review_key != reviewed_reviews_for
                    and int(session_state["current_round"]) < int(session_state["max_rounds"])
                    and not stop.is_set()
                ):
                    reviewed_reviews_for = review_key
                    state = await run_planner_round()
                    if state == "closed" or stop.is_set():
                        return
                    continue
                if (
                    reviewed_for != signature
                    and int(session_state["current_round"]) < int(session_state["max_rounds"])
                ):
                    reviewed_for = signature
                    state = await run_planner_round()
                    if state == "closed" or stop.is_set():
                        return
                    # A review that named work -- dispatched a direction, reopened one, even just
                    # re-proposed something it wants run -- asked for it, so the withheld
                    # directions are released along with it.  One that changed nothing, or that
                    # produced nothing usable, has said its piece: the hold stands and the next
                    # pass closes on the conclusion it declined to correct.
                    closing = closing and not (state == "committed" and round_mutations)
                    continue
                # Either the review already ran against this exact state, or there is no round
                # left to run one in. A conclusion the host can verify satisfies the goal on its
                # own; a later Planner-round limit must not recast it as "unreachable".
                settled = await finish_goal(
                    "met",
                    "前沿已结算，并保留至少一条通过源码证据校验、未被撤回的 worker 发现。",
                )
                if not settled:
                    # Strict mode refused the closure because nothing standing was
                    # reproduced.  Leaving the goal open here would leave the run
                    # ``running`` with no work left, so settle honestly instead.
                    await finish_goal(
                        "inconclusive",
                        "收束条件未满足，仍存在受阻方向或缺少有效动态验证。",
                    )
                return
            # A hard shared worker cap is an execution limit, not evidence that the
            # objective is absent. Keep the result reviewable as inconclusive.
            if int(goal["attempts"]) >= int(goal["max_total_attempts"]):
                await finish_goal("inconclusive", "worker 共享尝试上限已耗尽，未能完成所有证据方向")
                return
            if int(session_state["current_round"]) >= int(session_state["max_rounds"]):
                terminal = "unreachable" if queue["total"] and not queue["blocked"] and not queue["active"] else "inconclusive"
                reason = (
                    "所有已派发的证据方向均已结算且无受阻上下文，Planner 回合预算已耗尽"
                    if terminal == "unreachable"
                    else "Planner 回合预算已耗尽，仍存在受阻或未完成的上下文"
                )
                await finish_goal(terminal, reason)
                return
            state = await run_planner_round()
            if state == "closed" or stop.is_set():
                return
            if state == "committed":
                stalled_rounds = 0
                continue
            if state == "failed":
                stalled_rounds += 1
                if stalled_rounds <= int(policy.planner_decision_retries):
                    # A discarded round is not a frontier mutation: re-plan immediately.
                    continue
                if queue["ready"] or queue["running"]:
                    # Still-dispatchable work exists.  Run it instead of ending the run;
                    # rounds stay bounded by the session's own round cap.
                    continue
                if not any(
                    item.get("validation_state") == "candidate"
                    and is_vulnerability_finding(item)
                    and str(item.get("disposition") or "open") not in WITHDRAWN_FINDING_DISPOSITIONS
                    for item in self.store.list_findings(run_id)
                ):
                    await finish_goal(
                        "inconclusive",
                        f"Planner 连续 {stalled_rounds} 回合未能产出可验证决策，"
                        "且前沿已无可执行任务、无通过证据校验的结论",
                    )
                    return

    def _record_finding(
        self,
        run_id: str,
        unit_id: str | None,
        prepared: dict,
        *,
        finding_id: str | None = None,
        extra: dict | None = None,
    ) -> None:
        """Persist one prepared finding and report it, including when it replaced an earlier one.

        A finding occupies a stable slot per ``(run, unit, category)``, and re-running that
        direction writes a new conclusion into the same row: the id survives (so the human
        verifications bound to it do not become orphans) and so does the reviewer's verdict.
        That is a change of mind worth its own event, because nothing in the new conclusion
        says the old one was replaced.  ``finding_id`` is passed by callers whose write
        already happened inside another transaction; otherwise it is written here.
        """
        written: dict | None = None
        if finding_id is None:
            written = self.store.add_finding(prepared["record"])
            finding_id = str(written["finding_id"])
        payload = {**(prepared.get("event") or {}), "finding_id": finding_id, **(extra or {})}
        if written is not None and written["action"] == "superseded":
            self.bus.emit(run_id, unit_id, "finding_superseded", {
                **payload,
                "revision": written["revision"],
                "previous_revision": written["revision"] - 1,
            })
        project = self._merge_project_finding(run_id, finding_id, prepared)
        if project is not None:
            payload.update({
                "project_finding_id": project["project_finding_id"],
                "project_revision": project["revision"],
                "project_relation": project["action"],
                # A conclusion the ledger already holds is not a new discovery; the
                # report counts it under rediscovery and spends no "new findings" credit
                # on it.  A correction still is news.
                "known_state": "known" if project["action"] == "rediscovered" else "new",
            })
        self.bus.emit(
            run_id,
            unit_id,
            "finding_created" if prepared["candidate"] else "finding_rejected_by_validation",
            payload,
        )

    def _merge_project_finding(self, run_id: str, finding_id: str, prepared: dict) -> dict | None:
        """Fold a validated vulnerability into its project's ledger.

        Only a candidate vulnerability is ledger material: an observation, an invalid
        citation or a finding whose kind/severity disqualified it stays run-local.  The
        ledger write is best-effort by design -- losing a ledger row must not lose the run
        finding that is already persisted and reported.
        """
        record = prepared.get("record") or {}
        if not prepared.get("candidate") or not prepared.get("vulnerability"):
            return None
        run = self.store.get_run(run_id)
        project_id = str((run or {}).get("project_id") or "")
        if not project_id:
            return None
        anchor = prepared.get("anchor") or {}
        entry = ledger_record(record)
        entry["file_path"] = str(anchor.get("file_path") or entry["file_path"])
        entry["symbol"] = str(anchor.get("symbol") or entry["symbol"])
        entry["fingerprint"] = canonical_fingerprint(
            entry["file_path"], entry["symbol"], entry["dangerous_operation"]
        )
        try:
            merged = self.store.merge_project_finding(project_id, run_id, entry)
            self.store.link_finding_project(
                finding_id, merged["project_finding_id"], merged["revision"]
            )
        except Exception as exc:  # pragma: no cover - defensive: never lose the run finding
            self.bus.emit(run_id, None, "project_finding_merge_failed", {
                "finding_id": finding_id,
                "error": f"{type(exc).__name__}: {str(exc)[:200]}",
            })
            return None
        self.bus.emit(run_id, None, f"project_finding_{merged['action']}", {
            "finding_id": finding_id,
            "project_finding_id": merged["project_finding_id"],
            "project_id": project_id,
            "revision": merged["revision"],
            "disposition": merged["disposition"],
            "title": record.get("title"),
        })
        return merged

    def _build_planner_findings(self, run: dict, planner_task: dict, outcome: dict) -> list[dict]:
        """Adapt generic finding validation to a task that spans several source files."""
        refs = (planner_task.get("context_spec") or {}).get("source_refs") or []
        anchor = next((item for item in refs if isinstance(item, dict) and item.get("path")), {})
        virtual_unit = {
            "unit_id": planner_task["id"],
            "file_path": str(anchor.get("path") or "<project>"),
            # The task title is a *direction*, not a location.  Filing ledger rows under
            # it would make every run's wording of the same direction a different
            # vulnerability, so the anchor comes from the finding's own evidence.
            "symbol": "<project>",
            "virtual": True,
            "start_line": int(anchor.get("start_line") or 1),
            "end_line": int(anchor.get("end_line") or 1),
        }
        return self._build_goal_findings(run, virtual_unit, outcome)

    def _finding_anchor(self, run: dict, unit: dict, evidence: list[dict]) -> tuple[str, str]:
        """The (path, symbol) a finding is filed under.

        A file/slice unit already names its own anchor.  A Planner task spans several
        files, so its finding is filed where its first validated citation points; the
        symbol is looked up in the frozen project map, and ``<project>`` is used when the
        citation is outside any indexed symbol rather than inventing one.
        """
        path = str(unit.get("file_path") or "")
        symbol = str(unit.get("symbol") or "")
        if not unit.get("virtual"):
            return path, symbol
        first = next((item for item in evidence if isinstance(item, dict) and item.get("path")), None)
        if first is None:
            return path, "<project>"
        path = str(first.get("path") or path)
        line = int(first.get("start_line") or 0)
        return path, self._symbol_at(run["id"], path, line) or "<project>"

    def _symbol_at(self, run_id: str, path: str, line: int) -> str:
        project_map = self.store.get_project_map(run_id) or {}
        best: tuple[int, str] | None = None
        for item in project_map.get("symbols") or []:
            if not isinstance(item, dict) or item.get("path") != path:
                continue
            start = int(item.get("start_line") or 0)
            end = int(item.get("end_line") or 0)
            if start <= line <= end:
                span = end - start
                if best is None or span < best[0]:
                    best = (span, str(item.get("name") or ""))
        return best[1] if best else ""

    async def _execute_goal_task(self, run: dict) -> None:
        """Coordinate a durable, shared task queue with bounded concurrent workers.

        A task worker is deliberately narrower than the legacy audit loop: it can
        establish or rule out one source direction, then returns that result to the
        coordinator.  Only the coordinator closes the goal after every durable work
        item is resolved, which prevents a single "not found" response from becoming
        a project-wide negative conclusion.
        """
        run_id = run["id"]
        model_config = self._model_for_run(run)
        task = run["task_spec"]
        if self.health.is_open():
            error = "模型熔断窗口尚未结束；未发起新的模型请求"
            self.store.abandon_task_work(run_id, error)
            self.store.update_run(run_id, status="failed", finished_at=_now(), error=error)
            self.bus.emit(run_id, None, "run_failed", {"reason": "model_unavailable", "error": error})
            return

        goal = self.store.get_task_goal(run_id)
        if goal is None:
            raise RuntimeError("goal-task run has no durable goal")

        self.bus.emit(
            run_id,
            None,
            "run_started",
            {
                "snapshot_id": run["snapshot_id"],
                "scope": run["scope"],
                "prompt_id": run["prompt_id"],
                "model": run["model"],
                "budgets": run["budgets"],
                "total_units": run["total_units"],
                "mode": "goal_task",
                "task": task,
            },
        )
        self.bus.emit(
            run_id,
            None,
            "task_coordinator_started",
            {
                "goal_id": goal["id"],
                "objective": goal["objective"],
                "success_criteria": goal["success_criteria"],
                "max_iterations": goal["max_iterations"],
                "max_total_attempts": goal["max_total_attempts"],
                "max_workers": task["max_workers"],
            },
        )
        planned = self.store.list_task_work_items(run_id)
        self.bus.emit(
            run_id,
            None,
            "task_plan_created",
            {
                "goal_id": goal["id"],
                "strategy": "目标文本中的代码标识与路径优先，随后按稳定源码顺序处理",
                "work_items": len(planned),
                "scope_files": len(run.get("scope") or []),
                "first_items": [
                    {
                        "work_id": item["id"],
                        "summary": item["summary"],
                        "priority": item["priority"],
                    }
                    for item in planned[:8]
                ],
            },
        )

        stop = asyncio.Event()
        coordinator = asyncio.Lock()
        consecutive_errors = 0
        failure_message: str | None = None

        async def abort(message: str) -> None:
            nonlocal failure_message
            async with coordinator:
                if failure_message is not None:
                    return
                failure_message = message
                stop.set()
                self.store.abandon_task_work(run_id, message)
                self.store.update_run(run_id, status="failed", finished_at=_now(), error=message)
                self.bus.emit(run_id, None, "run_failed", {"error": message})

        async def account_model_result(outcome: dict) -> str | None:
            """Maintain the same endpoint breaker semantics as the legacy loop."""
            nonlocal consecutive_errors
            terminal_reason = outcome.get("terminal_reason")
            if terminal_reason in MODEL_FAILURE_REASONS:
                async with coordinator:
                    self.health.trip(outcome.get("error") or "model error", status=outcome.get("status"))
                    consecutive_errors += 1
                    if consecutive_errors >= MODEL_ERROR_ABORT_AFTER or self.health.is_open():
                        return (
                            f"模型熔断或连续失败阈值触发（本次 {consecutive_errors} 次），运行中止："
                            f"{outcome.get('error') or terminal_reason}"
                        )
                return None
            if terminal_reason == "completed":
                async with coordinator:
                    self.health.pass_()
                    consecutive_errors = 0
            return None

        async def execute_slot(slot: int) -> None:
            worker_id = f"{self.settings.worker}:{run_id[:8]}:{slot}"
            try:
                while not stop.is_set():
                    current = self.store.get_run(run_id)
                    if current is None or current["status"] != "running":
                        self.store.abandon_task_work(run_id, "Run is no longer running")
                        self.bus.emit(run_id, None, "run_cancelled", {"reason": "cancel requested"})
                        return

                    current_goal = self.store.get_task_goal(run_id)
                    if current_goal is None or current_goal["status"] not in {"open", "met"}:
                        return
                    if current_goal["status"] == "met" and task["stop_on_achieved"]:
                        return

                    work = self.store.claim_next_task_work(run_id, worker_id)
                    if work is None:
                        settled = self.store.settle_task_goal_if_idle(run_id)
                        if settled is not None:
                            stop.set()
                        return

                    unit = self.store.get_run_unit(run_id, work["unit_id"])
                    if unit is None:
                        self.store.resolve_task_work(
                            work["id"],
                            outcome="blocked",
                            result={
                                "summary": "冻结的源码单元已不存在",
                                "reasoning": "队列记录无法对应到可读取源码单元",
                                "next_focus": "",
                                "missing_context": ["冻结的源码单元"],
                                "terminal_reason": "missing_unit",
                            },
                            usage=None,
                            seen=None,
                            error="冻结的源码单元已不存在",
                        )
                        continue

                    invocation_id = uuid.uuid4().hex
                    self.bus.emit(
                        run_id,
                        unit["unit_id"],
                        "task_work_started",
                        {
                            "work_id": work["id"],
                            "worker_id": worker_id,
                            "attempt": int(work["attempt"]) + 1,
                            "max_attempts": work["max_attempts"],
                            "focus": work.get("focus") or "",
                            "file_path": unit["file_path"],
                            "symbol": unit["symbol"],
                            "agent_invocation_id": invocation_id, "request_index": 0,
                        },
                    )

                    def record(event: dict) -> None:
                        kind = event.get("kind", "task_agent_event")
                        payload = {key: value for key, value in event.items() if key != "kind"}
                        payload.update({
                            "work_id": work["id"],
                            "worker_id": worker_id,
                            # The same work item may be retried.  Attaching the durable
                            # attempt number to every tool/model event makes an expanded
                            # trace unambiguous even when workers interleave.
                            "attempt": int(work["attempt"]) + 1,
                        })
                        payload.setdefault("agent_invocation_id", invocation_id)
                        payload.setdefault("request_index", 0)
                        self.bus.emit(run_id, unit["unit_id"], kind, payload)

                    outcome = await pursue_task_work(
                        repository=self.repository,
                        snapshot_id=run["snapshot_id"],
                        snapshot_name=run["snapshot_name"],
                        unit=unit,
                        task=task,
                        attempt=int(work["attempt"]) + 1,
                        agent_invocation_id=invocation_id,
                        focus=work.get("focus") or "",
                        allowed_paths=allowed_paths_for_run(run),
                        config=model_config,
                        budgets=run["budgets"],
                        policy=(
                            policy_from_snapshot(run["agent_policy"])
                            if run.get("agent_policy", {}).get("version") == "whitebox-2"
                            else AgentPolicy()
                        ),
                        on_event=record,
                    )
                    outcome = _normalise_task_findings(outcome)

                    # The agent validates its own citations against the exact source
                    # ledger.  Persisting repeats the validation with snapshot bounds;
                    # a rejected artifact cannot satisfy the task objective.
                    prepared_findings: list[dict] = []
                    if outcome["outcome"] == "achieved":
                        prepared_findings = self._build_goal_findings(run, unit, outcome)
                        if not any(item["candidate"] for item in prepared_findings):
                            message = "目标发现须为风险等级明确且通过证据校验的漏洞，才能满足任务验收条件"
                            outcome = {
                                **outcome,
                                "outcome": "blocked",
                                "error": message,
                                "result": {
                                    **outcome["result"],
                                    "outcome": "blocked",
                                    "terminal_reason": "evidence_rejected",
                                    "finding": None,
                                    "findings": [],
                                    "missing_context": [message],
                                },
                            }

                    resolved = self.store.resolve_task_work(
                        work["id"],
                        outcome=outcome["outcome"],
                        result=outcome["result"],
                        usage=outcome["usage"],
                        seen=outcome["seen"],
                        error=outcome.get("error"),
                        findings=[item["record"] for item in prepared_findings if item["candidate"]],
                        stop_on_achieved=bool(task["stop_on_achieved"]),
                        goal_reason=outcome["result"].get("summary") or None,
                    )
                    if resolved is None:
                        # Cancellation/failure may have already released this lease.
                        return

                    if prepared_findings:
                        # Candidate findings were inserted in resolve_task_work's
                        # transaction with the goal state. Invalid artifacts remain
                        # reviewable but cannot affect the goal, so they are written
                        # afterwards under their own immutable IDs.
                        stored_ids = iter(resolved.get("finding_ids") or [])
                        for prepared in prepared_findings:
                            if prepared["candidate"]:
                                self._record_finding(
                                    run_id, unit["unit_id"], prepared, finding_id=next(stored_ids, None),
                                )
                            else:
                                self._record_finding(run_id, unit["unit_id"], prepared)

                    state_kind = {
                        "open": "task_work_requeued",
                        "done": "task_work_completed",
                        "exhausted": "task_work_exhausted",
                        "blocked": "task_work_blocked",
                        "skipped": "task_work_skipped",
                    }.get(resolved["state"], "task_work_settled")
                    self.bus.emit(
                        run_id,
                        unit["unit_id"],
                        state_kind,
                        {
                            "work_id": work["id"],
                            "worker_id": worker_id,
                            "state": resolved["state"],
                            "outcome": outcome["outcome"],
                            "attempt": resolved["attempt"],
                            "max_attempts": resolved["max_attempts"],
                            "summary": outcome["result"].get("summary", ""),
                            "terminal_reason": outcome.get("terminal_reason"),
                        },
                    )

                    failed = await account_model_result(outcome)
                    if failed:
                        await abort(failed)
                        return

                    if outcome["outcome"] == "achieved" and prepared_findings:
                        if resolved.get("goal_met"):
                            self.bus.emit(
                                run_id,
                                unit["unit_id"],
                                "task_goal_met",
                                {
                                    "goal_id": resolved["goal_id"],
                                    "work_id": work["id"],
                                    "finding_id": resolved.get("finding_id"),
                                    "finding_ids": resolved.get("finding_ids", []),
                                    "stop_on_achieved": task["stop_on_achieved"],
                                },
                            )
                            if task["stop_on_achieved"]:
                                stop.set()
                                return

                    # Cancellation can arrive after an agent response but before
                    # the coordinator's final settlement.  Do not turn that
                    # partially cancelled path into an unreachable conclusion.
                    current = self.store.get_run(run_id)
                    if current is None or current["status"] != "running":
                        self.store.abandon_task_work(run_id, "Run is no longer running")
                        self.bus.emit(run_id, None, "run_cancelled", {"reason": "cancel requested"})
                        return

                    settled = self.store.settle_task_goal_if_idle(run_id)
                    if settled is not None:
                        stop.set()
                        return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await abort(f"Goal worker {slot} failure: {type(exc).__name__}: {str(exc)[:400]}")

        worker_count = max(1, int(task["max_workers"]))
        workers = [
            asyncio.create_task(execute_slot(slot), name=f"task-{run_id[:8]}-{slot}")
            for slot in range(1, worker_count + 1)
        ]
        await asyncio.gather(*workers)

        if failure_message is not None:
            return
        current = self.store.get_run(run_id)
        if current is None or current["status"] != "running":
            self.store.abandon_task_work(run_id, "Run is no longer running")
            self.bus.emit(run_id, None, "run_cancelled", {"reason": "cancel requested"})
            return

        settled = self.store.settle_task_goal_if_idle(run_id) or self.store.get_task_goal(run_id)
        if settled is None:
            raise RuntimeError("goal-task run lost its durable goal")
        goal_status = settled["status"]
        if goal_status == "met":
            run_status = "completed"
            event_kind = "run_completed"
        elif goal_status == "unreachable":
            run_status = "unreachable"
            event_kind = "goal_unreachable"
        elif goal_status == "inconclusive":
            run_status = "inconclusive"
            event_kind = "goal_inconclusive"
        else:
            message = f"目标队列未能收束（状态：{goal_status}）"
            await abort(message)
            return
        self.store.update_run(run_id, status=run_status, finished_at=_now())
        self.bus.emit(
            run_id,
            None,
            event_kind,
            {
                "goal_id": settled["id"],
                "goal_status": goal_status,
                "reason": settled.get("terminal_reason"),
                "attempts": settled["attempts"],
            },
        )

    def _build_goal_findings(self, run: dict, unit: dict, outcome: dict) -> list[dict]:
        """Validate generic task results before their atomic queue settlement.

        A target task may establish more than one independently cited source fact from
        one unit.  Those records share the work-item transaction but get separate
        identities, evidence validation states and event rows.  The first single-result
        case keeps the historical ``task_goal`` category for compatibility.
        """
        result = outcome.get("result") or {}
        payloads = result.get("findings")
        if not isinstance(payloads, list):
            legacy = result.get("finding")
            payloads = [legacy] if isinstance(legacy, dict) else []
        payloads = [payload for payload in payloads if isinstance(payload, dict)]
        if not payloads:
            return []
        snapshot = self.repository.get_snapshot(run["snapshot_id"])
        file_lines = {item["path"]: item["line_count"] for item in snapshot["files"]}
        ranges = seen_ranges(unit, outcome.get("seen") or [], exact=outcome.get("seen_exact", False))
        prepared: list[dict] = []
        for index, payload in enumerate(payloads, 1):
            cited = _parse_evidence(
                str(payload.get("evidence") or ""),
                known_paths=file_lines,
            )
            evidence, problems = validate_evidence(cited, file_lines, ranges)
            vulnerability = is_vulnerability_finding(payload)
            candidate = bool(evidence) and vulnerability
            if not vulnerability:
                problems.append("A vulnerability kind and a low/medium/high/critical risk level are required")
            finding_id = uuid.uuid4().hex
            raw_preconditions = str(payload.get("preconditions") or "").strip()
            kind = str(payload.get("kind") or "source_observation").strip() or "source_observation"
            title = str(payload.get("title") or "目标相关源码发现")
            # The legacy table has a (run, unit, category) uniqueness constraint.  A
            # single task result retains ``task_goal``; additional results get stable
            # per-item category slots while their user-facing type lives in finding_kind.
            category = "task_goal" if len(payloads) == 1 else f"task_goal:{index}"
            anchor_path, anchor_symbol = self._finding_anchor(run, unit, evidence)
            dangerous_operation = str(payload.get("dangerous_operation") or "")
            finding = {
                "id": finding_id,
                "run_id": run["id"],
                "unit_id": unit["unit_id"],
                # The ledger identity is built from the finding's own anchor and sink, so
                # a second run -- or the same direction worded differently -- lands on
                # the same project row instead of a new vulnerability.
                "fingerprint": (
                    canonical_fingerprint(anchor_path, anchor_symbol, dangerous_operation)
                    if vulnerability
                    else fingerprint(
                        "task_goal", unit["file_path"], unit["symbol"],
                        f"{kind}|{title}|{payload.get('evidence') or ''}",
                    )
                ),
                "category": category,
                "finding_kind": kind,
                "title": title,
                "severity": str(payload.get("severity") or "unknown"),
                "summary": str(payload.get("summary") or ""),
                "evidence": evidence,
                "input_source": str(payload.get("input_source") or ""),
                "propagation": str(payload.get("propagation") or ""),
                "dangerous_operation": str(payload.get("dangerous_operation") or ""),
                "protection": str(payload.get("protection") or ""),
                "preconditions": [raw_preconditions] if raw_preconditions else [],
                "missing_context": list(result.get("missing_context") or []),
                "poc": payload.get("poc"),
                "remediation": str(payload.get("remediation") or ""),
                "validation_state": "candidate" if candidate else ("invalid_evidence" if not evidence else "invalid_finding"),
                "validation_errors": problems,
                "verdict": None,
                "created_at": _now(),
            }
            prepared.append({
                "record": finding,
                "candidate": candidate,
                "vulnerability": vulnerability,
                "anchor": {"file_path": anchor_path, "symbol": anchor_symbol},
                "event": {
                    "finding_id": finding_id,
                    "category": category,
                    "finding_kind": kind,
                    "title": title,
                    "severity": finding["severity"],
                    "validation_errors": problems,
                    "evidence": evidence,
                    "cited": cited,
                },
            })
        return prepared

    def _store_findings(self, run: dict, unit: dict, outcome: dict) -> list[dict]:
        """Validate and persist candidates, returning a short event summary."""
        snapshot = self.repository.get_snapshot(run["snapshot_id"])
        file_lines = {item["path"]: item["line_count"] for item in snapshot["files"]}
        ranges = seen_ranges(unit, outcome["seen"], exact=outcome.get("seen_exact", False))
        stored: list[dict] = []

        checks = outcome.get("checks")
        if checks is None:
            checks = outcome["analysis"].by_category()
        for category, check in checks.items():
            if check.conclusion != "candidate":
                continue
            cited = [ref.model_dump() for ref in check.evidence]
            evidence, problems = validate_evidence(cited, file_lines, ranges)
            # A finding stands on the citations that checked out. It is only demoted when
            # nothing at all is left, which is what "the model named code it never saw"
            # really means.
            state = "candidate" if evidence else "invalid_evidence"
            finding_id = uuid.uuid4().hex
            finding = {
                "id": finding_id,
                "run_id": run["id"],
                "unit_id": unit["unit_id"],
                "fingerprint": canonical_fingerprint(
                    unit["file_path"], unit["symbol"], check.dangerous_operation
                ),
                "category": category,
                "title": title_for(category, unit["file_path"], unit["symbol"]),
                "severity": check.severity or "unknown",
                "summary": check.reasoning,
                "evidence": evidence,
                "input_source": check.input_source,
                "propagation": check.propagation,
                "dangerous_operation": check.dangerous_operation,
                "protection": check.protection,
                "preconditions": check.preconditions,
                "missing_context": check.missing_context,
                "poc": check.poc.model_dump() if check.poc else None,
                "remediation": check.remediation,
                "validation_state": state,
                "validation_errors": problems,
                "verdict": None,
                "created_at": _now(),
            }
            self.store.add_finding(finding)
            self.bus.emit(
                run["id"],
                unit["unit_id"],
                "finding_created" if state == "candidate" else "finding_rejected_by_validation",
                {
                    "finding_id": finding_id,
                    "category": category,
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "validation_errors": problems,
                    "evidence": evidence,
                    "cited": cited,
                },
            )
            stored.append(
                {"finding_id": finding_id, "category": category, "invalid_evidence": bool(problems)}
            )
            self._merge_project_finding(
                run["id"], finding_id,
                {
                    "record": finding,
                    "candidate": state == "candidate",
                    "vulnerability": True,
                    "anchor": {"file_path": unit["file_path"], "symbol": unit["symbol"]},
                },
            )
        return stored
