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
from datetime import datetime, timezone

from .agent import _parse_evidence, audit_unit, plan_audit_frontier, pursue_planner_task, pursue_task_work
from .config import Settings
from .db import Store
from .events import EventBus
from .evidence import fingerprint, seen_ranges, title_for, validate_evidence
from .health import ModelHealth
from .prompts import system_prompt
from .source import SourceRepository
from .runtime import AgentPolicy
from .schemas import Check

# Two model-level failures in a row mean the endpoint itself is down; grinding
# through the rest of the queue would only burn budget.
MODEL_ERROR_ABORT_AFTER = 2
MODEL_FAILURE_REASONS = frozenset(("model_error", "request_timeout"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditWorker:
    def __init__(
        self,
        *,
        settings: Settings,
        store: Store,
        repository: SourceRepository,
        bus: EventBus,
        health: ModelHealth,
    ):
        self.settings = settings
        self.store = store
        self.repository = repository
        self.bus = bus
        self.health = health
        self._wake = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._current: asyncio.Task | None = None
        self._run_id: str | None = None
        self._stopping = False
        self._cancel_reason = "user_cancelled"

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

    @property
    def status(self) -> dict:
        return {"name": self.settings.worker, "current_run": self._run_id,
                "busy": self._current is not None, "alive": self._task is not None and not self._task.done()}

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
            self._current = asyncio.create_task(self._execute(run), name=f"run-{run['id']}")
            try:
                await self._current
            except asyncio.CancelledError:
                status = "interrupted" if self._stopping else "cancelled"
                self.store.update_run(run["id"], status=status, finished_at=_now(), error=self._cancel_reason)
                self.store.abandon_pending_units(run["id"], self._cancel_reason)
                if self.store.get_planner_session(run["id"]) is not None:
                    self.store.abandon_planner_tasks(run["id"], self._cancel_reason)
                else:
                    self.store.abandon_task_work(run["id"], self._cancel_reason)
                self.bus.emit(run["id"], None, f"run_{status}", {"reason": self._cancel_reason})
                if self._stopping:
                    raise
            except Exception as exc:  # a worker crash must not strand a run
                self.store.abandon_pending_units(run["id"], f"Worker failure: {type(exc).__name__}")
                if self.store.get_planner_session(run["id"]) is not None:
                    self.store.abandon_planner_tasks(run["id"], f"Worker failure: {type(exc).__name__}")
                else:
                    self.store.abandon_task_work(run["id"], f"Worker failure: {type(exc).__name__}")
                self.store.update_run(
                    run["id"], status="failed", finished_at=_now(), error=f"{type(exc).__name__}: {exc}"[:600]
                )
                self.bus.emit(run["id"], None, "run_failed", {"error": f"{type(exc).__name__}: {exc}"[:600]})
            finally:
                self._current = None
                self._run_id = None

    # --- one run -----------------------------------------------------------

    async def _execute(self, run: dict) -> None:
        if run.get("task_spec"):
            await self._execute_planner_task(run)
            return
        await self._execute_legacy(run)

    async def _execute_legacy(self, run: dict) -> None:
        run_id = run["id"]
        if self.health.is_open():
            error = "模型熔断窗口尚未结束；未发起新的模型请求"
            self.store.abandon_pending_units(run_id, error)
            self.store.update_run(run_id, status="failed", finished_at=_now(), error=error)
            self.bus.emit(run_id, None, "run_failed", {"reason": "model_unavailable", "error": error})
            return
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
            },
        )
        consecutive_errors = 0

        while True:
            current = self.store.get_run(run_id)
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
                },
            )

            saved_categories: set[str] = set()
            checkpoint = {"result": None, "usage": None, "seen": []}

            def record(event: dict) -> None:
                # Synchronous callback: the durable event is committed before the
                # model advances to another graph node or receives another tool result.
                kind = event.get("kind", "agent_event")
                payload = {key: value for key, value in event.items() if key != "kind"}
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
                config=self.settings.model,
                budgets=run["budgets"],
                policy=AgentPolicy(**run["agent_policy"]) if run.get("agent_policy", {}).get("version") == "whitebox-2" else AgentPolicy(),
                on_event=record,
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
                     "settled_categories": partial},
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
                },
            )

    def _policy_for_run(self, run: dict) -> AgentPolicy:
        policy = run.get("agent_policy") or {}
        return AgentPolicy(**policy) if policy.get("version") == "whitebox-2" else AgentPolicy()

    async def _execute_planner_task(self, run: dict) -> None:
        """Run ARTEX-style Planner rounds over a durable, dynamic task frontier.

        One Planner owns task creation and graph changes; many bounded workers only
        claim ready tasks.  A worker never decides that the project goal is impossible.
        Its evidence-bound summary becomes input for the next serialized Planner round.
        """
        run_id = run["id"]
        task_spec = run["task_spec"]
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
        coordinator = asyncio.Lock()
        failure_message: str | None = None
        consecutive_errors = 0

        self.bus.emit(
            run_id,
            None,
            "run_started",
            {
                "snapshot_id": run["snapshot_id"],
                "scope": run["scope"],
                "model": run["model"],
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
                settled = self.store.finalize_goal(run_id, state, basis, missing)
            except ValueError as exc:
                self.bus.emit(run_id, None, "planner_terminal_deferred", {
                    "state": state, "reason": str(exc), "basis_summary": basis,
                })
                return False
            status_map = {"met": ("completed", "run_completed"), "unreachable": ("unreachable", "goal_unreachable"), "inconclusive": ("inconclusive", "goal_inconclusive")}
            run_status, event_kind = status_map[state]
            self.store.update_run(run_id, status=run_status, finished_at=_now())
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
            plan = self.store.begin_planner_round(run_id, session["session_id"])
            if plan is None:
                return "no_round"
            self.bus.emit(run_id, None, "planner_round_started", {
                "plan_id": plan["id"], "round": plan["round_no"], "revision": plan["revision"],
                "session_id": session["session_id"],
            })

            def record(event: dict) -> None:
                kind = event.get("kind", "planner_agent_event")
                payload = {key: value for key, value in event.items() if key != "kind"}
                payload.update({"plan_id": plan["id"], "session_id": session["session_id"], "role": "planner"})
                self.bus.emit(run_id, None, kind, payload)

            context = self.store.list_planner_context(run_id)
            outcome = await plan_audit_frontier(
                project_map=project_map,
                run_context=context,
                task=task_spec,
                round_no=int(plan["round_no"]),
                config=self.settings.model,
                budgets=run["budgets"],
                policy=policy,
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
                await finish_goal("inconclusive", message)
                return "failed"
            tasks = list(decision.get("tasks") or [])
            updates = list(decision.get("updates") or [])
            self.store.finish_planner_round(
                run_id,
                plan["id"],
                goal_state=str(decision.get("goal_state") or "continue"),
                basis_summary=str(decision.get("basis_summary") or "Planner 已提交任务图更新。"),
                next_action=str(decision.get("next_action") or ""),
                missing_context=list(decision.get("missing_context") or []),
                tasks=tasks,
                updates=updates,
                usage=outcome.get("usage"),
            )
            queue = self.store.task_queue_state(run_id)
            self.bus.emit(run_id, None, "planner_round_committed", {
                "plan_id": plan["id"],
                "round": plan["round_no"],
                "revision": plan["revision"],
                "goal_state": decision.get("goal_state"),
                "basis_summary": decision.get("basis_summary"),
                "next_action": decision.get("next_action"),
                "task_count": len(tasks),
                "updates": updates,
                "queue": queue,
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
            worker_id = f"{self.settings.worker}:{run_id[:8]}:{slot}"
            try:
                while not stop.is_set():
                    current = self.store.get_run(run_id)
                    current_goal = self.store.get_task_goal(run_id)
                    if current is None or current["status"] != "running" or current_goal is None or current_goal["status"] != "open":
                        return
                    planner_task = self.store.claim_ready_task(run_id, worker_id)
                    if planner_task is None:
                        return
                    attempt = int(planner_task["attempts"]) + 1
                    task_id = planner_task["id"]
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

                    outcome = await pursue_planner_task(
                        repository=self.repository,
                        snapshot_id=run["snapshot_id"],
                        snapshot_name=run["snapshot_name"],
                        planner_task=planner_task,
                        run_task=task_spec,
                        attempt=attempt,
                        allowed_paths=set(run.get("scope") or []),
                        dependency_handoffs=dependency_handoffs,
                        peer_trace_search=search_peer_traces,
                        peer_trace_read=get_peer_trace,
                        config=self.settings.model,
                        budgets=run["budgets"],
                        policy=policy,
                        on_event=record,
                    )
                    prepared_findings: list[dict] = []
                    if outcome["outcome"] == "achieved":
                        prepared_findings = self._build_planner_findings(run, planner_task, outcome)
                        if not any(item["candidate"] for item in prepared_findings):
                            message = "Planner worker 的发现未通过持久化证据校验，不能满足目标"
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
                        self.store.add_finding(prepared["record"])
                        self.bus.emit(
                            run_id,
                            task_id,
                            "finding_created" if prepared["candidate"] else "finding_rejected_by_validation",
                            {**prepared["event"], "task_id": task_id, "task_key": planner_task["task_key"]},
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
                            await finish_goal("met", (outcome.get("result") or {}).get("summary") or "Worker produced evidence-backed findings.")
                            return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await abort(f"Planner worker {slot} failure: {type(exc).__name__}: {str(exc)[:400]}")

        async def run_worker_wave() -> None:
            workers = [
                asyncio.create_task(execute_slot(slot), name=f"planner-{run_id[:8]}-{slot}")
                for slot in range(1, max(1, int(task_spec["max_workers"])) + 1)
            ]
            await asyncio.gather(*workers)

        while not stop.is_set():
            current = self.store.get_run(run_id)
            goal = self.store.get_task_goal(run_id)
            session_state = self.store.get_planner_session(run_id)
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
            if queue["ready"] or queue["running"]:
                await run_worker_wave()
                continue
            # With stop_on_achieved disabled, workers are allowed to finish the
            # currently dispatched frontier after the first valid finding.  Once that
            # frontier is terminal, an evidence-backed candidate still satisfies the
            # host-verifiable completion condition; do not let a later Planner-round
            # limit incorrectly recast it as "unreachable".
            if not task_spec.get("stop_on_achieved", True):
                has_candidate = any(
                    item.get("validation_state") == "candidate"
                    for item in self.store.list_findings(run_id)
                )
                if has_candidate and not queue["active"]:
                    await finish_goal(
                        "met",
                        "已完成当前动态任务前沿，并保留至少一条通过源码证据校验的 worker 发现。",
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
            if state in {"closed", "failed"} or stop.is_set():
                return

    def _build_planner_findings(self, run: dict, planner_task: dict, outcome: dict) -> list[dict]:
        """Adapt generic finding validation to a task that spans several source files."""
        refs = (planner_task.get("context_spec") or {}).get("source_refs") or []
        anchor = next((item for item in refs if isinstance(item, dict) and item.get("path")), {})
        virtual_unit = {
            "unit_id": planner_task["id"],
            "file_path": str(anchor.get("path") or "<project>"),
            "symbol": str(planner_task.get("title") or planner_task.get("task_key") or "<planner task>"),
            "start_line": int(anchor.get("start_line") or 1),
            "end_line": int(anchor.get("end_line") or 1),
        }
        return self._build_goal_findings(run, virtual_unit, outcome)

    async def _execute_goal_task(self, run: dict) -> None:
        """Coordinate a durable, shared task queue with bounded concurrent workers.

        A task worker is deliberately narrower than the legacy audit loop: it can
        establish or rule out one source direction, then returns that result to the
        coordinator.  Only the coordinator closes the goal after every durable work
        item is resolved, which prevents a single "not found" response from becoming
        a project-wide negative conclusion.
        """
        run_id = run["id"]
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
                        self.bus.emit(run_id, unit["unit_id"], kind, payload)

                    outcome = await pursue_task_work(
                        repository=self.repository,
                        snapshot_id=run["snapshot_id"],
                        snapshot_name=run["snapshot_name"],
                        unit=unit,
                        task=task,
                        attempt=int(work["attempt"]) + 1,
                        focus=work.get("focus") or "",
                        allowed_paths=set(run.get("scope") or []),
                        config=self.settings.model,
                        budgets=run["budgets"],
                        policy=(
                            AgentPolicy(**run["agent_policy"])
                            if run.get("agent_policy", {}).get("version") == "whitebox-2"
                            else AgentPolicy()
                        ),
                        on_event=record,
                    )

                    # The agent validates its own citations against the exact source
                    # ledger.  Persisting repeats the validation with snapshot bounds;
                    # a rejected artifact cannot satisfy the task objective.
                    prepared_findings: list[dict] = []
                    if outcome["outcome"] == "achieved":
                        prepared_findings = self._build_goal_findings(run, unit, outcome)
                        if not any(item["candidate"] for item in prepared_findings):
                            message = "目标发现未通过持久化证据校验，不能满足任务验收条件"
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
                        for prepared in prepared_findings:
                            if not prepared["candidate"]:
                                self.store.add_finding(prepared["record"])
                            self.bus.emit(
                                run_id,
                                unit["unit_id"],
                                "finding_created" if prepared["candidate"] else "finding_rejected_by_validation",
                                prepared["event"],
                            )

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
            candidate = bool(evidence)
            finding_id = uuid.uuid4().hex
            raw_preconditions = str(payload.get("preconditions") or "").strip()
            kind = str(payload.get("kind") or "source_observation").strip() or "source_observation"
            title = str(payload.get("title") or "目标相关源码发现")
            # The legacy table has a (run, unit, category) uniqueness constraint.  A
            # single task result retains ``task_goal``; additional results get stable
            # per-item category slots while their user-facing type lives in finding_kind.
            category = "task_goal" if len(payloads) == 1 else f"task_goal:{index}"
            finding = {
                "id": finding_id,
                "run_id": run["id"],
                "unit_id": unit["unit_id"],
                "fingerprint": fingerprint(
                    "task_goal", unit["file_path"], unit["symbol"],
                    f"{kind}|{title}|{payload.get('evidence') or ''}",
                ),
                "category": category,
                "finding_kind": kind,
                "title": title,
                "severity": str(payload.get("severity") or "informational"),
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
                "validation_state": "candidate" if candidate else "invalid_evidence",
                "validation_errors": problems,
                "verdict": None,
                "created_at": _now(),
            }
            prepared.append({
                "record": finding,
                "candidate": candidate,
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
                "fingerprint": fingerprint(
                    category, unit["file_path"], unit["symbol"], check.dangerous_operation
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
        return stored
