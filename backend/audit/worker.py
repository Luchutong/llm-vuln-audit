"""The single background audit worker.

One run at a time, one unit at a time. The queue was frozen when the run was created,
so the worker only ever picks the next pending unit; it never adds scope. Cancellation
is observed between units and in-flight work is cancelled outright.
"""
from __future__ import annotations

import asyncio
import contextlib
import uuid
from datetime import datetime, timezone

from .agent import _parse_evidence, audit_unit, pursue_task_work
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
                self.store.abandon_task_work(run["id"], self._cancel_reason)
                self.bus.emit(run["id"], None, f"run_{status}", {"reason": self._cancel_reason})
                if self._stopping:
                    raise
            except Exception as exc:  # a worker crash must not strand a run
                self.store.abandon_pending_units(run["id"], f"Worker failure: {type(exc).__name__}")
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
            await self._execute_goal_task(run)
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
                        payload.update({"work_id": work["id"], "worker_id": worker_id})
                        self.bus.emit(run_id, unit["unit_id"], kind, payload)

                    outcome = await pursue_task_work(
                        repository=self.repository,
                        snapshot_id=run["snapshot_id"],
                        snapshot_name=run["snapshot_name"],
                        unit=unit,
                        task=task,
                        attempt=int(work["attempt"]) + 1,
                        focus=work.get("focus") or "",
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
                    prepared_finding = None
                    if outcome["outcome"] == "achieved":
                        prepared_finding = self._build_goal_finding(run, unit, outcome)
                        if not prepared_finding or not prepared_finding["candidate"]:
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
                        finding=(prepared_finding or {}).get("record") if prepared_finding and prepared_finding["candidate"] else None,
                        stop_on_achieved=bool(task["stop_on_achieved"]),
                        goal_reason=outcome["result"].get("summary") or None,
                    )
                    if resolved is None:
                        # Cancellation/failure may have already released this lease.
                        return

                    if prepared_finding is not None:
                        # Candidate findings were inserted in resolve_task_work's
                        # transaction with the goal state. An invalid artifact is still
                        # useful for review, but cannot affect the goal and can be
                        # written after the work settles.
                        if not prepared_finding["candidate"]:
                            self.store.add_finding(prepared_finding["record"])
                        self.bus.emit(
                            run_id,
                            unit["unit_id"],
                            "finding_created" if prepared_finding["candidate"] else "finding_rejected_by_validation",
                            prepared_finding["event"],
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

                    if outcome["outcome"] == "achieved" and prepared_finding:
                        if resolved.get("goal_met"):
                            self.bus.emit(
                                run_id,
                                unit["unit_id"],
                                "task_goal_met",
                                {
                                    "goal_id": resolved["goal_id"],
                                    "work_id": work["id"],
                                    "finding_id": resolved.get("finding_id"),
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

    def _build_goal_finding(self, run: dict, unit: dict, outcome: dict) -> dict | None:
        """Validate a custom-task finding before its atomic queue settlement."""
        payload = (outcome.get("result") or {}).get("finding")
        if not isinstance(payload, dict):
            return None
        snapshot = self.repository.get_snapshot(run["snapshot_id"])
        file_lines = {item["path"]: item["line_count"] for item in snapshot["files"]}
        cited = _parse_evidence(str(payload.get("evidence") or ""))
        evidence, problems = validate_evidence(
            cited,
            file_lines,
            seen_ranges(unit, outcome.get("seen") or [], exact=outcome.get("seen_exact", False)),
        )
        candidate = bool(evidence)
        finding_id = uuid.uuid4().hex
        raw_preconditions = str(payload.get("preconditions") or "").strip()
        finding = {
            "id": finding_id,
            "run_id": run["id"],
            "unit_id": unit["unit_id"],
            "fingerprint": fingerprint(
                "task_goal", unit["file_path"], unit["symbol"], str(payload.get("dangerous_operation") or "")
            ),
            "category": "task_goal",
            "title": str(payload.get("title") or "自定义目标发现"),
            "severity": str(payload.get("severity") or "unknown"),
            "summary": str(payload.get("summary") or ""),
            "evidence": evidence,
            "input_source": str(payload.get("input_source") or ""),
            "propagation": str(payload.get("propagation") or ""),
            "dangerous_operation": str(payload.get("dangerous_operation") or ""),
            "protection": str(payload.get("protection") or ""),
            "preconditions": [raw_preconditions] if raw_preconditions else [],
            "missing_context": list((outcome.get("result") or {}).get("missing_context") or []),
            "poc": payload.get("poc"),
            "remediation": str(payload.get("remediation") or ""),
            "validation_state": "candidate" if candidate else "invalid_evidence",
            "validation_errors": problems,
            "verdict": None,
            "created_at": _now(),
        }
        return {
            "record": finding,
            "candidate": candidate,
            "event": {
                "finding_id": finding_id,
                "category": "task_goal",
                "title": finding["title"],
                "severity": finding["severity"],
                "validation_errors": problems,
                "evidence": evidence,
                "cited": cited,
            },
        }

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
