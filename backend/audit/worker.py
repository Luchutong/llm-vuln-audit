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

from .agent import audit_unit
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
                self.bus.emit(run["id"], None, f"run_{status}", {"reason": self._cancel_reason})
                if self._stopping:
                    raise
            except Exception as exc:  # a worker crash must not strand a run
                self.store.abandon_pending_units(run["id"], f"Worker failure: {type(exc).__name__}")
                self.store.update_run(
                    run["id"], status="failed", finished_at=_now(), error=f"{type(exc).__name__}: {exc}"[:600]
                )
                self.bus.emit(run["id"], None, "run_failed", {"error": f"{type(exc).__name__}: {exc}"[:600]})
            finally:
                self._current = None
                self._run_id = None

    # --- one run -----------------------------------------------------------

    async def _execute(self, run: dict) -> None:
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
