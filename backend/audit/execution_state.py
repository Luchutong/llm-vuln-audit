"""Durable run admission and execution ownership, shared by every agent role."""
from __future__ import annotations

import contextvars
import json
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

POLICY_VERSION = "audit-runtime-3"
DEFAULT_RUN_LIMITS = {"responses": 256, "tools": 2048, "seconds": 1800}
FULL_RUN_LIMITS = {"responses": 512, "tools": 4096, "seconds": 3600}
MIN_RUN_LIMITS = {"responses": 1, "tools": 0, "seconds": 30}
MAX_RUN_LIMITS = {"responses": 4096, "tools": 32768, "seconds": 14400}
TERMINAL = frozenset({"completed", "inconclusive", "failed", "cancelled", "interrupted", "unreachable"})
CURRENT_EXECUTION = contextvars.ContextVar("audit_run_execution", default=None)
CURRENT_ROLE = contextvars.ContextVar("audit_execution_role", default={})
CURRENT_COMPARISON_DEADLINE = contextvars.ContextVar("audit_comparison_deadline", default=None)


@contextmanager
def comparison_deadline(deadline_monotonic: float | None):
    """Bound one comparison lifecycle without changing ordinary audit defaults.

    The deadline uses this process's monotonic clock. ContextVar scope propagates
    to the trial's async tasks and is restored when the trial exits.
    """
    token = CURRENT_COMPARISON_DEADLINE.set(deadline_monotonic)
    try:
        yield
    finally:
        CURRENT_COMPARISON_DEADLINE.reset(token)


def comparison_deadline_remaining() -> float | None:
    deadline = CURRENT_COMPARISON_DEADLINE.get()
    return None if deadline is None else deadline - time.monotonic()

EXECUTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS run_execution_state (
 run_id TEXT PRIMARY KEY, limits TEXT, responses_used INTEGER NOT NULL DEFAULT 0,
 tools_used INTEGER NOT NULL DEFAULT 0, active_elapsed_ms INTEGER NOT NULL DEFAULT 0,
 claim_epoch INTEGER NOT NULL DEFAULT 0, state_revision INTEGER NOT NULL DEFAULT 0,
 phase TEXT NOT NULL DEFAULT 'queued', stop_reason TEXT, poc_state TEXT NOT NULL DEFAULT '{}',
 context TEXT NOT NULL DEFAULT '{}', workflow TEXT NOT NULL DEFAULT '{}', final_summary TEXT, updated_at TEXT NOT NULL
);
"""

def stamp():
    return datetime.now(timezone.utc).isoformat()

def dump(value):
    return json.dumps(value, ensure_ascii=False)

@dataclass
class RunExecution:
    store: object
    run_id: str
    epoch: int

    def admit(self, dimension):
        return self.store.admit_execution(self.run_id, self.epoch, dimension)

@contextmanager
def execution_context(store, run_id, epoch):
    token = CURRENT_EXECUTION.set(RunExecution(store, run_id, epoch))
    try:
        yield
    finally:
        CURRENT_EXECUTION.reset(token)

@contextmanager
def execution_role(role, task_id=None):
    token = CURRENT_ROLE.set({"role": role, "task_id": task_id})
    try:
        yield
    finally:
        CURRENT_ROLE.reset(token)

class ExecutionStoreMixin:
    def _init_execution_state(self):
        self._active_clocks = {}
        self._active_agents = {}
        self._db.executescript(EXECUTION_SCHEMA)
        if "workflow" not in {row[1] for row in self._db.execute("PRAGMA table_info(run_execution_state)")}:
            self._db.execute("ALTER TABLE run_execution_state ADD COLUMN workflow TEXT NOT NULL DEFAULT '{}'")
        # Business revisions invalidate dynamic model caches. Logs never change it.
        for table in ("planner_tasks", "findings", "verifications", "task_work_items"):
            for action in ("INSERT", "UPDATE", "DELETE"):
                ref = "OLD" if action == "DELETE" else "NEW"
                if table == "verifications":
                    expression = f"(SELECT run_id FROM findings WHERE id = {ref}.finding_id)"
                else:
                    expression = f"{ref}.run_id"
                self._db.execute(f"CREATE TRIGGER IF NOT EXISTS execution_revision_{table}_{action} "
                    f"AFTER {action} ON {table} BEGIN UPDATE run_execution_state SET "
                    f"state_revision = state_revision + 1 WHERE run_id = {expression}; END")
        for action in ("INSERT", "UPDATE", "DELETE"):
            ref = "OLD" if action == "DELETE" else "NEW"
            self._db.execute(f"CREATE TRIGGER IF NOT EXISTS execution_revision_project_findings_{action} "
                f"AFTER {action} ON project_findings BEGIN UPDATE run_execution_state SET state_revision=state_revision+1 "
                f"WHERE run_id IN (SELECT id FROM runs WHERE project_id={ref}.project_id AND status IN ('pending','running','paused')); END")

    def _create_execution_state_tx(self, run):
        from .workflow import freeze_workflow
        limits = run.get("run_limits")
        if (run.get("task_spec") or {}).get("workflow_policy") == "discovery_first" and limits is None:
            limits = dict(DEFAULT_RUN_LIMITS)
        workflow = freeze_workflow(run, limits or DEFAULT_RUN_LIMITS)
        self._db.execute("INSERT INTO run_execution_state(run_id, limits, poc_state, workflow, updated_at) VALUES (?,?,?,?,?)",
                         (run["id"], dump(limits) if limits is not None else None, dump(run.get("poc_state") or {}), dump(workflow), stamp()))

    def workflow_state(self, run_id):
        summary = self.execution_summary(run_id)
        return (summary.get("workflow") or {}) if summary else {}

    def refresh_review_reserve(self, run_id, repository=None, *, additional_workers=0):
        """Repartition the existing ledger; this never admits or spends a request."""
        if not self.host_queue_enabled(run_id):
            return self.workflow_state(run_id)
        repository = repository or getattr(self, "_report_repository", None)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            clock_started = self._active_clocks.get(run_id)
            try:
                self.assert_execution_write(run_id)
                batches = self.review_batches_pending(run_id, "final", repository)
                workers = int(self._row("SELECT COUNT(*) FROM planner_tasks WHERE run_id=? AND state='running'", (run_id,))[0]) + additional_workers
                needed = 3 * len(batches) + 6 * workers
                seconds = 60 * (len(batches) + 2 * workers + 1)
                self._tick_execution_tx(run_id)
                row = self._row("SELECT * FROM run_execution_state WHERE run_id=?", (run_id,))
                value = json.loads(row["workflow"] or "{}")
                limits = json.loads(row["limits"] or "{}")
                if not value:
                    self._db.execute("COMMIT")
                    return {}
                previous = dict(value["limits"])
                target = value["used"]["review"] + needed
                if value["source"] != "explicit":
                    if target < value["limits"]["review"] and value["stage"] != "review":
                        released = value["limits"]["review"] - target
                        value["limits"]["review"] -= released
                        value["limits"][value["stage"]] += released
                    short = max(0, target - value["limits"]["review"])
                    for stage in ("discovery", "poc"):
                        take = min(short, max(0, value["limits"][stage] - value["used"][stage]))
                        value["limits"][stage] -= take
                        value["limits"]["review"] += take
                        short -= take
                remaining_seconds = max(0., float(limits.get("seconds", 0)) - row["active_elapsed_ms"] / 1000)
                funded = value["limits"]["review"] - value["used"]["review"] >= needed
                # Discovery must leave both the review window and the POC window on the
                # clock.  Reserving only the review window made the two gates mutually
                # exclusive: discovery stopped when ``remaining <= review`` while the POC
                # gate required ``remaining > review``.
                from .workflow import stage_poc_window
                poc_window = stage_poc_window(value)
                value["review_reserved_seconds"] = seconds
                value["review_reserve"] = {
                    "pending_items": sum(len(batch) for batch in batches), "estimated_batches": len(batches),
                    "workers": workers, "responses": needed, "seconds": seconds, "funded": funded,
                    "poc_window_seconds": poc_window,
                    "upstream_allowed": funded and remaining_seconds > seconds + poc_window,
                    "poc_window_blocks": (funded and remaining_seconds > seconds
                                          and remaining_seconds <= seconds + poc_window),
                    "reason": "actual_review_batches_and_inflight_workers",
                }
                self._db.execute("UPDATE run_execution_state SET workflow=?,updated_at=? WHERE run_id=?", (dump(value), stamp(), run_id))
                if previous != value["limits"]:
                    self.append_event(run_id, None, "workflow_budget_reallocated", {
                        "before": previous, "limits": value["limits"], "reserve": value["review_reserve"],
                        "reason": "按实际待审事实调整预留，整次上限与累计用量不变。"})
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                if clock_started is not None:
                    self._active_clocks[run_id] = clock_started
                raise
        return self.workflow_state(run_id)

    def set_workflow_stage(self, run_id, stage, *, reason=None, transfer_unused=False):
        """Persist phase ownership; neither resume nor role changes renew its allowance."""
        from .workflow import STAGES
        if stage not in STAGES:
            raise ValueError("unknown workflow stage")
        with self._lock:
            self.assert_execution_write(run_id)
            row = self._db.execute("SELECT workflow FROM run_execution_state WHERE run_id=?", (run_id,)).fetchone()
            value = json.loads(row[0] or "{}") if row else {}
            if not value:
                return {}
            if stage == "discovery" and value["stage"] != "discovery":
                raise ValueError("the discovery stage has already ended")
            if value["stage"] == "discovery" and stage != "discovery":
                value["discovery_stop"] = reason or "settled"
                if transfer_unused:
                    unused = max(0, value["limits"]["discovery"] - value["used"]["discovery"])
                    value["limits"]["discovery"] -= unused
                    value["limits"]["poc"] += unused
                    value["transferred"] = value.get("transferred", 0) + unused
            value["stage"] = stage
            self._db.execute("UPDATE run_execution_state SET workflow=?,updated_at=? WHERE run_id=?", (dump(value), stamp(), run_id))
        return self.workflow_state(run_id)

    def release_poc_quota(self, run_id):
        """Move the finished POC stage's unspent responses into the final review.

        A real closure run reviewed 21 of 22 batches and then ended
        ``final_review_incomplete`` with 75 responses in the review stage while the
        finished POC stage still held more than a thousand, having spent 138 of 1809.
        Called only when the POC stage is over for good -- the alternating
        POC/review loop during discovery still needs its own remaining quota.
        """
        with self._lock:
            self.assert_execution_write(run_id)
            row = self._db.execute("SELECT workflow FROM run_execution_state WHERE run_id=?", (run_id,)).fetchone()
            value = json.loads(row[0] or "{}") if row else {}
            if not value or value.get("source") == "explicit":
                return self.workflow_state(run_id)
            unused = max(0, value["limits"]["poc"] - value["used"]["poc"])
            if not unused:
                return self.workflow_state(run_id)
            value["limits"]["poc"] -= unused
            value["limits"]["review"] += unused
            value["transferred"] = value.get("transferred", 0) + unused
            self._db.execute("UPDATE run_execution_state SET workflow=?,updated_at=? WHERE run_id=?", (dump(value), stamp(), run_id))
        return self.workflow_state(run_id)

    def _claim_execution_tx(self, run_id):
        self._db.execute("INSERT OR IGNORE INTO run_execution_state(run_id, updated_at) VALUES (?,?)", (run_id, stamp()))
        self._db.execute("UPDATE run_execution_state SET claim_epoch=claim_epoch+1, phase='planning', updated_at=? WHERE run_id=?", (stamp(), run_id))
        self._active_clocks[run_id] = time.monotonic()

    def _tick_execution_tx(self, run_id, *, stop=False):
        started = self._active_clocks.get(run_id)
        if started is not None:
            current = time.monotonic()
            elapsed_ms = max(0, int((current-started)*1000))
            self._db.execute("UPDATE run_execution_state SET active_elapsed_ms=active_elapsed_ms+?, updated_at=? WHERE run_id=?", (elapsed_ms, stamp(), run_id))
            if stop:
                self._active_clocks.pop(run_id, None)
            else:
                self._active_clocks[run_id] = started + elapsed_ms/1000

    def execution_write_allowed(self, run_id, epoch=None):
        current = CURRENT_EXECUTION.get()
        if epoch is None and current is not None:
            epoch = current.epoch
        with self._lock:
            row = self._db.execute("SELECT r.status,s.claim_epoch,s.phase FROM runs r LEFT JOIN run_execution_state s ON s.run_id=r.id WHERE r.id=?", (run_id,)).fetchone()
            return bool(row and row["status"] in ("running", "paused") and row["phase"] not in ("ended", "paused") and (epoch is None or row["claim_epoch"] == epoch))

    def assert_execution_write(self, run_id):
        from .runtime import StopAudit
        current = CURRENT_EXECUTION.get()
        if current is not None and run_id != current.run_id:
            raise StopAudit("interrupted", "旧执行代次或已结束运行拒绝迟到业务写入")
        if current is not None:
            self._reject_expired_comparison(run_id, current.epoch)
        if current is not None and (run_id != current.run_id or not self.execution_write_allowed(run_id, current.epoch)):
            raise StopAudit("interrupted", "旧执行代次或已结束运行拒绝迟到业务写入")

    def _reject_expired_comparison(self, run_id, epoch):
        """Fence an expired trial before admission or business transaction entry.

        Epoch checks prevent a late owner from stopping a newer claim. Most write
        guards enter here before BEGIN. If an inner assertion is reached after
        BEGIN, reject the write and let its owner roll back; never commit another
        transaction's provisional business facts to save a terminal checkpoint.
        """
        from .runtime import StopAudit
        remaining = comparison_deadline_remaining()
        if remaining is None or remaining > 0:
            return
        reason = {"code": "batch_deadline_exceeded", "message": "Prompt 实验的墙钟截止时间已到期"}
        with self._lock:
            if not self._db.in_transaction:
                self.terminate_execution(run_id, "interrupted", reason, epoch=epoch)
        raise StopAudit(reason["code"], reason["message"])

    def _validate_execution_admission_tx(self, run_id, epoch, dimension, *, role=None,
                                         require_running=False):
        """Validate admission on the caller's transaction without spending a slot.

        The HTTP gateway uses this same fence before atomically charging its own
        request quota. A budget stop is persisted by the transaction owner; this
        helper never commits another caller's provisional facts.
        """
        from .runtime import StopAudit
        if dimension not in (None, "responses", "tools", "work"):
            raise ValueError("unknown budget dimension")
        # Acquiring SQLite's write lock may have waited past the scoped deadline.
        self._reject_expired_comparison(run_id, epoch)
        if not self.execution_write_allowed(run_id, epoch):
            raise StopAudit("interrupted", "运行已停止或执行资格已交接")
        if require_running:
            run = self._db.execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()
            if not run or run["status"] != "running":
                raise StopAudit("interrupted", "运行已暂停或停止，不再准入新请求")
        self._tick_execution_tx(run_id)
        row = self._db.execute("SELECT * FROM run_execution_state WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise StopAudit("interrupted", "运行缺少持久执行状态")
        previous_stop = json.loads(row["stop_reason"]) if row["stop_reason"] else {}
        if previous_stop.get("code") == "run_budget_exhausted":
            raise StopAudit("run_budget_exhausted", previous_stop["message"])
        limits = json.loads(row["limits"]) if row["limits"] else None
        workflow = json.loads(row["workflow"] or "{}")
        exceeded = None
        if limits:
            if row["active_elapsed_ms"] >= limits["seconds"]*1000:
                exceeded = "seconds"
            elif dimension in ("responses", "tools") and row[dimension+"_used"] >= limits[dimension]:
                exceeded = dimension
            elif dimension == "work" and row["responses_used"] >= limits["responses"]:
                exceeded = "responses"
            elif dimension in ("responses", "work") and limits["tools"] > 0 and row["tools_used"] >= limits["tools"]:
                exceeded = "tools"
        if exceeded:
            reason = {"code": "run_budget_exhausted", "dimension": exceeded, "message": f"整次审计 {exceeded} 预算已耗尽"}
            self._db.execute("UPDATE run_execution_state SET stop_reason=? WHERE run_id=?", (dump(reason), run_id))
            raise StopAudit("run_budget_exhausted", reason["message"])
        if workflow and dimension in ("responses", "tools", "work"):
            stage = workflow["stage"]
            remaining_time = (float(limits["seconds"]) - row["active_elapsed_ms"] / 1000) if limits else None
            # Same reservation as ``workflow_view``: the freeze reserves seconds for the
            # review window regardless of the orchestration policy, and discovery also
            # leaves the POC window.  Historical workflow rows without the field reserve
            # nothing extra.
            from .workflow import stage_poc_window
            reserved = (float(workflow["review_reserved_seconds"])
                        if stage != "review" else 0.)
            reserved += stage_poc_window(workflow)
            if ((dimension in ("responses", "work") and workflow["used"][stage] >= workflow["limits"][stage])
                    or (remaining_time is not None and remaining_time <= reserved)):
                raise StopAudit("stage_budget_exhausted", f"{stage} 阶段额度已到，保留后续阶段预算")
            role = CURRENT_ROLE.get().get("role") if role is None else role
            if role == "poc" and stage != "poc":
                raise StopAudit("stage_budget_exhausted", "POC 不得占用源码挖掘或最终复核额度")
            if role in {"worker", "recon"} and stage != "discovery":
                raise StopAudit("stage_budget_exhausted", "源码挖掘阶段已结束，不启动新的取证调用")
        return row, workflow

    def _consume_execution_admission_tx(self, run_id, dimension, workflow):
        """Spend an already validated slot inside the caller's transaction."""
        if dimension in ("responses", "tools"):
            self._db.execute(f"UPDATE run_execution_state SET {dimension}_used={dimension}_used+1 WHERE run_id=?", (run_id,))
            if workflow and dimension == "responses":
                workflow["used"][workflow["stage"]] += 1
                self._db.execute("UPDATE run_execution_state SET workflow=? WHERE run_id=?", (dump(workflow), run_id))

    def admit_execution(self, run_id, epoch, dimension):
        from .runtime import StopAudit
        if dimension not in (None, "responses", "tools", "work"):
            raise ValueError("unknown budget dimension")
        with self._lock:
            self._reject_expired_comparison(run_id, epoch)
            self._db.execute("BEGIN IMMEDIATE")
            clock_started = self._active_clocks.get(run_id)
            try:
                _, workflow = self._validate_execution_admission_tx(run_id, epoch, dimension)
                self._consume_execution_admission_tx(run_id, dimension, workflow)
                self._db.execute("COMMIT")
            except StopAudit as exc:
                if self._db.in_transaction:
                    self._db.execute("COMMIT" if exc.reason == "run_budget_exhausted" else "ROLLBACK")
                    if exc.reason != "run_budget_exhausted" and clock_started is not None:
                        self._active_clocks[run_id] = clock_started
                if exc.reason == "batch_deadline_exceeded":
                    self._reject_expired_comparison(run_id, epoch)
                raise
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                    if clock_started is not None:
                        self._active_clocks[run_id] = clock_started
                raise

    # Counters a later phase's smaller Execution must not overwrite: a peak is a peak,
    # and "did this run ever hit the ceiling" is answered by the run, not by its last
    # phase.  Every value is cumulative *within* one Execution, so taking the larger of
    # the two is monotone and never counts the same request twice.
    _CONTEXT_MAX_FIELDS = ("peak_request_bytes", "summary_requests", "summary_bytes",
                           "compactions", "dropped_groups", "limit_hits")

    @classmethod
    def _merge_context(cls, stored, incoming):
        merged = dict(stored or {})
        for key in cls._CONTEXT_MAX_FIELDS:
            merged[key] = max(int(merged.get(key) or 0), int(incoming.get(key) or 0))
        if incoming.get("history_bytes"):
            merged["history_bytes"] = int(incoming["history_bytes"])
        sources = dict(merged.get("sources") or {})
        for name, count in (incoming.get("sources") or {}).items():
            sources[name] = max(int(sources.get(name) or 0), int(count or 0))
        if sources:
            merged["sources"] = sources
        phases = {name: dict(entry) for name, entry in (merged.get("phases") or {}).items()}
        for name, entry in (incoming.get("phases") or {}).items():
            current = phases.setdefault(name, {})
            for key, value in entry.items():
                current[key] = max(int(current.get(key) or 0), int(value or 0))
        if phases:
            merged["phases"] = phases
        return merged

    def note_context(self, run_id, stats):
        """Persist the run's aggregate context-window usage.

        Written from ``Execution.note_context`` on every request, so it survives a
        process restart; the events remain the detailed record.  Each phase writes its
        own Execution's totals, so the run row keeps the larger of what it already had
        and what just arrived instead of letting the last phase redefine the peak.
        """
        with self._lock:
            if not self.execution_write_allowed(run_id):
                return
            row = self._db.execute("SELECT context FROM run_execution_state WHERE run_id=?",
                                   (run_id,)).fetchone()
            stored = json.loads(row["context"]) if row and row["context"] else {}
            merged = self._merge_context(stored, stats)
            self._db.execute("UPDATE run_execution_state SET context=?, updated_at=? WHERE run_id=?",
                             (dump(merged), stamp(), run_id))

    def count_model_requests(self, run_id, purpose=None):
        """Count the run's model requests, optionally by their recorded purpose.

        The run-wide summary allowance is enforced from this count rather than an
        in-process counter: a resumed run must not get a fresh quota, and a request that
        failed after admission still spent the budget it was admitted against.
        """
        query = "SELECT COUNT(*) AS total FROM events WHERE run_id=? AND kind='model_request'"
        args = [run_id]
        if purpose:
            query += " AND payload LIKE ?"
            args.append(f'%"purpose": "{purpose}"%')
        with self._lock:
            row = self._db.execute(query, args).fetchone()
        return int((row["total"] if row is not None else 0) or 0)

    def update_execution_agent(self, run_id, invocation_id, info=None):
        with self._lock:
            if info is not None and not self.execution_write_allowed(run_id):
                return
            agents = self._active_agents.setdefault(run_id, {})
            if info is None:
                agents.pop(invocation_id, None)
            else:
                agents[invocation_id] = info
                self._db.execute("UPDATE run_execution_state SET phase=?,updated_at=? WHERE run_id=? AND phase NOT IN ('ended','paused')", (info.get("phase", "exploring"), stamp(), run_id))

    def quiesce_execution(self, run_id):
        with self._lock:
            self._tick_execution_tx(run_id, stop=True)
            self._active_agents.pop(run_id, None)
            self._db.execute("UPDATE run_execution_state SET phase=CASE WHEN (SELECT status FROM runs WHERE id=?)='paused' THEN 'paused' ELSE phase END WHERE run_id=?", (run_id, run_id))

    def execution_summary(self, run_id):
        from .workflow import workflow_view
        with self._lock:
            row = self._db.execute("SELECT * FROM run_execution_state WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                return None
            value = dict(row)
            workflow = json.loads(value.get("workflow") or "{}")
            limits = json.loads(value["limits"]) if value["limits"] else None
            elapsed = value["active_elapsed_ms"]/1000
            if run_id in self._active_clocks:
                elapsed += time.monotonic()-self._active_clocks[run_id]
            usage = {"responses": value["responses_used"], "tools": value["tools_used"], "seconds": round(elapsed, 3)}
            blocked = self._db.execute("SELECT id FROM planner_tasks WHERE run_id=? AND state='blocked'", (run_id,)).fetchall()
            review = self.coverage_review(run_id) if hasattr(self, "coverage_review") else None
            directions = self.audit_direction_summary(run_id) if workflow and hasattr(self, "audit_direction_summary") else None
            verification = self._verification_progress(run_id)
            queue = self.poc_queue_view(run_id) if hasattr(self, "poc_queue_view") else None
            stats = (self.poc_statistics(run_id, queue)
                     if hasattr(self, "poc_statistics") else None)
            return {"policy_version": POLICY_VERSION, "phase": value["phase"], "claim_epoch": value["claim_epoch"], "state_revision": value["state_revision"],
                    "run_limits": limits, "run_usage": usage, "run_remaining": {k: max(0, limits[k]-usage[k]) for k in limits} if limits else None,
                    "active_executions": list(self._active_agents.get(run_id, {}).values()),
                    "stop_reason": json.loads(value["stop_reason"]) if value["stop_reason"] else None,
                    "context": json.loads(value.get("context") or "{}"),
                    "blocked_task_ids": [item["id"] for item in blocked], "poc": json.loads(value["poc_state"]),
                    "final_summary_available": bool(value["final_summary"]),
                    **({"workflow": workflow_view(workflow,
                         remaining_seconds=max(0., limits["seconds"]-elapsed) if limits else None)} if workflow else {}),
                    "verification": verification,
                    **({"poc_queue": queue} if queue is not None else {}),
                    **({"poc_statistics": stats} if stats is not None else {}),
                    **({"directions": directions} if directions is not None else {}),
                    **({"coverage_review": review} if review is not None else {})}

    def _verification_progress(self, run_id):
        """Current run representatives, never a different run's mutable ledger body."""
        from .db import WITHDRAWN_FINDING_DISPOSITIONS
        from .finding_policy import is_vulnerability_finding
        current = {}
        # Counting does not need source rendering. Historical records may contain
        # old evidence shapes and must remain deletable even if a viewer cannot
        # enrich them as a current finding.
        for row in self._rows("SELECT * FROM findings WHERE run_id=?", (run_id,)):
            finding = dict(row)
            if (finding.get("validation_state") != "candidate" or not is_vulnerability_finding(finding)
                    or finding.get("disposition", "open") in WITHDRAWN_FINDING_DISPOSITIONS):
                continue
            key = finding.get("project_finding_id") or finding["id"]
            version = (int(finding.get("project_revision") or finding.get("revision") or 1),
                       int(finding.get("revision") or 1), str(finding["id"]))
            if key not in current or version > current[key][0]:
                current[key] = version, finding
        findings = [entry[1] for entry in current.values()]
        reviews = {(item["finding_id"], int(item.get("revision") or 1), str(item.get("verification_id") or ""))
                   for item in self.list_verification_reviews(run_id)} if hasattr(self, "list_verification_reviews") else set()
        pending_reviews = self.unreviewed_verified_findings(run_id) if hasattr(self, "unreviewed_verified_findings") else []
        reviewed_count = (sum(self._current_review(item) is not None for item in findings)
                          if self.host_queue_enabled(run_id) else len(reviews))
        return {"total": len(findings), "pending": sum(item.get("verification_status") in {None, "", "unverified", "stale"} for item in findings),
                "verified": sum(item.get("verification_status") == "verified" for item in findings),
                "reviewed": reviewed_count, "pending_review": len(pending_reviews)}

    def get_final_summary(self, run_id):
        row = self._row("SELECT final_summary FROM run_execution_state WHERE run_id=?", (run_id,))
        return json.loads(row["final_summary"]) if row and row["final_summary"] else None

    def _host_summary_tx(self, run_id, status, stop_reason):
        from .db import WITHDRAWN_FINDING_DISPOSITIONS
        from .finding_policy import is_vulnerability_finding
        findings = self.list_findings(run_id)
        valid = [f for f in findings if f.get("validation_state") == "candidate" and f.get("disposition", "open") not in WITHDRAWN_FINDING_DISPOSITIONS and is_vulnerability_finding(f)]
        groups = {}
        for finding in valid:
            identity = finding.get("project_finding_id") or finding["id"]
            group = groups.setdefault(identity, {"id": identity, "project_finding_id": finding.get("project_finding_id"), "current_ledger": self.get_project_finding(identity) if finding.get("project_finding_id") else None, "finding_ids": [], "findings": []})
            group["finding_ids"].append(finding["id"])
            group["findings"].append({k: finding.get(k) for k in ("id", "revision", "project_revision", "title", "severity", "cvss", "cvss_assessment", "legacy_severity", "category", "evidence", "verification_status", "disposition", "file_path", "snapshot_id", "summary", "input_source", "propagation", "dangerous_operation", "protection", "preconditions", "poc", "remediation", "verifications")})
        tasks = self.list_tasks(run_id)
        return {"source": "host", "policy_version": POLICY_VERSION, "generated_at": stamp(), "run_id": run_id, "status": status, "complete": status in ("completed", "unreachable"), "stop_reason": stop_reason,
                "raw_finding_count": len(findings), "valid_finding_count": len(valid), "ledger_group_count": len(groups), "finding_groups": list(groups.values()),
                "tasks": [{k: t.get(k) for k in ("id", "title", "state", "error", "result", "dependencies")} for t in tasks],
                "coverage": self.planner_coverage(run_id), "execution": self.execution_summary(run_id), "verification_jobs": self.list_run_verification_jobs(run_id),
                "directions": self.audit_direction_summary(run_id) if hasattr(self, "audit_direction_summary") else {},
                "verification": self._verification_progress(run_id),
                "limitations": ["受阻、未执行、未读取方向均不代表安全。"]}

    def _terminal_execution_tx(self, run_id, status, reason):
        self._tick_execution_tx(run_id, stop=True)
        agents = list(self._active_agents.get(run_id, {}).values())
        phase = agents[-1].get("phase") if agents else "interrupted"
        self._db.execute("UPDATE run_units SET result=? WHERE run_id=? AND status='incomplete' AND (result IS NULL OR result='null')",
                         (dump({"phase": phase, "terminal_reason": reason["code"], "source": "host_checkpoint"}), run_id))
        self._db.execute("INSERT OR IGNORE INTO run_execution_state(run_id, updated_at) VALUES (?,?)", (run_id, stamp()))
        self._db.execute("UPDATE run_execution_state SET phase='ended',stop_reason=?,updated_at=? WHERE run_id=?", (dump(reason), stamp(), run_id))
        self._active_agents.pop(run_id, None)
        # No terminal run may leave a draft masquerading as active planning.
        self._db.execute("UPDATE planner_plans SET status='failed',error=COALESCE(error,?),"
                         "basis_summary=CASE WHEN basis_summary='' THEN ? ELSE basis_summary END,finished_at=?"
                         " WHERE run_id=? AND status='planning'",
                         (reason.get("message") or reason["code"], "执行已结束，本草稿未提交。", stamp(), run_id))
        if hasattr(self, "interrupt_poc_attempts"):
            row = self._db.execute("SELECT claim_epoch FROM run_execution_state WHERE run_id=?", (run_id,)).fetchone()
            self.interrupt_poc_attempts(run_id, epoch=int(row[0]) if row else None)
        summary = self._host_summary_tx(run_id, status, reason)
        self._db.execute("UPDATE run_execution_state SET final_summary=? WHERE run_id=?", (dump(summary), run_id))
        if hasattr(self, "_freeze_report_input_tx"):
            self._freeze_report_input_tx(run_id)
        # A polling reader cannot observe the terminal state before its durable
        # terminal event. Live fan-out is only an optimization over this log.
        self._db.execute("INSERT INTO events(run_id,unit_id,kind,payload,created_at) VALUES (?,NULL,?,?,?)",
                         (run_id, "run_"+status, dump({"reason": reason, "final_summary_available": True}), stamp()))

    def terminate_execution(self, run_id, status, reason, *, epoch=None):
        """One terminal transaction: status, frontier, goal, ownership, facts."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()
                if row is None:
                    self._db.execute("ROLLBACK")
                    return False
                state = self._db.execute("SELECT claim_epoch FROM run_execution_state WHERE run_id=?", (run_id,)).fetchone()
                if epoch is not None and state and state["claim_epoch"] != epoch:
                    self._db.execute("ROLLBACK")
                    return False
                if row["status"] in TERMINAL:
                    status = row["status"]
                    if self.get_final_summary(run_id):
                        self._db.execute("ROLLBACK")
                        return False
                    if status == "cancelled":
                        reason = {"code": "user_cancelled", "message": "用户取消审计"}
                stamp_now = stamp()
                message = reason.get("message") or reason["code"]
                goal_state = "met" if status == "completed" else "unreachable" if status == "unreachable" else "inconclusive"
                self._db.execute("UPDATE runs SET status=?,finished_at=COALESCE(finished_at,?),error=CASE WHEN ? IN ('failed','interrupted') THEN ? ELSE error END WHERE id=?", (status, stamp_now, status, message, run_id))
                self._db.execute("UPDATE task_goals SET status=?,terminal_reason=?,updated_at=? WHERE run_id=?", (goal_state, message, stamp_now, run_id))
                self._db.execute("UPDATE planner_sessions SET status='completed',terminal_state=?,terminal_reason=?,updated_at=? WHERE run_id=?", (goal_state, message, stamp_now, run_id))
                self._db.execute("UPDATE planner_tasks SET state=CASE WHEN state='running' THEN 'blocked' ELSE 'cancelled' END,error=?,finished_at=?,updated_at=? WHERE run_id=? AND state IN ('pending','ready','deferred','running')", (message, stamp_now, stamp_now, run_id))
                self._db.execute("UPDATE run_units SET status=CASE WHEN status='running' THEN 'incomplete' ELSE 'skipped' END,error=?,finished_at=? WHERE run_id=? AND status IN ('pending','running')", (message, stamp_now, run_id))
                self._db.execute("UPDATE task_work_items SET state=CASE WHEN state='running' THEN 'blocked' ELSE 'skipped' END,error=?,finished_at=? WHERE run_id=? AND state IN ('open','running')", (message, stamp_now, run_id))
                self._terminal_execution_tx(run_id, status, reason)
                self._db.execute("COMMIT")
                return True
            except Exception:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise
