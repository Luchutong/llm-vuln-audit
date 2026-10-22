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
MIN_RUN_LIMITS = {"responses": 1, "tools": 0, "seconds": 30}
MAX_RUN_LIMITS = {"responses": 4096, "tools": 32768, "seconds": 14400}
TERMINAL = frozenset({"completed", "inconclusive", "failed", "cancelled", "interrupted", "unreachable"})
CURRENT_EXECUTION = contextvars.ContextVar("audit_run_execution", default=None)
CURRENT_ROLE = contextvars.ContextVar("audit_execution_role", default={})

EXECUTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS run_execution_state (
 run_id TEXT PRIMARY KEY, limits TEXT, responses_used INTEGER NOT NULL DEFAULT 0,
 tools_used INTEGER NOT NULL DEFAULT 0, active_elapsed_ms INTEGER NOT NULL DEFAULT 0,
 claim_epoch INTEGER NOT NULL DEFAULT 0, state_revision INTEGER NOT NULL DEFAULT 0,
 phase TEXT NOT NULL DEFAULT 'queued', stop_reason TEXT, poc_state TEXT NOT NULL DEFAULT '{}',
 final_summary TEXT, updated_at TEXT NOT NULL
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
        self._db.execute("INSERT INTO run_execution_state(run_id, limits, poc_state, updated_at) VALUES (?,?,?,?)",
                         (run["id"], dump(run["run_limits"]) if run.get("run_limits") is not None else None, dump(run.get("poc_state") or {}), stamp()))

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
        if current is not None and (run_id != current.run_id or not self.execution_write_allowed(run_id, current.epoch)):
            raise StopAudit("interrupted", "旧执行代次或已结束运行拒绝迟到业务写入")

    def admit_execution(self, run_id, epoch, dimension):
        from .runtime import StopAudit
        if dimension not in (None, "responses", "tools", "work"):
            raise ValueError("unknown budget dimension")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                if not self.execution_write_allowed(run_id, epoch):
                    raise StopAudit("interrupted", "运行已停止或执行资格已交接")
                self._tick_execution_tx(run_id)
                row = self._db.execute("SELECT * FROM run_execution_state WHERE run_id=?", (run_id,)).fetchone()
                previous_stop = json.loads(row["stop_reason"]) if row["stop_reason"] else {}
                if previous_stop.get("code") == "run_budget_exhausted":
                    raise StopAudit("run_budget_exhausted", previous_stop["message"])
                limits = json.loads(row["limits"]) if row["limits"] else None
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
                    self._db.execute("COMMIT")
                    raise StopAudit("run_budget_exhausted", reason["message"])
                if dimension in ("responses", "tools"):
                    self._db.execute(f"UPDATE run_execution_state SET {dimension}_used={dimension}_used+1 WHERE run_id=?", (run_id,))
                self._db.execute("COMMIT")
            except Exception:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

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
        with self._lock:
            row = self._db.execute("SELECT * FROM run_execution_state WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                return None
            value = dict(row)
            limits = json.loads(value["limits"]) if value["limits"] else None
            elapsed = value["active_elapsed_ms"]/1000
            if run_id in self._active_clocks:
                elapsed += time.monotonic()-self._active_clocks[run_id]
            usage = {"responses": value["responses_used"], "tools": value["tools_used"], "seconds": round(elapsed, 3)}
            blocked = self._db.execute("SELECT id FROM planner_tasks WHERE run_id=? AND state='blocked'", (run_id,)).fetchall()
            return {"policy_version": POLICY_VERSION, "phase": value["phase"], "claim_epoch": value["claim_epoch"], "state_revision": value["state_revision"],
                    "run_limits": limits, "run_usage": usage, "run_remaining": {k: max(0, limits[k]-usage[k]) for k in limits} if limits else None,
                    "active_executions": list(self._active_agents.get(run_id, {}).values()),
                    "stop_reason": json.loads(value["stop_reason"]) if value["stop_reason"] else None,
                    "blocked_task_ids": [item["id"] for item in blocked], "poc": json.loads(value["poc_state"]),
                    "final_summary_available": bool(value["final_summary"])}

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
            group["findings"].append({k: finding.get(k) for k in ("id", "revision", "project_revision", "title", "severity", "category", "evidence", "verification_status", "disposition", "file_path", "snapshot_id", "summary", "input_source", "propagation", "dangerous_operation", "protection", "preconditions", "poc", "remediation", "verifications")})
        tasks = self.list_tasks(run_id)
        return {"source": "host", "policy_version": POLICY_VERSION, "generated_at": stamp(), "run_id": run_id, "status": status, "complete": status in ("completed", "unreachable"), "stop_reason": stop_reason,
                "raw_finding_count": len(findings), "valid_finding_count": len(valid), "ledger_group_count": len(groups), "finding_groups": list(groups.values()),
                "tasks": [{k: t.get(k) for k in ("id", "title", "state", "error", "result", "dependencies")} for t in tasks],
                "coverage": self.planner_coverage(run_id), "execution": self.execution_summary(run_id), "verification_jobs": self.list_run_verification_jobs(run_id),
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
        summary = self._host_summary_tx(run_id, status, reason)
        self._db.execute("UPDATE run_execution_state SET final_summary=? WHERE run_id=?", (dump(summary), run_id))
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
