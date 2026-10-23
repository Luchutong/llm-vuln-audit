"""Durable POC claims and guarded publication, mixed into the SQLite Store.

Claims survive pause/process restarts.  An uncertain runner submission is never
automatically submitted again: the runner's synchronous POST has no idempotency
protocol, so an interrupted attempt remains an explicit inconclusive result.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


POC_SCHEMA = """
CREATE TABLE IF NOT EXISTS poc_attempts (
    key TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    finding_id TEXT,
    ledger_id TEXT,
    revision INTEGER NOT NULL,
    finding_revision INTEGER NOT NULL DEFAULT 0,
    project_finding_revision INTEGER,
    target_key TEXT NOT NULL,
    execution_epoch INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL,
    verification_id TEXT,
    runner_job_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_poc_attempts_run ON poc_attempts(run_id, state);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _key(*parts) -> str:
    return hashlib.sha256(_dump(parts).encode()).hexdigest()


def poc_target_key(run: dict, policy, settings) -> str:
    """Opaque identity: neither runner addresses nor tokens are exposed to clients."""
    return _key(
        str(run.get("project_id") or run.get("snapshot_id") or ""),
        str(getattr(settings.poc, "runner_url", "")),
        str(policy.target), str(run.get("target_profile") or "unknown"),
    )


class PocStoreMixin:
    def set_poc_state(self, run_id: str, state: dict, epoch: int | None = None) -> bool:
        with self._lock:
            if not self._poc_allowed(run_id, epoch):
                return False
            return self._db.execute(
                "UPDATE run_execution_state SET poc_state=?,updated_at=? WHERE run_id=?",
                (_dump(state), _now(), run_id),
            ).rowcount == 1

    def _poc_allowed(self, run_id: str, epoch: int | None = None) -> bool:
        checker = getattr(self, "execution_write_allowed", None)
        if checker is not None:
            return bool(checker(run_id, epoch))
        run = self.get_run(run_id)
        return bool(run and run.get("status") == "running" and (
            epoch is None or int(run.get("execution_epoch") or 0) == epoch
        ))

    def claim_poc_notice(self, run_id: str, reason: str, epoch: int | None = None) -> bool:
        with self._lock:
            if not self._poc_allowed(run_id, epoch):
                return False
            return self._db.execute(
                "INSERT OR IGNORE INTO poc_attempts"
                " (key,run_id,revision,target_key,execution_epoch,state,created_at,updated_at)"
                " VALUES (?,?,0,?,?,'notice',?,?)",
                (_key("notice", run_id, reason), run_id, reason, int(epoch or 0), _now(), _now()),
            ).rowcount == 1

    def claim_poc_attempt(self, run_id: str, finding: dict, target_key: str, epoch: int | None = None) -> dict:
        revision = int(finding.get("project_revision") or finding.get("revision") or 1)
        own_revision = int(finding.get("revision") or 1)
        project_revision = int(finding["project_revision"]) if finding.get("project_revision") else None
        subject = str(finding.get("project_finding_id") or finding["id"])
        key = _key("attempt", run_id, subject, revision, target_key)
        with self._lock:
            if not self._poc_allowed(run_id, epoch):
                return {"key": key, "claimed": False, "state": "stopped"}
            self._db.execute("BEGIN IMMEDIATE")
            try:
                inserted = self._db.execute(
                    "INSERT OR IGNORE INTO poc_attempts"
                    " (key,run_id,finding_id,ledger_id,revision,finding_revision,project_finding_revision,target_key,execution_epoch,state,created_at,updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,'claimed',?,?)",
                    (key, run_id, finding["id"], finding.get("project_finding_id"), revision,
                     own_revision, project_revision, target_key, int(epoch or 0), _now(), _now()),
                ).rowcount == 1
                row = dict(self._db.execute("SELECT * FROM poc_attempts WHERE key=?", (key,)).fetchone())
                if not inserted and row["state"] == "claimed" and row["execution_epoch"] != int(epoch or 0):
                    self._db.execute("UPDATE poc_attempts SET execution_epoch=?,updated_at=? WHERE key=?", (int(epoch or 0), _now(), key))
                    row["execution_epoch"] = int(epoch or 0)
                    inserted = True
                if not inserted and row["state"] == "running" and row["execution_epoch"] != int(epoch or 0):
                    # A previous epoch may have submitted a synchronous runner job,
                    # but died before its ID was returned.  Never speculate/replay.
                    self._db.execute("UPDATE poc_attempts SET state='interrupted',updated_at=? WHERE key=?", (_now(), key))
                    row["state"] = "interrupted"
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return {**row, "claimed": inserted}

    def start_poc_attempt(self, attempt_key: str, epoch: int | None = None) -> bool:
        with self._lock:
            row = self._db.execute("SELECT * FROM poc_attempts WHERE key=?", (attempt_key,)).fetchone()
            if row is None or not self._poc_allowed(row["run_id"], epoch):
                return False
            return self._db.execute(
                "UPDATE poc_attempts SET state='running',updated_at=? WHERE key=? AND state='claimed' AND execution_epoch=?",
                (_now(), attempt_key, int(epoch or 0)),
            ).rowcount == 1

    def finish_poc_attempt_without_result(self, attempt_key: str, state: str, epoch: int | None = None) -> bool:
        if state not in {"unavailable", "interrupted"}:
            raise ValueError("Unsupported POC terminal state")
        with self._lock:
            row = self._db.execute("SELECT * FROM poc_attempts WHERE key=?", (attempt_key,)).fetchone()
            if row is None or not self._poc_allowed(row["run_id"], epoch):
                return False
            return self._db.execute(
                "UPDATE poc_attempts SET state=?,updated_at=? WHERE key=? AND state IN ('claimed','running') AND execution_epoch=?",
                (state, _now(), attempt_key, int(epoch or 0)),
            ).rowcount == 1

    def note_poc_job(self, attempt_key: str, job_id: str, epoch: int | None = None) -> bool:
        with self._lock:
            row = self._db.execute("SELECT * FROM poc_attempts WHERE key=?", (attempt_key,)).fetchone()
            if row is None or row["state"] != "running" or not self._poc_allowed(row["run_id"], epoch):
                return False
            return self._db.execute(
                "UPDATE poc_attempts SET runner_job_id=?,updated_at=? WHERE key=? AND execution_epoch=?",
                (str(job_id), _now(), attempt_key, int(epoch or 0)),
            ).rowcount == 1

    def record_automatic_verification_guarded(self, record: dict, *, attempt_key: str,
                                             epoch: int | None = None, jobs=()) -> bool:
        """Publish one result atomically, without overwriting a newer conclusion.

        Old-revision results remain history, but neither the run finding nor the
        canonical ledger is relabelled.  A nondiagnostic failure also cannot erase
        a still-valid verified result for exactly the same revision.
        """
        with self._lock:
            attempt = self._db.execute("SELECT * FROM poc_attempts WHERE key=?", (attempt_key,)).fetchone()
            if (attempt is None or attempt["state"] != "running"
                    or attempt["execution_epoch"] != int(epoch or 0)
                    or attempt["finding_id"] != record.get("finding_id")
                    or attempt["ledger_id"] != record.get("project_finding_id")
                    or attempt["revision"] != int(record.get("finding_revision") or 1)
                    or not self._poc_allowed(attempt["run_id"], epoch)):
                return False
            self._db.execute("BEGIN IMMEDIATE")
            try:
                finding = self._db.execute("SELECT * FROM findings WHERE id=?", (record["finding_id"],)).fetchone()
                if finding is None or finding["run_id"] != attempt["run_id"]:
                    self._db.execute("ROLLBACK")
                    return False
                self._insert_verification(record)
                revision = int(record.get("finding_revision") or 1)
                own_current = int(finding["revision"] or 1) == attempt["finding_revision"] and (
                    (finding["project_revision"] or None) == attempt["project_finding_revision"]
                )
                same_target = (record.get("agent") or {}).get("target_key") == attempt["target_key"]
                own_current = own_current and same_target
                status = str(record.get("status") or "inconclusive")
                decisive = status in {"verified", "rejected"}
                withdrawn = {"retracted", "duplicate", "superseded"}
                if own_current and finding["disposition"] not in withdrawn:
                    if decisive or finding["verification_status"] != "verified":
                        self._db.execute(
                            "UPDATE findings SET verification_status=?,verification_verdict=? WHERE id=?",
                            (status, record.get("verdict") or None, record["finding_id"]),
                        )
                ledger_id = record.get("project_finding_id")
                ledger = self._db.execute("SELECT * FROM project_findings WHERE id=?", (ledger_id,)).fetchone() if ledger_id else None
                current = own_current and (ledger is None or int(ledger["revision"] or 1) == revision)
                if ledger is not None and current and ledger["disposition"] not in withdrawn:
                    if decisive or ledger["verification_status"] != "verified":
                        self._db.execute(
                            "UPDATE project_findings SET verification_status=?,verification_verdict=?,latest_verification_id=? WHERE id=? AND revision=?",
                            (status, record.get("verdict") or None, record["id"], ledger_id, revision),
                        )
                for job in jobs:
                    if not job.get("job_id"):
                        continue
                    self._db.execute(
                        "INSERT INTO poc_verification_jobs"
                        " (id,verification_id,finding_id,project_finding_id,run_id,job_id,kind,request,result,exit_code,duration_ms,created_at)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (_key(record["id"], job["job_id"]), record["id"], record["finding_id"], ledger_id,
                         attempt["run_id"], job["job_id"], job.get("kind") or "script",
                         _dump(job.get("request") or {}), _dump(job.get("result") or {}),
                         job.get("exit_code"), job.get("duration_ms"), _now()),
                    )
                self._db.execute(
                    "UPDATE poc_attempts SET state=?,verification_id=?,updated_at=? WHERE key=?",
                    ("completed" if own_current and current else "superseded", record["id"], _now(), attempt_key),
                )
                self._db.execute("COMMIT")
                return True
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def compatible_verified_finding(self, run: dict, finding: dict) -> bool:
        """Whether a current verified conclusion can satisfy this run's POC gate.

        Both run findings and canonical ledger rows are accepted.  Older runs keep
        their old acceptance rule; new required runs reject historic status-only
        records whose version/source/target attribution cannot be established.
        """
        from .poc_readiness import normalize_poc_mode
        if str(finding.get("verification_status") or "") != "verified":
            return False
        if finding.get("validation_state", "candidate") != "candidate" or finding.get("disposition") in {"retracted", "duplicate", "superseded"}:
            return False
        _, legacy = normalize_poc_mode(run)
        if legacy:
            return True
        policy = run.get("poc_policy") or {}
        target_key = policy.get("target_key")
        if not target_key or run.get("target_profile") != "lab30":
            return False
        ledger_id = finding.get("project_finding_id") or (finding.get("id") if finding.get("project_id") else None)
        revision = int(finding.get("project_revision") or finding.get("revision") or 1)
        with self._lock:
            project = self._db.execute("SELECT content_key FROM projects WHERE id=?", (run.get("project_id"),)).fetchone()
            if project is None:
                return False
            if ledger_id:
                ledger = self._db.execute("SELECT revision,verification_status,disposition FROM project_findings WHERE id=? AND project_id=?", (ledger_id, run.get("project_id"))).fetchone()
                if ledger is None or ledger["revision"] != revision or ledger["verification_status"] != "verified" or ledger["disposition"] in {"retracted", "duplicate", "superseded"}:
                    return False
                rows = self._db.execute(
                    "SELECT v.*,r.project_id AS source_project_id FROM verifications v"
                    " JOIN findings f ON f.id=v.finding_id JOIN runs r ON r.id=f.run_id"
                    " WHERE v.project_finding_id=? AND v.finding_revision=? AND v.source='poc_agent' AND v.status='verified'",
                    (ledger_id, revision),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT v.*,r.project_id AS source_project_id FROM verifications v"
                    " JOIN findings f ON f.id=v.finding_id JOIN runs r ON r.id=f.run_id"
                    " WHERE v.finding_id=? AND v.finding_revision=? AND v.source='poc_agent' AND v.status='verified'",
                    (finding.get("id"), revision),
                ).fetchall()
            for row in rows:
                try:
                    agent, target = json.loads(row["agent"]), json.loads(row["target"])
                except (TypeError, ValueError):
                    continue
                if not isinstance(agent, dict) or not isinstance(target, dict):
                    continue
                if row["finding_id"] == finding.get("id") and agent.get("run_finding_revision") != int(finding.get("revision") or 1):
                    continue
                if (row["source_project_id"] == run.get("project_id")
                        and agent.get("source_content_key") == project["content_key"]
                        and agent.get("target_key") == target_key
                        and target.get("name") == policy.get("target", "lab30")
                        and bool(target.get("version"))):
                    return True
        return False
