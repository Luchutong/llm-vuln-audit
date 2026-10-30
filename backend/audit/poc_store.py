"""Durable POC claims and guarded publication, mixed into the SQLite Store.

Claims survive pause/process restarts.  An uncertain runner submission is never
automatically submitted again: the runner's synchronous POST has no idempotency
protocol, so an interrupted attempt remains an explicit inconclusive result.
"""
from __future__ import annotations

import hashlib
import json
import re
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
CREATE TABLE IF NOT EXISTS poc_request_quota (
    run_id TEXT NOT NULL,
    execution_epoch INTEGER NOT NULL DEFAULT 0,
    stage TEXT NOT NULL,
    request_limit INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    refused_at TEXT,
    PRIMARY KEY (run_id, execution_epoch, stage)
);
"""

# A stage's allowance is fixed when it is opened and may not be widened later in the
# same epoch: a second attempt that asked for more requests would otherwise quietly
# turn the host's hard quota into an SDK-side soft limit.
POC_QUOTA_STAGES = ("execute", "conclude")


def quota_stage(stage):
    return bool(re.fullmatch(r"(?:execute|conclude)(?:@[0-9a-f]{64})?", stage))


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
    def poc_queue_view(self, run_id):
        """Read the queue from current finding versions and durable attempts."""
        row = self._row("SELECT poc_policy,task_spec,status FROM runs WHERE id=?", (run_id,))
        policy = json.loads(row['poc_policy'] or '{}') if row else {}
        if not row or policy.get('session_policy') != 'session-queue-v1' or policy.get('mode') == 'off':
            return None
        from .finding_policy import is_vulnerability_finding
        current = {}
        for source in self._rows("SELECT * FROM findings WHERE run_id=? ORDER BY created_at", (run_id,)):
            finding = dict(source)
            if (finding.get('validation_state') != 'candidate' or not is_vulnerability_finding(finding)
                    or finding.get('disposition') in {'duplicate', 'retracted', 'superseded'}):
                continue
            key = finding.get('project_finding_id') or finding['id']
            version = (int(finding.get('project_revision') or finding.get('revision') or 1),
                       int(finding.get('revision') or 1), finding['id'])
            if key not in current or version > current[key][0]:
                current[key] = (version, finding)
        attempts = [dict(a) for a in self._rows(
            "SELECT * FROM poc_attempts WHERE run_id=? ORDER BY updated_at DESC", (run_id,))]
        continuation = json.loads(row['task_spec'] or '{}').get('continuation') or {}
        inherited = set(continuation.get('inherited_finding_ids') or [])
        retest = set(continuation.get('retest_finding_ids') or [])
        items, counts = [], {}
        for version, finding in current.values():
            attempt = next((a for a in attempts if a['finding_id'] == finding['id']
                            and a['revision'] == version[0] and a['finding_revision'] == version[1]), None)
            state = (attempt['state'] if attempt else 'reused' if finding['id'] in inherited - retest
                     else 'pending' if row['status'] in {'pending', 'running', 'paused'} else 'deferred')
            counts[state] = counts.get(state, 0) + 1
            items.append(dict(finding_id=finding['id'], title=finding['title'], revision=version[0], state=state,
                status=finding.get('verification_status') or 'unverified',
                verification_id=attempt['verification_id'] if attempt else None,
                job_id=attempt['runner_job_id'] if attempt else None))
        pulse = self._row("SELECT created_at,payload FROM events WHERE run_id=?"
            " AND kind='poc_queue_heartbeat' ORDER BY id DESC LIMIT 1", (run_id,))
        heartbeat = {**json.loads(pulse['payload']), 'at': pulse['created_at']} if pulse else None
        return dict(policy='session-queue-v1', total=len(items), counts=counts, items=items[:100],
                    omitted=max(0, len(items) - 100), heartbeat=heartbeat)

    def poc_statistics(self, run_id: str, view: dict | None = None) -> dict | None:
        """One server-side statistics object shared by JSON, Markdown and the page.

        The five categories never overwrite each other: host liveness says nothing
        about model progress, model progress says nothing about experiments, and an
        experiment says nothing about a published conclusion.  Carried-over results
        from a continuation are reported separately from what this round produced.
        """
        run = self._row("SELECT id,poc_policy,task_spec,status FROM runs WHERE id=?", (run_id,))
        if run is None:
            return None
        policy = json.loads(run["poc_policy"] or "{}") if run["poc_policy"] else {}
        task = json.loads(run["task_spec"] or "{}") if run["task_spec"] else {}
        if policy.get("mode") == "off" or not policy:
            return None
        continuation = task.get("continuation") or {}
        if not isinstance(continuation, dict):
            continuation = {}

        def payload(value):
            try:
                parsed = json.loads(value or "{}")
            except (TypeError, ValueError):
                return {}
            return parsed if isinstance(parsed, dict) else {}

        events = [dict(row, payload=payload(row["payload"])) for row in self._rows(
            "SELECT kind,payload,created_at FROM events WHERE run_id=? AND kind LIKE 'poc%'"
            " ORDER BY id", (run_id,))]
        counts: dict[str, int] = {}
        for event in events:
            counts[event["kind"]] = counts.get(event["kind"], 0) + 1

        def latest(kind):
            return next((event for event in reversed(events) if event["kind"] == kind), None)

        def total(kind, field):
            return sum(int(event["payload"].get(field) or 0) for event in events
                       if event["kind"] == kind and type(event["payload"].get(field)) is int)

        def age(iso):
            if not iso:
                return None
            try:
                when = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
            except ValueError:
                return None
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return max(0, round((datetime.now(timezone.utc) - when).total_seconds(), 1))

        heartbeat = latest("poc_queue_heartbeat")
        progress = latest("poc_queue_progress")
        streams = [event for event in events if event["kind"] == "poc_gateway_stream"]
        ended = [event for event in streams if event["payload"].get("state") == "end"]
        aborted = [event for event in ended if event["payload"].get("code")]
        stream_types: dict[str, int] = {}
        for event in ended:
            types = event["payload"].get("event_types")
            if isinstance(types, dict):
                for name, count in types.items():
                    if isinstance(name, str) and type(count) is int:
                        stream_types[name] = stream_types.get(name, 0) + count

        items = []
        view = view if view is not None else self.poc_queue_view(run_id)
        if view is not None:
            items = list(view.get("items") or [])
        inherited = set(continuation.get("inherited_finding_ids") or [])
        retest = set(continuation.get("retest_finding_ids") or [])
        carried = [item for item in items if item["finding_id"] in inherited - retest]
        retested = [item for item in items if item["finding_id"] in retest]
        current = [item for item in items if item["finding_id"] not in inherited]

        def status_counts(selection):
            values: dict[str, int] = {}
            for item in selection:
                state = str(item.get("status") or "unverified")
                values[state] = values.get(state, 0) + 1
            return values

        unsettled = [item for item in items if item.get("state") in
                     {"pending", "claimed", "running", "interrupted", "deferred", "reused"}]
        stop_reason = {}
        state_row = self._row("SELECT stop_reason FROM run_execution_state WHERE run_id=?", (run_id,))
        if state_row and state_row["stop_reason"]:
            try:
                stop_reason = json.loads(state_row["stop_reason"])
            except (TypeError, ValueError):
                stop_reason = {}
        recorded = [event for event in events if event["kind"] == "poc_verification_recorded"]
        verdicts: dict[str, int] = {}
        for event in recorded:
            status = str(event["payload"].get("status") or "unknown")
            verdicts[status] = verdicts.get(status, 0) + 1

        return {
            "version": "poc-statistics-v1",
            "run_status": str(run["status"]),
            "host": {
                "last_heartbeat_at": heartbeat["created_at"] if heartbeat else None,
                "heartbeat_age_seconds": age(heartbeat["created_at"]) if heartbeat else None,
                "current_item_seconds": (heartbeat["payload"].get("elapsed_seconds")
                                         if heartbeat else None),
                "soft_limit_exceeded": bool(heartbeat["payload"].get("soft_limit_exceeded"))
                if heartbeat else None,
                "note": "心跳只说明宿主仍在运行，不代表模型有新进展。",
            },
            "model": {
                "streams": len(ended),
                "aborted": len(aborted),
                "last_abort_code": aborted[-1]["payload"].get("code") if aborted else None,
                "event_types": stream_types,
                "content_events": sum(int(event["payload"].get("content_events") or 0) for event in ended),
                "received_bytes": sum(int(event["payload"].get("received_bytes") or 0) for event in ended),
                "last_elapsed_seconds": ended[-1]["payload"].get("elapsed_seconds") if ended else None,
                "first_event_seconds": ended[-1]["payload"].get("first_event_seconds") if ended else None,
                "usage": next((event["payload"].get("usage") or {} for event in reversed(ended)
                               if event["payload"].get("usage")), {}),
                "waiting_seconds": (progress["payload"].get("model_wait_seconds")
                                    if progress else None),
                "note": "HTTP 200 只代表响应头已到；keepalive/ping 不计入业务进展。",
            },
            "generation": {
                "text_chars": max((int(event["payload"].get("text_chars") or 0) for event in events
                                   if event["kind"] == "poc_queue_progress"), default=0),
                "thinking_chars": max((int(event["payload"].get("thinking_chars") or 0) for event in events
                                       if event["kind"] == "poc_queue_progress"), default=0),
                "tool_arg_chars": max((int(event["payload"].get("tool_arg_chars") or 0) for event in events
                                       if event["kind"] == "poc_queue_progress"), default=0),
                "note": "只保存字符与事件计数，不保存生成正文或思考内容。",
            },
            "experiments": {
                "jobs": counts.get("poc_job_finished", 0),
                "duration_ms": sum(int(event["payload"].get("duration_ms") or 0) for event in events
                                   if event["kind"] == "poc_job_finished"),
                "observations": (progress["payload"].get("observations") if progress else None),
                "last_at": latest("poc_job_finished")["created_at"] if latest("poc_job_finished") else None,
                "since_last_seconds": age(latest("poc_job_finished")["created_at"])
                if latest("poc_job_finished") else None,
                "checkpoints": counts.get("poc_queue_checkpoint", 0),
                "duplicates": sum(1 for event in events if event["kind"] == "poc_queue_experiment_refused"
                                  and str(event["payload"].get("error") or "") == "duplicate_experiment"),
                "supplements": counts.get("poc_queue_continued", 0),
            },
            "conclusion": {
                # Both events describe the same publication; count items, not log lines.
                "published": max(counts.get("poc_queue_item_published", 0), len(recorded)),
                "verdicts": verdicts,
                "unpublished_reason": (progress["payload"].get("unpublished_reason")
                                       if progress and not progress["payload"].get("published") else None),
            },
            "recovery": {
                "started": counts.get("poc_queue_recovery_started", 0),
                "published": counts.get("poc_queue_recovery_published", 0),
                "failed": counts.get("poc_queue_recovery_failed", 0),
                "skipped": counts.get("poc_queue_recovery_skipped", 0),
                "requests": total("poc_queue_recovery_started", "requests"),
            },
            "continuation": {
                "inherited": len(carried),
                "retested": len(retested),
                "inherited_status": status_counts(carried),
                "current_status": status_counts(current + retested),
                "parent_run_id": continuation.get("parent_run_id"),
                "root_run_id": continuation.get("root_run_id"),
                "note": "沿用结果来自更早的运行，不构成本轮成果。",
            },
            "unfinished": [{
                "finding_id": item.get("finding_id"), "title": item.get("title"),
                "state": item.get("state"), "status": item.get("status"),
                "reason": stop_reason.get("code") if stop_reason else None,
            } for item in unsettled[:24]],
            "unfinished_total": len(unsettled),
        }

    def interrupt_poc_attempts(self, run_id: str, epoch: int | None = None) -> int:
        """Administrative terminal cleanup, safe inside the caller's transaction.

        This only closes claim ownership. Known job facts and IDs remain, and no
        verdict is inferred or experiment resubmitted after an interruption.
        """
        with self._lock:
            clause = " AND execution_epoch=?" if epoch is not None else ""
            return self._db.execute(
                "UPDATE poc_attempts SET state='interrupted',updated_at=? WHERE run_id=?"
                " AND state IN ('claimed','running')" + clause,
                (_now(), run_id, int(epoch)) if epoch is not None else (_now(), run_id),
            ).rowcount

    # --- hard request quota -------------------------------------------------------

    def finalize_poc_verification_usage(self, run_id, verification_id, usage, epoch):
        """Complete metadata after a tool publication; never alter the verdict.

        The publication commits before the SDK returns its ResultMessage. A crash
        in between leaves explicitly provisional usage, not a missing conclusion.
        """
        with self._lock:
            if not self._poc_allowed(run_id, epoch):
                return False
            changed = self._db.execute(
                "UPDATE verifications SET agent=json_set(agent,'$.usage',json(?)) WHERE id=?"
                " AND EXISTS (SELECT 1 FROM poc_attempts a WHERE a.run_id=?"
                " AND a.verification_id=verifications.id AND a.execution_epoch=?)"
                " AND EXISTS (SELECT 1 FROM run_execution_state s WHERE s.run_id=? AND s.claim_epoch=?)",
                (json.dumps(usage, ensure_ascii=False), verification_id, run_id, int(epoch or 0), run_id, int(epoch or 0)),
            ).rowcount
            return bool(changed)

    def open_poc_request_stage(
        self, run_id: str, stage: str, limit: int, epoch: int | None = None,
    ) -> dict:
        """Fix one stage's real-request allowance for this run and epoch.

        The first opener wins: a later attempt in the same epoch is told the existing
        limit instead of replacing it, so a crash/restart cannot raise the ceiling it
        was given.  Stages are separate rows, which is how the conclusion's reserved
        requests stay untouchable by the experiment stage.
        """
        if not quota_stage(stage):
            raise ValueError("Unsupported POC request stage")
        if type(limit) is not int or limit < 1:
            raise ValueError("A POC request stage needs a positive integer limit")
        epoch_value = int(epoch or 0)
        with self._lock:
            if not self._poc_allowed(run_id, epoch):
                return {"ok": False, "reason": "stale_epoch", "stage": stage, "limit": 0, "used": 0}
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT request_limit,used,refused_at FROM poc_request_quota"
                    " WHERE run_id=? AND execution_epoch=? AND stage=?",
                    (run_id, epoch_value, stage),
                ).fetchone()
                if row is None:
                    self._db.execute(
                        "INSERT INTO poc_request_quota"
                        " (run_id,execution_epoch,stage,request_limit,used) VALUES (?,?,?,?,0)",
                        (run_id, epoch_value, stage, limit),
                    )
                    existing = limit
                    used = 0
                else:
                    existing, used = int(row["request_limit"]), int(row["used"])
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return {"ok": True, "stage": stage, "limit": existing, "used": used,
                "requested": limit, "narrowed": existing < limit}

    def reserve_poc_request(self, run_id: str, stage: str, epoch: int | None = None) -> dict:
        """Atomically charge a real request against every durable allowance.

        A refusal is final for the stage: the SDK must stop rather than retry, because
        a hard quota that answers "try again" is not a quota.  The reservation counts
        SDK retries, compaction and format corrections exactly like a first attempt.
        The quota, run/workflow response counters and request event commit together;
        a missing SDK result or an upstream error cannot erase an admitted request.
        """
        from .runtime import StopAudit
        if not quota_stage(stage):
            raise ValueError("Unsupported POC request stage")
        epoch_value = int(epoch or 0)
        limit = used = 0

        def refused(reason):
            return {"granted": False, "reason": reason, "stage": stage,
                    "limit": limit, "used": used, "remaining": max(0, limit - used)}

        with self._lock:
            try:
                self._reject_expired_comparison(run_id, epoch)
            except StopAudit as exc:
                return refused(exc.reason)
            self._db.execute("BEGIN IMMEDIATE")
            clock_started = self._active_clocks.get(run_id)
            try:
                owner = self._db.execute(
                    "SELECT claim_epoch FROM run_execution_state WHERE run_id=?", (run_id,),
                ).fetchone()
                if owner is not None and epoch is not None and owner["claim_epoch"] != epoch_value:
                    self._db.execute("ROLLBACK")
                    return refused("stale_epoch")
                row = self._db.execute(
                    "SELECT request_limit,used,refused_at FROM poc_request_quota"
                    " WHERE run_id=? AND execution_epoch=? AND stage=?",
                    (run_id, epoch_value, stage),
                ).fetchone()
                if row is not None:
                    limit, used = int(row["request_limit"]), int(row["used"])
                state, workflow = self._validate_execution_admission_tx(
                    run_id, epoch, "responses", role="poc", require_running=True,
                )
                if row is None:
                    self._db.execute("COMMIT")
                    return refused("stage_not_open")
                if row["refused_at"]:
                    self._db.execute("COMMIT")
                    return refused("quota_refused")
                if used >= limit:
                    self._db.execute(
                        "UPDATE poc_request_quota SET refused_at=? WHERE run_id=? AND execution_epoch=? AND stage=?",
                        (_now(), run_id, epoch_value, stage),
                    )
                    self._db.execute("COMMIT")
                    return refused("quota_exhausted")
                if stage.split("@", 1)[0] == "execute":
                    conclusion = self._db.execute(
                        "SELECT request_limit,used FROM poc_request_quota"
                        " WHERE run_id=? AND execution_epoch=? AND stage=?",
                        (run_id, epoch_value, stage.replace("execute", "conclude", 1)),
                    ).fetchone()
                    reserved = max(0, int(conclusion["request_limit"]) - int(conclusion["used"])) if conclusion else 0
                    # Opening a separate conclusion quota alone cannot protect the
                    # shared run/workflow slots. Leave its unused responses intact
                    # when admitting SDK experiment requests. Native admission keeps
                    # its existing semantics and does not acquire this reservation.
                    limits = json.loads(state["limits"]) if state["limits"] else None
                    available = []
                    if limits:
                        available.append(int(limits["responses"]) - int(state["responses_used"]))
                    if workflow:
                        available.append(int(workflow["limits"]["poc"]) - int(workflow["used"]["poc"]))
                    if reserved and any(remaining - 1 < reserved for remaining in available):
                        self._db.execute(
                            "UPDATE poc_request_quota SET refused_at=? WHERE run_id=? AND execution_epoch=? AND stage=?",
                            (_now(), run_id, epoch_value, stage),
                        )
                        self._db.execute("COMMIT")
                        return {**refused("quota_exhausted"), "conclusion_reserved": True,
                                "conclude_remaining": reserved,
                                "message": "保留结论阶段尚未使用的共享响应额度，实验阶段停止"}
                self._consume_execution_admission_tx(run_id, "responses", workflow)
                self._db.execute(
                    "UPDATE poc_request_quota SET used=used+1 WHERE run_id=? AND execution_epoch=? AND stage=?",
                    (run_id, epoch_value, stage),
                )
                run_used = int(state["responses_used"]) + 1
                workflow_used = int(workflow["used"]["poc"]) if workflow else None
                self._db.execute(
                    "INSERT INTO events(run_id,unit_id,kind,payload,created_at) VALUES (?,NULL,?,?,?)",
                    (run_id, "poc_gateway_request", json.dumps({
                        "runtime": "claude_sdk", "role": "poc", "stage": stage,
                        "phase": "poc_" + stage, "execution_epoch": int(state["claim_epoch"]),
                        "request_index": run_used, "stage_request_index": used + 1,
                        "run_responses_used": run_used, "workflow_responses_used": workflow_used,
                    }, ensure_ascii=False), _now()),
                )
                self._db.execute("COMMIT")
            except StopAudit as exc:
                if self._db.in_transaction:
                    self._db.execute("COMMIT" if exc.reason == "run_budget_exhausted" else "ROLLBACK")
                    if exc.reason != "run_budget_exhausted" and clock_started is not None:
                        self._active_clocks[run_id] = clock_started
                if exc.reason == "batch_deadline_exceeded":
                    try:
                        self._reject_expired_comparison(run_id, epoch)
                    except StopAudit:
                        pass
                return refused(exc.reason)
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                    if clock_started is not None:
                        self._active_clocks[run_id] = clock_started
                raise
        return {"granted": True, "stage": stage, "limit": limit, "used": used + 1,
                "remaining": max(0, limit - used - 1), "request_index": run_used,
                "run_responses_used": run_used, "workflow_responses_used": workflow_used}

    def poc_request_quota(self, run_id: str, epoch: int | None = None) -> dict:
        """Public, credential-free view of this epoch's request quota."""
        rows = self._rows(
            "SELECT stage,request_limit,used,refused_at FROM poc_request_quota"
            " WHERE run_id=? AND execution_epoch=? ORDER BY stage",
            (run_id, int(epoch or 0)),
        )
        return {
            row["stage"]: {
                "limit": int(row["request_limit"]),
                "used": int(row["used"]),
                "remaining": max(0, int(row["request_limit"]) - int(row["used"])),
                "refused": bool(row["refused_at"]),
                "refused_at": row["refused_at"],
            }
            for row in rows
        }

    def _upsert_poc_job_fact(self, attempt: dict, job: dict, verification_id: str = "") -> bool:
        job_id = str(job.get("job_id") or "")
        if not job_id:
            return False
        result = job.get("result") or {}
        if not isinstance(result, dict):
            return False
        ident = _key("job", attempt["run_id"], job_id)
        existing = self._db.execute("SELECT result,verification_id FROM poc_verification_jobs WHERE id=?", (ident,)).fetchone()
        if existing:
            previous = json.loads(existing["result"] or "{}")
            previous_status = previous.get("execution_status") or previous.get("status")
            incoming_status = result.get("execution_status") or result.get("status")
            if (previous_status in {"finished", "timeout", "precondition_failed", "rejected"}
                    and incoming_status in {"submitting", "running", "queued", "unknown"}):
                return False
            verification_id = verification_id or existing["verification_id"]
        self._db.execute(
            "INSERT INTO poc_verification_jobs"
            " (id,verification_id,finding_id,project_finding_id,run_id,job_id,kind,request,result,exit_code,duration_ms,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET"
            " verification_id=excluded.verification_id,request=excluded.request,result=excluded.result,"
            " exit_code=excluded.exit_code,duration_ms=excluded.duration_ms",
            (ident, verification_id, attempt["finding_id"], attempt["ledger_id"], attempt["run_id"], job_id,
             job.get("kind") or "script", _dump(job.get("request") or {}), _dump(result),
             job.get("exit_code"), job.get("duration_ms"), _now()),
        )
        return True

    def persist_poc_job_fact(self, attempt_key: str, job: dict, epoch: int | None = None) -> bool:
        """Save execution facts immediately, independently of conclusion publication.

        A late completed fact from the interrupted owner may be archived, but it
        can never reopen its claim, update finding status or overwrite a new epoch.
        """
        with self._lock:
            row = self._db.execute("SELECT * FROM poc_attempts WHERE key=?", (attempt_key,)).fetchone()
            if row is None or row["state"] not in {"running", "interrupted"}:
                return False
            if epoch is not None and row["execution_epoch"] != int(epoch):
                return False
            current = self._db.execute("SELECT claim_epoch FROM run_execution_state WHERE run_id=?", (row["run_id"],)).fetchone()
            if current is not None and current["claim_epoch"] != row["execution_epoch"]:
                return False
            return self._upsert_poc_job_fact(dict(row), job)

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
                    self._upsert_poc_job_fact(dict(attempt), job, record["id"])
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
