"""One durable integration/final-review queue and immutable terminal report inputs.

The Planner uses its existing bounded model loop. A batch leases exact revisions;
completed Worker tasks are evidence for a review, never an automatic sign-off.
"""
from __future__ import annotations

import hashlib
import base64
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_review_batches (
 id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
 epoch INTEGER NOT NULL, phase TEXT NOT NULL, input_hash TEXT NOT NULL,
 items TEXT NOT NULL, decisions TEXT NOT NULL DEFAULT '[]',
 status TEXT NOT NULL DEFAULT 'pending', plan_id TEXT, created_at TEXT NOT NULL, finished_at TEXT
);
CREATE INDEX IF NOT EXISTS audit_review_queue ON audit_review_batches(run_id,phase,status);
CREATE TABLE IF NOT EXISTS audit_review_items (
 run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, phase TEXT NOT NULL,
 item_id TEXT NOT NULL, revision TEXT NOT NULL, batch_id TEXT NOT NULL,
 decision TEXT NOT NULL, PRIMARY KEY(run_id,phase,item_id,revision)
);
CREATE TABLE IF NOT EXISTS frozen_run_reports (
 run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
 input_hash TEXT NOT NULL, input_json TEXT NOT NULL, created_at TEXT NOT NULL,
 facts_json TEXT, markdown TEXT, output_hash TEXT, zip_blob BLOB, json_export TEXT
);
CREATE TRIGGER IF NOT EXISTS frozen_report_input_immutable
BEFORE UPDATE OF input_hash,input_json,created_at ON frozen_run_reports
BEGIN SELECT RAISE(ABORT,'frozen report input is immutable'); END;
CREATE TRIGGER IF NOT EXISTS frozen_report_output_immutable
BEFORE UPDATE OF facts_json,markdown,output_hash,zip_blob,json_export ON frozen_run_reports
WHEN OLD.facts_json IS NOT NULL
BEGIN SELECT RAISE(ABORT,'frozen report output is immutable'); END;
"""


def dump(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint(value):
    return hashlib.sha256(dump(value).encode()).hexdigest()


def finding_fact_revision(entry, record):
    """Review outputs must never invalidate their own input revision."""
    from .final_review import latest_verification
    verification = latest_verification(record) or {}
    return fingerprint({"version": "review-facts-v2", "claim": entry["frozen_claim"],
                        "cvss": entry.get("frozen_cvss_assessment"),
                        "sources": entry["source_record_refs"],
                        "verification": verification,
                        "conflicts": [c for c in entry["conflicts"] if c.get("kind") != "review_contested"]})


def stamp():
    return datetime.now(timezone.utc).isoformat()


def review_terminal_reason(entries, pending_batches, discovery_stop=None):
    """Final-state diagnosis is independent of an earlier phase-transition message."""
    pending = sum(entry.get("final_disposition") == "pending" for entry in entries)
    contested = sum(entry.get("final_disposition") == "contested" for entry in entries)
    unreviewed = sum(len(group) for group in pending_batches)
    if unreviewed:
        return {"code": "final_review_incomplete", "message": f"审计已结束，仍有 {unreviewed} 项未完成终审；已保存事实和阶段报告。"}
    if pending:
        return {"code": "final_review_needs_evidence", "message": f"终审已结束，{pending} 条结论仍需补证；未将其计入已接受漏洞。"}
    if contested:
        return {"code": "final_review_contested", "message": f"终审已结束，{contested} 条结论存疑或被排除；详见逐项处置。"}
    stop = discovery_stop or {}
    return {"code": stop.get("code") or "audit_partial", "message": "审计与终审已结束，未完成的源码方向及运行限制保留在阶段报告中。"}


def validate_batch(batch, decisions, *, current_items=None):
    """Exact input/decision set, exact content revisions, no graph expansion."""
    decisions = [dict(decision) for decision in decisions]
    expected = {item["item_id"]: item for item in batch.get("items", [])}
    current = {item["item_id"]: item for item in (current_items if current_items is not None else expected.values())}
    aliases = {}
    for item in current.values():
        if item["kind"] == "finding":
            for alias in (item["item_id"], item.get("finding_id")):
                if alias:
                    aliases.setdefault(alias, set()).add(item["item_id"])
    supplied = [d.get("item_id") for d in decisions]
    if len(supplied) != len(set(supplied)) or set(supplied) != set(expected):
        raise ValueError("review_decisions 必须对当前批次每个 item_id 恰好处置一次；未完成也须明确 needs_evidence")
    for decision in decisions:
        item = expected[decision["item_id"]]
        if decision.get("revision") != item["revision"]:
            raise ValueError("批次结论版本已变化，请读取当前批次后重新提交")
        allowed = {"resolve", "needs_evidence", "skip"} if item["kind"] == "direction" else (
            {"accept", "needs_evidence", "contested", "duplicate", "withdraw"} if batch["phase"] == "final"
            else {"retain", "needs_evidence", "contested", "duplicate", "withdraw"})
        if decision.get("decision") not in allowed or len(str(decision.get("rationale") or "").strip()) < 8:
            raise ValueError("批次处置类型或具体理由不合法")
        if item.get("review_input_omitted") and decision["decision"] != "needs_evidence":
            raise ValueError("完整审查输入超过限额，本项只能明确 needs_evidence")
        if decision["decision"] == "duplicate":
            target = decision.get("duplicate_of")
            matches = aliases.get(target, set())
            if len(matches) != 1:
                raise ValueError("duplicate_of 必须引用本运行另一条当前规范结论的 item_id；"
                                 "未知、历史或歧义 ID 不可用。当前可用 item_id："
                                 + ",".join(key for key, value in current.items()
                                            if value["kind"] == "finding" and key != item["item_id"])[:1000])
            decision["duplicate_of"] = next(iter(matches))
            if decision["duplicate_of"] == item["item_id"]:
                raise ValueError("duplicate_of 不能指向自身，包括本项的 finding_id 别名")
        if decision["decision"] == "accept" and (item.get("conflicts") or item.get("verification_status") == "rejected"):
            raise ValueError("存在未裁定冲突或动态反证，不能直接 accept；请 contested 或 needs_evidence")
        if decision["decision"] == "accept" and not item.get("evidence_complete"):
            raise ValueError("终审批次没有完整提供所引源码，不能 accept；请 needs_evidence")
        if decision["decision"] == "accept" and item.get("requires_verification_review"):
            raise ValueError("动态已验证结论尚缺同版本正式观测复核，保留 needs_evidence")
    by_id = {decision["item_id"]: decision for decision in decisions}
    for decision in decisions:
        if decision["decision"] == "duplicate" and by_id.get(decision["duplicate_of"], {}).get("decision") in {"duplicate", "withdraw"}:
            raise ValueError("duplicate_of 必须保留一条当前主结论，不能指向本批次同时重复或撤回的项")
    return decisions


class ReviewStoreMixin:
    def host_queue_enabled(self, run_id):
        row = self._row("SELECT task_spec FROM runs WHERE id=?", (run_id,))
        return bool(row and json.loads(row[0] or "{}").get("orchestration_policy") == "host-queue-v1")

    def _init_reviews(self):
        self._db.executescript(SCHEMA)
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(frozen_run_reports)")}
        for name, kind in (("zip_blob", "BLOB"), ("json_export", "TEXT")):
            if name not in columns:
                self._db.execute(f"ALTER TABLE frozen_run_reports ADD COLUMN {name} {kind}")

    def batch_review_enabled(self, run_id):
        row = self._row("SELECT task_spec FROM runs WHERE id=?", (run_id,))
        return bool(row and json.loads(row[0] or "{}").get("review_policy") == "batch-v1")

    @staticmethod
    def _review_row(row):
        if row is None:
            return None
        return {**dict(row), "items": json.loads(row["items"]), "decisions": json.loads(row["decisions"])}

    def active_review_batch(self, run_id, phase=None):
        row = self._row("SELECT * FROM audit_review_batches WHERE run_id=? AND status='pending'"
                        + (" AND phase=?" if phase else "") + " ORDER BY created_at,id LIMIT 1",
                        (run_id, phase) if phase else (run_id,))
        return self._review_row(row)

    def list_review_batches(self, run_id):
        return [self._review_row(row) for row in self._rows(
            "SELECT * FROM audit_review_batches WHERE run_id=? ORDER BY created_at,id", (run_id,))]

    def _review_records(self, run_id, records):
        row = self._row("SELECT snapshot_id FROM runs WHERE id=?", (run_id,))
        snapshot_id = row[0] if row else None
        return [record if record.get("snapshot_id") else {**record, "snapshot_id": snapshot_id}
                for record in records]

    def host_progress_stalled(self, run_id):
        """Persist no-progress protection across pause/resume, ignoring log churn."""
        from .directions import _seen_spans
        from .final_review import canonical_groups
        with self._lock:
            self.assert_execution_write(run_id)
            seen = [span for row in self._rows("SELECT seen FROM planner_task_attempts WHERE run_id=?", (run_id,))
                    for span in json.loads(row[0] or "[]")]
            entries, _ = canonical_groups(self.list_findings(run_id))
            claims = [{key: item["frozen_claim"].get(key) for key in (
                "finding_id", "category", "primary_location", "evidence", "cvss", "input_source",
                "dangerous_operation", "propagation", "protection", "preconditions")}
                for item in entries]
            directions = [(d["id"], d["state"]) for d in self._audit_direction_records(run_id).values()
                          if d["state"] in {"resolved", "skipped"}]
            gaps = self.coverage_review(run_id) or {}
            identity = fingerprint({"seen": _seen_spans(seen), "claims": claims,
                                    "directions": sorted(directions), "skips": gaps.get("skips", [])})
            row = self._row("SELECT workflow FROM run_execution_state WHERE run_id=?", (run_id,))
            workflow = json.loads(row[0] or "{}")
            previous = workflow.get("progress_checkpoint") or {}
            unchanged = previous.get("input_hash") == identity
            failures = int(previous.get("unchanged", 0)) + 1 if unchanged else 0
            workflow["progress_checkpoint"] = {"input_hash": identity, "unchanged": failures}
            self._db.execute("UPDATE run_execution_state SET workflow=? WHERE run_id=?", (dump(workflow), run_id))
            return failures >= 2

    def _review_candidates(self, run_id, phase):
        from .final_review import canonical_groups, comparison_candidates
        from .review_input import compact_observations
        items = []
        tasks = {task["task_key"]: task for task in self.list_tasks(run_id)}
        hosted = self.host_queue_enabled(run_id)
        if (phase == "integration" or hosted) and self.discovery_first(run_id):
            for direction in self._audit_direction_records(run_id).values():
                if direction["state"] not in {"pending", "assigned"}:
                    continue
                if hosted and direction.get("requirement", "required") != "required":
                    continue
                task = tasks.get(direction.get("assigned_task_key"))
                if (not task or task["state"] not in {"completed", "blocked", "exhausted"}) and phase == "integration":
                    continue
                task = task or {}
                result = task.get("result") or {}
                basis = {"direction": {k: direction.get(k) for k in ("id", "text", "paths", "assigned_task_key")},
                         "task_key": task.get("task_key"), "task_state": task.get("state"), "attempts": task.get("attempts"),
                         "summary": result.get("summary"), "reasoning": result.get("reasoning"),
                         "worker_results": result.get("direction_results", [])}
                basis["read_ranges"] = [ref for attempt in (self.list_task_attempts(task["id"]) if task else [])
                                        for ref in (attempt.get("seen") or [])][:32]
                items.append({"kind": "direction", "item_id": direction["id"], "revision": fingerprint(basis),
                              "task_key": task.get("task_key"), "payload": basis})
        records = self._review_records(run_id, self.list_findings(run_id))
        by_finding = {record["id"]: record for record in records}
        canonical, _ = canonical_groups(records)
        peers = comparison_candidates(canonical)
        revisions = {e["canonical_id"]: finding_fact_revision(e, by_finding[e["frozen_claim"]["finding_id"]])
                     for e in canonical} if hosted else {}
        prior_reviews = {r["item_id"]: json.loads(r["decision"]) for r in self._rows(
            "SELECT item_id,revision,decision FROM audit_review_items WHERE run_id=? AND phase='final'", (run_id,))
                         if revisions.get(r["item_id"]) == r["revision"]}
        conflict_ids = {ident for row in self._rows(
            "SELECT payload FROM events WHERE run_id=? AND kind='finding_duplicate_candidate'", (run_id,))
            for ident in ([json.loads(row[0]).get("finding_id")] + json.loads(row[0]).get("candidate_ids", []))}
        for entry in canonical:
            claim = entry["frozen_claim"]
            raw = by_finding[claim["finding_id"]]
            if hosted and phase == "integration" and not entry["conflicts"] and claim["finding_id"] not in conflict_ids:
                continue
            from .final_review import current_review, latest_verification
            # Scripts are downloadable artifacts. Keep complete claim prose,
            # references and statuses; oversized fields get an exact read manifest.
            payload = {k: claim.get(k) for k in (
                "finding_id", "revision", "title", "category", "vulnerability_type", "rating_text", "cvss",
                "assessment_revision", "file_path", "primary_location", "summary", "input_source", "propagation",
                "dangerous_operation", "protection", "preconditions", "missing_context", "remediation", "evidence",
                "verification_status", "verification_id")}
            verification = latest_verification(raw) or {}
            payload["verification_observations"] = compact_observations(verification)
            availability = payload["verification_observations"]["fact_availability"]
            required_reads = []
            if phase == "final" and availability["conclusion_missing"] and availability["successful_jobs"]:
                payload["verification_job_facts"] = (verification.get("agent") or {}).get("job_results") or []
                required_reads = ["payload.verification_job_facts"]
            payload["comparison_candidates"] = peers.get(entry["canonical_id"], [])
            payload["related_review_decisions"] = {peer["item_id"]: prior_reviews[peer["item_id"]]
                for peer in payload["comparison_candidates"] if peer["item_id"] in prior_reviews}
            payload["verification_review"] = current_review(raw)
            if phase == "final":
                integration = self._row("SELECT decision,batch_id FROM audit_review_items"
                                        " WHERE run_id=? AND phase='integration' AND item_id=? AND revision=?",
                                        (run_id, entry["canonical_id"], finding_fact_revision(entry, raw) if hosted else fingerprint(entry)))
                if integration:
                    payload["integration_review"] = {**json.loads(integration["decision"]),
                                                     "batch_id": integration["batch_id"]}
            items.append({"kind": "finding", "item_id": entry["canonical_id"],
                          "revision": finding_fact_revision(entry, raw) if hosted else fingerprint(entry), "finding_id": claim["finding_id"],
                          "finding_revision": claim["revision"], "verification_id": claim.get("verification_id"),
                          "verification_status": claim.get("verification_status"), "conflicts": entry["conflicts"],
                          "requires_verification_review": claim.get("verification_status") == "verified" and not current_review(raw),
                          "required_read_fields": required_reads,
                          "payload": payload})
        return items

    def review_batches_pending(self, run_id, phase, repository=None):
        """Pure packing used by both budget estimates and actual leases."""
        reviewed = {(r["item_id"], r["revision"]) for r in self._rows(
            "SELECT item_id,revision FROM audit_review_items WHERE run_id=? AND phase=?", (run_id, phase))}
        if phase == "integration" and self.host_queue_enabled(run_id):
            for batch in self.list_review_batches(run_id):
                if batch["phase"] == phase and batch["status"] == "deferred":
                    reviewed.update((i["item_id"], i["revision"]) for i in batch["items"])
        from .review_input import source_input, bounded_item, comparison_groups
        groups, selected = [], []
        pending = [i for i in self._review_candidates(run_id, phase) if (i["item_id"], i["revision"]) not in reviewed]
        soft_limit = 32768 if self.host_queue_enabled(run_id) else 24576
        for related in comparison_groups(pending):
            prepared = [bounded_item(source_input(i, repository) if phase == "final" and i["kind"] == "finding" else i)
                        for i in related]
            if selected and (len(selected + prepared) > 8 or len(dump(selected + prepared).encode()) > soft_limit):
                groups.append(selected)
                selected = []
            for item in prepared:
                if selected and (len(selected) >= 8 or len(dump(selected + [item]).encode()) > soft_limit):
                    groups.append(selected)
                    selected = []
                selected.append(item)
        if selected:
            groups.append(selected)
        return groups

    def read_review_input(self, run_id, batch_id, item_id, field, offset=0, limit=1024, *, repository=None):
        """Read only leased facts; host receipts live in the existing batch JSON.

        Reading changes no fact revision or input_hash. Publication rechecks the stored
        receipts and the live revision, so a forged manifest or a stale page cannot pass.
        """
        from .review_input import digest, field_values, source_input, access_complete, same_input
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 1024:
            raise ValueError("分页 offset/limit 必须是有效整数，limit 最大 1024")
        with self._lock:
            batch = self.active_review_batch(run_id)
            run = self._row("SELECT status FROM runs WHERE id=?", (run_id,))
            if (not run or run[0] != "running" or not batch or batch["id"] != batch_id
                    or not self.execution_write_allowed(run_id, batch["epoch"])):
                raise ValueError("审查批次已失效或不属于当前执行")
            item = next((i for i in batch["items"] if i["item_id"] == item_id), None)
            manifest = next((p for p in (item or {}).get("paged_fields", []) if p["field"] == field), None)
            if not manifest:
                raise ValueError("只能读取当前批次清单中的 item_id 与 paged_fields.field")
            full = next((i for i in self._review_candidates(run_id, batch["phase"]) if i["item_id"] == item_id), None)
            if not same_input(item, full):
                raise ValueError("结论版本已变化，旧页不能作为审查依据")
            if batch["phase"] == "final" and full["kind"] == "finding":
                full = source_input(full, repository)
            text = dump(field_values(full)[field])
            if digest(text) != manifest["sha256"] or len(text) != manifest["characters"]:
                raise ValueError("被审原文已变化，请重新领取批次")
            if offset > len(text):
                raise ValueError("分页偏移超过字段长度")
            stop = min(len(text), offset + limit)
            ranges = item.setdefault("read_ranges", {}).setdefault(field, [])
            ranges.append([offset, stop])
            # Coalesce receipts rather than letting repeated reads inflate batch size.
            merged = []
            for start, end in sorted(ranges):
                if merged and start <= merged[-1][1]:
                    merged[-1][1] = max(end, merged[-1][1])
                else:
                    merged.append([start, end])
            item["read_ranges"][field] = merged
            complete = access_complete(item)
            item["review_input_omitted"] = not complete
            self._db.execute("UPDATE audit_review_batches SET items=? WHERE id=?", (dump(batch["items"]), batch_id))
            return {"batch_id": batch_id, "item_id": item_id, "revision": item["revision"], "field": field,
                    "sha256": manifest["sha256"], "offset": offset, "text": text[offset:stop],
                    "total_characters": len(text), "next_offset": stop if stop < len(text) else None,
                    "all_paged_fields_read": complete}

    def defer_review_batch(self, run_id, batch_id, reason):
        with self._lock:
            self.assert_execution_write(run_id)
            self._db.execute("UPDATE audit_review_batches SET status='deferred',finished_at=? WHERE id=? AND run_id=? AND status='pending'",
                             (stamp(), batch_id, run_id))
            self.append_event(run_id, None, "review_batch_deferred", {"batch_id": batch_id, "reason": reason})

    def prepare_review_batch(self, run_id, phase, epoch, repository=None):
        from .review_input import same_input
        if phase not in {"integration", "final"}:
            raise ValueError("unsupported review phase")
        if not self.batch_review_enabled(run_id):
            return None
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                if not self.execution_write_allowed(run_id, epoch):
                    raise ValueError("review execution is no longer active")
                if phase == "final":
                    self._db.execute("UPDATE audit_review_batches SET status='deferred',finished_at=?"
                                     " WHERE run_id=? AND phase='integration' AND status='pending'", (stamp(), run_id))
                candidates = self._review_candidates(run_id, phase)
                current = {item["item_id"]: item for item in candidates}
                active = self.active_review_batch(run_id, phase)
                if active and (active["epoch"] != epoch or any(not same_input(i, current.get(i["item_id"])) for i in active["items"])):
                    self._db.execute("UPDATE audit_review_batches SET status='stale',finished_at=? WHERE id=?", (stamp(), active["id"]))
                    active = None
                if active:
                    self._db.execute("COMMIT")
                    return active
                groups = self.review_batches_pending(run_id, phase, repository)
                selected = groups[0] if groups else []
                if not selected:
                    self._db.execute("COMMIT")
                    return None
                batch_id = uuid.uuid4().hex
                self._db.execute("INSERT INTO audit_review_batches(id,run_id,epoch,phase,input_hash,items,created_at) VALUES(?,?,?,?,?,?,?)",
                                 (batch_id, run_id, epoch, phase, fingerprint(selected), dump(selected), stamp()))
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise
        return self.active_review_batch(run_id, phase)

    def validate_review_decisions(self, run_id, batch, decisions, *, current_items=None, verification_reviews=None):
        """The publication gate and transaction share the same semantic checks."""
        from .review_input import access_complete, same_input
        # Never trust read receipts supplied by the model or a caller's cached batch.
        stored = self.active_review_batch(run_id, batch["phase"])
        if not stored or stored["id"] != batch["id"] or not self.execution_write_allowed(run_id, stored["epoch"]):
            raise ValueError("审查批次已经失效")
        batch = {**stored, "items": [{**i, "review_input_omitted": not access_complete(i) if i.get("paged_fields") else bool(i.get("review_input_omitted"))}
                                     for i in stored["items"]]}
        current = {item["item_id"]: item for item in (
            current_items if current_items is not None else self._review_candidates(run_id, batch["phase"]))}
        for item in batch["items"]:
            if not same_input(item, current.get(item["item_id"])):
                raise ValueError("批次输入已变化，旧版本处置不能提交")
            if item.get("required_read_fields") and item.get("review_input_omitted"):
                raise ValueError("POC 已保存成功作业但未发布结论；必须用 read_review_input 完整读取本项作业事实后再处置，不能把空观测字段认定为没有实验。")
        reviews = list(verification_reviews or [])
        if reviews and not (self.host_queue_enabled(run_id) and batch["phase"] == "final"):
            raise ValueError("本批次不能提交动态复核")
        reviewed = {}
        for review in reviews:
            item = next((i for i in batch["items"] if i.get("finding_id") == review.get("finding_id")), None)
            observations = current.get((item or {}).get("item_id"), {}).get("payload", {}).get("verification_observations") or {}
            if (not item or item.get("verification_status") != "verified" or item.get("review_input_omitted")
                    or item.get("finding_revision") != review.get("revision")
                    or item.get("verification_id") != review.get("verification_id")
                    or review.get("finding_id") in reviewed
                    or review.get("decision") not in {"confirmed", "contested"}
                    or len(str(review.get("rationale_summary") or "").strip()) < 3
                    or not observations.get("normal_observation") or not observations.get("attack_observation")):
                raise ValueError("动态复核必须对应当前 final 批次的精确版本和完整正常／攻击观测")
            reviewed[review["finding_id"]] = review["decision"]
        validated_items = []
        for item in batch["items"]:
            decision = reviewed.get(item.get("finding_id"))
            validated_items.append({**item,
                "requires_verification_review": False if decision == "confirmed" else item.get("requires_verification_review"),
                "conflicts": item.get("conflicts", []) + ([{"kind": "review_contested"}] if decision == "contested" else [])})
        decisions = validate_batch({**batch, "items": validated_items}, decisions, current_items=current.values())
        by_decision = {d["item_id"]: d for d in decisions}
        for decision in decisions:
            if decision["decision"] != "accept":
                continue
            item = current[decision["item_id"]]
            peers = {peer["item_id"] for peer in item.get("payload", {}).get("comparison_candidates", [])}
            retained = {peer for peer in peers if by_decision.get(peer, {}).get("decision") not in {"duplicate", "withdraw"}}
            distinct = set(decision.get("distinct_from") or [])
            if not retained.issubset(distinct) or not distinct.issubset(peers):
                raise ValueError("accept 前须判读 comparison_candidates：同一根因用 duplicate；不同根因在 distinct_from 列出保留的对照 item_id，并在 rationale 说明操作或前提差异。POC 状态及评分不同不代表不同根因。")
        tasks = {task["task_key"]: task for task in self.list_tasks(run_id)}
        directions = self._audit_direction_records(run_id)
        for decision in decisions:
            item = current[decision["item_id"]]
            if item["kind"] == "direction" and decision["decision"] == "resolve":
                self._validate_direction_resolution_tx(run_id, directions[item["item_id"]],
                    {"task_key": item["task_key"], "finding_ids": []}, tasks)
        return decisions

    def _commit_review_batch_tx(self, run_id, batch_id, decisions, plan_id, verification_reviews=None):
        batch = self.active_review_batch(run_id)
        if not batch or batch["id"] != batch_id or not self.execution_write_allowed(run_id, batch["epoch"]):
            raise ValueError("批次已经失效、提交过或不属于当前执行")
        current = {i["item_id"]: i for i in self._review_candidates(run_id, batch["phase"])}
        decisions = self.validate_review_decisions(run_id, batch, decisions, current_items=current.values(),
                                                 verification_reviews=verification_reviews)
        # Host provenance belongs to the persisted decision, never the model's
        # extra-forbidden publication schema.
        for decision in decisions:
            decision["input_policy"] = "paged-facts-v2"
        if verification_reviews:
            stored = self.record_verification_reviews(run_id, verification_reviews, plan_id=plan_id)
            if len(stored) != len(verification_reviews):
                raise ValueError("动态复核输入已变化，终审与复核全部回滚")
        by_id = {i["item_id"]: i for i in batch["items"]}
        updates = []
        for decision in decisions:
            item = by_id[decision["item_id"]]
            choice = decision["decision"]
            if item["kind"] == "direction" and choice in {"resolve", "skip"}:
                updates.append({"direction_id": item["item_id"], "action": choice,
                                "task_key": item["task_key"], "rationale_summary": decision["rationale"]})
            if item["kind"] == "direction" and choice == "needs_evidence" and batch["phase"] != "final":
                records = self._audit_direction_records(run_id)
                records[item["item_id"]].update(state="pending", assigned_task_key=None,
                                               review_reason=decision["rationale"])
                self._persist_audit_directions_tx(run_id, records)
            if item["kind"] == "finding" and choice in {"withdraw", "duplicate"}:
                related = current.get(decision.get("duplicate_of")) if choice == "duplicate" else None
                if choice == "duplicate" and (not related or related["kind"] != "finding" or related["item_id"] == item["item_id"]):
                    raise ValueError("重复结论引用必须属于本运行的另一条当前结论")
                affected = [item["finding_id"]]
                if self.host_queue_enabled(run_id):
                    from .final_review import group_key
                    affected = [r["id"] for r in self.list_findings(run_id) if group_key(r) == item["item_id"]]
                for finding_id in affected:
                    self._db.execute("UPDATE findings SET disposition=?,disposition_reason=?,disposition_by=?,disposition_at=? WHERE id=? AND run_id=?",
                                     ("duplicate" if choice == "duplicate" else "retracted", decision["rationale"], "planner_batch:" + batch_id,
                                      stamp(), finding_id, run_id))
                    if related:
                        self._db.execute("UPDATE findings SET derived_from_finding_id=? WHERE id=?", (related["finding_id"], finding_id))
                self.append_event(run_id, None, "review_group_disposition", {"batch_id": batch_id,
                    "item_id": item["item_id"], "source_finding_ids": affected, "decision": choice})
            if item["kind"] == "finding" and choice == "accept":
                row = self.get_finding(item["finding_id"])
                if not row or not row.get("evidence") or row.get("validation_state") != "candidate":
                    raise ValueError("终审 accept 必须有本轮通过校验的源码证据")
            self._db.execute("INSERT INTO audit_review_items VALUES(?,?,?,?,?,?)",
                             (run_id, batch["phase"], item["item_id"], item["revision"], batch_id, dump(decision)))
        if updates:
            self._apply_direction_updates_tx(run_id, updates, [], [])
        self._db.execute("UPDATE audit_review_batches SET status='completed',decisions=?,plan_id=?,finished_at=? WHERE id=?",
                         (dump(decisions), plan_id, stamp(), batch_id))
        self.append_event(run_id, None, "review_batch_completed", {
            "batch_id": batch_id, "phase": batch["phase"], "items": len(decisions), "plan_id": plan_id})

    def review_snapshot(self, run_id):
        return {"version": "review-batches-v1", "batches": self.list_review_batches(run_id)}

    def attach_final_decisions(self, run_id, records):
        from .final_review import canonical_groups
        records = self._review_records(run_id, records)
        canonical, _ = canonical_groups(records)
        current = {item["canonical_id"]: item for item in canonical}
        accepted = {}
        for row in self._rows("SELECT * FROM audit_review_items WHERE run_id=? AND phase='final'", (run_id,)):
            item = current.get(row["item_id"])
            raw = next((r for r in records if item and r["id"] == item["current_claim_ref"]["finding_id"]), None)
            revision = finding_fact_revision(item, raw) if item and self.host_queue_enabled(run_id) else fingerprint(item)
            if item and revision == row["revision"]:
                accepted[item["current_claim_ref"]["finding_id"]] = {
                    **json.loads(row["decision"]), "batch_id": row["batch_id"], "source": "planner_final_batch"}
        return [{**record, "final_review_required": True,
                 **({"final_review_decision": accepted[record["id"]]} if record["id"] in accepted else {})}
                for record in records]

    def _freeze_report_input_tx(self, run_id):
        if not self.batch_review_enabled(run_id):
            return
        if self._row("SELECT 1 FROM frozen_run_reports WHERE run_id=?", (run_id,)):
            return
        run = self.get_run(run_id)
        if not run or run["status"] not in {"completed", "unreachable", "inconclusive", "failed", "cancelled", "interrupted"}:
            return
        records = self.attach_final_decisions(run_id, self.list_findings(run_id))
        payload = {"run": run, "all_records": records, "findings": records,
                   "planner": self.get_planner_session(run_id), "goal": self.get_task_goal(run_id),
                   "tasks": self.list_tasks(run_id), "plans": self.list_plans(run_id),
                   "project_map": self.get_project_map(run_id), "snapshot": self.get_snapshot(run["snapshot_id"]),
                   "report_narrative": self.latest_plan_narrative(run_id), "review_snapshot": self.review_snapshot(run_id),
                   "verification_jobs": self.list_run_verification_jobs(run_id),
                   "generated_at": run.get("finished_at") or stamp(), "units": [], "work_items": []}
        from .final_review import canonical_groups
        from .report_bundle import attach_source_evidence
        # Save host-read bytes now, including explicit unavailability. Lazy
        # rendering after a restart must not consult changed or deleted files.
        canonical, _ = canonical_groups(records)
        source_facts = {"canonical_findings": canonical}
        repository = getattr(self, "_report_repository", None)
        if repository is None:
            class UnavailableSource:
                def read_source(self, *args):
                    raise FileNotFoundError("终态冻结时没有源码读取器，不能事后补造证据")
            repository = UnavailableSource()
        attach_source_evidence(source_facts, repository)
        payload["frozen_source_evidence"] = source_facts["source_evidence"]
        from .report import collect_evidence
        try:
            evidence = collect_evidence(payload, Path(self.path).parent / "evidence")
        except OSError:
            evidence = []
            payload["freeze_limitations"] = ["附件读取失败，报告保留发现和验证事实，未冻结附件内容。"]
        payload["frozen_evidence"] = [{"name": name, "sha256": hashlib.sha256(data).hexdigest(),
                                       "data": base64.b64encode(data).decode("ascii")} for name, data in evidence]
        self._db.execute("INSERT OR IGNORE INTO frozen_run_reports(run_id,input_hash,input_json,created_at) VALUES(?,?,?,?)",
                         (run_id, fingerprint(payload), dump(payload), stamp()))

    def frozen_report(self, run_id):
        row = self._row("SELECT * FROM frozen_run_reports WHERE run_id=?", (run_id,))
        if row is None:
            return None
        return {**dict(row), "input": json.loads(row["input_json"]),
                "facts": json.loads(row["facts_json"]) if row["facts_json"] else None}

    def store_report_rendering(self, run_id, facts, markdown, zip_blob=None, json_export=None):
        with self._lock:
            self._db.execute("UPDATE frozen_run_reports SET facts_json=?,markdown=?,output_hash=?,zip_blob=?,json_export=? WHERE run_id=? AND facts_json IS NULL",
                             (dump(facts), markdown, fingerprint({"facts": facts, "markdown": markdown}), zip_blob, json_export, run_id))
        return self.frozen_report(run_id)
