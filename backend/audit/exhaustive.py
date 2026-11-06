"""Explicit whole-project exploration. Reviews nominate work, never vulnerabilities."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

POLICY = "exhaustive-v1"
MAX_LEADS = 256

def enabled(task):
    return task.get("exploration_policy") == POLICY and task.get("focus_scope") == "all"


def fingerprint(finding):
    fields = {key: finding.get(key) for key in ("id", "revision", "vulnerability_type", "primary_location", "evidence", "summary", "disposition")}
    return hashlib.sha256(json.dumps(fields, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def contains(ref, spans):
    return any(path == ref["path"] and start <= ref["start_line"] <= ref["end_line"] <= end
               for path, ranges in spans.items() for start, end in ranges)


def _normalise(value):
    """Collapse presentation-only whitespace so one observation is one lead."""
    return " ".join(str(value or "").split())


class ExhaustiveMixin:
    def exhaustive_enabled(self, run_id):
        row = self._row("SELECT task_spec FROM runs WHERE id=?", (run_id,))
        return bool(row and enabled(json.loads(row[0] or "{}")))

    def _current_exhaustive_record(self, record):
        # A reference to an old claim cannot continue to discharge an audit lead.
        triage = record.get("triage") or {}
        if triage.get("outcome") == "covered":
            for ref in triage.get("finding_refs", []):
                row = self._row("SELECT * FROM findings WHERE id=? AND run_id=?", (ref["id"], record["run_id"]))
                if row is None or row["verification_status"] == "rejected" or row["validation_state"] != "candidate" or fingerprint(dict(row)) != ref["fingerprint"]:
                    return {**record, "state": "pending", "requirement": "advisory",
                            "triage": {**triage, "outcome": "stale"}}
        return record

    def _capture_observation_leads(self, row, result, records, seen, known_files, omitted_leads=()):
        if not self.exhaustive_enabled(row["run_id"]):
            return
        from .directions import _seen_spans
        spans = _seen_spans(seen or [])
        previous = json.loads(row["result"] or "{}")
        omitted = set(previous.get("host_omitted_leads") or []) | set(omitted_leads)
        from .investigation import enabled as bounded
        frozen = json.loads(self._db.execute("SELECT task_spec FROM runs WHERE id=?", (row["run_id"],)).fetchone()[0])
        for observation in result.get("observations") or []:
            if not isinstance(observation, dict):
                continue
            # A worker that actually settled one concrete risk can say so. Everything
            # else remains a lead: a fact, a protection scoped to one input, or a risk
            # the worker itself still considers open. The flag is the worker's judgment;
            # the host never turns a lead into a vulnerability.
            if observation.get("follow_up") is False:
                continue
            if bounded(frozen) and any(observation.get(key) is not None for key in ("candidate_id", "finding_index", "finding_id")):
                continue  # Owner and actual read checked by the transaction gate.
            refs = []
            raw = observation.get("evidence") or ""
            for path, file in known_files.items():
                for match in re.finditer(re.escape(path) + r":(\d+)(?:-(\d+))?(?!\d)", str(raw)):
                    start, end = int(match[1]), int(match[2] or match[1])
                    ref = dict(path=path, start_line=start, end_line=end)
                    if 1 <= start <= end <= file.get("line_count", 0) and contains(ref, spans):
                        refs.append(ref)
            if not refs:
                continue  # Unread/fabricated citations cannot nominate source-backed work.
            refs = sorted({(r["path"], r["start_line"], r["end_line"]) for r in refs})
            key = json.dumps([ observation.get("kind"), _normalise(observation.get("title")),
                               _normalise(observation.get("summary")), refs], ensure_ascii=False)
            identity = "dir_" + hashlib.sha256((row["run_id"] + "\0observation\0" + key).encode()).hexdigest()[:32]
            if identity in records:
                continue
            if len(records) >= MAX_LEADS:
                omitted.add(identity)
                continue
            records[identity] = dict(id=identity, run_id=row["run_id"], origin_task_id=row["id"],
                origin_task_key=row["task_key"], source_kind="observation",
                text=str(observation.get("title") or "源码观察") + "：" + str(observation.get("summary") or ""),
                paths=sorted({r[0] for r in refs}), state="pending", requirement="advisory", assigned_task_key=None,
                review_evidence=[dict(path=p, start_line=a, end_line=b) for p, a, b in refs],
                unknown_paths=[], created_at=datetime.now(timezone.utc).isoformat())
        result["host_omitted_leads"] = sorted(omitted)

    def _triage_exhaustive_lead(self, run_id, record, update):
        if not self.exhaustive_enabled(run_id) or record.get("requirement") != "advisory":
            raise ValueError("triage is only available for advisory leads in exhaustive-v1")
        choice = update.get("triage_outcome")
        if choice not in {"investigate", "covered", "no_evidence", "out_of_scope", "blocked"}:
            raise ValueError("triage requires a supported triage_outcome")
        from .role_policy import enabled as worker_owned, validate_planner_actions
        task = json.loads(self._row("SELECT task_spec FROM runs WHERE id=?", (run_id,))[0] or "{}")
        validate_planner_actions(task, direction_updates=[update], directions={record["id"]: record})
        refs = update.get("evidence") or []
        if (not refs and choice in {"no_evidence", "out_of_scope"} and record.get("source_kind") == "observation"
                and record.get("review_evidence")):
            # The observation itself was captured from worker-read spans. Reusing that
            # exact citation keeps triage to one decision instead of a redundant re-read,
            # while still requiring a concrete rationale and worker-read source.
            refs = [dict(ref) for ref in record["review_evidence"]]
        if choice in {"covered", "no_evidence"} or (choice == "out_of_scope" and record.get("paths")):
            from .directions import _seen_spans
            seen = [r for row in self._rows("SELECT seen FROM planner_task_attempts WHERE run_id=?", (run_id,))
                    for r in json.loads(row[0] or "[]")]
            spans = _seen_spans(seen)
            # A lead whose named paths no worker ever read has no citation to copy. The
            # only honest settlement is an explicit scope limitation: it must not invent
            # Planner navigation as evidence, and it must not stay pending forever just
            # because the evidence is missing. `no_evidence` still requires real reads;
            # `out_of_scope` records the limitation and cannot be used as proof of absence.
            unread = (choice == "out_of_scope" and record.get("paths")
                      and not set(record["paths"]).intersection(spans))
            if unread:
                if refs:
                    raise ValueError("线索点名路径从未被 worker 读取，不能提交非读取区间作为分流证据")
            else:
                if not refs or any(not contains(ref, spans) for ref in refs):
                    raise ValueError("线索分流必须引用 worker 实际读取过的原始源码区间；Planner 导航不是证据")
                if record.get("paths") and not set(r["path"] for r in refs).intersection(record["paths"]):
                    raise ValueError("分流证据必须关联当前线索的源码路径")
        finding_refs = []
        if choice == "covered":
            if not update.get("finding_ids"):
                raise ValueError("covered requires actual current finding_ids, not a claim that a finding exists")
            for ident in update["finding_ids"]:
                row = self._row("SELECT * FROM findings WHERE id=? AND run_id=?", (ident, run_id))
                finding = dict(row) if row else {}
                location = json.loads(finding.get("primary_location") or "{}")
                if (finding.get("validation_state") != "candidate" or finding.get("finding_kind") != "vulnerability"
                    or finding.get("disposition") in {"retracted", "duplicate", "superseded"}
                    or finding.get("verification_status") == "rejected"
                    or location.get("path") not in record.get("paths", [])):
                    raise ValueError("covered 须引用本运行有效结论及相关根因主定位；共同 evidence/同类型不能代替")
                finding_refs.append(dict(id=ident, fingerprint=fingerprint(finding)))
                if worker_owned(task) and not any(
                    ref["path"] == location["path"] and ref["start_line"] <= location["line"] <= ref["end_line"]
                    for ref in refs):
                    raise ValueError("covered 的读取依据须覆盖被引用 finding 的实际根因行，不能只在同文件")
        if choice == "investigate":
            if not record.get("paths") or record.get("unknown_paths"):
                raise ValueError("investigate requires known frozen source paths; unknown paths need explicit out_of_scope/blocked")
            record.update(requirement="required", state="pending", assigned_task_key=None)
        elif choice in {"covered", "no_evidence", "out_of_scope"}:
            record["state"] = "skipped" if choice == "out_of_scope" else "resolved"
            record["resolution_reason"] = update["rationale_summary"]
            if choice == "out_of_scope":
                record["limitation"] = "独立分流排除此调查范围，不能作为漏洞不存在的证明。"
        record["triage"] = dict(policy=POLICY, outcome=choice, rationale=update["rationale_summary"],
                                evidence=refs, finding_refs=finding_refs)

    def exhaustive_omitted(self, run_id):
        if not self.exhaustive_enabled(run_id):
            return 0
        return len({ident for row in self._rows("SELECT result FROM planner_tasks WHERE run_id=?", (run_id,))
                    for ident in json.loads(row[0] or "{}").get("host_omitted_leads", [])})
