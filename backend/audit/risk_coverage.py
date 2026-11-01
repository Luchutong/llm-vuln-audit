"""Bounded source-signal obligations, separate from file reads and safe claims.

Only indexed operations produce obligations. Dynamic edges remain navigation gaps.
The frozen set cannot grow every Planner round. Classification is independently
reviewed; an unrelated or undecidable signal is never silently marked safe.
"""
from __future__ import annotations

import hashlib
import json
import re

MAX_OBLIGATIONS = 256
SINKS = {
    "sqli": {"query", "exec", "mysqli_query", "mysql_query", "rawquery"},
    "command_injection": {"system", "exec", "shell_exec", "passthru", "popen", "proc_open"},
    "file_write": {"move_uploaded_file", "file_put_contents", "fwrite", "copy", "rename", "unlink"},
    "file_read": {"file_get_contents", "readfile", "fopen"},
    "deserialization": {"unserialize"},
    "request": {"curl_exec", "fsockopen"},
}


def freeze(project_map, task, snapshot_id):
    files = {r["path"]: r for r in project_map.get("files") or [] if not r.get("dependency_tree")}
    obligations = {}
    for call in project_map.get("calls") or []:
        path, line = call.get("path"), call.get("line")
        if path not in files or type(line) is not int or not 1 <= line <= files[path].get("line_count", 0):
            continue
        name = re.split(r"::|->|\\", str(call.get("name") or ""))[-1].lower()
        for risk, names in SINKS.items():
            if name not in names:
                continue
            # exec() can be shell or PDO: don't pretend the index determines semantics.
            key = json.dumps([snapshot_id, path, line, risk, name], ensure_ascii=False)
            ident = "risk-" + hashlib.sha256(key.encode()).hexdigest()[:20]
            required = task.get("focus_scope") == "all" or task.get("scenario") == risk
            obligations[ident] = {"id": ident, "path": path, "line": line, "operation": call.get("name"),
                                  "risk": risk, "objective_ref": "objective-main", "required": required,
                                  "relation": "candidate" if required else "unresolved",
                                  "source": {"snapshot_id": snapshot_id, "path": path, "start_line": line, "end_line": line},
                                  "auxiliary_paths": sorted({edge.get("to_path") for edge in project_map.get("includes") or []
                                                             if edge.get("from_path") == path and edge.get("to_path")})[:12],
                                  "state": "pending"}
    rows = sorted(obligations.values(), key=lambda o: (not o["required"], o["path"], o["line"], o["risk"]))
    return {"version": "risk-obligations/v1", "items": rows[:MAX_OBLIGATIONS], "omitted": len(rows[MAX_OBLIGATIONS:]),
            "omitted_required": sum(o["required"] for o in rows[MAX_OBLIGATIONS:]),
            "indexed_operation_families": sorted(SINKS),
            "limitations": ["仅索引 PHP 中显式调用的操作信号；输出语句、动态框架路由、跨存储读回和其他语言仍需人工规划与实际取证。complete 仅表示本冻结义务集合已结算。"],
            "notice": "调用索引只产生待查信号；不是可利用性或完整数据流证明。未解析动态关系保留为缺口。"}


class RiskCoverageMixin:
    def risk_coverage(self, run_id):
        row = self._row("SELECT task_spec FROM runs WHERE id=?", (run_id,))
        task = json.loads(row[0] or "{}") if row else {}
        frozen = task.get("risk_obligation_set")
        if not frozen:
            return None
        decisions = {r["item_id"]: json.loads(r["decision"]) for r in self._rows(
            "SELECT item_id,decision FROM audit_review_items WHERE run_id=? AND phase='final'", (run_id,))}
        items = []
        for item in frozen["items"]:
            decision = decisions.get(item["id"], {})
            relation = (decision.get("focus") or {}).get("relation", item["relation"])
            state = decision.get("risk_outcome", "pending")
            required = item["required"] or relation in {"relevant", "supporting"}
            items.append({**item, "required": required, "relation": relation, "state": state,
                          "review": decision or None})
        unsettled = [o for o in items if o["required"] and o["state"] not in {"supported", "no_evidence", "not_applicable"}]
        return {**frozen, "items": items, "total": len(items), "required": sum(o["required"] for o in items),
                "pending_required": len(unsettled) + frozen["omitted_required"],
                "complete": not unsettled and not frozen["omitted_required"],
                "by_state": {state: sum(o["state"] == state for o in items) for state in
                             ("supported", "no_evidence", "not_applicable", "blocked", "pending")}}

    def list_risk_obligations(self, run_id, *, offset=0, limit=20):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("offset >= 0, limit 1..100 must be strict integers")
        summary = self.risk_coverage(run_id) or {"items": [], "total": 0, "complete": None}
        return {**summary, "items": summary["items"][offset:offset+limit], "offset": offset, "limit": limit,
                "next_offset": offset + limit if offset + limit < summary["total"] else None}

    def risk_review_candidates(self, run_id):
        from .review_store import fingerprint
        summary = self.risk_coverage(run_id)
        if not summary:
            return []
        tasks = self.list_tasks(run_id)
        known_files = {f["path"]: f for f in (self.get_project_map(run_id) or {}).get("files", [])}
        rows = []
        for obligation in summary["items"]:
            # Unrelated/unknown navigation leads must not become mandatory review
            # batches merely by existing in the index. The frozen all/scenario
            # policy (or an already reviewed relevant dependency) owns this gate.
            if not obligation['required']:
                continue
            task_refs = []
            for task in tasks:
                spec = task.get("context_spec") or {}
                seen = [ref for attempt in self.list_task_attempts(task["id"]) for ref in attempt.get("seen") or []]
                read = any(ref.get("path") == obligation["path"] and ref.get("start_line", 0) <= obligation["line"] <= ref.get("end_line", 0) for ref in seen)
                assigned = obligation["id"] in spec.get("obligation_ids", [])
                if not assigned and not read:
                    continue
                task_refs.append({"task_key": task["task_key"], "state": task["state"], "operation_read": read,
                                  "association": "explicit_assignment" if assigned else "host_exact_read_match",
                                  "summary": (task.get("result") or {}).get("summary"),
                                  "outcome": (task.get("result") or {}).get("outcome")})
            known_file = known_files.get(obligation["path"], {})
            payload = {"obligation": {k: v for k, v in obligation.items() if k not in {"state", "review", "relation", "required"}},
                       "tasks": task_refs,
                       "evidence": [{"evidence_id": obligation["id"], "snapshot_id": obligation["source"]["snapshot_id"],
                                     "path": obligation["path"], "range": {"start": max(1, obligation["line"] - 8),
                                     "end": min(int(known_file.get("line_count") or obligation["line"]), obligation["line"] + 8)}}]}
            rows.append({"kind": "risk", "item_id": obligation["id"], "revision": fingerprint(payload),
                         "payload": payload, "operation_read": any(t["operation_read"] for t in task_refs)})
        return rows
