"""Host-owned audit obligations, stored in existing task JSON without a migration."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from .finding_policy import is_vulnerability_finding

OPEN_DIRECTION_STATES = frozenset({"pending", "assigned"})


def _load(value, default):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value) if value else default
    except (ValueError, TypeError):
        return default


def _dump(value):
    return json.dumps(value, ensure_ascii=False)


def _text(value):
    return " ".join(str(value or "").split())


_SOURCE_NAME = re.compile(r"[\w./-]+\.(?:php|py|js|ts|sh|yaml|yml|ini|conf)\b")


def unknown_source_names(text, known_paths):
    """Names a direction text mentions that no frozen source path resolves.

    A worker writes prose, not paths: ``report.php/member_lookup.php`` names two
    files, so a token only counts as unknown when none of its slash-delimited
    parts resolves.  Reading that joined token as one path marked a real
    direction advisory-only and refused its assignment, which the Planner could
    neither correct nor work around.
    """
    unknown = []
    for name in _SOURCE_NAME.findall(text):
        parts = [part for part in name.split("/") if part]
        if any(any(path == part or path.endswith("/" + part) for path in known_paths) for part in parts):
            continue
        unknown.append(name)
    return unknown


def _seen_spans(rows):
    """Keep bounded intervals; expanding original line numbers is unnecessary."""
    grouped = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        path, start, end = row.get("path"), row.get("start_line"), row.get("end_line")
        if not isinstance(path, str) or type(start) is not int or type(end) is not int or start < 1 or end < start:
            continue
        grouped.setdefault(path, []).append((start, end))
    result = {}
    for path, intervals in grouped.items():
        merged = []
        for start, end in sorted(intervals):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        result[path] = merged
    return result


def has_new_source_evidence(seen, previous):
    before = _seen_spans(previous)
    for path, intervals in _seen_spans(seen).items():
        for start, end in intervals:
            if not any(left <= start and end <= right for left, right in before.get(path, [])):
                return True
    return False


class DirectionStoreMixin:
    def discovery_first(self, run_id: str) -> bool:
        row = self._row("SELECT task_spec FROM runs WHERE id=?", (run_id,))
        return bool(row and (_load(row["task_spec"], {}) or {}).get("workflow_policy") == "discovery_first")

    def _audit_direction_records(self, run_id):
        records = {}
        for row in self._db.execute("SELECT id,task_key,result FROM planner_tasks WHERE run_id=? ORDER BY created_at,id", (run_id,)):
            result = _load(row["result"], {}) or {}
            for item in result.get("host_directions") or []:
                if isinstance(item, dict) and item.get("id"):
                    records[item["id"]] = {**item, "origin_task_id": row["id"], "origin_task_key": row["task_key"]}
        return records

    def _persist_audit_directions_tx(self, run_id, records):
        grouped = {}
        for item in records.values():
            grouped.setdefault(item["origin_task_id"], []).append(item)
        for row in self._db.execute("SELECT id,result FROM planner_tasks WHERE run_id=?", (run_id,)).fetchall():
            result = _load(row["result"], {}) or {}
            if row["id"] in grouped or "host_directions" in result:
                result["host_directions"] = sorted(grouped.get(row["id"], []), key=lambda item: item["id"])
                self._db.execute("UPDATE planner_tasks SET result=? WHERE id=?", (_dump(result), row["id"]))

    def list_audit_directions(self, run_id: str, *, cursor: int = 0, limit: int = 20, state: str = "open") -> dict:
        if type(cursor) is not int or cursor < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("direction cursor and limit must be strict integers, cursor >=0 and limit 1..100")
        if state not in {"all", "open", "pending", "assigned", "resolved", "skipped"}:
            raise ValueError("direction state must be all/open/pending/assigned/resolved/skipped")
        with self._lock:
            records = sorted(self._audit_direction_records(run_id).values(), key=lambda item: item["id"]) if self.discovery_first(run_id) else []
        required_open = sum(item["state"] in OPEN_DIRECTION_STATES and item.get("requirement", "required") == "required" for item in records)
        advisory_count = sum(item.get("requirement", "required") == "advisory" for item in records)
        open_count = required_open if self.host_queue_enabled(run_id) else sum(item["state"] in OPEN_DIRECTION_STATES for item in records)
        selected = [item for item in records if state == "all" or (state == "open" and item["state"] in OPEN_DIRECTION_STATES) or item["state"] == state]
        page = selected[cursor:cursor + limit]
        return {"items": page, "total": len(selected), "unsettled_total": open_count,
                "unsettled_required_total": required_open, "advisory_total": advisory_count,
                "offset": cursor, "limit": limit, "next_cursor": cursor + len(page) if cursor + len(page) < len(selected) else None}

    def audit_direction_summary(self, run_id: str) -> dict:
        with self._lock:
            records = list(self._audit_direction_records(run_id).values()) if self.discovery_first(run_id) else []
        hosted = self.host_queue_enabled(run_id)
        advisory = [item for item in records if item.get("requirement", "required") == "advisory"]
        obligations = [item for item in records if item.get("requirement", "required") == "required"] if hosted else records
        counts = {state: sum(item["state"] == state for item in obligations) for state in ("pending", "assigned", "resolved", "skipped")}
        required_open = [item for item in records if item["state"] in OPEN_DIRECTION_STATES and item.get("requirement", "required") == "required"]
        unresolved = sorted((required_open if hosted else [item for item in records if item["state"] in OPEN_DIRECTION_STATES]), key=lambda item: item["id"])
        return {"version": "audit-directions-v1", "total": len(records), **{key + "_total": value for key, value in counts.items()},
                "unsettled_total": len(unresolved), "complete": not unresolved, "items": unresolved[:4],
                "unsettled_required_total": len(required_open), "advisory_total": len(advisory),
                "required_total": len(records) - len(advisory), "advisory_items": advisory[:4],
                "omitted": max(0, len(unresolved) - 4), "next_cursor": 4 if len(unresolved) > 4 else None}

    def assigned_task_directions(self, run_id: str, task_key: str) -> list[dict]:
        if not self.discovery_first(run_id):
            return []
        with self._lock:
            return sorted((item for item in self._audit_direction_records(run_id).values()
                           if item["state"] == "assigned" and item.get("assigned_task_key") == task_key), key=lambda item: item["id"])

    def _project_active_directions(self, task):
        if task is None or not self.discovery_first(task["run_id"]):
            return task
        result = dict(task.get("result") or {})
        active = self.assigned_task_directions(task["run_id"], task["task_key"])
        result["active_directions"] = active
        # A completed Worker assessment may explicitly clear its own remaining
        # work. The host obligation remains open until Planner evidence review,
        # but must not be re-labelled as a Worker request to keep executing.
        if task.get("state") in {"pending", "ready", "running", "deferred"}:
            result["remaining_work"] = [item["text"] for item in active]
        task["result"] = result
        return task

    def _capture_worker_directions_tx(self, row, stored_result):
        records = self._audit_direction_records(row["run_id"])
        previous = _load(row["result"], {}) or {}
        task_spec = _load(row["context_spec"], {}) or {}
        declared = [str(ref.get("path") or "") for ref in task_spec.get("source_refs") or [] if isinstance(ref, dict)]
        declared += [str(path) for path in task_spec.get("scope_paths") or []]
        project_map = self.get_project_map(row["run_id"]) or {}
        known_paths = [item["path"] for item in project_map.get("files") or [] if isinstance(item, dict) and item.get("path")]
        selected = set(task_spec.get("direction_ids") or [])
        batch_policy = self.batch_review_enabled(row["run_id"])
        for value in stored_result.get("remaining_work") or []:
            text = _text(value)
            if not text:
                continue
            if batch_policy:
                referred = set(re.findall(r"dir_[a-f0-9]{32}", text)) & set(records)
                repeated = [item for item in records.values() if item["id"] in selected and item["text"] == text]
                if referred or repeated:
                    # The assessment preserves the follow-up text. Explicit
                    # references do not mint another obligation on an origin row.
                    continue
            identity = "dir_" + hashlib.sha256((row["run_id"] + "\0" + text).encode()).hexdigest()[:32]
            if identity in records:
                continue
            paths = sorted(path for path in known_paths if path in text)
            local = bool(paths) and all(any(path == target or path.startswith(target.rstrip("/") + "/") for target in declared if target) for path in paths)
            hosted = self.host_queue_enabled(row["run_id"])
            auto_assign = not hosted and not int(row["revisions"] or 0) and local
            unknown = unknown_source_names(text, known_paths)
            records[identity] = {"id": identity, "origin_task_id": row["id"], "origin_task_key": row["task_key"],
                                 "text": text, "paths": paths, "state": "assigned" if auto_assign or identity in selected else "pending",
                                 "assigned_task_key": row["task_key"] if auto_assign or identity in selected else None,
                                 **({"requirement": "advisory", "unknown_paths": unknown} if hosted else {}),
                                 "created_at": datetime.now(timezone.utc).isoformat()}
        stored_result["host_directions"] = [item for item in records.values() if item["origin_task_id"] == row["id"]]
        # Origin rows other than this task are unchanged by capture. Preserve the
        # host register even when the model omits it or fabricates a similarly named field.
        return records

    def _worker_batch_progress_tx(self, row, stored_result, seen, progress):
        previous = _load(row["result"], {}) or {}
        counters = dict(previous.get("host_progress") or {})
        known_keys = set(str(key) for key in counters.get("conclusion_keys") or [])
        incoming = set(str(key) for key in (progress or {}).get("new_conclusion_keys") or [] if isinstance(key, str) and key)
        previous_seen = []
        for attempt in self._db.execute("SELECT seen FROM planner_task_attempts WHERE task_id=? AND attempt>0", (row["id"],)):
            previous_seen.extend(_load(attempt["seen"], []) or [])
        new_evidence = has_new_source_evidence(seen or [], previous_seen)
        gained = bool(incoming - known_keys) or new_evidence
        success = stored_result.get("outcome") in {"achieved", "no_evidence", "continue"} and stored_result.get("terminal_reason", "completed") == "completed" and not stored_result.get("error")
        productive = success and gained
        counters.update(conclusion_keys=sorted(known_keys | incoming),
                        successful_batches=int(counters.get("successful_batches") or 0) + int(productive),
                        failed_attempts=int(counters.get("failed_attempts") or 0) + int(not productive),
                        new_evidence=new_evidence, new_conclusions=len(incoming - known_keys), productive=productive)
        stored_result["host_progress"] = counters
        return productive, counters["failed_attempts"]

    def _apply_direction_updates_tx(self, run_id, updates, proposals, reopened):
        if not self.discovery_first(run_id):
            if updates or any(item.get("direction_ids") for item in proposals):
                raise ValueError("direction_updates require discovery_first workflow")
            return
        records = self._audit_direction_records(run_id)
        tasks = {row["task_key"]: dict(row) for row in self._db.execute("SELECT * FROM planner_tasks WHERE run_id=?", (run_id,))}
        explicitly_selected = {item["task_key"]: list(item.get("direction_ids") or []) for item in proposals}
        selected_targets = {}
        for task_key, ids in explicitly_selected.items():
            for identity in ids:
                if identity in selected_targets and selected_targets[identity] != task_key:
                    raise ValueError(f"方向 {identity} 不能同时分派给多个工作项"
                                     f"（{selected_targets[identity]}、{task_key}）；每个方向每轮只能由一个任务领取")
                selected_targets[identity] = task_key
        for key in reopened:
            selected = set(explicitly_selected.get(key, []))
            for record in records.values():
                if record.get("assigned_task_key") == key and record["state"] == "assigned" and record["id"] not in selected:
                    record.update(state="pending", assigned_task_key=None)
            spec = _load(tasks[key]["context_spec"], {}) or {}
            spec["direction_ids"] = sorted(selected)
            self._db.execute("UPDATE planner_tasks SET context_spec=? WHERE id=?", (_dump(spec), tasks[key]["id"]))
        combined = list(updates)
        for task_key, ids in explicitly_selected.items():
            for direction_id in ids:
                explicit = next((item for item in combined if item.get("direction_id") == direction_id), None)
                if explicit is not None and (explicit.get("action") != "assign" or explicit.get("task_key") != task_key):
                    raise ValueError("direction_updates must agree with task direction_ids")
                if explicit is None:
                    combined.append({"direction_id": direction_id, "action": "assign", "task_key": task_key,
                                     "rationale_summary": "Planner 在当前任务定义中显式选择该未决方向。"})
        ids = [item.get("direction_id") for item in combined]
        if len(ids) != len(set(ids)):
            raise ValueError("each direction can receive only one update per round")
        for update in combined:
            identity = update.get("direction_id")
            record = records.get(identity)
            if record is None:
                raise ValueError("direction_id does not belong to this run")
            if record["state"] not in OPEN_DIRECTION_STATES:
                raise ValueError("settled direction cannot be reassigned or silently overwritten")
            action, task_key = update.get("action"), update.get("task_key")
            reason = _text(update.get("rationale_summary"))
            if len(reason) < 8 or reason.casefold() in {"unknown", "待补充", "无", "不适用"}:
                raise ValueError("direction settlement requires a concrete rationale of at least eight characters")
            if action == "assign":
                target = tasks.get(task_key)
                if target is None or target["state"] not in {"pending", "ready", "deferred"}:
                    raise ValueError("direction assignment requires a dispatchable task in this run")
                current = tasks.get(record.get("assigned_task_key"))
                if current is not None and current["state"] == "running":
                    raise ValueError("cannot take a direction away from a running task")
                if self.host_queue_enabled(run_id):
                    if record.get("unknown_paths"):
                        # The Planner cannot edit a direction's text, so an assignment
                        # refusal that only says "fix the scope" is a dead end: the run
                        # repeated it for three rounds until the coverage review closed.
                        # Name what is unknown and the two actions that can settle it.
                        raise ValueError(
                            f"方向 {identity} 的文本点名了冻结源码中不存在的文件："
                            f"{'、'.join(record['unknown_paths'])}；该方向不能升级为必做方向。"
                            "对本轮同一方向改用 skip（rationale 说明该路径不在冻结源码内，"
                            "仍可直接派发任务读其它已知路径）；该方向从未派发，不能 resolve。"
                            "其余任务与方向更新可随下一轮重新提交。")
                    record["requirement"] = "required"
                record.update(state="assigned", assigned_task_key=task_key)
                spec = _load(self._db.execute("SELECT context_spec FROM planner_tasks WHERE id=?", (target["id"],)).fetchone()[0], {}) or {}
                spec["direction_ids"] = sorted(set(spec.get("direction_ids") or []) | {identity})
                self._db.execute("UPDATE planner_tasks SET context_spec=? WHERE id=?", (_dump(spec), target["id"]))
            elif action == "resolve":
                self._validate_direction_resolution_tx(run_id, record, update, tasks)
                record.update(state="resolved", resolution_task_key=task_key, finding_ids=list(update.get("finding_ids") or []), resolution_reason=reason)
            elif action == "skip":
                record.update(state="skipped", resolution_reason=reason, limitation="该方向未完成源码审查；此项是显式范围限制，不能作为漏洞不存在的证据。")
            else:
                raise ValueError("unsupported direction update action")
        self._persist_audit_directions_tx(run_id, records)
        if combined:
            self.append_event(run_id, None, "audit_directions_updated", {"updates": combined, "summary": self.audit_direction_summary(run_id)})

    def _validate_direction_resolution_tx(self, run_id, record, update, tasks):
        if self.host_queue_enabled(run_id):
            task = tasks.get(update.get("task_key"))
            result = _load(task.get("result"), {}) if task else {}
            matching = [item for item in result.get("direction_results", []) if isinstance(item, dict)
                        and item.get("direction_id") == record["id"] and item.get("outcome") in {"supported", "no_evidence"}
                        and len(_text(item.get("rationale"))) >= 8]
            if len(matching) != 1 or record.get("assigned_task_key") != update.get("task_key"):
                raise ValueError("必做方向必须有同一 direction_id 的 supported/no_evidence 取证结果，completed 或路径相交不能替代")
        finding_ids = update.get("finding_ids") or []
        if finding_ids:
            for finding_id in finding_ids:
                row = self._db.execute("SELECT * FROM findings WHERE id=? AND run_id=?", (finding_id, run_id)).fetchone()
                finding = dict(row) if row else {}
                evidence = _load(finding.get("evidence"), []) or []
                paths = {ref.get("path") for ref in evidence if isinstance(ref, dict)}
                if (not finding or finding.get("validation_state") != "candidate" or not is_vulnerability_finding(finding)
                        or finding.get("disposition") not in {None, "", "open"} or finding.get("verification_status") == "rejected"
                        or not paths or (record.get("paths") and not paths.intersection(record["paths"]))):
                    raise ValueError("direction resolution requires current validated findings from this run matching the direction paths")
            return
        task = tasks.get(update.get("task_key"))
        result = _load(task.get("result"), {}) if task else {}
        if not task or task["state"] != "completed" or result.get("outcome") not in {"achieved", "no_evidence"}:
            raise ValueError("direction resolution requires a completed evidence-bearing task or current finding_ids")
        read_paths = set()
        for attempt in self._db.execute("SELECT seen FROM planner_task_attempts WHERE task_id=? AND attempt>0", (task["id"],)):
            read_paths.update(_seen_spans(_load(attempt["seen"], []) or []))
        if not read_paths or (record.get("paths") and not read_paths.intersection(record["paths"])):
            raise ValueError("direction resolution task has not actually read the related source paths")
