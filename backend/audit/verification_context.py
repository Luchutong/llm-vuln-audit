"""Bounded Planner verification summaries and lossless, run-scoped detail queries.

Only summaries travel in the prefetched situation.  Long observations stay in the
host's context and are read in explicit, character-addressed chunks; they are never
silently truncated and then represented as reviewed.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

LIST_KEYS = {
    "records": "verification_records",
    "pending": "verification_reviews_required",
    "reviews": "verification_reviews",
}
IDENTITY_KEYS = (
    "id", "finding_id", "verification_id", "revision", "status", "verification_status",
    "verdict", "verification_verdict", "execution_status", "decision", "plan_id", "created_at",
)


def json_bytes(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def rows(context: dict, kind: str) -> list[dict]:
    if kind not in LIST_KEYS:
        raise ValueError("kind 必须为 records、pending 或 reviews")
    values = context.get(LIST_KEYS[kind]) or []
    if kind == "records" and context.get("verification_details"):
        values = context["verification_details"]
    return [item for item in values if isinstance(item, dict)]


def summary(row: dict) -> dict:
    """Keep identities exact.  Text previews are explicitly summaries, not observations."""
    result = {key: row[key] for key in IDENTITY_KEYS if key in row}
    for key in ("title", "finding_title", "summary", "rationale_summary", "rationale"):
        if key in row:
            value = str(row.get(key) or "")
            result[key] = value[:100]
            if len(value) > 100:
                result.setdefault("preview_fields", []).append(key)
    result["detail_available"] = bool(row.get("verification_id"))
    result["observations_preloaded"] = False
    return result


def projection(context: dict, *, count: int = 4) -> dict:
    result: dict = {}
    totals = {}
    for kind, key in LIST_KEYS.items():
        values = rows(context, kind)
        totals[kind] = len(values)
        # Pending reviews are oldest first.  Completed histories show the most recent.
        selected = values[:count] if kind == "pending" else values[-count:]
        result[key] = [summary(value) for value in selected]
    if not any(totals.values()):
        result["verification_access"] = {"totals": totals}
        return result
    result["verification_access"] = {
        "totals": totals,
        "list_tool": "list_verifications",
        "detail_tool": "read_verification",
        "review_batch_limit": count,
        "observations_preloaded": False,
        "notice": "仅预载摘要；复核前按 verification_id 完整读取 normal_observation 和 attack_observation。遗漏项仍待复核。",
    }
    return result


def list_page(context: dict, *, kind: str = "pending", cursor: str = "", limit: int = 4,
              byte_limit: int = 8 * 1024) -> dict:
    values = rows(context, kind)
    signatures = [{key: row.get(key) for key in IDENTITY_KEYS if key in row} for row in values]
    version = hashlib.sha256(json.dumps(signatures, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:20]
    offset = 0
    if cursor:
        try:
            given, raw_offset = cursor.split(":", 1)
            offset = int(raw_offset)
        except (TypeError, ValueError):
            raise ValueError("cursor 无效；请从空游标重新查询") from None
        if given != version:
            raise ValueError("验证列表已更新；请从空游标重新查询，不能沿用旧版本游标")
        if offset < 0 or offset > len(values):
            raise ValueError("cursor 越界；请从空游标重新查询")
    result = {"kind": kind, "items": [], "total": len(values), "cursor": cursor,
              "next_cursor": None, "remaining": len(values) - offset, "version": version}
    for row in values[offset:offset + min(16, max(1, limit))]:
        result["items"].append(summary(row))
        consumed = offset + len(result["items"])
        result["next_cursor"] = f"{version}:{consumed}" if consumed < len(values) else None
        result["remaining"] = len(values) - consumed
        if json_bytes(result) > byte_limit:
            result["items"].pop()
            consumed -= 1
            result["next_cursor"] = f"{version}:{consumed}" if consumed < len(values) else None
            result["remaining"] = len(values) - consumed
            break
    if offset < len(values) and not result["items"]:
        raise ValueError("验证标识本身超过查询容量；宿主保留原记录，不能裁损标识")
    return result


def detail_record(context: dict, verification_id: str) -> dict:
    """Resolve only the current run's supplied records, never a global Store lookup."""
    if not verification_id:
        raise ValueError("verification_id 不能为空")
    sources = [item for item in (context.get("verification_details") or []) if isinstance(item, dict)]
    sources.extend(rows(context, "records"))
    sources.extend(rows(context, "pending"))
    matched = [row for row in sources if str(row.get("verification_id") or "") == verification_id]
    if not matched:
        raise ValueError("本次运行没有该 verification_id；不能读取其他运行的验证")
    # Full detail wins over legacy bounded records; pending carries the current revision.
    result: dict = {}
    for row in reversed(matched):
        result.update(row)
    pending = next((row for row in rows(context, "pending")
                    if str(row.get("verification_id") or "") == verification_id), None)
    if pending is not None:
        for key in ("revision", "finding_id", "verification_status", "verification_verdict"):
            if key in pending:
                result[key] = pending[key]
    if "revision" not in result:
        finding = next((item for item in context.get("findings") or []
                        if isinstance(item, dict) and item.get("id") == result.get("finding_id")), {})
        result["revision"] = int(finding.get("revision") or 1)
    result["reviews"] = [row for row in rows(context, "reviews")
                         if str(row.get("verification_id") or "") == verification_id]
    return result


def field_text(record: dict, name: str) -> tuple[str, str]:
    if name not in record:
        raise ValueError("field 不存在；先用 read_verification 的空 field 获取字段列表")
    value = record[name]
    if isinstance(value, str):
        return value, "text"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")), "json"


def field_key(record: dict, name: str) -> tuple:
    text, _ = field_text(record, name)
    return (str(record.get("finding_id") or ""), str(record.get("verification_id") or ""),
            int(record.get("revision") or 1), name, hashlib.sha256(text.encode()).hexdigest())


def read_chunk(context: dict, *, verification_id: str, field: str = "", offset: int = 0,
               limit: int = 1024) -> tuple[dict, dict | None]:
    record = detail_record(context, verification_id)
    identity = {key: record[key] for key in IDENTITY_KEYS if key in record}
    if not field:
        return {**identity, "fields": [{"name": name, "length": len(field_text(record, name)[0]),
                                        "encoding": field_text(record, name)[1]}
                                       for name in record], "offset_unit": "unicode_characters"}, None
    text, encoding = field_text(record, field)
    if offset > len(text):
        raise ValueError("offset 超过字段长度；请按 next_offset 顺序读取")
    end = min(len(text), offset + min(1024, max(1, limit)))
    chunk = {**identity, "field": field, "encoding": encoding, "text": text[offset:end],
             "offset": offset, "end_offset": end, "total_characters": len(text),
             "next_offset": end if end < len(text) else None, "complete": offset == 0 and end == len(text),
             "offset_unit": "unicode_characters"}
    return chunk, {"key": field_key(record, field), "start": offset, "end": end}


def read_complete(intervals: list[tuple[int, int]], length: int) -> bool:
    if not intervals:
        return False
    end = 0
    for start, stop in sorted(intervals):
        if start > end:
            return False
        end = max(end, stop)
    return end >= length
