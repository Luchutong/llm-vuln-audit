"""Recon brief normalization against the frozen project map.

Recon output is navigation, never evidence.  A reference outside the frozen snapshot, a
line beyond the file, or a directory the host cannot confirm is dropped with a
diagnostic instead of being retried or promoted into a finding.
"""
from __future__ import annotations

from typing import Any

NOTICE = (
    "这是侦察子 agent 的导航线索，不是 finding 证据，也不是安全结论；"
    "引用其中任何路径仍必须由 worker 读取原始行号后才会成为证据。"
    "files_examined 由宿主按真实读记录填写。"
)


def _clamp(ref: Any, files_by_path: dict) -> tuple[dict | None, str]:
    if not isinstance(ref, dict):
        return None, "not_object"
    path = str(ref.get("path") or "")
    if path not in files_by_path:
        return None, "unknown_path"
    line_count = int(files_by_path[path].get("line_count") or 1)
    try:
        start = int(ref.get("start_line") or 1)
        end = int(ref.get("end_line") or start)
    except (TypeError, ValueError):
        return None, "bad_range"
    start = max(1, min(start, line_count))
    end = max(start, min(end, line_count))
    return {"path": path, "start_line": start, "end_line": end,
            "why": str(ref.get("why") or "")}, ""


def normalize_brief(brief: dict, files_by_path: dict) -> tuple[dict, list[dict]]:
    """Return the sanitized brief and one diagnostic per dropped item."""
    diagnostics: list[dict] = []

    def keep_refs(refs: Any, label: str) -> list[dict]:
        kept = []
        for index, ref in enumerate(refs or []):
            value, reason = _clamp(ref, files_by_path)
            if value is None:
                diagnostics.append({
                    "code": "recon_ref_dropped", "list": label, "index": index,
                    "path": str((ref or {}).get("path") if isinstance(ref, dict) else "")[:300],
                    "reason": reason,
                })
                continue
            kept.append(value)
        return kept

    layout = []
    for index, area in enumerate(brief.get("layout") or []):
        if not isinstance(area, dict):
            diagnostics.append({"code": "recon_area_dropped", "index": index, "reason": "not_object"})
            continue
        path = str(area.get("path") or "").strip("/")
        if path in files_by_path or any(candidate.startswith(f"{path}/") for candidate in files_by_path):
            layout.append({"path": path, "role": str(area.get("role") or ""),
                           "notes": str(area.get("notes") or "")})
        else:
            diagnostics.append({"code": "recon_area_dropped", "index": index,
                                "path": path[:300], "reason": "unknown_path"})
    sanitized = {
        "summary": str(brief.get("summary") or ""),
        "layout": layout,
        "entry_candidates": keep_refs(brief.get("entry_candidates"), "entry_candidates"),
        "data_stores": keep_refs(brief.get("data_stores"), "data_stores"),
        "security_boundaries": keep_refs(brief.get("security_boundaries"), "security_boundaries"),
        "reading_plan": keep_refs(brief.get("reading_plan"), "reading_plan"),
        "uncertainties": [str(text)[:400] for text in brief.get("uncertainties") or []][:8],
        "notice": NOTICE,
    }
    return sanitized, diagnostics
