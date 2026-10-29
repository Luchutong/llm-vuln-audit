"""Deterministic ordering for planner navigation suggestions.

Adapted from AutoCVE's small candidate-ordering helper.  Ordering is advice only: two
candidates on the same path with the same type are still two candidates, because only
evidence and an explicit disposition may merge a root cause.
"""
from __future__ import annotations

from typing import Any, Iterable


def _text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) else ""


def rank_candidates(candidates: Iterable[Any], *, checkpoints: Iterable[str] = (),
                    limit: int | None = None) -> list[dict]:
    """Return ``[{candidate, score, reasons}]`` in a stable, reproducible order."""
    needles = [str(item).casefold() for item in checkpoints if str(item).strip()]
    ranked: list[dict] = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            continue
        location = candidate.get("primary_location")
        location = location if isinstance(location, dict) else {}
        path = _text(location.get("path") or candidate.get("file_path") or candidate.get("path"))
        cause = _text(candidate.get("vulnerability_type") or candidate.get("category"))
        title = _text(candidate.get("title"))
        haystack = f"{path} {cause} {title}".casefold()
        hits = [needle for needle in needles if needle in haystack]
        evidence = candidate.get("evidence")
        evidence_count = len(evidence) if isinstance(evidence, list) else (1 if _text(evidence) else 0)
        score = 3 * len(hits)
        reasons: list[str] = []
        if hits:
            reasons.append("checkpoint:" + ",".join(hits))
        if path and (location.get("line") or candidate.get("line")):
            score += 2
            reasons.append("located")
        elif path:
            score += 1
            reasons.append("path_only")
        if evidence_count:
            score += 1
            reasons.append("cited")
        if _text(candidate.get("disposition") or "open") == "open" \
                and _text(candidate.get("verification_status")) not in {"verified", "rejected"}:
            score += 1
            reasons.append("unresolved")
        ranked.append({"candidate": candidate, "score": score, "reasons": reasons,
                       "_index": index})
    ranked.sort(key=lambda item: (-item["score"], _text(item["candidate"].get("id")), item["_index"]))
    for item in ranked:
        item.pop("_index", None)
    return ranked[:limit] if limit is not None else ranked
