"""Evidence-reference validation.

A candidate is only stored as a candidate when every cited line range belongs to the
frozen snapshot *and* falls inside code the model actually saw: the unit text handed
to it, or a range one of the three read-only tools returned. This is what keeps the
report's "original line number" claim checkable.
"""
from __future__ import annotations

import hashlib
from difflib import get_close_matches

MAX_REPORTED_ERRORS = 8


def evidence_inventory(ranges: list[tuple[str, int, int]], limit: int = 20, max_bytes: int = 1200) -> str:
    """Only ranges actually delivered; navigation can never grow this inventory."""
    heading = "已读证据（路径均相对快照根，保留源码包根目录）："
    if len(heading.encode("utf-8")) + 3 > max_bytes:
        return ""
    shown = []
    for path, start, end in ranges[:limit]:
        entry = f"{path}:{start}-{end}"
        if len((heading + "；".join([*shown, entry])).encode("utf-8")) + 60 > max_bytes:
            break
        shown.append(entry)
    text = heading + ("；".join(shown) or "无已列出范围")
    omitted = len(ranges) - len(shown)
    suffix = f"；另 {omitted} 段未列出" if omitted else ""
    return text + suffix if len((text + suffix).encode("utf-8")) <= max_bytes else heading


def seen_ranges(unit: dict, tool_reads: list[dict], *, exact: bool = False) -> list[tuple[str, int, int]]:
    """Ranges the model demonstrably received: its own unit plus every tool result.

    Adjacent and overlapping reads are merged first. A model that reads 380-395, 396-415
    and 416-430 has read 380-430, and citing that span should not be rejected as "never
    read" — which is what happened while each tool result stayed a separate island. Only
    ranges that already touch are merged, so no gap ever becomes readable by accident.
    """
    # New runs include the cleaned unit in an exact delivered-line ledger. Do not
    # silently grant visibility to omitted comments or truncated source lines.
    raw: list[tuple[str, int, int]] = [] if exact else [(unit["file_path"], int(unit["start_line"]), int(unit["end_line"]))]
    for read in tool_reads:
        path = read.get("path")
        start = read.get("start_line")
        end = read.get("end_line")
        if isinstance(path, str) and isinstance(start, int) and isinstance(end, int) and start <= end:
            raw.append((path, start, end))

    merged: list[tuple[str, int, int]] = []
    for path, start, end in sorted(raw):
        # Sorted by start, so one pass is enough: extending the open range only ever makes
        # it easier for the next one to touch it.
        if merged and merged[-1][0] == path and start <= merged[-1][2] + 1:
            merged[-1] = (path, merged[-1][1], max(merged[-1][2], end))
        else:
            merged.append((path, start, end))
    return merged


def _covered(path: str, start: int, end: int, ranges: list[tuple[str, int, int]]) -> bool:
    for seen_path, seen_start, seen_end in ranges:
        if seen_path != path:
            continue
        # The cited span must sit inside a single range the model was shown.
        if seen_start <= start and end <= seen_end:
            return True
    return False


def validate_evidence(
    evidence: list[dict],
    file_lines: dict[str, int],
    ranges: list[tuple[str, int, int]],
) -> tuple[list[dict], list[str]]:
    """Split the citations into the ones that hold up and the ones that do not.

    Returns `(verified, problems)`. Dropping the bad references rather than the whole
    verdict matters: a candidate that cites the sink correctly but also invents a range in
    a file it never opened is still a candidate, and discarding it outright would turn a
    real detection into a false negative. What must not survive is the invented citation,
    so it is removed from the stored evidence and reported instead.

    A candidate left with no verified reference at all has nothing checkable behind it and
    is stored as invalid.
    """
    problems: list[str] = []
    verified: list[dict] = []
    if not evidence:
        return [], ["no evidence line ranges were provided"]

    for index, ref in enumerate(evidence, 1):
        path = ref.get("path")
        start = ref.get("start_line")
        end = ref.get("end_line")

        if not isinstance(path, str) or path not in file_lines:
            # Suggestions are drawn exclusively from delivered evidence. An unseen
            # similarly named file must not become visible through a rejection hint.
            visible = sorted({item[0] for item in ranges})
            candidates = []
            if isinstance(path, str):
                candidates = [item for item in visible if item.endswith("/" + path)]
                candidates = candidates[:3] or get_close_matches(path, visible, n=3, cutoff=0.6)
            hint = f"; 已读候选路径（需原样引用并核对行号）: {', '.join(candidates)}" if candidates else ""
            problems.append(f"evidence[{index}]: path {path!r} is not a file in this snapshot{hint}")
            continue
        if type(start) is not int or type(end) is not int or start < 1 or end < start:
            problems.append(f"evidence[{index}]: line range {start!r}-{end!r} is not a valid range")
            continue
        if end > file_lines[path]:
            problems.append(
                f"evidence[{index}]: lines {start}-{end} exceed {path} which has {file_lines[path]} lines"
            )
            continue
        if not _covered(path, start, end, ranges):
            problems.append(
                f"evidence[{index}]: lines {start}-{end} of {path} were never read by this unit"
            )
            continue
        verified.append({"path": path, "start_line": start, "end_line": end})

    return verified, problems[:MAX_REPORTED_ERRORS]


def fingerprint(category: str, file_path: str, symbol: str, dangerous_operation: str) -> str:
    """Stable identity for de-duplicating repeated candidates of the same weakness."""
    material = "|".join(
        (
            category,
            file_path.strip().lower(),
            symbol.strip().lower(),
            " ".join(dangerous_operation.split()).lower()[:200],
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def title_for(category: str, file_path: str, symbol: str) -> str:
    label = {
        "sqli": "SQL 注入",
        "xss_r": "反射型 XSS",
        "command_injection": "命令注入",
    }.get(category, category)
    return f"{label} · {symbol} ({file_path})"
