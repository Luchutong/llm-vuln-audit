"""Canonical, cross-run finding identity for a project's vulnerability ledger.

A run-local finding is an audit trail entry: it belongs to the task attempt that produced
it and its ``(run_id, unit_id, category)`` slot is re-used when that direction runs again.
The project ledger is the other axis: *this vulnerability in this project*, one row no
matter how many runs rediscover it.

The fingerprint has to survive a model that re-words its summary every round, so it is
built only from facts that do not drift:

    v1 | vulnerability | file path | symbol | normalised dangerous operation

Title, summary, evidence prose and the task that produced it are deliberately excluded.
When the model's anchor is stable but its wording of the sink drifted, an exact match
fails; :func:`pick_merge_candidate` then allows a merge only when there is exactly one
candidate at the same ``(path, symbol)`` whose sink tokens overlap strongly enough.

Planner findings are the hard case: a task spans several files, so it has no symbol and
is filed as ``<project>``.  There the sink description is pure model prose and may even
change language between runs, so text overlap is not an identity.  The project's content
key freezes the source, which makes cited line ranges stable coordinates: two findings
under ``<project>`` are the same vulnerability when they cite mostly the same lines of
the same file.  Ambiguity (several such candidates) still creates a new row.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata

FINDING_FINGERPRINT_SCHEMA = 1
MERGE_THRESHOLD = 0.6
ANCHOR_THRESHOLD = 0.5
PROJECT_SYMBOL = "<project>"

word = re.compile(r"[0-9a-z_㐀-鿿]+")


def normalise_sink(value: object) -> str:
    """Lowercase, NFKC, collapse whitespace and trim prose punctuation, capped at 200."""
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    text = re.sub(r"\s+", " ", text).strip()
    text = text.strip("`\"'，。；：、,.;:")
    return text[:200]


def sink_tokens(value: object) -> set[str]:
    """Tokens compared by the fallback merge; single characters are too weak to count."""
    return {token for token in word.findall(normalise_sink(value)) if len(token) > 1}


def sink_similarity(left: object, right: object) -> float:
    """Jaccard overlap of two dangerous-operation descriptions."""
    first, second = sink_tokens(left), sink_tokens(right)
    if not first or not second:
        return 0.0
    return len(first & second) / len(first | second)


def canonical_fingerprint(
    file_path: str,
    symbol: str,
    dangerous_operation: str,
    *,
    category: str = "vulnerability",
) -> str:
    """The ledger identity of one vulnerability, independent of how it was worded."""
    path = unicodedata.normalize("NFC", str(file_path or ""))
    sink = normalise_sink(dangerous_operation)
    body = f"v{FINDING_FINGERPRINT_SCHEMA}|{category}|{path}|{str(symbol or '')}|{sink}"
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:32]


def pick_merge_candidate(finding: dict, candidates: list[dict]) -> dict | None:
    """The single existing ledger row this finding should update, if one is unambiguous.

    Two sinks in the same function are a real possibility, so a near match is only
    accepted when it is the *only* one above the threshold: ambiguity creates a new row
    instead of risking two distinct vulnerabilities being collapsed into one.

    Symbol-less (Planner) findings are matched by cited line ranges first.  Their sink
    wording is model prose and may be rephrased, or even translated, between runs; the
    line ranges point at a source that the project's content key has frozen.
    """
    if str(finding.get("symbol") or "") == PROJECT_SYMBOL:
        anchored = [
            item for item in candidates
            if str(item.get("symbol") or "") == PROJECT_SYMBOL
            and anchor_overlap(finding, item) >= ANCHOR_THRESHOLD
        ]
        if len(anchored) == 1:
            return anchored[0]
    scored = [
        (sink_similarity(finding.get("dangerous_operation"), item.get("dangerous_operation")), item)
        for item in candidates
    ]
    scored = [(score, item) for score, item in scored if score >= MERGE_THRESHOLD]
    if len(scored) != 1:
        return None
    return scored[0][1]


def _evidence(value: object) -> list:
    """Evidence is a list in a run finding and a JSON string in a ledger row."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return []
    return value if isinstance(value, list) else []


def evidence_lines(item: dict, path: str) -> set[int]:
    """Line numbers cited in one file, expanded over each range.

    The expansion is capped so an over-broad citation cannot claim a whole file.
    """
    lines: set[int] = set()
    for ref in _evidence(item.get("evidence")):
        if not isinstance(ref, dict) or str(ref.get("path") or "") != path:
            continue
        try:
            start = int(ref.get("start_line") or 0)
            end = int(ref.get("end_line") or start)
        except (TypeError, ValueError):
            continue
        if start <= 0:
            continue
        lines.update(range(start, max(start, min(end, start + 400)) + 1))
    return lines


def anchor_overlap(finding: dict, candidate: dict) -> float:
    """Jaccard overlap of the cited line coordinates in the finding's primary file."""
    path = str(finding.get("file_path") or "")
    if not path or str(candidate.get("file_path") or "") != path:
        return 0.0
    left, right = evidence_lines(finding, path), evidence_lines(candidate, path)
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def ledger_record(finding: dict) -> dict:
    """Adapt a run-local finding dict to the ledger's column names.

    ``file_path``/``symbol`` come from the finding's resolved unit or task; callers that
    build the record already know its anchor and pass it explicitly.
    """
    record = {
        "id": finding["id"],
        "fingerprint": finding.get("fingerprint") or canonical_fingerprint(
            finding.get("file_path", ""), finding.get("symbol", ""),
            finding.get("dangerous_operation", ""),
        ),
        "file_path": str(finding.get("file_path") or ""),
        "symbol": str(finding.get("symbol") or ""),
        "category": finding.get("category") or "task_goal",
        "finding_kind": finding.get("finding_kind", ""),
        "title": finding.get("title") or "",
        "severity": finding.get("severity") or "unknown",
        "summary": finding.get("summary") or "",
        "evidence": finding.get("evidence") or [],
        "input_source": finding.get("input_source") or "",
        "propagation": finding.get("propagation") or "",
        "dangerous_operation": finding.get("dangerous_operation") or "",
        "protection": finding.get("protection") or "",
        "preconditions": finding.get("preconditions") or [],
        "missing_context": finding.get("missing_context") or [],
        "poc": finding.get("poc"),
        "remediation": finding.get("remediation") or "",
        "validation_state": finding.get("validation_state") or "candidate",
        "created_at": finding.get("created_at") or "",
    }
    return record


def backfill_project_ledger(store) -> int:
    """Idempotently fold existing run findings into their projects' ledgers.

    Only validated vulnerability conclusions become ledger rows: an observation, an
    invalid citation or a withdrawn conclusion is audit history, not something a later
    run should start from.  Findings already linked are skipped, so this is safe on every
    older database.
    """
    from .finding_policy import is_vulnerability_finding

    linked = 0
    for run in store.list_runs():
        project_id = str(run.get("project_id") or "")
        if not project_id:
            continue
        for finding in store.list_findings(run["id"]):
            if finding.get("project_finding_id"):
                continue
            if finding.get("validation_state") != "candidate" or not is_vulnerability_finding(finding):
                continue
            record = ledger_record(finding)
            if not record["file_path"]:
                continue
            record["fingerprint"] = canonical_fingerprint(
                record["file_path"], record["symbol"], record["dangerous_operation"]
            )
            merged = store.merge_project_finding(project_id, run["id"], record)
            store.link_finding_project(
                finding["id"], merged["project_finding_id"], merged["revision"]
            )
            linked += 1
    return linked


def finding_anchor(finding: dict, unit: dict | None = None) -> tuple[str, str]:
    """The (path, symbol) a finding is filed under: its evidence, never its task title."""
    path = str(finding.get("file_path") or "")
    symbol = str(finding.get("symbol") or "")
    if not path:
        path = str((unit or {}).get("file_path") or "")
    if not symbol:
        symbol = str((unit or {}).get("symbol") or "")
    return path, symbol
