"""The shared boundary between vulnerability findings and audit observations.

Evidence validity and severity do not decide whether a source fact is a vulnerability.
New goal results must explicitly declare the vulnerability kind and a risk level.
Historical fixed-category findings predate ``finding_kind`` and remain readable.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

LEGACY_VULNERABILITY_CATEGORIES = frozenset({"sqli", "xss_r", "command_injection"})
VULNERABILITY_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


def is_vulnerability_finding(finding: Mapping[str, Any]) -> bool:
    kind = str(finding.get("finding_kind") or finding.get("kind") or "").strip().casefold()
    if kind:
        return kind == "vulnerability" and finding.get("severity") in VULNERABILITY_SEVERITIES
    return finding.get("category") in LEGACY_VULNERABILITY_CATEGORIES


def partition_findings(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    vulnerabilities: list[dict] = []
    observations: list[dict] = []
    for finding in findings:
        (vulnerabilities if is_vulnerability_finding(finding) else observations).append(finding)
    return vulnerabilities, observations


def source_observations(findings: list[dict], tasks: list[dict]) -> list[dict]:
    """Project observations without deleting or rewriting historical findings.

    New observations live in durable attempt results, not the findings table. Stable
    IDs allow the UI to retain disclosure state while a run is refreshed.
    """
    _, records = partition_findings(findings)
    records = list(records)
    seen: set[tuple[str, str, int]] = set()
    for task in tasks:
        history = task.get("attempt_history") or []
        # Some old task records carry only their most recent persisted result.
        attempts = history or [{"attempt": task.get("attempts", task.get("attempt", 0)),
                                "result": task.get("result") or {}}]
        for attempt in attempts:
            result = attempt.get("result") or {}
            for index, observation in enumerate(result.get("observations") or []):
                if not isinstance(observation, dict):
                    continue
                task_id = str(task.get("id") or task.get("task_key") or "task")
                number = str(attempt.get("attempt", attempt.get("attempt_no", 0)))
                key = (task_id, number, index)
                if key in seen:
                    continue
                seen.add(key)
                # Evidence strings are parsed with the same original-file range parser
                # used by worker findings; saved dict ranges are already API-ready.
                evidence = observation.get("evidence") or []
                if isinstance(evidence, str):
                    from .agent import _parse_evidence

                    evidence = _parse_evidence(evidence, known_paths=[])
                first_ref = evidence[0] if evidence else {}
                record_id = f"observation:{task_id}:{number}:{index}"
                records.append({
                    **observation,
                    "id": record_id,
                    "fingerprint": record_id,
                    "run_id": task.get("run_id"),
                    "unit_id": task_id,
                    "task_id": task_id,
                    "task_key": task.get("task_key"),
                    "attempt": attempt.get("attempt", attempt.get("attempt_no", 0)),
                    "category": "audit_observation",
                    "finding_kind": observation.get("kind") or "source_observation",
                    "severity": "informational",
                    "evidence": evidence,
                    "file_path": first_ref.get("path", ""),
                    "symbol": task.get("title") or task.get("summary") or "排查记录",
                    "line": first_ref.get("start_line", 1),
                    "unit_start_line": first_ref.get("start_line", 1),
                    "unit_end_line": first_ref.get("end_line", 1),
                    "input_source": "", "propagation": "", "dangerous_operation": "",
                    "protection": "", "preconditions": [], "missing_context": [],
                    "poc": None, "remediation": "", "disposition": "open",
                    "revision": 1, "superseded_summary": [],
                    "validation_state": "observation",
                    "validation_errors": [],
                    "verdict": None,
                    "verifications": [],
                    "created_at": attempt.get("finished_at") or attempt.get("created_at"),
                })
    return records
