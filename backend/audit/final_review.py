"""Final-review contract: one delivery unit per conclusion, conflict kept visible.

The report must not resolve a semantic conflict by precedence ("latest", "highest
score", "verified wins").  This module therefore keeps three separate things apart:

* source records -- every finding row this run produced, including superseded drafts,
  withdrawals and duplicates.  They are never deleted or rewritten by reporting;
* the canonical group -- one ledger identity, with exactly one *current* claim chosen
  by revision order, not by content preference;
* the final disposition -- new runs require an exact-version independent final batch;
  static acceptance is distinct from dynamic verification. Legacy runs retain their
  dynamic-verification/confirmed-review rule. Conflicts stay visible in both paths.

It also defines the bounded review batch (``ReviewBatch/v1``): every claimed item must
carry exactly one decision, and the batch is complete only when the sets match.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .cvss_assessment import rating_text
from .finding_policy import is_vulnerability_finding
from .project_findings import exact_run_identity, pick_run_merge_candidate
from .worker_strategies import canonical_vulnerability_type

ACCEPTED, PENDING, CONTESTED = "accepted", "pending", "contested"
REVIEW_BATCH_VERSION = "review-batch/v1"
REVIEW_DECISIONS = ("keep", "revise", "duplicate", "needs_evidence", "withdraw")
MAX_REVIEW_ITEMS = 400


def withdrawn(finding: dict) -> bool:
    from .db import WITHDRAWN_FINDING_DISPOSITIONS

    return str(finding.get("disposition") or "open") in WITHDRAWN_FINDING_DISPOSITIONS


def group_key(finding: dict) -> str:
    """The delivery identity: the ledger row when there is one, else the record."""
    return str(finding.get("project_finding_id") or finding["id"])


def record_currency(finding: dict) -> tuple[int, int, str]:
    """Order records of one group: ledger revision first, then run revision, then id."""
    return (
        int(finding.get("project_revision") or finding.get("revision") or 1),
        int(finding.get("revision") or 1),
        str(finding["id"]),
    )


def latest_verification(finding: dict) -> dict | None:
    verifications = finding.get("verifications") or []
    latest = str(finding.get("latest_verification_id") or "")
    if latest:
        match = next((item for item in verifications if str(item.get("id")) == latest), None)
        if match is not None:
            return match
    return verifications[-1] if verifications else None


def current_review(finding: dict) -> dict | None:
    """The review of this exact conclusion revision and verification, if one exists.

    A review of an older revision, or of a different verification of the same revision,
    does not carry over: the claim changed under it.
    """
    verification = latest_verification(finding)
    verification_id = str((verification or {}).get("id") or "")
    revision = int(finding.get("revision") or 1)
    return next(
        (
            review
            for review in reversed(finding.get("verification_reviews") or [])
            if int(review.get("revision") or 1) == revision
            and str(review.get("verification_id") or "") == verification_id
        ),
        None,
    )


def evidence_refs(finding: dict) -> list[dict]:
    snapshot_id = str(finding.get("snapshot_id") or "")
    refs = []
    for item in finding.get("evidence") or []:
        if not isinstance(item, dict) or not item.get("path"):
            continue
        start, end = int(item.get("start_line") or 0), int(item.get("end_line") or 0)
        if start < 1 or end < start:
            continue
        refs.append({
            "evidence_id": source_evidence_id(snapshot_id, item["path"], start, end),
            "snapshot_id": snapshot_id,
            "path": item["path"],
            "start_line": start,
            "end_line": end,
            "range": {"start": start, "end": end},
        })
    return refs


def source_evidence_id(snapshot_id: str, path: str, start: int, end: int) -> str:
    raw = f"{snapshot_id}|{path}|{start}|{end}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def claim_snapshot(finding: dict) -> dict:
    """The frozen claim shown for one group; ratings keep their own revision.

    Only host-checked facts live here.  ``summary``/``remediation`` are the claim's own
    prose and are labelled as such by the renderer; they never stand in for evidence.
    """
    assessment = finding.get("cvss_assessment") or {}
    verification = latest_verification(finding)
    return {
        "finding_id": finding["id"],
        "revision": int(finding.get("revision") or 1),
        "project_revision": int(finding.get("project_revision") or 0),
        "title": finding.get("title") or "",
        "category": finding.get("category") or "",
        "vulnerability_type": finding_type(finding),
        "rating_text": rating_text(finding),
        "cvss": finding.get("cvss") or None,
        "assessment_revision": int(assessment.get("assessment_revision") or 0),
        "file_path": finding.get("file_path") or "",
        "primary_location": finding.get("primary_location") or {},
        "evidence": evidence_refs(finding),
        "input_source": finding.get("input_source") or "",
        "propagation": finding.get("propagation") or "",
        "dangerous_operation": finding.get("dangerous_operation") or "",
        "protection": finding.get("protection") or "",
        "preconditions": list(finding.get("preconditions") or []),
        "missing_context": list(finding.get("missing_context") or []),
        "summary": finding.get("summary") or "",
        "remediation": finding.get("remediation") or "",
        "poc": finding.get("poc") or None,
        "verification_status": finding.get("verification_status") or "unverified",
        "verification_verdict": finding.get("verification_verdict") or "",
        "verification_id": str((verification or {}).get("id") or ""),
        "validation_errors": list(finding.get("validation_errors") or []),
    }


def finding_type(finding: dict) -> str:
    # An explicit unknown/other is still the Worker's classification. Category
    # fallback is solely for historical records without the dedicated field.
    return canonical_vulnerability_type(finding.get("vulnerability_type") or finding.get("category"))


def conflicts(records: list[dict], current: dict) -> list[dict]:
    """Contradictions the report must show instead of resolving by precedence."""
    found: list[dict] = []
    types = {finding_type(item) for item in records}
    known = {value for value in types if value not in {"", "unknown", "other"}}
    if len(known) > 1:
        found.append({
            "kind": "category_mismatch",
            "detail": "同一台账下的记录使用了不同的根因类型：" + "、".join(sorted(known)),
            "finding_ids": [item["id"] for item in records],
        })
    verdicts = {str(item.get("verification_verdict") or "") for item in records}
    if "verified" in verdicts and "rejected" in verdicts:
        found.append({
            "kind": "verification_disagreement",
            "detail": "同一台账下的记录对动态验证给出了相反结论。",
            "finding_ids": [item["id"] for item in records],
        })
    review = current_review(current)
    if review is not None and str(review.get("decision")) == "contested":
        found.append({
            "kind": "review_contested",
            "detail": str(review.get("rationale") or "正式复核对该结论存疑。"),
            "finding_ids": [current["id"]],
            "review_id": review.get("id"),
        })
    return found


def disposition(current: dict, found: list[dict]) -> tuple[str, str]:
    final = current.get("final_review_decision") or {}
    if final.get("source") == "planner_final_batch":
        if final.get("decision") == "accept" and not found:
            return ACCEPTED, "独立终审批次接受源码结论；动态验证状态单独保留"
        if final.get("decision") == "contested":
            return CONTESTED, str(final.get("rationale") or "终审批次对结论存疑")
        if final.get("decision") == "needs_evidence":
            return PENDING, str(final.get("rationale") or "终审批次要求补证")
    review = current_review(current)
    if any(item["kind"] == "review_contested" for item in found):
        return CONTESTED, "正式复核未确认当前结论"
    if current.get("final_review_required") and not final:
        if found:
            return CONTESTED, "存在冲突，独立终审批次尚未裁定"
        return PENDING, "当前版本尚未完成独立终审批次；动态复核不替代终审"
    status = str(current.get("verification_status") or "unverified")
    if status == "verified" and review is not None and str(review.get("decision")) == "confirmed":
        if found:
            return CONTESTED, "已确认，但同一台账仍存在相互矛盾的记录"
        return ACCEPTED, "动态验证成立且当前结论已通过正式复核"
    if found:
        return CONTESTED, "同一台账存在相互矛盾的记录，尚未裁定主结论"
    if status == "verified":
        return PENDING, "动态验证成立，但当前结论尚未通过正式复核"
    if status == "rejected":
        return CONTESTED, "动态验证反证了当前结论，等待处置"
    if status in {"inconclusive", "stale"}:
        return PENDING, f"动态验证结论为 {status}，需要补证或重试"
    return PENDING, "尚无动态验证，仅静态证据支持"


def canonical_groups(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """One current claim per ledger identity, plus the records it stands on."""
    current_records = [
        item for item in findings
        if item.get("validation_state") == "candidate" and not withdrawn(item)
        and is_vulnerability_finding(item)
    ]
    groups: dict[str, list[dict]] = {}
    for item in current_records:
        groups.setdefault(group_key(item), []).append(item)
    canonical = []
    for identity, records in groups.items():
        records = sorted(records, key=record_currency)
        current = records[-1]
        found = conflicts(records, current)
        final, reason = disposition(current, found)
        assessment = current.get("cvss_assessment") or {}
        canonical.append({
            "canonical_id": identity,
            "final_batch_review": current.get("final_review_decision"),
            "acceptance_basis": "static_review" if (current.get("final_review_decision") or {}).get("decision") == "accept"
                                and current.get("verification_status") != "verified" else "dynamic_review",
            "current_claim_ref": {
                "finding_id": current["id"],
                "revision": int(current.get("revision") or 1),
                "project_revision": int(current.get("project_revision") or 0),
            },
            "frozen_claim": claim_snapshot(current),
            "frozen_cvss_assessment": assessment,
            "assessment_revision": int(assessment.get("assessment_revision") or 0),
            "source_record_refs": [
                {
                    "finding_id": item["id"],
                    "revision": int(item.get("revision") or 1),
                    "project_revision": int(item.get("project_revision") or 0),
                    "disposition": item.get("disposition") or "open",
                    "validation_state": item.get("validation_state") or "",
                    "verification_status": item.get("verification_status") or "",
                    "verification_verdict": item.get("verification_verdict") or "",
                    "created_at": item.get("created_at") or "",
                    "current": item is current,
                }
                for item in records
            ],
            "duplicate_refs": [],
            "merge_suggestions": [],
            "conflicts": found,
            "final_disposition": final,
            "disposition_reason": reason,
        })
    canonical.sort(key=lambda item: str(item["canonical_id"]))
    return canonical, current_records


def comparison_candidates(canonical: list[dict]) -> dict[str, list[dict]]:
    """Same typed anchor or a cited peer anchor nominates a comparison, never a merge.

    Shared utility citations alone do not match: a citation must cover the other
    claim's actual primary coordinate. This links entry/helper views of one chain.
    """
    def coordinate(claim):
        location = claim.get("primary_location") or {}
        path, line = location.get("path") or claim.get("file_path"), location.get("line")
        return (path, line) if path and type(line) is int and line > 0 else None

    def covers(claim, coord):
        return any(ref.get("path") == coord[0]
                   and (ref.get("range") or {}).get("start", ref.get("start_line", 0)) <= coord[1]
                   <= (ref.get("range") or {}).get("end", ref.get("end_line", 0))
                   for ref in claim.get("evidence") or [])

    peers = {}
    for index, entry in enumerate(canonical):
        a = entry["frozen_claim"]
        coord = coordinate(a)
        if not coord or a.get("vulnerability_type") in {None, "", "unknown", "other"}:
            continue
        for other in canonical[index + 1:]:
            b = other["frozen_claim"]
            target = coordinate(b)
            if not target or a["vulnerability_type"] != b.get("vulnerability_type"):
                continue
            if coord != target and not covers(a, target) and not covers(b, coord):
                continue
            basis = ("同类型且主定位相同" if coord == target else "同类型且证据覆盖对方主定位，可能是跨文件同一链路")
            for owner, peer in ((entry, other), (other, entry)):
                peers.setdefault(owner["canonical_id"], []).append({"item_id": peer["canonical_id"], **{key: peer["frozen_claim"].get(key) for key in (
                    "finding_id", "revision", "title", "vulnerability_type", "primary_location", "summary",
                    "input_source", "dangerous_operation", "protection", "preconditions", "missing_context", "evidence", "cvss", "verification_status")},
                 "basis": basis + "；须统一核对根因与必要前提，不自动归并。"})
                peers[owner["canonical_id"]][-1]["basis_kind"] = "same_anchor" if coord == target else "cited_anchor"
    return peers


def merge_suggestions(canonical: list[dict]) -> None:
    """Cross-ledger near-duplicates are suggestions, never silent merges.

    Only an unambiguous candidate at the same typed coordinate *and* similar sink text
    qualifies; a shared file, type or line alone does not.  The suggestion is recorded
    on both entries and surfaces in the appendix and the action items.
    """
    by_finding = {entry["frozen_claim"]["finding_id"]: entry for entry in canonical}
    comparisons = comparison_candidates(canonical)
    for entry in canonical:
        entry["comparison_candidates"] = comparisons.get(entry["canonical_id"], [])
    exact: dict[str, dict] = {}
    pairs: set[tuple[str, str]] = set()
    for entry in canonical:
        claim = entry["frozen_claim"]
        others = [other["frozen_claim"] for other in canonical if other is not entry]
        match = pick_run_merge_candidate(claim, others) if others else None
        target = by_finding.get(str((match or {}).get("finding_id") or ""))
        if target is None:
            identity = exact_run_identity(claim)
            if identity is not None:
                target = exact.get(identity)
                exact.setdefault(identity, entry)
        if target is None or target is entry:
            continue
        if (target["canonical_id"] in ((entry.get("final_batch_review") or {}).get("distinct_from") or [])
                or entry["canonical_id"] in ((target.get("final_batch_review") or {}).get("distinct_from") or [])):
            continue  # A current explicit distinction is a decision, not a pending merge.
        pair = tuple(sorted((entry["canonical_id"], target["canonical_id"])))
        if pair in pairs:
            continue
        pairs.add(pair)
        for owner, peer in ((entry, target), (target, entry)):
            owner["merge_suggestions"].append({
                "other_canonical_id": peer["canonical_id"],
                "basis": "主定位坐标一致且危险操作相似（疑似跨台账重复）",
                "action": "需人工或终审裁定是否归并；不自动合并，来源记录全部保留。",
            })
            owner["duplicate_refs"].append({
                "canonical_id": peer["canonical_id"],
                "finding_id": peer["current_claim_ref"]["finding_id"],
                "relation": "suspected_duplicate",
            })


def observations(findings: list[dict]) -> list[dict]:
    records = [
        item for item in findings
        if item.get("validation_state") == "candidate" and not withdrawn(item)
        and not is_vulnerability_finding(item)
    ]
    return [
        {
            "finding_id": item["id"],
            "title": item.get("title") or "",
            "kind": item.get("finding_kind") or "source_observation",
            "file_path": item.get("file_path") or "",
            "evidence": evidence_refs(item),
            "summary": item.get("summary") or "",
        }
        for item in records
    ]


def verification_attempts(findings: list[dict]) -> list[dict]:
    from .review_input import verification_fact_availability

    attempts: list[dict] = []
    seen: set[str] = set()
    for finding in findings:
        for record in finding.get("verifications") or []:
            if str(record.get("id")) in seen:
                continue
            seen.add(str(record.get("id")))
            agent = record.get("agent") if isinstance(record.get("agent"), dict) else {}
            # ``finding_revision`` is the ledger (project) revision; the run finding's
            # own revision is recorded by the host as ``run_finding_revision``.  Reviews
            # are keyed by the latter, so the exact claim version must use it too.
            revision = agent.get("run_finding_revision")
            if revision is None:
                revision = finding.get("revision") or record.get("finding_revision") or 1
            job_results = {
                str(item.get("job_id")): item
                for item in agent.get("job_results") or []
                if isinstance(item, dict) and item.get("job_id")
            }
            jobs = []
            for job in agent.get("jobs") or []:
                if isinstance(job, dict):
                    jobs.append(job)
                elif str(job) in job_results:
                    jobs.append(job_results[str(job)])
                elif job:
                    # Older records kept the host's job id list without embedding the
                    # result; the id is still a host-issued record, so keep it visible.
                    jobs.append({"job_id": str(job)})
            attempts.append({
                "verification_id": record.get("id"),
                "finding_ref": {
                    "finding_id": finding["id"],
                    "revision": int(revision),
                },
                "ledger_revision": record.get("finding_revision"),
                "context_id": (record.get("target") or {}).get("context_id") or agent.get("context_id") or "",
                "target_version": record.get("target_version") or "",
                "job_refs": [
                    {
                        "job_id": job.get("job_id"),
                        "kind": job.get("kind"),
                        "status": (job.get("result") or {}).get("status") or job.get("status") or "",
                        "exit_code": (job.get("result") or {}).get("exit_code", job.get("exit_code")),
                    }
                    for job in jobs if isinstance(job, dict)
                ],
                "normal_evidence": record.get("normal_observation") or "",
                "attack_evidence": record.get("attack_observation") or "",
                "fact_availability": verification_fact_availability(record),
                "conclusion_reason": agent.get("reason") or "",
                "execute_reason": (agent.get("usage") or {}).get("execute_reason") or "",
                "observed_job_ids": list(job_results),
                "final_script": record.get("modified_script") or "",
                "artifacts": list(record.get("artifacts") or []),
                "execution_status": record.get("execution_status") or "",
                "verdict": record.get("verdict") or "",
                "status": record.get("status") or "",
                "source": record.get("source") or "",
                "inherited_from": agent.get("continuation_source") or None,
                "browser_execution": bool(record.get("browser_execution")),
                "notes": record.get("notes") or "",
            })
    return attempts


def reviews(findings: list[dict]) -> list[dict]:
    records, seen = [], set()
    for finding in findings:
        for review in finding.get("verification_reviews") or []:
            if str(review.get("id")) in seen:
                continue
            seen.add(str(review.get("id")))
            records.append({
                "review_id": review.get("id"),
                "finding_ref": {"finding_id": finding["id"],
                                "revision": int(review.get("revision") or 1)},
                "verification_id": review.get("verification_id") or "",
                "decision": review.get("decision") or "",
                "rationale": review.get("rationale") or "",
                "observed_normal": review.get("observed_normal") or "",
                "observed_attack": review.get("observed_attack") or "",
                "created_at": review.get("created_at") or "",
            })
    return records


# --- bounded review batch ---------------------------------------------------


def build_review_batch(run_id: str, epoch: Any, facts: dict) -> dict:
    """The host's frozen input list for one bounded final-review stage.

    Only canonical current claims are in scope: the review decides the disposition of a
    conclusion; it does not get to discover new tasks or re-open the audit graph.
    """
    items = []
    for entry in facts["canonical_findings"][:MAX_REVIEW_ITEMS]:
        claim = entry["frozen_claim"]
        items.append({
            "item_id": entry["canonical_id"],
            "finding_id": claim["finding_id"],
            "revision": claim["revision"],
            "verification_id": claim["verification_id"],
            "verification_status": claim["verification_status"],
            "conflicts": [item["kind"] for item in entry["conflicts"]],
            "suggested_disposition": entry["final_disposition"],
        })
    payload = json.dumps(
        {"run_id": run_id, "epoch": epoch,
         "items": [(item["item_id"], item["revision"], item["verification_id"]) for item in items]},
        ensure_ascii=False, sort_keys=True,
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return {
        "version": REVIEW_BATCH_VERSION,
        "batch_id": digest[:16],
        "run_id": run_id,
        "epoch": epoch,
        "input_hash": digest,
        "item_refs": items,
        "decisions": [],
        "unresolved_items": [item["item_id"] for item in items],
    }


def apply_review_batch(batch: dict, decisions: list[dict]) -> tuple[list[dict], list[str]]:
    """Validate exact one-decision-per-item; return accepted decisions and errors.

    The batch is complete only when every claimed item has exactly one decision.  A
    missing item is not "keep by default", and an unknown or stale item is an error,
    not an extra conclusion.
    """
    errors: list[str] = []
    claimed = {item["item_id"]: item for item in batch.get("item_refs") or []}
    seen: set[str] = set()
    accepted: list[dict] = []
    for decision in decisions:
        item_id = str(decision.get("item_id") or "")
        if item_id in seen:
            errors.append(f"duplicate_decision:{item_id}")
            continue
        item = claimed.get(item_id)
        if item is None:
            errors.append(f"unknown_item:{item_id}")
            continue
        seen.add(item_id)
        choice = str(decision.get("decision") or "")
        if choice not in REVIEW_DECISIONS:
            errors.append(f"invalid_decision:{item_id}:{choice}")
            continue
        if choice in {"duplicate", "withdraw", "revise"} and not str(decision.get("rationale") or "").strip():
            errors.append(f"missing_rationale:{item_id}")
            continue
        if choice == "duplicate" and not str(decision.get("duplicate_of") or "").strip():
            errors.append(f"missing_duplicate_target:{item_id}")
            continue
        if int(decision.get("revision") or 0) not in {0, int(item["revision"])}:
            errors.append(f"stale_revision:{item_id}")
            continue
        accepted.append({**decision, "item_id": item_id})
    missing = sorted(set(claimed) - seen)
    if missing:
        errors.append("missing_decisions:" + ",".join(missing))
    return accepted, errors


def items_by_id(facts: dict) -> dict[str, dict]:
    return {entry["canonical_id"]: entry for entry in facts.get("canonical_findings") or []}
