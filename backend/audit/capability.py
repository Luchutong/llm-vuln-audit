"""New-run capability contract. Legacy runs deliberately have no implicit upgrade."""
from __future__ import annotations

POLICY = "audit-capability-v1"
RELATIONS = {"relevant", "supporting", "incidental", "unresolved"}
POC_SCOPE_POLICY = "explicit-scenario-v1"


def enabled(run):
    return (run.get("task_spec") or {}).get("capability_policy") == POLICY


def freeze_focus(task):
    return {"version": "audit-focus/v1", "objective_ref": "objective-main",
            "objective": task["objective"], "scenario": task.get("scenario"),
            "scope": task.get("focus_scope", "targeted"),
            "sources": [{"kind": "user_objective", "text": task["objective"]},
                        *([{"kind": "explicit_scenario", "value": task["scenario"]}] if task.get("scenario") else [])],
            "policy": "源码整包可读；旁路发现保留，但仅独立复核为 relevant 的结论可支撑目标。supporting 须有真实必要链路，不能独立达成。"}


def focus_evidence_ranges(claim):
    """Union adjacent validated citations without bridging an unread source gap."""
    from .evidence import seen_ranges
    refs = []
    for ref in claim.get('evidence') or []:
        left = (ref.get('range') or {}).get('start', ref.get('start_line'))
        right = (ref.get('range') or {}).get('end', ref.get('end_line'))
        if isinstance(ref.get('path'), str) and type(left) is int and type(right) is int and 0 < left <= right:
            refs.append(dict(path=ref['path'], start_line=left, end_line=right))
    return [dict(path=path, start_line=left, end_line=right)
            for path, left, right in seen_ranges({}, refs, exact=True)]


def validate_focus(run, assessment, *, claim, known_ids=(), obligations=()):
    """Validate ownership/structure; semantic judgment remains the independent review.

    Shared includes are navigation, never an input->sink proof. Evidence ranges must
    be a subset of the host-validated claim, and cannot name another snapshot.
    """
    if not enabled(run):
        return
    if not assessment or assessment.get("objective_ref") != "objective-main" or assessment.get("relation") not in RELATIONS:
        raise ValueError("须独立提交 focus：objective_ref=objective-main、relation 与目标关联依据；不能用 worker 的自标代替复核")
    if len(str(assessment.get("rationale") or "").strip()) < 12:
        raise ValueError("focus.rationale 须说明用户目标与具体输入、业务边界及危险操作的关联")
    relation = assessment["relation"]
    if relation in {"incidental", "unresolved"}:
        return
    refs = assessment.get("evidence") or []
    allowed = focus_evidence_ranges(claim)
    def contains(ref):
        return (type(ref.get('start_line')) is int and type(ref.get('end_line')) is int and any(
                   ref.get("path") == r['path'] and r['start_line'] <= ref['start_line'] <= ref['end_line'] <= r['end_line']
                   for r in allowed)
                )
    if not refs or any(not contains(ref) for ref in refs):
        import json
        raise ValueError("focus.evidence 必须来自本结论实际读取并校验的源码区间；本项允许的连续区间："
                         + json.dumps(allowed, ensure_ascii=False, separators=(',', ':')))
    scenario = (run.get("task_spec") or {}).get("scenario")
    from .worker_strategies import canonical_vulnerability_type
    if relation == "relevant" and scenario and canonical_vulnerability_type(claim.get("vulnerability_type")) != canonical_vulnerability_type(scenario):
        raise ValueError("显式分场景中的其他漏洞类型只能作为经复核的 supporting/incidental，不能直接 relevant")
    if relation == "supporting":
        targets = set(assessment.get("supports") or [])
        if not targets or targets - (set(known_ids) | set(obligations)):
            raise ValueError("supporting 必须引用本运行实际的目标主张或风险义务")
        flow = assessment.get("chain") or []
        if not {"input", "sink"} <= {node.get("kind") for node in flow}:
            raise ValueError("supporting 须给出必要的数据/状态依赖 input→sink；共享 include 不是依赖证明。"
                "risk_outcome=supported 只表示风险有 finding 支持，不要求 relation=supporting；"
                "若本项自身属于目标，独立判断 relevant 并引用本项证据；依赖尚未证明时保留 pending/blocked")
        if any(not contains(node.get("evidence") or {}) for node in flow):
            raise ValueError("必要依赖链每个节点必须绑定本结论实际读取的源码行")


def focus_summary(entries):
    counts = {relation: 0 for relation in RELATIONS}
    for entry in entries:
        assessment = (entry.get("final_batch_review") or {}).get("focus") or {}
        counts[assessment.get("relation") if assessment.get("relation") in RELATIONS else "unresolved"] += 1
    return {"version": "audit-focus/v1", **counts,
            "complete": counts["unresolved"] == 0,
            "goal_supporting_ids": [e["canonical_id"] for e in entries if e.get("final_disposition") == "accepted"
                                    and ((e.get("final_batch_review") or {}).get("focus") or {}).get("relation") == "relevant"]}


def poc_in_focus(run, finding, *, known_ids=()):
    """Cost admission, never a finding disposition or an assertion of safety.

    Unknown types remain eligible. An explicit retest overrides automatic routing;
    a supporting chain still needs source-bound references and a real owned target.
    """
    task = run.get("task_spec") or {}
    if not enabled(run) or task.get("poc_scope_policy") != POC_SCOPE_POLICY:
        return True
    continuation = task.get("continuation") or {}
    if finding.get("id") in (continuation.get("retest_finding_ids") or []):
        return True
    if task.get("focus_scope", "targeted") != "targeted" or not task.get("scenario"):
        return True
    from .worker_strategies import canonical_vulnerability_type
    actual = canonical_vulnerability_type(finding.get("vulnerability_type"))
    if actual in {None, "", "unknown", "other"} or actual == canonical_vulnerability_type(task["scenario"]):
        return True
    focus = finding.get("focus") or {}
    if focus.get("relation") != "supporting":
        return False
    try:
        validate_focus(run, focus, claim=finding, known_ids=known_ids,
                       obligations=[item["id"] for item in (task.get("risk_obligation_set") or {}).get("items") or []])
    except (ValueError, TypeError):
        return False
    return True


def outcome(run, coverage, entries, *, risk=None):
    """A versioned policy projection, never a retrospective rewrite of legacy facts."""
    from .report_readable import delivery_gaps
    def gaps(entry):
        return delivery_gaps(entry, run.get("task_spec"))
    focus = focus_summary(entries)
    mode = (run.get("poc_policy") or {}).get("mode", "off")
    verification = coverage["verification"]
    verified_relevant = [e for e in entries if e["canonical_id"] in focus["goal_supporting_ids"]
                         and e["frozen_claim"].get("verification_status") == "verified"
                         and e["frozen_claim"].get("verified_compatible") is True]
    dynamic_met = mode != "required" or bool(verified_relevant)
    source_required = (run.get("task_spec") or {}).get("completion_policy") == "coverage_review"
    sources_met = not source_required or coverage["files"]["complete"] is True
    directions_met = coverage["directions"]["complete"] is not False
    final_met = coverage["final_review"]["pending"] == 0
    risk_met = not risk or risk.get("complete") is True
    # A completed source review with zero findings is still not a goal-success claim.
    focus_met = focus["complete"] and bool(focus["goal_supporting_ids"])
    complete = bool(run.get("status") == "completed" and sources_met and directions_met and risk_met
                    and focus_met and final_met and dynamic_met and not verification.get("pending_review"))
    return {"status": run.get("status"), "stop_reason": (run.get("execution_summary") or {}).get("stop_reason"),
            "policy_version": POLICY, "coverage_complete": coverage["files"]["complete"],
            "directions_complete": coverage["directions"]["complete"], "verification_complete": dynamic_met,
            "audit_complete": complete,
            "dimensions": {"execution_status": run.get("status"), "focus_complete": focus_met,
                           "source_review_complete": sources_met and directions_met,
                           "risk_obligations_complete": risk_met,
                           "dynamic_verification": {"mode": mode, "requirement_met": dynamic_met,
                                                    "verified": verification.get("verified"),
                                                    "pending": verification.get("pending"),
                                                    "policy": "至少一条目标相关兼容验证" if mode == "required" else "不设动态通过数量门槛"},
                           "final_review_complete": final_met,
                           "delivery_readiness": {"complete": all(not gaps(e) for e in entries),
                                                  "basis": "材料填写完整性检查，不代替修复正确性与回归有效性的独立复核。",
                                                  "gaps": [{"canonical_id": e["canonical_id"], "items": gaps(e)}
                                                           for e in entries if gaps(e)]}},
            "focus": focus}
