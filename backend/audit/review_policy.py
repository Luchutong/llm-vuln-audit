"""Bounded review costs and explicit peer judgments; no automatic sign-off."""

COMPARISON_POLICY = "explicit-peers-v1"


def batch_response_reserve(items, *, corrections=2):
    # Exact-field pagination is host work and consumes no model requests. Semantic
    # publication has one first attempt and at most two corrections across all rounds.
    return 1 + min(2, max(0, corrections))


def validate_peer_assessments(decisions, current):
    by_id = {decision["item_id"]: decision for decision in decisions}
    problems = []
    for decision in decisions:
        if decision["decision"] not in {"accept", "duplicate"}:
            continue
        item = current[decision["item_id"]]
        peers = {peer["item_id"] for peer in item.get("payload", {}).get("comparison_candidates", [])}
        assessments = decision.get("comparison_assessments") or []
        supplied = [a["item_id"] for a in assessments]
        field = f"review_decisions[{decision['item_id']}].comparison_assessments"
        if len(supplied) != len(set(supplied)) or set(supplied) - peers:
            problems.append(f"{field} 只能逐项引用本项 comparison_candidates 的规范 item_id，不能使用运行 finding_id 或重复项；"
                            f"允许的 item_id：{','.join(sorted(peers))}")
        for assessment in assessments:
            if (assessment.get("relation") not in {"same_root", "distinct", "unresolved"}
                    or len(str(assessment.get("rationale") or "").strip()) < 12):
                problems.append(f"{field}[{assessment['item_id']}] 须填写 relation=same_root|distinct|unresolved，"
                                "以及 rationale（至少12字的实际根因／操作／前提判读）；没有 relation_note 字段")
        judged = {a["item_id"]: a for a in assessments}
        if decision["decision"] == "duplicate":
            target = decision.get("duplicate_of")
            if target not in judged or judged[target]["relation"] != "same_root":
                problems.append(f"{field}[{target}]：duplicate 须对 duplicate_of 的规范 item_id 明确提交 "
                                "relation=same_root 与 rationale，说明实际根因依据")
            continue
        retained = {peer for peer in peers if by_id.get(peer, {}).get("decision") not in {"duplicate", "withdraw"}}
        for peer in sorted(retained):
            if peer not in judged or judged[peer]["relation"] != "distinct":
                problems.append(f"{field}[{peer}]：accept 须提交 {{item_id:{peer},relation:distinct,rationale:具体差异至少12字}}；"
                                "不能只填 distinct_from。same_root 应 duplicate 并选保留主结论；本批其他项可指向该主结论，"
                                "未决应 needs_evidence，不能为接受捏造 distinct")
    if problems:
        raise ValueError("候选对照逐项要求：" + "；".join(problems))
