"""Bounded review costs and explicit peer judgments; no automatic sign-off."""

COMPARISON_POLICY = "explicit-peers-v1"


def batch_response_reserve(items, *, corrections=2):
    # Reader requests must leave room for the first publication and its corrections.
    return 1 + min(2, max(0, corrections)) + (2 if any(i.get("paged_fields") for i in items) else 0)


def validate_peer_assessments(decisions, current):
    by_id = {decision["item_id"]: decision for decision in decisions}
    for decision in decisions:
        if decision["decision"] not in {"accept", "duplicate"}:
            continue
        item = current[decision["item_id"]]
        peers = {peer["item_id"] for peer in item.get("payload", {}).get("comparison_candidates", [])}
        assessments = decision.get("comparison_assessments") or []
        supplied = [a["item_id"] for a in assessments]
        if len(supplied) != len(set(supplied)) or set(supplied) - peers:
            raise ValueError("comparison_assessments 只能逐项引用本项 comparison_candidates 的规范 item_id，不能使用运行 finding_id 或重复项")
        if any(a.get("relation") not in {"same_root", "distinct", "unresolved"}
               or len(str(a.get("rationale") or "").strip()) < 12 for a in assessments):
            raise ValueError("comparison_assessments 每项须有合法关系和至少12字的实际根因／操作／前提判读")
        judged = {a["item_id"]: a for a in assessments}
        if decision["decision"] == "duplicate":
            target = decision.get("duplicate_of")
            if target not in judged or judged[target]["relation"] != "same_root":
                raise ValueError("duplicate 须对 duplicate_of 的规范 item_id 明确提交 same_root 判读和实际根因依据")
            continue
        retained = {peer for peer in peers if by_id.get(peer, {}).get("decision") not in {"duplicate", "withdraw"}}
        if any(peer not in judged or judged[peer]["relation"] != "distinct" for peer in retained):
            raise ValueError("accept 须逐项说明保留对照的 distinct 根因／操作／前提差异；same_root 应 duplicate，unresolved 应 needs_evidence，不能只填 distinct_from")
        if any(len(str(judged[peer].get("rationale") or "").strip()) < 12 for peer in retained):
            raise ValueError("每项 distinct 判读须说明实际根因／危险操作／利用前提差异，评分与 POC 状态不同不构成差异")
