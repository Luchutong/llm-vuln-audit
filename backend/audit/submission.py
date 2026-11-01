"""Host-owned references and examples. Never pre-author a semantic sign-off."""
from __future__ import annotations


def review_contract(batch):
    if not batch:
        return {}
    items = batch.get("items") or []
    return {
        "version": "review-submission/v1", "batch_id": batch["id"],
        "items": [{"item_id": item["item_id"], "revision": item["revision"], "kind": item["kind"],
                   "peer_comparison_contract": [{"item_id": peer["item_id"], "finding_id_alias": peer.get("finding_id"),
                       "relation": "same_root|distinct|unresolved", "rationale": "实际根因／危险操作／前提差异，至少12字"}
                       for peer in item.get("payload", {}).get("comparison_candidates", [])],
                   "focus_evidence_ranges": [{"path": ref.get("path"), "start_line": (ref.get("range") or {}).get("start"),
                                              "end_line": (ref.get("range") or {}).get("end")} for ref in item.get("payload",{}).get("evidence") or []],
                   "allowed_decisions": ["resolve", "needs_evidence", "skip"] if item["kind"] in {"direction", "risk"} else
                   (["accept", "needs_evidence", "contested", "duplicate", "withdraw"] if batch["phase"] == "final" else
                    ["retain", "needs_evidence", "contested", "duplicate", "withdraw"]),
                   **({"verification_review_ref": {"finding_id": item["finding_id"], "revision": item["finding_revision"],
                                                    "verification_id": item.get("verification_id")},
                       "verification_review_required_fields": ["decision:confirmed|contested", "rationale_summary:真实双侧观测判读"]}
                      if item.get("requires_verification_review") else {})} for item in items],
        "fill_in": ["独立处置与具体 rationale", "目标关联 focus（新任务）", "需要时的正常/攻击判读 rationale_summary",
                    "实际候选差异 distinct_from（不能自动全选）"],
        "focus_contract": {"objective_ref": "objective-main", "relation": "relevant|supporting|incidental|unresolved",
                           "rationale": "独立判断目标与实际源码操作的关系，至少12字",
                           "evidence_format": {"path": "逐项复制本 item payload.evidence 内实际路径", "start_line": "区间内原始起始行", "end_line": "区间内原始结束行"},
                           "notice": "不是 evidence_id/range 对象。支持 relevant/supporting 必须给出区间，不能复制另一项的引用。"},
        "read_policy": "引用不是读取凭据；先完整读取本项分页字段及实际源码。宿主不预填完整读取、接受、确认或差异判读。",
        "peer_policy": "duplicate_of、distinct_from、comparison_assessments.item_id 均使用规范 item_id，不能复制运行 finding_id。"
                       "accept 对保留对照须同时提交 comparison_assessments=[{item_id,relation:distinct,rationale}] 与 distinct_from，逐项说明真实差异；"
                       "同根因须 duplicate 并选主结论，未决用 needs_evidence。评分／POC 差别不是根因差别。",
    }


def review_example(batch):
    return {"goal_state": "continue", "basis_summary": "逐项审查当前冻结输入；证据不足的项保留待审。", "tasks": [],
            "review_batch_id": batch["id"],
            "review_decisions": [{"item_id": item["item_id"], "revision": item["revision"],
                                  "decision": "needs_evidence", "rationale": "请替换为本项缺少的具体证据与下一步措施。",
                                  "comparison_assessments": [{"item_id": peer["item_id"], "relation": "unresolved",
                                      "rationale": "此处仅示范结构，须读取双方实际根因与操作后独立判读。"}
                                      for peer in item.get("payload", {}).get("comparison_candidates", [])],
                                  **({"focus": {"objective_ref": "objective-main", "relation": "unresolved",
                                               "rationale": "此处仅示范字段结构，须根据原始目标和本项源码独立判读。", "evidence": [], "supports": [], "chain": []}}
                                     if item["kind"] in {"finding", "risk"} else {}),
                                  **({"risk_outcome": "pending"} if item["kind"] == "risk" else {})}
                                 for item in batch.get("items") or []]}


def worker_example():
    return {"outcome": "blocked", "summary": "请填写当前源码实际支持的结论与缺口。", "reasoning": "请填写可公开复核的具体依据。",
            "findings": [], "missing_context": ["仅在确实缺少源码/运行前提时填写；不要把工具额度停止当成安全结论。"]}
