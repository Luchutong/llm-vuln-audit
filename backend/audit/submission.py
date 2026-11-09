"""Host-owned references and examples. Never pre-author a semantic sign-off."""
from __future__ import annotations


def review_contract(batch):
    if not batch:
        return {}
    items = batch.get("items") or []
    batch_ids = {item["item_id"] for item in items}
    return {
        "version": "review-submission/v1", "batch_id": batch["id"],
        "items": [{"item_id": item["item_id"], "revision": item["revision"], "kind": item["kind"],
                   **({"direction_resolution": item["payload"]["resolution_context"]}
                      if (item.get("payload") or {}).get("resolution_context") else {}),
                   "peer_comparison_contract": [{"item_id": peer["item_id"], "finding_id_alias": peer.get("finding_id"),
                       "in_current_batch": peer["item_id"] in batch_ids,
                       "relation": "same_root|distinct|unresolved", "rationale": "实际根因／危险操作／前提差异，至少12字"}
                       for peer in item.get("payload", {}).get("comparison_candidates", [])],
                   "focus_evidence_ranges": [{"path": ref.get("path"), "start_line": (ref.get("range") or {}).get("start"),
                                              "end_line": (ref.get("range") or {}).get("end")} for ref in item.get("payload",{}).get("evidence") or []],
                   "allowed_decisions": (["resolve", "needs_evidence"] if (item.get("payload", {}).get("resolution_context") or {}).get("requirement") == "required"
                                         else ["resolve", "needs_evidence", "skip"]) if item["kind"] in {"direction", "risk"} else
                   (["accept", "needs_evidence", "contested", "duplicate", "withdraw"] if batch["phase"] == "final" else
                    ["retain", "needs_evidence", "contested", "duplicate", "withdraw"]),
                   **({"verification_review_ref": {"finding_id": item["finding_id"], "revision": item["finding_revision"],
                                                    "verification_id": item.get("verification_id")},
                       "verification_review_required_fields": ["decision:confirmed|contested", "rationale_summary:真实双侧观测判读"]}
                      if item.get("requires_verification_review") else {})} for item in items],
        "fill_in": ["独立处置与具体 rationale", "目标关联 focus（新任务）", "需要时的正常/攻击判读 rationale_summary",
                    "逐项 comparison_assessments（item_id、relation、rationale），真实不同才写入 distinct_from"],
        "verification_review_refs": [{"item_id": item["item_id"], "finding_id": item["finding_id"],
            "revision": item["finding_revision"], "verification_id": item["verification_id"],
            "required_for_accept": bool(item.get("requires_verification_review"))}
            for item in items if batch["phase"] == "final" and item.get("verification_status") == "verified" and item.get("verification_id")],
        "verification_review_policy": "verification_reviews 只能引用 verification_review_refs 的 finding_id/revision/verification_id；"
            "inconclusive/unverified 不在此列表，禁止为其提交 confirmed/contested 动态复核。"
            "有原作业但没有完整双侧结论时可独立静态审查，不能补造动态确认。",
        "focus_contract": {"objective_ref": "objective-main", "relation": "relevant|supporting|incidental|unresolved",
                           "rationale": "独立判断目标与实际源码操作的关系，至少12字",
                           "evidence_format": {"path": "逐项复制本 item payload.evidence 内实际路径", "start_line": "区间内原始起始行", "end_line": "区间内原始结束行"},
                           "notice": "不是 evidence_id/range 对象。支持 relevant/supporting 必须给出区间，不能复制另一项的引用。"},
        "read_policy": "引用不是读取凭据；先完整读取本项分页字段及实际源码。宿主不预填完整读取、接受、确认或差异判读。",
        "risk_support_policy": "全量探索的 risk_outcome=supported 须提供实际 finding_ids，只能取自本项 payload.findings 的当前有效结论；"
                               "SQL 注入必须由以本项操作行（主定位或明确执行行）为准的结论支持；"
                               "命令注入/代码执行若该 sink 是同一利用链的落点（例如反序列化触发 __wakeup、控制器包含进入 eval），"
                               "可引用该链根因结论，但其 evidence 必须实际覆盖本项操作行，且 dangerous_operation/propagation/summary 明确写出本项文件；"
                               "两个互不相关的 sink 不能用一段共同证据合报结清。payload.findings 是导航事实，不是既定判决。"
                               "无漏洞用 no_evidence 并说明实际防护依据。",
        "peer_policy": "duplicate_of、distinct_from、comparison_assessments.item_id 均使用规范 item_id，不能复制运行 finding_id。"
                       "accept 对保留对照须同时提交 comparison_assessments=[{item_id,relation:distinct,rationale}] 与 distinct_from，逐项说明真实差异；"
                       "同根因须 duplicate 并选主结论，未决用 needs_evidence。评分／POC 差别不是根因差别。",
    }


def review_schema(schema, batch, *, allow_direction_updates=False):
    """Advertise only review actions and their reachable field definitions.

    Validation still uses the full PlannerDecision and the Store's exact-version
    checks. Removing unrelated scheduling examples leaves room for actual facts.
    """
    names = {"goal_state", "basis_summary", "review_batch_id", "review_decisions", "verification_reviews"}
    if allow_direction_updates:
        names.add("direction_updates")
    schema["properties"] = {key: value for key, value in schema["properties"].items() if key in names}
    schema["properties"]["goal_state"] = {"const": "continue"}
    schema["properties"]["review_batch_id"] = {"const": batch["id"]}
    if batch["phase"] != "final":
        schema["properties"]["verification_reviews"]["maxItems"] = 0
    definitions = schema.get("$defs", {})
    used = set()

    def visit(value):
        if isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, dict):
            ref = value.get("$ref", "")
            if ref.startswith("#/$defs/"):
                name = ref.removeprefix("#/$defs/")
                if name not in used:
                    used.add(name)
                    visit(definitions[name])
            for item in value.values():
                visit(item)

    visit(schema["properties"])
    schema["$defs"] = {key: value for key, value in definitions.items() if key in used}
    return schema


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


def worker_evidence_reference():
    """Synthetic wire examples, independent of any audited project or answers."""
    def ref(path, start, end=None):
        return dict(path=path, start_line=start, end_line=start if end is None else end)
    def node(kind, path, line, explanation):
        return dict(kind=kind, evidence=ref(path, line), explanation=explanation)
    def claim(title, category, path, line, flow):
        return dict(title=title, kind="vulnerability", vulnerability_type=category,
            summary="此处仅演示已经读取的来源、根因与敏感操作如何填写；实际审计必须重新独立取证。",
            primary_location=dict(path=path, line=line),
            evidence="; ".join(f"{n['evidence']['path']}:{n['evidence']['start_line']}-{n['evidence']['end_line']}" for n in flow),
            dataflow=flow)
    examples = [
        dict(case="根因与操作同处", finding=claim("演示：查询直接执行拼接输入", "sqli", "demo/search.php", 4, [
            node("input", "demo/search.php", 3, "请求参数在此处进入搜索词变量。"),
            node("sink", "demo/search.php", 4, "该行拼接并执行 SQL，根因与危险操作同处。")]),
            source_assumption="仅在实际读取证明第3行取参、第4行拼接并执行查询时，才可这样标注。"),
        dict(case="跨文件输入到操作", finding=claim("演示：调用参数进入仓库查询", "sqli", "demo/repository.php", 8, [
            node("input", "demo/controller.php", 3, "请求参数传入当前审计的仓库函数。"),
            node("sink", "demo/repository.php", 8, "函数拼接参数并执行 SQL，主定位保留在此操作行。")]),
            source_assumption="必须实际读取调用者、被调用者及必要传播上下文；跨文件不要求相同路径。"),
        dict(case="错误身份判断与后续操作分离", finding=claim("演示：客户端角色决定敏感操作权限", "auth_bypass", "demo/guard.php", 5, [
            node("input", "demo/guard.php", 3, "客户端请求中的角色值进入身份判断。"),
            node("root_cause", "demo/guard.php", 5, "该行信任可伪造角色放行，导致下游敏感操作可达。"),
            node("sink", "demo/action.php", 9, "被该错误边界保护的敏感写入在此执行。")]),
            source_assumption="读取并证明 guard 的放行结果确实控制 action；不能因路径共享或函数名猜测因果。"),
        dict(case="不当字段授权与后续写入分离", finding=claim("演示：不当授权字段进入账户写入", "mass_assignment", "demo/update.php", 5, [
            node("input", "demo/update.php", 3, "请求携带待更新的字段名和字段值。"),
            node("root_cause", "demo/update.php", 5, "该行允许普通账号提交敏感列，形成字段授权缺陷。"),
            node("sink", "demo/update.php", 8, "已获不当授权的字段在此处写入账户记录。")]),
            source_assumption="须读取字段授权与写入语句；不能将一个普通赋值操作直接认定为授权缺陷。"),
    ]
    return dict(version="worker-dataflow-v2", notice="所有 demo/ 路径与行号均为合成结构参考，不属于当前快照，不授予读取凭据，不得直接提交这些示例。",
        rules=["每条 finding 至少包含真实 input 与 sink 节点；input 可是请求、持久化数据或配置来源。",
               "primary_location 是真实根因坐标；没有显式 root_cause 时，须由同位置 sink 覆盖。",
               "根因与 sink 分离时，用唯一 root_cause 节点覆盖主定位，保留原 sink；节点按本条链的逻辑顺序解释。",
               "覆盖指路径完全相同且 start_line <= primary_location.line <= end_line。引用的每一行都须实际读取。",
               "宿主校验坐标与读取，独立审查判断因果与漏洞是否成立；不能为通过格式改变事实。"],
        examples=examples,
        negative_examples=[dict(case="主定位落在普通 input/transform，sink 位于别处，却未给 root_cause",
            remedy="先核对真正根因；仅在该处确为缺陷时显式给 root_cause。不要机械改 kind 或移动主定位。"),
            dict(case="将 sink 引用拉长以包住另一行，区间包含未读行",
                 remedy="分别保留真实节点区间；补读决定性源码或保持 pending，不能制造读取凭据。")],
        disproof_example=dict(basis="effective_protection", rationale="仅当已读源码证明本输入路径实际使用参数绑定且不存在结构拼接时，才能排除此具体注入风险。",
                              evidence=[ref("demo/safe-query.php", 4, 5)]))
