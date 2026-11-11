"""Host-owned references and examples. Never pre-author a semantic sign-off."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

from .review_policy import allowed_review_decisions, bind_peer_indices


def reference_coordinates(item):
    """Small host-owned coordinates survive paging; they grant no read receipts."""
    if item.get("reference_coordinates") is not None:
        return deepcopy(item["reference_coordinates"])
    payload = item.get("payload") or {}
    return {
        "peers": [{key: peer.get(key) for key in ("item_id", "finding_id", "revision")}
                  for peer in payload.get("comparison_candidates") or []],
        "corroborations": [{key: ref.get(key) for key in ("finding_id", "revision", "task_key", "evidence")}
                           for ref in payload.get("worker_references") or []],
        "evidence": [{"path": ref.get("path"),
                      "start_line": (ref.get("range") or {}).get("start", ref.get("start_line")),
                      "end_line": (ref.get("range") or {}).get("end", ref.get("end_line"))}
                     for ref in payload.get("evidence") or []],
        "notice": "引用坐标不是源码或已读凭据；分页正文必须实际传送并审阅。",
    }


def focus_references(item):
    from .capability import focus_evidence_ranges
    ranges = focus_evidence_ranges({'evidence': reference_coordinates(item)['evidence']})
    return [dict(reference_id='src_' + hashlib.sha256(json.dumps(
        [item['item_id'], item['revision'], ref], sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16], **ref)
        for ref in ranges]


def bind_review_submission(payload, batch):
    """Bind logistics to the lease, without supplying any semantic decision."""
    if not isinstance(payload, dict):
        raise ValueError("审查发布必须为一个 JSON 对象")
    result = deepcopy(payload)
    allowed = {"goal_state", "basis_summary", "review_batch_id", "review_decisions", "verification_reviews", "direction_updates"}
    for key in set(result) - allowed:
        if key in {"tasks", "updates", "project_updates", "coverage_review", "missing_context", "next_action", "report"} and not result[key]:
            result.pop(key)
        else:
            raise ValueError(f"审查发布顶层不允许字段 {key}；verification_reviews 仅放在顶层")
    if result.get("review_batch_id", batch["id"]) != batch["id"]:
        raise ValueError("review_batch_id 不属于当前审查租约")
    result["review_batch_id"] = batch["id"]
    items = {item["item_id"]: item for item in batch["items"]}
    values = result.get("review_decisions")
    if not isinstance(values, list) or len(values) != len(items):
        raise ValueError("review_decisions 必须对当前批次每项恰好提交一次")
    for index, value in enumerate(values):
        if not isinstance(value, dict):
            raise ValueError("review_decisions 每项必须为对象")
        value.setdefault("item_id", batch["items"][index]["item_id"])
        if not isinstance(value["item_id"], str):
            raise ValueError("review_decisions.item_id 必须是当前租约中的字符串 ID")
        item = items.get(value["item_id"])
        if not item or value.get("revision", item["revision"]) != item["revision"]:
            raise ValueError("review_decisions 的 item_id/revision 不属于当前冻结版本")
        value["revision"] = item["revision"]
        if item['kind'] == 'direction':
            for field in ('risk_outcome','focus','duplicate_of','distinct_from','comparison_assessments'):
                if value.get(field) not in (None, [], {}):
                    raise ValueError(f"review_decisions[{item['item_id']}].{field}：direction 不允许此字段；只提交当前项的合法动作与依据")
                value.pop(field, None)
            context=(item.get('payload') or {}).get('resolution_context') or {}
            outcomes={r.get('outcome') for r in context.get('worker_results') or []}
            if value.get('decision')=='resolve' and outcomes=={'supported'} and not value.get('finding_ids'):
                ids=context.get('eligible_finding_ids') or [f['id'] for f in context.get('eligible_findings') or []]
                raise ValueError(f"review_decisions[{item['item_id']}].finding_ids：supported 方向 resolve 必须显式选取当前有效 finding ID；可对照 {ids}")
            if value.get('decision')=='resolve' and outcomes=={'no_evidence'} and value.get('finding_ids'):
                raise ValueError(f"review_decisions[{item['item_id']}].finding_ids：no_evidence 方向须为空，引用对应 Worker 的实际源码反证")
        focus = value.get('focus')
        if isinstance(focus, dict) and focus.get('supports'):
            if not isinstance(focus['supports'], list) or any(not isinstance(ident, str) for ident in focus['supports']):
                raise ValueError(f"review_decisions[{item['item_id']}].focus：supports 必须为当前目标 ID 列表")
            targets = item.get('focus_target_refs') or []
            aliases = {}
            for ref in targets:
                for alias in (ref['item_id'], ref['finding_id']):
                    aliases.setdefault(alias, set()).add(ref['item_id'])
            if any(len(aliases.get(ident, ())) > 1 for ident in focus['supports']):
                raise ValueError(f"review_decisions[{item['item_id']}].focus：supports 别名不唯一，请使用规范 item_id")
            focus['supports'] = [next(iter(aliases[ident])) if len(aliases.get(ident, ())) == 1 else ident
                                 for ident in focus['supports']]
        if isinstance(focus, dict) and 'evidence_refs' in focus:
            ids = focus.pop('evidence_refs')
            refs = {ref['reference_id']: {k:v for k,v in ref.items() if k != 'reference_id'} for ref in focus_references(item)}
            if not isinstance(ids, list) or any(not isinstance(ident, str) or ident not in refs for ident in ids):
                raise ValueError(f"review_decisions[{item['item_id']}].focus.evidence_refs 只能引用当前项当前版本的 focus_evidence_refs")
            bound = [refs[ident] for ident in dict.fromkeys(ids)]
            if ids and focus.get('evidence') and focus['evidence'] != bound:
                raise ValueError('focus.evidence 与 evidence_refs 不一致；请选择一种引用格式')
            if ids or not focus.get('evidence'):
                focus['evidence'] = bound
        if item['kind'] == 'risk' and value.get('risk_outcome') not in {
                'supported', 'no_evidence', 'not_applicable', 'blocked', 'pending'}:
            raise ValueError(f"review_decisions[{item['item_id']}].risk_outcome：必须明确填写 supported/no_evidence/not_applicable/blocked/pending；"
                             '这是风险处置结果，不能填 focus.relation 的 relevant/supporting/incidental/unresolved')
        if value.get("decision") not in allowed_review_decisions(item, batch["phase"]):
            raise ValueError(f"review_decisions[{item['item_id']}].decision 只能为 "
                             + ",".join(allowed_review_decisions(item, batch["phase"])))
    result['review_decisions'] = bind_peer_indices(result['review_decisions'])
    refs = {r["finding_id"]: r for r in review_contract(batch)["verification_review_refs"]}
    for value in result.get("verification_reviews") or []:
        if not isinstance(value, dict):
            raise ValueError("verification_reviews 每项必须为顶层数组中的对象")
        ref = refs.get(value.get("finding_id")) if isinstance(value.get("finding_id"), str) else None
        if not ref:
            raise ValueError("verification_reviews 仅允许当前 final 批次中 verified 的 finding_id")
        for key in ("revision", "verification_id"):
            if value.get(key, ref[key]) != ref[key]:
                raise ValueError(f"verification_reviews[{ref['finding_id']}].{key} 与冻结版本不符")
            value[key] = ref[key]
    return result

def review_contract(batch):
    if not batch:
        return {}
    items = batch.get("items") or []
    batch_ids = {item["item_id"] for item in items}
    return {
        "field_hierarchy": {"top_level": ["goal_state", "basis_summary", "review_batch_id", "review_decisions", "verification_reviews"],
                            "review_decisions[]": ["item_id", "revision", "decision", "rationale", "focus", "risk_outcome", "finding_ids", "comparison_assessments", "duplicate_of"],
                            "verification_reviews[]": ["finding_id", "revision", "verification_id", "decision", "rationale_summary"],
                            "notice": "verification_reviews 只在顶层，不能放入 review_decisions；宿主绑定当前 ID/版本，显式给出错误值仍会拒绝。"},
        'fields_by_kind': {
            'direction': ['item_id','revision','decision','rationale','finding_ids'],
            'finding': ['item_id','revision','decision','rationale','focus','comparison_assessments','duplicate_of'],
            'risk': ['item_id','revision','decision','rationale','focus','risk_outcome','finding_ids']},
        "version": "review-submission/v1", "batch_id": batch["id"],
        "items": [{"item_id": item["item_id"], "revision": item["revision"], "kind": item["kind"],
                   **({"direction_resolution": item["payload"]["resolution_context"]}
                      if (item.get("payload") or {}).get("resolution_context") else {}),
                   "peer_comparison_contract": [{"item_id": peer["item_id"], "finding_id_alias": peer.get("finding_id"),
                       "in_current_batch": peer["item_id"] in batch_ids,
                       "relation": "same_root|distinct|unresolved", "rationale": "实际根因／危险操作／前提差异，至少12字"}
                       for peer in reference_coordinates(item)["peers"]],
                   "focus_evidence_ranges": reference_coordinates(item)["evidence"],
                   "focus_evidence_refs": focus_references(item),
                   "focus_target_refs": item.get('focus_target_refs') or [],
                   "allowed_decisions": allowed_review_decisions(item, batch["phase"]),
                   **({'required_fields': ['decision', 'rationale', 'risk_outcome'],
                       'risk_outcome_contract': {
                           'supported': '须由本项实际操作对应的 finding_ids 支持；仍独立判断 focus 目标关系。',
                           'no_evidence': '已核对本项操作的防护或反证，给出具体依据。',
                           'not_applicable': '索引信号不构成该类危险操作，给出具体源码依据。',
                           'pending|blocked': '未结算或缺补证，明确缺口；允许 focus.unresolved。'},
                       'focus_relation_notice': 'risk_outcome=supported 不等于 focus.relation=supporting。'
                           '后者只用于另一目标的必要依赖，必须 supports 和带源码的 input→sink chain；'
                           '本项自身处于审计目标内时独立判断 relevant；结算结果不能配 unresolved。'}
                      if item['kind'] == 'risk' else {}),
                   **({"verification_review_ref": {"finding_id": item["finding_id"], "revision": item["finding_revision"],
                                                    "verification_id": item.get("verification_id")},
                       "verification_review_required_fields": ["decision:confirmed|contested", "rationale_summary:真实双侧观测判读"]}
                      if item.get("requires_verification_review") else {})} for item in items],
        "fill_in": ["独立处置与具体 rationale", "目标关联 focus（新任务）", "需要时的正常/攻击判读 rationale_summary",
                    "逐项 comparison_assessments（item_id、relation、rationale）；distinct_from 由宿主生成，无须重复填写"],
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
                           "preferred_evidence": "evidence_refs:[当前 item 的 focus_evidence_refs.reference_id]；宿主绑定坐标，省略 evidence。",
                           "supports_format": "supporting 必须用 focus_target_refs.item_id 引用目标，并给出 input→sink 必要依赖链；"
                               "表中的 finding_id 是其运行别名，宿主仅在无歧义时转换。直接属于本次目标的风险独立判断 relevant，无需 supports。",
                           "notice": "证据可引用本项已校验连续区间的并集，不能跨未读空隙、扩大到正文上下文或引用同伴证据。宿主只绑定坐标，不代填目标关系或判决。"},
        "read_policy": "引用不是读取凭据；先完整读取本项分页字段及实际源码。宿主不预填完整读取、接受、确认或差异判读。",
        "risk_support_policy": "全量探索的 risk_outcome=supported 须提供实际 finding_ids，只能取自本项 payload.findings 的当前有效结论；"
                               "SQL 注入必须由以本项操作行（主定位或明确执行行）为准的结论支持；"
                               "命令注入/代码执行若该 sink 是同一利用链的落点（例如反序列化触发 __wakeup、控制器包含进入 eval），"
                               "可引用该链根因结论，但其 evidence 必须实际覆盖本项操作行，且 dangerous_operation/propagation/summary 明确写出本项文件；"
                               "两个互不相关的 sink 不能用一段共同证据合报结清。payload.findings 是导航事实，不是既定判决。"
                               "无漏洞用 no_evidence 并说明实际防护依据。",
        "peer_policy": "duplicate_of、distinct_from、comparison_assessments.item_id 均使用规范 item_id，不能复制运行 finding_id。"
                       "accept 对保留对照提交 comparison_assessments=[{item_id,relation:distinct,rationale}]，逐项说明真实差异；distinct_from 索引由宿主生成。"
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
    schema["properties"]["goal_state"] = {"const": "continue", "type": "string"}
    schema["properties"]["review_batch_id"] = {"const": batch["id"], "type": "string"}
    schema["additionalProperties"] = False
    schema["required"] = ["basis_summary", "review_decisions"]
    # Share field definitions rather than duplicating the full decision schema for
    # every item. Each branch still binds its own IDs, revision and legal actions.
    def branch_from(name):
        base = schema["$defs"][name]
        properties = {}
        for key, value in base["properties"].items():
            ref = name + "_" + key
            schema["$defs"].setdefault(ref, deepcopy(value))
            properties[key] = {"$ref": "#/$defs/" + ref}
        return {"type": "object", "properties": properties, "required": list(base.get("required", [])),
                "additionalProperties": False}
    branches = []
    for item in batch["items"]:
        branch = branch_from("PlannerBatchDecision")
        branch["properties"]["item_id"] = {"const": item["item_id"], "type": "string"}
        branch["properties"]["revision"] = {"const": item["revision"], "type": "string"}
        branch["properties"]["decision"] = {"enum": allowed_review_decisions(item, batch["phase"]), "type": "string"}
        if item['kind'] == 'direction':
            fields = {'item_id','revision','decision','rationale','finding_ids'}
            branch['properties'] = {k:v for k,v in branch['properties'].items() if k in fields}
            context=(item.get('payload') or {}).get('resolution_context') or {}
            outcomes={r.get('outcome') for r in context.get('worker_results') or []}
            if outcomes in ({'supported'},{'no_evidence'}):
                ids=context.get('eligible_finding_ids') or [f['id'] for f in context.get('eligible_findings') or []]
                branch['properties']['finding_ids']=dict(type='array',maxItems=min(8,len(ids)),items=dict(type='string',**({'enum':ids} if ids else {})))
                if outcomes=={'supported'}:
                    branch['allOf']=[{'if':{'properties':{'decision':{'const':'resolve'}},'required':['decision']},
                                      'then':{'required':['finding_ids'],'properties':{'finding_ids':{'minItems':1}}}}]
                else:
                    branch['properties']['finding_ids']['maxItems']=0
            branches.append(branch)
            continue
        focus = deepcopy(schema['$defs']['FocusAssessment'])
        # Prefer bound evidence refs; retain typed legacy coordinates without
        # repeating every allowed range here. The common focus gate checks scope.
        refs = focus_references(item)
        focus['properties']['evidence_refs'] = dict(type='array', maxItems=len(refs),
            items={'type':'string', **({'enum':[ref['reference_id'] for ref in refs]} if refs else {})},
            description='优先选当前项的 focus_evidence_refs.reference_id；宿主还原为 evidence 坐标，省略 evidence。')
        branch['properties']['focus'] = {'anyOf':[focus,{'type':'null'}]}
        if item['kind'] == 'risk':
            fields = {'item_id', 'revision', 'decision', 'rationale', 'focus', 'risk_outcome', 'finding_ids'}
            branch['properties'] = {k:v for k,v in branch['properties'].items() if k in fields}
            branch['required'] = list(dict.fromkeys([*branch['required'], 'risk_outcome']))
            branch['properties']['risk_outcome'] = dict(type='string',
                enum=['supported','no_evidence','not_applicable','blocked','pending'])
            ids = sorted({r['finding_id'] for r in item.get('focus_target_refs') or []})
            branch['properties']['finding_ids'] = dict(type='array',maxItems=min(8,len(ids)),
                items=dict(type='string', **({'enum':ids} if ids else {})))
            # Shared property definitions keep the explicit relation branches small.
            focus_fields = {}
            for name,spec in focus['properties'].items():
                key = 'ReviewFocus_' + item['item_id'] + '_' + name
                schema['$defs'][key] = spec
                focus_fields[name] = {'$ref':'#/$defs/' + key}
            relations = []
            targets = sorted({r['item_id'] for r in item.get('focus_target_refs') or []})
            for relation in ['relevant','supporting','incidental','unresolved']:
                props = {**focus_fields,'relation':{'type':'string','const':relation}}
                required = list(focus.get('required') or [])
                if relation == 'supporting':
                    props['supports'] = dict(type='array',minItems=1,maxItems=16,
                        items=dict(type='string',**({'enum':targets} if targets else {})))
                    props['chain'] = dict(type='array',minItems=2,maxItems=24,
                        items={'$ref':'#/$defs/FlowNode'},description='必须包含 input 和 sink，逐节点引用本项已读源码。')
                    required.extend(['supports','chain'])
                relations.append(dict(type='object',additionalProperties=False,properties=props,required=required))
            branch['properties']['focus'] = {'anyOf':[*relations,{'type':'null'}]}
            settled = deepcopy(branch)
            settled['properties']['risk_outcome']['enum'] = ['supported','no_evidence','not_applicable']
            settled['properties']['focus'] = {'anyOf':relations[:3]}
            settled['required'] = [*settled['required'],'focus']
            pending = deepcopy(branch)
            pending['properties']['risk_outcome']['enum'] = ['pending','blocked']
            # Every alternative is a complete object, also valid for strict providers.
            branch['anyOf'] = [settled,pending]
            branches.append(branch)
            continue
        peers = sorted({peer["item_id"] for peer in reference_coordinates(item)["peers"]})
        assessment = deepcopy(schema["$defs"]["PeerAssessment"])
        assessment["properties"]["item_id"] = {"type": "string", **({"enum": peers} if peers else {})}
        branch["properties"]["comparison_assessments"] = {
            "type": "array", "maxItems": len(peers), "items": assessment}
        branch["properties"].pop("distinct_from", None)
        targets = sorted(set(peers) | {i["item_id"] for i in batch["items"]
                                     if i["kind"] == "finding" and i["item_id"] != item["item_id"]})
        branch["properties"]["duplicate_of"] = ({"anyOf": [{"type": "string", "enum": targets}, {"type": "null"}]}
                                                if targets else {"type": "null"})
        branches.append(branch)
    schema["properties"]["review_decisions"] = {
        "type": "array", "minItems": len(branches), "maxItems": len(branches), "items": {"anyOf": branches}}
    refs = review_contract(batch)["verification_review_refs"]
    verification_branches = []
    for ref in refs:
        branch = branch_from("PlannerVerificationReview")
        for key in ("finding_id", "revision", "verification_id"):
            branch["properties"][key] = {"const": ref[key], "type": "integer" if key == "revision" else "string"}
        verification_branches.append(branch)
    schema["properties"]["verification_reviews"] = {
        "type": "array", "maxItems": len(refs),
        "items": {"anyOf": verification_branches} if refs else {"type": "object", "additionalProperties": False},
    }
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
    return {"goal_state": "continue", "basis_summary": "逐项审查当前冻结输入；证据不足的项保留待审。",
            "review_batch_id": batch["id"],
            "review_decisions": [{"item_id": item["item_id"], "revision": item["revision"],
                                  "decision": "needs_evidence", "rationale": "请替换为本项缺少的具体证据与下一步措施。",
                                  **({"comparison_assessments": [{"item_id": peer["item_id"], "relation": "unresolved",
                                      "rationale": "此处仅示范结构，须读取双方实际根因与操作后独立判读。"}
                                      for peer in reference_coordinates(item)["peers"]]} if item['kind']=='finding' else {}),
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
