"""Versioned ownership of scheduling, source judgments and investigation checkpoints.

This is an independent implementation of candidate/evidence/terminal-action ideas;
it neither imports AutoCVE nor delegates runtime, storage or verification to it.
"""
from __future__ import annotations

from .evidence import seen_ranges

POLICY = "worker-evidence-v2"
PREVIOUS_POLICY = "worker-evidence-v1"
MAX_CANDIDATES = 16


class WorkerAssessmentError(ValueError):
    """A rejected worker submission, whose transaction has not committed."""


def enabled(task):
    return (task or {}).get("role_policy") in {PREVIOUS_POLICY, POLICY}


def separate_root(task):
    return (task or {}).get("role_policy") == POLICY


def triage_allowed(task, record=None):
    return (task or {}).get("exploration_policy") == "exhaustive-v1" and (
        record is None or record.get("requirement") == "advisory")


def validate_planner_actions(task, updates=(), project_updates=(), direction_updates=(), directions=None, tasks=None, *, coverage_updates=()):
    for update in direction_updates or []:
        if update.get("action") == "triage" and not triage_allowed(task, (directions or {}).get(update.get("direction_id"), {})):
            raise ValueError("必做方向不能 triage；triage 仅用于 exhaustive-v1 的 advisory 方向；当前方向请 assign 领取或引用 worker_results 用 resolve 结算")
    if enabled(task) and (project_updates or any(
        item.get("action") in {"retract", "duplicate"} for item in updates or [])):
        raise ValueError("Planner 仅调度；撤回/判重须交独立审查批次，不能直接处置 worker 发现")
    if enabled(task):
        if task.get("focus_scope") == "all" and coverage_updates:
            raise ValueError("冻结全量范围不能通过 coverage_review skip 跳过源码；未完成读取须保留覆盖缺口")
        for update in updates or []:
            target = (tasks or {}).get(update.get("task_key"), {})
            if update.get("action") in {"cancel", "defer"} and any(
                c.get("status") == "pending" for c in (target.get("result") or {}).get("candidate_journal") or []):
                raise ValueError("任务仍有 worker pending 候选，不能取消/延后以隐藏取证缺口；请继续调查或保留阻塞")
        for update in direction_updates or []:
            record = (directions or {}).get(update.get("direction_id"), {})
            from .investigation import enabled as bounded
            if bounded(task) and update.get("action") == "triage" and record.get("requirement", "required") == "required":
                raise ValueError("必做方向不能 triage；用 assign 领取，或依据 worker_results 用 resolve 结算；证据不足保留未决")
            if update.get("action") == "triage" and update.get("triage_outcome") == "no_evidence":
                raise ValueError("Planner 不得用 triage no_evidence 排除源码风险；请 investigate，由 worker 提交带反证的 direction_results")
            excludes = (update.get("action") == "skip" or update.get("triage_outcome") == "out_of_scope")
            if excludes and task.get("focus_scope") == "all" and record.get("paths"):
                raise ValueError("冻结全量范围内的已知源码不能 out_of_scope/skip；未读取/无 finding/阶段或预算限制须保留 blocked 或派工取证")


def candidate_context(journal):
    return {"pending": [{k: v for k, v in c.items() if k not in {"source_attempt", "anchor_history"}}
                        for c in journal if c["status"] == "pending"],
            "settled": [{k: c[k] for k in ("candidate_id", "status", "primary_location")}
                        for c in journal if c["status"] != "pending"]}


def planner_schema(schema, *, full_scope=False, exhaustive=False):
    """Do not advertise semantic disposition buttons to the scheduler."""
    schema["properties"]["project_updates"]["maxItems"] = 0
    if full_scope:
        schema["properties"]["coverage_review"]["maxItems"] = 0
    schema["$defs"]["PlannerTaskUpdate"]["properties"]["action"]["enum"] = ["cancel", "defer", "reprioritize", "reopen"]
    if not exhaustive:
        action = schema["$defs"]["PlannerDirectionUpdate"]["properties"]["action"]
        action["enum"] = [value for value in action["enum"] if value != "triage"]
    for option in schema["$defs"]["PlannerDirectionUpdate"]["properties"]["triage_outcome"].get("anyOf", []):
        if "enum" in option:
            option["enum"] = [choice for choice in option["enum"] if choice != "no_evidence"]
    return schema


WORKER_CONTRACT = """# Worker 取证职责
你负责当前工作项的源码判断，不把具体风险的成立性交给 Planner 猜测。Planner 只安排任务和预算；独立终审复核你的证据。
每条 finding 的 dataflow 至少有 input 和 sink 两个节点，各自引用本次真正读过的源码；sink 节点须覆盖 primary_location。按独立危险操作形成结论，不把两处独立 sink 合报。
维护少量 candidate_updates（至多16个）：candidate_id 在同一任务内稳定，primary_location 为候选操作行；status=pending 时写 hypothesis、missing_context 和具体 next_step。尚未证实的假设保留 pending，不能为交付编造利用链。
同一 pending 假设经过补证需要更正根因定位时，显式提供 reanchor_from=上次 primary_location、reanchor_reason（至少12字），evidence 同时引用本次实际读过的新旧定位；宿主保存更正历史。已结算候选不能移动，不同风险须使用不同 ID。
局部候选由当前worker继续调查，不把同一候选重复抄进remaining_work或交给Planner重建近义任务；只有超出当前工作项的具体问题才交回调度。
status=supported 必须用 finding_index（本次 findings 的零起始序号）关联实际发布且同主定位的结论；status=excluded 必须给 disproof。未在本轮更新的候选不会消失，宿主保留它并继续计入待办。
disproof={basis:effective_protection|unreachable|not_applicable,rationale:具体防护/不可达依据,evidence:[{path,start_line,end_line}]}。排除一个风险不代表排除同文件其他风险。direction_results.outcome=no_evidence、observation.follow_up=false 也须有这种已读源码反证。
没有反证不能因为缺 finding、阶段结束、影响有限或同伴说安全而排除；用 needs_evidence/pending 并说明下一步。确认一个漏洞后继续检查当前任务中不同的候选；单次发布是检查点，不是全项目终止。
CSRF 必须核对浏览器凭据、请求来源及替代防护；登录CSRF也可能发生于未认证入口。缺 token 或 SameSite 值本身都不足以自动接受/排除。无动态观测只报告静态依据与条件，不自标 verified。
会话固定须分别核对 SID 投递、受害者认证、攻击者复用及认证后 SID 轮换。源码接受 URL SID 时，检查受害者访问链接后在站内登录的链路；不能把跨站 POST 登录当成所有会话固定路径的必要步骤。按真实链路判断防护，诱导访问仍须作为前提记录。
"""

WORKER_CONTRACT_V2 = WORKER_CONTRACT.replace(
    "sink 节点须覆盖 primary_location。",
    "primary_location 指向真实根因，不要求等于最终 sink。根因与 sink 同处时，sink 可直接覆盖主定位；"
    "不同时须添加且仅添加一个 kind=root_cause 节点，引用覆盖主定位的实际源码，并解释缺陷如何导向本条 sink。"
    "认证绕过可定位错误身份判断，批量赋值可定位不当字段授权，会话固定可定位接受外部 SID 的操作；"
    "后续查询、写入或响应仍标为 sink。不能为了过格式校验移动根因、把普通输入冒充根因、改写 sink 含义或扩大引用范围。"
    "input 可表示真实请求、持久化数据或配置来源，不得虚构攻击者输入。"
    "工具 schema 内附有同位置、跨文件、边界绕过和反证的完整结构参考；demo/ 路径只用于示范，不是当前快照证据。")


def worker_contract(task):
    return WORKER_CONTRACT_V2 if separate_root(task) else WORKER_CONTRACT

PLANNER_CONTRACT = """# Planner 调度职责
你负责范围、优先级、依赖、领取方向与预算，不代替 worker 作源码否定判断。
每个必读文件须用实际 source_refs 或已存在的符号选中，目录和 query_hints 仅供导航。不能猜测 src/lib 等未在冻结项目图出现的路径。
completed 任务只可按额度用 updates.reopen 重读原范围；不能在 tasks 中重新定义。改变 blocked 任务范围须同回合提交同 task_key 的 tasks 与 updates.reopen，保留其 pending 候选。
具体源码线索用 investigate 派给窄任务，或 covered 引用真实同根因 finding。no_evidence 由领取该方向的 worker 提交带源码反证的 direction_results，再引用对应任务结算；不得用 triage no_evidence 绕过取证。
全量任务内已知源码路径不能因未读、缺 finding、当前阶段禁止派工或预算不足而 out_of_scope/skip；这些都是未决覆盖缺口。源码不在快照的线索可明确记录范围限制。
全量任务也不能用 coverage_review skip 绕过范围内源码的读取；派工读取或保留覆盖缺口。
不能通过 retract/duplicate/project_updates 自行改变发现的有效性；将争议留给独立审查批次。你可重开任务补证，但不能为清空队列改写证据含义。
"""

REVIEWER_CONTRACT = """# 独立审查职责
本回合只审查当前冻结小批的精确版本。不得派工、扩大范围或改写原始worker证据。
质疑与接受都说明具体源码/实验依据；证据不足保留needs_evidence，不能把无法补证转换为安全或范围排除。
核对独立根因、输入到操作链及worker反证；发现、反证、规范版本和你的处置分别留存。静态接受不能冒充动态验证。
会话固定分别核对 SID 投递、受害者站内认证、认证后轮换与攻击者复用；URL SID 路径不必依赖跨站 POST 登录。只把实际利用链上的防护作为反证；诱导访问、令牌有效性等前提须明确，仍由当前证据判读。
"""


def _read(ref, spans):
    start, end = ref.get("start_line"), ref.get("end_line")
    # Live publication receives merged ranges, while SQLite keeps exact delivered
    # lines. Use the same interval union for both; never merge across an unread gap.
    spans = seen_ranges({}, [{"path": path, "start_line": left, "end_line": right}
        for path, left, right in spans if type(left) is int and type(right) is int and 0 < left <= right], exact=True)
    return (type(start) is int and type(end) is int and start > 0 and any(
        ref.get("path") == path and left <= start <= end <= right for path, left, right in spans))


def validate_disproof(disproof, spans, *, paths=()):
    from .schemas import WorkerDisproof
    proof = WorkerDisproof.model_validate(disproof or {}).model_dump()
    if any(not _read(ref, spans) for ref in proof["evidence"]):
        raise ValueError("worker 反证必须来自本次实际读取的源码区间")
    if paths and not set(paths).intersection(ref["path"] for ref in proof["evidence"]):
        raise ValueError("worker 反证必须针对本方向的源码路径")
    return proof


def merge_candidates(previous, updates, findings, spans, file_lines, *, referenced_findings=()):
    """Keep unresolved candidates even when the model omits them in the next pass."""
    from .schemas import WorkerCandidateUpdate
    journal = {item["candidate_id"]: dict(item) for item in previous or []}
    ids = set()
    for raw in updates or []:
        item = WorkerCandidateUpdate.model_validate(raw).model_dump()
        ident, location = item["candidate_id"], item["primary_location"]
        if ident in ids:
            raise ValueError("candidate_updates 的 candidate_id 不能重复")
        ids.add(ident)
        if not 1 <= location["line"] <= file_lines.get(location["path"], 0):
            raise ValueError("候选主定位必须属于冻结源码原始行")
        previous_item = journal.get(ident)
        moved = previous_item is not None and previous_item["primary_location"] != location
        if moved:
            old = previous_item["primary_location"]
            if (previous_item["status"] != "pending" or item.get("reanchor_from") != old
                    or len(item.get("reanchor_reason", "").strip()) < 12):
                raise ValueError("同一 candidate_id 不能悄悄更换根因位置；同一 pending 假设补证后定位更正须提供 reanchor_from=原主定位、reanchor_reason(至少12字)及新旧定位证据；不同风险建立新候选")
            if any(not _read({"path": anchor["path"], "start_line": anchor["line"], "end_line": anchor["line"]},
                             [(ref["path"], ref["start_line"], ref["end_line"]) for ref in item["evidence"]])
                   for anchor in (old, location)):
                raise ValueError("候选定位更正必须同时引用本次实际读过的新旧主定位源码")
        elif item.get("reanchor_from") is not None:
            raise ValueError("reanchor_from 仅用于更正既有 pending 候选的主定位")
        if any(not _read(ref, spans) for ref in item["evidence"]):
            raise ValueError("候选证据必须来自本次实际读取的源码")
        if item["status"] != "pending" and item["missing_context"]:
            raise ValueError("候选仍缺关键上下文时只能 pending，不能宣告 supported/excluded")
        if item.get("blocked_on") and (item["status"] != "pending" or not item["missing_context"] or not item["next_step"].strip()):
            raise ValueError("blocked_on 只用于 pending，必须列出 missing_context 和具体 next_step")
        if item["status"] == "supported":
            index = item["finding_index"]
            existing_id = item.get("finding_id")
            existing = next((f for f in referenced_findings if f.get("id") == existing_id), None) if existing_id else None
            if existing_id:
                if index is not None or existing is None or existing.get("primary_location") != location:
                    raise ValueError("supported 候选 finding_id 须唯一关联本次 finding_references 中同主定位的有效漏洞")
            elif index is None or index >= len(findings) or findings[index].get("primary_location") != location:
                raise ValueError("supported 候选须关联本次 findings 中同主定位的实际 finding_index")
        elif item["status"] == "excluded":
            item["disproof"] = validate_disproof(item.get("disproof"), spans, paths=[location["path"]])
        elif not item["next_step"].strip():
            raise ValueError("pending 候选必须写出具体 next_step，不能静默丢弃")
        history = list((previous_item or {}).get("anchor_history") or [])
        if moved:
            history.append(dict(primary_location=previous_item["primary_location"], reason=item["reanchor_reason"]))
        if history:
            item["anchor_history"] = history
        journal[ident] = item
    if len(journal) > MAX_CANDIDATES:
        raise ValueError("当前任务候选账本已达16项；先发布/排除已有候选，将额外具体方向交回 Planner")
    return list(journal.values())


def _flow_errors(finding, index, spans):
    """Actionable field paths; coordinate binding is not a causal sign-off."""
    nodes = finding.get("dataflow") or []
    location = finding.get("primary_location") or {}
    ref = {"path": location.get("path"), "start_line": location.get("line"), "end_line": location.get("line")}
    def covers(node):
        e = node.get("evidence") or {}
        return _read(ref, [(e.get("path"), e.get("start_line"), e.get("end_line"))])
    def coord(e):
        return f"{e.get('path')}:{e.get('start_line', e.get('line'))}-{e.get('end_line', e.get('line'))}"
    prefix = f"findings[{index}]（{str(finding.get('title') or '未命名')[:60]}）"
    errors = []
    if not {"input", "sink"} <= {n.get("kind") for n in nodes}:
        errors.append(prefix + ".dataflow 缺少 input→sink 节点；保留实际数据来源与敏感操作，缺证据用 pending")
    unread = [f"dataflow[{i}].evidence={coord(n.get('evidence') or {})}" for i, n in enumerate(nodes)
              if not _read(n.get("evidence") or {}, spans)]
    if unread:
        errors.append(prefix + " 的引用必须来自本次实际读取的源码：" + "；".join(unread[:3]))
    roots = [n for n in nodes if n.get("kind") == "root_cause"]
    sinks = [n for n in nodes if n.get("kind") == "sink"]
    bound = (len(roots) == 1 and covers(roots[0])) if roots else any(covers(n) for n in sinks)
    if not bound:
        actual = "; ".join(f"dataflow[{i}].{n.get('kind')}={coord(n.get('evidence') or {})}"
                           for i, n in enumerate(nodes) if n.get("kind") in {"sink", "root_cause"}) or "无 root_cause/sink"
        errors.append(prefix + f".primary_location={coord(location)} 未绑定唯一根因节点；当前 {actual}。"
            "保持真实根因位置；根因与 sink 分离时添加一个 root_cause 节点，其 evidence 同路径且 start_line≤主定位行≤end_line，"
            "explanation 说明缺陷与本条 sink 的联系；不要移动主定位或扩大 sink 区间来过校验")
    return errors


def _assessment_disproof(task, item, label, spans, *, paths=()):
    try:
        return validate_disproof(item.get("disproof"), spans, paths=paths)
    except ValueError as exc:
        if not separate_root(task):
            raise
        raise ValueError(label + ".disproof：" + ('direction_id='+item['direction_id']+'；' if item.get('direction_id') else '')
            + "须提供 {basis:effective_protection|unreachable|not_applicable,"
            "rationale:具体源码反证,evidence:[{path,start_line,end_line}]}，并引用本次实际读取的对应路径；"
            + ('本方向要求的路径至少覆盖一条：'+', '.join(paths)+'；' if paths else '') + str(exc)) from exc


def validate_assessment(task, result, seen, file_lines, *, previous=(), known_findings=()):
    """Shared live-publication and transaction gate; no semantic verdict from prose."""
    if not enabled(task):
        return []
    spans = [(r["path"], r["start_line"], r["end_line"]) for r in seen or []]
    findings = result.get("findings") or ([result["finding"]] if result.get("finding") else [])
    from .finding_reuse import validate_references
    references = validate_references(task, result.get("finding_references"), known_findings, spans)
    if result.get("outcome") == "achieved" and not findings and not references:
        raise ValueError("achieved 必须有实际发布的 finding；候选检查点不能替代漏洞结论")
    errors = []
    for index, finding in enumerate(findings):
        if separate_root(task):
            errors.extend(_flow_errors(finding, index, spans))
            continue
        nodes = finding.get("dataflow") or []
        if not {"input", "sink"} <= {node.get("kind") for node in nodes}:
            raise ValueError("worker finding 须提供已读 input→sink dataflow，证据不足先保存 pending 候选")
        if any(not _read(node.get("evidence") or {}, spans) for node in nodes):
            raise ValueError("worker dataflow 必须来自本次实际读取的源码")
        location = finding.get("primary_location") or {}
        if not any(node.get("kind") == "sink" and _read(
            {"path": location.get("path"), "start_line": location.get("line"), "end_line": location.get("line")},
            [(node["evidence"]["path"], node["evidence"]["start_line"], node["evidence"]["end_line"])]) for node in nodes):
            raise ValueError("dataflow 的 sink 节点必须覆盖本条 primary_location")
    if errors:
        raise ValueError("\n".join(errors[:6]))
    reference_ids = {r["finding_id"] for r in references}
    journal = merge_candidates(previous, result.get("candidate_updates"), findings, spans, file_lines,
        referenced_findings=[f for f in known_findings if f.get("id") in reference_ids])
    from .investigation import enabled as bounded, linked_observations
    linked = linked_observations(result, journal, known_findings, spans) if bounded(task) else set()
    proofs = 0
    for index, item in enumerate(result.get("direction_results") or []):
        if item.get("outcome") == "no_evidence":
            _assessment_disproof(task, item, f"direction_results[{index}]", spans,
                paths=(task.get("assigned_direction_paths") or {}).get(item.get("direction_id"), []))
            proofs += 1
    for index, item in enumerate(result.get("observations") or []):
        if item.get("follow_up") is False and index not in linked:
            _assessment_disproof(task, item, f"observations[{index}]", spans)
            proofs += 1
    proofs += sum(item.get("status") == "excluded" for item in result.get("candidate_updates") or [])
    if result.get("outcome") == "no_evidence" and (not proofs or any(c["status"] == "pending" for c in journal)):
        raise ValueError("no_evidence 需要已读源码反证且不能遗留 pending 候选；未完成用 continue/blocked")
    return journal


def pending_work(journal):
    return [f"{item['primary_location']['path']}:{item['primary_location']['line']} "
            f"候选 {item['candidate_id']}：{item['hypothesis']}；下一步：{item['next_step']}"
            for item in journal if item["status"] == "pending"]
