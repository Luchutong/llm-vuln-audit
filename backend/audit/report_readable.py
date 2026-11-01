"""Versioned delivery views. Only immutable terminal inputs/facts may enter here.

This module never opens the repository, the ledger, a runner or a model. Archive
bytes and the original quality_result remain owned by frozen_reports.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import html
import io
import json
import math
import re
import zipfile
from pathlib import PurePosixPath
from datetime import datetime
from zoneinfo import ZoneInfo

VERSION = "delivery-report/v1"
TEMPLATE = "readable-2026-11-01-r3"
DISPOSITIONS = {"accepted": "终审接受", "pending": "待终审", "contested": "存疑或排除"}
VERIFICATION = {"verified": "动态验证通过", "unverified": "未动态验证", "stale": "结论已更新，待重新验证",
                "inconclusive": "动态验证未决", "not_applicable": "动态验证不适用", "failed": "动态验证失败"}
LABELS = {"execution_status":"执行状态", "focus_complete":"目标关联已结算", "source_review_complete":"源码复核已结算",
          "risk_obligations_complete":"冻结风险义务已结算", "dynamic_verification":"动态验证要求", "final_review_complete":"独立终审已结算",
          "delivery_readiness":"交付材料", "complete":"已结算", "gaps":"待补充材料", "mode":"模式", "requirement_met":"已满足本轮要求",
          "verified":"当前验证通过数", "pending":"待处理数", "policy":"冻结政策", "canonical_id":"规范编号", "items":"事项",
          "identity":"实际身份", "preconditions":"实验前提", "state_changes":"状态变化", "target_version":"目标版本",
          "security_property":"待验证的安全属性", "attacker_identity":"攻击前身份", "resource_owner":"资源属主", "initial_state":"初始状态",
          "control":"正常对照", "attack_variable":"攻击变量", "expected_discriminator":"预期判别条件", "observed_discriminator":"实际判别观测",
          "normal_job_ids":"正常侧作业", "attack_job_ids":"攻击侧作业", "readback_job_ids":"读回作业", "limitations":"限制",
          "kind":"节点类型", "explanation":"源码关系说明", "evidence":"源码引用", "path":"路径", "start_line":"起始行", "end_line":"结束行", "reason":"理由"}


def dump(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else str(value).encode()).hexdigest()


def redact(value):
    """Only presentation is redacted; original attachments/fact hashes stay intact."""
    value = str(value)
    value = re.sub(r"(?im)^(\s*(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie)\s*:\s*).+$", r"\1[已脱敏]", value)
    value = re.sub(r"(?i)([?&](?:access_token|api_key|token|secret|password)=)[^&\s\"'<>]+", r"\1[已脱敏]", value)
    value = re.sub(r"\bsk-[A-Za-z0-9_-]{20,}\b", "[API 凭据已脱敏]", value)
    return value


def text(value):
    """Prose preserves paragraphs, list steps and pipes; raw HTML stays inert."""
    if value is None or value == "" or value == [] or value == {}:
        return "暂无数据"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, list):
        return "\n".join((f"- 第 {i} 项\n  " + text(item).replace("\n", "\n  ")) if isinstance(item,dict)
                         else "- " + text(item).replace("\n", "\n  ") for i,item in enumerate(value,1))
    if isinstance(value, dict):
        return "\n".join(f"- {html.escape(LABELS.get(str(key),str(key)))}：" +
                         ("\n  " + text(item).replace("\n", "\n  ") if isinstance(item,(list,dict)) and item else text(item))
                         for key, item in value.items())
    # Treat embedded fences as literal text. Source/scripts use fence() instead.
    return html.escape(redact(value), quote=False).replace("```", "&#96;&#96;&#96;").replace("~~~", "&#126;&#126;&#126;")


def cell(value):
    return text(value).replace("\n", "<br>").replace("|", "&#124;").replace("`", "&#96;")


def fence(value, language="text"):
    value = redact(value or "")
    marker = "`" * max(3, 1 + max((len(m.group()) for m in re.finditer(r"`+", value)), default=0))
    lang = re.sub(r"[^a-zA-Z0-9_+-]", "", str(language))
    return f"{marker}{lang}\n{value}\n{marker}"


def numbering(facts):
    return {item["canonical_id"]: f"C-{i:02d}" for i, item in enumerate(
        sorted(facts.get("canonical_findings") or [], key=lambda item: item["canonical_id"]), 1)}


def _related(facts, entry):
    # All revisions of this canonical identity are history, but never another identity.
    refs = {(r["finding_id"], int(r.get("revision") or 1)) for r in entry.get("source_record_refs") or []}
    current = entry.get("current_claim_ref") or {}
    refs.add((current.get("finding_id"), int(current.get("revision") or 1)))
    attempts = [a for a in facts.get("verification_attempts") or [] if
                ((a.get("finding_ref") or {}).get("finding_id"), int((a.get("finding_ref") or {}).get("revision") or 1)) in refs]
    verification_ids = {a.get("verification_id") for a in attempts}
    reviews = [r for r in facts.get("reviews") or [] if r.get("verification_id") in verification_ids and
               ((r.get("finding_ref") or {}).get("finding_id"), int((r.get("finding_ref") or {}).get("revision") or 1)) in refs]
    evidence_ids = {r.get("evidence_id") for r in (entry.get("frozen_claim") or {}).get("evidence") or []}
    evidence = [e for e in facts.get("source_evidence") or [] if e.get("evidence_id") in evidence_ids]
    return attempts, reviews, evidence


def document(frozen, view="audit", canonical_id=None):
    facts = frozen["facts"]
    payload = frozen.get("input") or {}
    run, snapshot = payload.get("run") or {}, payload.get("snapshot") or {}
    entries = facts.get("canonical_findings") or []
    numbers = numbering(facts)
    scoped = canonical_id is not None or view == "accepted"
    if view == "accepted":
        entries = [item for item in entries if item.get("final_disposition") == "accepted"]
    if canonical_id is not None:
        entries = [item for item in entries if item["canonical_id"] == canonical_id]
        if not entries:
            raise KeyError(canonical_id)
    if scoped:
        entries = copy.deepcopy(entries)
        for entry in entries:
            # Peer summaries are full other claims in the parent's comparison input.
            # Single reports may retain reference IDs, never those other claim bodies.
            entry["comparison_candidates"] = [{"item_id": peer.get("item_id")} for peer in entry.get("comparison_candidates") or []]
            entry["merge_suggestions"] = [{"other_canonical_id": peer.get("other_canonical_id"), "action": peer.get("action")}
                                          for peer in entry.get("merge_suggestions") or []]
    attempts, reviews, sources = [], [], []
    frozen_verifications = {v.get("id"): v for record in payload.get("all_records") or [] for v in record.get("verifications") or []}
    for entry in entries:
        a, r, s = _related(facts, entry)
        for attempt in a:
            original = frozen_verifications.get(attempt.get("verification_id")) or {}
            agent = original.get("agent") or {}
            attempts.append({**attempt, "experiment_context": {"identity": agent.get("identity"),
                            "preconditions": agent.get("preconditions"), "state_changes": agent.get("state_changes"),
                            "target_version": original.get("target_version") or attempt.get("target_version")}})
        reviews.extend(r); sources.extend(s)
    def unique(items, key):
        return list({item.get(key): item for item in items}.values())
    source_hashes = {"frozen_input": frozen.get("input_hash"), "facts": digest(dump(facts)),
                     "archive_output": frozen.get("output_hash"), "renderer": VERSION,
                     "template": digest(TEMPLATE)}
    return {
        "schema_version": VERSION, "view": "finding" if canonical_id is not None else view,
        "scope": {"run_id": run.get("id") or facts.get("provenance", {}).get("run_id"),
                  "canonical_ids": [item["canonical_id"] for item in entries],
                  "selection": "single" if canonical_id else "accepted" if view == "accepted" else "all"},
        "source_hashes": source_hashes,
        "metadata": {"source_name": snapshot.get("name") or run.get("snapshot_name"),
                     "objective": (run.get("task_spec") or {}).get("objective"),
                     "success_criteria": (run.get("task_spec") or {}).get("success_criteria"),
                     "snapshot_id": run.get("snapshot_id"), "source_hash": snapshot.get("archive_sha256"),
                     "created_at": run.get("created_at"), "finished_at": run.get("finished_at"),
                     "policy": (run.get("task_spec") or {}).get("capability_policy", "legacy"),
                     "poc_mode": (run.get("poc_policy") or {}).get("mode", "legacy"),
                     "historical_relayout": not (run.get("task_spec") or {}).get("capability_policy")},
        "counts": {"canonical": len(entries), **{state: sum(e.get("final_disposition") == state for e in entries)
                                                    for state in DISPOSITIONS}},
        "parent_summary": {"counts": facts.get("counts"), "run_outcome": facts.get("run_outcome"),
                           "coverage": facts.get("coverage")} if scoped else None,
        "run_outcome": facts.get("run_outcome") if canonical_id is None else None,
        "coverage": facts.get("coverage") if canonical_id is None else None,
        "risk_obligations": facts.get("risk_obligations") if not scoped else None,
        "action_items": ([item for item in facts.get("action_items") or []
                          if item.get("object") in {entry["canonical_id"] for entry in entries}]
                         if view == "accepted" else facts.get("action_items") if canonical_id is None else None),
        "limitations": facts.get("limitations") if canonical_id is None else None,
        "numbering": {item["canonical_id"]: numbers[item["canonical_id"]] for item in entries},
        "canonical_findings": entries,
        "verification_attempts": unique(attempts, "verification_id"),
        "reviews": unique(reviews, "review_id"), "source_evidence": unique(sources, "evidence_id"),
        "original_quality_result": facts.get("quality_result") if canonical_id is None else None,
        "publication": {"accepted": sum(e.get("final_disposition") == "accepted" for e in entries),
                        "pending_in_parent": (facts.get("counts") or {}).get("pending"),
                        "audit_complete": (facts.get("run_outcome") or {}).get("audit_complete") is True,
                        "basis": "独立终审已接受的冻结结论可单独交付；其他未决项不阻止其报告，动态验证与终审分别标注。"},
    }


def _location(claim):
    loc = claim.get("primary_location") or {}
    if loc.get("path"):
        return f"{loc['path']}:{loc.get('line', '?')}"
    refs = claim.get("evidence") or []
    return f"{refs[0].get('path')}:{(refs[0].get('range') or {}).get('start', '?')}" if refs else claim.get("file_path")


def _score(entry):
    cvss = (entry.get("frozen_claim") or {}).get("cvss") or {}
    try:
        value = float(cvss.get("base_score", -1))
        return value if math.isfinite(value) else -1
    except (ValueError, TypeError):
        return -1


def verification_label(claim):
    if claim.get('verification_status') == 'verified' and claim.get('verified_compatible') is False:
        return '历史验证通过，当前兼容性未确认'
    return VERIFICATION.get(claim.get('verification_status'), '暂无数据')


def rating_summary(claim):
    cvss = claim.get('cvss') or {}
    score = cvss.get('base_score')
    severity = {'critical':'严重', 'high':'高危', 'medium':'中危', 'low':'低危', 'none':'无'}.get(cvss.get('severity'), '严重程度未记录')
    return f'{score} / {severity}' if isinstance(score,(int,float)) and not isinstance(score,bool) and math.isfinite(score) else '待评分'


def _ordered(doc):
    return sorted(doc["canonical_findings"], key=lambda e: (-_score(e), doc["numbering"][e["canonical_id"]]))


def _nested_markdown(markdown):
    lines, opened = [], None
    for line in markdown.splitlines():
        marker = re.match(r"^(`{3,}|~{3,})", line)
        if marker:
            if opened is None:
                opened = marker.group()
            elif marker.group() == opened:
                opened = None
        heading = re.match(r"^(#{1,6}) (.*)", line) if opened is None else None
        lines.append(("#" * min(6, len(heading[1]) + 2) + " " + heading[2]) if heading else line)
    return "\n".join(lines)


def _header(doc, title):
    m = doc["metadata"]
    def timestamp(value):
        try:
            date = datetime.fromisoformat(str(value).replace('Z','+00:00'))
            return date.astimezone(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S') if date.tzinfo else text(value)
        except (TypeError,ValueError):
            return text(value)
    lines = [f"# {title}", "", f"源码包：{text(m['source_name'])}", "", f"审计目标：{text(m['objective'])}", "",
             f"时间（Asia/Shanghai）：{timestamp(m['created_at'])} 至 {timestamp(m['finished_at'])}", ""]
    if m["historical_relayout"]:
        lines += ["> 基于历史冻结事实重排版；保留当时政策、结论和完成性，未重新审计。", ""]
    return lines


def _inventory(doc, entries):
    lines = ["| 编号 | 漏洞与主位置 | CVSS 3.1 | 动态验证 | 独立终审 | 详单 |", "|---|---|---|---|---|---|"]
    for entry in entries:
        claim = entry["frozen_claim"]
        number = doc["numbering"][entry["canonical_id"]]
        lines.append(f"| {number} | {cell(claim.get('title'))}<br>{cell(_location(claim))} | "
                     f"{cell(rating_summary(claim))} | {cell(verification_label(claim))} | "
                     f"{cell(DISPOSITIONS.get(entry.get('final_disposition'), '暂无数据'))} | [详单](findings/{number}.md) |")
    return lines + [""]


def delivery_gaps(entry):
    claim = entry.get("frozen_claim") or {}
    gaps = []
    def present(value):
        if isinstance(value,list):
            return bool(value) and all(present(item) for item in value)
        return str(value or '').strip().strip('。.').casefold() not in {'','无','待补充','暂无数据','todo','unknown','n/a','none','不适用','-','—','...','…'}
    if not present(claim.get("remediation")):
        gaps.append("修复建议待补充")
    if not present(claim.get("retest")):
        gaps.append("修复后复测步骤与回归条件待补充")
    if not present(claim.get("preconditions")):
        gaps.append("登录、权限与业务初始状态待补充")
    return gaps


def finding_markdown(doc, entry):
    claim = entry["frozen_claim"]
    number = doc["numbering"][entry["canonical_id"]]
    lines = _header(doc, f"{number} {cell(claim.get('title'))}")
    lines += [f"结论版本：{text(claim.get('revision'))}；评分版本：{text(entry.get('assessment_revision'))}", "",
              f"CVSS 3.1：{text(rating_summary(claim))}；动态验证：{verification_label(claim)}；"
              f"独立终审：{DISPOSITIONS.get(entry.get('final_disposition'), '暂无数据')}", "",
              "## 影响与受影响位置", "", text(claim.get("summary")), "", text(_location(claim)), "",
              "## 利用前提", "", text(claim.get("preconditions")), "",
              "## 根因与源码证据", "", "输入：" + text(claim.get("input_source")), "",
              "传播与持久化读回：" + text(claim.get("propagation")), "",
              "危险操作：" + text(claim.get("dangerous_operation")), "", "防护及其缺口：" + text(claim.get("protection")), ""]
    focus = (entry.get("final_batch_review") or {}).get("focus") or {}
    relation = {"relevant": "目标相关", "supporting": "必要辅助链", "incidental": "附带发现", "unresolved": "相关性待判断"}.get(focus.get("relation"), "历史未记录相关性")
    lines += ["目标关联的独立判读：" + relation, "", text(focus.get("rationale")), ""]
    if claim.get("dataflow"):
        lines += ["结构化数据与状态链（节点仍以实际源码取证为准）：", "", text(claim["dataflow"]), ""]
    _, reviews, sources = _related(doc, entry)
    for source in sources:
        loc = f"{source.get('path')}:{(source.get('range') or {}).get('start')}-{(source.get('range') or {}).get('end')}"
        lines += [f"### {cell(loc)}", ""]
        if source.get("available"):
            lines += [fence("\n".join(f"{line['number']:>5}  {line['text']}" for line in source.get("excerpt") or [])), ""]
            if source.get("truncated"):
                lines += ["冻结时仅保存了部分片段；完整上下文未包含于本报告。", ""]
        else:
            lines += ["源码片段不可用：" + text(source.get("reason")), ""]
    if not sources:
        lines += ["未冻结源码片段；不以当前文件补写历史证据。", ""]
    lines += ["## 复现与实际验证", "", "### 待执行的复现材料（预期）", ""]
    poc = claim.get("poc") or {}
    for key, label in (("instructions", "环境、登录与步骤"), ("normal_input", "正常对照"),
                       ("attack_input", "攻击输入"), ("expected_result", "预期判别条件")):
        lines += [f"{label}：", "", text(poc.get(key)), ""]
    if poc.get("script"):
        lines += ["复现脚本（以下内容本身不证明已执行）：", "", fence(poc["script"], poc.get("language", "text")), ""]
    attempts, _, _ = _related(doc, entry)
    lines += ["### 已保存的实际观测", ""]
    if not attempts:
        lines += ["本次未保存动态执行记录。以上为待执行材料，不能视为已复现。", ""]
    for index, attempt in enumerate(attempts, 1):
        ref = attempt.get("finding_ref") or {}
        current = ref == {k: entry["current_claim_ref"][k] for k in ("finding_id", "revision")}
        lines += [f"#### 实验 {index}（{'当前修订' if current else '历史修订'}）", "",
                  f"执行状态：{text(attempt.get('execution_status'))}；判定：{text(attempt.get('verdict'))}", "",
                  "正常观测：", "", text(attempt.get("normal_evidence")), "", "攻击观测：", "", text(attempt.get("attack_evidence")), "",
                  "实验结论依据：", "", text(attempt.get("conclusion_reason")), ""]
        if attempt.get("experiment_context"):
            lines += ["实际身份、实验前提与状态变化：", "", text(attempt["experiment_context"]), ""]
        if attempt.get("inherited_from"):
            lines += ["来源：历史继承验证。", "", text(attempt["inherited_from"]), ""]
        if attempt.get("experiment"):
            lines += ["实验判别合同（预期与实际分开）：", "", text(attempt["experiment"]), ""]
        if attempt.get("final_script"):
            lines += ["实际适配脚本：", "", fence(attempt["final_script"]), ""]
    lines += ["## 终审结论与限制", "", DISPOSITIONS.get(entry.get("final_disposition"), "暂无数据"), "",
              text((entry.get("final_batch_review") or {}).get("rationale") or entry.get("disposition_reason")), "",
              "缺失上下文：", "", text(claim.get("missing_context")), ""]
    for review in reviews:
        lines += ["动态验证的独立复核：", "", text(review.get("rationale")), ""]
    cvss = claim.get("cvss") or {}
    assessment = entry.get("frozen_cvss_assessment") or {}
    lines += ["## CVSS 3.1 依据", "", text(cvss.get("base_vector") or cvss.get("vector")), "",
              text(assessment.get("metric_details") or assessment.get("metrics") or assessment.get("cvss_input") or assessment.get("metric_proposals")), "",
              "## 修复建议与复测", "", text(claim.get("remediation")), "", "复测与回归：", "", text(claim.get("retest")), ""]
    if delivery_gaps(entry):
        lines += ["交付待办（不改变漏洞成立或终审处置）：", "", text(delivery_gaps(entry)), ""]
    lines += ["## 来源与附件", "", f"规范身份：{text(entry['canonical_id'])}", "",
              f"运行：{text(doc['scope']['run_id'])}；证据快照：{text(doc['metadata']['snapshot_id'])}", "",
              "冻结来源哈希：", "", text(doc["source_hashes"]), "",
              "完整源码片段、实验引用、原始产物及哈希见同名 JSON / ZIP。", ""]
    return "\n".join(lines)


def markdown(doc):
    if doc["view"] == "finding":
        return finding_markdown(doc, doc["canonical_findings"][0])
    if doc["view"] in {"vulnerabilities", "accepted"}:
        accepted_only = doc["view"] == "accepted"
        lines = _header(doc, "已确认漏洞审计报告" if accepted_only else "漏洞审计报告汇编")
        if accepted_only:
            lines += [f"本报告单独交付 {doc['counts']['accepted']} 条已获独立终审接受的冻结结论。", "",
                      "其他未决项不影响上述结论形成报告；本报告不代表整次穷尽审计完成。动态验证状态逐条标注，静态接受不等于已动态复现。", "",
                      f"父任务待终审：{text(doc['publication']['pending_in_parent'])} 条；整体完成：{'是' if doc['publication']['audit_complete'] else '否'}。", "",
                      "按冻结规范结论身份计数；不重新合并历史台账，疑似同根因仍保留对照与限制。", ""]
        if not doc["canonical_findings"]:
            lines += ["本次未形成可交付漏洞结论；这不构成项目安全的证明。", ""]
        for state, label in (("accepted", DISPOSITIONS["accepted"]),) if accepted_only else DISPOSITIONS.items():
            entries = [e for e in _ordered(doc) if e.get("final_disposition") == state]
            lines += [f"## {label}（{len(entries)}）", ""]
            for entry in entries:
                number = doc["numbering"][entry["canonical_id"]]
                lines += [f"- [{number} {cell(entry['frozen_claim'].get('title'))}](#{number.lower()})"]
            lines += [""]
            for entry in entries:
                number = doc["numbering"][entry["canonical_id"]]
                lines += [f'<a id="{number.lower()}"></a>', "",
                          _nested_markdown(finding_markdown(doc, entry)), ""]
        return "\n".join(lines)
    lines = _header(doc, "审计执行报告")
    outcome = doc.get("run_outcome") or {}
    lines += ["## 结果与完成性", "", "本轮冻结策略已完成。" if outcome.get("audit_complete") else "本轮为阶段结果；未完成范围与限制保留如下。", "",
              "执行状态：" + {"completed":"本次执行已结束", "inconclusive":"未完成", "cancelled":"已取消", "interrupted":"已中断", "failed":"执行失败", "unreachable":"目标未证实"}.get(outcome.get("status"), "暂无数据"), "",
              "停止原因：" + text((outcome.get("stop_reason") or {}).get("message") or (outcome.get("stop_reason") or {}).get("code")), "",
              "自动验证模式：" + {"off": "未启用", "auto": "环境满足时可选执行", "required": "要求兼容的动态验证"}.get(doc["metadata"]["poc_mode"], "历史模式未记录"), "",
              "分维度完成性：", "", text(outcome.get("dimensions")) if outcome.get('dimensions') else '历史未记录分维度结果；保留当时完成性，不重新推算。', "",
              "## 漏洞清单", "", f"规范结论 {doc['counts']['canonical']}；终审接受 {doc['counts']['accepted']}；"
              f"待终审 {doc['counts']['pending']}；存疑或排除 {doc['counts']['contested']}。", ""]
    if doc['counts']['accepted']:
        lines += [f"已确认的 {doc['counts']['accepted']} 条结论可独立交付；其他待审项不阻止下载“已确认漏洞报告”。", ""]
    if doc["canonical_findings"]:
        if doc["metadata"]["historical_relayout"]:
            lines += _inventory(doc, _ordered(doc))
        else:
            for relation, label in (("relevant", "目标相关结论"), ("supporting", "必要辅助链（不独立支撑目标达成）"),
                                    ("incidental", "附带发现（保留台账，不计为目标达成）"), ("unresolved", "目标关联待判断")):
                subset = [entry for entry in _ordered(doc) if ((entry.get("final_batch_review") or {}).get("focus") or {}).get("relation", "unresolved") == relation]
                if subset:
                    lines += [f"### {label}", ""] + _inventory(doc, subset)
    else:
        lines += ["本次未形成可交付漏洞结论；不代表源码没有漏洞。", ""]
    coverage = doc.get('coverage') or {}
    files, directions, verification = (coverage.get(key) or {} for key in ('files','directions','verification'))
    lines += ["## 覆盖与未完成工作", "", "应审文件、实际读取、带理由跳过、方向结算分别计数，不是安全覆盖率。", "",
              f"应审文件 {text(files.get('total'))}；实际读取 {text(files.get('read'))}；读取或带理由跳过后复核 {text(files.get('reviewed'))}；跳过 {text(files.get('skipped'))}；待复核 {text(files.get('pending'))}。", "",
              f"必做方向 {text(directions.get('required'))}；已解决 {text(directions.get('resolved'))}；明确跳过 {text(directions.get('skipped'))}；未结算 {text(directions.get('unsettled'))}。", "",
              f"动态验证：当前通过 {text(verification.get('verified'))}；待验证 {text(verification.get('pending'))}；待独立动态复核 {text(verification.get('pending_review'))}。", ""]
    if files.get('skip_details'):
        lines += ['明确跳过的文件（不作为安全结论）：', '']
        lines += [f"- {text(item.get('path'))}：{text(item.get('reason'))}" for item in files['skip_details']]
        lines += ['']
    risk = doc.get('risk_obligations') or {}
    if risk:
        lines += [f"冻结风险义务 {text(risk.get('total'))}；其中必做 {text(risk.get('required'))}；未结算必做 {text(risk.get('pending_required'))}。读取与分派均不自动结清义务。", '', text(risk.get('limitations')), '']
        advisory_pending = sum(not item.get('required') and item.get('state') in {'pending','blocked'} for item in risk.get('items') or [])
        if advisory_pending:
            lines += [f'另有 {advisory_pending} 项非必做导航信号未结算；未将其认定为安全，也不据此阻塞本次目标。', '']
    lines += ["## 后续行动", ""]
    for action in doc.get('action_items') or []:
        number = doc['numbering'].get(action.get('object'), '')
        lines += [f"- {number + '：' if number else ''}{text(action.get('action') or action.get('detail') or action.get('title'))}"]
    if not doc.get('action_items'):
        lines += ['暂无冻结的补证动作；修复与复测材料仍按下列检查。']
    lines += ['']
    for entry in _ordered(doc):
        gaps = delivery_gaps(entry)
        if gaps:
            lines += [f"- {doc['numbering'][entry['canonical_id']]}：{'；'.join(gaps)}"]
    lines += ["", "## 限制与追溯", "", text(doc.get("limitations")), "", text(doc["source_hashes"]), "",
              "漏洞详单见漏洞审计报告汇编，技术事实与原始日志见归档原件。", ""]
    return "\n".join(lines)


def _attachments(frozen, doc):
    """Use only names actually owned by the selected frozen rows, never id prefixes."""
    from .report import original_poc_name, adapted_script_name, safe_name
    allowed = set()
    refs = {r["finding_id"] for e in doc["canonical_findings"] for r in e.get("source_record_refs") or []}
    verification_ids = {a["verification_id"] for a in doc["verification_attempts"]}
    for record in (frozen.get("input") or {}).get("all_records") or []:
        if record.get("id") not in refs:
            continue
        if (record.get("poc") or {}).get("script"):
            allowed.add(original_poc_name(record, record["poc"]))
        for v in record.get("verifications") or []:
            if v.get("id") not in verification_ids:
                continue
            allowed.add(adapted_script_name(record, v))
            allowed.add(f"{v['id']}-runner-manifest.json")
            allowed.update(safe_name(str(a.get("path") or "")) for a in v.get("artifacts") or [])
            allowed.update(str(a.get("stored")) for a in v.get("files") or [])
    result, missing = {}, []
    for item in (frozen.get("input") or {}).get("frozen_evidence") or []:
        name = item.get("name", "")
        if name not in allowed:
            continue
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name or any(part in {"", "."} for part in name.split("/")):
            missing.append({"name": name, "reason": "unsafe_archive_path"}); continue
        data = base64.b64decode(item["data"], validate=True)
        if item.get("sha256") and digest(data) != item["sha256"]:
            missing.append({"name": name, "reason": "hash_mismatch"}); continue
        result["evidence/" + name] = data
    present = {name.removeprefix("evidence/") for name in result}
    missing += [{"name": name, "reason": "not_frozen"} for name in sorted(allowed - present) if name]
    return result, missing


def export(frozen, *, view="audit", format="markdown", canonical_id=None):
    doc = document(frozen, view, canonical_id)
    md = markdown(doc)
    from .report_layout_quality import evaluate
    quality = {**evaluate(doc, md), "renderer": VERSION, "template": TEMPLATE}
    doc["render_quality"] = quality
    if format == "markdown":
        return md.encode()
    if format == "json":
        return dump(doc).encode()
    files, missing = _attachments(frozen, doc)
    source_files = []
    for entry in doc['canonical_findings']:
        number = doc['numbering'][entry['canonical_id']]
        _, _, source_refs = _related(doc, entry)
        for index, source in enumerate(source_refs,1):
            name = f'evidence/source/{number}-{index:02d}.txt'
            if source.get('available'):
                # These are exact frozen excerpt lines, never a later repository read.
                data = '\n'.join(str(line['number']) + '\t' + line['text'] for line in source.get('excerpt') or []).encode()
                files[name] = data
                source_files.append({'evidence_id':source.get('evidence_id'), 'member':name,
                                     'path':source.get('path'),'range':source.get('range'),
                                     'source_file_hash':source.get('content_hash'), 'fragment_sha256':digest(data),
                                     'truncated_at_freeze':bool(source.get('truncated'))})
            else:
                missing.append({'evidence_id':source.get('evidence_id'),'reason':source.get('reason') or 'source_not_frozen'})
    main = "finding.md" if canonical_id else ("accepted-findings.md" if view == "accepted" else "report.md" if view == "audit" else "vulnerability-report.md")
    files[main] = md.encode()
    if canonical_id or view == "accepted":
        files["finding-facts.json" if canonical_id else "accepted-facts.json"] = dump(doc).encode()
        if view == "accepted":
            for entry in doc["canonical_findings"]:
                files[f"findings/{doc['numbering'][entry['canonical_id']]}.md"] = finding_markdown(doc, entry).encode()
    else:
        files["report.md"] = markdown(document(frozen, "audit")).encode()
        files["vulnerability-report.md"] = markdown(document(frozen, "vulnerabilities")).encode()
        files["final-review.json"] = dump(frozen["facts"]).encode()
        for entry in doc["canonical_findings"]:
            files[f"findings/{doc['numbering'][entry['canonical_id']]}.md"] = finding_markdown(doc, entry).encode()
    files["render-quality.json"] = dump(quality).encode()
    files["manifest.json"] = dump({"schema_version": VERSION, "main_document": main, "scope": doc["scope"],
                                    "source_hashes": doc["source_hashes"], "numbering": doc["numbering"],
                                    "artifact_hashes": {name: digest(data) for name, data in sorted(files.items())},
                                    "missing_attachments": missing,
                                    "source_fragments": source_files,
                                    "evidence_display": "原始附件/JSON 保持冻结事实及哈希；Markdown 对认证头、Cookie、令牌参数和 API 凭据脱敏。正文 hash 为脱敏呈现的哈希；原始证据 hash 单独保留。"}).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return buffer.getvalue()
