"""Deterministic rendering of the final-review fact package.

Seven fixed sections, in the order the plan fixes them.  Every number, location, rating
and status in the document comes from the fact package; the renderer never queries a
mutable finding or ledger row, never prints a Python container, and never shows a
model-submitted snippet where the snapshot excerpt belongs.

The same function serves a complete final report and an honest stage report: an
unfinished run keeps every pending or contested claim visible with its reason instead of
hiding findings that still need review.
"""
from __future__ import annotations

import re

RENDERER_VERSION = "final-report/v2"
SECTION_TITLES = (
    "1. 执行与终审摘要",
    "2. 范围和方法",
    "3. 规范漏洞清单",
    "4. 逐条漏洞详单",
    "5. 实际验证和终审理由",
    "6. 覆盖与未决项",
    "7. 附录与证据索引",
)

DISPOSITION_LABELS = {"accepted": "已接受", "pending": "待终审", "contested": "存疑/排除"}
EXECUTION_LABELS = {
    "success": "执行完成",
    "not_triggered": "执行完成，尚无确定结论",
    "not_run": "未执行",
    "authentication_failed": "身份认证失败",
    "state_mismatch": "账号状态不符",
    "environment_mismatch": "环境不符",
    "environment_unavailable": "环境不可用",
    "other_error": "执行失败",
    "conclusion_error": "已有成功作业，验证结论阶段未完成",
    "timeout": "执行超时",
}
VERIFICATION_LABELS = {
    "unverified": "未验证",
    "verified": "动态确认",
    "rejected": "动态反证",
    "inconclusive": "不确定",
    "stale": "已过期",
    "environment_unavailable": "环境不可用",
    "pending": "待验证",
}
VERDICT_LABELS = {"verified": "对照成立", "rejected": "结论被反证", "uncertain": "不确定"}
REVIEW_LABELS = {"confirmed": "复核确认", "contested": "复核存疑"}
PUBLISH_LABELS = {
    "releasable_final": "可发布（完整终审）",
    "releasable_partial": "可发布（阶段报告）",
    "review_required": "需要修复交付错误",
}
MAX_CELL = 160


def _safe_name(value: str) -> str:
    cleaned = str(value or "").replace("\\", "/").rsplit("/", 1)[-1].strip()[:120]
    return "".join(ch for ch in cleaned if ch.isprintable() and ch not in '/\\:*?"<>|') or "poc.php"


def _cell(value: object, limit: int = MAX_CELL) -> str:
    import json
    text = "—" if value is None or value == "" else (
        json.dumps(value, ensure_ascii=False, separators=(",", ":")) if isinstance(value, (dict, list)) else str(value))
    text = text.replace("\r", " ").replace("\n", " ").replace("|", "&#124;")
    return text[:limit] + ("…" if len(text) > limit else "")


def _fence(lines: list[str], lang: str = "") -> list[str]:
    return [f"```{lang}", *lines, "```"]


def _code_excerpt(entry: dict) -> list[str]:
    lines = [
        f"{int(line['number']):>5}  {line['text']}"
        for line in entry.get("excerpt") or [] if isinstance(line, dict)
    ]
    return _fence(lines, "php" if str(entry.get("path") or "").endswith(".php") else "")


def _location(claim: dict) -> str:
    primary = claim.get("primary_location") or {}
    if primary.get("path") and primary.get("line"):
        return f"{primary['path']}:{primary['line']}"
    evidence = claim.get("evidence") or []
    if evidence:
        ref = evidence[0]
        return f"{ref['path']}:{ref['range']['start']}-{ref['range']['end']}"
    return claim.get("file_path") or "位置未记录"


def _static_label(claim: dict) -> str:
    if claim.get("validation_errors"):
        return f"宿主校验有缺口（{len(claim['validation_errors'])} 项）"
    if claim.get("missing_context"):
        return f"缺上下文（{len(claim['missing_context'])} 项）"
    return "证据已记录"


def _verification_label(claim: dict) -> str:
    status = str(claim.get("verification_status") or "unverified")
    label = VERIFICATION_LABELS.get(status, status)
    verdict = VERDICT_LABELS.get(str(claim.get("verification_verdict") or ""))
    return f"{label}（{verdict}）" if verdict else label


def _review_for(facts: dict, claim: dict) -> dict | None:
    for review in facts.get("reviews") or []:
        ref = review.get("finding_ref") or {}
        if ref.get("finding_id") != claim["finding_id"]:
            continue
        if int(ref.get("revision") or 0) != int(claim["revision"]):
            continue
        if str(review.get("verification_id") or "") != str(claim.get("verification_id") or ""):
            continue
        return review
    return None


def _review_label(facts: dict, claim: dict) -> str:
    review = _review_for(facts, claim)
    if review is None:
        return "未复核"
    return REVIEW_LABELS.get(str(review.get("decision")), str(review.get("decision") or "未复核"))


def _attempt_for(facts: dict, claim: dict) -> dict | None:
    verification_id = str(claim.get("verification_id") or "")
    if not verification_id:
        return None
    return next((item for item in facts.get("verification_attempts") or []
                 if str(item.get("verification_id")) == verification_id), None)


def _attempts_for_entry(facts: dict, entry: dict) -> list[dict]:
    findings = {record["finding_id"] for record in entry.get("source_record_refs") or []}
    return [
        item for item in facts.get("verification_attempts") or []
        if str((item.get("finding_ref") or {}).get("finding_id") or "") in findings
    ]


def _number(entry: dict, index: int) -> str:
    return f"C-{index:02d}"


def _summary(facts: dict) -> list[str]:
    counts = facts["counts"]
    outcome = facts["run_outcome"]
    quality = facts.get("quality_result") or {}
    coverage = facts["coverage"]
    stop = outcome.get("stop_reason") or {}
    stop_text = "；".join(str(stop[key]) for key in ("code", "message") if stop.get(key)) or "—"
    lines = [
        f"## {SECTION_TITLES[0]}",
        "",
        f"- 运行：`{facts['provenance']['run_id']}`；状态：{outcome.get('status') or '—'}；停止原因：{_cell(stop_text)}",
        f"- 审计完整性：{'完成（状态、覆盖与验证均闭环）' if outcome.get('audit_complete') else '未完成，本报告为阶段报告'}",
        f"- 报告类型：{quality.get('report_kind', 'stage')}；发布状态：{PUBLISH_LABELS.get(quality.get('publishability'), quality.get('publishability') or '未评估')}",
        "",
        f"- 原始记录：{counts['raw_records']}",
        f"- 有效记录：{counts['valid_records']}",
        f"- 规范结论：{counts['canonical']}",
        f"- 已接受漏洞：{counts['accepted']}",
        f"- 待终审：{counts['pending']}",
        f"- 存疑或排除：{counts['contested']}",
        "",
        "“已接受漏洞”以当前版本的正式终审处置为准：静态证据充分可接受；动态已验证结论还须完成同版本观测复核。其余结论逐条保留，"
        "不会因为缺少终审额度而从报告中消失。",
        "",
        "| 完成维度 | 已完成 | 分母 | 说明 |",
        "|---|---:|---:|---|",
        f"| 源码覆盖（读取） | {coverage['files']['read']} | {coverage['files']['total']} | 已读只表示宿主记录过读取 |",
        f"| 源码覆盖（读取+带理由跳过） | {coverage['files']['reviewed']} | {coverage['files']['total']} | 跳过不是安全结论 |",
        f"| 必做方向结算 | {coverage['directions']['resolved'] + coverage['directions']['skipped']} | {coverage['directions'].get('required', coverage['directions']['total'])} | 未决 {coverage['directions']['unsettled']} 个 |",
        f"| 动态验证完成 | {coverage['verification']['verified'] + coverage['verification']['pending_review']} | {coverage['verification']['total']} | 待验证 {coverage['verification']['pending']} 条 |",
        f"| 正式复核 | {coverage['final_review']['accepted']} | {counts['canonical']} | 复核存疑或未复核不计入已接受 |",
        "",
    ]
    if coverage["files"]["pending"] is not None:
        lines.insert(len(lines) - 1, f"| 源码覆盖（仍待复核） | {max(0, coverage['files']['total'] - coverage['files']['reviewed'])} | "
                                     f"{coverage['files']['total']} | 未读且未跳过 {coverage['files']['pending']} 个 |")
    failed = quality.get("failed_checks") or []
    if failed:
        lines += [f"- 发布门禁未通过：{'、'.join(failed[:10])}"
                  + ("（其余见 result.json）" if len(failed) > 10 else ""), ""]
    accepted = [entry["canonical_id"] for entry in facts["canonical_findings"]
                if entry["final_disposition"] == "accepted"]
    if accepted:
        lines += ["**已接受漏洞**", ""]
        lines += [f"- {_number(entry, index)} {entry['frozen_claim']['title']}"
                  f"（{_location(entry['frozen_claim'])}）"
                  for index, entry in enumerate(facts["canonical_findings"], 1)
                  if entry["canonical_id"] in accepted]
        lines.append("")
    open_ids = {entry["canonical_id"] for entry in facts["canonical_findings"]
                if entry["final_disposition"] != "accepted"}
    if open_ids:
        lines += ["**仍需终审的结论**", ""]
        lines += [f"- {_number(entry, index)} {entry['frozen_claim']['title']}："
                  f"{DISPOSITION_LABELS[entry['final_disposition']]}——{entry['disposition_reason']}"
                  for index, entry in enumerate(facts["canonical_findings"], 1)
                  if entry["canonical_id"] in open_ids]
        lines.append("")
    return lines


def _scope(facts: dict) -> list[str]:
    provenance = facts["provenance"]
    appendix = facts.get("appendix") or {}
    usage = appendix.get("usage") or {}
    limits = usage.get("run_limits") or {}
    used = usage.get("run_usage") or {}
    context = usage.get("context") or {}
    lines = [
        f"## {SECTION_TITLES[1]}",
        "",
        f"- 项目：{_cell(provenance.get('project_id') or '—')}；快照：`{provenance['snapshot_id']}`",
        f"- 源码包哈希（archive sha256）：`{provenance['source_hash'] or '未记录'}`",
        f"- 事实包：{facts['schema_version']}；渲染器：{provenance['renderer_version']}；模板哈希：`{provenance['template_hash']}`",
        f"- 输入哈希：`{provenance['input_hash']}`；冻结时间：{provenance['frozen_at'] or '—'}；生成时间：{provenance['generated_at'] or '—'}",
        f"- 模型配置：{_cell(provenance.get('model') or '未记录')}；策略版本：{_cell(provenance.get('policy_version') or '未记录')}",
        "",
        "本次报告只使用宿主记录的冻结事实：源码引用由服务器从快照读取并核对哈希，"
        "动态验证取自隔离 runner 的作业记录，正式复核按 finding revision 与 verification id 精确引用。"
        "模型的结论陈述与修复建议以“结论陈述”标注，不作为证据；未执行、环境失败与验证不确定都不解释为误报。",
        "",
        "| 预算 | 上限 | 实际使用 | 剩余 |",
        "|---|---:|---:|---:|",
    ]
    for key, label in (("responses", "模型响应"), ("tools", "工具调用"), ("seconds", "秒")):
        if key in limits or key in used:
            lines.append(f"| {label} | {_cell(limits.get(key, '—'))} | {_cell(used.get(key, '—'))} | "
                         f"{_cell((usage.get('run_remaining') or {}).get(key, '—'))} |")
    if not limits and not used:
        lines.append("| 运行预算 | — | — | — |")
    if context:
        lines += [
            "",
            f"- 上下文：峰值请求 {context.get('peak_request_bytes', '—')} 字节 / 上限 "
            f"{context.get('history_bytes', '—')} 字节；摘要请求 {context.get('summary_requests', 0)} 次；"
            f"硬上限命中 {context.get('limit_hits', 0)} 次。",
        ]
    poc = usage.get("poc") or {}
    workflow = usage.get("workflow") or {}
    if workflow:
        lines += ["", "| 阶段 | 请求配额 | 已用 |", "|---|---:|---:|"]
        for key, label in (("discovery", "源码挖掘"), ("poc", "POC 验证"), ("review", "统一终审")):
            lines.append(f"| {label} | {workflow['limits'].get(key, '—')} | {workflow['used'].get(key, '—')} |")
        reserve = workflow.get("review_reserve") or {}
        lines.append(f"- 调度政策：{workflow.get('version', '—')}；配额：{'固定分配' if workflow.get('source') == 'explicit' else '自动分配'}。")
        if reserve:
            lines.append(f"- 待终审 {reserve.get('pending_items', 0)} 项，预计 {reserve.get('estimated_batches', 0)} 批；"
                         f"当前预留 {reserve.get('responses', 0)} 次请求、{reserve.get('seconds', 0)} 秒；按实际批次容量与 Worker 调整，不增加整次额度。")
    if poc:
        lines.append("- POC 执行：" + "；".join(
            f"{label} {poc.get(key, '—')}" for key, label in
            (("jobs", "作业"), ("resets", "复位"), ("recorded", "已记录"), ("confirmed", "确认"))
            if key in poc) + "。")
    lines.append("")
    return lines


def _inventory(facts: dict) -> list[str]:
    lines = [
        f"## {SECTION_TITLES[2]}",
        "",
        "| 编号 | 标题 | 类型 | 评分 | 位置 | 静态判读 | 动态验证 | 正式终审 | 处置 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for index, entry in enumerate(facts["canonical_findings"], 1):
        claim = entry["frozen_claim"]
        lines.append("| " + " | ".join([
            _number(entry, index),
            _cell(claim["title"], 60),
            _cell(claim.get("vulnerability_type") or claim.get("category") or "—"),
            _cell(claim.get("rating_text"), 70),
            _cell(_location(claim), 70),
            _cell(_static_label(claim)),
            _cell(_verification_label(claim)),
            _cell(_review_label(facts, claim)),
            f"{DISPOSITION_LABELS[entry['final_disposition']]}：{_cell(entry['disposition_reason'], 70)}",
        ]) + " |")
    if not facts["canonical_findings"]:
        lines.append("| — | 本次运行没有可交付的规范结论 | — | — | — | — | — | — | — |")
    lines.append("")
    return lines


def _detail(facts: dict) -> list[str]:
    lines = [f"## {SECTION_TITLES[3]}", ""]
    evidence = {item["evidence_id"]: item for item in facts.get("source_evidence") or []}
    for index, entry in enumerate(facts["canonical_findings"], 1):
        claim = entry["frozen_claim"]
        number = _number(entry, index)
        lines += [
            f"### {number} {claim['title']}",
            "",
            f"- 当前版本：finding `{claim['finding_id']}` revision {claim['revision']}"
            f"（项目版本 {claim['project_revision']}）；CVSS 评分版本 {entry['assessment_revision'] or '—'}",
            f"- 位置：`{_location(claim)}`；文件：`{claim.get('file_path') or '未记录'}`",
            f"- 证据引用：" + ("；".join(
                f"`{ref['evidence_id']}` {ref['path']}:{ref['range']['start']}-{ref['range']['end']}"
                for ref in claim["evidence"]) or "无"),
            f"- 根因类别：{_cell(claim.get('category') or '—')}（规范类型 {_cell(claim.get('vulnerability_type') or '—')}）",
            "",
            "**结论陈述（模型产出，不是证据）**",
            "",
            _cell(claim.get("summary") or "未提供", 2000),
            "",
            f"- 攻击前身份与适用前提：{_cell('；'.join(claim.get('preconditions') or []) or '未声明', 600)}",
            f"- 入口 → 传播 → 危险操作/状态变更：{_cell(claim.get('input_source') or '未记录', 300)}"
            f" → {_cell(claim.get('propagation') or '未记录', 300)} → {_cell(claim.get('dangerous_operation') or '未记录', 300)}",
            f"- 防护与边界：{_cell(claim.get('protection') or '未记录', 400)}",
            f"- 静态判读：{_static_label(claim)}"
            + (f"；缺失上下文：{_cell('；'.join(claim.get('missing_context') or []), 400)}"
               if claim.get("missing_context") else ""),
            f"- 动态验证：{_verification_label(claim)}"
            + (f"（verification `{claim['verification_id']}`）" if claim.get("verification_id") else ""),
            f"- 正式终审：{('独立批次 ' + entry['final_batch_review']['batch_id']) if entry.get('final_batch_review') else _review_label(facts, claim)}；处置：{DISPOSITION_LABELS[entry['final_disposition']]}"
            f"——{entry['disposition_reason']}",
            "",
        ]
        attempt = _attempt_for(facts, claim)
        if entry["final_disposition"] == "accepted" and attempt is not None and entry.get("acceptance_basis") != "static_review":
            lines += ["**实际影响（来自动态验证观测）**", "",
                      _cell(attempt.get("attack_evidence") or "未记录", 1200), ""]
        else:
            lines += ["**实际影响**", "",
                      "未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。", ""]
        assessment = entry.get("frozen_cvss_assessment") or {}
        lines += [
            f"- 评分依据：{_cell(claim.get('rating_text'))}；引擎 {_cell(assessment.get('engine_version') or '未记录')}；"
            f"适用结论版本 {assessment.get('conclusion_revision', '—')}",
            f"- 修复方案（结论陈述）：{_cell(claim.get('remediation') or '未提供', 1200)}",
            "",
            "**源码片段（宿主从冻结快照读取）**",
            "",
        ]
        shown = False
        for ref in claim["evidence"]:
            fact = evidence.get(ref["evidence_id"])
            if fact is None:
                continue
            if fact.get("available"):
                lines.append(f"`{fact['path']}:{fact['range']['start']}-{fact['range']['end']}`"
                             f"（sha256 `{(fact.get('content_hash') or '')[:16]}…`）")
                lines.append("")
                lines += _code_excerpt(fact)
                if fact.get("truncated"):
                    lines += ["", "片段按上限截断；完整内容见证据索引。"]
                lines.append("")
                shown = True
        if not shown:
            reasons = [f"{fact['path']}:{fact['range']['start']}-{fact['range']['end']}：{fact.get('reason') or '无可用片段'}"
                       for fact in evidence.values()
                       if fact["evidence_id"] in {ref["evidence_id"] for ref in claim["evidence"]}]
            lines += ["源码片段不可用——" + ("；".join(reasons) or "该结论没有有效的源码证据引用。"), ""]
            lines.append("")
        if claim.get("validation_errors"):
            lines += ["**宿主校验缺口**", ""] + [f"- {_cell(item, 400)}" for item in claim["validation_errors"]] + [""]
    if not facts["canonical_findings"]:
        lines += ["本次运行没有规范结论，因此没有逐条详单。", ""]
    return lines


def _verification(facts: dict) -> list[str]:
    lines = [f"## {SECTION_TITLES[4]}", ""]
    reviews = facts.get("reviews") or []
    for index, entry in enumerate(facts["canonical_findings"], 1):
        claim = entry["frozen_claim"]
        attempts = _attempts_for_entry(facts, entry)
        related = [review for review in reviews
                   if (review.get("finding_ref") or {}).get("finding_id")
                   in {record["finding_id"] for record in entry["source_record_refs"]}]
        if not attempts and not related:
            continue
        lines += [f"### {_number(entry, index)} {claim['title']}", ""]
        for attempt in attempts:
            ref = attempt.get("finding_ref") or {}
            lines += [
                f"- verification `{attempt['verification_id']}`（finding `{ref.get('finding_id')}` revision "
                f"{ref.get('revision')}，context `{attempt.get('context_id') or '—'}`，target "
                f"{_cell(attempt.get('target_version') or '—')}）",
                f"  - 执行状态：{EXECUTION_LABELS.get(str(attempt.get('execution_status')), attempt.get('execution_status') or '—')}；"
                f"判定：{VERDICT_LABELS.get(str(attempt.get('verdict')), attempt.get('verdict') or '—')}；来源：{_cell(attempt.get('source') or '—')}",
                f"  - 正常侧观测：{_cell(attempt.get('normal_evidence') or '未记录', 800)}",
                f"  - 攻击侧观测：{_cell(attempt.get('attack_evidence') or '未记录', 800)}",
            ]
            availability = attempt.get("fact_availability") or {}
            if availability.get("jobs_total"):
                lines.append(f"  - 已保存作业事实：{availability['jobs_total']} 个；"
                             f"满足执行及前提检查的作业：{availability.get('successful_jobs', 0)} 个。"
                             "作业完成不等同于漏洞成立。")
                if availability.get("conclusion_missing"):
                    lines.append("  - 结论未完整发布；缺少正常／攻击侧发布内容不代表没有执行观测。")
                if attempt.get("observed_job_ids"):
                    lines.append("  - 已观测作业 ID：" + "；".join(
                        f"`{_cell(ident)}`" for ident in attempt["observed_job_ids"]))
            if attempt.get("conclusion_reason") or attempt.get("execute_reason"):
                lines.append(f"  - 结论结束原因：{_cell(attempt.get('conclusion_reason') or '未记录')}；"
                             f"执行阶段结束原因：{_cell(attempt.get('execute_reason') or '未记录')}")
            jobs = attempt.get("job_refs") or []
            if jobs:
                lines.append("  - 作业：" + "；".join(
                    f"`{job.get('job_id')}` {job.get('kind') or ''} {job.get('status') or ''}"
                    f" exit={job.get('exit_code')}" for job in jobs[:12]))
            artifacts = attempt.get("artifacts") or []
            if artifacts:
                lines.append("  - 产物：" + "；".join(
                    f"`{item.get('path') or item.get('name') or '—'}`" for item in artifacts[:12]))
            if attempt.get("final_script"):
                # The script itself travels in the archive; the body names the file so a
                # reader can find it rather than trusting a snippet pasted here.
                filename = _safe_name((claim.get("poc") or {}).get("filename") or "poc.php")
                lines.append(f"  - 适配脚本：`{str(attempt['verification_id'])[:8]}-adapted-{filename}`（见证据包 evidence/）")
            if attempt.get("notes"):
                lines.append(f"  - 备注：{_cell(attempt['notes'], 600)}")
            lines.append("")
        for review in related:
            lines += [
                f"- 正式复核 `{review.get('review_id')}`：{REVIEW_LABELS.get(str(review.get('decision')), review.get('decision') or '—')}；"
                f"引用 revision {(review.get('finding_ref') or {}).get('revision')} / verification "
                f"`{review.get('verification_id') or '—'}`",
                f"  - 理由：{_cell(review.get('rationale') or '未记录', 800)}",
            ]
            if review.get("observed_normal") or review.get("observed_attack"):
                lines.append(f"  - 复核观测：正常侧 {_cell(review.get('observed_normal') or '未记录', 400)}；"
                             f"攻击侧 {_cell(review.get('observed_attack') or '未记录', 400)}")
            lines.append("")
    if len(lines) == 2:
        lines += ["本次运行没有动态验证或正式复核记录；相关结论均标注为未验证/未复核。", ""]
    return lines


def _coverage(facts: dict) -> list[str]:
    coverage = facts["coverage"]
    lines = [
        f"## {SECTION_TITLES[5]}",
        "",
        "| 独立分母 | 总数 | 已结算 | 未决/待办 | 闭环 |",
        "|---|---:|---:|---:|---|",
        f"| 文件覆盖 | {coverage['files']['total']} | 读取 {coverage['files']['read']}；读取+跳过 {coverage['files']['reviewed']} | "
        f"{coverage['files']['pending'] if coverage['files']['pending'] is not None else '—'} | "
        f"{_complete(coverage['files'].get('complete'))} |",
        f"| 必做方向 | {coverage['directions'].get('required', coverage['directions']['total'])} | 已决 {coverage['directions']['resolved']}；跳过 {coverage['directions']['skipped']} | "
        f"{coverage['directions']['unsettled']} | {_complete(coverage['directions'].get('complete'))} |",
        f"| 动态验证 | {coverage['verification']['total']} | 已验证 {coverage['verification']['verified']}；已复核记录 {coverage['verification']['reviewed']} | "
        f"待验证 {coverage['verification']['pending']}；待复核 {coverage['verification']['pending_review']} | — |",
        f"| 正式终审 | {coverage['final_review']['accepted'] + coverage['final_review']['pending'] + coverage['final_review']['contested']} | "
        f"已接受 {coverage['final_review']['accepted']} | 待终审 {coverage['final_review']['pending']}；存疑 {coverage['final_review']['contested']} | — |",
        "",
    ]
    skips = (coverage.get("files") or {}).get("skip_details") or []
    if skips:
        lines += ["**带理由跳过的文件**", ""]
        lines += [f"- `{item.get('path')}`：{_cell(item.get('reason') or '未提供理由', 300)}" for item in skips[:40]]
        lines.append("")
    items = facts.get("action_items") or []
    advisory = facts.get("advisory_directions") or []
    if advisory:
        lines += ["**后续建议（不阻止本次收束）**", ""]
        lines += [f"- `{item['id']}`：{_cell(item.get('text'), 600)}" for item in advisory]
        lines.append("")
    if items:
        lines += ["**补证与未决动作**", ""]
        for item in items:
            target = item.get("object") or item.get("other") or ""
            label = f"`{target}` " if target else ""
            count = f"{item['count']} 项：" if item.get("count") else ""
            lines.append(f"- {label}{count}{_cell(item.get('action'), 500)}"
                         + (f"（{_cell(item.get('title'), 80)}）" if item.get("title") else ""))
        lines.append("")
    lines += ["**限制**", ""] + [f"- {_cell(item, 400)}" for item in facts.get("limitations") or []] + [""]
    return lines


def _complete(value: object) -> str:
    return "是" if value is True else "否" if value is False else "—"


def _appendix(facts: dict) -> list[str]:
    appendix = facts.get("appendix") or {}
    lines = [f"## {SECTION_TITLES[6]}", ""]
    multi = [entry for entry in facts["canonical_findings"]
             if len(entry["source_record_refs"]) > 1]
    if multi:
        lines += ["**历史版本与来源记录**", "",
                  "| 规范结论 | finding | revision | 处置 | 验证 | 当前 |", "|---|---|---:|---|---|---|"]
        for entry in multi:
            for record in entry["source_record_refs"]:
                lines.append(f"| `{entry['canonical_id']}` | `{record['finding_id']}` | {record['revision']} | "
                             f"{_cell(record['disposition'])} | {_cell(record['verification_status'])} | "
                             f"{'是' if record.get('current') else '否'} |")
        lines.append("")
    withdrawn = appendix.get("withdrawn") or []
    if withdrawn:
        lines += ["**撤回、重复或替代记录**", ""]
        lines += [f"- `{item['finding_id']}`（revision {item['revision']}）：{_cell(item['disposition'])}"
                  f"——{_cell(item.get('title'), 120)}" for item in withdrawn[:80]]
        lines.append("")
    pairs = appendix.get("duplicate_pairs") or []
    comparisons = appendix.get("comparison_pairs") or []
    if comparisons:
        lines += ["**关联链路对照（位置或引用关联不代表重复）**", ""]
        lines += [f"- `{pair['canonical_ids'][0]}` ↔ `{pair['canonical_ids'][1]}`："
                  f"{'已明确区分根因' if pair['status'] == 'distinct' else '仍需对照判读'}；{_cell(pair.get('rationale'), 400)}"
                  for pair in comparisons]
        lines.append("")
    if pairs:
        lines += ["**疑似跨台账重复（仅建议，未合并）**", ""]
        lines += [f"- `{pair['canonical_ids'][0]}` ↔ `{pair['canonical_ids'][1]}`：{_cell(pair.get('basis'), 300)}"
                  for pair in pairs[:40]]
        lines.append("")
    tasks = appendix.get("tasks") or []
    if tasks:
        lines += ["**任务记录**", "", "| 任务 | 标题 | 状态 | 错误 |", "|---|---|---|---|"]
        lines += [f"| `{_cell(task.get('id'))}` | {_cell(task.get('title'), 80)} | {_cell(task.get('state'))} | "
                  f"{_cell(task.get('error'), 120)} |" for task in tasks[:40]]
        lines.append("")
    usage = appendix.get("usage") or {}
    if usage.get("run_limits") or usage.get("run_usage"):
        def _pair(value: object) -> str:
            if not isinstance(value, dict):
                return "—"
            return "；".join(
                f"{label} {value[key]}" for key, label in
                (("responses", "响应"), ("tools", "工具"), ("seconds", "秒")) if key in value
            ) or "—"
        lines += [f"- 用量：上限 {_pair(usage.get('run_limits'))}；实际 {_pair(usage.get('run_usage'))}；"
                  f"剩余 {_pair(usage.get('run_remaining'))}", ""]
    evidence = facts.get("source_evidence") or []
    if evidence:
        lines += ["**证据索引（服务器读取）**", "",
                  "| evidence_id | 路径 | 范围 | 文件哈希 | 可用 |", "|---|---|---|---|---|"]
        lines += [f"| `{item['evidence_id']}` | {_cell(item['path'], 100)} | "
                  f"{item['range']['start']}-{item['range']['end']} | "
                  f"`{(item.get('content_hash') or '')[:16]}` | {'是' if item.get('available') else '否'} |"
                  for item in evidence[:120]]
        lines.append("")
    if facts.get("observations"):
        lines += ["**来源观察（不计入漏洞数）**", ""]
        lines += [f"- `{item['finding_id']}`：{_cell(item.get('title'), 120)}" for item in facts["observations"][:60]]
        lines.append("")
    narrative = facts.get("narrative") or {}
    if narrative:
        lines += ["**运行叙述（模型产出，不是证据）**", ""]
        for key, value in narrative.items():
            text = value if isinstance(value, str) else "\n".join(str(item) for item in value)
            lines += [f"- {key}：{_cell(text, 800)}"]
        lines.append("")
    artifacts = appendix.get("artifacts") or {}
    lines += ["**附件与机器可读清单**", "",
              f"- Markdown：本报告（由事实包确定性生成）。",
              f"- JSON：{_cell(artifacts.get('json'), 200)}",
              f"- 证据包：{_cell(artifacts.get('evidence_dir'), 200)}",
              f"- 源码：{_cell(artifacts.get('source'), 200)}",
              f"- 事实包 ID：`{facts['provenance']['input_hash']}`；页面、Markdown、JSON 与证据包共用同一份事实。",
              ""]
    return lines


def render_final_report(facts: dict) -> str:
    """Render the seven-section report from one fact package."""
    provenance = facts.get("provenance") or {}
    quality = facts.get("quality_result") or {}
    kind = "完整终审报告" if quality.get("report_kind") == "final" else "阶段报告"
    publish = PUBLISH_LABELS.get(quality.get("publishability"), quality.get("publishability") or "未评估")
    lines = [
        f"# 源码审计{kind}（{str(provenance.get('run_id') or '')[:8]}）",
        "",
        f"> 报告类型：{kind}；发布状态：{publish}",
        f"> 事实包 {facts.get('schema_version')} · 渲染器 {provenance.get('renderer_version')} · "
        f"策略 {provenance.get('policy_version') or '未记录'}",
        f"> 运行 `{provenance.get('run_id')}` · 快照 `{provenance.get('snapshot_id')}` · "
        f"源码哈希 `{(provenance.get('source_hash') or '未记录')[:16]}…` · 输入哈希 `{provenance.get('input_hash')}`",
        "> 本报告由宿主从冻结事实包确定性生成；数量、位置、验证状态与评分均不由模型填写。",
        "",
    ]
    lines += _summary(facts)
    lines += _scope(facts)
    lines += _inventory(facts)
    lines += _detail(facts)
    lines += _verification(facts)
    lines += _coverage(facts)
    lines += _appendix(facts)
    return "\n".join(lines).rstrip("\n") + "\n"
