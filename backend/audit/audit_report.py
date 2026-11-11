"""One audit report plus its owned frozen evidence, without diagnostic exports."""
from __future__ import annotations

import io
import json
import zipfile

from . import report_readable as r

VERSION = "audit-evidence-report/v1"
TEMPLATE = "audit-evidence-2026-11-11-r2"


def document(frozen):
    doc = r.document(frozen, "report")
    doc["schema_version"] = VERSION
    # The derived report binds to input/facts. Including its own archive hash
    # would make first materialization and subsequent exports disagree.
    doc["source_hashes"].pop("archive_output", None)
    doc["source_hashes"].update(renderer=VERSION, template=r.digest(TEMPLATE))
    # SQLite freezes objects with sorted keys; first render and later reads must
    # present nested mappings in the same order as well.
    return json.loads(r.dump(doc))


def markdown(doc):
    lines = r._header(doc, "审计报告")
    outcome = doc.get("run_outcome") or {}
    counts = doc["counts"]
    lines += ["## 结果与完成性", "",
              "本轮冻结政策的完成条件已满足。" if outcome.get("audit_complete") is True else
              "本轮为阶段结果；尚未满足整体完成条件。", "",
              f"终审接受 {counts['accepted']}；待终审 {counts['pending']}；存疑或排除 {counts['contested']}。", "",
              "执行状态：" + r.text(outcome.get("status")) + "；停止原因：" + r.text(
                  (outcome.get("stop_reason") or {}).get("message") or (outcome.get("stop_reason") or {}).get("code")), "",
              "静态终审结论与动态验证分别标注；未执行实验不代表已复现。", "",
              "## 漏洞清单", ""]
    entries = r._ordered(doc)
    if entries:
        # The sole report uses local anchors instead of generating N other reports.
        inventory = "\n".join(r._inventory(doc, entries))
        for number in doc["numbering"].values():
            inventory = inventory.replace(f"findings/{number}.md", f"#{number.lower()}")
        lines += [inventory, ""]
    else:
        lines += ["本轮未形成漏洞结论；这不构成项目安全的证明。", ""]
    coverage = doc.get("coverage") or {}
    files, directions, verification = (coverage.get(key) or {} for key in ("files", "directions", "verification"))
    lines += ["## 覆盖与未完成工作", "",
              f"应审文件 {r.text(files.get('total'))}；实际读取 {r.text(files.get('read'))}；"
              f"读取或带理由跳过后复核 {r.text(files.get('reviewed'))}；跳过 {r.text(files.get('skipped'))}；"
              f"待复核 {r.text(files.get('pending'))}。", "",
              f"必做方向 {r.text(directions.get('required'))}；已解决 {r.text(directions.get('resolved'))}；"
              f"明确跳过 {r.text(directions.get('skipped'))}；未结算 {r.text(directions.get('unsettled'))}。", "",
              f"动态验证：当前通过 {r.text(verification.get('verified'))}；待验证 {r.text(verification.get('pending'))}；"
              f"待独立复核 {r.text(verification.get('pending_review'))}。", "",
              "读取和跳过的计数不代表安全覆盖率。", ""]
    for item in files.get("skip_details") or []:
        lines += [f"- 跳过 {r.text(item.get('path'))}：{r.text(item.get('reason'))}"]
    risk = doc.get("risk_obligations") or {}
    if risk:
        lines += ["", f"风险义务：必做 {r.text(risk.get('required'))}；未结算必做 {r.text(risk.get('pending_required'))}。", "",
                  r.text(risk.get("limitations")), ""]
    if doc.get("action_items"):
        lines += ["未完成事项：", "", r.text(doc["action_items"]), ""]
    lines += ["## 结论与证据", ""]
    for entry in entries:
        claim = entry["frozen_claim"]
        number = doc["numbering"][entry["canonical_id"]]
        final = entry.get("final_batch_review") or {}
        lines += [f'<a id="{number.lower()}"></a>', "", f"### {number} {r.cell(claim.get('title'))}", "",
                  f"终审：{r.DISPOSITIONS.get(entry.get('final_disposition'), '暂无数据')}；"
                  f"动态验证：{r.verification_label(claim)}；CVSS 3.1：{r.text(r.rating_summary(claim))}", "",
                  f"主位置：{r.text(r._location(claim))}；结论版本：{r.text(claim.get('revision'))}；"
                  f"评分版本：{r.text(entry.get('assessment_revision'))}", "",
                  r.text(claim.get("summary")), "",
                  "利用前提：" + r.text(claim.get("preconditions")), ""]
        for key, label in (("input_source", "可控输入"), ("propagation", "传播路径"),
                           ("dangerous_operation", "危险操作"), ("protection", "防护及缺口"), ("dataflow", "根因与数据流")):
            if claim.get(key):
                lines += [label + "：", "", r.text(claim[key]), ""]
        focus = final.get("focus") or {}
        if focus:
            lines += ["目标关联：" + r.text(focus), ""]
        lines += ["终审依据：" + r.text(final.get("rationale") or entry.get("disposition_reason")), ""]
        if claim.get("missing_context") or entry.get("conflicts"):
            lines += ["限制与反证：", "", r.text(claim.get("missing_context")), "", r.text(entry.get("conflicts")), ""]
        _, reviews, sources = r._related(doc, entry)
        lines += ["源码证据（原文及哈希见配套证据包 evidence.json）：", ""]
        for source in sources:
            location = f"{source.get('path')}:{(source.get('range') or {}).get('start')}-{(source.get('range') or {}).get('end')}"
            status = ("冻结片段" + ("，冻结时截断" if source.get("truncated") else "")) if source.get("available") else (
                "不可用：" + str(source.get("reason") or "未冻结源码片段"))
            lines += [f"- {r.text(source.get('evidence_id'))} · {r.text(location)} · {r.text(status)}"]
        if not sources:
            lines += ["未冻结源码片段；不以当前仓库内容补写历史证据。"]
        elif {ref.get("evidence_id") for ref in claim.get("evidence") or []} - {s.get("evidence_id") for s in sources}:
            lines += ["部分引用未冻结源码片段；缺失项见 manifest.json。"]
        lines += [""]
        poc = claim.get("poc") or {}
        for key, label in (("instructions", "待执行步骤"), ("normal_input", "预期正常对照"),
                           ("attack_input", "预期攻击输入"), ("expected_result", "预期判别条件")):
            if poc.get(key):
                lines += [label + "：", "", r.text(poc[key]), ""]
        attempts, _, _ = r._related(doc, entry)
        if not attempts:
            lines += ["未保存动态执行记录。", ""]
        for attempt in attempts:
            current = attempt.get("finding_ref") == {k: entry["current_claim_ref"][k] for k in ("finding_id", "revision")}
            lines += [f"实际实验 {r.text(attempt.get('verification_id'))}（{'当前修订' if current else '历史修订'}）："
                      f"{r.text(attempt.get('execution_status'))} / {r.text(attempt.get('verdict'))}", "",
                      "正常观测：" + r.text(attempt.get("normal_evidence")), "",
                      "攻击观测：" + r.text(attempt.get("attack_evidence")), "",
                      "判定依据：" + r.text(attempt.get("conclusion_reason")), ""]
            if attempt.get("inherited_from"):
                lines += ["继承验证（保留原始实验来源，未视为本轮重新执行）：", "", r.text(attempt["inherited_from"]), ""]
            if attempt.get("experiment_context"):
                lines += ["实验身份与前提：", "", r.text(attempt["experiment_context"]), ""]
        for review in reviews:
            lines += ["动态独立复核：" + r.text(review.get("rationale")), ""]
        cvss = claim.get("cvss") or {}
        assessment = entry.get("frozen_cvss_assessment") or {}
        if cvss or assessment:
            lines += ["CVSS 3.1 依据：", "", r.text(cvss.get("base_vector") or cvss.get("vector")), "",
                      r.text(assessment.get("metric_details") or assessment.get("metrics") or assessment.get("cvss_input")
                             or assessment.get("metric_proposals")), ""]
        # Existing helpful material is preserved, but never requested to fill a template.
        for key, label in (("remediation", "已有修复建议"), ("retest", "已有修复后复测说明")):
            if claim.get(key):
                lines += [label + "：", "", r.text(claim[key]), ""]
    lines += ["## 限制与追溯", "", r.text(doc.get("limitations")), "",
              f"运行：{r.text(doc['scope']['run_id'])}；源码快照：{r.text(doc['metadata']['snapshot_id'])}", "",
              r.text(doc["source_hashes"]), "",
              "配套证据包包含本报告、冻结证据索引、源码片段、已保存的实验材料及哈希清单；缺失附件在 manifest.json 明示。", ""]
    return "\n".join(lines)


def evidence(doc):
    keys = ("canonical_id", "current_claim_ref", "source_record_refs", "assessment_revision", "frozen_claim",
            "frozen_cvss_assessment", "final_disposition", "disposition_reason", "final_batch_review", "conflicts")
    return {"schema_version": VERSION, **{key: doc.get(key) for key in (
        "scope", "metadata", "source_hashes", "numbering", "counts", "run_outcome", "coverage",
        "risk_obligations", "action_items", "limitations", "source_evidence", "verification_attempts", "reviews")},
        "canonical_findings": [{key: entry[key] for key in keys if key in entry} for entry in doc["canonical_findings"]]}


def export(frozen, *, format="markdown"):
    doc = document(frozen)
    md = markdown(doc).encode()
    if format == "markdown":
        return md
    facts = evidence(doc)
    if format == "json":
        return r.dump(facts).encode()
    if format != "zip":
        raise ValueError("Unsupported audit report format")
    files, missing = r._attachments(frozen, doc, declared_only=True)
    files.update({"audit-report.md": md, "evidence.json": r.dump(facts).encode()})
    sources = []
    for index, source in enumerate(doc["source_evidence"]):
        if source.get("available"):
            fragment = "\n".join(str(line["number"]) + "\t" + line["text"] for line in source.get("excerpt") or []).encode()
            sources.append({"evidence_id": source.get("evidence_id"), "member": "evidence.json",
                            "pointer": f"/source_evidence/{index}", "fragment_sha256": r.digest(fragment),
                            "source_file_hash": source.get("content_hash"), "path": source.get("path"),
                            "range": source.get("range"), "truncated_at_freeze": bool(source.get("truncated"))})
        else:
            missing.append({"evidence_id": source.get("evidence_id"), "reason": source.get("reason") or "source_not_frozen"})
    recorded = {source.get("evidence_id") for source in doc["source_evidence"]}
    required = {ref.get("evidence_id") for entry in doc["canonical_findings"] for ref in entry["frozen_claim"].get("evidence") or []}
    missing += [{"evidence_id": key, "reason": "source_not_frozen"} for key in sorted(required - recorded, key=str)]
    files["manifest.json"] = r.dump({"schema_version": VERSION, "main_document": "audit-report.md",
        "scope": doc["scope"], "source_hashes": doc["source_hashes"], "numbering": doc["numbering"],
        "artifact_hashes": {name: r.digest(data) for name, data in sorted(files.items())},
        "source_fragments": sources, "missing_attachments": missing,
        "evidence_display": "Markdown 展示脱敏；evidence.json 和原始附件保留冻结证据及其哈希。"}).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return buffer.getvalue()
