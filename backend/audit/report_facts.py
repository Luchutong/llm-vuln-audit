"""Validate narrative references; persisted host facts remain authoritative."""
from .finding_policy import is_vulnerability_finding

def validate_report_references(report: dict, run_context: dict) -> None:
    from .db import WITHDRAWN_FINDING_DISPOSITIONS
    active = {f["id"]: int(f.get("revision") or 1) for f in run_context.get("findings", [])
              if f.get("validation_state") == "candidate" and f.get("disposition", "open") not in WITHDRAWN_FINDING_DISPOSITIONS and is_vulnerability_finding(f)}
    refs = {r.get("finding_id"): r.get("revision") for r in report.get("finding_refs", [])}
    if refs != active:
        raise ValueError("报告发现引用存在遗漏、外部 ID 或过期修订")
    tasks = {t["id"]: t for t in run_context.get("tasks", [])}
    for task_id in report.get("no_evidence_task_ids", []):
        task = tasks.get(task_id)
        result = (task or {}).get("result") or {}
        if not task or task.get("state") != "completed" or result.get("outcome") != "no_evidence":
            raise ValueError("报告无证据引用包含未执行、受阻或非无证据任务")

def render_host_summary(summary: dict) -> str:
    reason = summary.get("stop_reason") or {}
    doc = ["# 宿主阶段审计报告", "", f"运行：`{summary['run_id']}`", f"状态：{summary['status']}；完整性：{'已完成' if summary['complete'] else '未完成'}", f"停止原因：{reason.get('message') or reason.get('code')}", "", f"运行发现原始记录：{summary['raw_finding_count']}；当前有效记录：{summary['valid_finding_count']}；按台账身份分组：{summary['ledger_group_count']}", "", "## 当前有效发现", ""]
    for group in summary["finding_groups"]:
        doc += [f"### 台账 `{group['id']}`", ""]
        for finding in group["findings"]:
            doc += [f"- {finding.get('title')}（{finding.get('severity')}，验证：{finding.get('verification_status')}）", f"  来源 `{finding['id']}` / 修订 {finding.get('revision')}", f"  证据：{finding.get('evidence') or '见漏洞详情'}"]
            for field, label in (("summary", "结论"), ("input_source", "输入"), ("propagation", "传播"), ("dangerous_operation", "危险操作"), ("protection", "保护"), ("preconditions", "前提"), ("remediation", "修复建议")):
                if finding.get(field):
                    doc += [f"  {label}：{finding[field]}"]
            if finding.get("poc"):
                doc += ["", "可复核 POC（是否执行以验证记录为准）：", "", "````text", str(finding["poc"]), "````", ""]
        doc += [""]
    doc += ["## 覆盖与未决方向", "", "受阻、未执行、未读取方向均不代表安全。", ""]
    for task in summary["tasks"]:
        doc += [f"- {task['state']} · {task.get('title') or task['id']}：{task.get('error') or ''}"]
    import json
    doc += ["", "## 预算与覆盖事实", "", "```json", json.dumps({"execution": summary.get("execution"), "coverage": summary.get("coverage")}, ensure_ascii=False, indent=2), "```", ""]
    return "\n".join(doc)
