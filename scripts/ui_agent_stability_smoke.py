#!/usr/bin/env python3
"""Agent diagnostics acceptance using intercepted APIs only; no audits or live DB writes.

Serve frontend/dist on an unused localhost port, then run this script against it.
All API requests are fulfilled in memory; mutations are rejected by this fixture.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from playwright.sync_api import expect, sync_playwright
from ui_fixtures import COMPLETED_ID, LEDGER_ID, STAMP, event, sources_api, verification_record
from ui_smoke import Checks, goto, no_overflow, open_logs, save


def diagnostic_events():
    def frame(number, kind, request=1, **payload):
        return event(COMPLETED_ID, number, kind, {
            "role": "worker", "agent_invocation_id": "worker-diagnostics", "request_index": request,
            "phase": "task_execute", **payload,
        })

    return [frame(1, "model_request"),
            frame(2, "agent_parse_error", category="incomplete_code", error="loop body is incomplete",
                  hint="请提交完整的循环体", diagnostics={"closed_blocks": 1, "syntax_line": 2, "finish_reason": "stop"}),
            frame(3, "model_request", 2),
            frame(4, "tool_call", 2, tool="read_source", span_id="source-1", call_id="source-1",
                  args={"path": "src/upload.php", "start": True, "end": 12}),
            frame(5, "tool_result", 2, tool="read_source", span_id="source-1", call_id="source-1",
                  status="invalid_arguments", error_code="invalid_arguments", error="start must be an integer",
                  hint="起始行不能是布尔值", args={"path": "src/upload.php", "start": True, "end": 12}),
            frame(6, "agent_execution_error", 2, error_code="invalid_arguments", error="start must be an integer", hint="起始行不能是布尔值"),
            frame(7, "agent_code", 2, error="tool arguments rejected", code="print(read_source('src/upload.php', True, 12))"),
            frame(8, "model_request", 3),
            frame(9, "agent_code", 3, code="print('读取完成')", logs="读取完成", is_final=True),
            frame(10, "tool_call", role="poc", agent_invocation_id="poc-diagnostics", phase="poc_execute",
                  tool="run_poc", span_id="script-1", call_id="script-1", args={"language": "python", "script": "raise SystemExit(2)"}),
            frame(11, "tool_result", role="poc", agent_invocation_id="poc-diagnostics", phase="poc_execute",
                  tool="run_poc", span_id="script-1", call_id="script-1", status="ok", exit_code=2, execution_status="failed", preview="script failed"),
            frame(12, "poc_job_finished", role="poc", phase="poc_execute", exit_code=2, duration_ms=24),
            frame(13, "poc_http_observed", role="poc", phase="poc_execute", method="GET", path="/account/me.php", http_status=401),
            frame(14, "poc_job_started", role="poc", phase="poc_execute", job_kind="http", context_id="context-bob", identity="bob", jobs_used=8, max_jobs=8, jobs_remaining=0),
            frame(15, "poc_job_finished", role="poc", phase="poc_execute", job_kind="http", context_id="context-bob", identity="bob", jobs_used=8, max_jobs=8, jobs_remaining=0, http_status=403, exit_code=0, duration_ms=12),
            frame(16, "poc_job_rejected", role="poc", phase="poc_execute", job_kind="browser", context_id="context-bob", identity="bob", jobs_used=8, max_jobs=8, jobs_remaining=0, reason="job_limit")]


def run_checks(page, base, api, checks, screenshots):
    goto(page, base, f"#run/{COMPLETED_ID}")
    workflow = page.get_by_role("region", name="执行预算与验证策略")
    expect(workflow).to_contain_text("当前阶段：POC 验证")
    expect(workflow.locator('[data-stage="discovery"]')).to_contain_text("已用 142 / 配额 142")
    expect(workflow.locator('[data-stage="poc"]')).to_contain_text("已用 4 / 配额 102")
    expect(workflow.locator('[data-stage="review"]')).to_contain_text("剩余 10 次请求")
    expect(workflow).to_contain_text("静态阶段转入验证 38 次请求")
    expect(workflow).to_contain_text("未决方向 3")
    expect(workflow).to_contain_text("待验证 5")
    expect(workflow).to_contain_text("正式复核 2")
    expect(workflow).to_contain_text("待正式复核 1")
    expect(workflow).to_contain_text("源码阶段停止原因：已处理全部可执行源码方向")
    checks.passed("discovery-first stages show frozen allocation, actual consumption, transfer and unsettled review facts")
    for theme in ("dark", "light"):
        page.set_viewport_size({"width": 1440, "height": 900})
        if page.locator("html").get_attribute("data-theme") != theme:
            page.get_by_role("button", name=f"切换{'深' if theme == 'dark' else '浅'}色主题", exact=True).click()
        for width in (1440, 1024, 768, 390):
            page.set_viewport_size({"width": width, "height": 900})
            workflow.scroll_into_view_if_needed()
            no_overflow(page, f"workflow allocation {theme} {width}", checks)
            expect(workflow.locator('[data-stage="review"]')).to_be_visible()
            if screenshots:
                page.screenshot(path=str(screenshots / f"audit-workflow-{theme}-{width}.png"), animations="disabled")
    page.set_viewport_size({"width": 1440, "height": 900})
    summary = page.locator(".activity-stream .agent-diagnostics")
    expect(summary).to_contain_text("2 次异常请求 · 2 次已恢复")
    summary.get_by_role("button", name="错误与恢复", exact=False).click()
    expect(summary.locator(".diagnostic-counts")).to_contain_text("Worker · 源码审计")
    summary.get_by_role("button", name="Worker · 源码审计 · 请求 1 · 已恢复", exact=True).click()
    expect(summary).to_contain_text("恢复依据：事件 #9")
    expect(summary).to_contain_text("请提交完整的循环体")
    checks.passed("full-history incidents deduplicate nested errors and retain inspectable recovery evidence")

    script = page.locator('.activity-tool[data-tool="run_poc"]')
    expect(script).to_have_attribute("data-status", "warning")
    expect(script).to_contain_text("脚本执行失败 · 退出码 2")
    script.get_by_role("button").first.click()
    expect(script).to_contain_text("工具调用：调用完成")
    expect(script).to_contain_text("作业执行：脚本执行失败")
    expect(page.locator('.activity-message[data-event-kind="poc_http_observed"]')).to_contain_text("HTTP 401")
    invalid = page.locator('.activity-tool[data-tool="read_source"]')
    invalid.get_by_role("button").first.click()
    expect(invalid).to_contain_text("起始行不能是布尔值")
    invalid.get_by_role("tab", name="参数", exact=True).click()
    expect(invalid).to_contain_text('"start": true')
    checks.passed("call completion, failed script, HTTP status, actual arguments and correction hints remain distinct")
    http_started = page.locator('.activity-message[data-event-kind="poc_job_started"]')
    expect(http_started).to_contain_text("开始执行 HTTP 请求")
    expect(http_started).to_contain_text("共享作业配额 8/8，剩余 0")
    expect(http_started).to_contain_text("身份：Bob")
    rejection = page.locator('.activity-message[data-event-kind="poc_job_rejected"]')
    expect(rejection).to_contain_text("浏览器检查未提交")
    expect(rejection).to_contain_text("共享作业额度已用尽")
    checks.passed("HTTP and browser jobs retain type, identity and shared quota; rejected jobs remain visibly unsubmitted")

    dialog = open_logs(page)
    expect(dialog.locator(".agent-diagnostics")).to_contain_text("2 次异常请求 · 2 次已恢复")
    dialog.get_by_role("button", name="筛选轨迹", exact=False).click()
    dialog.get_by_role("combobox", name="按事件类型筛选轨迹", exact=True).select_option("agent_parse_error")
    expect(dialog.locator(".agent-diagnostics")).to_contain_text("2 次异常请求 · 2 次已恢复")
    for selector in (".trace-group > button", ".trace-phase > button", ".trace-event > button"):
        for button in dialog.locator(selector).all():
            if button.get_attribute("aria-expanded") == "false":
                button.click()
    expect(dialog.locator(".trace-groups")).to_contain_text("动作代码不完整")
    checks.passed("log filters retain complete error counts and expose the specific parse category")

    goto(page, base, f"#findings/{LEDGER_ID}")
    # FindingDetail's class may vary with the source/ledger layout; scope to the
    # precise verification disclosure rather than relying on that presentation.
    page.get_by_role("button", name="未决", exact=False).filter(has=page.locator(".faint.small")).first.click()
    expect(page.get_by_text("实验前提不符", exact=True)).to_be_visible()
    page.get_by_role("button", name="实验前提与实际身份", exact=True).click()
    expect(page.get_by_text('"actual_role": "admin"', exact=False)).to_be_visible()
    page.get_by_role("button", name="正常侧证据引用（1）", exact=True).click()
    expect(page.get_by_text("normal=member", exact=True)).to_be_visible()
    expect(page.get_by_text("输出通道 body", exact=False)).to_be_visible()
    page.get_by_role("button", name="攻击侧证据引用（1）", exact=True).click()
    expect(page.get_by_text("attack=admin", exact=True)).to_be_visible()
    expect(page.get_by_text("输出通道 headers", exact=False)).to_be_visible()
    page.get_by_role("button", name="作业执行历史（2）", exact=True).click()
    expect(page.get_by_role("button", name="script · failed-script", exact=False)).to_contain_text("退出码 2")
    expect(page.get_by_role("button", name="http · identity-check", exact=False)).to_contain_text("HTTP 200")
    page.get_by_role("button", name="script · failed-script", exact=False).click()
    expect(page.get_by_text("raise SystemExit(2)", exact=False)).to_be_visible()
    checks.passed("verification detail shows actual identity, preconditions, output citations and failed-job history")

    for theme in ("dark", "light"):
        page.set_viewport_size({"width": 1440, "height": 900})
        if page.locator("html").get_attribute("data-theme") != theme:
            page.get_by_role("button", name=f"切换{'深' if theme == 'dark' else '浅'}色主题", exact=True).click()
        for width in (1440, 1024, 768, 390):
            page.set_viewport_size({"width": width, "height": 900})
            no_overflow(page, f"verification diagnostics {theme} {width}", checks)
            if screenshots:
                page.screenshot(path=str(screenshots / f"agent-diagnostics-{theme}-{width}.png"), animations="disabled")
    old = verification_record()
    api.ledger_verifications[LEDGER_ID] = [old]
    api.ledger_records[LEDGER_ID].update(verification_status="verified", verification_verdict="confirmed")
    page.reload()
    page.get_by_role("button", name="已验证", exact=False).filter(has=page.locator(".faint.small")).first.click()
    expect(page.get_by_text("作业执行成功", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="实验前提与实际身份", exact=True)).to_have_count(0)
    checks.passed("legacy verification rows without context or evidence references remain readable")

    # The JSON publisher has no Python action event. Its rejected decisions must
    # still contribute to request diagnostics and retain inspectable recovery.
    context = {"role": "planner", "phase": "planner_publish", "agent_invocation_id": "planner-json"}
    api.event_overrides[COMPLETED_ID].extend([
        event(COMPLETED_ID, 17, "model_response", {**context, "request_index": 1, "content_empty": True, "finish_reason": "length"}),
        event(COMPLETED_ID, 18, "agent_parse_error", {**context, "request_index": 1, "category": "empty_response", "hint": "只提交最小完整 JSON 对象"}),
        event(COMPLETED_ID, 19, "model_retry", {**context, "request_index": 1}),
        event(COMPLETED_ID, 20, "model_response", {**context, "request_index": 2, "response_format": "json"}),
        event(COMPLETED_ID, 21, "agent_output_rejected", {**context, "request_index": 2, "error_code": "invalid_output", "hint": "任务路径不在冻结快照内"}),
        event(COMPLETED_ID, 22, "model_retry", {**context, "request_index": 2}),
        event(COMPLETED_ID, 23, "model_response", {**context, "request_index": 3, "response_format": "json"}),
        event(COMPLETED_ID, 24, "planner_agent_terminal", {**context, "request_index": 3, "reason": "completed"}),
    ])
    page.set_viewport_size({"width": 1440, "height": 900})
    goto(page, base, f"#run/{COMPLETED_ID}")
    expect(page.locator(".activity-stream .agent-diagnostics")).to_contain_text("4 次异常请求 · 4 次已恢复")
    dialog = open_logs(page)
    dialog.get_by_role("button", name="筛选轨迹", exact=False).click()
    kind = dialog.get_by_role("combobox", name="按事件类型筛选轨迹", exact=True)
    kind.select_option("model_response")
    for selector in (".trace-group > button", ".trace-phase > button"):
        for button in dialog.locator(selector).all():
            if button.get_attribute("aria-expanded") == "false":
                button.click()
    expect(dialog.locator(".trace-groups")).to_contain_text("模型输出额度耗尽，未返回正文")
    expect(dialog.locator(".trace-groups")).to_contain_text("模型 JSON 决策响应已记录")
    kind.select_option("agent_output_rejected")
    for selector in (".trace-group > button", ".trace-phase > button"):
        for button in dialog.locator(selector).all():
            if button.get_attribute("aria-expanded") == "false":
                button.click()
    expect(dialog.locator(".trace-groups")).to_contain_text("结构化决策未通过宿主校验")
    checks.passed("JSON publication shows empty output, rejected decisions and recovery without a Python action")
    api.runs[COMPLETED_ID].pop("execution_summary")
    api.runs[COMPLETED_ID]["task_spec"].pop("workflow_policy")
    goto(page, base, f"#run/{COMPLETED_ID}")
    page.reload()
    expect(page.get_by_label("已冻结的审计策略", exact=True)).to_contain_text("共享预算调度（旧政策）")
    expect(page.get_by_label("阶段配额与未决事项", exact=True)).to_have_count(0)
    checks.passed("historical runs keep legacy scheduling labels and do not invent stage consumption")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base")
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    api = sources_api()
    api.runs[COMPLETED_ID]["task_spec"].update(workflow_policy="discovery_first", completion_policy="coverage_review")
    api.runs[COMPLETED_ID]["execution_summary"] = {
        "phase": "poc", "run_limits": {"responses": 256, "tools": 2048, "seconds": 1800},
        "run_usage": {"responses": 148, "tools": 81, "seconds": 531},
        "run_remaining": {"responses": 108, "tools": 1967, "seconds": 1269},
        "active_executions": [], "blocked_task_ids": [], "poc": {"mode": "auto", "available": True},
        "final_summary_available": False,
        "workflow": {"version": "discovery-first-v1", "stage": "poc",
                     "limits": {"discovery": 142, "poc": 102, "review": 12},
                     "used": {"discovery": 142, "poc": 4, "review": 2},
                     "remaining": {"discovery": 0, "poc": 98, "review": 10},
                     "transferred": 38, "review_reserved_seconds": 60, "stage_remaining_seconds": 1209,
                     "discovery_stop": {"state": "met", "basis": "已处理全部可执行源码方向", "missing": [], "code": None}},
        "directions": {"total": 8, "unsettled_total": 3, "pending_total": 1, "assigned_total": 2},
        "verification": {"total": 9, "pending": 5, "verified": 3, "reviewed": 2, "pending_review": 1}}
    api.event_overrides[COMPLETED_ID] = diagnostic_events()
    record = verification_record()
    record.update(status="inconclusive", verdict="uncertain", execution_status="environment_mismatch", agent={
        "context_id": "independent-context", "jobs": ["failed-script", "identity-check"],
        "preconditions": {"identity": "alice", "expected_role": "member", "actual_role": "admin", "valid": False},
        "state_changes": [{"identity": "alice", "from": "member", "to": "admin"}],
        "normal_evidence": [{"job_id": "identity-check", "channel": "body", "excerpt": "normal=member"}],
        "attack_evidence": [{"job_id": "identity-check", "channel": "headers", "excerpt": "attack=admin"}],
        "job_results": [
            {"verification_id": record["id"], "finding_id": record["finding_id"], "job_id": "failed-script", "kind": "script", "exit_code": 2,
             "request": {"script": "raise SystemExit(2)"}, "result": {"stderr": "identity polluted"}},
            {"verification_id": record["id"], "finding_id": record["finding_id"], "job_id": "identity-check", "kind": "http",
             "request": {"path": "/account/me.php"}, "result": {"status": 200, "stdout": "normal=member\nattack=admin"}},
        ]})
    api.ledger_verifications[LEDGER_ID] = [record]
    api.ledger_records[LEDGER_ID].update(verification_status="inconclusive", verification_verdict="uncertain")
    writes = []

    def handle(route):
        if route.request.method != "GET":
            writes.append(f"{route.request.method} {route.request.url}")
            api.json(route, {"detail": "read-only browser fixture"}, 405)
        else:
            api.handle(route)

    checks = Checks()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=os.environ.get("CHROME_BIN"))
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.set_default_timeout(10000)
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.route("**/api/**", handle)
        try:
            run_checks(page, args.base.rstrip("/"), api, checks, args.screenshots)
            assert not writes, writes
            assert not errors, errors
            assert not api.unexpected, api.unexpected
            print(f"PASS {checks.count} agent stability browser checks; mock APIs only", flush=True)
        except Exception:
            save(page, args.screenshots, "agent-stability-failure")
            raise
        finally:
            browser.close()


if __name__ == "__main__":
    main()
