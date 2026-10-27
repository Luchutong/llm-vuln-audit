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
    page.get_by_role("button", name="攻击侧证据引用（1）", exact=True).click()
    expect(page.get_by_text("attack=admin", exact=True)).to_be_visible()
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base")
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    api = sources_api()
    api.event_overrides[COMPLETED_ID] = diagnostic_events()
    record = verification_record()
    record.update(status="inconclusive", verdict="uncertain", execution_status="environment_mismatch", agent={
        "context_id": "independent-context", "jobs": ["failed-script", "identity-check"],
        "preconditions": {"identity": "alice", "expected_role": "member", "actual_role": "admin", "valid": False},
        "state_changes": [{"identity": "alice", "from": "member", "to": "admin"}],
        "normal_evidence": [{"job_id": "identity-check", "channel": "stdout", "excerpt": "normal=member"}],
        "attack_evidence": [{"job_id": "identity-check", "channel": "stdout", "excerpt": "attack=admin"}],
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
