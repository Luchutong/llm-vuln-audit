#!/usr/bin/env python3
"""Budget/POC browser acceptance. Every API, including SSE, is intercepted in memory.

CHROME_BIN=... uv run --with playwright python scripts/ui_execution_smoke.py http://127.0.0.1:5173
"""
from __future__ import annotations

import argparse
import copy
import os
from pathlib import Path
import time
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from ui_fixtures import COMPLETED_ID, CREATED_ID, OBJECTIVE, PROJECT_ID, RUN_LIMITS, SNAPSHOT_ID, STAMP, MockAPI, event, finding, run
from ui_smoke import Checks, close_dialog, goto, no_overflow, open_logs, save


def execution(mode="off", terminal=False, limits=None):
    limits = limits or copy.deepcopy(RUN_LIMITS)
    return {"policy_version": "run-budget-1", "phase": "ended" if terminal else "task_execute",
            "run_limits": limits, "run_usage": {"responses": limits["responses"] if terminal else 12, "tools": 40, "seconds": 100.5},
            "run_remaining": {"responses": 0 if terminal else limits["responses"] - 12, "tools": limits["tools"] - 40, "seconds": limits["seconds"] - 100.5},
            "active_executions": [] if terminal else [{"invocation_id": "one", "role": "worker"}, {"invocation_id": "two", "role": "worker"}],
            "stop_reason": {"code": "run_budget_exhausted", "dimension": "responses", "message": "整次模型请求预算已耗尽"} if terminal else None,
            "blocked_task_ids": ["task-needs-context"] if terminal else [],
            "poc": {"mode": mode, "available": False, "reason": "runner_unavailable", "message": "隔离环境暂不可用，源码结论保留为未验证。"},
            "final_summary_available": terminal}


def phase_report():
    return {"source": "host", "status": "inconclusive", "complete": False,
            "stop_reason": {"code": "run_budget_exhausted", "dimension": "responses", "message": "整次模型请求预算已耗尽"},
            "raw_finding_count": 2, "valid_finding_count": 2, "ledger_group_count": 1,
            "finding_groups": [{"id": "ledger-one", "finding_ids": ["one", "two"]}],
            "tasks": [{"id": "task-needs-context", "title": "尚未穷尽的源码方向", "state": "blocked"}],
            "coverage": {"files_total": 69, "files_read": 48, "unread_count": 21},
            "limitations": ["仍有 21 个文件未完成核验；源码候选不代表已自动复现。"]}


class ExecutionAPI(MockAPI):
    def __init__(self):
        super().__init__()
        self.fail_create = False
        self.ready = False
        self.readiness_requests = 0
        self.reject_required_once = False
        self.readiness_fail_once = False
        self.hold_readiness = False
        self.pending_readiness = None

    def readiness(self):
        return {"available": self.ready, "reason": "ready" if self.ready else "runner_unavailable",
                "message": "隔离环境检查通过。" if self.ready else "隔离环境暂不可用，源码结论保留为未验证。",
                "checked_at": STAMP, "capabilities": {"supported_targets": ["dvwa"], "browser": self.ready}}

    def handle(self, route):
        path = urlsplit(route.request.url).path.removeprefix("/api")
        if path == "/poc/readiness":
            self.readiness_requests += 1
            if self.hold_readiness:
                self.pending_readiness = route
            elif self.readiness_fail_once:
                self.readiness_fail_once = False
                self.json(route, {"detail": "模拟环境检查失败，请重试"}, 503)
            else:
                self.json(route, self.readiness())
        elif path == "/runs" and route.request.method == "POST" and self.reject_required_once:
            self.reject_required_once = False
            self.ready = False
            self.json(route, {"detail": {"code": "poc_not_ready", "reason": "runner_unavailable", "message": "创建时环境已离线，请重新检查。", "checked_at": STAMP}}, 409)
        else:
            super().handle(route)


def draft(page, base):
    goto(page, base, f"#sources/{PROJECT_ID}/new?snapshot={SNAPSHOT_ID}")
    expect(page.get_by_role("textbox", name="审计任务", exact=True)).to_be_visible()
    page.get_by_role("textbox", name="审计任务", exact=True).fill(OBJECTIVE)
    expect(page.get_by_role("button", name="开始审计", exact=True)).to_be_enabled()


def options(page):
    page.get_by_role("button", name="高级执行设置", exact=True).click()
    return page.get_by_role("dialog", name="高级执行设置")


def navigate(page, hash):
    page.evaluate("hash => { location.hash = hash; }", hash)


def run_checks(page, base, api, checks, directory):
    draft(page, base)
    dialog = options(page)
    for label, value in (("整次模型请求上限", "256"), ("整次工具调用上限", "2048"), ("整次活跃时间（秒）", "1800"), ("模型响应次数", "24")):
        expect(dialog.get_by_role("spinbutton", name=label, exact=False)).to_have_value(value)
    expect(dialog.get_by_role("combobox", name="自动验证模式")).to_have_value("off")
    assert api.readiness_requests == 0
    checks.passed("new audit freezes distinct per-execution/global budgets and defaults automatic POC off")
    dialog.get_by_role("checkbox", name="发现需附 POC 脚本", exact=False).check()
    dialog.get_by_role("button", name="保存设置", exact=True).click()
    page.get_by_role("button", name="开始审计", exact=True).click()
    expect(page).to_have_url(base + f"/#run/{CREATED_ID}")
    assert api.create_bodies[-1]["poc_mode"] == "off" and api.create_bodies[-1]["task"]["require_poc"] is True
    assert api.create_bodies[-1]["run_limits"] == RUN_LIMITS
    checks.passed("requiring a POC script stays independent from starting the verification agent")

    draft(page, base)
    dialog = options(page)
    dialog.get_by_role("combobox", name="自动验证模式").select_option("auto")
    expect(dialog.get_by_role("status")).to_contain_text("环境不可用")
    dialog.get_by_role("button", name="保存设置", exact=True).click()
    page.get_by_role("button", name="开始审计", exact=True).click()
    expect(page).to_have_url(base + f"/#run/{CREATED_ID}")
    assert api.create_bodies[-1]["poc_mode"] == "auto" and api.create_bodies[-1]["task"]["require_poc"] is False
    checks.passed("auto mode permits static auditing when no verification environment exists")

    draft(page, base)
    dialog = options(page)
    dialog.get_by_role("combobox", name="自动验证模式").select_option("required")
    expect(dialog.get_by_role("status")).to_contain_text("环境不可用")
    dialog.get_by_role("button", name="保存设置", exact=True).click()
    expect(page.get_by_role("button", name="开始审计", exact=True)).to_be_disabled()
    before = api.create_count
    page.locator("form.composer").evaluate("form => form.requestSubmit()")
    expect(page.get_by_role("alert")).to_contain_text("必须验证模式")
    assert api.create_count == before
    dialog = options(page)
    api.readiness_fail_once = True
    dialog.get_by_role("button", name="重新检查环境").click()
    expect(dialog.get_by_role("status")).to_contain_text("环境检查失败")
    api.ready = True
    dialog.get_by_role("button", name="重新检查环境").click()
    expect(dialog.get_by_role("status")).to_contain_text("环境可用")
    api.reject_required_once = True
    dialog.get_by_role("button", name="保存设置", exact=True).click()
    page.get_by_role("button", name="开始审计", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("创建时环境已离线")
    expect(page.get_by_role("button", name="开始审计", exact=True)).to_be_disabled()
    dialog = options(page)
    api.ready = True
    dialog.get_by_role("button", name="重新检查环境").click()
    expect(dialog.get_by_role("status")).to_contain_text("环境可用")
    dialog.get_by_role("button", name="保存设置", exact=True).click()
    page.get_by_role("button", name="开始审计", exact=True).click()
    expect(page).to_have_url(base + f"/#run/{CREATED_ID}")
    assert api.create_bodies[-1]["poc_mode"] == "required"
    checks.passed("required mode blocks unavailable/readiness errors, handles a late 409 and recovers after recheck")

    clone = api.runs[COMPLETED_ID]
    clone.update(run_limits={"responses": 111, "tools": 555, "seconds": 999}, poc_mode="required", execution_summary=execution("required", True, {"responses": 111, "tools": 555, "seconds": 999}))
    goto(page, base, f"#run/{COMPLETED_ID}")
    page.get_by_role("button", name="基于此任务新建", exact=True).click()
    dialog = options(page)
    expect(dialog.get_by_role("spinbutton", name="整次模型请求上限", exact=False)).to_have_value("111")
    expect(dialog.get_by_role("combobox", name="自动验证模式")).to_have_value("off")
    dialog.get_by_role("button", name="保存设置", exact=True).click()
    page.get_by_role("button", name="开始审计", exact=True).click()
    expect(page).to_have_url(base + f"/#run/{CREATED_ID}")
    assert api.create_bodies[-1]["run_limits"] == {"responses": 111, "tools": 555, "seconds": 999}
    assert not {"usage", "execution_summary", "final_summary"} & set(api.create_bodies[-1])
    checks.passed("clone copies original allowances, starts POC off and never copies consumed usage")

    draft(page, base)
    dialog = options(page)
    api.hold_readiness = True
    dialog.get_by_role("combobox", name="自动验证模式").select_option("auto")
    expect(dialog.get_by_role("status")).to_contain_text("正在检查")
    dialog.get_by_role("combobox", name="自动验证模式").select_option("off")
    for _ in range(50):
        if api.pending_readiness is not None:
            break
        page.wait_for_timeout(20)
    assert api.pending_readiness is not None
    api.json(api.pending_readiness, api.readiness())
    api.pending_readiness = None
    api.hold_readiness = False
    expect(dialog.get_by_role("status")).to_have_count(0)
    dialog.get_by_role("button", name="保存设置", exact=True).click()
    expect(page.get_by_role("button", name="开始审计", exact=True)).to_be_enabled()
    checks.passed("switching POC off cancels a pending readiness response without restoring stale environment state")

    live_id = "budget-live"
    live_run = run(live_id, "running")
    live_run.update(run_limits=copy.deepcopy(RUN_LIMITS), poc_mode="auto", execution_summary=execution("auto"))
    api.runs[live_id] = live_run
    api.findings[live_id] = finding(live_id)
    api.event_overrides[live_id] = [event(live_id, 1, "run_started", {}), event(live_id, 2, "model_request", {"role": "worker", "task_id": "task-live", "agent_invocation_id": "active-one", "request_index": 1})]
    # A healthy EventSource that delivers no terminal frame: polling must still settle UI.
    page.add_init_script("""window.EventSource = class { constructor() { setTimeout(() => this.onopen?.({}), 0); } close() {} };""")
    goto(page, base, f"#run/{live_id}")
    expect(page.locator(".conversation-meta")).to_contain_text("审计中")
    expect(page.get_by_role("region", name="执行预算与验证策略")).to_contain_text("12 / 256")
    live_run.update(status="inconclusive", finished_at=STAMP, execution_summary=execution("auto", True), final_summary=phase_report())
    api.detail_overrides[live_id] = {"report_narrative": {"summary": "历史 Planner 曾主张完成，宿主最终事实覆盖该主张。"}}
    api.event_overrides[live_id] = [event(live_id, number, "model_response", {"role": "worker"}) for number in range(1, 2005)] + [event(live_id, 2005, "goal_inconclusive", {"reason": "整次模型请求预算已耗尽；末尾阶段报告已保存。"})]
    started = time.monotonic()
    expect(page.locator(".conversation-meta")).to_contain_text("结果未决", timeout=5500)
    assert time.monotonic() - started <= 5.1, "terminal transition waited more than five seconds"
    expect(page.get_by_role("region", name="宿主阶段报告")).to_contain_text("未完成")
    expect(page.locator(".activity-waiting")).to_have_count(0)
    open_logs(page)
    expect(page.locator(".trace-counts")).to_contain_text("2005 条事件")
    assert any(ident == live_id and after >= 2000 for ident, after in api.event_queries)
    checks.passed("terminal state arrives without SSE within five seconds, stops waiting and drains final events beyond page 2000")
    dialog = page.get_by_role("dialog", name="审计详情")
    dialog.get_by_role("tab", name="结果报告", exact=True).click()
    expect(dialog.get_by_role("region", name="宿主阶段报告")).to_contain_text("去重台账 1")
    expect(dialog.get_by_text("Planner 历史叙述", exact=True)).to_be_visible()
    expect(dialog.get_by_role("link", name="JSON", exact=True)).to_have_attribute("href", f"/api/runs/{live_id}/report?format=json")
    checks.passed("host final facts stay authoritative beside older Planner narrative and report download links")
    close_dialog(page)

    for theme in ("dark", "light"):
        page.evaluate("theme => { document.documentElement.dataset.theme = theme; }", theme)
        for width in (1440, 1024, 768, 390):
            page.set_viewport_size({"width": width, "height": 900 if width > 390 else 844})
            no_overflow(page, f"execution result {theme} {width}", checks)
            save(page, directory, f"execution-result-{theme}-{width}")
            page.get_by_role("button", name="审计详情", exact=True).click()
            dialog = page.get_by_role("dialog", name="审计详情")
            dialog.get_by_role("tab", name="结果报告", exact=True).click()
            no_overflow(page, f"phase report {theme} {width}", checks)
            save(page, directory, f"phase-report-{theme}-{width}")
            close_dialog(page)
    page.set_viewport_size({"width": 1440, "height": 900})
    draft(page, base)
    dialog = options(page)
    dialog.get_by_role("combobox", name="自动验证模式").select_option("auto")
    expect(dialog.get_by_role("status")).to_contain_text("环境可用")
    for theme in ("dark", "light"):
        page.evaluate("theme => { document.documentElement.dataset.theme = theme; }", theme)
        for width in (1440, 1024, 768, 390):
            page.set_viewport_size({"width": width, "height": 900 if width > 390 else 844})
            no_overflow(page, f"budget options {theme} {width}", checks)
            save(page, directory, f"budget-options-{theme}-{width}")
    assert not api.unexpected, api.unexpected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", nargs="?", default="http://127.0.0.1:5173")
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    checks = Checks()
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=os.environ.get("CHROME_BIN"), headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
        api = ExecutionAPI()
        context.route("**/api/**", api.handle)
        page = context.new_page()
        failures = []
        page.on("pageerror", lambda error: failures.append(str(error)))
        run_checks(page, args.base.rstrip("/"), api, checks, args.screenshots)
        assert not failures, failures
        browser.close()
    print(f"PASS {checks.count} execution checks (mock APIs only)")


if __name__ == "__main__":
    main()
