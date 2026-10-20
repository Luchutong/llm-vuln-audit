#!/usr/bin/env python3
"""Browser acceptance for the audit workspace.

Real-service mode is read-only: ui_smoke.py <frontend-url> [run-id]
Mock mode intercepts every /api request, including SSE, and never calls a model:
  ui_smoke.py <frontend-url> --mock --screenshots /tmp/audit-ui
Requires Playwright with Chromium. CHROME_BIN may select an existing executable.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import traceback
from typing import Any

from playwright.sync_api import Page, expect, sync_playwright

from ui_fixtures import ACTIVITY_ID, COMPLETED_ID, CREATED_ID, CRITERIA, LONG_LOG, LONG_VALUE, OBJECTIVE, SOURCE_PATH, MockAPI, activity_events, event, finding, run, snapshot, source_observations


class Checks:
    def __init__(self) -> None:
        self.count = 0

    def passed(self, message: str) -> None:
        self.count += 1
        print(f"  PASS {message}", flush=True)


def no_overflow(page: Page, label: str, checks: Checks) -> None:
    sizes = page.evaluate("""() => ({ viewport: innerWidth, root: document.documentElement.scrollWidth,
      body: document.body.scrollWidth, dialog: document.querySelector('[role=dialog]')?.getBoundingClientRect().toJSON() })""")
    assert sizes["root"] <= sizes["viewport"] + 1, f"{label}: document overflow {sizes}"
    assert sizes["body"] <= sizes["viewport"] + 1, f"{label}: body overflow {sizes}"
    if sizes["dialog"]:
        box = sizes["dialog"]
        assert box["x"] >= -1 and box["right"] <= sizes["viewport"] + 1, f"{label}: dialog leaves viewport {sizes}"
    checks.passed(f"{label}: no horizontal page overflow")


def save(page: Page, directory: Path | None, name: str) -> None:
    if directory:
        page.screenshot(path=str(directory / f"{name}.png"), full_page=True, animations="disabled")


def close_dialog(page: Page, trigger: Any | None = None) -> None:
    page.keyboard.press("Escape")
    expect(page.get_by_role("dialog")).to_have_count(0)
    if trigger is not None:
        expect(trigger).to_be_focused()


def goto(page: Page, base: str, suffix: str = "") -> None:
    page.goto(base + "/" + suffix, wait_until="domcontentloaded")


def workspace_ready(page: Page) -> None:
    expect(page.get_by_role("textbox", name="审计任务", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="发送审计任务", exact=True)).to_be_enabled()


def choose_snapshot(page: Page) -> None:
    page.get_by_role("button", name="选择已有快照", exact=True).click()
    dialog = page.get_by_role("dialog", name="选择已有源码快照", exact=True)
    dialog.get_by_role("button", name=re.compile("审计样例源码.zip")).click()
    expect(page.get_by_text("5 个可读文件", exact=False)).to_be_visible()


def open_findings(page: Page) -> Any:
    page.get_by_role("button", name="审计详情", exact=True).click()
    dialog = page.get_by_role("dialog", name="审计详情", exact=True)
    dialog.get_by_role("tab", name="发现与复核", exact=True).click()
    return dialog


def open_logs(page: Page) -> Any:
    """Full filtering and diagnostic details live in the audit detail drawer."""
    if not page.get_by_role("dialog", name="审计详情", exact=True).count():
        page.get_by_role("button", name="审计详情", exact=True).click()
    dialog = page.get_by_role("dialog", name="审计详情", exact=True)
    dialog.get_by_role("tab", name="执行日志", exact=True).click()
    return dialog


def expand_tool(page: Page) -> Any:
    """Navigate the public grouping disclosures without assuming generated IDs."""
    trace = page.locator(".trace")
    trace.get_by_role("button", name=re.compile(r"^筛选轨迹")).click()
    trace.get_by_role("combobox", name="按事件类型筛选轨迹").select_option("tool_call")
    trace.get_by_role("combobox", name="按角色筛选轨迹").select_option("worker")
    expand_visible_groups(trace)
    card = trace.locator(".trace-tool")
    expect(card).to_have_count(1)
    card.get_by_role("button", name=re.compile(r"^read_source")).click()
    return card


def expand_visible_groups(trace: Any) -> None:
    for group in trace.locator(".trace-group").all():
        toggle = group.locator(":scope > .disclosure-toggle")
        if toggle.get_attribute("aria-expanded") == "false":
            toggle.click()
    for phase in trace.locator(".trace-phase").all():
        toggle = phase.locator(":scope > .disclosure-toggle")
        if toggle.get_attribute("aria-expanded") == "false":
            toggle.click()


def responsive(page: Page, checks: Checks, label: str, directory: Path | None = None) -> None:
    for width in (1440, 1024, 768, 390):
        page.set_viewport_size({"width": width, "height": 900})
        page.wait_for_timeout(100)
        page.locator(".settings-page").evaluate_all("nodes => nodes.forEach(node => { node.scrollTop = 0; })")
        page.locator(".drawer-body").evaluate_all("nodes => nodes.forEach(node => { node.scrollTop = 0; })")
        no_overflow(page, f"{label} {width}px", checks)
        if width == 390:
            save(page, directory, f"{label}-mobile")
    page.set_viewport_size({"width": 1440, "height": 900})


def run_mock(page: Page, base: str, api: MockAPI, checks: Checks, directory: Path | None) -> None:
    page.route("**/api/**", api.handle)
    goto(page, base)
    workspace_ready(page)
    expect(page).to_have_title("VULN-AUDIT · 源码审计工作空间")
    expect(page.locator(".desktop-side .brand-wordmark")).to_have_text("VULN-AUDIT")
    assert page.locator(".desktop-side .brand-wordmark").evaluate("node => getComputedStyle(node).backgroundImage") != "none"
    checks.passed("VULN-AUDIT branding, local type effect and configured workspace loaded")
    save(page, directory, "draft-dark")

    upload = page.get_by_label("上传项目源码 ZIP", exact=True)
    upload.set_input_files({"name": "wrong.php", "mimeType": "text/plain", "buffer": b"<?php"})
    expect(page.get_by_role("alert")).to_contain_text("ZIP")
    assert api.upload_count == 0, "invalid extension reached API"
    page.evaluate("""() => {
      const input = document.querySelector('input[aria-label="上传项目源码 ZIP"]');
      const transfer = new DataTransfer();
      transfer.items.add(new File([new Uint8Array(64 * 1024 * 1024 + 1)], 'oversize.zip', {type: 'application/zip'}));
      input.files = transfer.files; input.dispatchEvent(new Event('change', {bubbles: true}));
    }""")
    expect(page.get_by_role("alert")).to_contain_text("64 MiB")
    assert api.upload_count == 0, "oversized archive reached API"
    checks.passed("invalid extension and >64 MiB archive rejected before network")

    archive = {"name": "project.zip", "mimeType": "application/zip", "buffer": b"PK\x03\x04ui-fixture"}
    upload.set_input_files(archive)
    expect(page.get_by_role("alert")).to_contain_text("模拟 ZIP 导入失败")
    upload.set_input_files(archive)
    expect(page.get_by_text("5 个可读文件", exact=False)).to_be_visible()
    assert api.upload_count == 2
    checks.passed("failed upload can retry the same file successfully")

    page.get_by_role("button", name="发送审计任务", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("8–2000")
    assert api.create_count == 0
    page.get_by_role("textbox", name="审计任务", exact=True).fill(OBJECTIVE)
    page.get_by_role("textbox", name="验收目标", exact=True).fill(CRITERIA)
    snapshot_trigger = page.get_by_role("button", name=re.compile(r"^快照"))
    snapshot_trigger.click()
    dialog = page.get_by_role("dialog", name="项目快照摘要")
    expect(dialog.get_by_text("可读文本", exact=True)).to_be_visible()
    expect(dialog.get_by_text("二进制文件", exact=True)).to_be_visible()
    expect(dialog.get_by_role("checkbox")).to_have_count(0)
    expect(dialog.get_by_text("typescript", exact=False)).to_be_visible()
    dialog.get_by_role("button", name="快照文件清单", exact=True).click()
    expect(dialog.get_by_text("src/client.ts", exact=True)).to_be_visible()
    expect(dialog.get_by_text("vendor/dependency.php", exact=True)).to_be_visible()
    dialog.get_by_role("button", name=re.compile("跳过的条目")).click()
    expect(dialog.get_by_text("build/oversized.js", exact=False)).to_be_visible()
    close_dialog(page, snapshot_trigger)
    checks.passed("whole multilingual snapshot includes dependency/text/binary metadata and skipped entries without scope selection")

    options = page.get_by_role("button", name="高级执行设置", exact=True)
    options.click()
    dialog = page.get_by_role("dialog", name="高级执行设置")
    expect(dialog.get_by_role("spinbutton", name="并发 worker", exact=False)).to_have_value("2")
    for label, value in (("共享总尝试上限", "64"), ("Planner 最大回合", "24"), ("模型响应次数", "24"), ("工具调用次数", "96"), ("墙钟时间（秒）", "1800")):
        expect(dialog.get_by_role("spinbutton", name=label, exact=False)).to_have_value(value)
    # Tab must wrap within the modal; Escape must restore the invoking control.
    dialog.get_by_role("button", name="关闭高级执行设置").focus()
    page.keyboard.press("Shift+Tab")
    expect(dialog.get_by_role("button", name="保存设置", exact=True)).to_be_focused()
    close_dialog(page, options)
    checks.passed("settings modal traps focus; Escape restores the trigger")

    api.hold_create = True
    page.locator("form.composer").evaluate("form => { form.requestSubmit(); form.requestSubmit(); }")
    page.wait_for_function("document.querySelector('button[aria-label=\"发送审计任务\"]').disabled")
    page.wait_for_timeout(150)
    assert api.create_count == 1, f"duplicate submission created {api.create_count} requests"
    api.finish_create()
    api.hold_create = False
    expect(page.get_by_role("alert")).to_contain_text("模拟队列暂时不可用")
    expect(page.get_by_role("textbox", name="审计任务", exact=True)).to_have_value(OBJECTIVE)
    expect(page.get_by_role("textbox", name="验收目标", exact=True)).to_have_value(CRITERIA)
    expect(page.get_by_text("5 个可读文件", exact=False)).to_be_visible()
    checks.passed("create failure preserves attachment and text; duplicate submit locked")

    page.get_by_role("button", name="移除附件", exact=True).click()
    choose_snapshot(page)
    assert api.upload_count == 2, "reusing snapshot uploaded again"
    page.get_by_role("button", name="发送审计任务", exact=True).click()
    expect(page).to_have_url(re.compile(f"#run/{CREATED_ID}$"))
    expect(page.get_by_role("button", name="停止审计", exact=True)).to_be_visible()
    expect(page.locator(".activity-stream")).to_be_visible()
    expect(page.locator(".trace")).to_have_count(0)
    open_logs(page)
    expect(page.locator(".trace-counts")).to_contain_text("11 条事件")
    expect(page.locator(".trace-counts")).to_contain_text("2 次工具活动")
    assert api.create_count == 2
    assert "scope" not in api.create_bodies[-1], "legacy scope field would be rejected by codeagent"
    assert api.create_bodies[-1]["budgets"] == {"responses": 24, "tools": 96, "seconds": 1800}
    expect(page.locator(".message-attachment")).to_contain_text("5 个可读文件")
    checks.passed("existing snapshot creates one run; SSE duplicate frames are deduplicated")
    close_dialog(page)
    save(page, directory, "running-dark")

    page.get_by_role("button", name="暂停运行", exact=True).click()
    expect(page.locator(".conversation-meta")).to_contain_text("已暂停", timeout=10000)
    expect(page.get_by_role("button", name="继续运行", exact=True)).to_be_visible()
    expect(page.locator(".result-card")).to_have_count(0)
    assert api.pause_count == 1 and api.runs[CREATED_ID]["status"] == "paused"
    assert api.runs[CREATED_ID]["id"] == CREATED_ID
    save(page, directory, "paused-dark")
    page.get_by_role("button", name="继续运行", exact=True).click()
    expect(page.locator(".conversation-meta")).to_contain_text("审计中", timeout=10000)
    assert api.resume_count == 1 and api.create_count == 2
    expect(page).to_have_url(re.compile(f"#run/{CREATED_ID}$"))
    checks.passed("pause/resume preserves one run and never presents a terminal result")

    # Stop is safe here: all requests, including mutations, remain in the mock router.
    page.get_by_role("button", name="停止审计", exact=True).click()
    expect(page.locator(".conversation-meta")).to_contain_text("已取消", timeout=10000)
    assert api.cancel_count == 1
    checks.passed("mock cancellation reaches the durable terminal state")
    page.reload(wait_until="domcontentloaded")
    expect(page.locator(".conversation-meta")).to_contain_text("已取消")
    expect(page.get_by_role("navigation", name="历史审计任务").get_by_role("button", name=re.compile(OBJECTIVE))).to_have_count(2)
    checks.passed("hash refresh restores the session and refreshed history")

    goto(page, base, f"#run/{COMPLETED_ID}")
    open_logs(page)
    expect(page.locator(".trace-counts")).to_contain_text("2001 条事件", timeout=15000)
    assert (COMPLETED_ID, 0) in api.event_queries and (COMPLETED_ID, 2000) in api.event_queries, api.event_queries
    expect(page.locator(".trace-footer")).to_contain_text("50 / 2001")
    checks.passed("terminal event log drains >2000 rows and discards replayed duplicates")
    card = expand_tool(page)
    expect(card.get_by_text("LONG_PAYLOAD_END", exact=False)).to_have_count(0)
    card.get_by_role("button", name="调用参数", exact=True).click()
    args = card.locator(".long-content").filter(has=page.get_by_text("已保存的参数", exact=True))
    preview = args.locator(".long-content-text")
    assert preview.evaluate("node => getComputedStyle(node).webkitLineClamp") == "3"
    assert "LONG_PAYLOAD_END" not in preview.inner_text()
    args.get_by_role("button", name="展开全文", exact=True).click()
    expect(preview).to_contain_text("LONG_PAYLOAD_END")
    assert len(preview.inner_text()) >= len(LONG_VALUE)
    args.get_by_role("button", name="收起", exact=True).click()
    expect(args.get_by_role("button", name="展开全文", exact=True)).to_have_attribute("aria-expanded", "false")
    card.get_by_role("button", name="已保存的返回预览", exact=True).click()
    expect(card.get_by_text("服务端受限预览", exact=False)).to_be_visible()
    checks.passed("10KB tool arguments stay three-line clamped; full saved value expands and collapses")
    save(page, directory, "completed-tools-dark")

    trace = page.locator(".trace")
    trace.get_by_role("combobox", name="按事件类型筛选轨迹").select_option("agent_code")
    trace.get_by_role("combobox", name="按角色筛选轨迹").select_option("all")
    expand_visible_groups(trace)
    code_card = trace.locator(".trace-code")
    expect(code_card).to_have_count(1)
    code_card.get_by_role("button", name=re.compile(r"^模型代码动作")).click()
    expect(code_card.get_by_text("服务端已截断脚本", exact=False)).to_be_visible()
    code_card.get_by_role("button", name="已执行的代码", exact=True).click()
    expect(code_card.get_by_text("print(read_source", exact=False)).to_be_visible()
    code_card.get_by_role("button", name="Print 与执行日志", exact=True).click()
    log_content = code_card.locator(".long-content").filter(has=page.get_by_text("已保存的 print / log 输出", exact=True))
    assert log_content.locator(".long-content-text").evaluate("node => getComputedStyle(node).webkitLineClamp") == "3"
    log_content.get_by_role("button", name="展开全文", exact=True).click()
    expect(log_content).to_contain_text("PRINT_LOG_END")
    assert len(log_content.locator(".long-content-text").inner_text()) == len(LONG_LOG)
    code_card.get_by_role("button", name="代码执行错误", exact=True).click()
    expect(code_card.get_by_text("OutputRejected", exact=False)).to_be_visible()
    expect(page.locator(".conversation-meta")).to_contain_text("目标已达成")
    checks.passed("executed code and long logs expand with saved truncation markers; a recovered code error does not fail the run")
    log_content.get_by_role("button", name="收起", exact=True).click()
    code_card.evaluate("""node => { const box = node.closest('.drawer-body');
      box.scrollTop += node.getBoundingClientRect().top - box.getBoundingClientRect().top - 14; }""")
    save(page, directory, "code-action-dark")
    trace.get_by_role("combobox", name="按事件类型筛选轨迹").select_option("tool_call")
    trace.get_by_role("combobox", name="按角色筛选轨迹").select_option("recon")
    expand_visible_groups(trace)
    expect(trace.locator(".trace-tool")).to_have_count(1)
    expect(trace.locator(".trace-tool")).to_contain_text("find_files")
    checks.passed("reconnaissance has its own role and trace filters")
    close_dialog(page)

    source_count = len(api.source_requests)
    trigger = page.get_by_role("button", name="审计详情", exact=True)
    dialog = open_findings(page)
    assert len(api.source_requests) == source_count, "source fetched before evidence disclosure opens"
    evidence = dialog.get_by_role("region", name="证据源码", exact=True)
    evidence.get_by_role("button", name=re.compile(r"^src\/upload\.php")).click()
    assert len(api.source_requests) == source_count, "source fetched before its source window opens"
    evidence.get_by_role("button", name=re.compile(r"^查看源码")).first.click()
    expect(dialog.get_by_role("region", name=re.compile(r"src\/upload\.php 第"))).to_be_visible()
    assert len(api.source_requests) >= source_count + 1
    expect(dialog.locator(".source-row.hit")).to_have_count(3)
    no_overflow(page, "evidence drawer 1440px", checks)
    checks.passed("evidence source loads lazily with original line numbers and highlights")

    dialog.get_by_role("button", name="记录一次人工复核", exact=True).click()
    dialog.get_by_role("combobox", name="人工结论", exact=True).select_option("confirmed")
    dialog.get_by_role("textbox", name=re.compile("人工复核说明")).fill("已核对原始源码及上下文。")
    dialog.get_by_role("button", name="提交复核记录", exact=True).click()
    expect(dialog.get_by_role("status")).to_contain_text("已记录")
    assert api.verification_count == 1
    dialog.get_by_role("tab", name="执行日志", exact=True).click()
    expect(page.locator(".trace-counts")).to_contain_text("2002 条事件", timeout=10000)
    checks.passed("a terminal run fetches new verification events without reopening its live stream")
    dialog.get_by_role("tab", name="结果报告", exact=True).click()
    expect(dialog.get_by_role("region", name="项目级审计报告", exact=True)).to_be_visible()
    expect(dialog.get_by_role("link", name="证据包", exact=True)).to_have_attribute("href", f"/api/runs/{COMPLETED_ID}/report?format=zip")
    checks.passed("human source review submits; report and evidence downloads remain available")
    dialog.locator(".drawer-body").evaluate("node => { node.scrollTop = 0; }")
    save(page, directory, "report-drawer-dark")
    responsive(page, checks, "report-drawer", directory)
    close_dialog(page, trigger)
    checks.passed("detail drawer Escape restores its opening control")

    responsive(page, checks, "conversation", directory)
    page.get_by_role("button", name="切换浅色主题", exact=True).click()
    expect(page.locator("html")).to_have_attribute("data-theme", "light")
    save(page, directory, "completed-light")
    page.reload(wait_until="domcontentloaded")
    expect(page.locator("html")).to_have_attribute("data-theme", "light")
    checks.passed("theme toggle persists across refresh")

    page.get_by_role("button", name="新建审计", exact=False).first.click()
    workspace_ready(page)
    responsive(page, checks, "draft", directory)
    page.set_viewport_size({"width": 390, "height": 844})
    navigation = page.get_by_role("button", name="打开导航", exact=True)
    navigation.click()
    expect(page.get_by_role("dialog", name="审计工作空间")).to_be_visible()
    no_overflow(page, "mobile navigation 390px", checks)
    save(page, directory, "navigation-mobile-light")
    close_dialog(page, navigation)
    checks.passed("mobile navigation is usable and Escape restores focus")
    assert not api.unexpected, f"Unhandled mock API routes: {api.unexpected}"


def run_profile_checks(page: Page, api: MockAPI, checks: Checks, directory: Path | None) -> None:
    """Exercise the existing codeagent provider catalogue without contacting providers."""
    page.set_viewport_size({"width": 1440, "height": 900})
    page.get_by_role("button", name="工作空间设置", exact=False).first.click()
    expect(page.get_by_role("heading", name="工作空间设置", exact=True)).to_be_visible()
    # Profile cards are the immediate parent of each .between row.
    def profile_card(name: str) -> Any:
        return page.locator(".settings-grid .panel > div > div").filter(has=page.get_by_text(name, exact=True)).filter(has=page.get_by_role("button", name="编辑", exact=True)).last
    env = profile_card("本地环境模型")
    expect(env.get_by_role("button", name="编辑", exact=True)).to_be_disabled()
    expect(env.get_by_role("button", name="删除", exact=True)).to_be_disabled()
    expect(env.get_by_role("button", name="正在使用", exact=True)).to_be_disabled()
    checks.passed("environment profile remains read-only")
    secondary = profile_card("备用模型档案")
    secondary.get_by_role("button", name="使用此档案", exact=True).click()
    expect(secondary.get_by_role("button", name="正在使用", exact=True)).to_be_disabled()
    assert api.selected_profile_id == "profile-secondary"
    checks.passed("selecting a provider profile updates the selected connection")

    page.get_by_role("button", name="新建档案", exact=True).click()
    page.get_by_label("档案名称", exact=True).fill("浏览器验证档案")
    page.get_by_label("模型标识", exact=True).fill("fixture-code-model")
    page.get_by_label("Base URL", exact=True).fill("http://example.invalid/v1")
    page.get_by_label("API Key", exact=True).fill("fixture-key-never-returned")
    page.get_by_role("button", name="保存档案", exact=True).click()
    expect(page.get_by_role("status")).to_contain_text("已保存模型档案")
    created = next(item for item in api.model_profiles if item["label"] == "浏览器验证档案")
    identifier = created["id"]
    fingerprint = api.key_fingerprints[identifier]
    assert all("fixture-key-never-returned" not in str(response) for response in api.config_responses)
    expect(page.get_by_text("fixture-key-never-returned", exact=False)).to_have_count(0)
    checks.passed("new provider connection saves without returning its API key")
    target = profile_card("浏览器验证档案")
    target.get_by_role("button", name="编辑", exact=True).click()
    expect(page.get_by_label("API Key（留空则保留原密钥）", exact=True)).to_have_value("")
    page.get_by_label("模型标识", exact=True).fill("fixture-code-model-revised")
    page.get_by_role("button", name="保存修改", exact=True).click()
    expect(page.get_by_role("status")).to_contain_text("已更新模型档案")
    assert api.key_fingerprints[identifier] == fingerprint
    assert "api_key" not in api.profile_requests[-1][2]
    checks.passed("editing a provider with an empty key preserves its saved credential")
    target.get_by_role("button", name="编辑", exact=True).click()
    page.get_by_role("checkbox", name="清除已保存的 API Key", exact=False).check()
    page.get_by_role("button", name="保存修改", exact=True).click()
    expect(page.get_by_role("status")).to_contain_text("已更新模型档案")
    assert api.profile_requests[-1][2]["api_key"] == ""
    assert not api.key_fingerprints[identifier]
    checks.passed("explicit clear-key option sends an empty credential")
    save(page, directory, "model-profiles-light")
    responsive(page, checks, "model-profiles", directory)
    page.once("dialog", lambda dialog: dialog.accept())
    target.get_by_role("button", name="删除", exact=True).click()
    expect(page.get_by_role("status")).to_contain_text("已删除")
    assert not any(item["id"] == identifier for item in api.model_profiles)
    checks.passed("unused stored provider can be deleted without affecting existing runs")
    page.get_by_role("button", name="新建审计", exact=False).first.click()
    workspace_ready(page)


def run_race_regressions(page: Page, api: MockAPI, checks: Checks) -> None:
    """Exercise stale requests while keeping all mutations inside the mock router."""
    page.set_viewport_size({"width": 1440, "height": 900})
    for destination in ("settings", "new-task"):
        page.get_by_role("button", name="新建审计", exact=False).first.click()
        workspace_ready(page)
        choose_snapshot(page)
        page.get_by_role("textbox", name="审计任务", exact=True).fill(OBJECTIVE)
        page.get_by_role("textbox", name="验收目标", exact=True).fill(CRITERIA)
        api.hold_create = True
        previous = api.create_count
        page.get_by_role("button", name="发送审计任务", exact=True).click()
        for _ in range(100):
            if api.pending_create is not None:
                break
            page.wait_for_timeout(50)
        assert api.pending_create is not None, "create request was never held"
        assert api.create_count == previous + 1
        if destination == "settings":
            page.get_by_role("button", name="工作空间设置", exact=False).first.click()
            expect(page.get_by_role("heading", name="工作空间设置", exact=True)).to_be_visible()
        else:
            page.get_by_role("button", name="新建审计", exact=False).first.click()
            workspace_ready(page)
        api.finish_create()
        api.hold_create = False
        # Give the released POST's promise a turn to invoke any stale callbacks.
        page.wait_for_timeout(300)
        if destination == "settings":
            expect(page).to_have_url(re.compile(r"#settings$"))
            expect(page.get_by_role("heading", name="工作空间设置", exact=True)).to_be_visible()
        else:
            assert "#run/" not in page.url, "stale create request hijacked the new draft"
            expect(page.get_by_role("textbox", name="审计任务", exact=True)).to_have_value("")
            expect(page.locator(".attachment-card")).to_have_count(0)
        checks.passed(f"pending create cannot hijack navigation to {destination}")

    second_id = "smoke-snapshot-b"
    second = snapshot()
    second.update(id=second_id, name="第二份源码.zip")
    api.snapshot_records[second_id] = second
    api.snapshot_read_failures[second_id] = 1
    page.reload(wait_until="domcontentloaded")
    workspace_ready(page)
    choose_snapshot(page)
    page.get_by_role("textbox", name="审计任务", exact=True).fill(OBJECTIVE)
    page.get_by_role("textbox", name="验收目标", exact=True).fill(CRITERIA)
    page.get_by_role("button", name="选择已有快照", exact=True).click()
    dialog = page.get_by_role("dialog", name="选择已有源码快照", exact=True)
    dialog.get_by_role("button", name=re.compile("第二份源码")).click()
    expect(page.get_by_role("alert")).to_contain_text("模拟快照读取暂时失败")
    expect(page.locator(".attachment-card")).to_have_count(0)
    expect(page.get_by_role("button", name=re.compile(r"^快照"))).to_be_disabled()
    previous = api.create_count
    page.get_by_role("button", name="发送审计任务", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("请先上传或选择源码 ZIP")
    assert api.create_count == previous, "failed snapshot B silently submitted stale snapshot A"
    checks.passed("failed snapshot switch clears the old attachment and prevents stale submission")
    page.get_by_role("button", name="选择已有快照", exact=True).click()
    page.get_by_role("dialog", name="选择已有源码快照", exact=True).get_by_role("button", name=re.compile("第二份源码")).click()
    expect(page.locator(".attachment-card")).to_contain_text("第二份源码.zip")
    expect(page.get_by_text("5 个可读文件", exact=False)).to_be_visible()
    expect(page.get_by_role("button", name=re.compile(r"^快照"))).to_be_enabled()
    expect(page.get_by_role("textbox", name="审计任务", exact=True)).to_have_value(OBJECTIVE)
    checks.passed("reselecting the same failed snapshot retries and restores its own snapshot")


def run_status_regressions(page: Page, base: str, api: MockAPI, checks: Checks) -> None:
    """A historical source claim can be withdrawn without losing its evidence record."""
    observed = api.findings[COMPLETED_ID]
    observed["disposition"] = "retracted"
    goto(page, base, f"#run/{COMPLETED_ID}")
    expect(page.locator(".result-card")).to_contain_text("其中 0 项仍被本次运行主张")
    page.get_by_role("button", name="审计详情", exact=True).click()
    summary = page.get_by_role("dialog", name="审计详情").locator(".stat").filter(has=page.get_by_text("有效漏洞候选", exact=True))
    expect(summary.locator(".stat-value")).to_have_text("0")
    expect(summary.locator(".stat-note")).to_contain_text("已撤回/取代/判重 1")
    checks.passed("withdrawn evidence remains stored while active findings and overview counts exclude it")
    close_dialog(page)
    observed["disposition"] = "contested"
    page.reload(wait_until="domcontentloaded")
    expect(page.locator(".result-card")).to_contain_text("其中 1 项仍被本次运行主张")
    checks.passed("contested claims retain their independent evidence and human-review states")
    observed["disposition"] = "open"

    failed_id = "smoke-failed-with-terminal-reason"
    import copy
    failed = copy.deepcopy(api.runs[COMPLETED_ID])
    failed.update(id=failed_id, status="failed", error="MOCK_WORKER_RUNTIME_ERROR: interpreter stopped unexpectedly")
    api.runs[failed_id] = failed
    api.findings[failed_id] = copy.deepcopy(observed)
    api.findings[failed_id].update(id=f"finding-{failed_id}", run_id=failed_id)
    goto(page, base, f"#run/{failed_id}")
    expect(page.get_by_role("alert")).to_contain_text("MOCK_WORKER_RUNTIME_ERROR")
    expect(page.locator(".result-card")).to_contain_text("已定位源码证据")
    checks.passed("run errors remain visible alongside a persisted goal terminal reason")


def run_result_classification_checks(page: Page, base: str, api: MockAPI, checks: Checks, directory: Path | None) -> None:
    """Facts stay traceable without being counted as vulnerabilities, including old API shapes."""
    import copy

    observed = api.findings[COMPLETED_ID]
    observed.update(severity="low", disposition="open", verdict="confirmed")
    goto(page, base, f"#run/{COMPLETED_ID}")
    expect(page.locator(".result-finding")).to_have_count(1)
    if page.get_by_role("button", name="切换深色主题", exact=True).count():
        page.get_by_role("button", name="切换深色主题", exact=True).click()
    expect(page.locator("html")).to_have_attribute("data-theme", "dark")
    expect(page.locator(".result-finding")).to_contain_text("low")
    expect(page.locator(".result-card")).to_contain_text("另有 2 条排查记录，不计为漏洞")
    dialog = open_findings(page)
    expect(dialog.locator(".finding-layout")).to_contain_text(observed["title"])
    expect(dialog.locator(".finding-layout")).not_to_contain_text("上传路径已规范化")
    checks.passed("real low-severity vulnerabilities remain candidates while safe observations are separate")

    observations = dialog.get_by_role("region", name="排查记录（非漏洞）", exact=True)
    before = len(api.source_requests)
    observations.get_by_role("button", name="查看排查记录（2）", exact=True).click()
    observations.get_by_role("button", name=re.compile(r"^排查记录\s*上传路径已规范化")).click()
    historical = observations.get_by_role("region", name="排查记录详情", exact=True)
    expect(historical).to_contain_text("不构成漏洞确认")
    review = observations.get_by_role("region", name="历史人工记录", exact=True)
    expect(review).to_contain_text("只读")
    expect(review.get_by_role("combobox")).to_have_count(0)
    review.get_by_role("button", name="查看历史记录（1）", exact=True).click()
    review.get_by_role("button", name=re.compile(r"^确认结论")).click()
    expect(review).to_contain_text("历史人工排查记录：已核对 basename 防护")
    expect(review.get_by_role("link", name="历史代码评审.txt", exact=True)).to_have_attribute("href", "/api/evidence/historical-review.txt")
    expect(observations.get_by_role("button", name="记录一次人工复核", exact=True)).to_have_count(0)
    assert len(api.source_requests) == before, "observation source loaded before explicit disclosure"
    observations.get_by_role("button", name=re.compile(r"^排查记录\s*上传路径已规范化")).click()
    observations.get_by_role("button", name=re.compile(r"^排查记录\s*已确认上传入口的认证边界")).click()
    expect(observations.get_by_role("region", name="排查记录详情", exact=True)).to_contain_text("第 1 次尝试")
    source = observations.get_by_role("region", name="排查依据源码", exact=True)
    source.get_by_role("button", name=re.compile(r"^src\/auth\.php")).click()
    assert len(api.source_requests) == before
    source.get_by_role("button", name=re.compile(r"^查看源码")).click()
    expect(source.get_by_role("region", name=re.compile(r"src\/auth\.php 第"))).to_be_visible()
    assert len(api.source_requests) >= before + 1
    assert api.source_requests[-1]["path"] == "src/auth.php"
    checks.passed("minimal attempt observations load source lazily and preserve historical human reviews read-only")
    observations.evaluate("""node => { const box = node.closest('.drawer-body');
      box.scrollTop += node.getBoundingClientRect().top - box.getBoundingClientRect().top - 12; }""")
    save(page, directory, "source-observation-dark")
    responsive(page, checks, "source-observations", directory)
    page.set_viewport_size({"width": 390, "height": 900})
    observations.evaluate("""node => { const box = node.closest('.drawer-body');
      box.scrollTop += node.getBoundingClientRect().top - box.getBoundingClientRect().top - 12; }""")
    save(page, directory, "source-observations-mobile-focused")
    page.set_viewport_size({"width": 1440, "height": 900})

    dialog.get_by_role("tab", name="结果报告", exact=True).click()
    expect(dialog.get_by_role("region", name="报告漏洞候选", exact=True)).to_contain_text("1 条引用通过")
    expect(dialog.get_by_role("region", name="人工复核清单", exact=True)).to_contain_text("确认漏洞 1 条")
    expect(dialog.get_by_role("region", name="排查记录（非漏洞）", exact=True)).to_contain_text("2 条")
    checks.passed("report separates observations and excludes their confirmed historical reviews from confirmed vulnerabilities")
    close_dialog(page)

    # A previous server may return source facts mixed into findings and metrics.
    fact = source_observations(COMPLETED_ID)[0]
    fact.update(severity="high", finding_kind="data_flow")
    api.detail_overrides[COMPLETED_ID] = {"findings": [copy.deepcopy(observed), fact], "source_observations": []}
    page.reload(wait_until="domcontentloaded")
    expect(page.locator(".result-card")).to_contain_text("共保存 1 项漏洞候选")
    expect(page.locator(".result-card")).to_contain_text("另有 1 条排查记录")
    expect(page.locator(".result-finding")).to_have_count(1)
    page.get_by_role("button", name="审计详情", exact=True).click()
    summary = page.get_by_role("dialog", name="审计详情").locator(".stat").filter(has=page.get_by_text("有效漏洞候选", exact=True))
    expect(summary.locator(".stat-value")).to_have_text("1")
    checks.passed("legacy mixed responses cannot classify a high-severity data-flow fact as a vulnerability")
    close_dialog(page)

    api.detail_overrides[COMPLETED_ID] = {"findings": [fact], "source_observations": []}
    page.reload(wait_until="domcontentloaded")
    expect(page.locator(".result-card")).to_contain_text("共保存 0 项漏洞候选")
    expect(page.locator(".result-card")).to_contain_text("历史任务状态沿用原判定")
    expect(page.locator(".result-finding")).to_have_count(0)
    expect(page.locator(".conversation-meta")).to_contain_text("目标已达成")
    dialog = open_findings(page)
    expect(dialog.locator(".finding-layout")).to_have_count(0)
    expect(dialog.get_by_role("region", name="排查记录（非漏洞）", exact=True)).to_contain_text("1 条")
    checks.passed("historical safe-only completed runs retain their status with zero vulnerabilities and an explicit explanation")
    no_overflow(page, "safe-only observation drawer 1440px", checks)
    save(page, directory, "historical-safe-only-dark")
    close_dialog(page)

    minimal = source_observations(COMPLETED_ID)[1]
    for key in ("file_path", "line", "unit_start_line", "unit_end_line"):
        minimal.pop(key, None)
    api.detail_overrides[COMPLETED_ID] = {"findings": [], "source_observations": [minimal]}
    page.reload(wait_until="domcontentloaded")
    dialog = open_findings(page)
    observations = dialog.get_by_role("region", name="排查记录（非漏洞）", exact=True)
    observations.get_by_role("button", name="查看排查记录（1）", exact=True).click()
    observations.get_by_role("button", name=re.compile(r"^排查记录\s*已确认上传入口的认证边界")).click()
    expect(observations.get_by_role("region", name="排查记录详情", exact=True)).to_contain_text("第 1 次尝试")
    expect(observations).not_to_contain_text("undefined")
    checks.passed("minimal historical observation projections retain attempt context without undefined location metadata")
    close_dialog(page)
    del api.detail_overrides[COMPLETED_ID]


def install_activity_stream(page: Page) -> None:
    """Control only the dedicated fixture stream; normal cases keep native SSE.

    Its initial frames still come from the strict API router. Later frames are released
    by the test so the running/pending UI can be observed before a result arrives.
    """
    page.add_init_script("""(() => {
      const NativeEventSource = window.EventSource;
      window.__auditActivityStreams = [];
      class ControlledStream extends EventTarget {
        constructor(url) {
          super(); this.url = String(url); this.readyState = 0; this.withCredentials = false;
          window.__auditActivityStreams.push(this);
          fetch(this.url).then(response => response.text()).then(body => {
            if (this.readyState === 2) return;
            this.readyState = 1; this.deliver('open', new Event('open'));
            for (const frame of body.split('\\n\\n')) {
              const data = frame.split('\\n').find(line => line.startsWith('data: '));
              if (data) this.message(JSON.parse(data.slice(6)));
            }
          }).catch(() => this.deliver('error', new Event('error')));
        }
        deliver(type, value) { this.dispatchEvent(value); this['on' + type]?.(value); }
        message(value) {
          if (this.readyState !== 1) return;
          this.deliver('message', new MessageEvent('message', {data: JSON.stringify(value), lastEventId: String(value.id)}));
        }
        close() { this.readyState = 2; }
      }
      window.EventSource = class extends NativeEventSource {
        constructor(url, options) {
          if (String(url).includes('/smoke-live-activity/')) return new ControlledStream(url);
          super(url, options);
        }
      };
      window.__emitAuditActivity = rows => {
        const active = window.__auditActivityStreams.filter(stream => stream.readyState === 1);
        rows.forEach(row => active.forEach(stream => stream.message(row)));
        return active.length;
      };
    })();""")


def run_chat_activity_checks(page: Page, base: str, api: MockAPI, checks: Checks, directory: Path | None) -> None:
    """Continuous activity remains readable while tools and retries update in place."""
    frames = activity_events()
    api.runs[ACTIVITY_ID] = run(ACTIVITY_ID, "running")
    api.findings[ACTIVITY_ID] = finding(ACTIVITY_ID)
    api.detail_overrides[ACTIVITY_ID] = {"findings": [], "source_observations": []}
    api.event_overrides[ACTIVITY_ID] = frames[:3]

    def emit(rows: list[dict[str, Any]]) -> None:
        present = {item["id"] for item in api.event_overrides[ACTIVITY_ID]}
        api.event_overrides[ACTIVITY_ID].extend(item for item in rows if item["id"] not in present)
        assert page.evaluate("rows => window.__emitAuditActivity(rows)", rows) == 1, "fixture stream is not active"
        page.wait_for_timeout(100)

    page.set_viewport_size({"width": 1440, "height": 900})
    goto(page, base, f"#run/{ACTIVITY_ID}")
    stream = page.locator(".activity-stream")
    expect(stream).to_be_visible()
    expect(stream.get_by_text("先检查上传入口的路径处理，再核对认证边界和文件写入。", exact=True)).to_be_visible()
    expect(stream.locator(".activity-tool")).to_have_count(0)
    expect(page.locator(".trace")).to_have_count(0)
    checks.passed("agent progress appears as plain activity before any tool is called; logs remain in details")
    save(page, directory, "progress-before-tools-dark")

    emit(frames[3:5])
    tools = stream.locator(".activity-tool")
    expect(tools).to_have_count(2)
    first = tools.filter(has=page.locator(".activity-tool-subject", has_text="src/upload.php:10–12"))
    expect(first).to_have_count(1)
    first_key = first.get_attribute("data-activity-key")
    first.get_by_role("button", name=re.compile(r"工具详情：")).click()
    params = first.locator(".activity-tool-detail")
    params.get_by_role("tab", name="参数", exact=True).click()
    expect(params.get_by_text("LONG_PAYLOAD_END", exact=False)).to_have_count(0)
    params.get_by_role("button", name="展开全文", exact=True).click()
    expect(params).to_contain_text("LONG_PAYLOAD_END")
    params.get_by_role("tab", name="参数", exact=True).focus()
    source_before = len(api.source_requests)
    emit([frames[5]])
    expect(tools).to_have_count(2)
    expect(first.locator(".activity-tool-detail")).to_be_visible()
    expect(params.get_by_role("tab", name="参数", exact=True)).to_be_focused()
    assert len(api.source_requests) == source_before, "opening tool parameters fetched source"
    emit([frames[6], frames[6]])
    expect(tools).to_have_count(2)
    assert first.get_attribute("data-activity-key") == first_key, "tool row identity changed when its result arrived"
    expect(first.locator(".activity-tool-detail")).to_be_visible()
    expect(params.get_by_role("tab", name="参数", exact=True)).to_be_focused()
    params.get_by_role("tab", name="返回预览", exact=True).click()
    expect(params).to_contain_text("WORKER_A_RETURN")
    expect(params).not_to_contain_text("WORKER_B_RETURN")
    assert "fixture-invocation-a" not in stream.inner_text()
    assert "reused-call" not in stream.inner_text()
    checks.passed("parallel workers with identical call IDs pair independently; inline details survive results and replay")

    params.get_by_role("tab", name="源码", exact=True).click()
    expect(params.get_by_role("region", name=re.compile(r"src\/upload\.php 第"))).to_be_visible()
    assert len(api.source_requests) >= source_before + 1
    assert api.source_requests[-1] == {"path": SOURCE_PATH, "start": 10, "end": 12}
    checks.passed("tool source is fetched only after the explicit source tab is opened")
    emit(frames[7:14])
    expect(stream).to_contain_text("第二次尝试只补读路径规范化相关源码")
    expect(stream.locator(".activity-tool")).to_have_count(4)
    error_tool = stream.locator('.activity-tool[data-tool="search_code"]')
    error_tool.get_by_role("button", name=re.compile("工具详情：")).click()
    error_detail = error_tool.locator(".activity-tool-detail")
    error_detail.get_by_role("tab", name="异常", exact=True).click()
    expect(error_detail).to_contain_text("模拟检索暂时失败")
    checks.passed("tool errors stay local; a new task attempt does not overwrite the previous invocation")
    save(page, directory, "activity-tools-error-dark")

    # Consecutive successful operations become one compact historical disclosure.
    history_start = len(api.event_overrides[ACTIVITY_ID])
    emit(frames[14:])
    expect(stream.get_by_role("button", name=re.compile(r"^加载更早的"))).to_be_visible()
    history_button = stream.get_by_role("button", name=re.compile(r"^加载更早的"))
    while history_button.count():
        history_button.click()
    expect(first.locator(".activity-tool-detail")).to_be_visible()
    expect(stream.locator(".activity-tool-group")).not_to_have_count(0)
    checks.passed("long activity histories paginate without losing an already expanded tool")

    scroll = page.locator(".chat-scroll")
    scroll.evaluate("node => { node.scrollTop = 0; node.dispatchEvent(new Event('scroll', {bubbles: true})); }")
    earlier = scroll.evaluate("node => node.scrollTop")
    last = {**frames[-1], "id": frames[-1]["id"] + 1, "kind": "audit_progress",
            "payload": {**frames[-1]["payload"], "message": "新增活动不会打断正在查看的历史，完成后继续核对部署条件。"}}
    emit([last])
    expect(page.get_by_role("button", name="有新活动", exact=True)).to_be_visible()
    assert abs(scroll.evaluate("node => node.scrollTop") - earlier) < 3
    page.get_by_role("button", name="有新活动", exact=True).click()
    expect(stream).to_contain_text("新增活动不会打断正在查看的历史")
    checks.passed("reading older activity preserves scroll position and offers a new-activity action")

    for theme in ("dark", "light"):
        page.set_viewport_size({"width": 1440, "height": 900})
        if page.locator("html").get_attribute("data-theme") != theme:
            page.get_by_role("button", name=f"切换{'深' if theme == 'dark' else '浅'}色主题", exact=True).click()
        for width in (1440, 1024, 768, 390):
            page.set_viewport_size({"width": width, "height": 900})
            scroll.evaluate("node => { node.scrollTop = node.scrollHeight; }")
            no_overflow(page, f"chat activity {theme} {width}px", checks)
            save(page, directory, f"chat-activity-{theme}-{width}")

    # The terminal transition drains the saved event log and closes the live stream.
    final = {**last, "id": last["id"] + 1, "kind": "run_completed", "payload": {"role": "host", "goal_status": "met"}}
    api.runs[ACTIVITY_ID].update(status="completed", finished_at=final["created_at"])
    emit([final])
    expect(page.locator(".result-card")).to_be_visible(timeout=10000)
    page.wait_for_function("window.__auditActivityStreams.every(stream => stream.readyState === 2)")
    rows_before = stream.locator("[data-activity-key]").count()
    page.reload(wait_until="domcontentloaded")
    expect(page.locator(".result-card")).to_be_visible()
    expect(page.locator(".activity-stream")).to_contain_text("新增活动不会打断正在查看的历史")
    assert (ACTIVITY_ID, 0) in api.event_queries
    assert history_start > 0 and rows_before > 0
    checks.passed("terminal activity closes its live stream and restores from the saved event log after refresh")


def run_activity_focus_checks(page: Page, base: str, api: MockAPI, checks: Checks, directory: Path | None) -> None:
    """Keyboard focus and expanded prose are as durable as expanded tool details."""
    context = {"role": "worker", "task_id": "task-upload", "attempt": 1,
               "agent_invocation_id": "focus-invocation", "request_index": 1, "phase": "explore"}
    rows = [event(ACTIVITY_ID, 1, "audit_progress", {**context,
             "message": "已定位上传入口，正在核对文件名处理和路径约束。"})]
    for index, (start, end) in enumerate(((10, 12), (24, 28))):
        rows.extend([
            event(ACTIVITY_ID, 2 + index * 2, "tool_call", {**context, "tool": "read_source", "call_id": f"focus-{index}",
                  "args": {"path": SOURCE_PATH, "start": start, "end": end}}),
            event(ACTIVITY_ID, 3 + index * 2, "tool_result", {**context, "tool": "read_source", "call_id": f"focus-{index}",
                  "status": "ok", "duration_ms": 14, "preview": "已读取原始源码；继续核对路径与部署条件。"}),
        ])
    api.runs[ACTIVITY_ID] = run(ACTIVITY_ID, "running")
    api.findings[ACTIVITY_ID] = finding(ACTIVITY_ID)
    api.detail_overrides[ACTIVITY_ID] = {"findings": [], "source_observations": []}
    api.event_overrides[ACTIVITY_ID] = rows
    page.set_viewport_size({"width": 1440, "height": 900})
    # Navigating to the very same hash is a same-document navigation: leave the
    # prior completed fixture so its event cursor and component state are released.
    goto(page, base)
    workspace_ready(page)
    goto(page, base, f"#run/{ACTIVITY_ID}")
    stream = page.locator(".activity-stream")
    expect(stream.locator(".activity-tool")).to_have_count(2)

    def emit(values: list[dict[str, Any]]) -> None:
        api.event_overrides[ACTIVITY_ID].extend(values)
        assert page.evaluate("rows => window.__emitAuditActivity(rows)", values) == 1
        page.wait_for_timeout(100)

    focused = stream.locator(".activity-tool-toggle").nth(1)
    focused.focus()
    focused.evaluate("node => { window.__focusedAuditControl = node; }")
    emit([event(ACTIVITY_ID, 6, "model_request", {**context, "request_index": 2})])
    expect(focused).to_be_focused()
    expect(focused).to_have_attribute("aria-expanded", "false")
    assert page.evaluate("document.activeElement === window.__focusedAuditControl")
    checks.passed("keyboard-focused tool controls survive the next model step without being folded or remounted")

    # Capture the ordinary conversation before the deliberately huge history stress case.
    scroll = page.locator(".chat-scroll")
    for theme in ("dark", "light"):
        if page.locator("html").get_attribute("data-theme") != theme:
            page.get_by_role("button", name=f"切换{'深' if theme == 'dark' else '浅'}色主题", exact=True).click()
        scroll.evaluate("node => { const intro = node.querySelector('.assistant-message'); node.scrollTop += intro.getBoundingClientRect().top - node.getBoundingClientRect().top - 22; }")
        save(page, directory, f"conversation-process-{theme}")
    page.set_viewport_size({"width": 390, "height": 844})
    scroll.evaluate("node => { const intro = node.querySelector('.assistant-message'); node.scrollTop += intro.getBoundingClientRect().top - node.getBoundingClientRect().top - 12; }")
    save(page, directory, "conversation-process-mobile")
    page.set_viewport_size({"width": 1440, "height": 900})

    long_summary = "逐项核对已读取的路径处理与目录约束，并记录尚未确认的部署条件。" * 55 + "已保存依据全文末尾。"
    emit([
        event(ACTIVITY_ID, 7, "model_response", {**context, "request_index": 2}),
        event(ACTIVITY_ID, 8, "task_assessment", {**context, "request_index": 2, "outcome": "no_evidence", "summary": long_summary,
              "rationale": "当前分支未证实路径绕过，其他上传入口仍需继续调查。"}),
        event(ACTIVITY_ID, 9, "task_agent_terminal", {**context, "request_index": 2, "reason": "completed"}),
    ])
    message = stream.locator('.activity-message[data-event-kind="task_assessment"]')
    message.get_by_role("button", name="展开全文", exact=True).click()
    expect(message).to_contain_text("已保存依据全文末尾。")
    collapse = message.get_by_role("button", name="收起", exact=True)
    collapse.focus()
    collapse.evaluate("node => { window.__focusedAuditControl = node; }")
    previous_scroll = scroll.evaluate("node => node.scrollTop")
    updates = [event(ACTIVITY_ID, 10 + index, "audit_progress", {**context,
               "task_id": "task-auth", "agent_invocation_id": "focus-another-worker", "request_index": index + 1,
               "message": f"继续核对第 {index + 1} 条认证边界线索。"}) for index in range(65)]
    emit(updates)
    expect(message).to_be_visible()
    expect(collapse).to_be_focused()
    assert page.evaluate("document.activeElement === window.__focusedAuditControl")
    expect(message).to_contain_text("已保存依据全文末尾。")
    expect(page.get_by_role("button", name="有新活动", exact=True)).to_be_visible()
    assert abs(scroll.evaluate("node => node.scrollTop") - previous_scroll) < 3
    checks.passed("expanded long audit prose stays mounted, focused and readable beyond the latest fifty activities")


def run_readonly(page: Page, base: str, run_id: str | None, checks: Checks, directory: Path | None) -> None:
    attempted: list[str] = []

    def guard(route: Any) -> None:
        if route.request.method not in {"GET", "HEAD", "OPTIONS"}:
            attempted.append(f"{route.request.method} {route.request.url}")
            route.abort("blockedbyclient")
        else:
            route.continue_()

    page.route("**/api/**", guard)
    goto(page, base, f"#run/{run_id}" if run_id else "")
    if run_id:
        expect(page.get_by_role("button", name="审计详情", exact=True)).to_be_visible(timeout=15000)
        checks.passed("existing session restored")
        page.get_by_role("button", name="审计详情", exact=True).click()
        dialog = page.get_by_role("dialog", name="审计详情", exact=True)
        for tab in ("项目与任务图", "执行日志", "发现与复核", "结果报告"):
            dialog.get_by_role("tab", name=tab, exact=True).click()
            expect(dialog.get_by_role("tabpanel")).to_be_visible()
            assert len(dialog.get_by_role("tabpanel").inner_text()) > 15, f"empty {tab}"
            no_overflow(page, tab, checks)
        save(page, directory, "real-report-dark")
        close_dialog(page)
        responsive(page, checks, "real-conversation", directory)
    else:
        expect(page.get_by_role("textbox", name="审计任务", exact=True)).to_be_visible(timeout=15000)
        responsive(page, checks, "real-draft", directory)
        page.get_by_role("button", name="工作空间设置", exact=False).first.click()
        expect(page.get_by_role("heading", name="工作空间设置", exact=True)).to_be_visible()
        checks.passed("read-only model configuration renders")
        save(page, directory, "real-settings-dark")
    assert not attempted, f"read-only mode attempted mutation: {attempted}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("frontend_url")
    parser.add_argument("run_id", nargs="?")
    parser.add_argument("--mock", action="store_true", help="intercept every API call with in-memory fixtures")
    parser.add_argument("--screenshots", type=Path, help="write dark/light/mobile screenshots here")
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    checks = Checks()
    errors: list[dict[str, str]] = []
    api = MockAPI()
    failed = False
    with sync_playwright() as pw:
        chrome = os.environ.get("CHROME_BIN")
        browser = pw.chromium.launch(**({"executable_path": chrome} if chrome else {}))
        page = browser.new_page(viewport={"width": 1440, "height": 900}, locale="zh-CN", timezone_id="Asia/Shanghai")
        if args.mock:
            install_activity_stream(page)
        page.set_default_timeout(10000)
        page.on("console", lambda msg: errors.append({"kind": "console", "text": msg.text, "url": msg.location.get("url", "")}) if msg.type == "error" else None)
        page.on("pageerror", lambda exc: errors.append({"kind": "pageerror", "text": str(exc), "url": ""}))
        try:
            if args.mock:
                run_mock(page, args.frontend_url.rstrip("/"), api, checks, args.screenshots)
                run_profile_checks(page, api, checks, args.screenshots)
                run_race_regressions(page, api, checks)
                run_status_regressions(page, args.frontend_url.rstrip("/"), api, checks)
                run_result_classification_checks(page, args.frontend_url.rstrip("/"), api, checks, args.screenshots)
                run_chat_activity_checks(page, args.frontend_url.rstrip("/"), api, checks, args.screenshots)
                run_activity_focus_checks(page, args.frontend_url.rstrip("/"), api, checks, args.screenshots)
            else:
                run_readonly(page, args.frontend_url.rstrip("/"), args.run_id, checks, args.screenshots)
        except Exception:
            failed = True
            traceback.print_exc()
            save(page, args.screenshots, "failure")
        # Keep errors from the entire visit, including initial load and intentional failures.
        hard = [item for item in errors if not (args.mock and item["kind"] == "console" and "Failed to load resource" in item["text"] and item["url"] in api.expected_failures)]
        if errors:
            print(f"\nConsole/page errors recorded: {len(errors)} ({len(hard)} unexpected)")
            for item in errors:
                print(f"  {item['kind']}: {item['text']} {item['url']}")
        if hard:
            failed = True
        if args.mock and api.unexpected:
            print("Unhandled mocked routes:", api.unexpected)
            failed = True
        browser.close()
    print(f"\n{'FAIL' if failed else 'PASS'}: {checks.count} browser checks; {'mock API only' if args.mock else 'real service read-only'}")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
