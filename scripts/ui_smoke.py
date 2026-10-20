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

from ui_fixtures import COMPLETED_ID, CREATED_ID, CRITERIA, LONG_LOG, LONG_VALUE, OBJECTIVE, SOURCE_PATH, MockAPI, snapshot


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
    expect(page.locator(".trace-counts")).to_contain_text("11 条事件")
    expect(page.locator(".trace-counts")).to_contain_text("2 次工具活动")
    assert api.create_count == 2
    assert "scope" not in api.create_bodies[-1], "legacy scope field would be rejected by codeagent"
    assert api.create_bodies[-1]["budgets"] == {"responses": 24, "tools": 96, "seconds": 1800}
    expect(page.locator(".message-attachment")).to_contain_text("5 个可读文件")
    checks.passed("existing snapshot creates one run; SSE duplicate frames are deduplicated")
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
    code_card.evaluate("""node => { const box = node.closest('.chat-scroll');
      box.scrollTop += node.getBoundingClientRect().top - box.getBoundingClientRect().top - 14; }""")
    save(page, directory, "code-action-dark")
    trace.get_by_role("combobox", name="按事件类型筛选轨迹").select_option("tool_call")
    trace.get_by_role("combobox", name="按角色筛选轨迹").select_option("recon")
    expand_visible_groups(trace)
    expect(trace.locator(".trace-tool")).to_have_count(1)
    expect(trace.locator(".trace-tool")).to_contain_text("find_files")
    checks.passed("reconnaissance has its own role and trace filters")

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
    summary = page.get_by_role("dialog", name="审计详情").locator(".stat").filter(has=page.get_by_text("有效证据化发现", exact=True))
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
        for tab in ("项目与任务图", "发现与复核", "结果报告"):
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
        page.set_default_timeout(10000)
        page.on("console", lambda msg: errors.append({"kind": "console", "text": msg.text, "url": msg.location.get("url", "")}) if msg.type == "error" else None)
        page.on("pageerror", lambda exc: errors.append({"kind": "pageerror", "text": str(exc), "url": ""}))
        try:
            if args.mock:
                run_mock(page, args.frontend_url.rstrip("/"), api, checks, args.screenshots)
                run_profile_checks(page, api, checks, args.screenshots)
                run_race_regressions(page, api, checks)
                run_status_regressions(page, args.frontend_url.rstrip("/"), api, checks)
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
