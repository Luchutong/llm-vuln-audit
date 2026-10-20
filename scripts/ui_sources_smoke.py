#!/usr/bin/env python3
"""Source-centered browser acceptance, with every API call intercepted locally.

  uv run --with playwright python scripts/ui_sources_smoke.py http://127.0.0.1:5173 \
      --screenshots /tmp/audit-sources-ui

CHROME_BIN may select an installed Chromium. No provider, audit worker, or real
backend is contacted; uploads and run creation mutate only the in-memory fixture.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import traceback

from playwright.sync_api import Page, expect, sync_playwright

from ui_fixtures import (
    COMPLETED_ID, CREATED_ID, EMPTY_PROJECT_ID, LEDGER_ID, NEWER_SNAPSHOT_ID,
    OBJECTIVE, OTHER_PROJECT_ID, OTHER_SNAPSHOT_ID, PROJECT_ID, SNAPSHOT_ID,
    STALE_LEDGER_ID, MockAPI, snapshot, sources_api,
)
from ui_smoke import Checks, goto, no_overflow, save


def navigate(page: Page, fragment: str) -> None:
    page.evaluate("hash => { location.hash = hash; }", fragment)


def ledger_ready(page: Page, total: int | None = None) -> None:
    region = page.get_by_role("region", name="漏洞台账", exact=True)
    expect(region).to_be_visible()
    if total is not None:
        expect(region.locator(".ledger-list-meta")).to_contain_text(f"共 {total} 条漏洞结论")
    else:
        expect(region.locator(".ledger-list-meta")).not_to_contain_text("正在读取")


def source_ready(page: Page, name: str = "审计样例源码") -> None:
    expect(page.get_by_role("heading", name=name, level=1, exact=True)).to_be_visible()


def ledger_query(page: Page, api: MockAPI, **expected: str) -> None:
    for _ in range(100):
        if api.ledger_queries and all(api.ledger_queries[-1].get(key) == value for key, value in expected.items()):
            return
        page.wait_for_timeout(25)
    raise AssertionError(f"Expected ledger query {expected}, received {api.ledger_queries[-1:]}")


def source_flows(page: Page, base: str, api: MockAPI, checks: Checks) -> None:
    goto(page, base)
    expect(page.get_by_role("heading", name="源码包", level=1, exact=True)).to_be_visible()
    expect(page.locator(".source-card")).to_have_count(3)
    primary = page.locator(".source-card").filter(has=page.get_by_role("link", name="审计样例源码", exact=True))
    expect(primary).to_contain_text("2 ZIP 快照")
    expect(primary).to_contain_text("2 次审计")
    expect(primary).to_contain_text("31 累计候选")
    assert api.upload_count == api.create_count == 0
    search = page.get_by_role("textbox", name="搜索源码包", exact=True)
    search.fill("认证项目")
    expect(page.locator(".source-card")).to_have_count(1)
    page.reload(wait_until="domcontentloaded")
    expect(search).to_have_value("认证项目")
    expect(page.locator(".source-card")).to_have_count(1)
    search.fill("")
    expect(page.locator(".source-card")).to_have_count(3)
    checks.passed("default library groups same-content ZIPs and restores source search on refresh")

    upload = page.get_by_label("上传项目源码 ZIP", exact=True)
    upload.set_input_files({"name": "wrong.php", "mimeType": "text/plain", "buffer": b"<?php"})
    expect(page.get_by_role("alert")).to_contain_text("ZIP")
    upload.set_input_files({"name": "empty.zip", "mimeType": "application/zip", "buffer": b""})
    expect(page.get_by_role("alert")).to_contain_text("压缩包为空")
    page.evaluate("""() => {
      const input = document.querySelector('input[aria-label="上传项目源码 ZIP"]');
      const files = new DataTransfer();
      files.items.add(new File([new Uint8Array(64 * 1024 * 1024 + 1)], 'oversize.zip', {type: 'application/zip'}));
      input.files = files.files; input.dispatchEvent(new Event('change', {bubbles: true}));
    }""")
    expect(page.get_by_role("alert")).to_contain_text("64 MiB")
    assert api.upload_count == 0
    api.fail_upload = True
    archive = {"name": "same-source.zip", "mimeType": "application/zip", "buffer": b"PK\x03\x04ui-fixture"}
    upload.set_input_files(archive)
    expect(page.get_by_role("alert")).to_contain_text("模拟 ZIP 导入失败")
    upload.set_input_files(archive)
    source_ready(page)
    expect(page.get_by_role("status")).to_contain_text("已复用已有 ZIP 快照")
    expect(page.get_by_role("status")).to_contain_text("已归入相同源码的已有项目")
    assert api.upload_count == 2 and api.create_count == 0
    checks.passed("upload validation and retry import into an existing project without starting an audit")

    page.get_by_role("navigation", name="源码包视图").get_by_role("link", name="ZIP 与源码", exact=True).click()
    select = page.get_by_role("combobox", name="浏览 ZIP 快照", exact=True)
    expect(select).to_have_value(NEWER_SNAPSHOT_ID)
    select.select_option(SNAPSHOT_ID)
    expect(page.get_by_role("heading", name="审计样例源码.zip", exact=True)).to_be_visible()
    page.go_back(wait_until="domcontentloaded")
    expect(select).to_have_value(NEWER_SNAPSHOT_ID)
    expect(page.get_by_role("heading", name="审计样例源码-重新打包.zip", exact=True)).to_be_visible()
    select.select_option(SNAPSHOT_ID)
    expect(page.get_by_role("heading", name="审计样例源码.zip", exact=True)).to_be_visible()
    checks.passed("browser back from an explicit archive to the default URL restores the latest ZIP")
    before = len(api.source_requests)
    page.get_by_role("textbox", name="搜索源码文件", exact=True).fill("upload.php")
    page.get_by_role("button", name=re.compile(r"^src\/upload\.php")).click()
    expect(page.locator(".source-row")).not_to_have_count(0)
    assert len(api.source_requests) >= before + 1
    assert api.source_requests[-1]["snapshot_id"] == SNAPSHOT_ID
    page.get_by_role("link", name="基于此 ZIP 开始审计", exact=True).click()
    expect(page.get_by_role("combobox", name="选择源码 ZIP", exact=True)).to_have_value(SNAPSHOT_ID)
    expect(page.locator(".attachment-card")).to_contain_text("a" * 16)
    checks.passed("source browser lazily reads the chosen archive and preserves that ZIP into a new audit")

    navigate(page, f"#sources/{PROJECT_ID}/new")
    select = page.get_by_role("combobox", name="选择源码 ZIP", exact=True)
    expect(select).to_have_value(NEWER_SNAPSHOT_ID)
    expect(page.locator(".attachment-card")).to_contain_text("审计样例源码-重新打包.zip")
    api.snapshot_read_failures[SNAPSHOT_ID] = 1
    select.select_option(SNAPSHOT_ID)
    expect(page.get_by_role("alert")).to_contain_text("模拟快照读取暂时失败")
    expect(page.get_by_role("button", name="开始审计", exact=True)).to_be_disabled()
    expect(page.locator(".attachment-card")).to_have_count(0)
    assert api.create_count == 0
    page.get_by_role("button", name="选择已有快照", exact=True).click()
    page.get_by_role("dialog", name="选择已有源码快照", exact=True).get_by_role("button", name=re.compile("^审计样例源码.zip")).click()
    expect(page.locator(".attachment-card")).to_contain_text("审计样例源码.zip")
    checks.passed("failed ZIP switch clears the previous archive and disables creation until that archive is retried")
    expect(page).to_have_url(re.compile(f"snapshot={SNAPSHOT_ID}$"))
    page.get_by_role("textbox", name="审计任务", exact=True).fill(OBJECTIVE)
    uploads = api.upload_count
    page.get_by_role("button", name="开始审计", exact=True).click()
    expect(page).to_have_url(re.compile(f"#run/{CREATED_ID}$"))
    expect(page.locator(".conversation-meta")).to_contain_text("审计样例源码.zip")
    assert api.create_count == 1 and api.upload_count == uploads
    assert api.create_bodies[-1]["snapshot_id"] == SNAPSHOT_ID
    assert "project_id" not in api.create_bodies[-1]
    expect(page.get_by_role("link", name="项目漏洞台账", exact=True)).to_be_visible()
    checks.passed("latest archive is the default; explicitly selecting an older ZIP submits exactly its snapshot_id")
    page.get_by_role("link", name="ZIP 与源码", exact=True).click()
    expect(page.get_by_role("combobox", name="浏览 ZIP 快照", exact=True)).to_have_value(SNAPSHOT_ID)
    page.reload(wait_until="domcontentloaded")
    expect(page.get_by_role("combobox", name="浏览 ZIP 快照", exact=True)).to_have_value(SNAPSHOT_ID)
    checks.passed("a run's ZIP browser opens its actual archive and restores that choice on refresh")

    navigate(page, f"#sources/{PROJECT_ID}/new?snapshot={OTHER_SNAPSHOT_ID}")
    expect(page.get_by_role("alert")).to_contain_text("不属于此源码项目")
    expect(page.get_by_role("textbox", name="审计任务", exact=True)).to_have_count(0)
    assert api.create_count == 1
    checks.passed("a snapshot belonging to another project cannot silently start an audit")


def ledger_flows(page: Page, api: MockAPI, checks: Checks) -> None:
    navigate(page, f"#sources/{PROJECT_ID}?tab=findings")
    source_ready(page)
    ledger_ready(page, 30)
    region = page.get_by_role("region", name="漏洞台账", exact=True)
    expect(region.get_by_role("link", name="上传路径可绕过目录边界", exact=False)).to_have_count(1)
    expect(region).not_to_contain_text("已撤回的历史推测")
    expect(region.get_by_role("combobox", name="所属源码包", exact=True)).to_have_count(0)
    assert api.ledger_queries[-1]["project_id"] == PROJECT_ID
    expect(page.locator(".sources-head")).to_contain_text("漏洞跨审计累计")
    expect(page.locator(".sources-metrics")).to_contain_text("31")
    checks.passed("project ledger deduplicates repeated run discoveries and distinguishes cumulative statistics from current rows")

    navigate(page, "#findings")
    ledger_ready(page, 31)
    expect(page.locator(".ledger-table tbody tr")).to_have_count(25)
    page.get_by_role("button", name="下一页", exact=True).click()
    ledger_ready(page, 31)
    expect(page.locator(".ledger-table tbody tr")).to_have_count(6)
    expect(page).to_have_url(re.compile(r"page=2"))
    page.reload(wait_until="domcontentloaded")
    ledger_ready(page, 31)
    expect(page.locator(".ledger-pagination")).to_contain_text("第 2 / 2 页")
    page.get_by_role("button", name="上一页", exact=True).click()
    ledger_ready(page, 31)
    page.go_back(wait_until="domcontentloaded")
    ledger_ready(page, 31)
    expect(page.locator(".ledger-pagination")).to_contain_text("第 2 / 2 页")
    before_detail = page.url
    page.locator(".ledger-finding-link").first.click()
    expect(page.locator(".ledger-detail-page")).to_be_visible()
    page.get_by_role("link", name="返回漏洞列表", exact=True).click()
    expect(page).to_have_url(before_detail)
    ledger_ready(page, 31)
    expect(page.locator(".ledger-pagination")).to_contain_text("第 2 / 2 页")
    checks.passed("global ledger paginates 25 rows and restores pagination through refresh and browser history")

    page.get_by_role("combobox", name="所属源码包", exact=True).select_option(PROJECT_ID)
    ledger_ready(page, 30)
    page.get_by_role("combobox", name="严重性", exact=True).select_option("high")
    ledger_ready(page, 1)
    page.get_by_role("combobox", name="验证状态", exact=True).select_option("stale")
    ledger_ready(page, 1)
    page.get_by_role("textbox", name="搜索漏洞", exact=True).fill("结论修订")
    page.get_by_role("button", name="搜索", exact=True).click()
    ledger_query(page, api, q="结论修订", severity="high", verification_status="stale")
    ledger_ready(page, 1)
    expect(page.locator(".ledger-pagination")).to_contain_text("第 1 / 1 页")
    page.reload(wait_until="domcontentloaded")
    ledger_ready(page, 1)
    expect(page.get_by_role("textbox", name="搜索漏洞", exact=True)).to_have_value("结论修订")
    expect(page.get_by_role("combobox", name="验证状态", exact=True)).to_have_value("stale")
    checks.passed("project, severity, verification and keyword filters are combined, persisted and reset to page one")

    navigate(page, f"#findings?project={PROJECT_ID}&disposition=all&q=已撤回")
    ledger_ready(page, 1)
    expect(page.get_by_role("link", name="已撤回的历史推测", exact=False)).to_be_visible()
    page.get_by_role("combobox", name="结论状态", exact=True).select_option("retracted")
    ledger_ready(page, 1)
    navigate(page, "#findings?q=NO_MATCH_UI_FIXTURE")
    ledger_ready(page, 0)
    expect(page.get_by_role("heading", name="没有匹配的漏洞发现", exact=True)).to_be_visible()
    page.get_by_role("button", name="重置筛选", exact=True).first.click()
    ledger_ready(page, 31)
    checks.passed("withdrawn findings remain accessible through disposition filters and empty searches can be reset")
    page.get_by_role("combobox", name="严重性", exact=True).select_option("unknown")
    ledger_ready(page, 1)
    expect(page.locator(".ledger-table tbody")).to_contain_text("未标注")
    checks.passed("findings with missing severity remain visible and can be filtered explicitly")


def detail_flows(page: Page, api: MockAPI, checks: Checks) -> None:
    navigate(page, f"#findings/{LEDGER_ID}")
    expect(page.get_by_role("heading", name="上传路径可绕过目录边界", level=1, exact=True)).to_be_visible()
    detail = page.locator(".ledger-detail-page")
    expect(detail).to_contain_text("当前台账结论")
    provenance = page.get_by_role("region", name="漏洞来源", exact=True)
    expect(provenance).to_contain_text("审计样例源码-重新打包.zip")
    expect(provenance).to_contain_text("审计样例源码.zip")
    expect(page.get_by_role("region", name="跨任务审计记录", exact=True).locator("tbody tr")).to_have_count(2)
    current = page.locator(".ledger-verification-source").filter(has=page.get_by_text("当前验证来源", exact=True))
    expect(current.get_by_role("link")).to_have_attribute("href", f"#run/{COMPLETED_ID}")
    expect(page.get_by_role("link", name="下载 POC", exact=True)).to_have_attribute("href", f"/api/findings/finding-{COMPLETED_ID}/poc")
    before = len(api.source_requests)
    evidence = page.get_by_role("region", name="证据源码", exact=True)
    evidence.get_by_role("button", name=re.compile(r"^src\/upload\.php")).click()
    assert len(api.source_requests) == before
    evidence.get_by_role("button", name=re.compile(r"^查看源码")).first.click()
    expect(evidence.locator(".source-row.hit")).to_have_count(3)
    assert api.source_requests[-1]["snapshot_id"] == SNAPSHOT_ID
    checks.passed("detail uses the canonical revision while retaining early-run verification, history and original POC downloads")
    checks.passed("evidence reads its actual older ZIP rather than the latest project or rediscovery snapshot")
    page.reload(wait_until="domcontentloaded")
    expect(page.get_by_role("heading", name="上传路径可绕过目录边界", level=1, exact=True)).to_be_visible()
    checks.passed("canonical finding details support direct URL refresh")

    navigate(page, f"#findings/{STALE_LEDGER_ID}")
    expect(page.get_by_role("heading", name="结论修订后需要重新验证", level=1, exact=True)).to_be_visible()
    expect(page.locator(".ledger-detail-tags")).to_contain_text("结论已更新，待重新验证")
    expect(page.locator(".ledger-detail-tags .chip-verified")).to_have_count(0)
    expect(page.locator(".ledger-verification-source").filter(has=page.get_by_text("当前验证来源", exact=True))).to_have_count(0)
    history = page.get_by_role("region", name="历史验证记录", exact=True)
    expect(history).to_contain_text("1 条")
    history.get_by_role("button", name=re.compile(r"已验证")).first.click()
    history.get_by_role("button", name=re.compile(r"已验证")).last.click()
    expect(history).to_contain_text("早期审计已在隔离靶场复现")
    checks.passed("stale conclusions keep old successful verification as history without labeling the current version verified")

    navigate(page, "#findings/ledger-other-project")
    expect(page.get_by_role("heading", name="认证边界缺少权限校验", level=1, exact=True)).to_be_visible()
    expect(page.get_by_role("region", name="漏洞来源", exact=True)).to_contain_text("来源任务不可用")
    before = len(api.source_requests)
    evidence = page.get_by_role("region", name="证据源码", exact=True)
    evidence.get_by_role("button", name=re.compile(r"^src\/auth\.php")).click()
    evidence.get_by_role("button", name=re.compile(r"^查看源码")).click()
    expect(evidence).to_contain_text("来源快照不可用")
    assert len(api.source_requests) == before
    checks.passed("missing historical sources leave the conclusion readable without fetching a different ZIP")


def failure_and_race_flows(page: Page, api: MockAPI, checks: Checks) -> None:
    navigate(page, f"#sources/{EMPTY_PROJECT_ID}")
    source_ready(page, "尚未审计的源码")
    expect(page.get_by_role("heading", name="还没有审计任务", exact=True)).to_be_visible()
    navigate(page, f"#sources/{EMPTY_PROJECT_ID}?tab=findings")
    ledger_ready(page, 0)
    expect(page.get_by_role("heading", name="还没有漏洞发现", exact=True)).to_be_visible()
    checks.passed("unaudited source projects and empty ledgers have actionable empty states")

    # StrictMode makes an initial aborted read before the live request.
    api.read_failures["/project-findings"] = 2
    navigate(page, "#findings")
    expect(page.get_by_role("alert")).to_contain_text("模拟读取暂时失败")
    api.read_failures["/project-findings"] = 0
    page.get_by_role("button", name="重新加载", exact=True).click()
    ledger_ready(page, 31)
    api.read_failures[f"/project-findings/{LEDGER_ID}"] = 2
    navigate(page, f"#findings/{LEDGER_ID}")
    expect(page.get_by_role("alert")).to_contain_text("无法读取漏洞详情")
    api.read_failures[f"/project-findings/{LEDGER_ID}"] = 0
    page.get_by_role("button", name="重新加载", exact=True).click()
    expect(page.get_by_role("heading", name="上传路径可绕过目录边界", level=1, exact=True)).to_be_visible()
    navigate(page, "#findings/no-such-finding")
    expect(page.get_by_role("alert")).to_contain_text("Project finding does not exist")
    navigate(page, "#sources/no-such-project")
    expect(page.get_by_role("alert")).to_contain_text("Project does not exist")
    checks.passed("list/detail reads can retry and unknown source or finding IDs show explicit errors")

    api.held_paths.add(f"/projects/{PROJECT_ID}")
    navigate(page, f"#sources/{PROJECT_ID}")
    expect(page.get_by_role("status")).to_contain_text("正在读取源码包")
    navigate(page, f"#sources/{OTHER_PROJECT_ID}")
    source_ready(page, "另一个认证项目")
    api.release_reads()
    page.wait_for_timeout(100)
    source_ready(page, "另一个认证项目")

    before = api.read_counts.get(f"/projects/{PROJECT_ID}", 0)
    api.held_paths.add(f"/projects/{PROJECT_ID}")
    navigate(page, f"#sources/{PROJECT_ID}")
    expect(page.locator('.sources-empty[role="status"]')).to_contain_text("正在读取源码包")
    page.wait_for_timeout(5500)
    # React StrictMode may start one aborted request and one live request, but the
    # workspace polling tick must not abort/restart the slow live read forever.
    assert api.read_counts.get(f"/projects/{PROJECT_ID}", 0) - before <= 2
    api.release_reads()
    source_ready(page)
    checks.passed("an initial project read slower than the five-second poll completes without starvation")
    api.held_paths.add(f"/project-findings/{LEDGER_ID}")
    navigate(page, f"#findings/{LEDGER_ID}")
    expect(page.get_by_role("status")).to_contain_text("正在读取漏洞详情")
    navigate(page, "#findings/ledger-other-project")
    expect(page.get_by_role("heading", name="认证边界缺少权限校验", level=1, exact=True)).to_be_visible()
    api.release_reads()
    page.wait_for_timeout(100)
    expect(page.get_by_role("heading", name="认证边界缺少权限校验", level=1, exact=True)).to_be_visible()
    checks.passed("late responses cannot replace the currently selected source project or canonical finding")


def refresh_flows(page: Page, api: MockAPI, checks: Checks) -> None:
    """Polling must update data without interrupting a reader's open evidence."""
    navigate(page, f"#findings/{LEDGER_ID}")
    expect(page.get_by_role("heading", name="上传路径可绕过目录边界", level=1, exact=True)).to_be_visible()
    evidence = page.get_by_role("region", name="证据源码", exact=True)
    evidence.get_by_role("button", name=re.compile(r"^src\/upload\.php")).click()
    window = evidence.get_by_role("button", name=re.compile(r"^查看源码")).first
    window.click()
    expect(evidence.locator(".source-row.hit")).to_have_count(3)
    window.focus()
    window.evaluate("node => { window.__ledgerFocusedControl = node; }")
    scroll = page.locator(".ledger-detail-page")
    scroll.evaluate("node => { node.scrollTop = Math.min(650, node.scrollHeight - node.clientHeight); }")
    previous = scroll.evaluate("node => node.scrollTop")
    before = api.read_counts[f"/project-findings/{LEDGER_ID}"]
    api.ledger_records[LEDGER_ID]["title"] = "上传路径可绕过目录边界（已刷新）"
    for _ in range(140):
        if api.read_counts[f"/project-findings/{LEDGER_ID}"] > before:
            break
        page.wait_for_timeout(50)
    expect(page.get_by_role("heading", name="上传路径可绕过目录边界（已刷新）", level=1, exact=True)).to_be_visible()
    expect(window).to_have_attribute("aria-expanded", "true")
    assert page.evaluate("document.activeElement === window.__ledgerFocusedControl")
    assert abs(scroll.evaluate("node => node.scrollTop") - previous) < 3
    api.read_failures[f"/project-findings/{LEDGER_ID}"] = 1
    page.get_by_role("button", name="刷新漏洞详情", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("刷新失败")
    expect(page.get_by_role("heading", name="上传路径可绕过目录边界（已刷新）", level=1, exact=True)).to_be_visible()
    expect(evidence.locator(".source-row.hit")).to_have_count(3)
    page.get_by_role("button", name="重试", exact=True).click()
    expect(page.get_by_role("alert")).to_have_count(0)
    api.ledger_records[LEDGER_ID]["title"] = "上传路径可绕过目录边界"
    checks.passed("detail polling updates its title while preserving open source, keyboard focus and reading position; failed refresh keeps content")

    navigate(page, f"#findings?project={PROJECT_ID}&page=2")
    ledger_ready(page, 30)
    search = page.get_by_role("textbox", name="搜索漏洞", exact=True)
    search.fill("尚未提交的检索")
    search.focus()
    search.evaluate("node => { window.__ledgerFocusedControl = node; }")
    scroll = page.get_by_role("region", name="漏洞台账", exact=True)
    scroll.evaluate("node => { node.scrollTop = 200; }")
    previous = scroll.evaluate("node => node.scrollTop")
    before = api.read_counts["/project-findings"]
    for _ in range(140):
        if api.read_counts["/project-findings"] > before:
            break
        page.wait_for_timeout(50)
    expect(search).to_have_value("尚未提交的检索")
    assert page.evaluate("document.activeElement === window.__ledgerFocusedControl")
    assert abs(scroll.evaluate("node => node.scrollTop") - previous) < 3
    expect(page.locator(".ledger-pagination")).to_contain_text("第 2 / 2 页")
    expect(page.get_by_role("combobox", name="所属源码包", exact=True)).to_have_value(PROJECT_ID)
    api.read_failures["/project-findings"] = 1
    page.get_by_role("button", name="刷新漏洞台账", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("刷新失败")
    expect(page.locator(".ledger-table tbody tr")).to_have_count(5)
    page.get_by_role("button", name="重试", exact=True).click()
    expect(page.get_by_role("alert")).to_have_count(0)
    expect(search).to_have_value("尚未提交的检索")
    checks.passed("list polling preserves page, filters, draft search, focus and scroll; failed refresh retains the existing rows")


def visual_flows(page: Page, checks: Checks, directory: Path | None) -> None:
    screens = (("library", "#sources"), ("workspace", f"#sources/{PROJECT_ID}"),
               ("archives", f"#sources/{PROJECT_ID}?tab=archives"),
               ("new-audit", f"#sources/{PROJECT_ID}/new"), ("findings", "#findings"),
               ("finding-detail", f"#findings/{LEDGER_ID}"))
    for theme in ("dark", "light"):
        page.set_viewport_size({"width": 1440, "height": 900})
        if page.locator("html").get_attribute("data-theme") != theme:
            page.get_by_role("button", name=f"切换{'深' if theme == 'dark' else '浅'}色主题", exact=True).click()
        for label, fragment in screens:
            navigate(page, fragment)
            if label == "library":
                expect(page.locator(".source-card")).to_have_count(3)
            elif label in {"workspace", "archives"}:
                source_ready(page)
            elif label == "new-audit":
                expect(page.get_by_role("combobox", name="选择源码 ZIP", exact=True)).to_be_visible()
            elif label == "findings":
                ledger_ready(page, 31)
            else:
                expect(page.get_by_role("heading", name="上传路径可绕过目录边界", level=1, exact=True)).to_be_visible()
            for width in (1440, 1024, 768, 390):
                page.set_viewport_size({"width": width, "height": 900})
                page.wait_for_timeout(60)
                no_overflow(page, f"{label} {theme} {width}px", checks)
                if label == "new-audit" and width == 390:
                    metrics = page.get_by_role("button", name="开始审计", exact=True).evaluate("""node => {
                      const label = node.querySelector('span');
                      const range = document.createRange(); range.selectNodeContents(label);
                      const text = range.getBoundingClientRect(), box = node.getBoundingClientRect();
                      return {textWidth: text.width, textHeight: text.height, width: box.width,
                        lineHeight: parseFloat(getComputedStyle(label).lineHeight)};
                    }""")
                    assert metrics["width"] >= 80 and metrics["textWidth"] < metrics["width"], metrics
                    assert metrics["textHeight"] <= metrics["lineHeight"] + 2, metrics
                save(page, directory, f"{label}-{theme}-{width}")
            page.set_viewport_size({"width": 1440, "height": 900})
    page.reload(wait_until="domcontentloaded")
    expect(page.locator("html")).to_have_attribute("data-theme", "light")
    checks.passed("source-library, workspace, ZIP browser, audit form, ledger and detail fit four widths in both themes")


def empty_library(page: Page, base: str, checks: Checks) -> None:
    api = MockAPI(snapshot_records={}, project_names={}, ledger_records={}, ledger_verifications={}, runs={}, findings={}, fail_upload=False)
    page.route("**/api/**", api.handle)
    goto(page, base, "#sources")
    expect(page.get_by_role("heading", name="导入第一个源码 ZIP", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="上传源码 ZIP", exact=True)).to_be_enabled()
    assert not api.unexpected
    checks.passed("an empty library starts with ZIP import and never creates an implicit audit")
    api.project_names[PROJECT_ID] = "审计样例源码"
    api.upload_result = snapshot()
    api.upload_project_reused = False
    archive = {"name": "new-source.zip", "mimeType": "application/zip", "buffer": b"PK\x03\x04ui-fixture"}
    page.get_by_label("上传项目源码 ZIP", exact=True).set_input_files(archive)
    source_ready(page)
    expect(page.get_by_role("status")).to_contain_text("已创建源码项目")
    assert api.create_count == 0 and api.upload_count == 1
    navigate(page, "#sources")
    expect(page.locator(".source-card")).to_have_count(1)
    repacked = snapshot()
    repacked.update(id="smoke-new-repacked", name="新压缩方式.zip", archive_sha256="0" * 64,
                    created_at="2026-10-20T12:30:00+00:00")
    api.upload_result, api.upload_project_reused = repacked, True
    page.get_by_label("上传项目源码 ZIP", exact=True).set_input_files(archive)
    source_ready(page)
    expect(page.get_by_role("status")).to_contain_text("已归入相同源码的已有项目")
    expect(page.get_by_role("status")).to_contain_text("ZIP 已导入")
    expect(page.locator(".sources-head")).to_contain_text("2 个 ZIP 快照")
    navigate(page, "#sources")
    expect(page.locator(".source-card")).to_have_count(1)
    assert api.create_count == 0 and api.upload_count == 2
    checks.passed("new-source and re-zipped uploads explain project creation/reuse while retaining one source project")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("frontend_url")
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    api, checks = sources_api(), Checks()
    errors: list[dict[str, str]] = []
    failed = False
    with sync_playwright() as pw:
        chrome = os.environ.get("CHROME_BIN")
        browser = pw.chromium.launch(**({"executable_path": chrome} if chrome else {}))
        page = browser.new_page(viewport={"width": 1440, "height": 900}, locale="zh-CN", timezone_id="Asia/Shanghai")
        page.set_default_timeout(10000)
        page.route("**/api/**", api.handle)
        page.on("console", lambda message: errors.append({"kind": "console", "text": message.text, "url": message.location.get("url", "")}) if message.type == "error" else None)
        page.on("pageerror", lambda error: errors.append({"kind": "pageerror", "text": str(error), "url": ""}))
        try:
            base = args.frontend_url.rstrip("/")
            source_flows(page, base, api, checks)
            ledger_flows(page, api, checks)
            detail_flows(page, api, checks)
            failure_and_race_flows(page, api, checks)
            refresh_flows(page, api, checks)
            visual_flows(page, checks, args.screenshots)
            other = browser.new_page(viewport={"width": 390, "height": 844}, locale="zh-CN")
            empty_library(other, base, checks)
            no_overflow(other, "empty library mobile", checks)
            other.close()
        except Exception:
            failed = True
            traceback.print_exc()
            save(page, args.screenshots, "failure")
        hard = [item for item in errors if not (item["kind"] == "console" and "Failed to load resource" in item["text"] and item["url"] in api.expected_failures)]
        for item in hard:
            print(f"  ERROR {item['kind']}: {item['text']} {item['url']}")
        if api.unexpected:
            print("Unhandled mocked routes:", api.unexpected)
        failed = failed or bool(hard or api.unexpected)
        browser.close()
    print(f"\n{'FAIL' if failed else 'PASS'}: {checks.count} source-centered browser checks; mock API only")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
