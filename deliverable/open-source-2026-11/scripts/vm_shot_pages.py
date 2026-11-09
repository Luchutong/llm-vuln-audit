#!/usr/bin/env python3
"""Capture report figures for pages whose data would otherwise need a paid model call.

The VULN-AUDIT repo ships offline UI fixtures (``scripts/ui_fixtures.py``) that answer
every ``/api`` request from memory. Reusing them lets us photograph the *real* rendered
pages -- run detail, finding ledger, model profiles, prompt-comparison experiment --
without spending tokens or inventing new audit results.

These figures illustrate UI structure only. They must be captioned as offline-fixture
captures and must never be cited as measured audit output.

Usage:
    python scripts/vm_shot_pages.py all
    python scripts/vm_shot_pages.py run report findings
"""
from __future__ import annotations

import pathlib
import re
import sys
from urllib.parse import parse_qs, urlsplit

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from playwright.sync_api import sync_playwright  # noqa: E402

import ui_prompt_comparison_v2_smoke as v2  # noqa: E402  (offline experiment fixture)
from ui_fixtures import (  # noqa: E402
    ACTIVITY_ID,
    COMPLETED_ID,
    PROJECT_ID,
    activity_events,
    finding,
    run,
    sources_api,
)

BASE = "http://192.168.239.128:5173"
DATE = "2026-11-07"
SHOTS = ROOT / "deliverable/open-source-2026-11/screens"
MOCK_DIR = SHOTS / "offline-fixture"
EXPERIMENT = v2.full_record()


def apply_archived_metrics() -> None:
    """Replace the fixture's placeholder scores with the frozen 10-26 archive numbers.

    The figure is rendered by the real page, but the numbers must match the tables in
    the report (W0 77.5% / W1 73.5% / W2 67.3% F1, n=3). Keeping the fixture values
    would put a conflicting chart next to the measured table.
    """
    import json

    archive = ROOT / "deliverable/lab30-validation-2026-10-26/03-prompt-comparison/summary.json"
    if not archive.exists():
        print("archive summary missing; keeping fixture scores")
        return
    data = json.loads(archive.read_text(encoding="utf-8"))
    real = {row["id"].split("-v")[0]: row for row in data["variants"]}
    for variant in EXPERIMENT["summary"]["variants"]:
        source = real.get(variant["id"].split("-v")[0])
        if not source:
            continue
        for key, metric in variant["metrics"].items():
            archived = source["metrics"].get(key)
            if not archived:
                continue
            metric["mean"] = archived["mean"]
            metric["sample_std"] = archived.get("sample_std")
            metric["n"] = archived.get("n", 3)

    # Paired deltas must follow the same rebuild: take the frozen per-round paired
    # differences instead of the fixture's placeholder +/-10 个百分点.
    for variant in EXPERIMENT["summary"]["variants"]:
        source = real.get(variant["id"].split("-v")[0])
        if not source:
            continue
        for key, field in (("f1", "paired_f1"), ("recall", "paired_recall")):
            if source.get(field) and key in variant["paired_deltas"]:
                variant["paired_deltas"][key] = source[field]


apply_archived_metrics()
PROMPTS = [
    {**variant, "builtin": True, "issues": [], "created_at": EXPERIMENT["created_at"],
     "used_by_runs": 0, "used_by_experiments": 1}
    for variant in EXPERIMENT["manifest"]["variants"]
]


def experiment_api(api):
    """Serve the prompt-comparison fixture; fall through to the standard fixture."""

    def handle(route) -> None:
        request = route.request
        path = urlsplit(request.url).path.removeprefix("/api")
        query = parse_qs(urlsplit(request.url).query)
        if path == "/prompt-experiments":
            summary = {key: EXPERIMENT[key] for key in
                       ("id", "protocol", "status", "created_at", "finished_at", "error", "manifest", "summary")}
            summary["summary"] = dict(EXPERIMENT["summary"])
            api.json(route, [summary])
        elif path == f"/prompt-experiments/{EXPERIMENT['id']}":
            api.json(route, EXPERIMENT)
        elif path == "/prompts" and request.method == "GET":
            api.json(route, PROMPTS)
        else:
            api.handle(route)

    return handle


def save(page, name: str, full: bool = True) -> None:
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    target = MOCK_DIR / f"{name}_{DATE}.png"
    page.screenshot(path=str(target), full_page=full, animations="disabled")
    print(f"saved {target.name} ({target.stat().st_size // 1024} KB)")


def settle(page, ms: int = 2500) -> None:
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(ms)


def goto(page, hash_path: str, ms: int = 2500) -> None:
    # A hash-only change does not reload the SPA, so reset to the index first; this
    # also dismisses any drawer left open by the previous capture.
    page.goto(f"{BASE}/#sources", wait_until="domcontentloaded")
    page.wait_for_timeout(300)
    page.goto(f"{BASE}/{hash_path}", wait_until="domcontentloaded")
    settle(page, ms)


def expand_process(page) -> None:
    """Open the collapsed routine-operation groups so tool calls are visible."""
    collapsed = page.locator('.activity-process-group > button[aria-expanded="false"]')
    while collapsed.count():
        collapsed.first.click()
        page.wait_for_timeout(120)


def prepare_active_run(api) -> None:
    """A running audit with planner rounds, parallel workers and a retried tool call."""
    api.runs[ACTIVITY_ID] = run(ACTIVITY_ID, "running")
    api.findings[ACTIVITY_ID] = finding(ACTIVITY_ID)
    api.detail_overrides[ACTIVITY_ID] = {
        "findings": [], "source_observations": [],
        "execution_summary": {"phase": "task_execute", "poc": {"mode": "off"},
                              "run_usage": {"seconds": 742}},
    }
    api.event_overrides[ACTIVITY_ID] = activity_events()[:14]
    api.detail_overrides[COMPLETED_ID] = {
        **api.detail_overrides.get(COMPLETED_ID, {}),
        "execution_summary": {"phase": "settled", "poc": {"mode": "auto"},
                              "run_usage": {"seconds": 2381}},
    }


def task_running(page) -> None:
    """Running audit: planner round, parallel workers, tool calls and budget meters."""
    goto(page, f"#run/{ACTIVITY_ID}", 3500)
    expand_process(page)
    page.wait_for_timeout(600)
    save(page, "S-B04a_3.6_执行详情_运行中")


def task_detail_map(page) -> None:
    """Audit-detail drawer, 项目与任务图 tab: planner rounds and the task graph."""
    goto(page, f"#run/{COMPLETED_ID}", 3000)
    page.get_by_role("button", name="审计详情", exact=True).click()
    dialog = page.get_by_role("dialog", name="审计详情", exact=True)
    dialog.wait_for(state="visible")
    dialog.get_by_role("tab", name="项目与任务图", exact=True).click()
    page.wait_for_timeout(1200)
    save(page, "S-B04c_3.6_任务图与覆盖", full=False)


def task_detail_findings(page) -> None:
    """Audit-detail drawer, 发现与验证 tab: type, severity and verification state."""
    goto(page, f"#run/{COMPLETED_ID}", 3000)
    page.get_by_role("button", name="审计详情", exact=True).click()
    dialog = page.get_by_role("dialog", name="审计详情", exact=True)
    dialog.wait_for(state="visible")
    dialog.get_by_role("tab", name="发现与验证", exact=True).click()
    page.wait_for_timeout(1200)
    save(page, "S-B05c_3.6_发现与验证", full=False)


def task_report_view(page) -> None:
    """Audit-detail drawer, 执行日志 tab: the durable event trace behind every claim."""
    page.set_viewport_size({"width": 1440, "height": 1600})
    goto(page, f"#run/{COMPLETED_ID}", 3000)
    page.get_by_role("button", name="审计详情", exact=True).first.click()
    dialog = page.get_by_role("dialog", name="审计详情", exact=True)
    dialog.wait_for(state="visible")
    dialog.get_by_role("tab", name="执行日志", exact=True).click()
    page.wait_for_timeout(1500)
    collapsed = dialog.locator('button[aria-expanded="false"], summary')
    for index in range(min(collapsed.count(), 6)):
        try:
            collapsed.nth(0).click()
            page.wait_for_timeout(400)
        except Exception:  # noqa: BLE001
            break
    collapsed = dialog.locator('button[aria-expanded="false"], summary')
    for index in range(min(collapsed.count(), 6)):
        try:
            collapsed.nth(0).click()
            page.wait_for_timeout(400)
        except Exception:  # noqa: BLE001
            break
    page.wait_for_timeout(800)
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    target = MOCK_DIR / f"S-B15_3.6_执行日志_{DATE}.png"
    dialog.screenshot(path=str(target), animations="disabled")
    print(f"saved {target.name} ({target.stat().st_size // 1024} KB)")
    page.set_viewport_size({"width": 1440, "height": 1000})


def task_archive(page) -> None:
    """The frozen 10-30 closure report rendered from the archived HTML artifact."""
    report = ROOT / "deliverable/lab30-closure-2026-10-30/index.html"
    page.set_viewport_size({"width": 1280, "height": 1400})
    page.goto(report.as_uri(), wait_until="load")
    page.wait_for_timeout(1500)
    save(page, "S-B16_7.3_归档审计报告页")
    page.set_viewport_size({"width": 1440, "height": 1000})


def task_evidence(page) -> None:
    """Finding evidence chain: open the source trace behind one candidate."""
    page.set_viewport_size({"width": 1440, "height": 1600})
    goto(page, f"#run/{COMPLETED_ID}", 3000)
    page.get_by_role("button", name="审计详情", exact=True).first.click()
    dialog = page.get_by_role("dialog", name="审计详情", exact=True)
    dialog.wait_for(state="visible")
    dialog.get_by_role("tab", name="发现与验证", exact=True).click()
    page.wait_for_timeout(1500)
    body = dialog.locator(".drawer-body")
    body.evaluate("node => { node.scrollTop = node.scrollHeight * 0.42; }")
    page.wait_for_timeout(1200)
    try:
        dialog.get_by_role("button", name=re.compile("处引用")).first.click()
        page.wait_for_timeout(1200)
        dialog.get_by_role("button", name=re.compile("查看源码")).first.click()
        page.wait_for_timeout(2200)
        body.evaluate("node => { node.scrollTop = node.scrollHeight * 0.40; }")
        page.wait_for_timeout(1200)
    except Exception as exc:  # noqa: BLE001
        print(f"source window not opened: {exc}")
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    target = MOCK_DIR / f"S-B09_6_漏洞证据链_{DATE}.png"
    dialog.screenshot(path=str(target), animations="disabled")
    print(f"saved {target.name} ({target.stat().st_size // 1024} KB)")
    page.set_viewport_size({"width": 1440, "height": 1000})


def task_run(page) -> None:
    """Completed run: conversation, coverage, budget, findings cards."""
    goto(page, f"#run/{COMPLETED_ID}", 3000)
    expand_process(page)
    page.wait_for_timeout(600)
    save(page, "S-B04b_3.6_执行详情_完成态")


def task_report(page) -> None:
    """Audit-detail drawer -> 结果报告 tab with the three download entries."""
    page.set_viewport_size({"width": 1440, "height": 1900})
    goto(page, f"#run/{COMPLETED_ID}", 3000)
    page.get_by_role("button", name="审计详情", exact=True).click()
    dialog = page.get_by_role("dialog", name="审计详情", exact=True)
    dialog.wait_for(state="visible")
    dialog.get_by_role("tab", name="结果报告", exact=True).click()
    page.wait_for_timeout(1500)
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    target = MOCK_DIR / f"S-B07_3.6_报告下载_{DATE}.png"
    dialog.screenshot(path=str(target), animations="disabled")
    print(f"saved {target.name} ({target.stat().st_size // 1024} KB)")
    page.set_viewport_size({"width": 1440, "height": 1000})


def task_findings(page) -> None:
    """Cross-project finding ledger: type, severity, verification state."""
    goto(page, "#findings", 3000)
    save(page, "S-B05_3.6_漏洞发现台账")


def task_project(page) -> None:
    """Project page tabs: findings ledger and snapshot archive."""
    goto(page, f"#sources/{PROJECT_ID}?tab=findings", 2500)
    save(page, "S-B05b_3.6_项目漏洞台账")
    goto(page, f"#sources/{PROJECT_ID}?tab=archives", 2500)
    save(page, "S-B02b_3.6_快照归档")


def task_settings(page) -> None:
    """Workspace settings: model profiles with masked base URL."""
    goto(page, "#settings", 3000)
    save(page, "S-B06_3.6_模型档案")


def task_prompts(page) -> None:
    """Prompt library: builtin and derived worker strategies."""
    goto(page, "#prompts", 3000)
    save(page, "S-B12_3.6_提示词库")


def task_experiments(page) -> None:
    """Prompt comparison: 3 strategies x 3 rounds, P/R/F1 side by side."""
    goto(page, "#experiments", 3000)
    save(page, "S-B08_5.4.3_Prompt实验列表")
    goto(page, f"#experiments/{EXPERIMENT['id']}", 3500)
    save(page, "S-B08b_5.4.3_Prompt实验三策略对比")


TASKS = {
    "running": task_running,
    "run": task_run,
    "verify": task_detail_findings,
    "evidence": task_evidence,
    "report": task_report,
    "reportview": task_report_view,
    "findings": task_findings,
    "project": task_project,
    "settings": task_settings,
    "prompts": task_prompts,
    "experiments": task_experiments,
    "archive": task_archive,
}


def main() -> int:
    names = sys.argv[1:] or ["all"]
    if names == ["all"]:
        names = list(TASKS)
    unknown = [name for name in names if name not in TASKS]
    if unknown:
        print(f"unknown tasks: {unknown}; choose from {list(TASKS)}")
        return 2

    api = sources_api()
    prepare_active_run(api)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        context = browser.new_context(
            viewport={"width": 1440, "height": 1000},
            device_scale_factor=2,
            locale="zh-CN",
        )
        context.add_init_script("try{localStorage.setItem('audit-theme','light');}catch(e){}")
        page = context.new_page()
        page.set_default_timeout(15000)
        page.route("**/api/**", experiment_api(api))
        try:
            for name in names:
                print(f"== {name}")
                TASKS[name](page)
        finally:
            context.close()
            browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
