#!/usr/bin/env python3
"""Drive the VULN-AUDIT web app on the lab VM and capture report screenshots.

Uses the locally installed Chrome via Playwright (no browser download). All pages
are forced to the light theme so the report figures stay consistent.

Examples:
    python scripts/vm_shot.py sb01
    python scripts/vm_shot.py sb02 --project 30fa6828cd3a417781e80da9e79d985c
    python scripts/vm_shot.py url --path "#findings" --out scratch.png
"""
from __future__ import annotations

import argparse
import pathlib
import sys

from playwright.sync_api import sync_playwright

BASE = "http://192.168.239.128:5173"
ROOT = pathlib.Path(__file__).resolve().parents[1]
SHOTS = ROOT / "deliverable/open-source-2026-11/screens"
DATE = "2026-11-07"


def launch(playwright):
    browser = playwright.chromium.launch(channel="chrome", headless=True)
    context = browser.new_context(
        viewport={"width": 1440, "height": 900},
        device_scale_factor=2,
        locale="zh-CN",
    )
    context.add_init_script("try{localStorage.setItem('audit-theme','light');}catch(e){}")
    return browser, context


def settle(page, ms: int = 2500) -> None:
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(ms)


def save(page, name: str, full: bool = True) -> pathlib.Path:
    SHOTS.mkdir(parents=True, exist_ok=True)
    target = SHOTS / name
    page.screenshot(path=str(target), full_page=full)
    print(f"saved {target.name} ({target.stat().st_size // 1024} KB)")
    return target


def task_sb01(page) -> None:
    """Architecture figure: render docs/architecture.svg at 2x and capture it."""
    SHOTS.mkdir(parents=True, exist_ok=True)
    svg = (ROOT / "docs/architecture.svg").as_uri()
    page.set_viewport_size({"width": 1500, "height": 1000})
    page.goto(svg)
    page.wait_for_timeout(800)
    target = SHOTS / f"S-B01_3.1_总体架构_{DATE}.png"
    page.screenshot(path=str(target), full_page=True)
    print(f"saved {target.name} ({target.stat().st_size // 1024} KB)")


def task_sb02(page, project: str | None) -> None:
    tab = sys.argv[sys.argv.index("--tab") + 1] if "--tab" in sys.argv else "archives"
    page.goto(f"{BASE}/#sources/{project}?tab={tab}")
    settle(page, 3000)
    save(page, f"S-B02_3.6_源码包库快照_{DATE}.png")


def task_sb03(page, project: str | None) -> None:
    page.goto(f"{BASE}/#sources/{project}/new")
    settle(page, 2000)
    # 用"快捷填充"写入审计目标，使表单具备真实内容
    try:
        page.get_by_text("追踪危险数据流", exact=False).first.click()
        page.wait_for_timeout(800)
    except Exception as exc:  # noqa: BLE001
        print(f"quick-fill skipped: {exc}")
    page.set_viewport_size({"width": 1440, "height": 1750})
    page.wait_for_timeout(800)
    save(page, f"S-B03_3.6_项目工作台_{DATE}.png")


def task_url(page, path: str, out: str) -> None:
    page.goto(f"{BASE}/{path}" if path.startswith("#") else path)
    settle(page, 2500)
    save(page, out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("task")
    parser.add_argument("--project", default="30fa6828cd3a417781e80da9e79d985c")
    parser.add_argument("--path", default="#sources")
    parser.add_argument("--out", default="scratch.png")
    args = parser.parse_args()

    with sync_playwright() as playwright:
        browser, context = launch(playwright)
        page = context.new_page()
        try:
            if args.task == "sb01":
                task_sb01(page)
            elif args.task == "sb02":
                task_sb02(page, args.project)
            elif args.task == "sb03":
                task_sb03(page, args.project)
            elif args.task == "url":
                task_url(page, args.path, args.out)
            else:
                print(f"unknown task {args.task}")
                return 2
        finally:
            context.close()
            browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
