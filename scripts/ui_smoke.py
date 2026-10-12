#!/usr/bin/env python3
"""Load every tab against a live run and report what the console said.

Type-checking proves the components compile; it does not prove they survive the payload the
API actually sends. This walks the four tabs with real data and fails on any console error
or on an element that never appeared — the earlier TaskView crash (`file_count` read off a
list DTO) only showed up here.

Usage: ui_smoke.py <frontend-url> [run-id]
"""
import os
import sys

from playwright.sync_api import sync_playwright

CHROME = os.environ.get("CHROME_BIN")
base = sys.argv[1].rstrip("/")
run_id = sys.argv[2] if len(sys.argv) > 2 else None

TABS = ["概览", "审计过程", "发现与验证", "实验报告", "Prompt 与实验", "配置"]


def main() -> int:
    problems: list[str] = []
    with sync_playwright() as pw:
        options = {"executable_path": CHROME} if CHROME else {}
        browser = pw.chromium.launch(**options)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        errors: list[str] = []
        page.on("console", lambda msg: errors.append(f"{msg.type}: {msg.text}") if msg.type == "error" else None)
        page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))

        page.goto(base, wait_until="networkidle")
        page.wait_for_timeout(1500)

        if run_id:
            # The four run tabs live inside RunView, reached by opening a run rather than
            # from the sidebar. The run is route state (`#run/<id>`), so deep-link it.
            page.goto(f"{base}/#run/{run_id}", wait_until="networkidle")
            page.wait_for_timeout(2500)
            heading = page.inner_text("body")[:120].replace("\n", " ")
            print("run view:", heading)

        for tab in TABS:
            errors.clear()
            try:
                page.get_by_role("button", name=tab).first.click(timeout=5000)
            except Exception as exc:
                problems.append(f"tab {tab!r} not clickable: {exc}")
                continue
            page.wait_for_timeout(1800)
            body = page.inner_text("body")
            hard = [e for e in errors if "favicon" not in e]
            print(f"{tab:<14} body={len(body):>6} chars  errors={len(hard)}")
            for item in hard[:6]:
                print("    ", item[:220])
            if hard:
                problems.append(f"tab {tab!r}: {hard[0][:200]}")
            if len(body) < 200:
                problems.append(f"tab {tab!r} rendered almost nothing ({len(body)} chars)")

        browser.close()

    if problems:
        print("\nPROBLEMS:")
        for item in problems:
            print(" -", item)
        return 1
    print("\nall tabs rendered without console errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
