#!/usr/bin/env python3
from playwright.sync_api import sync_playwright

out = r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\shots\pw_test.png"
with sync_playwright() as p:
    try:
        browser = p.chromium.launch(channel="chrome", headless=True,
                                    args=["--no-proxy-server"])
        print("launched system chrome")
    except Exception as e:
        print("channel chrome failed:", e)
        browser = p.chromium.launch(headless=True)
        print("launched bundled chromium")
    page = browser.new_page(viewport={"width": 1920, "height": 1080})
    resp = page.goto("http://127.0.0.1:18880", wait_until="networkidle", timeout=15000)
    print("status:", resp.status if resp else None)
    print("title:", page.title())
    page.screenshot(path=out, full_page=False)
    browser.close()
print("saved", out)
