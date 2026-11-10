#!/usr/bin/env python3
from playwright.sync_api import sync_playwright

out = r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\shots\pmf_setup_raw.png"
with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True, args=["--no-proxy-server"])
    page = browser.new_page(viewport={"width": 1920, "height": 1080})
    r = page.goto("http://127.0.0.1:18090/setup/", wait_until="networkidle", timeout=20000)
    print("status:", r.status, "title:", page.title())
    page.screenshot(path=out)
    browser.close()
print("saved", out)
