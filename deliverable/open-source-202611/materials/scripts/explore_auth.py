#!/usr/bin/env python3
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True, args=["--no-proxy-server"])
    page = browser.new_page(viewport={"width": 1920, "height": 1080})
    # find login link from homepage
    page.goto("http://127.0.0.1:18880", wait_until="networkidle")
    links = page.eval_on_selector_all("a", "els => els.map(e => ({text: e.innerText.trim(), href: e.getAttribute('href')}))")
    print("HOMEPAGE LINKS:")
    for l in links:
        if l["text"]:
            print("  ", l["text"][:20], "->", l["href"])
    # go to login
    page.goto("http://127.0.0.1:18880/auth/login.php", wait_until="networkidle")
    print("\nLOGIN URL:", page.url)
    inputs = page.eval_on_selector_all("input", "els => els.map(e => ({name:e.name, type:e.type, id:e.id, placeholder:e.placeholder}))")
    print("INPUTS:", inputs)
    forms = page.eval_on_selector_all("form", "els => els.map(e => ({action:e.action, method:e.method}))")
    print("FORMS:", forms)
    browser.close()
