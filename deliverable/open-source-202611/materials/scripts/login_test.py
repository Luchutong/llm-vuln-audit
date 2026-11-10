#!/usr/bin/env python3
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True, args=["--no-proxy-server"])
    context = browser.new_context(viewport={"width": 1920, "height": 1080})
    page = context.new_page()
    page.goto("http://127.0.0.1:18880/auth/login.php", wait_until="networkidle")
    page.fill("input[name='username']", "alice")
    page.fill("input[name='password']", "Alice123!")
    page.click("form button")
    page.wait_for_load_state("networkidle")
    print("after login url:", page.url)
    print("title:", page.title())
    # check auth evidence: top-right area text and any logout link
    body = page.inner_text("body")
    for kw in ["退出", "注销", "alice", "登录", "我的"]:
        print(f"contains {kw!r}: {kw in body}")
    links = page.eval_on_selector_all("a", "els => els.map(e => ({text:e.innerText.trim(), href:e.getAttribute('href')}))")
    print("top links:")
    for l in links[:18]:
        if l["text"]:
            print("  ", l["text"][:16], "->", l["href"])
    # navigate to wallet (vulnerable feature page)
    page.goto("http://127.0.0.1:18880/wallet/index.php", wait_until="networkidle")
    print("\nWALLET url:", page.url)
    print("WALLET title:", page.title())
    print("wallet body head:", page.inner_text("body")[:300].replace("\n", " | "))
    browser.close()
