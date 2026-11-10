#!/usr/bin/env python3
import sys
sys.path.insert(0, r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import")
import io
from playwright.sync_api import sync_playwright
from PIL import Image
from render_lib import chrome_frame

out = r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\shots\frame_test.png"
with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True, args=["--no-proxy-server"])
    page = browser.new_page(viewport={"width": 1920, "height": 1080})
    page.goto("http://127.0.0.1:18880", wait_until="networkidle")
    page_img = Image.open(io.BytesIO(page.screenshot()))
    browser.close()

framed = chrome_frame(page_img, "127.0.0.1:18880", "让每一份日常，都值得期待 · 拾光商城")
framed.save(out)
print("saved", out, framed.size)
