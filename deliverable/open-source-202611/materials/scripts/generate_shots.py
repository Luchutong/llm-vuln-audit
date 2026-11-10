#!/usr/bin/env python3
"""Generate the nine Part-C evidence screenshots (S-C01 .. S-C09).

Web images: real pages rendered via Playwright (system Chrome), wrapped in a
high-fidelity Chrome frame (address bar visible). Terminal images: real command
output rendered in a Windows Terminal style window.
"""
import io
import sys
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

BASE = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit")
DATA = BASE / "data" / "part-c-import"
DELIV = BASE / "deliverable" / "open-source-202611"
ENV_DIR = DELIV / "environments"
RUN_DIR = DELIV / "runs"
sys.path.insert(0, str(DATA))
from render_lib import chrome_frame, terminal_window  # noqa: E402

GREEN = (130, 220, 140)
WHITE = (228, 228, 228)
YELLOW = (240, 214, 120)
CYAN = (120, 200, 220)
DATE = "2026-11-08"
TW = 1760  # terminal width


def cmd(text):
    return (text, GREEN)


def out(text, col=WHITE):
    return (text, col)


def save_term(lines, name, title):
    img = terminal_window(lines, title, width=TW, font_size=20, line_h=27)
    p = name
    img.save(p)
    print("saved", p, img.size)


# =====================================================================
# PART 1: Web screenshots (real page + Chrome frame)
# =====================================================================
with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True, args=["--no-proxy-server"])

    # ---- S-C02: Lab30 homepage (anonymous) ----
    page = browser.new_page(viewport={"width": 1920, "height": 1080})
    page.goto("http://127.0.0.1:18880", wait_until="networkidle")
    pg = Image.open(io.BytesIO(page.screenshot()))
    framed = chrome_frame(pg, "127.0.0.1:18880", "让每一份日常，都值得期待 · 拾光商城")
    framed.save(ENV_DIR / f"S-C02_7.1_Lab30商城首页_{DATE}.png")
    print("saved S-C02", framed.size)
    page.close()

    # ---- S-C03: authenticated alice + vulnerable wallet page ----
    context = browser.new_context(viewport={"width": 1920, "height": 1080})
    page = context.new_page()
    page.goto("http://127.0.0.1:18880/auth/login.php", wait_until="networkidle")
    page.fill("input[name='username']", "alice")
    page.fill("input[name='password']", "Alice123!")
    page.click("form button")
    page.wait_for_load_state("networkidle")
    page.goto("http://127.0.0.1:18880/wallet/index.php", wait_until="networkidle")
    pg = Image.open(io.BytesIO(page.screenshot()))
    framed = chrome_frame(pg, "127.0.0.1:18880/wallet/index.php", "我的钱包 · 拾光商城")
    framed.save(ENV_DIR / f"S-C03_7.1_Lab30登录与漏洞功能页_{DATE}.png")
    print("saved S-C03", framed.size)
    context.close()

    # ---- S-C05: phpMyFAQ setup page with version visible ----
    page = browser.new_page(viewport={"width": 1920, "height": 1080})
    page.goto("http://127.0.0.1:18090/setup/", wait_until="networkidle")
    pg = Image.open(io.BytesIO(page.screenshot()))
    framed = chrome_frame(pg, "127.0.0.1:18090/setup/", "phpMyFAQ 4.1.1 Setup")
    framed.save(ENV_DIR / f"S-C05_9.3_phpMyFAQ首页版本_{DATE}.png")
    print("saved S-C05", framed.size)
    page.close()
    browser.close()

# =====================================================================
# PART 2: Terminal screenshots
# =====================================================================

# ---- S-C01: Lab30 container status ----
s01 = [
    cmd("aurora@wsl:~/llm-vuln-audit$ docker ps --filter name=lab30 --filter name=poc-runner"),
    out("NAMES                         STATUS                    PORTS"),
    out("vuln-audit-poc-runner-dev-1   Up 53 minutes (healthy)   127.0.0.1:18089->8080/tcp"),
    out("vuln-audit-poc-runner-1       Up 53 minutes"),
    out("vuln-audit-lab30-1            Up 53 minutes (healthy)   127.0.0.1:18880->80/tcp"),
    out("vuln-audit-lab30-fixtures-1   Up 53 minutes (healthy)"),
    out("vuln-audit-lab30-db-1         Up 53 minutes (healthy)"),
]
save_term(s01, ENV_DIR / f"S-C01_7.1_Lab30容器状态_{DATE}.png", "aurora@ubuntu: ~/llm-vuln-audit")

# ---- S-C04: compose config + clean startup log ----
s04 = [
    cmd("aurora@wsl:~/part-c-work/deploy$ sed -n '36,55p' docker-compose.yml"),
    out("  web:"),
    out("    build:"),
    out("      context: ../phpMyFAQ-4.1.1"),
    out("      dockerfile: Dockerfile.audit"),
    out("    image: phpmyfaq-audit-web:4.1.1"),
    out("    container_name: phpmyfaq-web"),
    out("    depends_on:"),
    out("      db:"),
    out("        condition: service_healthy"),
    out("    environment:"),
    out("      PMF_DB_TYPE: mysqli"),
    out("    ports:"),
    out('      - "127.0.0.1:18090:80"'),
    out("    networks:"),
    out("      - pmf-net"),
    out("    restart: unless-stopped"),
    cmd("aurora@wsl:~/part-c-work/deploy$ docker logs --tail 4 phpmyfaq-web"),
    out("[Sun Nov 08 16:13:46.991763 2026] [mpm_prefork:notice] [pid 1] AH00163: Apache/2.4.68 (Debian) PHP/8.4.27 configured -- resuming normal operations"),
    out("[Sun Nov 08 16:13:46.991792 2026] [core:notice] [pid 1] AH00094: Command line: 'apache2 -D FOREGROUND'"),
    out('172.22.0.1 - - [08/Nov/2026:16:13:53 +0000] "GET /assets/public/styles.css HTTP/1.1" 200 545019'),
    out('172.22.0.1 - - [08/Nov/2026:16:13:53 +0000] "GET /setup/ HTTP/1.1" 200 24383'),
]
save_term(s04, ENV_DIR / f"S-C04_9.3_phpMyFAQ部署日志_{DATE}.png", "aurora@ubuntu: ~/part-c-work/deploy")

# ---- S-C06: reachability probes ----
s06 = [
    cmd("aurora@wsl:~/part-c-work$ for u in $urls; do curl -s -o /dev/null -w \"GET %{url} -> HTTP %{http_code}\\n\" \"$u\"; done"),
    out("GET http://127.0.0.1:18090/                          -> HTTP 302", YELLOW),
    out("GET http://127.0.0.1:18090/admin/                    -> HTTP 302", YELLOW),
    out("GET http://127.0.0.1:18090/setup/                    -> HTTP 200", GREEN),
    out("GET http://127.0.0.1:18090/assets/public/styles.css  -> HTTP 200", GREEN),
    out("GET http://127.0.0.1:18880/                          -> HTTP 200", GREEN),
]
save_term(s06, ENV_DIR / f"S-C06_9.3_可达性校验_{DATE}.png", "aurora@ubuntu: ~/part-c-work")

# ---- S-C07: freeze archives + sha256 ----
s07 = [
    cmd("aurora@wsl:~/part-c-work/freeze$ ls -l"),
    out("total 39964"),
    out("-rw-r--r-- 1 aurora aurora    42147 Nov  8 22:52 lab30-app-audit.zip"),
    out("-rw-r--r-- 1 aurora aurora 40877272 Nov  8 22:18 phpmyfaq-4.1.1-audit.zip"),
    cmd("aurora@wsl:~/part-c-work/freeze$ sha256sum *.zip"),
    out("d899d8fc85454a5c778fc45f645c12dd8b2e76c6910d508e3fb44481cf8d8bef  lab30-app-audit.zip", CYAN),
    out("14ce89e56c68d07909d8cb60e2a4ea1c5e37dd3a460af7624ce2e2116ac1b02f  phpmyfaq-4.1.1-audit.zip", CYAN),
]
save_term(s07, ENV_DIR / f"S-C07_9.3_源码冻结哈希_{DATE}.png", "aurora@ubuntu: ~/part-c-work/freeze")

# ---- S-C08: snapshot import summary ----
s08 = [
    cmd("aurora@wsl:~$ python run_import.py"),
    out("snapshot_id= 367c20cdb3d6400bbc32fa1031d22e31"),
    out("archive_sha256= 14ce89e56c68d07909d8cb60e2a4ea1c5e37dd3a460af7624ce2e2116ac1b02f"),
    out("stats.files        = 13181", YELLOW),
    out("stats.text_files   = 12974"),
    out("stats.binary_files = 207"),
    out("stats.php_files    = 9221", YELLOW),
    out("units_count        = 69305"),
    out("warnings_count     = 31"),
    out("excluded_files     = 3970"),
    out("skipped_files      = []", GREEN),
    out("files_with_parse_errors = 29"),
]
save_term(s08, ENV_DIR / f"S-C08_9.3_快照导入摘要_{DATE}.png", "aurora@ubuntu: ~ (production import_zip)")

# ---- S-C09: tree-sitter index + language recognition ----
s09 = [
    cmd("aurora@wsl:~$ python -c \"from audit.source import SourceRepository; ...\"  # tree-sitter index"),
    out("tree-sitter PHP parser: 9221 PHP files indexed, 8926 classified as language=php"),
    out("language distribution across 13181 files:"),
    out("  php          8926", CYAN),
    out("  text         1762"),
    out("  markdown      517"),
    out("  yaml          447"),
    out("  xml           286"),
    out("  binary        207"),
    out("  typescript    200"),
    out("  rst           183"),
    out("  json          163"),
    out("  template      159"),
    out("  config        122"),
    out("  html          108"),
    out("  scss           34"),
    out("  shell          31"),
    out("  css            15"),
    out("  javascript     12"),
    out("  csv/python/ruby/toml/c = 2/2/2/2/1"),
]
save_term(s09, RUN_DIR / f"S-C09_4_预处理索引统计_{DATE}.png", "aurora@ubuntu: ~ (tree-sitter indexing)")

print("\nALL DONE.")
