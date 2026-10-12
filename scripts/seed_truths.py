#!/usr/bin/env python3
"""Record the ground truth for the six DVWA demo samples.

Each verdict below was established by reading the sample against the DVWA security-level
variant it comes from — not by asking the auditor and not by copying its answers — so the
confusion matrix measures the agent against something that exists before it runs.

Usage: seed_truths.py <base-url> <snapshot-id>
"""
import sys

import httpx

# (path, category, vulnerable, why the code says so)
SAMPLES = [
    (
        "vulnerabilities/sqli/source/low.php",
        "sqli",
        True,
        "low.php:5 取 $_REQUEST['id']，low.php:10/31 直接内插进 SQL 字符串（$query = \"... user_id = '$id'\";），"
        "无转义、无类型转换、无参数绑定；对照 impossible.php:11-17 的 is_numeric + intval + PDO bindParam。",
    ),
    (
        "vulnerabilities/sqli/source/impossible.php",
        "sqli",
        False,
        "impossible.php:11-12 is_numeric 校验后 intval 强制转整型，impossible.php:16-17 使用 PDO 预处理并 bindParam(PDO::PARAM_INT)，"
        "SQLite 分支同样 bindValue(SQLITE3_INTEGER)。输入无法影响语句结构。",
    ),
    (
        "vulnerabilities/xss_r/source/low.php",
        "xss_r",
        True,
        "low.php:8 把 $_GET['name'] 直接拼进 $html，无任何 HTML 编码；low.php:3 还显式关闭了 X-XSS-Protection。",
    ),
    (
        "vulnerabilities/xss_r/source/impossible.php",
        "xss_r",
        False,
        "impossible.php:9 先 htmlspecialchars 再拼进 $html（第 12 行），输出上下文与编码匹配。",
    ),
    (
        "vulnerabilities/exec/source/low.php",
        "command_injection",
        True,
        "low.php:5 取 $_REQUEST['ip']，low.php:14 直接拼进 shell_exec('ping -c 4 ' . $target)，无 escapeshellarg 或白名单。",
    ),
    (
        "vulnerabilities/exec/source/impossible.php",
        "command_injection",
        False,
        "impossible.php:12-17 按 '.' 切分并要求 4 段全部 is_numeric，再用数值段重新拼出 IP，"
        "拼接进 shell_exec 的字符串只能由数字与点组成。",
    ),
]

base = sys.argv[1].rstrip("/")
snapshot_id = sys.argv[2]

samples = [
    {
        "file_path": path,
        "category": category,
        "vulnerable": vulnerable,
        "independently_verified": True,
        "verification_basis": basis,
        "evidence": [],
    }
    for path, category, vulnerable, basis in SAMPLES
]

response = httpx.post(
    f"{base}/api/snapshots/{snapshot_id}/truths", json={"samples": samples}, timeout=60
)
print(response.status_code)
if response.status_code >= 400:
    print(response.text[:800])
    raise SystemExit(1)

for item in response.json():
    print(f"  {'漏洞' if item['vulnerable'] else '无漏洞'}  {item['category']:<18} {item['file_path']}")
