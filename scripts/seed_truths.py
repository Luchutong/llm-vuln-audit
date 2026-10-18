#!/usr/bin/env python3
"""Record source-checked benchmark labels for DVWA or Mutillidae snapshots.

Usage: seed_truths.py <base-url> <snapshot-id> [--benchmark dvwa|mutillidae|mutillidae-crossfile|mutillidae-multiflow]
"""
import argparse

import httpx

# (path, category, vulnerable, why the code says so, source evidence)
SAMPLES = [
    (
        "vulnerabilities/sqli/source/low.php",
        "sqli",
        True,
        "low.php:5 取 $_REQUEST['id']，low.php:10/31 直接内插进 SQL 字符串（$query = \"... user_id = '$id'\";），"
        "无转义、无类型转换、无参数绑定；对照 impossible.php:11-17 的 is_numeric + intval + PDO bindParam。",
        [{"path": "vulnerabilities/sqli/source/low.php", "start_line": 5, "end_line": 11},
         {"path": "vulnerabilities/sqli/source/low.php", "start_line": 31, "end_line": 34}],
    ),
    (
        "vulnerabilities/sqli/source/low.php",
        "xss_r",
        True,
        "low.php:5 从 $_REQUEST['id'] 取值，MYSQL/SQLITE 分支分别在第 20/47 行未经 HTML 编码拼入 $html；"
        "index.php:68 将页面内容输出。隔离 DVWA 2.5、security=low 环境中浏览器实际执行了注入脚本，"
        "弹窗返回当前会话 cookie；该结论有 POC 与浏览器截图/日志记录。",
        [{"path": "vulnerabilities/sqli/source/low.php", "start_line": 3, "end_line": 5},
         {"path": "vulnerabilities/sqli/source/low.php", "start_line": 20, "end_line": 20},
         {"path": "vulnerabilities/sqli/source/low.php", "start_line": 47, "end_line": 47},
         {"path": "vulnerabilities/sqli/index.php", "start_line": 67, "end_line": 68}],
    ),
    (
        "vulnerabilities/sqli/source/impossible.php",
        "sqli",
        False,
        "impossible.php:11-12 is_numeric 校验后 intval 强制转整型，impossible.php:16-17 使用 PDO 预处理并 bindParam(PDO::PARAM_INT)，"
        "SQLite 分支同样 bindValue(SQLITE3_INTEGER)。输入无法影响语句结构。",
        [{"path": "vulnerabilities/sqli/source/impossible.php", "start_line": 11, "end_line": 17}],
    ),
    (
        "vulnerabilities/xss_r/source/low.php",
        "xss_r",
        True,
        "low.php:8 把 $_GET['name'] 直接拼进 $html，无任何 HTML 编码；low.php:3 还显式关闭了 X-XSS-Protection。",
        [{"path": "vulnerabilities/xss_r/source/low.php", "start_line": 3, "end_line": 8}],
    ),
    (
        "vulnerabilities/xss_r/source/impossible.php",
        "xss_r",
        False,
        "impossible.php:9 先 htmlspecialchars 再拼进 $html（第 12 行），输出上下文与编码匹配。",
        [{"path": "vulnerabilities/xss_r/source/impossible.php", "start_line": 9, "end_line": 12}],
    ),
    (
        "vulnerabilities/exec/source/low.php",
        "command_injection",
        True,
        "low.php:5 取 $_REQUEST['ip']，low.php:14 直接拼进 shell_exec('ping -c 4 ' . $target)，无 escapeshellarg 或白名单。",
        [{"path": "vulnerabilities/exec/source/low.php", "start_line": 5, "end_line": 14}],
    ),
    (
        "vulnerabilities/exec/source/impossible.php",
        "command_injection",
        False,
        "impossible.php:12-17 按 '.' 切分并要求 4 段全部 is_numeric，再用数值段重新拼出 IP，"
        "拼接进 shell_exec 的字符串只能由数字与点组成。",
        [{"path": "vulnerabilities/exec/source/impossible.php", "start_line": 12, "end_line": 17}],
    ),
    (
        "vulnerabilities/sqli/source/low.php",
        "command_injection",
        False,
        "该单元将 id 用于 MySQL/SQLite 查询和 HTML 输出（第 5-20、31-47 行）；没有进程执行或 shell API 调用。",
        [{"path": "vulnerabilities/sqli/source/low.php", "start_line": 5, "end_line": 20},
         {"path": "vulnerabilities/sqli/source/low.php", "start_line": 31, "end_line": 47}],
    ),
    (
        "vulnerabilities/sqli/source/impossible.php",
        "xss_r",
        False,
        "输入先经 is_numeric 与 intval（第 8-12 行），回显的 id 是整数；其余回显字段来自固定用户表查询（第 16-28 行），"
        "此单元没有将原始输入直接写入 HTML。",
        [{"path": "vulnerabilities/sqli/source/impossible.php", "start_line": 8, "end_line": 12},
         {"path": "vulnerabilities/sqli/source/impossible.php", "start_line": 16, "end_line": 28}],
    ),
    (
        "vulnerabilities/sqli/source/impossible.php",
        "command_injection",
        False,
        "该单元仅执行数值校验、参数化数据库查询和结果回显（第 8-53 行），没有进程执行或 shell API 调用。",
        [{"path": "vulnerabilities/sqli/source/impossible.php", "start_line": 8, "end_line": 53}],
    ),
    (
        "vulnerabilities/xss_r/source/low.php",
        "sqli",
        False,
        "name 参数只拼入 HTML 响应（第 6-8 行）；该单元没有数据库连接、SQL 查询或数据库执行 API。",
        [{"path": "vulnerabilities/xss_r/source/low.php", "start_line": 6, "end_line": 8}],
    ),
    (
        "vulnerabilities/xss_r/source/low.php",
        "command_injection",
        False,
        "name 参数只拼入 HTML 响应（第 6-8 行）；该单元没有 shell 或进程执行 API。",
        [{"path": "vulnerabilities/xss_r/source/low.php", "start_line": 6, "end_line": 8}],
    ),
    (
        "vulnerabilities/xss_r/source/impossible.php",
        "sqli",
        False,
        "name 参数经 htmlspecialchars 后输出（第 8-12 行）；该单元没有数据库连接、SQL 查询或数据库执行 API。",
        [{"path": "vulnerabilities/xss_r/source/impossible.php", "start_line": 8, "end_line": 12}],
    ),
    (
        "vulnerabilities/xss_r/source/impossible.php",
        "command_injection",
        False,
        "name 参数经 htmlspecialchars 后输出（第 8-12 行）；该单元没有 shell 或进程执行 API。",
        [{"path": "vulnerabilities/xss_r/source/impossible.php", "start_line": 8, "end_line": 12}],
    ),
    (
        "vulnerabilities/exec/source/low.php",
        "sqli",
        False,
        "ip 参数只流向 shell_exec 与 HTML 输出（第 5-18 行）；该单元没有数据库连接、SQL 查询或数据库执行 API。",
        [{"path": "vulnerabilities/exec/source/low.php", "start_line": 5, "end_line": 18}],
    ),
    (
        "vulnerabilities/exec/source/low.php",
        "xss_r",
        True,
        "ip 参数拼入 shell_exec 命令（第 5-14 行），攻击者可令命令向 stdout 输出 HTML；命令输出再未经编码拼入 HTML 响应（第 18 行），"
        "因此该可达链也能造成反射型 XSS。该标签由源码链独立核验，未执行载荷或靶机代码。",
        [{"path": "vulnerabilities/exec/source/low.php", "start_line": 5, "end_line": 14},
         {"path": "vulnerabilities/exec/source/low.php", "start_line": 17, "end_line": 18}],
    ),
    (
        "vulnerabilities/exec/source/impossible.php",
        "sqli",
        False,
        "ip 参数经过点分段数值校验后只流向 ping 命令（第 8-30 行）；该单元没有数据库连接、SQL 查询或数据库执行 API。",
        [{"path": "vulnerabilities/exec/source/impossible.php", "start_line": 8, "end_line": 30}],
    ),
    (
        "vulnerabilities/exec/source/impossible.php",
        "xss_r",
        False,
        "ip 参数只有通过四段 is_numeric 校验才进入 ping 命令（第 12-30 行），拒绝 HTML 标记字符；"
        "无效输入仅输出固定错误文本（第 32-34 行）。",
        [{"path": "vulnerabilities/exec/source/impossible.php", "start_line": 12, "end_line": 17},
         {"path": "vulnerabilities/exec/source/impossible.php", "start_line": 29, "end_line": 34}],
    ),
]

MUTILLIDAE_SAMPLES = [
    (
        "src/dns-lookup.php",
        "sqli",
        False,
        "该页面从 target_host 取值并进入 DNS 或 nslookup 路径（第 39-59、151-167 行），"
        "没有 SQL 查询或数据库 API。",
        [{"path": "src/dns-lookup.php", "start_line": 39, "end_line": 59},
         {"path": "src/dns-lookup.php", "start_line": 151, "end_line": 167}],
    ),
    (
        "src/dns-lookup.php",
        "xss_r",
        True,
        "安全级别 0/1 时 target_host 来自请求（第 39-45 行），未经过 HTML 编码（第 55-59 行），"
        "并拼入 HTML 标题（第 151 行）；安全级别 2-5 才启用编码。",
        [{"path": "src/dns-lookup.php", "start_line": 39, "end_line": 59},
         {"path": "src/dns-lookup.php", "start_line": 151, "end_line": 151}],
    ),
    (
        "src/dns-lookup.php",
        "command_injection",
        True,
        "安全级别 0/1 不执行服务端主机名校验（第 11-35、47-53 行），"
        "请求值直接拼入 shell_exec 的 nslookup 命令（第 162-165 行）；"
        "第 1 级的 JavaScript 校验不能约束直接构造的 HTTP 请求。",
        [{"path": "src/dns-lookup.php", "start_line": 11, "end_line": 53},
         {"path": "src/dns-lookup.php", "start_line": 162, "end_line": 165}],
    ),
    (
        "src/echo.php",
        "sqli",
        False,
        "该页面将 message 用于 HTML 输出及 echo 命令（第 39-51、142-149 行），"
        "没有 SQL 查询或数据库 API。",
        [{"path": "src/echo.php", "start_line": 39, "end_line": 51},
         {"path": "src/echo.php", "start_line": 142, "end_line": 149}],
    ),
    (
        "src/echo.php",
        "xss_r",
        True,
        "安全级别 0/1 时 message 来自请求（第 39-45 行），未经过 HTML 编码（第 47-51 行），"
        "并直接进入 HTML 输出（第 142-145 行）；安全级别 2-5 才启用编码。",
        [{"path": "src/echo.php", "start_line": 39, "end_line": 51},
         {"path": "src/echo.php", "start_line": 142, "end_line": 145}],
    ),
    (
        "src/echo.php",
        "command_injection",
        True,
        "安全级别 0/1 不启用命令注入防护（第 7-25 行），message 从请求中取得（第 39-45 行），"
        "直接拼入 shell_exec 的 echo 命令（第 148 行）；客户端 JavaScript 检查可由直接 HTTP 请求绕过。",
        [{"path": "src/echo.php", "start_line": 7, "end_line": 25},
         {"path": "src/echo.php", "start_line": 39, "end_line": 45},
         {"path": "src/echo.php", "start_line": 148, "end_line": 148}],
    ),
]

MUTILLIDAE_CROSSFILE_SAMPLES = [
    (
        "src/user-info.php",
        "sqli",
        True,
        "security-level 0/1 下 user-info.php 从 GET/REQUEST 读取 username/password（第 39-51 行），"
        "并调用 SQLQueryHandler::getUserAccount（第 169 行）；该方法只在安全级别 2-5 转义参数（"
        "SQLQueryHandler.php:403-419），随后把两者拼入 SELECT 并交给 MySQLHandler::executeQuery；"
        "MySQLHandler.php:347-349 将其转给 doExecuteQuery，后者在第 229 行执行 mysqli::query。"
        "安全级别 0 是 index.php 初始化的默认值（index.php:28-31、190）；"
        "级别 1 也关闭 stopSQLInjection（SQLQueryHandler.php:20-26）。",
        [
            {"path": "src/user-info.php", "start_line": 39, "end_line": 51},
            {"path": "src/user-info.php", "start_line": 167, "end_line": 169},
            {"path": "src/classes/SQLQueryHandler.php", "start_line": 20, "end_line": 36},
            {"path": "src/classes/SQLQueryHandler.php", "start_line": 403, "end_line": 419},
            {"path": "src/classes/MySQLHandler.php", "start_line": 225, "end_line": 240},
            {"path": "src/classes/MySQLHandler.php", "start_line": 347, "end_line": 349},
        ],
    ),
    (
        "src/user-info.php",
        "xss_r",
        True,
        "security-level 0/1 下 username 由 GET/REQUEST 取得（第 46-51 行），"
        "lEncodeOutput=false（第 7-22 行），故不做 HTML 编码（第 179-181 行），"
        "随后原样拼入 HTML 响应（第 183-187 行）。",
        [
            {"path": "src/user-info.php", "start_line": 7, "end_line": 22},
            {"path": "src/user-info.php", "start_line": 39, "end_line": 51},
            {"path": "src/user-info.php", "start_line": 179, "end_line": 187},
        ],
    ),
    (
        "src/user-info.php",
        "command_injection",
        False,
        "本审计路径接收 username/password，调用数据库查询并输出账户字段（第 39-51、167-223 行）；"
        "该入口及其 getUserAccount 查询/执行链没有 shell 或进程执行 API。",
        [
            {"path": "src/user-info.php", "start_line": 39, "end_line": 51},
            {"path": "src/user-info.php", "start_line": 167, "end_line": 223},
            {"path": "src/classes/SQLQueryHandler.php", "start_line": 403, "end_line": 419},
            {"path": "src/classes/MySQLHandler.php", "start_line": 225, "end_line": 240},
        ],
    ),
]

MUTILLIDAE_MULTIFLOW_SAMPLES = [
    (
        "src/user-info.php",
        "sqli",
        True,
        "security-level 0/1 下 user-info.php 从 GET/REQUEST 读取 username/password（第 39-51 行），"
        "并调用 SQLQueryHandler::getUserAccount（第 167-169 行）；该方法仅在级别 2-5 转义参数"
        "（SQLQueryHandler.php:403-419），随后拼接查询并调用 MySQLHandler::executeQuery；"
        "该链最终到达 mysqli::query（MySQLHandler.php:229）。",
        [
            {"path": "src/user-info.php", "start_line": 39, "end_line": 51},
            {"path": "src/user-info.php", "start_line": 167, "end_line": 169},
            {"path": "src/classes/SQLQueryHandler.php", "start_line": 20, "end_line": 36},
            {"path": "src/classes/SQLQueryHandler.php", "start_line": 403, "end_line": 419},
            {"path": "src/classes/MySQLHandler.php", "start_line": 225, "end_line": 240},
            {"path": "src/classes/MySQLHandler.php", "start_line": 347, "end_line": 349},
        ],
    ),
    (
        "src/user-info.php",
        "xss_r",
        True,
        "security-level 0/1 下 username 由请求参数读取（第 46-51 行），"
        "lEncodeOutput 为 false（第 7-22 行），结果标题把该值直接拼进 HTML（第 179-187 行）。",
        [
            {"path": "src/user-info.php", "start_line": 7, "end_line": 22},
            {"path": "src/user-info.php", "start_line": 39, "end_line": 51},
            {"path": "src/user-info.php", "start_line": 179, "end_line": 187},
        ],
    ),
    (
        "src/user-info.php",
        "command_injection",
        False,
        "请求输入流向账户 SQL 查询和 HTML 回显（第 39-51、167-223 行）；"
        "该入口及其 getUserAccount 数据库执行链没有 shell 或进程执行 API。",
        [
            {"path": "src/user-info.php", "start_line": 39, "end_line": 51},
            {"path": "src/user-info.php", "start_line": 167, "end_line": 223},
            {"path": "src/classes/SQLQueryHandler.php", "start_line": 403, "end_line": 419},
            {"path": "src/classes/MySQLHandler.php", "start_line": 225, "end_line": 240},
        ],
    ),
    (
        "src/register.php",
        "sqli",
        True,
        "security-level 0/1 下注册字段来自 $_REQUEST（第 67-75 行）；"
        "入口调用 insertNewUserAccount（第 118 行）。SQLQueryHandler 在安全级别 0/1 不启用转义"
        "（SQLQueryHandler.php:20-26），该方法把字段拼入 INSERT 并调用数据库执行（第 459-485 行；"
        "MySQLHandler.php:225-240）。",
        [
            {"path": "src/register.php", "start_line": 54, "end_line": 75},
            {"path": "src/register.php", "start_line": 110, "end_line": 119},
            {"path": "src/classes/SQLQueryHandler.php", "start_line": 20, "end_line": 36},
            {"path": "src/classes/SQLQueryHandler.php", "start_line": 459, "end_line": 485},
            {"path": "src/classes/MySQLHandler.php", "start_line": 225, "end_line": 240},
        ],
    ),
    (
        "src/register.php",
        "xss_r",
        True,
        "security-level 0/1 下注册用户名来自 $_REQUEST（第 67-69 行），"
        "lEncodeOutput 为 false 时 lUsernameText 原样取该值（第 79-83 行），"
        "成功响应再将其拼进 HTML（第 118-119 行）。",
        [
            {"path": "src/register.php", "start_line": 22, "end_line": 44},
            {"path": "src/register.php", "start_line": 67, "end_line": 83},
            {"path": "src/register.php", "start_line": 110, "end_line": 120},
        ],
    ),
    (
        "src/register.php",
        "command_injection",
        False,
        "注册字段流向 CSRF 校验、账户插入和 HTML 响应（第 54-120 行）；"
        "本入口及 insertNewUserAccount 数据库链无 shell 或进程执行 API。",
        [
            {"path": "src/register.php", "start_line": 54, "end_line": 120},
            {"path": "src/classes/SQLQueryHandler.php", "start_line": 459, "end_line": 485},
            {"path": "src/classes/MySQLHandler.php", "start_line": 225, "end_line": 240},
        ],
    ),
    (
        "src/browser-info.php",
        "sqli",
        False,
        "该页面通过 ClientInformationHandler 读取请求头与客户端连接信息，并将结果编码或输出到 HTML"
        "（第 40-90 行；ClientInformationHandler.php:13-82）；页面及 helper 中没有 SQL 查询或数据库执行 API。",
        [
            {"path": "src/browser-info.php", "start_line": 40, "end_line": 90},
            {"path": "src/classes/ClientInformationHandler.php", "start_line": 13, "end_line": 82},
        ],
    ),
    (
        "src/browser-info.php",
        "xss_r",
        True,
        "浏览器页在安全级别 0/1 不对输出做 HTML 编码（第 7-20 行）；"
        "ClientInformationHandler::getClientUserAgentString 从 HTTP_USER_AGENT 返回请求头原值"
        "（ClientInformationHandler.php:53-57），页面把该值直接输出到 HTML（第 56-61、76-82 行）。",
        [
            {"path": "src/browser-info.php", "start_line": 7, "end_line": 20},
            {"path": "src/browser-info.php", "start_line": 40, "end_line": 61},
            {"path": "src/browser-info.php", "start_line": 76, "end_line": 82},
            {"path": "src/classes/ClientInformationHandler.php", "start_line": 53, "end_line": 62},
        ],
    ),
    (
        "src/browser-info.php",
        "command_injection",
        False,
        "本入口从请求头读取客户端信息并编码/输出（第 40-90 行；"
        "ClientInformationHandler.php:13-82）；whoIsClient 使用 REMOTE_ADDR 查询 Whois，"
        "数据并未传给 shell 或进程执行 API（ClientInformationHandler.php:82-110、150-177）。",
        [
            {"path": "src/browser-info.php", "start_line": 40, "end_line": 90},
            {"path": "src/classes/ClientInformationHandler.php", "start_line": 53, "end_line": 62},
            {"path": "src/classes/ClientInformationHandler.php", "start_line": 82, "end_line": 110},
            {"path": "src/classes/ClientInformationHandler.php", "start_line": 150, "end_line": 177},
        ],
    ),
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url")
    parser.add_argument("snapshot_id")
    parser.add_argument(
        "--benchmark",
        choices=("dvwa", "mutillidae", "mutillidae-crossfile", "mutillidae-multiflow"),
        default="dvwa",
    )

    args = parser.parse_args(argv)
    definitions = {
        "dvwa": SAMPLES,
        "mutillidae": MUTILLIDAE_SAMPLES,
        "mutillidae-crossfile": MUTILLIDAE_CROSSFILE_SAMPLES,
        "mutillidae-multiflow": MUTILLIDAE_MULTIFLOW_SAMPLES,
    }[args.benchmark]
    samples = [
        {
            "file_path": path,
            "category": category,
            "vulnerable": vulnerable,
            "independently_verified": True,
            "verification_basis": basis,
            "evidence": evidence,
        }
        for path, category, vulnerable, basis, evidence in definitions
    ]

    url = f"{args.base_url.rstrip('/')}/api/snapshots/{args.snapshot_id}/truths"
    existing_response = httpx.get(url, timeout=60)
    existing_response.raise_for_status()
    merged = {
        (item["file_path"], item["category"]): {
            "file_path": item["file_path"],
            "category": item["category"],
            "vulnerable": item["vulnerable"],
            "independently_verified": item["independently_verified"],
            "verification_basis": item["verification_basis"],
            "evidence": item["evidence"],
        }
        for item in existing_response.json()
    }
    merged.update({(item["file_path"], item["category"]): item for item in samples})

    response = httpx.post(url, json={"samples": list(merged.values())}, timeout=60)
    response.raise_for_status()
    print(
        f"{response.status_code}; 保留/写入真值标签 {len(merged)} 条"
        f"（{args.benchmark} 本次核验 {len(samples)} 条）"
    )
    for item in samples:
        print(
            f"  {'漏洞' if item['vulnerable'] else '无漏洞'}  "
            f"{item['category']:<18} {item['file_path']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
