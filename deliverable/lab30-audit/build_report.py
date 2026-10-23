#!/usr/bin/env python3
"""Render the Lab30 full-audit Markdown report from the flattened findings + score."""
from __future__ import annotations

import json
from collections import Counter, OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
AUDIT = HERE / "audit_findings.json"
SCORE = HERE / "score_all.json"

# 中文类别名（class -> 展示名），与 ground_truth 的 type 对齐
CLASS_CN = {
    "sqli": "SQL 注入", "xss_r": "反射型/属性型 XSS", "xss_s": "存储型 XSS",
    "command_injection": "命令注入", "path_traversal": "路径遍历/任意文件读取",
    "lfi": "本地文件包含", "rfi": "远程文件包含", "code_execution": "代码执行",
    "open_redirect": "开放重定向", "info_disclosure": "信息泄露", "weak_crypto": "弱密码哈希",
    "ssrf": "服务端请求伪造", "xxe": "XML 外部实体", "csrf": "跨站请求伪造",
    "insecure_deserialization": "不安全反序列化", "idor": "越权访问 IDOR",
    "auth_bypass": "认证/授权绕过", "price_manipulation": "价格篡改",
    "race_condition": "竞态条件", "session_fixation": "会话固定",
    "weak_type_comparison": "弱类型比较", "mass_assignment": "批量赋值",
}

SEV_ORDER = ["critical", "high", "medium", "low", "none"]


def loc_str(locs):
    return "; ".join(f"{l['path']}:{l['line']}" for l in locs)


def main() -> int:
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    score = json.loads(SCORE.read_text(encoding="utf-8"))
    items = []
    for it in audit["findings"]:
        cv = it["cvss"]
        items.append({
            "id": it["id"], "title": it["title"], "type": it["type"], "class": it.get("class"),
            "cwe": it.get("cwe"), "severity": it["severity"],
            "cvss_base_score": cv["base_score"],
            "location": [{"path": ref["path"], "line": ref["start_line"]} for ref in it["evidence"]],
            "route": it.get("route"), "description": it.get("description"),
            "attack_input": it.get("attack_input"), "normal_input": it.get("normal_input"),
            "expected_result": it.get("expected_result"), "impact": it.get("impact"),
            "remediation": it.get("remediation"),
        })
    by_class = Counter(it["class"] for it in items)
    by_sev = Counter(it["severity"] for it in items)

    lines: list[str] = []
    A = lines.append
    A("# 拾光商城 Lab30 Shop 全量白盒漏洞审计报告\n")
    A("> 审计对象：`lab30-shop-1.0.0-source.zip`（SHA-256 `67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c`）")
    A("> 方法：对绑定源码包做全量静态白盒审计（逐文件通读 + 数据流追踪），再以 `score_dataset.py` 对照 `datasets/lab30-shop/ground_truth.json` 离线评分。\n")

    A("## 一、评分总览\n")
    A("> 本报告明细来自 `audit_findings.json`（独立白盒审计结论），评分由 `score_dataset.py` 对照官方真值计算，两份来源相互独立。\n")
    A("| 指标 | 结果 |")
    A("| --- | --- |")
    A(f"| 真值漏洞 / 审计结论 | {score['truths']} / {score['findings']} |")
    A(f"| TP / FP / FN | {score['TP']} / {score['FP']} / {score['FN']} |")
    A(f"| Precision / Recall / F1 | {score['precision']:.4f} / {score['recall']:.4f} / {score['f1']:.4f} |")
    se = score["severity_evaluation"]; cv = score["cvss_evaluation"]
    A(f"| 文字等级一致 | {se['correct']}/{se['compared']}（accuracy {se['accuracy']:.2f}） |")
    A(f"| CVSS 基础分一致 | {cv['score_accuracy']*100:.0f}%，MAE {cv['score_mae']:.2f} |")
    A(f"| CVSS 基础向量一致 | {cv['vector_accuracy']*100:.0f}% |\n")

    A("## 二、漏洞类型总览（共 %d 个，覆盖 %d 类）\n" % (len(items), len(by_class)))
    A("| 类别(class) | 中文类型 | 数量 | 编号 |")
    A("| --- | --- | --- | --- |")
    groups: dict[str, list[str]] = OrderedDict()
    for it in items:
        groups.setdefault(it["class"], []).append(it["id"])
    for cls, ids in groups.items():
        A(f"| `{cls}` | {CLASS_CN.get(cls, cls)} | {len(ids)} | {', '.join(ids)} |")
    A("")
    A("严重度分布（CVSS 3.1 Base 派生）：" +
      "，".join(f"{sev} {by_sev.get(sev,0)}" for sev in SEV_ORDER if by_sev.get(sev)) + "。\n")

    A("## 三、%d 项漏洞明细\n" % len(items))
    A("| # | 漏洞标题 | 类型 | CWE | 位置(源码:行) | CVSS | 入口 | 攻击输入(摘要) |")
    A("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for it in items:
        route = it.get("route", "")
        sev = f"{it['cvss_base_score']} {it['severity']}"
        atk = (it.get("attack_input") or "").replace("|", "/").replace("\n", " ")
        A(f"| {it['id']} | {it['title']} | {it['type']} | {it['cwe']} | `{loc_str(it['location'])}` | {sev} | {route} | `{atk[:60]}` |")

    coverage = score.get("class_coverage") or {}
    if coverage:
        A("\n### 类别覆盖面（审计结论 vs 官方真值）\n")
        A("| 类别(class) | 检出/总数 | 漏报编号 |")
        A("| --- | --- | --- |")
        for cls, cov in coverage.items():
            missed = ", ".join(cov["missed_ids"]) if cov["missed_ids"] else "—"
            A(f"| `{cls}` | {cov['detected']}/{cov['total']} | {missed} |")
        A("")

    A("\n## 四、逐项数据流、影响与修复\n")
    for it in items:
        A(f"### {it['id']} · {it['title']}（{it['type']} / {it['cwe']} / {it['severity']} {it['cvss_base_score']}）")
        A(f"- **位置**：`{loc_str(it['location'])}`")
        A(f"- **入口**：{it.get('route','')}")
        A(f"- **数据流**：{it.get('description') or '—'}")
        A(f"- **攻击输入**：`{it.get('attack_input') or '—'}`（对照正常输入：`{it.get('normal_input') or '—'}`）")
        A(f"- **预期差异**：{it.get('expected_result') or '—'}")
        A(f"- **影响**：{it.get('impact') or '—'}")
        A(f"- **修复**：{it.get('remediation') or '—'}\n")

    extras = audit.get("checked_not_counted") or []
    if extras:
        A("## 五、排查过但不计入真值的项\n")
        for extra in extras:
            A(f"- {extra}")
        A("")

    A("## 六、评测脚本使用\n")
    A("```bash")
    A("# 在线全量审计（默认 all，穷尽全部类别并对全量 30 项评分）")
    A("python scripts/run_lab30_e2e.py --base http://127.0.0.1:8899 --zip lab30-shop-1.0.0-source.zip --check-cvss")
    A("# 只跑分场景（sqli / xss_r / command_injection）")
    A("python scripts/run_lab30_e2e.py --base http://127.0.0.1:8899 --zip ... --scenario sqli")
    A("# 离线：直接对导出的 findings.json 评分，不起服务、不跑模型")
    A("python scripts/run_lab30_e2e.py --offline findings.json --check-severity --check-cvss")
    A("# 只评某个类别（查看该类覆盖面）")
    A("python scripts/run_lab30_e2e.py --offline findings.json --class auth_bypass")
    A("```\n")
    A("## 七、边界说明")
    A("- 本报告为静态源码审计结论，未启动靶场执行 PoC；攻击输入为源码推导出的触发线索。")
    A("- 评分仅基于源码行号证据匹配、CVSS 3.1 Base 与文字等级；时序/环境指标未评估。")
    A("- 独立审计结论与官方真值逐条同源比对，用于交叉验证数据集完整性，不能替代自动化流水线的检出率测量。")

    out = HERE / "审计报告.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print("wrote", out, len(items), "items")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
