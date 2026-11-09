#!/usr/bin/env python3
"""Render the deployment view (frontend / FastAPI / SQLite / lab30 / poc-runner).

The functional view (docs/architecture.svg, produced by render_architecture.py)
answers "what the five stages do"; this one answers "what runs where", which the
report's 3.1 section needs for the technology-stack check. Facts are taken from
compose.yaml and labs/lab30/compose.yaml; re-run after changing ports or services.

    python scripts/render_deployment_view.py
    python scripts/render_deployment_view.py --out docs/architecture-deployment.svg
"""
from __future__ import annotations

import argparse
from pathlib import Path

INK = "#1F2937"
MUTED = "#5B6472"
EDGE = "#4B5563"
CLIENT_FILL, CLIENT_STROKE = "#F3F0FB", "#6C5BA8"
APP_FILL, APP_STROKE = "#EDF3FB", "#3C6FA8"
STORE_FILL, STORE_STROKE = "#FBF4E6", "#B98A34"
LAB_FILL, LAB_STROKE = "#EFF7EF", "#4A8A50"
CANVAS = "#FFFFFF"

W, H = 1120, 660


def esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def box(x: int, y: int, w: int, h: int, fill: str, stroke: str, rx: int = 10) -> str:
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" ry="{rx}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.6"/>')


def text(x: int, y: int, value: str, size: int = 14, fill: str = INK,
         weight: str = "normal", anchor: str = "start") -> str:
    return (f'<text x="{x}" y="{y}" font-family="Noto Sans CJK SC, Source Han Sans SC, '
            f'PingFang SC, Microsoft YaHei, sans-serif" font-size="{size}" fill="{fill}" '
            f'font-weight="{weight}" text-anchor="{anchor}">{esc(value)}</text>')


def arrow(x1: int, y1: int, x2: int, y2: int, dashed: bool = False) -> str:
    dash = ' stroke-dasharray="6 5"' if dashed else ""
    return (f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{EDGE}" '
            f'stroke-width="1.6" marker-end="url(#dep-arrow)"{dash}/>')


def build() -> str:
    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" role="img" aria-label="VULN-AUDIT 部署视图">',
        '<defs><marker id="dep-arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{EDGE}"/></marker></defs>',
        f'<rect x="0" y="0" width="{W}" height="{H}" fill="{CANVAS}"/>',
        text(40, 44, "VULN-AUDIT 部署视图（开发栈）", 20, INK, "bold"),
        text(40, 68, "浏览器 → FastAPI 应用 → SQLite / 快照存储；POC 经隔离 runner 访问本地 Lab30 靶场",
             12, MUTED),
    ]

    # 列标题
    out += [
        text(60, 112, "① 客户端", 13, CLIENT_STROKE, "bold"),
        text(380, 112, "② 应用层（FastAPI）", 13, APP_STROKE, "bold"),
        text(800, 112, "③ 存储层", 13, STORE_STROKE, "bold"),
    ]

    # 客户端
    out += [
        box(40, 130, 250, 150, CLIENT_FILL, CLIENT_STROKE),
        text(60, 162, "浏览器", 16, INK, "bold"),
        text(60, 188, "React 19 + Vite", 12, MUTED),
        text(60, 208, "127.0.0.1:5173", 12, MUTED),
        text(60, 236, "源码包 / 审计任务 / 运行详情", 11, MUTED),
        text(60, 254, "漏洞发现 / Prompt 实验 / 设置", 11, MUTED),
    ]

    # 应用层
    out += [
        box(340, 130, 380, 300, APP_FILL, APP_STROKE),
        text(362, 162, "FastAPI 应用（audit.app）", 16, INK, "bold"),
        text(362, 186, "127.0.0.1:8899", 12, MUTED),
    ]
    rows = [
        ("Planner / Worker 编排", "预算：请求 · 工具 · 时长"),
        ("只读源码工具", "tree-sitter PHP 索引 · 切片"),
        ("事件流 SSE", "事件先落库，再推送前端"),
        ("证据校验与降噪", "三段链 · 未验证显式标注"),
        ("报告导出", "Markdown / JSON / 证据 zip"),
        ("模型档案", "Base URL 脱敏 · 密钥不落快照"),
    ]
    for i, (title, sub) in enumerate(rows):
        y = 208 + i * 36
        out += [
            f'<rect x="358" y="{y}" width="344" height="30" rx="6" fill="#FFFFFF" '
            f'stroke="{APP_STROKE}" stroke-width="1" opacity="0.9"/>',
            text(370, y + 20, title, 12, INK, "bold"),
            text(560, y + 20, sub, 10.5, MUTED),
        ]

    # 存储层
    stores = [
        ("SQLite（WAL）", "data/audit.db · 事件/结论/评分"),
        ("不可变快照", "源码 ZIP · SHA-256 · 原始行号"),
        ("证据与报告", "POC 输出 · 证据 zip · 评分 JSON"),
    ]
    for i, (title, sub) in enumerate(stores):
        y = 130 + i * 100
        out += [
            box(780, y, 300, 84, STORE_FILL, STORE_STROKE),
            text(800, y + 30, title, 14, INK, "bold"),
            text(800, y + 54, sub, 11, MUTED),
        ]

    # 靶场与执行层
    out += [
        text(40, 470, "④ 靶场与隔离执行（本地 Docker Compose）", 13, LAB_STROKE, "bold"),
    ]
    labs = [
        ("lab30 商城（PHP）", ":18880 · 30 项真值 / 22 类"),
        ("lab30-db", "MariaDB · seed 固定"),
        ("lab30-fixtures", "一次性数据装载"),
        ("poc-runner", ":18089 转发 · Bearer · 隔离容器"),
    ]
    for i, (title, sub) in enumerate(labs):
        x = 40 + i * 265
        out += [
            box(x, 486, 245, 92, LAB_FILL, LAB_STROKE),
            text(x + 18, 516, title, 13.5, INK, "bold"),
            text(x + 18, 540, sub, 10.5, MUTED),
        ]

    # 连线
    out += [
        arrow(290, 205, 336, 205),           # 浏览器 -> 应用
        text(240, 196, "HTTP / SSE", 10, MUTED),
        arrow(722, 200, 776, 172),           # 应用 -> SQLite
        arrow(722, 240, 776, 262),           # 应用 -> 快照
        arrow(722, 280, 776, 352),           # 应用 -> 证据
        arrow(530, 432, 530, 482),           # 应用 -> 靶场执行层
        text(538, 462, "POC 作业", 10, MUTED),
        text(60, 590, "说明：开发栈为 Vite(5173) + Uvicorn(8899) 双进程；",
             11, MUTED),
        text(60, 610, "容器栈由 compose.yaml 以单端口 8899 提供同一应用，靶场栈在 labs/lab30/compose.yaml。",
             11, MUTED),
        text(60, 630, "POC 仅在 COMPOSE_PROFILES=poc 或 --poc 开启；关闭时结论显式标注“未验证”。",
             11, MUTED),
    ]

    out.append("</svg>")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parents[1] / "docs/architecture-deployment.svg")
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build(), encoding="utf-8")
    print(f"written: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
