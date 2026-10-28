#!/usr/bin/env python3
"""Render the system architecture figure (docs/architecture.svg) from code.

The report's Figure 1 must never drift from the design it describes, so the
diagram is generated instead of being drawn by hand.  Edit the ``MODULES`` /
``STORES`` tables below and re-run to regenerate:

    python scripts/render_architecture.py
    python scripts/render_architecture.py --out docs/architecture.svg

Only deterministic SVG is emitted: no external fonts, no network, no raster
assets.  The palette is fixed to a light theme so the figure reads correctly on
paper and inside light-theme Markdown previews.
"""
from __future__ import annotations

import argparse
from pathlib import Path

# --- palette (light theme) ---------------------------------------------------
INK = "#1F2937"
MUTED = "#5B6472"
EDGE = "#4B5563"
FEEDBACK = "#9AA1AC"
MODULE_FILL = "#EDF3FB"
MODULE_STROKE = "#3C6FA8"
STORE_FILL = "#FBF4E6"
STORE_STROKE = "#B98A34"
CANVAS = "#FFFFFF"

FONT = "'Segoe UI','Microsoft YaHei','Hiragino Sans GB',sans-serif"

AMP = chr(38)  # '&'


def _esc(text: str) -> str:
    """Escape the three characters that are unsafe inside SVG text nodes."""
    return (
        text.replace(AMP, AMP + "amp;")
        .replace("<", AMP + "lt;")
        .replace(">", AMP + "gt;")
    )


# --- layout ------------------------------------------------------------------
W, H = 1060, 930
MX, MW = 140, 300         # module column
SX, SW = 606, 372         # store column
TOP, BH, GAP = 104, 116, 42

MODULES = [
    ("① 代码预处理", "ZIP → 不可变快照", "tree-sitter 索引 · 切片 · omissions"),
    ("② Prompt 提示词工程", "四段式 + 场景子模板", "P0/P1/P2 演进 · 不可信输入约束"),
    ("③ LLM 推理挖掘", "Agent + 只读工具", "三段链证据 · 预算控制 · 两段式收尾"),
    ("④ POC 实操验证", "人工运行 / 隔离执行器", "正常·攻击对照 · 执行状态与结论分离"),
    ("⑤ 校验降噪与复盘", "证据校验 + 真值对照", "混淆矩阵 · 归因 · 下一轮优化项"),
]

STORES = [
    ("不可变快照", "文件清单 · SHA-256 · 原始行号"),
    ("提示词版本库", "冻结 Prompt 全文 · 场景版本"),
    ("运行事件库", "SQLite(WAL) 事件先落库再 SSE 推送"),
    ("靶场与 POC 执行器", "lab30 商城 · poc-runner 隔离容器"),
    ("真值集与指标", "CVSS 3.1 锚点 · 证据 zip 导出"),
]


def _box(x: int, y: int, w: int, h: int, fill: str, stroke: str) -> str:
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" ry="10" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="1.6"/>'
    )


def _text(x: int, y: int, body: str, size: float, fill: str,
          weight: str = "normal", anchor: str = "start") -> str:
    return (
        f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">'
        f"{_esc(body)}</text>"
    )


def _curve(d: str, colour: str = FEEDBACK) -> str:
    return (
        f'<path d="{d}" fill="none" stroke="{colour}" stroke-width="1.6" '
        f'stroke-dasharray="8 6" marker-end="url(#ah-fb)"/>'
    )


def build() -> str:
    tops = [TOP + i * (BH + GAP) for i in range(5)]
    out: list[str] = []
    out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" role="img" '
        f'aria-label="基于 LLM 辅助的漏洞挖掘与验证系统总体架构">'
    )
    out.append(
        "<defs>"
        '<marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        'markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{EDGE}"/></marker>'
        '<marker id="ah-fb" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        'markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{FEEDBACK}"/></marker>'
        "</defs>"
    )
    out.append(f'<rect x="0" y="0" width="{W}" height="{H}" fill="{CANVAS}"/>')

    out.append(_text(MX, 62, "固定五模块链路（自上而下）", 16, INK, "bold"))
    out.append(_text(SX, 62, "存储 / 外部交互对象", 16, INK, "bold"))

    # ①..⑤ 顺序箭头
    for i in range(4):
        cx = MX + 46
        out.append(
            f'<line x1="{cx}" y1="{tops[i] + BH}" x2="{cx}" y2="{tops[i + 1] - 6}" '
            f'stroke="{EDGE}" stroke-width="1.6" marker-end="url(#ah)"/>'
        )

    # 模块 <-> 存储 双向读写
    for y in tops:
        cy = y + BH // 2
        out.append(
            f'<line x1="{MX + MW}" y1="{cy}" x2="{SX - 6}" y2="{cy}" stroke="{EDGE}" '
            f'stroke-width="1.6" marker-start="url(#ah)" marker-end="url(#ah)"/>'
        )

    # 模块五的优化结论反哺模块二（Prompt）与模块一（切片规则）
    y5 = tops[4] + BH // 2
    out.append(
        _curve(
            f"M {MX} {y5} C {MX - 40} {y5}, {MX - 46} {tops[1] + BH // 2}, "
            f"{MX - 4} {tops[1] + BH // 2}"
        )
    )
    out.append(
        _curve(
            f"M {MX} {y5 + 18} C {MX - 62} {y5 + 18}, {MX - 62} {tops[0] + BH // 2}, "
            f"{MX - 4} {tops[0] + BH // 2}"
        )
    )
    mid_y = (y5 + tops[0] + BH // 2) // 2
    # 白色底牌压住反哺曲线，保证文字可读
    out.append(
        f'<rect x="{MX - 134}" y="{mid_y - 20}" width="126" height="44" rx="8" ry="8" '
        f'fill="{CANVAS}" stroke="{FEEDBACK}" stroke-width="1.2" stroke-dasharray="6 4"/>'
    )
    out.append(_text(MX - 71, mid_y - 2, "优化结论反哺", 13, MUTED, "normal", "middle"))
    out.append(_text(MX - 71, mid_y + 15, "切片 · Prompt", 12, MUTED, "normal", "middle"))

    for (title, sub, detail), y in zip(MODULES, tops):
        out.append(_box(MX, y, MW, BH, MODULE_FILL, MODULE_STROKE))
        out.append(_text(MX + 20, y + 34, title, 18, INK, "bold"))
        out.append(_text(MX + 20, y + 62, sub, 14, MUTED))
        out.append(_text(MX + 20, y + 88, detail, 12.5, MUTED))

    for (title, detail), y in zip(STORES, tops):
        out.append(_box(SX, y, SW, BH, STORE_FILL, STORE_STROKE))
        out.append(_text(SX + 20, y + 42, title, 16, INK, "bold"))
        out.append(_text(SX + 20, y + 72, detail, 12.5, MUTED))

    out.append("</svg>")
    return "\n".join(out) + "\n"


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Render docs/architecture.svg")
    parser.add_argument("--out", type=Path, default=repo / "docs" / "architecture.svg")
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build(), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
