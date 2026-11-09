#!/usr/bin/env python3
"""Prove that the prompt full texts printed in the report match the runtime source.

``backend/audit/prompts.py`` is the single source of truth for the built-in
P0/P1/P2 versions.  The report renders those texts with Markdown typography, so
this script reverses the typography and compares line by line:

    python scripts/render_report_prompts.py            # 打印差异明细
    python scripts/render_report_prompts.py --check    # 差异等于冻结清单则退出 0

Blank-line differences are pure typesetting and are counted separately.  The
remaining textual deltas are frozen in ``EXPECTED_DELTAS``: any new drift (an
edited prompt that was not mirrored into the report, or vice versa) fails
``--check`` instead of passing silently.

The scenario sections in the report are NOT covered here: ``SCENARIO_PROMPTS``
holds the compact registerable version, while the report prints an enriched
design draft (see report §4.2.2).
"""
from __future__ import annotations

import argparse
import difflib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REPORT = REPO / "deliverable" / "《网络安全》大实验-基于LLM辅助的漏洞挖掘设计与验证-完整设计报告.md"

sys.path.insert(0, str(REPO / "backend"))
from audit import prompts  # noqa: E402

SECTION_RE = re.compile(r"^\*\*(一|二|三|四|五)、(.+?)\*\*\s*$")

# 冻结的已知差异：报告定稿把"命令解释"澄清为"命令解释器"，判定条件与契约均未改动。
EXPECTED_DELTAS: dict[str, list[tuple[str, str]]] = {
    "P0": [
        (
            "**命令注入**：输入是否影响命令解释。注意参数边界、白名单或输入约束是否有效。",
            "**命令注入**：输入是否影响命令解释器。注意参数边界、白名单或输入约束是否有效。",
        )
    ],
    "P1": [("**命令注入**：输入是否影响命令解释。", "**命令注入**：输入是否影响命令解释器。")],
    "P2": [("**命令注入**：输入是否影响命令解释。", "**命令注入**：输入是否影响命令解释器。")],
}


def _report_block(tag: str) -> str:
    match = re.search(
        rf"<!-- PROMPT:{tag}:START -->(.*?)<!-- PROMPT:{tag}:END -->",
        REPORT.read_text(encoding="utf-8"),
        re.S,
    )
    if not match:
        raise SystemExit(f"报告中缺少 PROMPT:{tag} 标记块")
    return match.group(1)


def _reverse_typography(text: str) -> list[str]:
    """Undo the report-only formatting: bold section titles back to '# 一、…'."""
    out: list[str] = []
    for line in text.splitlines():
        hit = SECTION_RE.match(line.strip())
        out.append(f"# {hit.group(1)}、{hit.group(2)}" if hit else line)
    return out


def _compact(lines: list[str]) -> list[str]:
    return [line.rstrip() for line in lines if line.strip()]


def _source(tag: str) -> list[str]:
    return _compact(prompts.BUILTIN_PROMPTS[{"P0": 0, "P1": 1, "P2": 2}[tag]]["text"].splitlines())


def compare(tag: str) -> tuple[list[tuple[str, str]], int, int]:
    """返回（差异块列表，源码非空行数，空行排版差）。

    差异块按"连续差异段"整体记录：段内多行时以换行连接，避免逐行配对产生噪声。
    """
    source = _source(tag)
    raw_report = _reverse_typography(_report_block(tag))
    shown = _compact(raw_report)

    deltas: list[tuple[str, str]] = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, source, shown).get_opcodes():
        if op == "equal":
            continue
        deltas.append(("\n".join(source[i1:i2]), "\n".join(shown[j1:j2])))

    raw_source = prompts.BUILTIN_PROMPTS[{"P0": 0, "P1": 1, "P2": 2}[tag]]["text"].splitlines()
    blank_delta = (len(raw_report) - len(shown)) - (len(raw_source) - len(source))
    return deltas, len(source), blank_delta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="差异必须等于冻结清单")
    args = parser.parse_args()

    ok = True
    for tag in ("P0", "P1", "P2"):
        deltas, total, blank_delta = compare(tag)
        expected = EXPECTED_DELTAS[tag]
        match = deltas == expected
        ok = ok and match
        print(f"[{tag}] 非空行数 {total}　实质差异 {len(deltas)} 条　空行排版差 {blank_delta} 行"
              f"　{'与冻结清单一致' if match else '与冻结清单不一致'}")
        for src, dst in deltas:
            print(f"    - {(src.splitlines() or [''])[0][:90]}")
            print(f"    + {(dst.splitlines() or ['（报告中缺失）'])[0][:90]}")

    if args.check:
        print("\ncheck: " + ("PASS" if ok else "FAIL"))
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
