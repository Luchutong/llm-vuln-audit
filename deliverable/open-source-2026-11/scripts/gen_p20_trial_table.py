#!/usr/bin/env python3
"""Generate the P20 prompt-comparison tables from the frozen summary JSON.

Reads the checked-in archive (no model calls, no services) and emits a Markdown
document with: 9 trial rows, 3 strategy summary rows, class coverage appendix and
the significance statement required by the report's 5.4.3 section.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deliverable/lab30-validation-2026-10-26/03-prompt-comparison/summary.json"
TARGET = ROOT / "deliverable/open-source-2026-11/data/P20_九试次明细.md"

ORDER = ["worker-w0-v1", "worker-w1-v1", "worker-w2-v1"]
SHORT = {"worker-w0-v1": "W0", "worker-w1-v1": "W1", "worker-w2-v1": "W2"}
PERCENT = {"precision", "recall", "f1"}


def fmt(key: str, value: float) -> str:
    if key in PERCENT:
        return f"{value * 100:.2f}%"
    if key in {"cvss_mae"}:
        return f"{value:.3f}"
    if key in {"TP", "D", "U", "FP", "FN", "requests", "tool_calls"}:
        return f"{value:.0f}"
    if key in {"total_tokens", "input_tokens", "output_tokens"}:
        return f"{value:,.0f}"
    if key == "duration_seconds":
        return f"{value:.0f}s"
    return f"{value:.4f}"


def main() -> int:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    variants = {v["id"]: v for v in data["variants"]}
    rounds = data["complete_rounds"]
    n = len(rounds)

    lines: list[str] = []
    add = lines.append

    add("# P20 九试次逐次明细与三策略汇总")
    add("")
    add("> 数据来源：`deliverable/lab30-validation-2026-10-26/03-prompt-comparison/summary.json`")
    add(f"> 协议：`{data['protocol']}`（基线 `{data['baseline_prompt_id']}`，重复 {data['repeats']} 轮，"
        f"完整轮次 {data['complete_round_count']}/{data['repeats']}，preliminary={str(data['preliminary']).lower()}）")
    add("> 生成方式：`python scripts/gen_p20_trial_table.py`（纯本地读取归档，无模型调用、无服务依赖）")
    add("> 采集日期：2026-11-07（数据冻结于 2026-10-27 实验完成时）")
    add("")

    add("## 1. 九试次逐次明细")
    add("")
    add("| 试次 | 策略 | 轮次 | TP | D | U | FP | FN | Precision | Recall | F1 | 请求 | tokens | 耗时 |")
    add("| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    index = 0
    for vid in ORDER:
        metrics = variants[vid]["metrics"]
        for i, rnd in enumerate(rounds):
            index += 1
            row = [str(index), SHORT[vid], str(rnd)]
            for key in ("TP", "D", "U", "FP", "FN", "precision", "recall", "f1",
                        "requests", "total_tokens", "duration_seconds"):
                row.append(fmt(key, metrics[key]["values"][i]))
            add("| " + " | ".join(row) + " |")
    add("")

    add("## 2. 三策略汇总（mean ± 样本标准差，n=3）")
    add("")
    add("| 策略 | 全称 | TP | D | U | FP | FN | Precision | Recall | F1 | 平均请求 | 平均 tokens | 平均耗时 | CVSS MAE |")
    add("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for vid in ORDER:
        v = variants[vid]
        m = v["metrics"]

        def cell(key: str) -> str:
            return f"{fmt(key, m[key]['mean'])} ± {fmt(key, m[key]['sample_std'])}"

        add("| " + " | ".join([
            SHORT[vid], v["label"],
            cell("TP"), cell("D"), cell("U"), cell("FP"), cell("FN"),
            cell("precision"), cell("recall"), cell("f1"),
            cell("requests"), cell("total_tokens"), cell("duration_seconds"), cell("cvss_mae"),
        ]) + " |")
    add("")

    add("## 3. 总量核对")
    add("")
    usage = data["actual_total_usage"]
    add("| 指标 | 合计 | 说明 |")
    add("| --- | ---: | --- |")
    add(f"| 请求 | {usage['requests']['total']} | 9 个试次全部已知 |")
    add(f"| 工具调用 | {usage['tool_calls']['total']} | 同上 |")
    add(f"| 输入 tokens | {usage['input_tokens']['total']:,} | 同上 |")
    add(f"| 输出 tokens | {usage['output_tokens']['total']:,} | 同上 |")
    add(f"| 总 tokens | {usage['total_tokens']['total']:,} | 报告 5.4.3 与 10.1 引用此值 |")
    add("")

    add("## 4. 显著性口径（报告照抄，勿加码）")
    add("")
    add("> 每个策略仅 3 次重复，样本量不足以支撑显著性检验。本文仅报告均值与样本标准差，"
        "不宣称策略间差异具有统计显著性；W0 为基线，W1 相对 W0 的 F1 差值为 −4.0pp、"
        "W2 为 −10.2pp，均落在各自样本波动范围内。W2 呈现\"高精确、低召回、高方差\"特征"
        "（P 83.1%、R 64.4%、F1 SD 18.4%），W1 以多约 19% 的请求量换取更好的 CVSS 覆盖率而非更高检出率。")
    add("")
    add(f"> 指标口径说明（引自归档）：{data['interpretation']}")
    add("")

    add("## 5. 附录：类别覆盖（22 类 × 3 策略）")
    add("")
    header = "| 漏洞类别 | 真值数 | " + " | ".join(f"{SHORT[v]} 命中/总数" for v in ORDER) + " |"
    add(header)
    add("| --- | ---: | ---: | ---: | ---: |")
    for entry in data["class_coverage"]:
        cells = []
        for vid in ORDER:
            cov = entry["variants"][vid]
            cells.append(f"{cov['detected']}/{cov['total']}（{cov['recall'] * 100:.0f}%）")
        add(f"| {entry['class']} | {entry['total']} | " + " | ".join(cells) + " |")
    add("")

    add("---")
    add("")
    add("复核命令：")
    add("")
    add("```bash")
    add("python scripts/gen_p20_trial_table.py")
    add("# 逐字核对原始值")
    add("python -c \"import json;d=json.load(open('deliverable/lab30-validation-2026-10-26/03-prompt-comparison/summary.json',encoding='utf-8'));"
        "[print(v['id'],v['metrics']['f1']['values']) for v in d['variants']]\"")
    add("```")

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"written: {TARGET.relative_to(ROOT)}  ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
