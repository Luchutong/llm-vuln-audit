#!/usr/bin/env python3
"""Check that the exported report actually carries the two optimisation rounds.

The comparison is the part of the deliverable that cannot be checked by unit tests alone:
it depends on runs that exist in a live database, on the export endpoint, and on the two
views of the same numbers — the Markdown a reader gets and the JSON they would recompute
from — agreeing with each other.

Usage: verify_rounds.py <base-url> [prompt-id ...]     (default: P0 P1 P2)
"""
import json
import re
import sys

import httpx

REQUIRED_HEADINGS = [
    "## 1. ",
    "## 2. ",
    "## 3. ",
    "## 4. ",
    "### 4.2 Prompt 提示词工程模块",
    "#### 4.2.1 优化轮次与对比",
    "## 5. ",
    "## 6. ",
    "### 6.1 ",
    "### 6.2 ",
    "### 6.3 ",
    "### 6.4 ",
    "### 6.5 ",
    "### 6.6 ",
    "### 6.7 ",
]

MATRIX = re.compile(r"混淆矩阵：TP=(\d+)、FP=(\d+)、FN=(\d+)、TN=(\d+)")


def newest_by_prompt(runs: list[dict], wanted: list[str]) -> dict[str, dict]:
    """The newest run of each version — the same collapsing rule the report uses.

    Without it a re-run of P2 would be taken as a fourth round, and the comparison would
    quietly become "the latest attempt against the others".
    """
    newest: dict[str, dict] = {}
    for run in runs:
        if run["prompt_id"] not in wanted:
            continue
        known = newest.get(run["prompt_id"])
        if known is None or run["created_at"] > known["created_at"]:
            newest[run["prompt_id"]] = run
    return newest


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        raise SystemExit(__doc__)
    base = argv[1].rstrip("/")
    wanted = argv[2:] or ["P0", "P1", "P2"]
    failures: list[str] = []

    with httpx.Client(base_url=base, timeout=60) as client:
        picked = newest_by_prompt(client.get("/api/runs").raise_for_status().json(), wanted)
        missing = [pid for pid in wanted if pid not in picked]
        if missing:
            # Not a failure of the export: the rounds have not been run yet. Say which ones
            # are absent and stop, rather than reporting the comparison as broken.
            print(f"这些版本还没有运行记录，无法对比：{missing}")
            return 1

        order = sorted(picked.values(), key=lambda run: run["created_at"])
        for run in order:
            print(
                f"  {run['prompt_id']:<4} {run['status']:<10} {run['id'][:8]}  "
                f"{run['completed_units']}/{run['total_units']} units  {run['created_at'][:19]}"
            )
        last = order[-1]

        experiment = client.get(
            "/api/experiments", params={"run_ids": ",".join(run["id"] for run in order)}
        ).raise_for_status().json()
        print(f"\ncomparable={experiment['comparable']}  reasons={experiment['reasons']}")
        for note in experiment.get("notes", []):
            print(f"注意：{note}")
        if len(experiment["runs"]) != len(order):
            failures.append(f"实验对比返回 {len(experiment['runs'])} 行，期望 {len(order)} 行")
        paired = experiment.get("paired_comparisons") or []
        if len(paired) != max(0, len(order) - 1):
            failures.append(
                f"同样本配对比较返回 {len(paired)} 行，期望 {max(0, len(order) - 1)} 行"
            )
        for comparison in paired:
            values = comparison.get("delta_percentage_points") or {}
            if comparison.get("comparable"):
                if comparison.get("common_samples", 0) < 1:
                    failures.append(
                        f"{comparison.get('baseline_prompt_id')}→{comparison.get('prompt_id')} "
                        "标为可比较但没有共同样本"
                    )
            elif any(value is not None for value in values.values()):
                failures.append(
                    f"{comparison.get('baseline_prompt_id')}→{comparison.get('prompt_id')} "
                    "不可比较却报告了提升数值"
                )
        if not experiment["comparable"]:
            # The spec only allows claiming an improvement under one snapshot, scope, model
            # and budget. That is a finding about the runs, not a broken export — report it
            # and keep checking the export, which must still render honestly.
            print("注：这些运行不满足可比条件，报告应显式说明而不是照常给出结论。")

        markdown = client.get(f"/api/runs/{last['id']}/report", params={"format": "markdown"})
        markdown.raise_for_status()
        doc = markdown.text
        for heading in REQUIRED_HEADINGS:
            if f"\n{heading}" not in doc:
                failures.append(f"Markdown 缺少章节：{heading}")
        if re.search(r"\|\s*None\s*\|", doc):
            failures.append("Markdown 里出现了字面量 None，指标缺失应写成无法计算")
        if doc.count("| Prompt 版本 |") != 1:
            failures.append("4.2.1 的轮次对比表没有恰好在预期位置出现一次")
        if paired and "同样本配对比较（相对基线 " not in doc:
            failures.append("Markdown 缺少同样本配对比较表")
        # Only the table itself will do: a prompt id also appears in 4.2's version list, so
        # searching the whole chapter would pass even with the rounds table missing.
        section = doc.split("#### 4.2.1", 1)[1].split("\n### ", 1)[0] if "#### 4.2.1" in doc else ""
        for pid in wanted:
            if f"| {pid}" not in section and f"（`{pid}`）" not in section:
                failures.append(f"4.2.1 的对比表里没有 {pid}")

        bundle = client.get(f"/api/runs/{last['id']}/report", params={"format": "json"})
        bundle.raise_for_status()
        data = bundle.json()
        rounds = data.get("rounds") or {}
        if len(rounds.get("runs") or []) != len(order):
            failures.append("result.json 的 rounds 行数与实验对比不一致")
        if len(rounds.get("paired_comparisons") or []) != len(paired):
            failures.append("result.json 的同样本配对比较行数与实验 API 不一致")
        if [entry["run"]["prompt_id"] for entry in rounds.get("runs", [])] != [
            run["prompt_id"] for run in order
        ]:
            failures.append("result.json 的 rounds 顺序与运行时间顺序不一致")
        if not data.get("truths"):
            failures.append("result.json 缺少真值集，统计无法复算")

        # The Markdown is the human-readable view and the JSON is the machine-readable one;
        # if the matrix differs between them, one of the two is wrong and the reader cannot
        # tell which. This is the cheapest possible cross-check of that.
        match = MATRIX.search(doc)
        evaluation = (data.get("metrics") or {}).get("evaluation")
        if match is None:
            failures.append("Markdown 里找不到混淆矩阵，无法与 result.json 对照")
        elif evaluation is None:
            if "无法计算" not in doc:
                failures.append("没有可计算的混淆矩阵，但 Markdown 没有写明无法计算")
        else:
            printed = tuple(int(value) for value in match.groups())
            stored = (evaluation["TP"], evaluation["FP"], evaluation["FN"], evaluation["TN"])
            if printed != stored:
                failures.append(f"Markdown 混淆矩阵 {printed} 与 result.json {stored} 不一致")
            print(
                f"\n最新一轮（{last['prompt_id']}）混淆矩阵 TP/FP/FN/TN = {stored}，"
                f"未决样本 {len(evaluation['unresolved'])} 个"
            )

    if failures:
        print("\n失败：")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("\n通过：两轮优化对比在 Markdown 与 result.json 中一致。")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
