#!/usr/bin/env python3
"""Run the three lab prompt variants over the 30-challenge lab and score them.

This is a standalone coursework experiment: it reuses the open-findings executor
(``audit.agent.pursue_task_work``) with a caller-supplied instruction, so the same
source-reading, evidence-validation and budget machinery backs P0-lab/P1-lab/P2-lab
without routing through the three-category legacy pipeline.

Scoring is per challenge.  Each challenge file has one planted vulnerability kind in
``demo/lab30/manifest.json``.  For one prompt variant and one challenge:

* TP: a reported finding carries the planted ``kind``;
* FN: the planted ``kind`` was not reported;
* FP: a reported finding carries any other ``kind``.

Usage:
    lab_rounds.py [--prompts P0-lab P1-lab P2-lab] [--limit N]
                  [--responses 24 --tools 32 --seconds 600] [--output path.md]
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import os
import pathlib
import sys
import zipfile

BACKEND = pathlib.Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from audit.agent import pursue_task_work  # noqa: E402
from audit.config import Settings, find_env_file, load_env_file  # noqa: E402
from audit.lab_prompts import (  # noqa: E402
    LAB_KINDS,
    LAB_P0,
    LAB_P1,
    LAB_P2,
    LAB_P0_LITE,
    LAB_P1_LITE,
)
from audit.runtime import AgentPolicy  # noqa: E402
from audit.source import SourceRepository  # noqa: E402

LAB_ROOT = pathlib.Path(__file__).resolve().parents[1] / "demo" / "lab30"
PROMPTS = {
    "P0-lite": LAB_P0_LITE,
    "P1-lite": LAB_P1_LITE,
    "P0": LAB_P0,
    "P1": LAB_P1,
    "P2": LAB_P2,
}
KIND_LABELS = dict(LAB_KINDS)
KIND_SLUGS = tuple(slug for slug, _label in LAB_KINDS)


def build_zip(root: pathlib.Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            # Skip scratch/dot directories such as the runner's local audit data.
            if path.is_file() and not any(part.startswith(".") for part in path.relative_to(root).parts):
                archive.writestr(path.relative_to(root).as_posix(), path.read_bytes())
    return buffer.getvalue()


def challenge_units(snapshot: dict, challenge_file: str) -> list[dict]:
    units = [u for u in snapshot["units"] if u["file_path"] == challenge_file]
    top_level = [u for u in units if u.get("kind") == "top_level"]
    return top_level or units


async def run_one(
    repository: SourceRepository,
    snapshot_id: str,
    snapshot_name: str,
    unit: dict,
    instructions: str,
    config,
    budgets: dict,
) -> dict:
    task = {
        "objective": "找出该源码片段中可被外部输入触发的漏洞并标注其类型。",
        "success_criteria": "至少给出一个由原始行号支撑的漏洞 finding，或说明没有发现漏洞。",
        "require_poc": False,
        "max_iterations": 1,
        "max_total_attempts": 1,
    }
    return await pursue_task_work(
        repository=repository,
        snapshot_id=snapshot_id,
        snapshot_name=snapshot_name,
        unit=unit,
        task=task,
        attempt=1,
        config=config,
        budgets=budgets,
        policy=AgentPolicy(),
        instructions=instructions,
        allowed_kinds=KIND_SLUGS,
    )


def score(challenge: dict, findings: list[dict]) -> dict:
    kinds = [str(item.get("kind") or "").strip() for item in findings]
    planted = challenge["kind"]
    matched = planted in kinds
    tp = 1 if matched else 0
    fn = 0 if matched else 1
    fp = sum(1 for kind in kinds if kind != planted)
    return {"id": challenge["id"], "kind": planted, "difficulty": challenge["difficulty"],
            "tp": tp, "fp": fp, "fn": fn, "reported": kinds,
            "found": matched}


def totals(rows: list[dict]) -> dict:
    tp = sum(row["tp"] for row in rows)
    fp = sum(row["fp"] for row in rows)
    fn = sum(row["fn"] for row in rows)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
    }


def render_markdown(prompt_rows: dict[str, list[dict]]) -> str:
    lines = ["# 实验室 30 题：提示词对照", ""]
    lines.append("每行是某一提示词版本在一道题上的判定结果。TP=命中植入类型，FP=误报其他类型，FN=漏报。")
    lines.append("")
    lines.append("| 版本 | 题目 | 类型 | 难度 | 命中 | 误报数 | 漏报 | 报告类型 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for prompt_id, rows in prompt_rows.items():
        for row in rows:
            lines.append(
                f"| {prompt_id} | {row['id']} | {KIND_LABELS.get(row['kind'], row['kind'])} "
                f"| {row['difficulty']} | {'是' if row['tp'] else '否'} | {row['fp']} "
                f"| {row['fn']} | {', '.join(row['reported']) or '—'} |"
            )
    lines.append("")
    lines.append("| 版本 | TP | FP | FN | Precision | Recall |")
    lines.append("|---|---|---|---|---|---|")
    for prompt_id, rows in prompt_rows.items():
        total = totals(rows)
        lines.append(
            f"| {prompt_id} | {total['tp']} | {total['fp']} | {total['fn']} "
            f"| {total['precision']:.3f} | {total['recall']:.3f} |"
        )
    lines.append("")
    lines.append("> 结论边界：本表是一次顺序运行的描述性结果。30 道题来自同一自建样例集，样本量小、")
    lines.append("> 标签经源码核验而非动态 POC 实测，不能据此推断总体准确率或统计显著性。")
    return "\n".join(lines) + "\n"


async def main_async(args) -> int:
    manifest = json.loads((LAB_ROOT / "manifest.json").read_text(encoding="utf-8"))
    challenges = manifest["challenges"][: args.limit] if args.limit else manifest["challenges"]

    env_file = find_env_file(BACKEND)
    if env_file is not None:
        load_env_file(env_file)
    # Import staging writes PHP files under the snapshot directory.  Antivirus can
    # lock those files outside the lab's trusted zone, so default the data dir to a
    # location inside demo/lab30; an explicit AUDIT_DATA_DIR still wins.
    os.environ.setdefault("AUDIT_DATA_DIR", str(LAB_ROOT / ".audit-data"))
    settings = Settings.load()
    if not settings.model.configured:
        raise SystemExit("后端尚未配置模型。请先设置模型名称、兼容 API 地址和密钥。")

    repository = SourceRepository(settings.data_dir)
    data = build_zip(LAB_ROOT)
    snapshot = repository.import_zip(data, "lab30-benchmark.zip")
    print(f"快照：{snapshot['id']}（{len(snapshot['units'])} 个审计单元）")
    print(f"模型：{settings.model.label}; 预算：{args.budgets}")
    print(f"题目：{len(challenges)} 道；版本：{args.prompts}")

    prompt_rows: dict[str, list[dict]] = {}
    for prompt_id in args.prompts:
        rows: list[dict] = []
        for challenge in challenges:
            units = challenge_units(snapshot, challenge["file"])
            if not units:
                print(f"  {prompt_id} {challenge['id']}: 没有可审计单元，跳过")
                rows.append({"id": challenge["id"], "kind": challenge["kind"],
                             "difficulty": challenge["difficulty"], "tp": 0, "fp": 0, "fn": 1,
                             "reported": [], "found": False})
                continue
            try:
                outcome = await run_one(
                    repository, snapshot["id"], snapshot["name"], units[0],
                    PROMPTS[prompt_id], settings.model, args.budgets,
                )
                findings = (outcome.get("result") or {}).get("findings") or []
                row = score(challenge, findings)
                rows.append(row)
                status = "命中" if row["tp"] else ("漏报" if not row["reported"] else "误报")
                usage = outcome.get("usage") or {}
                print(f"  {prompt_id} {challenge['id']} {challenge['kind']}: {status} "
                      f"tokens={usage.get('input_tokens', 0) + usage.get('output_tokens', 0)}")
            except Exception as exc:  # a failed call must not abort the whole experiment
                rows.append({"id": challenge["id"], "kind": challenge["kind"],
                             "difficulty": challenge["difficulty"], "tp": 0, "fp": 0, "fn": 1,
                             "reported": [], "found": False})
                print(f"  {prompt_id} {challenge['id']}: 执行失败 {type(exc).__name__}: {str(exc)[:160]}")
        prompt_rows[prompt_id] = rows

    markdown = render_markdown(prompt_rows)
    output = args.output or pathlib.Path(__file__).resolve().parents[1] / "deliverable" / "lab30-report.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    print(f"\n报告：{output}")
    print(markdown)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompts", nargs="*", choices=tuple(PROMPTS), default=["P0-lite", "P1-lite", "P0", "P1", "P2"])
    parser.add_argument("--limit", type=int, default=0, help="只跑前 N 道题（0 表示全部）")
    parser.add_argument("--responses", type=int, default=24)
    parser.add_argument("--tools", type=int, default=32)
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--output", type=pathlib.Path, default=None)
    args = parser.parse_args(argv)
    args.budgets = {"responses": args.responses, "tools": args.tools, "seconds": args.seconds}
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
