#!/usr/bin/env python3
"""Run one real lab30 audit end to end and score it against the ground truth.

The manual flow is four commands (upload, create run, poll, score) and easy to get
wrong in the middle -- a stale ``prompt_id`` payload is rejected with 422 now that
``CreateRunRequest`` forbids extra fields, and scoring needs the run id that only
the second step prints.  This script does the whole chain and, at the end, calls
``score_dataset.py`` with the run it just produced.

Usage:
    run_lab30_e2e.py --base http://127.0.0.1:8899 --zip /path/lab30-shop-1.0.0-source.zip
    run_lab30_e2e.py --base http://127.0.0.1:8899 --zip ... --scenario xss_r --max-wait 7200

The run is a *scenario* run when ``--scenario`` is given: the host then forces
``stop_on_achieved`` off and only lets the goal be marked met once every direction
of that vulnerability class has been settled, which is what the ground truth scores.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]

# Objectives are deliberately multi-clause: the backend rejects vague task text, and a
# scenario run is graded on coverage, so the wording asks for every instance, not a sample.
OBJECTIVES = {
    "sqli": (
        "审计所选源码中所有 SQL 注入风险：逐个检查进入数据库查询的拼接点，"
        "包括搜索、筛选、排序、登录与详情参数，必须穷尽全部可利用入口，"
        "每条结论给出原始文件路径与行号证据、风险等级与触发条件。"
    ),
    "xss_r": (
        "审计所选源码中所有反射型 XSS 风险：逐个检查把请求参数原样输出到页面的位置，"
        "包括搜索回显、错误提示、跳转参数，必须穷尽全部可利用入口，"
        "每条结论给出原始文件路径与行号证据、风险等级与触发条件。"
    ),
    "command_injection": (
        "审计所选源码中所有命令注入风险：逐个检查把外部输入拼进系统命令调用的位置，"
        "包括诊断、导出、转换类功能，必须穷尽全部可利用入口，"
        "每条结论给出原始文件路径与行号证据、风险等级与触发条件。"
    ),
}

TERMINAL = {"met", "unmet", "failed", "cancelled", "stopped", "error"}
SCENARIOS = tuple(OBJECTIVES)


def client_for(base: str) -> httpx.Client:
    # trust_env=False: the system proxy answers 502 for 127.0.0.1 and would hide a
    # healthy local service behind a fake network error.
    return httpx.Client(base_url=base.rstrip("/"), timeout=300.0, trust_env=False)


def upload(client: httpx.Client, archive: Path) -> dict:
    print(f"[1/4] 上传快照: {archive.name} ({archive.stat().st_size / 1024:.0f} KB)")
    with archive.open("rb") as handle:
        response = client.post(
            "/api/snapshots",
            files={"file": (archive.name, handle, "application/zip")},
        )
    if response.status_code >= 400:
        sys.exit(f"    上传失败 {response.status_code}: {response.text[:400]}")
    snapshot = response.json()
    readable = [f for f in snapshot["files"] if not f.get("excluded")]
    print(f"    快照 {snapshot['id'][:8]} · 文件 {len(snapshot['files'])} 个（可读 {len(readable)}）")
    if snapshot.get("warnings"):
        for warning in snapshot["warnings"][:3]:
            print(f"    警告: {warning}")
    return snapshot


def create_run(client: httpx.Client, snapshot_id: str, scenario: str | None, objective: str | None,
               iterations: int, max_rounds: int, attempts: int) -> dict:
    task: dict = {
        "objective": objective or OBJECTIVES[scenario or "sqli"],
        "max_iterations": iterations,
        "max_planner_rounds": max_rounds,
        "max_total_attempts": attempts,
    }
    if scenario:
        task["scenario"] = scenario
    print(f"[2/4] 创建审计任务（scenario={scenario or '未指定'}）")
    response = client.post("/api/runs", json={"snapshot_id": snapshot_id, "task": task})
    if response.status_code >= 400:
        sys.exit(f"    创建失败 {response.status_code}: {response.text[:600]}")
    run = response.json()
    print(f"    run {run['id'][:8]} · 模型 {run.get('model')} · 预算 {run.get('budgets')}")
    return run


def poll(client: httpx.Client, run_id: str, max_wait: int, interval: int) -> dict:
    print(f"[3/4] 等待审计完成（最多 {max_wait}s，每 {interval}s 刷新）")
    started = time.time()
    last = ""
    while True:
        bundle = client.get(f"/api/runs/{run_id}").json()
        run = bundle["run"]
        findings = [f for f in bundle.get("findings") or [] if f.get("kind") == "vulnerability"]
        goal = bundle.get("goal") or {}
        line = (
            f"    {run['status']:<10} 单元 {run.get('completed_units')}/{run.get('total_units')}"
            f" · 漏洞 {len(findings)} · 目标 {goal.get('status', '—')} · {int(time.time() - started)}s"
        )
        if line != last:
            print(line, flush=True)
            last = line
        if run["status"] in TERMINAL:
            return bundle
        if time.time() - started > max_wait:
            print(f"    超时：{max_wait}s 内未结束，run {run_id[:8]} 仍在 {run['status']}（可用 --follow 续看）")
            return bundle
        time.sleep(interval)


def summarize(bundle: dict) -> None:
    run = bundle["run"]
    findings = [f for f in bundle.get("findings") or [] if f.get("kind") == "vulnerability"]
    print()
    print(f"结果: {run['status']} · 目标 {((bundle.get('goal') or {}).get('status')) or '—'}"
          f" · 漏洞候选 {len(findings)} 条")
    if run.get("error"):
        print(f"运行错误: {run['error'][:500]}")
    for finding in findings[:20]:
        evidence = "; ".join(
            f"{ref.get('path')}:{ref.get('start_line')}-{ref.get('end_line')}"
            for ref in (finding.get("evidence") or [])
            if ref.get("path")
        )
        print(f"  [{finding.get('severity', '?')}] {finding.get('title', '')[:60]}  {evidence[:110]}")
    if len(findings) > 20:
        print(f"  …… 其余 {len(findings) - 20} 条见 run 详情")


def score(run_id: str, base: str, scenario: str | None, out: Path) -> int:
    print()
    print("[4/4] 对数据集评分")
    cmd = [
        sys.executable, str(ROOT / "scripts" / "score_dataset.py"),
        "--api", base, "--run", run_id, "--out", str(out),
    ]
    if scenario:
        cmd += ["--scenario", scenario]
    return subprocess.call(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default="http://127.0.0.1:8899", help="审计实例基址")
    parser.add_argument("--zip", required=True, help="靶场源码 zip")
    parser.add_argument("--scenario", choices=SCENARIOS, default="sqli", help="只跑某个漏洞类（默认 sqli）")
    parser.add_argument("--objective", default=None, help="覆盖默认任务目标文案")
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--max-rounds", type=int, default=24)
    parser.add_argument("--attempts", type=int, default=64)
    parser.add_argument("--max-wait", type=int, default=5400, help="最长等待秒数")
    parser.add_argument("--interval", type=int, default=5, help="轮询间隔秒数")
    parser.add_argument("--out", default=None, help="评分明细输出路径")
    parser.add_argument("--no-score", action="store_true", help="只跑审计不评分")
    parser.add_argument("--follow", default=None, help="接入已有 run（跳过上传与创建）")
    args = parser.parse_args()

    base = args.base.rstrip("/")
    out = Path(args.out) if args.out else ROOT / "datasets" / "lab30-shop" / f"score_{args.scenario or 'all'}.json"

    with client_for(base) as client:
        try:
            client.get("/api/prompts").raise_for_status()
        except Exception as exc:  # noqa: BLE001 - any failure here means "not reachable"
            sys.exit(f"连不上 {base}: {exc}\n先启动后端：docker compose up -d，或 bash scripts/start.sh")

        if args.follow:
            run_id = args.follow
            print(f"[1/4] 跳过上传，接入已有 run {run_id[:8]}")
            print("[2/4] 跳过创建")
        else:
            snapshot = upload(client, Path(args.zip))
            run = create_run(client, snapshot["id"], args.scenario, args.objective,
                             args.iterations, args.max_rounds, args.attempts)
            run_id = run["id"]

        bundle = poll(client, run_id, args.max_wait, args.interval)
        summarize(bundle)

    if args.no_score:
        print("\n已跳过评分（--no-score）")
        return 0
    return score(run_id, base, args.scenario, out)


if __name__ == "__main__":
    raise SystemExit(main())
