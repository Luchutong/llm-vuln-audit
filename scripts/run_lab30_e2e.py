#!/usr/bin/env python3
"""Run one real lab30 audit end to end and score it against the ground truth.

The manual flow is four commands (upload, create run, poll, score) and easy to get
wrong in the middle -- a stale ``prompt_id`` payload is rejected with 422 now that
``CreateRunRequest`` forbids extra fields, and scoring needs the run id that only
the second step prints.  This script does the whole chain and, at the end, calls
``score_dataset.py`` with the run it just produced.

Usage:
    # 全量审计（默认）：穷尽源码中全部漏洞类别，对全量数据集评分
    run_lab30_e2e.py --base http://127.0.0.1:8899 --zip /path/lab30-shop-1.0.0-source.zip
    # 只跑某个分场景（sqli / xss_r / command_injection）
    run_lab30_e2e.py --base http://127.0.0.1:8899 --zip ... --scenario xss_r --max-wait 7200
    # 离线直接对已导出的 findings.json 评分（不起服务、不跑模型）
    run_lab30_e2e.py --offline findings.json --check-severity --check-cvss

A *scenario* run (sqli/xss_r/command_injection) lets the host force
``stop_on_achieved`` off and grade only that class. The default ``all`` run does
not send a scenario, disables stop-on-achieved itself, and asks for every
vulnerability class present in the source; the final score covers the full
dataset rather than one subset.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

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
    "all": (
        "对所选源码做全量白盒漏洞审计，穷尽其中全部可被外部输入触发的漏洞，"
        "不要找到第一处就停止。按以下类别逐类排查并逐条给出原始文件路径与行号证据、"
        "风险等级、触发前提与利用路径："
        "1) SQL 注入（直连拼接、跨文件函数拼接、入库后再拼接的二次注入）；"
        "2) XSS（反射型、存储型、HTML 属性/URL 型注入）；"
        "3) 命令注入（直连 shell 拼接、跨文件函数拼接）；"
        "4) 路径遍历与任意文件读取；5) 本地文件包含与远程文件包含；"
        "6) 代码执行（动态函数调用、模板表达式 eval）；7) 服务端请求伪造 SSRF；"
        "8) XML 外部实体 XXE；9) 跨站请求伪造 CSRF 缺失；10) 不安全反序列化（权益篡改与对象链命令执行）；"
        "11) 越权与 IDOR（对象归属未校验）；12) 认证/授权绕过（信任客户端 Cookie 角色、信任请求头、JWT 未校验签名）；"
        "13) 业务逻辑缺陷（信任客户端单价、提现竞态/重复支付、批量赋值改敏感字段）；"
        "14) 会话固定；15) 弱类型比较绕过；16) 弱密码哈希存储；17) 开放重定向；18) 异常与堆栈信息泄露。"
        "每条结论必须绑定原始源码行号证据，区分已确认漏洞与仅排查无证据的方向。"
    ),
}

# 后端 scenario 字段只接受这三个分场景；all 是本地全量模式，不下发给后端。
SPECIFIC_SCENARIOS = ("sqli", "xss_r", "command_injection")
TERMINAL = {"completed", "unreachable", "inconclusive", "interrupted", "failed", "cancelled",
            "met", "unmet", "stopped", "error"}
SCENARIOS = ("all",) + SPECIFIC_SCENARIOS


def client_for(base: str):
    # httpx is only needed for the online chain; keep the offline scoring path
    # on the standard library so it runs without the backend or its deps.
    import httpx
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
               iterations: int, max_rounds: int, attempts: int, poc_mode: str = "auto") -> dict:
    # ``all`` (or None) is the local full-audit mode: do not send a scenario, and
    # turn off stop-on-achieved ourselves so the planner keeps settling every class.
    specific = scenario if scenario in SPECIFIC_SCENARIOS else None
    task: dict = {
        "objective": objective or OBJECTIVES[specific or "all"],
        "max_iterations": iterations,
        "max_planner_rounds": max_rounds,
        "max_total_attempts": attempts,
        "stop_on_achieved": False,
        "completion_policy": "coverage_review" if specific is None else "goal",
    }
    if specific:
        task["scenario"] = specific
    print(f"[2/4] 创建审计任务（scenario={specific or 'all 全量'}）")
    response = client.post("/api/runs", json={"snapshot_id": snapshot_id, "task": task, "poc_mode": poc_mode})
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
        findings = [f for f in bundle.get("findings") or [] if f.get("finding_kind", f.get("kind")) == "vulnerability"]
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
    findings = [f for f in bundle.get("findings") or [] if f.get("finding_kind", f.get("kind")) == "vulnerability"]
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


def score(run_id: str | None, base: str, scenario: str | None, out: Path,
          *, offline: Path | None = None, check_severity: bool = True, check_cvss: bool = True,
          klass: str | None = None) -> int:
    print()
    print("[4/4] 对数据集评分" + ("（离线 findings）" if offline else ""))
    cmd = [sys.executable, str(ROOT / "scripts" / "score_dataset.py"), "--out", str(out)]
    if offline:
        cmd += ["--findings", str(offline)]
    else:
        cmd += ["--api", base, "--run", run_id]
    specific = scenario if scenario in SPECIFIC_SCENARIOS else None
    if specific:
        cmd += ["--scenario", specific]
    if klass:
        cmd += ["--class", klass]
    if check_severity:
        cmd.append("--check-severity")
    if check_cvss:
        cmd.append("--check-cvss")
    return subprocess.call(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default="http://127.0.0.1:8899", help="审计实例基址")
    parser.add_argument("--zip", default=None, help="靶场源码 zip（离线评分时可省略）")
    parser.add_argument("--scenario", choices=SCENARIOS, default="all",
                        help="审计范围：all 全量（默认）或 sqli/xss_r/command_injection 分场景")
    parser.add_argument("--class", dest="klass", default=None,
                        help="评分时只评某个类别（如 auth_bypass），透传给 score_dataset.py")
    parser.add_argument("--objective", default=None, help="覆盖默认任务目标文案")
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--max-rounds", type=int, default=24)
    parser.add_argument("--attempts", type=int, default=64)
    parser.add_argument("--max-wait", type=int, default=5400, help="最长等待秒数")
    parser.add_argument("--interval", type=int, default=5, help="轮询间隔秒数")
    parser.add_argument("--out", default=None, help="评分明细输出路径")
    parser.add_argument("--no-score", action="store_true", help="只跑审计不评分")
    parser.add_argument("--poc-mode", choices=("off", "auto", "required"), default="auto", help="自动验证策略，默认 auto")
    parser.add_argument("--follow", default=None, help="接入已有 run（跳过上传与创建）")
    parser.add_argument("--offline", default=None,
                        help="离线模式：直接对已导出的 findings.json 评分，不起服务、不跑模型")
    parser.add_argument("--check-severity", action="store_true", help="比较文字等级与 CVSS 基础分等级")
    parser.add_argument("--check-cvss", action="store_true", help="比较 CVSS 基础分与基础向量")
    args = parser.parse_args()

    base = args.base.rstrip("/")
    tag = args.scenario if args.scenario in SPECIFIC_SCENARIOS else "all"
    out = Path(args.out) if args.out else ROOT / "datasets" / "lab30-shop" / f"score_{tag}.json"

    # 离线评分：只调用 score_dataset.py，不连接后端。
    if args.offline:
        if args.no_score:
            print("已跳过评分（--no-score）")
            return 0
        return score(None, base, args.scenario, out, offline=Path(args.offline),
                     check_severity=args.check_severity, check_cvss=args.check_cvss,
                     klass=args.klass)

    if not args.zip and not args.follow:
        parser.error("在线模式需要 --zip 源码包，或使用 --offline findings.json 离线评分")

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
                             args.iterations, args.max_rounds, args.attempts, args.poc_mode)
            run_id = run["id"]

        bundle = poll(client, run_id, args.max_wait, args.interval)
        summarize(bundle)

    if args.no_score:
        print("\n已跳过评分（--no-score）")
        return 0
    return score(run_id, base, args.scenario, out,
                 check_severity=args.check_severity, check_cvss=args.check_cvss, klass=args.klass)


if __name__ == "__main__":
    raise SystemExit(main())
