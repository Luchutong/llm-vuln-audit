#!/usr/bin/env python3
"""Run one real lab30 audit end to end and score it against the ground truth.

The manual flow is four commands (upload, create run, poll, score) and easy to get
wrong in the middle -- a stale ``prompt_id`` payload is rejected with 422 now that
``CreateRunRequest`` forbids extra fields, and scoring needs the run id that only
the second step prints.  This script does the whole chain and, at the end, calls
``score_dataset.py`` with the run it just produced.

Usage:
    # 闭环验收（POC auto + 覆盖复核收束 + 前后复位靶场 + v2 评分）
    run_lab30_e2e.py --zip /path/lab30-shop-1.0.0-source.zip --closure
    # 闭环验收 + 放宽预算与阶段配额（整轮 1600 次请求，阶段 1230/250/120）
    run_lab30_e2e.py --zip /path/lab30-shop-1.0.0-source.zip --closure
        --run-limit responses=1600 --run-limit tools=12000 --run-limit seconds=14400
        --stage-limit discovery=1230 --stage-limit poc=250 --stage-limit review=120
        --max-rounds 96 --attempts 192 --max-wait 18000
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

# The closure profile is the one configuration the project's acceptance run uses.  Its
# budgets are ceilings, not targets: the previous full run spent 54 of 256 responses, so
# raising the ceiling costs nothing unless the Planner actually needs the room.
CLOSURE_BUDGETS = {"responses": 40, "tools": 160, "seconds": 3600}
CLOSURE_LIMITS = {"responses": 1024, "tools": 8192, "seconds": 5400}
CLOSURE_TASK = {
    "max_iterations": 5,
    "max_planner_rounds": 32,
    "max_total_attempts": 96,
    "max_workers": 2,
    "baseline_policy": "fresh",
}
DEFAULT_HISTORY_BYTES = 384 * 1024



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
               iterations: int, max_rounds: int, attempts: int, poc_mode: str = "auto",
               *, closure: bool = False, budgets: dict | None = None, limits: dict | None = None,
               quotas: dict | None = None, task_overrides: dict | None = None) -> dict:
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
    payload: dict = {"snapshot_id": snapshot_id, "task": task, "poc_mode": poc_mode}
    if closure:
        # A closure run must not inherit the project's historical findings and must
        # have room for the coverage review the acceptance criteria require. Explicit
        # operator overrides win over the profile so a run can be given more room.
        task.update(CLOSURE_TASK)
        task.update(task_overrides or {})
        task["completion_policy"] = "coverage_review"
        task["stop_on_achieved"] = False
        payload["budgets"] = {**CLOSURE_BUDGETS, **(budgets or {})}
        payload["run_limits"] = {**CLOSURE_LIMITS, **(limits or {})}
    else:
        if budgets:
            payload["budgets"] = {**budgets}
        if limits:
            payload["run_limits"] = {**limits}
    if quotas:
        # Explicit stage quotas are only accepted for the discovery-first workflow,
        # which ``coverage_review`` selects (and the API validates).
        task["workflow_limits"] = dict(quotas)
    print(f"[2/4] 创建审计任务（scenario={specific or 'all 全量'}{' · 闭环档' if closure else ''}）")
    response = client.post("/api/runs", json=payload)
    if response.status_code >= 400:
        sys.exit(f"    创建失败 {response.status_code}: {response.text[:600]}")
    run = response.json()
    print(f"    run {run['id'][:8]} · 模型 {run.get('model')} · 预算 {run.get('budgets')}")
    workflow = (run.get("execution_summary") or {}).get("workflow") or {}
    if workflow.get("limits"):
        print(f"    整次上限 {run.get('run_limits')} · 阶段配额 {workflow['limits']}（{workflow.get('source')}）")
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


def reset_target(label: str = "复位", *, strict: bool = True) -> dict | None:
    """Reset Lab30 through the host script and prove the seed accounts came back.

    The audit host, not the ``poc_runner``, owns the target: the runner refuses
    ``reset=True`` and this script's only reset path is the documented shell script.
    Refusing to start a closure run against a polluted target is the point -- a POC from
    the previous day can leave ``alice`` an administrator and every member finding then
    fails its preconditions before the model has done anything wrong.
    """
    script = ROOT / "scripts" / "reset_lab30.sh"
    print(f"[0/4] {label} Lab30 并核对种子账号")

    def fail(message: str) -> None:
        if strict:
            sys.exit(message)
        print(message)
        return None

    if not script.is_file():
        return fail(f"    未找到 {script}")
    try:
        proc = subprocess.run([str(script)], capture_output=True, text=True, timeout=240)
    except subprocess.TimeoutExpired:
        return fail("    复位脚本 240s 内未返回，已终止")
    payload: dict = {}
    for line in reversed((proc.stdout or "").strip().splitlines()):
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        break
    if proc.returncode != 0 or not payload.get("ok"):
        detail = payload.get("error") or payload.get("detail") or (proc.stderr or proc.stdout or "")[-400:]
        return fail(f"    复位失败（退出码 {proc.returncode}）：{detail}")
    accounts = payload.get("accounts") or []
    print(f"    种子已核对：{len(accounts)} 个账号 · 偏差 0")
    return payload


def closure_config(client: httpx.Client) -> dict:
    """Refuse to start a closure run whose backend cannot reset or compress."""
    config = client.get("/api/config").json()
    poc = config.get("poc") or {}
    if not poc.get("reset_between_findings"):
        sys.exit("闭环要求 poc.reset_between_findings=true：请用 ./scripts/start.sh --poc 启动后端"
                 "（或显式设置 POC_RESET_BETWEEN_FINDINGS=1）")
    if not poc.get("reset_command_configured"):
        sys.exit("闭环要求服务端配置 POC_LAB30_RESET_COMMAND（start.sh --poc 默认指向 scripts/reset_lab30.sh）")
    policy = config.get("agent_policy") or {}
    if policy.get("history_summary") is not True:
        sys.exit("闭环要求启用 LLM 摘要压缩（AUDIT_HISTORY_SUMMARY=1）")
    history_bytes = int(policy.get("history_bytes") or 0)
    if history_bytes != DEFAULT_HISTORY_BYTES:
        print(f"    注意：agent_policy.history_bytes={history_bytes}，默认基线为 {DEFAULT_HISTORY_BYTES}")
    return config


def collect_events(client: httpx.Client, run_id: str) -> list[dict]:
    """Page through the durable event log; the closure report counts events, not guesses."""
    events: list[dict] = []
    after = 0
    while True:
        page = client.get(f"/api/runs/{run_id}/event-log", params={"after": after}).json()
        batch = page.get("events") or []
        events.extend(batch)
        if not batch or not page.get("remaining"):
            return events
        after = int(batch[-1]["id"])


def closure_metrics(bundle: dict, events: list[dict], config: dict, *, seed: dict | None) -> dict:
    """The acceptance facts for one run, read from durable state only."""
    run = bundle["run"]
    summary = run.get("execution_summary") or {}
    kinds: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for event in events:
        kind = event.get("kind") or ""
        kinds[kind] = kinds.get(kind, 0) + 1
        if kind == "poc_verification_recorded":
            payload = event.get("payload") or {}
            verdict = str(payload.get("verdict") or "unknown")
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
            status = str(payload.get("execution_status") or "unknown")
            statuses[status] = statuses.get(status, 0) + 1
    context = summary.get("context") or {}
    history_bytes = int((config.get("agent_policy") or {}).get("history_bytes") or 0)
    peak = int(context.get("peak_request_bytes") or 0)
    poc_policy = run.get("poc_policy") or {}
    coverage = summary.get("coverage_review") or {}
    return {
        "run_id": run["id"],
        "status": run.get("status"),
        "stop_reason": summary.get("stop_reason"),
        "coverage": {
            "complete": coverage.get("complete"),
            "total": coverage.get("total"),
            "pending_total": coverage.get("pending_total"),
            "read_paths": len(coverage.get("read_paths") or []),
            "reviewed_paths": len(coverage.get("reviewed_paths") or []),
        },
        "poc": {
            "jobs": kinds.get("poc_job_finished", 0),
            "resets": kinds.get("poc_target_reset", 0),
            "reset_failures": kinds.get("poc_target_reset_failed", 0),
            "recorded": kinds.get("poc_verification_recorded", 0),
            "verdicts": verdicts,
            "execution_statuses": statuses,
            "confirmed": int(verdicts.get("confirmed", 0)),
            "authentication_failed": statuses.get("authentication_failed", 0),
            "state_mismatch": statuses.get("state_mismatch", 0),
            "auth_events": kinds.get("poc_authentication_failed", 0),
            "reset_between_findings": bool(poc_policy.get("reset_between_findings")),
            "seed_verified": bool(seed and seed.get("ok")),
            "seed_accounts": len((seed or {}).get("accounts") or []),
        },
        "context": {
            "history_bytes": history_bytes,
            "peak_request_bytes": peak,
            "peak_ratio": round(peak / history_bytes, 4) if history_bytes else None,
            "summary_requests": int(context.get("summary_requests") or 0),
            "compactions": int(context.get("compactions") or 0),
            "history_limit_hits": int(context.get("limit_hits") or 0),
            "sources": context.get("sources") or {},
        },
        "usage": summary.get("run_usage") or {},
        "events": len(events),
    }


def fetch_report(client: httpx.Client, run_id: str, path: Path) -> Path | None:
    response = client.get(f"/api/runs/{run_id}/report")
    if response.status_code >= 400:
        print(f"    报告获取失败 {response.status_code}: {response.text[:200]}")
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(response.text, encoding="utf-8")
    print(f"    Markdown 报告已写入: {path}")
    return path


def commit_sha() -> str:
    try:
        return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def closure_problems(closure: dict, score_code: int) -> list[str]:
    """Every acceptance condition that is false, in the order a reader checks them."""
    problems: list[str] = []
    if closure.get("status") == "failed":
        problems.append("run 状态为 failed")
    coverage = closure.get("coverage") or {}
    if coverage.get("complete") is not True:
        problems.append(f"覆盖复核未完成（pending {coverage.get('pending_total')}）")
    poc = closure.get("poc") or {}
    if int(poc.get("jobs") or 0) <= 0:
        problems.append("没有 POC 作业")
    if not poc.get("reset_between_findings"):
        problems.append("run 未冻结 reset_between_findings")
    if not poc.get("seed_verified"):
        problems.append("开跑前未验证种子账号")
    if int(poc.get("authentication_failed") or 0) > 0:
        problems.append(f"POC 认证失败 {poc['authentication_failed']} 条")
    context = closure.get("context") or {}
    if int(context.get("history_limit_hits") or 0) > 0:
        problems.append(f"上下文历史超限 {context['history_limit_hits']} 次")
    if score_code != 0:
        problems.append(f"评分脚本退出码 {score_code}")
    return problems


def read_score(path: Path) -> dict:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    keys = ("protocol", "TP", "D", "U", "FN", "precision", "recall", "f1", "truths", "findings")
    return {key: report.get(key) for key in keys if key in report}


def score(run_id: str | None, base: str, scenario: str | None, out: Path,
          *, offline: Path | None = None, check_severity: bool = True, check_cvss: bool = True,
          klass: str | None = None, protocol: str = "lab30-v2") -> int:
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
    if protocol:
        cmd += ["--protocol", protocol]
    if check_severity:
        cmd.append("--check-severity")
    if check_cvss:
        cmd.append("--check-cvss")
    return subprocess.call(cmd)


BUDGET_FIELDS = ("responses", "tools", "seconds")
RUN_LIMIT_FIELDS = ("responses", "tools", "seconds")
STAGE_FIELDS = ("discovery", "poc", "review")


def parse_pairs(values: list[str] | None, flag: str, fields: tuple[str, ...]) -> dict:
    """Parse repeated ``KEY=VALUE`` flags into an int dict, failing before the run starts."""
    parsed: dict = {}
    for value in values or []:
        key, _, raw = value.partition("=")
        key = key.strip()
        if key not in fields:
            raise SystemExit(f"{flag} 只接受 {'/'.join(fields)}，收到 {value!r}")
        try:
            parsed[key] = int(raw)
        except ValueError:
            raise SystemExit(f"{flag} 的取值必须是整数，收到 {value!r}") from None
        if parsed[key] < 0:
            raise SystemExit(f"{flag} 的取值不能为负，收到 {value!r}")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default="http://127.0.0.1:8899", help="审计实例基址")
    parser.add_argument("--zip", default=None, help="靶场源码 zip（离线评分时可省略）")
    parser.add_argument("--scenario", choices=SCENARIOS, default="all",
                        help="审计范围：all 全量（默认）或 sqli/xss_r/command_injection 分场景")
    parser.add_argument("--class", dest="klass", default=None,
                        help="评分时只评某个类别（如 auth_bypass），透传给 score_dataset.py")
    parser.add_argument("--objective", default=None, help="覆盖默认任务目标文案")
    parser.add_argument("--iterations", type=int, default=None,
                        help="单任务迭代上限（默认 3；--closure 档为 5）")
    parser.add_argument("--max-rounds", type=int, default=None,
                        help="Planner 轮次上限（默认 24；--closure 档为 32）")
    parser.add_argument("--attempts", type=int, default=None,
                        help="单任务尝试上限（默认 64；--closure 档为 96）")
    parser.add_argument("--max-wait", type=int, default=None,
                        help="最长等待秒数（默认 5400；--closure 为 7200）")
    parser.add_argument("--interval", type=int, default=5, help="轮询间隔秒数")
    parser.add_argument("--out", default=None, help="评分明细输出路径")
    parser.add_argument("--no-score", action="store_true", help="只跑审计不评分")
    parser.add_argument("--poc-mode", choices=("off", "auto", "required"), default="auto", help="自动验证策略，默认 auto")
    parser.add_argument("--follow", default=None, help="接入已有 run（跳过上传与创建）")
    parser.add_argument("--offline", default=None,
                        help="离线模式：直接对已导出的 findings.json 评分，不起服务、不跑模型")
    parser.add_argument("--check-severity", action="store_true", help="比较文字等级与 CVSS 基础分等级")
    parser.add_argument("--check-cvss", action="store_true", help="比较 CVSS 基础分与基础向量")
    parser.add_argument("--budget", action="append", metavar="KEY=VALUE",
                        help="覆盖单次执行预算（responses/tools/seconds），可重复")
    parser.add_argument("--run-limit", action="append", metavar="KEY=VALUE",
                        help="覆盖整次运行的模型请求上限（responses/tools/seconds），可重复")
    parser.add_argument("--stage-limit", action="append", metavar="KEY=VALUE",
                        help="覆盖 discovery-first 阶段配额（discovery/poc/review），可重复；仅全量覆盖复核")
    parser.add_argument("--closure", action="store_true",
                        help="闭环验收档：POC auto、覆盖复核收束、放宽预算、前后复位靶场，并写 closure.json")
    parser.add_argument("--legacy-score", action="store_true",
                        help="使用旧的 legacy_unit_v1 评分（默认 lab30-v2）")
    parser.add_argument("--no-preflight-reset", action="store_true",
                        help="闭环档跳过开跑前/结束后的靶场复位与种子断言（仅用于调试）")
    parser.add_argument("--closure-out", default=None, help="closure.json 输出路径（默认与评分文件同目录）")
    args = parser.parse_args()

    base = args.base.rstrip("/")
    tag = args.scenario if args.scenario in SPECIFIC_SCENARIOS else "all"
    out = Path(args.out) if args.out else ROOT / "datasets" / "lab30-shop" / f"score_{tag}.json"
    # v2 只接受完整真值：分场景或分类型筛选时退回 legacy 评分。
    protocol = "" if args.legacy_score or tag != "all" or args.klass else "lab30-v2"

    # 离线评分：只调用 score_dataset.py，不连接后端。
    if args.offline:
        if args.no_score:
            print("已跳过评分（--no-score）")
            return 0
        return score(None, base, args.scenario, out, offline=Path(args.offline),
                     check_severity=args.check_severity, check_cvss=args.check_cvss,
                     klass=args.klass, protocol=protocol)

    if not args.zip and not args.follow:
        parser.error("在线模式需要 --zip 源码包，或使用 --offline findings.json 离线评分")
    if args.closure and args.follow:
        parser.error("--closure 必须由本脚本发起 run：接受证据需要开跑前的复位与种子断言，不能用 --follow 补做")
    max_wait = args.max_wait if args.max_wait is not None else (7200 if args.closure else 5400)

    iterations = args.iterations if args.iterations is not None else 3
    rounds = args.max_rounds if args.max_rounds is not None else 24
    attempts = args.attempts if args.attempts is not None else 64
    # In the closure profile the task limits come from CLOSURE_TASK, so only an
    # explicitly passed flag may override them; silently widening via the old
    # positional values would hide a typo in a short run.
    overrides = {}
    if args.closure:
        for key, value in (("max_iterations", args.iterations), ("max_planner_rounds", args.max_rounds),
                           ("max_total_attempts", args.attempts)):
            if value is not None:
                overrides[key] = value

    budgets = parse_pairs(args.budget, "--budget", BUDGET_FIELDS)
    limits = parse_pairs(args.run_limit, "--run-limit", RUN_LIMIT_FIELDS)
    quotas = parse_pairs(args.stage_limit, "--stage-limit", STAGE_FIELDS)
    if quotas and tag != "all":
        parser.error("--stage-limit 只适用于全量覆盖复核（--scenario all），分场景任务以 goal 收束")
    if quotas.get("poc") and args.poc_mode == "off":
        parser.error("--poc-mode off 时 --stage-limit poc 必须为 0 或省略")
    if quotas and "responses" in limits:
        total = sum(quotas.get(key, 0) for key in STAGE_FIELDS)
        if total > limits["responses"]:
            parser.error(f"阶段配额合计 {total} 超过 --run-limit responses={limits['responses']}")

    seed: dict | None = None
    config: dict = {}
    closure: dict | None = None
    with client_for(base) as client:
        try:
            client.get("/api/prompts").raise_for_status()
        except Exception as exc:  # noqa: BLE001 - any failure here means "not reachable"
            sys.exit(f"连不上 {base}: {exc}\n先启动后端：docker compose up -d，或 bash scripts/start.sh")

        if args.closure:
            config = closure_config(client)
            if not args.no_preflight_reset:
                seed = reset_target()
            elif not args.follow:
                print("[0/4] 跳过开跑前复位（--no-preflight-reset）")

        if args.follow:
            run_id = args.follow
            print(f"[1/4] 跳过上传，接入已有 run {run_id[:8]}")
            print("[2/4] 跳过创建")
        else:
            snapshot = upload(client, Path(args.zip))
            run = create_run(client, snapshot["id"], args.scenario, args.objective,
                             iterations, rounds, attempts, args.poc_mode,
                             closure=args.closure, budgets=budgets, limits=limits, quotas=quotas,
                             task_overrides=overrides)
            run_id = run["id"]

        bundle = poll(client, run_id, max_wait, args.interval)
        summarize(bundle)

        if args.closure:
            closure = closure_metrics(bundle, collect_events(client, run_id), config, seed=seed)
            closure["frozen"] = {
                "budgets": run.get("budgets"),
                "run_limits": run.get("run_limits"),
                "workflow": (run.get("execution_summary") or {}).get("workflow"),
                "task_limits": {key: (run.get("task_spec") or {}).get(key) for key in
                                ("max_iterations", "max_planner_rounds", "max_total_attempts")},
            }
            report_path = out.with_name(f"report_{run_id[:8]}.md")
            if fetch_report(client, run_id, report_path) is not None:
                closure["report"] = str(report_path)
            closure["score_path"] = str(out)
            if not args.no_preflight_reset:
                closure["poc"]["post_run_reset"] = reset_target("运行结束后复位", strict=False) is not None

    score_code = 0
    if args.no_score:
        print("\n已跳过评分（--no-score）")
    else:
        score_code = score(run_id, base, args.scenario, out,
                           check_severity=args.check_severity, check_cvss=args.check_cvss,
                           klass=args.klass, protocol=protocol)

    if closure is None:
        return score_code

    closure["score"] = read_score(out) if not args.no_score else {}
    closure["commit"] = commit_sha()
    closure["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    problems = closure_problems(closure, score_code)
    closure["failed_checks"] = problems
    closure_path = Path(args.closure_out) if args.closure_out else out.with_name(f"closure_{run_id[:8]}.json")
    closure_path.parent.mkdir(parents=True, exist_ok=True)
    closure_path.write_text(json.dumps(closure, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n闭环验收明细已写入: {closure_path}")
    if problems:
        print("闭环验收未通过:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"闭环验收通过 · TP={closure['score'].get('TP')} · F1={closure['score'].get('f1')}"
          f" · POC confirmed={closure['poc']['confirmed']} · reset={closure['poc']['resets']}")
    return score_code


if __name__ == "__main__":
    raise SystemExit(main())
