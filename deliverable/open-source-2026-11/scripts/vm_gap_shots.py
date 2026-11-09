#!/usr/bin/env python3
"""补齐成员 B 交付里剩余的三张缺口截图（全部为真实运行，不使用离线夹具）。

    S-B08  5.4.3  Prompt 实验页：真实启动 lab30-full-v2（W0/W1/W2 × 3 轮 × 720 秒）
    S-B10  9.4    审计运行中：对 lab30 快照发起真实审计，运行中截覆盖/任务图/预算
    S-B11  9.4    审计成果指标：用 scripts/score_dataset.py 导出评分 JSON 后截图

子命令::

    python scripts/vm_gap_shots.py preflight                 # 服务/快照/策略/模型是否就绪
    python scripts/vm_gap_shots.py b08-start                 # 创建实验（只冻结，不花 token 之前先校验）
    python scripts/vm_gap_shots.py b08-watch <experiment_id> # 轮询到终态
    python scripts/vm_gap_shots.py b08-shoot <experiment_id> # 截实验页
    python scripts/vm_gap_shots.py b10-start                 # 发起 lab30 审计
    python scripts/vm_gap_shots.py b10-shoot <run_id>        # 运行中截两张
    python scripts/vm_gap_shots.py b11 <run_id>              # 导出评分 JSON + 截图

注意：S-B08 是**限时**实验，跑的同时不要再发别的审计，否则会压低它的成绩。
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import time
import urllib.error

import paramiko
from playwright.sync_api import sync_playwright

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from vm_real_run import API, BASE, ROOT, SHOTS, api_get, api_post, goto, launch  # noqa: E402

DATE = os.environ.get("SHOT_DATE", "2026-11-08")
STATE_DIR = ROOT / ".run"
VM_HOST = os.environ.get("VM_HOST", "192.168.239.128")
VM_USER = os.environ.get("VM_USER", "zsh")
VM_PASS = os.environ.get("VM_PASS", "")  # 归档副本已脱敏：口令由环境变量注入
VM_PORT = int(os.environ.get("VM_PORT", "22"))
VM_ROOT = os.environ.get(
    "VM_ROOT", "/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main")

# W0 / W1 / W2 是 worker_strategies.builtin_worker_strategies() 的稳定内置 id
B08_PAYLOAD = {
    "protocol": "lab30-full-v2",
    "prompt_ids": ["worker-w0-v1", "worker-w1-v1", "worker-w2-v1"],
    "baseline_prompt_id": "worker-w0-v1",
    "repeats": 3,
    "run_limits": {"seconds": 720},
    "experiment_wall_seconds": 7200,
}

DEFAULT_OBJECTIVE = (
    "对该 PHP 商城源码做白盒审计：追踪外部可控输入（$_GET/$_POST/$_COOKIE/$_FILES）"
    "流向 SQL 拼接、文件写入、命令执行、模板输出的完整数据流，"
    "给出由原始行号证据支撑的漏洞候选，并评估 CVSS 3.1。"
)


# ------------------------------------------------------------------ screenshots
def save(page, name: str, full: bool = True, height: int | None = None) -> pathlib.Path:
    if height:
        page.set_viewport_size({"width": 1600, "height": height})
        page.wait_for_timeout(600)
    SHOTS.mkdir(parents=True, exist_ok=True)
    target = SHOTS / f"{name}_{DATE}.png"
    page.screenshot(path=str(target), full_page=full, animations="disabled")
    print(f"  saved {target.name} ({target.stat().st_size // 1024} KB)", flush=True)
    return target


# ------------------------------------------------------------------------ SSH
def _ssh() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(VM_HOST, port=VM_PORT, username=VM_USER, password=VM_PASS,
                   timeout=15, allow_agent=False, look_for_keys=False)
    return client


def vm_exec(command: str, timeout: int = 1800) -> tuple[int, str, str]:
    client = _ssh()
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        return stdout.channel.recv_exit_status(), out, err
    finally:
        client.close()


def vm_pull(remote: str, local: pathlib.Path) -> None:
    client = _ssh()
    try:
        sftp = client.open_sftp()
        local.parent.mkdir(parents=True, exist_ok=True)
        sftp.get(remote, str(local))
        sftp.close()
    finally:
        client.close()


# ------------------------------------------------------------------- preflight
def cmd_preflight(_args) -> int:
    cfg = api_get("/api/config")
    print(f"model configured : {cfg.get('configured')}  model={cfg.get('model')} base={cfg.get('base_url')}")
    if cfg.get("missing"):
        print(f"  missing        : {cfg['missing']}")
    snaps = api_get("/api/snapshots")
    print(f"snapshots        : {len(snaps)}")
    for item in snaps[:6]:
        print(f"  - {item.get('id')}  {item.get('name') or item.get('source_name')}  files={item.get('file_count')}")
    projs = api_get("/api/projects")
    print(f"projects         : {len(projs)}")
    for item in projs[:6]:
        print(f"  - {item.get('id')}  {item.get('name')}")
    prompts = api_get("/api/prompts")
    ids = {item.get("id") for item in prompts} if isinstance(prompts, list) else set()
    for need in B08_PAYLOAD["prompt_ids"]:
        print(f"prompt {need:<16}: {'OK' if need in ids else 'MISSING'}")
    try:
        runs = api_get("/api/runs")
        print(f"runs             : {len(runs)}")
        for item in runs[:5]:
            print(f"  - {item.get('id')}  {item.get('status')}  {item.get('created_at')}")
    except Exception as exc:  # noqa: BLE001
        print(f"runs             : 读取失败 {exc}")
    return 0


# ----------------------------------------------------------------------- S-B04
def cmd_b04_shoot(args) -> int:
    """补拍执行详情抽屉：Planner 回合、任务图、覆盖统计都在这个 tab 里。"""
    rid = args.run_id
    with sync_playwright() as playwright:
        browser, context = launch(playwright)
        page = context.new_page()
        page.set_viewport_size({"width": 1600, "height": 1400})
        goto(page, f"#run/{rid}", 3000)
        page.get_by_role("button", name="审计详情", exact=True).first.click()
        page.get_by_role("dialog", name="审计详情", exact=True).wait_for(state="visible", timeout=15000)
        page.wait_for_timeout(900)
        page.get_by_role("tab", name="项目与任务图", exact=True).click()
        page.wait_for_timeout(2200)
        save(page, "S-B04_3.6_执行详情_任务图与覆盖", full=True)
        browser.close()
    return 0


# ----------------------------------------------------------------------- S-B08
def cmd_b08_start(_args) -> int:
    exp = api_post("/api/prompt-experiments", B08_PAYLOAD)
    ident = exp.get("id") or exp.get("experiment_id")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    (STATE_DIR / "last_experiment.json").write_text(
        json.dumps({"id": ident, "at": time.strftime("%F %T")}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(f"experiment created: {ident}")
    print(f"status={exp.get('status')}  trials={len(exp.get('trials') or [])}")
    for trial in (exp.get("trials") or [])[:12]:
        print(f"  trial {trial.get('id')}  round {trial.get('round_index')}  {trial.get('prompt_id')}")
    return 0


def _experiment(ident: str) -> dict:
    return api_get(f"/api/prompt-experiments/{ident}")


def cmd_b08_watch(args) -> int:
    ident = args.experiment_id
    deadline = time.time() + args.max_minutes * 60
    last = ""
    while time.time() < deadline:
        try:
            exp = _experiment(ident)
        except Exception as exc:  # noqa: BLE001
            print(f"  ! 读取失败 {exc}", flush=True)
            time.sleep(30)
            continue
        status = exp.get("status")
        trials = exp.get("trials") or []
        done = [t for t in trials if t.get("status") not in {"pending", "running", "not_started"}]
        line = f"{time.strftime('%H:%M:%S')} status={status} 已完成 {len(done)}/{len(trials)}"
        if line != last:
            print(line, flush=True)
            last = line
        for trial in done[-3:]:
            score = trial.get("score") or {}
            print(f"   trial {trial.get('prompt_id')} r{trial.get('round_index')} "
                  f"{trial.get('status')} f1={score.get('f1')}", flush=True)
        if status not in {"preparing", "running", "cancelling"}:
            print(f"终态: {status}")
            summary = exp.get("summary") or {}
            print(json.dumps(summary, ensure_ascii=False)[:2000])
            return 0
        time.sleep(args.interval)
    print("等待超时，实验仍在运行；稍后再执行 b08-watch。")
    return 4


def cmd_b08_shoot(args) -> int:
    ident = args.experiment_id
    with sync_playwright() as playwright:
        browser, context = launch(playwright)
        page = context.new_page()
        page.set_viewport_size({"width": 1600, "height": 1400})
        goto(page, f"#experiments/{ident}", 5000)
        page.wait_for_timeout(2500)
        save(page, "S-B08_5.4.3_Prompt实验对比_总览", full=True)
        goto(page, f"#experiments/{ident}?tab=trials", 4000)
        page.wait_for_timeout(2000)
        save(page, "S-B08b_5.4.3_Prompt实验_逐轮记录", full=True)
        browser.close()
    return 0


# ----------------------------------------------------------------------- S-B10
def _lab30_project() -> tuple[str, str]:
    projects = api_get("/api/projects")
    for item in projects:
        name = str(item.get("name") or "")
        if "lab30" in name.lower():
            snap = ""
            snaps = api_get(f"/api/projects/{item['id']}")
            candidates = snaps.get("snapshots") or []
            if candidates:
                snap = candidates[0].get("id") or ""
            return item["id"], snap
    raise SystemExit("未找到 lab30 项目，请先确认源码包库")


def cmd_b10_start(args) -> int:
    cfg = api_get("/api/config")
    if not cfg.get("configured"):
        print(f"模型未配置: missing={cfg.get('missing')}")
        return 3
    project_id, snapshot_id = _lab30_project()
    payload = {
        "task": {
            "objective": args.objective,
            "success_criteria": args.success,
            "max_iterations": args.max_iterations,
            "max_total_attempts": args.max_attempts,
            "max_planner_rounds": args.max_rounds,
            "max_workers": args.workers,
            "completion_policy": args.policy,
            "baseline_policy": "fresh",
            "workflow_policy": "discovery_first",
            "focus_scope": "all",
        },
        "run_limits": {"responses": args.responses, "tools": args.tools, "seconds": args.seconds},
        "poc_mode": "off",
        "project_id": project_id,
    }
    if args.snapshot:
        payload = {k: v for k, v in payload.items() if k != "project_id"}
        payload["snapshot_id"] = args.snapshot
    try:
        run = api_post("/api/runs", payload)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        print(f"HTTP {exc.code}: {detail[:1500]}")
        return exc.code
    rid = run.get("id") or run.get("run_id")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    (STATE_DIR / "last_gap_run.json").write_text(
        json.dumps({"run_id": rid, "project_id": project_id, "snapshot_id": snapshot_id,
                    "at": time.strftime("%F %T")}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"run created: {rid}  project={project_id} snapshot={snapshot_id}")
    return 0


def cmd_b10_shoot(args) -> int:
    rid = args.run_id
    with sync_playwright() as playwright:
        browser, context = launch(playwright)
        page = context.new_page()
        page.set_viewport_size({"width": 1600, "height": 1300})
        goto(page, f"#run/{rid}", 3000)
        state = api_get(f"/api/runs/{rid}")
        run = state.get("run") or state
        print(f"  status={run.get('status')}")
        save(page, "S-B10_9.4_审计运行中_覆盖与预算", full=False)
        try:
            page.get_by_role("button", name="审计详情", exact=True).first.click()
            page.get_by_role("dialog", name="审计详情", exact=True).wait_for(state="visible", timeout=15000)
            page.wait_for_timeout(800)
            page.get_by_role("tab", name="项目与任务图", exact=True).click()
            page.wait_for_timeout(2000)
            save(page, "S-B10b_9.4_审计运行中_任务图", full=False)
        except Exception as exc:  # noqa: BLE001
            print(f"  !! 任务图失败 {type(exc).__name__}: {exc}")
        browser.close()
    return 0


# ----------------------------------------------------------------------- S-B11
_SCORE_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>Lab30 评分回执 · {rid}</title>
<style>
 :root {{ color-scheme: light; }}
 * {{ box-sizing: border-box; }}
 body {{ margin:0; padding:32px 40px 44px; background:#f6f7f9; color:#14181f;
        font-family:"Segoe UI","Microsoft YaHei","PingFang SC",sans-serif; }}
 h1 {{ margin:0 0 6px; font-size:22px; letter-spacing:.2px; }}
 .sub {{ color:#5c6572; font-size:13px; margin-bottom:22px; }}
 .cmd {{ background:#0f172a; color:#d6e2f5; border-radius:8px; padding:12px 14px;
        font-family:ui-monospace,Consolas,"Courier New",monospace; font-size:12.5px;
        line-height:1.6; margin-bottom:20px; white-space:pre-wrap; word-break:break-all; }}
 .cards {{ display:grid; grid-template-columns:repeat(6,1fr); gap:12px; margin-bottom:22px; }}
 .card {{ background:#fff; border:1px solid #e3e7ee; border-radius:10px; padding:14px 16px; }}
 .card .k {{ font-size:12px; color:#5c6572; margin-bottom:6px; }}
 .card .v {{ font-size:24px; font-weight:700; font-variant-numeric:tabular-nums; }}
 .card.hi .v {{ color:#1f5fd6; }}
 .meta {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px 28px;
         background:#fff; border:1px solid #e3e7ee; border-radius:10px; padding:16px 20px; margin-bottom:20px; }}
 .meta div {{ font-size:13px; line-height:1.7; }}
 .meta b {{ color:#47505d; font-weight:600; margin-right:8px; }}
 pre {{ margin:0; background:#fff; border:1px solid #e3e7ee; border-radius:10px;
       padding:16px 18px; font-family:ui-monospace,Consolas,"Courier New",monospace;
       font-size:12px; line-height:1.55; max-height:640px; overflow:hidden;
       -webkit-mask-image:linear-gradient(#000 86%, transparent 100%); }}
 .h2 {{ font-size:14px; font-weight:700; margin:0 0 10px; color:#14181f; }}
</style></head><body>
<h1>Lab30 评分回执（scripts/score_dataset.py 导出）</h1>
<div class="sub">protocol {protocol} · 真值 {truths} 项 · 结论 {findings} 条 · 生成于 {generated}</div>
<div class="cmd">{command}</div>
<div class="cards">
  <div class="card"><div class="k">TP</div><div class="v">{TP}</div></div>
  <div class="card"><div class="k">FP</div><div class="v">{FP}</div></div>
  <div class="card"><div class="k">FN</div><div class="v">{FN}</div></div>
  <div class="card"><div class="k">Precision</div><div class="v">{precision}</div></div>
  <div class="card"><div class="k">Recall</div><div class="v">{recall}</div></div>
  <div class="card hi"><div class="k">F1</div><div class="v">{f1}</div></div>
</div>
<div class="meta">
  <div><b>run id</b>{rid}</div>
  <div><b>快照</b>{snapshot}</div>
  <div><b>评分范围</b>{scope}</div>
  <div><b>类别覆盖</b>{coverage}</div>
  <div><b>真值文件</b>{truth_file}</div>
  <div><b>评级口径</b>{rating}</div>
</div>
<div class="h2">导出的 JSON（原始内容）</div>
<pre>{json_text}</pre>
</body></html>
"""


def _fmt(value, digits: int = 4) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def cmd_b11(args) -> int:
    rid = args.run_id
    remote_json = f"/tmp/score_{rid}.json"
    command = (
        f'cd "{VM_ROOT}" && PY=backend/.venv/bin/python; test -x "$PY" || PY=python3; '
        f'$PY scripts/score_dataset.py --protocol lab30-v2 --api http://127.0.0.1:8899 '
        f'--run {rid} --out {remote_json}'
    )
    print("[1/4] 在虚拟机上导出评分 JSON …")
    code, out, err = vm_exec(command, timeout=900)
    print(out.strip()[-4000:])
    if err.strip():
        print("--- stderr ---\n" + err.strip()[-2000:])
    if code != 0:
        print(f"评分脚本退出码 {code}，终止。")
        return code
    local_json = STATE_DIR / f"score_{rid}.json"
    print(f"[2/4] 取回 {remote_json} …")
    vm_pull(remote_json, local_json)
    return _render_score(rid, local_json, command)


def _score_command(rid: str) -> str:
    return (f"cd {VM_ROOT} && backend/.venv/bin/python scripts/score_dataset.py "
            f"--protocol lab30-v2 --api http://127.0.0.1:8899 --run {rid} "
            f"--out /tmp/score_{rid}.json")


def _render_score(rid: str, local_json: pathlib.Path, command: str) -> int:
    report = json.loads(local_json.read_text(encoding="utf-8"))

    coverage = "—"
    classes = report.get("class_coverage") or {}
    if classes:
        # 注意：class_coverage[*]["detected"] 是"该类被检出的实例数"，不是布尔值也不是类别数。
        # 类别覆盖率 = 至少检出 1 项的类别数 / 类别总数；实例覆盖 = 全部检出实例 / 真值总数。
        total_classes = len(classes)
        hit_classes = sum(1 for item in classes.values() if item.get("detected"))
        try:
            hits = sum(int(item.get("detected", 0)) for item in classes.values())
            total_instances = sum(int(item.get("total", 0)) for item in classes.values())
            instance_part = f"，实例 {hits}/{total_instances}"
        except (TypeError, ValueError):
            instance_part = ""
        pct = f"{hit_classes / total_classes * 100:.1f}%" if total_classes else "—"
        coverage = f"{hit_classes}/{total_classes} 类（{pct}{instance_part}）"

    run_state = api_get(f"/api/runs/{rid}")
    run = run_state.get("run") or run_state
    snapshot = run.get("snapshot_name") or run.get("snapshot_id") or "—"

    html = _SCORE_HTML.format(
        rid=rid,
        protocol=report.get("protocol") or "lab30-v2",
        truths=report.get("truths", "—"),
        findings=report.get("findings", "—"),
        generated=time.strftime("%Y-%m-%d %H:%M:%S"),
        command=f"$ {command}",
        TP=report.get("TP", "—"), FP=report.get("FP", "—"), FN=report.get("FN", "—"),
        precision=_fmt(report.get("precision")), recall=_fmt(report.get("recall")),
        f1=_fmt(report.get("f1")),
        snapshot=snapshot, scope=report.get("scope", "—"), coverage=coverage,
        truth_file=report.get("truth_file", "—"),
        rating=report.get("rating_standard", "—"),
        json_text=json.dumps(report, ensure_ascii=False, indent=2)[:3600],
    )
    page_path = STATE_DIR / f"score_{rid}.html"
    page_path.write_text(html, encoding="utf-8")

    print("[3/4] 渲染回执页 …")
    with sync_playwright() as playwright:
        browser, context = launch(playwright)
        page = context.new_page()
        page.set_viewport_size({"width": 1600, "height": 1500})
        page.goto(page_path.as_uri(), wait_until="load")
        page.wait_for_timeout(1200)
        save(page, "S-B11_9.4_审计成果指标_评分JSON")
        browser.close()
    print("[4/4] 完成。原始 JSON 已存 .run/，截图已存 screens/。")
    return 0


# ------------------------------------------------------------------------ main
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)

    sub.add_parser("preflight")

    p_b04 = sub.add_parser("b04-shoot")
    p_b04.add_argument("run_id")

    sub.add_parser("b08-start")
    p_watch = sub.add_parser("b08-watch")
    p_watch.add_argument("experiment_id")
    p_watch.add_argument("--interval", type=int, default=60)
    p_watch.add_argument("--max-minutes", type=int, default=150)
    p_shot8 = sub.add_parser("b08-shoot")
    p_shot8.add_argument("experiment_id")

    p_b10 = sub.add_parser("b10-start")
    p_b10.add_argument("--objective", default=DEFAULT_OBJECTIVE)
    p_b10.add_argument("--success", default="产出带源码行号证据的可操作漏洞候选，并记录未覆盖方向")
    p_b10.add_argument("--responses", type=int, default=96)
    p_b10.add_argument("--tools", type=int, default=288)
    p_b10.add_argument("--seconds", type=int, default=1500)
    p_b10.add_argument("--max-iterations", type=int, default=3)
    p_b10.add_argument("--max-attempts", type=int, default=64)
    p_b10.add_argument("--max-rounds", type=int, default=20)
    p_b10.add_argument("--workers", type=int, default=1)
    p_b10.add_argument("--policy", default="coverage_review")
    p_b10.add_argument("--snapshot", default="")
    p_shot10 = sub.add_parser("b10-shoot")
    p_shot10.add_argument("run_id")

    p_b11 = sub.add_parser("b11")
    p_b11.add_argument("run_id")
    p_b11.add_argument("--json", default="", help="跳过 SSH，直接用本地评分 JSON 重渲染")

    args = parser.parse_args(argv)
    table = {
        "preflight": cmd_preflight,
        "b04-shoot": cmd_b04_shoot,
        "b08-start": cmd_b08_start,
        "b08-watch": cmd_b08_watch,
        "b08-shoot": cmd_b08_shoot,
        "b10-start": cmd_b10_start,
        "b10-shoot": cmd_b10_shoot,
        "b11": cmd_b11,
    }
    return table[args.action](args)


if __name__ == "__main__":
    raise SystemExit(main())
