#!/usr/bin/env python3
"""在虚拟机上发起**真实**审计并全程截图（不使用任何离线夹具）。

与 ``vm_shot_pages.py`` 的本质区别：
    vm_shot_pages.py 用 MockAPI 拦截 /api/* 返回夹具数据，只能证明"界面长这样"；
    本脚本调用真实后端，截图里的 run id、覆盖率、findings、事件数全部来自真实运行。

用法::

    # 1) 先看有没有可用快照
    python scripts/vm_real_run.py snapshots

    # 2) 发起一次真实审计（默认 goal 策略，预算 64 请求 / 1200 秒）
    python scripts/vm_real_run.py run --project <project_id>

    # 3) 只对已完成的 run 补拍全套
    python scripts/vm_real_run.py shoot <run_id>

    # 4) 打印某次 run 的成果指标（用于 D-B04 / S-B11）
    python scripts/vm_real_run.py metrics <run_id>
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
import urllib.request

from playwright.sync_api import sync_playwright

VM = "192.168.239.128"
API = f"http://{VM}:8899"
BASE = f"http://{VM}:5173"
ROOT = pathlib.Path(__file__).resolve().parents[1]
SHOTS = ROOT / "deliverable/open-source-2026-11/screens"
REAL_DIR = SHOTS / "real-run"
DATE = "2026-11-07"
STATE = ROOT / ".run/last_real_run.json"

DEFAULT_OBJECTIVE = (
    "对该 PHP 商城源码做白盒审计：追踪外部可控输入（$_GET/$_POST/$_COOKIE/$_FILES）"
    "流向 SQL 拼接、文件写入、命令执行、模板输出的完整数据流，"
    "给出由原始行号证据支撑的漏洞候选，并评估 CVSS 3.1。"
)


# ---------------------------------------------------------------- HTTP helpers
def api_get(path: str):
    with urllib.request.urlopen(f"{API}{path}", timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def api_post(path: str, payload: dict):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        f"{API}{path}", data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def config() -> dict:
    return api_get("/api/config")


# ------------------------------------------------------------------- create run
def start_run(args) -> dict:
    cfg = config()
    if not cfg.get("configured"):
        print("后端模型未配置，无法发起真实审计。missing =", cfg.get("missing"))
        print("先执行：bash scripts/vm_set_model.sh <MODEL> <BASE_URL> <API_KEY>")
        raise SystemExit(3)

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
        "run_limits": {
            "responses": args.responses,
            "tools": args.tools,
            "seconds": args.seconds,
        },
        "poc_mode": args.poc,
    }
    if args.project:
        payload["project_id"] = args.project
    else:
        payload["snapshot_id"] = args.snapshot

    run = api_post("/api/runs", payload)
    run_id = run.get("id") or run.get("run_id")
    print(f"run created: {run_id}", flush=True)
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({"run_id": run_id, "at": time.strftime("%F %T"),
                                 "project_id": args.project, "snapshot_id": args.snapshot},
                                ensure_ascii=False, indent=2), encoding="utf-8")
    return {"id": run_id, **run}


# --------------------------------------------------------------------- page ops
def launch(playwright):
    browser = playwright.chromium.launch(channel="chrome", headless=True)
    context = browser.new_context(
        viewport={"width": 1440, "height": 900},
        device_scale_factor=2,
        locale="zh-CN",
    )
    context.add_init_script("try{localStorage.setItem('audit-theme','light');}catch(e){}")
    return browser, context


def goto(page, path: str, ms: int = 2500) -> None:
    """SPA hash 路由切换不会重载，先回一个中性页再跳目标，避免弹窗残留。

    注意：运行中的审计页持有 SSE 长连接，``networkidle`` 永远不会成立，
    所以这里只用 ``domcontentloaded`` + 固定等待，不能等 networkidle。
    """
    page.goto(f"{BASE}/#sources", wait_until="domcontentloaded")
    page.wait_for_timeout(400)
    page.goto(f"{BASE}/{path}", wait_until="domcontentloaded")
    page.wait_for_timeout(ms)


def save(page, name: str, full: bool = True) -> pathlib.Path:
    """Save under real-run/<RUN_TAG>/ so successive runs never overwrite each other."""
    tag = os.environ.get("RUN_TAG", "").strip()
    out_dir = REAL_DIR / tag if tag else REAL_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{name}_{DATE}.png"
    page.screenshot(path=str(target), full_page=full, animations="disabled")
    print(f"  saved {tag + '/' if tag else ''}{target.name} "
          f"({target.stat().st_size // 1024} KB)", flush=True)
    return target


def open_detail(page, rid: str, tab: str) -> None:
    goto(page, f"#run/{rid}", 3000)
    page.get_by_role("button", name="审计详情", exact=True).first.click()
    dialog = page.get_by_role("dialog", name="审计详情", exact=True)
    dialog.wait_for(state="visible", timeout=15000)
    page.wait_for_timeout(600)
    if tab:
        dialog.get_by_role("tab", name=tab, exact=True).click()
        page.wait_for_timeout(1500)


# ------------------------------------------------------------------- screenshots
def shoot_running(page, rid: str) -> None:
    goto(page, f"#run/{rid}", 2500)
    page.set_viewport_size({"width": 1440, "height": 1100})
    save(page, "S-B04a_3.6_执行详情_运行中", full=False)
    page.set_viewport_size({"width": 1440, "height": 900})


def shoot_finished(page, rid: str) -> None:
    """Capture the post-run pages. 每个截图点独立容错，单点失败不影响其余。"""
    def attempt(label: str, fn) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            print(f"  !! {label} 失败: {type(exc).__name__}: {exc}", flush=True)
        page.keyboard.press("Escape")
        page.wait_for_timeout(600)

    def s04b() -> None:
        goto(page, f"#run/{rid}", 3000)
        page.set_viewport_size({"width": 1440, "height": 1200})
        save(page, "S-B04b_3.6_执行详情_完成态", full=False)

    def s05() -> None:
        goto(page, "#findings", 3000)
        save(page, "S-B05_3.6_漏洞发现台账")

    def detail(tab: str, name: str) -> None:
        def run() -> None:
            open_detail(page, rid, tab)
            if tab == "执行日志":
                for toggle in page.locator('[aria-expanded="false"]').all()[:6]:
                    try:
                        toggle.click()
                        page.wait_for_timeout(300)
                    except Exception:  # noqa: BLE001
                        pass
                page.wait_for_timeout(800)
            save(page, name, full=False)
        attempt(name, run)

    def s09() -> None:
        open_detail(page, rid, "发现与验证")
        # 证据窗口的真实文案是「查看源码 6–16 行」这类 Disclosure，不是固定短语
        opened = False
        for pattern in (re.compile(r"查看源码\s*\d+"), re.compile("查看源码")):
            try:
                page.get_by_role("button", name=pattern).first.click()
                opened = True
                break
            except Exception:  # noqa: BLE001
                continue
        if not opened:
            page.get_by_text(re.compile("查看源码")).first.click()
        page.wait_for_timeout(2200)
        save(page, "S-B09_6_漏洞证据链", full=False)

    attempt("S-B04b", s04b)
    attempt("S-B05", s05)
    detail("发现与验证", "S-B05c_3.6_发现与验证")
    detail("执行日志", "S-B15_3.6_执行日志")
    detail("结果报告", "S-B07_3.6_报告下载")
    attempt("S-B09", s09)

    page.set_viewport_size({"width": 1440, "height": 900})


# ------------------------------------------------------------------- run driving
def watch_and_shoot(rid: str, deadline_s: int) -> str:
    """轮询运行状态；运行中抓 1 张，结束后抓全套。返回终态。"""
    started = time.time()
    running_shot = False
    status = "unknown"
    with sync_playwright() as playwright:
        browser, context = launch(playwright)
        page = context.new_page()
        try:
            while True:
                try:
                    bundle = api_get(f"/api/runs/{rid}")
                except urllib.error.URLError as exc:
                    print(f"  poll error: {exc}", flush=True)
                    time.sleep(10)
                    continue
                # /api/runs/{id} 返回 bundle：{run: {...}, findings: [...], ...}
                run_obj = bundle.get("run") if isinstance(bundle.get("run"), dict) else bundle
                status = run_obj.get("status") or run_obj.get("state") or "unknown"
                elapsed = int(time.time() - started)
                print(f"  [{elapsed:>4}s] status={status}", flush=True)

                if status == "running" and not running_shot and elapsed >= 45:
                    running_shot = True
                    try:
                        shoot_running(page, rid)
                    except Exception as exc:  # noqa: BLE001
                        print(f"  !! 运行中截图失败: {exc}", flush=True)

                if status in ("completed", "failed", "cancelled", "error", "inconclusive"):
                    break
                if elapsed > deadline_s:
                    print(f"  超时 {deadline_s}s，仍为 {status}，停止等待", flush=True)
                    break
                time.sleep(15)

            if status in ("completed", "inconclusive"):
                print(f"  运行结束（{status}），开始补拍全套", flush=True)
                shoot_finished(page, rid)
            else:
                print(f"  终态 {status}，仅保留运行中截图", flush=True)
        finally:
            context.close()
            browser.close()
    return status


# ----------------------------------------------------------------------- metrics
def print_metrics(rid: str) -> None:
    """Print the observable outcome of one real run.

    TP/FP/FN are *not* computed here: precision-like numbers only exist relative to a
    frozen truth set, so they are produced offline by ``scripts/reproduce_release.py``.
    This function reports what the run itself recorded.
    """
    out = {"run_id": rid}
    for path, key in [
        (f"/api/runs/{rid}", "bundle"),
        (f"/api/runs/{rid}/report", "report"),
        (f"/api/runs/{rid}/event-log", "event_log"),
    ]:
        try:
            out[key] = api_get(path)
        except urllib.error.HTTPError as exc:
            out[key] = f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001
            out[key] = f"{type(exc).__name__}"

    bundle = out.get("bundle") if isinstance(out.get("bundle"), dict) else {}
    findings = bundle.get("findings")
    if findings is None and isinstance(bundle.get("run"), dict):
        findings = bundle["run"].get("findings")
    count = len(findings) if isinstance(findings, list) else "n/a"

    run = bundle.get("run") if isinstance(bundle.get("run"), dict) else bundle
    print(f"run_id   : {rid}", flush=True)
    print(f"status   : {run.get('status', 'n/a')}", flush=True)
    print(f"findings : {count}", flush=True)
    for key in ("covered_units", "total_units", "requests", "tool_calls"):
        if key in run:
            print(f"{key:9s}: {run[key]}", flush=True)

    STATE.parent.mkdir(parents=True, exist_ok=True)
    target = STATE.parent / f"metrics_{rid}.json"
    target.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"raw -> {target.relative_to(ROOT)}", flush=True)


# -------------------------------------------------------------------------- main
def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("snapshots")
    sub.add_parser("config")

    p_run = sub.add_parser("run")
    p_run.add_argument("--project", default=None)
    p_run.add_argument("--snapshot", default=None)
    p_run.add_argument("--objective", default=DEFAULT_OBJECTIVE)
    p_run.add_argument("--success", default=(
        "在源码中找到至少一处由原始行号证据支撑、具有明确触发条件的漏洞风险，"
        "并给出 CVSS 3.1 基础指标与依据。"))
    p_run.add_argument("--policy", default="goal", choices=["goal", "coverage_review"])
    p_run.add_argument("--responses", type=int, default=64)
    p_run.add_argument("--tools", type=int, default=256)
    p_run.add_argument("--seconds", type=int, default=1200)
    p_run.add_argument("--poc", default="off", choices=["off", "auto", "required"])
    p_run.add_argument("--workers", type=int, default=2)
    p_run.add_argument("--max-iterations", type=int, default=3)
    p_run.add_argument("--max-attempts", type=int, default=32)
    p_run.add_argument("--max-rounds", type=int, default=16)
    p_run.add_argument("--no-watch", action="store_true")

    p_shoot = sub.add_parser("shoot")
    p_shoot.add_argument("run_id")
    p_shoot.add_argument("--running-only", action="store_true")

    p_watch = sub.add_parser("watch")
    p_watch.add_argument("run_id")
    p_watch.add_argument("--deadline", type=int, default=2400)

    p_met = sub.add_parser("metrics")
    p_met.add_argument("run_id")

    args = parser.parse_args()

    if args.cmd == "config":
        print(json.dumps(config(), ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "snapshots":
        for path in ("/api/snapshots", "/api/projects"):
            try:
                print(f"--- {path} ---", flush=True)
                print(json.dumps(api_get(path), ensure_ascii=False, indent=1)[:1800])
            except Exception as exc:  # noqa: BLE001
                print(f"{path}: {type(exc).__name__} {exc}", flush=True)
        return 0

    if args.cmd == "run":
        if bool(args.project) == bool(args.snapshot):
            print("--project 与 --snapshot 必须二选一")
            return 2
        run = start_run(args)
        rid = run["id"]
        if args.no_watch:
            print(f"不等待，run_id={rid}", flush=True)
            return 0
        status = watch_and_shoot(rid, args.seconds + 600)
        print(f"final status: {status}", flush=True)
        print_metrics(rid)
        return 0

    if args.cmd == "watch":
        status = watch_and_shoot(args.run_id, args.deadline)
        print(f"final status: {status}", flush=True)
        print_metrics(args.run_id)
        return 0

    if args.cmd == "shoot":
        with sync_playwright() as playwright:
            browser, context = launch(playwright)
            page = context.new_page()
            try:
                if args.running_only:
                    shoot_running(page, args.run_id)
                else:
                    shoot_finished(page, args.run_id)
            finally:
                context.close()
                browser.close()
        return 0

    if args.cmd == "metrics":
        print_metrics(args.run_id)
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
