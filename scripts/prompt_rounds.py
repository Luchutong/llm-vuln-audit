#!/usr/bin/env python3
"""Compare prompt versions on one fixed snapshot and scope.

This is separate from the default Planner-led audit workflow.
Usage: prompt_rounds.py <base-url> <snapshot-id> [PROMPT_ID ...]
"""
from __future__ import annotations

import argparse
import json
import sys
import time

import httpx

from prompt_scope import (
    DVWA_SCOPE,
    MUTILLIDAE_CROSSFILE_SCOPE,
    MUTILLIDAE_MULTIFLOW_SCOPE,
    MUTILLIDAE_SCOPE,
)

TERMINAL = {"succeeded", "completed", "failed", "cancelled", "interrupted"}
CATEGORIES = ("sqli", "xss_r", "command_injection")
SCOPES = {
    "dvwa": DVWA_SCOPE,
    "mutillidae": MUTILLIDAE_SCOPE,
    "mutillidae-crossfile": MUTILLIDAE_CROSSFILE_SCOPE,
    "mutillidae-multiflow": MUTILLIDAE_MULTIFLOW_SCOPE,
}


def _show_events(events: list[dict]) -> None:
    for event in events:
        kind = event.get("kind", "")
        payload = event.get("payload") or {}
        if kind in {
            "unit_started", "unit_completed", "unit_incomplete", "finding_created",
            "model_retry", "run_failed",
        }:
            print(
                f"  {kind:<24} {(event.get('unit_id') or '')[:8]:<9} "
                f"{json.dumps(payload, ensure_ascii=False)[:240]}"
            )


def _run_prompt(
    client: httpx.Client,
    snapshot_id: str,
    prompt_id: str,
    timeout: int,
    scope: list[str],
    budgets: dict[str, int],
) -> dict:
    response = client.post(
        "/api/prompt-runs",
        json={
            "snapshot_id": snapshot_id,
            "scope": scope,
            "prompt_id": prompt_id,
            "budgets": budgets,
        },
    )
    if response.is_error:
        raise RuntimeError(f"{prompt_id} 创建失败 ({response.status_code}): {response.text[:800]}")
    run = response.json()
    run_id = run["id"]
    print(
        f"\n=== {prompt_id} {run_id} | model={run['model']} | "
        f"units={run['total_units']} | budgets={run['budgets']} ==="
    )
    cursor = 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        log_response = client.get(
            f"/api/runs/{run_id}/event-log", params={"after": cursor}
        )
        log_response.raise_for_status()
        log = log_response.json()
        events = log.get("events") or []
        _show_events(events)
        if events:
            cursor = max(event["id"] for event in events)

        detail_response = client.get(f"/api/runs/{run_id}")
        detail_response.raise_for_status()
        current = detail_response.json()["run"]
        if current["status"] in TERMINAL:
            print(
                f"=== {prompt_id} finished: {current['status']} "
                f"{current['completed_units']}/{current['total_units']} units ==="
            )
            if current["status"] not in {"succeeded", "completed"}:
                raise RuntimeError(
                    f"{prompt_id} finished with status={current['status']}: "
                    f"{current.get('error') or 'see run events'}"
                )
            return current
        time.sleep(2)

    final_response = client.get(f"/api/runs/{run_id}")
    final_response.raise_for_status()
    final_run = final_response.json()["run"]
    if final_run["status"] in TERMINAL:
        if final_run["status"] in {"succeeded", "completed"}:
            return final_run
        raise RuntimeError(f"{prompt_id} finished with status={final_run['status']}")
    cancel_response = client.post(f"/api/runs/{run_id}/cancel")
    if cancel_response.is_error:
        final_response = client.get(f"/api/runs/{run_id}")
        final_response.raise_for_status()
        final_run = final_response.json()["run"]
        if final_run["status"] in {"succeeded", "completed"}:
            return final_run
        cancel_response.raise_for_status()
    raise TimeoutError(f"{prompt_id} exceeded {timeout}s; cancelled run {run_id}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url")
    parser.add_argument("snapshot_id")
    parser.add_argument("versions", nargs="*", metavar="PROMPT_ID")
    parser.add_argument(
        "--benchmark",
        choices=tuple(SCOPES),
        default="dvwa",
        help="fixed coursework sample set (default: dvwa)",
    )
    parser.add_argument("--timeout-seconds", type=int, default=5400)
    parser.add_argument("--responses", type=int, default=8)
    parser.add_argument("--tools", type=int, default=16)
    parser.add_argument("--seconds", type=int, default=300)
    args = parser.parse_args(argv)
    versions = args.versions or ["P0", "P1", "P2"]
    scope = SCOPES[args.benchmark]
    if len(set(versions)) != len(versions):
        parser.error("each prompt version may be run only once per benchmark invocation")
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    if args.responses < 1 or args.tools < 0 or args.seconds < 1:
        parser.error("--responses and --seconds must be positive; --tools cannot be negative")
    budgets = {
        "responses": args.responses,
        "tools": args.tools,
        "seconds": args.seconds,
    }

    run_ids: list[str] = []
    try:
        with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=60) as client:
            config = client.get("/api/config")
            config.raise_for_status()
            model = config.json()
            if not model.get("configured"):
                raise RuntimeError(
                    "后端尚未配置模型。请先设置模型名称、兼容 API 地址和密钥并重启服务。"
                )
            prompts_response = client.get("/api/prompts")
            prompts_response.raise_for_status()
            available_prompts = {
                prompt["id"]: prompt for prompt in prompts_response.json()
            }
            missing_prompts = [version for version in versions if version not in available_prompts]
            if missing_prompts:
                raise RuntimeError(f"未知提示词版本：{missing_prompts}")
            print(
                f"模型：{model.get('model')}; 基准：{args.benchmark}; "
                f"固定范围：{len(scope)} 个 PHP 文件"
            )
            truths_response = client.get(f"/api/snapshots/{args.snapshot_id}/truths")
            truths_response.raise_for_status()
            truth_keys = {
                (item["file_path"], item["category"])
                for item in truths_response.json()
                if item["file_path"] in scope and item["category"] in CATEGORIES
            }
            expected_truths = len(scope) * len(CATEGORIES)
            print(f"真值覆盖：{len(truth_keys)}/{expected_truths} 个文件×漏洞类别")
            if len(truth_keys) < expected_truths:
                print(
                    f"注意：真值尚未覆盖完整 {expected_truths} 组；"
                    "配对统计仅使用有独立真值且两轮均已判定的共同样本，"
                    "未标注候选会使提升值不可计算。"
                )
            for version in versions:
                current = _run_prompt(
                    client, args.snapshot_id, version, args.timeout_seconds, scope, budgets
                )
                run_ids.append(current["id"])

            experiment_response = client.get(
                "/api/experiments", params={"run_ids": ",".join(run_ids)}
            )
            experiment_response.raise_for_status()
            experiment = experiment_response.json()
    except (httpx.HTTPError, RuntimeError, TimeoutError) as exc:
        print(f"\n实验未完成：{exc}", file=sys.stderr)
        return 1

    print("\n=== 配对比较（百分点差；不可比较时不会给出提升数值）===")
    print(f"comparable={experiment['comparable']} reasons={experiment['reasons']}")
    for note in experiment.get("notes", []):
        print(f"注意：{note}")
    for item in experiment.get("paired_comparisons", []):
        deltas = item.get("delta_percentage_points") or {}
        formatted = " ".join(
            f"{name}={value:+.2f}pp" if value is not None else f"{name}=不可计算"
            for name, value in deltas.items()
        )
        print(
            f"{item['baseline_prompt_id']}→{item['prompt_id']}: "
            f"common_samples={item['common_samples']} {formatted}"
        )
    print("\n运行 ID：" + ", ".join(run_ids))
    print("可用 scripts/verify_rounds.py 检查导出的 Markdown/JSON 报告。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
