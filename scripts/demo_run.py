#!/usr/bin/env python3
"""Coursework compatibility example: run a fixed prompt over DVWA and follow it.

Usage: demo_run.py <base-url> <snapshot-id> [prompt-id]

This does not use or replace the default Planner-led audit endpoint. Streams the
legacy run's event log, then prints per-unit verdicts, findings and metrics.
"""
import argparse
import json
import tempfile
import time
from pathlib import Path

import httpx

from prompt_scope import DVWA_SCOPE

# `completed` belongs here: leaving it out meant the follow loop never noticed a run that
# had finished cleanly and kept polling until its own deadline.
TERMINAL = {"succeeded", "completed", "failed", "cancelled", "interrupted"}

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("base_url")
parser.add_argument("snapshot_id")
parser.add_argument("prompt_id", nargs="?", default="P2")
args = parser.parse_args()
base = args.base_url.rstrip("/")
snapshot_id = args.snapshot_id
prompt_id = args.prompt_id

client = httpx.Client(base_url=base, timeout=600)

# `--follow <run-id>` attaches to a run that is already going instead of starting a
# second one over the same snapshot: two runs would each spend the model budget.
if snapshot_id == "--follow":
    run_id = prompt_id
    detail = client.get(f"/api/runs/{run_id}").json()["run"]
    print(f"following   : {run_id}  status={detail['status']}  units={detail['total_units']}")
    print()
else:
    response = client.post(
        "/api/runs",
        json={"snapshot_id": snapshot_id, "scope": DVWA_SCOPE, "prompt_id": prompt_id},
    )
    if response.status_code >= 400:
        print("create run failed:", response.status_code, response.text[:800])
        raise SystemExit(1)
    run = response.json()
    run_id = run["id"]
    print(f"run id      : {run_id}")
    print(f"prompt      : {run['prompt_id']} ({run['prompt_label']})")
    print(f"model       : {run['model']}")
    print(f"budgets     : {run['budgets']}")
    print(f"units       : {run['total_units']}")
    print()

# --- follow the event stream -------------------------------------------------
cursor = 0
deadline = time.time() + 3600
quiet_since = time.time()
while time.time() < deadline:
    log = client.get(f"/api/runs/{run_id}/event-log", params={"after": cursor}).json()
    for event in log["events"]:
        cursor = event["id"]
        quiet_since = time.time()
        kind = event["kind"]
        payload = event.get("payload") or {}
        unit = event.get("unit_id") or ""
        detail = ""
        if kind == "unit_started":
            detail = payload.get("file_path", "")
        elif kind == "unit_completed":
            conclusions = payload.get("conclusions") or {}
            usage = payload.get("usage") or {}
            detail = (
                "  ".join(f"{name}={conclusions.get(name, '—')}"
                          for name in ("sqli", "xss_r", "command_injection"))
                + f"  responses={usage.get('requests', 0)} tools={usage.get('tool_calls', 0)}"
            )
            if payload.get("exploration_incomplete"):
                detail += f"  [探索未走完:{payload['exploration_incomplete']}]"
        elif kind == "finding_created":
            # The event carries the citation, not a resolved path: the unit is known here,
            # so name it rather than printing the None:None this used to.
            refs = "、".join(
                f"{ref.get('path')}:{ref.get('start_line')}-{ref.get('end_line')}"
                for ref in (payload.get("evidence") or [])
            )
            detail = f"[{payload.get('category')}] {payload.get('title')}  证据 {refs or '—'}"
        elif kind == "finding_rejected_by_validation":
            detail = f"[{payload.get('category')}] {payload.get('title')}  " + "；".join(
                payload.get("validation_errors") or []
            )
        elif kind in ("unit_incomplete", "model_error"):
            detail = json.dumps(payload, ensure_ascii=False)[:300]
        elif kind == "run_started":
            detail = f"units={payload.get('units')}"
        print(f"{event['id']:>4}  {kind:<32} {unit[:8]:<9} {detail}")

    current = client.get(f"/api/runs/{run_id}").json()["run"]
    if current["status"] in TERMINAL:
        break
    if time.time() - quiet_since > 90:
        print(f"    ... no new events for 90s (status={current['status']})")
        quiet_since = time.time()
    time.sleep(2)

# --- final bundle ------------------------------------------------------------
bundle = client.get(f"/api/runs/{run_id}").json()
print("\n=== run ===")
print(json.dumps(bundle["run"], ensure_ascii=False, indent=2)[:1200])

print("\n=== units ===")
for unit in bundle["units"]:
    # The per-unit verdicts hang off `result`, and the counters off `usage`; the flat
    # fields this used to read (`conclusion`, `candidate_count`, `model_responses`) do not
    # exist on the API's unit object.
    result = unit.get("result") or {}
    conclusions = result.get("conclusions") or {}
    usage = unit.get("usage") or {}
    print(
        f"{unit['status']:<12} {unit['file_path']}:{unit['start_line']}-{unit['end_line']}"
        f"  {unit['symbol']}"
    )
    print(
        "             "
        + "  ".join(f"{name}={conclusions.get(name, '—')}"
                   for name in ("sqli", "xss_r", "command_injection"))
        + f"  responses={usage.get('requests', 0)} tools={usage.get('tool_calls', 0)}"
    )
    if result.get("exploration_incomplete"):
        print(f"             探索未走完（{result['exploration_incomplete']}），结论由收尾阶段给出")
    if unit.get("error"):
        print(f"             error: {unit['error'][:200]}")

print("\n=== findings ===")
for finding in bundle["findings"]:
    print(
        f"{finding['id'][:8]}  [{finding['category']}] {finding['severity']:<8}"
        f" {finding['validation_state']:<16} {finding['file_path']}:{finding['line']}"
        f"  {finding['title']}"
    )
    for ref in finding["evidence"]:
        print(f"          证据 {ref['path']}:{ref['start_line']}-{ref['end_line']}")
    for problem in finding["validation_errors"]:
        print(f"          剔除 {problem}")

print("\n=== metrics ===")
print(json.dumps(bundle["metrics"], ensure_ascii=False, indent=2))

run_id_file = Path(tempfile.gettempdir()) / "llm-vuln-audit-run-id.txt"
print(f"\nrun id saved to {run_id_file}")
with run_id_file.open("w", encoding="utf-8") as handle:
    handle.write(run_id)
