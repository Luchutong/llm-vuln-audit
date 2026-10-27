#!/usr/bin/env python3
"""Model-free Planner capacity replay and archived experiment diagnostics.

The default reads the checked-in validation archive. Optional --db/--run-id reads
an existing SQLite database in read-only mode; no migration, model, runner or
application service is started. JSON on stdout contains counts and IDs only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from audit.agent import _bound_situation, _planner_situation, _situation_bytes
from audit.db import Store
from audit.prompt_evaluation import DEFAULT_ANCHORS_PATH, DEFAULT_TRUTH_PATH, evaluate_v2


def capacity_checks():
    results = []
    for count in (0, 5, 10, 26, 200):
        records = [{"finding_id": f"synthetic-{index}", "verification_id": f"proof-{index}", "revision": 1,
                    "status": "verified", "normal_observation": "正常侧拒绝访问。" * 300,
                    "attack_observation": "攻击侧原始验证输出。" * 600} for index in range(count)]
        context = {"goal": {"status": "open"}, "tasks": [], "findings": [],
                   "verification_records": records, "verification_details": records,
                   "verification_reviews_required": records, "verification_reviews": []}
        situation = _planner_situation(context)
        bounded = _bound_situation(situation)
        size = _situation_bytes(bounded)
        assert size <= 16 * 1024 and bounded["closure_checks"]["unreviewed_verifications"] == count
        results.append({"records": count, "output_bytes": size, "pending_total": count, "passed": True})
    return results


def archived_diagnostics(folder):
    path = folder / "03-prompt-comparison/final_state.json"
    content = path.read_bytes()
    state = json.loads(content)
    truth = json.loads(DEFAULT_TRUTH_PATH.read_text())
    anchors = json.loads(DEFAULT_ANCHORS_PATH.read_text())
    trials = []
    for trial in state["trials"]:
        original = trial.get("score") or {}
        # Only explanatory links are rebuilt. Formal scores remain the saved
        # original: matched raw findings are not fully present in this export.
        auxiliary = evaluate_v2(truth, original.get("unmatched") or [], anchors)
        missed_ids = {str(item["id"]) for item in original.get("truth_results") or [] if not item.get("detected")}
        diagnoses = [item for item in auxiliary.get("missed_diagnostics") or [] if str(item.get("truth_id")) in missed_ids]
        trials.append({"trial_id": trial["id"], "prompt_id": trial["prompt_id"], "round": trial["round_index"],
            "evaluation_status": trial["evaluation_status"],
            "stored_score": {key: original.get(key) for key in ("TP", "D", "U", "FN", "precision", "recall", "f1")},
            "audit_elapsed_seconds": trial.get("audit_elapsed_seconds"),
            "stop_reason": (trial.get("stop_reason") or {}).get("code"),
            "auxiliary_from_unmatched_only": diagnoses})
    assert path.read_bytes() == content
    return {"experiment_id": state["id"], "artifact_sha256": hashlib.sha256(content).hexdigest(),
            "original_scores_unchanged": True, "trials": trials}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=ROOT / "deliverable/lab30-validation-2026-10-26")
    parser.add_argument("--db", type=Path)
    parser.add_argument("--run-id", action="append", default=[])
    args = parser.parse_args()
    if bool(args.db) != bool(args.run_id):
        parser.error("--db 和至少一个 --run-id 必须同时提供")
    result = {"model_calls": 0, "planner_capacity": capacity_checks(),
              "archive": archived_diagnostics(args.archive), "database_replays": []}
    if args.db:
        store = Store.open_readonly(args.db.resolve(strict=True))
        try:
            for run_id in args.run_id:
                if store.get_run(run_id) is None:
                    raise ValueError(f"run 不存在：{run_id}")
                bounded = _bound_situation(_planner_situation(store.list_planner_context(run_id)))
                result["database_replays"].append({"run_id": run_id, "output_bytes": _situation_bytes(bounded),
                    "counts": bounded["counts"], "closure_checks": bounded["closure_checks"]})
        finally:
            store.close()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
