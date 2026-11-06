#!/usr/bin/env python3
"""Explain the frozen Lab30 release gaps without running a model or changing data.

The checked-in release supplies the score. An optional read-only database supplies
the immutable report input, including historical Worker reads and directions.
Truth and anchors are used only for this post-run diagnostic, never for dispatch.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "deliverable/lab30-closure-2026-10-30"
sys.path.insert(0, str(ROOT / "backend"))

from audit.risk_coverage import freeze as freeze_signals  # noqa: E402
from score_dataset import parse_evidence, same_location  # noqa: E402


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_archive() -> dict:
    manifest = read_json(ARCHIVE / "reproduction-manifest.json")
    for relative, expected in manifest["files"].items():
        path = ROOT / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"Missing or changed frozen asset: {relative}")
    return manifest


def load_trace(path: Path, run_id: str) -> tuple[dict, dict]:
    # mode=ro must fail for a missing database; never create or migrate one.
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as connection:
        connection.execute("PRAGMA query_only=ON")
        row = connection.execute(
            "SELECT input_hash,input_json FROM frozen_run_reports WHERE run_id=?", (run_id,)
        ).fetchone()
    if row is None:
        raise ValueError(f"No immutable report input for run {run_id}")
    digest = hashlib.sha256(row[1].encode()).hexdigest()
    if digest != row[0]:
        raise ValueError("Frozen report input hash mismatch")
    payload = json.loads(row[1])
    if payload["run"]["id"] != run_id:
        raise ValueError("Frozen report run ID mismatch")
    return payload, {
        "available": True,
        "source": "frozen_run_reports.input_json; not the current project ledger",
        "input_hash": row[0],
        "input_json_sha256": digest,
    }


def covers(path: str, line: int, refs: object) -> bool:
    return any(same_location(path, p) and start <= line <= end
               for p, start, end in parse_evidence(refs))


def associated(direction: dict, locations: list[dict]) -> bool:
    return any(
        any(same_location(path, loc["path"]) for path in direction.get("paths", []))
        or loc["path"] in direction.get("text", "")
        for loc in locations
    )


def describe_gap(miss: dict, findings: list[dict], trace: dict | None) -> dict:
    locations = [{"path": x["path"], "line": x["line"]} for x in miss["scoring_locations"]]
    result = {"truth_id": miss["id"], "title": miss["title"], "type": miss["class"],
              "scoring_locations": locations}
    # Evidence may cover a second independent operation even though primary_location
    # names the first. This is a diagnostic lead, not a new scored finding.
    result["published_evidence_candidates"] = [
        {"id": f["id"], "type": f.get("vulnerability_type"),
         "primary_location": f.get("primary_location"), "title": f["title"]}
        for f in findings
        if any(covers(loc["path"], loc["line"], f.get("evidence")) for loc in locations)
    ]
    if trace is None:
        result.update(anchor_was_read=None, reads=None, related_directions=None, observations=None)
        return result
    reads, directions, observations = [], [], []
    for task in trace["tasks"]:
        key = task["task_key"]
        for attempt in task.get("attempt_history", []):
            for loc in locations:
                if covers(loc["path"], loc["line"], attempt.get("seen")):
                    reads.append({"task_key": key, "attempt": attempt["attempt"], **loc})
        outcome = task.get("result") or {}
        for direction in outcome.get("host_directions", []):
            if associated(direction, locations):
                directions.append({"origin_task_key": key, **{
                    name: direction.get(name) for name in
                    ("id", "text", "state", "requirement", "assigned_task_key")
                }})
        for observation in outcome.get("observations", []):
            if any(covers(loc["path"], loc["line"], observation.get("evidence")) for loc in locations):
                observations.append({"task_key": key, **{
                    name: observation.get(name) for name in ("kind", "title", "summary", "evidence")
                }})
    result.update(anchor_was_read=bool(reads), reads=reads,
                  related_directions=directions, observations=observations)
    return result


def signal_probe(trace: dict, misses: list[dict]) -> dict:
    project_map = trace["project_map"]
    task = trace["run"]["task_spec"]
    # Explicitly probe today's optional all-scope policy on the old frozen index.
    # Do not imply that this policy was enabled in the historical run.
    frozen = freeze_signals(project_map, {**task, "focus_scope": "all"}, project_map["snapshot_id"])
    matches = {}
    for miss in misses:
        matches[miss["truth_id"]] = [
            {name: item[name] for name in ("risk", "operation", "path", "line")}
            for item in frozen["items"]
            if any(same_location(item["path"], loc["path"]) and item["line"] == loc["line"]
                   for loc in miss["scoring_locations"])
        ]
    return {"scope": "current implementation, frozen index, hypothetical focus_scope=all",
            "signal_implementation_sha256": hashlib.sha256(
                (ROOT / "backend/audit/risk_coverage.py").read_bytes()).hexdigest(),
            "total": len(frozen["items"]), "omitted": frozen["omitted"],
            "anchor_matches": matches,
            "notice": "A signal at the same line does not prove the missing risk was covered; "
                      "database.php query is a SQL signal, not an exception-disclosure signal."}


def analyze(database: Path | None) -> dict:
    manifest = verify_archive()
    score = read_json(ARCHIVE / "scoring-result.json")
    findings = read_json(ARCHIVE / "findings.json")["findings"]
    closure = read_json(ROOT / "datasets/lab30-shop/closure_2969bcf2.json")
    trace, provenance = None, {"available": False, "reason": "--db was not supplied"}
    if database is not None:
        trace, provenance = load_trace(database, manifest["run_id"])
    gaps = [describe_gap(miss, findings, trace) for miss in score["missed_details"]]
    result = {
        "schema_version": "lab30-gap-analysis/v1",
        "scope": "post-run analysis; no new audit, POC execution or score improvement",
        "run_id": manifest["run_id"], "model_requests": 0, "runner_jobs": 0,
        "frozen_assets_verified": len(manifest["files"]),
        "baseline": {key: score[key] for key in
                     ("protocol", "TP", "FN", "FP", "D", "U", "precision", "recall", "f1")},
        "usage": closure["usage"], "run_limits": closure["frozen"]["run_limits"],
        "coverage": closure["coverage"], "trace": provenance, "gaps": gaps,
        "extra_prediction_diagnostics": score["diagnostics"],
    }
    if trace is not None:
        directions = [d for t in trace["tasks"] for d in (t.get("result") or {}).get("host_directions", [])]
        result["direction_counts"] = dict(sorted(Counter(
            f"{d.get('requirement', 'required')}:{d['state']}" for d in directions).items()))
        result["summary"] = {
            "missed_truths_with_anchor_read": sum(g["anchor_was_read"] for g in gaps),
            "missed_truths_with_pending_advisory": [g["truth_id"] for g in gaps if any(
                d["requirement"] == "advisory" and d["state"] == "pending"
                for d in g["related_directions"])],
            "worker_tasks": len(trace["tasks"]),
            "worker_attempts": sum(len(t.get("attempt_history", [])) for t in trace["tasks"]),
        }
        result["frozen_policy"] = {name: trace["run"]["task_spec"].get(name) for name in
                                   ("completion_policy", "focus_scope", "risk_coverage_policy", "orchestration_policy")}
        result["current_signal_probe"] = signal_probe(trace, gaps)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, help="Optional local audit.db, opened read-only")
    parser.add_argument("--out", type=Path, help="JSON destination; defaults to stdout")
    args = parser.parse_args()
    try:
        result = analyze(args.db)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f"Gap analysis failed: {exc}\n")
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        target = args.out.resolve()
        # Keep output away from the live database and immutable release inputs.
        protected = {ROOT / name for name in read_json(ARCHIVE / "reproduction-manifest.json")["files"]}
        protected.add(ARCHIVE / "reproduction-manifest.json")
        if args.db:
            database = args.db.resolve()
            protected.update(Path(str(database) + suffix) for suffix in ("", "-wal", "-shm"))
        if target in {path.resolve() for path in protected}:
            parser.error("--out must not overwrite the database or a frozen release asset")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        print(f"Gap analysis written to {target}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
