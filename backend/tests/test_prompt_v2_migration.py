"""Additive Prompt-v2 migration and legacy fingerprint collision compatibility."""
from __future__ import annotations

import sqlite3
import uuid

from audit.db import Store, now
from audit.project_findings import ledger_record
from tests.test_goal_tasks import run_payload
from tests.test_project_findings import _finding, _project


def test_pre_v2_database_preserves_rows_and_gains_legacy_defaults(tmp_path):
    path = tmp_path / "old.db"
    store = Store(path)
    store.add_prompt({"id": "old-prompt", "label": "旧提示词", "text": "旧正文", "created_at": now()})
    store.create_run(run_payload({"id": "snapshot", "name": "old.zip"}, "run", ["legacy.php"]))
    finding = _finding()
    store.add_finding(finding)
    project = _project(store)
    merged = store.merge_project_finding(project["id"], "run", ledger_record(finding))
    store.add_prompt_experiment({"id": "old-experiment", "created_at": now(), "status": "completed", "variants": ["P0-basic"]})
    store.close()
    # Remove exactly the additive v2 columns to model the actual previous release.
    with sqlite3.connect(path) as raw:
        for table, columns in {
            "prompts": ("kind", "contract_version"), "runs": ("worker_strategy",),
            "findings": ("vulnerability_type", "primary_location"),
            "project_findings": ("vulnerability_type", "primary_location"),
            "prompt_experiments": ("protocol", "manifest", "trials", "summary"),
        }.items():
            for column in columns:
                raw.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
    reopened = Store(path)
    try:
        prompt = reopened.get_prompt("old-prompt")
        assert prompt["text"] == "旧正文" and prompt["kind"] == "legacy" and prompt["contract_version"] == ""
        assert reopened.get_run("run")["worker_strategy"] == {}
        record = reopened.get_finding(finding["id"])
        assert record["vulnerability_type"] == "" and record["primary_location"] == {}
        ledger = reopened.get_project_finding(merged["project_finding_id"])
        assert ledger["vulnerability_type"] == "" and ledger["primary_location"] == {}
        experiment = reopened.get_prompt_experiment("old-experiment")
        assert experiment["protocol"] == "legacy_unit_v1"
        assert experiment["manifest"] == {} and experiment["trials"] == [] and experiment["summary"] == {}
    finally:
        reopened.close()


def test_distinct_known_causes_with_identical_legacy_fingerprint_create_separate_ledger_rows(tmp_path):
    store = Store(tmp_path / "audit.db")
    try:
        project = _project(store)
        common = _finding(path="public/a.php", symbol="<project>", sink="shared sensitive operation")
        first = {**common, "vulnerability_type": "sqli", "primary_location": {"path": "public/a.php", "line": 10}}
        second = {**common, "id": uuid.uuid4().hex, "vulnerability_type": "mass_assignment",
                  "primary_location": {"path": "public/a.php", "line": 10}}
        assert first["fingerprint"] == second["fingerprint"]
        one = store.merge_project_finding(project["id"], "run-1", ledger_record(first))
        two = store.merge_project_finding(project["id"], "run-2", ledger_record(second))
        assert one["project_finding_id"] != two["project_finding_id"]
        rows = store.list_project_findings(project["id"])
        assert {row["vulnerability_type"] for row in rows} == {"sqli", "mass_assignment"}
        # Repeating either incoming old-style fingerprint still finds its own cause.
        again = store.merge_project_finding(project["id"], "run-3", ledger_record({**second, "id": uuid.uuid4().hex}))
        assert again["project_finding_id"] == two["project_finding_id"]
    finally:
        store.close()
