"""Finding cleanup is atomic and cannot seed the next audit with deleted history."""
from __future__ import annotations

import json
import time

import pytest

from audit.db import Store
from audit.project_findings import backfill_project_ledger, canonical_fingerprint, ledger_record

STAMP = "2026-10-27T00:00:00+00:00"


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


def project(store, name):
    store.add_project({"id": name, "content_key": name, "name": name})
    store.add_snapshot({
        "id": "zip-" + name, "name": name + ".zip", "archive_sha256": name,
        "source": "upload", "created_at": STAMP,
    })
    store.attach_snapshot_project("zip-" + name, name, name, "lab30")


def run_record(name, owner=None, *, baseline=None):
    return {
        "id": name, "snapshot_id": "zip-" + (owner or "legacy"), "snapshot_name": "source.zip",
        "scope": ["a.php"], "prompt_id": "test", "prompt_label": "test", "prompt_text": "test",
        "model": "offline", "budgets": {"responses": 1, "tools": 1, "seconds": 30},
        "created_at": STAMP, "project_id": owner, "project_baseline": baseline or [],
    }


def run(store, name, owner=None, *, status="completed", baseline=None):
    store.create_run(run_record(name, owner, baseline=baseline))
    store._write("UPDATE runs SET status=? WHERE id=?", (status, name))


def finding(store, name, run_id, *, owner=None, path="a.php", linked=True):
    record = {
        "id": name, "run_id": run_id, "unit_id": name,
        "fingerprint": canonical_fingerprint(path, "entry", "query(input)"),
        "category": "task_goal", "finding_kind": "vulnerability", "title": name,
        "severity": "high", "summary": "unsafe input", "file_path": path, "symbol": "entry",
        "evidence": [{"path": path, "start_line": 1, "end_line": 2}],
        "input_source": "request", "propagation": "direct", "dangerous_operation": "query(input)",
        "protection": "none", "preconditions": [], "missing_context": [], "poc": {},
        "remediation": "validate", "validation_state": "candidate", "created_at": STAMP,
    }
    store.add_finding(record)
    ledger_id = None
    if owner is not None:
        merged = store.merge_project_finding(owner, run_id, ledger_record(record))
        ledger_id = merged["project_finding_id"]
        if linked:
            store.link_finding_project(name, ledger_id, merged["revision"])
    return ledger_id


def verification(store, name, finding_id, ledger_id=None):
    store.add_verification({
        "id": name, "finding_id": finding_id, "project_finding_id": ledger_id,
        "created_at": STAMP, "execution_status": "success", "verdict": "confirmed",
        "original_script": "", "modified_script": "", "modification_notes": "",
        "target_version": "", "command": "", "expected_result": "", "normal_observation": "",
        "attack_observation": "", "browser_execution": False, "notes": "", "files": [],
    })


def count(store, table):
    return store._row(f"SELECT COUNT(*) AS n FROM {table}")["n"]


def test_single_delete_removes_all_source_copies_and_verification_dependencies(store):
    project(store, "p")
    run(store, "r1", "p")
    run(store, "r2", "p")
    ledger_id = finding(store, "f1", "r1", owner="p")
    assert finding(store, "f2", "r2", owner="p", linked=False) == ledger_id
    other = finding(store, "other", "r2", owner="p", path="other.php")
    verification(store, "v1", "f1", ledger_id)
    verification(store, "orphan-v", "old-deleted-finding", ledger_id)
    store.set_project_finding_verification(ledger_id, "verified", "confirmed", "v1")
    store._write(
        "INSERT INTO verification_reviews(id,run_id,finding_id,revision,decision,rationale,created_at,verification_id)"
        " VALUES ('review','r1','f1',1,'accept','checked',?,'v1')", (STAMP,),
    )
    store._write(
        "INSERT INTO poc_attempts(key,run_id,finding_id,ledger_id,revision,target_key,state,created_at,updated_at)"
        " VALUES ('attempt','r1','f1',?,1,'lab30','completed',?,?)", (ledger_id, STAMP, STAMP),
    )
    store.add_poc_verification_job({
        "id": "job-row", "verification_id": "v1", "finding_id": "f1",
        "project_finding_id": ledger_id, "run_id": "r1", "job_id": "runner-job", "kind": "http",
    })
    store._write(
        "INSERT INTO attributions(id,run_id,file_path,category,kind,finding_id,created_at)"
        " VALUES ('attr','r1','a.php','sqli','matched','f1',?)", (STAMP,),
    )
    store._write("UPDATE findings SET derived_from_finding_id='f1' WHERE id='other'")
    store.append_event("r1", None, "finding_created", {"finding_id": "f1"})
    store._write("UPDATE runs SET project_baseline=? WHERE id='r2'", (json.dumps([
        store.get_project_finding(ledger_id), store.get_project_finding(other),
    ]),))

    result = store.delete_project_finding(ledger_id)

    assert result["deleted_project_findings"] == 1
    assert result["deleted_run_findings"] == 2
    assert result["affected_project_ids"] == ["p"]
    assert result["deleted"]["verifications"] == 2
    assert result["deleted"]["verification_reviews"] == 1
    assert result["deleted"]["poc_attempts"] == 1
    assert result["deleted"]["poc_verification_jobs"] == 1
    assert result["deleted"]["attributions"] == 1
    assert result["deleted"]["project_finding_cvss_history"] >= 1
    assert store.get_project_finding(ledger_id) is None
    assert store.get_finding("f1") is store.get_finding("f2") is None
    assert store.get_finding("other")["derived_from_finding_id"] is None
    assert store.get_project("p")["finding_counts"]["total"] == 1
    assert [row["id"] for row in store.get_run("r2")["project_baseline"]] == [other]
    assert count(store, "runs") == 2 and count(store, "snapshots") == 1
    assert count(store, "events") >= 1
    assert backfill_project_ledger(store) == 0


@pytest.mark.parametrize('legacy_project_id', [None, ''])
def test_project_clear_includes_unlinked_findings_but_preserves_other_project(store, legacy_project_id):
    for owner in ("p", "q"):
        project(store, owner)
        run(store, "r-" + owner, owner)
        finding(store, "f-" + owner, "r-" + owner, owner=owner)
    run(store, "old", None)
    store._write("UPDATE runs SET snapshot_id='zip-p' WHERE id='old'")
    store._write("UPDATE runs SET project_id=? WHERE id='old'", (legacy_project_id,))
    finding(store, "unlinked", "old", path="old.php")
    store._write("UPDATE runs SET status='running' WHERE id='r-q'")
    result = store.delete_project_findings("p")
    assert result["deleted_project_findings"] == 1
    assert result["deleted_run_findings"] == 2
    assert result["affected_project_ids"] == ["p"]
    assert store.get_finding("unlinked") is None
    assert store.get_finding("f-q") is not None
    assert store.get_project("p")["finding_counts"]["total"] == 0
    assert backfill_project_ledger(store) == 0
    assert store.get_snapshot("zip-p") is not None
    assert store.get_run("old") is not None


def test_global_clear_removes_legacy_and_orphan_validation_rows(store):
    project(store, "p")
    run(store, "r", "p")
    finding(store, "f", "r", owner="p")
    run(store, "legacy")
    finding(store, "legacy-f", "legacy")
    verification(store, "legacy-v", "legacy-f")
    verification(store, "orphan-v", "missing-finding", "missing-ledger")
    result = store.delete_project_findings()
    assert result["deleted_project_findings"] == 1
    assert result["deleted_run_findings"] == 2
    for table in ("findings", "project_findings", "verifications", "project_finding_runs", "project_finding_cvss_history"):
        assert count(store, table) == 0
    assert count(store, "runs") == 2
    assert store.delete_project_findings()["deleted_run_findings"] == 0


def test_foreign_historical_baseline_is_pruned_without_clearing_its_unrelated_jobs(store):
    for owner in ("p", "q"):
        project(store, owner)
        run(store, "r-" + owner, owner)
    ledger_id = finding(store, "f-p", "r-p", owner="p")
    other_id = finding(store, "f-q", "r-q", owner="q")
    store._write("UPDATE runs SET project_baseline=? WHERE id='r-q'", (json.dumps([
        store.get_project_finding(ledger_id), store.get_project_finding(other_id),
    ]),))
    store.add_poc_verification_job({
        "id": "other-job", "verification_id": "other-verification", "finding_id": "f-q",
        "project_finding_id": other_id, "run_id": "r-q", "job_id": "runner-job", "kind": "http",
    })
    store.delete_project_findings("p")
    assert store.get_project_finding(other_id) is not None
    assert count(store, "poc_verification_jobs") == 1
    assert [row["id"] for row in store.get_run("r-q")["project_baseline"]] == [other_id]


@pytest.mark.parametrize("status", ["pending", "running", "paused", "unknown"])
@pytest.mark.parametrize("scope", ["single", "project", "global"])
def test_busy_runs_reject_entire_cleanup_without_partial_deletion(store, status, scope):
    project(store, "p")
    run(store, "r", "p")
    ledger_id = finding(store, "f", "r", owner="p")
    run(store, "busy", "p", status=status)
    call = {
        "single": lambda: store.delete_project_finding(ledger_id),
        "project": lambda: store.delete_project_findings("p"),
        "global": lambda: store.delete_project_findings(),
    }[scope]
    with pytest.raises(ValueError, match="cancel"):
        call()
    assert store.get_finding("f") is not None
    assert store.get_project_finding(ledger_id) is not None
    store._write("UPDATE runs SET status='cancelled' WHERE id='busy'")
    assert call()["deleted_run_findings"] == 1  # failed transactions leave no temp selections


@pytest.mark.parametrize("ownership", ["clock", "agent"])
def test_terminal_status_still_waits_for_live_host_owner(store, ownership):
    project(store, "p")
    run(store, "r", "p")
    finding(store, "f", "r", owner="p")
    if ownership == "clock":
        store._active_clocks["r"] = time.monotonic()
    else:
        store._active_agents["r"] = {"worker": {"role": "worker"}}
    with pytest.raises(ValueError, match="quiescent"):
        store.delete_project_findings("p")
    assert store.get_finding("f") is not None


def test_empty_project_is_guarded_and_missing_resources_are_not_silently_accepted(store):
    project(store, "p")
    run(store, "pending", "p", status="pending")
    with pytest.raises(ValueError):
        store.delete_project_findings("p")
    with pytest.raises(KeyError):
        store.delete_project_findings("missing")
    with pytest.raises(KeyError):
        store.delete_project_finding("missing")
    store._write("UPDATE runs SET status='cancelled' WHERE id='pending'")
    assert store.delete_project_findings("p")["deleted_project_findings"] == 0


def test_cleanup_rolls_back_every_dependency_on_database_failure(store):
    project(store, "p")
    run(store, "r", "p")
    ledger_id = finding(store, "f", "r", owner="p")
    verification(store, "v", "f", ledger_id)
    store._db.execute("CREATE TRIGGER reject_cleanup BEFORE DELETE ON findings BEGIN SELECT RAISE(ABORT,'offline failure'); END")
    with pytest.raises(Exception, match="offline failure"):
        store.delete_project_findings("p")
    assert store.get_finding("f") is not None
    assert count(store, "verifications") == 1
    assert store.get_project_finding(ledger_id) is not None
    store._db.execute("DROP TRIGGER reject_cleanup")
    assert store.delete_project_findings("p")["deleted_run_findings"] == 1


def test_new_run_freezes_current_baseline_atomically_and_does_not_mutate_input(store):
    project(store, "p")
    run(store, "old", "p")
    ledger_id = finding(store, "f", "old", owner="p")
    stale_input = run_record("new", "p", baseline=[store.get_project_finding(ledger_id)])
    store.delete_project_findings("p")
    store.create_run(stale_input, freeze_project_baseline=True)
    assert store.get_run("new")["project_baseline"] == []
    assert stale_input["project_baseline"][0]["id"] == ledger_id
    with pytest.raises(ValueError):
        store.delete_project_findings("p")  # admission wins the opposite ordering


def test_restart_and_explicit_backfill_do_not_restore_cleared_findings(tmp_path):
    db = tmp_path / "restart.db"
    first = Store(db)
    project(first, "p")
    run(first, "r", "p")
    ledger_id = finding(first, "f", "r", owner="p")
    first._write("UPDATE runs SET project_baseline=? WHERE id='r'", (json.dumps([
        first.get_project_finding(ledger_id),
    ]),))
    first.delete_project_findings("p")
    first.close()
    restarted = Store(db)
    try:
        assert backfill_project_ledger(restarted) == 0
        assert restarted.list_project_findings("p") == []
        assert restarted.get_run("r")["project_baseline"] == []
        restarted.create_run(run_record("new", "p"), freeze_project_baseline=True)
        assert restarted.get_run("new")["project_baseline"] == []
    finally:
        restarted.close()
