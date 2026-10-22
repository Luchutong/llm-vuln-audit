"""Housekeeping APIs: deleting runs, snapshots and prompts.

The teacher's "测试记录没有提供删除接口" gap.  These tests exercise the Store
cascade directly (the route handlers are thin wrappers that translate
ValueError -> 409) and assert that deleting a finished audit leaves no orphan
rows across the tables it owns.
"""
from __future__ import annotations

import pytest

from audit.db import Store


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "audit.db")
    yield s
    s.close()


def _make_run(store: Store, run_id: str = "run1", status: str = "completed",
              snapshot_id: str = "snap1", project_id: str | None = None) -> None:
    store.create_run(
        {
            "id": run_id,
            "snapshot_id": snapshot_id,
            "snapshot_name": "snap.zip",
            "scope": ["a.php"],
            "prompt_id": "custom-prompt",
            "prompt_label": "Custom",
            "prompt_text": "…",
            "model": "test-model",
            "budgets": {"responses": 1, "tools": 0, "seconds": 30},
            "created_at": "2026-01-01T00:00:00+00:00",
        },
        [
            {"id": "u1", "file_path": "a.php", "symbol": "<top>",
             "start_line": 1, "end_line": 10, "priority": 0},
        ],
    )
    if project_id:
        store._write(
            "UPDATE runs SET project_id = ? WHERE id = ?", (project_id, run_id)
        )
    store._write(
        "UPDATE runs SET status = ? WHERE id = ?", (status, run_id)
    )


def _add_finding_with_verification(store: Store, run_id: str, finding_id: str = "f1") -> None:
    finding = {
        "id": finding_id,
        "run_id": run_id,
        "unit_id": "u1",
        "fingerprint": "fp-" + finding_id,
        "category": "sqli",
        "finding_kind": "",
        "title": "SQLi",
        "severity": "high",
        "summary": "s",
        "evidence": "e",
        "input_source": "i",
        "propagation": "p",
        "dangerous_operation": "d",
        "protection": "",
        "preconditions": "",
        "missing_context": [],
        "poc": {},
        "remediation": "",
        "validation_state": "candidate",
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    store.add_finding(finding)
    store.add_verification({
        "id": "v1",
        "finding_id": finding_id,
        "created_at": "2026-01-01T00:00:00+00:00",
        "execution_status": "success",
        "verdict": "confirmed",
        "original_script": "",
        "modified_script": "",
        "modification_notes": "",
        "target_version": "",
        "command": "",
        "expected_result": "",
        "normal_observation": "",
        "attack_observation": "",
        "browser_execution": False,
        "notes": "",
        "files": [],
    })
    store.append_event(run_id, "u1", "finding_recorded", {"finding_id": finding_id})


def test_delete_run_cascades_every_owned_row(store: Store) -> None:
    _make_run(store)
    _add_finding_with_verification(store, "run1")

    summary = store.delete_run("run1")

    assert summary["run_id"] == "run1"
    assert summary["deleted"]["runs"] == 1
    assert summary["deleted"]["findings"] == 1
    assert summary["deleted"]["verifications"] == 1
    assert summary["deleted"]["run_units"] == 1
    assert summary["deleted"]["events"] >= 1

    # Nothing left behind.
    assert store.get_run("run1") is None
    assert store.get_finding("f1") is None
    assert store.list_verifications("f1") == []
    assert store._row("SELECT COUNT(*) AS n FROM run_units WHERE run_id = ?", ("run1",))["n"] == 0
    assert store._row("SELECT COUNT(*) AS n FROM events WHERE run_id = ?", ("run1",))["n"] == 0


def test_delete_run_refuses_active_runs(store: Store) -> None:
    for status in ("pending", "running"):
        _make_run(store, run_id=f"run-{status}", status=status)
        with pytest.raises(ValueError, match=status):
            store.delete_run(f"run-{status}")
        assert store.get_run(f"run-{status}") is not None, f"{status} run must survive"


def test_delete_run_allows_paused_and_terminal(store: Store) -> None:
    for i, status in enumerate(("paused", "completed", "failed", "cancelled")):
        _make_run(store, run_id=f"run-{status}", status=status)
        summary = store.delete_run(f"run-{status}")
        assert summary["deleted"]["runs"] == 1


def test_delete_missing_run_raises(store: Store) -> None:
    with pytest.raises(KeyError):
        store.delete_run("does-not-exist")


def test_delete_terminal_runs_skips_active(store: Store) -> None:
    _make_run(store, run_id="done1", status="completed")
    _make_run(store, run_id="done2", status="failed")
    _make_run(store, run_id="busy", status="running")

    result = store.delete_terminal_runs()
    assert result["deleted_runs"] == 2
    assert {item["run_id"] for item in result["runs"]} == {"done1", "done2"}
    assert store.get_run("busy") is not None, "active run must survive the sweep"


def test_delete_terminal_runs_can_scope_to_project(store: Store) -> None:
    _make_run(store, run_id="p1-run", status="completed", project_id="proj1")
    _make_run(store, run_id="p2-run", status="completed", project_id="proj2")

    result = store.delete_terminal_runs(project_id="proj1")
    assert result["deleted_runs"] == 1
    assert store.get_run("p1-run") is None
    assert store.get_run("p2-run") is not None


def test_delete_snapshot_refuses_when_runs_reference_it(store: Store) -> None:
    store.add_snapshot({
        "id": "snap1", "name": "snap.zip", "created_at": "2026-01-01T00:00:00+00:00",
        "archive_sha256": "x", "source": "upload", "file_count": 1, "unit_count": 1,
        "warning_count": 0,
    })
    _make_run(store, run_id="bound-run", snapshot_id="snap1")

    with pytest.raises(ValueError, match="referenced by 1 run"):
        store.delete_snapshot("snap1")
    assert store.get_snapshot("snap1") is not None


def test_delete_snapshot_succeeds_without_runs(store: Store) -> None:
    store.add_snapshot({
        "id": "snap2", "name": "snap.zip", "created_at": "2026-01-01T00:00:00+00:00",
        "archive_sha256": "x", "source": "upload", "file_count": 1, "unit_count": 1,
        "warning_count": 0,
    })
    assert store.delete_snapshot("snap2") is True
    assert store.get_snapshot("snap2") is None


def test_delete_prompt_refuses_builtin_and_referenced(store: Store) -> None:
    store.upsert_builtin_prompt({
        "id": "builtin-1", "label": "P0", "phase": "baseline", "text": "…",
        "reason": "", "issues": [], "parent_id": None,
        "created_at": "2026-01-01T00:00:00+00:00",
    })
    with pytest.raises(ValueError, match="Built-in"):
        store.delete_prompt("builtin-1")

    store.add_prompt({
        "id": "draft", "label": "Draft", "phase": "custom", "text": "…",
        "reason": "", "issues": "[]", "parent_id": None,
        "created_at": "2026-01-01T00:00:00+00:00", "builtin": 0,
    })
    _make_run(store, run_id="uses-draft")
    store._write("UPDATE runs SET prompt_id = 'draft' WHERE id = 'uses-draft'")
    with pytest.raises(ValueError, match="referenced by 1 run"):
        store.delete_prompt("draft")

    # Orphan draft deletes cleanly.
    store._write("DELETE FROM runs WHERE id = 'uses-draft'")
    assert store.delete_prompt("draft") is True
    assert store.get_prompt("draft") is None


def test_deletion_refreshes_project_latest_records_and_counters(store: Store) -> None:
    store.add_project({"id": "project", "name": "Source", "content_key": "content"})
    for ident, stamp in (("old", "2026-01-01"), ("latest", "2026-02-01")):
        store.add_snapshot({"id": ident, "name": ident + ".zip", "created_at": stamp,
                            "archive_sha256": ident, "source": "upload"})
        store.attach_snapshot_project(ident, "project", "content", "unknown")
        _make_run(store, run_id="run-" + ident, snapshot_id=ident, project_id="project")
        store._write("UPDATE runs SET created_at = ? WHERE id = ?", (stamp, "run-" + ident))
    store._write("UPDATE projects SET run_count = 2, latest_run_id = 'run-latest' WHERE id = 'project'")
    store.delete_run("run-latest")
    project = store.get_project("project")
    assert project["run_count"] == 1 and project["latest_run_id"] == "run-old"
    store.delete_snapshot("latest")
    project = store.get_project("project")
    assert project["snapshot_count"] == 1 and project["latest_snapshot_id"] == "old"
    store.delete_run("run-old")
    store.delete_snapshot("old")
    project = store.get_project("project")
    assert project["run_count"] == project["snapshot_count"] == 0
    assert project["latest_run_id"] is None and project["latest_snapshot_id"] is None
