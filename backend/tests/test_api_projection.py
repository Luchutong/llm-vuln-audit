"""What `GET /api/runs/{id}` is allowed to say, and how much of it.

The run response is polled after every event, so it is the one surface where a field that
is merely *available* is not the same as a field that belongs there. Two things are pinned
here: a module row names a directory under a key that says so (the old `path` key made a
plan cite a module as a source file and send a worker to read a directory), and the pinned
investigations travel without their payloads (the answer is fetched one topic at a time).

The report renders from this same bundle, so the projection is also what the reviewer sees.
"""
from __future__ import annotations

import json

import pytest

from audit.app import _project_map_projection, _run_bundle
from audit.db import Store
from audit.source import SourceRepository
from tests.test_goal_tasks import create_planner_run


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "source-data")


def test_module_rows_name_their_directory_and_nothing_else_claims_to():
    """`modules[]` is the one architectural grouping that is not a file."""
    projection = _project_map_projection("run-1", {
        "snapshot_id": "s1",
        "scope": ["src/auth.php"],
        "stats": {"files": 1},
        "directories": ["src"],
        "entrypoints": [{"path": "public/index.php"}],
        "architecture": {
            "modules": [{"path": "src", "file_count": 3, "roles": ["source"]}],
            "bootstrap_files": [],
        },
    })

    module = projection["architecture"]["modules"][0]
    assert module["directory"] == "src"
    # Renamed, not duplicated: a row that still answered to `path` would keep the trap.
    assert "path" not in module
    assert module["file_count"] == 3
    # The file-shaped entries beside it keep the key that means a file.
    assert projection["entrypoints"][0]["path"] == "public/index.php"
    assert projection["directories"] == ["src"]


def test_the_run_bundle_serves_pinned_investigations_without_their_payloads(store, repository):
    """A poll must not grow with research the caller never asked for."""
    run, _snapshot = create_planner_run(store, repository)
    store.record_investigation({
        "run_id": run["id"],
        "round_no": 1,
        "kind": "recon",
        "tool": "investigate_project",
        "topic": "入口在哪",
        "payload": {"text": "很长的一段侦察简报" * 200},
    })

    bundle = _run_bundle(type("S", (), {"store": store})(), run["id"])

    overview = bundle["investigations"]
    assert overview["total"] == 1 and overview["by_status"] == {"active": 1}
    assert [item["topic"] for item in overview["recent"]] == ["入口在哪"]
    # The row travels, the answer does not. Asserted on the serialised bundle, because a
    # payload key that happens to be None and an absent one read the same to a type check
    # but not to a proxy counting bytes.
    assert overview["recent"][0]["payload"] is None
    assert "侦察简报" not in json.dumps(bundle["investigations"], ensure_ascii=False)
