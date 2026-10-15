"""A whole uploaded project is the audit scope, whatever language it is written in.

The historical API froze an explicit list of PHP files into ``runs.scope``.  A
Planner-led run over a complete project freezes ``scope_mode="snapshot"`` instead and
stores no list, so anything that rebuilds a path set from ``run["scope"]`` alone would
hand every worker an empty policy: every tool call would be rejected as out of scope and
every task would end up ``blocked``.  These tests pin the single helper that decides.
"""
import asyncio
from pathlib import Path

import pytest

from audit.agent import AuditDeps
from audit.runtime import AgentPolicy, Execution, SourceLedger, allowed_paths_for_run
from audit.source import SourceRepository
from tests.test_source import make_zip


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "source-data")


def test_allowed_paths_for_run_distinguishes_snapshot_from_explicit_scope():
    assert allowed_paths_for_run({"scope_mode": "snapshot", "scope": []}) is None
    assert allowed_paths_for_run({"scope_mode": "explicit", "scope": ["a.php"]}) == {"a.php"}
    # A row written before the column existed keeps its original frozen-scope meaning.
    assert allowed_paths_for_run({"scope": ["a.php"]}) == {"a.php"}
    assert allowed_paths_for_run({}) == set()


def _deps(repository: SourceRepository, snapshot_id: str, run: dict) -> AuditDeps:
    policy = AgentPolicy(request_seconds=1, tool_seconds=5)
    execution = Execution({"responses": 1, "tools": 4, "seconds": 5}, policy, lambda _event: None)
    execution.enter("explore")
    allowed = allowed_paths_for_run(run)
    return AuditDeps(
        repository=repository,
        snapshot_id=snapshot_id,
        unit={"file_path": "index.php"},
        execution=execution,
        ledger=SourceLedger(policy.source_bytes),
        allowed_paths=frozenset(allowed) if allowed is not None else None,
    )


def test_snapshot_scope_lets_a_worker_read_dependency_and_non_php_files(repository):
    snapshot = repository.import_zip(make_zip([
        ("index.php", "<?php require 'vendor/lib/helper.inc';"),
        ("vendor/lib/helper.inc", "<?php function vendor_helper() { return true; }"),
        ("static/js/app.js", "const TODO_MARKER = 1;\n"),
    ]), "snapshot-scope.zip")
    run = {"snapshot_id": snapshot["id"], "scope": [], "scope_mode": "snapshot"}
    deps = _deps(repository, snapshot["id"], run)
    assert deps.allowed_paths is None

    vendor = asyncio.run(deps.call("read_source", {"path": "vendor/lib/helper.inc", "start": 1, "end": 2}))
    assert "vendor_helper" in vendor
    javascript = asyncio.run(deps.call("search_code", {"query": "TODO_MARKER", "path": None}))
    assert "static/js/app.js" in javascript
    assert {item["path"] for item in deps.reads} == {"vendor/lib/helper.inc", "static/js/app.js"}


def test_explicit_scope_still_refuses_files_outside_the_frozen_list(repository):
    snapshot = repository.import_zip(make_zip([
        ("index.php", "<?php require 'vendor/lib/helper.inc';"),
        ("vendor/lib/helper.inc", "<?php function vendor_helper() { return true; }"),
    ]), "explicit-scope.zip")
    run = {"snapshot_id": snapshot["id"], "scope": ["index.php"], "scope_mode": "explicit"}
    deps = _deps(repository, snapshot["id"], run)
    assert deps.allowed_paths == frozenset({"index.php"})

    # The tool layer turns the rejection into a missing-context report rather than
    # letting the error escape, so the worker records it and stays within its scope.
    refused = asyncio.run(deps.call("read_source", {"path": "vendor/lib/helper.inc", "start": 1, "end": 2}))
    assert "frozen scope" in refused
    assert deps.reads == []


def test_binary_assets_are_navigable_but_reading_them_reports_missing_context(repository):
    snapshot = repository.import_zip(make_zip([
        ("index.php", "<?php echo 1;"),
        ("assets/logo.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"),
    ]), "assets.zip")
    run = {"snapshot_id": snapshot["id"], "scope": [], "scope_mode": "snapshot"}
    deps = _deps(repository, snapshot["id"], run)
    text = asyncio.run(deps.call("read_source", {"path": "assets/logo.png", "start": 1, "end": 2}))
    assert "未能补读" in text and "cannot be decoded" in text
    # The unreadable asset is registered in the snapshot for navigation.
    snapshot_json = repository.get_snapshot(snapshot["id"])
    assert snapshot_json["stats"]["binary_files"] == 1


def test_pure_non_php_project_reaches_a_worker_with_real_context(repository):
    """The end-to-end guard for P1.4: a JS/Python project must not be all-blocked."""
    snapshot = repository.import_zip(make_zip([
        ("app.py", "from flask import Flask\napp = Flask(__name__)\n"),
        ("templates/index.html", "<form action='/todos' method='post'></form>\n"),
        ("static/app.js", "fetch('/api/todos');\n"),
        ("requirements.txt", "flask==3.0.0\n"),
    ]), "pure-web.zip")
    bundle = repository.build_context_bundle(snapshot["id"], {"objective": "找出所有 HTTP 入口"})
    assert bundle["excerpts"]
    assert all(Path(item["path"]).suffix != ".php" for item in bundle["excerpts"])
    assert bundle["relation_summary"]["map_stats"]["files"] == 4
