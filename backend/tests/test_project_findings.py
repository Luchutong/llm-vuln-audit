"""The project ledger is the cross-run identity of a vulnerability.

A run finding belongs to the attempt that produced it.  The ledger row is "this
vulnerability in this project": a second run that re-finds it must update that row, not
create another one, and a run that does not re-find it must still carry it forward.
"""
from __future__ import annotations

import uuid

import pytest

from audit.db import Store
from audit.project_findings import canonical_fingerprint, ledger_record


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


def _project(store: Store, content_key: str = "key-1") -> dict:
    project = {
        "id": uuid.uuid4().hex,
        "content_key": content_key,
        "name": "DVWA",
        "target_profile": "dvwa",
    }
    store.add_project(project)
    return store.get_project_by_content_key(content_key)


def _finding(
    *,
    path: str = "vulnerabilities/sqli/index.php",
    symbol: str = "index",
    sink: str = "SELECT * FROM users WHERE id = '$_GET[id]'",
    severity: str = "high",
    title: str = "SQL 注入",
    summary: str = "用户输入直接拼入 SQL。",
    evidence: list[dict] | None = None,
) -> dict:
    return {
        "id": uuid.uuid4().hex,
        "run_id": "run",
        "unit_id": "unit",
        "fingerprint": canonical_fingerprint(path, symbol, sink),
        "file_path": path,
        "symbol": symbol,
        "category": "task_goal",
        "finding_kind": "vulnerability",
        "title": title,
        "severity": severity,
        "summary": summary,
        "evidence": evidence or [{"path": path, "start_line": 10, "end_line": 12}],
        "input_source": "$_GET[id]",
        "propagation": "直接拼接",
        "dangerous_operation": sink,
        "protection": "无",
        "preconditions": [],
        "missing_context": [],
        "poc": {"language": "bash", "script": "curl ..."},
        "remediation": "参数化查询",
        "validation_state": "candidate",
        "created_at": "2026-10-20T00:00:00+00:00",
    }


def _merge(store: Store, project: dict, run_id: str, finding: dict) -> dict:
    return store.merge_project_finding(project["id"], run_id, ledger_record(finding))


def test_project_counts_name_every_verification_state(store):
    """An unavailable environment must not make the ledger look empty.

    The counts drove the frontend's project summary; counting only ``verified`` and
    ``unverified`` reported zero for both after a run whose runner was unreachable.
    """
    project = _project(store)
    first = _merge(store, project, "run-1", _finding(path="vulnerabilities/sqli/source/low.php"))
    second = _merge(store, project, "run-1", _finding(path="vulnerabilities/brute/source/low.php"))
    store.set_project_finding_verification(
        first["project_finding_id"], "environment_unavailable", "uncertain", None
    )
    store.set_project_finding_verification(
        second["project_finding_id"], "verified", "confirmed", None
    )

    counts = store.list_projects()[0]["finding_counts"]
    assert counts["total"] == 2
    assert counts["verified"] == 1
    assert counts["environment_unavailable"] == 1
    assert counts["unverified"] == 0


def test_the_same_finding_twice_is_one_ledger_row(store):
    project = _project(store)
    finding = _finding()

    first = _merge(store, project, "run-1", finding)
    second = _merge(store, project, "run-2", {**finding, "id": uuid.uuid4().hex})

    assert first["action"] == "created"
    assert second["action"] == "rediscovered"
    assert first["project_finding_id"] == second["project_finding_id"]
    rows = store.list_project_findings(project["id"])
    assert len(rows) == 1
    assert rows[0]["revision"] == 1
    assert rows[0]["last_run_id"] == "run-2"
    assert rows[0]["origin_run_id"] == "run-1"


def test_a_reworded_sink_at_the_same_anchor_merges_into_the_row(store):
    project = _project(store)
    first = _finding(path="includes/auth.php", symbol="handle", sink="unserialize($_POST['data'])")
    second = _finding(path="includes/auth.php", symbol="handle", sink="调用 unserialize 处理 $_POST['data']")

    first_result = _merge(store, project, "run-1", first)
    second_result = _merge(store, project, "run-2", second)

    assert second_result["project_finding_id"] == first_result["project_finding_id"]
    # The sink wording moved, so this is a correction, not a plain rediscovery.
    assert second_result["action"] == "corrected"
    assert second_result["revision"] == 2


def test_a_correction_marks_the_previous_verification_stale(store):
    project = _project(store)
    finding = _finding()
    merged = _merge(store, project, "run-1", finding)
    store.set_project_finding_verification(
        merged["project_finding_id"], "verified", "confirmed", "verification-1"
    )

    _merge(store, project, "run-2", _finding(severity="critical"))

    row = store.get_project_finding(merged["project_finding_id"])
    assert row["revision"] == 2
    assert row["verification_status"] == "stale"
    assert row["verification_verdict"] is None
    assert row["superseded_summary"][0]["revision"] == 1


def test_a_withdrawn_ledger_row_is_not_restored_by_rediscovery(store):
    project = _project(store)
    finding = _finding()
    merged = _merge(store, project, "run-1", finding)
    store.set_project_finding_disposition(
        merged["project_finding_id"], "retract", "误报", run_id="run-1"
    )

    again = _merge(store, project, "run-2", {**finding, "id": uuid.uuid4().hex})

    assert again["project_finding_id"] == merged["project_finding_id"]
    assert again["disposition"] == "retracted"
    # Only the Planner's explicit reopen restores standing.
    restored = store.set_project_finding_disposition(
        merged["project_finding_id"], "reopen", "复核后确认", run_id="run-2"
    )
    assert restored["disposition"] == "open"


def test_carried_records_only_what_this_run_did_not_rediscover(store):
    project = _project(store)
    sql = _merge(store, project, "run-1", _finding())
    xss = _merge(
        store, project, "run-2",
        _finding(
            path="vulnerabilities/xss_r/index.php",
            symbol="index",
            sink="echo $_GET['name']",
            title="反射型 XSS",
        ),
    )

    count = store.record_carried_findings(project["id"], "run-2")
    carried = store.list_run_project_findings("run-2", relation="carried")

    assert count == 1
    assert [row["id"] for row in carried] == [sql["project_finding_id"]]
    assert xss["project_finding_id"] not in {row["id"] for row in carried}


def test_a_second_sink_in_the_same_symbol_is_not_merged(store):
    project = _project(store)
    first = _finding(sink="unserialize($_POST['data'])")
    second = _finding(sink="readfile($_GET['file'])")

    one = _merge(store, project, "run-1", first)
    two = _merge(store, project, "run-1", second)

    assert one["project_finding_id"] != two["project_finding_id"]
    assert len(store.list_project_findings(project["id"])) == 2


def test_a_planner_finding_merges_by_cited_lines_when_the_sink_is_rewritten(store):
    """Planner findings have no symbol, and the model may even change language."""
    project = _project(store)
    anchors = [
        {"path": "vulnerabilities/xss_r/source/low.php", "start_line": 6, "end_line": 8},
        {"path": "vulnerabilities/xss_r/index.php", "start_line": 51, "end_line": 51},
    ]
    first = _finding(
        path="vulnerabilities/xss_r/source/low.php", symbol="<project>",
        sink="未编码HTML输出，浏览器解析<script>执行", evidence=anchors,
    )
    second = _finding(
        path="vulnerabilities/xss_r/source/low.php", symbol="<project>",
        sink="Unescaped output of attacker-controlled input into HTML response",
        evidence=[{**anchors[0], "start_line": 6, "end_line": 8}, anchors[1]],
    )

    one = _merge(store, project, "run-1", first)
    two = _merge(store, project, "run-2", second)

    assert two["project_finding_id"] == one["project_finding_id"]
    assert len(store.list_project_findings(project["id"])) == 1


def test_two_planner_sinks_in_one_file_stay_separate_with_distinct_lines(store):
    project = _project(store)
    path = "vulnerabilities/xss_r/source/low.php"
    first = _finding(
        path=path, symbol="<project>", sink="echo $_GET['name']",
        evidence=[{"path": path, "start_line": 6, "end_line": 8}],
    )
    second = _finding(
        path=path, symbol="<project>", sink="include $_GET['page']",
        evidence=[{"path": path, "start_line": 30, "end_line": 32}],
    )

    one = _merge(store, project, "run-1", first)
    two = _merge(store, project, "run-1", second)

    assert one["project_finding_id"] != two["project_finding_id"]
    assert len(store.list_project_findings(project["id"])) == 2


def test_ambiguous_planner_anchors_create_a_new_row(store):
    """Two ledger rows both overlap the citation: the host must not guess which one it is."""
    project = _project(store)
    path = "vulnerabilities/xss_r/source/low.php"
    first = _finding(
        path=path, symbol="<project>", sink="sink alpha",
        evidence=[{"path": path, "start_line": 1, "end_line": 8}],
    )
    second = _finding(
        path=path, symbol="<project>", sink="sink omega",
        evidence=[{"path": path, "start_line": 5, "end_line": 12}],
    )
    _merge(store, project, "run-1", first)
    _merge(store, project, "run-2", second)

    third = _finding(
        path=path, symbol="<project>", sink="sink zeta",
        evidence=[{"path": path, "start_line": 1, "end_line": 12}],
    )
    merged = _merge(store, project, "run-3", third)

    assert merged["action"] == "created"
    assert len(store.list_project_findings(project["id"])) == 3
