"""Contract tests for generic, goal-driven PHP source audits.

These tests deliberately avoid the legacy SQLi/XSS/command-injection fixture.  A
goal task can return a neutral source fact, can carry several independently cited
results from one work item, and may omit its scope to audit every indexable file in
the uploaded snapshot.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from audit.db import Store, now
from audit.runtime import AgentPolicy
from audit.schemas import CreateRunRequest, GoalAssessment, TaskFinding


TASK = {
    "objective": "梳理 auth_login 函数中的认证边界和数据流。",
    "success_criteria": "至少保存一项含原始行号证据的认证边界发现。",
    "max_iterations": 2,
    "max_total_attempts": 8,
    "max_workers": 2,
    "stop_on_achieved": True,
}


def _unit(
    unit_id: str,
    path: str,
    symbol: str,
    *,
    priority: int = 0,
    start_byte: int = 0,
) -> dict:
    return {
        "id": unit_id,
        "file_path": path,
        "symbol": symbol,
        "kind": "function",
        "start_line": 3,
        "end_line": 8,
        "start_byte": start_byte,
        "end_byte": start_byte + 120,
        "priority": priority,
        "slice_index": 1,
        "slice_count": 1,
        "cleaned_lines": [
            {"number": 3, "text": f"function {symbol}() {{ return true; }}"},
        ],
    }


def _run_payload(run_id: str) -> dict:
    return {
        "id": run_id,
        "snapshot_id": "snapshot-1",
        "snapshot_name": "target.zip",
        "scope": ["src/auth.php"],
        "prompt_id": "goal-task",
        "prompt_label": "目标任务执行器",
        "prompt_text": "",
        "model": "test-model",
        "budgets": {"responses": 8, "tools": 16, "seconds": 30},
        "agent_policy": AgentPolicy().snapshot(),
        "task_spec": TASK,
        "created_at": now(),
    }


def _stored_finding(run_id: str, unit_id: str, *, number: int, kind: str, title: str) -> dict:
    return {
        "id": uuid4().hex,
        "run_id": run_id,
        "unit_id": unit_id,
        "fingerprint": f"task-contract:{unit_id}:{number}",
        # A work item may persist several generic results, so their durable
        # categories remain distinct without pretending they are fixed CVE classes.
        "category": f"task_goal:{number}",
        "finding_kind": kind,
        "title": title,
        "severity": "informational",
        "summary": "这是一项由上传源码原始行号支撑的通用目标发现。",
        "evidence": [{"path": "src/auth.php", "start_line": 3, "end_line": 8}],
        "input_source": "",
        "propagation": "",
        "dangerous_operation": "",
        "protection": "session 用户标识决定认证状态。",
        "preconditions": [],
        "missing_context": [],
        "poc": None,
        "remediation": "",
        "validation_state": "candidate",
        "validation_errors": [],
        "verdict": None,
        "created_at": now(),
    }


def test_task_finding_accepts_a_minimal_source_fact_without_vulnerability_template_fields():
    """A generic goal should not need input, sink, POC, or remediation fields."""
    finding = TaskFinding(
        title="认证状态读取边界",
        summary="认证函数从 session 读取用户标识并据此决定后续分支。",
        evidence="src/auth.php:3-8",
    )

    assert finding.kind == "source_observation"
    assert finding.severity is None
    assert finding.input_source == ""
    assert finding.dangerous_operation == ""
    assert finding.poc is None
    assert finding.remediation == ""


def test_goal_assessment_supports_multiple_generic_results_and_legacy_first_result_view():
    """One target pass can establish several source facts with different kinds."""
    assessment = GoalAssessment(
        outcome="achieved",
        summary="当前单元确认了认证边界和会话数据流。",
        reasoning="两个结论均直接由列出的源码范围支持。",
        findings=[
            {
                "title": "认证状态读取边界",
                "kind": "security_boundary",
                "summary": "认证函数从 session 读取用户标识并据此决定后续分支。",
                "evidence": "src/auth.php:3-5",
                "protection": "会话用户标识是认证状态的输入边界。",
            },
            {
                "title": "认证后的用户数据流",
                "kind": "data_flow",
                "summary": "认证后的用户标识被传入账户查询函数以加载账户资料。",
                "evidence": "src/auth.php:5-8",
                "severity": "low",
                "propagation": "session 用户标识传入账户查询函数。",
            },
        ],
    )

    assert [finding.kind for finding in assessment.findings] == ["security_boundary", "data_flow"]
    assert assessment.finding is not None
    assert assessment.finding.title == "认证状态读取边界"
    assert assessment.findings[0].poc is None
    assert assessment.findings[1].severity == "low"


def test_goal_request_may_omit_scope_but_fixed_audit_cannot():
    """An empty scope is the task-mode shorthand for the uploaded PHP source set."""
    task_request = CreateRunRequest(snapshot_id="snapshot-1", task=TASK)
    assert task_request.scope == []
    assert task_request.task is not None
    assert task_request.task.require_poc is False

    with pytest.raises(ValidationError, match="scope is required"):
        CreateRunRequest(snapshot_id="snapshot-1", prompt_id="P0")


def test_goal_api_expands_empty_scope_and_plans_user_named_units_first(tmp_path):
    """Task setup freezes all selectable files and does not reuse sink-priority order."""
    from audit.app import create_run

    store = Store(tmp_path / "audit.db")
    try:
        units = [
            # Its high legacy priority must not outrank a unit named in the target.
            _unit("other-unit", "src/other.php", "render_page", priority=99, start_byte=10),
            _unit("auth-unit", "src/auth.php", "auth_login", priority=0, start_byte=20),
        ]
        snapshot = {
            "id": "snapshot-1",
            "name": "target.zip",
            "files": [
                {"path": "src/other.php", "excluded": False},
                {"path": "src/auth.php", "excluded": False},
                {"path": "vendor/ignored.php", "excluded": True},
            ],
            "units": units,
        }
        state = SimpleNamespace(
            repository=SimpleNamespace(get_snapshot=lambda _snapshot_id: snapshot),
            store=store,
            settings=SimpleNamespace(model=SimpleNamespace(label="test-model")),
            worker=SimpleNamespace(notify=lambda: None),
        )
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))

        created = asyncio.run(create_run(request, CreateRunRequest(snapshot_id="snapshot-1", task=TASK)))

        assert created is not None
        assert created["scope"] == ["src/auth.php", "src/other.php"]
        work = store.list_task_work_items(created["id"])
        assert [item["unit_id"] for item in work] == ["auth-unit", "other-unit"]
        assert all("vendor/ignored.php" not in item["summary"] for item in work)
    finally:
        store.close()


def test_goal_api_allows_an_explicitly_selected_default_excluded_php_file(tmp_path):
    """Directory defaults keep first passes small without closing a source boundary."""
    from audit.app import create_run

    store = Store(tmp_path / "audit.db")
    try:
        vendor_unit = _unit("vendor-unit", "vendor/library.php", "library_guard")
        snapshot = {
            "id": "snapshot-1",
            "name": "target.zip",
            "files": [
                {"path": "src/auth.php", "excluded": False, "is_php": True},
                {"path": "vendor/library.php", "excluded": True, "is_php": True},
                {"path": "assets/readme.txt", "excluded": True, "is_php": False},
            ],
            "units": [vendor_unit],
        }
        state = SimpleNamespace(
            repository=SimpleNamespace(get_snapshot=lambda _snapshot_id: snapshot),
            store=store,
            settings=SimpleNamespace(model=SimpleNamespace(label="test-model")),
            worker=SimpleNamespace(notify=lambda: None),
        )
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))

        created = asyncio.run(create_run(
            request,
            CreateRunRequest(snapshot_id="snapshot-1", scope=["vendor/library.php"], task=TASK),
        ))

        assert created is not None
        assert created["scope"] == ["vendor/library.php"]
        assert [item["unit_id"] for item in store.list_task_work_items(created["id"])] == ["vendor-unit"]
    finally:
        store.close()


def test_task_work_persists_multiple_generic_findings_with_their_kinds(tmp_path):
    """The durable task result keeps every finding instead of a single vulnerability slot."""
    store = Store(tmp_path / "audit.db")
    try:
        run_id = "generic-findings-run"
        source_unit = _unit("auth-unit", "src/auth.php", "auth_login")
        store.create_run(_run_payload(run_id), [source_unit])
        run = store.claim_next_run()
        assert run is not None
        work = store.claim_next_task_work(run_id, "worker-1")
        assert work is not None

        records = [
            _stored_finding(run_id, source_unit["id"], number=1, kind="security_boundary", title="认证状态读取边界"),
            _stored_finding(run_id, source_unit["id"], number=2, kind="data_flow", title="认证后的用户数据流"),
        ]
        resolved = store.resolve_task_work(
            work["id"],
            outcome="achieved",
            result={"summary": "保存两项源代码目标发现。", "reasoning": "测试结论"},
            usage={"requests": 1},
            seen=[{"path": "src/auth.php", "start_line": 3, "end_line": 8}],
            findings=records,
            goal_reason="两项通用发现满足目标。",
        )

        assert resolved is not None
        assert resolved["finding_ids"] == [record["id"] for record in records]
        findings = store.list_findings(run_id)
        assert [finding["category"] for finding in findings] == ["task_goal:1", "task_goal:2"]
        assert [finding["finding_kind"] for finding in findings] == ["security_boundary", "data_flow"]
        assert all(finding["poc"] is None for finding in findings)
        assert all(finding["input_source"] == "" for finding in findings)
    finally:
        store.close()
