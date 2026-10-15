"""Contracts for generic findings and Planner frontier decisions."""
from __future__ import annotations

import asyncio
import io
from types import SimpleNamespace
import zipfile

import pytest
from pydantic import ValidationError
from pydantic_ai import ModelRetry

from audit.agent import _validate_planner_decision
from audit.db import Store
from audit.events import EventBus
from audit.schemas import CreateRunRequest, GoalAssessment, PlannerDecision, TaskFinding
from audit.source import SourceRepository


TASK = {
    "objective": "梳理认证入口、会话检查与敏感操作之间的跨文件边界。",
    "success_criteria": "每一项结论引用已读取的原始源码行号，无法判断时记录缺失上下文。",
    "max_iterations": 2,
    "max_total_attempts": 8,
    "max_planner_rounds": 4,
    "max_workers": 2,
    "stop_on_achieved": True,
    "require_poc": False,
}


def archive(files: dict[str, str]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as value:
        for path, content in files.items():
            value.writestr(path, content)
    return stream.getvalue()


def planner_task(key: str = "entry-flow", **changes) -> dict:
    payload = {
        "task_key": key,
        "title": "认证入口与处理链路",
        "objective": "从入口读取认证检查和敏感操作，确认是否满足审计目标。",
        "acceptance_criteria": "每个结论包含经 worker 实际读取的源码行号。",
        "rationale_summary": "项目图显示入口包含认证模块和处理函数。",
        "source_refs": [{"path": "src/app.php", "start_line": 1, "end_line": 6, "reason": "entry"}],
        "target_symbols": ["handle"],
        "dependencies": [],
        "query_hints": ["auth", "handle"],
        "priority": 70,
    }
    payload.update(changes)
    return payload


def test_task_finding_accepts_a_source_fact_without_attack_template_fields():
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


def test_goal_assessment_keeps_multiple_independently_cited_results():
    assessment = GoalAssessment(
        outcome="achieved",
        summary="当前项目方向确认了认证边界和会话数据流。",
        reasoning="两个结论分别由列出的源码行号支持。",
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

    assert [item.kind for item in assessment.findings] == ["security_boundary", "data_flow"]
    assert assessment.finding is not None
    assert assessment.finding.title == "认证状态读取边界"


def test_run_request_has_one_public_planner_mode():
    request = CreateRunRequest(snapshot_id="snapshot-1", task=TASK)
    assert request.scope == []
    assert request.task.require_poc is False
    assert request.task.max_planner_rounds == 4

    with pytest.raises(ValidationError, match="task"):
        CreateRunRequest(snapshot_id="snapshot-1")
    with pytest.raises(ValidationError, match="prompt_id"):
        CreateRunRequest(snapshot_id="snapshot-1", task=TASK, prompt_id="P0")


def test_planner_decision_uses_task_keys_and_multi_file_reading_instructions():
    decision = PlannerDecision(
        goal_state="continue",
        basis_summary="入口文件静态 include 认证和处理模块，先验证跨文件关系。",
        next_action="让 worker 读取入口和处理函数。",
        tasks=[
            planner_task(
                source_refs=[
                    {"path": "src/app.php", "start_line": 1, "end_line": 6, "reason": "entry"},
                    {"path": "src/handler.php", "start_line": 1, "end_line": 8, "reason": "operation"},
                ],
            ),
        ],
    )
    assert len(decision.tasks[0].source_refs) == 2
    assert decision.tasks[0].dependencies == []

    with pytest.raises(ValidationError, match="duplicate"):
        PlannerDecision(
            goal_state="continue",
            basis_summary="项目图需要两个方向。",
            tasks=[planner_task(), planner_task()],
        )


def test_host_rejects_planner_references_or_dependencies_outside_the_frozen_map():
    project_map = {
        "files": [
            {"path": "src/app.php", "line_count": 8},
            {"path": "src/handler.php", "line_count": 12},
        ],
    }
    outside = PlannerDecision(
        goal_state="continue",
        basis_summary="尝试读取未知路径。",
        tasks=[planner_task(source_refs=[{"path": "secrets.php", "start_line": 1, "end_line": 2}])],
    )
    with pytest.raises(ModelRetry, match="冻结范围外"):
        _validate_planner_decision(outside, project_map, [])

    unknown_dependency = PlannerDecision(
        goal_state="continue",
        basis_summary="尝试引用未创建任务。",
        tasks=[planner_task(dependencies=["missing-task"])],
    )
    with pytest.raises(ModelRetry, match="依赖不存在"):
        _validate_planner_decision(unknown_dependency, project_map, [])

    cyclic = PlannerDecision(
        goal_state="continue",
        basis_summary="两个方向错误地互相等待。",
        tasks=[
            planner_task("entry", dependencies=["operation"]),
            planner_task("operation", dependencies=["entry"]),
        ],
    )
    with pytest.raises(ModelRetry, match="循环"):
        _validate_planner_decision(cyclic, project_map, [])


def test_explicit_vendor_scope_is_frozen_into_the_project_map(tmp_path):
    """Default exclusions are convenience only; an explicit PHP selection remains legal."""
    from audit.app import create_run

    store = Store(tmp_path / "audit.db")
    repository = SourceRepository(tmp_path / "source-data")
    try:
        snapshot = repository.import_zip(
            archive({
                "src/app.php": "<?php\nfunction app() { return true; }\n",
                "vendor/library.php": "<?php\nfunction guarded_library() { return true; }\n",
                "assets/readme.txt": "not PHP",
            }),
            "scope.zip",
        )
        state = SimpleNamespace(
            repository=repository,
            store=store,
            settings=SimpleNamespace(model=SimpleNamespace(label="test-model")),
            bus=EventBus(store),
            worker=SimpleNamespace(notify=lambda: None),
        )
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))

        created = asyncio.run(create_run(
            request,
            CreateRunRequest(snapshot_id=snapshot["id"], scope=["vendor/library.php"], task=TASK),
        ))

        assert created["scope"] == ["vendor/library.php"]
        project_map = store.get_project_map(created["id"])
        assert project_map is not None and project_map["scope"] == ["vendor/library.php"]
        assert store.list_run_units(created["id"]) == []
    finally:
        store.close()
