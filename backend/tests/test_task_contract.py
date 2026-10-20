"""Contracts for vulnerability findings, audit observations, and Planner decisions."""
from __future__ import annotations

import asyncio
import io
from types import SimpleNamespace
import zipfile

import pytest
from pydantic import ValidationError
from pydantic_ai import ModelRetry

from audit.agent import _validate_planner_decision
from audit.config import PocSettings
from audit.db import Store
from audit.events import EventBus
from audit.schemas import (
    CreateRunRequest,
    GoalAssessment,
    PlannerDecision,
    PlannerSourceRef,
    TaskFinding,
    TaskObservation,
)
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


def test_source_facts_are_audit_observations_without_vulnerability_template_fields():
    observation = TaskObservation(
        title="认证状态读取边界",
        kind="security_boundary",
        summary="认证函数从 session 读取用户标识并据此决定后续分支。",
        evidence="src/auth.php:3-8",
    )

    assert observation.kind == "security_boundary"
    assert "severity" not in observation.model_dump()


@pytest.mark.parametrize("changes", [{}, {"kind": "data_flow", "severity": "low"}, {"kind": "vulnerability"}, {"severity": "high"}, {"kind": "vulnerability", "severity": None}, {"kind": "vulnerability", "severity": "informational"}])
def test_task_finding_requires_explicit_vulnerability_kind_and_severity(changes):
    with pytest.raises(ValidationError):
        TaskFinding(
            title="认证状态读取边界",
            summary="认证函数从 session 读取用户标识并据此决定后续分支。",
            evidence="src/auth.php:3-8",
            **changes,
        )


def test_vulnerability_poc_remains_optional_without_the_run_requirement():
    finding = TaskFinding(
        title="未鉴权的账户资料读取",
        kind="vulnerability",
        severity="medium",
        summary="请求参数选择账户记录后直接返回资料，读取路径没有认证检查。",
        evidence="src/auth.php:3-8",
    )
    assert finding.poc is None


def test_goal_assessment_keeps_multiple_independently_cited_results():
    assessment = GoalAssessment(
        outcome="achieved",
        summary="当前项目方向确认了两个有独立证据的漏洞。",
        reasoning="两个结论分别由列出的源码行号支持。",
        findings=[
            {
                "title": "会话认证绕过风险",
                "kind": "vulnerability",
                "severity": "high",
                "summary": "会话缺少用户标识时仍进入敏感处理分支，造成认证绕过。",
                "evidence": "src/auth.php:3-5",
            },
            {
                "title": "账户资料越权读取风险",
                "kind": "vulnerability",
                "summary": "客户端传入的用户标识被用于查询资料，未与会话用户绑定。",
                "evidence": "src/auth.php:5-8",
                "severity": "low",
                "propagation": "session 用户标识传入账户查询函数。",
            },
        ],
    )

    assert [item.kind for item in assessment.findings] == ["vulnerability", "vulnerability"]
    assert assessment.finding is not None
    assert assessment.finding.title == "会话认证绕过风险"


def test_safe_observations_do_not_satisfy_the_goal():
    payload = {
        "summary": "文件名已规范化，当前路径未证实目录穿越漏洞。",
        "reasoning": "写入目标来自 basename 处理后的文件名，原始路径未直接使用。",
        "observations": [{
            "title": "文件名经过路径规范化",
            "kind": "security_boundary",
            "summary": "写入前使用 basename 去除输入路径的目录部分。",
            "evidence": "src/upload.php:3-8",
        }],
    }
    assessment = GoalAssessment(outcome="no_evidence", **payload)
    assert len(assessment.observations) == 1
    assert assessment.findings == []
    assert assessment.finding is None
    with pytest.raises(ValidationError, match="observations cannot satisfy"):
        GoalAssessment(outcome="achieved", **payload)


def test_run_request_has_one_public_planner_mode():
    request = CreateRunRequest(snapshot_id="snapshot-1", task=TASK)
    assert request.task.require_poc is False
    assert request.task.max_planner_rounds == 4

    with pytest.raises(ValidationError, match="task"):
        CreateRunRequest(snapshot_id="snapshot-1")
    with pytest.raises(ValidationError, match="prompt_id"):
        CreateRunRequest(snapshot_id="snapshot-1", task=TASK, prompt_id="P0")
    # The whole snapshot is the scope now, so selecting files is no longer a request
    # field at all; a stale client must fail loudly instead of appearing to work.
    with pytest.raises(ValidationError, match="scope"):
        CreateRunRequest(snapshot_id="snapshot-1", task=TASK, scope=["src/app.php"])
    assert not hasattr(request, "scope")


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


def test_an_over_long_window_or_one_past_the_end_is_clamped_not_rejected():
    """An over-ask is cut down to size; only the frozen map and the task graph are hard.

    A window may sit anywhere inside a long file — `end_line <= 400` used to make
    everything below line 400 unaddressable.  What is bounded is the window's length,
    and a window running past the file's real line count is clamped to its end rather
    than costing the round (two such rejections used to end an entire run).
    """
    decision = PlannerDecision(
        goal_state="continue",
        basis_summary="长文件的下半部分同样是可读范围。",
        tasks=[planner_task(source_refs=[
            {"path": "src/app.php", "start_line": 1180, "end_line": 1260, "reason": "writer"},
            {"path": "src/app.php", "start_line": 300, "end_line": 900, "reason": "audit"},
        ])],
    )
    notes: list[dict] = []
    _validate_planner_decision(
        decision,
        {"files": [{"path": "src/app.php", "line_count": 900}]},
        [],
        on_sanitize=notes.append,
    )

    refs = decision.tasks[0].source_refs
    assert (refs[0].start_line, refs[0].end_line) == (900, 900)
    assert (refs[1].start_line, refs[1].end_line) == (300, 699)
    assert [note["field"] for note in notes] == ["source_refs", "source_refs"]

    # The payload guard is far above any usable reading window, and still refuses.
    with pytest.raises(ValidationError, match="4000 lines"):
        PlannerSourceRef(path="src/app.php", start_line=1, end_line=4001)


def test_over_long_hint_lists_are_trimmed_instead_of_costed_against_the_round():
    """One extra hint used to fail validation and, with one correction allowed, the run.

    The hints only tell a worker where to look and the context builder slices them
    anyway, so they are deduplicated and trimmed.  `scope_paths` and `dependencies`
    stay strict: dropping one of those silently would change what a worker may read
    or how the task graph is ordered.
    """
    hints = [f"hint-{index}" for index in range(20)]
    decision = PlannerDecision(
        goal_state="continue",
        basis_summary="覆盖两个方向的读取计划。",
        tasks=[planner_task(query_hints=hints + ["hint-0"])],
    )
    assert len(decision.tasks[0].query_hints) == 12
    assert decision.tasks[0].query_hints[:2] == ["hint-0", "hint-1"]

    symbols = PlannerDecision(
        goal_state="continue",
        basis_summary="覆盖两个方向的读取计划。",
        tasks=[planner_task(target_symbols=[f"sym{index}" for index in range(40)])],
    )
    assert len(symbols.tasks[0].target_symbols) == 24

    for field, value in (("scope_paths", [f"p{index}.php" for index in range(30)]),
                         ("dependencies", [f"task-{index}" for index in range(20)])):
        with pytest.raises(ValidationError):
            PlannerDecision(
                goal_state="continue",
                basis_summary="覆盖两个方向的读取计划。",
                tasks=[planner_task(**{field: value})],
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


def test_a_module_directory_is_a_scope_path_and_still_not_a_source_ref():
    """The contract the Planner is told, which the host was not honouring.

    ``PlannerTaskProposal.scope_paths`` is documented as the place a directory goes, and the
    Planner instruction says the same in as many words (``architecture.modules[]`` entries
    are directories, "目录只能写进 ``scope_paths``").  The host compared the field against the
    map's *file* list, so run ``e3bb0c7530`` had all three of its decisions refused for doing
    exactly what it was told -- and with one correction per phase, that ended the run.

    ``source_refs`` stays strict: a worker reads lines, and a directory has none.
    """
    project_map = {
        "files": [
            {"path": "src/app.php", "line_count": 8},
            {"path": "src/handler.php", "line_count": 12},
        ],
    }
    accepted = PlannerDecision(
        goal_state="continue",
        basis_summary="按 src 模块派发一个方向。",
        tasks=[planner_task(scope_paths=["./src/"])],
    )

    assert _validate_planner_decision(accepted, project_map, []) is accepted
    # Normalised to the map's own spelling, so the duplicate guard and the read ledger see
    # the same string the map would have written.
    assert accepted.tasks[0].scope_paths == ["src"]

    unknown = PlannerDecision(
        goal_state="continue",
        basis_summary="尝试引用不在快照里的目录。",
        tasks=[planner_task(scope_paths=["vendor"])],
    )
    with pytest.raises(ModelRetry, match="冻结范围外"):
        _validate_planner_decision(unknown, project_map, [])

    as_ref = PlannerDecision(
        goal_state="continue",
        basis_summary="把目录当成可以读行的源码路径。",
        tasks=[planner_task(source_refs=[{"path": "src", "start_line": 1, "end_line": 2}])],
    )
    with pytest.raises(ModelRetry, match="冻结范围外"):
        _validate_planner_decision(as_ref, project_map, [])


def test_whole_snapshot_scope_is_frozen_including_dependency_trees(tmp_path):
    """There is no scope picker: uploading a project puts every readable file in scope."""
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
            settings=SimpleNamespace(model=SimpleNamespace(label="test-model"), poc=PocSettings()),
            bus=EventBus(store),
            worker=SimpleNamespace(notify=lambda: None),
        )
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))

        created = asyncio.run(create_run(
            request,
            CreateRunRequest(snapshot_id=snapshot["id"], task=TASK),
        ))

        assert created["scope"] == []
        assert created["scope_mode"] == "snapshot"
        project_map = store.get_project_map(created["id"])
        assert project_map is not None
        assert project_map["scope"] == ["assets/readme.txt", "src/app.php", "vendor/library.php"]
        assert store.list_run_units(created["id"]) == []
    finally:
        store.close()
