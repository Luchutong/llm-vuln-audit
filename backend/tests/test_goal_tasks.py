"""Regression coverage for the Planner-led project audit workflow.

These tests intentionally exercise a project frontier rather than the retired
one-file-per-worker queue. A run freezes a project map, one Planner publishes
dependency-aware tasks, and workers return evidence-bound outcomes to the next
Planner round.
"""
from __future__ import annotations

import asyncio
import io
from types import SimpleNamespace
import zipfile

import pytest
from pydantic import ValidationError

from audit import worker as worker_module
from audit.agent import _scenario_constraint
from audit.config import ModelConfig, PocSettings
from audit.db import Store, now
from audit.events import EventBus
from audit.health import ModelHealth
from audit.metrics import summarise
from audit.runtime import AgentPolicy
from audit.schemas import CreateRunRequest
from audit.source import SourceRepository
from audit.worker import AuditWorker


TASK = {
    "objective": "追踪请求入口经过认证边界到敏感文件操作的跨文件路径。",
    "success_criteria": "保存至少一条由原始源码行号支撑的目标相关发现，或说明所有已规划方向为何不可达。",
    "max_iterations": 2,
    "max_total_attempts": 12,
    "max_planner_rounds": 3,
    "max_workers": 2,
    "stop_on_achieved": True,
    "require_poc": False,
}


def make_zip(files: dict[str, str]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, text in files.items():
            archive.writestr(path, text)
    return stream.getvalue()


def import_project(repository: SourceRepository) -> dict:
    return repository.import_zip(
        make_zip({
            "public/index.php": "<?php\nrequire __DIR__ . '/../src/auth.php';\nrequire __DIR__ . '/../src/files.php';\nhandle($_GET['path'] ?? 'readme.txt');\n",
            "src/auth.php": "<?php\nfunction require_admin() { return isset($_SESSION['admin']); }\n",
            "src/files.php": "<?php\nfunction handle($path) {\n  if (!require_admin()) { http_response_code(403); return; }\n  readfile('/srv/uploads/' . $path);\n}\n",
            "vendor/helper.inc": "<?php\nfunction vendor_helper() { return true; }\n",
        }),
        "project.zip",
    )


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "source-data")


def run_payload(snapshot: dict, run_id: str, scope: list[str], task: dict | None = None) -> dict:
    return {
        "id": run_id,
        "snapshot_id": snapshot["id"],
        "snapshot_name": snapshot["name"],
        "scope": scope,
        "prompt_id": "planner-v2",
        "prompt_label": "项目级 Planner",
        "prompt_text": "",
        "model": "test-model",
        "budgets": {"responses": 8, "tools": 16, "seconds": 30},
        "agent_policy": AgentPolicy().snapshot(),
        "task_spec": task or TASK,
        "created_at": now(),
    }


def create_planner_run(
    store: Store,
    repository: SourceRepository,
    *,
    run_id: str = "planner-run",
    task: dict | None = None,
    policy: AgentPolicy | None = None,
) -> tuple[dict, dict]:
    snapshot = import_project(repository)
    store.add_snapshot(snapshot)
    scope = ["public/index.php", "src/auth.php", "src/files.php"]
    frozen_task = task or TASK
    payload = run_payload(snapshot, run_id, scope, frozen_task)
    if policy is not None:
        payload["agent_policy"] = policy.snapshot()
    store.create_run(payload)
    project_map = repository.build_project_map(snapshot["id"], set(scope))
    store.create_planner_session(run_id, f"planner:{run_id}", frozen_task["max_planner_rounds"], project_map)
    run = store.claim_next_run()
    assert run is not None and run["status"] == "running"
    return run, snapshot


def proposal(
    key: str,
    *,
    dependencies: list[str] | None = None,
    path: str = "public/index.php",
    start: int = 1,
    end: int = 4,
) -> dict:
    return {
        "task_key": key,
        "title": f"{key} 跨文件审计方向",
        "objective": "从项目入口、认证检查和文件操作之间确认目标相关的可达路径。",
        "acceptance_criteria": "结论必须引用已读取的原始源码行号，并说明缺失上下文。",
        "rationale_summary": "冻结项目图显示入口 include 认证模块和文件处理模块，需要联合读取。",
        "source_refs": [{"path": path, "start_line": start, "end_line": end, "reason": "project_entry"}],
        "target_symbols": ["handle"],
        "dependencies": dependencies or [],
        "query_hints": ["require_admin", "readfile"],
        "priority": 80,
    }


def worker_outcome(
    outcome: str,
    *,
    finding: dict | None = None,
    seen: list[dict] | None = None,
) -> dict:
    findings = [finding] if finding else []
    return {
        "outcome": outcome,
        "result": {
            "outcome": outcome,
            "summary": "受控测试返回的项目级 worker 结论。",
            "reasoning": "结论只基于 worker 已读的原始源码范围。",
            "next_focus": "" if outcome != "continue" else "检查下一条跨文件调用关系。",
            "missing_context": [],
            "finding": finding,
            "findings": findings,
            "terminal_reason": "completed",
        },
        "usage": {"requests": 1, "tool_calls": 0, "input_tokens": 9, "output_tokens": 7},
        "seen": seen or [],
        "seen_exact": True,
        "error": None,
        "status": None,
        "terminal_reason": "completed",
    }


def make_worker(store: Store, repository: SourceRepository) -> AuditWorker:
    return AuditWorker(
        settings=SimpleNamespace(worker="planner-test-worker", model=ModelConfig(model="test")),
        store=store,
        repository=repository,
        bus=EventBus(store),
        health=ModelHealth(),
    )


def test_create_request_requires_a_planner_task_and_rejects_legacy_prompt_fields():
    request = CreateRunRequest(snapshot_id="snapshot-1", task=TASK)
    assert request.task.max_planner_rounds == 3
    assert not hasattr(request, "scope")

    with pytest.raises(ValidationError, match="task"):
        CreateRunRequest(snapshot_id="snapshot-1")
    with pytest.raises(ValidationError, match="prompt_id"):
        CreateRunRequest(snapshot_id="snapshot-1", task=TASK, prompt_id="P2")


def test_api_creation_freezes_a_project_map_not_a_static_source_queue(store, repository):
    """The public endpoint starts a Planner session with no per-file work items."""
    from audit.app import create_run

    snapshot = import_project(repository)
    state = SimpleNamespace(
        repository=repository,
        store=store,
        settings=SimpleNamespace(model=SimpleNamespace(label="test-model"), poc=PocSettings()),
        bus=EventBus(store),
        worker=SimpleNamespace(notify=lambda: None),
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))

    created = asyncio.run(create_run(request, CreateRunRequest(snapshot_id=snapshot["id"], task=TASK)))

    assert created["total_units"] == 0
    assert created["total_tasks"] == 0
    assert store.list_run_units(created["id"]) == []
    session = store.get_planner_session(created["id"])
    project_map = store.get_project_map(created["id"])
    assert session is not None and session["current_round"] == 0
    assert project_map is not None
    # The whole uploaded project is the frozen scope, dependency tree included.
    assert set(project_map["scope"]) == {"public/index.php", "src/auth.php", "src/files.php", "vendor/helper.inc"}
    assert created["scope"] == [] and created["scope_mode"] == "snapshot"


def test_project_map_and_bundle_keep_cross_file_context(repository):
    snapshot = import_project(repository)
    scope = {"public/index.php", "src/auth.php", "src/files.php"}
    project_map = repository.build_project_map(snapshot["id"], scope)
    assert project_map["stats"]["files"] == 3
    assert any(edge["from_path"] == "public/index.php" and edge["to_path"] == "src/auth.php" for edge in project_map["includes"])

    bundle = repository.build_context_bundle(
        snapshot["id"],
        {"context_spec": {"source_refs": [
            {"path": "public/index.php", "start_line": 1, "end_line": 4, "reason": "entry"},
            {"path": "src/files.php", "start_line": 1, "end_line": 5, "reason": "sink"},
        ], "target_symbols": ["handle"]}},
        scope,
    )
    paths = {excerpt["path"] for excerpt in bundle["excerpts"]}
    assert {"public/index.php", "src/files.php"}.issubset(paths)
    assert "src/auth.php" in paths, "static include neighbours should enrich the worker context"


def test_context_bundle_does_not_expand_empty_symbol_selection_to_every_file(repository):
    """An empty target-symbol list means no symbol filter, not all project symbols."""
    snapshot = repository.import_zip(
        make_zip({
            "public/index.php": "<?php\nrequire __DIR__ . '/../src/handler.php';\nhandle($_GET['q'] ?? '');\n",
            "src/handler.php": "<?php\nfunction handle($q) { return $q; }\n",
            "src/unrelated.php": "<?php\nfunction alphabetically_first_noise() { return true; }\n",
            "docs/help.php": "<?php\nfunction docs_only() { return true; }\n",
        }),
        "bundle.zip",
    )
    bundle = repository.build_context_bundle(
        snapshot["id"],
        {"context_spec": {
            "source_refs": [{"path": "public/index.php", "start_line": 1, "end_line": 3, "reason": "entry"}],
            "target_symbols": [],
            "query_hints": [],
        }},
        {"public/index.php", "src/handler.php", "src/unrelated.php", "docs/help.php"},
    )

    paths = {excerpt["path"] for excerpt in bundle["excerpts"]}
    assert {"public/index.php", "src/handler.php"}.issubset(paths)
    assert "src/unrelated.php" not in paths
    assert "docs/help.php" not in paths


def test_context_bundle_reconnaissance_uses_ranked_entries_not_alphabetical_symbols(repository):
    snapshot = repository.import_zip(
        make_zip({
            "public/index.php": "<?php\nrequire __DIR__ . '/../src/bootstrap.php';\nrun();\n",
            "src/bootstrap.php": "<?php\nfunction run() { return true; }\n",
            "src/a_first_symbol.php": "<?php\nfunction a_first_symbol() { return true; }\n",
            "docs/help.php": "<?php\nfunction documentation_symbol() { return true; }\n",
        }),
        "orientation.zip",
    )
    bundle = repository.build_context_bundle(
        snapshot["id"],
        {"context_spec": {"source_refs": [], "scope_paths": [], "target_symbols": [], "query_hints": []}},
        {"public/index.php", "src/bootstrap.php", "src/a_first_symbol.php", "docs/help.php"},
    )

    paths = {excerpt["path"] for excerpt in bundle["excerpts"]}
    assert {"public/index.php", "src/bootstrap.php"}.issubset(paths)
    assert "src/a_first_symbol.php" not in paths
    assert "docs/help.php" not in paths


def test_planner_store_tracks_dependencies_attempts_and_total_usage(store, repository):
    run, _ = create_planner_run(store, repository)
    session = store.get_planner_session(run["id"])
    assert session is not None
    plan = store.begin_planner_round(run["id"], session["session_id"])
    assert plan is not None
    store.finish_planner_round(
        run["id"],
        plan["id"],
        goal_state="continue",
        basis_summary="入口、认证和文件操作的静态关系需要依次验证。",
        next_action="先读取入口方向，再检查其依赖的文件操作方向。",
        tasks=[proposal("entry-flow"), proposal("file-operation", dependencies=["entry-flow"], path="src/files.php", end=5)],
        usage={"requests": 2, "tool_calls": 1, "input_tokens": 10, "output_tokens": 5},
    )

    tasks = {item["task_key"]: item for item in store.list_tasks(run["id"])}
    assert tasks["entry-flow"]["state"] == "ready"
    assert tasks["file-operation"]["state"] == "pending"
    claimed = store.claim_ready_task(run["id"], "worker-1")
    assert claimed is not None and claimed["task_key"] == "entry-flow"
    settled = store.resolve_task_attempt(
        claimed["id"], "worker-1", outcome="no_evidence",
        result={"summary": "入口未直接形成结论。", "reasoning": "已检查入口源码。"},
        usage={"requests": 1, "tool_calls": 0, "input_tokens": 4, "output_tokens": 2},
        seen=[{"path": "public/index.php", "start_line": 1, "end_line": 4}],
    )
    assert settled is not None and settled["state"] == "completed"
    next_task = store.claim_ready_task(run["id"], "worker-2")
    assert next_task is not None and next_task["task_key"] == "file-operation"
    store.resolve_task_attempt(
        next_task["id"], "worker-2", outcome="no_evidence",
        result={"summary": "文件操作方向无目标证据。", "reasoning": "已检查相关函数。"},
        usage={"requests": 1, "tool_calls": 0, "input_tokens": 5, "output_tokens": 3},
        seen=[{"path": "src/files.php", "start_line": 1, "end_line": 5}],
    )

    queue = store.task_queue_state(run["id"])
    assert queue["active"] == 0 and queue["counts"]["completed"] == 2
    refreshed = store.get_run(run["id"])
    assert refreshed is not None
    assert refreshed["usage"] == {"requests": 4, "tool_calls": 1, "input_tokens": 19, "output_tokens": 10}


def test_planner_worker_replans_after_dependency_aware_multiworker_wave(store, repository, monkeypatch):
    """Only the Planner creates tasks; workers return results for the next round."""
    run, _ = create_planner_run(store, repository)
    worker = make_worker(store, repository)
    planner_rounds: list[int] = []
    worker_keys: list[str] = []

    async def fake_plan(**kwargs):
        planner_rounds.append(kwargs["round_no"])
        if kwargs["round_no"] == 1:
            return {
                "decision": {
                    "goal_state": "continue",
                    "basis_summary": "项目图将入口、认证和文件处理连接为两个待验证方向。",
                    "next_action": "派发入口方向，完成后读取文件操作方向。",
                    "missing_context": [],
                    "tasks": [proposal("entry-flow"), proposal("file-operation", dependencies=["entry-flow"], path="src/files.php", end=5)],
                    "updates": [],
                },
                "usage": {"requests": 1, "tool_calls": 1, "input_tokens": 5, "output_tokens": 4},
                "error": None,
                "status": None,
                "terminal_reason": "completed",
            }
        return {
            "decision": {
                "goal_state": "unreachable",
                "basis_summary": "两个已执行方向均未形成验收条件要求的源码证据，且没有受阻依赖。",
                "next_action": "",
                "missing_context": [],
                "tasks": [],
                "updates": [],
            },
            "usage": {"requests": 1, "tool_calls": 1, "input_tokens": 4, "output_tokens": 3},
            "error": None,
            "status": None,
            "terminal_reason": "completed",
        }

    async def fake_pursue(**kwargs):
        worker_keys.append(kwargs["planner_task"]["task_key"])
        return worker_outcome("no_evidence")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))

    assert planner_rounds == [1, 2]
    assert worker_keys == ["entry-flow", "file-operation"]
    assert store.get_run(run["id"])["status"] == "unreachable"
    assert {item["state"] for item in store.list_tasks(run["id"])} == {"completed"}
    event_kinds = [event["kind"] for event in store.list_events(run["id"])]
    assert "planner_round_started" in event_kinds
    assert "planner_round_committed" in event_kinds
    assert event_kinds.count("planner_task_started") == 2


def test_evidence_backed_worker_finding_closes_a_stop_on_achieved_run(store, repository, monkeypatch):
    """The run is closed on the worker's conclusion -- after one round that reviews it."""
    run, _ = create_planner_run(store, repository)
    worker = make_worker(store, repository)
    rounds: list[int] = []

    async def fake_plan(**kwargs):
        rounds.append(kwargs["round_no"])
        if kwargs["round_no"] > 1:
            # The pre-closure review.  The host runs one Planner round before it closes on an
            # existing conclusion, so a Planner has somewhere to say "this one is wrong"
            # -- or, as here, to confirm it and let the run end.
            return {
                "decision": {
                    "goal_state": "met",
                    "basis_summary": "入口方向的结论站得住，收束。",
                    "next_action": "",
                    "missing_context": [],
                    "tasks": [],
                    "updates": [],
                },
                "usage": {"requests": 1, "tool_calls": 0, "input_tokens": 4, "output_tokens": 3},
                "error": None,
                "status": None,
                "terminal_reason": "completed",
            }
        return {
            "decision": {
                "goal_state": "continue",
                "basis_summary": "入口文件中的请求参数和文件操作需要验证。",
                "next_action": "派发跨文件数据流任务。",
                "missing_context": [],
                "tasks": [proposal("entry-flow")],
                "updates": [],
            },
            "usage": {"requests": 1, "tool_calls": 1, "input_tokens": 5, "output_tokens": 4},
            "error": None,
            "status": None,
            "terminal_reason": "completed",
        }

    finding = {
        "title": "未经规范化的文件名拼接",
        "kind": "vulnerability",
        "vulnerability_type": "path_traversal",
        "primary_location": {"path": "src/files.php", "line": 4},
        "severity": "high",
        "summary": "请求参数传入文件处理函数后与上传目录拼接并交给 readfile。",
        "evidence": "public/index.php:4-4; src/files.php:2-4",
        "input_source": "$_GET['path']",
        "propagation": "入口 handle 调用将 path 传入文件处理函数。",
        "dangerous_operation": "readfile('/srv/uploads/' . $path)",
        "protection": "认证检查不等于路径规范化。",
        "preconditions": "已通过认证的请求能够调用该入口。",
        "poc": None,
        "remediation": "在文件操作前规范化路径并限制在允许目录内。",
    }

    async def fake_pursue(**_kwargs):
        return worker_outcome(
            "achieved",
            finding=finding,
            seen=[
                {"path": "public/index.php", "start_line": 1, "end_line": 4},
                {"path": "src/files.php", "start_line": 1, "end_line": 5},
            ],
        )

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))

    assert store.get_run(run["id"])["status"] == "completed"
    goal = store.get_task_goal(run["id"])
    assert goal is not None and goal["status"] == "met"
    findings = store.list_findings(run["id"])
    assert len(findings) == 1 and findings[0]["validation_state"] == "candidate"
    assert findings[0]["task_key"] == "entry-flow"
    # Two rounds: the direction, then the review of the conclusion it produced.  A run that
    # closes on a conclusion nobody was shown is a run whose conclusion cannot be corrected.
    assert rounds == [1, 2]


def test_parallel_worker_retries_keep_invocations_and_request_indexes_in_the_durable_log(store, repository, monkeypatch):
    run, _ = create_planner_run(store, repository)
    worker = make_worker(store, repository)
    attempts = []

    async def fake_plan(**kwargs):
        kwargs["on_event"]({"kind": "audit_progress", "message": "维护待查漏洞方向。", "request_index": 1})
        return {
            "decision": {
                "goal_state": "continue" if kwargs["round_no"] == 1 else "unreachable",
                "basis_summary": "初次派发两个独立方向，结算后确认未证实漏洞。",
                "next_action": "", "missing_context": [], "updates": [],
                "tasks": [proposal("entry-flow"), proposal("sink-flow", path="src/files.php", end=5)]
                if kwargs["round_no"] == 1 else [],
            },
            "usage": {"requests": 1}, "terminal_reason": "completed", "error": None, "status": None,
        }

    async def fake_pursue(**kwargs):
        task = kwargs["planner_task"]
        attempts.append((task["task_key"], kwargs["attempt"], kwargs["agent_invocation_id"]))
        for event in (
            {"kind": "model_request", "attempt": 2, "request_index": 2},
            {"kind": "audit_progress", "message": "追踪当前输入路径。", "request_index": 2},
            {"kind": "tool_call", "tool": "read_source", "call_id": "tool-0001", "request_index": 2},
            {"kind": "tool_result", "tool": "read_source", "call_id": "tool-0001", "request_index": 2},
        ):
            kwargs["on_event"](event)
        await asyncio.sleep(0)
        return worker_outcome("continue" if kwargs["attempt"] == 1 else "no_evidence")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))

    assert {(key, attempt) for key, attempt, _ in attempts} == {
        ("entry-flow", 1), ("entry-flow", 2), ("sink-flow", 1), ("sink-flow", 2),
    }
    assert len({invocation for _, _, invocation in attempts}) == 4
    events = store.list_events(run["id"], limit=1000)
    for key, attempt, invocation in attempts:
        activity = [event for event in events if event["payload"].get("agent_invocation_id") == invocation]
        assert {event["kind"] for event in activity} >= {"planner_task_started", "model_request", "audit_progress", "tool_call", "tool_result"}
        assert all(event["payload"]["task_key"] == key for event in activity)
        assert all(event["payload"]["attempt"] == attempt for event in activity)
        request = next(event for event in activity if event["kind"] == "model_request")
        assert request["payload"]["request_index"] == 2
    planner_updates = [event for event in events if event["kind"] == "audit_progress" and event["payload"].get("role") == "planner"]
    assert len(planner_updates) == 2
    assert len({event["payload"]["agent_invocation_id"] for event in planner_updates}) == 2


def test_stop_on_achieved_false_finishes_the_current_frontier_then_marks_met(store, repository, monkeypatch):
    task = {**TASK, "stop_on_achieved": False}
    run, _ = create_planner_run(store, repository, task=task)
    worker = make_worker(store, repository)
    rounds: list[int] = []

    async def fake_plan(**kwargs):
        rounds.append(kwargs["round_no"])
        if kwargs["round_no"] > 1:
            return {
                "decision": {
                    "goal_state": "met",
                    "basis_summary": "前沿已跑完，入口方向的结论成立。",
                    "next_action": "",
                    "missing_context": [],
                    "tasks": [],
                    "updates": [],
                },
                "usage": {"requests": 1, "tool_calls": 0, "input_tokens": 2, "output_tokens": 2},
                "error": None,
                "status": None,
                "terminal_reason": "completed",
            }
        return {
            "decision": {
                "goal_state": "continue",
                "basis_summary": "创建两个独立的项目级证据方向。",
                "next_action": "等待 worker 完成当前前沿。",
                "missing_context": [],
                "tasks": [proposal("entry-flow"), proposal("file-operation", path="src/files.php", end=5)],
                "updates": [],
            },
            "usage": {"requests": 1, "tool_calls": 0, "input_tokens": 2, "output_tokens": 2},
            "error": None,
            "status": None,
            "terminal_reason": "completed",
        }

    seen = [{"path": "public/index.php", "start_line": 1, "end_line": 4}]
    found = {
        "title": "未经限制的文件读取", "kind": "vulnerability", "severity": "high",
        "vulnerability_type": "path_traversal", "primary_location": {"path": "public/index.php", "line": 4},
        "summary": "入口将未经限制的路径参数传给文件读取函数。",
        "evidence": "public/index.php:4-4",
    }

    async def fake_pursue(**kwargs):
        if kwargs["planner_task"]["task_key"] == "entry-flow":
            return worker_outcome("achieved", finding=found, seen=seen)
        return worker_outcome("no_evidence")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))

    assert store.get_run(run["id"])["status"] == "completed"
    assert {item["state"] for item in store.list_tasks(run["id"])} == {"completed"}
    assert store.get_task_goal(run["id"])["status"] == "met"
    # Both directions ran (nothing was held back) and the review is what closed the run.
    assert rounds == [1, 2]


def test_safe_worker_observation_does_not_stop_the_remaining_frontier(store, repository, monkeypatch):
    run, _ = create_planner_run(store, repository, task={**TASK, "max_workers": 1})
    worker = make_worker(store, repository)
    worker_keys = []

    async def fake_plan(**kwargs):
        return {
            "decision": {
                "goal_state": "continue" if kwargs["round_no"] == 1 else "unreachable",
                "basis_summary": "继续核对文件读取风险，安全的入口事实不能满足漏洞目标。",
                "next_action": "等待两个方向结算。",
                "missing_context": [],
                "tasks": [{**proposal("safe-direction"), "priority": 90}, proposal("remaining-direction")]
                if kwargs["round_no"] == 1 else [],
                "updates": [],
            },
            "usage": {"requests": 1, "tool_calls": 0},
            "error": None, "status": None, "terminal_reason": "completed",
        }

    async def fake_pursue(**kwargs):
        key = kwargs["planner_task"]["task_key"]
        worker_keys.append(key)
        if key == "safe-direction":
            # Simulate an older worker bypassing the stricter schema.
            return worker_outcome("achieved", finding={
                "title": "认证入口限制已生效", "kind": "security_boundary",
                "summary": "入口的访问权限检查拒绝不具备认证状态的请求。",
                "evidence": "public/index.php:1-4",
            }, seen=[{"path": "public/index.php", "start_line": 1, "end_line": 4}])
        return worker_outcome("no_evidence")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))

    assert worker_keys == ["safe-direction", "remaining-direction"]
    assert store.list_findings(run["id"]) == []
    assert store.get_run(run["id"])["status"] == "unreachable"
    assert store.get_task_goal(run["id"])["status"] == "unreachable"
    task = next(item for item in store.list_tasks(run["id"]) if item["task_key"] == "safe-direction")
    result = task["attempt_history"][0]["result"]
    assert result["outcome"] == "no_evidence"
    assert result["findings"] == []
    assert result["observations"][0]["kind"] == "security_boundary"
    assert not any(event["kind"] == "finding_created" for event in store.list_events(run["id"]))


@pytest.mark.parametrize("kind,severity", [
    ("source_observation", "informational"), ("data_flow", "high"),
])
def test_historical_non_vulnerability_cannot_satisfy_goal(store, repository, kind, severity):
    run, _ = create_planner_run(store, repository)
    store.add_finding({
        "id": "historical-observation", "run_id": run["id"], "unit_id": "historical-unit",
        "fingerprint": "historical-observation", "category": "task_goal", "finding_kind": kind,
        "title": "入口只接受固定文件名", "severity": severity,
        "summary": "路径已被规范化且限制在允许的目录内，未发现可控路径穿越。",
        "evidence": [{"path": "public/index.php", "start_line": 1, "end_line": 4}],
        "input_source": "", "propagation": "", "dangerous_operation": "", "protection": "",
        "preconditions": [], "missing_context": [], "poc": None, "remediation": "",
        "validation_state": "candidate", "created_at": now(),
    })
    with pytest.raises(ValueError, match="validated vulnerability finding"):
        store.finalize_goal(run["id"], "met", "安全观察不应使漏洞目标达成。")
    assert store.get_task_goal(run["id"])["status"] == "open"
    assert len(store.list_findings(run["id"])) == 1


def _conclusion_finding(run: dict, finding_id: str = "finding-1") -> dict:
    return {
        "id": finding_id, "run_id": run["id"], "unit_id": "unit-1",
        "fingerprint": finding_id, "category": "sqli", "finding_kind": "vulnerability",
        "title": "id 参数拼接进 SQL 查询", "severity": "high",
        "summary": "id 未经参数化直接拼接到查询。",
        "evidence": [{"path": "public/index.php", "start_line": 1, "end_line": 4}],
        "input_source": "GET id", "propagation": "直接拼接", "dangerous_operation": "SELECT ... WHERE id = '$id'",
        "protection": "", "preconditions": [], "missing_context": [], "poc": None, "remediation": "",
        "validation_state": "candidate", "created_at": now(),
    }


def test_strict_poc_mode_requires_a_verified_conclusion(store, repository):
    """With ``require_poc`` a static conclusion cannot satisfy the goal."""
    run, _ = create_planner_run(store, repository, task={**TASK, "require_poc": True})
    store.add_finding(_conclusion_finding(run))

    with pytest.raises(ValueError, match="validated vulnerability finding"):
        store.finalize_goal(run["id"], "met", "静态结论尚不足以收束。", require_verified=True)

    store.set_finding_verification_state("finding-1", "verified", "confirmed")
    settled = store.finalize_goal(run["id"], "met", "隔离环境已复现。", require_verified=True)
    assert settled["status"] == "met"


def test_a_rejected_conclusion_never_closes_the_goal(store, repository):
    """A finding the runner could not reproduce is not something to close on."""
    run, _ = create_planner_run(store, repository)
    store.add_finding(_conclusion_finding(run))
    store.set_finding_verification_state("finding-1", "rejected", "rejected")

    with pytest.raises(ValueError, match="validated vulnerability finding"):
        store.finalize_goal(run["id"], "met", "自动验证未复现。")


def test_mixed_worker_results_keep_only_vulnerabilities_in_findings(store, repository, monkeypatch):
    run, _ = create_planner_run(store, repository)
    worker = make_worker(store, repository)

    async def fake_plan(**kwargs):
        return {
            "decision": {
                "goal_state": "continue" if kwargs["round_no"] == 1 else "met",
                "basis_summary": "审计发现了未经限制的敏感文件读取。",
                "next_action": "", "missing_context": [],
                "tasks": [proposal("entry-flow")] if kwargs["round_no"] == 1 else [],
                "updates": [],
            },
            "usage": {"requests": 1, "tool_calls": 0},
            "error": None, "status": None, "terminal_reason": "completed",
        }

    async def fake_pursue(**kwargs):
        value = worker_outcome("achieved", finding={
            "title": "未经限制的敏感文件读取", "kind": "vulnerability", "severity": "high",
            "vulnerability_type": "path_traversal", "primary_location": {"path": "src/files.php", "line": 4},
            "summary": "处理函数将请求参数拼接至文件读取路径，缺少目录边界校验。",
            "evidence": "src/files.php:2-4",
        }, seen=[{"path": "src/files.php", "start_line": 1, "end_line": 5}])
        value["result"]["findings"].append({
            "title": "入口权限检查生效", "kind": "security_boundary",
            "summary": "权限检查只允许具有管理员会话的请求进入处理函数。",
            "evidence": "src/files.php:3-3",
        })
        return value

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))
    findings = store.list_findings(run["id"])
    assert len(findings) == 1 and findings[0]["finding_kind"] == "vulnerability"
    task = store.list_tasks(run["id"])[0]
    assert task["result"]["observations"][0]["kind"] == "security_boundary"
    assert store.get_task_goal(run["id"])["status"] == "met"


@pytest.mark.parametrize("severity", [None, "informational", "unknown"])
def test_vulnerability_without_a_grade_is_retained_as_needing_cvss(store, repository, severity):
    run, _ = create_planner_run(store, repository)
    worker = make_worker(store, repository)
    payload = {
        "title": "待确定影响的文件读取", "kind": "vulnerability", "severity": severity,
        "vulnerability_type": "path_traversal", "primary_location": {"path": "public/index.php", "line": 4},
        "summary": "此返回宣称存在文件读取漏洞，但没有给出有效的风险等级。",
        "evidence": "public/index.php:4-4",
    }
    outcome = worker_outcome("achieved", finding=payload,
        seen=[{"path": "public/index.php", "start_line": 1, "end_line": 4}])
    normalised = worker_module._normalise_task_findings(outcome)
    assert normalised["outcome"] == "achieved"
    assert normalised["result"]["observations"] == []
    prepared = worker._build_planner_findings(run, {"id": "test-task", **proposal("entry-flow")}, normalised)
    assert len(prepared) == 1 and prepared[0]["candidate"]
    assert prepared[0]["record"]["validation_state"] == "candidate"
    assert prepared[0]["record"]["cvss"] is None
    assert prepared[0]["record"]["cvss_assessment"]["status"] == "needs_information"
    assert store.get_task_goal(run["id"])["status"] == "open"


def test_legacy_queue_cannot_be_marked_achieved_with_a_source_observation(store, repository):
    run, _ = create_planner_run(store, repository)
    with pytest.raises(ValueError, match="requires a validated vulnerability finding"):
        store.resolve_task_work("legacy-work", outcome="achieved", result={}, usage=None, seen=[], findings=[{
            "finding_kind": "source_observation", "severity": "high", "validation_state": "candidate",
        }])
    assert store.get_task_goal(run["id"])["status"] == "open"
    assert store.list_findings(run["id"]) == []


def test_blocked_frontier_cannot_be_finalized_as_unreachable(store, repository):
    run, _ = create_planner_run(store, repository)
    session = store.get_planner_session(run["id"])
    assert session is not None
    plan = store.begin_planner_round(run["id"], session["session_id"])
    assert plan is not None
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue", basis_summary="需要检查动态依赖。",
        tasks=[proposal("dynamic-include")], usage={"requests": 1, "tool_calls": 0},
    )
    claimed = store.claim_ready_task(run["id"], "worker-1")
    assert claimed is not None
    store.resolve_task_attempt(
        claimed["id"], "worker-1", outcome="blocked",
        result={"summary": "运行时 include 无法静态解析。", "reasoning": "源码使用变量构造路径。", "missing_context": ["运行时 include 值"]},
        usage={"requests": 1}, seen=[], error="动态 include",
    )

    with pytest.raises(ValueError, match="unreachable"):
        store.finalize_goal(run["id"], "unreachable", "不应将缺失上下文当作否定结论。")
    settled = store.finalize_goal(run["id"], "inconclusive", "动态 include 缺少运行时值。")
    assert settled["status"] == "inconclusive"


def test_scenario_run_requires_an_exhausted_frontier_before_met(store, repository):
    """分场景运行：已有结论不足以收束，必须等前沿全部结算且无受阻方向。"""
    run, _ = create_planner_run(store, repository, task={**TASK, "scenario": "sqli"})
    store.add_finding(_conclusion_finding(run))

    session = store.get_planner_session(run["id"])
    assert session is not None
    plan = store.begin_planner_round(run["id"], session["session_id"])
    assert plan is not None
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue", basis_summary="还有同类方向未排查。",
        tasks=[proposal("another-sink")], usage={"requests": 1, "tool_calls": 0},
    )

    # 前沿仍有未结算方向，宿主必须拒绝 met。
    with pytest.raises(ValueError, match="穷尽"):
        store.finalize_goal(run["id"], "met", "已有结论，但方向尚未穷尽。")

    # 结算最后一条方向后，才允许收束 met。
    claimed = store.claim_ready_task(run["id"], "worker-1")
    assert claimed is not None
    store.resolve_task_attempt(
        claimed["id"], "worker-1", outcome="no_evidence",
        result={"summary": "该方向未发现可触发的 SQL 注入。"},
        usage={"requests": 1}, seen=[], error=None,
    )
    settled = store.finalize_goal(run["id"], "met", "同类方向已穷尽，汇报完成。")
    assert settled["status"] == "met"


def test_scenario_constraint_is_appended_to_the_planner_instruction():
    assert "SQL 注入" in _scenario_constraint("sqli")
    assert "反射型 XSS" in _scenario_constraint("xss_r")
    assert "命令注入" in _scenario_constraint("command_injection")
    assert _scenario_constraint(None) == ""
    assert _scenario_constraint("xxe") == ""


def test_planner_can_defer_and_later_resume_a_not_started_task(store, repository):
    run, _ = create_planner_run(store, repository)
    session = store.get_planner_session(run["id"])
    assert session is not None
    first = store.begin_planner_round(run["id"], session["session_id"])
    assert first is not None
    store.finish_planner_round(
        run["id"], first["id"], goal_state="continue", basis_summary="先建立两个方向。",
        tasks=[proposal("entry-flow"), proposal("later-direction", path="src/files.php", end=5)],
    )
    second = store.begin_planner_round(run["id"], session["session_id"])
    assert second is not None
    store.finish_planner_round(
        run["id"], second["id"], goal_state="continue", basis_summary="等待更多入口反馈后再处理第二方向。",
        updates=[{"task_key": "later-direction", "action": "defer", "rationale_summary": "先验证入口方向。"}],
    )
    deferred = next(item for item in store.list_tasks(run["id"]) if item["task_key"] == "later-direction")
    assert deferred["state"] == "deferred"
    assert store.task_queue_state(run["id"])["active"] >= 1

    third = store.begin_planner_round(run["id"], session["session_id"])
    assert third is not None
    store.finish_planner_round(
        run["id"], third["id"], goal_state="continue", basis_summary="入口反馈已到，恢复第二方向。",
        tasks=[proposal("later-direction", path="src/files.php", end=5)],
    )
    resumed = next(item for item in store.list_tasks(run["id"]) if item["task_key"] == "later-direction")
    assert resumed["state"] == "ready"


@pytest.mark.parametrize("legacy_observation", [False, True])
def test_dependency_handoff_and_peer_trace_search_are_durable_and_bounded(store, repository, legacy_observation):
    """Workers can reuse public peer activity without treating it as source proof."""
    run, _ = create_planner_run(store, repository)
    session = store.get_planner_session(run["id"])
    assert session is not None
    plan = store.begin_planner_round(run["id"], session["session_id"])
    assert plan is not None
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue", basis_summary="先建立前置与后续方向。",
        tasks=[
            proposal("entry-flow"),
            proposal("sink-flow", dependencies=["entry-flow"], path="src/files.php", end=5),
        ],
    )
    predecessor = store.claim_ready_task(run["id"], "worker-1")
    assert predecessor is not None and predecessor["task_key"] == "entry-flow"
    store.append_event(
        run["id"], predecessor["id"], "tool_call",
        {"tool": "search_code", "args": {"query": "readfile"}, "attempt": 1, "role": "worker"},
    )
    store.append_event(
        run["id"], predecessor["id"], "tool_result",
        {
            "tool": "search_code", "status": "ok", "new_lines": 1,
            "preview": "src/files.php:4 | readfile('/srv/uploads/' . $path);",
            "attempt": 1, "role": "worker",
        },
    )
    observation = {
        "title": "入口调用数据流", "kind": "data_flow",
        "summary": "入口将路径参数交给文件处理函数；是否形成漏洞仍需检查目标函数。",
        "evidence": "public/index.php:4-4",
    }
    store.resolve_task_attempt(
        predecessor["id"], "worker-1", outcome="no_evidence",
        result={
            "summary": "入口将路径传入处理函数，需要后续确认规范化。",
            "reasoning": "入口文件包含 files.php 并将请求参数传给 handle。",
            "next_focus": "读取 readfile 前的路径校验。",
            "missing_context": [],
            "findings": [observation] if legacy_observation else [],
            "observations": [] if legacy_observation else [observation],
        },
        usage={"requests": 1}, seen=[],
    )
    dependent = next(item for item in store.list_tasks(run["id"]) if item["task_key"] == "sink-flow")
    assert dependent["state"] == "ready"
    context = store.list_planner_context(run["id"])
    compact = next(item for item in context["tasks"] if item["task_key"] == "entry-flow")
    assert compact["observations"] == [observation]

    handoffs = store.get_planner_dependency_handoffs(dependent["id"])
    assert handoffs == [
        {
            "task_key": "entry-flow",
            "title": "entry-flow 跨文件审计方向",
            "state": "completed",
            "outcome": "no_evidence",
            "summary": "入口将路径传入处理函数，需要后续确认规范化。",
            "rationale": "入口文件包含 files.php 并将请求参数传给 handle。",
            "next_focus": "读取 readfile 前的路径校验。",
            "missing_context": [],
            "findings": [],
            "observations": [observation],
            "error": None,
        }
    ]
    matches = store.search_planner_worker_traces(
        run["id"], exclude_task_id=dependent["id"], query="readfile",
    )
    assert len(matches) == 2
    assert {item["kind"] for item in matches} == {"tool_call", "tool_result"}
    assert all(item["task_key"] == "entry-flow" for item in matches)
    assert "private_reasoning" not in str(matches)

    trace = store.get_planner_worker_trace(
        run["id"], exclude_task_id=dependent["id"], task_key="entry-flow",
        event_ids=[matches[0]["event_id"]],
    )
    assert len(trace) == 1
    assert trace[0]["event_id"] == matches[0]["event_id"]
    assert store.get_planner_worker_trace(
        run["id"], exclude_task_id=predecessor["id"], task_key="entry-flow",
    ) == []


def test_peer_assessment_keeps_bounded_source_observations():
    payload = Store._public_worker_trace_payload("task_assessment", {
        "outcome": "no_evidence", "summary": "该方向没有证实漏洞。",
        "observations": [{
            "title": "有效目录边界", "kind": "security_boundary", "summary": "边界有效。" * 1000,
            "evidence": "src/files.php:2-4", "private_metadata": "must not be handed off",
        }] * 20,
        "private_reasoning": "must not be handed off",
    })
    assert len(payload["observations"]) == 8
    assert len(payload["observations"][0]["summary"]) == 1200
    assert payload["observations"][0]["evidence"] == "src/files.php:2-4"
    assert "must not be handed off" not in str(payload)


def test_planner_metrics_use_frontier_progress_not_static_file_coverage():
    metrics = summarise(
        {"task_spec": TASK, "scope": ["public/index.php", "src/files.php"]},
        [], [], [],
        tasks=[
            {"state": "completed"},
            {"state": "blocked"},
            {"state": "ready"},
        ],
    )
    assert metrics["truth_status"] == "planner_goal_not_comparable"
    assert metrics["total_units"] == 0
    assert metrics["total_tasks"] == 3
    assert metrics["terminal_tasks"] == 2
    assert metrics["active_tasks"] == 1
    assert metrics["task_coverage"] == pytest.approx(2 / 3)


def test_restart_marks_an_inflight_planner_task_inconclusive(store, repository):
    run, _ = create_planner_run(store, repository)
    session = store.get_planner_session(run["id"])
    assert session is not None
    plan = store.begin_planner_round(run["id"], session["session_id"])
    assert plan is not None
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue", basis_summary="创建入口方向。",
        tasks=[proposal("entry-flow")], usage={"requests": 1},
    )
    claimed = store.claim_ready_task(run["id"], "worker-1")
    assert claimed is not None and claimed["state"] == "running"

    assert store.interrupt_stale_runs() == 1
    assert store.get_run(run["id"])["status"] == "interrupted"
    assert store.get_task_goal(run["id"])["status"] == "inconclusive"
    assert store.get_planner_session(run["id"])["terminal_state"] == "inconclusive"
    assert store.get_planner_task(claimed["id"])["state"] == "blocked"


def _frontier_decision(tasks: list[dict], goal_state: str = "continue", **extra) -> dict:
    return {
        "decision": {
            "goal_state": goal_state,
            "basis_summary": "受控测试的前沿决策。",
            "next_action": "" if goal_state != "continue" else "派发方向。",
            "missing_context": [],
            "tasks": tasks,
            "updates": [],
        },
        "usage": {"requests": 1, "tool_calls": 0},
        "error": None,
        "status": None,
        "terminal_reason": "completed",
        **extra,
    }


def _host_fault_outcome() -> dict:
    """What a worker returns when the provider, not the code, failed."""
    return {
        "outcome": "blocked",
        "result": {"outcome": "blocked", "summary": "", "terminal_reason": "model_error"},
        "usage": {"requests": 1, "tool_calls": 0},
        "seen": [],
        "error": "provider returned 503 after retries",
        "status": 503,
        "terminal_reason": "model_error",
    }


def test_a_host_fault_requeues_without_charging_the_task_attempt(store, repository, monkeypatch):
    run, _ = create_planner_run(store, repository, task={**TASK, "max_workers": 1})
    worker = make_worker(store, repository)
    passes: list[int] = []

    async def fake_plan(**kwargs):
        if kwargs["round_no"] > 1:
            return _frontier_decision([], goal_state="unreachable")
        return _frontier_decision([proposal("entry-flow")])

    async def fake_pursue(**kwargs):
        passes.append(kwargs["attempt"])
        if len(passes) == 1:
            return _host_fault_outcome()
        return worker_outcome("no_evidence")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))

    tasks = store.list_tasks(run["id"])
    assert [task["state"] for task in tasks] == ["completed"]
    # The outage produced one more real pass, not one fewer attempt.
    assert passes == [1, 1]
    assert tasks[0]["attempts"] == 1
    history = tasks[0]["attempt_history"]
    assert [item["outcome"] for item in history] == ["host_retry", "no_evidence"]
    assert history[0]["attempt"] == -1 and history[0]["state"] == "ready"
    retries = [event for event in store.list_events(run["id"], limit=1000)
               if event["kind"] == "planner_task_host_retry"]
    assert len(retries) == 1
    assert retries[0]["payload"]["host_failures"] == 1


def test_host_retries_are_bounded_before_the_task_settles_normally(store, repository, monkeypatch):
    run, _ = create_planner_run(
        store, repository,
        task={**TASK, "max_workers": 1},
        policy=AgentPolicy(host_retries=1),
    )
    worker = make_worker(store, repository)

    async def fake_plan(**kwargs):
        if kwargs["round_no"] > 1:
            return _frontier_decision([], goal_state="inconclusive")
        return _frontier_decision([proposal("entry-flow")])

    async def fake_pursue(**kwargs):
        return _host_fault_outcome()

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))

    task = store.list_tasks(run["id"])[0]
    # One retry was available, so the first pass was handed back and the second --
    # still the task's first attempt -- settled as blocked.
    assert task["state"] == "blocked"
    assert task["attempts"] == 1
    retries = [event for event in store.list_events(run["id"], limit=1000)
               if event["kind"] == "planner_task_host_retry"]
    assert len(retries) == 1
    assert retries[0]["payload"]["max_host_retries"] == 1
