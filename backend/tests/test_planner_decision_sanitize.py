"""Tolerance for an over-asking Planner, and honesty about why a round ended.

Six observed runs failed for three reasons, none of them the model's: a directory
offered as a file path, a line window past the end of its file, and too many query
hints.  Each was a *recoverable over-ask* that the host answered by rejecting the whole
structured decision -- with one correction allowed per phase, the second one ended the
run as `inconclusive` before a single worker had been dispatched.

These tests pin the two halves of the fix: an over-ask is cut down to size and reported,
and a round that still produces nothing usable no longer settles the run by itself.
"""
from __future__ import annotations

import asyncio
import io
from types import SimpleNamespace
import zipfile

import pytest

from audit import agent
from audit import worker as worker_module
from audit.agent import model_failure_reason
from audit.config import ModelConfig
from audit.db import Store, now
from audit.events import EventBus
from audit.health import ModelHealth
from audit.runtime import AgentPolicy
from audit.source import SourceRepository
from audit.worker import AuditWorker
from tests.code_model import ModelFactory, final_answer

CONFIG = ModelConfig(model="test", base_url="https://example.invalid", api_key="private-test-key")

TASK = {
    "objective": "追踪请求入口经过认证边界到文件读取的跨文件路径。",
    "success_criteria": "结论必须引用原始源码行号，或说明所有方向为何不可达。",
    "max_iterations": 2,
    "max_total_attempts": 12,
    "max_planner_rounds": 3,
    "max_workers": 2,
    "stop_on_achieved": True,
    "require_poc": False,
}

FILES = {
    "public/index.php": "<?php\nrequire '../src/auth.php';\nhandle($_GET['path'] ?? 'readme.txt');\n",
    "src/auth.php": "<?php\nfunction require_admin() { return isset($_SESSION['admin']); }\n",
    "src/files.php": "<?php\nfunction handle($path) {\n  readfile('/srv/uploads/' . $path);\n}\n",
}


def make_zip(files: dict[str, str]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, text in files.items():
            archive.writestr(path, text)
    return stream.getvalue()


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "source-data")


def create_planner_run(store: Store, repository: SourceRepository) -> dict:
    snapshot = repository.import_zip(make_zip(FILES), "sanitize.zip")
    store.add_snapshot(snapshot)
    store.create_run({
        "id": "sanitize-run",
        "snapshot_id": snapshot["id"],
        "snapshot_name": snapshot["name"],
        "scope": [],
        "scope_mode": "snapshot",
        "prompt_id": "planner-v2",
        "prompt_label": "项目级 Planner",
        "prompt_text": "",
        "model": "test-model",
        "budgets": {"responses": 8, "tools": 16, "seconds": 30},
        "agent_policy": AgentPolicy().snapshot(),
        "task_spec": TASK,
        "created_at": now(),
    })
    project_map = repository.build_project_map(snapshot["id"], None)
    store.create_planner_session("sanitize-run", "planner:sanitize-run", TASK["max_planner_rounds"], project_map)
    run = store.claim_next_run()
    assert run is not None
    return run


def make_worker(store: Store, repository: SourceRepository) -> AuditWorker:
    return AuditWorker(
        settings=SimpleNamespace(worker="sanitize-worker", model=ModelConfig(model="test")),
        store=store,
        repository=repository,
        bus=EventBus(store),
        health=ModelHealth(),
    )


def task_payload(end_line: int) -> dict:
    return {
        "task_key": "src-read",
        "title": "src 目录的读取路径",
        "objective": "读取 src 下的文件，确认请求数据如何到达 readfile。",
        "acceptance_criteria": "worker 必须引用原始源码行号。",
        "rationale_summary": "覆盖统计显示 src 模块尚未被读过。",
        "source_refs": [{"path": "src/files.php", "start_line": 1, "end_line": end_line, "reason": "sink"}],
        "scope_paths": [],
        "target_symbols": ["handle"],
        "dependencies": [],
        "query_hints": ["readfile"],
        "priority": 80,
    }


def decision_payload(tasks: list[dict]) -> dict:
    return {
        "goal_state": "continue",
        "basis_summary": "覆盖统计显示 src 模块无人读过。",
        "next_action": "派发覆盖 src 的证据方向。",
        "missing_context": [],
        "tasks": tasks,
        "updates": [],
    }


# --- an over-ask is cut down, not costed against the round --------------------------


def test_an_over_long_reference_is_clamped_and_reported_not_rejected(monkeypatch):
    """`src/files.php` is four lines long; asking for forty is a recoverable over-ask.

    The Planner is handed the whole point of the fix here: the reference it gets back
    is a window it can actually read, and the host records what it changed so a
    reviewer can tell a clamped proposal from a model that read the map correctly.
    """
    events: list[dict] = []
    # The over-ask is in the decision itself, so the model hands it in and reads the
    # clamp note off the sanitising event rather than off a retry.
    factory = ModelFactory({"planner_decision": [final_answer(decision_payload([task_payload(40)]))]})
    monkeypatch.setattr(agent, "build_code_model", factory)

    async def run() -> dict:
        return await agent.plan_audit_frontier(
            project_map={
                "files": [{"path": path, "line_count": text.count("\n")} for path, text in FILES.items()],
            },
            run_context={"goal": {}, "tasks": [], "plans": []},
            task={"objective": TASK["objective"], "success_criteria": TASK["success_criteria"]},
            round_no=1,
            config=CONFIG,
            budgets={"responses": 4, "tools": 4, "seconds": 8},
            policy=AgentPolicy(request_seconds=0.5),
            on_event=events.append,
        )

    result = asyncio.run(run())

    assert result["decision"] is not None, result
    ref = result["decision"]["tasks"][0]["source_refs"][0]
    assert (ref["start_line"], ref["end_line"]) == (1, 4)
    sanitized = [event for event in events if event["kind"] == "planner_decision_sanitized"]
    assert len(sanitized) == 1
    assert sanitized[0]["field"] == "source_refs"
    assert sanitized[0]["task_key"] == "src-read"
    assert sanitized[0]["before"] == {"start_line": 1, "end_line": 40}
    assert sanitized[0]["after"] == {"start_line": 1, "end_line": 4}
    assert "只有" in sanitized[0]["reason"]


# --- a round that produces nothing usable no longer ends the run --------------------


def planner_outcome(decision: dict | None, *, terminal_reason: str = "completed") -> dict:
    return {
        "decision": decision,
        "usage": {"requests": 1, "tool_calls": 1, "input_tokens": 5, "output_tokens": 4},
        "error": None if decision is not None else "Planner 未返回可验证的任务决策",
        "status": None,
        "terminal_reason": terminal_reason,
    }


def proposal(key: str, path: str = "src/files.php", end: int = 4) -> dict:
    return {
        "task_key": key,
        "title": f"{key} 跨文件审计方向",
        "objective": "从项目入口、认证检查和文件操作之间确认目标相关的可达路径。",
        "acceptance_criteria": "结论必须引用已读取的原始源码行号，并说明缺失上下文。",
        "rationale_summary": "冻结项目图显示入口 include 认证模块和文件处理模块，需要联合读取。",
        "source_refs": [{"path": path, "start_line": 1, "end_line": end, "reason": "project_entry"}],
        "target_symbols": ["handle"],
        "dependencies": [],
        "query_hints": ["readfile"],
        "priority": 80,
    }


def worker_outcome(outcome: str) -> dict:
    return {
        "outcome": outcome,
        "result": {
            "outcome": outcome,
            "summary": "受控测试返回的项目级 worker 结论。",
            "reasoning": "结论只基于 worker 已读的原始源码范围。",
            "next_focus": "",
            "missing_context": [],
            "finding": None,
            "findings": [],
            "terminal_reason": "completed",
        },
        "usage": {"requests": 1, "tool_calls": 0, "input_tokens": 9, "output_tokens": 7},
        "seen": [],
        "seen_exact": True,
        "error": None,
        "status": None,
        "terminal_reason": "completed",
    }


def test_a_bad_round_is_retried_and_a_later_good_round_still_completes(store, repository, monkeypatch):
    """The observed failure mode: one unparseable decision ended the whole run.

    Now the discarded round is recorded as a failed draft and the host plans again, so a
    single bad structured output costs one round instead of the run: the direction the
    second round proposes is still dispatched, executed, and reported.
    """
    run = create_planner_run(store, repository)
    worker = make_worker(store, repository)
    rounds: list[int] = []

    async def fake_plan(**kwargs):
        rounds.append(kwargs["round_no"])
        if kwargs["round_no"] == 1:
            return planner_outcome(None, terminal_reason="invalid_output")
        if kwargs["round_no"] == 2:
            return planner_outcome({
                "goal_state": "continue",
                "basis_summary": "项目图将入口和文件处理连接为一个待验证方向。",
                "next_action": "派发文件读取方向。",
                "missing_context": [],
                "tasks": [proposal("src-read")],
                "updates": [],
            })
        return planner_outcome({
            "goal_state": "unreachable",
            "basis_summary": "已派发方向未形成验收条件要求的源码证据，且没有受阻依赖。",
            "next_action": "",
            "missing_context": [],
            "tasks": [],
            "updates": [],
        })

    async def fake_pursue(**kwargs):
        return worker_outcome("no_evidence")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))

    assert rounds == [1, 2, 3]
    assert store.get_run(run["id"])["status"] == "unreachable"
    events = store.list_events(run["id"])
    failures = [event for event in events if event["kind"] == "planner_round_failed"]
    assert len(failures) == 1
    assert failures[0]["payload"]["round"] == 1
    assert failures[0]["payload"]["terminal_reason"] == "invalid_output"
    # A discarded round leaves a failed draft and no frontier; the rounds that followed
    # both committed, and the direction the second one proposed actually ran.
    assert [event["payload"]["round"] for event in events if event["kind"] == "planner_round_committed"] == [2, 3]
    assert [event["payload"]["task_count"] for event in events
            if event["kind"] == "planner_round_committed"] == [1, 0]
    assert [item["state"] for item in store.list_tasks(run["id"])] == ["completed"]


def test_exhausted_decision_retries_settle_with_a_readable_reason(store, repository, monkeypatch):
    """When re-planning does not help, the run ends — once, and saying why."""
    run = create_planner_run(store, repository)
    worker = make_worker(store, repository)
    rounds: list[int] = []

    async def fake_plan(**kwargs):
        rounds.append(kwargs["round_no"])
        return planner_outcome(None, terminal_reason="invalid_output")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    asyncio.run(worker._execute(run))

    # One retry is allowed by default, so the run survives the first bad decision and
    # only settles after the second.
    assert rounds == [1, 2]
    state = store.get_run(run["id"])
    assert state["status"] == "inconclusive"
    goal = store.get_task_goal(run["id"])
    assert "未能产出可验证决策" in goal["terminal_reason"]
    assert goal["terminal_reason"].startswith("Planner 连续 2 回合")


def test_a_spent_budget_is_labelled_budget_not_invalid_output():
    """Two different facts shared one label, so neither could be acted on.

    A host stop named `budget` means the phase ran out of allowance; a schema rejection
    means the model cannot follow the contract.  The first is worth re-requesting under a
    larger budget, the second is not.
    """
    from pydantic import ValidationError

    assert model_failure_reason(agent.StopAudit("budget", "响应预算已用尽")) == "budget"
    assert model_failure_reason(ValidationError.from_exception_data("Check", [])) == "invalid_output"
    # A phase that names its own reason keeps it: "timeout" must not be flattened.
    assert model_failure_reason(agent.StopAudit("timeout", "wall clock")) == "timeout"
