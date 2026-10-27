"""Replay Planner publication failures without provider calls or live audit data.

Exploration still runs the real CodeAgent and interpreter. The terminal phase uses
raw JSON, the real decision validator, and a temporary durable task frontier.
"""
from __future__ import annotations

import asyncio
import json
import threading
from types import SimpleNamespace

import pytest

from audit import agent, worker as worker_module
from audit.config import ModelConfig
from audit.db import Store
from audit.runtime import AgentPolicy
from audit.source import SourceRepository
from tests.code_model import Always, ModelFactory, call, code, final_answer
from tests.test_goal_tasks import TASK, create_planner_run, make_worker, proposal, worker_outcome


CONFIG = ModelConfig(model="offline-replay", base_url="https://example.invalid", api_key="test")


def _decision(*keys: str) -> dict:
    return {
        "goal_state": "continue",
        "basis_summary": "入口和认证、文件读取模块存在调用关系，交由 worker 核对原始行。",
        "next_action": "读取源码并确认输入和权限约束。",
        "missing_context": [],
        "tasks": [proposal(key) for key in keys or ("entry-flow",)],
        "updates": [],
    }


@pytest.fixture
def frontier(tmp_path):
    store = Store(tmp_path / "audit.db")
    repository = SourceRepository(tmp_path / "source-data")
    run, _ = create_planner_run(store, repository)
    project_map = store.get_project_map(run["id"])
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    value = SimpleNamespace(store=store, repository=repository, run=run, project_map=project_map, plan=plan)
    yield value
    store.close()


async def _plan(frontier, events, *, policy=None, responses=8, tools=12):
    context = lambda: frontier.store.list_planner_context(
        frontier.run["id"], project_map=frontier.project_map,
    )
    return await agent.plan_audit_frontier(
        project_map=frontier.project_map,
        run_context=context(),
        context_reader=context,
        task=TASK,
        round_no=1,
        config=CONFIG,
        budgets={"responses": responses, "tools": tools, "seconds": 8},
        policy=policy or AgentPolicy(request_seconds=0.5, decision_confirmations=0),
        repository=frontier.repository,
        snapshot_id=frontier.run["snapshot_id"],
        allowed_paths=set(frontier.run["scope"]),
        pins=frontier.store,
        run_id=frontier.run["id"],
        plan_id=frontier.plan["id"],
        on_event=events.append,
    )


@pytest.mark.parametrize("exploration_stop", ["no_progress", "context_limit"])
def test_exploration_stop_still_publishes_and_commits_a_dispatchable_task(
    frontier, monkeypatch, exploration_stop,
):
    if exploration_stop == "no_progress":
        exploration = Always([call("get_project_map")])
        policy = AgentPolicy(request_seconds=0.5, decision_confirmations=0, no_progress_calls=1)
    else:
        # Real interpreter output expands the next request past the history cap.
        # The JSON publication starts with fresh bounded host context.
        exploration = Always([code("print('x' * 131072)")])
        policy = AgentPolicy(
            request_seconds=0.5, decision_confirmations=0,
            history_bytes=96 * 1024, code_output_bytes=150 * 1024,
        )
    factory = ModelFactory({
        "planner_explore": exploration,
        "planner_publish": [json.dumps(_decision(), ensure_ascii=False)],
    })
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []

    outcome = asyncio.run(_plan(frontier, events, policy=policy))

    assert outcome["decision"] is not None, outcome
    assert outcome["terminal_reason"] == "completed"
    assert any(item["kind"] == "planner_exploration_stopped" and item["reason"] == exploration_stop for item in events)
    assert factory.phases[-1] == "planner_publish"
    assert factory.phases.count("planner_publish") == 1
    assert not [item for item in events if item.get("phase") == "planner_publish" and item["kind"] in {"tool_call", "agent_code", "agent_parse_error"}]
    assert outcome["usage"]["requests"] == len(factory.built().requests)

    decision = outcome["decision"]
    frontier.store.finish_planner_round(
        frontier.run["id"], frontier.plan["id"],
        goal_state=decision["goal_state"], basis_summary=decision["basis_summary"],
        tasks=decision["tasks"], updates=decision["updates"], usage=outcome["usage"],
    )
    dispatched = frontier.store.claim_ready_task(frontier.run["id"], "offline-worker")
    assert dispatched is not None
    assert dispatched["task_key"] == "entry-flow"
    assert dispatched["state"] == "running"


def test_truncated_then_invalid_schema_json_recovers_with_two_corrections(frontier, monkeypatch):
    factory = ModelFactory({"planner_publish": [
        '{"goal_state":"continue","tasks":[',
        json.dumps({"goal_state": "not-a-goal-state"}),
        json.dumps(_decision(), ensure_ascii=False),
    ]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []

    outcome = asyncio.run(_plan(frontier, events, tools=0))

    assert outcome["decision"] is not None, outcome
    assert outcome["terminal_reason"] == "completed"
    assert factory.phases == ["planner_publish"] * 3
    assert outcome["usage"]["requests"] == 3
    assert len([item for item in events if item["kind"] == "model_retry"]) == 2
    parse_errors = [item for item in events if item["kind"] == "agent_parse_error"]
    assert [item["category"] for item in parse_errors] == ["invalid_json"]
    assert parse_errors[0]["diagnostics"]["line"] == 1
    assert parse_errors[0]["diagnostics"]["column"] > 0
    assert len([item for item in events if item["kind"] == "agent_output_rejected"]) == 1


def test_malformed_exploration_actions_fall_back_to_json_within_original_budget(frontier, monkeypatch):
    private_prose = "private-offline-reasoning-sentinel"
    factory = ModelFactory({
        "planner_explore": [private_prose] * 3,
        "planner_publish": [json.dumps(_decision(), ensure_ascii=False)],
    })
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []

    outcome = asyncio.run(_plan(frontier, events))

    assert outcome["decision"] is not None, outcome
    assert outcome["terminal_reason"] == "completed"
    assert factory.phases == ["planner_explore"] * 3 + ["planner_publish"]
    assert outcome["usage"]["requests"] == 4
    assert any(item["kind"] == "planner_exploration_stopped" and item["reason"] in {"budget", "invalid_output"} for item in events)
    assert private_prose not in json.dumps(events, ensure_ascii=False)


def test_three_invalid_json_answers_stop_without_a_fourth_request(frontier, monkeypatch):
    factory = ModelFactory({"planner_publish": ["{", "{", "{"]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []

    outcome = asyncio.run(_plan(frontier, events, tools=0))

    assert outcome["decision"] is None
    assert outcome["terminal_reason"] == "invalid_output"
    assert factory.phases == ["planner_publish"] * 3
    assert outcome["usage"]["requests"] == 3
    assert frontier.store.list_tasks(frontier.run["id"]) == []


def test_publication_corrections_cannot_exceed_remaining_response_budget(frontier, monkeypatch):
    factory = ModelFactory({"planner_publish": ["{", "{"]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []

    outcome = asyncio.run(_plan(frontier, events, responses=2, tools=0))

    assert outcome["decision"] is None
    assert outcome["terminal_reason"] == "budget"
    assert factory.phases == ["planner_publish"] * 2
    assert outcome["usage"]["requests"] == 2
    assert frontier.store.list_tasks(frontier.run["id"]) == []


@pytest.mark.parametrize("phase", ["planner_explore", "planner_decision", "planner_publish"])
def test_more_than_two_new_tasks_requires_a_corrected_smaller_batch(frontier, monkeypatch, phase):
    oversized = _decision("entry-flow", "files-flow", "auth-flow")
    accepted = _decision("entry-flow", "files-flow")
    render = json.dumps if phase == "planner_publish" else final_answer
    factory = ModelFactory({phase: [render(oversized), render(accepted)]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []

    options = {"tools": 0} if phase == "planner_publish" else {}
    if phase == "planner_decision":
        # Five requests reserve both confirmations and all JSON publication
        # corrections, leaving exploration no allowance to spend.
        options.update(responses=5, policy=AgentPolicy(request_seconds=0.5, decision_confirmations=2))
    outcome = asyncio.run(_plan(frontier, events, **options))

    assert outcome["decision"] is not None, outcome
    assert [item["task_key"] for item in outcome["decision"]["tasks"]] == ["entry-flow", "files-flow"]
    assert factory.phases == [phase] * 2
    assert len([item for item in events if item["kind"] == "model_retry"]) == 1


def test_cancelled_publication_does_not_retry_or_commit_late_output(frontier, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def delayed_answer(messages):
        entered.set()
        release.wait(timeout=2)
        return json.dumps(_decision(), ensure_ascii=False)

    factory = ModelFactory({"planner_publish": [delayed_answer]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []

    async def cancel_in_flight():
        task = asyncio.create_task(_plan(frontier, events, tools=0))
        assert await asyncio.to_thread(entered.wait, 1)
        task.cancel()
        try:
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()
        await asyncio.sleep(0.03)

    asyncio.run(cancel_in_flight())

    assert factory.phases == ["planner_publish"]
    assert frontier.store.list_tasks(frontier.run["id"]) == []
    assert any(item["kind"] == "planner_agent_terminal" and item["reason"] == "cancelled" for item in events)


def test_recovered_publication_dispatches_worker_and_saves_a_candidate(tmp_path, monkeypatch):
    """Run the actual worker orchestration, replacing only its source-audit output."""
    store = Store(tmp_path / "end-to-end.db")
    repository = SourceRepository(tmp_path / "end-to-end-source")
    try:
        run, _ = create_planner_run(store, repository)
        policy = AgentPolicy(request_seconds=0.5, decision_confirmations=0, no_progress_calls=1)
        run["agent_policy"] = policy.snapshot()
        store._write("UPDATE runs SET agent_policy=? WHERE id=?", (json.dumps(policy.snapshot()), run["id"]))
        close = {
            "goal_state": "met", "basis_summary": "已核对 Worker 的源码证据，当前结论成立。",
            "tasks": [], "updates": [],
        }
        factory = ModelFactory({
            "planner_explore": Always([call("get_project_map")]),
            "planner_publish": [json.dumps(_decision()), json.dumps(close)],
        })
        monkeypatch.setattr(agent, "build_code_model", factory)
        worker_tasks = []

        async def simulated_source_audit(**kwargs):
            worker_tasks.append(kwargs["planner_task"]["task_key"])
            return worker_outcome(
                "achieved",
                finding={
                    "title": "未经规范化的文件名拼接", "kind": "vulnerability", "severity": "high",
                    "summary": "请求参数经 handle 传入文件操作函数，未经规范化拼接上传目录。",
                    "evidence": "public/index.php:4-4; src/files.php:2-4",
                    "vulnerability_type": "path_traversal",
                    "primary_location": {"path": "src/files.php", "line": 4},
                    "input_source": "$_GET['path']", "propagation": "入口调用将路径传入 handle。",
                    "dangerous_operation": "readfile('/srv/uploads/' . $path)",
                    "protection": "认证检查未限制路径。", "preconditions": "已通过认证。",
                    "poc": None, "remediation": "规范化路径并验证允许目录。",
                },
                seen=[
                    {"path": "public/index.php", "start_line": 1, "end_line": 4},
                    {"path": "src/files.php", "start_line": 1, "end_line": 5},
                ],
            )

        monkeypatch.setattr(worker_module, "pursue_planner_task", simulated_source_audit)

        asyncio.run(make_worker(store, repository)._execute(run))

        assert worker_tasks == ["entry-flow"]
        assert store.get_run(run["id"])["status"] == "completed"
        saved = store.list_findings(run["id"])
        assert len(saved) == 1
        assert saved[0]["validation_state"] == "candidate"
        assert saved[0]["task_key"] == "entry-flow"
        events = store.list_events(run["id"], limit=1000)
        assert [item["kind"] for item in events].count("planner_round_committed") == 2
        assert any(item["kind"] == "finding_created" for item in events)
        assert factory.phases.count("planner_publish") == 2
        assert not [item for item in events if item["kind"] == "planner_round_failed"]
    finally:
        store.close()
