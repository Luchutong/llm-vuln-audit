"""Regressions from the scenario run: stable tools and bounded final publication."""
from __future__ import annotations

import asyncio
import ast
import json
from types import SimpleNamespace

import pytest

from audit import agent
from audit.codemodel import HostStop
from audit.execution_state import CURRENT_EXECUTION
from audit.runtime import AgentPolicy, Execution, SourceLedger, StopAudit
from audit.schemas import GoalAssessment
from audit.toolkit import final_answer_contract
from tests.code_model import Always, Answer, Host, ModelFactory, Phase, call, code, final_answer
from tests.test_agent_runtime import CONFIG, UNIT, Repository


def execution(events):
    value = Execution({"responses": 24, "tools": 48, "seconds": 30},
                      AgentPolicy(repeated_calls=20, no_progress_calls=20), events.append)
    value.enter("task_execute")
    return value


def test_worker_duplicate_navigation_keeps_the_first_json_response():
    async def scenario():
        events = []
        deps = agent.AuditDeps(Repository(), "s1", UNIT, execution(events), SourceLedger(4096))
        calls = []
        deps.local_tools["find_files"] = lambda args: calls.append(args) or '{"matches":[{"path":"a.php"}]}'
        first = await deps.call("find_files", {"pattern": "*.php"})
        second = await deps.call("find_files", {"pattern": "*.php"})
        assert json.loads(first) == json.loads(second)
        assert len(calls) == 1
        assert [item["status"] for item in events if item["kind"] == "tool_result"] == ["ok", "duplicate"]
    asyncio.run(scenario())


def test_navigation_error_remains_parseable_json():
    async def scenario():
        deps = agent.AuditDeps(Repository(), "s1", UNIT, execution([]), SourceLedger(4096))
        def fail(args):
            raise ValueError("outside frozen scope")
        deps.local_tools["list_tree"] = fail
        result = json.loads(await deps.call("list_tree", {"path": "../"}))
        assert result["ok"] is False
        assert "outside frozen scope" in result["error"]
        assert result["error_code"] == "scope_denied"
        assert not deps.notes  # A scope/usage error is not missing source context.
    asyncio.run(scenario())


def test_dynamic_planner_tools_refresh_instead_of_replaying_a_stale_projection():
    async def scenario():
        events = []
        contexts = iter([
            {"coverage": {"files_read": 1}},
            {"coverage": {"files_read": 2}},
            {"tasks": [{"task_key": "first", "state": "completed"}]},
            {"tasks": [{"task_key": "second", "state": "blocked"}]},
        ])
        deps = agent.PlannerDeps({}, {}, execution(events), context_reader=lambda: next(contexts))
        assert json.loads(await deps.call("get_coverage", {}))["files_read"] == 1
        assert json.loads(await deps.call("get_coverage", {}))["files_read"] == 2
        assert json.loads(await deps.call("get_task_results", {}))["tasks"][0]["task_key"] == "first"
        assert json.loads(await deps.call("get_task_results", {}))["tasks"][0]["task_key"] == "second"
        assert deps.repeats == 0
    asyncio.run(scenario())


def test_pinned_json_does_not_gain_a_prose_suffix():
    deps = agent.PlannerDeps({}, {}, execution([]))
    raw = '{"matches":[{"path":"a.php"}],"truncated":false}'
    assert json.loads(deps._replay({"round_no": 1, "revision": 1}, raw)) == json.loads(raw)


def test_json_truncation_preserves_the_declared_keys_and_a_parseable_document():
    result = agent._planner_json({"query": "authentication", "traces": [
        {"id": index, "summary": "source evidence " * 200} for index in range(50)
    ]}, limit=1200)
    value = json.loads(result)
    assert len(result.encode()) <= 1200
    assert value["query"] == "authentication"
    assert isinstance(value["traces"], list)
    assert value["truncated"] is True
    assert "raw_prefix" not in value


def test_large_pins_cannot_hide_blocked_counts_or_closure_constraints():
    context = {
        "tasks": [{"task_key": f"blocked-{index}", "state": "blocked", "error": "source unavailable " * 30}
                  for index in range(50)],
        "investigations": {"total": 80, "recent": [
            {"id": f"pin-{index}", "topic": "navigation " * 200, "payload": "unbounded body" * 100}
            for index in range(80)
        ]},
    }
    bounded = agent._bound_situation(agent._planner_situation(context), limit=4096)
    rendered = agent._planner_json(bounded, limit=4096)
    parsed = json.loads(rendered)
    assert "raw_prefix" not in parsed
    assert parsed["counts"]["blocked"] == 50
    assert parsed["closure_checks"]["blocked_tasks"] == 50
    assert parsed["closure_checks"]["all_dispatched_tasks_settled"] is False
    assert parsed["blockers"] and parsed["blockers"][0]["state"] == "blocked"
    assert len(rendered.encode()) <= 4096


def test_python_errors_have_a_finite_consecutive_correction_limit():
    host = Host(policy=AgentPolicy(output_corrections=2))
    result = Phase(host, output_model=Answer).play(Always([code("value = null")]))
    assert result.reason() == "invalid_output"
    assert len(result.model.requests) == 3
    assert len(host.events_of("agent_execution_error")) == 3
    assert host.execution.corrections == 2


def test_a_successful_action_resets_only_the_consecutive_correction_counter():
    host = Host(policy=AgentPolicy(output_corrections=1))
    result = Phase(host, output_model=Answer).play([
        code("value = null"), code("print('recovered')"),
        code("another = null"), final_answer({"note": "settled"}),
    ])
    assert result.failure is None
    assert result.gate.published == Answer(note="settled")
    assert host.execution.corrections == 2


def test_generated_final_answer_example_is_python_and_uses_the_current_schema():
    contract = final_answer_contract(GoalAssessment)
    example = contract.rsplit("\n", 1)[-1]
    ast.parse(example)
    assert "outcome" in example and "summary" in example and "reasoning" in example
    assert "None / True / False" in contract


def test_invalid_registered_tool_arguments_count_once_without_dispatch():
    from audit.toolkit import WORKER_TOOLS
    host = Host()
    result = Phase(host, specs=WORKER_TOOLS, output_model=Answer).play([
        code("read_source(start=1, end=3)"), final_answer({"note": "bounded correction"}),
    ])
    assert result.failure is None
    assert host.execution.tools == 1
    assert host.calls == []
    assert len(host.events_of("tool_result")) == 1
    assert host.events_of("tool_result")[0]["status"] == "invalid_arguments"


def run_worker(monkeypatch, script, responses):
    factory = ModelFactory(script)
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []
    result = asyncio.run(agent.pursue_task_work(
        repository=Repository(), snapshot_id="s1", snapshot_name="sample.zip", unit=UNIT,
        initial_excerpts=[{"path": "a.php", "lines": UNIT["cleaned_lines"]}],
        task={"objective": "inspect the source", "require_poc": False}, attempt=1,
        config=CONFIG, budgets={"responses": responses, "tools": 48, "seconds": 10},
        policy=AgentPolicy(request_seconds=1), on_event=events.append,
    ))
    return result, factory, events


def test_worker_has_no_implicit_eight_request_cap(monkeypatch):
    result, factory, _ = run_worker(monkeypatch, {"task_execute": [
        *[call("find_files", pattern=f"unread-{index}") for index in range(9)],
        final_answer({"outcome": "no_evidence", "summary": "No supported candidate.", "reasoning": "Only known source was read."}),
    ]}, responses=16)
    assert result["outcome"] == "no_evidence", result
    assert len(factory.built().requests) == 10


def test_worker_reserves_publication_even_when_exploration_never_finishes(monkeypatch):
    result, factory, events = run_worker(monkeypatch, {
        "task_execute": Always([code("print('still exploring')")]),
        "task_publish": [final_answer({"outcome": "no_evidence", "summary": "Source is inconclusive.",
                                       "reasoning": "No supported evidence was obtained."})],
    }, responses=6)
    assert result["outcome"] == "no_evidence", result
    assert factory.phases == ["task_execute"] * 3 + ["task_publish"]
    assert result["usage"]["requests"] == 4
    assert any(event["kind"] == "task_exploration_stopped" and event["reason"] == "budget" for event in events)
    assert "def read_source(" not in factory.prompts[-1]


def test_runtime_callbacks_restore_the_owner_context_across_an_unrelated_thread():
    async def scenario():
        seen = []
        class Store:
            def assert_execution_write(self, run_id):
                current = CURRENT_EXECUTION.get()
                seen.append((run_id, current.run_id, current.epoch))
        host = Host()
        host.execution.run_execution = SimpleNamespace(store=Store(), run_id="run-a", epoch=7)
        gate = Phase(host, output_model=Answer).gate()
        assert CURRENT_EXECUTION.get() is None
        await asyncio.to_thread(gate.accept, {"note": "valid"})
        assert seen == [("run-a", "run-a", 7)]
        assert CURRENT_EXECUTION.get() is None
    asyncio.run(scenario())


def test_shared_run_budget_stop_cannot_be_relabelled_as_a_local_failure():
    with pytest.raises(StopAudit, match="hard run budget"):
        agent.model_failure_reason(StopAudit("run_budget_exhausted", "hard run budget"))
