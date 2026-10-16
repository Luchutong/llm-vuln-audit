"""Exercise the real code-action loop with controlled provider responses.

The unit and the goal executor are driven end to end: the budgets, the phase boundaries,
the read ledger and the tool dispatcher are the production ones, and only the provider
call is a script.  So what these tests assert is what the *run* does -- how many requests a
phase could spend, which phase a failure ended, what the model was shown -- rather than
what a simulated loop was told to do.
"""
import asyncio
import json
import threading
import time
from typing import NamedTuple

import httpx
import openai
import pytest
from pydantic_ai import ModelRetry

from audit import agent
from audit.config import ModelConfig
from audit.evidence import seen_ranges, validate_evidence
from audit.runtime import AgentPolicy, Execution, SourceLedger
from audit.schemas import PlannerDecision
from tests.code_model import Always, ModelFactory, call, code, final_answer

UNIT = {
    "id": "u1", "file_path": "a.php", "symbol": "<top-level>", "kind": "top_level",
    "start_line": 1, "end_line": 4, "slice_index": 1, "slice_count": 1,
    "cleaned_lines": [{"number": 1, "text": "<?php"}, {"number": 3, "text": "echo $_GET['x'];"}],
}
CONFIG = ModelConfig(model="test", base_url="https://example.invalid", api_key="private-test-key")


class Repository:
    def __init__(self):
        self.searches = 0

    def get_context(self, snapshot_id, unit):
        return {"excerpts": [{"path": "entry.php", "lines": [{"number": 1, "text": "include 'a.php';"}]}],
                "unresolved_dependencies": []}

    def search_code(self, snapshot_id, query, path=None, limit=40, *, allowed_paths=None, include_dependencies=False):
        self.searches += 1
        return {"matches": [], "truncated": False, "scanned_files": 0, "scan_truncated": False}

    def read_source(self, snapshot_id, path, start, end):
        return {"path": path, "lines": [{"number": start, "text": "echo $_GET['x'];"}], "truncated": False}

    def get_snapshot(self, snapshot_id):
        return {"files": [{"path": "a.php", "line_count": 4}, {"path": "entry.php", "line_count": 1}]}


def verdict(conclusion="no_candidate", evidence="不适用", **overrides):
    result = {
        "conclusion": conclusion, "reasoning": "根据已读语法、语义及运行前提判断。", "evidence": evidence,
        "input_source": "$_GET['x']", "propagation": "传入 echo", "dangerous_operation": "echo",
        "protection": "无", "preconditions": "需要对应入口", "missing_context": "无", "severity": "high",
    }
    result.update(overrides)
    return result


def decision(**overrides):
    return {"summary": "三类检查", "sqli": verdict(), "xss_r": verdict(), "command_injection": verdict(), **overrides}


def provider_error(status: int, message: str) -> openai.APIStatusError:
    """The provider refusing a request, the way the client under the loop raises it."""
    request = httpx.Request("POST", "https://example.invalid/v1/chat/completions")
    response = httpx.Response(status, request=request, json={"error": {"message": message}})
    kind = {401: openai.AuthenticationError, 503: openai.InternalServerError}.get(status)
    return (kind or openai.BadRequestError)(message, response=response, body=None)


class Run(NamedTuple):
    """One unit's result, the events it emitted, and the client it really used."""

    result: dict
    events: list[dict]
    factory: ModelFactory

    @property
    def prompts(self) -> list[str]:
        """Every request the unit made, as text."""
        return self.factory.prompts

    @property
    def phases(self) -> list[str]:
        """The phase each of those requests was made in."""
        return self.factory.phases


def run(monkeypatch, script, *, budgets=None, policy=None, repo=None, unit=None) -> Run:
    """Drive one unit with a scripted model; ``script`` is what the model writes per phase."""
    factory = ModelFactory(script)
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []
    result = asyncio.run(agent.audit_unit(
        repository=repo or Repository(), snapshot_id="s1", snapshot_name="demo.zip", unit=unit or UNIT,
        prompt_text="审计当前 PHP 单元的三类漏洞", config=CONFIG,
        budgets=budgets or {"responses": 8, "tools": 16, "seconds": 2},
        policy=policy or AgentPolicy(request_seconds=0.5), on_event=events.append,
    ))
    return Run(result, events, factory)


def offered_tools(monkeypatch) -> list[set[str]]:
    """Every tool table the run offered, captured where the registry is materialised.

    What a phase offers is built from one registry, so a test reads the surface there
    rather than inferring it from whichever call happened to succeed.
    """
    seen: list[set[str]] = []
    original = agent.build_tools

    def counted(specs, gate, **kwargs):
        seen.append({item.name for item in specs})
        return original(specs, gate, **kwargs)

    monkeypatch.setattr(agent, "build_tools", counted)
    return seen


def test_normal_audit_explains_all_categories_without_generating_unneeded_pocs(monkeypatch):
    """One request settles all three categories, and no POC phase is opened for them."""
    tables = offered_tools(monkeypatch)
    outcome = run(monkeypatch, {"explore": [final_answer(decision())]})

    assert outcome.result["analysis"] is not None
    assert outcome.result["usage"]["model_attempts"] == 1
    # The one call is the host's own prepared read; the model wrote no code to repeat it.
    assert outcome.result["usage"]["tool_calls"] == 1
    assert [e["kind"] for e in outcome.events][-1] == "agent_terminal"
    assert tables == [{"read_source", "search_code", "get_context"}]
    assert "entry.php:1" in outcome.prompts[0]


def test_repeated_tool_calls_stop_and_force_a_tool_free_verdict(monkeypatch):
    """The same query twice is not progress; the verdict is then settled without tools."""
    repo = Repository()
    outcome = run(monkeypatch, {
        "explore": Always([call("search_code", query="missing")]),
        "verdict": [final_answer(decision())],
    }, repo=repo)

    assert outcome.result["analysis"] is not None, outcome.result
    assert outcome.result["exploration_incomplete"] == "no_progress"
    assert repo.searches == 1, "duplicates must not re-read the repository"
    assert outcome.result["usage"]["model_attempts"] == 4
    assert any(e.get("reason") == "no_progress" for e in outcome.events)


def test_distinct_empty_searches_also_stop_without_progress(monkeypatch):
    """A search that finds nothing three times over is stagnation too."""
    outcome = run(monkeypatch, {
        "explore": [
            call("search_code", query="missing1"),
            call("search_code", query="missing2"),
            call("search_code", query="missing3"),
        ],
        "verdict": [final_answer(decision())],
    })

    assert outcome.result["analysis"] is not None, outcome.result
    assert outcome.result["exploration_incomplete"] == "no_progress"
    assert outcome.result["usage"]["model_attempts"] == 4


def test_malformed_output_has_shared_corrections_and_a_finite_end(monkeypatch):
    """Corrections come from the policy, and the phase still ends.

    One correction was too few to be useful: a provider that never produces the
    required shape must terminate, but a provider that needs a second try should get
    it.  The count is `AgentPolicy.output_corrections`, and the end is still finite --
    the refusals come back as observations, so they cost requests of the same phase
    rather than of a new one.
    """
    outcome = run(monkeypatch, Always([final_answer({"summary": "missing categories"})]))

    assert outcome.result["analysis"] is None
    assert outcome.result["incomplete"] == "invalid_output"
    assert outcome.result["usage"]["corrections"] == AgentPolicy().output_corrections
    # One reply, then exactly the two corrections the policy allows, then the stop: the
    # request after that one is refused by the host before it is ever sent.  The refusals
    # are observations of the phase's own steps, so the run ends on the arithmetic rather
    # than on a step count: exploration's last request is refused as invalid_output, and
    # the tool-free phase behind it -- still owed to the unit -- gets one more, which is
    # refused on its own first correction.
    corrections = AgentPolicy().output_corrections
    assert outcome.result["usage"]["phases"]["explore"]["model_attempts"] == 1 + corrections
    assert len(outcome.factory.built().requests) == (1 + corrections) + 1


def test_planner_project_map_tool_returns_a_compact_overview():
    """The Planner gets navigation metadata, not a full project-map payload."""
    events: list[dict] = []
    execution = Execution(
        {"responses": 4, "tools": 1, "seconds": 2},
        AgentPolicy(request_seconds=0.5),
        events.append,
    )
    execution.enter("planner")
    project_map = {
        "snapshot_id": "snapshot-1",
        "scope": [f"modules/{number}/handler.php" for number in range(600)],
        "files": [
            {"path": f"modules/{number}/handler.php", "line_count": 40, "size": 1024}
            for number in range(600)
        ],
        "directories": [f"modules/{number}" for number in range(600)],
        "symbols": [
            {"path": f"modules/{number}/handler.php", "name": f"handle_{number}", "kind": "function"}
            for number in range(600)
        ],
        "includes": [
            {"from_path": f"modules/{number}/handler.php", "to_path": "bootstrap.php", "line": 2}
            for number in range(600)
        ],
        "calls": [
            {"path": f"modules/{number}/handler.php", "name": f"dispatch_{number}", "line": 10}
            for number in range(600)
        ],
        "entrypoints": [{"path": "index.php", "confidence": "high"}],
        "stats": {"files": 600, "symbols": 600, "includes": 600, "calls": 600, "entrypoints": 1},
        "architecture": {
            "modules": [{"path": "modules", "file_count": 600}],
            "role_counts": {"entry": 1, "application": 599},
        },
    }

    payload_text = asyncio.run(agent.PlannerDeps(
        project_map=project_map,
        run_context={},
        execution=execution,
    ).call("get_project_map", {}))
    payload = json.loads(payload_text)

    assert payload["overview"] is True
    assert "scope" not in payload
    assert "calls" not in payload
    assert len(payload_text.encode("utf-8")) < 16 * 1024
    assert events[-1]["tool"] == "get_project_map"


def test_planner_task_history_stays_structured_and_bounded():
    """The history shows the whole run, and degrades to a *visible* slice, never to a fragment.

    Eight tasks used to be the cap, and eight was the point past which a round stopped being
    able to see a settled direction.  The list is unbounded in principle now, so the bound is
    a structural one: oldest entries go, the newest stay, the omission is recorded, and what
    remains is still parseable JSON.  A byte-prefix truncation here would hand the model a
    fragment of its own frontier and no way to tell that it was one.
    """
    execution = Execution(
        {"responses": 4, "tools": 1, "seconds": 2},
        AgentPolicy(request_seconds=0.5),
        lambda _event: None,
    )
    execution.enter("planner")
    long_text = "多文件审计摘要" * 400
    payload_text = asyncio.run(agent.PlannerDeps(
        project_map={"stats": {}, "architecture": {}},
        run_context={
            "goal": {"objective": long_text, "success_criteria": long_text},
            "tasks": [
                {
                    "task_key": f"task-{number}", "state": "completed", "objective": long_text,
                    "dependencies": ["prior"], "rationale_summary": long_text,
                    "result": {"summary": long_text, "missing_context": [long_text] * 4},
                }
                for number in range(20)
            ],
            "plans": [
                {"round_no": number, "status": "completed", "basis_summary": long_text, "next_action": long_text}
                for number in range(10)
            ],
        },
        execution=execution,
    ).call("get_task_results", {}))
    payload = json.loads(payload_text)

    assert "raw_prefix" not in payload
    assert len(payload["tasks"]) + len(payload["plans"]) < 30, "the block must actually be bounded"
    assert payload["omitted"]["tasks"] + payload["omitted"]["plans"] > 0
    assert "省去了" in payload["notice"]
    # The newest end of the history is the part a round must not lose: it is the direction
    # most likely to be duplicated.
    assert payload["tasks"][-1]["task_key"] == "task-19"
    assert payload["plans"][-1]["round_no"] == 9
    assert len(payload_text.encode("utf-8")) <= 12 * 1024


def test_a_round_may_dispatch_nothing_while_the_frontier_still_has_work():
    """ARTEX's hard floor, and only that.

    A round with tasks already pending/ready/running is allowed to publish an empty plan --
    it can be there to update a direction or to confirm the frontier is still moving.  The
    old unconditional rejection is what pushed the Planner into inventing a task every round,
    and a differently-named second attempt at a settled direction is exactly the duplicate
    this design exists to prevent.
    """
    project_map = {"stats": {}, "architecture": {}, "files": []}
    empty = PlannerDecision(
        goal_state="continue", basis_summary="前沿仍在推进。", next_action="等待在跑的任务。",
        tasks=[], updates=[],
    )

    def validate(prior_tasks):
        return agent._validate_planner_decision(
            empty.model_copy(deep=True), project_map, prior_tasks, policy=AgentPolicy()
        )

    assert validate([{"task_key": "run-1", "state": "running"}]) is not None
    assert validate([{"task_key": "wait-1", "state": "ready"}]) is not None
    # An empty frontier is the one case where "continue" with nothing to run is a refusal.
    with pytest.raises(ModelRetry):
        validate([{"task_key": "done-1", "state": "completed"}])
    with pytest.raises(ModelRetry):
        validate([])


def test_a_discovery_turn_cannot_consume_the_reserved_decision_request(monkeypatch):
    """A discovery turn cannot consume the request reserved for publishing tasks.

    Exploration spends its whole allowance and is stopped on the request after it. The
    round must still reach the phase that publishes the decision, because the host holds
    requests back for it. The decision phase keeps its tools for a bounded confirmation
    allowance; the reserve covers that allowance and the publishing request behind it, so
    a round can never end because "the model was still exploring".
    """
    events: list[dict] = []
    project_map = {
        "snapshot_id": "snapshot-1",
        "scope": ["public/index.php", "src/handler.php"],
        "files": [
            {"path": "public/index.php", "line_count": 8, "roles": ["entrypoint"], "module": "public"},
            {"path": "src/handler.php", "line_count": 12, "roles": ["application_code"], "module": "src"},
        ],
        "symbols": [{"path": "src/handler.php", "name": "handle", "kind": "function", "start_line": 2, "end_line": 8}],
        "includes": [{"from_path": "public/index.php", "to_path": "src/handler.php", "line": 2}],
        "calls": [{"path": "public/index.php", "name": "handle", "line": 4}],
        "entrypoints": [{"path": "public/index.php", "reason": "web_root_index", "confidence": "high"}],
        "unresolved_root_candidates": [],
        "architecture": {
            "role_counts": {"entrypoint": 1, "application_code": 1},
            "include_graph": {"resolved_edges": 1, "unresolved_edges": 0, "cross_module_edges": 1},
            "bootstrap_files": [],
            "modules": [{
                "path": "public", "file_count": 1, "role_counts": {"entrypoint": 1},
                "entrypoints": ["public/index.php"], "resolved_include_edges": 1,
                "unresolved_include_edges": 0, "notable_calls": [{"name": "handle", "count": 1}],
            }],
        },
        "stats": {"files": 2, "symbols": 1, "includes": 1, "calls": 1, "entrypoints": 1},
        "limitations": [],
    }

    # One scripted step per phase.  Exploration's code block makes exactly one tool call,
    # which is what the old scripted provider did per request -- so the counters the
    # assertions below read keep their meaning.  The decision is handed in during the
    # decision phase, which is the request the reserve bought.
    factory = ModelFactory({
        "planner_explore": [code("print(get_project_map())")],
        "planner_decision": [final_answer({
            "goal_state": "continue",
            "basis_summary": "入口静态 include 处理函数，先验证跨文件请求处理方向。",
            "next_action": "派发入口和处理函数的联合读取任务。",
            "missing_context": [],
            "tasks": [{
                "task_key": "entry-handler",
                "title": "入口到处理函数的数据流",
                "objective": "读取入口和处理函数，确认请求数据如何进入目标操作。",
                "acceptance_criteria": "worker 引用两个文件的原始行号并说明跨文件关系。",
                "rationale_summary": "项目图显示 public/index.php 静态包含 src/handler.php 并调用 handle。",
                "source_refs": [
                    {"path": "public/index.php", "start_line": 1, "end_line": 8, "reason": "request entry"},
                    {"path": "src/handler.php", "start_line": 1, "end_line": 12, "reason": "handler"},
                ],
                "scope_paths": [],
                "target_symbols": ["handle"],
                "dependencies": [],
                "query_hints": ["handle"],
                "priority": 80,
            }],
            "updates": [],
        })],
    })
    monkeypatch.setattr(agent, "build_code_model", factory)
    policy = AgentPolicy(request_seconds=0.5)
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=project_map,
        run_context={"goal": {}, "tasks": [], "plans": []},
        task={"objective": "确认请求入口到目标操作的跨文件路径。", "success_criteria": "源码行号可复核。"},
        round_no=1,
        config=CONFIG,
        budgets={"responses": 6, "tools": 4, "seconds": 2},
        policy=policy,
        on_event=events.append,
    ))

    assert result["decision"] is not None, result
    assert result["decision"]["tasks"][0]["task_key"] == "entry-handler"
    # The round declared how many requests exploration could spend, the model spent
    # exactly those and no more, and the request after them is the decision's.  The
    # reserve is what a decision costs -- one request to publish it, the corrections it
    # is allowed, and the confirmations the decision phase may spend before its tools are
    # withdrawn -- so the arithmetic is read off the policy rather than hard-coded here;
    # with an allowance this small it leaves exploration a single request, which is the
    # point of holding it back.
    explore = next(item for item in events if item["kind"] == "agent_phase" and item["phase"] == "planner_explore")
    reserve = 1 + policy.output_corrections + policy.decision_confirmations
    assert explore["response_limit"] == 6 - reserve
    assert result["usage"]["model_attempts"] == explore["response_limit"] + 1
    # Every exploration request was answered with another query -- one call per request,
    # as the scripted provider used to answer -- and the decision request with none: the
    # reserve is what makes the round end in a decision instead of a tool call that has
    # nowhere left to go.
    assert result["usage"]["tool_calls"] == explore["response_limit"]
    assert any(item["kind"] == "planner_exploration_stopped" and item["reason"] == "budget" for item in events)
    assert any(item["kind"] == "agent_phase" and item["phase"] == "planner_decision" for item in events)
    prompts = factory.prompts
    assert "主机生成的项目结构概览" in prompts[0]
    assert '"overview":true' in prompts[0]
    # The reserve bought a request whose prompt says exploration is over -- and the
    # queries that ended the exploration phase were its own, not the decision's.
    assert "本轮探索阶段已经结束" in prompts[-1]
    assert factory.phases == ["planner_explore", "planner_decision"]
    # The decision phase starts from that prompt and nothing else: a phase boundary is a
    # reset, so exploration's own turns are not re-sent as observations.  Read off the
    # request rather than its text -- the host's own blocks carry the same strings by
    # design, and the point here is what the request is made of.
    assert [message.role for message in factory.built().requests[-1]] == ["system", "user"]


def test_tool_flood_cannot_spend_the_reserved_model_budget(monkeypatch):
    """One request may write a whole reading loop, so the tool ceiling is what stops it.

    Code-as-action means a single step can call a tool twenty times -- the shape the old
    one-call-per-request protocol made impossible -- so the flood is a code block now and
    the ceiling it hits is the host's, raised from inside the loop it is running in.
    """
    flood = code("for line in range(1, 20):\n    print(read_source(path=\"a.php\", start=line, end=line))")
    outcome = run(
        monkeypatch,
        {"explore": Always([flood]), "verdict": [final_answer(decision())]},
        budgets={"responses": 8, "tools": 3, "seconds": 2},
    )

    assert outcome.result["analysis"] is not None, outcome.result
    # The preparation read is the first call; the flood spends the two that are left and
    # the third raises, so the tool ceiling is what ended exploration.
    assert outcome.result["usage"]["tool_calls"] == 3
    assert outcome.result["usage"]["model_attempts"] == 2
    assert any(
        e["kind"] == "exploration_stopped" and e["reason"] == "budget" for e in outcome.events
    ), "探索必须是被预算停下的，而不是自己写完的"


def test_total_wall_clock_never_gets_a_new_minimum_floor(monkeypatch):
    """A request that hangs is bounded by the unit's clock, not by a fresh grace period.

    The provider call is a script that sleeps in the loop's own thread, which is where a
    real request would be waiting: nothing about the code-action loop hands a hung request
    a new floor, and the unit's own wall clock still ends it.
    """
    def slow(messages):
        time.sleep(0.2)
        return final_answer(decision())

    started = time.monotonic()
    outcome = run(
        monkeypatch,
        {"explore": [slow]},
        budgets={"responses": 8, "tools": 16, "seconds": 0.08},
        policy=AgentPolicy(request_seconds=0.05),
    )

    assert time.monotonic() - started < 0.5
    assert outcome.result["analysis"] is None
    assert outcome.result["incomplete"] == "timeout"
    assert outcome.result["usage"]["model_attempts"] <= 2


def test_provider_401_is_not_retried_in_settlement(monkeypatch):
    """A refused endpoint is not asked again by the phase that settles the unit.

    The old driver let the provider's error out of the exploration phase; the migration
    turned it into a labelled failure the phase handler was willing to swallow, which sent
    one more request to an endpoint already known to be down.  The label is what tells the
    two apart, so this asserts the request count as much as the outcome.
    """
    outcome = run(monkeypatch, Always([provider_error(401, f"invalid api key: {CONFIG.api_key}")]))

    assert len(outcome.factory.built().requests) == 1
    assert outcome.result["incomplete"] == "model_error"
    assert outcome.result["status"] == 401
    assert CONFIG.api_key not in str(outcome.result) + str(outcome.events)


def proof(category="xss_r", **overrides):
    """One complete POC payload, so a test writes only the part it is varying."""
    payload = {
        "category": category,
        "poc": {
            "filename": "xss.php",
            "language": "php",
            "script": "<?php echo 'ok';",
            "instructions": "Set the target URL, then run php xss.php.",
            "normal_input": "q=hello",
            "attack_input": "q=<script>alert(1)</script>",
            "expected_result": "The browser executes the payload only for the attack input.",
        },
        "remediation": "Encode the value for its HTML output context.",
    }
    payload.update(overrides)
    return payload


def poc_fields(value: str) -> dict:
    """Every POC field set to the same text, for the blank and placeholder cases."""
    return {
        "filename": value, "language": value, "script": value, "instructions": value,
        "normal_input": value, "attack_input": value, "expected_result": value,
    }


def test_poc_failure_keeps_negative_categories_and_does_not_invent_a_script(monkeypatch):
    """A refused POC is one category's failure: the other two verdicts are already settled."""
    outcome = run(monkeypatch, {
        "explore": [final_answer(decision(xss_r=verdict("candidate", "a.php:3-3")))],
        "poc": Always([final_answer(proof(category="sqli"))]),
    })

    assert outcome.result["analysis"] is None
    assert set(outcome.result["checks"]) == {"sqli", "command_injection"}
    assert outcome.result["verdicts"]["xss_r"].conclusion == "candidate"
    assert outcome.result["result"]["verdicts"]["xss_r"]["evidence"] == "a.php:3-3"
    assert outcome.result["result"]["poc_status"]["xss_r"] == "incomplete"
    assert any(e["kind"] == "unit_checkpoint" for e in outcome.events)


def test_candidate_missing_a_source_to_sink_field_is_corrected_before_poc(monkeypatch):
    """The retry allowance goes to the verdict, which is the only response that can fix it.

    A candidate whose input source is blank is refused before the POC phase opens, so the
    correction is spent where the missing field actually is -- and the phase that produced
    it is the one that produced it again.
    """
    outcome = run(monkeypatch, {
        "explore": [
            final_answer(decision(xss_r=verdict("candidate", "a.php:3-3", input_source="无"))),
            final_answer(decision(xss_r=verdict("candidate", "a.php:3-3"))),
        ],
        "poc": [final_answer(proof())],
    })

    assert outcome.result["analysis"] is not None, outcome.result
    assert outcome.result["usage"]["corrections"] == 1
    assert outcome.phases == ["explore", "explore", "poc"]


def test_empty_poc_fields_cannot_complete_a_candidate(monkeypatch):
    """An empty script is not a script; the category stays incomplete."""
    outcome = run(monkeypatch, {
        "explore": [final_answer(decision(xss_r=verdict("candidate", "a.php:3-3")))],
        "poc": Always([final_answer(proof(poc=poc_fields("")))]),
    })

    assert outcome.result["analysis"] is None
    assert "xss_r" not in outcome.result["checks"]
    assert outcome.result["result"]["poc_status"]["xss_r"] == "incomplete"


@pytest.mark.parametrize("placeholder", ["-", "—"])
def test_placeholder_poc_fields_cannot_complete_a_candidate(monkeypatch, placeholder):
    """A dash in every field is a refusal to write the POC, not a POC."""
    outcome = run(monkeypatch, {
        "explore": [final_answer(decision(xss_r=verdict("candidate", "a.php:3-3")))],
        "poc": Always([final_answer(proof(poc=poc_fields(placeholder), remediation=placeholder))]),
    })

    assert outcome.result["analysis"] is None
    assert "xss_r" not in outcome.result["checks"]
    assert outcome.result["result"]["poc_status"]["xss_r"] == "incomplete"


def test_model_failure_during_poc_marks_the_saved_verdict_as_incomplete(monkeypatch):
    """The verdict survives a provider that dies during the POC phase."""
    outcome = run(monkeypatch, {
        "explore": [final_answer(decision(xss_r=verdict("candidate", "a.php:3-3")))],
        "poc": Always([provider_error(503, "temporary outage")]),
    })

    assert outcome.result["analysis"] is None
    assert outcome.result["incomplete"] == "model_error"
    assert outcome.result["result"]["verdicts"]["xss_r"]["conclusion"] == "candidate"
    assert outcome.result["result"]["poc_status"]["xss_r"] == "incomplete"


def test_current_model_request_counts_toward_the_history_cap(monkeypatch):
    """The request about to be sent is measured, not just the history behind it.

    A unit whose own rendering already exceeds the cap must be caught before the first
    request goes out, so the client is built and then never used for a call.
    """
    huge_unit = {
        **UNIT,
        "cleaned_lines": [{"number": 1, "text": "x" * 1200}],
    }
    outcome = run(
        monkeypatch,
        {"explore": [final_answer(decision())]},
        unit=huge_unit,
        policy=AgentPolicy(request_seconds=0.5, history_bytes=200),
    )

    assert outcome.factory.built().requests == []
    assert outcome.result["analysis"] is None
    assert outcome.result["incomplete"] == "context_limit"


def test_initial_rendering_never_shows_source_the_ledger_did_not_record(monkeypatch):
    """What the model is shown and what counts as evidence are the same set of lines."""
    long_path = "nested/" + "x" * 80 + ".php"
    many_lines = [{"number": number, "text": f"visible-{number}"} for number in range(1, 80)]
    limited_unit = {**UNIT, "file_path": long_path, "cleaned_lines": many_lines}
    outcome = run(
        monkeypatch,
        {"explore": [final_answer(decision())]},
        unit=limited_unit,
        policy=AgentPolicy(request_seconds=0.5, source_bytes=500),
    )

    assert outcome.result["analysis"] is not None
    first = outcome.prompts[0]
    assert "visible-1" in first
    assert "visible-79" not in first


def test_context_limit_during_host_preparation_still_gets_a_tool_free_verdict(monkeypatch):
    """A ledger the host filled up during preparation must not skip the verdict.

    The script keys the one answer to the verdict phase, so an exploration phase that
    opened at all would run out of script and fail the test.
    """
    outcome = run(
        monkeypatch,
        {"verdict": [final_answer(decision())]},
        policy=AgentPolicy(request_seconds=0.5, source_bytes=45),
    )

    assert outcome.result["analysis"] is not None, outcome.result
    assert outcome.result["exploration_incomplete"] == "context_limit"


def test_evidence_parser_keeps_parent_traversal_for_the_snapshot_validator():
    assert agent._parse_evidence("../a.php:3-3") == [{"path": "../a.php", "start_line": 3, "end_line": 3}]


def test_goal_evidence_parser_uses_the_frozen_paths_without_extension_assumptions():
    """Goal citations use actual snapshot paths, including framework/CLI names."""
    refs = agent._parse_evidence(
        "modules/access.module:2-3；bin/worker:4；src/my file.php:5-6；legacy/handler.php6:7-8",
        known_paths={
            "modules/access.module",
            "bin/worker",
            "src/my file.php",
            "legacy/handler.php6",
        },
    )

    assert refs == [
        {"path": "modules/access.module", "start_line": 2, "end_line": 3},
        {"path": "bin/worker", "start_line": 4, "end_line": 4},
        {"path": "src/my file.php", "start_line": 5, "end_line": 6},
        {"path": "legacy/handler.php6", "start_line": 7, "end_line": 8},
    ]


def test_a_cited_range_does_not_also_become_a_single_line_citation():
    r"""`path:82-89` used to yield a phantom `path:8` beside the range.

    The single-line tail accepts `82-89` once its greedy ``\d+`` backtracks, so a
    finding that cited one range arrived with an extra citation to the file's imports --
    which validation accepts, because the worker did read them.
    """
    refs = agent._parse_evidence(
        "定义于 src/service.py:82-89 与 src/service.py:258-260；另见 src/service.py:301。",
        known_paths={"src/service.py"},
    )

    assert refs == [
        {"path": "src/service.py", "start_line": 82, "end_line": 89},
        {"path": "src/service.py", "start_line": 258, "end_line": 260},
        {"path": "src/service.py", "start_line": 301, "end_line": 301},
    ]


def test_goal_evidence_parser_retains_unknown_citations_for_validation():
    """One valid source range must not silently erase a fabricated neighbour."""
    refs = agent._parse_evidence(
        "a.php:2-2; ghost.module:4-4",
        known_paths={"a.php"},
    )
    verified, problems = validate_evidence(
        refs,
        {"a.php": 3},
        [("a.php", 1, 3)],
    )

    assert verified == [{"path": "a.php", "start_line": 2, "end_line": 2}]
    assert any("ghost.module" in problem for problem in problems)


def test_invalid_citation_is_corrected_against_exact_displayed_lines(monkeypatch):
    """A citation to a line nobody read is refused, and the refusal is the retry's reason."""
    outcome = run(monkeypatch, {
        "explore": [
            final_answer(decision(xss_r=verdict("candidate", "a.php:2-2"))),
            final_answer(decision(xss_r=verdict("insufficient_context"))),
        ],
    })

    assert outcome.result["usage"]["corrections"] == 1
    assert outcome.result["terminal_reason"] == "insufficient_context"


def test_read_ledger_never_grants_an_omitted_or_truncated_line():
    ledger = SourceLedger(1000)
    text, _, _ = ledger.offer("a.php", [{"number": 1, "text": "short"}, {"number": 2, "text": "x" * 500}], 40)
    assert "short" in text and "x" * 500 not in text
    refs, errors = validate_evidence([{"path": "a.php", "start_line": 2, "end_line": 2}],
                                    {"a.php": 4}, seen_ranges(UNIT, ledger.reads(), exact=True))
    assert refs == [] and errors
    assert "x" * 500 not in ledger.replay()


def test_a_correction_retry_records_the_reason_the_host_refused_the_output():
    """One correction is the whole round's margin, so its cause has to be readable."""
    events = []
    policy = AgentPolicy()
    execution = Execution({"responses": 4, "tools": 4, "seconds": 60}, policy, events.append)
    execution.enter("planner_decision")

    execution.before_model(deadline=execution.deadline, limit=4, correction=False)
    execution.before_model(
        deadline=execution.deadline, limit=4, correction=True,
        reason="任务 t1 的 src/app.php:1-40 超出文件行数 12",
    )
    retry = next(event for event in events if event["kind"] == "model_retry")
    assert retry["corrections"] == 1
    assert "超出文件行数 12" in retry["reason"]

    # A first request is not a correction, and it must not carry a stale reason.
    assert "reason" not in next(event for event in events if event["kind"] == "model_request")


def test_cancellation_propagates_and_emits_a_terminal_checkpoint(monkeypatch):
    """A cancel arriving while a request is in flight is not swallowed, and is recorded.

    The request blocks in the loop's own thread, which is where a real one waits, so the
    cancel really does arrive mid-request.  The release is a `finally` and not a line after
    the run: the loop's thread is still inside the scripted step when the unit has already
    ended, and `asyncio.run` joins the thread pool on its way out.
    """
    started, release = threading.Event(), threading.Event()

    def blocking(messages):
        started.set()
        release.wait(5)
        return final_answer(decision())

    factory = ModelFactory({"explore": [blocking]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []

    async def cancel():
        task = asyncio.create_task(agent.audit_unit(
            repository=Repository(), snapshot_id="s1", snapshot_name="demo.zip", unit=UNIT,
            prompt_text="audit", config=CONFIG,
            budgets={"responses": 8, "tools": 16, "seconds": 10}, on_event=events.append))
        try:
            await asyncio.to_thread(started.wait, 5)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                return
            raise AssertionError("Cancellation was swallowed")
        finally:
            release.set()

    asyncio.run(cancel())
    assert any(e.get("reason") == "cancelled" for e in events)


def test_goal_executor_returns_achieved_only_with_exact_source_evidence(monkeypatch):
    """A goal worker that can cite the exact line reaches `achieved`, and the run records it."""
    factory = ModelFactory({"task_execute": [final_answer({
        "outcome": "achieved",
        "summary": "找到用户输入直达输出的位置。",
        "reasoning": "当前单元把请求参数直接写入响应，满足给定目标。",
        "next_focus": "",
        "missing_context": [],
        "finding": {
            "title": "未编码的请求参数输出",
            "severity": "high",
            "summary": "请求参数在 a.php 中直接输出。",
            "evidence": "a.php:3-3",
            "input_source": "$_GET['x']",
            "propagation": "参数直接传给 echo",
            "dangerous_operation": "echo（a.php:3）",
            "protection": "未见 HTML 上下文编码",
            "preconditions": "通过包含该文件的入口提供 x 参数",
            "poc": {
                "filename": "controlled_xss_poc.php",
                "language": "php",
                "script": "<?php echo 'controlled test artifact';",
                "instructions": "仅在本地受控演示环境中运行。",
                "normal_input": "x=plain",
                "attack_input": "x=<script>alert(1)</script>",
                "expected_result": "攻击输入会原样进入响应，而正常输入不会产生脚本标记。",
            },
            "remediation": "按 HTML 上下文编码输出值。",
        },
    })]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []
    result = asyncio.run(agent.pursue_task_work(
        repository=Repository(),
        snapshot_id="s1",
        snapshot_name="demo.zip",
        unit=UNIT,
        task={
            "objective": "寻找请求参数未经编码输出的可达路径。",
            "success_criteria": "保存至少一处带原始行号的直接输出证据。",
            "max_iterations": 2,
            "max_workers": 2,
            "stop_on_achieved": True,
        },
        attempt=1,
        config=CONFIG,
        budgets={"responses": 8, "tools": 16, "seconds": 2},
        policy=AgentPolicy(request_seconds=0.5),
        on_event=events.append,
    ))

    assert result["outcome"] == "achieved", result
    assert result["result"]["finding"]["evidence"] == "a.php:3-3"
    assert any("寻找请求参数未经编码输出的可达路径" in message for message in factory.prompts)
    assessment = next(event for event in events if event["kind"] == "task_assessment")
    assert assessment["outcome"] == "achieved"
    assert assessment["rationale"] == "当前单元把请求参数直接写入响应，满足给定目标。"
    assert assessment["evidence"]["summary"] == "a.php:3-3"
    assert assessment["evidence"]["references"] == [{"path": "a.php", "start_line": 3, "end_line": 3}]
    assert assessment["evidence"]["findings"][0]["title"] == "未编码的请求参数输出"
    assert assessment["evidence"]["reviewed_ranges"]
    calls = [event for event in events if event["kind"] == "tool_call"]
    results = [event for event in events if event["kind"] == "tool_result"]
    assert calls and results
    assert {event["call_id"] for event in calls} == {event["call_id"] for event in results}
    assert all(event["span_id"] and event["duration_ms"] >= 0 for event in results)


def test_goal_executor_requeues_model_failure_instead_of_calling_it_missing_context(monkeypatch):
    """A dead endpoint is retryable, so the item goes back to the queue rather than `blocked`."""
    factory = ModelFactory(Always([provider_error(503, "temporary outage")]))
    monkeypatch.setattr(agent, "build_code_model", factory)
    result = asyncio.run(agent.pursue_task_work(
        repository=Repository(),
        snapshot_id="s1",
        snapshot_name="demo.zip",
        unit=UNIT,
        task={
            "objective": "寻找请求参数未经编码输出的可达路径。",
            "success_criteria": "保存至少一处带原始行号的直接输出证据。",
            "max_iterations": 2,
            "max_workers": 2,
            "stop_on_achieved": True,
        },
        attempt=1,
        config=CONFIG,
        budgets={"responses": 8, "tools": 16, "seconds": 2},
        policy=AgentPolicy(request_seconds=0.5),
    ))

    assert result["outcome"] == "continue"
    assert result["terminal_reason"] == "model_error"
    assert CONFIG.api_key not in str(result)


def test_goal_executor_does_not_accept_achieved_without_the_required_poc(monkeypatch):
    """A vulnerability task cannot satisfy its goal with evidence alone when POC is required."""
    factory = ModelFactory(Always([final_answer({
        "outcome": "achieved",
        "summary": "找到用户输入直达输出的位置。",
        "reasoning": "当前单元把请求参数直接写入响应，满足给定目标。",
        "next_focus": "",
        "missing_context": [],
        "finding": {
            "title": "未编码的请求参数输出",
            "severity": "high",
            "summary": "请求参数在 a.php 中直接输出。",
            "evidence": "a.php:3-3",
            "input_source": "$_GET['x']",
            "propagation": "参数直接传给 echo",
            "dangerous_operation": "echo（a.php:3）",
            "protection": "未见 HTML 上下文编码",
            "preconditions": "通过包含该文件的入口提供 x 参数",
            "remediation": "按 HTML 上下文编码输出值。",
        },
    })]))
    monkeypatch.setattr(agent, "build_code_model", factory)
    result = asyncio.run(agent.pursue_task_work(
        repository=Repository(),
        snapshot_id="s1",
        snapshot_name="demo.zip",
        unit=UNIT,
        task={
            "objective": "寻找请求参数未经编码输出的可达路径。",
            "success_criteria": "保存至少一处带原始行号和 POC 的直接输出证据。",
            "max_iterations": 2,
            "max_total_attempts": 8,
            "max_workers": 2,
            "stop_on_achieved": True,
            "require_poc": True,
        },
        attempt=1,
        config=CONFIG,
        budgets={"responses": 8, "tools": 16, "seconds": 2},
        policy=AgentPolicy(request_seconds=0.5),
    ))

    assert result["outcome"] == "continue"
    assert result["terminal_reason"] == "invalid_output"
    # The worker keeps its allowance, so the refusal is an observation it can act on: it is
    # asked again for each correction the policy allows, and the request after the last one
    # is refused by the host rather than sent.
    assert len(factory.built().requests) == 1 + AgentPolicy().output_corrections


def test_goal_executor_allows_a_source_fact_goal_without_poc_when_explicitly_disabled(monkeypatch):
    """The POC gate is configurable for non-vulnerability source facts."""
    factory = ModelFactory(Always([final_answer({
        "outcome": "achieved",
        "summary": "已确认输出点缺少 HTML 上下文编码。",
        "reasoning": "当前目标只要求确认源码事实，不要求制作利用脚本。",
        "next_focus": "",
        "missing_context": [],
        "finding": {
            "title": "未编码的请求参数输出",
            "severity": "medium",
            "summary": "请求参数在 a.php 中直接输出。",
            "evidence": "a.php:3-3",
            "input_source": "$_GET['x']",
            "propagation": "参数直接传给 echo",
            "dangerous_operation": "echo（a.php:3）",
            "protection": "未见 HTML 上下文编码",
            "preconditions": "通过包含该文件的入口提供 x 参数",
            "remediation": "按 HTML 上下文编码输出值。",
        },
    })]))
    monkeypatch.setattr(agent, "build_code_model", factory)
    result = asyncio.run(agent.pursue_task_work(
        repository=Repository(),
        snapshot_id="s1",
        snapshot_name="demo.zip",
        unit=UNIT,
        task={
            "objective": "确认所选源码是否将请求参数未经 HTML 上下文编码直接输出。",
            "success_criteria": "保存至少一处带原始行号的源码事实。",
            "max_iterations": 2,
            "max_total_attempts": 8,
            "max_workers": 2,
            "stop_on_achieved": True,
            "require_poc": False,
        },
        attempt=1,
        config=CONFIG,
        budgets={"responses": 8, "tools": 16, "seconds": 2},
        policy=AgentPolicy(request_seconds=0.5),
    ))

    assert result["outcome"] == "achieved", result
    assert result["result"]["finding"]["poc"] is None
    assert len(factory.built().requests) == 1


def test_goal_executor_persists_host_observed_scope_limits_with_the_assessment(monkeypatch):
    """Out-of-scope dependency notes are durable even if the model omits them."""
    class ScopeLimitedRepository(Repository):
        def get_context(self, snapshot_id, unit):
            return {
                "excerpts": [],
                "unresolved_dependencies": [
                    {"reason": "Related source is outside this task's frozen scope", "path": "vendor/helper.inc"},
                ],
            }

    factory = ModelFactory({"task_execute": [final_answer({
        "outcome": "achieved",
        "summary": "已确认当前函数读取请求参数并输出。",
        "reasoning": "结论仅来自当前单元中已显示的请求参数与输出语句。",
        "next_focus": "",
        "missing_context": [],
        "finding": {
            "title": "请求参数输出位置",
            "summary": "当前函数将请求参数传给输出语句。",
            "evidence": "a.php:3-3",
        },
    })]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events: list[dict] = []
    result = asyncio.run(agent.pursue_task_work(
        repository=ScopeLimitedRepository(),
        snapshot_id="s1",
        snapshot_name="demo.zip",
        unit=UNIT,
        task={
            "objective": "确认当前函数中的请求参数输出边界。",
            "success_criteria": "保存一条带源码行号的输出位置结论。",
            "max_iterations": 2,
            "max_total_attempts": 8,
            "max_workers": 2,
            "stop_on_achieved": True,
            "require_poc": False,
        },
        attempt=1,
        config=CONFIG,
        budgets={"responses": 8, "tools": 16, "seconds": 2},
        policy=AgentPolicy(request_seconds=0.5),
        on_event=events.append,
    ))

    assert result["outcome"] == "achieved", result
    assert any("无法解析的依赖" in note for note in result["result"]["missing_context"])
    assessment = next(event for event in events if event["kind"] == "task_assessment")
    assert assessment["missing_context"] == result["result"]["missing_context"]


def test_planner_worker_preloads_a_multi_file_bundle_when_no_tools_are_available(monkeypatch):
    """A dynamic task must not fall back to its first file when its tool budget is zero."""
    class BundleRepository(Repository):
        def build_context_bundle(self, snapshot_id, task, allowed_paths, max_bytes):
            assert allowed_paths == {"a.php", "b.php"}
            return {
                "excerpts": [
                    {"path": "a.php", "start_line": 3, "end_line": 3,
                     "lines": [{"number": 3, "text": "$value = $_GET['x'];"}], "reason": "entry"},
                    {"path": "b.php", "start_line": 2, "end_line": 2,
                     "lines": [{"number": 2, "text": "echo $value;"}], "reason": "sink"},
                ],
                "unresolved_dependencies": [],
                "limitations": [],
            }

    factory = ModelFactory({"task_execute": [final_answer({
        "outcome": "achieved",
        "summary": "已读取入口与输出文件中的数据流。",
        "reasoning": "入口读取请求参数，另一文件将同一变量输出，两个行号均已展示。",
        "next_focus": "",
        "missing_context": [],
        "finding": {
            "title": "跨文件请求参数输出",
            "kind": "data_flow",
            "summary": "请求参数在入口读取后进入输出文件。",
            "evidence": "a.php:3-3; b.php:2-2",
        },
    })]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events: list[dict] = []
    result = asyncio.run(agent.pursue_planner_task(
        repository=BundleRepository(),
        snapshot_id="s1",
        snapshot_name="demo.zip",
        planner_task={
            "id": "task-1", "task_key": "entry-output", "title": "入口到输出",
            "context_spec": {"source_refs": []},
        },
        run_task={
            "objective": "确认请求参数从入口到输出的跨文件路径。",
            "success_criteria": "保存两个文件的原始行号证据。",
            "max_iterations": 2,
            "max_total_attempts": 8,
            "max_workers": 1,
            "stop_on_achieved": True,
            "require_poc": False,
        },
        attempt=1,
        allowed_paths={"a.php", "b.php"},
        config=CONFIG,
        budgets={"responses": 4, "tools": 0, "seconds": 2},
        policy=AgentPolicy(request_seconds=0.5),
        on_event=events.append,
    ))

    assert result["outcome"] == "achieved", result
    assert any("文件: a.php" in message and "3 | $value = $_GET['x'];" in message for message in factory.prompts)
    assert any("b.php:2 | echo $value;" in message for message in factory.prompts)
    assert {item["path"] for item in result["seen"]} == {"a.php", "b.php"}
    assert any(event["kind"] == "planner_context_prepared" for event in events)
    assert not [event for event in events if event["kind"] == "tool_call"]


def test_planner_worker_can_search_a_bounded_peer_trace_as_an_untrusted_lead(monkeypatch):
    """Peer activity is available to a Planner worker but cannot replace source evidence."""
    searches: list[str] = []
    tables = offered_tools(monkeypatch)
    factory = ModelFactory({"task_execute": [
        call("search_peer_traces", query="auth"),
        final_answer({
            "outcome": "no_evidence",
            "summary": "同行记录提供了认证线索，但当前任务未取得决定性行号。",
            "reasoning": "同行工具摘要只用于定位；本任务没有将其作为源码引用。",
            "next_focus": "",
            "missing_context": [],
        }),
    ]})
    monkeypatch.setattr(agent, "build_code_model", factory)

    def search_peer(query: str) -> list[dict]:
        searches.append(query)
        return [{
            "event_id": 19,
            "task_key": "entry-auth",
            "title": "入口认证链",
            "kind": "task_assessment",
            "trace": {"summary": "认证函数读取 session。", "rationale": "见该任务自己的源码范围。"},
        }]

    events: list[dict] = []
    result = asyncio.run(agent.pursue_task_work(
        repository=Repository(),
        snapshot_id="s1",
        snapshot_name="demo.zip",
        unit=UNIT,
        task={
            "objective": "确认入口认证条件是否在敏感操作前得到验证。",
            "success_criteria": "结论必须来自本 worker 已读取的原始源码行号。",
            "max_iterations": 2,
            "max_total_attempts": 8,
            "require_poc": False,
        },
        attempt=1,
        allowed_paths={"a.php", "entry.php"},
        initial_excerpts=[{"path": "a.php", "lines": UNIT["cleaned_lines"]}],
        peer_trace_search=search_peer,
        peer_trace_read=lambda task_key, event_ids: [],
        config=CONFIG,
        budgets={"responses": 4, "tools": 2, "seconds": 2},
        policy=AgentPolicy(request_seconds=0.5),
        on_event=events.append,
    ))

    assert result["outcome"] == "no_evidence", result
    assert searches == ["auth"]
    # The worker is offered the peer tools only when the run really has traces to search.
    assert {"search_peer_traces", "get_peer_trace"} <= tables[0]
    assert any(
        event["kind"] == "tool_result" and event["tool"] == "search_peer_traces" and event["status"] == "ok"
        for event in events
    )
    assert any("未验证的审计线索" in message for message in factory.prompts)
