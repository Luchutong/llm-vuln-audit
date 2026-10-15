"""Exercise the actual PydanticAI graph with controlled provider responses."""
import asyncio
import json
import time
from dataclasses import replace

import pytest
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from audit import agent
from audit.config import ModelConfig
from audit.evidence import seen_ranges, validate_evidence
from audit.runtime import AgentPolicy, SourceLedger

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

    def search_code(self, snapshot_id, query, path=None, limit=40):
        self.searches += 1
        return {"matches": [], "truncated": False}

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


def output(info, data):
    return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, json.dumps(data, ensure_ascii=False))])


def run(monkeypatch, function, *, budgets=None, policy=None, repo=None, unit=None):
    model = FunctionModel(function)
    monkeypatch.setattr(agent, "build_model", lambda config: model)
    events = []
    result = asyncio.run(agent.audit_unit(
        repository=repo or Repository(), snapshot_id="s1", snapshot_name="demo.zip", unit=unit or UNIT,
        prompt_text="审计当前 PHP 单元的三类漏洞", config=CONFIG,
        budgets=budgets or {"responses": 8, "tools": 16, "seconds": 2},
        policy=policy or AgentPolicy(request_seconds=0.5), on_event=events.append,
    ))
    return result, events


def test_normal_audit_explains_all_categories_without_generating_unneeded_pocs(monkeypatch):
    def provider(messages, info):
        assert {tool.name for tool in info.function_tools} <= {"read_source", "search_code", "get_context"}
        assert "entry.php:1" in str(messages)
        return output(info, decision())
    result, events = run(monkeypatch, provider)
    assert result["analysis"] is not None
    assert result["usage"]["model_attempts"] == 1
    assert result["usage"]["tool_calls"] == 1
    assert [e["kind"] for e in events][-1] == "agent_terminal"


def test_repeated_tool_calls_stop_and_force_a_tool_free_verdict(monkeypatch):
    def provider(messages, info):
        if info.function_tools:
            return ModelResponse(parts=[ToolCallPart("search_code", {"query": "missing"})])
        return output(info, decision())
    repo = Repository()
    result, events = run(monkeypatch, provider, repo=repo)
    assert result["analysis"] is not None, result
    assert result["exploration_incomplete"] == "no_progress"
    assert repo.searches == 1, "duplicates must not re-read the repository"
    assert result["usage"]["model_attempts"] == 4
    assert any(e.get("reason") == "no_progress" for e in events)


def test_distinct_empty_searches_also_stop_without_progress(monkeypatch):
    count = 0
    def provider(messages, info):
        nonlocal count
        count += 1
        if info.function_tools:
            return ModelResponse(parts=[ToolCallPart("search_code", {"query": f"missing{count}"})])
        return output(info, decision())
    result, _ = run(monkeypatch, provider)
    assert result["analysis"] is not None
    assert result["exploration_incomplete"] == "no_progress"
    assert result["usage"]["model_attempts"] == 4


def test_malformed_output_has_one_shared_correction_and_a_finite_end(monkeypatch):
    calls = 0
    def provider(messages, info):
        nonlocal calls
        calls += 1
        return output(info, {"summary": "missing categories"})
    result, _ = run(monkeypatch, provider)
    assert result["analysis"] is None
    assert result["incomplete"] == "invalid_output"
    assert result["usage"]["corrections"] == 1
    assert calls <= 3


def test_tool_flood_cannot_spend_the_reserved_model_budget(monkeypatch):
    def provider(messages, info):
        if info.function_tools:
            return ModelResponse(parts=[ToolCallPart("read_source", {"path": "a.php", "start": n, "end": n}) for n in range(1, 20)])
        return output(info, decision())
    result, _ = run(monkeypatch, provider, budgets={"responses": 8, "tools": 3, "seconds": 2})
    assert result["analysis"] is not None, result
    assert result["usage"]["tool_calls"] <= 3
    assert result["usage"]["model_attempts"] <= 8


def test_total_wall_clock_never_gets_a_new_minimum_floor(monkeypatch):
    async def provider(messages, info):
        await asyncio.sleep(10)
        return output(info, decision())
    started = time.monotonic()
    result, _ = run(monkeypatch, provider, budgets={"responses": 8, "tools": 16, "seconds": 0.08},
                    policy=AgentPolicy(request_seconds=0.05))
    assert time.monotonic() - started < 0.5
    assert result["analysis"] is None
    assert result["incomplete"] in ("timeout", "request_timeout")
    assert result["usage"]["model_attempts"] <= 2


def test_provider_401_is_not_retried_in_settlement(monkeypatch):
    from pydantic_ai.exceptions import ModelHTTPError
    calls = 0
    def provider(messages, info):
        nonlocal calls
        calls += 1
        raise ModelHTTPError(401, "test", {"message": "private-test-key"})
    result, events = run(monkeypatch, provider)
    assert calls == 1
    assert result["incomplete"] == "model_error"
    assert result["status"] == 401
    assert CONFIG.api_key not in str(result) + str(events)


def test_poc_failure_keeps_negative_categories_and_does_not_invent_a_script(monkeypatch):
    def provider(messages, info):
        schema = info.output_tools[0].parameters_json_schema
        if "category" in schema.get("properties", {}):
            return output(info, {"category": "sqli"})
        return output(info, decision(xss_r=verdict("candidate", "a.php:3-3")))
    result, events = run(monkeypatch, provider)
    assert result["analysis"] is None
    assert set(result["checks"]) == {"sqli", "command_injection"}
    assert result["verdicts"]["xss_r"].conclusion == "candidate"
    assert result["result"]["verdicts"]["xss_r"]["evidence"] == "a.php:3-3"
    assert result["result"]["poc_status"]["xss_r"] == "incomplete"
    assert any(e["kind"] == "unit_checkpoint" for e in events)


def test_candidate_missing_a_source_to_sink_field_is_corrected_before_poc(monkeypatch):
    calls = []

    def provider(messages, info):
        schema = info.output_tools[0].parameters_json_schema
        is_poc = "category" in schema.get("properties", {})
        calls.append("poc" if is_poc else "verdict")
        if is_poc:
            return output(info, {
                "category": "xss_r",
                "poc": {
                    "filename": "xss.php", "language": "php", "script": "<?php echo 'ok';",
                    "instructions": "Set the target URL, then run php xss.php.",
                    "normal_input": "q=hello", "attack_input": "q=<script>alert(1)</script>",
                    "expected_result": "The browser executes the payload only for the attack input.",
                },
                "remediation": "Encode the value for its HTML output context.",
            })
        if calls.count("verdict") == 1:
            return output(info, decision(xss_r=verdict("candidate", "a.php:3-3", input_source="无")))
        return output(info, decision(xss_r=verdict("candidate", "a.php:3-3")))

    result, _ = run(monkeypatch, provider)
    assert result["analysis"] is not None, result
    assert result["usage"]["corrections"] == 1
    assert calls == ["verdict", "verdict", "poc"]


def test_empty_poc_fields_cannot_complete_a_candidate(monkeypatch):
    def provider(messages, info):
        schema = info.output_tools[0].parameters_json_schema
        if "category" in schema.get("properties", {}):
            return output(info, {
                "category": "xss_r",
                "poc": {
                    "filename": "xss.php", "language": "php", "script": "",
                    "instructions": "", "normal_input": "", "attack_input": "", "expected_result": "",
                },
                "remediation": "Encode output.",
            })
        return output(info, decision(xss_r=verdict("candidate", "a.php:3-3")))

    result, _ = run(monkeypatch, provider)
    assert result["analysis"] is None
    assert "xss_r" not in result["checks"]
    assert result["result"]["poc_status"]["xss_r"] == "incomplete"


@pytest.mark.parametrize("placeholder", ["-", "—"])
def test_placeholder_poc_fields_cannot_complete_a_candidate(monkeypatch, placeholder):
    def provider(messages, info):
        schema = info.output_tools[0].parameters_json_schema
        if "category" in schema.get("properties", {}):
            return output(info, {
                "category": "xss_r",
                "poc": {
                    "filename": placeholder, "language": placeholder, "script": placeholder,
                    "instructions": placeholder, "normal_input": placeholder,
                    "attack_input": placeholder, "expected_result": placeholder,
                },
                "remediation": placeholder,
            })
        return output(info, decision(xss_r=verdict("candidate", "a.php:3-3")))

    result, _ = run(monkeypatch, provider)
    assert result["analysis"] is None
    assert "xss_r" not in result["checks"]
    assert result["result"]["poc_status"]["xss_r"] == "incomplete"


def test_model_failure_during_poc_marks_the_saved_verdict_as_incomplete(monkeypatch):
    from pydantic_ai.exceptions import ModelHTTPError

    def provider(messages, info):
        schema = info.output_tools[0].parameters_json_schema
        if "category" in schema.get("properties", {}):
            raise ModelHTTPError(503, "test", {"message": "temporary outage"})
        return output(info, decision(xss_r=verdict("candidate", "a.php:3-3")))

    result, _ = run(monkeypatch, provider)
    assert result["analysis"] is None
    assert result["incomplete"] == "model_error"
    assert result["result"]["verdicts"]["xss_r"]["conclusion"] == "candidate"
    assert result["result"]["poc_status"]["xss_r"] == "incomplete"


def test_current_model_request_counts_toward_the_history_cap(monkeypatch):
    calls = 0

    def provider(messages, info):
        nonlocal calls
        calls += 1
        return output(info, decision())

    huge_unit = {
        **UNIT,
        "cleaned_lines": [{"number": 1, "text": "x" * 1200}],
    }
    result, _ = run(
        monkeypatch,
        provider,
        unit=huge_unit,
        policy=AgentPolicy(request_seconds=0.5, history_bytes=200),
    )
    assert calls == 0
    assert result["analysis"] is None
    assert result["incomplete"] == "context_limit"


def test_initial_rendering_never_shows_source_the_ledger_did_not_record(monkeypatch):
    received = []

    def provider(messages, info):
        received.append(str(messages))
        return output(info, decision())

    long_path = "nested/" + "x" * 80 + ".php"
    many_lines = [{"number": number, "text": f"visible-{number}"} for number in range(1, 80)]
    limited_unit = {**UNIT, "file_path": long_path, "cleaned_lines": many_lines}
    result, _ = run(
        monkeypatch,
        provider,
        unit=limited_unit,
        policy=AgentPolicy(request_seconds=0.5, source_bytes=500),
    )
    assert result["analysis"] is not None
    assert received
    assert "visible-1" in received[0]
    assert "visible-79" not in received[0]


def test_context_limit_during_host_preparation_still_gets_a_tool_free_verdict(monkeypatch):
    def provider(messages, info):
        assert not info.function_tools
        return output(info, decision())

    result, _ = run(
        monkeypatch,
        provider,
        policy=AgentPolicy(request_seconds=0.5, source_bytes=45),
    )
    assert result["analysis"] is not None, result
    assert result["exploration_incomplete"] == "context_limit"


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
    calls = 0
    def provider(messages, info):
        nonlocal calls
        calls += 1
        if calls == 1:
            return output(info, decision(xss_r=verdict("candidate", "a.php:2-2")))
        return output(info, decision(xss_r=verdict("insufficient_context")))
    result, _ = run(monkeypatch, provider)
    assert result["usage"]["corrections"] == 1
    assert result["terminal_reason"] == "insufficient_context"


def test_read_ledger_never_grants_an_omitted_or_truncated_line():
    ledger = SourceLedger(1000)
    text, _, _ = ledger.offer("a.php", [{"number": 1, "text": "short"}, {"number": 2, "text": "x" * 500}], 40)
    assert "short" in text and "x" * 500 not in text
    refs, errors = validate_evidence([{"path": "a.php", "start_line": 2, "end_line": 2}],
                                    {"a.php": 4}, seen_ranges(UNIT, ledger.reads(), exact=True))
    assert refs == [] and errors
    assert "x" * 500 not in ledger.replay()


def test_cancellation_propagates_and_emits_a_terminal_checkpoint(monkeypatch):
    async def provider(messages, info):
        await asyncio.Event().wait()
    monkeypatch.setattr(agent, "build_model", lambda config: FunctionModel(provider))
    events = []
    async def cancel():
        task = asyncio.create_task(agent.audit_unit(
            repository=Repository(), snapshot_id="s1", snapshot_name="demo.zip", unit=UNIT,
            prompt_text="audit", config=CONFIG, budgets={"responses": 8, "tools": 16, "seconds": 10}, on_event=events.append))
        await asyncio.sleep(0.01)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            return
        raise AssertionError("Cancellation was swallowed")
    asyncio.run(cancel())
    assert any(e.get("reason") == "cancelled" for e in events)


def test_goal_executor_returns_achieved_only_with_exact_source_evidence(monkeypatch):
    received = []
    events = []

    def provider(messages, info):
        received.append(str(messages))
        return output(info, {
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
        })

    monkeypatch.setattr(agent, "build_model", lambda config: FunctionModel(provider))
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
    assert any("寻找请求参数未经编码输出的可达路径" in message for message in received)
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
    from pydantic_ai.exceptions import ModelHTTPError

    def provider(messages, info):
        raise ModelHTTPError(503, "test", {"message": "temporary outage"})

    monkeypatch.setattr(agent, "build_model", lambda config: FunctionModel(provider))
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
    calls = 0

    def provider(messages, info):
        nonlocal calls
        calls += 1
        return output(info, {
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
        })

    monkeypatch.setattr(agent, "build_model", lambda config: FunctionModel(provider))
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
    assert calls >= 2


def test_goal_executor_allows_a_source_fact_goal_without_poc_when_explicitly_disabled(monkeypatch):
    """The POC gate is configurable for non-vulnerability source facts."""
    calls = 0

    def provider(messages, info):
        nonlocal calls
        calls += 1
        return output(info, {
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
        })

    monkeypatch.setattr(agent, "build_model", lambda config: FunctionModel(provider))
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
    assert calls == 1


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

    def provider(messages, info):
        return output(info, {
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
        })

    monkeypatch.setattr(agent, "build_model", lambda config: FunctionModel(provider))
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

    received: list[str] = []

    def provider(messages, info):
        received.append(str(messages))
        return output(info, {
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
        })

    monkeypatch.setattr(agent, "build_model", lambda config: FunctionModel(provider))
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
    assert any("文件: a.php" in message and "3 | $value = $_GET['x'];" in message for message in received)
    assert any("b.php:2 | echo $value;" in message for message in received)
    assert {item["path"] for item in result["seen"]} == {"a.php", "b.php"}
    assert any(event["kind"] == "planner_context_prepared" for event in events)
    assert not [event for event in events if event["kind"] == "tool_call"]


def test_planner_worker_can_search_a_bounded_peer_trace_as_an_untrusted_lead(monkeypatch):
    """Peer activity is available to a Planner worker but cannot replace source evidence."""
    received: list[str] = []
    turns = 0
    searches: list[str] = []

    def provider(messages, info):
        nonlocal turns
        received.append(str(messages))
        if turns == 0:
            turns += 1
            assert {"search_peer_traces", "get_peer_trace"} <= {tool.name for tool in info.function_tools}
            return ModelResponse(parts=[ToolCallPart("search_peer_traces", {"query": "auth"})])
        return output(info, {
            "outcome": "no_evidence",
            "summary": "同行记录提供了认证线索，但当前任务未取得决定性行号。",
            "reasoning": "同行工具摘要只用于定位；本任务没有将其作为源码引用。",
            "next_focus": "",
            "missing_context": [],
        })

    def search_peer(query: str) -> list[dict]:
        searches.append(query)
        return [{
            "event_id": 19,
            "task_key": "entry-auth",
            "title": "入口认证链",
            "kind": "task_assessment",
            "trace": {"summary": "认证函数读取 session。", "rationale": "见该任务自己的源码范围。"},
        }]

    monkeypatch.setattr(agent, "build_model", lambda config: FunctionModel(provider))
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
    assert any(
        event["kind"] == "tool_result" and event["tool"] == "search_peer_traces" and event["status"] == "ok"
        for event in events
    )
    assert any("未验证的审计线索" in message for message in received)
