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
