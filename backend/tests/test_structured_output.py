"""Offline publication replay: the real model gate, without a provider or interpreter."""
import asyncio
import json
import threading

import pytest

from audit.codemodel import ModelCallFailed
from audit.config import ModelConfig
from audit.runtime import AgentPolicy
from audit.structured_output import StructuredOutputIssue, drive_structured_phase, parse_json_object
from tests.code_model import Answer, Host, Outcome, Phase, ScriptedCodeModel, transcript


async def _play(script, *, host=None, limit=8, max_steps=8, validate=None):
    host = host or Host()
    gate = Phase(host, output_model=Answer, phase="planner_publish", limit=limit, validate=validate).gate()
    model = ScriptedCodeModel(script, gate=gate)
    outcome = Outcome(model=model, gate=gate, host=host)
    try:
        outcome.output = await drive_structured_phase(
            model, gate, "发布审计决策。契约：{note: string}。", "只使用已读源码。", max_steps=max_steps,
        )
    except BaseException as exc:
        outcome.failure = exc
    return outcome


def play(script, **kwargs):
    return asyncio.run(_play(script, **kwargs))


@pytest.mark.parametrize("text", [
    '{"note":"done"}',
    ' \n {"note":"中文，带引号 \\" 与花括号 {}"} \t',
    '```json\n{"note":"done"}\n```',
    '```JSON\r\n{"note":"done"}\r\n```',
    '```\n{"note":"done"}\n```',
])
def test_publication_accepts_one_complete_json_object(text):
    assert isinstance(parse_json_object(text), dict)


@pytest.mark.parametrize("text", [
    '', '  ', None, [],
    'final_answer({"note":"done"})',
    '<code>final_answer({"note":"done"})</code>',
    '{"note":"a"} {"note":"b"}',
    '说明\n{"note":"done"}',
    '{"note":"done"}\n说明',
    "{'note': 'done'}",
    '{"note":None}', '{"note":NaN}', '{"note":Infinity}',
    '{"note":"first","note":"second"}',
    '[{"note":"done"}]', '"done"', 'null',
    '```python\n{"note":"done"}\n```',
    '```json\n{"note":"done"}',
    '```json\n{"note":"done"}\n```\n```json\n{}\n```',
])
def test_publication_does_not_guess_or_execute_invalid_output(text):
    with pytest.raises(StructuredOutputIssue):
        parse_json_object(text)


def test_json_error_position_is_recorded_without_response_text():
    secret_prose = "PRIVATE_MODEL_PROSE"
    outcome = play(['{"note": "' + secret_prose, '{"note":"recovered"}'])
    assert outcome.failure is None
    assert outcome.output == Answer(note="recovered")
    assert outcome.gate.closed
    assert outcome.host.execution.attempts == 2
    assert outcome.host.execution.corrections == 1
    error = outcome.host.events_of("agent_parse_error")[0]
    assert error["category"] == "invalid_json"
    assert error["diagnostics"]["line"] == 1
    assert error["diagnostics"]["column"] > 0
    assert secret_prose not in json.dumps(outcome.host.events)
    assert secret_prose not in transcript(outcome.model.requests[1])
    assert len(outcome.model.requests[1]) == 3
    assert not outcome.host.events_of("agent_code")
    assert not outcome.host.calls
    assert outcome.host.events_of("agent_error_summary")[0]["categories"]["invalid_json"] == {
        "errors": 1, "recovered": 1,
    }


def test_json_publication_uses_the_existing_usage_and_provider_contract():
    outcome = play(['{"note":"done"}'], host=Host(budgets={"responses": 8, "tools": 0, "seconds": 600}))
    assert outcome.failure is None
    assert outcome.gate.published == Answer(note="done")
    assert outcome.host.execution.usage.requests == 1
    assert outcome.host.execution.usage.input_tokens == 120
    assert outcome.host.execution.usage.output_tokens == 8
    assert outcome.host.execution.tools == 0
    assert len(outcome.host.events_of("model_request")) == 1
    assert len(outcome.host.events_of("model_response")) == 1
    assert outcome.model.params[0]["stop_sequences"] is None
    assert outcome.model.params[0]["response_format"] is None
    assert outcome.model.params[0]["tools_to_call_from"] is None
    assert outcome.model.params[0]["timeout"] <= AgentPolicy().request_seconds
    assert outcome.model.params[0]["max_tokens"] == 1024


def test_typed_and_host_rejections_are_corrected_and_counted_once():
    def validate(value):
        if value.note != "ok":
            raise ValueError("note 必须是 ok")
        return value

    outcome = play(['{"note":"x","extra":true}', '{"note":"no"}', '{"note":"ok"}'], validate=validate)
    assert outcome.failure is None
    assert outcome.output == Answer(note="ok")
    assert outcome.host.execution.attempts == 3
    assert outcome.host.execution.corrections == 2
    assert "Extra inputs are not permitted" in transcript(outcome.model.requests[1])
    assert "note 必须是 ok" in transcript(outcome.model.requests[2])
    counts = outcome.host.events_of("agent_error_summary")[0]["categories"]["invalid_output"]
    assert counts == {"errors": 2, "recovered": 1}


def test_persistent_format_failure_obeys_two_corrections_and_total_requests():
    outcome = play(["not JSON", "not JSON", "not JSON"])
    assert outcome.reason() == "invalid_output"
    assert outcome.host.execution.attempts == 3
    assert outcome.host.execution.corrections == 2
    assert len(outcome.model.requests) == 3
    assert outcome.gate.published is None
    assert outcome.gate.closed
    assert len(outcome.host.events_of("agent_error_summary")) == 1


def test_parse_correction_cannot_extend_the_run_response_budget():
    host = Host(budgets={"responses": 1, "tools": 8, "seconds": 600})
    outcome = play(["not JSON"], host=host)
    assert outcome.reason() == "budget"
    assert outcome.host.execution.attempts == 1
    assert outcome.host.execution.corrections == 0


def test_publication_max_steps_is_a_hard_bound():
    outcome = play(["not JSON"], max_steps=1)
    assert outcome.reason() == "invalid_output"
    assert len(outcome.model.requests) == 1
    assert outcome.host.execution.attempts == 1


def test_request_timeout_is_retried_as_a_transient_failure_not_a_format_error():
    """A timeout is a network fault: it is retried as a provider failure, never parsed.

    Each retry is a real request, so it spends the phase's response allowance and leaves
    a ``provider_retry`` event -- and a timeout must not enter the format-correction loop
    the way a malformed JSON answer does.
    """
    policy = AgentPolicy(transient_backoff_seconds=0, transient_max_backoff_seconds=0)
    attempts = policy.transient_retries + 1
    outcome = play([TimeoutError("offline timeout")] * attempts, host=Host(policy=policy))
    assert isinstance(outcome.failure, ModelCallFailed)
    assert outcome.reason() == "request_timeout"
    assert len(outcome.model.requests) == attempts
    assert len(outcome.host.events_of("provider_retry")) == policy.transient_retries
    assert not outcome.host.events_of("agent_parse_error")
    assert outcome.host.execution.corrections == 0


def test_response_after_the_deadline_cannot_publish():
    host = Host()

    def after_deadline(_messages):
        host.execution.started -= 1000
        return '{"note":"late"}'

    outcome = play([after_deadline], host=host)
    assert outcome.reason() == "timeout"
    assert outcome.gate.published is None


def test_cancellation_closes_the_gate_before_late_provider_response():
    async def scenario():
        host = Host()
        gate = Phase(host, output_model=Answer, phase="planner_publish").gate()
        started = asyncio.Event()
        release = threading.Event()
        loop = asyncio.get_running_loop()

        def stalled(_messages):
            loop.call_soon_threadsafe(started.set)
            assert release.wait(timeout=3)
            return '{"note":"late"}'

        model = ScriptedCodeModel([stalled], gate=gate)
        task = asyncio.create_task(drive_structured_phase(model, gate, "契约", "态势", max_steps=3))
        await asyncio.wait_for(started.wait(), timeout=1)
        task.cancel()
        try:
            with pytest.raises(asyncio.CancelledError):
                await task
            assert gate.closed
        finally:
            release.set()
        # Let the abandoned provider thread attempt record_response on the closed gate.
        await asyncio.sleep(0.05)
        assert gate.published is None
        assert host.execution.attempts == 1
        assert not host.events_of("model_response")

    asyncio.run(scenario())


def test_truncation_diagnosis_retains_only_position_and_finish_reason():
    with pytest.raises(StructuredOutputIssue) as caught:
        parse_json_object('{"note":"incomplete', response_finish_reason="length")
    assert caught.value.category == "truncated_output"
    assert caught.value.diagnostics["finish_reason"] == "length"
    assert caught.value.diagnostics["line"] == 1
    assert "incomplete" not in str(caught.value)


def test_corrected_publication_passes_the_real_sdk_message_preparation():
    outcome = play(['{"note":"incomplete', '{"note":"done"}'])
    assert outcome.failure is None
    for messages, parameters in zip(outcome.model.requests, outcome.model.params):
        # ScriptedCodeModel replaces the transport only. Exercise the actual dependency
        # conversion too: it merges the adjacent user context and correction messages.
        prepared = outcome.model._prepare_completion_kwargs(messages, **parameters)
        assert [message["role"] for message in prepared["messages"]] == ["system", "user"]
        assert isinstance(prepared["messages"][1]["content"], list)
        assert all(part["type"] == "text" for message in prepared["messages"] for part in message["content"])
        assert "response_format" not in prepared
        assert "tools" not in prepared
        assert "tool_choice" not in prepared
        assert "stop" not in prepared
        assert prepared["extra_body"]["thinking"] == {"type": "disabled"}
    assert "上一次发布被宿主拒绝" in prepared["messages"][1]["content"][0]["text"]


def test_publication_override_and_telemetry_do_not_mutate_the_frozen_profile():
    async def scenario():
        host = Host()
        gate = Phase(host, output_model=Answer, phase="planner_publish").gate()
        model = ScriptedCodeModel(['{"note":"private-result-body"}'], gate=gate)
        profile = ModelConfig(model="offline-model", base_url="https://example.invalid", api_key="offline-key", thinking="enabled")
        configured_body = profile.extra_body()
        model.extra_body = configured_body
        published = await drive_structured_phase(model, gate, "契约", "只使用已有证据", max_steps=3)
        assert published.note == "private-result-body"
        assert model.params[0]["extra_body"]["thinking"] == {"type": "disabled"}
        assert model.extra_body is configured_body
        assert configured_body == {"thinking": {"type": "enabled"}}
        assert profile.thinking == "enabled"
        response = host.events_of("model_response")[0]
        assert response["response_format"] == "json"
        assert response["request_parameters"] == {
            "max_output_tokens": 1024, "thinking": "disabled", "stop_sequences": [],
        }
        assert response["content_empty"] is False
        assert "private-result-body" not in json.dumps(host.events)
        assert "offline-key" not in json.dumps(host.events)

    asyncio.run(scenario())
