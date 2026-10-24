"""The gate every phase's model request passes through.

A phase's loop belongs to the library now, so the host's guarantees have to be attached to
the one place a request starts.  These tests drive the real gate, the real interpreter and
the real tool table with a scripted model: what they assert is that a budget, a deadline, a
context cap or a host stop still ends the phase before another request is made, and that a
failure the model *should* see comes back as an observation instead of ending it.
"""
import asyncio
import json

import httpx
import openai
import pytest

from audit.codemodel import FINAL_ANSWER_ACCEPTED, HostStop, ModelCallFailed, request_bytes
from audit.runtime import AgentPolicy, StopAudit
from audit.toolkit import PLANNER_TOOLS
from tests.code_model import CONFIG, Answer, Host, Phase, code, transcript


def status_error(status: int, message: str) -> openai.APIStatusError:
    """The provider refusing a request, the way the client sees it."""
    request = httpx.Request("POST", "https://example.invalid/v1/chat/completions")
    response = httpx.Response(status, request=request, json={"error": {"message": message}})
    return openai.BadRequestError(message, response=response, body=None)


def test_one_request_can_carry_a_whole_reading_loop():
    """The point of the migration: several tool calls, one model request."""
    host = Host({"read_source": lambda args: f"{args['path']}:1 | {args['path']}"})
    outcome = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play([
        code('for path in ["a.php", "b.php"]:\n    print(read_source(path=path, start=1, end=2))'),
        code('final_answer({"note": "done"})'),
    ])

    assert outcome.failure is None
    assert [name for name, _ in host.calls] == ["read_source", "read_source"]
    assert host.calls[0][1] == {"path": "a.php", "start": 1, "end": 2}
    assert len(outcome.model.requests) == 2
    # What the code printed is what the model read next, and both reads were charged.
    assert "a.php:1 | a.php" in transcript(outcome.model.requests[1])
    assert host.execution.phases["planner_explore"] == {"model_attempts": 2, "tool_calls": 2}
    assert outcome.output == FINAL_ANSWER_ACCEPTED
    assert outcome.gate.published == Answer(note="done")


def test_the_response_budget_ends_the_phase_before_the_request():
    host = Host({}, budgets={"responses": 2, "tools": 8, "seconds": 600})
    outcome = Phase(host, output_model=Answer, limit=8).play([
        code("print('one')"), code("print('two')"), code("print('three')"),
    ])

    assert outcome.reason() == "budget"
    assert len(outcome.model.requests) == 2
    assert outcome.gate.published is None


def test_the_phase_limit_ends_the_phase_before_the_request():
    """``max_steps`` is the phase's own allowance, below the run's."""
    host = Host({}, budgets={"responses": 8, "tools": 8, "seconds": 600})
    outcome = Phase(host, output_model=Answer, limit=1).play([
        code("print('one')"), code("print('two')"),
    ])

    assert outcome.reason() == "budget"
    assert len(outcome.model.requests) == 1


def test_a_spent_wall_clock_ends_the_phase():
    host = Host({}, budgets={"responses": 8, "tools": 8, "seconds": 0})
    outcome = Phase(host, output_model=Answer).play([code("print('one')")])

    assert outcome.reason() == "timeout"
    assert outcome.model.requests == []


def test_the_history_cap_counts_the_request_being_made():
    """Measured on the request about to go out, not on the history behind it."""
    probe = Phase(Host({"read_source": "x"}), phase="probe").play([
        code("print(read_source(path='a.php', start=1, end=1))"),
    ])
    size = request_bytes(probe.model.requests[0])
    assert size > 0

    host = Host({"read_source": "x"}, policy=AgentPolicy(history_bytes=size + 1))
    outcome = Phase(host, phase="probe", output_model=Answer).play([
        code("print('one')"), code("print('two')"),
    ])

    assert outcome.reason() == "context_limit"
    assert len(outcome.model.requests) == 1


def test_the_request_carries_the_ceiling_and_the_thinking_switch():
    host = Host()
    outcome = Phase(host, output_model=Answer).play([code('final_answer({"note": "n"})')])
    params = outcome.model.params[0]

    assert params["timeout"] == pytest.approx(AgentPolicy().request_seconds)
    assert params["max_tokens"] == 1024
    assert params["extra_body"] == CONFIG.extra_body()


def test_a_provider_error_keeps_its_label():
    """A provider 400 is the provider answering, not this repository failing."""
    host = Host()
    outcome = Phase(host, output_model=Answer).play([status_error(400, "InvalidParameter")])

    assert isinstance(outcome.failure, ModelCallFailed)
    assert outcome.failure.reason == "model_error"
    assert outcome.failure.status_code == 400
    assert outcome.gate.published is None


def test_a_stalled_request_is_a_timeout_not_a_provider_error():
    host = Host()
    stall = openai.APITimeoutError(request=httpx.Request("POST", "https://example.invalid"))
    outcome = Phase(host, output_model=Answer).play([stall])

    assert outcome.reason() == "request_timeout"
    # A request that never completed is still a spent attempt, and the host counted it.
    assert host.execution.attempts == 1


def test_an_unexpected_failure_keeps_its_class_name():
    host = Host()
    outcome = Phase(host, output_model=Answer).play([RuntimeError("boom")])

    assert type(outcome.failure) is RuntimeError
    assert outcome.reason() is None


def test_a_host_stop_is_not_the_models_business():
    """A spent tool budget ends the phase; it is not an observation to recover from."""
    host = Host({"read_source": StopAudit("no_progress", "重复读取或连续工具调用未增加代码证据")})
    outcome = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play([
        code("print(read_source(path='a.php', start=1, end=1))"),
        code("print('this step must never run')"),
    ])

    assert outcome.reason() == "no_progress"
    assert len(outcome.model.outputs) == 1
    assert "this step" not in outcome.model.outputs[0]
    assert outcome.gate.published is None


def test_a_tool_error_is_the_models_business():
    """A tool that refuses comes back as an observation, and the phase goes on."""
    host = Host({"read_source": ValueError("这个窗口超出允许范围")})
    outcome = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play([
        code("print(read_source(path='a.php', start=1, end=1))"),
        code('final_answer({"note": "recovered"})'),
    ])

    assert outcome.failure is None
    assert outcome.gate.published.note == "recovered"
    assert "这个窗口超出允许范围" in transcript(outcome.model.requests[1])
    assert outcome.codes[0]["error"] is not None


def test_a_rejected_answer_returns_as_the_next_steps_observation():
    """The refusal is not a dead end: the model reads why and hands in a better one."""
    host = Host()
    outcome = Phase(host, output_model=Answer).play([
        code('final_answer({"note": "x", "extra": 1})'),
        code('final_answer({"note": "ok"})'),
    ])

    assert outcome.failure is None
    assert outcome.gate.published == Answer(note="ok")
    assert host.execution.corrections == 1
    rejected = outcome.codes[0]
    assert rejected["is_final"] is False
    assert "extra: Extra inputs are not permitted" in rejected["error"]
    # The same words are on the durable retry event and in the next request.
    assert host.events_of("model_retry")[0]["reason"] == "extra: Extra inputs are not permitted"
    assert "Extra inputs are not permitted" in transcript(outcome.model.requests[1])


def test_the_hosts_own_rules_run_after_the_shape_check():
    """``_validate_planner_decision`` reaches the loop through the gate's ``validate``."""
    def validate(value: Answer) -> Answer:
        if value.note != "ok":
            raise ValueError("note 必须是 ok")
        return value

    host = Host()
    outcome = Phase(host, output_model=Answer, validate=validate).play([
        code('final_answer({"note": "no"})'),
        code('final_answer({"note": "ok"})'),
    ])

    assert outcome.gate.published == Answer(note="ok")
    assert host.execution.corrections == 1
    assert "note 必须是 ok" in transcript(outcome.model.requests[1])
    assert "note 必须是 ok" in json.dumps(host.events_of("model_retry"), ensure_ascii=False)


def test_repeated_rejections_end_the_phase_as_invalid_output():
    host = Host(policy=AgentPolicy(output_corrections=1))
    outcome = Phase(host, output_model=Answer).play([
        code('final_answer({"bad": 1})'), code('final_answer({"worse": 2})'),
    ])

    assert outcome.reason() == "invalid_output"
    assert outcome.gate.published is None
    assert len(outcome.model.requests) == 2
    assert host.execution.corrections == 1
    assert "Extra inputs" in str(outcome.failure)


def test_each_answered_request_is_counted_once():
    host = Host()
    outcome = Phase(host, output_model=Answer).play([
        code("print('one')"), code('final_answer({"note": "n"})'),
    ])

    usage = host.execution.snapshot()
    assert usage["requests"] == 2
    assert usage["input_tokens"] == 240
    assert usage["output_tokens"] == 16
    assert [event["attempt"] for event in host.events_of("model_request")] == [1, 2]
    assert len(host.events_of("model_response")) == 2
    assert outcome.gate.published == Answer(note="n")


def test_a_text_phase_takes_the_prose_as_the_answer():
    host = Host()
    outcome = Phase(host, output_model=None).play([code('final_answer("这是一份 POC 记录。")')])

    assert outcome.gate.published == "这是一份 POC 记录。"
    assert outcome.failure is None


def test_the_code_action_is_recorded_with_its_observation():
    host = Host({"read_source": "a.php:1 | <?php"})
    outcome = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play([
        code("print(read_source(path='a.php', start=1, end=1))"),
        code('final_answer({"note": "n"})'),
    ])

    first, second = outcome.codes
    assert first["code"] == "print(read_source(path='a.php', start=1, end=1))"
    assert first["is_final"] is False and first["truncated"] is False
    assert first["code_bytes"] == len(first["code"])
    assert "a.php:1 | <?php" in first["logs"]
    assert second["code"] == 'final_answer({"note": "n"})'
    assert second["is_final"] is True
    # A code action is recorded when its step ends, which is why the calls it made come
    # first: the library reports the step after running it, and that is also the first
    # moment the code, what it printed and how it ended are all known at once.
    assert [event["kind"] for event in host.events] == [
        "model_request", "model_response", "tool_call", "tool_result", "agent_code",
        "model_request", "model_response", "agent_code",
    ]


def test_code_longer_than_the_policy_is_recorded_truncated():
    host = Host(policy=AgentPolicy(code_bytes=64))
    literal = "x" * 200
    outcome = Phase(host, output_model=Answer).play([
        code(f"print({literal!r})"), code('final_answer({"note": "n"})'),
    ])

    first = outcome.codes[0]
    assert len(first["code"]) == 64
    assert first["truncated"] is True
    assert first["code_bytes"] > 64


def test_a_phase_publishes_once():
    """A phase that already handed in its result refuses a second one."""
    async def scenario() -> tuple[str, str]:
        host = Host()
        gate = Phase(host, output_model=Answer).gate()
        accepted = await gate._accept({"note": "first"})
        try:
            await gate._accept({"note": "second"})
        except HostStop as stop:
            return accepted, stop.audit.reason
        raise AssertionError("第二次终局没有被拒绝")

    accepted, reason = asyncio.run(scenario())
    assert accepted == FINAL_ANSWER_ACCEPTED
    assert reason == "invalid_output"


def test_a_closed_phase_refuses_further_callbacks():
    async def scenario() -> str:
        host = Host()
        gate = Phase(host, output_model=Answer).gate()
        gate.close()
        try:
            await asyncio.to_thread(gate.call_tool, "read_source", {})
        except HostStop as stop:
            return stop.audit.reason
        raise AssertionError("已关闭的阶段仍然受理了工具调用")

    assert asyncio.run(scenario()) == "cancelled"


# --- replies the loop could not parse -----------------------------------------------


def test_a_reply_without_a_code_block_is_recorded_and_corrected():
    """The library's parse failure used to leave no trace at all.

    A step with no ``code_action`` was skipped by the recorder, so a conclusion phase that
    answered in prose three times ended as ``budget`` with nothing saying why.  The step is
    now a durable ``agent_parse_error``, and the next request is a bounded correction.
    """
    host = Host()
    outcome = Phase(host, output_model=Answer).play([
        "这里先说明结论：该漏洞成立。",
        code('final_answer({"note": "done"})'),
    ])

    assert outcome.failure is None
    assert outcome.gate.published == Answer(note="done")
    parse_errors = host.events_of("agent_parse_error")
    assert len(parse_errors) == 1
    event = parse_errors[0]
    assert event["phase"] == "planner_explore"
    assert event["step"] == 1
    # The request that produced the unparsable reply, not the correction that follows it.
    assert event["request_index"] == 1
    assert event["category"] == "no_code_block"
    assert "代码块" in event["hint"]
    assert host.execution.corrections == 1
    retries = host.events_of("model_retry")
    assert len(retries) == 1 and retries[0]["reason"] == event["hint"]
    # A reply with no code is not a code action: nothing was executed, so no action is
    # recorded for that step (only the corrected submission that follows is).
    assert all(entry.get("step") != 1 for entry in host.events_of("agent_code"))
    # The fixed hint is the retry's reason, which is what the durable event carries; the
    # framework's own parse message still reaches the model as the step's error.
    assert len(outcome.model.requests) == 2


def test_a_spent_correction_allowance_is_invalid_output_and_sends_no_request():
    host = Host(policy=AgentPolicy(output_corrections=1))
    outcome = Phase(host, output_model=Answer, limit=6).play([
        "散文一。", "散文二。", "散文三。",
    ])

    assert outcome.reason() == "invalid_output"
    assert outcome.gate.published is None
    # Two replies were sent, then the second correction was refused before a third request.
    assert len(outcome.model.requests) == 2
    assert host.execution.corrections == 1
    assert len(host.events_of("agent_parse_error")) == 2


def test_an_ordinary_spent_allowance_is_still_budget():
    """Only an exhausted *correction* allowance is a format failure."""
    host = Host()
    outcome = Phase(host, output_model=Answer, limit=2).play([
        code("print('one')"), code("print('two')"), code('final_answer({"note": "n"})'),
    ])

    assert outcome.reason() == "budget"
    assert host.execution.corrections == 0
    assert host.events_of("agent_parse_error") == []


def test_a_stop_token_may_omit_the_fence_around_a_complete_python_action():
    host = Host()
    outcome = Phase(host, output_model=Answer).play([
        '<code>\nfinal_answer({"note": "n"})',
    ])

    assert outcome.failure is None
    assert outcome.gate.published == Answer(note="n")
    assert host.events_of("agent_parse_error") == []


def test_a_parse_failure_never_persists_the_reply_that_caused_it():
    """The framework's exception quotes the whole reply; the event carries fixed text only."""
    marker = "PRIVATE_MODEL_REPLY_MARKER"
    host = Host()
    Phase(host, output_model=Answer).play([
        f"报告如下：{marker}", code('final_answer({"note": "n"})'),
    ])

    persisted = json.dumps(host.events, ensure_ascii=False)
    assert marker not in persisted
    assert all(marker not in str(event.get("hint") or "") for event in host.events_of("agent_parse_error"))


def test_a_response_event_records_the_reply_size_against_its_cap():
    host = Host()
    outcome = Phase(host, output_model=Answer).play([code('final_answer({"note": "n"})')])

    event = host.events_of("model_response")[0]
    assert event["output_chars"] == len(outcome.model.outputs[0])
    assert event["output_bytes"] >= event["output_chars"]
    assert event["output_tokens"] == 8
    assert event["max_output_tokens"] == 1024
