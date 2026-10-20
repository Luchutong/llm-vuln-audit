"""Public progress is an explicit action, separate from reasoning and source tools.

Scripted provider replies run through the real gate and interpreter.  These assertions
cover what reaches durable events, what consumes a budget, and the correlation that
allows the UI to keep parallel agents and successive model responses separate.
"""
from __future__ import annotations

import asyncio
import json
import time
from uuid import UUID

import pytest

from audit.codemodel import HostStop
from audit.toolkit import PLANNER_TOOLS
from tests.code_model import Answer, Host, Phase, code, final_answer


@pytest.mark.parametrize("before_source", [True, False])
def test_progress_keeps_its_order_with_source_tools_in_one_response(before_source):
    host = Host({"read_source": "a.php:1 | <?php"})
    progress = "report_progress(message='检查上传入口到文件写入函数的参数流向。')"
    source = "print(read_source(path='a.php', start=1, end=1))"
    actions = [progress, source] if before_source else [source, progress]
    outcome = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play([
        code("\n".join(actions)), final_answer({"note": "done"}),
    ])

    assert outcome.failure is None
    assert outcome.gate.published == Answer(note="done")
    assert host.calls == [("read_source", {"path": "a.php", "start": 1, "end": 1})]
    assert host.execution.tools == 1
    assert len(outcome.model.requests) == 2
    activities = [event["kind"] for event in host.events if event["request_index"] == 1]
    expected = ["audit_progress", "tool_call", "tool_result"] if before_source else [
        "tool_call", "tool_result", "audit_progress",
    ]
    assert activities == ["model_request", "model_response", *expected, "agent_code"]
    progress_event, = host.events_of("audit_progress")
    assert progress_event["message"] == "检查上传入口到文件写入函数的参数流向。"
    assert progress_event["source"] == "agent"
    assert progress_event["phase"] == "planner_explore"


def test_progress_does_not_spend_source_tool_budget_or_request_an_extra_response():
    host = Host(budgets={"responses": 1, "tools": 0, "seconds": 600})
    outcome = Phase(host, output_model=Answer).play([code(
        "report_progress('已检查输入过滤，正在汇总引用。')\n"
        "final_answer({'note': 'done'})"
    )])

    assert outcome.failure is None
    assert outcome.gate.published == Answer(note="done")
    assert len(host.events_of("audit_progress")) == 1
    assert len(outcome.model.requests) == host.execution.attempts == 1
    assert host.execution.snapshot()["tool_calls"] == 0
    assert outcome.gate.tool_calls == 0
    assert host.calls == []


@pytest.mark.parametrize("phase", [
    "explore", "verdict", "poc", "task_execute", "planner_explore",
    "planner_decision", "planner_publish", "recon",
])
def test_progress_is_available_including_phases_without_source_tools(phase):
    host = Host()
    outcome = Phase(host, output_model=Answer, phase=phase).play([code(
        "report_progress('正在整理本阶段已读取的源码证据。')\n"
        "final_answer({'note': 'done'})"
    )])

    assert outcome.failure is None
    event, = host.events_of("audit_progress")
    assert event["phase"] == phase
    assert event["request_index"] == 1
    assert host.calls == []


def test_only_one_nonempty_progress_is_accepted_from_one_model_response():
    host = Host()
    outcome = Phase(host, output_model=Answer).play([code(
        "report_progress(' \\n\\t ')\n"
        "report_progress('正在定位上传后的文件名处理。')\n"
        "report_progress('正在定位上传后的文件名处理。')\n"
        "report_progress('本次响应的第二条不同进展也不应持久化。')\n"
        "final_answer({'note': 'done'})"
    )])

    assert outcome.failure is None
    assert [event["message"] for event in host.events_of("audit_progress")] == [
        "正在定位上传后的文件名处理。",
    ]


def test_a_repeated_message_is_ignored_across_model_responses():
    host = Host()
    outcome = Phase(host, output_model=Answer).play([
        code("report_progress('正在检查入口参数。')"),
        code("report_progress('正在检查入口参数。')"),
        code("report_progress('正在检查文件写入参数。')"),
        final_answer({"note": "done"}),
    ])

    assert outcome.failure is None
    assert [(event["message"], event["request_index"]) for event in host.events_of("audit_progress")] == [
        ("正在检查入口参数。", 1), ("正在检查文件写入参数。", 3),
    ]


@pytest.mark.parametrize("message", ["a" * 1000, "源" * 1000, "🔎" * 1000])
def test_progress_is_clipped_by_both_unicode_characters_and_utf8_bytes(message):
    host = Host()
    outcome = Phase(host, output_model=Answer).play([code(
        f"report_progress({message!r})\nfinal_answer({{'note': 'done'}})"
    )])

    assert outcome.failure is None
    event, = host.events_of("audit_progress")
    rendered = event["message"]
    assert rendered and len(rendered) <= 280
    assert len(rendered.encode("utf-8")) <= 1024
    assert "\ufffd" not in rendered
    assert message.startswith(rendered)


def test_prose_outside_the_code_block_is_never_converted_to_public_progress():
    host = Host()
    private_marker = "PRIVATE_REASONING_SENTINEL_please_do_not_persist"
    outcome = Phase(host, output_model=Answer).play([
        f"Thought: {private_marker}\n" + final_answer({"note": "done"}),
    ])

    assert outcome.failure is None
    assert outcome.gate.published == Answer(note="done")
    assert host.events_of("audit_progress") == []
    assert private_marker not in json.dumps(host.events, ensure_ascii=False)


def test_progress_before_the_first_model_response_is_ignored():
    async def scenario():
        host = Host()
        gate = Phase(host).gate()
        reply = await asyncio.to_thread(gate.report_progress, "还没有任何模型响应。")
        return host, reply

    host, reply = asyncio.run(scenario())
    assert isinstance(reply, str)
    assert host.events_of("audit_progress") == []
    assert host.execution.attempts == host.execution.tools == 0


@pytest.mark.parametrize("stopped_by", ["closed", "phase_deadline", "execution_deadline"])
def test_progress_respects_host_shutdown_and_deadlines(stopped_by):
    async def scenario():
        host = Host()
        gate = Phase(host).gate()
        host.execution.attempts = 1
        if stopped_by == "closed":
            gate.close()
        elif stopped_by == "phase_deadline":
            gate.deadline = time.monotonic() - 1
        else:
            host.execution.started = time.monotonic() - host.execution.budgets["seconds"] - 1
        with pytest.raises(HostStop) as captured:
            await asyncio.to_thread(gate.report_progress, "已结束的阶段不能继续发布进展。")
        return host, captured.value.audit.reason

    host, reason = asyncio.run(scenario())
    assert reason == ("cancelled" if stopped_by == "closed" else "timeout")
    assert host.events_of("audit_progress") == []


def test_invocations_have_unique_stable_ids_and_response_indexes():
    histories = []
    for _ in range(2):
        host = Host()
        host.execution.enter("prepare")
        outcome = Phase(host, output_model=Answer).play([
            code("report_progress('正在定位审计范围。')"),
            final_answer({"note": "done"}),
        ])
        assert outcome.failure is None
        histories.append(host.events)

    ids = []
    for events in histories:
        invocation_ids = {event["agent_invocation_id"] for event in events}
        invocation_id, = invocation_ids
        assert UUID(invocation_id).hex == invocation_id
        ids.append(invocation_id)
        assert events[0]["request_index"] == 0
        assert [event["request_index"] for event in events if event["kind"] == "model_request"] == [1, 2]
        assert [event["request_index"] for event in events if event["kind"] == "agent_code"] == [1, 2]
        assert [event["attempt"] for event in events if event["kind"] == "model_request"] == [1, 2]
    assert len(set(ids)) == 2


def test_a_progress_callback_queued_before_gate_close_cannot_publish_afterward():
    async def scenario():
        host = Host()
        gate = Phase(host).gate()
        host.execution.attempts = 1
        # Scheduling the callback creates its coroutine before the event loop runs it.
        queued = gate._progress("取消前已经排队，取消后不能再发布。")
        gate.close()
        with pytest.raises(HostStop) as captured:
            await queued
        assert captured.value.audit.reason == "cancelled"
        assert host.events_of("audit_progress") == []

    asyncio.run(scenario())
