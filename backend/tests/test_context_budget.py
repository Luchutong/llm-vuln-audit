"""The request-side context compressor, unit by unit.

The compressor exists because the library replays every ActionStep and the host's only
other answer was to stop the phase.  Its own guarantees are what these tests pin down: the
trigger is a share of ``history_bytes``, the protected prefix and the newest steps are
never rewritten, a summary is produced at most once per aged prefix, and every failure
degrades deterministically instead of ending the phase.
"""
import pytest
from smolagents.models import ChatMessage, TokenUsage

from audit.context_budget import (
    SUMMARY_HEADER,
    HistoryCompactor,
    message_bytes,
    messages_bytes,
    trim_message,
)
from audit.runtime import AgentPolicy


def policy(**overrides) -> AgentPolicy:
    values = dict(
        history_bytes=4096,
        history_trigger_ratio=0.85,
        history_target_ratio=0.60,
        history_keep_steps=2,
        history_summary=True,
        history_summary_bytes=1024,
        history_summary_input_bytes=2048,
        history_summary_max_output_tokens=256,
        history_action_bytes=256,
        history_observation_bytes=128,
    )
    values.update(overrides)
    return AgentPolicy(**values)


def user(text: str) -> ChatMessage:
    return ChatMessage(role="user", content=[{"type": "text", "text": text}])


def system(text: str = "system prompt") -> ChatMessage:
    return ChatMessage(role="system", content=text)


def assistant(text: str) -> ChatMessage:
    return ChatMessage(role="assistant", content=text)


def observation(text: str) -> ChatMessage:
    return ChatMessage(role="tool-response", content=[{"type": "text", "text": text}])


def step(index: int, size: int) -> list[ChatMessage]:
    return [
        assistant(f"<code>\nprint(read_source(path='f{index}.php'))\n</code>"),
        observation("x" * size),
    ]


def conversation(groups: list[list[ChatMessage]], prefix: list[ChatMessage] | None = None):
    messages = list(prefix if prefix is not None else [system(), user("审计任务")])
    for group in groups:
        messages.extend(group)
    return messages


class Gate:
    """The two callbacks the compressor uses, plus what it emitted."""

    response_format = "code"

    def __init__(self, *, reply: str | None = "已读取 f1.php:1-20，未发现过滤；待办：订单接口。"):
        self.reply = reply
        self.starts: list[dict] = []
        self.failures: list[dict] = []
        self.events: list[tuple[str, dict]] = []

    def start_summary(self, message_count: int, request_bytes: int) -> float:
        self.starts.append({"messages": message_count, "bytes": request_bytes})
        return 5.0

    def record_summary(self, message, *, prompt_bytes: int):
        if self.reply is None:
            return None, "empty"
        return self.reply, ""

    def summary_failed(self, *, reason: str, before_bytes: int) -> None:
        self.failures.append({"reason": reason, "before_bytes": before_bytes})

    def emit_context(self, kind: str, payload: dict) -> None:
        self.events.append((kind, payload))


class Model:
    def __init__(self, text: str = "已读取 f1.php:1-20，未发现过滤；待办：订单接口。"):
        self.text = text
        self.calls: list[dict] = []

    def summarize(self, messages, *, timeout: float) -> ChatMessage:
        self.calls.append({"messages": list(messages), "timeout": timeout})
        return ChatMessage(role="assistant", content=self.text,
                           token_usage=TokenUsage(input_tokens=10, output_tokens=5))


def test_below_the_trigger_the_request_is_untouched():
    """No summary request is spent on a conversation that still fits."""
    messages = conversation([step(1, 100), step(2, 100)])
    model = Model()
    built, info = HistoryCompactor(policy()).compact(messages, Gate(), model)

    assert built is messages
    assert info == {"cached": False, "groups": 0, "summary_bytes": 0, "dropped_groups": 0}
    assert model.calls == []


def test_the_prefix_and_the_newest_steps_survive_compression():
    messages = conversation([step(index, 700) for index in range(6)])
    gate, model = Gate(), Model()
    compactor = HistoryCompactor(policy())
    built, info = compactor.compact(messages, gate, model)

    assert len(model.calls) == 1
    assert info["summary_bytes"] > 0
    assert messages_bytes(built) < messages_bytes(messages)
    assert messages_bytes(built) <= policy().history_bytes
    # The system and task messages are the request's standing instruction, and the last
    # ``history_keep_steps`` groups are what the next step actually needs verbatim.
    assert built[0] is messages[0] and built[1] is messages[1]
    assert built[-1] is messages[-1] and built[-2] is messages[-2]
    assert any(getattr(item, "content", None) and SUMMARY_HEADER in str(item.content)
               for item in built)


def test_one_summary_serves_every_later_request_with_the_same_prefix():
    """The cache is keyed by the aged prefix, so a repeat step costs nothing."""
    messages = conversation([step(index, 700) for index in range(6)])
    gate, model = Gate(), Model()
    compactor = HistoryCompactor(policy())

    first, first_info = compactor.compact(messages, gate, model)
    second, second_info = compactor.compact(messages, gate, model)

    assert len(model.calls) == 1 and len(gate.starts) == 1
    assert first_info["cached"] is False
    assert second_info["cached"] is True
    assert messages_bytes(first) == messages_bytes(second)


def test_a_newly_aged_step_does_not_re_summarize_the_whole_history():
    """An additional aged group is either kept verbatim or sent once, never re-summarized
    from scratch when the cached summary still covers a prefix."""
    groups = [step(index, 700) for index in range(6)]
    compactor, gate, model = HistoryCompactor(policy()), Gate(), Model()
    compactor.compact(conversation(groups), gate, model)
    assert len(model.calls) == 1

    longer = conversation(groups + [step(6, 60)])
    built, info = compactor.compact(longer, gate, model)

    assert messages_bytes(built) <= policy().history_bytes
    assert info["cached"] is True
    # At most one incremental summary: old summary plus the newly aged step.
    assert len(model.calls) <= 2


def test_a_failed_summary_degrades_deterministically_instead_of_ending_the_phase():
    messages = conversation([step(index, 700) for index in range(6)])
    gate, model = Gate(reply=None), Model()
    built, info = HistoryCompactor(policy()).compact(messages, gate, model)

    assert gate.failures and gate.failures[0]["reason"] == "empty"
    assert info["summary_bytes"] == 0
    assert messages_bytes(built) < messages_bytes(messages)
    # Clipped, not summarized: the aged observations keep only their bounded head.
    assert any("x" * 200 not in str(getattr(item, "content", "")) for item in built)


def test_a_provider_failure_in_the_summary_is_a_failure_event_not_a_raise():
    messages = conversation([step(index, 700) for index in range(6)])

    class Broken(Model):
        def summarize(self, messages, *, timeout):
            raise RuntimeError("provider down")

    gate = Gate()
    built, info = HistoryCompactor(policy()).compact(messages, gate, Broken())

    assert gate.failures[0]["reason"] == "RuntimeError"
    assert messages_bytes(built) <= policy().history_bytes
    assert info["summary_bytes"] == 0


def test_a_summary_request_is_bounded_and_typed():
    """The summary request must itself fit the window and survive role merging."""
    messages = conversation([step(index, 700) for index in range(8)])
    gate, model = Gate(), Model()
    HistoryCompactor(policy()).compact(messages, gate, model)

    request = model.calls[0]["messages"]
    assert len(request) == 1
    assert isinstance(request[0].content, list)
    assert "上下文压缩器" in request[0].content[0]["text"]
    # The history body is bounded by the input budget and the whole request -- measured the
    # way the hard gate measures it, JSON escaping included -- still fits the window, so a
    # summary request can never be the request that trips `context_limit`.
    body = request[0].content[0]["text"].partition("<history>\n")[2].partition("\n</history>")[0]
    assert len(body.encode("utf-8")) <= policy().history_summary_input_bytes
    assert messages_bytes(request) <= policy().history_bytes


def test_trimmming_a_message_keeps_a_valid_typed_content():
    """``get_clean_message_list`` merges same-role messages and asserts list content."""
    trimmed = trim_message(observation("y" * 5000), head=128)

    assert isinstance(trimmed.content, list)
    assert trimmed.content[0]["type"] == "text"
    assert "宿主截断" in trimmed.content[0]["text"]
    assert message_bytes(trimmed) < 500


def test_images_are_named_rather_than_carried():
    message = ChatMessage(role="tool-response", content=[
        {"type": "text", "text": "screenshot"},
        {"type": "image", "image": "data:image/png;base64," + "A" * 4000},
    ])
    trimmed = trim_message(message, head=512)

    assert isinstance(trimmed.content, list)
    assert all(part.get("type") != "image" for part in trimmed.content)
    assert message_bytes(trimmed) < 1024


def test_structured_publication_is_never_summarized():
    messages = conversation([step(index, 700) for index in range(6)])

    class JsonGate(Gate):
        response_format = "json"

    model = Model()
    built, _ = HistoryCompactor(policy()).compact(messages, JsonGate(), model)

    assert built is messages
    assert model.calls == []


@pytest.mark.parametrize("keep", [1, 2, 4])
def test_the_number_of_aged_groups_follows_the_keep_setting(keep: int):
    """Every group before the last ``history_keep_steps`` is aged; the rest stay verbatim."""
    groups = [step(index, 300) for index in range(keep + 3)]
    messages = conversation(groups)
    gate, model = Gate(), Model()
    built, info = HistoryCompactor(policy(history_bytes=2048, history_keep_steps=keep,
                                          history_summary_input_bytes=4096)).compact(messages, gate, model)

    assert info["groups"] == len(groups)
    assert messages_bytes(messages) > 2048 * 0.85
    assert len(model.calls) == 1
    # Every group before the keep window is gone; the kept ones are byte-identical.  The
    # keep window is the one part compression never rewrites, so a request can still be
    # large when those steps are -- that case is the hard gate's, not the compressor's.
    assert messages_bytes(built) < messages_bytes(messages)
    assert [message for group in groups[-keep:] for message in group] == built[-2 * keep:]
    assert built[-1] is messages[-1]
