"""Request-side context control: measure it, summarize it, and degrade before failing.

``smolagents`` replays the whole ``ActionStep`` history on every step, so a phase's
request grows until it crosses ``history_bytes`` and the phase is stopped with
``context_limit``.  The host already bounds what it *projects* between phases (Planner
situation, task results, the source ledger); this module bounds the request a phase is
about to send, without touching the library's memory:

* below the trigger ratio nothing happens and no request is made;
* above it the aged steps are replaced by one host-made summary.  That summary is a real,
  budgeted provider request, cached by the exact prefix it covers, so the next step --
  which only aged one more step -- reuses it instead of summarizing again;
* if the summary cannot be produced (no budget left, provider failure, empty or truncated
  output) the same substitution is made deterministically by clipping the aged steps;
  only a request that still exceeds ``history_bytes`` reaches the hard gate.

The summary is never evidence.  It is injected under a fixed warning header, publishing
still replays the source ledger, and the agent prompts say not to cite it.
"""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from smolagents.models import ChatMessage

SUMMARY_HEADER = (
    "以下是宿主压缩的早期会话摘要（不是源码证据，不可作为 finding 证据引用；"
    "需要时重新读取源码）"
)
SUMMARY_INSTRUCTIONS = (
    "你是同一个白盒审计会话的上下文压缩器。把下面的早期动作历史压缩成一段续接摘要，"
    "供同一个审计 agent 继续工作。\n"
    "必须保留：已读取的文件与行号范围、工具调用的结论、失败原因、已确认的源码事实、未完成的方向。\n"
    "严禁：编造输入中不存在的事实；引用输入中没有出现的源码或行号；输出与审计无关的内容。\n"
    "只输出纯文本摘要，不要代码块，不要 Markdown 标题，总长不超过 {limit} 字节。"
)

# A summary shorter than this is treated as a failure: a two-word reply is not a
# usable hand-off, and silently installing it would lose far more than clipping.
MIN_SUMMARY_CHARS = 24


def _role(message: Any) -> str:
    role = message.get("role") if isinstance(message, dict) else getattr(message, "role", None)
    return str(getattr(role, "value", role) or "").lower()


def _content(message: Any) -> Any:
    return message.get("content") if isinstance(message, dict) else getattr(message, "content", None)


def message_text(message: Any) -> str:
    """The readable text of one message, with images named rather than embedded."""
    content = _content(message)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        pieces: list[str] = []
        for part in content:
            if not isinstance(part, dict):
                pieces.append(str(part))
            elif part.get("type") == "image":
                pieces.append("[截图]")
            else:
                pieces.append(str(part.get("text") or ""))
        return "\n".join(piece for piece in pieces if piece)
    return "" if content is None else str(content)


def message_bytes(message: Any) -> int:
    """Bytes this message contributes, by the same rule the hard gate uses."""
    if isinstance(message, ChatMessage):
        return len(message.model_dump_json().encode("utf-8"))
    if isinstance(message, dict):
        return len(json.dumps(message, ensure_ascii=False, default=str).encode("utf-8"))
    return len(str(message).encode("utf-8"))


def messages_bytes(messages: Any) -> int:
    return sum(message_bytes(message) for message in messages or ())


def _with_content(message: Any, content: Any) -> Any:
    if isinstance(message, ChatMessage):
        return dataclasses.replace(message, content=content)
    return {**message, "content": content}


def clip_text(text: str, head: int, tail: int = 0) -> str:
    """Keep a bounded head (and optional tail) of a UTF-8 string.

    Cuts on byte boundaries and decodes with ``ignore`` so a multi-byte character is
    never split into a lone surrogate.
    """
    raw = text.encode("utf-8")
    if len(raw) <= head + tail:
        return text
    marker = f"\n…[宿主截断，原 {len(raw)} 字节]…\n".encode("utf-8")
    head_part = raw[: max(0, head)].decode("utf-8", "ignore")
    tail_part = raw[len(raw) - tail:].decode("utf-8", "ignore") if tail > 0 else ""
    return head_part + marker.decode("utf-8") + tail_part


def strip_images(message: Any) -> tuple[Any, int]:
    """Replace screenshot parts with a count; images are not carried into summaries."""
    content = _content(message)
    if not isinstance(content, list):
        return message, 0
    images = sum(1 for part in content if isinstance(part, dict) and part.get("type") == "image")
    if not images:
        return message, 0
    parts = [part for part in content if not (isinstance(part, dict) and part.get("type") == "image")]
    parts.insert(0, {"type": "text", "text": f"[已省略 {images} 张截图]"})
    return _with_content(message, parts), images


def trim_message(message: Any, *, head: int, tail: int = 0) -> Any:
    """A copy of one message with its text bounded; the original stays untouched."""
    message, _ = strip_images(message)
    content = _content(message)
    if isinstance(content, str):
        clipped = clip_text(content, head, tail)
        if clipped == content:
            return message
        return _with_content(message, [{"type": "text", "text": clipped}])
    if isinstance(content, list):
        text = message_text(message)
        if len(text.encode("utf-8")) <= head + tail:
            return message
        return _with_content(message, [{"type": "text", "text": clip_text(text, head, tail)}])
    return message


@dataclass
class SplitHistory:
    """A request cut into the parts compression treats differently."""

    prefix: list
    groups: list[list]


def split_history(messages: Any) -> SplitHistory:
    """Split system/task messages from ActionStep groups.

    A group starts at an assistant message and owns everything up to the next one:
    the model's code, the tool call, its observation and the error, if any.
    """
    prefix: list = []
    groups: list[list] = []
    current: list | None = None
    for message in messages or ():
        if _role(message) == "assistant":
            current = [message]
            groups.append(current)
        elif current is None:
            prefix.append(message)
        else:
            current.append(message)
    return SplitHistory(prefix, groups)


def group_digest(group: list) -> str:
    """A stable identity for one ActionStep group, ignoring images and raw payloads."""
    hasher = hashlib.sha256()
    for message in group:
        hasher.update(_role(message).encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(message_text(message).encode("utf-8", "ignore"))
        hasher.update(b"\x00")
    return hasher.hexdigest()[:20]


def _render_group(group: list, *, action_bytes: int, observation_bytes: int) -> str:
    lines = []
    for message in group:
        role = _role(message) or "message"
        head = action_bytes if role in {"assistant", "tool-call"} else observation_bytes
        tail = head // 3 if role not in {"assistant", "tool-call"} else 0
        lines.append(f"[{role}] " + message_text(trim_message(message, head=head, tail=tail)))
    return "\n".join(line for line in lines if line.strip())


def pre_trim_text(groups: list[list], policy: Any) -> str:
    """Deterministically fit the aged steps into the summary request's own budget.

    The summary request must not itself cross the history cap, so the input is clipped
    first.  Newest groups survive; the oldest are dropped and counted.
    """
    rendered = [
        _render_group(group,
                      action_bytes=int(policy.history_action_bytes),
                      observation_bytes=int(policy.history_observation_bytes))
        for group in groups
    ]
    budget = int(policy.history_summary_input_bytes)
    dropped = 0
    while len(rendered) > 1 and sum(len(item.encode("utf-8")) for item in rendered) > budget:
        rendered.pop(0)
        dropped += 1
    text = "\n\n".join(rendered)
    if len(text.encode("utf-8")) > budget:
        text = clip_text(text, budget, budget // 4)
    if dropped:
        text = f"[更早的 {dropped} 个步骤已省略]\n\n" + text
    return text


def summary_messages(text: str, policy: Any) -> list[ChatMessage]:
    prompt = SUMMARY_INSTRUCTIONS.format(limit=int(policy.history_summary_bytes))
    # Typed parts, not a bare string: ``get_clean_message_list`` merges consecutive
    # same-role messages and asserts their content is a list.
    return [ChatMessage(role="user", content=[{
        "type": "text", "text": prompt + "\n\n<history>\n" + text + "\n</history>",
    }])]


def user_message(text: str) -> ChatMessage:
    return ChatMessage(role="user", content=[{"type": "text", "text": text}])


def _omission(count: int, size: int) -> ChatMessage:
    return user_message(f"[已省略历史步骤 {count} 个，共 {size} 字节；需要时重新读取源码]")


@dataclass
class HistoryCompactor:
    """One phase's request compressor, including its summary cache.

    The cache records *which aged-group prefix* the summary covers.  A later request in
    the same phase has the same prefix plus newer groups, so it reuses the summary and
    only has to represent the newly aged steps -- the alternative, re-summarizing on
    every step, would spend the whole response budget on bookkeeping.
    """

    policy: Any
    summary: str = ""
    covered: list[str] = field(default_factory=list)
    failed_for: tuple[str, ...] | None = None
    quota_exhausted: bool = False
    # Set when a new summary request succeeded; the compaction event is emitted once,
    # after the rebuilt request's real size is known.
    _fresh: bool = False

    # --- entry -------------------------------------------------------------------

    def compact(self, messages: Any, gate: Any, model: Any) -> tuple[Any, dict]:
        policy = self.policy
        info = {"cached": False, "groups": 0, "summary_bytes": 0, "dropped_groups": 0}
        total = messages_bytes(messages)
        trigger = int(policy.history_bytes * policy.history_trigger_ratio)
        if total <= trigger:
            return messages, info
        if str(getattr(gate, "response_format", "code")) == "json":
            # A structured publication is exactly two messages.  There is no history to
            # summarize; if it is oversized the hard gate reports it with diagnostics.
            return messages, info
        split = split_history(messages)
        keep = max(1, int(policy.history_keep_steps))
        aged, recent = split.groups[:-keep], split.groups[-keep:]
        info["groups"] = len(split.groups)
        if not aged:
            return messages, info
        digests = [group_digest(group) for group in aged]

        summary = ""
        if policy.history_summary and not self.quota_exhausted:
            if gate.summary_affordable():
                summary = self._ensure_summary(aged, digests, gate, model)
            else:
                # A summary is a full request.  When the phase has only one response left,
                # buying it would leave the compacted request with nothing to be sent
                # with -- observed in a live run, where the summary landed and the phase
                # ended on ``budget`` without ever exercising the compression it paid for.
                # Degrade deterministically instead, and say once why.
                self.quota_exhausted = True
                gate.summary_failed(reason="budget", before_bytes=total)
        covered = self._covered_count(digests)

        built, dropped, cached = self._compose(split.prefix, aged, recent, summary, covered, digests)
        # A summary that covers a prefix but leaves the request above target gets one
        # incremental attempt (old summary + newly aged steps), still within the phase
        # and run allowances.
        target = int(policy.history_bytes * policy.history_target_ratio)
        if (summary and covered < len(aged) and messages_bytes(built) > target
                and policy.history_summary and not self.quota_exhausted
                and gate.summary_affordable()):
            extended = self._request_summary(aged, gate, model, previous=summary)
            if extended:
                self.summary, self.covered = extended, list(digests)
                summary = extended
                covered = len(aged)
                built, dropped, cached = self._compose(split.prefix, aged, recent, summary, covered, digests)
        info["dropped_groups"] = dropped
        info["summary_bytes"] = len(summary.encode("utf-8")) if summary else 0
        # ``cached`` means "a summary already existed and was reused", not "a summary is
        # present": the first compaction in a phase always pays for one.
        info["cached"] = bool(summary) and cached and not self._fresh
        if self._fresh:
            self._fresh = False
            gate.emit_context("context_summarized", {
                "before_bytes": total,
                "after_bytes": messages_bytes(built),
                "summary_bytes": info["summary_bytes"],
                "groups": len(aged),
                "cached": False,
                "dropped_groups": dropped,
            })
        return built, info

    # --- summary ----------------------------------------------------------------

    def _covered_count(self, digests: list[str]) -> int:
        """How many leading aged groups the cached summary already stands for."""
        if not self.summary or not self.covered:
            return 0
        return len(self.covered) if digests[: len(self.covered)] == self.covered else 0

    def _covers(self, digests: list[str]) -> bool:
        return bool(digests) and self._covered_count(digests) == len(digests)

    def _ensure_summary(self, aged: list[list], digests: list[str], gate: Any, model: Any) -> str:
        if self._covers(digests):
            return self.summary
        if self.quota_exhausted or self.failed_for == tuple(digests):
            usable = bool(self.summary) and self.covered and digests[: len(self.covered)] == self.covered
            return self.summary if usable else ""
        # An existing summary covering a strict prefix is still usable: the caller appends
        # the newly aged steps deterministically instead of paying for a re-summary.
        if self.summary and self.covered and digests[: len(self.covered)] == self.covered:
            return self.summary
        text = self._request_summary(aged, gate, model)
        if text:
            self.covered = list(digests)
        return text

    def _request_summary(self, aged: list[list], gate: Any, model: Any, *, previous: str = "") -> str:
        text = pre_trim_text(aged, self.policy)
        if previous:
            text = ("此前摘要：\n" + clip_text(previous, int(self.policy.history_summary_bytes))
                    + "\n\n新滑出的早期步骤：\n" + text)
        messages = summary_messages(text, self.policy)
        prompt_bytes = messages_bytes(messages)
        try:
            ceiling = gate.start_summary(len(messages), prompt_bytes)
            reply = model.summarize(messages, timeout=ceiling)
        except (asyncio.CancelledError, KeyboardInterrupt, SystemExit):
            raise
        except BaseException as exc:  # HostStop, ModelCallFailed, provider errors
            reason = getattr(getattr(exc, "audit", None), "reason", None) or type(exc).__name__
            gate.summary_failed(reason=str(reason)[:80], before_bytes=prompt_bytes)
            if str(reason) in {"budget", "summary_budget"}:
                self.quota_exhausted = True
            return ""
        summary, reason = gate.record_summary(reply, prompt_bytes=prompt_bytes)
        if not summary:
            gate.summary_failed(reason=reason, before_bytes=prompt_bytes)
            if reason in {"budget", "summary_budget"}:
                self.quota_exhausted = True
            return ""
        self.summary = summary
        self._fresh = True
        return summary

    # --- composition ------------------------------------------------------------

    def _compose(self, prefix: list, aged: list[list], recent: list[list], summary: str,
                 covered: int, digests: list[str]) -> tuple[list, int, bool]:
        """Build the compressed request; drop aged detail only while it is still too big."""
        cached = bool(summary) and covered > 0
        target = int(self.policy.history_bytes * self.policy.history_target_ratio)
        limit = int(self.policy.history_bytes)

        def build(cut: int) -> list:
            parts = list(prefix)
            if summary:
                parts.append(user_message(SUMMARY_HEADER + "\n" + summary))
            if cut > covered:
                parts.append(_omission(cut - covered, messages_bytes(
                    [message for group in aged[covered:cut] for message in group])))
            for group in aged[cut:]:
                for message in group:
                    role = _role(message)
                    head = (int(self.policy.history_action_bytes) if role in {"assistant", "tool-call"}
                            else int(self.policy.history_observation_bytes))
                    tail = head // 3 if role not in {"assistant", "tool-call"} else 0
                    parts.append(trim_message(message, head=head, tail=tail))
            for group in recent:
                parts.extend(group)
            return parts

        cut = covered
        parts = build(cut)
        size = messages_bytes(parts)
        while cut < len(aged) and size > target:
            cut += 1
            parts = build(cut)
            size = messages_bytes(parts)
        # Dropping below the covered prefix would discard facts only the summary holds;
        # that is still preferable to a request the provider cannot accept.
        while size > limit and cut < len(aged):
            cut += 1
            parts = build(cut)
            size = messages_bytes(parts)
        return parts, cut - covered, cached
