"""Test doubles for the code-action loop.

The loop is driven end to end here rather than mocked: a scripted model stands in for the
provider, a dict-backed dispatcher stands in for ``deps.call``, and everything between
them -- the gate, the interpreter, the tool table, the prompt -- is the real thing.  That
is the point of these doubles: a test can then assert what the *run* does (budgets,
observations, accepted answers) without a provider and without a network.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from pydantic import BaseModel, ConfigDict
from smolagents.models import ChatMessage, TokenUsage

from audit.codemodel import AuditCodeModel, PhaseGate
from audit.config import ModelConfig
from audit.executor import build_agent, drive_phase
from audit.runtime import AgentPolicy, Execution, StopAudit
from audit.toolkit import ToolSpec, build_tools

CONFIG = ModelConfig(model="test-code-model", base_url="https://example.invalid", api_key="test-key")


class Answer(BaseModel):
    """A phase's terminal contract, as a test phase uses one.

    One required field and extra fields forbidden, so a test can drive both halves of the
    gate's validation: a shape the host accepts, and a shape it refuses by name.
    """

    model_config = ConfigDict(extra="forbid")
    note: str


def code(body: str) -> str:
    """One scripted step: what the model writes, in the phase's own format."""
    return f"<code>\n{body.strip()}\n</code>"


def call(name: str, **args) -> str:
    """One scripted step that calls a host tool and shows what came back.

    ``print`` rather than a bare call: an expression statement's value is discarded by the
    interpreter, so the model would see nothing, and a test asserting on the observation
    would be asserting on an empty string.  ``repr`` on the values keeps a string argument
    quoted, so a reply carrying a quote cannot end the call early.
    """
    rendered = ", ".join(f"{key}={value!r}" for key, value in args.items())
    return code(f"print({name}({rendered}))")


class FinalAnswer(str):
    """A semantic answer fixture whose transport follows the requested phase.

    It remains the same Python action string for CodeAgent phases. A structured
    publication phase requests JSON, so the scripted provider renders the original
    payload directly instead of pretending that JSON publication executes Python.
    Raw strings and malformed actions are never adapted by this marker.
    """

    def __new__(cls, payload: Any):
        value = super().__new__(cls, code(f"final_answer({payload!r})"))
        value.payload = payload
        return value


def final_answer(payload: Any) -> FinalAnswer:
    """One scripted step that hands the phase its answer.

    The payload is rendered as a Python literal, so a text phase's ``"done"`` answer
    becomes ``final_answer("done")`` and a dict becomes a dict literal.  A raw string
    used to be interpolated unquoted, which turned every text answer into a NameError
    in the interpreter -- a broken test, not a broken phase.
    """
    return FinalAnswer(payload)


class Always:
    """A script that never runs out: a model that only ever keeps calling tools.

    Indexed modulo its length and long enough that the step counter cannot exhaust it, so
    a test can drive the budget gates rather than the script.  ``len`` stays finite so a
    failure message can still print a length.
    """

    def __init__(self, steps: Iterable[Any]):
        self.steps = list(steps)
        assert self.steps, "Always 至少要一步"

    def __len__(self) -> int:
        return 1_000_000

    def __getitem__(self, index: int) -> Any:
        return self.steps[index % len(self.steps)]


def transcript(messages) -> str:
    """One request's messages as text, so a test can assert what the model was told.

    A chat message's own text is used as it stands rather than dumped: a test asserting
    ``'"overview":true'`` is looking for that substring in a prompt, and a JSON dump would
    hand it back with the quotes escaped.  ``ensure_ascii=False`` for the same reason --
    the tool replies and the refusals are Chinese, and an escaped ``\\u4f60`` is neither
    readable in a failure nor searchable by a test.
    """
    parts = []
    for message in messages:
        content = getattr(message, "content", None)
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            # The loop writes a request's text as a list of typed parts, so a raw
            # substring of a prompt would never be found in it otherwise.
            parts.append("\n".join(
                item["text"] for item in content
                if isinstance(item, dict) and isinstance(item.get("text"), str)
            ))
        elif hasattr(message, "model_dump"):
            parts.append(json.dumps(message.model_dump(), ensure_ascii=False, default=str))
        else:
            parts.append(str(message))
    return "\n".join(parts)


_FALLBACK_LOOP: asyncio.AbstractEventLoop | None = None


def current_loop() -> asyncio.AbstractEventLoop:
    """The loop a gate's callbacks run on.

    A phase that is really played runs inside ``asyncio.run``; a test that only builds
    tools never calls a callback, and gets one shared loop rather than a leak per test.
    """
    global _FALLBACK_LOOP
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        if _FALLBACK_LOOP is None or _FALLBACK_LOOP.is_closed():
            _FALLBACK_LOOP = asyncio.new_event_loop()
        return _FALLBACK_LOOP


class ScriptedCodeModel(AuditCodeModel):
    """An ``AuditCodeModel`` whose provider call is a script.

    Only ``_complete`` is replaced, so a test still exercises the gate (the ceiling and
    the budget check before every request), the request parameters, the usage accounting
    and the failure labelling -- the whole path the run takes against the endpoint.  A
    script entry is the model's output, an exception to raise instead, or a callable
    taking the messages it was sent.

    The script is one phase's steps, or a dict of steps per phase name for a test that
    drives several phases through one model -- which is how the run works, and why the
    step counter is per phase rather than per model.
    """

    # The compressor's own prompt names itself; a scripted model uses that to tell a
    # summary request from a conversation step, because a summary must not consume the
    # phase's script -- it is host bookkeeping, not an ActionStep.
    SUMMARY_MARKER = "上下文压缩器"
    DEFAULT_SUMMARY = "已读取 a.php:1-40，入口参数未过滤，随后 b.php 读取失败；未完成的方向：订单接口。"

    def __init__(self, script: Iterable[Any] | dict[str, Iterable[Any]], *,
                 gate: PhaseGate | None = None, max_tokens: int = 1024,
                 summary: str | None = None):
        super().__init__(CONFIG, gate=gate, max_tokens=max_tokens)
        self.summary = self.DEFAULT_SUMMARY if summary is None else summary
        self.summaries: list[list[Any]] = []
        self.summary_params: list[dict] = []
        # A subscriptable script is kept as it is rather than copied: ``Always`` is one, and
        # materialising it would be a million entries.  Anything else is drained once, so a
        # generator cannot be consumed by the first phase that reads it.
        self.script = dict(script) if isinstance(script, dict) else (
            script if hasattr(script, "__getitem__") else list(script)
        )
        self.requests: list[list[Any]] = []
        self.outputs: list[str] = []
        self.params: list[dict] = []
        self.asked: dict[str, int] = {}
        # The phase of each request, in order: a test asserting "the decision was handed in
        # during exploration" reads this rather than the gate's bookkeeping.
        self.phases: list[str] = []

    def steps_for(self, phase: str):
        if isinstance(self.script, dict):
            return self.script.get(phase, ())
        return self.script

    def create_client(self):
        # Nothing is ever sent, so no HTTP client is created either: a real one would
        # leave a socket pool behind in every test for no gain.
        return None

    def _complete(self, messages, **kwargs) -> ChatMessage:
        if any(self.SUMMARY_MARKER in transcript([message]) for message in messages):
            self.summaries.append(list(messages))
            self.summary_params.append(dict(kwargs))
            if isinstance(self.summary, BaseException):
                raise self.summary
            return ChatMessage(
                role="assistant", content=self.summary,
                token_usage=TokenUsage(input_tokens=90, output_tokens=20),
            )
        phase = self.gate.execution.phase if self.gate is not None else ""
        index = self.asked.get(phase, 0)
        self.asked[phase] = index + 1
        self.requests.append(list(messages))
        self.params.append(dict(kwargs))
        self.phases.append(phase)
        script = self.steps_for(phase)
        if index >= len(script):
            raise AssertionError(
                f"{phase or '本阶段'}只脚本了 {len(script)} 步，循环却要第 {index + 1} 次请求："
                "多出来的请求说明预算闸门没有拦住"
            )
        step = script[index]
        if isinstance(step, BaseException):
            raise step
        text = step(messages) if callable(step) else step
        if isinstance(text, FinalAnswer) and getattr(self.gate, "response_format", None) == "json":
            text = json.dumps(text.payload, ensure_ascii=False)
        self.outputs.append(text)
        return ChatMessage(
            role="assistant", content=text, token_usage=TokenUsage(input_tokens=120, output_tokens=8)
        )


class ModelFactory:
    """Stands in for ``<module>.build_code_model``: the seam a test injects through.

    The driver asks for one client per round, at the first phase that actually runs, and
    re-points that one client at each later phase's gate.  Injecting a factory therefore
    reproduces the real shape -- one model, many phases -- while giving the test the object
    to assert on: the scripts it consumed, the requests it was sent, and ``prompts``, the
    same requests as readable text.

    It is deliberately not the production constructor: nothing is built until the driver
    asks, so a test that asserts a run made no request at all can still see that.
    """

    def __init__(self, script: Iterable[Any] | dict[str, Iterable[Any]], **kwargs):
        self.script = script
        self.kwargs = kwargs
        self.configs: list[ModelConfig] = []
        self.model: ScriptedCodeModel | None = None

    def __call__(self, config: ModelConfig, *, gate: PhaseGate, max_tokens: int) -> ScriptedCodeModel:
        self.configs.append(config)
        if self.model is None:
            self.model = ScriptedCodeModel(
                self.script, gate=gate, max_tokens=max_tokens, **self.kwargs
            )
        else:
            self.model.attach(gate)
        return self.model

    def built(self) -> ScriptedCodeModel:
        assert self.model is not None, "这一轮根本没有请求过模型客户端"
        return self.model

    @property
    def prompts(self) -> list[str]:
        """Every request the run made, as text -- prompt assembly is asserted this way."""
        return [transcript(messages) for messages in self.built().requests]

    @property
    def phases(self) -> list[str]:
        """The phase each request was made in, in order."""
        return self.built().phases


class Host:
    """A fake host: the real ``Execution`` plus a dict-backed dispatcher.

    ``dispatch`` mirrors the two real dispatchers in the order that matters: the tool
    budget is taken first, so a code action cannot spend past it and a call that never got
    the budget is not recorded as a call at all.  An entry of ``responses`` may be the
    answer text, a callable of the arguments, or an exception to raise -- which is how a
    test drives the difference between a tool error the model should see and a host stop
    the model must not be able to recover from.
    """

    def __init__(self, responses: dict | None = None, *, budgets: dict | None = None,
                 policy: AgentPolicy | None = None):
        self.events: list[dict] = []
        self.calls: list[tuple[str, dict]] = []
        self.responses = dict(responses or {})
        self.policy = policy or AgentPolicy(code_output_bytes=2 * 1024, code_seconds=5, code_bytes=512)
        self.execution = Execution(
            dict(budgets or {"responses": 8, "tools": 24, "seconds": 600}),
            self.policy,
            self.events.append,
        )

    async def dispatch(self, name: str, args: dict) -> str:
        self.execution.before_tool()
        call_id = f"test-{self.execution.tools:04d}"
        self.calls.append((name, args))
        self.execution.emit({
            "kind": "tool_call", "tool": name, "args": args, "call_id": call_id,
            "phase": self.execution.phase,
        })
        reply = self.responses.get(name)
        if isinstance(reply, BaseException):
            self.execution.emit({"kind": "tool_result", "tool": name, "status": "error",
                                 "call_id": call_id, "phase": self.execution.phase})
            raise reply
        text = str(reply) if reply is not None else f"{name}: 测试没有登记这个工具的返回内容"
        if callable(reply):
            text = str(reply(args))
        self.execution.emit({
            "kind": "tool_result", "tool": name, "status": "ok", "chars": len(text),
            "call_id": call_id, "phase": self.execution.phase,
            "usage": self.execution.snapshot(),
        })
        return text

    def events_of(self, kind: str) -> list[dict]:
        return [event for event in self.events if event.get("kind") == kind]


@dataclass
class Outcome:
    """What one scripted phase did."""

    model: ScriptedCodeModel
    gate: PhaseGate
    host: Host
    agent: Any = None
    output: Any = None
    failure: BaseException | None = None
    codes: list[dict] = field(default_factory=list)

    def reason(self) -> str | None:
        return getattr(self.failure, "reason", None)

    @property
    def code_blocks(self) -> list[str]:
        return [entry["code"] for entry in self.codes]


class Phase:
    """One phase's plumbing, so a test only has to write the model's script."""

    def __init__(self, host: Host, *, specs: tuple[ToolSpec, ...] = (), output_model=None,
                 validate: Callable[[Any], Any] | None = None, limit: int = 8,
                 phase: str = "planner_explore", instructions: str = "",
                 max_steps: int = 5, name: str = "test"):
        self.host = host
        self.specs = specs
        self.output_model = output_model
        self.validate = validate
        self.limit = limit
        self.phase = phase
        self.instructions = instructions
        self.max_steps = max_steps
        self.name = name

    def gate(self) -> PhaseGate:
        self.host.execution.phase = self.phase
        self.host.execution.phases.setdefault(self.phase, {"model_attempts": 0, "tool_calls": 0})
        return PhaseGate(
            execution=self.host.execution,
            loop=current_loop(),
            dispatch=self.host.dispatch,
            deadline=self.host.execution.deadline + 60,
            limit=self.limit,
            output_model=self.output_model,
            validate=self.validate,
        )

    def play(self, script, *, task: str = "完成本阶段", max_steps: int | None = None) -> Outcome:
        """Run one phase to its end and report what happened."""
        return asyncio.run(self._play(script, task=task, max_steps=max_steps))

    async def _play(self, script, *, task: str, max_steps: int | None) -> Outcome:
        gate = self.gate()
        model = ScriptedCodeModel(script, gate=gate)
        tools = build_tools(self.specs, gate)
        agent = build_agent(
            model=model, gate=gate, tools=tools, instructions=self.instructions,
            max_steps=max_steps or self.max_steps, name=self.name,
        )
        outcome = Outcome(model=model, gate=gate, host=self.host, agent=agent)
        try:
            outcome.output = await drive_phase(agent, gate, task, max_steps=max_steps or self.max_steps)
        except BaseException as exc:  # noqa: BLE001 - the failure is the result a test asserts on
            outcome.failure = exc
        outcome.codes = [
            event for event in self.host.events
            if event.get("kind") == "agent_code" and event.get("phase") == self.phase
        ]
        return outcome


__all__ = [
    "CONFIG", "Always", "Answer", "Host", "ModelFactory", "Outcome", "Phase", "ScriptedCodeModel",
    "StopAudit", "call", "code", "current_loop", "final_answer", "transcript",
]
