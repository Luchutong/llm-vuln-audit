"""The model client, and the one gate every model request of a phase passes through.

The loop inside a phase belongs to ``smolagents`` now: the model writes a code block, the
block calls this run's own read-only tools, and the loop repeats until a final answer is
accepted.  The host still owns everything around that loop -- budgets, phase boundaries,
the event log, the read ledger, decision validation -- and none of it may be stepped
around, so every host call the loop makes goes through :class:`PhaseGate`.

The loop runs in a worker thread: ``smolagents``' client is synchronous, while
``Execution``, the event bus and the sqlite connection all belong to the event loop
thread.  ``PhaseGate`` is therefore written in halves -- a public method the agent thread
calls, which blocks on the loop for its answer, and the coroutine that runs on the loop
thread and is the only half allowed to touch ``Execution``, the dispatcher or ``emit``.

``AuditCodeModel.generate`` is the one place a model request starts, which makes it the
one place ``Execution.before_model`` has to be enforced.  That is the guarantee the
hand-written ``agent.iter`` loop used to give by checking before every step.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from pydantic import BaseModel, ValidationError
from smolagents.models import ChatMessage, OpenAIModel

from .config import ModelConfig
from .runtime import Execution, StopAudit

# How long a single phase waits for the loop to answer a host callback.  The loop only
# ever does local work here (ledger bookkeeping, one sqlite write, one emit), so this is
# a deadlock detector rather than a budget: if it fires, the driver is wedged and the
# phase has to end rather than block its thread forever.
CALLBACK_SECONDS = 30.0

# The agent loop's own wrappers.  A failure the host raised travels out through them, so
# recovering the host's label means unwrapping exactly these and stopping at the first
# thing that is not one of them.
_FRAMEWORK_ERRORS = frozenset({
    "AgentError", "AgentGenerationError", "AgentExecutionError", "AgentParsingError",
    "AgentMaxStepsError", "AgentToolCallError", "AgentToolExecutionError",
})

# Failures that mean the request itself never completed, as opposed to the provider
# answering with an error.  Both are in ``worker.MODEL_FAILURE_REASONS``: a request that
# ran past the ceiling is the host's own limit firing, so it must not be counted as the
# provider answering badly.
_TIMEOUT_ERRORS = frozenset({
    "APITimeoutError", "TimeoutException", "ReadTimeout", "ConnectTimeout", "WriteTimeout",
    "PoolTimeout", "Timeout",
})

_PROVIDER_ERRORS = frozenset({
    "APIError", "APIStatusError", "APIConnectionError", "AuthenticationError",
    "PermissionDeniedError", "RateLimitError", "BadRequestError", "NotFoundError",
    "ConflictError", "UnprocessableEntityError", "InternalServerError",
})

FINAL_ANSWER_ACCEPTED = "最终答案已通过宿主校验。"


class HostStop(BaseException):
    """A host decision to end this phase, carried across the agent loop untouched.

    The agent loop treats ``Exception`` as the model's business: a rejected tool
    argument, a failed parse and a refused final answer become an observation, and the
    model gets another step to correct itself.  A spent budget, an expired deadline or a
    closed phase are not the model's business -- the host already decided -- and asking
    the model again would spend the very allowance the decision was about.  Deriving from
    ``BaseException`` is the only way to cross the loop's ``except Exception`` handlers,
    which is the same device ``smolagents`` uses for its own ``FinalAnswerException``.
    """

    def __init__(self, audit: StopAudit):
        super().__init__(audit.reason, str(audit))
        self.audit = audit


class ModelCallFailed(Exception):
    """A model request that failed, labelled the way this run's accounting expects.

    ``reason`` is ``model_error`` or ``request_timeout``, and the provider's own exception
    is kept as ``cause`` so the driver can still read a status code off it.  The label has
    to be recovered by the driver through :func:`unwrap_failure`: the loop wraps whatever
    the client raised into its own ``AgentGenerationError``, and a provider 400 that
    arrives as an ``AgentGenerationError`` would otherwise be recorded as our bug.
    """

    def __init__(self, reason: str, cause: BaseException):
        super().__init__(f"{type(cause).__name__}: {cause}")
        self.reason = reason
        self.cause = cause
        self.status_code = getattr(cause, "status_code", None)


class OutputRejected(ValueError):
    """The host refused a final answer; the message is what the model reads next.

    Raised from inside the ``final_answer`` tool call, so the interpreter turns it into
    the observation of the current step and the model corrects it in the same loop.  The
    same text is handed to ``before_model`` as the correction reason, which is where the
    durable ``model_retry`` event gets it from.
    """


def unwrap_failure(exc: BaseException) -> BaseException:
    """Recover the failure the host raised from under the loop's wrappers.

    Returns the ``StopAudit`` behind a :class:`HostStop`, the :class:`ModelCallFailed`
    itself, or the first cause that is not one of the loop's own error types -- so a
    provider error keeps its label and an unexpected bug keeps its real class name.
    """
    current: BaseException = exc
    while type(current).__name__ in _FRAMEWORK_ERRORS:
        cause = current.__cause__ or current.__context__
        if cause is None:
            return current
        current = cause
    if isinstance(current, HostStop):
        return current.audit
    return current


def request_bytes(messages: Any) -> int:
    """Bytes of the request about to be sent, counted the way the cap means it.

    ``history_size`` used to do this over pydantic-ai's message classes; the cap is the
    same one, and so is the rule that the request being made right now is part of it.
    ``ChatMessage.model_dump_json`` drops ``raw``, so this measures what is sent rather
    than the provider's own response object.
    """
    total = 0
    for message in messages or ():
        if isinstance(message, ChatMessage):
            total += len(message.model_dump_json().encode("utf-8"))
        elif isinstance(message, dict):
            total += len(json.dumps(message, ensure_ascii=False, default=str).encode("utf-8"))
        else:
            total += len(str(message).encode("utf-8"))
    return total


def rejection_reason(exc: BaseException) -> str:
    """One line per rejected field, in the words the model has to act on."""
    if isinstance(exc, ValidationError):
        parts = [
            "{}: {}".format(".".join(str(item) for item in error["loc"]) or "(根)", error["msg"])
            for error in exc.errors()[:6]
        ]
        return ("；".join(parts) or "输出不符合本阶段的契约")[:800]
    return str(exc)[:800]


@dataclass
class PhaseGate:
    """The host side of one phase: budgets, events, tools and the final answer.

    One gate per ``CodeAgent.run``.  ``dispatch`` is the existing ``deps.call`` of the
    phase, so a code action reaches the run's tools by exactly the route a tool call did;
    ``output_model``/``validate`` are the phase's terminal contract, applied to whatever
    the model hands to ``final_answer``.
    """

    execution: Execution
    loop: asyncio.AbstractEventLoop
    dispatch: Callable[[str, dict], Awaitable[str]]
    deadline: float
    limit: int
    output_model: type[BaseModel] | None = None
    validate: Callable[[Any], Any] | None = None
    published: Any = None
    pending_correction: str | None = None
    closed: bool = False
    tool_calls: int = 0

    def _on_loop(self, callback: Callable[[], Awaitable]) -> Any:
        """Run one host callback on the event loop and wait for its answer.

        Called from the agent thread only, and blocking there is the point: the loop's
        view of the phase has to be settled before the agent acts on the answer.

        The callback is a factory rather than a coroutine for two reasons: a phase which is
        already over creates nothing to await (building the coroutine first and then
        raising would leave an un-awaited coroutine behind on every late callback), and
        the payload it builds -- an event dict, a snapshot -- is then built on the loop
        thread, which is the only thread allowed to read ``Execution``.
        """
        if self.closed:
            raise HostStop(StopAudit("cancelled", "本阶段已经结束，宿主不再受理模型侧的动作"))
        future = asyncio.run_coroutine_threadsafe(callback(), self.loop)
        return future.result(timeout=CALLBACK_SECONDS)

    def request_ceiling(self, messages: Any) -> float:
        """Open one model request and return how long it may take."""
        return self._on_loop(lambda: self._open_request(messages))

    def call_tool(self, name: str, args: dict) -> str:
        """Run one host tool and return the text the model reads as its observation."""
        return self._on_loop(lambda: self._call_tool(name, args))

    def accept(self, payload: Any) -> str:
        """Publish the phase's terminal answer, or refuse it with a reason.

        Refusing raises :class:`OutputRejected`, which the interpreter turns into the
        step's observation; accepting records the sanitized value on the gate, which is
        what the driver reads -- never the value the model wrote.
        """
        return self._on_loop(lambda: self._accept(payload))

    def record_response(self, message: ChatMessage) -> None:
        """Count one answered request.  Failures are counted by ``before_model``."""
        self._on_loop(lambda: self._record(message))

    def report_progress(self, message: str) -> str:
        """Accept an explicit public update, never model response prose or reasoning."""
        return self._on_loop(lambda: self._progress(message))

    def record_code(self, *, step: int, code: str, logs: str | None,
                    is_final: bool, error: str | None = None) -> None:
        """Record one code action durably.

        The code is an *action*, so it is persisted and shown the way ``tool_call`` is;
        what the model wrote outside the code fences is its own reasoning and stays in
        memory only, which is where the run's "no hidden reasoning is stored" rule draws
        the line.
        """
        limit = self.execution.policy.code_bytes
        clipped = code[:limit]
        self._on_loop(lambda: self._emit_code({
            "kind": "agent_code",
            "phase": self.execution.phase,
            "step": step,
            "code": clipped,
            "code_bytes": len(code.encode("utf-8")),
            "truncated": len(clipped) < len(code),
            # Not capped again here: the interpreter has already cut the printed output to
            # the policy's limit and marked the cut, and the event should carry the
            # observation the model actually read rather than a second-hand version of it.
            "logs": logs or None,
            "is_final": bool(is_final),
            "error": (error or "")[:400] or None,
            "usage": self.execution.snapshot(),
        }))

    def close(self) -> None:
        """End the phase: from here on the loop gets host stops instead of callbacks."""
        self.closed = True

    def failure(self, exc: BaseException) -> BaseException:
        """Label a failed request without touching anything shared.

        Runs on the agent thread, on the way out of ``generate``.  A failure the host
        raised is passed through so it is not relabelled as the provider's.
        """
        if isinstance(exc, (HostStop, ModelCallFailed)):
            return exc
        name = type(exc).__name__
        if name in _TIMEOUT_ERRORS or isinstance(exc, TimeoutError):
            return ModelCallFailed("request_timeout", exc)
        if name in _PROVIDER_ERRORS or getattr(exc, "status_code", None) is not None:
            return ModelCallFailed("model_error", exc)
        return exc

    # --- event loop thread ---------------------------------------------------------

    async def _open_request(self, messages: Any) -> float:
        if self.published is not None:
            raise HostStop(StopAudit("invalid_output", "本阶段已经交回终局，不再发起模型请求"))
        if request_bytes(messages) > self.execution.policy.history_bytes:
            # Measured on the request being made, not on the history behind it: an
            # oversized first request has to be caught like any other.
            raise HostStop(StopAudit("context_limit", "模型历史已达到上下文上限"))
        correction, reason = self.pending_correction is not None, self.pending_correction
        self.pending_correction = None
        try:
            return self.execution.before_model(
                deadline=self.deadline, limit=self.limit, correction=correction, reason=reason
            )
        except StopAudit as stop:
            raise HostStop(stop) from None

    async def _call_tool(self, name: str, args: dict) -> str:
        self.tool_calls += 1
        try:
            return await self.dispatch(name, args)
        except StopAudit as stop:
            raise HostStop(stop) from None

    async def _progress(self, message: str) -> str:
        # A callback can already be queued when drive_phase closes the gate.
        # Recheck on its owning loop so a late interpreter cannot publish afterward.
        if self.closed:
            raise HostStop(StopAudit("cancelled", "本阶段已经结束，宿主不再受理模型侧的动作"))
        if self.published is not None:
            return "本阶段已结束，未新增进展。"
        try:
            accepted = self.execution.report_progress(message, deadline=self.deadline)
        except StopAudit as stop:
            raise HostStop(stop) from None
        return "公开进展已保存。" if accepted else "未新增进展，请继续当前审计动作。"

    async def _accept(self, payload: Any) -> str:
        if self.published is not None:
            raise HostStop(StopAudit("invalid_output", "本阶段已经交回终局，不接受第二次终局"))
        try:
            value = self._typed(payload)
        except (ValidationError, ValueError) as exc:
            reason = rejection_reason(exc)
            self.pending_correction = reason
            raise OutputRejected(reason) from None
        self.published = value
        return FINAL_ANSWER_ACCEPTED

    def _typed(self, payload: Any) -> Any:
        model = self.output_model
        if model is None:
            # A text phase (a POC write-up): the answer is the prose itself.
            return payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, default=str)
        if isinstance(payload, model):
            value = payload
        elif isinstance(payload, str):
            value = model.model_validate_json(payload)
        elif isinstance(payload, dict):
            value = model.model_validate(payload)
        else:
            value = model.model_validate(payload)
        # The host's own rules run after the shape check, on a typed object, exactly as
        # they ran inside the framework's output validator.
        return self.validate(value) if self.validate is not None else value

    async def _record(self, message: ChatMessage) -> None:
        usage = getattr(message, "token_usage", None)
        self.execution.usage.add(
            requests=1,
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
        )
        self.execution.emit({
            "kind": "model_response",
            "phase": self.execution.phase,
            "usage": self.execution.snapshot(),
        })

    async def _emit_code(self, event: dict) -> None:
        self.execution.emit(event)


class AuditCodeModel(OpenAIModel):
    """The run's only model client.

    One client per driver, with the gate swapped at each phase boundary, so a run makes
    one HTTP client rather than one per phase.  Two deliberate choices keep this inside
    the repository's rules:

    * no invisible retries -- ``retry=False`` disables the library's own rate-limit
      retries and ``client_kwargs={"max_retries": 0}`` disables the OpenAI SDK's, because
      the host budgets every attempt and a hidden retry would multiply that budget;
    * the request carries the phase's ceiling and ``extra_body`` (which is where the
      ``LLM_THINKING`` switch lives), both applied at call time so one client can serve
      phases with different limits.
    """

    def __init__(self, config: ModelConfig, *, gate: PhaseGate, max_tokens: int):
        super().__init__(
            model_id=config.model,
            api_base=config.base_url or None,
            api_key=config.api_key or None,
            client_kwargs={"max_retries": 0},
            retry=False,
        )
        self.gate = gate
        self.max_tokens = max_tokens
        self.extra_body = config.extra_body()

    def attach(self, gate: PhaseGate) -> None:
        """Point the client at the next phase's gate."""
        self.gate = gate

    def generate(self, messages, stop_sequences=None, response_format=None,
                 tools_to_call_from=None, **kwargs) -> ChatMessage:
        # The gate comes first: a phase that cannot afford another request must not open
        # one, and the ceiling it returns is what the HTTP client is given as its timeout.
        ceiling = self.gate.request_ceiling(messages)
        kwargs.setdefault("timeout", ceiling)
        kwargs.setdefault("max_tokens", self.max_tokens)
        kwargs.setdefault("extra_body", self.extra_body)
        try:
            message = self._complete(
                messages,
                stop_sequences=stop_sequences,
                response_format=response_format,
                tools_to_call_from=tools_to_call_from,
                **kwargs,
            )
        except BaseException as exc:
            raise self.gate.failure(exc) from exc
        self.gate.record_response(message)
        return message

    def _complete(self, messages, **kwargs) -> ChatMessage:
        """The one provider call.  Tests replace this and keep every gate behaviour."""
        return super().generate(messages, **kwargs)
