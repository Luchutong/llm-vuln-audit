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
import time
from concurrent.futures import TimeoutError as CallbackTimeout
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from pydantic import BaseModel, ValidationError
from smolagents.models import ChatMessage, OpenAIModel

from .config import ModelConfig
from .actions import ActionIssue, extract_action
from .runtime import Execution, StopAudit
from .tool_errors import ToolFailure, note_tool_result, public_value

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

# What the model is told after a reply the loop could not parse.  It is fixed text, not
# the framework's exception: that message quotes the whole model reply, and this run
# never persists model prose.
PARSE_CORRECTION = (
    "上一条回复没有可解析的代码块。请只输出一个代码块：把本阶段的动作写成 Python 代码；"
    "结束本阶段时在该代码块里调用 final_answer(...)，参数是普通 dict。代码块之外不要写结果。"
)

# The loop raises one class for "nothing usable in this reply"; the category is what the
# durable event carries instead of the exception itself.
PARSE_ERROR_CATEGORIES = {"AgentParsingError": "no_code_block"}


def finish_reason(message: ChatMessage) -> str | None:
    """The provider's ``finish_reason`` when the client kept the raw response.

    ``ChatMessage.raw`` is the provider's own object or dict; it is optional, and its
    absence must not turn a recorded response into a failure.
    """
    raw = getattr(message, "raw", None)
    if raw is None:
        return None
    choices = raw.get("choices") if isinstance(raw, dict) else getattr(raw, "choices", None)
    if not choices:
        return None
    first = choices[0]
    reason = first.get("finish_reason") if isinstance(first, dict) else getattr(first, "finish_reason", None)
    return str(reason)[:40] if reason else None



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
    callback_seconds: float = CALLBACK_SECONDS
    output_model: type[BaseModel] | None = None
    validate: Callable[[Any], Any] | None = None
    published: Any = None
    pending_correction: str | None = None
    closed: bool = False
    tool_calls: int = 0
    consecutive_corrections: int = 0
    action_diagnostics: dict = field(default_factory=dict)
    action_issue: ActionIssue | None = None
    error_counts: dict = field(default_factory=dict)
    outstanding_error: str | None = None
    action_tags: tuple[str, str] = ("<code>", "</code>")
    request_tool_errors: dict = field(default_factory=dict)
    callback_abort: StopAudit | None = None

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
        if self.callback_abort is not None:
            raise HostStop(self.callback_abort)
        if self.closed:
            raise HostStop(StopAudit("cancelled", "本阶段已经结束，宿主不再受理模型侧的动作"))
        ceiling = min(self.callback_seconds, self.deadline - time.monotonic())
        if ceiling <= 0:
            self.callback_abort = StopAudit("timeout", "本阶段截止时间已到，停止宿主回调且不重复提交动作。")
            raise HostStop(self.callback_abort)
        async def restored_callback():
            from .execution_state import execution_context
            owner = getattr(self.execution, "run_execution", None)
            try:
                if self.callback_abort is not None:
                    raise HostStop(self.callback_abort)
                if owner is None:
                    return await callback()
                with execution_context(owner.store, owner.run_id, owner.epoch):
                    return await callback()
            except StopAudit as stop:
                raise HostStop(stop) from None

        future = asyncio.run_coroutine_threadsafe(restored_callback(), self.loop)
        try:
            return future.result(timeout=ceiling)
        except CallbackTimeout:
            if future.done():
                # A completed callback may itself have raised TimeoutError; it no
                # longer has outstanding work and retains its original taxonomy.
                return future.result()
            self.callback_abort = StopAudit("timeout", "宿主回调等待超时，已取消原回调；停止本阶段，不重复提交可能仍有副作用的动作。")
            future.cancel()
            raise HostStop(self.callback_abort) from None

    def request_ceiling(self, messages: Any) -> float:
        """Open one model request and return how long it may take."""
        return self._on_loop(lambda: self._open_request(messages))

    def call_tool(self, name: str, args: dict) -> str:
        """Run one host tool and return the text the model reads as its observation."""
        return self._on_loop(lambda: self._call_tool(name, args))

    def reject_tool_call(self, name: str, error: str, *, args: dict | None = None, hint: str = "") -> None:
        """A registered call with invalid arguments is still a charged attempt."""
        async def rejected():
            self.execution.before_tool()
            self.tool_calls += 1
            call_id = f"invalid-tool-{self.execution.tools}"
            envelope = {"tool": name, "args": public_value(args or {}), "call_id": call_id,
                        "span_id": f"{self.execution.phase}:{call_id}", "phase": self.execution.phase}
            self.execution.emit({"kind": "tool_call", **envelope})
            self.execution.emit({"kind": "tool_result", "tool": name, "call_id": call_id,
                                 **envelope, "status": "invalid_arguments", "error_type": "TypeError",
                                 "output": public_value(error), "preview": public_value(error),
                                 "error_code": "invalid_arguments", "error": public_value(error), "hint": hint})
            note_tool_result(self.execution, f"{name}:arguments", ToolFailure("invalid_arguments", error, hint))
            self.request_tool_errors[name] = {"error_code": "invalid_arguments", "error": public_value(error), "hint": hint}
        self._on_loop(rejected)

    def accept(self, payload: Any) -> str:
        """Publish the phase's terminal answer, or refuse it with a reason.

        Refusing raises :class:`OutputRejected`, which the interpreter turns into the
        step's observation; accepting records the sanitized value on the gate, which is
        what the driver reads -- never the value the model wrote.
        """
        return self._on_loop(lambda: self._accept(payload))

    def record_response(self, message: ChatMessage, *, max_output_tokens: int | None = None) -> None:
        """Count one answered request.  Failures are counted by ``before_model``."""
        self._on_loop(lambda: self._record(message, max_output_tokens=max_output_tokens))

    def record_parse_error(self, *, step: int, error: BaseException) -> None:
        """Record a reply the loop could not parse, and make the next request a correction.

        A reply with no code block used to leave no trace at all: the loop raised its own
        parsing error, the step had no ``code_action``, and the recorder skipped it, so a
        conclusion phase that answered three times in prose ended as "budget" with
        nothing saying why.  Only the fixed category and hint are kept -- the framework
        exception quotes the whole reply, which this run never persists.
        """
        category = self.action_issue.category if self.action_issue else PARSE_ERROR_CATEGORIES.get(type(error).__name__)
        if category is None or self.closed:
            return
        self._on_loop(lambda: self._emit_parse_error(step=step, category=category))

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
        tool_counts = getattr(self.execution, "tool_diagnostics", {}).get(self.execution.phase, {})
        if not self.closed and (self.error_counts or tool_counts):
            self.execution.emit({"kind": "agent_error_summary", "phase": self.execution.phase,
                                 "role": getattr(self.execution, "role_context", {}).get("role") or self.execution.phase.partition("_")[0],
                                 "categories": self.error_counts,
                                 "tool_categories": tool_counts})
        self.closed = True

    def _count_error(self, category: str) -> None:
        counts = self.error_counts.setdefault(category, {"errors": 0, "recovered": 0})
        counts["errors"] += 1
        self.outstanding_error = category

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
        if correction and self.consecutive_corrections >= self.execution.policy.output_corrections:
            raise HostStop(StopAudit(
                "invalid_output", "连续输出或代码纠正已用尽；最后一次拒绝：" + str(reason or "")[:300]
            ))
        try:
            ceiling = self.execution.before_model(
                deadline=self.deadline, limit=self.limit, correction=correction, reason=reason
            )
            if correction:
                self.consecutive_corrections += 1
            return ceiling
        except StopAudit as stop:
            raise HostStop(stop) from None

    async def _call_tool(self, name: str, args: dict) -> str:
        self.tool_calls += 1
        try:
            result = await self.dispatch(name, args)
            # A corrected argument call may use different values; record recovery
            # only once an actual dispatch succeeds, not merely because Python ran.
            failed = isinstance(result, str) and result.startswith(f"{name} 调用失败：")
            failure_fields = {}
            try:
                payload = json.loads(result)
                failed = failed or (isinstance(payload, dict) and (payload.get("ok") is False or bool(payload.get("error"))))
                if failed and isinstance(payload, dict):
                    failure_fields = {key: payload.get(key) for key in ("error_code", "error", "hint")}
            except (TypeError, ValueError):
                pass
            source = getattr(self.dispatch, "__self__", None)
            last_failure = getattr(source, "last_failure", None) or getattr(getattr(source, "reader", None), "last_failure", None)
            if last_failure:
                failed, failure_fields = True, last_failure.fields()
            if failed:
                self.request_tool_errors[name] = failure_fields or {"error_code": "tool_contract", "error": "工具调用失败", "hint": "依据错误及工具契约修正调用。"}
            if not failed:
                self.request_tool_errors.pop(name, None)
                note_tool_result(self.execution, f"{name}:arguments", None)
            return result
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
        owner = getattr(self.execution, "run_execution", None)
        if owner is not None:
            owner.store.assert_execution_write(owner.run_id)
        if self.published is not None:
            raise HostStop(StopAudit("invalid_output", "本阶段已经交回终局，不接受第二次终局"))
        try:
            value = self._typed(payload)
        except (ValidationError, ValueError) as exc:
            reason = rejection_reason(exc)
            self.pending_correction = reason
            self._count_error("evidence" if "证据" in reason or "evidence" in reason else "invalid_output")
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

    async def _record(self, message: ChatMessage, *, max_output_tokens: int | None = None) -> None:
        usage = getattr(message, "token_usage", None)
        self.execution.usage.add(
            requests=1,
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
        )
        content = message.content if isinstance(message.content, str) else str(message.content or "")
        self.request_tool_errors = {}
        action, self.action_diagnostics, self.action_issue = extract_action(content, finish_reason(message), self.action_tags)
        if finish := finish_reason(message):
            self.action_diagnostics["finish_reason"] = finish
        if action is not None:
            # The project's extraction is shared by all roles. Canonicalize one valid
            # action for the dependency parser without preserving its surrounding prose.
            if self.action_tags[0] in action or self.action_tags[1] in action:
                self.action_issue = ActionIssue("ambiguous_code_blocks", "动作正文含内部传输边界，请重新提交单个动作。")
            message.content = self.action_tags[0] + "\n" + action + "\n" + self.action_tags[1]
        event = {
            "kind": "model_response",
            "phase": self.execution.phase,
            # How much the model produced, beside the cap it was given: a reply that fills
            # the cap is a truncation diagnosis, and a short reply that still failed to
            # parse is a format one.
            "output_chars": len(content),
            "output_bytes": len(content.encode("utf-8")),
            "output_tokens": getattr(usage, "output_tokens", 0) or 0,
            "usage": self.execution.snapshot(),
        }
        if max_output_tokens:
            event["max_output_tokens"] = int(max_output_tokens)
        if finish := finish_reason(message):
            event["finish_reason"] = finish
        self.execution.emit(event)

    async def _emit_parse_error(self, *, step: int, category: str) -> None:
        # A callback can already be queued when the phase is closed; a parse error then
        # has nothing to correct and must not reopen the gate.
        if self.closed or self.published is not None:
            return
        # The next request is a correction: it is bounded by the same allowance a rejected
        # final answer uses, and it tells the model exactly how to answer instead.
        hint = self.action_issue.hint if self.action_issue else PARSE_CORRECTION
        self.pending_correction = hint
        self._count_error(category)
        self.execution.emit({
            "kind": "agent_parse_error",
            "phase": self.execution.phase,
            "step": step,
            "request_index": self.execution.attempts,
            "category": category,
            "hint": hint,
            "error_code": category,
            "diagnostics": dict(self.action_diagnostics),
            "usage": self.execution.snapshot(),
        })

    async def _emit_code(self, event: dict) -> None:
        self.execution.emit(event)
        error = str(event.get("error") or "")
        if not error and self.request_tool_errors:
            failure = next(iter(self.request_tool_errors.values()))
            hint = failure.get("hint") or "按工具契约修正调用；失败返回不能视为成功。"
            category = failure.get("error_code") or "tool_contract"
            self.pending_correction = f"{category}: {failure.get('error') or '工具调用失败'} {hint}"[:800]
            self._count_error(category)
            self.execution.emit({"kind": "agent_execution_error", "phase": self.execution.phase,
                                 "category": category, "error_code": category, "hint": hint,
                                 "step": event.get("step"), "reason": public_value(failure.get("error") or "工具调用失败")})
        elif not error:
            self.consecutive_corrections = 0
            if self.outstanding_error:
                self.error_counts[self.outstanding_error]["recovered"] += 1
                self.outstanding_error = None
        elif not self.closed and self.published is None and self.pending_correction is None:
            # Interpreter failures are model actions too. Previously only schema and
            # fence errors spent corrections, so invalid Python consumed the entire
            # request allowance without ever reaching a bounded correction path.
            kind = error.partition(":")[0]
            category = self.action_issue.category if self.action_issue else (
                error.split(": ", 2)[1] if kind == "ActionIssue" else
                "invalid_python" if kind in {"SyntaxError", "NameError", "InterpreterError"}
                else "tool_contract" if kind in {"JSONDecodeError", "TypeError", "KeyError", "IndexError"}
                else "runtime_error"
            )
            hints = {
                "invalid_python": "仅使用已赋值变量；语句必须完整，循环含冒号和缩进体；json 已预载。",
                "unauthorized_import": "宿主只允许系统提示列出的内存处理模块；网络/文件/进程代码放进 runner 脚本。",
                "tool_contract": "按工具声明修正类型、参数名和范围；JSON 工具先检查 error 再访问成功字段。",
            }
            hint = self.action_issue.hint if self.action_issue else hints.get(category, "根据错误位置修正动作，保留已获取的证据。")
            self.pending_correction = (error[:400] + " " + hint)[:800]
            self._count_error(category)
            self.execution.emit({
                "kind": "agent_execution_error", "category": category,
                "step": event.get("step"), "reason": error[:400],
                "phase": self.execution.phase, "error_code": category, "hint": hint,
                "diagnostics": dict(self.action_diagnostics),
                "consecutive_corrections": self.consecutive_corrections,
            })


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
        self.gate.record_response(message, max_output_tokens=self.max_tokens)
        return message

    def _complete(self, messages, **kwargs) -> ChatMessage:
        """The one provider call.  Tests replace this and keep every gate behaviour."""
        return super().generate(messages, **kwargs)
