"""A bounded publication phase, without executable model code.

Exploration still belongs to CodeAgent.  Publishing an already explored decision does
not need a Python interpreter or tools: one JSON object reaches the same typed host
validator, request ledger and cancellation gate as an ordinary final answer.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any

from smolagents.models import ChatMessage

from .codemodel import AuditCodeModel, OutputRejected, PhaseGate, finish_reason, unwrap_failure
from .runtime import StopAudit


JSON_PUBLICATION_RULES = (
    "本阶段只发布结构化决策。只输出一个完整的 JSON 对象，可使用一个 json 代码围栏。"
    "不要输出 Python、XML、解释、推理或多个对象，不要调用 final_answer 或任何工具。"
    "使用 JSON 的双引号、true、false 和 null；字段、类型、数量及真实 ID 必须遵守宿主契约。"
)
_JSON_FENCE = re.compile(r"\A```(?:json)?[ \t]*\r?\n(?P<body>[\s\S]*?)\r?\n?```\Z", re.IGNORECASE)


@dataclass
class StructuredOutputIssue(ValueError):
    """A public diagnosis which never quotes a model's response or hidden reasoning."""

    category: str
    hint: str
    diagnostics: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return self.hint


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            # Even a key is untrusted response text. Do not echo it into durable errors.
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def _constant(_value: str) -> Any:
    raise ValueError("non_finite_json_number")


def parse_json_object(content: Any, *, response_finish_reason: str | None = None) -> dict:
    """Accept exactly one JSON object, optionally enclosed in one JSON fence.

    There is deliberately no extraction from surrounding prose, Python literal fallback,
    brace completion or silent duplicate-key replacement.  A partial decision must be
    resubmitted rather than guessed by the host.
    """
    diagnostics: dict[str, Any] = {"response_format": "json"}
    if response_finish_reason:
        diagnostics["finish_reason"] = response_finish_reason
    if not isinstance(content, str) or not content.strip():
        raise StructuredOutputIssue(
            "empty_response", "回复没有可见 JSON 正文；请重新提交一个完整 JSON 对象。", diagnostics
        )
    text = content.strip()
    if text.startswith("```"):
        fenced = _JSON_FENCE.fullmatch(text)
        if fenced is None:
            raise StructuredOutputIssue(
                "truncated_output" if response_finish_reason == "length" else "invalid_json",
                "JSON 围栏必须完整且只能有一个；也可以直接提交 JSON 对象，不要添加说明。",
                diagnostics,
            )
        text = fenced.group("body")
        diagnostics["fenced"] = True
    try:
        value = json.loads(text, object_pairs_hook=_object_pairs, parse_constant=_constant)
    except json.JSONDecodeError as exc:
        diagnostics.update(line=exc.lineno, column=exc.colno, position=exc.pos)
        raise StructuredOutputIssue(
            "truncated_output" if response_finish_reason == "length" else "invalid_json",
            f"JSON 在第 {exc.lineno} 行、第 {exc.colno} 列无效；检查引号、逗号及括号，重新提交完整对象。",
            diagnostics,
        ) from None
    except (ValueError, RecursionError):
        raise StructuredOutputIssue(
            "invalid_json", "JSON 不允许重复字段、NaN、Infinity 或过深嵌套；请重新提交标准 JSON 对象。",
            diagnostics,
        ) from None
    if not isinstance(value, dict):
        raise StructuredOutputIssue("invalid_json", "顶层必须是单个 JSON 对象，不能是数组、字符串或 null。", diagnostics)
    return value


async def drive_structured_phase(model: AuditCodeModel, gate: PhaseGate, system_prompt: str,
                                 user_prompt: str, *, max_steps: int) -> Any:
    """Publish through the existing gate, with no additional retry allowance.

    The model and gate callbacks remain on their existing threads. Each correction spends
    an ordinary request and the gate's ordinary correction allowance. Faulty responses are
    never saved or replayed into an expanding history: the next request carries the same
    bounded source context and one sanitized rejection hint.
    """
    gate.response_format = "json"
    model.attach(gate)
    messages = [
        ChatMessage(role="system", content=[{"type": "text", "text": system_prompt + "\n\n" + JSON_PUBLICATION_RULES}]),
        ChatMessage(role="user", content=[{"type": "text", "text": user_prompt}]),
    ]
    correction: str | None = None
    try:
        for step in range(1, max(0, max_steps) + 1):
            request_messages = list(messages)
            if correction:
                request_messages.append(ChatMessage(
                    role="user",
                    # smolagents merges consecutive roles before the SDK call. Every
                    # message must use typed parts so that correction messages can be
                    # merged without its string-content assertion failing.
                    content=[{"type": "text", "text": "上一次发布被宿主拒绝：" + correction + "\n保留已确认事实与真实 ID，只重新提交完整 JSON 对象。"}],
                ))
            # Avoid native response_format/tool-choice requirements: compatible providers
            # which serve the existing audit loop may not support those API extensions.
            response = await asyncio.to_thread(
                model.generate, request_messages, stop_sequences=None,
                response_format=None, tools_to_call_from=None,
            )
            try:
                payload = parse_json_object(response.content, response_finish_reason=finish_reason(response))
            except StructuredOutputIssue as issue:
                await asyncio.to_thread(
                    gate.record_structured_error, step=step, category=issue.category,
                    hint=issue.hint, diagnostics=issue.diagnostics,
                )
                correction = issue.hint
                continue
            try:
                await asyncio.to_thread(gate.accept, payload)
            except OutputRejected as exc:
                # _accept has already charged the rejection to this gate. Emitting the
                # public diagnosis must not consume the same correction twice.
                correction = str(exc)
                await asyncio.to_thread(
                    gate.record_structured_error, step=step, category="invalid_output",
                    hint=correction, diagnostics={"response_format": "json"}, count_error=False,
                )
                continue
            await asyncio.to_thread(gate.record_structured_success)
            return gate.published
        raise StopAudit("invalid_output", "结构化发布在允许的请求数内未通过宿主校验；最后一次拒绝：" + (correction or "未取得有效 JSON 对象")[:300])
    except BaseException as exc:
        failure = unwrap_failure(exc)
        if failure is exc:
            raise
        raise failure from None
    finally:
        # Cancellation can abandon a provider thread, but closing the gate ensures a
        # late response cannot publish a decision or reopen another request.
        gate.close()
