"""The audit agent: one unit in, one structured UnitAnalysis out.

The agent's autonomy is deliberately narrow. The queue decides *what* is examined and
the fixed checklist decides *which* categories are reported; the model only decides
which additional code it needs in order to answer. It has exactly three read-only
tools, and every range they return is recorded so evidence citations can be checked
against what the model actually saw.
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field

from pydantic import ValidationError
from pydantic_ai import Agent, RunContext, UsageLimits
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.settings import ModelSettings
from pydantic_ai.usage import RunUsage

from .config import ModelConfig
from .schemas import CATEGORIES, CATEGORY_LABELS, CategoryPoc, CategoryVerdict, Check, PocBundle, UnitAnalysis
from .source import SourceRepository

MAX_TOOL_TEXT = 32 * 1024
# The forced answer inlines what exploration read; a unit that wandered through a whole
# framework must not push the settlement call past the context window.
MAX_SETTLEMENT_CONTEXT = 120 * 1024
# The wrap-up phase runs on its own wall clock, not on what is left of exploration.
SETTLE_SECONDS = 420.0
# Even past the deadline a call gets this much, so a long settlement degrades into a
# slow answer instead of an immediate failure.
SETTLE_MIN_CALL = 60.0
# Ceiling on one settlement call. `retries=1` means up to two attempts inside it.
SETTLE_CALL_SECONDS = 200.0
# Per-request timeout, passed to the model. This is the one that matters: without it a
# single hung request consumes the whole call budget and the correction attempt never
# happens, which is how the first settlement call died with a bare `TimeoutError` and no
# indication of how long it had waited.
SETTLE_REQUEST_SECONDS = 90.0


@dataclass
class AuditDeps:
    """Everything a tool call needs, plus the record of what was handed to the model."""

    repository: SourceRepository
    snapshot_id: str
    unit: dict
    reads: list[dict] = field(default_factory=list)
    calls: set = field(default_factory=set)
    repeats: int = 0
    tool_limit: int = 0

    def record(self, path: str, start_line: int, end_line: int) -> None:
        self.reads.append({"path": path, "start_line": start_line, "end_line": end_line})

    def first_time(self, name: str, args: dict) -> bool:
        """False when this exact tool call has already been made for this unit.

        A small model that cannot resolve a fact will sometimes re-issue the identical
        search instead of concluding. Re-running it returns the same bytes and burns the
        unit's whole budget, so the repeat is refused and the model is told why.
        """
        key = (name, tuple(sorted(args.items())))
        if key in self.calls:
            self.repeats += 1
            return False
        self.calls.add(key)
        return True

    def budget_note(self) -> str:
        """A squeeze appended to tool results once the tool budget runs low.

        The prompts say what a verdict must establish; nothing in them bounds how far to
        chase it, and an unbounded checklist makes a model explore until the unit dies as
        `incomplete` — which is the one outcome that yields no finding at all.
        """
        if not self.tool_limit:
            return ""
        remaining = self.tool_limit - len(self.calls)
        if remaining > max(2, self.tool_limit // 4):
            return ""
        return (
            f"\n\n【预算提示】工具调用已用 {len(self.calls)}/{self.tool_limit} 次，剩余 {max(remaining, 0)} 次。"
            "请立即停止探索，基于已经读到的代码给出三类的结构化结论；"
            "任何仍未证实的事实写进 missing_context 或 preconditions，不要再去读新文件。"
        )


def build_model(config: ModelConfig):
    provider = OpenAIProvider(base_url=config.base_url, api_key=config.api_key)
    return OpenAIChatModel(config.model, provider=provider)


def _format_lines(lines: list[dict]) -> str:
    return "\n".join(f"{line['number']:>5} | {line['text']}" for line in lines)


def render_unit(unit: dict, snapshot_name: str, budgets: dict | None = None) -> str:
    """The single user message: the frozen slice with original line numbers."""
    header = [
        f"快照: {snapshot_name}",
        f"文件: {unit['file_path']}",
        f"符号: {unit['symbol']}（{unit['kind']}）",
        f"原始行范围: {unit['start_line']}-{unit['end_line']}",
        f"切片: 第 {unit['slice_index']} / {unit['slice_count']} 片",
    ]
    if unit.get("class_name"):
        header.append(f"所属类: {unit['class_name']}")
    if unit.get("parse_incomplete"):
        header.append("注意: 本文件存在 PHP 语法解析错误，索引可能不完整")
    if unit.get("slice_count", 1) > 1:
        header.append("注意: 本单元是被拆分的切片之一，边界处可能缺少上下文")
    rule = unit.get("slice_rule") or {}
    if rule:
        header.append(f"切片规则: {rule.get('boundary', 'unknown')}（重叠 {rule.get('overlap_lines', 0)} 行）")

    omitted = unit.get("omissions") or []
    body = [
        "",
        "```php",
        _format_lines(unit.get("cleaned_lines") or []),
        "```",
    ]
    if omitted:
        kinds: dict[str, int] = {}
        for item in omitted:
            kinds[item.get("reason", "unknown")] = kinds.get(item.get("reason", "unknown"), 0) + 1
        summary = "、".join(f"{name} ×{count}" for name, count in sorted(kinds.items()))
        body.append(f"\n（为节省上下文，清洗时省略了 {summary}；行号仍为原始文件行号，可用工具读回。）")
    body.append(
        "\n如果判断需要本单元之外的代码（被 include 的文件、调用方、类定义、初始化逻辑），"
        "先用工具读取，再下结论；读不到就把结论定为 insufficient_context 并写明缺什么。"
    )
    if budgets:
        body.append(
            f"\n## 本单元的工具预算\n"
            f"你最多可以做 {budgets['tools']} 次工具调用、最多 {budgets['responses']} 次模型往返。"
            "预算用尽时本单元会被记为「未完成」，既不算漏洞也不算安全——所以给出结论永远优于继续探索。\n"
            "- 上面的代码就是本单元的全部内容，不必再读一遍；只有需要原始（未清洗）文本时才读回。\n"
            "- 同一个工具用完全相同的参数重复调用会被拒绝；结果就在上文，请直接用。\n"
            "- 优先回答决定结论的那个问题。若某个事实在代码里查不到（例如配置值、运行时开关、"
            "与他处重复的初始化逻辑），就把它写成前提或 missing_context，用已有证据下结论。\n"
            "- 目标是判断本单元的这三类漏洞，不是把整个项目的调用链读完；探索本身不计分。\n"
            "- 三类都必须给出结论；没有任何一类可以是空的。"
        )
    return "\n".join(header + body)


async def audit_unit(
    *,
    repository: SourceRepository,
    snapshot_id: str,
    snapshot_name: str,
    unit: dict,
    prompt_text: str,
    config: ModelConfig,
    budgets: dict,
    on_event=None,
) -> dict:
    """Run one unit. Returns the analysis (or None) plus budget accounting.

    Never raises for model-side problems: a failed unit is reported as incomplete,
    because the report must not turn an execution failure into a negative finding.

    `on_event(turn)` is an optional diagnostic tap used by scripts/demo_trace.py; the
    worker leaves it unset so a run records only its event log.
    """
    deps = AuditDeps(
        repository=repository,
        snapshot_id=snapshot_id,
        unit=unit,
        tool_limit=int(budgets.get("tools") or 0),
    )
    agent: Agent[AuditDeps, UnitAnalysis] = Agent(
        build_model(config),
        deps_type=AuditDeps,
        output_type=UnitAnalysis,
        instructions=prompt_text,
        model_settings=ModelSettings(extra_body=config.extra_body()),
        # One correction attempt for output validation; the spec allows exactly one.
        retries=1,
    )

    @agent.tool
    async def read_source(ctx: RunContext[AuditDeps], path: str, start: int, end: int) -> str:
        """Read original source lines from the snapshot.

        Args:
            path: Snapshot-relative file path, exactly as printed in the unit header.
            start: First line to read, one-based.
            end: Last line to read, inclusive.
        """
        if not ctx.deps.first_time("read_source", {"path": path, "start": start, "end": end}):
            return f"read_source({path}, {start}-{end}) 已经调用过，内容见上文工具返回。请不要重复读取，直接下结论。"
        try:
            result = ctx.deps.repository.read_source(ctx.deps.snapshot_id, path, start, end)
        except (ValueError, FileNotFoundError) as exc:
            return f"read_source failed: {exc}"
        ctx.deps.record(result["path"], result["start_line"], result["end_line"])
        text = _format_lines(result["lines"])
        if result.get("truncated"):
            text += f"\n... truncated at line {result['end_line']}; continue from line {result['next_start']}"
        return (text + ctx.deps.budget_note())[:MAX_TOOL_TEXT]

    @agent.tool
    async def search_code(ctx: RunContext[AuditDeps], query: str, path: str | None = None) -> str:
        """Search the snapshot for a literal string, to find callers, sinks or definitions.

        Args:
            query: Literal text to find, at most 200 characters.
            path: Optional single file to restrict the search to.
        """
        if not ctx.deps.first_time("search_code", {"query": query, "path": path}):
            return f"search_code({query!r}) 已经调用过，结果见上文。同一个搜索不会给出新结果，请改用已有证据下结论。"
        try:
            result = ctx.deps.repository.search_code(ctx.deps.snapshot_id, query, path, limit=40)
        except (ValueError, FileNotFoundError) as exc:
            return f"search_code failed: {exc}"
        if not result["matches"]:
            return f"no matches for {query!r}"
        lines = []
        for match in result["matches"]:
            ctx.deps.record(match["path"], match["line"], match["line"])
            lines.append(f"{match['path']}:{match['line']}: {match['text'].strip()[:300]}")
        if result.get("truncated"):
            lines.append("... results truncated")
        return ("\n".join(lines) + ctx.deps.budget_note())[:MAX_TOOL_TEXT]

    @agent.tool
    async def get_context(ctx: RunContext[AuditDeps]) -> str:
        """Fetch the owning class, include statements, related functions, call sites and
        the list of dependencies that could not be resolved statically."""
        if not ctx.deps.first_time("get_context", {}):
            return "get_context() 已经调用过，内容见上文工具返回。请直接下结论。"
        try:
            result = ctx.deps.repository.get_context(ctx.deps.snapshot_id, ctx.deps.unit)
        except (ValueError, FileNotFoundError) as exc:
            return f"get_context failed: {exc}"
        chunks = []
        for excerpt in result["excerpts"]:
            ctx.deps.record(excerpt["path"], excerpt["start_line"], excerpt["end_line"])
            chunks.append(
                f"--- {excerpt['path']}:{excerpt['start_line']}-{excerpt['end_line']}"
                f"（{excerpt.get('reason', 'context')}）\n{_format_lines(excerpt['lines'])}"
            )
        unresolved = result.get("unresolved_dependencies") or []
        if unresolved:
            chunks.append(
                "无法静态解析的依赖:\n"
                + "\n".join(
                    f"- {item.get('path')}:{item.get('line', '?')} {item.get('expression', '')} — {item['reason']}"
                    for item in unresolved[:20]
                )
            )
        return (("\n\n".join(chunks) or "no static context available") + ctx.deps.budget_note())[:MAX_TOOL_TEXT]

    limits = UsageLimits(
        request_limit=budgets["responses"],
        tool_calls_limit=budgets["tools"],
    )
    started = time.monotonic()
    usage = {"requests": 0, "tool_calls": 0, "input_tokens": 0, "output_tokens": 0}
    # Our own accumulator, passed into the run and incremented in place. `result.usage` is
    # only reachable when the run returns, and the usual end of exploration here is a
    # raised budget error — which is why the report used to show "0 次工具调用" for units
    # that had in fact read thirty ranges through the tools.
    accumulator = RunUsage()

    def capture() -> None:
        for name in usage:
            value = getattr(accumulator, name, None)
            if isinstance(value, int):
                usage[name] = value

    handler = None
    if on_event is not None:
        turn = {"n": 0}

        def _describe(event) -> dict | None:
            kind = getattr(event, "event_kind", "")
            part = getattr(event, "part", None)
            # Use the completed events: a part_start for a tool call may still carry
            # empty args while the call is being streamed.
            if kind == "function_tool_call":
                turn["n"] += 1
                args = part.args_as_dict() if hasattr(part, "args_as_dict") else getattr(part, "args", None)
                return {"turn": turn["n"], "tool": getattr(part, "tool_name", "?"), "args": args}
            if kind == "function_tool_result":
                content = getattr(part, "content", "")
                return {"tool": getattr(part, "tool_name", "?"),
                        "chars": len(str(content)), "preview": str(content)[:160]}
            if kind != "part_start" or not part:
                return None
            part_kind = getattr(part, "part_kind", "")
            if part_kind == "retry-prompt":
                return {"retry": str(getattr(part, "content", ""))[:300]}
            if part_kind == "final-result":
                return {"final": True}
            return None

        def handler(_ctx, event_stream):
            async def consume():
                async for event in event_stream:
                    described = _describe(event)
                    if described is not None:
                        on_event(described)
            return consume()

    try:
        result = await asyncio.wait_for(
            agent.run(
                render_unit(unit, snapshot_name, budgets),
                deps=deps,
                usage=accumulator,
                usage_limits=limits,
                event_stream_handler=handler,
            ),
            timeout=budgets["seconds"],
        )
    except asyncio.TimeoutError:
        capture()
        return await _settle(
            repository=repository, snapshot_id=snapshot_id, unit=unit, snapshot_name=snapshot_name,
            prompt_text=prompt_text, config=config, budgets=budgets, deps=deps, usage=usage,
            reason="timeout", error=f"Unit exceeded the {budgets['seconds']}s wall-clock budget",
            on_event=on_event, started=started,
        )
    except UsageLimitExceeded as exc:
        capture()
        return await _settle(
            repository=repository, snapshot_id=snapshot_id, unit=unit, snapshot_name=snapshot_name,
            prompt_text=prompt_text, config=config, budgets=budgets, deps=deps, usage=usage,
            reason="budget", error=f"Budget exhausted: {exc}", on_event=on_event, started=started,
        )
    except Exception as exc:
        # Includes the model failing to produce the structured output at all, which is
        # the common case for a small model: it is a prompt for settlement, not a dead end.
        status = getattr(exc, "status_code", None)
        capture()
        return await _settle(
            repository=repository, snapshot_id=snapshot_id, unit=unit, snapshot_name=snapshot_name,
            prompt_text=prompt_text, config=config, budgets=budgets, deps=deps, usage=usage,
            reason="error", error=f"{type(exc).__name__}: {str(exc)[:400]}", status=status,
            on_event=on_event, started=started,
        )

    capture()
    return {"analysis": result.output, "usage": usage, "seen": deps.reads, "repeats": deps.repeats,
            "incomplete": None, "error": None, "settled": False}


def _gathered_context(repository: SourceRepository, snapshot_id: str, deps: AuditDeps) -> str:
    """Everything the exploration phase read, inlined so the forced answer can use it.

    The transcript is rebuilt from the recorded reads rather than from the model's
    message history: the reads are exact, they survive a failed or cancelled run, and
    they are the same ranges the evidence validator accepts.
    """
    if not deps.reads:
        return ""
    blocks: list[str] = []
    budget = MAX_SETTLEMENT_CONTEXT
    seen: set[tuple[str, int, int]] = set()
    for read in deps.reads:
        key = (read["path"], read["start_line"], read["end_line"])
        if key in seen:
            continue
        seen.add(key)
        try:
            result = repository.read_source(snapshot_id, read["path"], read["start_line"], read["end_line"])
        except (ValueError, FileNotFoundError):
            continue
        block = (
            f"--- {result['path']}:{result['start_line']}-{result['end_line']}\n"
            f"{_format_lines(result['lines'])}"
        )
        if len(block) > budget:
            break
        budget -= len(block)
        blocks.append(block)
    if not blocks:
        return ""
    return "\n\n# 探索阶段读到的代码\n\n" + "\n\n".join(blocks)


async def _settle(
    *,
    repository: SourceRepository,
    snapshot_id: str,
    unit: dict,
    snapshot_name: str,
    prompt_text: str,
    config: ModelConfig,
    budgets: dict,
    deps: AuditDeps,
    usage: dict,
    reason: str,
    error: str,
    on_event=None,
    started: float = 0.0,
    status: int | None = None,
) -> dict:
    """Force the answer after exploration ends, with the tools taken away.

    The unit is still reported `incomplete` if this fails: a unit the model could not
    answer is never a negative result.
    """
    def unfinished(error_text: str, verdicts=None) -> dict:
        # `usage` counts nothing when exploration never returned a result: pydantic-ai's
        # UsageLimitExceeded carries no usage object, so the numbers would be a fabricated
        # zero. Reporting None says "unknown", which is what the run actually knows.
        return {"analysis": None, "usage": usage if usage["requests"] else None,
                "seen": deps.reads, "repeats": deps.repeats,
                "incomplete": reason, "error": error_text, "status": status,
                "settled": False, "verdicts": verdicts}

    # Settlement is a phase with a wall clock of its own. The exploration budget is
    # already spent by the time we get here, so inheriting it left every settlement
    # call timing out on the 30s floor. Ending a run the same way ARTEX does: the
    # wrap-up turn gets a budget of its own, not the remainder of the one that ran out.
    deadline = time.monotonic() + SETTLE_SECONDS

    def remaining() -> float:
        return max(SETTLE_MIN_CALL, deadline - time.monotonic())

    def call_ceiling() -> float:
        """How long one settlement call may take: the phase deadline, capped per call."""
        return max(SETTLE_MIN_CALL, min(SETTLE_CALL_SECONDS, deadline - time.monotonic()))

    context = render_unit(unit, snapshot_name, None) + _gathered_context(repository, snapshot_id, deps)

    def build(schema):
        return Agent(
            build_model(config),
            output_type=schema,
            instructions=prompt_text,
            # `timeout` bounds one HTTP request, so a hung request still leaves room for the
            # correction attempt; the outer wait in `settle_call` bounds the whole call.
            model_settings=ModelSettings(extra_body=config.extra_body(), timeout=SETTLE_REQUEST_SECONDS),
            retries=1,
        )

    async def settle_call(schema, message: str):
        """One forced answer, timed, with the elapsed time reported on failure.

        The first version of this returned a bare `TimeoutError` with no duration, which
        could equally have meant a hung endpoint or a phase deadline that had already
        passed. The elapsed number is what makes the failure diagnosable.
        """
        started_call = time.monotonic()
        ceiling = call_ceiling()
        try:
            return await asyncio.wait_for(build(schema).run(message), timeout=ceiling)
        except Exception as exc:
            elapsed = time.monotonic() - started_call
            raise RuntimeError(
                f"{type(exc).__name__} after {elapsed:.0f}s "
                f"(ceiling {ceiling:.0f}s, {SETTLE_REQUEST_SECONDS:.0f}s per request): {str(exc)[:200]}"
            ) from exc

    # One category per call. A candidate that omits a required field burns the call's
    # retries, so judging all three at once lets one sloppy category destroy the other
    # two; alone, each category fails or succeeds on its own.
    verdicts: dict[str, CategoryVerdict] = {}
    for key, label in (("sqli", "SQL 注入"), ("xss_r", "反射型 XSS"), ("command_injection", "命令注入")):
        try:
            result = await settle_call(
                CategoryVerdict,
                f"{context}\n\n# 现在作答\n\n"
                f"工具已停用，不会再读到任何新代码。只判断 {key}（{label}）这一类。\n"
                "输出对象的每一个字段都必须填写：\n"
                "- evidence：`路径:起行-止行`，多条用 `;` 分隔；行号是原始文件行号，"
                "路径必须与单元头部完全一致。非 candidate 时写 不适用。\n"
                "- input_source / propagation / dangerous_operation：输入来源、传播路径、"
                "危险操作，各自一句话并可带行号；非 candidate 时写 不适用。\n"
                "- protection：已有的防护以及它为什么没有覆盖这条路径；没有任何防护时写 无。\n"
                "- preconditions：触发所需的前提条件，例如需要先登录、需要某个参数名、"
                "需要特定安全等级或数据库分支；非 candidate 时写 不适用。\n"
                "- missing_context：还缺什么上下文；没有就写 无。\n"
                "- severity：low / medium / high / critical；非 candidate 时填 low。\n"
                "- conclusion 为 candidate 时，evidence、input_source、propagation、"
                "dangerous_operation、preconditions 必须有实质内容，写 不适用 会被判为无效。",
            )
        except Exception as exc:
            return unfinished(
                f"{error} | 收尾阶段 {key} 判定失败: {exc}",
                verdicts=verdicts,
            )
        _add_usage(usage, result.usage)
        verdicts[key] = result.output
        if on_event is not None:
            on_event({"settled": key, "conclusion": result.output.conclusion})

    candidates = {name for name, check in verdicts.items() if check.conclusion == "candidate"}
    proofs: dict[str, CategoryPoc] = {}
    if candidates:
        listed = "、".join(sorted(candidates))
        for name in sorted(candidates):
            verdict = verdicts[name]
            try:
                poc_result = await settle_call(
                    PocBundle,
                    f"{context}\n\n# 现在作答\n\n"
                    f"已判定 {name} 为 candidate，依据是：{verdict.reasoning[:400]}\n\n"
                    "工具已停用。请只为这一个类别给出一个完整可运行的验证脚本，"
                    "包含正常输入与攻击输入，并说明两者的预期差异；同时给出修复建议。"
                    "proofs 里只放一条。",
                )
            except Exception as exc:
                return unfinished(
                    f"{error} | 已判定 candidate 为 {listed}，但收尾阶段未能产出 POC"
                    f"（{name}）: {exc}",
                    verdicts=verdicts,
                )
            _add_usage(usage, poc_result.usage)
            for item in poc_result.output.proofs:
                proofs.setdefault(item.category, item)
        missing = sorted(candidates - set(proofs))
        if missing:
            return unfinished(
                f"{error} | 已判定 candidate 为 {listed}，但收尾阶段未返回 POC：{'、'.join(missing)}",
                verdicts=verdicts,
            )

    checks: dict[str, Check] = {}
    for name in CATEGORIES:
        try:
            checks[name] = _to_check(name, verdicts[name], proofs.get(name))
        except (ValidationError, ValueError) as exc:
            return unfinished(f"{error} | 收尾结果不完整（{name}）: {str(exc)[:400]}", verdicts=verdicts)

    summary = "；".join(
        f"{CATEGORY_LABELS[name]}[{verdicts[name].conclusion}]："
        f"{verdicts[name].reasoning.strip().splitlines()[0][:120]}"
        for name in CATEGORIES
        if verdicts[name].reasoning.strip()
    )
    analysis = UnitAnalysis(summary=summary, **checks)
    if on_event is not None:
        on_event({"settled": "done"})
    return {"analysis": analysis, "usage": usage, "seen": deps.reads, "repeats": deps.repeats,
            "incomplete": None, "error": None, "settled": True,
            "exploration_incomplete": reason, "exploration_error": error}


def _add_usage(usage: dict, run_usage) -> None:
    for name in usage:
        value = getattr(run_usage, name, None)
        if isinstance(value, int):
            usage[name] += value


# Text the model writes when a field carries no information. Treated as blank, so a
# candidate that only ever says this is reported incomplete rather than as a finding.
_BLANK = {"", "无", "不适用", "n/a", "na", "none", "null", "-", "—"}


def _blank(value: str | None) -> bool:
    return value is None or value.strip().strip("。.") in _BLANK


# Only these extensions are indexed, so a path can be recognised by its ending even
# when the model buries it in a sentence.
_SOURCE_PATH = r"(?P<path>[\w./\\-]+\.(?:php|inc|phtml))"
_EVIDENCE_RANGE = re.compile(
    _SOURCE_PATH + r"[^\d]{0,12}(?P<start>\d+)[^\d]{0,6}(?:-|–|—|~|至|到)[^\d]{0,6}(?P<end>\d+)"
)
_EVIDENCE_LINE = re.compile(_SOURCE_PATH + r"[^\d]{0,12}(?P<line>\d+)")


def _parse_evidence(text: str) -> list[dict]:
    """Read the cited line ranges back out of the model's prose.

    The model is asked for `path:start-end` because it fills a flat string field
    reliably and drops nested objects — but it does not stop there: it writes
    `low.php:3-10（$_REQUEST 取值）`, `第 3-10 行`, or just a bare single line. Anchoring
    the whole chunk matched none of those and silently produced zero evidence, which
    then read as "candidate without evidence". The pattern below therefore anchors on
    the snapshot's own file extensions (only `.php`/`.inc`/`.phtml` are indexed), which
    marks where the path ends and lets any surrounding prose through.

    Anything still unparseable is dropped, and `_to_check` reports the raw text.
    """
    refs: list[dict] = []
    if _blank(text):
        return refs
    for chunk in re.split(r"[;\n；,，。]", text.replace("`", "")):
        chunk = chunk.strip()
        if not chunk:
            continue
        match = _EVIDENCE_RANGE.search(chunk)
        if match:
            refs.append({
                "path": match.group("path").lstrip("./").replace("\\", "/"),
                "start_line": int(match.group("start")),
                "end_line": int(match.group("end")),
            })
            continue
        match = _EVIDENCE_LINE.search(chunk)
        if match:
            line = int(match.group("line"))
            refs.append({
                "path": match.group("path").lstrip("./").replace("\\", "/"),
                "start_line": line,
                "end_line": line,
            })
    return refs


def _parse_list(text: str) -> list[str]:
    if _blank(text):
        return []
    parts = re.split(r"[;\n；]|(?<=。)\s*", text)
    return [part.strip().strip("-• ") for part in parts if not _blank(part)]


def _to_check(name: str, verdict: CategoryVerdict, proof: CategoryPoc | None) -> Check:
    """Turn a settlement verdict into a stored check, or fail loudly.

    Anything short of a complete candidate raises: the caller reports the unit as
    incomplete, because a candidate the harness could not assemble is an execution
    failure, and the report must never turn that into a negative.
    """
    evidence = _parse_evidence(verdict.evidence)
    payload = {
        "conclusion": verdict.conclusion,
        "reasoning": verdict.reasoning,
        "evidence": evidence,
        "missing_context": _parse_list(verdict.missing_context),
    }
    if verdict.conclusion != "candidate":
        # Non-candidate text is kept as written; it explains why the category was cleared.
        payload["protection"] = "" if _blank(verdict.protection) else verdict.protection
        payload["severity"] = None
        return Check(**payload)

    blanks = [
        field
        for field, value in (
            ("evidence", verdict.evidence),
            ("input_source", verdict.input_source),
            ("propagation", verdict.propagation),
            ("dangerous_operation", verdict.dangerous_operation),
            ("preconditions", verdict.preconditions),
        )
        if _blank(value)
    ]
    if not evidence:
        blanks.append(f"evidence(无法解析: {verdict.evidence[:200]!r})")
    if proof is None:
        blanks.append("poc")
    if blanks:
        raise ValueError(f"{name} 判为 candidate 但缺少: {', '.join(blanks)}")

    payload.update({
        "input_source": verdict.input_source,
        "propagation": verdict.propagation,
        "dangerous_operation": verdict.dangerous_operation,
        "protection": verdict.protection,
        "preconditions": _parse_list(verdict.preconditions),
        "severity": verdict.severity,
        "poc": proof.poc,
        "remediation": proof.remediation,
    })
    return Check(**payload)
