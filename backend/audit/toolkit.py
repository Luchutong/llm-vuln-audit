"""The host's tool surface, declared once, so the prompt and the dispatcher cannot drift.

Today each tool is written twice: once as a decorated function whose docstring is what the
model reads, and once as a branch of ``deps.call`` that actually runs it.  Nothing keeps
those two in step, so ``test_planner_tools.py`` asserts ``offered == wired`` after the
fact.  In code-as-action the model calls tools as plain Python functions, so the surface
has to be declarative anyway -- and once it is declared in one table, that assertion stops
being a test and becomes a build-time check (:func:`build_tools`).

A spec says *what exists and how the model calls it*.  It never says what a call does:
that stays in ``deps.call``, with its scope checks, pins, read ledger, duplicate detection,
budgets and ``tool_call``/``tool_result`` events.  A code action is another caller of that
one dispatcher, not a second implementation beside it.
"""
from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel
from smolagents.local_python_executor import BASE_PYTHON_TOOLS, FinalAnswerException
from smolagents.tools import Tool


class _Required:
    """Marks a declared parameter the model must pass."""

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return "REQUIRED"


REQUIRED = _Required()


@dataclass(frozen=True)
class Arg:
    """One declared parameter, in the form the prompt renders it.

    ``type`` is one of the interpreter's own authorized type names; ``default`` matters
    twice over -- it is what a missing argument binds to, and the prompt has no place to
    render it, so the default belongs in the description as well.
    """

    type: str
    description: str
    default: Any = REQUIRED
    minimum: int | None = None
    maximum: int | None = None
    max_length: int | None = None
    nullable: bool = False
    value_type: str | None = None
    item_type: str | None = None
    max_items: int | None = None

    def validate(self, name: str, value: Any) -> None:
        if value is None and (self.nullable or self.default is None):
            return
        kind = self.value_type or self.type
        valid = {
            "string": lambda: isinstance(value, str),
            "integer": lambda: type(value) is int,
            "number": lambda: type(value) in {int, float},
            "boolean": lambda: type(value) is bool,
            "array": lambda: isinstance(value, list),
            "object": lambda: isinstance(value, dict),
            "any": lambda: True,
        }.get(kind)
        if valid is not None and not valid():
            raise TypeError(f"{name} 必须是 {kind}，收到 {type(value).__name__}")
        if self.minimum is not None and value < self.minimum:
            raise TypeError(f"{name} 必须 >= {self.minimum}")
        if self.maximum is not None and value > self.maximum:
            raise TypeError(f"{name} 必须 <= {self.maximum}")
        if self.max_length is not None and len(value) > self.max_length:
            raise TypeError(f"{name} 长度必须 <= {self.max_length}")
        if self.max_items is not None and len(value) > self.max_items:
            raise TypeError(f"{name} 元素数量必须 <= {self.max_items}")
        if self.item_type and isinstance(value, list):
            for index, item in enumerate(value):
                Arg(self.item_type, "数组元素").validate(f"{name}[{index}]", item)

    def prompt_description(self) -> str:
        constraints = []
        if self.default is not REQUIRED:
            constraints.append(f"默认 {self.default!r}")
        if self.minimum is not None:
            constraints.append(f">= {self.minimum}")
        if self.maximum is not None:
            constraints.append(f"<= {self.maximum}")
        if self.max_length is not None:
            constraints.append(f"长度 <= {self.max_length}")
        if self.value_type:
            constraints.append(self.value_type + (" 或 None" if self.default is None else ""))
        if self.item_type:
            constraints.append(f"元素类型 {self.item_type}")
        if self.max_items is not None:
            constraints.append(f"元素数量 <= {self.max_items}")
        return self.description + (" [" + "; ".join(constraints) + "]" if constraints else "")


@dataclass(frozen=True)
class ToolSpec:
    """One host tool as the model sees it."""

    name: str
    description: str
    args: dict[str, Arg] = field(default_factory=dict)
    # The dispatcher name, when the model-facing name differs from the one ``deps.call``
    # knows.  Reconnaissance draws this distinction today: the model calls ``grep`` and
    # the dispatcher is asked for ``search_code``.
    route: str | None = None
    output_format: Literal["text", "json"] = "text"
    output_fields: tuple[str, ...] = ()

    @property
    def inputs(self) -> dict[str, dict]:
        return {name: {"type": arg.type, "description": arg.prompt_description()} for name, arg in self.args.items()}

    def signature(self) -> inspect.Signature:
        """The call shape the model was shown, as a real signature."""
        return inspect.Signature([
            inspect.Parameter(
                name,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                **({} if arg.default is REQUIRED else {"default": arg.default}),
            )
            for name, arg in self.args.items()
        ])

    def bind(self, args: tuple, kwargs: dict) -> dict:
        """Map what the model wrote onto the declared parameters.

        The prompt shows each tool as a Python function, so the model may call it
        positionally or by keyword.  Binding through a real signature makes a mistake come
        back as the model's own error message ("missing a required argument: 'path'")
        instead of a TypeError about ``**kwargs``.
        """
        try:
            bound = self.signature().bind(*args, **kwargs)
        except TypeError as exc:
            raise TypeError(f"{self.name}: {exc}") from None
        bound.apply_defaults()
        values = dict(bound.arguments)
        for name, value in values.items():
            self.args[name].validate(name, value)
        if "start" in values and "end" in values and values["end"] != 0 and values["end"] < values["start"]:
            raise TypeError(f"{self.name}: end 必须 >= start（0 仅在声明允许时使用）")
        return values


def spec(name: str, description: str, *, route: str | None = None,
         output_format: Literal["text", "json"] = "text", output_fields: tuple[str, ...] = (), **args: Arg) -> ToolSpec:
    return ToolSpec(name=name, description=description, args=args, route=route, output_format=output_format,
                    output_fields=output_fields)


class HostTool(Tool):
    """One host tool as the interpreter sees it: a Python function that dispatches.

    The declared signature lives in the spec rather than in ``forward``'s own parameters,
    so ``skip_forward_signature_validation`` is set -- nothing is lost by that, because
    the signature the model reads is rendered from ``inputs``, and the arguments are bound
    against a real ``inspect.Signature`` here before they reach the dispatcher.
    """

    skip_forward_signature_validation = True

    def __init__(self, spec: ToolSpec, gate: Any):
        super().__init__()
        self.spec = spec
        self.gate = gate
        self.name = spec.name
        contract = (
            "返回 JSON 字符串；用 json.loads 解析，首次、缓存复用和失败时均保持 JSON。"
            "失败结构为 {ok: false, tool: 工具名, error: 原因}，先检查 error 再读取成功字段；截断在结构内标记 truncated。"
            if spec.output_format == "json" else
            "返回可直接阅读的文本，不是 JSON；不要用 json.loads 解析。"
        )
        self.description = spec.description + "\n" + contract
        if spec.output_fields:
            self.description += " 成功字段：" + ", ".join(spec.output_fields) + "。失败时先检查 ok/error。"
        self.inputs = spec.inputs
        self.output_type = "string"
        self._signature = spec.signature()

    def forward(self, *args, **kwargs) -> str:
        try:
            bound = self.spec.bind(args, kwargs)
        except TypeError as exc:
            reject = getattr(self.gate, "reject_tool_call", None)
            hint = f"正确签名：{self.spec.name}{self._signature}"
            if reject:
                reject(self.spec.name, str(exc), args={"positional": list(args), "keywords": kwargs},
                       hint=hint)
            if self.spec.output_format == "json":
                from .tool_errors import public_value
                return json.dumps({"ok": False, "tool": self.spec.name, "error_code": "invalid_arguments",
                                   "error": public_value(str(exc)), "hint": hint}, ensure_ascii=False)
            raise
        return self.gate.call_tool(self.spec.route or self.spec.name, bound)


class FinalAnswerTool(Tool):
    """The terminal action of a phase, checked by the host before it is accepted.

    The library's own ``final_answer`` accepts anything, which is exactly what this run
    cannot do: a phase ends with a decision, and the rules that decide whether a decision
    is usable are the host's.  So the answer goes to the gate, and only a gate that
    accepted it raises ``FinalAnswerException`` -- the one signal that ends the loop.  A
    refusal comes back as a normal exception, which the interpreter turns into the step's
    observation, and the model corrects itself in the same loop.
    """

    name = "final_answer"
    description = "交回本阶段的最终结果并结束本阶段。宿主会按本阶段的契约校验；不通过时你会收到一条 Observation 说明原因，请修正后重交。"
    inputs = {"answer": {
        "type": "any",
        "description": "本阶段要求的最终结果：一个结构化对象，或本阶段的正文。",
    }}
    output_type = "string"
    skip_forward_signature_validation = True

    def __init__(self, gate: Any, description: str | None = None):
        super().__init__()
        self.gate = gate
        if description:
            self.description = description

    @classmethod
    def for_model(cls, gate: Any, model: type[BaseModel], label: str) -> "FinalAnswerTool":
        """The terminal tool with the phase's own structure written on it.

        The framework used to send the output model's JSON schema with every request.  In
        code-as-action there is no such class inside the sandbox -- the model writes a dict
        literal -- so the shape has to be stated where the model reads its tools.  Generated
        from the model rather than transcribed beside it: a field added to the structure
        reaches the model without anyone remembering to update a prompt.
        """
        return cls(gate, description=(
            f"交回本阶段的最终结果（{label}）并结束本阶段。宿主按下面的结构校验；"
            "不通过时你会收到一条 Observation 说明原因，请修正后重新交回。\n"
            "answer 是一个 dict（也可以按字段名写成关键字参数）：\n"
            + final_answer_contract(model)
        ))

    def forward(self, *args, **kwargs) -> str:
        raise FinalAnswerException(self.gate.accept(self.payload(args, kwargs)))

    @staticmethod
    def payload(args: tuple, kwargs: dict) -> Any:
        """Read the answer out of the call, whichever way the model wrote it.

        ``final_answer(decision)`` and ``final_answer(goal_state=..., tasks=[...])`` are
        both natural readings of "hand over the result", and a structured answer written
        field by field is the easier one to get right, so both are accepted.  Mixing them
        is a mistake worth naming rather than guessing at.
        """
        if args and kwargs:
            raise TypeError("final_answer 只接受一个位置参数，或一组与最终结构同名的关键字参数，不要混用")
        if args:
            if len(args) != 1:
                raise TypeError(f"final_answer 只接受一个位置参数，收到 {len(args)} 个")
            return args[0]
        if not kwargs:
            raise TypeError("final_answer 需要一个参数：本阶段要求的最终结果")
        return kwargs


def final_answer_contract(model: type[BaseModel]) -> str:
    """Render the wire schema beside a Python-safe, minimal submission example."""
    schema = model.model_json_schema()

    def example(item: dict, seen: frozenset[str] = frozenset()) -> Any:
        ref = item.get("$ref")
        if ref:
            name = ref.rsplit("/", 1)[-1]
            if name in seen:
                return None
            return example(schema.get("$defs", {}).get(name, {}), seen | {name})
        if "default" in item:
            return item["default"]
        if "const" in item:
            return item["const"]
        if item.get("enum"):
            return item["enum"][0]
        alternatives = item.get("anyOf") or item.get("oneOf")
        if alternatives:
            return example(next((value for value in alternatives if value.get("type") != "null"), alternatives[0]), seen)
        kind = item.get("type")
        if kind == "object" or "properties" in item:
            return {name: example(value, seen) for name, value in item.get("properties", {}).items()
                    if name in item.get("required", [])}
        if kind == "array":
            return []
        if kind == "boolean":
            return False
        if kind in {"integer", "number"}:
            return item.get("minimum", 0)
        if kind == "null":
            return None
        return "请填写已核实的依据"

    return (
        json.dumps(schema, ensure_ascii=False)
        + "\n上面是 JSON Schema 元数据，不是可以直接执行的 Python。"
        "代码中的空值和布尔值必须写 None / True / False，不能写 null / true / false。"
        "下面仅演示本阶段必需字段和 Python 语法，请按已核实事实填写并遵守业务校验：\n"
        + "final_answer(" + repr(example(schema)) + ")"
    )


class ProgressTool(Tool):
    """A status control channel, separate from source tools and their budgets."""

    name = "report_progress"
    description = (
        "在同一代码块的源码工具调用前，向用户提交一句公开审计进展（当前检查重点或下一步动作）。"
        "不要输出内部逐步推理、隐藏思维链或未经验证的漏洞结论；这不是证据或最终评估。"
        "每次模型响应最多保存一条，最多280字符；无需为此单独发起一次模型响应。"
    )
    inputs = {"message": {"type": "string", "description": "一句简短、面向用户的公开工作进展。"}}
    output_type = "string"

    def __init__(self, gate: Any):
        super().__init__()
        self.gate = gate

    def forward(self, message: str) -> str:
        return self.gate.report_progress(message)


def build_tools(specs, gate, *, final_answer: Any = None) -> dict[str, Tool]:
    """Build one phase's tool table, final answer included.

    The checks here are the structural half of what the tests used to assert after the
    fact: a duplicate name, or a name that something else already owns -- the interpreter's
    base builtins (``send_tools`` lets them win a collision, so a tool named ``max`` would
    be silently replaced by the builtin) or the phase's own ``final_answer`` (installed
    last, so a host tool of that name would be silently replaced by the terminal one).
    """
    names = [item.name for item in specs]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    assert not duplicated, f"工具注册表里有重复的名字：{duplicated}"
    shadowed = sorted(set(names) & (set(BASE_PYTHON_TOOLS) | {"final_answer", "report_progress"}))
    assert not shadowed, (
        f"工具名已被解释器内置实现或本阶段的 final_answer 占用，模型根本调不到宿主：{shadowed}"
    )
    tools: dict[str, Tool] = {item.name: HostTool(item, gate) for item in specs}
    tools["final_answer"] = final_answer or FinalAnswerTool(gate)
    tools["report_progress"] = ProgressTool(gate)
    return tools


# --- The Planner's read-only surface ------------------------------------------------
# Descriptions and argument wording are the ones the Planner prompt has been carrying;
# they are the model's contract, so they move here verbatim rather than being rewritten.
PLANNER_TOOLS: tuple[ToolSpec, ...] = (
    spec(
        "get_project_map",
        "Return the compact frozen project overview; use focused search for detailed paths, symbols, includes or calls.",
        output_fields=('overview', 'project_stats', 'architecture', 'high_confidence_entrypoints'),
        output_format="json",
    ),
    spec(
        "search_project_map",
        "Find a path, symbol, include expression or call name in the frozen project map.",
        output_fields=('query', 'matches_by_kind', 'truncated'),
        query=Arg("string", "要查找的路径片段、符号名、include 表达式或调用名，<= 200 字符。", max_length=200),
        output_format="json",
    ),
    spec(
        "get_task_results",
        "Return durable summaries from previous Planner tasks and rounds, without hidden reasoning.",
        output_fields=('goal', 'tasks', 'findings', 'plans'),
        output_format="json",
    ),
    spec(
        "get_coverage",
        "Return the host-computed reading coverage for this round: which files workers really read, and which first-party modules nobody has read.",
        output_fields=('files_read',),
        output_format="json",
    ),
    spec(
        "get_investigation",
        "Return one pinned investigation in full, by its topic_key or its 1-based position in the situation block; these records never change, and re-asking their question replays them.",
        output_fields=('id', 'topic', 'payload'),
        topic_key=Arg("string", "已固定调查的 topic_key；留空则按 index 取。默认空串。", ""),
        index=Arg("integer", "该调查在态势块里的 1-based 序号；topic_key 为空时使用。默认 0（不按序号取）。", 0),
        output_format="json",
    ),
    spec(
        "read_source",
        "Read original lines from one frozen project file so a proposed reading window is checked against the real source instead of guessed; at most 200 lines per call, and the lines you read here are never evidence.",
        path=Arg("string", "快照内相对路径，例如 app/main.py。"),
        start=Arg("integer", "起始行号（1-based，含）。默认 1。", 1, minimum=1),
        end=Arg("integer", "结束行号（含）；0 表示从 start 起最多 200 行。默认 0。", 0, minimum=0),
    ),
    spec(
        "search_code",
        "Find a literal string or identifier, NOT a regex or OR expression (run search_code(query='login') and search_code(query='role') separately), in project text files; query <=200 characters; optional snapshot-relative file or directory; dependency trees are skipped unless included. The snapshot is frozen, so a query this run already ran replays that answer instead of searching again.",
        query=Arg("string", "要查找的字面量字符串或标识符，<= 200 字符。", max_length=200),
        path=Arg("any", "可选的快照内相对文件或目录；为 None（默认）时搜索整个项目。", None, value_type="string"),
        include_dependencies=Arg("boolean", "是否一并搜索依赖/vendor 目录。默认 False。", False),
    ),
    spec(
        "list_tree",
        "List directories and files below a project-relative path; the cheapest way to learn the layout. The snapshot is frozen, so an identical listing replays the answer this run already pinned.",
        output_fields=('path', 'child_directories', 'files_here', 'truncated'),
        path=Arg("string", "项目内相对目录；空串表示项目根。默认空串。", ""),
        depth=Arg("integer", "展开层数，宿主最多展开 3 层。默认 2。", 2, minimum=1),
        output_format="json",
    ),
    spec(
        "find_files",
        "Find files by name, glob (for example **/*.js) or substring; returns paths and metadata only. The snapshot is frozen, so an identical search replays the answer this run already pinned.",
        output_fields=('pattern', 'matches', 'match_count', 'truncated'),
        pattern=Arg("string", "文件名子串或 glob，例如 **/*.py。"),
        limit=Arg("integer", "最多返回多少条，宿主上限 40。默认 20。", 20, minimum=1),
        output_format="json",
    ),
    spec(
        "file_summary",
        "Return one file's metadata and symbol outline; read the file for its actual content. The snapshot is frozen, so an identical summary replays the answer this run already pinned.",
        output_fields=('path', 'language', 'line_count', 'symbols'),
        path=Arg("string", "快照内相对路径。"),
        output_format="json",
    ),
    spec(
        "investigate_project",
        "Send a reconnaissance sub-agent into the frozen project to answer one question about layout, entry points, data stores, security boundaries or reading order; returns navigation leads only, never evidence. A question this run already asked is answered from its pinned brief without reconnaissance; only new questions count against the per-round limit. Set revise=true only for a brief you have reason to believe is wrong -- it re-runs that one question and supersedes the pinned record.",
        output_fields=('summary', 'uncertainties'),
        question=Arg("string", "关于布局、入口点、数据存储、安全边界或阅读顺序的一个问题。"),
        revise=Arg("boolean", "只在该问题的既有简报有理由被认为是错的时设为 True：会重跑这一个问题并取代旧记录。默认 False。", False),
        output_format="json",
    ),
)


# --- The worker's read-only surface --------------------------------------------------
# One reading unit's tools, whether it is a legacy category unit or a Planner task.  The
# descriptions are the docstrings the decorated registrations used to carry, verbatim, so
# what the model reads has not changed with the mechanism.  The two peer-trace tools are
# only offered when the run really has another worker's traces to search; a tool that
# could only ever answer "this mode does not provide them" is not offered at all.
WORKER_TOOLS: tuple[ToolSpec, ...] = (
    spec(
        "read_source",
        "Read original snapshot lines; path is snapshot-relative, start/end are inclusive original line numbers.",
        path=Arg("string", "快照内相对路径。"),
        start=Arg("integer", "起始行号（1-based，含）。", minimum=1),
        end=Arg("integer", "结束行号（含）。", minimum=1),
    ),
    spec(
        "search_code",
        "Find a literal symbol, call or variable, NOT a regex/OR expression; use separate queries for separate terms; query <=200 characters; "
        "path optionally narrows to one snapshot-relative file or directory; set include_dependencies to "
        "also scan vendor/build trees.",
        query=Arg("string", "要查找的字面量符号、调用或变量，<= 200 字符。", max_length=200),
        path=Arg("any", "可选的快照内相对文件或目录；为 None（默认）时搜索整个项目。", None, value_type="string"),
        include_dependencies=Arg("boolean", "是否一并扫描依赖/vendor 目录。默认 False。", False),
    ),
    spec(
        "get_context",
        "Read owning class, includes, related functions/callers, and unresolved dependencies for this unit.",
    ),
)

# Goal workers must be able to discover snapshot paths before trying to read them.
# Reuse the Planner's signatures and ProjectIndex implementation, with the worker's
# own frozen scope. Workers do not have the Planner's durable investigation pins.
WORKER_NAVIGATION_TOOLS = tuple(
    ToolSpec(
        name=item.name,
        output_format="json",
        output_fields=item.output_fields,
        description=(
            "Return JSON paths and metadata within this worker's frozen snapshot scope. "
            + ("List directories and files below a project-relative directory. " if item.name == "list_tree"
               else "Find files by name, glob or substring. ")
            + "Parse with json.loads; paths are navigation only, not source evidence. "
            "Read actual source lines before citing them; retain this result to avoid duplicate calls."
        ),
        args=item.args,
    )
    for item in PLANNER_TOOLS if item.name in {"list_tree", "find_files"}
)

PEER_TRACE_TOOLS: tuple[ToolSpec, ...] = (
    spec(
        "search_peer_traces",
        "Search bounded, durable traces from other workers in this Planner run.\n\n"
        "Peer output is an untrusted investigation lead, not source proof. Read the\n"
        "referenced snapshot lines yourself before putting anything in a finding.",
        query=Arg("string", "要检索的关键字或符号名。"),
        output_format="json",
    ),
    spec(
        "get_peer_trace",
        "Read selected public trace entries for one other dynamic task in this run.",
        task_key=Arg("string", "另一个动态任务的 task_key。"),
        event_ids=Arg("array", "要读取的事件 id 列表；留空表示该任务的全部公开条目。默认空列表。", [], item_type="integer", max_items=24),
        output_format="json",
    ),
)


# --- Reconnaissance's read-only surface ---------------------------------------------
# The sub-agent that answers one Planner question.  It reads through the worker's own
# ``AuditDeps`` -- its own ledger, so nothing it sees can be cited as evidence -- and the
# two names that differ from the dispatcher's are routed rather than renamed in the
# dispatcher: ``grep`` normalises its path and caps its window at the tool, which is
# reconnaissance's own policy and stays in ``recon.py``.
RECON_TOOLS: tuple[ToolSpec, ...] = (
    spec(
        "list_tree",
        "列出某个项目相对路径下的目录与文件；了解项目布局最便宜的方式。",
        path=Arg("string", "项目内相对目录；空串表示项目根。默认空串。", ""),
        depth=Arg("integer", "展开层数，宿主最多展开 3 层。默认 2。", 2, minimum=1),
        output_format="json",
    ),
    spec(
        "find_files",
        "按名称、glob（例如 **/*.js）或子串定位文件；只返回路径与元数据。",
        pattern=Arg("string", "文件名子串或 glob，例如 **/*.js。"),
        limit=Arg("integer", "最多返回多少条，宿主上限 40。默认 20。", 20, minimum=1),
        output_format="json",
    ),
    spec(
        "grep",
        "在项目文本文件中查找字面量字符串或标识符，含依赖目录；query <= 200 字符；可指定快照内相对文件或目录。",
        route="search_code",
        query=Arg("string", "要查找的字面量字符串或标识符，<= 200 字符。", max_length=200),
        path=Arg("any", "可选的快照内相对文件或目录；为 None（默认）时搜索整个项目。", None, value_type="string"),
        include_dependencies=Arg("boolean", "是否一并搜索依赖/vendor 目录。默认 True。", True),
    ),
    spec(
        "read_file",
        "读取某个项目文本文件的原始行片段；二进制文件无法读取。每次调用有行数上限。",
        route="read_source",
        path=Arg("string", "快照内相对路径。"),
        start=Arg("integer", "起始行号（1-based，含）。默认 1。", 1, minimum=1),
        end=Arg("integer", "结束行号（含）；0 表示从 start 起读满上限。默认 0。", 0, minimum=0),
    ),
    spec(
        "file_summary",
        "返回一个文件的元数据与符号大纲；要看实际内容请用 read_file。",
        path=Arg("string", "快照内相对路径。"),
        output_format="json",
    ),
)
