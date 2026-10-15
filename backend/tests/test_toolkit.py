"""The tool surface: declared once, and both readers of it agree.

In code-as-action the model calls tools as Python functions, so the surface has to be
declarative.  These tests hold the two things that declaration buys: the prompt the model
reads is rendered from it, and the dispatcher the calls arrive at is the same table -- so a
tool cannot be offered without being wired, and a wired tool cannot be missing from the
prompt.
"""
import keyword

import pytest
from smolagents.local_python_executor import BASE_PYTHON_TOOLS
from smolagents.tools import AUTHORIZED_TYPES

from audit.agent import PlannerDeps
from audit.executor import attach_phase, build_agent
from audit.toolkit import (
    PLANNER_TOOLS, REQUIRED, Arg, FinalAnswerTool, HostTool, ToolSpec, build_tools, spec as make_spec,
)
from tests.code_model import Answer, Host, Phase, ScriptedCodeModel, code


def tools_for(host: Host, specs=PLANNER_TOOLS) -> dict:
    return build_tools(specs, Phase(host, specs=specs).gate())


def test_the_registry_builds_one_tool_per_spec():
    host = Host()
    tools = tools_for(host)

    assert set(tools) == {item.name for item in PLANNER_TOOLS} | {"final_answer"}
    assert isinstance(tools["final_answer"], FinalAnswerTool)
    for item in PLANNER_TOOLS:
        assert isinstance(tools[item.name], HostTool)
        assert tools[item.name].spec is item


def test_the_prompt_shows_the_signature_the_model_must_call():
    rendered = tools_for(Host())["read_source"].to_code_prompt()

    assert "def read_source(path: string, start: integer, end: integer) -> string:" in rendered
    # The interpreter renders no defaults in the signature, so the wording has to say them.
    assert "Args:" in rendered
    assert "默认 1。" in rendered


def test_every_declared_name_and_type_is_one_the_interpreter_accepts():
    """A typo'd type or a reserved word would fail at build time; say so here instead."""
    for item in PLANNER_TOOLS:
        assert item.name.isidentifier() and not keyword.iskeyword(item.name)
        assert item.name not in BASE_PYTHON_TOOLS
        assert item.description.strip()
        for name, arg in item.args.items():
            assert name.isidentifier() and not keyword.iskeyword(name)
            assert arg.type in AUTHORIZED_TYPES
            assert arg.description.strip()


def test_a_declared_type_the_interpreter_does_not_know_is_refused():
    bad = make_spec("bad_tool", "说明", path=Arg("str", "改了名字的类型"))
    with pytest.raises(ValueError, match="must be one of"):
        build_tools((bad,), Phase(Host()).gate())


def test_a_name_the_interpreter_already_owns_is_refused():
    """``send_tools`` lets the base builtins win a collision, so this must fail loudly."""
    shadow = make_spec("max", "会覆盖解释器内置的 max")
    with pytest.raises(AssertionError, match="模型根本调不到宿主"):
        build_tools((shadow,), Phase(Host()).gate())


def test_a_duplicate_name_is_refused():
    twice = (make_spec("same", "一"), make_spec("same", "二"))
    with pytest.raises(AssertionError, match="重复的名字"):
        build_tools(twice, Phase(Host()).gate())


def test_a_duplicate_of_final_answer_is_refused():
    """The phase's own terminal tool must not be shadowed by a host tool."""
    clash = make_spec("final_answer", "冒充终局工具")
    with pytest.raises(AssertionError, match="模型根本调不到宿主"):
        build_tools((clash,), Phase(Host()).gate())


def test_only_the_hosts_final_answer_may_be_installed():
    """``attach_phase`` refuses anything else: the library's own accepts any payload."""
    host = Host()
    outcome = Phase(host, output_model=Answer).play([code('final_answer({"note": "n"})')])
    tools = tools_for(host)
    tools["final_answer"] = HostTool(PLANNER_TOOLS[0], outcome.gate)

    with pytest.raises(AssertionError, match="每个阶段都必须装上宿主的 final_answer"):
        attach_phase(outcome.agent, tools=tools, gate=outcome.gate, model=outcome.model)


def test_the_interpreter_is_given_exactly_the_phase_tools():
    """The plan's structural check: what the registry declares is what the code can call."""
    host = Host({"read_source": "a.php:1 | line"})
    outcome = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play([
        code("print(read_source(path='a.php', start=1, end=1))"),
        code('final_answer({"note": "n"})'),
    ])

    static = set(outcome.agent.python_executor.static_tools)
    assert static == set(outcome.agent.tools) | set(BASE_PYTHON_TOOLS)
    assert {item.name for item in PLANNER_TOOLS} <= static


def test_a_spec_may_route_to_a_different_dispatcher_name():
    """Reconnaissance calls ``grep``; the dispatcher is asked for ``search_code``."""
    tool_spec = make_spec("grep", "在快照里搜索", route="search_code",
                          query=Arg("string", "要查找的字面量。"))
    host = Host({"search_code": "a.php:1: hit"})
    outcome = Phase(host, specs=(tool_spec,), output_model=Answer).play([
        code("print(grep(query='eval'))"),
        code('final_answer({"note": "n"})'),
    ])

    assert host.calls == [("search_code", {"query": "eval"})]
    assert "a.php:1: hit" in outcome.codes[0]["logs"]


def test_a_tool_table_from_an_earlier_phase_is_refused():
    """A tool carries the gate it was built with; re-using one would call a closed phase."""
    host = Host()
    explore = Phase(host, specs=PLANNER_TOOLS, phase="planner_explore").gate()
    model = ScriptedCodeModel([], gate=explore)
    agent = build_agent(model=model, gate=explore, tools=build_tools(PLANNER_TOOLS, explore),
                        instructions="", max_steps=3)
    decision = Phase(host, specs=PLANNER_TOOLS, phase="planner_decision").gate()

    with pytest.raises(AssertionError, match="上一个阶段的闸门"):
        attach_phase(agent, tools=build_tools(PLANNER_TOOLS, explore), gate=decision, model=model)

    attach_phase(agent, tools=build_tools(PLANNER_TOOLS, decision), gate=decision, model=model)
    assert set(agent.tools) == {item.name for item in PLANNER_TOOLS} | {"final_answer"}
    assert model.gate is decision


def test_a_mistyped_call_names_the_tool_and_the_problem():
    tool_spec = PLANNER_TOOLS[5]
    assert tool_spec.name == "read_source"
    with pytest.raises(TypeError, match="read_source: missing a required argument: 'path'"):
        tool_spec.bind((), {})
    with pytest.raises(TypeError, match="read_source: got an unexpected keyword argument 'startt'"):
        tool_spec.bind((), {"path": "a.php", "startt": 1})


def test_positional_and_keyword_arguments_bind_the_same_way():
    tool_spec = PLANNER_TOOLS[5]
    assert tool_spec.bind(("a.php", 3, 9), {}) == {"path": "a.php", "start": 3, "end": 9}
    assert tool_spec.bind((), {"path": "a.php", "start": 3, "end": 9}) == {"path": "a.php", "start": 3, "end": 9}


def test_omitted_arguments_fall_back_to_their_declared_default():
    tool_spec = PLANNER_TOOLS[5]
    assert tool_spec.bind(("a.php",), {}) == {"path": "a.php", "start": 1, "end": 0}
    assert ToolSpec("x", "y").bind((), {}) == {}


def test_a_missing_required_argument_is_declared_required():
    tool_spec = PLANNER_TOOLS[5].args["path"]
    assert tool_spec.default is REQUIRED


@pytest.mark.parametrize("args, kwargs, expected", [
    ((), {"note": "n"}, {"note": "n"}),
    (({"note": "n"},), {}, {"note": "n"}),
    (("正文",), {}, "正文"),
])
def test_the_answer_tool_reads_a_payload_written_either_way(args, kwargs, expected):
    assert FinalAnswerTool.payload(args, kwargs) == expected


@pytest.mark.parametrize("args, kwargs, message", [
    ((), {}, "需要一个参数"),
    (({},), {"note": "n"}, "不要混用"),
    (({"a": 1}, {"b": 2}), {}, "只接受一个位置参数"),
])
def test_a_payload_written_two_ways_is_named_rather_than_guessed(args, kwargs, message):
    with pytest.raises(TypeError, match=message):
        FinalAnswerTool.payload(args, kwargs)


def test_the_registry_and_the_dispatcher_are_the_same_table():
    """Allowed to drift today; P1 derives ``_handlers`` from the registry and this stays."""
    wired = set(PlannerDeps._handlers(object.__new__(PlannerDeps)))
    assert wired == {item.name for item in PLANNER_TOOLS}
