"""Where the interpreter's boundary is, and what the model sees on the far side of it.

The interpreter is a process-internal one: the library's own documentation says it is not
a security sandbox, and the run does not treat it as one.  What it does guarantee is that
the model's code can only reach the host through the tools this phase was given -- there is
no ``os``, no ``open``, no ``__class__`` walk, and no ``eval`` -- and that every way of
overstepping comes back as an observation rather than a crash or a host side effect.

Every test here also asserts the same second thing: the phase survived.  A refused probe
is the model's business, not the run's.
"""
import pytest
from smolagents.local_python_executor import InterpreterError

from audit.executor import failure_reason
from audit.runtime import AgentPolicy
from audit.toolkit import PLANNER_TOOLS
from tests.code_model import Answer, Host, Phase, code

RECOVERED = code('final_answer({"note": "recovered"})')


def run_probe(probe: str, *, host: Host | None = None, policy: AgentPolicy | None = None):
    """Run one probe as the model's first step, then let the phase end normally."""
    host = host or Host({}, policy=policy)
    outcome = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play([code(probe), RECOVERED])
    assert outcome.failure is None, f"探针不该让整个阶段失败：{outcome.failure!r}"
    assert outcome.gate.published == Answer(note="recovered")
    return host, outcome.codes[0]


@pytest.mark.parametrize("probe, expected", [
    ("import os\nprint(os.getcwd())", "Import of os is not allowed"),
    ("import subprocess", "Import of subprocess is not allowed"),
    ("import socket", "Import of socket is not allowed"),
    ("from pathlib import Path", "Import from pathlib is not allowed"),
    ("import json.os", "Import of json.os is not allowed"),
    ("print(open('/etc/passwd').read())", "Forbidden function evaluation: 'open'"),
    ("print(__import__('subprocess'))", "Forbidden function evaluation: '__import__'"),
    ("print(globals())", "Forbidden function evaluation: 'globals'"),
    ("exec('print(1)')", "Forbidden function evaluation: 'exec'"),
    ("print(eval('1+1'))", "Forbidden function evaluation: 'eval'"),
    ("print(().__class__.__bases__)", "Forbidden access to dunder attribute: __bases__"),
    ("print(getattr('', '__class__'))", "Forbidden access to dunder attribute: __class__"),
])
def test_reaching_outside_the_tools_is_refused(probe, expected):
    host, step = run_probe(probe)

    assert expected in step["error"]
    assert host.calls == []
    assert step["is_final"] is False


def test_the_allowed_modules_are_the_ones_the_policy_says():
    """The boundary is "no ``os``/``socket``", not "no import at all" -- say which."""
    host, step = run_probe("import re\nprint(bool(re.search(r'\\d+', 'abc123')))")

    assert step["error"] is None
    assert "True" in step["logs"]


def test_json_tool_records_can_be_parsed_in_the_same_action_without_a_retry():
    host = Host({"list_tree": '{"files_here":[{"path":"src/upload.php"}]}'})
    outcome = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play([code(
        "import json\n"
        "listing = json.loads(list_tree(path='src'))\n"
        "final_answer({'note': listing['files_here'][0]['path']})"
    )])
    assert outcome.failure is None
    assert outcome.gate.published == Answer(note="src/upload.php")
    assert len(outcome.model.requests) == 1
    assert not [step for step in outcome.codes if step.get("error")]


def test_an_ordinary_python_error_is_just_an_error():
    host, step = run_probe("print(1 / 0)")

    assert "ZeroDivisionError" in step["error"]
    assert host.calls == []


def test_a_runaway_block_is_abandoned():
    """The host stops waiting for it; the phase is not held hostage by one code block."""
    host, step = run_probe("while True:\n    pass", policy=AgentPolicy(code_seconds=1))

    assert "maximum execution time" in step["error"]
    assert host.execution.phases["planner_explore"]["model_attempts"] == 2


def test_printed_output_comes_back_cut_and_marked():
    host, step = run_probe('print("x" * 5000)', policy=AgentPolicy(code_output_bytes=600))
    printed = step["logs"].split("Execution logs:\n", 1)[1].split("\nLast output from code snippet:")[0]

    assert "_This content has been truncated to stay below 600 characters_" in printed
    # Both ends survive: the first thing printed and the last thing printed are what the
    # model asked to see.
    assert printed.index("x" * 100) < printed.index("truncated")
    assert printed.rstrip().endswith("x" * 100)


def test_the_tool_budget_cannot_be_spent_from_inside_one_code_block():
    host = Host({"read_source": "x"}, budgets={"responses": 8, "tools": 3, "seconds": 600})
    outcome = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play(
        [code("for i in range(100):\n    print(read_source(path='a.php', start=1, end=1))")],
        max_steps=3,
    )

    assert outcome.reason() == "budget"
    assert host.execution.budgets["tools"] == 3
    # One count, three places: the counter, the phase's own tally, and the events.
    assert host.execution.phases["planner_explore"]["tool_calls"] == 3
    assert len(host.events_of("tool_call")) == 3
    # The fourth attempt never became a call, and the loop got no further request.
    assert len(host.calls) == 3
    assert len(outcome.model.requests) == 1


def test_a_mistyped_tool_call_names_the_argument():
    host, step = run_probe("print(read_source(start=1))")

    assert "missing a required argument: 'path'" in step["error"]
    assert host.calls == []


def test_a_mistyped_keyword_is_named_too():
    host, step = run_probe("print(read_source(path='a.php', startt=1))")

    assert "unexpected keyword argument 'startt'" in step["error"]
    assert host.calls == []


def test_the_model_may_call_a_tool_positionally():
    """The prompt shows each tool as a Python function, so both call styles work."""
    host = Host({"read_source": lambda args: f"{args['path']}:{args['start']}-{args['end']}"})
    host, step = run_probe("print(read_source('a.php', 3, 9))", host=host)

    assert host.calls == [("read_source", {"path": "a.php", "start": 3, "end": 9})]
    assert "a.php:3-9" in step["logs"]


def test_omitted_arguments_take_the_declared_defaults():
    host = Host({"list_tree": lambda args: f"depth={args['depth']} path={args['path']!r}"})
    host, step = run_probe("print(list_tree())", host=host)

    assert host.calls == [("list_tree", {"path": "", "depth": 2})]
    assert "depth=2" in step["logs"]


def test_the_reason_is_read_from_under_the_interpreter_echo():
    """The wrappers repeat the whole code block in their message; the reason is under them."""
    refusal = ValueError("任务 x 的 scope_paths 引用了冻结范围外的路径")
    echo = InterpreterError(f"Code execution failed at line 'print(1)' due to: {refusal}")
    echo.__cause__ = refusal

    assert failure_reason(echo) == f"ValueError: {refusal}"
    # Anything that is not one of those wrappers comes back whole, class name included, so
    # a host refusal and a slip in the model's own code stay told apart.
    assert failure_reason(KeyError("nope")) == "KeyError: 'nope'"
    assert failure_reason(None) is None


def test_a_refused_answer_leaves_its_reason_in_the_event():
    """The event is read for *why* the action failed, not for a copy of the action.

    Live run ``e3bb0c7530`` handed in a 5.9 KB decision, had it refused, and left no
    readable trace of the refusal in any of its 40 ``agent_code`` events: the interpreter
    writes ``Code execution failed at line '<the whole block>' due to: …``, so the 400-byte
    event budget kept the echo of the model's own code and dropped the reason.
    """
    filler = "\n".join(f"value_{index} = {index}" for index in range(40))
    outcome = Phase(Host({}), specs=PLANNER_TOOLS, output_model=Answer).play([
        code(f"{filler}\nfinal_answer({{'nope': 1}})"),
        RECOVERED,
    ])

    assert outcome.failure is None
    step = outcome.codes[0]
    assert step["is_final"] is False
    # The refusal the host raised, with its class name, and both fields it refused.
    assert step["error"].startswith("OutputRejected: ")
    assert "note: Field required" in step["error"]
    assert "nope: Extra inputs are not permitted" in step["error"]
    # Nothing of the interpreter's echo of the code it was raised under.
    assert "value_39" not in step["error"]
    assert "Code execution failed" not in step["error"]
    # The phase carried on and the model corrected itself, which is the whole point of
    # handing a refusal back as an observation.
    assert outcome.gate.published == Answer(note="recovered")


def test_variables_survive_from_one_step_to_the_next():
    """A phase is one conversation: what the model worked out stays worked out."""
    host = Host({"read_source": lambda args: f"{args['path']}:1 | line"})
    outcome = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play([
        code("rows = [read_source(path=p, start=1, end=1) for p in ['a.php', 'b.php']]"),
        code("print(len(rows), rows[1])"),
        RECOVERED,
    ])

    assert outcome.failure is None
    assert "2 b.php:1 | line" in outcome.codes[1]["logs"]
    assert len(host.calls) == 2
