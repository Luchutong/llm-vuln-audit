"""How a phase's code loop is built and run.

A phase is host code wrapped around one ``CodeAgent.run``: the host assembles the prompt,
prefetches the situation, pins the answers and commits the round, and the loop inside does
the model-tool-exchange on the model's own terms.  This module is the seam between them --
the interpreter with its limits, the agent with this repository's prompt, the callback that
records each code action, and the thread hop that keeps the synchronous loop off the event
loop while host callbacks are marshalled back onto it.

One agent and one interpreter serve a whole driver: the loop re-sends tools and variables
on every ``run``, so a phase boundary is a new tool table plus a new gate, and the
variables a phase defined are still there in the next one.
"""
from __future__ import annotations

import asyncio
import functools
import uuid
from pathlib import Path
from typing import Any, Callable

import yaml
from smolagents import CodeAgent
from smolagents.local_python_executor import LocalPythonExecutor
from smolagents.memory import ActionStep
from smolagents.monitoring import LogLevel

from .codemodel import AuditCodeModel, PhaseGate, unwrap_failure
from .actions import check_action
from .safe_encoding import FACADE_NAME, bind_encoding_imports, encoding_facade
from .runtime import AgentPolicy
from .toolkit import FinalAnswerTool, build_tools

PROMPT_FILE = Path(__file__).with_name("prompts") / "code_agent.yaml"
POC_PROMPT_FILE = Path(__file__).with_name("prompts") / "code_agent_poc.yaml"
POC_CONCLUDE_PROMPT_FILE = Path(__file__).with_name("prompts") / "code_agent_poc_conclude.yaml"
# Tools return JSON navigation records. Parsing those records is an ordinary
# in-memory operation, not access to the server filesystem or process environment.
AUTHORIZED_DATA_IMPORTS = ["json", "base64"]


class AuditPythonExecutor(LocalPythonExecutor):
    """Preflight a whole action before the library executes any statement."""

    gate_reader: Callable | None = None

    def __call__(self, code_action: str):
        gate = self.gate_reader() if self.gate_reader else None
        diagnostics = gate.action_diagnostics if gate is not None else {}
        if gate is not None and gate.action_issue is not None:
            raise gate.action_issue
        check_action(code_action, self.authorized_imports, diagnostics)
        # Explicit imports must not reintroduce the stdlib module's CLI helpers,
        # whose globals contain real sys.argv and open despite import restrictions.
        self.state[FACADE_NAME] = encoding_facade()
        return super().__call__(bind_encoding_imports(code_action))


@functools.lru_cache(maxsize=3)
def prompt_templates(kind: str = "audit") -> dict:
    """This repository's own code-action prompt, parsed once per role.

    ``audit`` is the frozen-snapshot surface every Planner/worker/recon phase acts on.
    ``poc`` reads the same code-action contract but describes an agent whose only way to
    touch the target is the isolated runner; the audit wording ("the tools read a frozen
    snapshot", "use list_tree") would otherwise send it looking for tools it does not have.
    ``poc_conclude`` is the same agent after every tool has been withdrawn: the execution
    tutorial and the HTTP example are gone, so the only action left is handing in the
    verdict.  Each cached dict is read-only after parsing and is never mutated per agent.
    """
    path = {
        "poc": POC_PROMPT_FILE,
        "poc_conclude": POC_CONCLUDE_PROMPT_FILE,
    }.get(kind, PROMPT_FILE)
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def build_executor(policy: AgentPolicy) -> LocalPythonExecutor:
    """The interpreter a phase's code runs in.

    ``additional_authorized_imports`` adds JSON data parsing to the library's base set:
    ``re``, ``math``, ``collections``, ``itertools``, ``datetime``, ``statistics``,
    ``time``, ``random``, ``queue``, ``stat``, ``unicodedata`` -- enough to filter and
    count lines, and nothing that can reach the filesystem, the network or a process.
    ``os``, ``sys``, ``subprocess``, ``socket``, ``pathlib``, ``io`` and ``shutil`` are in
    the interpreter's own dangerous list and are not reachable even by name.

    The wall-clock limit is applied by a thread pool, which cannot stop a thread that has
    already started: it bounds how long the host *waits* for a code block, not how long
    the block runs.  A runaway block therefore delays the phase by at most this much.
    """
    executor = AuditPythonExecutor(
        additional_authorized_imports=list(AUTHORIZED_DATA_IMPORTS),
        max_print_outputs_length=policy.code_output_bytes,
        timeout_seconds=policy.code_seconds,
    )
    # Import using the same safe-module machinery as model code; no host module is
    # exposed directly, and a failed action no longer leaves json undefined.
    executor("import json")
    return executor


# The loop's wrappers whose message echoes the model's whole code block into its head.
# What is wanted is the reason *under* them, not the bottom of the chain: an interpreter
# timeout is raised inside ``except FuturesTimeoutError``, so walking all the way down
# lands on a bare ``TimeoutError`` with no message at all.
_ECHO_WRAPPERS = frozenset({"AgentExecutionError", "InterpreterError"})


def failure_reason(error: BaseException | None) -> str | None:
    """Why a code action failed, in the words the event is read for.

    The interpreter builds its message as ``Code execution failed at line '<the whole
    block>' due to: <type>: <message>``: the reason is at the *end* of a message whose head
    is the model's own code.  Cutting that to an event budget therefore keeps the echo and
    drops the reason -- live run ``e3bb0c7530`` handed in a 5.9 KB decision, had it refused,
    and left no readable trace of why in any of its 40 ``agent_code`` events.

    The reason is recovered from under the wrappers instead.  The library raises inside its
    own ``except`` block, so what the host or the code actually raised is chained as
    ``__context__``: the refusal the host raised (``OutputRejected``, whose text is the
    refusal), a ``NameError`` from the model's own code, or the interpreter's own timeout.
    The class name stays on the front, so a host refusal and a slip in the code are still
    told apart.
    """
    if error is None:
        return None
    if not isinstance(error, BaseException):
        return str(error)
    current = error
    for _ in range(10):
        if type(current).__name__ not in _ECHO_WRAPPERS:
            break
        inner = current.__cause__ or current.__context__
        if inner is None or inner is current:
            break
        current = inner
    return f"{type(current).__name__}: {current}"


def step_recorder(model: AuditCodeModel) -> Callable[[ActionStep], None]:
    """Record every code action as it happens, including the ones that failed.

    A step that errored still carries the code the model wrote and whatever it printed
    before the error, and those are the steps most worth having in the log.  The closing
    step and the loop's own last-chance request carry no code and are skipped.

    A reply the loop could not parse has no ``code_action`` either, and used to be
    skipped entirely -- a conclusion phase that answered in prose three times left no
    trace of why it never submitted.  That step is recorded as a parse event instead, and
    the phase's next request becomes a correction.

    The recorder reads the gate off the model rather than closing over the one its phase
    started with.  It is registered once, for the whole driver, and a phase boundary
    re-points the model; closing over the gate instead would leave the recorder writing
    every later phase's code actions to a gate that is already closed.
    """

    def record(step: ActionStep) -> None:
        if model.gate.action_issue is not None and (step.code_action or type(step.error).__name__ == "AgentParsingError"):
            model.gate.record_parse_error(step=step.step_number, error=model.gate.action_issue)
            return
        if not step.code_action:
            if step.error is not None:
                model.gate.record_parse_error(step=step.step_number, error=step.error)
            return
        model.gate.record_code(
            step=step.step_number,
            code=step.code_action,
            logs=step.observations,
            is_final=step.is_final_answer,
            error=failure_reason(step.error),
        )

    return record


def build_agent(*, model: AuditCodeModel, gate: PhaseGate, tools: dict, instructions: str,
                max_steps: int, name: str = "audit",
                templates: dict | None = None) -> CodeAgent:
    """Build one driver's agent.  Its tools and gate are replaced at each phase boundary.

    ``templates`` selects a role-specific prompt; ``None`` keeps the audit template every
    existing caller already gets.  A caller that passes its own dict must not mutate it:
    the cached templates are shared by every agent built from them.
    """
    executor = build_executor(gate.execution.policy)
    executor.gate_reader = lambda: model.gate
    token = uuid.uuid4().hex
    tags = (f"<audit_action_{token}>", f"</audit_action_{token}>")
    gate.action_tags = tags
    return CodeAgent(
        tools=list(tools.values()),
        model=model,
        prompt_templates=templates if templates is not None else prompt_templates(),
        instructions=instructions,
        max_steps=max_steps,
        executor=executor,
        # Parsing tool JSON is allowed; host IO modules remain unavailable.
        additional_authorized_imports=list(AUTHORIZED_DATA_IMPORTS),
        # Both of these would spend a model request on something the host already does.
        planning_interval=None,
        provide_run_summary=False,
        # The library prints its own trace to stdout, which in a server process is noise.
        verbosity_level=LogLevel.OFF,
        stream_outputs=False,
        use_structured_outputs_internally=False,
        code_block_tags=tags,
        # Typed registration: the closing step and the last-chance request are not actions.
        # The recorder follows the model's gate, so it is registered once for the driver.
        step_callbacks={ActionStep: step_recorder(model)},
        name=name,
    )


def attach_phase(agent: CodeAgent, *, tools: dict, gate: PhaseGate, model: AuditCodeModel,
                 instructions: str | None = None, templates: dict | None = None) -> None:
    """Move the agent to its next phase.

    The loop re-sends tools and variables at the start of every ``run``, and the system
    prompt is derived from ``self.tools`` on every read, so a phase boundary is exactly
    this: the new table, the new gate, the new instructions, and the model pointed at it.

    ``instructions`` is optional for the drivers whose phases share one role text.  A
    driver whose phases mean different things (the POC agent explores with tools and then
    concludes without them) must pass it: the rendered system prompt is rebuilt from
    ``agent.instructions`` and the current tool table on every read, so the conclusion
    request carries the conclusion rules instead of the exploration rules.  ``templates``
    does the same for the role text itself: the conclusion's template no longer teaches
    ``run_poc`` or shows an HTTP call, because neither is available in that phase.

    The table has to be built for *this* gate: a tool carries the gate it was built with,
    and re-using the previous phase's table would send the new phase's calls to a gate that
    is already closed.  Both of those are asserted rather than hoped for.
    """
    assert isinstance(tools.get("final_answer"), FinalAnswerTool), (
        "每个阶段都必须装上宿主的 final_answer：库自带的那个接受任何内容，会绕过本阶段的校验"
    )
    stale = sorted(name for name, tool in tools.items() if tool.gate is not gate)
    assert not stale, f"这些工具还是上一个阶段的闸门，调用会被当作已结束的阶段拒绝：{stale}"
    agent.tools = dict(tools)
    gate.action_tags = agent.code_block_tags
    if templates is not None:
        # The cached dictionaries are shared and read-only during rendering; assigning
        # one to the agent does not mutate it.
        agent.prompt_templates = templates
    if instructions is not None:
        # ``system_prompt`` is a read-only property that renders from these two fields;
        # the next ``run`` reads it again, so no cached copy has to be invalidated.
        agent.instructions = instructions
    model.attach(gate)


async def drive_phase(agent: CodeAgent, gate: PhaseGate, task: str, *,
                      max_steps: int | None = None, reset: bool = False) -> Any:
    """Run one phase's loop on a worker thread and report what ended it.

    The return value is the loop's own, and says nothing about whether the phase
    produced anything: a loop that ran out of steps still returns a string from its
    last-chance request.  What the phase concluded is on the gate.

    ``reset`` clears the loop's memory before the phase's task message, leaving the
    interpreter's variables alone.  A phase whose prompt already carries the situation it
    needs -- the host prefetches the overview, the frontier and the pinned investigations
    into every one of them -- starts bounded instead of inheriting the previous phase's
    observations, which are the part that grows without limit.  Carrying them is what made
    a refused decision fatal: live run ``e3bb0c7530`` reached ~170 KB of history by its
    first publish request, and the request after it -- the one correction a refused
    decision is allowed -- was refused by ``history_bytes`` before it was ever sent.

    Failures come back as the host's own: a ``StopAudit`` that ended the phase, or the
    provider failure with ``reason`` still attached, both with the loop's wrappers
    removed, so the driver's failure taxonomy keeps reading the real class name.
    """
    try:
        return await asyncio.to_thread(agent.run, task, reset=reset, max_steps=max_steps)
    except BaseException as exc:
        failure = unwrap_failure(exc)
        if failure is exc:
            raise
        # ``from None``: the wrapper's own message ("Error in generating model output")
        # adds nothing the unwrapped failure does not already say, and its traceback is
        # still in the log through the failure's own frames.
        raise failure from None
    finally:
        gate.close()
