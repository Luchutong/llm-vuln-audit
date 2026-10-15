"""The Planner's read-only tool surface, and the boundary that makes it safe.

The Planner used to plan blind: it had to hand workers file:line windows while having no
way to read a line itself, and its only content search was the PHP symbol index -- empty
on a project with no PHP in it.  It now has the full read-only surface under a ledger of
its own.  The surface and the separation are pinned together here, because either one
alone is a defect: a read tool whose lines could stand in for a worker's evidence, or a
tool table that answers a name nobody wired with something else.
"""
from __future__ import annotations

import asyncio
import io
import itertools
import re
import zipfile
from types import SimpleNamespace

import pytest

from audit import agent
from audit.agent import AuditDeps, PlannerDeps
from audit.config import ModelConfig
from audit.evidence import seen_ranges, validate_evidence
from audit.runtime import AgentPolicy, Execution, SourceLedger
from audit.source import SourceRepository
from tests.code_model import Always, ModelFactory, call, code, final_answer

CONFIG = ModelConfig(model="test", base_url="https://example.invalid", api_key="private-test-key")

# A file with no PHP in it is the point: the Planner's old search could only see symbols
# derived from PHP, so on this project every content query came back empty.
FILES = {
    "public/index.php": "<?php\nrequire '../src/bootstrap.php';\nrouter();\n",
    "src/bootstrap.php": (
        "<?php\n"
        "function router() { return handle(); }\n"
        "function handle() { return readfile($_GET['f']); }\n"
    ),
    "static/app.js": "fetch('/api/users');\nconsole.log('boot');\n",
    "config/app.yaml": "database: sqlite\nsecret: local-only\n",
}

TASK = {
    "objective": "找出从 HTTP 入口到文件读取的路径。",
    "success_criteria": "结论引用原始源码行号。",
}


@pytest.fixture
def project(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, text in FILES.items():
            archive.writestr(path, text)
    repository = SourceRepository(tmp_path / "source-data")
    snapshot = repository.import_zip(stream.getvalue(), "planner-tools.zip")
    return SimpleNamespace(
        repository=repository,
        snapshot_id=snapshot["id"],
        project_map=repository.build_project_map(snapshot["id"], None),
    )


def decision_payload():
    return {
        "goal_state": "continue",
        "basis_summary": "入口静态包含 bootstrap，文件读取集中在 handle。",
        "next_action": "让 worker 读取入口与 bootstrap 的原始行。",
        "missing_context": [],
        "tasks": [{
            "task_key": "entry-read",
            "title": "入口到文件读取的路径",
            "objective": "读取入口与 bootstrap，确认请求参数如何到达文件读取。",
            "acceptance_criteria": "worker 引用两个文件的原始行号。",
            "rationale_summary": "项目图显示入口包含 bootstrap，handle 调用 readfile。",
            "source_refs": [
                {"path": "public/index.php", "start_line": 1, "end_line": 3, "reason": "entry"},
                {"path": "src/bootstrap.php", "start_line": 1, "end_line": 4, "reason": "sink"},
            ],
            "scope_paths": [],
            "target_symbols": ["handle"],
            "dependencies": [],
            "query_hints": ["readfile"],
            "priority": 80,
        }],
        "updates": [],
    }


def offered_tools(prompts: list[str]) -> set[str]:
    """The tool signatures the model was handed, read off the prompt it was handed them in.

    In code-as-action the tool table reaches the model as the rendered signatures of the
    phase's own tools, so this is the offered set -- the same thing the function-tool
    schema used to be.
    """
    assert prompts, "这一轮没有发出任何请求"
    return set(re.findall(r"def (\w+)\(", prompts[0]))


def run_round(monkeypatch, project, script, *, allowed_paths=None, policy=None):
    factory = ModelFactory(script)
    monkeypatch.setattr(agent, "build_code_model", factory)
    events: list[dict] = []
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=project.project_map,
        run_context={"goal": {}, "tasks": [], "plans": []},
        task=TASK,
        round_no=1,
        config=CONFIG,
        # The round holds back what a decision costs (one request plus its corrections),
        # so the allowance has to cover that reserve *and* the exploration calls a test
        # wants to see, or exploration gets nothing to spend.
        budgets={"responses": 8, "tools": 12, "seconds": 8},
        policy=policy or AgentPolicy(request_seconds=0.5),
        repository=project.repository,
        snapshot_id=project.snapshot_id,
        allowed_paths=allowed_paths,
        on_event=events.append,
    ))
    return result, events, factory.prompts


def tool_results(events: list[dict], tool: str) -> list[dict]:
    return [event for event in events if event["kind"] == "tool_result" and event["tool"] == tool]


def test_the_planner_reads_a_file_with_no_php_in_it_and_search_finds_it_too(monkeypatch, project):
    """Both halves of the old blind spot, in one round.

    `search_code` has to see a plain text file, and `read_source` has to return the real
    lines of one -- a Planner that can only search a PHP symbol index cannot write a
    usable reading instruction for the rest of the project.
    """
    script = {
        "planner_explore": [
            call("search_code", query="fetch"),
            call("read_source", path="static/app.js", start=1, end=2),
            final_answer(decision_payload()),
        ],
    }

    result, events, prompts = run_round(monkeypatch, project, script)

    assert result["decision"] is not None, result
    search = tool_results(events, "search_code")[0]
    assert search["status"] == "ok"
    assert "static/app.js:1" in search["preview"]
    read = tool_results(events, "read_source")[0]
    assert read["status"] == "ok"
    assert "fetch('/api/users');" in read["preview"]
    # The Planner's own calls are labelled as the Planner's, so the timeline never mixes
    # a planning read with a worker's read.
    calls = [event for event in events if event["kind"] == "tool_call" and event["tool"] in {"read_source", "search_code"}]
    assert calls and all(event["call_id"].startswith("planner-tool-") for event in calls)

    # Every tool the model was offered has a branch that answers it: the table is the
    # single wiring point, and a registration without a handler is the exact shape of
    # the bug where an unlisted name was answered with a project search.
    execution = Execution({"responses": 8, "tools": 8, "seconds": 5}, AgentPolicy(), lambda event: None)
    wired = set(PlannerDeps(project_map=project.project_map, run_context={}, execution=execution)._handlers())
    assert offered_tools(prompts) == wired | {"final_answer"}


def test_a_path_outside_the_frozen_scope_is_refused_without_being_read(monkeypatch, project):
    """`allowed_paths` was stored and never consulted; the Planner's tools consult it.

    `config/app.yaml` is inside the snapshot but outside this run's frozen scope, so the
    refusal has to come from the scope rather than from the file being unreadable.
    """
    script = {
        "planner_explore": [
            call("read_source", path="config/app.yaml", start=1, end=2),
            call("read_source", path="src/bootstrap.php", start=1, end=2),
            final_answer(decision_payload()),
        ],
    }

    result, events, _ = run_round(
        monkeypatch, project, script, allowed_paths=["public/index.php", "src/bootstrap.php"]
    )

    # Selected by outcome rather than by position: how many exploration turns the round
    # grants is the host's allowance to set, and this test is about which answer each
    # path gets, not about how many times the model may ask.
    refused = next(item for item in tool_results(events, "read_source") if item["status"] == "context_missing")
    allowed = next(item for item in tool_results(events, "read_source") if item["status"] == "ok")
    assert "outside this task's frozen scope" in refused["preview"]
    assert "local-only" not in refused["preview"]
    assert "router" in allowed["preview"]
    # A refusal is a tool answer, not the end of the round.
    assert result["decision"] is not None, result


def test_an_unknown_tool_name_is_refused_instead_of_answered_with_a_map_search():
    """The fallback used to answer any unlisted name with a project search.

    That is worse than an error: it looks like a successful call that returned the wrong
    thing, so a tool added to the registration without a branch would degrade silently.
    """
    events: list[dict] = []
    execution = Execution({"responses": 8, "tools": 8, "seconds": 5}, AgentPolicy(), events.append)
    execution.enter("planner_explore")
    deps = PlannerDeps(project_map={"files": []}, run_context={}, execution=execution)

    text = asyncio.run(deps.call("get_findings", {}))

    assert "不是本回合可用的 Planner 工具" in text
    assert "files" not in text
    refusal = [event for event in events if event["kind"] == "tool_result"][0]
    assert refusal["status"] == "context_missing"


def test_lines_the_planner_read_are_still_not_evidence_a_worker_can_cite(project):
    """The whole reason a real read tool is safe to give the Planner.

    Evidence is checked against exactly one ledger -- the reading unit's own.  The lines
    below are readable and really were read by the Planner, and a worker that did not
    read them is still refused; once it reads them itself, the same citation holds.
    """
    policy = AgentPolicy()
    cited = [{"path": "src/bootstrap.php", "start_line": 2, "end_line": 2}]
    file_lines = {"src/bootstrap.php": 4}
    unit = {"file_path": "src/bootstrap.php"}

    def reader(ledger, prefix):
        return AuditDeps(
            repository=project.repository,
            snapshot_id=project.snapshot_id,
            unit=unit,
            execution=Execution({"responses": 4, "tools": 4, "seconds": 5}, policy, lambda event: None),
            ledger=ledger,
            allowed_paths=None,
            call_prefix=prefix,
        )

    planner_reader = reader(SourceLedger(policy.planner_source_bytes), "planner-tool")
    asyncio.run(planner_reader.read_source_text({"path": "src/bootstrap.php", "start": 2, "end": 2}))

    worker_reader = reader(SourceLedger(policy.source_bytes), "tool")
    verified, problems = validate_evidence(
        cited, file_lines, seen_ranges(unit, worker_reader.reads, exact=True)
    )
    assert not verified
    assert "were never read by this unit" in problems[0]

    asyncio.run(worker_reader.read_source_text({"path": "src/bootstrap.php", "start": 2, "end": 2}))
    verified, problems = validate_evidence(
        cited, file_lines, seen_ranges(unit, worker_reader.reads, exact=True)
    )
    assert problems == []
    assert verified == cited

    # The Planner's ledger holds the same line and is a different object entirely: it is
    # never handed to a worker, so it can never be the ledger a finding is checked against.
    assert planner_reader.ledger is not worker_reader.ledger
    assert planner_reader.ledger.lines


def test_a_repeated_look_before_deciding_does_not_end_the_round(project, monkeypatch):
    """The duplicate brake is an exploration brake, and only that.

    The decision phase kept its tools, so a Planner that re-checks a listing and an
    overview it already has -- the re-checks the pinned answers exist to make cheap --
    used to reach the round-wide duplicate count and lose the round it was about to
    decide.  A live run lost all three of its rounds that way and planned nothing at all.
    Here exploration really reads the project and ends on its own allowance, and the
    decision phase opens by asking for two things it already has: both are refused as
    duplicates, and the round still ends in a decision.
    """
    script = {
        # Exploration really reads the project, one call per step, and ends on its own
        # allowance rather than by choosing to stop.
        "planner_explore": [
            call("get_project_map"),
            call("list_tree", path="", depth=2),
            call("search_code", query="readfile"),
        ],
        "planner_decision": [
            # The overview and the root listing, both already answered this round, asked
            # for in one step -- as one response used to carry both calls.
            code("print(get_project_map())\nprint(list_tree(path='', depth=2))"),
            final_answer(decision_payload()),
        ],
    }

    result, events, _ = run_round(monkeypatch, project, script)

    assert result["decision"] is not None, result
    reused = [
        item for item in events
        if item["kind"] == "tool_result" and item["status"] == "duplicate"
    ]
    assert [item["tool"] for item in reused] == ["get_project_map", "list_tree"]
    assert any(item["kind"] == "agent_phase" and item["phase"] == "planner_decision" for item in events)


def test_a_model_that_only_ever_calls_tools_still_publishes_the_round(project, monkeypatch):
    """The host, not the model, decides that a round ends in a decision.

    Every phase that still has tools is answered with another tool call -- the shape of a
    live run that spent all three of its rounds browsing and planned nothing at all.  The
    confirmation allowance is a slice rather than the round's remainder, and when it runs
    out the host withdraws the tools and asks for the decision alone, so the round's one
    required output no longer depends on the model choosing to stop.
    """
    # A different query every time: the point here is a model that never stops asking,
    # not one that repeats itself -- so the scripted step is a callable that numbers its
    # own calls, and ``Always`` is what makes it unending.
    asked = itertools.count(1)
    never_stops = Always([lambda messages: call("search_code", query=f"needle-{next(asked)}")])
    script = {
        "planner_explore": never_stops,
        "planner_decision": never_stops,
        "planner_publish": [final_answer(decision_payload())],
    }

    policy = AgentPolicy(request_seconds=0.5)
    result, events, _ = run_round(monkeypatch, project, script, policy=policy)

    assert result["decision"] is not None, result
    withdrawn = [item for item in events if item["kind"] == "planner_tools_withdrawn"]
    assert [item["reason"] for item in withdrawn] == ["budget"]
    phases = [item["phase"] for item in events if item["kind"] == "model_request"]
    # Exploration, then the bounded confirmation slice, then the phase with no tools: the
    # allowance is what the policy says it is, and nothing the model does extends it.
    assert phases.count("planner_decision") == policy.decision_confirmations
    assert phases[-1] == "planner_publish"
    assert not [item for item in events if item["kind"] == "tool_call" and item["phase"] == "planner_publish"]
