"""Reconnaissance is a bounded navigation aid, never a source of evidence.

The recon sub-agent exists so the Planner can look at a project it does not understand
yet.  Three properties make that safe, and each is pinned here: its reads live in their
own ledger, its requests and its call ids stay out of the Planner's, and every way it can
fail ends in an empty brief instead of a failed run.
"""
import asyncio
import io
import zipfile

import pytest

from audit import agent, recon
from audit.config import ModelConfig
from audit.runtime import AgentPolicy
from audit.source import SourceRepository
from tests.code_model import ModelFactory, call, final_answer

CONFIG = ModelConfig(model="test", base_url="https://example.invalid", api_key="private-test-key")

FILES = {
    "public/index.php": "<?php\nrequire '../src/bootstrap.php';\nrouter();\n",
    "src/bootstrap.php": (
        "<?php\n"
        "function router() { return db(); }\n"
        "function db() { return new PDO('sqlite::memory:'); }\n"
    ),
    "config/app.yaml": "database: sqlite\n",
    "static/app.js": "fetch('/api/users');\n",
}


class Project:
    def __init__(self, repository, snapshot, project_map):
        self.repository = repository
        self.snapshot = snapshot
        self.project_map = project_map

    @property
    def snapshot_id(self):
        return self.snapshot["id"]

    def line_count(self, path):
        record = next(item for item in self.project_map["files"] if item["path"] == path)
        return record["line_count"]


@pytest.fixture
def project(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, content in FILES.items():
            archive.writestr(path, content)
    repository = SourceRepository(tmp_path / "source-data")
    snapshot = repository.import_zip(stream.getvalue(), "project.zip")
    return Project(repository, snapshot, repository.build_project_map(snapshot["id"], None))


def planner_decision_payload():
    return {
        "goal_state": "continue",
        "basis_summary": "侦察线索指出数据库访问集中在 src/bootstrap.php。",
        "next_action": "让 worker 读取入口与 bootstrap 的原始行。",
        "missing_context": [],
        "tasks": [{
            "task_key": "entry-db",
            "title": "入口到数据库访问的路径",
            "objective": "读取入口与 bootstrap，确认请求数据如何进入数据库访问。",
            "acceptance_criteria": "worker 引用两个文件的原始行号。",
            "rationale_summary": "项目图显示入口包含 bootstrap。",
            "source_refs": [
                {"path": "public/index.php", "start_line": 1, "end_line": 3, "reason": "entry"},
                {"path": "src/bootstrap.php", "start_line": 1, "end_line": 3, "reason": "db"},
            ],
            "scope_paths": [],
            "target_symbols": ["db"],
            "dependencies": [],
            "query_hints": ["db"],
            "priority": 80,
        }],
        "updates": [],
    }


def recon_run(monkeypatch, script, project):
    """Run one reconnaissance pass against the real snapshot.

    Recon is driven the way production drives it -- one code-action loop behind one gate
    -- and the brief asserted on is the one the *gate* accepted, never whatever the loop
    came back with.
    """
    factory = ModelFactory(script)
    monkeypatch.setattr(recon, "build_code_model", factory)
    events = []
    result = asyncio.run(recon.run_recon(
        repository=project.repository,
        snapshot_id=project.snapshot_id,
        project_map=project.project_map,
        allowed_paths=None,
        question="这个项目应该从哪里开始读？",
        objective="找出从 HTTP 入口到数据库访问的路径。",
        success_criteria="每条结论引用原始源码行号。",
        config=CONFIG,
        policy=AgentPolicy(request_seconds=0.5),
        emit=events.append,
        budget_seconds=8.0,
        round_no=1,
    ))
    return result, events, factory


def test_recon_brief_drops_everything_the_host_cannot_confirm(monkeypatch, project):
    """A hallucinated path costs one entry, not a retry: the rest of the brief is usable."""
    script = [
        call("read_file", path="src/bootstrap.php", start=1, end=2),
        final_answer({
            "summary": "这是一个 PHP 前端控制器项目，数据库访问集中在 src/bootstrap.php。",
            "layout": [
                {"path": "src", "role": "application code", "notes": "引导与路由"},
                {"path": "vendor", "role": "dependencies", "notes": "本项目并不存在"},
            ],
            "entry_candidates": [
                {"path": "public/index.php", "start_line": 1, "end_line": 3, "why": "前端控制器"},
                {"path": "src/ghost.php", "start_line": 1, "end_line": 2, "why": "编造的路径"},
            ],
            "data_stores": [{"path": "src/bootstrap.php", "start_line": 1, "end_line": 99, "why": "PDO"}],
            "security_boundaries": [],
            "reading_plan": [{"path": "../etc/passwd", "start_line": 1, "end_line": 2, "why": "越界尝试"}],
            "uncertainties": ["运行时路由未确认"],
        }),
    ]

    result, _events, _factory = recon_run(monkeypatch, script, project)
    brief = result["brief"]

    assert [item["path"] for item in brief["layout"]] == ["src"]
    assert [item["path"] for item in brief["entry_candidates"]] == ["public/index.php"]
    assert brief["reading_plan"] == []
    # The line range is clamped to what the file really has, never left to over-claim.
    assert brief["data_stores"] == [{
        "path": "src/bootstrap.php",
        "start_line": 1,
        "end_line": project.line_count("src/bootstrap.php"),
        "why": "PDO",
    }]
    # ``files_examined`` is the host's read record, not the model's claim.
    assert brief["files_examined"] == ["src/bootstrap.php"]
    assert {item["path"] for item in brief["reads"]} == {"src/bootstrap.php"}
    assert {item["start_line"] for item in brief["reads"]} == {1, 2}
    assert "不是 finding 证据" in brief["notice"]


def test_recon_failure_leaves_the_planner_round_alive(monkeypatch, project):
    """A broken recon model must not abort the run: planning continues without a brief."""

    # The round holds back what a decision costs, so at this allowance exploration has
    # nothing to spend and the single recon call is the decision phase's own -- which is
    # where the model has to be able to ask a question and still hand the decision in.
    script = {"planner_decision": [
        call("investigate_project", question="从哪里开始读？"),
        final_answer(planner_decision_payload()),
    ]}
    # Recon's own client is the broken half: a scripted step that is an exception is what
    # the provider being down looks like from inside the sub-agent's loop.
    recon_factory = ModelFactory([RuntimeError("recon provider is down")])

    monkeypatch.setattr(agent, "build_code_model", ModelFactory(script))
    monkeypatch.setattr(recon, "build_code_model", recon_factory)
    events = []
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=project.project_map,
        run_context={"goal": {}, "tasks": [], "plans": []},
        task={"objective": "找出从 HTTP 入口到数据库访问的路径。", "success_criteria": "每条结论引用原始源码行号。"},
        round_no=1,
        config=CONFIG,
        budgets={"responses": 4, "tools": 4, "seconds": 8},
        policy=AgentPolicy(request_seconds=0.5),
        repository=project.repository,
        snapshot_id=project.snapshot_id,
        allowed_paths=None,
        on_event=events.append,
    ))

    # One request: the sub-agent opened its loop, the provider refused, and recon stopped
    # there rather than retrying the round away.
    assert len(recon_factory.built().requests) == 1
    assert result["decision"] is not None, result
    terminal = [event for event in events if event["kind"] == "recon_terminal"]
    assert [event["reason"] for event in terminal] == ["internal_error"]
    # Every recon event is labelled as reconnaissance, so the timeline cannot mistake
    # it for Planner activity.
    assert all(event["role"] == "recon" for event in events if event["kind"].startswith("recon_"))
    assert "recon provider is down" in terminal[0]["error"]


def test_recon_requests_and_spans_stay_out_of_the_planner(monkeypatch, project):
    """Recon spends its own budget, and its tool spans never merge with the Planner's."""
    factory = ModelFactory({"planner_decision": [
        call("investigate_project", question="数据库访问集中在哪？"),
        final_answer(planner_decision_payload()),
    ]})
    recon_factory = ModelFactory([
        call("grep", query="PDO"),
        final_answer({
            "summary": "数据库访问集中在 src/bootstrap.php 的 db() 函数。",
            "entry_candidates": [{"path": "public/index.php", "start_line": 1, "end_line": 3, "why": "入口"}],
        }),
    ])

    monkeypatch.setattr(agent, "build_code_model", factory)
    monkeypatch.setattr(recon, "build_code_model", recon_factory)
    events = []
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=project.project_map,
        run_context={"goal": {}, "tasks": [], "plans": []},
        task={"objective": "找出从 HTTP 入口到数据库访问的路径。", "success_criteria": "每条结论引用原始源码行号。"},
        round_no=1,
        config=CONFIG,
        budgets={"responses": 4, "tools": 4, "seconds": 8},
        policy=AgentPolicy(request_seconds=0.5),
        repository=project.repository,
        snapshot_id=project.snapshot_id,
        allowed_paths=None,
        on_event=events.append,
    ))

    assert result["decision"] is not None, result
    recon_requests = len(recon_factory.built().requests)
    assert recon_requests == 2  # one tool step and one brief
    # The Planner terminal usage counts only the Planner's own requests; recon's two
    # requests never appear in it.
    planner_calls = len(factory.prompts)
    planner_terminal = [event for event in events if event["kind"] == "planner_agent_terminal"][-1]
    assert planner_terminal["usage"]["requests"] < planner_calls + recon_requests

    recon_tools = [
        event for event in events
        if event["kind"] in {"tool_call", "tool_result"} and event.get("role") == "recon"
    ]
    assert recon_tools and all(event["call_id"].startswith("recon-tool-") for event in recon_tools)
    planner_tools = [
        event for event in events
        if event["kind"] == "tool_call" and event.get("role") != "recon"
    ]
    assert planner_tools and all(event["call_id"].startswith("planner-tool-") for event in planner_tools)
    assert {event["call_id"] for event in recon_tools}.isdisjoint({event["call_id"] for event in planner_tools})


def test_a_second_reconnaissance_call_in_the_same_round_is_refused(monkeypatch, project):
    """New questions per round are capped: recon informs the decision, it does not replace it.

    The cap counts *new* questions only.  Asking one that the run already had answered is
    replayed from the pinned record and costs no reconnaissance at all -- see
    ``test_planner_pins.py`` for that half.
    """
    recon_factory = ModelFactory([
        final_answer({"summary": "这是一个 PHP 前端控制器项目，数据库访问集中在 src/bootstrap.php。"}),
    ])

    # The first question is asked while exploring, the second one after the host has said
    # exploration is over: the cap is per round, not per phase, so the second is refused
    # wherever it is asked from.  The allowance has to leave exploration the one request
    # the first question needs -- the reserve is the decision's, not reconnaissance's.
    script = {
        "planner_explore": [call("investigate_project", question="第 1 次侦察")],
        "planner_decision": [
            call("investigate_project", question="第 2 次侦察"),
            final_answer(planner_decision_payload()),
        ],
    }

    monkeypatch.setattr(agent, "build_code_model", ModelFactory(script))
    monkeypatch.setattr(recon, "build_code_model", recon_factory)
    events = []
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=project.project_map,
        run_context={"goal": {}, "tasks": [], "plans": []},
        task={"objective": "找出从 HTTP 入口到数据库访问的路径。", "success_criteria": "每条结论引用原始源码行号。"},
        round_no=1,
        config=CONFIG,
        budgets={"responses": 6, "tools": 4, "seconds": 8},
        policy=AgentPolicy(request_seconds=0.5, recon_calls_per_round=1),
        repository=project.repository,
        snapshot_id=project.snapshot_id,
        allowed_paths=None,
        on_event=events.append,
    ))

    assert result["decision"] is not None, result
    assert len(recon_factory.built().requests) == 1
    refusals = [
        event for event in events
        if event["kind"] == "tool_result" and event.get("tool") == "investigate_project"
        and event.get("status") == "context_missing"
    ]
    assert len(refusals) == 1
    assert "侦察调用已用尽" in refusals[0]["preview"]


def test_disabled_reconnaissance_reports_itself_instead_of_failing(monkeypatch, project):
    """A run with recon switched off must still plan, and must say why no brief exists."""

    # The model asks for recon in both phases that still have tools -- the shape of a
    # Planner that will not take no for an answer -- and only answers once the host has
    # withdrawn them, which is what a disabled recon has to survive.
    script = {
        "planner_explore": [call("investigate_project", question="从哪里开始读？")],
        "planner_decision": [
            call("investigate_project", question="从哪里开始读？"),
            final_answer(planner_decision_payload()),
        ],
        "planner_publish": [final_answer(planner_decision_payload())],
    }

    # A script that fails loudly: disabled reconnaissance must not open a loop, so this is
    # only ever reached if the guard is gone.
    recon_factory = ModelFactory([AssertionError("recon must not call the model when it is disabled")])

    monkeypatch.setattr(agent, "build_code_model", ModelFactory(script))
    monkeypatch.setattr(recon, "build_code_model", recon_factory)
    events = []
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=project.project_map,
        run_context={"goal": {}, "tasks": [], "plans": []},
        task={"objective": "找出从 HTTP 入口到数据库访问的路径。", "success_criteria": "每条结论引用原始源码行号。"},
        round_no=1,
        config=CONFIG,
        # Exploration only gets what the round holds back from the decision's own reserve,
        # so the allowance has to leave it at least the one recon call this test is about.
        budgets={"responses": 6, "tools": 4, "seconds": 8},
        policy=AgentPolicy(request_seconds=0.5, recon_enabled=False),
        repository=project.repository,
        snapshot_id=project.snapshot_id,
        allowed_paths=None,
        on_event=events.append,
    ))

    assert result["decision"] is not None, result
    # Not even the client is built, let alone a request sent.
    assert recon_factory.model is None
    skipped = [event for event in events if event["kind"] == "recon_skipped"]
    assert [event["reason"] for event in skipped] == ["disabled"]
    assert not [event for event in events if event["kind"] == "recon_terminal"]
