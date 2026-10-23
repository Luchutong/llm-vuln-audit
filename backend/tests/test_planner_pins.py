"""A round reuses what the run already paid for, and says so.

Every round builds a fresh Planner with no memory of the last one, so without these
records round 5 asks round 2's question again and gets a newly generated answer for it --
paying twice and planning against something that may no longer match what earlier rounds
acted on.  Pinning makes the second ask free and byte-identical, and makes the *first*
ask of a revised question an explicit, recorded revision.
"""
from __future__ import annotations

import asyncio
import json
import io
import zipfile
from types import SimpleNamespace

import pytest

from audit import agent, recon
from audit.config import ModelConfig
from audit.db import Store
from audit.runtime import AgentPolicy
from audit.source import SourceRepository
from tests.code_model import ModelFactory, call, final_answer

CONFIG = ModelConfig(model="test", base_url="https://example.invalid", api_key="private-test-key")

FILES = {
    "public/index.php": "<?php\nrequire '../src/bootstrap.php';\nrouter();\n",
    "src/bootstrap.php": (
        "<?php\n"
        "function router() { return handle(); }\n"
        "function handle() { return readfile($_GET['f']); }\n"
    ),
    "static/app.js": "fetch('/api/users');\nconsole.log('boot');\n",
}

TASK = {"objective": "找出从 HTTP 入口到文件读取的路径。", "success_criteria": "结论引用原始源码行号。"}


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def project(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, text in FILES.items():
            archive.writestr(path, text)
    repository = SourceRepository(tmp_path / "source-data")
    snapshot = repository.import_zip(stream.getvalue(), "pins.zip")
    return SimpleNamespace(
        repository=repository,
        snapshot_id=snapshot["id"],
        project_map=repository.build_project_map(snapshot["id"], None),
    )


def decision_payload():
    return {
        "goal_state": "continue",
        "basis_summary": "入口包含 bootstrap，文件读取集中在 handle。",
        "next_action": "让 worker 读取入口与 bootstrap。",
        "missing_context": [],
        "tasks": [{
            "task_key": "entry-read",
            "title": "入口到文件读取",
            "objective": "读取入口与 bootstrap，确认请求参数如何到达文件读取。",
            "acceptance_criteria": "worker 引用原始行号。",
            "rationale_summary": "项目图显示入口包含 bootstrap。",
            "source_refs": [{"path": "public/index.php", "start_line": 1, "end_line": 3, "reason": "entry"}],
            "scope_paths": [],
            "target_symbols": ["handle"],
            "dependencies": [],
            "query_hints": ["readfile"],
            "priority": 80,
        }],
        "updates": [],
    }


def tool_then_decide(queued: list[tuple[str, dict]]):
    """Look up the queued calls, then hand the decision in -- all inside exploration.

    The old scripting answered one tool call per request and published once the queue was
    empty.  Code-as-action makes that a script instead: the calls are the model's own
    steps and the decision is, too, so the queue emptying is what makes it stop.  The
    round is the same round -- only what the model writes per request has changed.
    """
    return [call(name, **args) for name, args in queued] + [final_answer(decision_payload())]


def run_round(store, project, monkeypatch, script, *, round_no=1):
    monkeypatch.setattr(agent, "build_code_model", ModelFactory({"planner_explore": script}))
    events: list[dict] = []
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=project.project_map,
        run_context={"goal": {"id": "goal-1"}, "tasks": [], "plans": []},
        task=TASK,
        round_no=round_no,
        config=CONFIG,
        # The round reserves what a decision costs (one request plus its corrections), so
        # the allowance has to cover that reserve as well as the exploration a test drives,
        # including a rejected call and the correction its retry allowance buys.
        budgets={"responses": 8, "tools": 4, "seconds": 8},
        policy=AgentPolicy(request_seconds=0.5),
        repository=project.repository,
        snapshot_id=project.snapshot_id,
        allowed_paths=None,
        pins=store,
        run_id="pins-run",
        plan_id=f"plan-{round_no}",
        on_event=events.append,
    ))
    return result, events


def tool_text(events: list[dict], tool: str) -> str:
    return [event for event in events if event["kind"] == "tool_result" and event["tool"] == tool][-1]["preview"]


def spy_search(project, monkeypatch) -> dict:
    """Count real content searches, so "reused" is measured rather than asserted."""
    calls = {"search": 0}
    original = project.repository.search_code

    def counted(*args, **kwargs):
        calls["search"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(project.repository, "search_code", counted)
    return calls


def test_a_repeated_search_is_replayed_from_the_pin_without_searching_again(store, project, monkeypatch):
    """The second round gets the first round's bytes, and the repository sees one query."""
    calls = spy_search(project, monkeypatch)
    query = {"query": "readfile"}

    _, first = run_round(store, project, monkeypatch, tool_then_decide([("search_code", dict(query))]))
    first_text = tool_text(first, "search_code")
    assert "src/bootstrap.php:3" in first_text
    assert calls["search"] == 1
    pinned = store.list_investigations("pins-run", include_payload=True)
    assert [item["kind"] for item in pinned] == ["search"]
    assert pinned[0]["payload"]["text"].startswith(first_text)

    _, second = run_round(
        store, project, monkeypatch, tool_then_decide([("search_code", dict(query))]), round_no=2
    )

    assert calls["search"] == 1, "the pinned answer must not be re-executed"
    assert tool_text(second, "search_code").startswith(first_text)
    reused = [event for event in second if event["kind"] == "planner_investigation_reused"]
    assert len(reused) == 1
    assert reused[0]["pinned_round"] == 1 and reused[0]["revision"] == 1
    # Only one row: a reuse is not a new pin.
    assert len(store.list_investigations("pins-run")) == 1


def spy_recon(monkeypatch) -> dict:
    """Count real reconnaissance requests, so "re-derived" is measured rather than asserted.

    The counting happens inside the scripted step, which is where a provider request
    really is: a brief that was replayed from its pin never reaches this at all.
    """
    calls = {"n": 0}

    def brief(messages):
        calls["n"] += 1
        return final_answer({"summary": "这是一个 PHP 前端控制器项目，数据库访问集中在 src/bootstrap.php。"})

    # One shared client for the whole test, so the count is of requests rather than of the
    # sub-agents that were built; enough steps that a missing pin would be visible.
    monkeypatch.setattr(recon, "build_code_model", ModelFactory([brief] * 8))
    return calls


def test_revise_supersedes_the_pin_and_appends_a_revision(store, project, monkeypatch):
    """Correcting a pinned answer is an append with a lineage, never an overwrite.

    Only a reconnaissance brief can be corrected: navigation and search read a frozen
    snapshot, so re-asking them could only return the same bytes.  The replaced record
    keeps its own answer and the round that produced it -- the pin table is a history, and
    a history whose old rows are rewritten is not one.
    """
    calls = spy_recon(monkeypatch)
    question = {"question": "这个项目应该从哪里开始读？"}

    run_round(store, project, monkeypatch, tool_then_decide([("investigate_project", dict(question))]))
    assert calls["n"] == 1

    _, events = run_round(
        store, project, monkeypatch,
        tool_then_decide([("investigate_project", {**question, "revise": True})]), round_no=2,
    )

    assert calls["n"] == 2, "revise is the one path that re-runs the investigation"
    rows = store.list_investigations("pins-run", include_payload=True)
    assert [row["revision"] for row in rows] == [1, 2]
    assert rows[0]["status"] == "superseded"
    assert rows[0]["superseded_by"] == rows[1]["id"]
    assert rows[0]["reason"] == "同一话题被重新调查"
    # The replaced record keeps its answer and the round that produced it.
    assert rows[0]["round_no"] == 1 and rows[0]["payload"]["summary"].startswith("这是一个 PHP 前端控制器")
    assert rows[1]["status"] == "active" and rows[1]["round_no"] == 2
    assert [item["kind"] for item in events if item["kind"] == "planner_investigation_superseded"] == [
        "planner_investigation_superseded"
    ]


def test_a_stray_revise_on_a_navigation_tool_cannot_re_run_a_pinned_answer(store, project, monkeypatch):
    """A frozen query has one answer, whatever flags the model attaches to it.

    No navigation or search tool declares `revise` any more, so the flag has no path into
    the pin table: the tool body builds the arguments the host looks the topic up by.  A
    live run sent the flag on nearly every call, which is why the model's habit is driven
    through the real tool schema here rather than asserted about the source: the malformed
    call is rejected, the retry allowance buys one correction, and the corrected call
    replays round one's bytes instead of executing the search again.
    """
    calls = spy_search(project, monkeypatch)
    query = {"query": "readfile"}

    _, first = run_round(store, project, monkeypatch, tool_then_decide([("search_code", dict(query))]))
    first_text = tool_text(first, "search_code")
    assert calls["search"] == 1

    _, second = run_round(
        store, project, monkeypatch,
        tool_then_decide([
            ("search_code", {**query, "revise": True}),  # rejected: the schema has no such flag
            ("search_code", dict(query)),                # the correction the retry buys
        ]),
        round_no=2,
    )

    assert calls["search"] == 1, "a stray flag must not buy a second execution"
    assert tool_text(second, "search_code").startswith(first_text)
    assert [event["kind"] for event in second if event["kind"] == "planner_investigation_reused"] == [
        "planner_investigation_reused"
    ]
    # One row, still active: nothing was superseded and nothing was appended.
    rows = store.list_investigations("pins-run")
    assert [row["revision"] for row in rows] == [1] and rows[0]["status"] == "active"
    assert [event for event in second if event["kind"] == "planner_investigation_superseded"] == []


def test_a_read_window_is_never_pinned(store, project, monkeypatch):
    """Reads are the one tool whose answer must not be copied into the pin table.

    What the Planner read stays in its own ledger and is re-read on demand: storing source
    text in this table would make the pin a second, quieter copy of the project.
    """
    reads = {"count": 0}
    original = project.repository.read_source

    def counted(*args, **kwargs):
        reads["count"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(project.repository, "read_source", counted)
    window = {"path": "src/bootstrap.php", "start": 1, "end": 4}

    _, first = run_round(store, project, monkeypatch, tool_then_decide([("read_source", dict(window))]))
    assert "readfile" in tool_text(first, "read_source")
    run_round(store, project, monkeypatch, tool_then_decide([("read_source", dict(window))]), round_no=2)

    assert reads["count"] == 2
    assert store.list_investigations("pins-run") == []
    assert store.investigation_overview("pins-run")["total"] == 0


def test_a_reconnaissance_brief_is_reused_without_running_recon_again(store, project, monkeypatch):
    """Reconnaissance is the expensive one, and the one a round is most likely to repeat."""
    recon_calls = spy_recon(monkeypatch)
    question = {"question": "这个项目应该从哪里开始读？"}

    _, first = run_round(store, project, monkeypatch, tool_then_decide([("investigate_project", dict(question))]))
    assert recon_calls["n"] == 1
    assert "PHP 前端控制器" in tool_text(first, "investigate_project")
    pinned = store.list_investigations("pins-run", include_payload=True)
    assert [row["kind"] for row in pinned] == ["recon"]
    assert pinned[0]["topic"] == question["question"]
    assert pinned[0]["payload"]["summary"].startswith("这是一个 PHP 前端控制器")

    _, second = run_round(
        store, project, monkeypatch, tool_then_decide([("investigate_project", dict(question))]), round_no=2
    )

    assert recon_calls["n"] == 1, "the pinned brief must be replayed, not re-derived"
    replayed = tool_text(second, "investigate_project")
    assert "PHP 前端控制器" in replayed
    assert json.loads(replayed)["summary"].startswith("这是一个 PHP 前端控制器")
    reused = [event for event in second if event["kind"] == "planner_investigation_reused"]
    assert reused[0]["pinned_round"] == 1
    assert len(store.list_investigations("pins-run")) == 1
