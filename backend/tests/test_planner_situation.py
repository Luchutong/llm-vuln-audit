"""Every round is handed the whole run's situation, and may act on none of it.

The Planner is rebuilt each round with no memory of the last one, so "do not dispatch this
again" cannot be left to the model asking the right question -- and until now it was: the
prompt carried the last eight task summaries, which is exactly the point past which a
settled direction becomes invisible and comes back under a new name.  The host prefetches
the frontier, every settled direction, every persisted finding and every pinned
investigation into the prompt instead (the same move ARTEX makes with its per-round graph
overview), and the one hard rule travels with it: a round may legitimately dispatch nothing
while work is in flight, and may not when the frontier is empty.
"""
from __future__ import annotations

import asyncio
import io
import json
import zipfile
from types import SimpleNamespace

import pytest

from audit import agent
from audit.config import ModelConfig
from audit.runtime import AgentPolicy, Execution
from audit.source import SourceRepository
from tests.code_model import Always, ModelFactory, final_answer

CONFIG = ModelConfig(model="test", base_url="https://example.invalid", api_key="private-test-key")

FILES = {
    "public/index.php": "<?php\nrequire '../src/bootstrap.php';\nrouter();\n",
    "src/bootstrap.php": (
        "<?php\n"
        "function router() { return handle(); }\n"
        "function handle() { return readfile($_GET['f']); }\n"
    ),
}

TASK = {"objective": "找出从 HTTP 入口到文件读取的路径。", "success_criteria": "结论引用原始源码行号。"}


@pytest.fixture
def project(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, text in FILES.items():
            archive.writestr(path, text)
    repository = SourceRepository(tmp_path / "source-data")
    snapshot = repository.import_zip(stream.getvalue(), "situation.zip")
    return SimpleNamespace(
        repository=repository,
        snapshot_id=snapshot["id"],
        project_map=repository.build_project_map(snapshot["id"], None),
    )


def empty_decision() -> dict:
    return {
        "goal_state": "continue",
        "basis_summary": "前沿里已有在跑的方向，本轮不新增。",
        "next_action": "等待在跑的任务回收证据。",
        "missing_context": [],
        "tasks": [],
        "updates": [],
    }


def decide(script=None) -> dict:
    """A script in which the model reads the situation and hands a decision in.

    With the budget these tests use, exploration has nothing to spend, so the decision
    phase is the only one that runs -- and its request is the one the situation block has
    to reach.  The prompt text is read back through ``ModelFactory.prompts`` rather than
    captured by a wrapping provider: the request is the same request either way.
    """
    return {"planner_decision": script or [final_answer(empty_decision())]}


def run_round(monkeypatch, project, script, *, run_context=None):
    factory = ModelFactory(script)
    monkeypatch.setattr(agent, "build_code_model", factory)
    events: list[dict] = []
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=project.project_map,
        run_context=run_context or {"goal": {"id": "goal-1"}, "tasks": [], "plans": []},
        task=TASK,
        round_no=1,
        config=CONFIG,
        budgets={"responses": 4, "tools": 4, "seconds": 8},
        policy=AgentPolicy(request_seconds=0.5),
        repository=project.repository,
        snapshot_id=project.snapshot_id,
        allowed_paths=None,
        on_event=events.append,
    ))
    return result, events, factory.prompts


def prior_run_context() -> dict:
    return {
        "goal": {"id": "goal-1", "objective": "找出文件读取路径", "success_criteria": "引用行号", "status": "open"},
        "tasks": [
            {
                "task_key": "entry-read", "state": "completed", "attempts": 1,
                "title": "入口到文件读取", "dependencies": [],
                "result": {"summary": "handle 直接把 $_GET['f'] 交给 readfile。"},
            },
            {
                "task_key": "auth-check", "state": "running", "attempts": 1,
                "title": "鉴权边界", "dependencies": ["entry-read"],
                "result": {},
            },
            {
                "task_key": "config-load", "state": "exhausted", "attempts": 3,
                "title": "配置加载", "dependencies": [],
                "result": {"summary": "两次尝试都读不到配置入口。"},
            },
        ],
        "findings": [
            {
                "id": "f-1", "category": "path_traversal", "finding_kind": "vulnerability",
                "title": "未过滤的文件读取", "severity": "high", "validation_state": "validated",
                "verdict": None, "paths": ["src/bootstrap.php"],
            },
        ],
        "investigations": {"total": 2, "by_status": {"active": 2}, "recent": [{"topic_key": "k", "payload": None}]},
    }


def test_the_round_is_told_the_frontier_settled_work_findings_and_pins(monkeypatch, project):
    """The four things a round must not have to ask for, in one prefetched block."""
    _, events, prompts = run_round(monkeypatch, project, decide(), run_context=prior_run_context())

    prompt = prompts[0]
    assert "# 本轮态势" in prompt
    situation = json.loads(prompt.split("# 本轮态势", 1)[1].split("\n# 覆盖统计", 1)[0].split("\n", 1)[1])
    # In flight, and the round can see it: this is what makes a zero-dispatch round legal.
    assert [item["task_key"] for item in situation["frontier"]] == ["auth-check"]
    # Settled directions arrive with their conclusion, which is what stops re-dispatching.
    settled = {item["task_key"]: item for item in situation["settled"]}
    assert set(settled) == {"entry-read", "config-load"}
    assert "readfile" in settled["entry-read"]["result_summary"]
    assert "读不到" in settled["config-load"]["result_summary"]
    # Findings are the durable conclusions, not summaries of them.
    assert [item["id"] for item in situation["findings"]] == ["f-1"]
    assert situation["findings"][0]["paths"] == ["src/bootstrap.php"]
    assert situation["counts"] == {
        "frontier": 1, "settled": 2, "findings": 1, "observations": 0, "pinned_investigations": 2,
        "project_findings": 0,
    }
    assert "允许本轮派出 0 个任务" in situation["dispatch_rule"] or "0 个任务" in situation["dispatch_rule"]

    # The same block is what a reviewer reads back, so "the Planner ignored it" can be told
    # apart from "the host never had it".
    prepared = [event for event in events if event["kind"] == "planner_situational_prepared"]
    assert len(prepared) == 1
    assert prepared[0]["frontier"] == ["auth-check"]
    assert prepared[0]["settled"] == ["entry-read", "config-load"]
    assert prepared[0]["finding_ids"] == ["f-1"]
    assert prepared[0]["counts"]["pinned_investigations"] == 2


def test_a_round_may_dispatch_nothing_while_the_frontier_has_work(monkeypatch, project):
    """A5's hard floor: the frontier is the gate, not "every round must produce a task"."""
    result, events, _ = run_round(monkeypatch, project, decide(), run_context=prior_run_context())

    assert result["decision"] is not None, result
    assert result["decision"]["tasks"] == []
    assert result["decision"]["goal_state"] == "continue"


def test_a_round_cannot_dispatch_nothing_out_of_an_empty_frontier(monkeypatch, project):
    """...and the other half of the floor: an empty frontier plus an unmet goal is a refusal.

    Without this the round would end with nothing running and the goal still open, which the
    host can only settle as inconclusive.
    """
    # A model that keeps re-submitting the same refused decision: the correction
    # allowance is what it spends, and the round still ends without one.
    result, events, _ = run_round(
        monkeypatch, project,
        {"planner_decision": Always([final_answer(empty_decision())])},
        run_context={"goal": {"id": "goal-1", "status": "open"}, "tasks": [], "plans": []},
    )

    assert result["decision"] is None, result
    assert result["terminal_reason"] != "completed"
    rendered = json.dumps(events, ensure_ascii=False)
    assert "前沿为空" in rendered


def test_the_situation_drops_the_oldest_entries_and_says_so():
    """A byte cap on this block must never shorten the frontier or lie about the totals."""
    situation = {
        "goal": {"status": "open"},
        "frontier": [{"task_key": "live", "title": "在跑的方向"}],
        "settled": [
            {"task_key": f"old-{number}", "result_summary": "结论摘要" * 40} for number in range(60)
        ],
        "findings": [{"id": f"f-{number}", "title": "标题" * 40} for number in range(60)],
        "pinned_investigations": {"total": 0},
        "counts": {"frontier": 1, "settled": 60, "findings": 60, "pinned_investigations": 0},
        "dispatch_rule": "规则",
        "notice": "说明",
    }

    bounded = agent._bound_situation(situation, limit=8 * 1024)

    assert [item["task_key"] for item in bounded["frontier"]] == ["live"]
    assert bounded["omitted"]["settled"] > 0 and bounded["omitted"]["findings"] > 0
    # Newest kept, oldest dropped, and the totals still describe the real run.
    assert bounded["settled"][-1]["task_key"] == "old-59"
    assert bounded["findings"][-1]["id"] == "f-59"
    assert bounded["counts"]["settled"] == 60 and bounded["counts"]["findings"] == 60
    assert "省去了" in bounded["notice"]
    assert len(agent._planner_json(bounded, limit=8 * 1024).encode("utf-8")) <= 8 * 1024

    # A block that already fits is handed over untouched -- no omitted marker, no rewriting.
    small = agent._bound_situation({**situation, "settled": [], "findings": []}, limit=8 * 1024)
    assert "omitted" not in small
    assert small["notice"] == "说明"


def test_the_history_tool_carries_the_findings_the_trim_points_it_at():
    """The trimmed block names get_task_results as the way to see the rest, so it must have it.

    A pointer to a tool that returns less than promised is worse than no pointer: the round
    would conclude the older conclusions no longer exist.
    """
    history = agent._planner_task_results(prior_run_context())

    assert [item["id"] for item in history["findings"]] == ["f-1"]
    assert history["findings"][0]["paths"] == ["src/bootstrap.php"]
    assert [item["task_key"] for item in history["tasks"]] == ["entry-read", "auth-check", "config-load"]


def test_the_situation_lists_pins_without_their_bodies_and_the_tool_returns_one():
    """Payloads stay out of the prompt (ARTEX keeps a report out of its list view too)."""
    execution = Execution({"responses": 8, "tools": 8, "seconds": 5}, AgentPolicy(), lambda event: None)
    execution.enter("planner")

    class Pins:
        def list_investigations(self, run_id, **kwargs):
            assert kwargs.get("include_payload") is True
            return [{
                "id": "inv-1", "run_id": run_id, "topic": "项目从哪里开始读？", "topic_key": "abc",
                "kind": "recon", "tool": "investigate_project", "round_no": 1, "revision": 1,
                "status": "active", "reason": None, "superseded_by": None,
                "files_read": ["public/index.php"], "payload": {"summary": "这是一个 PHP 前端控制器。"},
            }]

    situation = agent._planner_situation({
        "goal": {}, "tasks": [], "findings": [],
        "investigations": {"total": 1, "by_status": {"active": 1}, "recent": [{"topic_key": "abc"}]},
    })
    assert "payload" not in json.dumps(situation["pinned_investigations"])

    deps = agent.PlannerDeps(
        project_map={"files": []}, run_context={}, execution=execution,
        pins=Pins(), run_id="run-1", policy=AgentPolicy(),
    )
    detail = json.loads(asyncio.run(deps.call("get_investigation", {"index": 1})))
    assert detail["payload"]["summary"] == "这是一个 PHP 前端控制器。"
    assert detail["files_read"] == ["public/index.php"]
    assert "不会因为现在再问一次而变化" in detail["notice"]

    # An out-of-range or unattached lookup is a *refusal answer*, like every other tool
    # failure on this surface -- the round continues and the Planner can correct itself.
    refused = asyncio.run(deps.call("get_investigation", {"index": 9}))
    assert "超出范围" in refused
    bare = agent.PlannerDeps(project_map={"files": []}, run_context={}, execution=execution)
    assert "固定调查记录" in asyncio.run(bare.call("get_investigation", {"index": 1}))


def closure_context(**overrides) -> dict:
    """A run that has one standing conclusion and nothing being worked on."""
    completed = {
        "task_key": "entry-read", "state": "completed", "attempts": 1,
        "title": "入口到文件读取", "dependencies": [],
        "result": {"summary": "handle 直接把 $_GET['f'] 交给 readfile。"},
    }
    finding = {
        "id": "f-1", "unit_id": "entry-read", "category": "task_goal_vulnerability",
        "finding_kind": "vulnerability", "title": "未过滤的文件读取", "severity": "high",
        "summary": "入口把请求参数直接交给 readfile。", "validation_state": "candidate",
        "verdict": None, "disposition": "open", "revision": 1, "paths": ["src/bootstrap.php"],
    }
    return {
        "goal": {"id": "goal-1", "objective": "找出文件读取路径", "success_criteria": "引用行号", "status": "open"},
        "tasks": [completed],
        "findings": [finding],
        **overrides,
    }


def test_the_situation_says_when_the_round_is_the_run_s_last_look_at_its_own_result():
    """Doing nothing in this round means "the conclusion stands", so the round is told.

    The host closes a run on a conclusion it can verify, and it runs one Planner round first
    so that conclusion can still be corrected.  The round cannot infer that from an empty
    frontier alone -- an empty frontier is equally consistent with "nothing has been
    dispatched yet" -- so the block states it, and states what silence is taken to mean.
    """
    situation = agent._planner_situation(closure_context())

    assert situation["closure_review"] is True
    assert "收束前复核" in situation["notice"]
    assert "什么都不改" in situation["notice"]
    assert "reopen/retract/duplicate" in situation["notice"]

    # A direction the host is holding back still counts as nothing running -- and the round
    # has to say something if it wants it run, which is what this notice is for.
    ready = {
        "task_key": "file-operation", "state": "ready", "attempts": 0,
        "title": "文件操作", "dependencies": [], "result": {},
    }
    held = agent._planner_situation(closure_context(tasks=[closure_context()["tasks"][0], ready]))
    assert held["closure_review"] is True

    # Work in flight: the host is not at a closure point, so this round is an ordinary one.
    running = closure_context(tasks=[{**closure_context()["tasks"][0], "state": "running"}])
    assert agent._planner_situation(running)["closure_review"] is False


def test_a_conclusion_that_cannot_close_the_run_is_not_reviewed():
    """Only the conclusion the host would actually close on makes a round a review."""
    base = closure_context()["findings"][0]
    for override in (
        {"validation_state": "invalid_evidence"},
        {"disposition": "retracted"},
        {"disposition": "duplicate"},
        {"disposition": "superseded"},
        {"finding_kind": "security_boundary", "severity": "informational"},
        {"finding_kind": "data_flow", "severity": "low"},
        {"severity": "informational"},
    ):
        situation = agent._planner_situation(closure_context(findings=[{**base, **override}]))
        assert situation["closure_review"] is False, override
        assert "收束前复核" not in situation["notice"], override


def test_historical_safe_records_and_new_observations_remain_visible_without_counting_as_findings():
    context = closure_context()
    context["tasks"][0]["id"] = "entry-read"
    observation = {
        "title": "文件名规范化处理",
        "kind": "security_boundary",
        "summary": "输入路径在进入文件写入前使用 basename 取得文件名。",
        "evidence": "src/bootstrap.php:2-3",
    }
    context["tasks"][0]["result"]["observations"] = [observation]
    context["findings"][0].update(finding_kind="source_observation", severity="informational")

    situation = agent._planner_situation(context)
    history = agent._planner_task_results(context)
    for block in (situation, history):
        assert block["findings"] == []
        assert len(block["observations"]) == 2
        historical, current = block["observations"]
        assert historical["id"] == "f-1"
        assert historical["task_key"] == "entry-read"
        assert current["evidence"] == observation["evidence"]
        assert current["summary"] == observation["summary"]
    assert situation["closure_review"] is False
    assert situation["counts"]["observations"] == 2
    assert "goal_state=met" not in situation["notice"]


def test_observations_are_trimmed_structurally_with_true_totals():
    situation = agent._planner_situation({
        "tasks": [{"task_key": "read-upload", "state": "completed", "observations": [{
            "title": f"排查依据{number}", "kind": "data_flow", "summary": "排查说明" * 160,
            "evidence": "src/upload.php:1-20",
        } for number in range(30)]}],
    })
    bounded = agent._bound_situation(situation, limit=4 * 1024)
    assert bounded["omitted"]["observations"] > 0
    assert bounded["counts"]["observations"] == 30
    assert bounded["observations"][-1]["title"] == "排查依据29"
    assert len(json.dumps(bounded, ensure_ascii=False).encode("utf-8")) < 5 * 1024


def test_the_project_ledger_and_verification_state_travel_with_the_situation():
    """A new conversation must see what the project already concluded, and how sure it is."""
    context = {
        "goal": {"id": "goal-1", "status": "open"},
        "tasks": [],
        "findings": [],
        "project": {
            "id": "project-1", "name": "DVWA", "content_key": "abc",
            "target_profile": "dvwa",
        },
        "project_findings": [{
            "id": "pf-1", "revision": 2, "title": "SQL 注入", "file_path": "vulnerabilities/sqli/index.php",
            "symbol": "index", "severity": "high", "disposition": "open",
            "verification_status": "verified", "verification_verdict": "confirmed",
            "origin_run_id": "run-1", "paths": ["vulnerabilities/sqli/index.php"],
        }],
        "verification_summary": {"verified": 1},
    }

    situation = agent._planner_situation(context)

    assert situation["project"]["name"] == "DVWA"
    assert situation["project_findings"][0]["already_known"] is True
    assert situation["project_findings"][0]["verification_status"] == "verified"
    assert situation["verification_summary"] == {"verified": 1}
    assert situation["counts"]["project_findings"] == 1
    # A verified project conclusion is grounds for a closure review, with the frontier quiet.
    assert situation["closure_review"] is True
    assert "project_updates" in situation["notice"]


def test_ledger_trimming_keeps_verified_and_rejected_rows_over_unverified_leads():
    rows = [
        {
            "id": f"pf-{number}", "title": "台账结论" * 20, "file_path": "src/app.php",
            "symbol": "handle", "severity": "high", "disposition": "open",
            "verification_status": "verified" if number == 0 else (
                "rejected" if number == 1 else "unverified"
            ),
        }
        for number in range(30)
    ]
    situation = agent._planner_situation({"tasks": [], "project_findings": rows})

    bounded = agent._bound_situation(situation, limit=4 * 1024)

    kept = {item["id"] for item in bounded["project_findings"]}
    assert {"pf-0", "pf-1"}.issubset(kept)
    assert bounded["omitted"]["project_findings"] > 0
    assert bounded["counts"]["project_findings"] == 30
