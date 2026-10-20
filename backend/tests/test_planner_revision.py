"""Correcting a recorded conclusion: append a revision, never rewrite the record.

A settled direction is the run's memory of what it concluded, so "this conclusion is
wrong" cannot be answered by writing over it -- the fact that it was concluded, and that
it was later corrected, is itself part of the audit.  ARTEX's correction path is a
follow-up intent derived from the original finding, and this file pins the same shape
here: the settled row is re-opened by appending a revision, the earlier attempts stay
exactly where they are, the attempt allowance is extended rather than spent (a correction
is not a retry), and every refusal says which of those rules the round ran into.
"""
from __future__ import annotations

import asyncio

import pytest
from pydantic_ai import ModelRetry

from audit import agent
from audit import worker as worker_module
from audit.db import Store
from audit.runtime import AgentPolicy
from audit.schemas import PlannerDecision
from audit.source import SourceRepository
from tests.test_goal_tasks import (
    TASK,
    create_planner_run,
    make_worker,
    proposal,
    worker_outcome,
)


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "source-data")


def task_row(store, run, key: str) -> dict:
    return next(item for item in store.list_tasks(run["id"]) if item["task_key"] == key)


def dispatch_one(store, run, key: str = "entry-flow") -> None:
    """Publish one direction in a round of its own."""
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    assert plan is not None
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue",
        basis_summary="先建立入口方向。", tasks=[proposal(key)],
    )


def run_one_attempt(
    store, run, key: str = "entry-flow", *, worker_id: str = "worker-1",
    outcome: str = "no_evidence", summary: str = "第一版结论：入口未做路径校验。",
) -> dict:
    claimed = store.claim_ready_task(run["id"], worker_id)
    assert claimed is not None and claimed["task_key"] == key
    settled = store.resolve_task_attempt(
        claimed["id"], worker_id, outcome=outcome,
        result={"summary": summary, "reasoning": "结论只基于 worker 已读的原始源码范围。"},
        usage={"requests": 1}, seen=[{"path": "public/index.php", "start_line": 1, "end_line": 4}],
    )
    assert settled is not None
    return settled


def correct(store, run, *keys: str, rationale: str = "上一轮的结论基于错误的行窗口，需要重跑。", tasks=None):
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    assert plan is not None
    return store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue",
        basis_summary="更正已结算方向的结论。",
        tasks=list(tasks or []),
        updates=[
            {"task_key": key, "action": "reopen", "rationale_summary": rationale} for key in keys
        ],
        reopen_attempts=1,
    )


def test_a_correction_puts_the_direction_back_on_the_frontier(store, repository):
    run, _ = create_planner_run(store, repository)
    dispatch_one(store, run)
    run_one_attempt(store, run)
    assert task_row(store, run, "entry-flow")["state"] == "completed"

    correct(store, run, "entry-flow")

    row = task_row(store, run, "entry-flow")
    # The row is set to pending and the same transaction re-derives its real state, so a
    # direction whose dependencies are satisfied comes straight back as dispatchable.
    assert row["state"] == "ready"
    assert row["revisions"] == 1
    assert row["error"] is None and row["finished_at"] is None
    # Monotone: the attempt that produced the conclusion being corrected still happened.
    assert row["attempts"] == 1
    assert store.get_planner_session(run["id"])["task_reopens"] == 1


def test_a_revision_extends_the_attempt_allowance_instead_of_spending_it(store, repository):
    """A correction must not be killed by the cap it is correcting under.

    The shared goal budget is what the frontier checks on every claim, so a revision that
    only extended the per-task cap would be re-opened and exhausted in the same breath.
    """
    cap = {**TASK, "max_total_attempts": 1}
    run, _ = create_planner_run(store, repository, task=cap)
    dispatch_one(store, run)
    before = run_one_attempt(store, run)
    assert before["max_attempts"] == 2

    correct(store, run, "entry-flow")

    row = task_row(store, run, "entry-flow")
    assert row["max_attempts"] == 3
    goal = store.get_task_goal(run["id"])
    assert goal["max_total_attempts"] == 2

    # The cap was already spent by the attempt being corrected, so this claim is only
    # possible because the revision raised the shared budget.
    claimed = store.claim_ready_task(run["id"], "worker-2")
    assert claimed is not None and claimed["task_key"] == "entry-flow"
    assert claimed["attempts"] == 1
    assert "exhausted" not in store.task_queue_state(run["id"])["counts"]


def test_the_earlier_attempts_of_a_corrected_direction_are_never_rewritten(store, repository):
    """Append-only, which is what makes "this was corrected" a fact rather than a claim."""
    run, _ = create_planner_run(store, repository)
    dispatch_one(store, run)
    run_one_attempt(store, run, worker_id="worker-1", summary="第一版结论：入口未做路径校验。")
    task_id = task_row(store, run, "entry-flow")["id"]
    before = store.list_task_attempts(task_id)
    assert [row["attempt"] for row in before] == [1]

    correct(store, run, "entry-flow")
    run_one_attempt(
        store, run, worker_id="worker-2", outcome="blocked",
        summary="重跑结论：路径校验在另一个文件里，本方向缺少运行时值。",
    )

    after = store.list_task_attempts(task_id)
    assert [row["attempt"] for row in after] == [1, 2]
    assert after[0] == before[0]
    assert after[1]["state"] == "blocked"
    assert "另一个文件" in after[1]["result"]["summary"]
    # The corrected conclusion is still readable next to the one that replaced it.
    assert after[0]["result"]["summary"].startswith("第一版结论")


def test_re_opening_a_direction_whose_premise_failed_lands_blocked_with_a_reason(store, repository):
    """A revision cannot jump the graph: dependency state still decides the frontier."""
    run, _ = create_planner_run(store, repository)
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue", basis_summary="先建立前置与后续方向。",
        tasks=[proposal("entry-flow"), proposal("sink-flow", dependencies=["entry-flow"])],
    )
    run_one_attempt(store, run, "entry-flow", outcome="blocked", summary="入口方向受阻。")
    assert task_row(store, run, "sink-flow")["state"] == "blocked"

    correct(store, run, "sink-flow")

    row = task_row(store, run, "sink-flow")
    assert row["state"] == "blocked"
    assert "依赖未形成可用结论" in row["error"]
    assert row["revisions"] == 1


# --- refusals ---------------------------------------------------------------


def prior(*, state: str = "completed", revisions: int = 0, key: str = "entry-flow") -> dict:
    return {
        "task_key": key, "state": state, "revisions": revisions,
        "files": ["public/index.php"], "dependencies": [],
    }


def correction(*keys: str) -> PlannerDecision:
    return PlannerDecision.model_validate({
        "goal_state": "continue",
        "basis_summary": "上一轮的结论基于错误的行窗口，需要重跑那个方向。",
        "next_action": "重开该方向并让 worker 重新取证。",
        "missing_context": [],
        "tasks": [],
        "updates": [
            {"task_key": key, "action": "reopen", "rationale_summary": "该结论引用的行窗口属于另一个函数。"}
            for key in keys
        ],
    })


def validate(decision, priors, *, policy=None, run_reopens: int = 0, findings=None):
    return agent._validate_planner_decision(
        decision,
        {"stats": {}, "architecture": {}, "files": [{"path": "public/index.php", "line_count": 4}]},
        priors,
        policy=policy or AgentPolicy(),
        # The duplicate guard only compares directions that concluded something, so the
        # default here is a run whose entry direction already has a finding.
        findings=[{"id": "f-1", "finding_kind": "vulnerability", "severity": "high",
                   "paths": ["public/index.php"]}] if findings is None else findings,
        run_reopens=run_reopens,
    )


def test_a_correction_the_host_would_accept_is_accepted():
    decision = validate(correction("entry-flow"), [prior()])
    assert [item.action for item in decision.updates] == ["reopen"]


def test_a_running_direction_cannot_be_re_opened():
    """It is already being investigated: the frontier will run it, so this is not a correction."""
    with pytest.raises(ModelRetry) as excinfo:
        validate(correction("entry-flow"), [prior(state="running")])
    assert "正在执行" in str(excinfo.value)


def test_a_direction_with_no_conclusion_has_nothing_to_correct():
    message = None
    for state in ("pending", "ready"):
        with pytest.raises(ModelRetry) as excinfo:
            validate(correction("entry-flow"), [prior(state=state)])
        message = str(excinfo.value)
        assert "还没有结论可更正" in message
    # And it says what to do instead rather than only what not to do.
    assert "重新提交" in message
    # A deferral is a live direction too, and comes back the same way.
    with pytest.raises(ModelRetry):
        validate(correction("entry-flow"), [prior(state="deferred")])


def test_the_per_task_revision_allowance_is_a_policy_value():
    policy = AgentPolicy(task_reopens=2)
    validate(correction("entry-flow"), [prior(revisions=1)], policy=policy)
    with pytest.raises(ModelRetry) as excinfo:
        validate(correction("entry-flow"), [prior(revisions=2)], policy=policy)
    assert "已经重开 2 次" in str(excinfo.value)
    # The bar is the policy, not a literal.
    validate(correction("entry-flow"), [prior(revisions=2)], policy=AgentPolicy(task_reopens=3))


def test_the_run_wide_revision_allowance_bounds_the_whole_round():
    """Two corrections in one round cost two of the run's chances, not one."""
    policy = AgentPolicy(run_reopens=1)
    with pytest.raises(ModelRetry) as excinfo:
        validate(
            correction("entry-flow", "sink-flow"),
            [prior(), prior(key="sink-flow")],
            policy=policy,
        )
    assert "重开次数" in str(excinfo.value)
    # The same round is fine while the run still has room.
    validate(
        correction("entry-flow", "sink-flow"),
        [prior(), prior(key="sink-flow")],
        policy=AgentPolicy(run_reopens=2),
    )
    # And a run that already spent them refuses even the first of the round.
    with pytest.raises(ModelRetry):
        validate(correction("entry-flow"), [prior()], policy=policy, run_reopens=1)


def test_a_re_opened_direction_is_no_longer_a_duplicate_target():
    """The guard's exit has to actually work: re-opening frees the file set to be re-read."""
    files = ["public/index.php"]
    with pytest.raises(ModelRetry):
        validate(
            PlannerDecision.model_validate({
                "goal_state": "continue",
                "basis_summary": "重新读取入口文件确认路径处理。",
                "next_action": "派发同一入口方向。",
                "missing_context": [],
                "tasks": [proposal("entry-again")],
                "updates": [],
            }),
            [{**prior(), "files": files}],
        )
    # Re-opened, the direction is pending again: the frontier owns it now, so the guard has
    # nothing to say about a proposal that reads the same files it always read.
    validate(
        PlannerDecision.model_validate({
            "goal_state": "continue",
            "basis_summary": "入口方向正在重跑，另派一条读取同一区域的相邻方向。",
            "next_action": "派发相邻方向。",
            "missing_context": [],
            "tasks": [proposal("entry-neighbour")],
            "updates": [],
        }),
        [{**prior(state="pending", revisions=1), "files": files}],
    )


# --- what the round is told --------------------------------------------------


def test_settled_work_resting_on_a_corrected_direction_is_flagged():
    """The Planner decides whether to follow the correction; the host only tells it."""
    situation = agent._planner_situation({
        "goal": {}, "findings": [], "tasks": [
            {"task_key": "entry-flow", "state": "ready", "revisions": 1, "dependencies": [], "files": []},
            {"task_key": "sink-flow", "state": "completed", "revisions": 0,
             "dependencies": ["entry-flow"], "files": [], "result": {"summary": "后续方向已结算。"}},
            {"task_key": "docs-flow", "state": "completed", "revisions": 0,
             "dependencies": [], "files": [], "result": {"summary": "文档方向已结算。"}},
        ],
    })

    settled = {item["task_key"]: item for item in situation["settled"]}
    assert settled["sink-flow"]["stale_dependency"] == ["entry-flow"]
    assert "stale_dependency" not in settled["docs-flow"]
    assert "stale_dependency" not in situation["frontier"][0]
    assert "stale_dependency" in situation["notice"]
    # The frontier carries the revision count, so a round can tell a re-run from a first run.
    assert situation["frontier"][0]["revisions"] == 1


def test_a_direction_that_already_absorbed_its_correction_stops_flagging_its_successors():
    """Staleness is "under revision right now", not "was revised once".

    Otherwise every later round would keep warning about a premise that has since been
    re-established, and the flag would stop meaning anything.
    """
    situation = agent._planner_situation({
        "goal": {}, "findings": [], "tasks": [
            {"task_key": "entry-flow", "state": "completed", "revisions": 1,
             "dependencies": [], "files": [], "result": {"summary": "重跑后的结论。"}},
            {"task_key": "sink-flow", "state": "completed", "revisions": 0,
             "dependencies": ["entry-flow"], "files": [], "result": {"summary": "后续方向已结算。"}},
        ],
    })

    settled = {item["task_key"]: item for item in situation["settled"]}
    assert "stale_dependency" not in settled["sink-flow"]
    assert "stale_dependency" not in situation["notice"]
    assert settled["entry-flow"]["revisions"] == 1


# --- the round reports it ----------------------------------------------------


def test_the_round_that_corrects_a_direction_says_so(store, repository, monkeypatch):
    """A correction is the moment the run changed its mind, and it is worth an event."""
    run, _ = create_planner_run(store, repository)
    worker = make_worker(store, repository)
    worker_keys: list[str] = []

    async def fake_plan(**kwargs):
        if kwargs["round_no"] == 1:
            decision = {
                "goal_state": "continue", "basis_summary": "项目图显示入口需要单独验证。",
                "next_action": "派发入口方向。", "missing_context": [],
                "tasks": [proposal("entry-flow")], "updates": [],
            }
        elif kwargs["round_no"] == 2:
            decision = {
                "goal_state": "continue", "basis_summary": "上一轮的结论引用了错误的行窗口。",
                "next_action": "重开入口方向重新取证。", "missing_context": [],
                "tasks": [],
                "updates": [{
                    "task_key": "entry-flow", "action": "reopen",
                    "rationale_summary": "该结论引用的行窗口属于另一个函数。",
                }],
            }
        else:
            decision = {
                "goal_state": "unreachable",
                "basis_summary": "重跑后仍未形成验收条件要求的源码证据。",
                "next_action": "", "missing_context": [], "tasks": [], "updates": [],
            }
        return {
            "decision": decision,
            "usage": {"requests": 1, "tool_calls": 1, "input_tokens": 5, "output_tokens": 4},
            "error": None, "status": None, "terminal_reason": "completed",
        }

    async def fake_pursue(**kwargs):
        worker_keys.append(kwargs["planner_task"]["task_key"])
        return worker_outcome("no_evidence")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))

    # The corrected direction really was investigated a second time.
    assert worker_keys == ["entry-flow", "entry-flow"]
    events = [item for item in store.list_events(run["id"]) if item["kind"] == "planner_task_reopened"]
    assert len(events) == 1
    payload = events[0]["payload"]
    assert payload["task_key"] == "entry-flow"
    assert payload["revisions"] == 1
    assert payload["state"] == "ready"
    assert payload["attempts"] == 1 and payload["max_attempts"] == 3
    assert "行窗口" in payload["reason"]
    # Announced, not re-announced: a correction that produced no reopen reports nothing.
    assert [item["kind"] for item in store.list_events(run["id"])].count("planner_round_committed") == 3
