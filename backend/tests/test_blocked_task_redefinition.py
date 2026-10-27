"""Blocked directions can be narrowed by an explicit, atomic Planner correction."""
from __future__ import annotations

import pytest
from pydantic_ai import ModelRetry

from audit.agent import _validate_planner_decision
from audit.db import Store
from audit.runtime import AgentPolicy
from audit.schemas import PlannerDecision
from audit.source import SourceRepository
from tests.test_goal_tasks import create_planner_run, proposal


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "source-data")


def decision(*, tasks=None, updates=None):
    return PlannerDecision.model_validate({
        "goal_state": "continue", "basis_summary": "将受阻的大范围缩小为已明确的剩余数据流。",
        "tasks": [proposal("sql-injection-dataflow", start=2, end=3)] if tasks is None else tasks,
        "updates": [{"task_key": "sql-injection-dataflow", "action": "reopen",
                     "rationale_summary": "先只检查剩余两行，不重发已经保存的结论。"}] if updates is None else updates,
    })


def prior(*, state="blocked", dependencies=None, revisions=0):
    return {"task_key": "sql-injection-dataflow", "state": state, "revisions": revisions,
            "files": ["public/index.php"], "dependencies": dependencies or []}


def validate(value, priors=None, **kwargs):
    return _validate_planner_decision(
        value, {"files": [{"path": "public/index.php", "line_count": 4}]},
        [prior()] if priors is None else priors, **kwargs,
    )


def publish(store, run, *, tasks=None, updates=None):
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    assert plan is not None
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue", basis_summary="缩小受阻方向并保留历史。",
        tasks=tasks or [], updates=updates or [],
    )
    return plan


def blocked_run(store, repository, *, policy=None):
    run, _ = create_planner_run(store, repository, policy=policy)
    publish(store, run, tasks=[proposal("sql-injection-dataflow")])
    claimed = store.claim_ready_task(run["id"], "worker-1")
    assert claimed is not None
    store.resolve_task_attempt(
        claimed["id"], "worker-1", outcome="blocked",
        result={"summary": "已有发现保存，但另一段数据流仍需检查。", "remaining_work": ["检查入口下一段数据流。"]},
        usage={"requests": 1}, seen=[{"path": "public/index.php", "start_line": 1, "end_line": 2}],
    )
    return run, store.get_planner_task(claimed["id"])


def test_blocked_task_can_be_narrowed_and_reopened_in_one_decision():
    value = validate(decision())
    assert value.tasks[0].source_refs[0].start_line == 2
    assert value.updates[0].action == "reopen"


@pytest.mark.parametrize("state", ["blocked", "running", "completed", "exhausted", "cancelled", "skipped"])
def test_redefinition_requires_blocked_state_and_explicit_reopen(state):
    with pytest.raises(ModelRetry, match="不能重新定义"):
        validate(decision(updates=[]), [prior(state=state)])
    if state != "blocked":
        with pytest.raises(ModelRetry, match="不能重新定义"):
            validate(decision(), [prior(state=state)])


def test_atomic_redefinition_cannot_drop_old_dependencies():
    priors = [prior(dependencies=["auth-premise"]), {"task_key": "auth-premise", "state": "completed"}]
    with pytest.raises(ModelRetry, match="不能删除原依赖"):
        validate(decision(), priors)
    replacement = proposal("sql-injection-dataflow", dependencies=["auth-premise"])
    assert validate(decision(tasks=[replacement]), priors).tasks[0].dependencies == ["auth-premise"]


def test_atomic_redefinition_still_checks_paths_and_dependency_cycles():
    with pytest.raises(ModelRetry, match="冻结范围外"):
        validate(decision(tasks=[proposal("sql-injection-dataflow", path="outside.php")]))
    replacement = proposal("sql-injection-dataflow", dependencies=["dependent-task"])
    priors = [prior(), {"task_key": "dependent-task", "state": "blocked", "dependencies": ["sql-injection-dataflow"]}]
    with pytest.raises(ModelRetry, match="依赖图存在循环"):
        validate(decision(tasks=[replacement]), priors)


def test_atomic_redefinition_spends_the_same_revision_allowance_as_reopen():
    with pytest.raises(ModelRetry, match="已经重开"):
        validate(decision(), [prior(revisions=2)], policy=AgentPolicy(task_reopens=2))
    with pytest.raises(ModelRetry, match="重开次数"):
        validate(decision(), policy=AgentPolicy(run_reopens=1), run_reopens=1)
    twice = decision()
    twice.updates.append(twice.updates[0].model_copy())
    with pytest.raises(ModelRetry, match="只能 reopen 一次"):
        validate(twice)


def test_correction_is_not_mistaken_for_a_new_duplicate_direction():
    other = {"task_key": "other-concluded", "state": "completed", "files": ["public/index.php"]}
    findings = [{"id": "existing-finding", "finding_kind": "vulnerability", "severity": "high",
                 "paths": ["public/index.php"]}]
    assert validate(decision(), [prior(), other], findings=findings).updates[0].action == "reopen"


def test_store_commits_new_definition_and_reopen_without_rewriting_history(store, repository):
    run, original = blocked_run(store, repository)
    before_attempts = store.list_task_attempts(original["id"])
    old_plan = store.list_plans(run["id"])[0]
    replacement = proposal("sql-injection-dataflow", start=2, end=3)
    replacement["objective"] = "只审计尚未结算的两行数据流并保留已有结论。"
    update = decision().updates[0].model_dump()

    new_plan = publish(store, run, tasks=[replacement], updates=[update])

    revised = store.get_planner_task(original["id"])
    assert revised["id"] == original["id"] and revised["session_id"] == original["session_id"]
    assert revised["state"] == "ready" and revised["revisions"] == 1
    assert revised["attempts"] == 1 and revised["max_attempts"] == original["max_attempts"] + 1
    assert revised["objective"] == replacement["objective"]
    assert revised["context_spec"]["source_refs"][0]["start_line"] == 2
    assert revised["plan_id"] == new_plan["id"]
    assert store.list_task_attempts(original["id"]) == before_attempts
    saved_old_plan = next(plan for plan in store.list_plans(run["id"]) if plan["id"] == old_plan["id"])
    assert saved_old_plan["task_snapshot"] == old_plan["task_snapshot"]
    assert store.get_planner_session(run["id"])["task_reopens"] == 1
    claimed = store.claim_ready_task(run["id"], "worker-2")
    assert claimed is not None and claimed["id"] == original["id"]


def test_store_refuses_unpaired_redefinition_atomically(store, repository):
    run, original = blocked_run(store, repository)
    with pytest.raises(ValueError, match="cannot be redefined"):
        publish(store, run, tasks=[proposal("sql-injection-dataflow", start=2, end=3)])
    assert store.get_planner_task(original["id"]) == original
    assert store.get_planner_session(run["id"])["task_reopens"] == 0


@pytest.mark.parametrize("policy", [AgentPolicy(task_reopens=0), AgentPolicy(run_reopens=0)])
def test_store_cannot_bypass_frozen_reopen_budget(store, repository, policy):
    run, original = blocked_run(store, repository, policy=policy)
    with pytest.raises(ValueError, match="reopen allowance exhausted"):
        publish(store, run, tasks=[proposal("sql-injection-dataflow")],
                updates=[decision().updates[0].model_dump()])
    assert store.get_planner_task(original["id"]) == original


def test_store_retains_dependency_guards_for_a_narrowed_task(store, repository):
    run, _ = create_planner_run(store, repository)
    publish(store, run, tasks=[proposal("auth-premise"),
                              proposal("sql-injection-dataflow", dependencies=["auth-premise"])])
    claimed = store.claim_ready_task(run["id"], "worker-1")
    assert claimed["task_key"] == "auth-premise"
    store.resolve_task_attempt(claimed["id"], "worker-1", outcome="blocked", result={}, usage={}, seen=[])
    original = next(task for task in store.list_tasks(run["id"]) if task["task_key"] == "sql-injection-dataflow")
    with pytest.raises(ValueError, match="cannot remove dependencies"):
        publish(store, run, tasks=[proposal("sql-injection-dataflow")],
                updates=[decision().updates[0].model_dump()])
    assert store.get_planner_task(original["id"]) == original


def test_narrowed_task_with_a_failed_premise_stays_blocked(store, repository):
    run, _ = create_planner_run(store, repository)
    publish(store, run, tasks=[proposal("auth-premise"),
                              proposal("sql-injection-dataflow", dependencies=["auth-premise"])])
    claimed = store.claim_ready_task(run["id"], "worker-1")
    store.resolve_task_attempt(claimed["id"], "worker-1", outcome="blocked", result={}, usage={}, seen=[])
    replacement = proposal("sql-injection-dataflow", dependencies=["auth-premise"], start=2, end=3)
    publish(store, run, tasks=[replacement], updates=[decision().updates[0].model_dump()])
    revised = next(task for task in store.list_tasks(run["id"]) if task["task_key"] == "sql-injection-dataflow")
    assert revised["state"] == "blocked" and revised["revisions"] == 1
    assert "依赖未形成可用结论" in revised["error"]
    assert revised["dependencies"] == ["auth-premise"]
    assert store.claim_ready_task(run["id"], "worker-2") is None


def test_ready_task_redefinition_rechecks_new_dependencies(store, repository):
    run, _ = create_planner_run(store, repository)
    publish(store, run, tasks=[proposal("sql-injection-dataflow")])
    publish(store, run, tasks=[proposal("auth-premise"),
                              proposal("sql-injection-dataflow", dependencies=["auth-premise"])])
    revised = next(task for task in store.list_tasks(run["id"]) if task["task_key"] == "sql-injection-dataflow")
    assert revised["state"] == "pending"
    assert store.claim_ready_task(run["id"], "worker-1")["task_key"] == "auth-premise"
