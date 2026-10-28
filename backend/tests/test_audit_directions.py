"""Durable host directions and successful-batch accounting use temporary stores."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from audit.db import Store
from audit.schemas import PlannerDecision, TaskSpec
from audit.source import SourceRepository
from tests.test_goal_tasks import TASK, create_planner_run, proposal


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "directions.sqlite")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "sources")


def create(store, repository, *, legacy=False, cap=12, iterations=2):
    task = {**TASK, "max_iterations": iterations, "max_total_attempts": cap,
            "workflow_policy": "legacy" if legacy else "discovery_first"}
    return create_planner_run(store, repository, task=task)[0]


def commit(store, run, *, tasks=(), updates=(), directions=()):
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    assert plan
    return store.finish_planner_round(run["id"], plan["id"], goal_state="continue", basis_summary="按原始源码证据分派及结算未决方向。",
                                      tasks=list(tasks), updates=list(updates), direction_updates=list(directions))


def settle(store, run, *, remaining=(), outcome="achieved", key="initial-flow", seen=None, progress=None):
    row = store.claim_ready_task(run["id"], "worker")
    assert row and row["task_key"] == key
    return store.resolve_task_attempt(row["id"], "worker", outcome=outcome,
                                     result={"summary": "本批已保存有原始源码依据的审查结果。", "remaining_work": list(remaining)},
                                     usage={"requests": 1}, seen=seen if seen is not None else [{"path": "public/index.php", "start_line": 1, "end_line": 4}],
                                     progress=progress)


def test_new_workflow_is_explicit_and_legacy_default_is_unchanged():
    assert TaskSpec.model_validate(TASK).workflow_policy == "legacy"
    assert TaskSpec.model_validate({**TASK, "workflow_policy": "discovery_first"}).workflow_policy == "discovery_first"
    with pytest.raises(ValidationError):
        PlannerDecision.model_validate({"basis_summary": "明确结算本轮未决方向。", "direction_updates": [{
            "direction_id": "dir_" + "1" * 32, "action": "resolve", "rationale_summary": "不能没有任何宿主证据就宣告已经结算。",
        }]})


def test_direction_ids_are_stable_and_worker_cannot_replace_the_host_register(store, repository):
    run = create(store, repository)
    commit(store, run, tasks=[proposal("initial-flow")])
    text = "public/index.php:4 的输入是否进入未受约束的文件路径，需补读实现。"
    first = settle(store, run, remaining=[text])
    original = store.list_audit_directions(run["id"])["items"]
    assert len(original) == 1 and original[0]["state"] == "assigned"
    assert original[0]["id"].startswith("dir_")
    claimed = store.claim_ready_task(run["id"], "worker")
    assert claimed["result"]["active_directions"][0]["id"] == original[0]["id"]
    store.resolve_task_attempt(claimed["id"], "worker", outcome="achieved", result={
        "remaining_work": [text], "host_directions": [{"id": "dir_forged", "state": "resolved"}],
    }, usage={}, seen=[], progress={"new_conclusion_keys": ["another-real-host-validated-conclusion"]})
    assert store.list_audit_directions(run["id"])["items"][0]["id"] == original[0]["id"]
    assert first["result"]["host_progress"]["failed_attempts"] == 0


def test_narrow_reopen_inherits_only_selected_ids_and_keeps_unassigned_obligations(store, repository):
    run = create(store, repository, iterations=1)
    commit(store, run, tasks=[proposal("initial-flow")])
    texts = ["public/index.php:4 的路径参数需要确认输入约束。", "src/auth.php:2 的管理员边界需要独立复核。"]
    settle(store, run, remaining=texts)
    blocked = settle(store, run, remaining=texts)
    assert blocked["state"] == "blocked"
    records = store.list_audit_directions(run["id"])["items"]
    chosen = next(item for item in records if "public/index" in item["text"])
    other = next(item for item in records if item["id"] != chosen["id"])
    replacement = {**proposal("initial-flow"), "direction_ids": [chosen["id"]]}
    before = store.list_task_attempts(blocked["id"])
    commit(store, run, tasks=[replacement], updates=[{
        "task_key": "initial-flow", "action": "reopen", "rationale_summary": "仅补查入口参数约束，认证边界交给独立任务。",
    }])
    current = store.get_planner_task(blocked["id"])
    assert current["result"]["remaining_work"] == [chosen["text"]]
    assert store.list_audit_directions(run["id"], state="pending")["items"][0]["id"] == other["id"]
    assert store.list_task_attempts(blocked["id"]) == before
    assert store.get_task_goal(run["id"])["max_total_attempts"] == 12


def test_reopen_without_selected_ids_does_not_reinject_old_work(store, repository):
    run = create(store, repository, iterations=1)
    commit(store, run, tasks=[proposal("initial-flow")])
    text = "public/index.php:4 的输入边界还未完成审查。"
    settle(store, run, remaining=[text])
    row = settle(store, run, remaining=[text])
    commit(store, run, tasks=[{**proposal("initial-flow", path="src/auth.php", start=1, end=2)}], updates=[{
        "task_key": "initial-flow", "action": "reopen", "rationale_summary": "改为仅检查认证模块，原入口方向留在宿主待办。",
    }])
    assert store.get_planner_task(row["id"])["result"]["remaining_work"] == []
    assert store.audit_direction_summary(run["id"])["pending_total"] == 1


def test_all_pages_are_required_for_closure_and_skips_preserve_limitations(store, repository):
    run = create(store, repository)
    commit(store, run, tasks=[proposal("initial-flow")])
    settle(store, run, remaining=[f"src/auth.php:2 未审查方向编号 {index}，需要独立核对。" for index in range(201)])
    summary = store.audit_direction_summary(run["id"])
    assert summary["total"] == 201 and len(summary["items"]) == 4 and summary["omitted"] == 197
    with pytest.raises(ValueError, match="201"):
        store.finalize_goal(run["id"], "met", "不能把摘要以外的方向当成不存在。")
    records, cursor = [], 0
    while cursor is not None:
        page = store.list_audit_directions(run["id"], cursor=cursor, limit=25)
        records.extend(page["items"])
        cursor = page["next_cursor"]
    assert len({row["id"] for row in records}) == 201
    # Direct Store calls also validate settlement; a forged ID cannot clear the queue.
    with pytest.raises(ValueError, match="does not belong"):
        commit(store, run, directions=[{"direction_id": "dir_" + "0" * 32, "action": "skip", "rationale_summary": "该运行没有这一条真实方向，必须拒绝。"}])
    commit(store, run, directions=[{"direction_id": records[0]["id"], "action": "skip", "rationale_summary": "部署侧配置未包含在快照中，该方向保留为未审查限制。"}])
    skipped = store.list_audit_directions(run["id"], state="skipped")["items"][0]
    assert "未完成源码审查" in skipped["limitation"]
    assert store.audit_direction_summary(run["id"])["unsettled_total"] == 200


def test_successful_batches_do_not_consume_failure_retries_but_all_count_toward_run_cap(store, repository):
    run = create(store, repository, cap=4, iterations=1)
    commit(store, run, tasks=[proposal("initial-flow")])
    for index in range(4):
        row = settle(store, run, remaining=["public/index.php:4 仍有不同输入方向需要核对。"],
                     progress={"new_conclusion_keys": [f"validated-root-{index}"]})
        assert row["state"] == "ready"
        assert row["result"]["host_progress"]["failed_attempts"] == 0
        assert row["attempts"] == index + 1
    assert store.get_task_goal(run["id"])["attempts"] == 4
    assert store.claim_ready_task(run["id"], "worker") is None


def test_repeated_conclusions_and_reads_are_not_fabricated_progress(store, repository):
    run = create(store, repository, iterations=1)
    commit(store, run, tasks=[proposal("initial-flow")])
    text = "public/index.php:4 这条方向仍需要补查。"
    first = settle(store, run, remaining=[text], progress={"new_conclusion_keys": ["same-root"]})
    second = settle(store, run, remaining=[text], progress={"new_conclusion_keys": ["same-root"]})
    assert first["result"]["host_progress"]["productive"] is True
    assert second["result"]["host_progress"]["productive"] is False
    assert second["state"] == "blocked"
    assert second["result"]["host_progress"]["failed_attempts"] == 1


def test_legacy_attempt_counting_and_remaining_work_stay_unchanged(store, repository):
    run = create(store, repository, legacy=True, iterations=1)
    commit(store, run, tasks=[proposal("initial-flow")])
    row = settle(store, run, remaining=["public/index.php:4 原有历史运行保持旧的尝试口径。"])
    assert row["state"] == "blocked" and row["attempts"] == 1
    assert "host_progress" not in row["result"]
    assert store.audit_direction_summary(run["id"])["total"] == 0


def test_worker_can_clear_its_remaining_work_before_planner_settles_the_host_obligation(store, repository):
    run = create(store, repository)
    commit(store, run, tasks=[proposal("initial-flow")])
    text = "public/index.php:4 的请求输入边界仍需补读并核对。"
    first = settle(store, run, remaining=[text])
    direction = store.list_audit_directions(run["id"])["items"][0]
    assert first["state"] == "ready" and direction["state"] == "assigned"
    second = settle(store, run, remaining=[], outcome="no_evidence")
    assert second["state"] == "completed"
    assert second["result"]["remaining_work"] == []
    assert second["result"]["active_directions"][0]["id"] == direction["id"]
    assert store.audit_direction_summary(run["id"])["unsettled_total"] == 1
    commit(store, run, directions=[{
        "direction_id": direction["id"], "action": "resolve", "task_key": "initial-flow",
        "rationale_summary": "后续尝试已完成该入口全部四行核对，方向结算引用保留的实际读取范围。",
    }])
    assert store.audit_direction_summary(run["id"])["complete"] is True


def test_completed_task_can_explicitly_settle_a_direction_it_actually_read(store, repository):
    run = create(store, repository)
    commit(store, run, tasks=[proposal("initial-flow")])
    settle(store, run, remaining=["src/auth.php:2 的认证边界需要独立核对。"])
    direction = store.list_audit_directions(run["id"])["items"][0]
    commit(store, run, tasks=[{**proposal("auth-followup", path="src/auth.php", end=2),
                              "direction_ids": [direction["id"]]}])
    assert store.assigned_task_directions(run["id"], "auth-followup")[0]["id"] == direction["id"]
    settle(store, run, key="auth-followup", remaining=[], outcome="no_evidence",
           seen=[{"path": "src/auth.php", "start_line": 1, "end_line": 2}])
    commit(store, run, directions=[{
        "direction_id": direction["id"], "action": "resolve", "task_key": "auth-followup",
        "rationale_summary": "独立任务已读取认证函数原始两行，并记录这一边界的核对结论。",
    }])
    assert store.audit_direction_summary(run["id"])["complete"] is True
    assert store.list_audit_directions(run["id"], state="resolved")["total"] == 1


def test_unread_task_or_unrelated_finding_cannot_settle_a_direction(store, repository):
    run = create(store, repository)
    commit(store, run, tasks=[proposal("initial-flow")])
    settle(store, run, remaining=["src/auth.php:2 的认证边界需要独立核对。"])
    direction = store.list_audit_directions(run["id"])["items"][0]
    # The original task only read public/index.php, not the auth.php obligation.
    for resolution in ({"task_key": "initial-flow"}, {"finding_ids": ["not-in-this-run"]}):
        session = store.get_planner_session(run["id"])
        plan = store.begin_planner_round(run["id"], session["session_id"])
        assert plan
        with pytest.raises(ValueError, match="related source|validated findings"):
            store.finish_planner_round(run["id"], plan["id"], goal_state="continue", basis_summary="宿主必须拒绝无法关联的结算依据。",
                                       direction_updates=[{"direction_id": direction["id"], "action": "resolve",
                                                           "rationale_summary": "无关记录不能证明指定认证边界已得到源码核对。", **resolution}])
    assert store.audit_direction_summary(run["id"])["unsettled_total"] == 1


def test_assignment_cannot_steal_an_inflight_direction(store, repository):
    run = create(store, repository)
    commit(store, run, tasks=[proposal("initial-flow")])
    settle(store, run, remaining=["public/index.php:4 的输入边界需要继续核对。"])
    direction = store.list_audit_directions(run["id"])["items"][0]
    running = store.claim_ready_task(run["id"], "still-running")
    assert running
    with pytest.raises(ValueError, match="running task"):
        commit(store, run, tasks=[proposal("replacement-flow")], directions=[{
            "direction_id": direction["id"], "action": "assign", "task_key": "replacement-flow",
            "rationale_summary": "正在执行的方向不能被另一个任务抢走。",
        }])
    assert store.assigned_task_directions(run["id"], "initial-flow")[0]["id"] == direction["id"]
    assert not any(item["task_key"] == "replacement-flow" for item in store.list_tasks(run["id"]))


def test_productive_seen_ranges_do_not_reset_failure_counter_and_persist_across_reopen(store, repository):
    run = create(store, repository, iterations=1)
    commit(store, run, tasks=[proposal("initial-flow")])
    text = "public/index.php:4 的输入边界需要继续核对。"
    first = settle(store, run, remaining=[text], seen=[{"path": "public/index.php", "start_line": 1, "end_line": 2}])
    second = settle(store, run, remaining=[text], seen=[{"path": "public/index.php", "start_line": 2, "end_line": 4}])
    assert first["state"] == second["state"] == "ready"
    assert second["result"]["host_progress"]["successful_batches"] == 2
    third = settle(store, run, remaining=[text], seen=[{"path": "public/index.php", "start_line": 1, "end_line": 4}])
    assert third["state"] == "blocked"
    assert third["result"]["host_progress"]["failed_attempts"] == 1
    assert store.get_task_goal(run["id"])["attempts"] == 3
