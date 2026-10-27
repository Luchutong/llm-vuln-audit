"""Follow partial audit work through caps, failed retries and explicit reopens."""
from __future__ import annotations

import asyncio

import pytest

from audit import agent, worker as worker_module
from audit.db import Store, TASK_RETRY_FAILURE_REASONS
from audit.schemas import GoalAssessment
from audit.source import SourceRepository
from tests.test_blocker_progress_recovery import _findings, _plan
from tests.test_goal_tasks import TASK, create_planner_run, make_worker, proposal, worker_outcome


REMAINING = ["src/files.php: 核对尚未审查的路径约束与文件访问边界。"]


@pytest.fixture
def audit(tmp_path):
    store = Store(tmp_path / "audit.db")
    repository = SourceRepository(tmp_path / "sources")
    task = {
        **TASK, "max_iterations": 3, "max_planner_rounds": 6,
        "max_total_attempts": 12, "stop_on_achieved": False, "completion_policy": "coverage_review",
    }
    run, _ = create_planner_run(store, repository, task=task)
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    store.finish_planner_round(run["id"], plan["id"], goal_state="continue", basis_summary="审计小批任务。", tasks=[proposal("batch")])
    yield store, repository, run
    store.close()


def _resolve(store, run, *, outcome="no_evidence", remaining=None, error=None, reason="completed"):
    claimed = store.claim_ready_task(run["id"], "worker")
    assert claimed is not None
    result = {
        "outcome": outcome, "summary": "当前已核对方向尚无可利用证据。", "reasoning": "结论仅覆盖当前实际核对的源码方向。",
        "remaining_work": list(remaining or []), "findings": [], "terminal_reason": reason,
    }
    if error:
        result.update(summary="", reasoning="", error=error)
    return store.resolve_task_attempt(
        claimed["id"], "worker", outcome=outcome, result=result,
        usage={"requests": 1}, seen=[], error=error, terminal_reason=reason,
    )


def test_no_evidence_with_remaining_directions_requeues_and_blocks_at_cap(audit):
    store, _, run = audit
    assessment = GoalAssessment.model_validate({
        "outcome": "no_evidence", "summary": "仅完成当前局部范围的排查。",
        "reasoning": "当前结论不能代表尚未检查的路径边界。", "remaining_work": REMAINING,
    })
    assert assessment.remaining_work == REMAINING
    for attempt in range(1, 4):
        resolved = _resolve(store, run, remaining=REMAINING)
        assert resolved["state"] == ("ready" if attempt < 3 else "blocked")
        assert resolved["result"]["remaining_work"] == REMAINING
    assert store.task_queue_state(run["id"])["blocked"] == 1
    assert store.get_task_goal(run["id"])["status"] == "open"
    assert len(store.list_tasks(run["id"])[0]["attempt_history"]) == 3


@pytest.mark.parametrize("reason", sorted(TASK_RETRY_FAILURE_REASONS))
def test_retry_failure_preserves_previous_unsettled_directions(audit, reason):
    store, _, run = audit
    _resolve(store, run, remaining=REMAINING)

    retry = _resolve(store, run, outcome="continue", remaining=[], reason=reason, error="宿主未取得有效模型结论")

    assert retry["state"] == "ready"
    assert retry["result"]["remaining_work"] == REMAINING
    assert retry["attempt_history"][-1]["result"]["remaining_work"] == REMAINING
    context = store.list_planner_context(run["id"])
    assert context["tasks"][0]["remaining_work"] == REMAINING


def test_normal_completion_can_explicitly_clear_previous_remaining_work(audit):
    store, _, run = audit
    _resolve(store, run, remaining=REMAINING)

    resolved = _resolve(store, run, remaining=[])

    assert resolved["state"] == "completed"
    assert resolved["result"]["remaining_work"] == []
    assert resolved["attempt_history"][0]["result"]["remaining_work"] == REMAINING


def test_failed_attempt_after_explicit_reopen_retains_remaining_work(audit):
    store, _, run = audit
    for _ in range(3):
        _resolve(store, run, remaining=REMAINING)
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue", basis_summary="继续处理已经持久化的剩余方向。",
        updates=[{"task_key": "batch", "action": "reopen", "rationale_summary": "重开小批任务继续核对剩余边界。"}],
    )

    failed = _resolve(store, run, outcome="continue", remaining=[], reason="context_limit", error="宿主模型历史超限")

    assert failed["state"] == "blocked" and failed["attempts"] == 4
    assert failed["result"]["remaining_work"] == REMAINING
    assert failed["attempt_history"][-1]["result"]["remaining_work"] == REMAINING
    assert store.list_planner_context(run["id"])["tasks"][0]["remaining_work"] == REMAINING


def test_genuine_blocked_result_keeps_blocked_even_with_remaining_work(audit):
    store, _, run = audit

    resolved = _resolve(store, run, outcome="blocked", remaining=REMAINING, error="缺少部署期配置", reason="missing_context")

    assert resolved["state"] == "blocked"
    assert resolved["result"]["remaining_work"] == REMAINING
    assert resolved["attempts"] == 1


def test_third_saved_batch_is_retained_and_reopened_worker_receives_remaining_focus(tmp_path, monkeypatch):
    """Exercise real orchestration and the real adapter after the third partial batch."""
    store = Store(tmp_path / "full-lifecycle.db")
    repository = SourceRepository(tmp_path / "full-lifecycle-sources")
    try:
        task = {
            **TASK, "max_iterations": 3, "max_planner_rounds": 6,
            "max_total_attempts": 12, "stop_on_achieved": False,
            "completion_policy": "coverage_review", "max_workers": 1,
        }
        run, _ = create_planner_run(store, repository, task=task)
        rounds, attempts, focuses = [], [], []
        real_adapter = agent.pursue_planner_task

        async def fake_plan(**kwargs):
            rounds.append(kwargs["round_no"])
            if kwargs["round_no"] == 1:
                return _plan(proposal("batch"))
            old = store.list_tasks(run["id"])[0]
            assert old["state"] == "blocked" and old["attempts"] == 3
            assert old["result"]["remaining_work"] == REMAINING
            assert store.list_planner_context(run["id"])["tasks"][0]["remaining_work"] == REMAINING
            assert len(store.list_findings(run["id"])) == 1
            assert store.list_findings(run["id"])[0]["revision"] == 3
            return _plan(updates=[{
                "task_key": "batch", "action": "reopen",
                "rationale_summary": "三批结果已保存，重开任务继续核对明确记录的剩余方向。",
            }])

        async def source_assessment(**kwargs):
            focuses.append(kwargs["focus"])
            result = worker_outcome("no_evidence", seen=[
                {"path": "src/files.php", "start_line": 1, "end_line": 5},
            ])
            result["result"]["remaining_work"] = []
            return result

        async def fake_worker(**kwargs):
            attempts.append(kwargs["attempt"])
            if kwargs["attempt"] <= 3:
                result = _findings(f"batch-{kwargs['attempt']}", count=1)
                result["result"]["finding"]["dangerous_operation"] = "readfile($request_path)"
                result["result"]["remaining_work"] = REMAINING
                return result
            assert kwargs["planner_task"]["result"]["remaining_work"] == REMAINING
            return await real_adapter(**kwargs)

        monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
        monkeypatch.setattr(worker_module, "pursue_planner_task", fake_worker)
        monkeypatch.setattr(agent, "pursue_task_work", source_assessment)

        asyncio.run(make_worker(store, repository)._execute(run))

        assert rounds == [1, 2]
        assert attempts == [1, 2, 3, 4]
        assert len(focuses) == 1 and REMAINING[0] in focuses[0]
        settled = store.list_tasks(run["id"])[0]
        assert settled["state"] == "completed" and settled["attempts"] == 4
        assert settled["result"]["remaining_work"] == []
        assert settled["attempt_history"][2]["result"]["remaining_work"] == REMAINING
        assert len(store.list_findings(run["id"])) == 1
        assert store.list_findings(run["id"])[0]["revision"] == 3
        assert store.get_run(run["id"])["status"] == "completed"
    finally:
        store.close()
