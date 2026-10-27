"""A historical blocked task must not erase progress made by replacement workers."""
from __future__ import annotations

import asyncio
import copy
import json

import pytest

from audit import worker as worker_module
from audit.db import Store
from audit.execution_state import CURRENT_EXECUTION, DEFAULT_RUN_LIMITS
from audit.source import SourceRepository
from audit.worker import _blocker_progress_signature
from tests.test_goal_tasks import TASK, create_planner_run, make_worker, proposal, worker_outcome


@pytest.fixture
def audit(tmp_path):
    store = Store(tmp_path / "audit.db")
    repository = SourceRepository(tmp_path / "sources")
    task = {
        **TASK, "max_planner_rounds": 8, "max_total_attempts": 8,
        "stop_on_achieved": False, "completion_policy": "coverage_review",
    }
    run, _ = create_planner_run(store, repository, task=task)
    yield store, repository, run
    store.close()


def _plan(*tasks, updates=None, state="continue"):
    return {
        "decision": {
            "goal_state": state, "basis_summary": "拆分宽泛方向并复核未解决的旧阻塞。",
            "tasks": list(tasks), "updates": updates or [], "missing_context": [],
        },
        "usage": {"requests": 1}, "terminal_reason": "completed", "error": None,
    }


def _blocked():
    result = worker_outcome("blocked")
    result.update(terminal_reason="context_limit", error="StopAudit: 模型历史已达到上下文上限")
    result["result"].update(terminal_reason="context_limit", missing_context=[])
    return result


def _findings(prefix, count=4):
    findings = [{
        "title": f"{prefix} 缺少边界限制的敏感操作 {index}", "kind": "vulnerability", "severity": "high",
        "summary": "当前入口可将外部请求参数传入敏感操作，缺少相应边界限制。",
        "vulnerability_type": "path_traversal", "primary_location": {"path": "public/index.php", "line": 4},
        "evidence": "public/index.php:4-4", "input_source": "$_GET['path']",
        "propagation": "请求参数传入 handle。", "dangerous_operation": f"{prefix}-operation-{index}",
        "protection": "未限制敏感操作参数。", "preconditions": "具有当前入口所需身份。",
        "remediation": "限制敏感操作允许的输入与对象。",
    } for index in range(count)]
    result = worker_outcome(
        "achieved", finding=findings[0],
        seen=[
            {"path": "public/index.php", "start_line": 1, "end_line": 4},
            {"path": "src/auth.php", "start_line": 1, "end_line": 2},
            {"path": "src/files.php", "start_line": 1, "end_line": 5},
        ],
    )
    result["result"]["findings"] = findings
    return result


def _install_replacement_wave(monkeypatch, store, run, *, repair="reopen", terminal_action=None):
    rounds, attempts = [], []

    async def fake_plan(**kwargs):
        rounds.append(kwargs["round_no"])
        if kwargs["round_no"] == 1:
            return _plan(proposal("wide"))
        if kwargs["round_no"] == 2:
            return _plan(proposal("small-a"), proposal("small-b"))
        if terminal_action is not None:
            terminal_action()
        if repair == "reopen":
            return _plan(updates=[{
                "task_key": "wide", "action": "reopen",
                "rationale_summary": "较小替代方向已经返回证据，重新结算旧方向尚未覆盖的残余问题。",
            }])
        if repair == "met":
            return _plan(state="met")
        return _plan()

    async def fake_worker(**kwargs):
        key = kwargs["planner_task"]["task_key"]
        attempts.append((key, kwargs["attempt"]))
        if key == "wide":
            return _blocked() if kwargs["attempt"] == 1 else worker_outcome("no_evidence")
        return _findings(key)

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_worker)
    return rounds, attempts


def test_replacement_findings_allow_another_round_to_reopen_and_settle_old_block(audit, monkeypatch):
    store, repository, run = audit
    rounds, attempts = _install_replacement_wave(monkeypatch, store, run)

    asyncio.run(make_worker(store, repository)._execute(run))

    assert rounds == [1, 2, 3]
    assert ("wide", 2) in attempts
    assert len(store.list_findings(run["id"])) == 8
    assert store.get_run(run["id"])["status"] == "completed"
    assert store.task_queue_state(run["id"])["blocked"] == 0
    assert all(task["state"] == "completed" for task in store.list_tasks(run["id"]))
    progress = [event for event in store.list_events(run["id"]) if event["kind"] == "planner_blocker_progress"]
    assert len(progress) == 1
    assert progress[0]["payload"]["validated_candidates"] == 8
    assert progress[0]["payload"]["settled_attempts"] == 3


@pytest.mark.parametrize("repair", ["noop", "met"])
def test_new_findings_are_kept_but_unchanged_block_still_ends_inconclusive(audit, monkeypatch, repair):
    store, repository, run = audit
    rounds, _ = _install_replacement_wave(monkeypatch, store, run, repair=repair)

    asyncio.run(make_worker(store, repository)._execute(run))

    assert rounds == [1, 2, 3]
    assert len(store.list_findings(run["id"])) == 8
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.task_queue_state(run["id"])["blocked"] == 1
    assert store.get_task_goal(run["id"])["status"] == "inconclusive"
    assert store.execution_summary(run["id"])["stop_reason"]["code"] == "unresolved_blockers"


def test_noop_replanning_with_only_a_blocker_stops_after_one_repair_opportunity(audit, monkeypatch):
    store, repository, run = audit
    rounds = []

    async def fake_plan(**kwargs):
        rounds.append(kwargs["round_no"])
        # A fresh plan ID, rationale, event or priority is not evidence of progress.
        kwargs["on_event"]({"kind": "audit_progress", "message": "再次考虑同一个未解决方向。"})
        return _plan(proposal("wide")) if kwargs["round_no"] == 1 else _plan()

    async def fake_worker(**kwargs):
        return _blocked()

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_worker)

    asyncio.run(make_worker(store, repository)._execute(run))

    assert rounds == [1, 2]
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.get_task_goal(run["id"])["attempts"] == 1
    assert not [event for event in store.list_events(run["id"]) if event["kind"] == "planner_blocker_progress"]


def test_repeated_trivial_replacement_tasks_remain_bounded_by_shared_attempts(tmp_path, monkeypatch):
    """The shared worker cap is the last bound left after every direction is settled.

    This run uses the goal completion policy on purpose: under coverage review the gap
    review now preempts the cap (a blocked direction no longer suppresses it), and that
    separate bound is covered in ``test_coverage_review_policy.py``.
    """
    store = Store(tmp_path / "audit.db")
    repository = SourceRepository(tmp_path / "sources")
    task = {**TASK, "max_planner_rounds": 8, "max_total_attempts": 4,
            "stop_on_achieved": False, "completion_policy": "goal"}
    run, _ = create_planner_run(store, repository, task=task)
    rounds, attempts = [], []

    async def fake_plan(**kwargs):
        rounds.append(kwargs["round_no"])
        return _plan(proposal("wide" if kwargs["round_no"] == 1 else f"trivial-{kwargs['round_no']}"))

    async def fake_worker(**kwargs):
        key = kwargs["planner_task"]["task_key"]
        attempts.append(key)
        return _blocked() if key == "wide" else worker_outcome("no_evidence")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_worker)

    try:
        asyncio.run(make_worker(store, repository)._execute(run))
        assert len(attempts) == 4
        assert len(rounds) <= 4
        assert store.get_run(run["id"])["status"] == "inconclusive"
        assert store.execution_summary(run["id"])["stop_reason"]["code"] == "worker_attempt_limit"
    finally:
        store.close()


def test_user_cancellation_during_progress_review_is_not_replaced_by_blocker_stop(audit, monkeypatch):
    store, repository, run = audit

    def cancel():
        store.terminate_execution(run["id"], "cancelled", {"code": "user_cancelled", "message": "用户取消"})

    rounds, _ = _install_replacement_wave(monkeypatch, store, run, terminal_action=cancel)

    asyncio.run(make_worker(store, repository)._execute(run))

    assert rounds == [1, 2, 3]
    assert store.get_run(run["id"])["status"] == "cancelled"
    assert store.execution_summary(run["id"])["stop_reason"]["code"] == "user_cancelled"
    assert len(store.list_findings(run["id"])) == 8


def test_total_response_budget_still_stops_during_progress_review(audit, monkeypatch):
    store, repository, run = audit
    limits = {**DEFAULT_RUN_LIMITS, "responses": 2}
    store._write("UPDATE run_execution_state SET limits=? WHERE run_id=?", (json.dumps(limits), run["id"]))

    def exhaust():
        owner = CURRENT_EXECUTION.get()
        for _ in range(3):
            owner.admit("responses")

    rounds, _ = _install_replacement_wave(monkeypatch, store, run, terminal_action=exhaust)

    asyncio.run(make_worker(store, repository)._execute(run))

    assert rounds == [1, 2, 3]
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.execution_summary(run["id"])["stop_reason"]["code"] == "run_budget_exhausted"
    assert store.execution_summary(run["id"])["run_usage"]["responses"] == 2
    assert len(store.list_findings(run["id"])) == 8


def test_remaining_work_keeps_goal_worker_running_after_saving_a_batch(audit, monkeypatch):
    store, repository, run = audit
    # The opt-in legacy "first finding" policy must not discard explicit remaining
    # work from the same small-batch result either.
    run["task_spec"] = {**run["task_spec"], "completion_policy": "goal", "stop_on_achieved": True, "max_workers": 1}
    store._write("UPDATE runs SET task_spec=? WHERE id=?", (json.dumps(run["task_spec"]), run["id"]))
    attempts = []
    remaining = ["src/files.php: 核对文件读取路径的剩余边界。"]

    async def fake_plan(**kwargs):
        return _plan(proposal("batch")) if kwargs["round_no"] == 1 else _plan(state="met")

    async def fake_worker(**kwargs):
        attempts.append(kwargs["attempt"])
        result = _findings(f"batch-{kwargs['attempt']}", count=1)
        if kwargs["attempt"] == 1:
            result["result"]["remaining_work"] = remaining
        else:
            result["result"]["finding"]["evidence"] = "src/files.php:4-4"
            result["result"]["findings"][0]["evidence"] = "src/files.php:4-4"
            result["result"]["finding"]["primary_location"] = {"path": "src/files.php", "line": 4}
            result["result"]["findings"][0]["primary_location"] = {"path": "src/files.php", "line": 4}
        return result

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_worker)

    asyncio.run(make_worker(store, repository)._execute(run))

    assert attempts == [1, 2]
    assert len(store.list_findings(run["id"])) == 2
    assert store.get_run(run["id"])["status"] == "completed"
    requeued = [item for item in store.list_events(run["id"]) if item["kind"] == "planner_task_requeued"]
    assert requeued[0]["payload"]["remaining_work"] == remaining
    assert store.list_tasks(run["id"])[0]["attempt_history"][0]["result"]["remaining_work"] == remaining


def test_small_batches_revise_the_same_coordinate_instead_of_duplicating_it(audit, monkeypatch):
    store, repository, run = audit
    attempts = []

    async def fake_plan(**kwargs):
        return _plan(proposal("batch")) if kwargs["round_no"] == 1 else _plan(state="met")

    async def fake_worker(**kwargs):
        attempts.append(kwargs["attempt"])
        result = _findings(f"revision-{kwargs['attempt']}", count=1)
        result["result"]["finding"]["dangerous_operation"] = "readfile($request_path)"
        result["result"]["finding"]["summary"] = f"第 {kwargs['attempt']} 次补充同一操作的可复核影响说明。"
        if kwargs["attempt"] == 1:
            result["result"]["remaining_work"] = ["public/index.php: 补充核对同一根因的影响边界。"]
        return result

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_worker)

    asyncio.run(make_worker(store, repository)._execute(run))

    assert attempts == [1, 2]
    findings = store.list_findings(run["id"])
    assert len(findings) == 1
    assert findings[0]["revision"] == 2
    assert findings[0]["title"].startswith("revision-2")
    assert findings[0]["superseded_summary"][0]["title"].startswith("revision-1")
    assert store.get_run(run["id"])["status"] == "completed"


@pytest.mark.parametrize("identity_field", ["dangerous_operation", "preconditions"])
@pytest.mark.parametrize("common_prefix", ["", "相同前缀" * 100])
def test_same_location_different_operations_or_preconditions_survive_separate_batches(
    audit, monkeypatch, identity_field, common_prefix,
):
    store, repository, run = audit
    attempts = []

    async def fake_plan(**kwargs):
        return _plan(proposal("batch")) if kwargs["round_no"] == 1 else _plan(state="met")

    async def fake_worker(**kwargs):
        attempts.append(kwargs["attempt"])
        result = _findings(f"independent-{kwargs['attempt']}", count=1)
        payload = result["result"]["finding"]
        payload["dangerous_operation"] = "readfile($request_path)"
        payload[identity_field] = common_prefix + ("操作甲" if kwargs["attempt"] == 1 else "操作乙")
        if kwargs["attempt"] == 1:
            result["result"]["remaining_work"] = ["public/index.php: 检查同一行另外的敏感操作和独立前提。"]
        return result

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_worker)

    asyncio.run(make_worker(store, repository)._execute(run))

    assert attempts == [1, 2]
    findings = store.list_findings(run["id"])
    assert len(findings) == 2
    assert len({item["category"] for item in findings}) == 2
    assert all(item["revision"] == 1 for item in findings)
    assert {item[identity_field][0] if identity_field == "preconditions" else item[identity_field] for item in findings} == {
        common_prefix + "操作甲", common_prefix + "操作乙",
    }
    assert store.get_run(run["id"])["status"] == "completed"


def test_identity_trims_outer_whitespace_but_ignores_title_summary_and_cvss(audit):
    store, repository, run = audit
    task = {"id": "stable-task", "context_spec": {"source_refs": [{"path": "public/index.php", "start_line": 1, "end_line": 4}]}}
    first = _findings("identity", count=1)
    first["result"]["finding"].update(dangerous_operation=" readfile($path) \n", preconditions=" 有效普通会员会话 ")
    second = copy.deepcopy(first)
    second["result"]["finding"].update(
        title="修订后的风险标题", summary="补充当前操作同一前提下的直接影响。", severity="critical",
        dangerous_operation="readfile($path)", preconditions="有效普通会员会话",
        cvss_input={"AV": {"value": "N", "rationale": "接口可通过网络请求访问。"}},
    )
    worker = make_worker(store, repository)

    before = worker._build_planner_findings(run, task, first)[0]["record"]
    after = worker._build_planner_findings(run, task, second)[0]["record"]

    assert before["category"] == after["category"]
    assert before["title"] != after["title"]
    assert before["summary"] != after["summary"]


def test_legacy_frozen_policy_keeps_historical_category_slots(audit):
    store, repository, run = audit
    legacy_run = {**run, "agent_policy": dict(run["agent_policy"])}
    legacy_run["agent_policy"].pop("worker_publication_findings", None)
    task = {"id": "legacy-task", "context_spec": {"source_refs": [{"path": "public/index.php", "start_line": 1, "end_line": 4}]}}
    outcome = _findings("legacy", count=1)
    worker = make_worker(store, repository)

    historical = worker._build_planner_findings(legacy_run, task, outcome)
    current = worker._build_planner_findings(run, task, outcome)

    assert historical[0]["record"]["category"] == "task_goal"
    assert current[0]["record"]["category"].startswith("task_goal:v2:")


def test_progress_signature_ignores_metadata_and_canonicalizes_read_windows():
    tasks = [{
        "id": "task", "state": "blocked", "attempts": 1, "revisions": 0,
        "context_spec": {"source_refs": [{"path": "a.php", "start_line": 1, "end_line": 4}]},
        "dependencies": [], "attempt_history": [{
            "attempt": 1, "state": "blocked", "outcome": "blocked",
            "seen": [{"path": "a.php", "start_line": 1, "end_line": 4}],
        }],
    }]
    base = _blocker_progress_signature(tasks, [])
    changed = copy.deepcopy(tasks)
    changed[0].update(plan_id="different", updated_at="later", title="renamed", priority=99)
    changed[0]["attempt_history"][0].update(id=99, created_at="later", usage={"requests": 99})
    changed[0]["attempt_history"][0]["seen"] = [
        {"path": "a.php", "start_line": 1, "end_line": 2},
        {"path": "a.php", "start_line": 3, "end_line": 4},
    ]
    changed.append({"id": "placeholder", "state": "deferred", "attempts": 0, "revisions": 0})
    assert _blocker_progress_signature(changed, []) == base
    changed[0]["revisions"] = 1
    assert _blocker_progress_signature(changed, []) != base
    changed[0]["revisions"] = 0
    changed[0]["attempt_history"][0]["seen"].append({"path": "a.php", "start_line": 5, "end_line": 5})
    assert _blocker_progress_signature(changed, []) != base


def test_progress_signature_tracks_only_validated_candidate_versions():
    candidate = {"id": "finding", "finding_kind": "vulnerability", "validation_state": "candidate", "revision": 1}
    base = _blocker_progress_signature([], [candidate])
    assert _blocker_progress_signature([], [{**candidate, "revision": 2}]) != base
    assert _blocker_progress_signature([], [{**candidate, "disposition": "retracted"}]) != base
    assert _blocker_progress_signature([], [{**candidate, "verification_status": "rejected"}]) != base
    assert _blocker_progress_signature([], [{**candidate, "validation_state": "rejected"}]) == _blocker_progress_signature([], [])
