"""Exercise discovery-first review boundaries without models or a live runner."""
from __future__ import annotations

import asyncio
import json

from audit import worker as worker_module
from audit.execution_state import CURRENT_EXECUTION
from tests.test_discovery_workflow import create  # noqa: F401 - shared temporary-store fixture
from tests.test_goal_tasks import _conclusion_finding, make_worker


def _add_findings(store, run, count):
    for index in range(count):
        finding = _conclusion_finding(run, f"review-boundary-{index}")
        finding["unit_id"] = f"unit-review-boundary-{index}"
        finding["dangerous_operation"] = f"independent SQL sink {index}"
        store.add_finding(finding)
    assert len(store.list_findings(run["id"])) == count
    return store.list_findings(run["id"])


def _planner_result(reviews=None):
    return {"decision": {"goal_state": "continue", "tasks": [],
                         "basis_summary": "本轮复核已有观测；尚未执行的源码方向保留未决。",
                         "verification_reviews": reviews or []},
            "usage": {"requests": 1}, "terminal_reason": "completed"}


def _mark_attempted(verified_for, findings):
    for item in findings:
        verified_for[item.get("project_finding_id") or item["id"]] = int(
            item.get("project_revision") or item.get("revision") or 1)


def test_resume_reviews_previous_batch_then_continues_waiting_pocs(create, monkeypatch):
    store, repository, run = create(poc=True)
    findings = _add_findings(store, run, 3)
    previous = findings[0]
    store.set_finding_verification_state(previous["id"], "verified", "confirmed")
    store.set_workflow_stage(run["id"], "review", reason={
        "state": "inconclusive", "basis": "离线恢复：源码阶段尚有明确的覆盖限制。"})
    assert len(store.unreviewed_verified_findings(run["id"])) == 1
    store.request_pause(run["id"])
    store.quiesce_execution(run["id"])
    assert store.resume_run(run["id"])
    resumed = store.claim_next_run()
    assert resumed["execution_epoch"] > run["execution_epoch"]
    calls = []

    async def planner(**kwargs):
        assert store.workflow_state(run["id"])["stage"] == "review"
        CURRENT_EXECUTION.get().admit("responses")
        pending = store.unreviewed_verified_findings(run["id"])
        calls.append(("review", len(pending)))
        return _planner_result([{
            "finding_id": item["id"], "revision": item.get("revision") or 1,
            "verification_id": item.get("verification_id") or "", "decision": "confirmed",
            "rationale_summary": "复核宿主保存的正常与攻击观测，结论版本和验证引用一致。",
        } for item in pending])

    async def verify(_self, run_id, pending, verified_for, **kwargs):
        assert store.unreviewed_verified_findings(run_id) == []
        assert store.workflow_state(run_id)["stage"] == "poc"
        assert kwargs["max_findings"] == 2
        CURRENT_EXECUTION.get().admit("responses")
        selected = [item for item in pending if item["id"] != previous["id"]]
        assert len(selected) == 2
        calls.append(("poc", len(selected)))
        for item in selected:
            store.set_finding_verification_state(item["id"], "inconclusive", "uncertain")
        _mark_attempted(verified_for, pending)
        return {"processed": len(selected), "remaining": 0,
                "processed_findings": [{"finding_id": item["id"], "status": "inconclusive"} for item in selected]}

    monkeypatch.setattr(worker_module, "plan_audit_frontier", planner)
    monkeypatch.setattr(worker_module.PocVerifier, "verify_standing", verify)
    asyncio.run(make_worker(store, repository)._execute(resumed))
    assert calls == [("review", 1), ("poc", 2), ("review", 0)]
    assert len(store.list_verification_reviews(run["id"])) == 1
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.workflow_state(run["id"])["used"] == {"discovery": 0, "poc": 1, "review": 2}


def test_each_two_nonverified_results_still_receive_a_planner_review(create, monkeypatch):
    store, repository, run = create(poc=True)
    _add_findings(store, run, 6)
    store.set_workflow_stage(run["id"], "poc", reason={
        "state": "inconclusive", "basis": "仅验证已保存候选，不将未读源码解释为安全。"})
    calls = []
    processed = set()

    async def verify(_self, run_id, pending, verified_for, **kwargs):
        assert kwargs["max_findings"] == 2
        assert store.workflow_state(run_id)["stage"] == "poc"
        CURRENT_EXECUTION.get().admit("responses")
        selected = [item for item in pending if item["id"] not in processed][:2]
        assert len(selected) == 2
        statuses = ("inconclusive", "rejected")
        for item, status in zip(selected, statuses):
            processed.add(item["id"])
            store.set_finding_verification_state(item["id"], status,
                "uncertain" if status == "inconclusive" else "rejected")
        _mark_attempted(verified_for, selected)
        calls.append(("poc", len(selected)))
        return {"processed": 2, "remaining": 6 - len(processed),
                "processed_findings": [{"finding_id": item["id"], "status": status}
                                       for item, status in zip(selected, statuses)]}

    async def planner(**kwargs):
        assert store.workflow_state(run["id"])["stage"] == "review"
        assert store.unreviewed_verified_findings(run["id"]) == []
        CURRENT_EXECUTION.get().admit("responses")
        calls.append(("review", len(processed)))
        return _planner_result()

    monkeypatch.setattr(worker_module, "plan_audit_frontier", planner)
    monkeypatch.setattr(worker_module.PocVerifier, "verify_standing", verify)
    asyncio.run(make_worker(store, repository)._execute(run))
    assert calls == [("poc", 2), ("review", 2), ("poc", 2), ("review", 4),
                     ("poc", 2), ("review", 6)]
    assert len(processed) == 6
    assert store.list_verification_reviews(run["id"]) == []  # No invented verified sign-off.
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.workflow_state(run["id"])["used"] == {"discovery": 0, "poc": 3, "review": 3}


def test_default_round_limit_reserves_six_rounds_for_dynamic_review(create, monkeypatch):
    store, repository, run = create(poc=True)
    _add_findings(store, run, 1)
    task = {**run["task_spec"], "max_planner_rounds": 24}
    store._write("UPDATE runs SET task_spec=? WHERE id=?", (json.dumps(task), run["id"]))
    store._write("UPDATE planner_sessions SET max_rounds=24,current_round=17 WHERE run_id=?", (run["id"],))
    run = store.get_run(run["id"])
    assert store.workflow_state(run["id"])["review_reserved_rounds"] == 6
    calls = []

    async def planner(**kwargs):
        stage = store.workflow_state(run["id"])["stage"]
        CURRENT_EXECUTION.get().admit("responses")
        calls.append(("planner", stage, kwargs["round_no"]))
        return _planner_result()

    async def verify(_self, run_id, pending, verified_for, **kwargs):
        CURRENT_EXECUTION.get().admit("responses")
        calls.append(("poc", store.workflow_state(run_id)["stage"], None))
        _mark_attempted(verified_for, pending)
        return {"processed": 1, "remaining": 0,
                "processed_findings": [{"finding_id": pending[0]["id"], "status": "inconclusive"}]}

    async def no_source(**kwargs):
        raise AssertionError("Reserved Planner rounds must not dispatch another source worker")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", planner)
    monkeypatch.setattr(worker_module.PocVerifier, "verify_standing", verify)
    monkeypatch.setattr(worker_module, "pursue_planner_task", no_source)
    asyncio.run(make_worker(store, repository)._execute(run))
    assert calls == [("planner", "discovery", 18), ("poc", "poc", None), ("planner", "review", 19)]
    final = store.get_run(run["id"])
    assert final["status"] == "inconclusive"
    assert final["execution_summary"]["stop_reason"]["code"] == "discovery_round_limit"
    assert final["execution_summary"]["workflow"]["used"] == {"discovery": 1, "poc": 1, "review": 1}
    assert store.get_planner_session(run["id"])["current_round"] == 19
