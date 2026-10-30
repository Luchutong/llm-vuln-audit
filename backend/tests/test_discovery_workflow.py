"""Stage allocation is durable and shares the original global admission gate."""
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from audit import worker as worker_module
from audit.db import Store
from audit.execution_state import DEFAULT_RUN_LIMITS, CURRENT_EXECUTION, execution_context, execution_role
from audit.runtime import StopAudit
from audit.source import SourceRepository
from audit.workflow import freeze_workflow
from tests.test_goal_tasks import TASK, _conclusion_finding, import_project, make_worker, proposal, run_payload, worker_outcome


@pytest.fixture
def create(tmp_path):
    stores = []
    def factory(*, poc=True, total=256, seconds=1800):
        index = len(stores)
        store = Store(tmp_path / f"workflow-{index}.db")
        stores.append(store)
        repository = SourceRepository(tmp_path / f"sources-{index}")
        snapshot = import_project(repository)
        store.add_snapshot(snapshot)
        scope = ["public/index.php", "src/auth.php", "src/files.php"]
        task = {**TASK, "completion_policy": "coverage_review", "workflow_policy": "discovery_first",
                "stop_on_achieved": False, "max_planner_rounds": 12}
        payload = run_payload(snapshot, f"workflow-{index}", scope, task)
        payload.update(project_mode="project", poc_policy={"mode": "auto" if poc else "off", "enabled": poc},
                       run_limits={**DEFAULT_RUN_LIMITS, "responses": total, "seconds": seconds})
        store.create_run(payload)
        store.create_planner_session(payload["id"], "offline-session", 12,
                                     repository.build_project_map(snapshot["id"], set(scope)))
        run = store.claim_next_run()
        return store, repository, run
    yield factory
    for store in stores:
        store.close()


@pytest.mark.parametrize("poc,expected", [(True, {"discovery": 180, "poc": 64, "review": 12}),
                                          (False, {"discovery": 244, "poc": 0, "review": 12})])
def test_new_default_allocation_and_old_run_compatibility(create, poc, expected):
    store, _, run = create(poc=poc)
    value = store.workflow_state(run["id"])
    assert value["limits"] == expected
    assert value["review_reserved_seconds"] == 60
    assert value["used"] == dict.fromkeys(expected, 0)
    assert freeze_workflow({"task_spec": TASK}, DEFAULT_RUN_LIMITS) == {}


def test_discovery_leaves_a_poc_window_the_poc_stage_can_use(create):
    """The two gates must not be mutually exclusive.

    Discovery used to stop exactly when ``remaining <= review reserve`` while the
    POC stage required ``remaining > review reserve``, so a run that spent its
    clock on discovery could never start POC.  Discovery now leaves the POC
    window; once the stage switches, the same seconds admit POC work.
    """
    store, _, run = create(poc=True, total=256, seconds=1800)
    task = {**run["task_spec"], "orchestration_policy": "host-queue-v1"}
    store._write("UPDATE runs SET task_spec=? WHERE id=?", (json.dumps(task), run["id"]))
    run = store.get_run(run["id"])
    value = store.workflow_state(run["id"])
    window = value["poc_reserved_seconds"]
    assert window > 0
    review = float(value["review_reserved_seconds"])
    store._active_clocks.pop(run["id"], None)
    # One second inside the POC window: discovery is over, POC still has room.
    store._write("UPDATE run_execution_state SET active_elapsed_ms=? WHERE run_id=?",
                 (int((1800 - review - window + 1) * 1000), run["id"]))
    summary = store.execution_summary(run["id"])
    assert summary["workflow"]["stage_remaining_seconds"] == pytest.approx(1, abs=1)
    reserve = store.refresh_review_reserve(run["id"])
    assert not reserve["review_reserve"]["upstream_allowed"]
    assert reserve["review_reserve"]["poc_window_blocks"]
    with pytest.raises(StopAudit):
        store.admit_execution(run["id"], run["execution_epoch"], "responses")
    store.set_workflow_stage(run["id"], "poc")
    workflow = store.workflow_state(run["id"])
    assert workflow["stage_remaining_seconds"] > 0
    store.admit_execution(run["id"], run["execution_epoch"], "responses")


def test_poc_window_does_not_shrink_the_review_window(create):
    store, _, run = create(poc=True, total=256, seconds=1800)
    value = store.workflow_state(run["id"])
    assert value["review_reserved_seconds"] > 0
    assert value["poc_reserved_seconds"] + 180 <= 1800
    # A historical row without the frozen field keeps the old behaviour.
    legacy = dict(value)
    legacy.pop("poc_reserved_seconds")
    from audit.workflow import workflow_view
    view = workflow_view(legacy, remaining_seconds=1800)
    assert view["poc_reserved_seconds"] == 0
    assert view["stage_remaining_seconds"] == pytest.approx(1800 - value["review_reserved_seconds"])


def test_last_stage_response_is_admitted_atomically_and_tools_can_complete_it(create):
    store, _, run = create(total=8)
    limit = store.workflow_state(run["id"])["limits"]["discovery"]
    def admit(_):
        try:
            store.admit_execution(run["id"], run["execution_epoch"], "responses")
            return True
        except StopAudit as exc:
            assert exc.reason == "stage_budget_exhausted"
            return False
    with ThreadPoolExecutor(4) as pool:
        assert sum(pool.map(admit, range(limit + 4))) == limit
    store.admit_execution(run["id"], run["execution_epoch"], "tools")
    summary = store.execution_summary(run["id"])
    assert summary["run_usage"]["responses"] == limit
    assert summary["stop_reason"] is None
    assert store.get_run(run["id"])["status"] == "running"
    store.set_workflow_stage(run["id"], "review")
    store.admit_execution(run["id"], run["execution_epoch"], "responses")


def test_transfer_preserves_total_and_protected_review_and_phase_ownership(create):
    store, _, run = create()
    epoch = run["execution_epoch"]
    with execution_context(store, run["id"], epoch):
        with execution_role("poc"):
            with pytest.raises(StopAudit, match="POC"):
                store.admit_execution(run["id"], epoch, "responses")
        with execution_role("worker"):
            store.admit_execution(run["id"], epoch, "responses")
        store.set_workflow_stage(run["id"], "poc", reason={"state": "met"}, transfer_unused=True)
        value = store.workflow_state(run["id"])
        assert value["transferred"] == 179
        assert value["limits"] == {"discovery": 1, "poc": 243, "review": 12}
        with execution_role("worker"):
            with pytest.raises(StopAudit, match="源码挖掘阶段已结束"):
                store.admit_execution(run["id"], epoch, "responses")
        store.set_workflow_stage(run["id"], "review")
        with execution_role("poc"):
            with pytest.raises(StopAudit, match="POC"):
                store.admit_execution(run["id"], epoch, "responses")
        with pytest.raises(ValueError, match="already ended"):
            store.set_workflow_stage(run["id"], "discovery")
    assert sum(value["limits"].values()) == 256


def test_finished_poc_quota_moves_to_the_final_review(create):
    """A finished stage's unspent responses are the last stage's to use.

    A real closure run reviewed 21 of 22 batches and then closed "final review
    incomplete" with 75 responses in the review stage while the finished POC stage
    still held more than a thousand.  The POC stage had spent 138 of its 1809.
    """
    store, _, run = create()
    epoch = run["execution_epoch"]
    store.admit_execution(run["id"], epoch, "responses")
    store.set_workflow_stage(run["id"], "poc", reason={"state": "met"}, transfer_unused=True)
    store.set_workflow_stage(run["id"], "review")
    before = store.workflow_state(run["id"])
    assert before["limits"]["poc"] > before["limits"]["review"]
    after = store.release_poc_quota(run["id"])
    assert after["limits"]["poc"] == before["used"]["poc"]
    assert after["limits"]["review"] == before["limits"]["review"] + (before["limits"]["poc"] - before["used"]["poc"])
    assert sum(after["limits"].values()) == sum(before["limits"].values())
    assert store.release_poc_quota(run["id"])["limits"] == after["limits"]
    # An explicit allocation is the operator's and is never rewritten.
    store2, _, run2 = create()
    store2.set_workflow_stage(run2["id"], "poc", reason={"state": "met"})
    explicit_before = store2.workflow_state(run2["id"])
    explicit_before["source"] = "explicit"
    store2._write("UPDATE run_execution_state SET workflow=? WHERE run_id=?",
                  (json.dumps(explicit_before), run2["id"]))
    assert store2.release_poc_quota(run2["id"])["limits"] == explicit_before["limits"]


def test_pause_resume_and_reopen_connection_do_not_renew_stage_consumption(create):
    store, _, run = create()
    epoch = run["execution_epoch"]
    store.admit_execution(run["id"], epoch, "responses")
    store.set_workflow_stage(run["id"], "poc", reason={"state": "inconclusive"})
    store.admit_execution(run["id"], epoch, "responses")
    expected = store.workflow_state(run["id"])
    store.request_pause(run["id"])
    store.quiesce_execution(run["id"])
    assert store.resume_run(run["id"])
    resumed = store.claim_next_run()
    assert resumed["execution_epoch"] > epoch
    assert store.workflow_state(run["id"])["used"] == expected["used"]
    path = store._db.execute("PRAGMA database_list").fetchone()[2]
    reopened = Store(path)
    try:
        value = reopened.workflow_state(run["id"])
        assert value["stage"] == "poc"
        assert value["used"] == expected["used"]
    finally:
        reopened.close()


def test_final_review_time_is_reserved_without_changing_global_stop_reason(create):
    store, _, run = create()
    store._active_clocks.pop(run["id"], None)
    store._write("UPDATE run_execution_state SET active_elapsed_ms=? WHERE run_id=?", (1740000, run["id"]))
    with pytest.raises(StopAudit) as stopped:
        store.admit_execution(run["id"], run["execution_epoch"], "responses")
    assert stopped.value.reason == "stage_budget_exhausted"
    assert store.execution_summary(run["id"])["stop_reason"] is None
    store.set_workflow_stage(run["id"], "review")
    store.admit_execution(run["id"], run["execution_epoch"], "responses")
    assert store.workflow_state(run["id"])["stage_remaining_seconds"] == 60


def test_last_stage_response_cannot_be_spent_on_history_summary(create):
    from audit.codemodel import PhaseGate
    from audit.runtime import AgentPolicy, Execution
    store, _, run = create(total=8)
    cap = store.workflow_state(run["id"])["limits"]["discovery"]
    for _ in range(cap - 1):
        store.admit_execution(run["id"], run["execution_epoch"], "responses")
    async def check():
        with execution_context(store, run["id"], run["execution_epoch"]):
            execution = Execution({"responses": 24, "tools": 8, "seconds": 30}, AgentPolicy(), lambda event: None)
            gate = PhaseGate(execution=execution, loop=asyncio.get_running_loop(), dispatch=None,
                             deadline=execution.deadline, limit=24)
            assert not await gate._can_summarize()
    asyncio.run(check())


def test_reworded_duplicate_is_not_a_new_successful_batch_but_another_sink_is():
    from audit.worker import _new_conclusion_keys
    original = {"id": "old", "finding_kind": "vulnerability", "validation_state": "candidate", "disposition": "open",
                "vulnerability_type": "sqli", "primary_location": {"path": "query.php", "line": 5},
                "dangerous_operation": "PDO query executes concatenated user parameter", "fingerprint": "original"}
    reworded = {**original, "id": "new", "title": "same query reworded", "fingerprint": "new-prose-fingerprint",
                "dangerous_operation": "PDO query executes concatenated user parameter statement"}
    assert _new_conclusion_keys([{"candidate": True, "record": reworded}], [original]) == []
    distinct = {**reworded, "primary_location": {"path": "other.php", "line": 6}}
    assert _new_conclusion_keys([{"candidate": True, "record": distinct}], [original]) == [distinct["fingerprint"]]


@pytest.mark.parametrize("premature_met", [False, True])
def test_static_workers_finish_before_two_item_validation_and_final_review(create, monkeypatch, premature_met):
    store, repository, run = create()
    calls = []
    async def planner(**kwargs):
        stage = store.workflow_state(run["id"])["stage"]
        calls.append(("planner", stage))
        CURRENT_EXECUTION.get().admit("responses")
        return {"decision": {"goal_state": "continue" if kwargs["round_no"] == 1 and not premature_met else "met",
                "basis_summary": "已按实际源码证据完成本轮方向并复核当前结论。",
                "tasks": [proposal("source-flow")] if kwargs["round_no"] == 1 else []},
                "usage": {"requests": 1}, "terminal_reason": "completed"}
    async def source(**kwargs):
        calls.append(("worker", store.workflow_state(run["id"])["stage"]))
        CURRENT_EXECUTION.get().admit("responses")
        finding = {"title": "入口未约束路径进入文件操作", "kind": "vulnerability", "severity": "high",
                   "summary": "外部路径未经约束传入文件读取操作，能够越过预期目录。",
                   "vulnerability_type": "path_traversal", "primary_location": {"path": "public/index.php", "line": 4},
                   "evidence": "public/index.php:4-4", "dangerous_operation": "readfile of user-selected path"}
        return worker_outcome("achieved", finding=finding, seen=[
            {"path": "public/index.php", "start_line": 1, "end_line": 4},
            {"path": "src/auth.php", "start_line": 1, "end_line": 2},
            {"path": "src/files.php", "start_line": 1, "end_line": 5}])
    async def verify(_self, run_id, pending, verified_for, **kwargs):
        calls.append(("poc", store.workflow_state(run_id)["stage"]))
        assert kwargs["max_findings"] == 2
        CURRENT_EXECUTION.get().admit("responses")
        for finding in pending:
            verified_for[finding.get("project_finding_id") or finding["id"]] = finding.get("project_revision") or finding.get("revision") or 1
        return {"processed": 1, "remaining": 0}
    monkeypatch.setattr(worker_module, "plan_audit_frontier", planner)
    monkeypatch.setattr(worker_module, "pursue_planner_task", source)
    monkeypatch.setattr(worker_module.PocVerifier, "verify_standing", verify)
    asyncio.run(make_worker(store, repository)._execute(run))
    assert calls == [("planner", "discovery"), ("worker", "discovery"),
                     ("planner", "discovery"), ("poc", "poc"), ("planner", "review")]
    final = store.get_run(run["id"])
    assert final["status"] == "completed", final.get("error")
    workflow = final["execution_summary"]["workflow"]
    assert workflow["used"] == {"discovery": 3, "poc": 1, "review": 1}
    assert len(store.list_findings(run["id"])) == 1
    from audit.report_facts import render_host_summary
    host = final["final_summary"]
    assert host["execution"]["workflow"] == workflow
    report = render_host_summary(host)
    assert f"| 源码规划与挖掘 | {workflow['limits']['discovery']} | 3 |" in report
    assert "待验证：1；正式复核记录：0" in report


def test_stage_exhaustion_preserves_partial_findings_and_uses_only_reserved_review(create, monkeypatch):
    store, repository, run = create(total=8, poc=False)
    store.add_finding(_conclusion_finding(run))
    stages = []
    async def planner(**kwargs):
        state = store.workflow_state(run["id"])
        stage = state["stage"]
        stages.append(stage)
        for _ in range(state["remaining"][stage]):
            CURRENT_EXECUTION.get().admit("responses")
        return {"decision": {"goal_state": "continue", "tasks": [],
                              "basis_summary": "保留尚未执行方向，当前没有新的源码结算依据。"},
                "usage": {"requests": state["remaining"][stage]}, "terminal_reason": "completed"}
    async def no_worker(**kwargs):
        pytest.fail("No extra worker or POC should start after the discovery allowance")
    monkeypatch.setattr(worker_module, "plan_audit_frontier", planner)
    monkeypatch.setattr(worker_module, "pursue_planner_task", no_worker)
    monkeypatch.setattr(worker_module.PocVerifier, "verify_standing", no_worker)
    asyncio.run(make_worker(store, repository)._execute(run))
    assert stages == ["discovery", "review"]
    final = store.get_run(run["id"])
    assert final["status"] == "inconclusive"
    assert final["execution_summary"]["stop_reason"]["code"] == "stage_budget_exhausted"
    assert len(store.list_findings(run["id"])) == 1
    assert final["execution_summary"]["workflow"]["used"] == {"discovery": 7, "poc": 0, "review": 1}
