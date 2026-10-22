"""Runtime regressions use isolated SQLite, fake clocks and fake agent calls only."""
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from audit.db import Store
from audit.execution_state import DEFAULT_RUN_LIMITS, execution_context
from audit.runtime import AgentPolicy, Execution, StopAudit
from audit.schemas import CreateRunRequest
from audit.source import SourceRepository
from tests.test_goal_tasks import TASK, create_planner_run, import_project, make_worker, proposal, run_payload, worker_outcome

@pytest.fixture
def setup_run(tmp_path):
    store = Store(tmp_path / "audit.db")
    repository = SourceRepository(tmp_path / "sources")
    run, _ = create_planner_run(store, repository)
    store._write("UPDATE run_execution_state SET limits=? WHERE run_id=?", (json.dumps(DEFAULT_RUN_LIMITS), run["id"]))
    yield store, repository, store.get_run(run["id"])
    store.close()

def test_strict_run_limits_and_defaults():
    value = CreateRunRequest(snapshot_id="s", task=TASK)
    assert value.run_limits.model_dump() == DEFAULT_RUN_LIMITS
    assert value.poc_mode == "off"
    for payload in ({"responses": "24"}, {"tools": True}, {"seconds": 29}, {"tools": -1}, {"responses": 4097}, {"unexpected": 1}, {"seconds": 30.5}):
        with pytest.raises(ValidationError):
            CreateRunRequest(snapshot_id="s", task=TASK, run_limits=payload)

def test_atomic_admission_last_response_and_resume_does_not_reset(setup_run):
    store, _, run = setup_run
    limits = {**DEFAULT_RUN_LIMITS, "responses": 1}
    store._write("UPDATE run_execution_state SET limits=? WHERE run_id=?", (json.dumps(limits), run["id"]))
    epoch = run["execution_epoch"]
    def admit(_):
        try:
            store.admit_execution(run["id"], epoch, "responses")
            return True
        except StopAudit:
            return False
    with ThreadPoolExecutor(2) as pool:
        assert sum(pool.map(admit, range(2))) == 1
    assert store.execution_summary(run["id"])["run_usage"]["responses"] == 1
    store.request_pause(run["id"])
    assert store.resume_run(run["id"]) is False
    store.quiesce_execution(run["id"])
    assert store.resume_run(run["id"])
    resumed = store.claim_next_run()
    assert resumed["execution_epoch"] == epoch + 1
    assert resumed["execution_summary"]["run_usage"]["responses"] == 1
    with pytest.raises(StopAudit):
        store.admit_execution(run["id"], resumed["execution_epoch"], "responses")

def test_local_and_shared_attempts_have_one_owner(setup_run):
    store, _, run = setup_run
    with execution_context(store, run["id"], run["execution_epoch"]):
        execution = Execution({"responses": 24, "tools": 1, "seconds": 30}, AgentPolicy(), lambda event: None)
        execution.enter("task_execute")
        for _ in range(10):
            execution.before_model(deadline=execution.deadline, limit=24, correction=False)
        execution.before_tool()
        with pytest.raises(StopAudit):
            execution.before_tool()
    summary = store.execution_summary(run["id"])
    assert summary["run_usage"]["responses"] == 10
    assert summary["run_usage"]["tools"] == 1

def test_late_epoch_business_results_are_rejected(setup_run):
    store, _, run = setup_run
    store.request_pause(run["id"])
    store.quiesce_execution(run["id"])
    assert store.resume_run(run["id"])
    resumed = store.claim_next_run()
    with execution_context(store, run["id"], run["execution_epoch"]):
        with pytest.raises(StopAudit, match="迟到"):
            store.begin_planner_round(run["id"], "old-thread")
    assert resumed["execution_epoch"] != run["execution_epoch"]

def test_exit_guard_and_cancellation_are_terminal_atomic(setup_run, monkeypatch):
    store, repository, run = setup_run
    worker = make_worker(store, repository)
    async def returns_without_finalization(_):
        return
    monkeypatch.setattr(worker, "_execute_body", returns_without_finalization)
    asyncio.run(worker._execute(run))
    result = store.get_run(run["id"])
    assert result["status"] == "failed"
    assert result["execution_summary"]["stop_reason"]["code"] == "worker_exit_without_terminal"
    assert result["final_summary"]["status"] == "failed"
    assert store.get_task_goal(run["id"])["status"] == "inconclusive"
    assert store.get_planner_session(run["id"])["terminal_state"] == "inconclusive"
    assert store.list_events(run["id"])[-1]["kind"] == "run_failed"
    store.update_run(run["id"], status="completed")
    assert store.get_run(run["id"])["status"] == "failed"

@pytest.mark.parametrize("dimension", ["responses", "tools", "seconds"])
def test_global_exhaustion_has_report_without_another_model(setup_run, monkeypatch, dimension):
    store, repository, run = setup_run
    limits = {**DEFAULT_RUN_LIMITS, dimension: 0 if dimension == "tools" else 1}
    store._write("UPDATE run_execution_state SET limits=? WHERE run_id=?", (json.dumps(limits), run["id"]))
    if dimension == "seconds":
        store._write("UPDATE run_execution_state SET active_elapsed_ms=1000 WHERE run_id=?", (run["id"],))
    elif dimension == "responses":
        store.admit_execution(run["id"], run["execution_epoch"], "responses")
    calls = []
    async def body(_):
        if dimension == "seconds":
            await asyncio.Event().wait()  # no tool/model events: independent watchdog
        else:
            store.admit_execution(run["id"], run["execution_epoch"], dimension)
            calls.append("must not run")
    worker = make_worker(store, repository)
    monkeypatch.setattr(worker, "_execute_body", body)
    asyncio.run(asyncio.wait_for(worker._execute(run), 2))
    result = store.get_run(run["id"])
    assert result["status"] == "inconclusive"
    assert result["execution_summary"]["stop_reason"]["dimension"] == dimension
    assert result["final_summary"]["source"] == "host"
    assert calls == []

def test_scenario_blockers_and_standing_finding_never_strand_run(setup_run, monkeypatch):
    from audit import worker as worker_module
    store, repository, run = setup_run
    task = {**TASK, "scenario": "sqli", "max_planner_rounds": 24}
    store._write("UPDATE runs SET task_spec=? WHERE id=?", (json.dumps(task), run["id"]))
    store._write("UPDATE planner_sessions SET max_rounds=24 WHERE run_id=?", (run["id"],))
    # The first task yields a valid finding, the second remains blocked. This is
    # the old unconditional-return path after finalize_goal('met') was refused.
    finding = {"title": "SQL query injection", "kind": "vulnerability", "severity": "high", "summary": "request reaches query", "evidence": "public/index.php:4-4"}
    async def plan(**kwargs):
        return {"decision": {"goal_state": "continue", "basis_summary": "审计入口", "tasks": [proposal("valid"), proposal("blocked", path="src/files.php")] if kwargs["round_no"] == 1 else [], "updates": []}, "terminal_reason": "completed", "usage": {}}
    async def pursue(**kwargs):
        if kwargs["planner_task"]["task_key"] == "valid":
            return worker_outcome("achieved", finding=finding, seen=[{"path": "public/index.php", "start_line": 4, "end_line": 4}])
        return worker_outcome("blocked")
    monkeypatch.setattr(worker_module, "plan_audit_frontier", plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", pursue)
    asyncio.run(make_worker(store, repository)._execute(store.get_run(run["id"])))
    result = store.get_run(run["id"])
    assert result["status"] == "inconclusive"
    assert result["final_summary"]
    assert store.get_planner_session(run["id"])["current_round"] <= 3

def test_required_not_ready_rejects_before_creating_any_run(tmp_path):
    from audit.app import create_run
    from audit.config import PocSettings
    from audit.events import EventBus
    store = Store(tmp_path / "audit.db")
    repository = SourceRepository(tmp_path / "sources")
    snapshot = import_project(repository)
    state = SimpleNamespace(store=store, repository=repository, settings=SimpleNamespace(poc=PocSettings(), model=SimpleNamespace(label="fake")), bus=EventBus(store), worker=SimpleNamespace(notify=lambda: None))
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))
    try:
        with pytest.raises(HTTPException) as failure:
            asyncio.run(create_run(request, CreateRunRequest(snapshot_id=snapshot["id"], task=TASK, poc_mode="required")))
        assert failure.value.status_code == 409
        assert failure.value.detail["code"] == "poc_not_ready"
        assert store.list_runs() == []
    finally:
        store.close()

def test_legacy_limits_null_and_new_tables_deleted(setup_run):
    store, repository, run = setup_run
    snapshot = import_project(repository)
    store.create_run(run_payload(snapshot, "legacy", [], TASK))
    assert store.get_run("legacy")["run_limits"] is None
    store.terminate_execution(run["id"], "cancelled", {"code": "user_cancelled"})
    store.delete_run(run["id"])
    assert store.execution_summary(run["id"]) is None
    assert not store._rows("SELECT * FROM poc_attempts WHERE run_id=?", (run["id"],))


def test_rejected_met_with_standing_finding_and_blocked_frontier_is_terminal(setup_run):
    from tests.test_goal_tasks import _conclusion_finding
    store, repository, run = setup_run
    task = {**TASK, "scenario": "sqli"}
    store._write("UPDATE runs SET task_spec=? WHERE id=?", (json.dumps(task), run["id"]))
    store.add_finding(_conclusion_finding(run))
    plan = store.begin_planner_round(run["id"], store.get_planner_session(run["id"])["session_id"])
    store.finish_planner_round(run["id"], plan["id"], goal_state="continue", basis_summary="存在未解决方向", tasks=[proposal("blocked")])
    work = store.claim_ready_task(run["id"], "worker")
    store.resolve_task_attempt(work["id"], "worker", outcome="blocked", result={"missing_context": ["runtime dependency"]}, usage={}, seen=[], error="missing dependency")
    store._write("UPDATE planner_sessions SET current_round=max_rounds WHERE run_id=?", (run["id"],))
    asyncio.run(make_worker(store, repository)._execute(store.get_run(run["id"])))
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.get_task_goal(run["id"])["status"] == "inconclusive"
    assert store.get_final_summary(run["id"])["valid_finding_count"] == 1
    assert store.has_event(run["id"], "planner_terminal_deferred")


def test_six_ledger_groups_cannot_be_replaced_by_a_one_group_model_report(setup_run):
    from tests.test_goal_tasks import _conclusion_finding
    from audit.report import render_markdown
    from audit.report_facts import validate_report_references
    store, _, run = setup_run
    for index in range(16):
        finding = {**_conclusion_finding(run, f"finding-{index}"), "unit_id": f"unit-{index}", "title": f"SQL injection {index}"}
        store.add_finding(finding)
        store.link_finding_project(finding["id"], f"ledger-{index % 6}", 1)
    context = store.list_planner_context(run["id"])
    with pytest.raises(ValueError, match="遗漏"):
        validate_report_references({"finding_refs": [{"finding_id": "finding-0", "revision": 1}]}, context)
    store.terminate_execution(run["id"], "inconclusive", {"code": "unresolved_blockers", "message": "Incomplete audit"})
    final_run = store.get_run(run["id"])
    summary = final_run["final_summary"]
    assert summary["raw_finding_count"] == summary["valid_finding_count"] == 16
    assert summary["ledger_group_count"] == 6
    assert {g["id"] for g in summary["finding_groups"]} == {f"ledger-{i}" for i in range(6)}
    report = render_markdown({"run": final_run, "report_narrative": {"summary": "Only one vulnerability. Everything else is safe."}})
    assert "Only one vulnerability" not in report
    assert "SQL injection 15" in report and "按台账身份分组：6" in report


def test_blocked_and_stale_report_references_are_rejected(setup_run):
    from audit.report_facts import validate_report_references
    with pytest.raises(ValueError, match="无证据"):
        validate_report_references({"finding_refs": [], "no_evidence_task_ids": ["blocked"]}, {"tasks": [{"id": "blocked", "state": "blocked", "result": {"outcome": "no_evidence"}}]})


def test_cancel_and_completion_race_has_one_coherent_terminal(setup_run):
    from tests.test_goal_tasks import _conclusion_finding
    store, _, run = setup_run
    store.add_finding(_conclusion_finding(run))
    def close():
        try:
            store.finalize_goal(run["id"], "met", "standing evidence")
        except ValueError:
            pass
    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(close), pool.submit(store.request_cancel, run["id"])]
        for future in futures:
            future.result()
    final_run = store.get_run(run["id"])
    assert final_run["status"] in ("completed", "cancelled")
    expected = "met" if final_run["status"] == "completed" else "inconclusive"
    assert store.get_task_goal(run["id"])["status"] == expected
    assert store.get_planner_session(run["id"])["terminal_state"] == expected
    assert final_run["final_summary"]["status"] == final_run["status"]


def test_delete_rollback_keeps_state_and_attempts_together(setup_run):
    store, _, run = setup_run
    store.terminate_execution(run["id"], "cancelled", {"code": "user_cancelled"})
    store._db.execute("CREATE TRIGGER fail_delete BEFORE DELETE ON runs BEGIN SELECT RAISE(ABORT,'rollback fixture'); END")
    with pytest.raises(Exception, match="rollback fixture"):
        store.delete_run(run["id"])
    assert store.get_run(run["id"]) is not None
    assert store.get_final_summary(run["id"]) is not None


def test_active_time_counts_wall_clock_once_and_excludes_quiescent_pause(setup_run, monkeypatch):
    from audit import execution_state
    store, _, run = setup_run
    clock = [0.0]
    monkeypatch.setattr(execution_state.time, "monotonic", lambda: clock[0])
    store._active_clocks[run["id"]] = 0
    clock[0] = 5
    for _ in range(2):
        store.admit_execution(run["id"], run["execution_epoch"], "responses")
    assert store.execution_summary(run["id"])["run_usage"]["seconds"] == 5
    store.request_pause(run["id"])
    clock[0] = 7
    store.quiesce_execution(run["id"])
    clock[0] = 100
    assert store.execution_summary(run["id"])["run_usage"]["seconds"] == 7
    assert store.resume_run(run["id"])
    store.claim_next_run()
    clock[0] = 103
    assert store.execution_summary(run["id"])["run_usage"]["seconds"] == 10
