"""Real-request admission uses temporary SQLite only; no SDK or runner is started."""
from __future__ import annotations

import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from audit.db import Store
from audit import execution_state
from audit.execution_state import comparison_deadline, execution_role
from audit.workflow import freeze_workflow
from tests.test_goal_tasks import TASK, run_payload
from tests.test_poc_store import record, state


@pytest.fixture
def create(tmp_path):
    stores = []

    def factory(*, responses=12, poc=3, seconds=1800, workflow=True, limited=True, conclude_requests=1):
        store = Store(tmp_path / f"gateway-{len(stores)}.sqlite")
        stores.append(store)
        task = {**TASK}
        if workflow:
            task.update(workflow_policy="discovery_first",
                        workflow_limits={"discovery": 1, "poc": poc, "review": 1})
        payload = run_payload({"id": "snapshot", "name": "Offline target"}, "run", [], task)
        payload["poc_policy"] = {"mode": "auto", "enabled": True}
        if limited:
            payload["run_limits"] = {"responses": responses, "tools": 50, "seconds": seconds}
        store.create_run(payload)
        run = store.claim_next_run()
        if workflow:
            store.set_workflow_stage(run["id"], "poc")
        epoch = run["execution_epoch"]
        for stage in ("execute", "conclude"):
            limit = conclude_requests if stage == "conclude" else 40
            assert store.open_poc_request_stage(run["id"], stage, limit, epoch=epoch)["ok"]
        return store, run

    yield factory
    for store in stores:
        store.close()


def usage(store, run):
    row = store._db.execute(
        "SELECT responses_used,workflow FROM run_execution_state WHERE run_id=?", (run["id"],),
    ).fetchone()
    workflow = json.loads(row["workflow"] or "{}")
    return int(row["responses_used"]), workflow.get("used", {}).get("poc")


def admissions(store, run):
    return [event for event in store.list_events(run["id"])
            if event["kind"] == "poc_gateway_request"]


def reserve(store, run, stage="execute"):
    return store.reserve_poc_request(run["id"], stage, epoch=run["execution_epoch"])


def test_parallel_connections_share_run_workflow_and_real_request_ledger(create):
    store, run = create(poc=3)
    reopened = Store(store.path)
    try:
        def admit(index):
            owner = (store, reopened)[index % 2]
            return reserve(owner, run, ("execute", "conclude")[index % 2])

        with ThreadPoolExecutor(8) as pool:
            replies = list(pool.map(admit, range(12)))
        assert sum(reply["granted"] for reply in replies) == 3
        assert {reply["reason"] for reply in replies if not reply["granted"]} <= {
            "stage_budget_exhausted", "quota_exhausted", "quota_refused"}
        assert usage(store, run) == (3, 3)
        quota = store.poc_request_quota(run["id"], run["execution_epoch"])
        assert sum(stage["used"] for stage in quota.values()) == 3
        requests = admissions(reopened, run)
        assert [event["payload"]["request_index"] for event in requests] == [1, 2, 3]
        assert requests[-1]["payload"]["workflow_responses_used"] == 3
        assert all(event["payload"]["runtime"] == "claude_sdk" for event in requests)
        assert not {"model_request", "model_response"} & {event["kind"] for event in store.list_events(run["id"])}
        assert store.execution_summary(run["id"])["stop_reason"] is None
    finally:
        reopened.close()


def test_run_budget_overrides_a_larger_gateway_stage_allowance(create):
    store, run = create(responses=1, workflow=False)
    assert reserve(store, run, "conclude")["granted"]
    denied = reserve(store, run, "conclude")
    assert denied["reason"] == "run_budget_exhausted"
    assert denied["used"] == 1
    assert usage(store, run) == (1, None)
    assert len(admissions(store, run)) == 1
    assert store.execution_summary(run["id"])["stop_reason"]["dimension"] == "responses"


def test_native_and_sdk_requests_consume_the_same_frozen_workflow_allowance(create):
    store, run = create(poc=3)
    with execution_role("poc"):
        store.admit_execution(run["id"], run["execution_epoch"], "responses")
    assert reserve(store, run)["granted"]
    assert reserve(store, run, "conclude")["granted"]
    assert reserve(store, run)["reason"] == "stage_budget_exhausted"
    assert usage(store, run) == (3, 3)
    assert len(admissions(store, run)) == 2


def test_stage_quota_refusal_spends_no_run_slots_and_preserves_conclusion_allowance(create):
    store, run = create(poc=3)
    store._write("UPDATE poc_request_quota SET request_limit=1 WHERE run_id=? AND stage='execute'", (run["id"],))
    assert reserve(store, run)["granted"]
    assert reserve(store, run)["reason"] == "quota_exhausted"
    assert reserve(store, run)["reason"] == "quota_refused"
    assert usage(store, run) == (1, 1)
    assert len(admissions(store, run)) == 1
    assert reserve(store, run, "conclude")["granted"]
    assert usage(store, run) == (2, 2)


@pytest.mark.parametrize("ceiling", ["run", "workflow"])
def test_execute_atomically_leaves_three_shared_responses_for_conclusion(create, ceiling):
    store, run = create(responses=4 if ceiling == "run" else 12, poc=4,
                        workflow=ceiling == "workflow", conclude_requests=3)
    with ThreadPoolExecutor(6) as pool:
        replies = list(pool.map(lambda _: reserve(store, run), range(8)))
    assert sum(reply["granted"] for reply in replies) == 1
    refusal = next(reply for reply in replies if reply.get("conclusion_reserved"))
    assert refusal["reason"] == "quota_exhausted"
    assert refusal["conclude_remaining"] == 3
    assert refusal["used"] == 1
    assert usage(store, run) == (1, 1 if ceiling == "workflow" else None)
    assert store.execution_summary(run["id"])["stop_reason"] is None
    for _ in range(3):
        assert reserve(store, run, "conclude")["granted"]
    assert usage(store, run) == (4, 4 if ceiling == "workflow" else None)
    assert len(admissions(store, run)) == 4
    quota = store.poc_request_quota(run["id"], run["execution_epoch"])
    assert quota["execute"]["limit"] == 40
    assert quota["execute"]["used"] == 1 and quota["execute"]["refused"]
    assert quota["conclude"]["used"] == 3
    assert store.execution_summary(run["id"])["stop_reason"] is None


def test_no_experiment_starts_when_only_the_conclusion_responses_remain(create):
    store, run = create(responses=3, workflow=False, conclude_requests=3)
    refusal = reserve(store, run)
    assert refusal["reason"] == "quota_exhausted" and refusal["conclusion_reserved"]
    assert usage(store, run) == (0, None)
    assert not admissions(store, run)
    assert store.execution_summary(run["id"])["stop_reason"] is None
    for _ in range(3):
        assert reserve(store, run, "conclude")["granted"]


def test_only_unused_conclusion_responses_are_reserved(create):
    store, run = create(responses=5, workflow=False, conclude_requests=3)
    assert reserve(store, run, "conclude")["granted"]
    assert reserve(store, run)["granted"]
    assert reserve(store, run)["granted"]
    refusal = reserve(store, run)
    assert refusal["conclusion_reserved"] and refusal["conclude_remaining"] == 2
    assert usage(store, run) == (3, None)
    assert reserve(store, run, "conclude")["granted"]
    assert reserve(store, run, "conclude")["granted"]
    assert usage(store, run) == (5, None)


@pytest.mark.parametrize("fence", ["old_epoch", "pause_requested", "paused", "cancelled", "ended"])
def test_execution_fences_refuse_without_spending_any_counter(create, fence):
    store, run = create()
    if fence == "old_epoch":
        store._write("UPDATE run_execution_state SET claim_epoch=claim_epoch+1 WHERE run_id=?", (run["id"],))
    elif fence == "pause_requested":
        store.request_pause(run["id"])
    elif fence == "paused":
        store._write("UPDATE run_execution_state SET phase='paused' WHERE run_id=?", (run["id"],))
    elif fence == "cancelled":
        store.request_cancel(run["id"])
    else:
        store._write("UPDATE run_execution_state SET phase='ended' WHERE run_id=?", (run["id"],))
    denied = reserve(store, run)
    assert denied["reason"] == ("stale_epoch" if fence == "old_epoch" else "interrupted")
    assert usage(store, run) == (0, 0)
    assert store.poc_request_quota(run["id"], run["execution_epoch"])["execute"]["used"] == 0
    assert not admissions(store, run)


@pytest.mark.parametrize("stage", ["discovery", "review"])
def test_gateway_does_not_depend_on_http_task_role_context(create, stage):
    store, run = create()
    workflow = store.workflow_state(run["id"])
    workflow["stage"] = stage
    store._write("UPDATE run_execution_state SET workflow=? WHERE run_id=?", (json.dumps(workflow), run["id"]))
    assert reserve(store, run)["reason"] == "stage_budget_exhausted"
    assert usage(store, run) == (0, 0)
    assert not admissions(store, run)


@pytest.mark.parametrize("boundary", ["run_seconds", "review_reserve", "comparison_deadline"])
def test_elapsed_and_scoped_deadlines_refuse_without_charging(create, boundary):
    store, run = create(seconds=100)
    store._active_clocks.pop(run["id"], None)
    if boundary == "comparison_deadline":
        with comparison_deadline(time.monotonic() - 1):
            denied = reserve(store, run)
        assert denied["reason"] == "batch_deadline_exceeded"
        assert store.get_run(run["id"])["status"] == "interrupted"
    else:
        elapsed = 100_000 if boundary == "run_seconds" else 95_000
        store._write("UPDATE run_execution_state SET active_elapsed_ms=? WHERE run_id=?", (elapsed, run["id"]))
        denied = reserve(store, run)
        assert denied["reason"] == ("run_budget_exhausted" if boundary == "run_seconds" else "stage_budget_exhausted")
    assert usage(store, run) == (0, 0)
    assert not admissions(store, run)


def test_comparison_deadline_is_rechecked_after_acquiring_the_write_transaction(create, monkeypatch):
    store, run = create()
    # The deadline passes while acquiring the database writer lock. No real wait
    # or target is needed to reproduce that boundary deterministically.
    remaining = iter((1.0, -1.0))
    monkeypatch.setattr(execution_state, "comparison_deadline_remaining", lambda: next(remaining, -1.0))
    assert reserve(store, run)["reason"] == "batch_deadline_exceeded"
    assert usage(store, run) == (0, 0)
    assert not admissions(store, run)
    assert store.get_run(run["id"])["status"] == "interrupted"


def test_gateway_event_failure_rolls_back_all_admission_counters(create):
    store, run = create()
    store._db.execute("CREATE TRIGGER reject_gateway_event BEFORE INSERT ON events "
                      "WHEN NEW.kind='poc_gateway_request' BEGIN SELECT RAISE(ABORT,'event unavailable'); END")
    with pytest.raises(sqlite3.IntegrityError, match="event unavailable"):
        reserve(store, run)
    assert usage(store, run) == (0, 0)
    assert store.poc_request_quota(run["id"], run["execution_epoch"])["execute"]["used"] == 0
    assert not admissions(store, run)
    store._db.execute("DROP TRIGGER reject_gateway_event")
    assert reserve(store, run)["granted"]
    assert usage(store, run) == (1, 1)


def test_refused_stage_admission_does_not_erase_actual_active_time(create, monkeypatch):
    store, run = create(poc=0)
    store._active_clocks[run["id"]] = 0.0
    monkeypatch.setattr(execution_state.time, "monotonic", lambda: 1.5)
    assert reserve(store, run)["reason"] == "stage_budget_exhausted"
    assert usage(store, run) == (0, 0)
    assert store.execution_summary(run["id"])["run_usage"]["seconds"] == 1.5


def test_historical_null_limits_count_requests_without_inventing_a_run_ceiling(create):
    store, run = create(workflow=False, limited=False)
    for _ in range(3):
        assert reserve(store, run)["granted"]
    assert usage(store, run) == (3, None)
    summary = store.execution_summary(run["id"])
    assert summary["run_limits"] is None and summary["run_remaining"] is None
    assert len(admissions(store, run)) == 3


def test_resume_preserves_run_and_workflow_usage_when_epoch_quota_reopens(create):
    store, run = create(poc=2)
    assert reserve(store, run)["granted"]
    store.request_pause(run["id"])
    store.quiesce_execution(run["id"])
    assert store.resume_run(run["id"])
    newer = store.claim_next_run()
    assert newer["execution_epoch"] > run["execution_epoch"]
    store.open_poc_request_stage(newer["id"], "execute", 40, epoch=newer["execution_epoch"])
    assert reserve(store, run)["reason"] == "stale_epoch"
    assert reserve(store, newer)["granted"]
    assert reserve(store, newer)["reason"] == "stage_budget_exhausted"
    assert usage(store, newer) == (2, 2)
    assert len(admissions(store, newer)) == 2


@pytest.mark.parametrize("boundary", ["run", "workflow"])
def test_last_admitted_response_can_publish_even_after_a_following_request_is_refused(state, boundary):
    store, run, finding = state
    epoch = run["execution_epoch"]
    limits = {"responses": 1 if boundary == "run" else 10, "tools": 50, "seconds": 1800}
    store._write("UPDATE run_execution_state SET limits=? WHERE run_id=?",
                 (json.dumps(limits), run["id"]))
    if boundary == "workflow":
        workflow = freeze_workflow({"task_spec": {"workflow_policy": "discovery_first",
            "workflow_limits": {"discovery": 8, "poc": 1, "review": 1}},
            "poc_policy": {"mode": "auto", "enabled": True}}, limits)
        workflow["stage"] = "poc"
        store._write("UPDATE run_execution_state SET workflow=? WHERE run_id=?", (json.dumps(workflow), run["id"]))
    attempt = store.claim_poc_attempt(run["id"], finding, "target", epoch)
    assert store.start_poc_attempt(attempt["key"], epoch)
    assert store.open_poc_request_stage(run["id"], "conclude", 1, epoch=epoch)["ok"]
    assert reserve(store, run, "conclude")["granted"]
    assert reserve(store, run, "conclude")["reason"] == ("run_budget_exhausted" if boundary == "run" else "stage_budget_exhausted")
    assert store.record_automatic_verification_guarded(record(finding), attempt_key=attempt["key"], epoch=epoch)
    assert store.get_finding(finding["id"])["verification_status"] == "verified"
    assert len(admissions(store, run)) == 1
