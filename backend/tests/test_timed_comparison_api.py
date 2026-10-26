"""Limited comparison timing/API contracts, with no model or audit database."""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from audit import app as app_module
from audit.execution_state import (CURRENT_COMPARISON_DEADLINE, DEFAULT_RUN_LIMITS,
                                   comparison_deadline, comparison_deadline_remaining, execution_context)
from audit.db import Store
from audit.runtime import AgentPolicy, Execution, StopAudit
from audit.schemas import CreateRunRequest, PromptExperimentRequest, RunLimits
from audit.source import SourceRepository
from tests.test_goal_tasks import create_planner_run
from tests.test_project_findings import _finding


def full_request(**changes):
    value = {"protocol": "lab30-full-v2", "prompt_ids": ["a", "b", "c"],
             "baseline_prompt_id": "a", "repeats": 3}
    return PromptExperimentRequest(**{**value, **changes})


def test_only_full_experiments_default_to_twelve_minutes():
    full = full_request()
    assert full.run_limits.seconds == 720 and full.experiment_wall_seconds == 7200
    assert full.run_limits.responses == 256 and full.run_limits.tools == 2048
    assert PromptExperimentRequest().run_limits.seconds == 1800
    assert RunLimits().seconds == 1800 and DEFAULT_RUN_LIMITS["seconds"] == 1800
    run = CreateRunRequest(snapshot_id="snapshot", task={"objective": "完整检查项目安全缺陷"})
    assert run.run_limits.seconds == 1800


def test_partial_full_run_limits_also_default_seconds_without_mutating_input():
    original = {"responses": 123}
    full = full_request(run_limits=original)
    assert full.run_limits.responses == 123 and full.run_limits.seconds == 720
    assert original == {"responses": 123}
    assert PromptExperimentRequest(run_limits={"responses": 123}).run_limits.seconds == 1800


@pytest.mark.parametrize("seconds", [721, 1800, 14400, True, "720", 720.0])
def test_full_seconds_cannot_exceed_cap_or_be_coerced(seconds):
    with pytest.raises(ValidationError):
        full_request(run_limits={"seconds": seconds})


@pytest.mark.parametrize("wall", [7199, 7201, 0, True, "7200", 7200.0, None])
def test_batch_wall_is_a_fixed_strict_two_hour_budget(wall):
    with pytest.raises(ValidationError):
        full_request(experiment_wall_seconds=wall)


def test_total_lifecycle_headroom_is_validated_for_actual_trial_count():
    assert full_request().repeats * 3 * (720 + 60) + 180 == 7200
    with pytest.raises(ValidationError, match="7200"):
        full_request(repeats=4)
    assert full_request(repeats=4, run_limits={"seconds": 525}).run_limits.seconds == 525
    with pytest.raises(ValidationError, match="7200"):
        full_request(repeats=4, run_limits={"seconds": 526})
    five = ["a", "b", "c", "d", "e"]
    assert full_request(prompt_ids=five, repeats=5, run_limits={"seconds": 220}).repeats == 5
    with pytest.raises(ValidationError, match="7200"):
        full_request(prompt_ids=five, repeats=5, run_limits={"seconds": 221})


def execution():
    records = []
    value = Execution(budgets={"responses": 24, "tools": 96, "seconds": 720},
                      policy=AgentPolicy(), emit=records.append)
    value.enter("task_execute")
    return value, records


def test_model_request_timeout_is_capped_by_scoped_comparison_deadline():
    value, records = execution()
    with comparison_deadline(time.monotonic() + 3):
        seconds = value.before_model(deadline=value.deadline, limit=24, correction=False)
    assert 0 < seconds <= 3
    assert value.attempts == 1
    assert sum(e["kind"] == "model_request" for e in records) == 1
    assert CURRENT_COMPARISON_DEADLINE.get() is None


def test_expired_batch_deadline_refuses_before_billing_or_publishing_request():
    value, records = execution()
    with comparison_deadline(time.monotonic() - 1):
        with pytest.raises(StopAudit) as error:
            value.before_model(deadline=value.deadline, limit=24, correction=False)
    assert error.value.reason == "batch_deadline_exceeded"
    assert value.attempts == 0 and value.corrections == 0
    assert not any(e["kind"] == "model_request" for e in records)


def test_deadline_scope_restores_parent_even_on_failure_and_ordinary_audits_unchanged():
    assert comparison_deadline_remaining() is None
    with comparison_deadline(time.monotonic() + 100):
        parent = CURRENT_COMPARISON_DEADLINE.get()
        with pytest.raises(RuntimeError):
            with comparison_deadline(time.monotonic() + 1):
                raise RuntimeError("test")
        assert CURRENT_COMPARISON_DEADLINE.get() == parent
    assert CURRENT_COMPARISON_DEADLINE.get() is None
    value, _ = execution()
    seconds = value.before_model(deadline=value.deadline, limit=24, correction=False)
    assert 179 < seconds <= AgentPolicy().request_seconds


def test_context_deadlines_do_not_leak_between_async_trials():
    async def one(seconds):
        with comparison_deadline(time.monotonic() + seconds):
            await asyncio.sleep(0)
            return comparison_deadline_remaining()
    async def scenario():
        return await asyncio.gather(one(10), one(20))
    a, b = asyncio.run(scenario())
    assert 9 < a <= 10 and 19 < b <= 20
    assert comparison_deadline_remaining() is None


@pytest.fixture
def scoped_run(tmp_path):
    store = Store(tmp_path / "audit.db")
    repository = SourceRepository(tmp_path / "source")
    run, _ = create_planner_run(store, repository)
    yield store, run
    store.close()


@pytest.mark.parametrize("dimension", [None, "responses", "tools", "work"])
def test_expired_deadline_atomically_fences_new_admission_without_billing(scoped_run, dimension):
    store, run = scoped_run
    with comparison_deadline(time.monotonic() - 1):
        with pytest.raises(StopAudit) as error:
            store.admit_execution(run["id"], run["execution_epoch"], dimension)
    assert error.value.reason == "batch_deadline_exceeded"
    current = store.get_run(run["id"])
    assert current["status"] == "interrupted"
    assert current["execution_summary"]["stop_reason"]["code"] == "batch_deadline_exceeded"
    assert current["execution_summary"]["run_usage"]["responses"] == 0
    assert current["execution_summary"]["run_usage"]["tools"] == 0
    assert current["final_summary"] is not None


def test_expired_before_tool_never_counts_and_fences_its_owner(scoped_run):
    store, run = scoped_run
    with execution_context(store, run["id"], run["execution_epoch"]):
        value, _ = execution()
        with comparison_deadline(time.monotonic() - 1):
            with pytest.raises(StopAudit) as error:
                value.before_tool()
    assert error.value.reason == "batch_deadline_exceeded" and value.tools == 0
    assert store.get_run(run["id"])["status"] == "interrupted"
    assert store.execution_summary(run["id"])["run_usage"]["tools"] == 0


def test_expired_model_request_fences_its_owner_before_counting(scoped_run):
    store, run = scoped_run
    with execution_context(store, run["id"], run["execution_epoch"]):
        value, _ = execution()
        with comparison_deadline(time.monotonic() - 1):
            with pytest.raises(StopAudit):
                value.before_model(deadline=value.deadline, limit=24, correction=False)
    assert value.attempts == 0
    assert store.get_run(run["id"])["status"] == "interrupted"


def test_expired_scope_refuses_late_finding_write(scoped_run):
    store, run = scoped_run
    record = {**_finding(), "run_id": run["id"]}
    with execution_context(store, run["id"], run["execution_epoch"]), comparison_deadline(time.monotonic() - 1):
        with pytest.raises(StopAudit) as error:
            store.add_finding(record)
    assert error.value.reason == "batch_deadline_exceeded"
    assert not store.list_findings(run["id"])
    assert store.get_run(run["id"])["status"] == "interrupted"


def test_expired_old_owner_cannot_terminate_new_claim(scoped_run):
    store, run = scoped_run
    store.request_pause(run["id"])
    store.quiesce_execution(run["id"])
    assert store.resume_run(run["id"])
    newer = store.claim_next_run()
    assert newer["execution_epoch"] != run["execution_epoch"]
    with execution_context(store, run["id"], run["execution_epoch"]), comparison_deadline(time.monotonic() - 1):
        with pytest.raises(StopAudit):
            store.add_finding({**_finding(), "run_id": run["id"]})
    assert store.get_run(run["id"])["status"] == "running"
    assert store.execution_write_allowed(run["id"], newer["execution_epoch"])


def test_inner_transaction_rejects_without_nested_begin_or_committing_business(scoped_run):
    store, run = scoped_run
    with execution_context(store, run["id"], run["execution_epoch"]), comparison_deadline(time.monotonic() - 1):
        store._db.execute("BEGIN IMMEDIATE")
        try:
            with pytest.raises(StopAudit):
                store.assert_execution_write(run["id"])
        finally:
            store._db.execute("ROLLBACK")
        with pytest.raises(StopAudit):
            store.admit_execution(run["id"], run["execution_epoch"], None)
    assert store.get_run(run["id"])["status"] == "interrupted"


class FakeFull:
    def __init__(self):
        self.calls = []

    def events(self, ident, trial_id, after=0, limit=100, attempt=None, *, before=None):
        self.calls.append({"ident": ident, "trial_id": trial_id, "after": after,
                           "limit": limit, "attempt": attempt, "before": before})
        return {"events": [{"id": 98}, {"id": 99}], "remaining": 0,
                "has_earlier": True, "event_cursor": 99}

    def trial_detail(self, ident, trial_id, attempt=None):
        self.calls.append({"detail": ident, "trial_id": trial_id, "attempt": attempt})
        return {"trial": {"id": trial_id}, "run": {"id": "isolated-run"},
                "events": [{"id": 1001}, {"id": 1002}], "event_cursor": 1002, "has_earlier": True}


class FakeExperiments:
    def __init__(self):
        self.full = FakeFull()
        self.started = []

    def start_full(self, payload):
        self.started.append(payload.model_dump())
        return {"id": "offline-experiment", "protocol": payload.protocol, "status": "running"}


@pytest.fixture
def api(monkeypatch):
    experiments = FakeExperiments()
    monkeypatch.setattr(app_module.app.state, "services", SimpleNamespace(prompt_experiments=experiments), raising=False)
    client = TestClient(app_module.app)
    yield client, experiments
    client.close()


def test_create_api_freezes_new_limits_and_refuses_over_budget_before_start(api):
    client, service = api
    body = {"protocol": "lab30-full-v2", "prompt_ids": ["a", "b", "c"], "baseline_prompt_id": "a"}
    response = client.post("/api/prompt-experiments", json=body)
    assert response.status_code == 201
    assert service.started[0]["run_limits"]["seconds"] == 720
    assert service.started[0]["experiment_wall_seconds"] == 7200
    response = client.post("/api/prompt-experiments", json={**body, "repeats": 4})
    assert response.status_code == 422 and len(service.started) == 1


def test_events_before_and_after_are_mutually_exclusive(api):
    client, service = api
    path = "/api/prompt-experiments/experiment/trials/trial/events"
    response = client.get(path, params={"after": 10, "before": 100})
    assert response.status_code == 400 and service.full.calls == []
    assert client.get(path, params={"before": 0}).status_code == 422
    response = client.get(path, params={"before": 100, "limit": 50, "attempt": 1})
    assert response.status_code == 200
    assert service.full.calls[-1] == {"ident": "experiment", "trial_id": "trial", "after": 0,
                                      "limit": 50, "attempt": 1, "before": 100}
    assert response.json()["has_earlier"] and response.json()["event_cursor"] == 99
    response = client.get(path, params={"after": 99})
    assert response.status_code == 200 and service.full.calls[-1]["before"] is None


def test_trial_detail_preserves_latest_page_cursor_and_earlier_flag(api):
    client, service = api
    response = client.get("/api/prompt-experiments/experiment/trials/trial", params={"attempt": 1})
    assert response.status_code == 200
    payload = response.json()
    assert payload["event_cursor"] == 1002 and payload["has_earlier"] is True
    assert [x["id"] for x in payload["events"]] == [1001, 1002]
    assert service.full.calls[-1] == {"detail": "experiment", "trial_id": "trial", "attempt": 1}
