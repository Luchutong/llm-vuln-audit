"""Runner facts survive verdict absence; no actions against the actual project."""
import asyncio
import copy
import json

import pytest

from audit import poc
from audit.poc import PocVerifier
from audit.runtime import StopAudit
from audit.schemas import PocVerificationResult
from tests.test_poc_agent import CONFIG, FINDING, FakeBus, FakeClient, FakeStore, settings
from tests.test_poc_http_contract import job
from tests.test_poc_store import state, record


def _claim(store, run, finding):
    claim = store.claim_poc_attempt(run["id"], finding, "target", run["execution_epoch"])
    assert claim["claimed"]
    assert store.start_poc_attempt(claim["key"], run["execution_epoch"])
    return claim


def test_job_fact_is_available_before_verdict_and_is_linked_without_duplicate_rows(state):
    store, run, finding = state
    claim = _claim(store, run, finding)
    fact = job("http-1", body="normal and attack", headers={"location": "https://outside.invalid/"})
    assert store.note_poc_job(claim["key"], fact["job_id"], run["execution_epoch"])

    assert store.persist_poc_job_fact(claim["key"], fact, run["execution_epoch"])

    before = store._rows("SELECT * FROM poc_verification_jobs WHERE run_id=?", (run["id"],))
    assert len(before) == 1 and before[0]["verification_id"] == ""
    assert json.loads(before[0]["result"])["body"] == "normal and attack"
    assert store.list_verifications(finding["id"]) == []
    verdict = record(finding)
    assert store.record_automatic_verification_guarded(verdict, attempt_key=claim["key"], epoch=run["execution_epoch"], jobs=[fact])
    after = store._rows("SELECT * FROM poc_verification_jobs WHERE run_id=?", (run["id"],))
    assert len(after) == 1 and after[0]["id"] == before[0]["id"]
    assert after[0]["verification_id"] == verdict["id"]


def test_terminal_run_interrupts_claim_and_keeps_completed_job_metadata(state):
    store, run, finding = state
    claim = _claim(store, run, finding)
    fact = job("finished-http", http_status=503)
    store.note_poc_job(claim["key"], fact["job_id"], run["execution_epoch"])
    store.persist_poc_job_fact(claim["key"], fact, run["execution_epoch"])

    assert store.terminate_execution(run["id"], "inconclusive", {"code": "run_budget_exhausted", "message": "请求预算耗尽"})

    row = store._row("SELECT * FROM poc_attempts WHERE key=?", (claim["key"],))
    assert row["state"] == "interrupted" and row["runner_job_id"] == "finished-http"
    assert store.list_verifications(finding["id"]) == []
    facts = store._rows("SELECT * FROM poc_verification_jobs WHERE run_id=?", (run["id"],))
    assert len(facts) == 1 and json.loads(facts[0]["result"])["http_status"] == 503
    assert not store.record_automatic_verification_guarded(record(finding), attempt_key=claim["key"], epoch=run["execution_epoch"])


def test_administrative_interrupt_is_transaction_compatible_and_does_not_drop_job_id(state):
    store, run, finding = state
    claim = _claim(store, run, finding)
    store.note_poc_job(claim["key"], "unknown-job", run["execution_epoch"])
    store._db.execute("BEGIN IMMEDIATE")
    assert store.interrupt_poc_attempts(run["id"], epoch=run["execution_epoch"]) == 1
    store._db.execute("COMMIT")
    assert store.interrupt_poc_attempts(run["id"], epoch=run["execution_epoch"]) == 0
    assert store._row("SELECT runner_job_id FROM poc_attempts WHERE key=?", (claim["key"],))["runner_job_id"] == "unknown-job"


@pytest.mark.parametrize("raw_http_status", [False, True])
def test_late_facts_cannot_downgrade_finished_job_or_cross_a_new_owner_epoch(state, raw_http_status):
    store, run, finding = state
    claim = _claim(store, run, finding)
    fact = job("http-1")
    if raw_http_status:
        fact["result"]["status"] = 200
    store.persist_poc_job_fact(claim["key"], fact, run["execution_epoch"])
    assert not store.persist_poc_job_fact(claim["key"], job("http-1", status="unknown", execution_status="unknown"), run["execution_epoch"])
    store._write("UPDATE run_execution_state SET claim_epoch=claim_epoch+1 WHERE run_id=?", (run["id"],))
    assert not store.persist_poc_job_fact(claim["key"], job("another"), run["execution_epoch"])
    assert len(store._rows("SELECT * FROM poc_verification_jobs WHERE run_id=?", (run["id"],))) == 1


def test_live_dispatch_persists_a_job_even_when_conclusion_is_missing(state, tmp_path, monkeypatch):
    store, run, finding = state
    store._write("UPDATE projects SET target_profile='lab30' WHERE id=?", (run["project_id"],))
    events = FakeBus()

    async def fake_agent(*, deps, **kwargs):
        from audit.runtime import AgentPolicy, Execution
        deps.execution = Execution({"responses": 4, "tools": 8, "seconds": 10}, AgentPolicy(), lambda event: None)
        deps.execution.enter("poc_execute")
        await deps.call("run_poc", {"language": "python", "script": "print('facts')"})
        raise StopAudit("stage_budget_exhausted", "本阶段额度已耗尽")

    monkeypatch.setattr(poc, "run_poc_agent", fake_agent)
    verifier = PocVerifier(store=store, bus=events, settings=settings(tmp_path), client_factory=FakeClient)
    with pytest.raises(StopAudit, match="本阶段"):
        asyncio.run(verifier.verify_standing(run["id"], [finding], {}, model_config=CONFIG))
    attempts = store._rows("SELECT * FROM poc_attempts WHERE run_id=?", (run["id"],))
    assert len(attempts) == 1 and attempts[0]["state"] == "interrupted"
    assert len(store._rows("SELECT * FROM poc_verification_jobs WHERE run_id=?", (run["id"],))) == 1
    assert store.list_verifications(finding["id"]) == []


def test_verifier_chooses_current_run_ledger_version_and_processes_only_a_small_batch(tmp_path, monkeypatch):
    store = FakeStore()
    verifier = PocVerifier(store=store, bus=FakeBus(), settings=settings(tmp_path), client_factory=FakeClient)
    processed = []

    async def fake_verify(run, finding, policy, prepared, client, **kwargs):
        processed.append(finding["id"])
        return PocVerificationResult(status="inconclusive", summary="离线对照不足"), "completed", {}, {}, []

    monkeypatch.setattr(verifier, "verify_finding", fake_verify)
    candidates = [
        {**FINDING, "id": "old", "run_id": "run-1", "project_revision": 1},
        {**FINDING, "id": "current", "run_id": "run-1", "project_revision": 3},
        {**FINDING, "id": "same-version", "run_id": "run-1", "project_revision": 3},
        {**FINDING, "id": "external", "run_id": "other-run", "project_revision": 50},
        {**FINDING, "id": "second", "project_finding_id": "second-ledger"},
        {**FINDING, "id": "third", "project_finding_id": "third-ledger"},
        {**FINDING, "id": "duplicate", "project_finding_id": "fourth-ledger", "disposition": "duplicate"},
    ]
    verified = {}

    first = asyncio.run(verifier.verify_standing("run-1", candidates, verified, model_config=CONFIG, max_findings=2))

    assert processed == ["same-version", "second"]
    assert first["processed"] == first["attempted"] == 2
    assert first["remaining"] == 1
    assert len(first["processed_findings"]) == 2
    second = asyncio.run(verifier.verify_standing("run-1", candidates, verified, model_config=CONFIG, max_findings=2))
    assert processed == ["same-version", "second", "third"]
    assert second["processed"] == 1 and second["remaining"] == 0


def test_http_only_inconclusive_still_records_successful_execution(tmp_path):
    from audit.poc import PocPolicy
    store = FakeStore()
    verifier = PocVerifier(store=store, bus=FakeBus(), settings=settings(tmp_path), client_factory=FakeClient)
    verifier._record(store.run, FINDING, PocPolicy(), PocVerificationResult(status="inconclusive", summary="影响未证实"),
        prepared={}, jobs=[job("http-1")], artifacts={}, usage={}, reason="completed")
    assert store.records[0]["execution_status"] == "not_triggered"


def test_a_runtime_failure_after_http_success_is_not_a_negative_experiment(tmp_path):
    from audit.poc import PocPolicy
    store = FakeStore()
    verifier = PocVerifier(store=store, bus=FakeBus(), settings=settings(tmp_path), client_factory=FakeClient)
    verifier._record(store.run, FINDING, PocPolicy(), PocVerificationResult(status="inconclusive", summary="结论阶段中断"),
        prepared={}, jobs=[job("http-1")], artifacts={}, usage={}, reason="sdk_api_error")
    assert store.records[0]["execution_status"] == "conclusion_error"
    assert store.records[0]['agent']['job_results'][0]['job_id'] == 'http-1'


@pytest.mark.parametrize('jobs', [[], [job('http-1')]])
def test_successful_conclusion_does_not_hide_an_incomplete_sdk_experiment(tmp_path, jobs):
    from audit.poc import PocPolicy
    store = FakeStore()
    verifier = PocVerifier(store=store, bus=FakeBus(), settings=settings(tmp_path), client_factory=FakeClient)
    usage = dict(execute_reason='sdk_api_error', diagnostics=[dict(stage='execute', http_status=429)])
    verifier._record(store.run, FINDING, PocPolicy(), PocVerificationResult(status='inconclusive', summary='攻击观测不足'),
        prepared={}, jobs=jobs, artifacts={}, usage=usage, reason='completed')
    record = store.records[0]
    assert record['execution_status'] == 'execution_error'
    assert record['status'] == 'inconclusive'
    assert record['agent']['usage'] == usage
    assert record['agent']['job_results'] == jobs


def test_a_second_finding_is_not_claimed_after_the_first_uses_the_stage_allowance(tmp_path, monkeypatch):
    class BudgetStore(FakeStore):
        allowance = 7

        def __init__(self):
            super().__init__()
            self.claimed = []

        def workflow_state(self, run_id):
            return {"stage": "poc", "remaining": {"poc": self.allowance}, "stage_remaining_seconds": 10}

        def claim_poc_attempt(self, run_id, finding, target_key, epoch):
            self.claimed.append(finding["id"])
            return {"claimed": True, "key": finding["id"]}

    store = BudgetStore()
    bus = FakeBus()
    verifier = PocVerifier(store=store, bus=bus, settings=settings(tmp_path), client_factory=FakeClient)
    policies = []

    async def fake_verify(run, finding, policy, prepared, client, **kwargs):
        policies.append(policy.max_responses)
        store.allowance = 3
        return PocVerificationResult(status="inconclusive", summary="正常侧证据不足"), "completed", {}, {}, []

    monkeypatch.setattr(verifier, "verify_finding", fake_verify)
    second = {**FINDING, "id": "second", "project_finding_id": "second-ledger"}
    verified = {}
    summary = asyncio.run(verifier.verify_standing("run-1", [FINDING, second], verified, model_config=CONFIG, max_findings=2))

    assert store.claimed == [FINDING["id"]]
    assert policies == [7]
    assert summary["processed"] == 1 and summary["remaining"] == 1
    assert "second-ledger" not in verified
    assert "poc_verification_deferred" in bus.kinds()


def test_expired_stage_gate_runs_before_any_poc_claim(tmp_path):
    from audit.execution_state import CURRENT_EXECUTION

    class BudgetStore(FakeStore):
        claimed = False

        def claim_poc_attempt(self, *args):
            self.claimed = True
            raise AssertionError("An exhausted execution must not claim a new experiment")

    class ExpiredOwner:
        def admit(self, dimension):
            assert dimension == "work"
            raise StopAudit("stage_budget_exhausted", "已保留最终复核额度")

    store = BudgetStore()
    verifier = PocVerifier(store=store, bus=FakeBus(), settings=settings(tmp_path), client_factory=FakeClient)
    token = CURRENT_EXECUTION.set(ExpiredOwner())
    try:
        with pytest.raises(StopAudit, match="最终复核"):
            asyncio.run(verifier.verify_standing("run-1", [FINDING], {}, model_config=CONFIG))
    finally:
        CURRENT_EXECUTION.reset(token)
    assert not store.claimed


def test_completed_durable_claims_do_not_consume_the_next_small_execution_batch(tmp_path, monkeypatch):
    class ResumedStore(FakeStore):
        def claim_poc_attempt(self, run_id, finding, target_key, epoch):
            return {"claimed": finding["id"] not in {"completed-1", "completed-2"}, "state": "completed"}

    store = ResumedStore()
    verifier = PocVerifier(store=store, bus=FakeBus(), settings=settings(tmp_path), client_factory=FakeClient)
    candidates = [{**FINDING, "id": ident, "project_finding_id": ident}
        for ident in ("completed-1", "completed-2", "pending-1", "pending-2", "pending-3")]
    processed = []

    async def fake_verify(run, finding, *args, **kwargs):
        processed.append(finding["id"])
        return PocVerificationResult(status="inconclusive", summary="离线对照不足"), "completed", {}, {}, []

    monkeypatch.setattr(verifier, "verify_finding", fake_verify)
    verified = {}
    summary = asyncio.run(verifier.verify_standing("run-1", candidates, verified, model_config=CONFIG, max_findings=2))

    assert processed == ["pending-1", "pending-2"]
    assert summary["processed"] == 2 and summary["remaining"] == 1
    assert {"completed-1", "completed-2"} <= set(verified)


def test_another_run_revising_shared_ledger_does_not_remove_fresh_run_evidence(state, tmp_path, monkeypatch):
    from audit.project_findings import ledger_record
    from tests.test_goal_tasks import run_payload
    from tests.test_project_findings import _finding

    store, run, finding = state
    fresh = {**run["task_spec"], "baseline_policy": "fresh"}
    store._write("UPDATE runs SET task_spec=? WHERE id=?", (json.dumps(fresh), run["id"]))
    second = run_payload({"id": "snap", "name": "Lab30"}, "other-run", [])
    second.update(project_id=run["project_id"], project_mode="project", poc_policy={"mode": "auto", "enabled": True})
    store.create_run(second)
    other = {**_finding(title="另一轮修订 SQL 注入", summary="另一轮补充的影响范围。"),
        "run_id": "other-run", "protection": "另一轮核对到仅有字符串过滤，仍未参数化。"}
    store.add_finding(other)
    merged = store.merge_project_finding(run["project_id"], "other-run", ledger_record(other))
    assert merged["project_finding_id"] == finding["project_finding_id"]
    assert merged["revision"] > finding["project_revision"]
    verifier = PocVerifier(store=store, bus=FakeBus(), settings=settings(tmp_path), client_factory=FakeClient)
    processed = []

    async def fake_verify(run, source, *args, **kwargs):
        processed.append(source)
        return PocVerificationResult(status="inconclusive", summary="本轮证据可执行，影响未确定"), "completed", {}, {}, []

    monkeypatch.setattr(verifier, "verify_finding", fake_verify)
    result = asyncio.run(verifier.verify_standing(run["id"], [finding], {}, model_config=CONFIG))

    assert result["attempted"] == 1 and processed[0]["id"] == finding["id"]
    assert processed[0]["summary"] == finding["summary"]
