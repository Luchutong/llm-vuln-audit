"""Durable POC claims use only a temporary SQLite database."""
import asyncio

import pytest

from audit.db import Store
from audit.poc import PocVerifier
from audit.poc_store import POC_SCHEMA, PocStoreMixin
from audit.project_findings import ledger_record
from audit.schemas import PocVerificationResult
from tests.test_goal_tasks import run_payload
from tests.test_project_findings import _finding, _project
from tests.test_poc_agent import FakeBus, FakeClient, CONFIG, settings


@pytest.fixture
def state(tmp_path):
    store_type = Store if issubclass(Store, PocStoreMixin) else type("PocTestStore", (PocStoreMixin, Store), {})
    store = store_type(tmp_path / "audit.db")
    store._db.executescript(POC_SCHEMA)
    project = _project(store)
    payload = run_payload({"id": "snap", "name": "Lab30"}, "run", [])
    payload.update(project_id=project["id"], project_mode="project", poc_policy={"mode": "auto", "enabled": True})
    store.create_run(payload)
    run = store.claim_next_run()
    finding = _finding()
    store.add_finding(finding)
    merged = store.merge_project_finding(project["id"], "run", ledger_record(finding))
    store.link_finding_project(finding["id"], merged["project_finding_id"], merged["revision"])
    finding = store.get_finding(finding["id"])
    yield store, run, finding
    store.close()


def record(finding, *, status="verified", record_id="verification-1"):
    value = {field: "" for field in (
        "original_script", "modified_script", "modification_notes", "target_version", "command",
        "expected_result", "normal_observation", "attack_observation", "notes",
    )}
    return {**value, "id": record_id, "finding_id": finding["id"], "created_at": "2026-10-23T00:00:00+00:00",
            "execution_status": "success", "verdict": "confirmed" if status == "verified" else "uncertain",
            "browser_execution": False, "files": [], "source": "poc_agent", "status": status,
            "target": {"name": "lab30", "version": "2.5"}, "agent": {"target_key": "target"}, "artifacts": [],
            "project_finding_id": finding["project_finding_id"], "finding_revision": finding["project_revision"]}


def test_claim_completed_publication_is_atomic_and_not_repeated(state):
    store, run, finding = state
    epoch = run["execution_epoch"]
    claim = store.claim_poc_attempt("run", finding, "target", epoch)
    assert claim["claimed"]
    assert not store.claim_poc_attempt("run", finding, "target", epoch)["claimed"]
    assert store.start_poc_attempt(claim["key"], epoch)
    assert store.note_poc_job(claim["key"], "job-1", epoch)
    jobs = [{"job_id": "job-1", "kind": "script", "request": {}, "result": {"exit_code": 0}}]
    assert store.record_automatic_verification_guarded(record(finding), attempt_key=claim["key"], epoch=epoch, jobs=jobs)
    assert not store.record_automatic_verification_guarded(record(finding), attempt_key=claim["key"], epoch=epoch, jobs=jobs)
    assert len(store.list_verifications(finding["id"])) == len(store.list_run_verification_jobs("run")) == 1
    assert store.get_project_finding(finding["project_finding_id"])["verification_status"] == "verified"
    assert store.claim_poc_attempt("run", finding, "target", epoch)["state"] == "completed"


def test_old_revision_result_is_history_without_overwriting_new_conclusion(state):
    store, run, finding = state
    epoch = run["execution_epoch"]
    claim = store.claim_poc_attempt("run", finding, "target", epoch)
    store.start_poc_attempt(claim["key"], epoch)
    store._db.execute("UPDATE project_findings SET revision=revision+1,verification_status='stale' WHERE id=?", (finding["project_finding_id"],))
    assert store.record_automatic_verification_guarded(record(finding), attempt_key=claim["key"], epoch=epoch)
    assert store.get_project_finding(finding["project_finding_id"])["verification_status"] == "stale"
    assert store.claim_poc_attempt("run", finding, "target", epoch)["state"] == "superseded"


def test_inconclusive_does_not_erase_valid_verified_revision(state):
    store, run, finding = state
    epoch = run["execution_epoch"]
    store.set_finding_verification_state(finding["id"], "verified", "confirmed")
    store.set_project_finding_verification(finding["project_finding_id"], "verified", "confirmed", None)
    claim = store.claim_poc_attempt("run", finding, "target", epoch)
    store.start_poc_attempt(claim["key"], epoch)
    assert store.record_automatic_verification_guarded(record(finding, status="inconclusive"), attempt_key=claim["key"], epoch=epoch)
    assert store.get_finding(finding["id"])["verification_status"] == "verified"
    assert store.get_project_finding(finding["project_finding_id"])["verification_status"] == "verified"


def test_late_verification_for_changed_run_finding_is_history_only(state):
    store, run, finding = state
    claim = store.claim_poc_attempt("run", finding, "target", run["execution_epoch"])
    store.start_poc_attempt(claim["key"], run["execution_epoch"])
    store._write("UPDATE findings SET revision=revision+1,verification_status='stale' WHERE id=?", (finding["id"],))
    assert store.record_automatic_verification_guarded(record(finding), attempt_key=claim["key"], epoch=run["execution_epoch"])
    assert store.get_finding(finding["id"])["verification_status"] == "stale"
    assert store.get_project_finding(finding["project_finding_id"])["verification_status"] != "verified"
    assert len(store.list_verifications(finding["id"])) == 1


def test_paused_or_old_epoch_cannot_publish_and_durable_notice_is_once(state):
    store, run, finding = state
    epoch = run["execution_epoch"]
    assert store.claim_poc_notice("run", "unsupported_target", epoch)
    assert not store.claim_poc_notice("run", "unsupported_target", epoch)
    claim = store.claim_poc_attempt("run", finding, "target", epoch)
    store.start_poc_attempt(claim["key"], epoch)
    store._db.execute("UPDATE run_execution_state SET claim_epoch=claim_epoch+1 WHERE run_id='run'")
    assert not store.record_automatic_verification_guarded(record(finding), attempt_key=claim["key"], epoch=epoch)
    assert store.list_verifications(finding["id"]) == []
    resumed = store.claim_poc_attempt("run", finding, "target", epoch + 1)
    assert not resumed["claimed"] and resumed["state"] == "interrupted"


def test_claimed_but_not_started_attempt_can_resume_safely(state):
    store, run, finding = state
    epoch = run["execution_epoch"]
    store.claim_poc_attempt("run", finding, "target", epoch)
    store._db.execute("UPDATE run_execution_state SET claim_epoch=claim_epoch+1 WHERE run_id='run'")
    resumed = store.claim_poc_attempt("run", finding, "target", epoch + 1)
    assert resumed["claimed"] and resumed["state"] == "claimed"


def test_unknown_target_has_one_durable_notice_and_no_per_finding_verifications(state, tmp_path):
    store, run, finding = state
    store._db.execute("UPDATE projects SET target_profile='unknown' WHERE id=?", (run["project_id"],))
    bus = FakeBus()
    for _ in range(3):
        verifier = PocVerifier(store=store, bus=bus, settings=settings(tmp_path), client_factory=lambda: (_ for _ in ()).throw(AssertionError("must not create runner")))
        result = asyncio.run(verifier.verify_standing("run", [finding], {}, model_config=CONFIG))
        assert result["not_applicable"] == 1
    assert bus.kinds() == ["poc_verification_skipped"]
    assert store.list_verifications(finding["id"]) == []


def test_new_required_mode_rejects_status_only_or_wrong_target_history(state):
    import json
    store, run, finding = state
    store._write("UPDATE runs SET poc_policy=? WHERE id='run'", (json.dumps({"mode": "required", "enabled": True, "target": "lab30", "target_key": "target"}),))
    store.set_finding_verification_state(finding["id"], "verified", "confirmed")
    store.set_project_finding_verification(finding["project_finding_id"], "verified", "confirmed", None)
    run = store.get_run("run")
    finding = store.get_finding(finding["id"])
    assert not store.compatible_verified_finding(run, finding)
    claim = store.claim_poc_attempt("run", finding, "target", run["execution_epoch"])
    store.start_poc_attempt(claim["key"], run["execution_epoch"])
    result = record(finding)
    result["agent"] = {"source_content_key": run["project_content_key"], "target_key": "target", "run_finding_revision": finding["revision"]}
    assert store.record_automatic_verification_guarded(result, attempt_key=claim["key"], epoch=run["execution_epoch"])
    assert store.compatible_verified_finding(run, store.get_finding(finding["id"]))
    assert not store.compatible_verified_finding({**run, "poc_policy": {**run["poc_policy"], "target_key": "other-target"}}, finding)
    store._write("UPDATE project_findings SET revision=revision+1 WHERE id=?", (finding["project_finding_id"],))
    assert not store.compatible_verified_finding(run, finding)


def test_same_ledger_revision_has_one_claim_even_for_different_run_finding_revisions(state):
    store, run, finding = state
    claim = store.claim_poc_attempt("run", finding, "target", run["execution_epoch"])
    duplicate = store.claim_poc_attempt("run", {**finding, "id": "other-run-finding", "revision": finding["revision"] + 4}, "target", run["execution_epoch"])
    assert claim["claimed"]
    assert not duplicate["claimed"] and duplicate["key"] == claim["key"]


def test_resume_queries_known_job_without_preparing_or_resubmitting(state, tmp_path, monkeypatch):
    from audit import poc
    from audit.poc import PocPolicy
    from audit.poc_store import poc_target_key
    store, run, finding = state
    configuration = settings(tmp_path)
    target_key = poc_target_key(run, PocPolicy.from_run(run, configuration), configuration)
    claim = store.claim_poc_attempt("run", finding, target_key, run["execution_epoch"])
    store.start_poc_attempt(claim["key"], run["execution_epoch"])
    store.note_poc_job(claim["key"], "prior-job", run["execution_epoch"])
    store._write("UPDATE run_execution_state SET claim_epoch=claim_epoch+1 WHERE run_id='run'")
    class Client(FakeClient):
        queried = []
        async def get_job(self, job_id):
            self.queried.append(job_id)
            return {"job_id": job_id, "status": "completed"}
        async def prepare_target(self, *args, **kwargs):
            raise AssertionError("must not reset a target to recover an old job")
    async def no_agent(**kwargs):
        raise AssertionError("must not execute an agent to recover an old job")
    monkeypatch.setattr(poc, "run_poc_agent", no_agent)
    client = Client()
    bus = FakeBus()
    verifier = PocVerifier(store=store, bus=bus, settings=configuration, client_factory=lambda: client)
    result = asyncio.run(verifier.verify_standing("run", [finding], {}, model_config=CONFIG))
    assert result["attempted"] == 0 and result["inconclusive"] == 1
    assert client.queried == ["prior-job"]
    assert store.list_verifications(finding["id"]) == []
    assert "poc_job_recovered" in bus.kinds()
