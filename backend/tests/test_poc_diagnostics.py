"""Correlated server diagnostics: runner contract, host tool and evidence channel."""
import asyncio
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from audit.poc_agent import PocDeps, _evidence_channels, evidence_errors
from audit.poc_runner import PocRunnerError
from audit.poc_tool_service import PocToolService
from audit.schemas import PocEvidenceReference, PocVerificationResult

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from poc_runner import collector  # noqa: E402
from poc_runner import runner as runner_module  # noqa: E402

REQUEST_ID = "ab" * 16


def http_job(job_id="job-1", *, diagnostics=None, context_id="ctx-1"):
    result = {"status": "finished", "execution_status": "finished", "http_status": 200,
              "body": "BODY", "headers": {"content-type": "text/html"}, "timed_out": False, "error": ""}
    job = {
        "job_id": job_id, "kind": "http", "context_id": context_id, "identity": "alice",
        "exit_code": 0, "precondition": {"ok": True}, "request": {"method": "GET", "path": "/index.php"},
        "result": result,
    }
    if diagnostics is not None:
        job["diagnostics"] = diagnostics
    return job


def page(items, *, available=True, reason=None):
    return {"available": available, "reason": reason or "", "items": items,
            "next_cursor": "", "truncated": False}


class FakeClient:
    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.calls = reply, error, []

    async def diagnostics(self, job_id, cursor=""):
        self.calls.append((job_id, cursor))
        if self.error is not None:
            raise self.error
        return self.reply


def service(client, jobs=()):
    return PocToolService(
        client=client, policy={}, target="lab30",
        finding={"id": "finding-1", "title": "LFI", "vulnerability_type": "lfi"},
        prepared={"ok": True, "identity": "alice"}, context_id="ctx-1", jobs=list(jobs),
    )


DIAG = {"kind": "php_warning", "message": "Undefined array key user", "source_path": "app/public/a.php", "line": 11}


def test_http_job_exposes_server_diagnostics_only_when_a_page_was_retrieved():
    assert "server_diagnostics" not in _evidence_channels(http_job())
    unavailable = page([], available=False, reason="logs_pending")
    assert "server_diagnostics" not in _evidence_channels(http_job(diagnostics=unavailable))
    assert "server_diagnostics" in _evidence_channels(http_job(diagnostics=page([DIAG])))


def test_evidence_channel_renders_the_stored_page_deterministically():
    from audit.poc_agent import _evidence_channel
    job = http_job(diagnostics=page([DIAG]))
    assert _evidence_channel(job, "server_diagnostics") == "php_warning: Undefined array key user (app/public/a.php:11)"


def test_evidence_validation_accepts_server_diagnostics_excerpts():
    job = http_job(diagnostics=page([DIAG]))
    deps = service(None, [job])
    text = "php_warning: Undefined array key user (app/public/a.php:11)"
    result = PocVerificationResult(
        status="verified", jobs=["job-1"], normal_observation="normal", attack_observation="attack",
        normal_evidence=[PocEvidenceReference(job_id="job-1", channel="server_diagnostics", excerpt=text)],
        attack_evidence=[PocEvidenceReference(job_id="job-1", channel="server_diagnostics", excerpt=text)],
    )
    assert evidence_errors(result, deps) == []
    forged = result.model_copy(update={"normal_evidence": [PocEvidenceReference(
        job_id="job-1", channel="server_diagnostics", excerpt="php_fatal: invented")]})
    assert any("server_diagnostics" in note for note in evidence_errors(forged, deps))


def test_tool_reads_one_page_for_a_known_http_job():
    client = FakeClient(reply={"available": True, "target_version": "lab30-shop-1.0.0",
                               "items": [DIAG], "next_cursor": "", "truncated": False})
    deps = service(client, [http_job()])
    reply = json.loads(asyncio.run(deps.call("read_verification_diagnostics", {"job_id": "job-1"})))
    assert reply["ok"] is True and reply["available"] is True
    assert reply["items"][0]["message"] == DIAG["message"]
    assert client.calls == [("job-1", "")]


@pytest.mark.parametrize("job_id", ["", "other-job", None])
def test_tool_refuses_unknown_jobs_without_querying_the_runner(job_id):
    client = FakeClient(reply=page([]))
    deps = service(client, [http_job()])
    reply = json.loads(asyncio.run(deps.call("read_verification_diagnostics", {"job_id": job_id})))
    assert reply["available"] is False and reply["reason"] == "unknown_job"
    assert client.calls == []


def test_script_and_browser_jobs_declare_the_capability_gap():
    job = {"job_id": "job-s", "kind": "script", "context_id": "ctx-1", "result": {}, "exit_code": 0}
    client = FakeClient(reply=page([DIAG]))
    deps = service(client, [job])
    reply = json.loads(asyncio.run(deps.call("read_verification_diagnostics", {"job_id": "job-s"})))
    assert reply["available"] is False and reply["reason"] == "capability_unavailable"
    assert client.calls == []


@pytest.mark.parametrize("failure,reason", [
    (PocRunnerError("boom", status_code=404), "unknown_job"),
    (PocRunnerError("boom", status_code=500), "capability_unavailable"),
])
def test_runner_refusals_become_reasons_not_verdicts(failure, reason):
    deps = service(FakeClient(error=failure), [http_job()])
    reply = json.loads(asyncio.run(deps.call("read_verification_diagnostics", {"job_id": "job-1"})))
    assert reply["available"] is False and reply["reason"] == reason


def test_unavailable_runner_page_keeps_its_own_reason():
    deps = service(FakeClient(reply={"available": False, "reason": "logs_pending"}), [http_job()])
    reply = json.loads(asyncio.run(deps.call("read_verification_diagnostics", {"job_id": "job-1"})))
    assert reply == {"ok": True, "available": False, "reason": "logs_pending", "job_id": "job-1",
                     "message": ""}


# ---- runner endpoint -------------------------------------------------------------

class FakeDiagnostics:
    def __init__(self, page_or_error):
        self.value, self.calls = page_or_error, []

    @property
    def enabled(self):
        return True

    async def fetch(self, request_id, cursor=""):
        self.calls.append((request_id, cursor))
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


def runner_job(**overrides):
    job = {"job_id": "job-1", "kind": "http", "context_id": "ctx-1", "identity": "alice",
           "request_id": REQUEST_ID, "created_ts": runner_module.time.time()}
    job.update(overrides)
    return job


def call_runner(job, diagnostics, cursor=""):
    previous = runner_module.DIAGNOSTICS
    runner_module.DIAGNOSTICS = diagnostics
    runner_module._jobs["job-1"] = job
    try:
        return asyncio.run(runner_module.job_diagnostics("job-1", cursor))
    finally:
        runner_module.DIAGNOSTICS = previous
        runner_module._jobs.pop("job-1", None)


def test_runner_returns_items_for_the_minted_request_id():
    diagnostics = FakeDiagnostics({"seen": True, "items": [dict(DIAG)], "next_cursor": "", "truncated": False})
    reply = call_runner(runner_job(), diagnostics)
    assert reply["available"] is True and reply["request_id"] == REQUEST_ID
    assert reply["items"] == [{"diagnostic_id": f"{REQUEST_ID[:8]}-0", "request_id": REQUEST_ID,
                               "kind": "php_warning", "message": DIAG["message"],
                               "source_path": "app/public/a.php", "line": 11}]
    assert diagnostics.calls == [(REQUEST_ID, "")]


def test_runner_distinguishes_pending_from_expired_and_empty():
    pending = call_runner(runner_job(), FakeDiagnostics({"seen": False, "items": []}))
    assert pending["available"] is False and pending["reason"] == "logs_pending"
    expired = call_runner(runner_job(created_ts=runner_module.time.time() - 3600),
                          FakeDiagnostics({"seen": False, "items": []}))
    assert expired["reason"] == "window_expired"
    empty = call_runner(runner_job(), FakeDiagnostics({"seen": True, "items": []}))
    assert empty["available"] is True and empty["items"] == [] and empty["item_count"] == 0


@pytest.mark.parametrize("job,reason", [
    ({"kind": "script"}, "capability_unavailable"),
    ({"request_id": ""}, "no_request"),
])
def test_runner_declares_unsupported_or_uncorrelated_jobs(job, reason):
    reply = call_runner(runner_job(**job), FakeDiagnostics({"seen": True, "items": []}))
    assert reply["available"] is False and reply["reason"] == reason


def test_runner_reports_a_dead_collector_instead_of_no_errors():
    reply = call_runner(runner_job(), FakeDiagnostics(runner_module.httpx.ConnectError("down")))
    assert reply["available"] is False and reply["reason"] == "collector_unavailable"


def test_runner_endpoint_rejects_bad_cursors_and_unknown_jobs():
    previous = runner_module.DIAGNOSTICS
    runner_module.DIAGNOSTICS = FakeDiagnostics({"seen": True, "items": []})
    try:
        with pytest.raises(runner_module.HTTPException) as bad_cursor:
            asyncio.run(runner_module.job_diagnostics("job-1", "12x"))
        assert bad_cursor.value.status_code == 400
        with pytest.raises(runner_module.HTTPException) as missing:
            asyncio.run(runner_module.job_diagnostics("missing-job", ""))
        assert missing.value.status_code == 404
    finally:
        runner_module.DIAGNOSTICS = previous


# ---- collector -------------------------------------------------------------------

def record(errors, request_id=REQUEST_ID):
    return {"request_id": request_id, "errors": errors,
            "status": 500, "request_uri": "/index.php?a=1", "ts": 1}


def test_collector_pages_and_never_echoes_container_paths(tmp_path):
    path = tmp_path / "diagnostics.jsonl"
    path.write_text(json.dumps(record([
        {"kind": "php_fatal", "message": "Uncaught Error:  boom", "source_path": "/var/www/shop/app/src/a.php", "line": 7},
    ])) + "\n")
    store = collector.Store(path)
    first = store.page(REQUEST_ID, "", 0)
    assert first["seen"] is True and first["items"] == [{
        "kind": "php_fatal", "message": "Uncaught Error: boom", "source_path": "app/src/a.php", "line": 7}]
    assert first["next_cursor"] == "" and first["truncated"] is False
    assert store.page("cd" * 16, "", 0)["seen"] is False


def test_collector_bounds_items_and_byte_pages(tmp_path):
    path = tmp_path / "diagnostics.jsonl"
    path.write_text(json.dumps(record([
        {"kind": "php_warning", "message": f"warning {index}", "source_path": "a.php", "line": index}
        for index in range(1, 6)
    ])) + "\n")
    store = collector.Store(path)
    first = store.page(REQUEST_ID, "", 0)
    assert len(first["items"]) == 5 and first["truncated"] is False
    store._add(record([{"kind": "php_warning", "message": "x" * 500, "source_path": "a.php", "line": index}
                       for index in range(6, 26)]))
    # The per-request window is capped at one page of entries; the byte budget can still
    # split what it returns, and that split is reported rather than silently dropped.
    assert len(store.entries[REQUEST_ID]) == collector.PAGE_ITEMS
    assert store.page(REQUEST_ID, "", 0)["truncated"] is True
    bounded = collector.Store(path)
    bounded._add(record([{"kind": "php_warning", "message": "y" * 500, "source_path": "a.php", "line": index}
                         for index in range(1, 21)]))
    page = bounded.page(REQUEST_ID, "", 0)
    assert page["truncated"] is True and int(page["next_cursor"]) > 0
    rest = bounded.page(REQUEST_ID, page["next_cursor"], 0)
    assert rest["truncated"] is False and rest["next_cursor"] == ""


def test_collector_drops_records_without_a_valid_request_id(tmp_path):
    path = tmp_path / "diagnostics.jsonl"
    path.write_text(json.dumps(record([], request_id="../../etc")) + "\n"
                    + json.dumps(record([{"kind": "php_error", "message": "x", "source_path": "a.php", "line": 1}])) + "\n")
    store = collector.Store(path)
    assert store.page(REQUEST_ID, "", 0)["items"][0]["message"] == "x"
    assert store.page("../../etc", "", 0)["seen"] is False
