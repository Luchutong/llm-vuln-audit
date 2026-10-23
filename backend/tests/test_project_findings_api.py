"""Read-only canonical ledger browsing, provenance and cross-run verification."""
from __future__ import annotations

import io
import json
import uuid
import zipfile
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from audit import app as app_module
from audit.config import ModelConfig, Settings
from audit.db import Store
from audit.project_findings import canonical_fingerprint, ledger_record


@pytest.fixture
def state(tmp_path, monkeypatch):
    store = Store(tmp_path / "audit.db")
    value = SimpleNamespace(store=store)
    monkeypatch.setattr(app_module, "services", lambda request: value)
    value.client = TestClient(app_module.app)
    yield value
    value.client.close()
    store.close()


def project(store, name="项目一"):
    ident = uuid.uuid4().hex
    store.add_project({"id": ident, "content_key": ident, "name": name})
    return ident


def run(store, project_id, name="source.zip"):
    ident, snapshot_id = uuid.uuid4().hex, uuid.uuid4().hex
    store.add_snapshot({
        "id": snapshot_id, "name": name, "created_at": "2026-10-20T00:00:00+00:00",
        "archive_sha256": snapshot_id, "source": "uploaded_zip", "project_id": project_id,
    })
    store.attach_snapshot_project(snapshot_id, project_id, project_id, "unknown")
    store.create_run({
        "id": ident, "snapshot_id": snapshot_id, "snapshot_name": name, "scope": [],
        "project_id": project_id, "project_mode": "project", "prompt_id": "planner-v2",
        "prompt_label": "项目级 Planner", "prompt_text": "", "model": "test", "budgets": {},
        "created_at": "2026-10-20T00:00:00+00:00",
    })
    return ident, snapshot_id


def finding(store, project_id, run_id, *, path="src/auth.php", severity="high", title="输入可触发注入", corrected=False):
    ident = uuid.uuid4().hex
    record = {
        "id": ident, "run_id": run_id, "unit_id": ident, "file_path": path, "symbol": "handle",
        "fingerprint": canonical_fingerprint(path, "handle", "unsafe_query"),
        "category": "task_goal", "finding_kind": "vulnerability", "title": title,
        "severity": severity, "summary": title + "：攻击输入进入危险操作。",
        "evidence": [{"path": path, "start_line": 2, "end_line": 4 if corrected else 3}],
        "input_source": "请求参数", "propagation": "直接拼接", "dangerous_operation": "unsafe_query",
        "protection": "未编码", "preconditions": ["可访问入口"], "missing_context": [],
        "poc": {"filename": "poc.py", "language": "python", "script": "print('proof')\n"},
        "remediation": "使用安全参数接口", "validation_state": "candidate",
        "created_at": "2026-10-20T00:00:00+00:00",
    }
    store.add_finding(record)
    merged = store.merge_project_finding(project_id, run_id, ledger_record(record))
    store.link_finding_project(ident, merged["project_finding_id"], merged["revision"])
    return merged["project_finding_id"], ident


def verification(store, finding_id, project_finding_id=None, *, source="poc_agent", revision=1):
    ident = uuid.uuid4().hex
    record = {
        "id": ident, "finding_id": finding_id, "project_finding_id": project_finding_id,
        "finding_revision": revision, "source": source, "status": "verified", "verdict": "confirmed",
        "created_at": "2026-10-20T00:00:00+00:00", "execution_status": "success",
        "original_script": "print('proof')\n", "modified_script": "", "modification_notes": "",
        "target_version": "test", "command": "python poc.py", "expected_result": "出现差异",
        "normal_observation": "拒绝", "attack_observation": "读取成功", "browser_execution": False,
        "notes": "", "files": [], "agent": {"summary": "验证成功"}, "artifacts": [],
    }
    if source == "poc_agent":
        store.record_automatic_verification(record)
    else:
        store.add_verification(record)
    return ident


def test_default_page_is_compact_stable_and_excludes_withdrawn(state):
    p = project(state.store)
    r, _ = run(state.store, p)
    expected = []
    for index in range(30):
        ledger_id, _ = finding(state.store, p, r, path=f"src/{index}.php")
        if index < 3:
            state.store._write(
                "UPDATE project_findings SET disposition = ? WHERE id = ?",
                (("retracted", "duplicate", "superseded")[index], ledger_id),
            )
        else:
            expected.append(ledger_id)
    # A tie must not duplicate or skip rows between offset pages.
    state.store._write("UPDATE project_findings SET updated_at = '2026-10-20T00:00:00+00:00'")
    first = state.client.get("/api/project-findings").json()
    second = state.client.get("/api/project-findings", params={"offset": 25}).json()
    assert (first["total"], first["offset"], first["limit"]) == (27, 0, 25)
    assert [row["id"] for row in first["items"] + second["items"]] == sorted(expected, reverse=True)
    assert "poc" not in first["items"][0] and "evidence" not in first["items"][0]
    assert state.client.get("/api/project-findings", params={"disposition": "all"}).json()["total"] == 30


def test_filters_use_canonical_status_and_literal_search(state):
    p, other = project(state.store, "核心审计包"), project(state.store, "其他包")
    r, snapshot_id = run(state.store, p, "original.zip")
    other_run, _ = run(state.store, other)
    target, _ = finding(state.store, p, r, path="src/a_100%.php", severity="critical")
    finding(state.store, p, r, path="src/ax1000.php", severity="medium")
    finding(state.store, other, other_run)
    state.store.set_project_finding_verification(target, "environment_unavailable", "uncertain", None)
    params = {"project_id": p, "q": "a_100%", "severity": "unknown", "verification_status": "environment_unavailable"}
    response = state.client.get("/api/project-findings", params=params)
    assert response.status_code == 200
    row = response.json()["items"][0]
    assert response.json()["total"] == 1 and row["id"] == target
    assert row["last_run"]["snapshot_id"] == snapshot_id
    assert row["origin_run"]["snapshot_name"] == "original.zip"
    assert state.client.get("/api/project-findings", params={"q": "核心审计包"}).json()["total"] == 2
    assert state.client.get("/api/project-findings", params={"q": "' OR 1=1 --"}).json()["total"] == 0
    state.store.set_project_finding_disposition(target, "retract", "误报", run_id=r)
    assert state.client.get("/api/project-findings", params={"disposition": "retracted"}).json()["items"][0]["id"] == target


def test_current_detail_uses_latest_conclusion_and_actual_audited_zip(state):
    p = project(state.store)
    first_run, first_snapshot = run(state.store, p, "first.zip")
    ledger, first_finding = finding(state.store, p, first_run, title="第一次结论")
    early_verification = verification(state.store, first_finding, ledger)
    last_run, last_snapshot = run(state.store, p, "second.zip")
    same_ledger, last_finding = finding(state.store, p, last_run, severity="critical", title="更正后的结论", corrected=True)
    run(state.store, p, "newest-not-audited.zip")
    assert same_ledger == ledger
    response = state.client.get(f"/api/project-findings/{ledger}")
    assert response.status_code == 200
    detail = response.json()
    assert detail["finding"]["title"] == "更正后的结论"
    assert detail["finding"]["superseded_summary"][0]["title"] == "第一次结论"
    assert detail["finding"]["verification_status"] == "stale" and detail["current_verification"] is None
    assert detail["origin_run"]["snapshot_id"] == first_snapshot
    assert detail["last_run"]["snapshot_id"] == last_snapshot
    assert detail["project"]["latest_snapshot_id"] != last_snapshot
    assert {row["relation"] for row in detail["history"]} == {"created", "corrected"}
    assert detail["verifications"][0]["id"] == early_verification
    assert detail["verifications"][0]["run_id"] == first_run
    assert detail["poc_finding_id"] == last_finding
    assert detail["poc_download_path"] == f"/api/findings/{last_finding}/poc"
    assert state.client.get(detail["poc_download_path"]).text == detail["finding"]["poc"]["script"]
    assert state.client.get("/api/project-findings", params={"verification_status": "verified"}).json()["total"] == 0
    assert state.client.get("/api/project-findings", params={"verification_status": "stale"}).json()["total"] == 1


def test_rediscovery_keeps_early_current_verification_and_legacy_history(state):
    p = project(state.store)
    first_run, _ = run(state.store, p)
    ledger, first_finding = finding(state.store, p, first_run)
    current_id = verification(state.store, first_finding, ledger)
    legacy_id = verification(state.store, first_finding, source="legacy_human", revision=None)
    next_run, _ = run(state.store, p, "repacked.zip")
    _, latest_finding = finding(state.store, p, next_run)
    detail = state.client.get(f"/api/project-findings/{ledger}").json()
    assert detail["finding"]["last_finding_id"] == latest_finding
    assert detail["current_verification"]["id"] == current_id
    assert detail["current_verification"]["run_id"] == first_run
    assert detail["finding"]["verification_status"] == "verified"
    assert {row["id"] for row in detail["verifications"]} == {current_id, legacy_id}
    assert len(detail["verifications"]) == 2


def test_missing_history_sources_and_mismatched_poc_are_explicit(state):
    p = project(state.store)
    ledger, _ = finding(state.store, p, "missing-run")
    state.store._write("UPDATE project_findings SET poc = ? WHERE id = ?", ('{"script":"different"}', ledger))
    detail = state.client.get(f"/api/project-findings/{ledger}").json()
    assert detail["origin_run"] is None and detail["last_run"] is None
    assert detail["poc_finding_id"] is None and detail["poc_download_path"] is None
    assert detail["history"][0]["snapshot_id"] is None
    assert state.client.get("/api/project-findings").json()["items"][0]["last_run"] is None


@pytest.mark.parametrize("params", [
    {"offset": -1}, {"limit": 0}, {"limit": 101}, {"severity": "urgent"},
    {"verification_status": "confirmed"}, {"disposition": "deleted"}, {"q": "x" * 201},
])
def test_invalid_filters_are_rejected(state, params):
    assert state.client.get("/api/project-findings", params=params).status_code == 422


def test_missing_ids_and_optional_project_ledger(state):
    assert state.client.get("/api/project-findings/missing").status_code == 404
    assert state.client.get("/api/project-findings", params={"project_id": "missing"}).status_code == 404
    p = project(state.store)
    r, _ = run(state.store, p)
    finding(state.store, p, r)
    default = state.client.get(f"/api/projects/{p}").json()
    compact = state.client.get(f"/api/projects/{p}", params={"include_findings": "false"}).json()
    assert len(default["findings"]) == 1 and "findings" not in compact
    assert compact["runs"][0]["id"] == r and len(compact["snapshots"]) == 1


def test_uploaded_snapshot_keeps_project_provenance_when_read_and_audited(tmp_path, monkeypatch):
    data_dir = tmp_path / "service-data"
    data_dir.mkdir()
    services = app_module.Services(Settings(
        data_dir=data_dir,
        model=ModelConfig(model="test", base_url="http://127.0.0.1:1/v1", api_key="test"),
    ))
    monkeypatch.setattr(app_module, "services", lambda request: services)
    # No lifespan/worker is started: creating the run must never call a real model.
    client = TestClient(app_module.app)
    try:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("index.php", "<?php echo 1;\n")
        uploaded_response = client.post("/api/snapshots", files={"file": ("real-source.zip", buffer.getvalue(), "application/zip")})
        assert uploaded_response.status_code == 200
        uploaded = uploaded_response.json()
        response = client.get(f"/api/snapshots/{uploaded['id']}")
        assert response.status_code == 200
        snapshot = response.json()
        assert snapshot["project_id"] == uploaded["project_id"]
        assert snapshot["content_key"] == uploaded["content_key"]
        assert snapshot["target_profile"] == uploaded["target_profile"]
        frozen_index = json.loads((services.repository.snapshots / uploaded["id"] / "index.json").read_text())
        assert "project_id" not in frozen_index
        assert "project_id" not in services.repository.get_snapshot(uploaded["id"])
        created_response = client.post("/api/runs", json={
            "snapshot_id": snapshot["id"], "task": {"objective": "审计现有源码包中的注入风险与证据"},
        })
        assert created_response.status_code == 200
        created = created_response.json()
        assert created["project_id"] == snapshot["project_id"]
        assert created["snapshot_id"] == snapshot["id"]
        assert created["snapshot_name"] == "real-source.zip"
    finally:
        client.close()
        services.store.close()
