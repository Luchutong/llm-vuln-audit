"""Destructive ledger APIs use only isolated fixtures and never start a worker."""
from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from audit import app as app_module
from audit.config import ModelConfig, Settings
from test_project_findings_api import finding, project, run, state, verification


def _finish(store, run_id: str) -> None:
    store._write("UPDATE runs SET status = 'completed' WHERE id = ?", (run_id,))


def test_delete_single_removes_all_sources_and_downloads_but_keeps_archives(state):
    project_id = project(state.store)
    first_run, first_snapshot = run(state.store, project_id)
    ledger_id, first_finding = finding(state.store, project_id, first_run)
    verification(state.store, first_finding, ledger_id)
    _finish(state.store, first_run)
    second_run, second_snapshot = run(state.store, project_id, "repacked.zip")
    same_ledger, second_finding = finding(state.store, project_id, second_run)
    assert same_ledger == ledger_id
    _finish(state.store, second_run)
    retained, _ = finding(state.store, project_id, second_run, path="src/other.php")
    assert state.client.get(f"/api/findings/{second_finding}/poc").status_code == 200

    response = state.client.delete(f"/api/project-findings/{ledger_id}")

    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["deleted_project_findings"] == 1
    assert summary["deleted_run_findings"] == 2
    assert summary["affected_project_ids"] == [project_id]
    assert summary["deleted"]["verifications"] == 1
    assert state.client.get(f"/api/project-findings/{ledger_id}").status_code == 404
    for finding_id in (first_finding, second_finding):
        assert state.client.get(f"/api/findings/{finding_id}").status_code == 404
        assert state.client.get(f"/api/findings/{finding_id}/poc").status_code == 404
    assert state.client.get(f"/api/project-findings/{retained}").status_code == 200
    assert state.store.get_run(first_run) is not None
    assert state.store.get_run(second_run) is not None
    assert state.store.get_snapshot(first_snapshot) is not None
    assert state.store.get_snapshot(second_snapshot) is not None


@pytest.mark.parametrize("use_alias", [False, True])
def test_project_clear_is_scoped_and_includes_withdrawn_findings(state, use_alias):
    target_project, other_project = project(state.store), project(state.store)
    target_run, snapshot_id = run(state.store, target_project)
    other_run, _ = run(state.store, other_project)
    target, _ = finding(state.store, target_project, target_run)
    state.store.set_project_finding_disposition(target, "retract", "历史误报", run_id=target_run)
    retained, _ = finding(state.store, other_project, other_run)
    _finish(state.store, target_run)
    # An unrelated project may still be auditing; it must not block this clear.
    if use_alias:
        response = state.client.delete(f"/api/projects/{target_project}/findings")
    else:
        response = state.client.delete("/api/project-findings", params={"project_id": target_project})

    assert response.status_code == 200, response.text
    assert response.json()["deleted_project_findings"] == 1
    assert response.json()["affected_project_ids"] == [target_project]
    assert state.client.get(f"/api/project-findings/{target}").status_code == 404
    assert state.client.get(f"/api/project-findings/{retained}").status_code == 200
    assert state.store.get_run(target_run) is not None
    assert state.store.get_snapshot(snapshot_id) is not None
    project_response = state.client.get(f"/api/projects/{target_project}")
    assert project_response.status_code == 200
    assert project_response.json()["findings"] == []


def test_global_clear_is_idempotent_and_retains_all_projects(state):
    project_ids = [project(state.store), project(state.store)]
    for project_id in project_ids:
        run_id, _ = run(state.store, project_id)
        finding(state.store, project_id, run_id)
        _finish(state.store, run_id)

    response = state.client.delete("/api/project-findings")

    assert response.status_code == 200, response.text
    assert response.json()["deleted_project_findings"] == 2
    assert response.json()["deleted_run_findings"] == 2
    assert set(response.json()["affected_project_ids"]) == set(project_ids)
    assert state.client.get("/api/project-findings", params={"disposition": "all"}).json()["total"] == 0
    assert len(state.client.get("/api/projects").json()) == 2
    second = state.client.delete("/api/project-findings")
    assert second.status_code == 200
    assert second.json()["deleted_project_findings"] == 0
    assert second.json()["deleted_run_findings"] == 0


@pytest.mark.parametrize("endpoint", [
    "/api/project-findings/missing",
    "/api/project-findings?project_id=missing",
    "/api/projects/missing/findings",
])
def test_missing_delete_scope_is_404(state, endpoint):
    assert state.client.delete(endpoint).status_code == 404


@pytest.mark.parametrize("status", ["pending", "running", "paused"])
@pytest.mark.parametrize("scope", ["single", "project", "global"])
def test_active_or_resumable_audits_return_conflict_without_partial_deletion(state, status, scope):
    project_id = project(state.store)
    run_id, _ = run(state.store, project_id)
    ledger_id, finding_id = finding(state.store, project_id, run_id)
    state.store._write("UPDATE runs SET status = ? WHERE id = ?", (status, run_id))
    if scope == "single":
        endpoint = f"/api/project-findings/{ledger_id}"
    elif scope == "project":
        endpoint = f"/api/projects/{project_id}/findings"
    else:
        endpoint = "/api/project-findings"

    response = state.client.delete(endpoint)

    assert response.status_code == 409, response.text
    assert state.store.get_project_finding(ledger_id) is not None
    assert state.store.get_finding(finding_id) is not None


@pytest.mark.parametrize("params", [{"project_id": ""}, {"severity": "high"}, {"q": "注入"}])
def test_bulk_clear_rejects_empty_scope_and_search_filters(state, params):
    assert state.client.delete("/api/project-findings", params=params).status_code == 422


def test_next_full_audit_starts_with_empty_baseline_after_clear(tmp_path, monkeypatch):
    """Exercise source upload and run creation without lifespan, models or Lab30."""
    monkeypatch.setenv("LAB30_SEED", "0")
    settings = Settings(
        data_dir=tmp_path,
        model=ModelConfig(model="test", base_url="http://127.0.0.1:1/v1", api_key="test"),
    )
    services = app_module.Services(settings)
    monkeypatch.setattr(app_module, "services", lambda request: services)
    client = TestClient(app_module.app)
    try:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("index.php", "<?php echo $_GET['q'];\n")
        uploaded = client.post(
            "/api/snapshots", files={"file": ("clean-test.zip", buffer.getvalue(), "application/zip")}
        )
        assert uploaded.status_code == 200, uploaded.text
        snapshot = uploaded.json()
        payload = {
            "snapshot_id": snapshot["id"], "poc_mode": "off",
            "task": {"objective": "全源码审计输入边界及危险操作"},
        }
        first_response = client.post("/api/runs", json=payload)
        assert first_response.status_code == 200, first_response.text
        first_run = first_response.json()["id"]
        ledger_id, _ = finding(services.store, snapshot["project_id"], first_run, path="index.php")
        _finish(services.store, first_run)
        # A later terminal run already froze the old discovery; clearing must strip
        # this historical baseline as well as removing the live project ledger.
        baseline_response = client.post("/api/runs", json=payload)
        assert baseline_response.status_code == 200, baseline_response.text
        baseline_run = baseline_response.json()
        assert [item["id"] for item in baseline_run["project_baseline"]] == [ledger_id]
        _finish(services.store, baseline_run["id"])

        cleared = client.delete(f"/api/projects/{snapshot['project_id']}/findings")

        assert cleared.status_code == 200, cleared.text
        assert services.store.get_run(baseline_run["id"])["project_baseline"] == []
        next_response = client.post("/api/runs", json=payload)
        assert next_response.status_code == 200, next_response.text
        assert next_response.json()["snapshot_id"] == snapshot["id"]
        assert next_response.json()["project_baseline"] == []
        assert services.repository.get_snapshot(snapshot["id"])["files"]
    finally:
        client.close()
        services.store.close()
