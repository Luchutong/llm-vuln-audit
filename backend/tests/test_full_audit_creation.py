"""Explicit full-audit and fresh-baseline API contracts, without executing a model."""
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from audit import app as app_module
from audit.config import ModelConfig, Settings
from audit.schemas import TaskSpec
from test_project_findings_api import finding, verification


@pytest.fixture
def state(tmp_path, monkeypatch):
    services = app_module.Services(Settings(
        data_dir=tmp_path,
        model=ModelConfig(model="offline-model", base_url="http://127.0.0.1:1/v1", api_key="offline-key"),
    ))
    monkeypatch.setattr(app_module, "services", lambda request: services)
    # No lifespan is entered, so the queued audits never start background workers.
    client = TestClient(app_module.app)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("index.php", "<?php\n$input = $_GET['q'];\necho $input;\n")
        zipped.writestr("other.php", "<?php\n$input = $_GET['other'];\necho $input;\n")
    uploaded = client.post("/api/snapshots", files={"file": ("offline.zip", archive.getvalue(), "application/zip")})
    assert uploaded.status_code == 200, uploaded.text
    services.client = client
    services.snapshot = uploaded.json()
    yield services
    client.close()
    services.store.close()


def create(state, **task):
    response = state.client.post("/api/runs", json={
        "snapshot_id": state.snapshot["id"], "poc_mode": "off",
        "task": {"objective": "审查全部第一方源码及可执行审计方向", **task},
    })
    assert response.status_code == 200, response.text
    return response.json()


def test_explicit_full_coverage_freezes_consistent_criteria_and_goal(state):
    created = create(state, completion_policy="coverage_review", stop_on_achieved=True)
    spec = created["task_spec"]
    assert spec["completion_policy"] == "coverage_review"
    assert spec["stop_on_achieved"] is False
    assert "至少一处" not in spec["success_criteria"]
    assert "未覆盖" in spec["success_criteria"]
    assert "预算耗尽" in spec["success_criteria"]
    assert "CVSS 3.1" in spec["success_criteria"]
    goal = state.store.get_task_goal(created["id"])
    assert goal["success_criteria"] == spec["success_criteria"]
    assert goal["status"] == "open"
    assert spec["workflow_policy"] == "discovery_first"
    assert created["execution_summary"]["workflow"]["limits"] == {"discovery": 244, "poc": 0, "review": 12}


def test_an_explicit_frozen_legacy_workflow_is_not_upgraded(state):
    created = create(state, completion_policy="coverage_review", workflow_policy="legacy")
    assert created["task_spec"]["workflow_policy"] == "legacy"
    assert not created["execution_summary"].get("workflow")
    assert "directions" not in created["execution_summary"]


def test_legacy_api_keeps_goal_policy_without_interpreting_objective_words(state):
    created = create(state)
    spec = created["task_spec"]
    assert spec["completion_policy"] == "goal"
    assert spec["stop_on_achieved"] is True
    assert spec["baseline_policy"] == "inherit"
    assert spec["success_criteria"] == TaskSpec(objective=spec["objective"]).success_criteria
    assert "至少一处" in spec["success_criteria"]


def test_full_scenario_preserves_the_exhaustive_class_contract(state):
    created = create(state, completion_policy="coverage_review", scenario="sqli", stop_on_achieved=True)
    assert created["task_spec"]["completion_policy"] == "coverage_review"
    assert created["task_spec"]["scenario"] == "sqli"
    assert created["task_spec"]["stop_on_achieved"] is False
    assert "穷尽所选分场景" in created["task_spec"]["success_criteria"]
    assert "至少一处" not in created["task_spec"]["success_criteria"]


def test_full_audit_preserves_an_explicit_fixed_time_experiment_criterion(state):
    frozen_criterion = "在宿主规定的时间内尽可能挖掘并保存有已读源码证据的漏洞，同时记录未覆盖方向；不要求穷尽，不能找到第一条就停止。"
    created = create(state, completion_policy="coverage_review", success_criteria=frozen_criterion, stop_on_achieved=True)
    assert created["task_spec"]["success_criteria"] == frozen_criterion
    assert created["task_spec"]["stop_on_achieved"] is False
    assert state.store.get_task_goal(created["id"])["success_criteria"] == frozen_criterion


def test_fresh_baseline_is_empty_without_deleting_the_shared_ledger(state):
    first = create(state)
    ledger_id, finding_id = finding(state.store, state.snapshot["project_id"], first["id"], path="index.php")
    state.store._write("UPDATE runs SET status='completed' WHERE id=?", (first["id"],))
    inherited = create(state)
    assert [row["id"] for row in inherited["project_baseline"]] == [ledger_id]
    fresh = create(state, completion_policy="coverage_review", baseline_policy="fresh")
    assert fresh["task_spec"]["baseline_policy"] == "fresh"
    assert fresh["project_baseline"] == []
    assert state.store.get_project_finding(ledger_id) is not None
    assert state.store.get_finding(finding_id) is not None
    assert state.store.get_run(inherited["id"])["project_baseline"][0]["id"] == ledger_id
    assert state.store.get_snapshot(state.snapshot["id"]) is not None
    baseline_events = state.store._rows(
        "SELECT payload FROM events WHERE run_id=? AND kind='project_findings_baseline_frozen'", (fresh["id"],),
    )
    frozen = json.loads(baseline_events[0]["payload"])
    assert frozen["baseline_policy"] == "fresh"
    assert frozen["count"] == 0
    assert frozen["ids"] == []


def test_fresh_run_hides_old_verified_conclusions_but_retains_its_own_findings(state):
    first = create(state)
    ledger_id, historical_finding = finding(state.store, state.snapshot["project_id"], first["id"], path="index.php")
    verification(state.store, historical_finding, ledger_id)
    state.store._write("UPDATE runs SET status='completed' WHERE id=?", (first["id"],))
    inherited = create(state)
    known_context = state.store.list_planner_context(inherited["id"])
    assert [item["id"] for item in known_context["project_findings"]] == [ledger_id]
    assert known_context["verification_summary"]["verified"] == 1

    # Goal mode isolates the standing-finding guard from the separate coverage gate:
    # even a historically verified ledger entry cannot complete a fresh audit.
    fresh = create(state, completion_policy="goal", baseline_policy="fresh")
    context = state.store.list_planner_context(fresh["id"])
    assert context["project_findings"] == []
    assert context["project_baseline_ids"] == []
    assert context["findings"] == []
    assert all(count == 0 for count in context["verification_summary"].values())
    with pytest.raises(ValueError, match="without a validated vulnerability finding"):
        state.store.finalize_goal(fresh["id"], "met", "旧台账已验证，尝试跳过本次取证。")
    assert state.store.get_task_goal(fresh["id"])["status"] == "open"

    _, new_finding = finding(state.store, state.snapshot["project_id"], fresh["id"], path="index.php", title="本次独立取证发现")
    current = state.store.list_planner_context(fresh["id"])
    assert current["project_findings"] == []
    assert [item["id"] for item in current["findings"]] == [new_finding]
    assert current["findings"][0]["title"] == "本次独立取证发现"
    assert state.store.get_finding(historical_finding) is not None


def test_successful_fresh_audit_never_claims_unseen_history_as_carried(state):
    first = create(state)
    old_ledger, old_finding = finding(state.store, state.snapshot["project_id"], first["id"], path="index.php")
    verification(state.store, old_finding, old_ledger)
    state.store._write("UPDATE runs SET status='completed' WHERE id=?", (first["id"],))

    inherited = create(state)
    assert state.store.record_carried_findings(state.snapshot["project_id"], inherited["id"]) == 1
    assert state.store.finalize_goal(inherited["id"], "met", "显式沿用项目中已验证的历史结论。")["status"] == "met"
    assert len(state.store.list_run_project_findings(inherited["id"], relation="carried")) == 1

    fresh = create(state, completion_policy="goal", baseline_policy="fresh")
    current_ledger, _ = finding(state.store, state.snapshot["project_id"], fresh["id"], path="other.php", title="本次独立审计发现")
    assert current_ledger != old_ledger
    assert state.store.record_carried_findings(state.snapshot["project_id"], fresh["id"]) == 0
    assert state.store.finalize_goal(fresh["id"], "met", "本轮已独立形成有效结论。")["status"] == "met"
    assert state.store.list_run_project_findings(fresh["id"], relation="carried") == []
    detail = state.client.get(f"/api/runs/{fresh['id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["carried_findings"] == []
    assert detail.json()["metrics"]["carried_findings"] == 0
    assert state.store.get_project_finding(old_ledger) is not None


@pytest.mark.parametrize("field,value", [("completion_policy", "automatic"), ("baseline_policy", "drop-everything")])
def test_unknown_policies_are_rejected(state, field, value):
    response = state.client.post("/api/runs", json={
        "snapshot_id": state.snapshot["id"],
        "task": {"objective": "审计所有第一方源码入口", field: value},
    })
    assert response.status_code == 422
    assert state.store.list_runs() == []
