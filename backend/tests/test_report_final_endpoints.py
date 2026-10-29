"""HTTP contract: one fact package behind the page, Markdown, JSON and the evidence ZIP."""
from __future__ import annotations

import copy
import io
import json
import re
import zipfile
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from audit import app as app_module
from audit.report_final import SECTION_TITLES
from tests.test_final_review_bundle import FakeRepository, accepted, bundle, finding, verification


@pytest.fixture
def api(tmp_path, monkeypatch):
    payload = bundle([accepted("f1"), finding("f2", verifications=[verification("v2")])])
    repository = FakeRepository({"app/account/update.php": [
        "<?php", "$role = $_POST['role'];", "db()->exec('UPDATE users SET role=' . $role);",
        "header('Location: /account/me.php');", "",
    ]})
    store = SimpleNamespace(
        get_run=lambda run_id: payload["run"],
        list_findings=lambda run_id: payload["findings"],
        get_snapshot=lambda snapshot_id: payload["snapshot"],
        list_truths=lambda snapshot_id: [],
        list_prompts=lambda: [],
    )
    state = SimpleNamespace(store=store, repository=repository,
                            settings=SimpleNamespace(evidence_dir=tmp_path))
    monkeypatch.setattr(app_module.app.state, "services", state, raising=False)
    monkeypatch.setattr(app_module, "_run_bundle", lambda state, run_id: copy.deepcopy(payload))
    monkeypatch.setattr(app_module, "_round_comparison", lambda state, run: {})
    client = TestClient(app_module.app)
    yield client, payload
    client.close()


def test_json_and_markdown_come_from_the_same_final_review_package(api):
    client, payload = api
    response = client.get("/api/runs/run-1/report?format=json")
    assert response.status_code == 200
    data = json.loads(response.text)
    facts = data["final_review"]
    assert facts["schema_version"] == "final-review/v1"
    assert facts["quality_result"]["report_kind"] == "stage"
    assert data["report_quality"]["publishability"] == facts["quality_result"]["publishability"]
    assert facts["counts"]["accepted"] == 1
    assert facts["counts"]["pending"] == 1
    assert len(data["findings"]) == len(payload["findings"])

    markdown = client.get("/api/runs/run-1/report?format=markdown").text
    for title in SECTION_TITLES:
        assert f"## {title}" in markdown
    assert f"- 已接受漏洞：{facts['counts']['accepted']}" in markdown
    assert f"- 待终审：{facts['counts']['pending']}" in markdown
    assert "已接受漏洞" in markdown


def test_zip_carries_the_same_report_and_the_machine_readable_facts(api):
    client, _payload = api
    markdown = client.get("/api/runs/run-1/report?format=markdown").text
    payload = client.get("/api/runs/run-1/report?format=zip").content
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = set(archive.namelist())
        assert {"report.md", "result.json", "final-review.json", "report-quality.json"} <= names
        # The two exports are two requests, so only the generation stamp may differ;
        # everything the report claims is recomputed from the same frozen rows.
        pattern = re.compile(r"生成时间：[^；]+")
        assert pattern.sub("生成时间：…", archive.read("report.md").decode("utf-8")) \
            == pattern.sub("生成时间：…", markdown)
        facts = json.loads(archive.read("final-review.json"))
        quality = json.loads(archive.read("report-quality.json"))
        result = json.loads(archive.read("result.json"))
    assert facts["counts"] == result["final_review"]["counts"]
    assert quality == facts["quality_result"]
    assert facts["provenance"]["input_hash"] == result["final_review"]["provenance"]["input_hash"]
    assert quality["recomputed"]["canonical"] == facts["counts"]["canonical"]


def test_final_review_endpoint_returns_facts_with_publish_gates(api):
    client, _payload = api
    response = client.get("/api/runs/run-1/final-review")
    assert response.status_code == 200
    facts = response.json()
    assert facts["run_outcome"]["status"] == "completed"
    assert "structure" in facts["quality_result"]["layers"]
    assert facts["review_batch"]["item_refs"]
    assert facts["source_evidence"][0]["available"] is True


def test_legacy_run_keeps_its_historical_layout_and_has_no_facts_package(api, monkeypatch):
    client, payload = api
    legacy = copy.deepcopy(payload)
    legacy.pop("planner")
    legacy["run"].pop("task_spec")
    legacy["run"]["final_summary"] = {
        "run_id": "run-1", "status": "completed", "complete": True, "stop_reason": None,
        "raw_finding_count": 2, "valid_finding_count": 2, "ledger_group_count": 2,
        "finding_groups": [], "tasks": [], "coverage": {}, "execution": {},
        "verification_jobs": [], "directions": {}, "verification": {}, "limitations": [],
    }
    monkeypatch.setattr(app_module, "_run_bundle", lambda state, run_id: copy.deepcopy(legacy))
    markdown = client.get("/api/runs/run-1/report?format=markdown")
    assert markdown.status_code == 200
    assert "## 1. 执行与终审摘要" not in markdown.text
    assert client.get("/api/runs/run-1/final-review").status_code == 409
    result = json.loads(client.get("/api/runs/run-1/report?format=json").text)
    assert "final_review" not in result
