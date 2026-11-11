"""Minimal model publication, report closure and evidence ownership on frozen inputs."""
import asyncio
import base64
import copy
import io
import json
import zipfile

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from audit import agent, audit_report, output_policy
from audit.frozen_reports import materialize
from audit.report import original_poc_name
from audit.report_layout_quality import evaluate
from audit.report_readable import delivery_gaps, digest, export
from audit.runtime import AgentPolicy
from audit.schemas import GoalAssessment, PlannerDecision, TaskSpec
from tests.code_model import ModelFactory, final_answer
from tests.test_report_delivery import frozen_report, client  # noqa: F401
from tests.test_worker_strategies import assessment, Repository, UNIT, CONFIG
from tests.test_host_queue import hosted, add_claim  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_run_continuations import finish, request

TASK = dict(output_policy=output_policy.POLICY, require_poc=False,
            objective="核对当前源码中的可达漏洞风险", success_criteria="保存真实原始行号依据")


@pytest.mark.parametrize("require_poc", [False, True])
def test_wire_keeps_evidence_and_only_requires_poc_when_requested(require_poc):
    task = {**TASK, "require_poc": require_poc, "role_policy": "worker-evidence-v2"}
    schema = agent._worker_publication_schema(3, task=task)
    finding = schema["$defs"]["TaskFinding"]
    assert not {"remediation", "retest", "severity"} & finding["properties"].keys()
    assert ("poc" in finding["properties"]) is require_poc
    assert ("PocSpec" in schema["$defs"]) is require_poc
    assert {"evidence", "dataflow", "primary_location", "vulnerability_type"} <= set(finding["required"])
    assert {"input_source", "propagation", "dangerous_operation", "protection", "preconditions", "cvss_input"} <= finding["properties"].keys()
    assert {"direction_results", "candidate_updates", "missing_context", "remaining_work", "observations"} <= schema["properties"].keys()
    assert "reasoning" not in schema["properties"]
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(schema["examples"][0])


def test_new_task_defaults_and_historical_explicit_policy_keep_their_meaning():
    assert TaskSpec(objective=TASK["objective"]).output_policy == output_policy.POLICY
    old = agent._worker_publication_schema(3, task={"output_policy": "legacy"})
    assert {"remediation", "retest", "poc", "severity"} <= old["$defs"]["TaskFinding"]["properties"].keys()
    assert "reasoning" in old["required"]
    assert not output_policy.enabled({})


@pytest.mark.parametrize("phase", ["task_execute", "task_publish"])
def test_real_worker_accepts_one_explanation_without_an_extra_request(monkeypatch, phase):
    payload = assessment()
    payload.pop("reasoning")
    payload["findings"][0].pop("severity")
    factory = ModelFactory({phase: [final_answer(payload) if phase == "task_execute" else json.dumps(payload)]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    result = asyncio.run(agent.pursue_task_work(repository=Repository(), snapshot_id="snapshot", snapshot_name="demo.zip",
        unit=UNIT, task=TASK, attempt=1, config=CONFIG, budgets=dict(responses=4, tools=0, seconds=5),
        policy=AgentPolicy(request_seconds=1, worker_explore_responses=1 if phase == "task_execute" else 0)))
    assert result["outcome"] == "achieved", result
    assert result["usage"]["requests"] == 1
    assert result["result"]["summary"] == result["result"]["reasoning"] == payload["summary"]
    assert result["result"]["findings"][0]["evidence"]


def test_summary_alias_does_not_create_missing_evidence_or_override_explicit_reasoning():
    payload = assessment()
    before = copy.deepcopy(payload)
    assert output_policy.worker_payload(payload, TASK)["reasoning"] == payload["reasoning"]
    assert payload == before
    for value in ({"summary": "x"}, {"summary": None}, {}):
        with pytest.raises(ValidationError):
            GoalAssessment.model_validate(output_policy.worker_payload({"outcome": "no_evidence", **value}, TASK))


def test_planner_display_only_prose_cannot_block_a_structured_decision():
    schema = output_policy.planner_schema(PlannerDecision.model_json_schema(), TASK)
    assert not {"report", "next_action"} & schema["properties"].keys()
    assert "ReportNarrative" not in schema["$defs"]
    payload = dict(goal_state="inconclusive", basis_summary="当前仍有需要补证的真实源码方向。", report="malformed prose", next_action=42)
    value = PlannerDecision.model_validate(output_policy.planner_payload(json.dumps(payload), TASK))
    assert value.report is None and not value.next_action
    assert "decision.report" not in agent._scenario_constraint("sqli", minimal=True)
    assert "decision.report" in agent._scenario_constraint("sqli")


def test_unrequired_fix_plans_are_not_delivery_gaps_but_prerequisites_still_are():
    entry = dict(frozen_claim={"preconditions": ["普通用户能够触发当前入口"]})
    assert not delivery_gaps(entry, TASK)
    assert len(delivery_gaps(entry)) == 2
    assert delivery_gaps(dict(frozen_claim={}), TASK) == ["登录、权限与业务初始状态待补充"]


@pytest.mark.parametrize("format", ["markdown", "json", "zip"])
def test_one_report_preserves_all_dispositions_and_frozen_inputs(format):
    frozen = frozen_report()
    before = copy.deepcopy(frozen)
    value = export(frozen, view="report", format=format)
    assert export(frozen, view="report", format=format) == value
    assert frozen == before
    doc = audit_report.document(frozen)
    md = audit_report.markdown(doc)
    quality = evaluate(doc, md)
    assert quality["passed"], quality
    assert "# 审计报告" in md and "待终审" in md and "终审接受" in md
    assert "findings/C-" not in md
    assert "修复建议待补充" not in md and "修复后复测步骤与回归条件待补充" not in md
    assert "## 限制与追溯" in md
    assert all(entry["frozen_claim"]["title"] in md for entry in doc["canonical_findings"])


def test_evidence_pack_is_owned_hash_checked_and_contains_no_repeated_report_views():
    frozen = frozen_report()
    record = frozen["input"]["all_records"][0]
    name = original_poc_name(record, record["poc"])
    raw = b"owned original script\n"
    frozen["input"]["frozen_evidence"].append(dict(name=name, data=base64.b64encode(raw).decode(), sha256=digest(raw)))
    with zipfile.ZipFile(io.BytesIO(export(frozen, view="report", format="zip"))) as archive:
        assert set(archive.namelist()) == {"audit-report.md", "evidence.json", "manifest.json", "evidence/" + name}
        manifest = json.loads(archive.read("manifest.json"))
        facts = json.loads(archive.read("evidence.json"))
        assert archive.read("audit-report.md") == export(frozen, view="report")
        assert archive.read("evidence/" + name) == raw
        assert facts["source_evidence"] == audit_report.document(frozen)["source_evidence"]
        assert len({s["evidence_id"] for s in facts["source_evidence"]}) == len(facts["source_evidence"])
        assert len(manifest["source_fragments"]) == len(facts["source_evidence"])
        assert all("comparison_candidates" not in entry for entry in facts["canonical_findings"])
        for member, sha in manifest["artifact_hashes"].items():
            assert digest(archive.read(member)) == sha
    frozen["input"]["frozen_evidence"][-1]["sha256"] = "wrong"
    with zipfile.ZipFile(io.BytesIO(export(frozen, view="report", format="zip"))) as archive:
        assert "evidence/" + name not in archive.namelist()
        assert any(item.get("reason") == "hash_mismatch" for item in json.loads(archive.read("manifest.json"))["missing_attachments"])


def test_missing_source_and_no_execution_are_disclosed_without_new_source_reads():
    frozen = frozen_report()
    frozen["facts"]["source_evidence"] = []
    frozen["facts"]["verification_attempts"] = []
    md = export(frozen, view="report").decode()
    assert "未冻结源码片段" in md and "未保存动态执行记录" in md
    with zipfile.ZipFile(io.BytesIO(export(frozen, view="report", format="zip"))) as archive:
        assert any(item.get("reason") == "source_not_frozen" for item in json.loads(archive.read("manifest.json"))["missing_attachments"])


def test_manual_verification_does_not_require_uncreated_adapted_scripts_or_runner_manifests():
    frozen = frozen_report()
    for record in frozen["input"]["all_records"]:
        for verification in record.get("verifications") or []:
            verification.update(source="operator", modified_script="")
    for attempt in frozen["facts"]["verification_attempts"]:
        attempt["final_script"] = ""
    with zipfile.ZipFile(io.BytesIO(export(frozen, view="report", format="zip"))) as archive:
        missing = json.loads(archive.read("manifest.json"))["missing_attachments"]
        assert not any("adapted-poc" in item.get("name", "") or "runner-manifest" in item.get("name", "") for item in missing)


@pytest.mark.parametrize("format", ["markdown", "json", "zip"])
def test_report_api_serves_the_two_deliverables_and_keeps_original_archive(client, format):
    http, saved = client
    response = http.get(f"/api/runs/run-1/report?view=report&format={format}")
    assert response.status_code == 200
    assert response.content == export(saved, view="report", format=format)
    assert http.get("/api/runs/run-1/report?view=archive").text == "original archive"


@pytest.mark.parametrize("parent_policy", [None, "legacy", output_policy.POLICY])
@pytest.mark.parametrize("mode", ["audit", "poc_review", "review"])
def test_continuation_and_retest_freeze_the_output_contract_without_changing_parent(hosted, parent_policy, mode):
    store, repo, run = hosted
    if parent_policy:
        spec = {**run["task_spec"], "output_policy": parent_policy}
        store._write("UPDATE runs SET task_spec=? WHERE id=?", (json.dumps(spec), run["id"]))
    add_claim(store, run, 1)
    finish(store, run)
    parent = copy.deepcopy(store.frozen_report(run["id"]))
    child = store.create_continuation(run["id"], request(mode=mode))
    assert child["task_spec"]["output_policy"] == (parent_policy or output_policy.POLICY)
    assert store.frozen_report(run["id"]) == parent
    finish(store, child)
    frozen = materialize(store, repo, child["id"])
    if parent_policy != "legacy":
        assert frozen["markdown"] == export(frozen, view="report").decode()
        assert frozen["zip_blob"] == export(frozen, view="report", format="zip")
        assert frozen["json_export"] == export(frozen, view="report", format="json").decode()
        assert json.loads(frozen["json_export"])["schema_version"] == audit_report.VERSION
        with zipfile.ZipFile(io.BytesIO(frozen["zip_blob"])) as archive:
            assert "audit-report.md" in archive.namelist()
            assert "final-review.json" not in archive.namelist()
