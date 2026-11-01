"""Frozen-scope delivery exports: no mutable fallbacks, truthful state and bytes."""
import base64
import copy
import io
import json
import zipfile
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from audit import app as app_module
from audit.capability import POLICY, freeze_focus, outcome, validate_focus
from audit.report_bundle import build_final_review
from audit.report_readable import document, export, digest
from tests.test_final_review_bundle import bundle, finding, accepted, verification, FakeRepository


def frozen_report():
    a, b = accepted("first"), finding("other", status="unverified")
    a["poc"] = {"filename": "demo.py", "language": "python", "script": "print('``` | 中文')", "instructions": "1. 登录 Alice\n2. 获取 CSRF\n3. 改变对象标识", "normal_input": "id=own", "attack_input": "id=other", "expected_result": "读回其他账户对象"}
    a["final_review_required"] = True
    a["final_review_decision"] = {"decision": "accept", "rationale": "实际独立终审理由：读取源码与双侧观测一致。"}
    a["remediation"] = "第一步\n\n第二步 | 保留完整段落\n" + "修复细节" * 300
    a["cvss"]["base_vector"] = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    payload = bundle([a, b])
    payload["all_records"] = payload["findings"]
    payload["run"]["poc_policy"] = {"mode": "off"}
    payload["snapshot"]["name"] = "商城源码.zip"
    payload["frozen_evidence"] = [{"name": "unrelated-secret.txt", "data": base64.b64encode(b"OTHER FINDING").decode()}]
    facts = build_final_review(payload, repository=FakeRepository({"app/account/update.php": ["<?php", "$id = $_POST['id'];", "query($id);", "echo $id;"]}))
    return {"facts": facts, "input": payload, "input_hash": "frozen-input-hash", "output_hash": "archive-hash", "markdown": "original archive", "json_export": '{"original":true}', "zip_blob": b"original-zip"}


@pytest.mark.parametrize("view", ["audit", "vulnerabilities"])
@pytest.mark.parametrize("format", ["markdown", "json", "zip"])
def test_exports_are_deterministic_and_do_not_mutate_frozen_facts(view, format):
    saved = frozen_report()
    before = copy.deepcopy(saved)
    data = export(saved, view=view, format=format)
    assert data == export(saved, view=view, format=format)
    assert saved == before
    if format == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            assert manifest["main_document"] == ("report.md" if view == "audit" else "vulnerability-report.md")
            assert json.loads(archive.read("final-review.json")) == saved["facts"]
            assert json.loads(archive.read("render-quality.json"))["passed"]
            assert {"report.md", "vulnerability-report.md", "findings/C-01.md", "findings/C-02.md", "render-quality.json"} <= set(archive.namelist())
            for name, hash_ in manifest["artifact_hashes"].items():
                assert digest(archive.read(name)) == hash_


def test_individual_closure_never_contains_other_claims_or_parent_facts():
    saved = frozen_report()
    doc = document(saved, canonical_id="first")
    assert doc["counts"]["canonical"] == 1
    assert doc["parent_summary"]["counts"]["canonical"] == 2
    assert "other" not in doc["numbering"]
    data = export(saved, format="zip", canonical_id="first")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert "final-review.json" not in archive.namelist()
        assert "finding-facts.json" in archive.namelist()
        assert "evidence/unrelated-secret.txt" not in archive.namelist()
        scoped = json.loads(archive.read("finding-facts.json"))
        assert [e["canonical_id"] for e in scoped["canonical_findings"]] == ["first"]
        assert all(a["finding_ref"]["finding_id"] == "first" for a in scoped["verification_attempts"])
    with pytest.raises(KeyError):
        export(saved, canonical_id="ledger-from-another-run")


def test_markdown_preserves_reason_vector_multiline_remediation_and_poc():
    saved = frozen_report()
    md = export(saved, canonical_id="first").decode()
    assert "实际独立终审理由" in md
    assert "未进行独立终审" not in md
    assert "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" in md
    assert saved["facts"]["canonical_findings"][0]["frozen_claim"]["remediation"] in md
    assert "1. 登录 Alice\n2. 获取 CSRF" in md
    assert "````python\nprint('``` | 中文')\n````" in md
    assert "POC 执行：。" not in md
    audit = export(saved).decode()
    assert "商城源码.zip" in audit
    assert all(line.count("|") == 7 for line in audit.splitlines() if line.startswith("|"))


@pytest.mark.parametrize("mode,verified,complete", [("off", False, True), ("auto", False, True), ("required", False, False), ("required", True, True)])
def test_new_policy_completion_is_mode_aware(mode, verified, complete):
    saved = frozen_report()
    entries = [saved["facts"]["canonical_findings"][0]]
    entries[0]["frozen_claim"]["verification_status"] = "verified" if verified else "unverified"
    entries[0]["frozen_claim"]["verified_compatible"] = verified
    entries[0]["final_batch_review"]["focus"] = {"relation": "relevant"}
    coverage = {"files": {"complete": True}, "directions": {"complete": True},
                "verification": {"pending": 0 if verified else 1, "verified": int(verified), "pending_review": 0}, "final_review": {"pending": 0}}
    run = {"status": "completed", "task_spec": {"capability_policy": POLICY, "completion_policy": "coverage_review"}, "poc_policy": {"mode": mode}}
    assert outcome(run, coverage, entries)["audit_complete"] == complete
    run["status"] = "interrupted"
    assert outcome(run, coverage, entries)["audit_complete"] is False


def test_goal_relevance_is_not_a_keyword_or_self_declared_acceptance():
    run = {"task_spec": {"capability_policy": POLICY, "scenario": "sqli"}}
    claim = {"vulnerability_type": "mass_assignment", "evidence": [{"path": "x.php", "range": {"start": 1, "end": 5}}]}
    focus = {"objective_ref": "objective-main", "relation": "relevant", "rationale": "用户目标和具体输入操作完全相关。", "evidence": [{"path": "x.php", "start_line": 1, "end_line": 2}]}
    with pytest.raises(ValueError, match="显式分场景"):
        validate_focus(run, focus, claim=claim)
    focus["relation"] = "supporting"
    focus["supports"] = ["target-finding"]
    with pytest.raises(ValueError, match="input→sink"):
        validate_focus(run, focus, claim=claim, known_ids=["target-finding"])
    focus["relation"] = "incidental"
    validate_focus(run, focus, claim=claim)
    coverage = {"files": {"complete": True}, "directions": {"complete": True}, "verification": {}, "final_review": {"pending": 0}}
    run.update(status="completed", poc_policy={"mode": "off"})
    entry = {"canonical_id": "side", "final_disposition": "accepted", "final_batch_review": {"focus": focus}, "frozen_claim": {"verification_status": "verified"}}
    assert outcome(run, coverage, [entry])["audit_complete"] is False


@pytest.fixture
def client(monkeypatch):
    saved = frozen_report()
    store = SimpleNamespace(get_run=lambda run_id: saved["input"]["run"] if run_id == "run-1" else None,
                            frozen_report=lambda run_id: saved if run_id == "run-1" else None)
    monkeypatch.setattr(app_module.app.state, "services", SimpleNamespace(store=store), raising=False)
    monkeypatch.setattr(app_module, "_saved_report", lambda state, run_id: saved)
    client = TestClient(app_module.app)
    yield client, saved
    client.close()


def test_api_archive_compatibility_derived_membership_and_format(client):
    http, saved = client
    for format, key in (("markdown", "markdown"), ("json", "json_export"), ("zip", "zip_blob")):
        raw = http.get(f"/api/runs/run-1/report?format={format}")
        assert raw.content == http.get(f"/api/runs/run-1/report?format={format}&view=archive").content
        assert raw.headers["etag"] == '"archive-hash"'
    one = http.get("/api/runs/run-1/canonical-findings/first/report?format=json")
    assert one.status_code == 200
    assert one.json()["counts"]["canonical"] == 1
    assert http.get("/api/runs/run-1/canonical-findings/not-in-run/report").status_code == 404
    assert http.get("/api/runs/missing/report?view=audit").status_code == 404
    assert http.get("/api/runs/run-1/report?view=bad").status_code == 422
    assert http.get("/api/runs/run-1/report?format=exe").status_code == 422
    saved["input"]["run"]["status"] = "running"
    assert http.get("/api/runs/run-1/report?view=audit").json()["detail"]["code"] == "report_not_ready"


def test_legacy_missing_facts_never_rebuilds_live_history(client):
    http, saved = client
    saved["facts"] = None
    assert http.get("/api/runs/run-1/report?view=audit").json()["detail"]["code"] == "legacy_facts_unavailable"
    assert http.get("/api/runs/run-1/report").text == "original archive"
    saved['input']['run']['task_spec']['capability_policy'] = POLICY
    assert http.get("/api/runs/run-1/report?view=audit").json()["detail"]["code"] == "report_not_ready"


def test_new_exports_and_source_listing_do_not_materialize_missing_historical_facts(client, monkeypatch):
    http, saved = client
    saved['facts'] = None
    before = copy.deepcopy(saved)
    store = app_module.app.state.services.store
    store.get_project_finding = lambda finding_id: {'id': finding_id}
    store.project_finding_history = lambda finding_id: [{'run_id': 'run-1'}]
    def unexpected_materialization(*args):
        pytest.fail('Read-only delivery endpoints must not generate historical facts')
    monkeypatch.setattr(app_module, '_saved_report', unexpected_materialization)
    for path in ('/api/runs/run-1/report?view=audit',
                 '/api/runs/run-1/canonical-findings/first/report'):
        response = http.get(path)
        assert response.status_code == 409
        assert response.json()['detail']['code'] == 'legacy_facts_unavailable'
    assert http.get('/api/project-findings/first/reports').json() == {'items': [], 'current_available': False}
    assert saved == before


@pytest.mark.parametrize('alias,canonical,accepted_count', [('df7c56ad',3,0),('2bf893de',18,18),('2969bcf2',23,23)])
def test_recent_frozen_fixtures_preserve_historical_counts_completion_and_quality(alias,canonical,accepted_count):
    from pathlib import Path
    source = json.loads((Path(__file__).parent/'fixtures/recent_capability_runs.json').read_text())
    case = next(case for case in source['runs'] if case['run_alias'] == alias)
    saved = dict(input=case['metadata'],facts=case['facts'],input_hash=case['archive_hashes']['input_hash'],output_hash=case['archive_hashes']['output_hash'])
    before = copy.deepcopy(saved)
    result = json.loads(export(saved,view='audit',format='json'))
    assert result['counts']['canonical'] == canonical
    assert result['counts']['accepted'] == accepted_count
    assert result['original_quality_result'] == case['facts']['quality_result']
    assert result['run_outcome'] == case['facts']['run_outcome']
    assert result['metadata']['historical_relayout'] is True
    assert saved == before
    if alias == '2bf893de':
        assert result['metadata']['poc_mode'] == 'off'
        assert result['run_outcome']['audit_complete'] is False  # do not recalculate history
    if alias == '2969bcf2':
        assert result['coverage']['files']['total'] == 61
        assert result['coverage']['files']['read'] == 59
        assert result['coverage']['files']['reviewed'] == 61


def test_layout_gate_detects_broken_scopes_fences_and_missing_sections():
    from audit.report_layout_quality import evaluate
    from audit.report_readable import markdown
    doc = document(frozen_report(), canonical_id="first")
    md = markdown(doc)
    assert evaluate(doc, md)["passed"]
    doc["scope"]["canonical_ids"] = ["unrelated"]
    quality = evaluate(doc, md + "\n```python\n")
    assert not quality["passed"]
    assert {"scope_matches", "fences"} <= set(quality["failed_checks"])
    assert not evaluate(doc, "# Empty report")["checks"]["sections"]


def test_nonfinite_legacy_score_is_unknown_not_a_rendered_number():
    saved = frozen_report()
    saved['facts']['canonical_findings'][0]['frozen_claim']['cvss']['base_score'] = float('nan')
    md = export(saved).decode()
    assert 'nan' not in md.casefold()
    assert '待评分' in md


def test_markdown_redaction_does_not_change_original_evidence_hashes():
    saved = frozen_report()
    saved['facts']['canonical_findings'][0]['frozen_claim']['poc']['script'] = 'Authorization: Bearer live-value\nCookie: SID=live-session\nGET /path?api_key=live-key'
    original = copy.deepcopy(saved)
    md = export(saved, canonical_id="first").decode()
    assert all(value not in md for value in ('live-value','live-session','live-key'))
    assert '[已脱敏]' in md
    assert original == saved


def test_ledger_report_source_requires_exact_conclusion_and_assessment(client,monkeypatch):
    http,saved = client
    entry = saved['facts']['canonical_findings'][0]
    claim = entry['frozen_claim']
    ledger = {**copy.deepcopy(claim),'id':entry['canonical_id'],'revision':claim['project_revision'],
              'cvss_assessment':{'assessment_revision':entry['assessment_revision']}}
    store = app_module.app.state.services.store
    store.get_project_finding = lambda finding_id: ledger
    store.project_finding_history = lambda finding_id: [{'run_id':'run-1'}]
    path = f'/api/project-findings/{entry["canonical_id"]}/reports'
    result = http.get(path).json()
    assert result['current_available'] is True
    assert result['items'][0]['canonical_id'] == entry['canonical_id']
    ledger['revision'] += 1
    assert http.get(path).json()['current_available'] is False
    ledger['revision'] -= 1
    ledger['cvss'] = {**ledger['cvss'],'base_score':0}
    # Equal assessment revision integers alone do not prove identity.
    assert http.get(path).json()['current_available'] is False
