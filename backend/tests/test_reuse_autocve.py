"""Reused AutoCVE-shaped helpers: deterministic, bounded and evidence-safe."""
from __future__ import annotations

import json
import shutil

from audit.reuse.autocve import knowledge
from audit.reuse.autocve.candidates import rank_candidates
from audit.reuse.autocve.finding_contract import derive_state, validate_finding
from audit.reuse.autocve.recon import normalize_brief
from audit.reuse.autocve.knowledge import KNOWLEDGE_DIR


def test_knowledge_selection_is_deterministic_and_hash_bound():
    first = knowledge.route(languages=["php"], checkpoints=["mass assignment", "role"])
    again = knowledge.route(languages=["php"], checkpoints=["role"])
    assert [item.id for item in first.refs] == [item.id for item in again.refs]
    assert first.total_bytes <= knowledge.DEFAULT_MAX_BYTES
    assert first.manifest_version == knowledge.MANIFEST_VERSION
    for ref in first.refs:
        assert len(ref.sha256) == 64
        assert ref.bytes > 0
    prompt = first.prompt()
    assert "不是源码证据" in prompt
    assert "php-authorization" in prompt


def test_knowledge_respects_language_and_checkpoint_ordering():
    php = knowledge.route(languages=["php"], checkpoints=["sqli"])
    assert php.refs and php.refs[0].id == "php-input-to-sink"
    xss = knowledge.route(languages=["php"], checkpoints=["xss_r"])
    assert xss.refs[0].id == "php-output-xss"
    python = knowledge.route(languages=["python"], checkpoints=["sqli"])
    assert python.refs == ()


def test_knowledge_byte_cap_and_missing_resource_are_diagnostic(tmp_path):
    shutil.copytree(KNOWLEDGE_DIR, tmp_path / "knowledge")
    directory = tmp_path / "knowledge"
    selection = knowledge.route(languages=["php"], max_bytes=100, directory=directory)
    assert selection.refs == ()
    codes = {item["code"] for item in selection.diagnostics}
    assert "resource_over_bytes" in codes

    manifest = json.loads((directory / "manifest.json").read_text("utf-8"))
    manifest["entries"][0]["file"] = "missing.md"
    (directory / "manifest.json").write_text(json.dumps(manifest), "utf-8")
    selection = knowledge.route(languages=["php"], directory=directory)
    assert "resource_missing" in {item["code"] for item in selection.diagnostics}
    assert all(ref.id != manifest["entries"][0]["id"] for ref in selection.refs)


def test_knowledge_hash_mismatch_is_not_silently_trusted(tmp_path):
    shutil.copytree(KNOWLEDGE_DIR, tmp_path / "knowledge")
    directory = tmp_path / "knowledge"
    target = directory / "php-input-to-sink.md"
    target.write_text(target.read_text("utf-8") + "\n改过的内容\n", "utf-8")
    selection = knowledge.route(languages=["php"], checkpoints=["sql"], directory=directory)
    assert "resource_hash_mismatch" in {item["code"] for item in selection.diagnostics}
    assert all(ref.id != "php-input-to-sink" for ref in selection.refs)


def _payload(**overrides):
    payload = {
        "kind": "vulnerability",
        "title": "会员资料批量赋值",
        "summary": "普通用户可以提交 role 字段并改写自身角色。",
        "evidence": "app/public/account/update.php:2-9",
        "vulnerability_type": "mass_assignment",
        "primary_location": {"path": "app/public/account/update.php", "line": 4},
        "input_source": "$_POST['role']",
        "propagation": "直接拼进 UPDATE",
        "dangerous_operation": "UPDATE users SET role=$_POST[role]",
        "impact": "普通用户可提升为 admin",
    }
    payload.update(overrides)
    return payload


def test_contract_accepts_a_cited_candidate_without_forcing_a_poc():
    result = validate_finding(_payload())
    assert result.ok is True
    assert result.state == "static_supported"
    # A claim with a citation but only a sink is a candidate, not a weaker rejection.
    thin = validate_finding(_payload(propagation="", impact=""))
    assert thin.ok is True
    assert thin.state == "static_candidate"


def test_contract_rejects_missing_cause_and_location_field_by_field():
    result = validate_finding(_payload(vulnerability_type="", primary_location={},
                                       input_source="", propagation="",
                                       dangerous_operation="", impact=""))
    assert result.ok is False
    codes = {item.code for item in result.rejections}
    assert {"root_cause_missing", "primary_location_invalid"} <= codes
    fields = {item.field for item in result.rejections}
    assert {"vulnerability_type", "primary_location"} <= fields


def test_contract_basis_is_required_only_for_a_supported_state():
    bare = {"title": "越权读取", "kind": "vulnerability",
            "summary": "用户可控 id 直接查询他人订单。", "evidence": "app/order.php:8-9",
            "vulnerability_type": "idor", "primary_location": {"path": "app/order.php", "line": 9}}
    assert validate_finding(bare).ok is True
    # Claiming the stricter state without naming any basis field is a rejection, not an
    # automatic downgrade: the model asked for that state, so it must support it.
    supported = validate_finding(bare, state="static_supported")
    assert {"basis_missing", "sink_missing", "impact_missing", "path_missing"} <= {
        item.code for item in supported.rejections}
    sink_only = validate_finding({**bare, "dangerous_operation": "SELECT ... WHERE id=$_GET[id]",
                                  "impact": "可读取他人订单"}, state="static_supported")
    assert {item.code for item in sink_only.rejections} == {"path_missing"}


def test_contract_unknown_type_requires_a_classification_reason():
    rejected = validate_finding(_payload(vulnerability_type="unknown"))
    assert "root_cause_missing" in {item.code for item in rejected.rejections}
    accepted = validate_finding(_payload(vulnerability_type="unknown",
                                         classification_reason="暂无法归入既有根因"))
    assert accepted.ok is True


def test_contract_needs_evidence_accepts_missing_fact_without_a_poc():
    payload = _payload(dangerous_operation="", primary_location=None,
                       missing_context=["缺少 role 校验的中间件源码"])
    result = validate_finding(payload, state="needs_evidence",
                              missing_context=["缺少 role 校验的中间件源码"])
    assert result.ok is True
    assert result.state == "needs_evidence"


def test_contract_static_supported_requires_sink_impact_and_path():
    base = _payload()
    assert validate_finding(base, state="static_supported").ok is True
    gaps = validate_finding(_payload(dangerous_operation="", impact="", propagation=""),
                            state="static_supported")
    assert gaps.ok is False
    assert {"sink_missing", "impact_missing", "path_missing"} <= {
        item.code for item in gaps.rejections}


def test_contract_ignores_model_confirmed_state_fields():
    result = validate_finding(_payload(confirmed=True, is_verified=True,
                                       verification_status="verified", verdict="confirmed"))
    assert result.ok is True
    assert {item["field"] for item in result.ignored} == {
        "confirmed", "is_verified", "verification_status", "verdict"}


def test_contract_does_not_drop_medium_or_low_severity():
    for severity in ("low", "medium"):
        assert validate_finding(_payload(severity=severity)).ok is True


def test_state_derivation_treats_poc_as_description_not_execution():
    assert derive_state(_payload(poc={"script": "echo 1;"})) == "static_supported"
    assert derive_state(_payload()) == "static_supported"
    assert derive_state(_payload(dangerous_operation="")) == "static_candidate"
    assert derive_state(_payload(missing_context=["缺少中间件"])) == "needs_evidence"


def _brief(**overrides):
    brief = {
        "summary": "项目入口集中在 public 目录。",
        "layout": [{"path": "app/public", "role": "web", "notes": ""}],
        "entry_candidates": [{"path": "app/public/index.php", "start_line": 2,
                              "end_line": 999, "why": "入口"}],
        "data_stores": [{"path": "../etc/passwd", "start_line": 1, "end_line": 2, "why": "越界"}],
        "security_boundaries": [],
        "reading_plan": [{"path": "app/public/account/update.php", "start_line": 1,
                          "end_line": 5, "why": "写操作"}],
        "uncertainties": ["无法确认部署目录"],
    }
    brief.update(overrides)
    return brief


def test_recon_keeps_only_frozen_paths_and_clamps_lines():
    files = {
        "app/public/index.php": {"line_count": 40},
        "app/public/account/update.php": {"line_count": 12},
    }
    brief, diagnostics = normalize_brief(_brief(), files)
    assert [item["path"] for item in brief["entry_candidates"]] == ["app/public/index.php"]
    assert brief["entry_candidates"][0]["end_line"] == 40
    assert brief["data_stores"] == []
    assert "导航线索" in brief["notice"]
    assert "evidence" not in brief
    codes = {(item["code"], item.get("reason")) for item in diagnostics}
    assert ("recon_ref_dropped", "unknown_path") in codes
    assert any(item.get("path") == "../etc/passwd" for item in diagnostics)


def test_recon_layout_accepts_known_directories_only():
    files = {"app/public/index.php": {"line_count": 10}}
    brief, diagnostics = normalize_brief(_brief(layout=[
        {"path": "app/public", "role": "web", "notes": ""},
        {"path": "outside", "role": "?", "notes": ""},
    ]), files)
    assert [item["path"] for item in brief["layout"]] == ["app/public"]
    assert any(item["code"] == "recon_area_dropped" and item.get("path") == "outside"
               for item in diagnostics)


def test_candidate_ordering_is_stable_and_never_merges():
    one = {"id": "b", "title": "SQL 注入", "vulnerability_type": "sqli",
           "primary_location": {"path": "app/a.php", "line": 3},
           "evidence": ["app/a.php:3-4"], "disposition": "open"}
    two = {"id": "a", "title": "SQL 注入", "vulnerability_type": "sqli",
           "primary_location": {"path": "app/a.php", "line": 3}, "evidence": []}
    ranked = rank_candidates([one, two], checkpoints=["sqli"])
    assert [item["candidate"]["id"] for item in ranked] == ["b", "a"]
    assert all(set(item) == {"candidate", "score", "reasons"} for item in ranked)
    assert ranked[0]["score"] > ranked[1]["score"]
    assert len(rank_candidates([one, two])) == 2
