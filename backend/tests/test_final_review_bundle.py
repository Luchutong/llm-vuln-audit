"""Final-review fact package: counts, conflicts, duplicates, and publish gates.

The counts fixture reproduces the 70/62/46 relation the plan names: 70 raw records,
62 valid candidates, 46 canonical ledger groups.  Nothing here reads a benchmark truth:
the report may only recompute what the run's own records say.
"""
from __future__ import annotations

import json

import pytest

from audit import final_review
from audit.report_bundle import build_and_render, build_final_review
from audit.report_final import SECTION_TITLES, render_final_report
from audit.report_quality import evaluate


class FakeRepository:
    def __init__(self, files: dict[str, list[str]] | None = None):
        self.files = files or {}

    def get_snapshot(self, snapshot_id: str) -> dict:
        return {"id": snapshot_id, "name": "lab30.zip", "archive_sha256": "b" * 64,
                "files": len(self.files)}

    def read_source(self, snapshot_id: str, path: str, start: int = 1, end: int = 200) -> dict:
        lines = self.files.get(path)
        if lines is None:
            raise FileNotFoundError(path)
        if start < 1 or end < start:
            raise ValueError("bad range")
        if start > len(lines):
            raise ValueError("start beyond end")
        out = [{"number": number, "text": lines[number - 1]}
               for number in range(start, min(end, len(lines)) + 1)]
        return {"snapshot_id": snapshot_id, "path": path, "sha256": "a" * 64,
                "lines": out, "start_line": start, "end_line": out[-1]["number"],
                "truncated": False, "next_start": None}


def verification(verification_id: str, *, revision: int = 1, verdict: str = "verified",
                 execution_status: str = "success", jobs=None) -> dict:
    return {
        "id": verification_id,
        "finding_revision": revision,
        "target": {"context_id": f"ctx-{verification_id}"},
        "target_version": "3.1.1",
        "execution_status": execution_status,
        "verdict": verdict,
        "status": "recorded",
        "source": "poc_agent",
        "normal_observation": "普通请求返回 200，未触发越权。",
        "attack_observation": "攻击请求返回管理员字段。",
        "browser_execution": False,
        "notes": "",
        "modified_script": "<?php echo 1;" if execution_status == "success" else "",
        "artifacts": [{"path": f"{verification_id}.txt"}],
        "agent": {"jobs": jobs if jobs is not None else [
            {"job_id": f"job-{verification_id}", "kind": "run_poc",
             "result": {"status": "succeeded", "exit_code": 0}}
        ]},
    }


def review(decision: str, *, revision: int = 1, verification_id: str = "v1",
           review_id: str = "rev1") -> dict:
    return {
        "id": review_id, "revision": revision, "verification_id": verification_id,
        "decision": decision, "rationale": "对照观测与源码一致。" if decision == "confirmed" else "观测与结论不符。",
        "observed_normal": "200", "observed_attack": "admin", "created_at": "2026-10-28T00:00:00Z",
    }


def finding(finding_id: str, *, revision: int = 1, project_id: str | None = None,
            project_revision: int = 0, status: str = "verified", verdict: str = "verified",
            verifications: list[dict] | None = None, reviews: list[dict] | None = None,
            category: str = "sqli", kind: str = "vulnerability",
            path: str = "app/account/update.php", line: int = 4,
            title: str | None = None, summary: str = "越权写入角色字段。",
            missing_context: list[str] | None = None) -> dict:
    return {
        "id": finding_id,
        "run_id": "run-1",
        "snapshot_id": "snap-1",
        "unit_id": "task-1",
        "finding_kind": kind,
        "title": title or f"漏洞 {finding_id}",
        "category": category,
        "summary": summary,
        "severity": "high",
        "cvss": {"base_score": 8.8, "severity": "high", "base_vector": "CVSS:3.1/AV:N/AC:L"},
        "cvss_assessment": {"assessment_revision": 2, "conclusion_revision": revision,
                            "engine_version": "cvss-3.1-host", "status": "scored", "source": "auto"},
        "validation_state": "candidate",
        "disposition": "open",
        "disposition_reason": "",
        "revision": revision,
        "project_finding_id": project_id,
        "project_revision": project_revision,
        "verification_status": status,
        "verification_verdict": verdict,
        "latest_verification_id": verifications[-1]["id"] if verifications else None,
        "verifications": verifications or [],
        "verification_reviews": reviews or [],
        "evidence": [{"path": path, "start_line": line, "end_line": line + 2, "symbol": "update"}],
        "primary_location": {"path": path, "line": line},
        "file_path": path,
        "line": line,
        "input_source": "$_POST['role']",
        "propagation": "直接拼接",
        "dangerous_operation": "UPDATE users SET role=$_POST[role]",
        "protection": "无",
        "preconditions": ["登录为普通用户"],
        "missing_context": missing_context or [],
        "remediation": "使用白名单字段。",
        "poc": {"filename": "poc.php"},
        "validation_errors": [],
        "created_at": "2026-10-28T00:00:00Z",
    }


def accepted(finding_id: str, *, project_id: str | None = None, line: int = 4) -> dict:
    return finding(finding_id, project_id=project_id, line=line,
                   verifications=[verification("v1")], reviews=[review("confirmed")])


def bundle(findings: list[dict], *, status: str = "completed", pending_verification: int = 0,
           coverage: dict | None = None) -> dict:
    coverage = coverage if coverage is not None else {
        "version": "coverage-review-v1", "total": 61, "pending_total": 0,
        "read_paths": [f"f{i}.php" for i in range(61)],
        "reviewed_paths": [f"f{i}.php" for i in range(61)],
        "skips": [], "complete": True,
    }
    directions = {"total": 10, "resolved_total": 10, "skipped_total": 0,
                  "unsettled_total": 0, "complete": True}
    verification_counts = {
        "total": len({item.get("project_finding_id") or item["id"] for item in findings
                      if item["finding_kind"] == "vulnerability"
                      and item["validation_state"] == "candidate" and item["disposition"] == "open"}),
        "verified": sum(1 for item in findings if item["verification_status"] == "verified"),
        "pending": pending_verification,
        "reviewed": sum(len(item["verification_reviews"]) for item in findings),
        "pending_review": 0,
    }
    return {
        "run": {
            "id": "run-1", "status": status, "snapshot_id": "snap-1", "project_id": "proj-1",
            "created_at": "2026-10-28T00:00:00Z", "finished_at": "2026-10-28T01:00:00Z",
            "model_profile": {"id": "p1", "model": "deepseek-chat"},
            "execution_summary": {
                "policy_version": "whitebox-2", "claim_epoch": 3,
                "run_limits": {"responses": 1600, "tools": 8192, "seconds": 5400},
                "run_usage": {"responses": 394, "tools": 522, "seconds": 1640.0},
                "run_remaining": {"responses": 1206, "tools": 7670, "seconds": 3760},
                "stop_reason": {"code": "invalid_output_limit", "message": "输出上限"},
                "context": {"peak_request_bytes": 131861, "history_bytes": 393216,
                            "summary_requests": 0, "limit_hits": 0},
                "poc": {"jobs": 21, "resets": 6, "recorded": 6, "confirmed": 5},
                "verification": verification_counts,
                "directions": directions,
                "coverage_review": coverage,
            },
            "task_spec": {"completion_policy": "coverage_review"},
        },
        "planner": {"run_id": "run-1"},
        "findings": findings,
        "tasks": [{"id": "task-1", "title": "账户写操作", "state": "completed"}],
        "project_map": {"files": [{"path": f"f{i}.php"} for i in range(61)]},
        "snapshot": {"archive_sha256": "b" * 64},
        "report_narrative": {},
    }


def render(payload: dict, repo: FakeRepository | None = None) -> tuple[dict, str]:
    if repo is None:
        repo = FakeRepository({"app/account/update.php": [
            "<?php", "$role = $_POST['role'];", "db()->exec('UPDATE users SET role=' . $role);",
            "header('Location: /account/me.php');", "",
        ]})
    return build_and_render(payload, all_records=payload["findings"],
                            repository=repo, generated_at="2026-10-28T02:00:00Z")


def test_counts_follow_raw_valid_canonical_relation():
    # 16 groups carry a superseded draft (32 records), 30 groups are single: 62 valid
    # records over 46 ledger groups, plus 8 observations = 70 raw records.
    records, index = [], 0
    for group in range(16):
        records.append(finding(f"draft-{group}", project_id=f"pf-{group}", project_revision=1,
                               status="unverified", verdict=""))
        records.append(finding(f"current-{group}", project_id=f"pf-{group}", project_revision=2))
    for group in range(30):
        records.append(finding(f"solo-{group}"))
    for group in range(8):
        records.append(finding(f"obs-{group}", kind="source_observation", category="note"))
    payload = bundle(records)
    facts, markdown = render(payload)

    assert facts["counts"]["raw_records"] == 70
    assert facts["counts"]["valid_records"] == 62
    assert facts["counts"]["canonical"] == 46
    quality = facts["quality_result"]
    assert quality["recomputed"]["canonical"] == 46
    assert "rendered_counts_match_facts" not in quality["failed_checks"]
    assert "record_mapping_closed" not in quality["failed_checks"]
    assert "required_sections_present" not in quality["failed_checks"]
    assert markdown.count("## ") >= len(SECTION_TITLES)
    for label, value in (("原始记录", 70), ("有效记录", 62), ("规范结论", 46)):
        assert f"- {label}：{value}" in markdown
    # The observation is not a vulnerability and never enters the accepted count.
    assert facts["counts"]["accepted"] == 0
    assert len(facts["observations"]) == 8


def test_verified_without_formal_review_stays_pending_and_is_actionable():
    payload = bundle([finding("f1", verifications=[verification("v1")])])
    facts, markdown = render(payload)

    entry = facts["canonical_findings"][0]
    assert entry["final_disposition"] == "pending"
    assert "正式复核" in entry["disposition_reason"]
    assert facts["counts"]["accepted"] == 0
    assert any(item["kind"] == "complete_claim" for item in facts["action_items"])
    assert facts["quality_result"]["publishability"] == "releasable_partial"
    assert facts["quality_result"]["report_kind"] == "stage"


def test_confirmed_review_of_exact_revision_accepts_the_claim():
    payload = bundle([accepted("f1")])
    facts, markdown = render(payload)

    entry = facts["canonical_findings"][0]
    assert entry["final_disposition"] == "accepted"
    assert entry["frozen_claim"]["verification_id"] == "v1"
    assert facts["counts"]["accepted"] == 1
    assert "已接受漏洞：1" in markdown
    assert facts["quality_result"]["publishability"] == "releasable_final"


def test_review_of_a_different_verification_does_not_confirm_current_claim():
    # The review confirmed the earlier verification of the same revision; a newer POC
    # attempt changed the verification id, so the claim is unconfirmed again.
    old = verification("v0")
    payload = bundle([finding("f1", verifications=[old, verification("v1")],
                              reviews=[review("confirmed", verification_id="v0")])])
    facts, _ = render(payload)
    entry = facts["canonical_findings"][0]
    assert entry["final_disposition"] == "pending"
    assert facts["counts"]["accepted"] == 0


def test_category_conflict_makes_the_group_contested_not_accepted():
    first = finding("f1", project_id="pf-1", project_revision=1, category="csrf",
                    verifications=[verification("v1")], reviews=[review("confirmed")])
    second = finding("f2", project_id="pf-1", project_revision=2, category="sqli",
                     verifications=[verification("v2")], reviews=[review("confirmed", verification_id="v2", review_id="rev2")])
    payload = bundle([first, second])
    facts, markdown = render(payload)

    entry = facts["canonical_findings"][0]
    assert entry["current_claim_ref"]["finding_id"] == "f2"
    assert entry["final_disposition"] == "contested"
    assert [item["kind"] for item in entry["conflicts"]] == ["category_mismatch"]
    assert facts["counts"]["accepted"] == 0
    assert "conflicts_disclosed" not in facts["quality_result"]["failed_checks"]
    assert "存疑/排除" in markdown


def test_accepted_claim_with_a_later_conflicting_record_is_contested():
    confirmed = finding("f1", verifications=[verification("v1")], reviews=[review("confirmed")])
    rejected = finding("f2", project_id=None, path="other.php", line=9,
                       status="rejected", verdict="rejected",
                       verifications=[verification("v2", verdict="rejected")])
    # Same ledger must be shared for a conflict inside one canonical group.
    rejected["project_finding_id"] = None
    payload = bundle([confirmed, rejected])
    facts, _ = render(payload)
    # Different ledger identities: accepted stays accepted and the pair is not a conflict.
    dispositions = {entry["canonical_id"]: entry["final_disposition"]
                    for entry in facts["canonical_findings"]}
    assert sorted(dispositions.values()) == ["accepted", "contested"]


def test_suspected_cross_ledger_duplicate_is_a_suggestion_and_an_action_item():
    one = accepted("f1", project_id=None, line=4)
    two = accepted("f2", project_id=None, line=4)
    payload = bundle([one, two])
    facts, markdown = render(payload)

    for entry in facts["canonical_findings"]:
        assert entry["merge_suggestions"], entry["canonical_id"]
    assert facts["appendix"]["duplicate_pairs"]
    assert any(item["kind"] == "merge_review" for item in facts["action_items"])
    assert "duplicates_disclosed" not in facts["quality_result"]["failed_checks"]
    # Nothing is merged: both claims remain in the canonical inventory.
    assert facts["counts"]["canonical"] == 2
    assert "疑似跨台账重复" in markdown


def test_different_sink_on_the_same_line_is_not_suggested_as_duplicate():
    one = accepted("f1", line=4)
    two = accepted("f2", line=4)
    two["dangerous_operation"] = "include($_GET['page'])"
    two["category"] = "sqli"
    payload = bundle([one, two])
    facts, _ = render(payload)
    assert all(not entry["merge_suggestions"] for entry in facts["canonical_findings"])


def test_missing_snapshot_range_is_reported_unavailable_and_downgrades_the_report():
    payload = bundle([accepted("f1", line=4)])
    facts, markdown = render(payload, FakeRepository({}))
    entry = facts["source_evidence"][0]
    assert entry["available"] is False
    assert "FileNotFoundError" in entry["reason"]
    assert "源码片段不可用" in markdown
    quality = facts["quality_result"]
    assert "source_excerpts_readable" in quality["failed_checks"]
    assert quality["publishability"] == "releasable_partial"
    assert "source_excerpts_readable" in {item["check"] for item in quality["failed_objects"]}


def test_source_excerpt_comes_from_the_snapshot_not_from_the_model():
    payload = bundle([finding("f1", line=1, verifications=[verification("v1")], reviews=[review("confirmed")])])
    facts, markdown = render(payload, FakeRepository({"app/account/update.php": [
        "<?php", "$role = $_POST['role'];", "db()->exec(\"UPDATE users SET role=$role\");"]}))
    entry = facts["source_evidence"][0]
    assert entry["available"] is True
    assert entry["content_hash"] == "a" * 64
    assert entry["excerpt"][1]["text"] == "$role = $_POST['role'];"
    assert "$_POST['role']" in markdown
    assert facts["quality_result"]["publishability"] == "releasable_final"


def test_source_evidence_uses_the_run_snapshot_when_the_finding_row_omits_it():
    record = finding("f1", line=1, verifications=[verification("v1")],
                     reviews=[review("confirmed")])
    record.pop("snapshot_id")
    payload = bundle([record])
    facts, _ = render(payload)
    entry = facts["source_evidence"][0]
    assert entry["snapshot_id"] == "snap-1"
    assert entry["available"] is True


def test_every_evidence_reference_gets_an_entry_not_just_the_first_four():
    record = finding("f1", line=1, verifications=[verification("v1")],
                     reviews=[review("confirmed")])
    record["evidence"] = [
        {"path": "app/account/update.php", "start_line": line, "end_line": line + 1}
        for line in range(1, 6)
    ]
    facts, _ = render(bundle([record]))
    assert len(facts["source_evidence"]) == 5
    assert all(entry["available"] for entry in facts["source_evidence"])
    assert "source_excerpts_readable" not in facts["quality_result"]["failed_checks"]


def test_verification_refs_use_the_run_finding_revision_and_resolve_job_ids():
    record = finding("f1", project_id="pf-1", project_revision=25,
                     verifications=[{
                         **verification("v1", verdict="confirmed", revision=25),
                         "agent": {
                             "run_finding_revision": 1,
                             "jobs": ["job-1"],
                             "job_results": [{"job_id": "job-1", "kind": "script",
                                              "result": {"status": "finished", "exit_code": 0}}],
                         },
                     }],
                     reviews=[review("confirmed")])
    facts, _ = render(bundle([record]))
    attempt = facts["verification_attempts"][0]
    # The ledger revision is kept as metadata; the review coordinate is the run finding.
    assert attempt["ledger_revision"] == 25
    assert attempt["finding_ref"]["revision"] == 1
    assert attempt["job_refs"] == [{
        "job_id": "job-1", "kind": "script", "status": "finished", "exit_code": 0,
    }]
    quality = facts["quality_result"]
    assert "claim_verification_refs" not in quality["failed_checks"]
    assert "accepted_have_full_verification" not in quality["failed_checks"]
    assert quality["publishability"] == "releasable_final"


def test_confirmed_poc_verdict_satisfies_the_accepted_evidence_gate():
    record = finding("f1", verifications=[verification("v1", verdict="confirmed")],
                     reviews=[review("confirmed")])
    facts, _ = render(bundle([record]))
    quality = facts["quality_result"]
    assert facts["counts"]["accepted"] == 1
    assert "accepted_have_full_verification" not in quality["failed_checks"]
    assert quality["publishability"] == "releasable_final"


def test_dict_repr_in_rendered_text_is_a_review_required_defect():
    payload = bundle([finding("f1", verifications=[verification("v1")])])
    facts, markdown = render(payload)
    markdown += "\n宿主对象意外泄漏：" + str({'path': 'x.php', 'line': 1})
    quality = evaluate(facts, markdown=markdown)
    assert "no_dict_repr" in quality["failed_checks"]
    assert quality["publishability"] == "review_required"


def test_attributed_payload_and_source_literals_do_not_fail_the_format_gate():
    value = "攻击者可提交 x.<base64url({'sub':1,'role':'admin'})>.x 格式的 token"
    payload = bundle([{**finding('f1', summary="示例：{'path': 'file.php'}", verifications=[verification('v1')]),
                       'preconditions': [value]}])
    facts, markdown = render(payload)
    assert value in markdown
    assert 'no_dict_repr' not in facts['quality_result']['failed_checks']
    # A real unattributed dump remains a defect even if a legitimate literal exists.
    assert 'no_dict_repr' in evaluate(facts, markdown + "\n" + str({'raw_records': 900, 'unread': 4}))['failed_checks']


def test_rendered_counts_must_match_the_facts():
    payload = bundle([accepted("f1")])
    facts, markdown = render(payload)
    assert "rendered_counts_match_facts" not in facts["quality_result"]["failed_checks"]
    tampered = markdown.replace("- 已接受漏洞：1", "- 已接受漏洞：9")
    quality = evaluate(facts, markdown=tampered)
    assert "rendered_counts_match_facts" in quality["failed_checks"]
    assert quality["publishability"] == "review_required"


def test_narrative_cannot_claim_more_accepted_findings_than_the_facts():
    payload = bundle([accepted("f1")])
    payload["report_narrative"] = {"header": "本次共确认 7 个漏洞。"}
    facts, _ = render(payload)
    assert "narrative_within_facts" in facts["quality_result"]["failed_checks"]
    assert facts["quality_result"]["publishability"] == "review_required"


def test_uncertain_run_still_renders_a_complete_stage_report():
    payload = bundle([accepted("f1"), finding("f2", verifications=[verification("v2")])],
                     status="inconclusive")
    facts, markdown = render(payload)
    quality = facts["quality_result"]
    assert quality["report_kind"] == "stage"
    assert quality["publishability"] == "releasable_partial"
    for title in SECTION_TITLES:
        assert f"## {title}" in markdown
    assert "已接受漏洞：1" in markdown
    assert "待终审：1" in markdown
    assert "阶段报告" in markdown


def test_quality_statistics_are_recomputable_from_the_bundle_alone():
    payload = bundle([accepted("f1"), finding("f2", verifications=[verification("v2")])])
    facts = build_final_review(payload, all_records=payload["findings"],
                               repository=FakeRepository(), generated_at="t")
    quality = facts["quality_result"]
    assert quality["statistics"]["canonical"] == len(facts["canonical_findings"])
    assert quality["statistics"]["reviews"] == len(facts["reviews"])
    assert quality["recomputed"]["dispositions"] == {"accepted": 1, "pending": 1, "contested": 0}
    # Same input, same package hash: assembly is deterministic.
    again = build_final_review(payload, all_records=payload["findings"],
                               repository=FakeRepository(), generated_at="t")
    assert again["provenance"]["input_hash"] == facts["provenance"]["input_hash"]
    assert json.dumps(facts, sort_keys=True, default=str) == json.dumps(again, sort_keys=True, default=str)


def test_review_batch_requires_exactly_one_decision_per_item():
    payload = bundle([accepted("f1"), finding("f2", verifications=[verification("v2")])])
    facts = build_final_review(payload, all_records=payload["findings"])
    batch = facts["review_batch"]
    items = batch["item_refs"]
    assert [item["item_id"] for item in items] == [entry["canonical_id"]
                                                   for entry in facts["canonical_findings"]]

    decisions = [
        {"item_id": items[0]["item_id"], "revision": items[0]["revision"], "decision": "keep"},
    ]
    accepted_items, errors = final_review.apply_review_batch(batch, decisions)
    assert accepted_items and any(error.startswith("missing_decisions:") for error in errors)

    duplicates = decisions + decisions
    _, errors = final_review.apply_review_batch(batch, duplicates)
    assert any(error.startswith("duplicate_decision:") for error in errors)

    unknown = decisions + [{"item_id": "does-not-exist", "decision": "keep"}]
    _, errors = final_review.apply_review_batch(batch, unknown)
    assert "unknown_item:does-not-exist" in errors

    stale = [{"item_id": items[0]["item_id"], "revision": 99, "decision": "keep"}]
    _, errors = final_review.apply_review_batch(batch, stale)
    assert any(error.startswith("stale_revision:") for error in errors)

    without_rationale = [{"item_id": items[0]["item_id"], "decision": "withdraw"}]
    _, errors = final_review.apply_review_batch(batch, without_rationale)
    assert any(error.startswith("missing_rationale:") for error in errors)


def test_rendered_report_has_no_python_container_text():
    payload = bundle([accepted("f1")])
    facts, markdown = render(payload)
    assert "{" not in markdown
    assert render_final_report(facts).startswith("# 源码审计")
