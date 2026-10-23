"""Vulnerability results, historical observations and exports share one boundary."""
from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from audit.app import _run_bundle
from audit.finding_policy import is_vulnerability_finding, source_observations
from audit.report import collect_evidence, render_json, render_markdown


def finding(**changes):
    record = {
        "id": "vulnerability-1", "run_id": "run-1", "unit_id": "task-1",
        "fingerprint": "unique-1", "category": "task_goal", "finding_kind": "vulnerability",
        "title": "上传后可执行用户控制的脚本", "severity": "low",
        "summary": "已读取的入口将用户提供的脚本写入可执行目录，缺少文件类型限制。",
        "evidence": [{"path": "src/upload.php", "start_line": 3, "end_line": 8}],
        "validation_state": "candidate", "validation_errors": [],
        "preconditions": [], "verdict": None, "verifications": [],
        "file_path": "src/upload.php", "symbol": "upload", "poc": None,
    }
    return {**record, **changes}


def observation(**changes):
    return finding(
        id="historical-observation", fingerprint="observation-fp",
        finding_kind="security_boundary", severity="informational",
        title="特定上传路径具有类型检查",
        summary="本次读取的分支在写文件前检查扩展名；这一局部事实不代表整个项目安全。",
        verdict="confirmed", verifications=[{
            "id": "review-1", "notes": "旧人工复核原文仍保留。",
            "verdict": "confirmed", "files": [{"stored": "review-1-proof.txt"}],
        }], **changes,
    )


def task():
    return {
        "id": "task-2", "run_id": "run-1", "task_key": "upload-boundary",
        "state": "completed", "title": "检查另一条上传路径", "attempts": 1,
        "attempt_history": [{"attempt": 1, "result": {
            "outcome": "no_evidence", "observations": [{
                "kind": "security_boundary", "title": "另一分支拒绝可执行后缀",
                "summary": "已经读取的检查分支拒绝脚本后缀，未在本方向证实漏洞。",
                "evidence": "modules/upload.module:9-14",
            }],
        }}],
    }


@pytest.mark.parametrize("kind", ["source_observation", "data_flow", "security_boundary", "unknown"])
def test_explicit_observations_never_become_vulnerabilities_even_with_high_severity(kind):
    assert not is_vulnerability_finding(finding(finding_kind=kind, severity="high"))


@pytest.mark.parametrize("severity", [None, "informational", "unknown"])
def test_unrated_explicit_vulnerabilities_are_not_observations(severity):
    assert is_vulnerability_finding(finding(severity=severity))


def test_low_risk_and_historical_fixed_category_vulnerabilities_are_retained():
    assert is_vulnerability_finding(finding(severity="low"))
    assert is_vulnerability_finding({"category": "sqli"})
    assert not is_vulnerability_finding({"category": "task_goal"})
    assert not is_vulnerability_finding(finding(category="sqli", finding_kind="data_flow"))


def test_observations_project_saved_attempts_with_stable_ids_and_source_ranges():
    original = observation()
    tasks = [task()]
    records = source_observations([finding(), original], tasks)
    assert records[0] is original
    assert records[0]["verifications"][0]["notes"] == "旧人工复核原文仍保留。"
    assert records[1]["evidence"] == [{"path": "modules/upload.module", "start_line": 9, "end_line": 14}]
    assert records[1]["file_path"] == "modules/upload.module"
    assert records[1]["id"] == source_observations([], tasks)[0]["id"]
    assert records[1]["validation_state"] == "observation"
    assert tasks[0]["attempt_history"][0]["result"]["outcome"] == "no_evidence"


@pytest.mark.parametrize("planner", [False, True])
def test_run_api_splits_historical_and_new_observations_without_changing_saved_records(planner):
    saved = [finding(), observation()]
    before = deepcopy(saved)
    run = {
        "id": "run-1", "snapshot_id": "snapshot-1", "task_spec": {"objective": "审计文件上传漏洞"},
        "status": "completed", "scope": [],
    }
    store = SimpleNamespace(
        get_run=lambda _: run, list_findings=lambda _: saved, list_truths=lambda _: [],
        get_planner_session=lambda _: {"session_id": "planner-1"} if planner else None,
        list_tasks=lambda _: [task()], get_task_goal=lambda _: {"status": "met"},
        get_project_map=lambda _: {}, list_plans=lambda _: [],
        list_planner_observations=lambda _: [], investigation_overview=lambda _: {},
        list_run_units=lambda _: [], list_task_work_items=lambda _: [task()],
        list_task_goals=lambda _: [{"status": "met"}], list_attributions=lambda _: [],
    )
    bundle = _run_bundle(SimpleNamespace(store=store), "run-1")
    assert [f["id"] for f in bundle["findings"]] == ["vulnerability-1"]
    assert len(bundle["source_observations"]) == 2
    assert bundle["metrics"]["candidate_findings"] == 1
    assert bundle["metrics"]["confirmed"] == 0
    assert bundle["metrics"]["source_observations"] == 2
    assert bundle["run"]["status"] == "completed"
    assert saved == before


def test_report_and_evidence_preserve_historical_reviews_outside_vulnerability_results(tmp_path):
    old = observation()
    bundle = {
        "run": {
            "id": "run-1", "snapshot_name": "project.zip", "snapshot_id": "snapshot-1",
            "model": "mock", "status": "completed", "scope": [], "budgets": {},
            "task_spec": {"objective": "审计文件上传漏洞", "success_criteria": "发现有证据的漏洞"},
        },
        "planner": {}, "goals": [{"status": "met"}], "tasks": [task()],
        "findings": [old], "metrics": {},
    }
    exported = json.loads(render_json(bundle))
    assert exported["findings"] == []
    assert len(exported["source_observations"]) == 2
    # Re-exporting an API projection must not duplicate attempt observations.
    assert len(json.loads(render_json(exported))["source_observations"]) == 2
    markdown = render_markdown(bundle)
    assert "证据校验通过的发现：0" in markdown
    assert "排查记录（不计入漏洞）" in markdown
    assert "本历史运行沿用原有达标状态" in markdown
    assert "旧人工复核原文仍保留。" in markdown
    assert "modules/upload.module:9-14" in markdown
    (tmp_path / "review-1-proof.txt").write_text("historical evidence")
    assert collect_evidence(bundle, tmp_path) == [("review-1-proof.txt", b"historical evidence")]
