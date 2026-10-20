"""The project-mode report: the Planner's prose beside host-rendered verification facts.

Two different kinds of statement now share the report. The Planner writes the narrative
around what the host already established; the host writes the counts, the job ids and the
verification status. The tests below pin the boundary: a narrative never becomes evidence,
an automatic record is never presented as a human verdict, and an unverified finding is
never allowed to read like a finding that was excluded.
"""
import json

from audit.metrics import summarise
from audit.report import collect_evidence, render_json, render_markdown

RUN = {
    "id": "p" * 32,
    "snapshot_id": "s" * 32,
    "snapshot_name": "dvwa.zip",
    "scope": ["vuln.php"],
    "prompt_id": "P0",
    "prompt_label": "P0 初始版",
    "prompt_text": "# 一、审计角色\n\n四段式提示词全文。",
    "model": "test-model",
    "budgets": {"responses": 8, "tools": 16, "seconds": 300},
    "status": "completed",
    "created_at": "2026-01-01T00:00:00+00:00",
    "started_at": "2026-01-01T00:00:00+00:00",
    "finished_at": "2026-01-01T00:10:00+00:00",
    "error": None,
    "usage": {"requests": 12, "tool_calls": 9, "input_tokens": 1000, "output_tokens": 200},
    "project_id": "proj-1",
    "project_mode": "project",
    "poc_policy": {"target": "dvwa", "job_seconds": 30, "max_jobs": 8},
    "task_spec": {
        "objective": "审计 DVWA 的注入面。",
        "success_criteria": "保存一条带原始行号的注入结论。",
        "max_iterations": 2,
        "max_total_attempts": 8,
        "max_workers": 2,
        "max_planner_rounds": 3,
        "stop_on_achieved": True,
        "require_poc": True,
    },
}

TRUTHS = [{
    "file_path": "vuln.php", "category": "sqli", "vulnerable": True,
    "independently_verified": True, "verification_basis": "人工验证：注入返回 5 行",
}]


def unit(unit_id="u1", file_path="vuln.php"):
    return {
        "unit_id": unit_id, "file_path": file_path, "symbol": "<top-level>",
        "status": "completed", "error": None, "result": {"conclusions": {}},
        "seen": [], "start_line": 1, "end_line": 10,
    }


def task_finding(**over):
    base = {
        "id": "f1", "unit_id": "u1", "file_path": "vuln.php", "symbol": "<top-level>",
        "fingerprint": "fp-sqli", "category": "task_goal", "finding_kind": "vulnerability",
        "title": "SQL 注入 · vuln.php", "severity": "high",
        "summary": "输入直接拼接进查询。",
        "evidence": [{"path": "vuln.php", "start_line": 3, "end_line": 5}],
        "input_source": "$_GET['id']", "propagation": "→ $query",
        "dangerous_operation": "mysqli_query", "protection": "无", "preconditions": [],
        "missing_context": [], "poc": None, "remediation": "改用参数绑定。",
        "validation_state": "candidate", "validation_errors": [], "disposition": "open",
        "verdict": None, "verifications": [],
        "verification_status": "unverified", "verification_verdict": None,
    }
    base.update(over)
    return base


def automatic(**over):
    base = {
        "id": "v1", "source": "poc_agent", "status": "verified", "verdict": "confirmed",
        "created_at": "2026-01-01T00:05:00+00:00",
        "notes": "攻击侧返回 5 行，正常侧 1 行。",
        "command": "php poc.php 1' OR '1'='1",
        "attack_observation": "5 行",
        "normal_observation": "1 行",
        "target": {"name": "dvwa", "security": "low", "version": "2.5"},
        "agent": {"jobs": ["job-abc"], "policy": {"job_seconds": 30}},
        "artifacts": [],
        "files": [],
    }
    base.update(over)
    return base


def bundle(findings=(), *, narrative=None, carried=None, jobs=None):
    findings = list(findings)
    made = {
        "run": RUN,
        "units": [unit()],
        "findings": findings,
        "attributions": [],
        "metrics": summarise(RUN, [unit()], findings, TRUTHS),
        "snapshot": {"id": RUN["snapshot_id"], "name": "dvwa.zip", "files": [], "warnings": []},
        "truths": TRUTHS,
        "prompts": [],
        "rounds": {},
        "generated_at": "2026-01-01T00:10:00+00:00",
        "version": "test",
        # Presence of a planner session is what routes the bundle to the project layout.
        "planner": {"max_rounds": 3},
        "plans": [],
        "tasks": [],
        "project_map": {"stats": {}},
        "report_narrative": narrative or {},
        "carried_findings": carried or [],
        "verification_jobs": jobs or [],
    }
    return made


def test_the_narrative_leads_the_report_and_is_attributed_to_the_planner():
    narrative = {
        "summary": "确认一条 SQL 注入并在隔离靶场复现。",
        "conclusion": "vuln.php 的 id 参数仍可注入。",
        "limitations": ["XSS 面未覆盖。"],
    }
    doc = render_markdown(bundle([task_finding(verification_status="verified")], narrative=narrative))

    assert doc.index("## 结论摘要") < doc.index("## 1. 目标与判定边界")
    assert "以下叙述由 Planner 生成" in doc
    assert "确认一条 SQL 注入并在隔离靶场复现。" in doc
    assert "**Planner 结论**" in doc
    assert "vuln.php 的 id 参数仍可注入。" in doc
    assert "**Planner 声明的限制**" in doc
    assert "- XSS 面未覆盖。" in doc


def test_a_run_without_a_narrative_says_the_host_rendered_it_alone():
    doc = render_markdown(bundle([task_finding()]))
    assert "## 结论摘要" not in doc
    assert "本次运行未产出 Planner 叙述" in doc


def test_an_automatic_record_is_rendered_as_facts_not_as_a_human_verdict():
    finding = task_finding(
        verification_status="verified", verification_verdict="confirmed",
        verifications=[automatic()],
    )
    doc = render_markdown(bundle([finding]))

    assert "- 自动验证结论：已验证（confirmed）" in doc
    assert "**自动验证记录**" in doc
    assert "job-abc" in doc and "dvwa" in doc and "low" in doc
    assert "第 1 条自动验证记录的补充说明：" in doc
    assert "**人工验证记录**" not in doc
    assert "人工复核记录" not in doc


def test_a_historical_human_record_is_kept_read_only_under_its_own_label():
    legacy = {
        "id": "h1", "created_at": "2026-01-01T00:01:00+00:00",
        "execution_status": "success", "verdict": "confirmed",
        "command": "手工 curl", "normal_observation": "1 行", "attack_observation": "5 行",
        "files": [], "notes": "历史上人工确认。",
    }
    finding = task_finding(verification_status="unverified", verifications=[legacy])
    doc = render_markdown(bundle([finding]))
    assert "**历史人工记录（只读）**" in doc
    assert "第 1 条历史记录的补充说明：" in doc
    # The read-only record does not become the finding's current status.
    assert "- 自动验证结论：未自动验证" in doc


def test_unverified_is_stated_as_not_checked_rather_than_excluded():
    finding = task_finding(verification_status="unverified")
    doc = render_markdown(bundle([finding]))
    assert "**未验证与验证未通过的发现**" in doc
    assert "未验证不等于排除" in doc
    assert "| SQL 注入 · vuln.php |" in doc


def test_carried_project_findings_are_not_counted_as_new_discoveries():
    carried = [
        {
            "id": "pf1", "title": "命令注入 · exec.php", "file_path": "exec.php",
            "symbol": "run", "severity": "critical", "revision": 2,
            "verification_status": "verified", "verification_verdict": "confirmed",
            "origin_run_id": "r" * 32, "discovered_at": "2025-12-01T00:00:00+00:00",
        },
        {
            "id": "pf2", "title": "反射型 XSS · low.php", "file_path": "low.php",
            "symbol": "<project>", "severity": "low", "revision": 3,
            "verification_status": "inconclusive", "verification_verdict": "uncertain",
            "origin_run_id": "r" * 32, "discovered_at": "2025-12-01T00:00:00+00:00",
        },
    ]
    doc = render_markdown(bundle([task_finding(verification_status="verified")], carried=carried))
    section = doc.split("### 项目既有发现（沿用）", 1)[1].split("### ", 1)[0]
    assert "exec.php:run" in section and "已验证（confirmed）" in section
    assert "不计入本次的新发现" in section
    assert "r" * 32 in section
    # The Planner's sentinel symbol is an internal key, not a source location.
    assert "<project>" not in section
    assert "| low.php |" in section


def test_json_export_carries_the_frozen_policy_narrative_and_per_finding_verification():
    narrative = {"summary": "摘要", "conclusion": "结论", "limitations": []}
    finding = task_finding(
        verification_status="verified", verification_verdict="confirmed",
        verifications=[automatic()],
    )
    value = json.loads(render_json(bundle([finding], narrative=narrative)))
    assert value["verification_policy"] == RUN["poc_policy"]
    assert value["report_narrative"]["summary"] == "摘要"
    assert value["findings"][0]["verification"] == {
        "status": "verified",
        "verdict": "confirmed",
        "records": [json.loads(json.dumps(automatic(), default=str))],
    }
    assert value["carried_findings"] == []


def test_the_evidence_archive_carries_a_runner_manifest_per_automatic_record(tmp_path):
    job = {
        "id": 1, "verification_id": "v1", "finding_id": "f1", "run_id": RUN["id"],
        "job_id": "job-abc", "kind": "script",
        "request": {"language": "php", "script_sha256": "d" * 64},
        "result": {"status": "ok", "exit_code": 0, "duration_ms": 120},
        "exit_code": 0, "duration_ms": 120, "created_at": "2026-01-01T00:05:00+00:00",
    }
    finding = task_finding(
        verification_status="verified", verification_verdict="confirmed",
        verifications=[automatic()],
    )
    files = dict(collect_evidence(bundle([finding], jobs=[job]), tmp_path))
    manifest = json.loads(files["v1-runner-manifest.json"])
    assert manifest["schema"] == "poc-runner-manifest/v1"
    assert manifest["target"]["security"] == "low"
    assert manifest["jobs"][0]["job_id"] == "job-abc"
    assert manifest["jobs"][0]["exit_code"] == 0
