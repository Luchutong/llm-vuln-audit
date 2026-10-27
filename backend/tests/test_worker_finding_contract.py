"""Root-cause output requirements apply at the live boundary, not history loading."""
import hashlib

import pytest
from pydantic import ValidationError

from audit.schemas import GoalAssessment, TaskFinding, TaskSpec
from audit.worker import AuditWorker
from audit.worker_strategies import (
    ROOT_CAUSE_TYPES,
    builtin_worker_strategies,
    validate_worker_classification,
    worker_classification_contract,
)


def finding(**changes):
    return {
        "title": "Request reaches a dangerous operation", "kind": "vulnerability",
        "summary": "The displayed source passes attacker input into the sensitive operation.",
        "evidence": "src/entry.php:12-14", **changes,
    }


@pytest.mark.parametrize("cause", [value for value in ROOT_CAUSE_TYPES if value not in {"unknown", "other"}])
def test_every_known_root_cause_is_accepted_explicitly(cause):
    item = TaskFinding.model_validate(finding(vulnerability_type=cause))
    assert validate_worker_classification(item.model_dump()) == (cause, [])


@pytest.mark.parametrize("cause,canonical", [
    ("SQL injection", "sqli"), ("命令注入", "command_injection"),
    (" reflected_xss ", "xss_r"), ("STORED_XSS", "xss_s"),
])
def test_only_deterministic_existing_aliases_are_normalized(cause, canonical):
    item = TaskFinding.model_validate(finding(vulnerability_type=cause))
    assert item.vulnerability_type == canonical
    assert validate_worker_classification(item.model_dump()) == (canonical, [])


@pytest.mark.parametrize("cause", [None, "", " \n", 7, False, ["sqli"], {"type": "sqli"}])
def test_missing_or_non_string_classification_cannot_use_title_to_guess(cause):
    canonical, errors = validate_worker_classification(finding(
        title="SQL injection in request processing", vulnerability_type=cause,
    ))
    assert canonical is None and errors
    assert "必须提供 vulnerability_type" in errors[0]


@pytest.mark.parametrize("cause", ["rce_because_impact", "unexpected-root", "file_inclusion_unspecified"])
def test_unknown_labels_survive_parsing_and_are_rejected_instead_of_silently_becoming_unknown(cause):
    item = TaskFinding.model_validate(finding(
        vulnerability_type=cause, classification_reason="A deliberately unsupported class must not become unknown.",
    ))
    assert item.vulnerability_type == cause
    canonical, errors = validate_worker_classification(item.model_dump())
    assert canonical is None and "不在支持的根因分类" in errors[0]


@pytest.mark.parametrize("cause", ["unknown", "other"])
@pytest.mark.parametrize("reason", [None, "", "unknown", "待补充", "?", "........", "不确定"])
def test_uncertain_or_unlisted_types_require_a_concrete_reason(cause, reason):
    canonical, errors = validate_worker_classification(finding(
        vulnerability_type=cause, classification_reason=reason,
    ))
    assert canonical is None and errors and "classification_reason" in errors[0]


@pytest.mark.parametrize("cause,reason", [
    ("unknown", "缺少鉴权辅助函数源码，无法区分对象授权缺失与认证绕过。"),
    ("other", "请求日志保留策略泄露了跨租户元数据，该已确认根因不属于现有分类。"),
])
def test_explicit_unknown_and_other_are_allowed_with_a_specific_reason(cause, reason):
    item = TaskFinding.model_validate(finding(vulnerability_type=cause, classification_reason=reason))
    assert validate_worker_classification(item.model_dump()) == (cause, [])


def test_classification_does_not_infer_lfi_rfi_or_command_execution_from_consequences():
    for cause in ("lfi", "rfi", "command_injection", "code_execution", "path_traversal"):
        item = finding(vulnerability_type=cause, title="Remote code execution through file input")
        assert validate_worker_classification(item) == (cause, [])


def test_history_with_omitted_fields_remains_loadable_but_needs_live_correction():
    historical = TaskFinding.model_validate(finding())
    assert historical.vulnerability_type is None
    assert historical.classification_reason == ""
    assert historical.primary_location is None
    canonical, errors = validate_worker_classification(historical.model_dump())
    assert canonical is None and errors
    explicit_old_unknown = TaskFinding.model_validate(finding(vulnerability_type="unknown"))
    assert explicit_old_unknown.vulnerability_type == "unknown"


def test_classification_reason_is_bounded_without_making_it_mandatory_for_history():
    with pytest.raises(ValidationError):
        TaskFinding.model_validate(finding(classification_reason="x" * 1201))


def test_shared_contract_is_independent_of_strategy_and_has_no_benchmark_answers():
    contract = worker_classification_contract()
    assert all(cause in contract for cause in ROOT_CAUSE_TYPES)
    assert "primary_location" in contract and "classification_reason" in contract
    assert "unknown" in contract and "other" in contract
    assert "不从标题" in contract and "实际读取" in contract
    assert "Lab30" not in contract and "TP" not in contract
    records = {row["id"]: row for row in builtin_worker_strategies()}
    baseline = "识别当前任务中由源码支持的可操作漏洞，说明影响，并准确指出根因或危险操作的位置。"
    assert records["worker-w0-v1"]["text"] == baseline
    assert records["worker-w1-v1"]["text"] == baseline + "逐项核对攻击者输入来源、传播路径、关键操作及已有防护；说明防护是否覆盖当前输入路径，不能只凭函数名称判断。"
    assert len({hashlib.sha256(row["text"].encode()).hexdigest() for row in records.values()}) == 5


def test_new_test_can_opt_out_of_project_baseline_without_changing_legacy_defaults():
    values = {"objective": "Audit the complete uploaded source", "success_criteria": "Find evidence-backed vulnerabilities"}
    assert TaskSpec.model_validate(values).baseline_policy == "inherit"
    assert TaskSpec.model_validate({**values, "baseline_policy": "fresh"}).baseline_policy == "fresh"
    with pytest.raises(ValidationError):
        TaskSpec.model_validate({**values, "baseline_policy": "reset-project"})


def test_bounded_remaining_work_can_accompany_a_small_batch_of_findings():
    payload = {
        "outcome": "achieved", "summary": "A first batch has valid findings.",
        "reasoning": "More request entry points need a separate bounded pass.",
        "findings": [finding(vulnerability_type="command_injection")],
        "remaining_work": ["src/admin.php: inspect authorization before state changes"],
    }
    result = GoalAssessment.model_validate(payload)
    assert result.remaining_work == payload["remaining_work"]
    assert GoalAssessment.model_validate({key: value for key, value in payload.items() if key != "remaining_work"}).remaining_work == []
    with pytest.raises(ValidationError):
        GoalAssessment.model_validate({**payload, "remaining_work": ["src/admin.php"] * 9})
    for direction in ("", "待补充", "x" * 1601):
        with pytest.raises(ValidationError):
            GoalAssessment.model_validate({**payload, "remaining_work": [direction]})


class PersistenceRepository:
    def get_snapshot(self, snapshot_id):
        return {"files": [{"path": "src/entry.php", "line_count": 40}]}


PERSISTENCE_UNIT = {
    "unit_id": "u1", "file_path": "src/entry.php", "symbol": "handle",
    "start_line": 1, "end_line": 40,
}


def prepare_finding_for_persistence(payload, *, marker="run"):
    worker = AuditWorker.__new__(AuditWorker)
    worker.repository = PersistenceRepository()
    run = {"id": "run", "snapshot_id": "snapshot"}
    result = {"findings": [payload]}
    if marker == "run":
        run["agent_policy"] = {"worker_publication_findings": 2}
    elif marker == "result":
        result["agent_policy"] = {"worker_publication_findings": 2}
    elif marker == "strategy":
        run["worker_strategy"] = builtin_worker_strategies()[0]
    outcome = {
        "result": result, "seen_exact": True,
        "seen": [{"path": "src/entry.php", "start_line": 12, "end_line": 14}],
    }
    return worker._build_goal_findings(run, PERSISTENCE_UNIT, outcome)[0]


@pytest.mark.parametrize("marker", ["run", "result", "strategy"])
@pytest.mark.parametrize("changes,expected", [
    ({"vulnerability_type": None}, "vulnerability_type"),
    ({"vulnerability_type": "misspelled-root"}, "不在支持的根因分类"),
    ({"vulnerability_type": "unknown", "classification_reason": ""}, "classification_reason"),
    ({"vulnerability_type": "other", "classification_reason": "待补充"}, "classification_reason"),
    ({"primary_location": None}, "primary_location"),
    ({"primary_location": {"path": "src/entry.php", "line": 16}}, "never read"),
])
def test_new_worker_persistence_rechecks_classification_and_primary_location(marker, changes, expected):
    payload = finding(
        vulnerability_type="command_injection", primary_location={"path": "src/entry.php", "line": 13},
    )
    payload.update(changes)
    prepared = prepare_finding_for_persistence(payload, marker=marker)
    assert prepared["candidate"] is False
    assert prepared["record"]["validation_state"] != "candidate"
    assert expected in "; ".join(prepared["record"]["validation_errors"])


@pytest.mark.parametrize("marker", ["run", "result", "strategy"])
@pytest.mark.parametrize("cause,reason", [
    ("command_injection", ""),
    ("unknown", "缺少请求分发辅助函数，无法确定具体根因类别。"),
    ("other", "这是已确认的日志保留策略缺陷，不属于已有安全类型。"),
])
def test_new_worker_persistence_accepts_known_and_explicit_uncertain_classification(marker, cause, reason):
    payload = finding(vulnerability_type=cause, classification_reason=reason,
                      primary_location={"path": "src/entry.php", "line": 13})
    prepared = prepare_finding_for_persistence(payload, marker=marker)
    assert prepared["candidate"] is True
    assert prepared["record"]["validation_state"] == "candidate"
    assert prepared["record"]["vulnerability_type"] == cause
    assert prepared["record"]["primary_location"] == payload["primary_location"]
    assert prepared["record"]["category"].startswith("task_goal:v2:")


def test_unmarked_historical_outcome_keeps_legacy_optional_fields_and_slot():
    prepared = prepare_finding_for_persistence(finding(), marker="historical")
    assert prepared["candidate"] is True
    assert prepared["record"]["vulnerability_type"] is None
    assert prepared["record"]["category"] == "task_goal"


def test_resumed_old_run_persists_two_new_batches_without_overwriting_previous_findings(tmp_path):
    from contextlib import closing

    from audit.db import Store

    with closing(Store(tmp_path / "batch-history.sqlite")) as store:
        run = {
            "id": "run", "snapshot_id": "snapshot", "snapshot_name": "source.zip",
            "scope": ["src/entry.php"], "prompt_id": "old-custom-prompt", "prompt_label": "Old prompt",
            "prompt_text": "Audit source", "model": "offline-test",
            "budgets": {"responses": 8, "tools": 0, "seconds": 60},
            "created_at": "2026-10-01T00:00:00+00:00",
        }
        store.create_run(run, [{
            "id": "u1", "file_path": "src/entry.php", "symbol": "handle",
            "start_line": 1, "end_line": 40, "priority": 0,
        }])
        assert "worker_publication_findings" not in (store.get_run("run").get("agent_policy") or {})
        categories = []
        for line in (12, 14):
            payload = finding(title=f"Command input reaches distinct operation {line}",
                              vulnerability_type="command_injection", dangerous_operation=f"system($input_{line})",
                              primary_location={"path": "src/entry.php", "line": line})
            prepared = prepare_finding_for_persistence(payload, marker="result")
            assert prepared["candidate"]
            categories.append(prepared["record"]["category"])
            store.add_finding(prepared["record"])
        records = store.list_findings("run")
        assert len(set(categories)) == 2
        assert len(records) == 2 and all(item["revision"] == 1 for item in records)
        assert {item["primary_location"]["line"] for item in records} == {12, 14}
