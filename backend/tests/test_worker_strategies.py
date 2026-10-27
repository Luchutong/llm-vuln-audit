"""New strategy slots use the real code-action loop and source evidence gates."""
from __future__ import annotations

import asyncio
import hashlib

import pytest
from pydantic import ValidationError

from audit import agent
from audit.config import ModelConfig
from audit.project_findings import canonical_fingerprint, ledger_record, pick_merge_candidate
from audit.runtime import AgentPolicy
from audit.schemas import PrimaryLocation, TaskFinding
from audit.worker import AuditWorker
from audit.worker_strategies import (
    builtin_worker_strategies, canonical_vulnerability_type, freeze_worker_strategy,
    root_causes_compatible, validate_primary_location,
    worker_host_contract,
)
from tests.code_model import ModelFactory, final_answer


UNIT = {
    "unit_id": "u1", "file_path": "src/a.php", "symbol": "handle", "kind": "function",
    "start_line": 1, "end_line": 4, "slice_index": 1, "slice_count": 1,
    "cleaned_lines": [{"number": 1, "text": "<?php"}, {"number": 3, "text": "echo $_GET['x'];"}],
}
FILE_LINES = {"src/a.php": 4, "src/b.php": 6}
SEEN = [("src/a.php", 1, 1), ("src/a.php", 3, 3)]
EVIDENCE = [{"path": "src/a.php", "start_line": 3, "end_line": 3}]
CONFIG = ModelConfig(model="offline-test", base_url="https://example.invalid", api_key="test-key")


class Repository:
    def get_snapshot(self, snapshot_id):
        return {"files": [{"path": path, "line_count": lines} for path, lines in FILE_LINES.items()]}

    def build_context_bundle(self, snapshot_id, planner_task, allowed_paths, source_bytes):
        return {"excerpts": [{"path": "src/a.php", "start_line": 1, "end_line": 3,
                              "lines": UNIT["cleaned_lines"]}]}


def finding(**changes):
    result = {
        "title": "请求参数未经编码输出", "kind": "vulnerability", "severity": "medium",
        "summary": "请求参数在输出位置直接写入响应内容，导致脚本注入风险。",
        "evidence": "src/a.php:3-3", "vulnerability_type": "xss_r",
        "primary_location": {"path": "src/a.php", "line": 3},
        "dangerous_operation": "echo $_GET['x']",
    }
    return {**result, **changes}


def assessment(**changes):
    return {
        "outcome": "achieved", "summary": "当前源码存在未经编码输出的输入。",
        "reasoning": "已读取第三行直接将请求输入写入响应。", "findings": [finding(**changes)],
    }


def drive(monkeypatch, steps, strategy=None):
    factory = ModelFactory(steps)
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []
    outcome = asyncio.run(agent.pursue_task_work(
        repository=Repository(), snapshot_id="snapshot", snapshot_name="sample.zip", unit=UNIT,
        task={"objective": "检查源码中的可达漏洞", "success_criteria": "提供真实源码证据", "require_poc": False},
        attempt=1, config=CONFIG, budgets={"responses": 5, "tools": 0, "seconds": 3},
        policy=AgentPolicy(request_seconds=1), worker_strategy=strategy,
        on_event=events.append,
    ))
    return outcome, events, factory


def test_strategy_enters_real_worker_without_replacing_host_contract(monkeypatch):
    bound = []
    for strategy in builtin_worker_strategies():
        outcome, events, factory = drive(monkeypatch, [final_answer(assessment())], strategy)
        assert outcome["outcome"] == "achieved", outcome
        prompt = factory.prompts[0]
        assert strategy["text"] in prompt
        assert "不得执行脚本、请求网络" in prompt
        assert "primary_location" in prompt
        assert "CVSS" in prompt
        event = next(item for item in events if item["kind"] == "worker_strategy_bound")
        assert event["strategy_id"] == strategy["id"]
        assert event["strategy_sha256"] == hashlib.sha256(strategy["text"].encode()).hexdigest()
        assert event["host_contract_sha256"] == hashlib.sha256(worker_host_contract().encode()).hexdigest()
        bound.append(event)
    assert len({item["host_contract_sha256"] for item in bound}) == 1
    assert len({item["strategy_sha256"] for item in bound}) == 5


def test_strategy_rejects_missing_type_then_corrects_in_same_budget(monkeypatch):
    outcome, _, factory = drive(monkeypatch, [
        final_answer(assessment(vulnerability_type=None)), final_answer(assessment()),
    ], builtin_worker_strategies()[0])
    assert outcome["outcome"] == "achieved", outcome
    assert outcome["usage"]["requests"] == 2
    assert any("必须提供 vulnerability_type" in prompt for prompt in factory.prompts[1:])


def test_strategy_rejects_unread_main_location_then_corrects(monkeypatch):
    outcome, _, factory = drive(monkeypatch, [
        final_answer(assessment(primary_location={"path": "src/a.php", "line": 2})),
        final_answer(assessment()),
    ], builtin_worker_strategies()[1])
    assert outcome["outcome"] == "achieved", outcome
    assert any("never read" in prompt for prompt in factory.prompts[1:])


def test_legacy_worker_does_not_require_new_finding_fields(monkeypatch):
    outcome, events, _ = drive(monkeypatch, [final_answer(assessment(vulnerability_type=None, primary_location=None))])
    assert outcome["outcome"] == "achieved", outcome
    assert not any(item["kind"] == "worker_strategy_bound" for item in events)


def test_planner_task_passes_strategy_into_real_worker(monkeypatch):
    strategy = builtin_worker_strategies()[2]
    factory = ModelFactory([final_answer(assessment())])
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []
    outcome = asyncio.run(agent.pursue_planner_task(
        repository=Repository(), snapshot_id="snapshot", snapshot_name="sample.zip",
        planner_task={"id": "task", "task_key": "output", "title": "检查输出边界"},
        run_task={"objective": "检查输入输出路径", "require_poc": False},
        attempt=1, allowed_paths=None, config=CONFIG,
        budgets={"responses": 3, "tools": 0, "seconds": 3},
        worker_strategy=strategy, on_event=events.append,
    ))
    assert outcome["outcome"] == "achieved", outcome
    assert strategy["text"] in factory.prompts[0]
    assert next(event for event in events if event["kind"] == "worker_strategy_bound")["strategy_id"] == strategy["id"]


@pytest.mark.parametrize("location", [
    {"path": "src/a.php", "line": True}, {"path": "src/a.php", "line": "3"},
    {"path": "../src/a.php", "line": 3}, {"path": "/src/a.php", "line": 3},
    {"path": "src/./a.php", "line": 3}, {"path": "src\\a.php", "line": 3},
])
def test_primary_location_schema_rejects_invalid_coordinates(location):
    with pytest.raises(ValidationError):
        PrimaryLocation.model_validate(location)


@pytest.mark.parametrize("location", [
    {"path": "a.php", "line": 3}, {"path": "src/a.php", "line": 5},
    {"path": "src/a.php", "line": True}, {"path": "src/a.php", "line": 2},
    {"path": "src/b.php", "line": 3},
])
def test_primary_location_host_checks_snapshot_reads_and_evidence(location):
    coordinate, errors = validate_primary_location({"primary_location": location}, FILE_LINES, SEEN, EVIDENCE, required=True)
    assert coordinate is None and errors


def test_primary_location_must_be_in_this_findings_evidence():
    _, errors = validate_primary_location({"primary_location": {"path": "src/a.php", "line": 1}}, FILE_LINES, SEEN, EVIDENCE, required=True)
    assert errors and "evidence" in errors[0]


def test_aliases_are_deterministic_and_unknown_is_preserved():
    assert canonical_vulnerability_type("SQL injection") == "sqli"
    assert canonical_vulnerability_type("not-a-recognized-root") == "unknown"
    assert TaskFinding.model_validate(finding(vulnerability_type="reflected_xss")).vulnerability_type == "xss_r"
    assert root_causes_compatible(None, "sqli")
    assert not root_causes_compatible("sqli", "mass_assignment")


def test_known_different_causes_have_distinct_identity_and_never_fuzzy_merge():
    original = canonical_fingerprint("src/a.php", "handle", "same operation")
    assert original == canonical_fingerprint("src/a.php", "handle", "same operation", vulnerability_type=None)
    first = canonical_fingerprint("src/a.php", "handle", "same operation", vulnerability_type="sqli")
    second = canonical_fingerprint("src/a.php", "handle", "same operation", vulnerability_type="mass_assignment")
    assert first != second
    payload = {"file_path": "src/a.php", "symbol": "<project>", "dangerous_operation": "same operation", "evidence": EVIDENCE}
    assert pick_merge_candidate({**payload, "vulnerability_type": "sqli"}, [{**payload, "vulnerability_type": "mass_assignment"}]) is None
    assert pick_merge_candidate({**payload, "vulnerability_type": "sqli"}, [payload]) == payload


def test_worker_persistence_repeats_new_contract_and_carries_fields():
    worker = AuditWorker.__new__(AuditWorker)
    worker.repository = Repository()
    run = {"id": "run", "snapshot_id": "snapshot", "worker_strategy": builtin_worker_strategies()[0]}
    outcome = {"result": assessment(), "seen": [{"path": path, "start_line": start, "end_line": end} for path, start, end in SEEN], "seen_exact": True}
    prepared = worker._build_goal_findings(run, UNIT, outcome)[0]
    assert prepared["candidate"]
    for item in (prepared["record"], prepared["event"], ledger_record(prepared["record"])):
        assert item["vulnerability_type"] == "xss_r"
        assert item["primary_location"] == {"path": "src/a.php", "line": 3}
    bad = {**outcome, "result": assessment(primary_location=None)}
    assert not worker._build_goal_findings(run, UNIT, bad)[0]["candidate"]
    invalid = {**outcome, "result": assessment(vulnerability_type=None)}
    assert not worker._build_goal_findings(run, UNIT, invalid)[0]["candidate"]
    invalid_type = {**outcome, "result": assessment(vulnerability_type={"wrong": "sqli"})}
    assert not worker._build_goal_findings(run, UNIT, invalid_type)[0]["candidate"]


def test_different_root_causes_in_one_task_have_distinct_stable_run_slots():
    worker = AuditWorker.__new__(AuditWorker)
    worker.repository = Repository()
    run = {"id": "run", "snapshot_id": "snapshot", "worker_strategy": builtin_worker_strategies()[0]}
    common = {"seen": [{"path": path, "start_line": start, "end_line": end} for path, start, end in SEEN], "seen_exact": True}
    first = worker._build_goal_findings(run, UNIT, {**common, "result": assessment(vulnerability_type="sqli")})[0]
    second = worker._build_goal_findings(run, UNIT, {**common, "result": assessment(vulnerability_type="mass_assignment")})[0]
    assert first["record"]["category"] != second["record"]["category"]


def test_freezing_strategy_rejects_legacy_or_empty_text():
    with pytest.raises(ValueError):
        freeze_worker_strategy({"id": "old", "text": "legacy"})
    with pytest.raises(ValueError):
        freeze_worker_strategy({**builtin_worker_strategies()[0], "text": " "})
