"""Replay Worker publication failures without model calls or a live project library."""
from __future__ import annotations

import asyncio
import copy
import json

import pytest

from audit import agent
from audit.runtime import AgentPolicy
from audit.schemas import GoalAssessment
from tests.code_model import ModelFactory, code
from test_worker_strategies import CONFIG, UNIT, Repository, assessment, finding


def drive(monkeypatch, script, *, policy=None, responses=8):
    factory = ModelFactory(script)
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []
    result = asyncio.run(agent.pursue_task_work(
        repository=Repository(), snapshot_id="snapshot", snapshot_name="offline.zip", unit=UNIT,
        task={"objective": "检查输入输出边界与可达漏洞", "success_criteria": "引用已读源码证据", "require_poc": False},
        attempt=1, config=CONFIG, budgets={"responses": responses, "tools": 0, "seconds": 8},
        policy=policy or AgentPolicy(worker_explore_responses=0, request_seconds=1), on_event=events.append,
    ))
    return result, events, factory


def test_publication_schema_requires_live_coordinates_without_rewriting_history_contract():
    schema = agent._worker_publication_schema(2)
    fields = schema["$defs"]["TaskFinding"]
    assert {"vulnerability_type", "primary_location"} <= set(fields["required"])
    assert fields["properties"]["vulnerability_type"]["enum"]
    assert fields["properties"]["primary_location"] == {"$ref": "#/$defs/PrimaryLocation"}
    assert schema["properties"]["findings"]["maxItems"] == 2
    historical = GoalAssessment.model_json_schema()["$defs"]["TaskFinding"]
    assert "vulnerability_type" not in historical["required"]
    assert "primary_location" not in historical["required"]


def test_exploration_is_followed_by_small_json_publication_and_bounded_corrections(monkeypatch):
    payload = assessment()
    result, events, factory = drive(monkeypatch, {
        "task_execute": [code("print('已读源码，交回有依据的结论')")],
        "task_publish": ['{"outcome":', json.dumps(assessment(vulnerability_type="misspelled-class")), json.dumps(payload)],
    }, policy=AgentPolicy(worker_explore_responses=1, request_seconds=1))
    assert result["outcome"] == "achieved", result
    assert factory.phases == ["task_execute", "task_publish", "task_publish", "task_publish"]
    assert result["usage"]["requests"] == 4
    assert result["usage"]["corrections"] == 2
    assert not [row for row in events if row["kind"] == "agent_code" and row["phase"] == "task_publish"]
    assert result["result"]["findings"][0]["vulnerability_type"] == "xss_r"
    assert all(params["stop_sequences"] is None for params, phase in zip(factory.built().params, factory.phases) if phase == "task_publish")
    assert all(row["request_parameters"]["thinking"] == "disabled" for row in events
               if row["kind"] == "model_response" and row["phase"] == "task_publish")


def test_intermediate_python_assembly_cannot_reset_json_publication_limit(monkeypatch):
    # The real failure alternated truncated responses with successful assignments.
    # Publishing now has no interpreter, so these cannot reset its correction cap.
    result, events, factory = drive(monkeypatch, {"task_publish": [
        "<code>values = []</code>", "<code>print('building a result')</code>", "<code>values.append({})</code>",
    ]})
    assert factory.phases == ["task_publish"] * 3
    assert result["outcome"] == "continue", result
    assert result["terminal_reason"] == "invalid_output"
    assert result["usage"]["requests"] == 3
    assert result["result"]["findings"] == []
    assert result["result"]["missing_context"] == []
    assert not [row for row in events if row["kind"] == "agent_code"]


def test_history_capacity_failure_is_not_reported_as_missing_source(monkeypatch):
    result, events, factory = drive(monkeypatch, {}, policy=AgentPolicy(worker_explore_responses=0, history_bytes=1))
    assert result["outcome"] == "continue"
    assert result["terminal_reason"] == "context_limit"
    assert result["result"]["missing_context"] == []
    assert "并非源码缺失" in result["result"]["next_focus"]
    assert result["usage"]["requests"] == 0
    assert not [row for row in events if row["kind"] == "model_request"]


def test_remaining_directions_survive_a_successful_batch(monkeypatch):
    payload = assessment()
    payload["remaining_work"] = ["src/b.php 中的对象归属检查尚未完成，需要补读该入口的权限条件。"]
    result, events, _ = drive(monkeypatch, {"task_publish": [json.dumps(payload)]})
    assert result["outcome"] == "achieved"
    assert result["result"]["remaining_work"] == payload["remaining_work"]
    assert "src/b.php" in result["result"]["next_focus"]
    assert len(result["result"]["findings"]) == 1
    assert next(row for row in events if row["kind"] == "task_assessment")["remaining_work"] == payload["remaining_work"]


def test_large_batch_is_rejected_then_small_batch_retains_pending_work(monkeypatch):
    large = assessment()
    large["findings"] = [finding(title=f"输入未经转义输出的独立位置{index}") for index in range(3)]
    small = copy.deepcopy(large)
    small["findings"] = small["findings"][:2]
    small["remaining_work"] = ["第三个不同输出位置尚未提交，需要沿其输入路径继续核对后保存。"]
    result, events, _ = drive(monkeypatch, {"task_publish": [json.dumps(large), json.dumps(small)]})
    assert result["outcome"] == "achieved", result
    assert result["usage"]["requests"] == 2
    assert len(result["result"]["findings"]) == 2
    assert result["result"]["remaining_work"] == small["remaining_work"]
    assert any("最多提交 2" in row.get("hint", "") for row in events)


@pytest.mark.parametrize("invalid", [
    {"vulnerability_type": None},
    {"vulnerability_type": "misspelled-class"},
    {"primary_location": None},
    {"vulnerability_type": "unknown", "classification_reason": ""},
])
def test_normal_worker_requires_explicit_classification_and_evidence_coordinate(monkeypatch, invalid):
    result, _, factory = drive(monkeypatch, {"task_publish": [json.dumps(assessment(**invalid)), json.dumps(assessment())]})
    assert result["outcome"] == "achieved", result
    assert result["usage"]["requests"] == 2
    assert factory.phases == ["task_publish"] * 2


def test_publication_corrections_do_not_add_to_total_request_budget(monkeypatch):
    result, _, factory = drive(monkeypatch, {"task_publish": ["{"]}, responses=1)
    assert result["usage"]["requests"] == 1
    assert len(factory.built().requests) == 1
    assert result["result"]["findings"] == []
