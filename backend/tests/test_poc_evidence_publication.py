"""Evidence corrections publish JSON within the original allowance, without runner I/O."""
import asyncio
import copy
import json

import pytest

from audit import poc_agent
from audit.poc_agent import PocDeps, evidence_errors, host_check
from audit.schemas import PocVerificationResult
from tests.code_model import CONFIG, ModelFactory, final_answer, transcript


RAW_OUTPUT = 'NORMAL: one row\nMIDDLE: retained line\nATTACK: private "row"\n'


def experiment(kind="script"):
    channel = {"script": "stdout", "http": "body", "browser": "body_text"}[kind]
    result = {"status": "finished", channel: RAW_OUTPUT}
    if kind == "http":
        result.update(execution_status="finished", http_status=200, headers={})
    elif kind == "browser":
        result.update(available=True)
    job = {
        "job_id": "completed-job", "kind": kind, "context_id": "context-one",
        "identity": "alice", "precondition": {"ok": True}, "exit_code": 0,
        "result": result,
    }
    # No runner methods exist: either phase calling a runner would fail this test.
    deps = PocDeps(
        client=object(), target="lab30", finding={"id": "finding", "category": "sqli"},
        context_id="context-one", jobs=[job],
        policy={"max_steps": 8, "max_seconds": 10, "max_responses": 4},
        job_scripts={"completed-job": "print('paired experiment')"} if kind == "script" else {},
    )
    payload = {
        "status": "verified", "summary": "已确认攻击返回私有记录。", "jobs": ["completed-job"],
        "normal_observation": "正常侧返回一行。", "attack_observation": "攻击侧返回私有记录。",
        "normal_evidence": [{"job_id": "completed-job", "channel": channel, "excerpt": "NORMAL: one row"}],
        "attack_evidence": [{"job_id": "completed-job", "channel": channel, "excerpt": 'ATTACK: private "row"'}],
    }
    return deps, payload


def run_publication(monkeypatch, deps, payloads):
    factory = ModelFactory({
        "poc_execute": [final_answer("探索结束")],
        "poc_conclude": [json.dumps(item, ensure_ascii=False) for item in payloads],
    })
    monkeypatch.setattr(poc_agent, "build_code_model", factory)
    events = []
    result, reason = asyncio.run(poc_agent.run_poc_agent(
        finding=deps.finding, deps=deps, config=CONFIG, on_event=events.append,
    ))
    return result, reason, factory, events


@pytest.mark.parametrize("kind", ["script", "http", "browser"])
@pytest.mark.parametrize("status", ["verified", "rejected"])
def test_spliced_excerpt_is_corrected_as_json_without_reexecuting(monkeypatch, kind, status):
    deps, corrected = experiment(kind)
    corrected["status"] = status
    invalid = copy.deepcopy(corrected)
    invalid["attack_evidence"][0]["excerpt"] = 'NORMAL: one row...ATTACK: private "row"'
    invalid_before = copy.deepcopy(invalid)
    jobs_before = copy.deepcopy(deps.jobs)

    result, reason, factory, events = run_publication(monkeypatch, deps, [invalid, corrected])

    assert result.status == status and reason == "completed"
    assert deps.jobs == jobs_before and invalid == invalid_before
    assert factory.phases == ["poc_execute", "poc_conclude", "poc_conclude"]
    assert deps.execution.snapshot()["requests"] == 3
    retries = [item for item in events if item["kind"] == "model_retry"]
    assert len(retries) == 1 and retries[0]["phase"] == "poc_conclude"
    assert "连续" in retries[0]["reason"] and "原文片段" in retries[0]["reason"]
    correction = transcript(factory.built().requests[-1])
    assert "上一次发布被宿主拒绝" in correction and "不得添加省略号或拼接" in correction
    assert len([item for item in events if item["kind"] == "poc_evidence_rejected"]) == 1
    assert not [item for item in events if item["kind"] == "tool_call"]


def test_wrong_channel_and_state_metadata_get_a_channel_specific_correction(monkeypatch):
    deps, corrected = experiment()
    deps.jobs[0]["state_changes"] = [{"field": "role", "before": "customer", "after": "admin"}]
    invalid = copy.deepcopy(corrected)
    invalid["attack_evidence"][0].update(channel="body_text", excerpt="customer -> admin")

    result, reason, _, events = run_publication(monkeypatch, deps, [invalid, corrected])

    assert result.status == "verified" and reason == "completed"
    rejection = next(item for item in events if item["kind"] == "poc_evidence_rejected")
    assert any("body_text" in error and "仅 stdout/stderr" in error for error in rejection["errors"])
    retry = next(item for item in events if item["kind"] == "model_retry")
    assert "state_changes不是输出通道" in retry["reason"]


def test_exhausted_evidence_corrections_keep_inconclusive_diagnosis_and_job_facts(monkeypatch):
    deps, invalid = experiment()
    invalid["attack_evidence"][0]["excerpt"] = "PRIVATE_UNQUOTED_MODEL_EXCERPT"
    jobs_before = copy.deepcopy(deps.jobs)

    result, reason, factory, events = run_publication(monkeypatch, deps, [invalid] * 3)

    assert result.status == "inconclusive" and result.verdict == "uncertain"
    assert reason == "invalid_output"
    assert result.summary == "宿主证据校验未通过，当前结论无法确定。"
    assert result.adapted_script == ""
    assert "原文片段" in result.evidence_notes and "结论纠正未完成（invalid_output）" in result.evidence_notes
    assert result.jobs == ["completed-job"] and deps.jobs == jobs_before
    assert factory.phases == ["poc_execute"] + ["poc_conclude"] * 3
    assert deps.execution.snapshot()["requests"] == 4
    assert len([item for item in events if item["kind"] == "model_retry"]) == 2
    assert len([item for item in events if item["kind"] == "poc_evidence_rejected"]) == 3
    persisted = json.dumps(events, ensure_ascii=False)
    assert "PRIVATE_UNQUOTED_MODEL_EXCERPT" not in persisted
    assert invalid["status"] == "verified" and invalid["summary"] == "已确认攻击返回私有记录。"


@pytest.mark.parametrize("problem", ["context", "precondition", "exit", "timeout"])
def test_corrections_cannot_promote_invalid_job_provenance(monkeypatch, problem):
    deps, candidate = experiment()
    job = deps.jobs[0]
    if problem == "context":
        job["context_id"] = "another-context"
    elif problem == "precondition":
        job["precondition"] = {"ok": False}
    elif problem == "exit":
        job["exit_code"] = 1
    else:
        job["result"]["timed_out"] = True

    result, reason, factory, _ = run_publication(monkeypatch, deps, [candidate] * 3)

    assert result.status == "inconclusive" and reason == "invalid_output"
    assert result.adapted_script == ""
    assert factory.phases.count("poc_conclude") == 3


def test_evidence_diagnosis_is_pure_and_literal_ellipsis_keeps_exact_match_semantics():
    deps, payload = experiment()
    candidate = PocVerificationResult(**payload)
    before = candidate.model_dump()
    candidate.attack_evidence[0].excerpt = "invented...excerpt"
    invalid_before = candidate.model_dump()
    assert evidence_errors(candidate, deps)
    assert candidate.model_dump() == invalid_before

    candidate = PocVerificationResult(**before)
    deps.jobs[0]["result"]["stdout"] += "literal...output\n"
    candidate.attack_evidence[0].excerpt = "literal...output"
    assert evidence_errors(candidate, deps) == []
    assert host_check(candidate, deps).status == "verified"
