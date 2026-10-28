"""Three runner job types share execution and evidence rules; no live target."""
import asyncio
import copy
import json

import pytest

from audit import poc_agent
from audit.poc_agent import PocDeps, host_check, successful_job
from audit.runtime import AgentPolicy, Execution, StopAudit
from audit.schemas import PocVerificationResult
from tests.code_model import CONFIG, Always, ModelFactory, call, code, final_answer
from tests.test_poc_agent import FakeClient


def job(ident, kind="http", **result):
    payload = {"status": "finished", **result}
    if kind == "http":
        payload = {"execution_status": "finished", "http_status": 200, "body": "control", "headers": {}, **payload}
    elif kind == "browser":
        payload = {"available": True, **payload}
    return {"job_id": ident, "kind": kind, "context_id": "ctx", "precondition": {"ok": True}, "exit_code": 0, "result": payload}


def data(finding=None, jobs=None, **kwargs):
    value = PocDeps(client=FakeClient(), policy={}, target="lab30", finding=finding or {"id": "f", "vulnerability_type": "open_redirect"}, context_id="ctx", **kwargs)
    value.jobs = list(jobs or [])
    value.execution = Execution({"responses": 12, "tools": 40, "seconds": 10}, AgentPolicy(), lambda event: None)
    value.execution.enter("poc_execute")
    return value


def redirect_result(channel="headers", excerpt="location: https://outside.invalid/"):
    return PocVerificationResult(
        status="verified", summary="正常地址留在站内，攻击地址产生外部重定向。",
        jobs=["normal", "attack"], normal_observation="正常页面正文。", attack_observation="Location指向站外。",
        normal_evidence=[{"job_id": "normal", "channel": "body", "excerpt": "control"}],
        attack_evidence=[{"job_id": "attack", "channel": channel, "excerpt": excerpt}],
    )


def test_http_body_and_headers_support_exact_paired_evidence_without_a_script():
    deps = data(jobs=[job("normal"), job("attack", http_status=302, headers={"location": "https://outside.invalid/"})])
    checked = host_check(redirect_result(), deps)
    assert checked.status == "verified"
    assert checked.adapted_script == ""


def test_http_legacy_body_text_is_an_alias_for_the_actual_http_body():
    deps = data(jobs=[job("normal"), job("attack", body="attack proof")])
    assert host_check(redirect_result("body_text", "attack proof"), deps).status == "verified"


@pytest.mark.parametrize("status", [200, 302, 401, 403, 503])
def test_http_response_execution_is_independent_of_http_semantics(status):
    assert successful_job(job("http", http_status=status))
    # A finished request alone cannot replace the paired original citations.
    assert host_check(PocVerificationResult(status="verified", summary="请求已完成", jobs=["http"]), data(jobs=[job("http", http_status=status)])).status == "inconclusive"


@pytest.mark.parametrize("kind", ["http", "script", "browser"])
@pytest.mark.parametrize("problem", ["exit", "boolean_exit", "timeout", "error", "identity", "context", "unknown_job", "forged_excerpt"])
def test_invalid_execution_or_reference_cannot_support_a_deterministic_verdict(kind, problem):
    normal = job("normal", kind, stdout="control", body="control", body_text="control")
    attack = job("attack", kind, stdout="proof", body="proof", body_text="proof")
    channel = "stdout" if kind == "script" else "body" if kind == "http" else "body_text"
    value = redirect_result(channel, "proof")
    value.normal_evidence[0].channel = channel
    if problem == "exit": attack["exit_code"] = 1
    if problem == "boolean_exit": attack["exit_code"] = False
    if problem == "timeout": attack["result"]["timed_out"] = True
    if problem == "error": attack["result"]["error"] = "failed"
    if problem == "identity": attack["precondition"] = {"ok": False}
    if problem == "context": attack["context_id"] = "other"
    if problem == "unknown_job": value.attack_evidence[0].job_id = "missing"
    if problem == "forged_excerpt": value.attack_evidence[0].excerpt = "invented output"
    assert host_check(value, data(jobs=[normal, attack])).status == "inconclusive"


def test_canonical_xss_type_requires_browser_even_without_xss_words_in_title():
    finding = {"id": "f", "vulnerability_type": "xss_r", "title": "属性值输出缺少编码", "summary": "请求参数直接写入页面"}
    value = redirect_result("body", "proof")
    deps = data(finding=finding, jobs=[job("normal"), job("attack", body="proof")])
    assert host_check(value, deps).status == "inconclusive"


def test_http_control_and_browser_attack_can_jointly_verify_xss():
    finding = {"id": "f", "vulnerability_type": "xss_s", "title": "留言输出缺少编码"}
    value = redirect_result("dialogs", "executed")
    value.browser_execution = True
    deps = data(finding=finding, jobs=[job("normal"), job("attack", "browser", dialogs=["executed"])])
    assert host_check(value, deps).status == "verified"


@pytest.mark.parametrize("expected", [{"role": "customer"}, {"unknown": 1}, {"balance": {"nested": 1}}, []])
def test_expected_state_is_rejected_locally_before_runner(expected):
    deps = data()
    reply = json.loads(asyncio.run(deps.call("target_prepare", {"expected_state": expected})))
    assert reply["error"] == "invalid_expected_state"
    assert deps.client.prepared == []
    assert deps.jobs == []


def test_supported_expected_state_and_identity_use_runner_contract():
    deps = data()
    reply = json.loads(asyncio.run(deps.call("target_prepare", {"identity": "bob", "expected_state": {"balance": "100.00", "tier": "standard"}})))
    assert reply["ok"] is True
    assert len(deps.client.prepared) == 1


@pytest.mark.parametrize("form,encoded", [(False, "a%20b%26%3D%2F%E4%B8%AD"), (True, "a+b%26%3D%2F%E4%B8%AD")])
def test_url_encoding_is_memory_only_and_keeps_payload_characters(form, encoded):
    deps = data()
    reply = json.loads(asyncio.run(deps.call("url_encode", {"value": "a b&=/中", "form": form})))
    assert reply["encoded"] == encoded
    assert deps.jobs == [] and deps.client.jobs == []


def test_one_allowed_job_withdraws_execution_tools_before_another_model_request(monkeypatch):
    factory = ModelFactory({
        "poc_execute": [call("run_poc", language="python", script="print('proof')")],
        "poc_conclude": [json.dumps({"status": "inconclusive", "summary": "已有作业，证据仍不足。"})],
    })
    monkeypatch.setattr(poc_agent, "build_code_model", factory)
    deps = data(max_jobs=1)
    deps.policy.update(max_jobs=1, max_steps=8, max_seconds=10)
    events = []

    result, reason = asyncio.run(poc_agent.run_poc_agent(finding=deps.finding, deps=deps, config=CONFIG, on_event=events.append))

    assert result.status == "inconclusive" and reason == "completed"
    assert factory.phases == ["poc_execute", "poc_conclude"]
    assert len(deps.jobs) == 1
    assert any(event["kind"] == "poc_execution_finished" and event["reason"] == "job_limit" for event in events)
    assert not [event for event in events if event["kind"] == "agent_code" and event["phase"] == "poc_conclude"]


def test_json_conclusion_recovers_twice_without_expanding_the_original_allowance(monkeypatch):
    factory = ModelFactory({
        "poc_execute": [final_answer("结束")],
        "poc_conclude": ['{"status":', '{"status":"invalid"}', '{"status":"inconclusive","summary":"证据不足"}'],
    })
    monkeypatch.setattr(poc_agent, "build_code_model", factory)
    deps = data()
    deps.policy.update(max_steps=1, max_seconds=10)
    result, reason = asyncio.run(poc_agent.run_poc_agent(finding=deps.finding, deps=deps, config=CONFIG))
    assert result.status == "inconclusive" and reason == "completed"
    assert factory.phases == ["poc_execute"] + ["poc_conclude"] * 3


@pytest.mark.parametrize("execution_status,timed_out", [("timeout", False), ("finished", True), ("error", False)])
def test_http_tool_never_relabels_a_failed_or_timed_out_response_as_finished(execution_status, timed_out):
    class Client(FakeClient):
        async def http_observe(self, **kwargs):
            return {"ok": True, "job_id": kwargs["job_id"], "context_id": "ctx", "status": 200,
                "execution_status": execution_status, "timed_out": timed_out, "exit_code": 0,
                "body": "proof", "precondition": {"ok": True}}

    deps = data()
    deps.client = Client()
    reply = json.loads(asyncio.run(deps.call("http_observe", {"path": "/account/me.php"})))

    assert reply["execution_status"] == execution_status
    assert deps.jobs[0]["result"]["timed_out"] == timed_out
    assert not successful_job(deps.jobs[0])


def test_http_header_citation_uses_sorted_original_fields():
    deps = data(jobs=[job("normal"), job("attack", http_status=302,
        headers={"z-test": "last", "location": "https://outside.invalid/", "a-test": "first"})])
    assert host_check(redirect_result("headers", "a-test: first\nlocation: https://outside.invalid/\nz-test: last"), deps).status == "verified"
    assert host_check(redirect_result("headers", "Location: https://outside.invalid/"), deps).status == "inconclusive"


def test_small_stage_allowance_leaves_three_responses_for_json_conclusion(monkeypatch):
    factory = ModelFactory({
        "poc_execute": Always([code("print('bounded exploration')")]),
        "poc_conclude": ['{"status":', '{"status":"invalid"}', '{"status":"inconclusive","summary":"证据不足"}'],
    })
    monkeypatch.setattr(poc_agent, "build_code_model", factory)
    deps = data()
    deps.policy.update(max_steps=8, max_seconds=10, max_responses=4)

    result, reason = asyncio.run(poc_agent.run_poc_agent(finding=deps.finding, deps=deps, config=CONFIG))

    assert result.status == "inconclusive" and reason == "completed"
    assert deps.execution.snapshot()["requests"] == 4
    assert factory.phases == ["poc_execute"] + ["poc_conclude"] * 3


def test_an_unaffordable_poc_allowance_makes_no_model_request(monkeypatch):
    factory = ModelFactory({})
    monkeypatch.setattr(poc_agent, "build_code_model", factory)
    deps = data()
    deps.policy["max_responses"] = 3
    with pytest.raises(StopAudit, match="剩余额度"):
        asyncio.run(poc_agent.run_poc_agent(finding=deps.finding, deps=deps, config=CONFIG))
    assert factory.model is None


def test_persistent_account_state_mismatch_withdraws_execution_tools(monkeypatch):
    class Client(FakeClient):
        async def prepare_target(self, *args, **kwargs):
            return {"ok": False, "identity": "alice", "precondition": {
                "ok": False, "reason": "required_account_state_mismatch", "actual": {"balance": 0}}}

    factory = ModelFactory({
        "poc_execute": [call("target_prepare", expected_state={"balance": 100})],
        "poc_conclude": ['{"status":"inconclusive","summary":"必要账号前提不符，需人工复位"}'],
    })
    monkeypatch.setattr(poc_agent, "build_code_model", factory)
    deps = data()
    deps.client = Client()
    events = []
    result, reason = asyncio.run(poc_agent.run_poc_agent(finding=deps.finding, deps=deps, config=CONFIG, on_event=events.append))

    assert result.status == "inconclusive" and reason == "completed"
    assert factory.phases == ["poc_execute", "poc_conclude"]
    assert any(event["kind"] == "poc_execution_finished" and event["reason"] == "precondition_failed" for event in events)
    assert not deps.jobs
