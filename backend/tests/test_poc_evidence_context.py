"""Fail closed on ambiguous provenance without executing a target or a model."""
import asyncio

import pytest

from audit.poc_agent import PocDeps, host_check
from audit.poc_runner import PocRunnerUnavailable
from audit.runtime import AgentPolicy, Execution, StopAudit
from audit.schemas import PocVerificationResult


def job(ident="good", **changes):
    value = {
        "job_id": ident, "kind": "script", "context_id": "context-one",
        "precondition": {"ok": True, "actual": {"username": "alice", "role": "customer"}},
        "exit_code": 0,
        "result": {"status": "finished", "stdout": "NORMAL: one row\nATTACK: extra private row", "stderr": "", "timed_out": False},
    }
    value.update(changes)
    return value


def verdict(**changes):
    value = {
        "status": "verified", "jobs": ["good"], "normal_observation": "One row",
        "attack_observation": "Additional private row",
        "normal_evidence": [{"job_id": "good", "channel": "stdout", "excerpt": "NORMAL: one row"}],
        "attack_evidence": [{"job_id": "good", "channel": "stdout", "excerpt": "ATTACK: extra private row"}],
    }
    value.update(changes)
    return PocVerificationResult(**value)


def deps(jobs):
    return PocDeps(client=None, policy={}, target="lab30", finding={"category": "sqli"},
                   context_id="context-one", jobs=jobs, job_scripts={"good": "print('paired experiment')"})


def test_exact_paired_success_is_accepted():
    checked = host_check(verdict(), deps([job()]))
    assert checked.status == "verified"
    assert checked.adapted_script == "print('paired experiment')"


@pytest.mark.parametrize("changes", [
    {"exit_code": 1}, {"context_id": "other-experiment"}, {"precondition": {"ok": False}},
    {"precondition": {}}, {"kind": "http"},
    {"result": {"status": "finished", "stdout": "NORMAL: one row\nATTACK: extra private row", "timed_out": True}},
    {"result": {"status": "running", "stdout": "NORMAL: one row\nATTACK: extra private row"}},
])
def test_an_unrelated_success_never_rescues_invalid_referenced_job(changes):
    checked = host_check(verdict(), deps([job("unrelated"), job(**changes)]))
    assert checked.status == "inconclusive"
    assert checked.verdict == "uncertain"
    assert checked.adapted_script == ""


@pytest.mark.parametrize("changes", [
    {"jobs": ["unknown"]}, {"jobs": []}, {"normal_evidence": []}, {"attack_evidence": []},
    {"normal_observation": ""},
    {"attack_evidence": [{"job_id": "good", "channel": "stdout", "excerpt": "invented extra private row"}]},
    {"attack_evidence": [{"job_id": "good", "channel": "dialogs", "excerpt": "ATTACK: extra private row"}]},
    {"attack_evidence": [{"job_id": "unknown", "channel": "stdout", "excerpt": "ATTACK: extra private row"}]},
])
def test_incomplete_or_invented_provenance_is_inconclusive(changes):
    assert host_check(verdict(**changes), deps([job()])).status == "inconclusive"


def test_failed_last_script_is_kept_as_history_and_never_downloaded_as_proof():
    data = deps([job(), job("failed", exit_code=1)])
    data.scripts = [data.job_scripts["good"], "raise RuntimeError('last attempt')"]
    data.job_scripts["failed"] = data.scripts[-1]
    checked = host_check(verdict(adapted_script=data.scripts[-1]), data)
    assert checked.status == "verified"
    assert checked.adapted_script == data.job_scripts["good"]


def test_successful_privilege_change_records_post_state_without_invalidating_original_precondition():
    changed = job(postcondition={"ok": False, "actual": {"role": "admin"}},
                  state_changes=[{"field": "role", "before": "customer", "after": "admin"}])
    assert host_check(verdict(), deps([changed])).status == "verified"


def test_rejected_also_requires_both_sides_of_the_experiment():
    assert host_check(verdict(status="rejected", normal_evidence=[]), deps([job()])).status == "inconclusive"


def test_uncertain_submission_is_queried_once_and_never_resubmitted():
    class Client:
        submissions = []
        queries = []

        async def run_job(self, **kwargs):
            self.submissions.append(kwargs)
            raise PocRunnerUnavailable("response lost after submission")

        async def get_job(self, ident):
            self.queries.append(ident)
            return {"job_id": ident, "status": "running"}

    async def scenario():
        client = Client()
        data = deps([])
        data.client = client
        events = []
        data.execution = Execution({"responses": 4, "tools": 8, "seconds": 30}, AgentPolicy(), events.append)
        data.execution.enter("poc_execute")
        for _ in range(2):
            with pytest.raises(StopAudit, match="原作业|上一作业"):
                await data.call("run_poc", {"language": "python", "script": "print('fixture')"})
        assert len(client.submissions) == 1
        assert client.queries == [client.submissions[0]["job_id"]]
        assert data.jobs[0]["result"]["status"] == "running"
        assert len([e for e in events if e["kind"] == "tool_result"]) == 2
    asyncio.run(scenario())


def test_callback_timeout_cancels_pending_operation_and_cannot_be_retried():
    import time
    from audit.codemodel import HostStop, PhaseGate

    async def scenario():
        entered, cancelled = asyncio.Event(), asyncio.Event()
        async def dispatch(name, args):
            entered.set()
            try:
                await asyncio.sleep(10)
            finally:
                cancelled.set()
        execution = Execution({"responses": 4, "tools": 8, "seconds": 30}, AgentPolicy(), lambda _: None)
        execution.enter("poc_execute")
        gate = PhaseGate(execution=execution, loop=asyncio.get_running_loop(), dispatch=dispatch,
                         deadline=time.monotonic() + 10, limit=4, callback_seconds=.05)
        with pytest.raises(HostStop) as first:
            await asyncio.to_thread(gate.call_tool, "run_poc", {})
        assert first.value.audit.reason == "timeout"
        await asyncio.wait_for(cancelled.wait(), 1)
        with pytest.raises(HostStop):
            await asyncio.to_thread(gate.call_tool, "run_poc", {})
        assert gate.tool_calls == 1 and entered.is_set()
    asyncio.run(scenario())


def test_quoted_credentials_in_public_arguments_are_redacted():
    import json
    from audit.tool_errors import public_value
    cleaned = public_value({"script": 'payload = {"password": "SYNTHETIC_PASSWORD_MARKER"}',
                            "body": '{"api_key":"SYNTHETIC_KEY_MARKER"}'})
    assert "SYNTHETIC" not in json.dumps(cleaned)


def test_two_jobs_with_same_artifact_name_keep_separate_bytes():
    class Client:
        count = 0
        async def run_job(self, **kwargs):
            self.count += 1
            return {"job_id": str(self.count), "context_id": "context-one", "status": "finished",
                    "exit_code": 0, "stdout": "fixture", "precondition": {"ok": True},
                    "artifacts": [{"name": "out.txt"}]}
        async def fetch_artifact(self, ident, name):
            return (ident + " bytes").encode()
    async def scenario():
        data = deps([])
        data.client = Client()
        data.execution = Execution({"responses": 4, "tools": 8, "seconds": 30}, AgentPolicy(), lambda _: None)
        data.execution.enter("poc_execute")
        for _ in range(2):
            await data.call("run_poc", {"language": "python", "script": "print('fixture')"})
        assert data.artifacts == {"1-out.txt": b"1 bytes", "2-out.txt": b"2 bytes"}
        assert data.jobs[0]["artifacts"][0]["name"] == "1-out.txt"
    asyncio.run(scenario())


@pytest.mark.parametrize('changes', [
    {'exit_code': None}, {'exit_code': 1},
    {'result': {'available': True, 'status': 'failed', 'dialogs': ['attack'], 'body_text': 'normal'}},
    {'result': {'available': True, 'status': 'finished', 'timed_out': True, 'dialogs': ['attack'], 'body_text': 'normal'}},
])
def test_browser_output_never_promotes_failed_or_unknown_execution(changes):
    browser = job(kind='browser', result={'available': True, 'status': 'finished',
                                          'dialogs': ['attack'], 'body_text': 'normal'})
    browser.update(changes)
    checked = host_check(verdict(
        normal_evidence=[{'job_id': 'good', 'channel': 'body_text', 'excerpt': 'normal'}],
        attack_evidence=[{'job_id': 'good', 'channel': 'dialogs', 'excerpt': 'attack'}],
    ), deps([browser]))
    assert checked.status == 'inconclusive'
