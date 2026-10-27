"""POC slots account for experiments, including failed and uncertain submissions.

No network, model or live target is used. The same fake serves all three actions,
so a per-tool budget can never accidentally satisfy these tests.
"""
import asyncio
import json

import pytest

from audit.poc_agent import PocDeps
from audit.poc_runner import PocRunnerError, PocRunnerUnavailable
from audit.runtime import AgentPolicy, Execution, StopAudit


ARGS = {
    "run_poc": {"language": "python", "script": "print('control and attack')"},
    "http_observe": {"path": "/account/me.php"},
    "browser_check": {"path": "/"},
}


class Client:
    def __init__(self, mode="success"):
        self.mode = mode
        self.submissions = []
        self.queries = []

    def result(self, kind, args):
        result = {"job_id": args["job_id"], "context_id": args["context_id"],
                  "identity": args["identity"], "status": "finished", "exit_code": 0,
                  "precondition": {"ok": True}, "stdout": "control and attack", "artifacts": []}
        if kind == "http":
            result.update(status=200, body="control and attack", headers={})
        elif kind == "browser":
            result.update(available=True, dialogs=["control and attack"])
        if self.mode == "failed":
            result.update(status="error", execution_status="error", error="controlled_failure", exit_code=None)
        return result

    async def submit(self, kind, args):
        self.submissions.append((kind, args))
        if self.mode in {"unknown", "recovered"}:
            raise PocRunnerUnavailable("reply lost after acceptance")
        if self.mode == "refused":
            raise PocRunnerError("controlled refusal", status_code=409)
        if self.mode == "malformed":
            raise PocRunnerError("not JSON after acceptance")
        if self.mode == "cancelled":
            raise asyncio.CancelledError()
        return self.result(kind, args)

    async def run_job(self, **args):
        return await self.submit("script", args)

    async def http_observe(self, **args):
        return await self.submit("http", args)

    async def browser_check(self, **args):
        return await self.submit("browser", args)

    async def get_job(self, ident):
        self.queries.append(ident)
        kind, args = self.submissions[-1]
        if self.mode == "recovered":
            return self.result(kind, args)
        return {"job_id": ident, "context_id": "ctx-one", "status": "running"}


def make_deps(client=None, **overrides):
    events = []
    data = PocDeps(client=client or Client(), policy={}, target="lab30", finding={"id": "f-one"},
                   context_id="ctx-one", **overrides)
    data.execution = Execution({"responses": 5, "tools": 50, "seconds": 60}, AgentPolicy(), events.append)
    data.execution.enter("poc_execute")
    return data, events


@pytest.mark.parametrize("tool", ARGS)
def test_eighth_job_is_admitted_ninth_is_rejected_before_runner(tool):
    async def scenario():
        data, events = make_deps()
        for _ in range(8):
            reply = json.loads(await data.call(tool, ARGS[tool]))
            assert not reply.get("error")
        ninth = json.loads(await data.call(tool, ARGS[tool]))
        assert ninth["error"] == "job_limit"
        assert len(data.jobs) == len(data.client.submissions) == 8
        accepted = [e for e in events if e["kind"] == "poc_job_started"]
        assert [e["jobs_used"] for e in accepted] == list(range(1, 9))
        assert accepted[-1]["jobs_remaining"] == 0
        rejected = [e for e in events if e["kind"] == "poc_job_rejected"][-1]
        assert rejected["context_id"] == "ctx-one" and rejected["identity"] == "alice"
        assert rejected["reason"] == "job_limit"
        assert all(args["job_id"] for _, args in data.client.submissions)
        assert len({args["job_id"] for _, args in data.client.submissions}) == 8
    asyncio.run(scenario())


def test_three_tools_share_the_same_eight_slots():
    async def scenario():
        data, _ = make_deps()
        tools = ["run_poc", "http_observe", "browser_check"]
        for n in range(8):
            tool = tools[n % 3]
            await data.call(tool, ARGS[tool])
        for tool in tools:
            assert json.loads(await data.call(tool, ARGS[tool]))["error"] == "job_limit"
        assert len(data.client.submissions) == 8
    asyncio.run(scenario())


@pytest.mark.parametrize("tool,args", [
    ("run_poc", {"language": "bash", "script": "echo 1"}),
    ("run_poc", {"language": "python", "script": ""}),
    ("run_poc", {"language": "python", "script": "print(1)", "timeout_seconds": True}),
    ("run_poc", {"language": "python", "script": "print(1)", "artifacts": ["../secret"]}),
    ("http_observe", {"path": "//remote.invalid"}),
    ("http_observe", {"path": "/", "method": "DELETE"}),
    ("http_observe", {"path": "/", "body": {}}),
    ("browser_check", {"path": "/", "wait_ms": False}),
    ("browser_check", {"path": "/", "script": []}),
    ("browser_check", {"path": "../outside"}),
    ("http_observe", {"path": "/", "identity": []}),
])
def test_local_argument_rejection_does_not_reserve_a_job(tool, args):
    data, events = make_deps()
    response = json.loads(asyncio.run(data.call(tool, args)))
    assert response["ok"] is False
    assert not data.jobs and not data.client.submissions
    assert not any(e["kind"] == "poc_job_started" for e in events)


@pytest.mark.parametrize("tool", ARGS)
@pytest.mark.parametrize("mode", ["failed", "refused"])
def test_failed_or_refused_remote_submission_keeps_its_slot(tool, mode):
    async def scenario():
        data, _ = make_deps(Client(mode), max_jobs=1)
        first = json.loads(await data.call(tool, ARGS[tool]))
        assert first["ok"] is False
        assert len(data.jobs) == 1
        assert json.loads(await data.call(tool, ARGS[tool]))["error"] == "job_limit"
        assert len(data.client.submissions) == 1
    asyncio.run(scenario())


@pytest.mark.parametrize("tool", ARGS)
def test_unknown_submission_only_queries_original_id_and_blocks_all_new_actions(tool):
    async def scenario():
        data, events = make_deps(Client("unknown"))
        with pytest.raises(StopAudit, match="原作业"):
            await data.call(tool, ARGS[tool])
        ident = data.client.submissions[0][1]["job_id"]
        assert data.client.queries == [ident]
        assert data.jobs[0]["result"]["status"] == "running"
        for next_tool in ARGS:
            with pytest.raises(StopAudit, match="上一作业"):
                await data.call(next_tool, ARGS[next_tool])
        assert len(data.client.submissions) == 1
        assert len(data.jobs) == 1
        assert any(e["kind"] == "poc_job_finished" and e["reason"] == "submission_unresolved" for e in events)
    asyncio.run(scenario())


@pytest.mark.parametrize("tool", ARGS)
def test_lost_response_recovers_original_job_without_consuming_another_slot(tool):
    async def scenario():
        data, _ = make_deps(Client("recovered"), max_jobs=1)
        response = json.loads(await data.call(tool, ARGS[tool]))
        assert not response.get("error")
        assert data.client.queries == [data.client.submissions[0][1]["job_id"]]
        assert len(data.jobs) == 1 and len(data.client.submissions) == 1
        assert not data.submission_unresolved
    asyncio.run(scenario())


@pytest.mark.parametrize("tool", ARGS)
@pytest.mark.parametrize("mode", ["cancelled", "malformed"])
def test_cancelled_or_malformed_submission_retains_unknown_history(tool, mode):
    async def scenario():
        data, _ = make_deps(Client(mode))
        if mode == "cancelled":
            with pytest.raises(asyncio.CancelledError):
                await data.call(tool, ARGS[tool])
        else:
            assert json.loads(await data.call(tool, ARGS[tool]))["ok"] is False
        assert data.submission_unresolved
        assert data.jobs[0]["result"]["status"] == "unknown"
        with pytest.raises(StopAudit):
            await data.call(tool, ARGS[tool])
        assert len(data.client.submissions) == 1
    asyncio.run(scenario())
