"""The Claude SDK adapter's host guarantees, exercised without an SDK or a model.

Every test here drives the adapter through an injected fake: the point is not to test
the SDK, it is to prove the boundaries the host keeps around it -- one runtime per
attempt, a hard request quota, host-owned evidence ids, and a conclusion that can only
come from the final structured output.
"""
import asyncio
import json
from types import SimpleNamespace

import pytest

from audit.db import Store
from audit.poc_tool_service import PocToolService
from audit.runtimes.claude_poc import (
    CONCLUDE_STAGE,
    EXECUTE_STAGE,
    ClaudeCodePocRuntime,
    ClaudePocLimits,
    EvidenceRefTable,
    MemoryPocRequestGateway,
    StorePocRequestGateway,
    _StageToolExecution,
)
from tests.test_goal_tasks import run_payload


# --- fixtures -----------------------------------------------------------------------


def limits(tmp_path, **overrides):
    values = {
        "model": "test-model",
        "gateway_url": "http://gateway.internal",
        "workspace": str(tmp_path),
        "execute_turns": 6,
        "conclude_turns": 2,
        "execute_requests": 8,
        "conclude_requests": 3,
        "max_seconds": 60,
    }
    values.update(overrides)
    return ClaudePocLimits(**values)


def http_job(job_id="job-1", *, context_id="ctx-1", ok=True, body="MEMBER_SESSION 200",
             headers=None, kind="http"):
    return {
        "job_id": job_id,
        "kind": kind,
        "context_id": context_id,
        "identity": "alice",
        "exit_code": 0,
        "precondition": {"ok": ok, "reason": "" if ok else "identity_or_role_mismatch"},
        "result": {
            "status": "finished", "execution_status": "finished", "http_status": 200,
            "body": body, "headers": headers or {"content-type": "text/plain"},
        },
        "request": {"path": "/account/update.php", "language": "python", "script_sha256": "a" * 64},
    }


def service(tmp_path, jobs=(), context_id="ctx-1"):
    deps = PocToolService(
        client=None,
        policy={"browser": True},
        target="lab30",
        finding={"id": "finding-1", "title": "mass assignment", "vulnerability_type": "mass_assignment"},
        prepared={"ok": True, "identity": "alice"},
        context_id=context_id,
        jobs=list(jobs),
    )
    return deps


class ResultMessage:
    """Stand-in for ``ResultMessage``: only the fields the host reads."""

    def __init__(self, structured=None, *, usage=None, turns=1, is_error=False,
                 subtype="success", cost=None):
        self.type = "result"
        self.structured_output = structured
        self.usage = usage if usage is not None else {}
        self.num_turns = turns
        self.is_error = is_error
        self.subtype = subtype
        self.total_cost_usd = cost


class Assistant:
    type = "assistant"

    def __init__(self, text):
        self.content = text
        self.message = {"text": text}


class FakeSDK:
    """A scripted ``claude_agent_sdk``.

    ``script`` holds one callable per ``query()`` call; it receives the options and
    returns the messages the SDK would stream.  The adapter calls ``query`` once per
    stage attempt, so the order is experiment, conclusion, correction, ...
    """

    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.tools = {}
        self.servers = []

    def ClaudeAgentOptions(self, **kwargs):
        return SimpleNamespace(**kwargs)

    def tool(self, name, description, schema):
        def register(handler):
            self.tools[name] = {"description": description, "schema": schema, "handler": handler}
            return self.tools[name]
        return register

    def create_sdk_mcp_server(self, *, name, version, tools):
        server = {"name": name, "version": version, "tools": list(tools)}
        self.servers.append(server)
        return server

    def query(self, *, prompt, options):
        index = len(self.calls)
        self.calls.append({"prompt": prompt, "options": options})
        handler = self.script[min(index, len(self.script) - 1)]

        async def stream():
            for message in handler(options):
                yield message
        return stream()

    def stage_options(self):
        return [call["options"] for call in self.calls]


def conclude(payload, **kwargs):
    return lambda options_: [ResultMessage(payload, **kwargs)]


def execute(*messages):
    tail = list(messages)
    if not tail or not isinstance(tail[-1], ResultMessage):
        tail.append(ResultMessage())
    return lambda options_: tail


async def run(runtime, service_, events, *, run_id="run-1", epoch=1):
    return await runtime.verify(service=service_, emit=events.append,
                                run_id=run_id, epoch=epoch)


# --- readiness ----------------------------------------------------------------------


def test_missing_sdk_is_an_explicit_failure_not_a_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(ClaudeCodePocRuntime, "_load_sdk", lambda self: None)
    runtime = ClaudeCodePocRuntime(
        limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
        cli_probe=lambda: ("2.1.310", ""),
    )
    events = []
    outcome = asyncio.run(run(runtime, service(tmp_path), events))

    assert outcome.status == "unavailable"
    assert outcome.reason == "runtime_unavailable"
    assert outcome.result is None
    assert [event["kind"] for event in events][:2] == [
        "poc_runtime_readiness", "poc_runtime_unavailable",
    ]
    assert events[0]["reason"] == "sdk_missing"
    # The SDK was never asked to run anything, and no legacy loop was entered.
    assert not any(event["kind"].startswith("poc_runtime_stage") for event in events)


@pytest.mark.parametrize("field,reason", [
    ("model", "model_unconfigured"),
    ("gateway_url", "gateway_unconfigured"),
    ("workspace", "workspace_unconfigured"),
])
def test_readiness_names_the_missing_deployment_input(tmp_path, field, reason):
    runtime = ClaudeCodePocRuntime(
        limits=limits(tmp_path, **{field: ""}), gateway=MemoryPocRequestGateway(),
        sdk=FakeSDK([]), cli_probe=lambda: ("2.1.310", ""),
    )
    readiness = runtime.readiness()
    assert readiness.ready is False
    assert readiness.reason == reason
    assert readiness.snapshot()["capability"] is False


def test_readiness_rejects_an_unpinned_cli(tmp_path):
    runtime = ClaudeCodePocRuntime(
        limits=limits(tmp_path, cli_version="2.0.0"), gateway=MemoryPocRequestGateway(),
        sdk=FakeSDK([]), cli_probe=lambda: ("2.1.310", ""),
    )
    assert runtime.readiness().reason == "cli_version_mismatch"


def test_readiness_requires_an_isolated_empty_workspace(tmp_path):
    (tmp_path / ".git").mkdir()
    runtime = ClaudeCodePocRuntime(
        limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
        sdk=FakeSDK([]), cli_probe=lambda: ("2.1.310", ""),
    )
    assert runtime.readiness().reason == "workspace_not_isolated"


# --- stage separation ---------------------------------------------------------------


def test_the_two_stages_see_different_tools_and_options(tmp_path):
    sdk = FakeSDK([execute(Assistant("ran the experiment")), conclude({"status": "inconclusive", "summary": "证据不足"})])
    gateway = MemoryPocRequestGateway()
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=gateway, sdk=sdk,
                                   cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, service(tmp_path), events))

    assert outcome.status == "completed"
    assert outcome.result is not None and outcome.result.verdict == "uncertain"
    execute_options, conclude_options = sdk.stage_options()

    assert execute_options.tools == []
    assert set(execute_options.mcp_servers) == {"poc"}
    assert "mcp__poc__run_poc" in execute_options.allowed_tools
    assert not hasattr(execute_options, "output_format")
    assert execute_options.permission_mode == "dontAsk"
    assert execute_options.setting_sources == []
    assert execute_options.extra_args == {"no-session-persistence": None}
    assert execute_options.env["ANTHROPIC_BASE_URL"] == "http://gateway.internal"
    # The task's own config directory, not the invoking user's.
    assert execute_options.env["CLAUDE_CONFIG_DIR"] == str(tmp_path / ".claude")
    assert "身份决策" in execute_options.system_prompt

    assert conclude_options.mcp_servers == {}
    assert conclude_options.allowed_tools == []
    assert conclude_options.output_format["type"] == "json_schema"
    assert conclude_options.output_format["schema"]["required"] == ["status", "summary"]
    # Each stage's rules are explicit; the SDK never loads Claude Code's own prompt.
    assert "结论阶段" in conclude_options.system_prompt

    # Both stages were opened before the experiment ran, conclusion first.
    assert list(gateway.limits) == [("run-1", 1, "conclude"), ("run-1", 1, "execute")]


def test_conclusion_stage_refuses_withdrawn_tools(tmp_path):
    sdk = FakeSDK([])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    deps = service(tmp_path)
    runtime._service = deps
    runtime._stage = CONCLUDE_STAGE
    events = []
    runtime._emit_cb = events.append

    reply = asyncio.run(runtime.call_tool("run_poc", {"script": "print(1)"}))
    assert json.loads(reply)["error"] == "tools_withdrawn"
    assert deps.jobs == []
    assert [event["kind"] for event in events] == ["poc_runtime_tool_withdrawn"]


def test_transcript_text_is_not_bridged_into_events(tmp_path):
    secret = "内部推理：先读 public/account/update.php 第 4 行"
    sdk = FakeSDK([execute(Assistant(secret)), conclude({"status": "inconclusive", "summary": "证据不足"})])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    asyncio.run(run(runtime, service(tmp_path), events))
    assert secret not in json.dumps(events, ensure_ascii=False)


# --- evidence ids -------------------------------------------------------------------


def test_evidence_refs_are_built_only_from_displayed_usable_jobs(tmp_path):
    good = http_job("job-good", body="MEMBER_SESSION 200\nUPDATE ok")
    foreign = http_job("job-foreign", context_id="ctx-other", body="foreign")
    failed = http_job("job-failed", ok=False, body="failed")
    deps = service(tmp_path, jobs=[good, foreign, failed])
    table = EvidenceRefTable.build(deps)

    job_ids = {ref.job_id for ref in table._refs.values()}
    assert job_ids == {"job-good"}
    assert all(ref.ref_id.startswith("ev-") for ref in table._refs.values())
    assert table.resolve("ev-0000000000000000") is None
    assert table.resolve("job-good") is None
    assert any(ref.channel == "body" for ref in table._refs.values())


def test_conclusion_resolves_refs_host_side_and_publishes_only_the_final_output(tmp_path):
    job = http_job("job-1", body="MEMBER_SESSION 200\nrole: admin")
    deps = service(tmp_path, jobs=[job])
    table = EvidenceRefTable.build(deps)
    body_ref = next(ref for ref in table._refs.values() if ref.channel == "body")

    payload = {
        "status": "verified",
        "summary": "普通会员会话下角色被改写",
        "normal_observation": "正常登录后角色为 customer",
        "attack_observation": "提交 role=admin 后用户表角色变为 admin",
        "jobs": ["job-1"],
        "normal_refs": [body_ref.ref_id],
        "attack_refs": [body_ref.ref_id],
    }
    sdk = FakeSDK([execute(ResultMessage({"status": "inconclusive"})), conclude(payload)])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, deps, events))

    assert outcome.status == "completed"
    assert outcome.result.status == "verified"
    assert outcome.result.verdict == "confirmed"
    assert outcome.result.jobs == ["job-1"]
    # The excerpt is the host's own text, not something the model copied.
    assert outcome.result.attack_evidence[0].excerpt in job["result"]["body"]

    # Only the conclusion stage's output was a candidate: the experiment stage's
    # structured output (a decoy) was never read.
    assert len(sdk.calls) == 2
    assert outcome.result.status != "inconclusive"


def test_unknown_or_unusable_ref_is_rejected_and_corrected_once(tmp_path):
    good = http_job("job-good", body="MEMBER_SESSION 200")
    deps = service(tmp_path, jobs=[good])
    table = EvidenceRefTable.build(deps)
    ref = next(iter(table._refs.values()))

    rejected = {
        "status": "verified", "summary": "s", "normal_observation": "n",
        "attack_observation": "a", "jobs": ["job-good"],
        # A well-formed id that the host never issued.
        "normal_refs": [ref.ref_id, "ev-ffffffffffffffff"],
        "attack_refs": [ref.ref_id],
    }
    accepted = {
        "status": "inconclusive", "summary": "证据不足",
    }
    sdk = FakeSDK([execute(), conclude(rejected), conclude(accepted)])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, deps, events))

    assert outcome.status == "completed"
    assert outcome.result.status == "inconclusive"
    assert any(event["kind"] == "poc_runtime_conclusion_rejected"
               and event["reason"] == "evidence_ref_rejected" for event in events)
    # The correction prompt tells the model exactly which id was refused.
    assert "ev-ffffffffffffffff" in sdk.calls[2]["prompt"]


def test_a_job_from_another_context_cannot_support_a_verified_claim(tmp_path):
    good = http_job("job-good", body="MEMBER_SESSION 200")
    foreign = http_job("job-foreign", context_id="ctx-other", body="foreign")
    deps = service(tmp_path, jobs=[good, foreign])
    table = EvidenceRefTable.build(deps)
    ref = next(iter(table._refs.values()))
    claim = {
        "status": "verified", "summary": "s", "normal_observation": "n",
        "attack_observation": "a", "jobs": ["job-good", "job-foreign"],
        "normal_refs": [ref.ref_id], "attack_refs": [ref.ref_id],
    }
    sdk = FakeSDK([execute(), conclude(claim), conclude(claim), conclude(claim)])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, deps, events))

    assert outcome.status == "conclusion_rejected"
    assert outcome.result is None
    assert [event["reason"] for event in events
            if event["kind"] == "poc_runtime_conclusion_rejected"] == [
        "host_check_rejected", "host_check_rejected",
    ]


def test_a_host_check_downgrade_gets_at_most_one_semantic_correction(tmp_path):
    job = http_job("job-good", body="only this")
    deps = service(tmp_path, jobs=[job])
    table = EvidenceRefTable.build(deps)
    ref = next(iter(table._refs.values()))
    bad = {
        "status": "verified", "summary": "s", "normal_observation": "", "attack_observation": "",
        "jobs": ["job-good"], "normal_refs": [ref.ref_id], "attack_refs": [ref.ref_id],
    }
    sdk = FakeSDK([execute(), conclude(bad), conclude(bad), conclude(bad)])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, deps, events))

    assert outcome.status == "conclusion_rejected"
    assert outcome.result is None
    reasons = [event["reason"] for event in events if event["kind"] == "poc_runtime_conclusion_rejected"]
    assert reasons == ["host_check_rejected", "host_check_rejected"]
    # One answer + one semantic correction = two requests; the third is never spent.
    assert len(sdk.calls) == 3  # experiment + two conclusions


def test_missing_structured_output_is_retried_once_then_stops(tmp_path):
    sdk = FakeSDK([execute(), conclude(None), conclude(None), conclude({"status": "inconclusive"})])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, service(tmp_path), events))
    assert outcome.status == "conclusion_rejected"
    assert [event["reason"] for event in events
            if event["kind"] == "poc_runtime_conclusion_rejected"] == [
        "missing_structured_output", "missing_structured_output",
    ]
    assert len(sdk.calls) == 3


# --- hard request quota -------------------------------------------------------------


def test_memory_gateway_first_opener_wins_and_refusal_is_final():
    gateway = MemoryPocRequestGateway()
    first = gateway.open_stage(run_id="run-1", epoch=0, stage="conclude", limit=3)
    second = gateway.open_stage(run_id="run-1", epoch=0, stage="conclude", limit=30)
    assert first["limit"] == 3 and second["limit"] == 3 and second["narrowed"] is True

    assert [gateway.reserve(run_id="run-1", epoch=0, stage="conclude")["granted"] for _ in range(3)] == [True] * 3
    refused = gateway.reserve(run_id="run-1", epoch=0, stage="conclude")
    assert refused == {"granted": False, "reason": "quota_exhausted", "stage": "conclude",
                       "limit": 3, "used": 3, "remaining": 0}
    # A later reservation in the same stage reports the refusal, not a retryable state.
    again = gateway.reserve(run_id="run-1", epoch=0, stage="conclude")
    assert again["reason"] == "quota_refused"


def test_quota_refusal_stops_the_sdk_instead_of_retrying(tmp_path):
    sdk = FakeSDK([])
    gateway = MemoryPocRequestGateway()
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path, execute_requests=1),
                                    gateway=gateway, sdk=sdk, cli_probe=lambda: ("2.1.310", ""))

    def exhausting(options_):
        # One granted request, then the gateway refuses: the SDK must be stopped, not
        # handed a retryable error.
        runtime.reserve_upstream_request(EXECUTE_STAGE)
        runtime.reserve_upstream_request(EXECUTE_STAGE)
        return [ResultMessage()]

    sdk.script = [exhausting, conclude({"status": "inconclusive"})]
    events = []
    outcome = asyncio.run(run(runtime, service(tmp_path), events))

    # The refusal ended the experiment and was not retried; the conclusion, whose
    # requests were reserved first, still ran on the jobs that exist.
    assert outcome.status == "completed"
    assert outcome.usage["execute_reason"] == "quota_exhausted"
    assert len(sdk.calls) == 2
    assert "output_format" in sdk.calls[1]["options"].__dict__
    assert any(event["kind"] == "poc_runtime_quota_refused"
               and event["stage"] == EXECUTE_STAGE for event in events)
    # The conclusion's reserved requests were opened before the experiment and survive
    # the experiment stage's refusal.
    assert gateway.snapshot(run_id="run-1", epoch=1)["conclude"]["limit"] == 3


def test_store_quota_is_durable_and_per_stage(tmp_path):
    store = Store(tmp_path / "audit.db")
    try:
        store.create_run(run_payload({"id": "snap", "name": "Lab30"}, "run", []))
        run = store.claim_next_run()
        run_id, epoch = run["id"], int(run.get("execution_epoch") or 0)
        assert store.open_poc_request_stage(run_id, "conclude", 3, epoch=epoch)["ok"]
        assert store.open_poc_request_stage(run_id, "execute", 40, epoch=epoch)["ok"]
        # Re-opening cannot widen; a different stage has its own allowance.
        assert store.open_poc_request_stage(run_id, "conclude", 99, epoch=epoch)["limit"] == 3
        assert store.open_poc_request_stage(run_id, "execute", 99, epoch=epoch)["limit"] == 40

        for _ in range(3):
            assert store.reserve_poc_request(run_id, "conclude", epoch=epoch)["granted"] is True
        assert store.reserve_poc_request(run_id, "conclude", epoch=epoch)["reason"] == "quota_exhausted"
        assert store.reserve_poc_request(run_id, "conclude", epoch=epoch)["reason"] == "quota_refused"
        assert store.reserve_poc_request(run_id, "execute", epoch=epoch)["granted"] is True

        quota = store.poc_request_quota(run_id, epoch=epoch)
        assert quota["conclude"] == {"limit": 3, "used": 3, "remaining": 0, "refused": True, "refused_at": quota["conclude"]["refused_at"]}
        assert quota["conclude"]["refused_at"]
        assert quota["execute"]["used"] == 1
    finally:
        store.close()


def test_insufficient_quota_defers_before_any_experiment(tmp_path):
    sdk = FakeSDK([execute(), conclude({"status": "inconclusive"})])
    gateway = MemoryPocRequestGateway()
    gateway.open_stage(run_id="run-1", epoch=1, stage=EXECUTE_STAGE, limit=1)
    assert gateway.reserve(run_id="run-1", epoch=1, stage=EXECUTE_STAGE)["granted"] is True

    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=gateway,
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, service(tmp_path), events))

    assert outcome.status == "deferred"
    assert outcome.reason == "quota_deferred"
    assert sdk.calls == []
    assert any(event["kind"] == "poc_runtime_deferred" for event in events)


def test_a_non_success_subtype_is_not_treated_as_a_conclusion(tmp_path):
    sdk = FakeSDK([
        execute(),
        conclude({"status": "inconclusive"}, subtype="error_max_turns"),
        conclude({"status": "inconclusive"}, subtype="error_max_turns"),
    ])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, service(tmp_path), events))
    assert outcome.status == "conclusion_rejected"
    assert [event["reason"] for event in events
            if event["kind"] == "poc_runtime_conclusion_rejected"] == [
        "missing_structured_output", "missing_structured_output",
    ]


def test_every_stage_request_is_reserved_at_the_gateway_including_corrections(tmp_path):
    gateway = MemoryPocRequestGateway()
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=gateway, sdk=FakeSDK([]),
                                    cli_probe=lambda: ("2.1.310", ""))

    def reserve_and(payload):
        def handler(options_):
            stage = CONCLUDE_STAGE if hasattr(options_, "output_format") else EXECUTE_STAGE
            runtime.reserve_upstream_request(stage)
            return [ResultMessage(payload)]
        return handler

    # The first conclusion is a format failure; the retry is a second real request.
    runtime._sdk.script = [
        reserve_and(None),
        reserve_and(None),
        reserve_and({"status": "inconclusive"}),
    ]
    outcome = asyncio.run(run(runtime, service(tmp_path), []))
    assert outcome.status == "completed"
    quota = gateway.snapshot(run_id="run-1", epoch=1)
    assert quota["execute"]["used"] == 1
    assert quota["conclude"]["used"] == 2


def test_store_gateway_satisfies_the_adapter_protocol(tmp_path):
    store = Store(tmp_path / "audit.db")
    try:
        store.create_run(run_payload({"id": "snap", "name": "Lab30"}, "run", []))
        run = store.claim_next_run()
        gateway = StorePocRequestGateway(store)
        epoch = int(run.get("execution_epoch") or 0)
        opened = gateway.open_stage(run_id=run["id"], epoch=epoch, stage="conclude", limit=2)
        assert opened["ok"] is True
        assert gateway.reserve(run_id=run["id"], epoch=epoch, stage="conclude")["granted"] is True
        assert gateway.snapshot(run_id=run["id"], epoch=epoch)["conclude"]["used"] == 1
    finally:
        store.close()


# --- usage --------------------------------------------------------------------------


def test_unknown_usage_stays_unknown_instead_of_becoming_zero(tmp_path):
    sdk = FakeSDK([execute(ResultMessage()), conclude({"status": "inconclusive"}, usage={})])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    outcome = asyncio.run(run(runtime, service(tmp_path), []))

    usage = outcome.usage["usage"]
    assert usage["input_tokens"] is None
    assert usage["output_tokens"] is None
    assert usage["cost_usd"] is None


def test_usage_is_summed_across_stages(tmp_path):
    sdk = FakeSDK([
        execute(ResultMessage(usage={"input_tokens": 10, "output_tokens": 4}, cost=0.01)),
        conclude({"status": "inconclusive"},
                 usage={"input_tokens": 5, "output_tokens": 2}, cost=0.02),
    ])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    outcome = asyncio.run(run(runtime, service(tmp_path), []))
    assert outcome.usage["usage"]["input_tokens"] == 15
    assert outcome.usage["usage"]["output_tokens"] == 6
    assert outcome.usage["usage"]["cost_usd"] == pytest.approx(0.03)


# --- one ledger ---------------------------------------------------------------------


def test_the_sdk_path_adds_no_second_model_ledger_or_job_table(tmp_path):
    """The SDK owns the message loop; the host must not keep a parallel copy of it."""
    job = http_job("job-1", body="MEMBER_SESSION 200")
    deps = service(tmp_path, jobs=[job])
    jobs_before = list(deps.jobs)
    sdk = FakeSDK([
        execute(ResultMessage(usage={"input_tokens": 10, "output_tokens": 4})),
        conclude({"status": "inconclusive"},
                 usage={"input_tokens": 5, "output_tokens": 2}),
    ])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, deps, events))

    kinds = [event["kind"] for event in events]
    # The legacy loop's model ledger has no twin here: usage comes from the SDK's result
    # messages, and the only per-stage usage event is the adapter's own.
    assert "model_request" not in kinds
    assert "model_response" not in kinds
    assert kinds.count("poc_runtime_usage") == 2
    assert outcome.usage["usage"]["input_tokens"] == 15

    # Job facts still have one owner: the service table that the runner calls populate.
    assert deps.jobs == jobs_before
    assert deps.jobs[0] is job


def test_an_mcp_tool_call_is_paired_by_the_service_not_the_adapter(tmp_path):
    sdk = FakeSDK([])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    deps = service(tmp_path)
    runtime._service = deps
    runtime._stage = EXECUTE_STAGE
    events = []
    # ``verify`` attaches this same event owner; here the stage is set up directly so the
    # MCP handler can be called without an SDK stream.
    deps.execution = _StageToolExecution(events.append)
    runtime._build_mcp_server()
    handler = sdk.tools["target_status"]["handler"]

    # No runner client is attached, so the tool raises; the pairing must still be durable
    # because a call with no result reads as a hung tool in the trace.
    with pytest.raises(AttributeError):
        asyncio.run(handler({"identity": "alice"}))

    assert [event["kind"] for event in events] == ["tool_call", "tool_result"]
    assert events[0]["call_id"] == events[1]["call_id"]
    # The adapter does not add a second, MCP-level call event of its own.
    assert [event["tool"] for event in events] == ["target_status", "target_status"]


# --- cancellation -------------------------------------------------------------------


def test_a_stopped_execution_cancels_without_a_conclusion(tmp_path):
    sdk = FakeSDK([execute(), conclude({"status": "inconclusive"})])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    deps = service(tmp_path)
    deps.should_stop = lambda: True
    events = []
    outcome = asyncio.run(run(runtime, deps, events))
    assert outcome.status == "cancelled"
    assert outcome.result is None
    assert not sdk.calls


# --- SDK failures -------------------------------------------------------------------


def test_an_sdk_crash_ends_the_attempt_without_running_the_conclusion(tmp_path):
    def crash(options_):
        raise RuntimeError("process exited with 137")

    sdk = FakeSDK([crash, conclude({"status": "inconclusive"})])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, service(tmp_path), events))

    assert outcome.status == "failed"
    assert outcome.reason == "sdk_error"
    assert outcome.result is None
    assert len(sdk.calls) == 1
    assert any(event["kind"] == "poc_runtime_stage_failed" and event["stage"] == EXECUTE_STAGE
               for event in events)


def test_an_sdk_reported_error_ends_the_attempt_with_its_facts(tmp_path):
    sdk = FakeSDK([execute(ResultMessage(is_error=True, subtype="error_during_execution")),
                   conclude({"status": "inconclusive"})])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    deps = service(tmp_path, jobs=[http_job("job-1")])
    outcome = asyncio.run(run(runtime, deps, events))
    # A reported SDK error is not an answer: the attempt stops here, and the host keeps
    # the jobs it already has instead of asking the model to conclude over them.
    assert outcome.status == "failed"
    assert outcome.reason == "sdk_error"
    assert outcome.result is None
    assert [job["job_id"] for job in deps.jobs] == ["job-1"]
    assert any(event["kind"] == "poc_runtime_stage_stopped" and event["reason"] == "sdk_error"
               for event in events)


def test_an_api_error_after_jobs_can_use_only_the_reserved_conclusion(tmp_path):
    deps = service(tmp_path, jobs=[http_job(body='normal role=member\nattack role=admin')])
    refs = EvidenceRefTable.build(deps)
    body = next(ref for ref in refs._refs.values() if ref.channel == 'body')
    failed = ResultMessage(is_error=True, subtype='success')
    failed.terminal_reason = 'api_error'
    failed.stop_reason = 'stop_sequence'
    payload = {'status': 'verified', 'verdict': 'confirmed', 'summary': '两侧原始观测支持角色修改风险',
               'normal_observation': '正常身份为普通会员', 'attack_observation': '攻击后身份改变',
               'jobs': ['job-1'], 'normal_refs': [body.ref_id], 'attack_refs': [body.ref_id]}
    sdk = FakeSDK([execute(failed), conclude(payload)])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=sdk, cli_probe=lambda: ('2.1.310', ''))
    events = []
    outcome = asyncio.run(run(runtime, deps, events))
    assert outcome.result and outcome.result.status == 'verified'
    assert outcome.usage['execute_reason'] == 'sdk_api_error'
    assert len(sdk.calls) == 2
    stopped = next(e for e in events if e['kind'] == 'poc_runtime_stage_stopped')
    assert 'api_error' in stopped['message'] and 'success' not in stopped['message']
    assert len(deps.jobs) == 1  # No experiment or side effect was replayed.


def test_an_api_error_without_job_facts_does_not_spend_the_conclusion(tmp_path):
    failed = ResultMessage(is_error=True, subtype='success')
    failed.terminal_reason = 'api_error'
    sdk = FakeSDK([execute(failed)])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=sdk, cli_probe=lambda: ('2.1.310', ''))
    outcome = asyncio.run(run(runtime, service(tmp_path), []))
    assert outcome.reason == 'sdk_api_error' and outcome.result is None
    assert len(sdk.calls) == 1


def test_host_rejection_keeps_the_proposed_status_and_specific_errors(tmp_path):
    deps = service(tmp_path, jobs=[http_job('good'), http_job('failed', ok=False)])
    refs = EvidenceRefTable.build(deps)
    ref = next(ref for ref in refs._refs.values() if ref.channel == 'body')
    payload = {'status': 'verified', 'summary': '引用错了失败作业', 'jobs': ['failed'],
               'normal_observation': 'normal', 'attack_observation': 'attack',
               'normal_refs': [ref.ref_id], 'attack_refs': [ref.ref_id]}
    sdk = FakeSDK([execute(), conclude(payload), conclude({'status': 'inconclusive', 'summary': '已保存作业，引用不足以作出确定判断'})])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=sdk, cli_probe=lambda: ('2.1.310', ''))
    events = []
    outcome = asyncio.run(run(runtime, deps, events))
    rejected = next(e for e in events if e['kind'] == 'poc_runtime_conclusion_rejected')
    assert rejected['proposed_status'] == 'verified' and rejected['status'] == 'inconclusive'
    assert rejected['errors'] and 'failed' in ' '.join(rejected['errors'])
    assert rejected['job_ids'] == ['failed'] and rejected['context_id'] == 'ctx-1'
    assert outcome.result.status == 'inconclusive'


def test_sdk_cleanup_can_finish_after_two_seconds_inside_the_original_deadline(tmp_path):
    import time
    class SlowSDK(FakeSDK):
        def query(self, *, prompt, options):
            if self.calls:
                return super().query(prompt=prompt, options=options)
            self.calls.append({'prompt': prompt, 'options': options})
            async def stream():
                try:
                    await asyncio.sleep(100)
                    yield ResultMessage()
                finally:
                    await asyncio.sleep(2.05)
            return stream()
    class ShortExecute(ClaudeCodePocRuntime):
        async def _run_stage(self, **kwargs):
            if kwargs['stage'] == EXECUTE_STAGE:
                kwargs['deadline'] = time.monotonic() + .01
            return await super()._run_stage(**kwargs)
    sdk = SlowSDK([execute(), conclude({'status': 'inconclusive', 'summary': '正常清理后保留未确定结论'})])
    runtime = ShortExecute(limits=limits(tmp_path, max_seconds=10), gateway=MemoryPocRequestGateway(),
                           sdk=sdk, cli_probe=lambda: ('2.1.310', ''))
    events = []
    outcome = asyncio.run(run(runtime, service(tmp_path, jobs=[http_job()]), events))
    assert outcome.reason == 'completed' and outcome.result.status == 'inconclusive'
    assert len(sdk.calls) == 2
    assert not any(e['kind'] == 'poc_runtime_cleanup_failed' for e in events)


def test_unconfirmed_cleanup_never_opens_a_new_sdk_stage(tmp_path):
    class BlockedSDK(FakeSDK):
        def query(self, *, prompt, options):
            self.calls.append({'prompt': prompt, 'options': options})
            async def stream():
                try:
                    await asyncio.sleep(100)
                    yield ResultMessage()
                finally:
                    await released.wait()
            return stream()
    async def scenario():
        nonlocal released
        released = asyncio.Event()
        sdk = BlockedSDK([])
        runtime = ClaudeCodePocRuntime(limits=limits(tmp_path, max_seconds=.08), gateway=MemoryPocRequestGateway(),
                                       sdk=sdk, cli_probe=lambda: ('2.1.310', ''))
        events = []
        try:
            outcome = await run(runtime, service(tmp_path, jobs=[http_job()]), events)
        finally:
            released.set()
            await asyncio.sleep(.01)
        assert outcome.reason == 'sdk_cleanup_timeout' and outcome.result is None
        assert len(sdk.calls) == 1
        assert any(e['kind'] == 'poc_runtime_cleanup_failed' and e['primary_reason'] == 'budget' for e in events)
    released = None
    asyncio.run(scenario())


def test_api_error_recovery_cannot_turn_unknown_references_into_verified(tmp_path):
    failed = ResultMessage(is_error=True, subtype='success')
    failed.terminal_reason = 'api_error'
    payload = {'status': 'verified', 'summary': '伪造引用应被拒绝', 'normal_observation': 'normal', 'attack_observation': 'attack',
               'jobs': ['job-1'], 'normal_refs': ['ev-invented'], 'attack_refs': ['ev-invented']}
    sdk = FakeSDK([execute(failed)] + [conclude(payload)] * 3)
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=sdk, cli_probe=lambda: ('2.1.310', ''))
    outcome = asyncio.run(run(runtime, service(tmp_path, jobs=[http_job()]), []))
    assert outcome.result is None and outcome.status != 'completed'
    assert len(sdk.calls) <= 4  # One execute plus the existing three conclusion attempts.


def test_a_missing_mcp_builder_is_an_explicit_unavailable(tmp_path):
    class NoBuilder(FakeSDK):
        create_sdk_mcp_server = None

    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                    sdk=NoBuilder([]), cli_probe=lambda: ("2.1.310", ""))
    outcome = asyncio.run(run(runtime, service(tmp_path), []))
    assert outcome.status == "unavailable"
    assert outcome.reason == "runtime_unavailable"


# --- runtime selection --------------------------------------------------------------


def test_poc_runtime_defaults_to_legacy_and_rejects_unknown_values():
    from audit.config import PocSettings

    assert PocSettings.from_environ({}).runtime == "legacy"
    assert PocSettings.from_environ({"POC_RUNTIME": "claude_sdk"}).runtime == "claude_sdk"
    with pytest.raises(ValueError):
        PocSettings.from_environ({"POC_RUNTIME": "something-else"})


def test_a_run_can_downgrade_but_not_promote_the_runtime():
    from types import SimpleNamespace
    from audit.config import PocSettings
    from audit.poc import PocPolicy

    legacy = SimpleNamespace(poc=PocSettings(enabled=True, runtime="legacy"))
    sdk = SimpleNamespace(poc=PocSettings(enabled=True, runtime="claude_sdk"))

    assert PocPolicy.from_run({"poc_policy": {"runtime": "claude_sdk"}}, legacy).runtime == "legacy"
    assert PocPolicy.from_run({"poc_policy": {}}, legacy).runtime == "legacy"
    assert PocPolicy.from_run({"poc_policy": {}}, sdk).runtime == "claude_sdk"
    assert PocPolicy.from_run({"poc_policy": {"runtime": "claude_sdk"}}, sdk).runtime == "claude_sdk"
    assert PocPolicy.from_run({"poc_policy": {"runtime": "legacy"}}, sdk).runtime == "legacy"


def test_the_verifier_never_falls_back_to_the_legacy_loop(tmp_path, monkeypatch):
    from audit import poc
    from audit.poc import PocPolicy, PocVerifier

    calls = []

    async def legacy_agent(**kwargs):
        calls.append(kwargs)
        raise AssertionError("the claude_sdk runtime must not call the legacy loop")

    monkeypatch.setattr(poc, "run_poc_agent", legacy_agent)
    verifier = PocVerifier(store=_WiringStore(), bus=_WiringBus(),
                           settings=_WiringSettings(), client_factory=lambda: object())
    monkeypatch.setattr(verifier, "_record", lambda *a, **k: {})
    run = {"id": "run-1", "execution_epoch": 1}
    finding = {"id": "finding-1", "vulnerability_type": "mass_assignment"}

    result, reason, record, artifacts, jobs = asyncio.run(verifier._verify_with_context(
        run, finding, PocPolicy(enabled=True, runtime="claude_sdk"),
        {"ok": True, "identity": "alice"}, object(), model_config=None, context_id="ctx-1",
    ))

    assert calls == []
    assert result.status == "inconclusive"
    assert reason == "runtime_unavailable"
    assert record == {} and artifacts == {} and jobs == []
    readiness = [payload for _, kind, payload in verifier.bus.events
                 if kind == "poc_runtime_readiness"]
    # This wiring has no gateway service attached, so readiness must report that and
    # stop before any model request; every other precondition is also a valid stop.
    assert readiness and readiness[0]["reason"] in {"sdk_missing", "model_unconfigured",
                                                    "gateway_unconfigured", "workspace_unconfigured",
                                                    "gateway_service_missing"}


def test_the_verifier_still_uses_the_legacy_loop_when_that_is_the_runtime(tmp_path, monkeypatch):
    from audit import poc
    from audit.poc import PocPolicy, PocVerifier
    from audit.schemas import PocVerificationResult

    calls = []

    async def legacy_agent(**kwargs):
        calls.append(kwargs)
        return PocVerificationResult(status="inconclusive", summary="legacy"), "completed"

    monkeypatch.setattr(poc, "run_poc_agent", legacy_agent)
    verifier = PocVerifier(store=_WiringStore(), bus=_WiringBus(),
                           settings=_WiringSettings(), client_factory=lambda: object())
    monkeypatch.setattr(verifier, "_record", lambda *a, **k: {})
    result, reason, _, _, _ = asyncio.run(verifier._verify_with_context(
        {"id": "run-1", "execution_epoch": 1}, {"id": "finding-1"},
        PocPolicy(enabled=True, runtime="legacy"), {"ok": True, "identity": "alice"}, object(),
        model_config=None, context_id="ctx-1",
    ))
    assert len(calls) == 1
    assert result.status == "inconclusive" and reason == "completed"


class _WiringBus:
    def __init__(self):
        self.events = []

    def emit(self, run_id, finding_id, kind, payload):
        self.events.append((run_id, kind, payload))


class _WiringStore:
    def execution_write_allowed(self, run_id, epoch=None):
        return True


class _WiringSettings:
    poc = SimpleNamespace(enabled=True, runtime="claude_sdk", runner_url="",
                          runner_token="", target="lab30", job_seconds=30,
                          max_steps=8, max_jobs=8, max_seconds=300, browser=True,
                          max_script_bytes=32768, reset_between_findings=False,
                          reset_command="", reset_timeout=30)
    evidence_dir = None
