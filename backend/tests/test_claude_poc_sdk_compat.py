"""Offline checks of the pinned SDK surface and a stopped, silent SDK stream.

The custom transport speaks the real SDK control protocol without starting a CLI,
contacting a model or reaching a runner.
"""
import asyncio
import json
import time
from types import SimpleNamespace

import pytest

from audit.runtime import StopAudit
from audit.runtimes.claude_poc import (
    CONCLUDE_STAGE,
    EXECUTE_STAGE,
    TOOL_NAMES,
    ClaudeCodePocRuntime,
    MemoryPocRequestGateway,
)
from tests.test_claude_poc_runtime import (
    FakeSDK,
    ResultMessage,
    conclude,
    execute,
    limits,
    run,
    service,
)


def test_cli_resolution_prefers_the_sdk_wheel(tmp_path, monkeypatch):
    package = tmp_path / "claude_agent_sdk"
    bundled = package / "_bundled" / "claude"
    bundled.parent.mkdir(parents=True)
    bundled.write_text("not executed")
    monkeypatch.setattr("audit.runtimes.claude_poc.shutil.which", lambda _: "/system/claude")

    assert ClaudeCodePocRuntime._resolve_cli_path(
        SimpleNamespace(__file__=str(package / "__init__.py")),
    ) == str(bundled)


def test_cli_probe_normalizes_the_cli_version_banner(monkeypatch):
    calls = []
    monkeypatch.setattr("audit.runtimes.claude_poc.shutil.which", lambda value: value)

    def probe(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="2.1.320 (Claude Code)\n")

    monkeypatch.setattr("audit.runtimes.claude_poc.subprocess.run", probe)
    assert ClaudeCodePocRuntime._probe_cli("/wheel/claude") == ("2.1.320", "")
    assert calls[0][0] == ["/wheel/claude", "--version"]
    assert set(calls[0][1]["env"]) <= {"PATH", "HOME", "LANG", "LC_ALL"}


def test_readiness_probes_the_executable_used_by_the_sdk(tmp_path, monkeypatch):
    sdk = pytest.importorskip("claude_agent_sdk")
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(), sdk=sdk)
    probed = []

    def probe(binary):
        probed.append(binary)
        return "2.1.320", ""

    monkeypatch.setattr(runtime, "_resolve_cli_path", lambda _: "/wheel/claude")
    monkeypatch.setattr(runtime, "_probe_cli", probe)
    assert runtime.readiness().ready
    assert probed == ["/wheel/claude"]
    options = runtime._options(EXECUTE_STAGE, runtime._build_mcp_server(), "rules")
    assert str(options.cli_path).endswith("audit/runtimes/claude_cli.py")
    assert options.env["AUDIT_POC_CLAUDE_REAL_CLI"] == "/wheel/claude"


def test_real_sdk_options_accept_only_namespaced_poc_tools(tmp_path):
    sdk = pytest.importorskip("claude_agent_sdk")
    runtime = ClaudeCodePocRuntime(
        limits=limits(tmp_path), gateway=MemoryPocRequestGateway(), sdk=sdk,
        cli_probe=lambda: ("2.1.320", ""),
    )
    options = runtime._options(EXECUTE_STAGE, runtime._build_mcp_server(), "rules")
    assert isinstance(options, sdk.ClaudeAgentOptions)
    assert options.allowed_tools == [f"mcp__poc__{name}" for name in TOOL_NAMES]
    assert options.mcp_servers["poc"]["type"] == "sdk"
    assert options.tools == []
    assert options.strict_mcp_config is True
    assert runtime._options(CONCLUDE_STAGE, None, "conclude").mcp_servers == {}


def test_readiness_requires_the_controlled_gateway_to_be_ready(tmp_path):
    class OfflineGateway(MemoryPocRequestGateway):
        def check_readiness(self):
            return {"ready": False, "reason": "upstream_unconfigured", "message": "upstream missing"}

    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=OfflineGateway(), sdk=FakeSDK([]),
                                   cli_probe=lambda: ("2.1.310", ""))
    state = runtime.readiness()
    assert not state.ready and state.reason == "upstream_unconfigured"


def test_real_sdk_query_routes_mcp_and_parses_final_structured_output_offline(tmp_path):
    sdk = pytest.importorskip("claude_agent_sdk")

    class ProtocolTransport(sdk.Transport):
        def __init__(self):
            self.queue = asyncio.Queue()
            self.closed = False
            self.tool_response = None

        async def connect(self):
            pass

        async def write(self, text):
            item = json.loads(text)
            if item["type"] == "control_request":
                assert item["request"]["subtype"] == "initialize"
                await self.queue.put({
                    "type": "control_response",
                    "response": {"subtype": "success", "request_id": item["request_id"], "response": {}},
                })
            elif item["type"] == "user":
                assert item["message"]["content"] == "exercise MCP"
                await self.queue.put({
                    "type": "control_request", "request_id": "mcp-init",
                    "request": {
                        "subtype": "mcp_message", "server_name": "poc",
                        "message": {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                                    "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                                               "clientInfo": {"name": "offline-test", "version": "1.0"}}},
                    },
                })
            elif item["type"] == "control_response":
                if item["response"]["request_id"] == "mcp-init":
                    await self.queue.put({
                        "type": "control_request", "request_id": "mcp-ready",
                        "request": {"subtype": "mcp_message", "server_name": "poc",
                                    "message": {"jsonrpc": "2.0", "method": "notifications/initialized"}},
                    })
                    return
                if item["response"]["request_id"] == "mcp-ready":
                    await self.queue.put({
                        "type": "control_request", "request_id": "mcp-call",
                        "request": {"subtype": "mcp_message", "server_name": "poc",
                                    "message": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                                "params": {"name": "url_encode", "arguments": {"value": "a b"}}}},
                    })
                    return
                self.tool_response = item["response"]["response"]["mcp_response"]
                await self.queue.put({
                    "type": "result", "subtype": "success", "is_error": False,
                    "duration_ms": 1, "duration_api_ms": 1, "num_turns": 1,
                    "session_id": "offline-session", "terminal_reason": "completed",
                    "usage": {"input_tokens": 7, "output_tokens": 3},
                    "structured_output": {"status": "inconclusive", "summary": "offline"},
                })

        async def read_messages(self):
            while True:
                item = await self.queue.get()
                if item is None:
                    return
                yield item

        async def close(self):
            self.closed = True
            await self.queue.put(None)

        def is_ready(self):
            return not self.closed

        async def end_input(self):
            await self.queue.put(None)

    async def scenario():
        transport = ProtocolTransport()
        runtime = ClaudeCodePocRuntime(
            limits=limits(tmp_path), gateway=MemoryPocRequestGateway(), sdk=sdk,
            cli_probe=lambda: ("2.1.320", ""),
        )
        runtime._service = service(tmp_path)
        runtime._stage = EXECUTE_STAGE
        options = runtime._options(EXECUTE_STAGE, runtime._build_mcp_server(), "rules")
        messages = [message async for message in sdk.query(
            prompt="exercise MCP", options=options, transport=transport,
        )]
        assert transport.closed
        assert transport.tool_response["result"]["isError"] is False
        reply = json.loads(transport.tool_response["result"]["content"][0]["text"])
        assert reply["encoded"] == "a%20b"
        assert isinstance(messages[-1], sdk.ResultMessage)
        assert messages[-1].structured_output == {"status": "inconclusive", "summary": "offline"}
        assert messages[-1].usage == {"input_tokens": 7, "output_tokens": 3}

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


class SilentSDK(FakeSDK):
    def __init__(self):
        super().__init__([])
        self.entered = asyncio.Event()
        self.closed = False
        self.owner = None
        self.closer = None

    def query(self, *, prompt, options):
        self.calls.append({"prompt": prompt, "options": options})

        async def stream():
            self.owner = asyncio.current_task()
            self.entered.set()
            try:
                await asyncio.Event().wait()
                yield ResultMessage()
            finally:
                self.closer = asyncio.current_task()
                self.closed = True
        return stream()


def test_host_stop_closes_a_silent_sdk_in_the_iteration_task(tmp_path):
    async def scenario():
        sdk = SilentSDK()
        runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                       sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
        deps = service(tmp_path)
        stopped = False
        deps.should_stop = lambda: stopped
        task = asyncio.create_task(run(runtime, deps, []))
        await sdk.entered.wait()
        stopped = True
        outcome = await asyncio.wait_for(task, timeout=1)
        assert outcome.status == "cancelled"
        assert sdk.closed and sdk.owner is sdk.closer
        assert len(sdk.calls) == 1

    asyncio.run(scenario())


def test_external_cancellation_closes_the_silent_sdk_and_propagates(tmp_path):
    async def scenario():
        sdk = SilentSDK()
        runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                       sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
        task = asyncio.create_task(run(runtime, service(tmp_path), []))
        revoked = []
        runtime._revoke_stage_capability = revoked.append
        await sdk.entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert sdk.closed and sdk.owner is sdk.closer
        assert revoked == [EXECUTE_STAGE]

    asyncio.run(scenario())


def test_real_sdk_silent_transport_is_closed_on_host_stop(tmp_path, monkeypatch):
    sdk = pytest.importorskip("claude_agent_sdk")
    real_query = sdk.query

    class IdleTransport(sdk.Transport):
        def __init__(self):
            self.queue = asyncio.Queue()
            self.entered = asyncio.Event()
            self.closed = False

        async def connect(self):
            pass

        async def write(self, text):
            item = json.loads(text)
            if item["type"] == "control_request":
                await self.queue.put({
                    "type": "control_response",
                    "response": {"subtype": "success", "request_id": item["request_id"], "response": {}},
                })
            elif item["type"] == "user":
                self.entered.set()

        async def read_messages(self):
            while True:
                item = await self.queue.get()
                if item is None:
                    return
                yield item

        async def close(self):
            self.closed = True
            await self.queue.put(None)

        def is_ready(self):
            return not self.closed

        async def end_input(self):
            await self.queue.put(None)

    async def scenario():
        transport = IdleTransport()
        monkeypatch.setattr(sdk, "query", lambda *, prompt, options: real_query(
            prompt=prompt, options=options, transport=transport,
        ))
        runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                       sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
        deps = service(tmp_path)
        stopped = False
        deps.should_stop = lambda: stopped
        task = asyncio.create_task(run(runtime, deps, []))
        await transport.entered.wait()
        stopped = True
        outcome = await asyncio.wait_for(task, timeout=1)
        assert outcome.status == "cancelled"
        assert transport.closed

    asyncio.run(scenario())


def test_a_silent_stage_deadline_stops_and_closes_its_sdk(tmp_path):
    async def scenario():
        sdk = SilentSDK()
        runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                       sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
        with pytest.raises(StopAudit) as failure:
            await runtime._run_stage(stage=EXECUTE_STAGE, server=None, prompt="", system_prompt="",
                                     deadline=time.monotonic() + 0.03)
        assert failure.value.reason == "budget"
        assert sdk.closed

    asyncio.run(scenario())


def test_durable_http_quota_refusal_keeps_the_conclusion_available(tmp_path):
    gateway = MemoryPocRequestGateway()

    class HttpRefusalSDK(FakeSDK):
        def query(self, *, prompt, options):
            self.calls.append({"prompt": prompt, "options": options})

            async def stream():
                if len(self.calls) == 1:
                    assert gateway.reserve(run_id="run-1", epoch=1, stage=EXECUTE_STAGE)["granted"]
                    assert not gateway.reserve(run_id="run-1", epoch=1, stage=EXECUTE_STAGE)["granted"]
                    # A real CLI may remain silent in its retry path after the HTTP
                    # refusal. The adapter must stop it from the durable host signal.
                    await asyncio.Event().wait()
                yield ResultMessage({"status": "inconclusive", "summary": "quota stopped"})
            return stream()

    sdk = HttpRefusalSDK([])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path, execute_requests=1), gateway=gateway,
                                   sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    outcome = asyncio.run(asyncio.wait_for(run(runtime, service(tmp_path), []), timeout=1))
    assert outcome.status == "completed"
    assert outcome.usage["execute_reason"] == "quota_exhausted"
    assert len(sdk.calls) == 2


@pytest.mark.parametrize("reason", [
    "run_budget_exhausted", "stage_budget_exhausted", "timeout", "interrupted", "stale_epoch",
])
def test_gateway_run_or_stage_refusal_is_a_host_stop(tmp_path, reason):
    class RefusingGateway(MemoryPocRequestGateway):
        def stage_refusal(self, *, run_id, epoch, stage):
            assert (run_id, epoch, stage) == ("run-1", 1, EXECUTE_STAGE)
            return {"reason": reason}

    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=RefusingGateway(),
                                   sdk=FakeSDK([]), cli_probe=lambda: ("2.1.310", ""))
    runtime._run_id, runtime._epoch = "run-1", 1
    with pytest.raises(StopAudit) as failure:
        asyncio.run(runtime._run_stage(stage=EXECUTE_STAGE, server=None, prompt="", system_prompt="",
                                       deadline=time.monotonic() + 1))
    assert failure.value.reason == ("interrupted" if reason == "stale_epoch" else reason)
    assert runtime._sdk.calls == []


@pytest.mark.parametrize("terminal_reason", ["aborted_streaming", "aborted_tools", "max_turns"])
def test_sdk_terminal_stop_is_never_an_accepted_conclusion(tmp_path, terminal_reason):
    result = ResultMessage({"status": "inconclusive", "summary": "unfinished"})
    result.terminal_reason = terminal_reason
    sdk = FakeSDK([execute(), lambda _: [result]])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    outcome = asyncio.run(run(runtime, service(tmp_path), []))
    assert outcome.result is None
    assert outcome.reason.startswith("stopped:")


def test_sdk_error_text_cannot_impersonate_gateway_quota_refusal(tmp_path):
    sdk = FakeSDK([lambda _: (_ for _ in ()).throw(RuntimeError("quota_exhausted")),
                   conclude({"status": "inconclusive"})])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    outcome = asyncio.run(run(runtime, service(tmp_path), []))
    assert outcome.reason == "sdk_error"
    assert len(sdk.calls) == 1


def _sdk_result_then_exception(real_sdk, final, failure):
    """The pinned SDK yields an error result before its typed exit exception."""
    class ErrorResultSDK(FakeSDK):
        ResultError = real_sdk.ResultError

        def query(self, *, prompt, options):
            index = len(self.calls)
            self.calls.append({"prompt": prompt, "options": options})

            async def stream():
                if index == 0:
                    if final is not None:
                        yield final
                    raise failure
                yield real_sdk.ResultMessage(
                    subtype="success", duration_ms=1, duration_api_ms=1, is_error=False,
                    num_turns=1, session_id="offline-conclusion", terminal_reason="completed",
                    structured_output={"status": "inconclusive", "summary": "offline conclusion"},
                )

            return stream()

    return ErrorResultSDK([])


@pytest.mark.parametrize("subtype,terminal,expected_reason", [
    ("error_max_turns", "max_turns", "turn_limit"),
    ("error_max_budget_usd", "max_budget_usd", "budget"),
])
def test_real_sdk_error_result_exit_preserves_the_reserved_conclusion(
    tmp_path, caplog, subtype, terminal, expected_reason,
):
    real_sdk = pytest.importorskip("claude_agent_sdk")
    private = "fake-credential-and-private-error-result"
    final = real_sdk.ResultMessage(
        subtype=subtype, duration_ms=1, duration_api_ms=1, is_error=True,
        num_turns=6, session_id="offline-execution", terminal_reason=terminal,
        usage={"input_tokens": 7, "output_tokens": 3}, errors=[private],
    )
    failure = real_sdk.ResultError(private, data={
        "subtype": subtype, "is_error": True, "terminal_reason": terminal,
        "session_id": "offline-execution", "errors": [private],
    }, exit_code=1)
    sdk = _sdk_result_then_exception(real_sdk, final, failure)
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, service(tmp_path), events))

    assert outcome.status == "completed" and outcome.reason == "completed"
    assert outcome.result.status == "inconclusive"
    assert outcome.usage["execute_reason"] == expected_reason
    assert len(sdk.calls) == 2 and sdk.calls[1]["options"].mcp_servers == {}
    assert private not in json.dumps(events) and private not in caplog.text


@pytest.mark.parametrize("mismatch", [
    "missing_final", "subtype", "terminal_reason", "successful_final", "ordinary_exception",
])
def test_real_sdk_exit_exception_without_a_matching_error_result_fails_closed(tmp_path, caplog, mismatch):
    real_sdk = pytest.importorskip("claude_agent_sdk")
    private = "fake-credential-and-private-unmatched-exception"
    final = real_sdk.ResultMessage(
        subtype="error_max_turns", duration_ms=1, duration_api_ms=1, is_error=True,
        num_turns=6, session_id="offline-execution", terminal_reason="max_turns",
    )
    data = {"subtype": "error_max_turns", "is_error": True,
            "terminal_reason": "max_turns", "session_id": "offline-execution"}
    if mismatch == "missing_final":
        final = None
    elif mismatch == "subtype":
        data["subtype"] = "error_during_execution"
    elif mismatch == "terminal_reason":
        data["terminal_reason"] = "api_error"
    elif mismatch == "successful_final":
        final.is_error = False
    failure = (RuntimeError(private) if mismatch == "ordinary_exception"
               else real_sdk.ResultError(private, data=data, exit_code=1))
    sdk = _sdk_result_then_exception(real_sdk, final, failure)
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, service(tmp_path), events))

    assert outcome.status == "failed" and outcome.reason == "sdk_error"
    assert outcome.result is None and len(sdk.calls) == 1
    assert private not in json.dumps(events) and private not in caplog.text
