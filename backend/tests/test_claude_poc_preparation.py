"""Preparation regression: only fake credentials, transports and temporary files."""
import asyncio
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from audit.poc import PocPolicy, PocVerifier
from audit.runtime import StopAudit
from audit.runtimes.claude_cli import clean_environment
from audit.runtimes.claude_poc import (
    ClaudeCodePocRuntime, MemoryPocRequestGateway, PocRuntimeOutcome,
    StorePocRequestGateway, _StageToolExecution, _public_url,
)
from tests.test_claude_poc_runtime import FakeSDK, conclude, execute, limits, run, service


def test_cli_process_removes_inherited_provider_routes_and_credentials(tmp_path):
    fake = tmp_path / "fake-cli"
    fake.write_text(f"#!{sys.executable}\nimport json, os, sys\n"
                    "print(json.dumps({'args':sys.argv[1:], 'keys':sorted(os.environ), "
                    "'gateway':os.environ.get('ANTHROPIC_BASE_URL')}))\n")
    fake.chmod(0o700)
    wrapper = Path(__file__).parents[1] / "audit/runtimes/claude_cli.py"
    env = {
        "PATH": "/usr/bin:/bin", "AUDIT_POC_CLAUDE_REAL_CLI": str(fake),
        "ANTHROPIC_BASE_URL": "http://127.0.0.1/mock-gateway", "ANTHROPIC_AUTH_TOKEN": "fake-capability",
        "ANTHROPIC_API_KEY": "fake-provider-key", "ANTHROPIC_CUSTOM_HEADERS": "fake-header",
        "CLAUDE_CODE_OAUTH_TOKEN": "fake-oauth", "CLAUDE_CODE_USE_BEDROCK": "1",
        "AWS_ACCESS_KEY_ID": "fake-cloud-key", "HTTPS_PROXY": "http://unused-proxy",
    }
    result = subprocess.run([sys.executable, str(wrapper), "--version"], env=env,
                            capture_output=True, text=True, timeout=5, check=True)
    payload = json.loads(result.stdout)
    assert payload["args"] == ["--version"]
    assert payload["gateway"] == env["ANTHROPIC_BASE_URL"]
    assert "ANTHROPIC_AUTH_TOKEN" in payload["keys"]
    assert not set(payload["keys"]) & {
        "AUDIT_POC_CLAUDE_REAL_CLI", "ANTHROPIC_API_KEY", "ANTHROPIC_CUSTOM_HEADERS",
        "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "AWS_ACCESS_KEY_ID", "HTTPS_PROXY",
    }
    assert env["ANTHROPIC_API_KEY"] == "fake-provider-key"


def test_environment_does_not_mutate_its_caller():
    source = {"PATH": "/bin", "ANTHROPIC_API_KEY": "fake-secret", "DISABLE_AUTOUPDATER": "0"}
    cleaned = clean_environment(source)
    assert cleaned["DISABLE_AUTOUPDATER"] == "1"
    assert "ANTHROPIC_API_KEY" not in cleaned
    assert source["DISABLE_AUTOUPDATER"] == "0"


def test_public_gateway_url_excludes_all_credential_locations():
    assert _public_url("https://user:fake-secret@example.test/api?key=fake-secret#token") == "https://example.test/api"


def test_store_bridge_preserves_trusted_refusal_after_capability_cleanup():
    class Registry:
        refusal = {}
        revoked = []
        def issue_capability(self, **kwargs):
            return "fake-token"
        def refusal_for_capability(self, token):
            return self.refusal
        def revoke_capability(self, token):
            self.revoked.append(token)
            self.refusal = {}

    registry = Registry()
    gateway = StorePocRequestGateway(SimpleNamespace(_poc_model_gateway=registry))
    token = gateway.issue_capability(run_id="run", epoch=2, stage="execute")
    registry.refusal = {"reason": "run_budget_exhausted"}
    gateway.revoke_capability(token)
    assert registry.revoked == [token]
    assert gateway.stage_refusal(run_id="run", epoch=2, stage="execute") == {"reason": "run_budget_exhausted"}
    assert gateway.stage_refusal(run_id="other", epoch=2, stage="execute") == {}


@pytest.mark.parametrize("reason", ["run_budget_exhausted", "stage_budget_exhausted", "interrupted", "batch_deadline_exceeded"])
def test_global_refusal_never_starts_a_conclusion_sdk(tmp_path, reason):
    class RefusingGateway(MemoryPocRequestGateway):
        def stage_refusal(self, **kwargs):
            return {"reason": reason}
    sdk = FakeSDK([execute(), conclude({"status": "inconclusive", "summary": "unused"})])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=RefusingGateway(), sdk=sdk,
                                   cli_probe=lambda: ("2.1.310", ""))
    outcome = asyncio.run(run(runtime, service(tmp_path), []))
    assert outcome.status == ("cancelled" if reason == "interrupted" else "failed")
    assert outcome.reason == reason
    assert sdk.calls == []


def test_sdk_tools_use_host_budget_before_incrementing_local_sequence():
    calls = []
    def refuse():
        calls.append("admission")
        raise StopAudit("run_budget_exhausted", "tools")
    execution = _StageToolExecution(lambda _: None, admit=refuse)
    with pytest.raises(StopAudit):
        execution.before_tool()
    assert calls == ["admission"]
    assert execution.tools == 0


def test_sdk_inherits_the_remaining_attempt_policy(tmp_path, monkeypatch):
    deps = service(tmp_path)
    deps.policy.update(max_seconds=7, max_responses=5)
    monkeypatch.setenv("POC_CLAUDE_MAX_SECONDS", "300")
    monkeypatch.setenv("POC_CLAUDE_EXECUTE_REQUESTS", "40")
    monkeypatch.setenv("POC_CLAUDE_CONCLUDE_REQUESTS", "3")
    captured = []
    async def verify(runtime, **kwargs):
        captured.append(runtime.limits)
        return PocRuntimeOutcome("completed", None, "completed", {})
    monkeypatch.setattr(ClaudeCodePocRuntime, "verify", verify)
    verifier = PocVerifier.__new__(PocVerifier)
    verifier.store = SimpleNamespace()
    asyncio.run(verifier._verify_with_sdk({"execution_epoch": 2}, deps, lambda _: None, "run"))
    assert captured[0].max_seconds == 7
    assert captured[0].execute_requests == 2
    assert captured[0].conclude_requests == 3


def test_missing_sdk_configuration_never_prepares_or_closes_a_target(tmp_path):
    verifier = PocVerifier.__new__(PocVerifier)
    verifier.bus = SimpleNamespace(emit=lambda *args: None)
    verifier._sdk_readiness = lambda *args, **kwargs: {"ready": False, "reason": "gateway_disabled"}
    verifier._record = lambda *args, **kwargs: {"reason": kwargs["reason"]}
    class NoRunnerActions:
        def __getattr__(self, name):
            raise AssertionError("runner action attempted: " + name)
    result, reason, record, artifacts, jobs = asyncio.run(verifier.verify_finding(
        {"id": "run"}, {"id": "finding"}, PocPolicy(runtime="claude_sdk"), {}, NoRunnerActions(),
        model_config=None,
    ))
    assert result.status == "inconclusive"
    assert reason == record["reason"] == "runtime_unavailable"
    assert artifacts == {} and jobs == []


def test_adapter_and_http_gateway_share_capabilities_and_real_admission_counts(tmp_path):
    import httpx
    from fastapi import FastAPI
    from audit.db import Store
    from audit.poc_model_gateway import PocModelGateway, router
    from tests.test_goal_tasks import run_payload
    from tests.test_claude_poc_runtime import ResultMessage

    store = Store(tmp_path / "offline-integration.sqlite")
    payload = run_payload({"id": "snapshot", "name": "offline"}, "run-1", [])
    payload["run_limits"] = {"responses": 10, "tools": 50, "seconds": 1800}
    store.create_run(payload)
    claimed = store.claim_next_run()
    observed = []
    provider_key = "fake-provider-host-only"
    def upstream(request):
        assert request.headers["x-api-key"] == provider_key
        observed.append(request)
        return httpx.Response(200, json={"offline": True})
    registry = PocModelGateway(store, enabled=True, upstream_url="https://model.invalid",
                                upstream_api_key=provider_key, transport=httpx.MockTransport(upstream))
    store._poc_model_gateway = registry
    app = FastAPI()
    app.state.services = SimpleNamespace(poc_gateway=registry)
    app.include_router(router, prefix="/api/internal/poc-gateway")
    issued_tokens = []
    class HttpSDK(FakeSDK):
        def query(self, *, prompt, options):
            stage = "execute" if options.mcp_servers else "conclude"
            self.calls.append({"prompt": prompt, "options": options})
            async def stream():
                token = options.env["ANTHROPIC_AUTH_TOKEN"]
                issued_tokens.append(token)
                assert token != provider_key
                assert provider_key not in json.dumps(options.env)
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                             base_url="http://host.invalid") as client:
                    response = await client.post("/api/internal/poc-gateway/v1/messages",
                        json={"model": options.model, "max_tokens": 10, "messages": []},
                        headers={"Authorization": "Bearer " + token})
                assert response.status_code == 200
                yield ResultMessage({"status": "inconclusive", "summary": "offline only"}
                                    if stage == "conclude" else None)
            return stream()
    sdk = HttpSDK([])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=StorePocRequestGateway(store),
                                   sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    events = []
    try:
        outcome = asyncio.run(runtime.verify(service=service(tmp_path), emit=events.append,
                                              run_id="run-1", epoch=claimed["execution_epoch"]))
        assert outcome.status == "completed"
        assert outcome.result.status == "inconclusive"
        assert len(observed) == len(issued_tokens) == 2
        assert issued_tokens[0] != issued_tokens[1]
        assert all(not registry.refusal_for_capability(token) for token in issued_tokens)
        assert registry._capabilities == {}
        assert store.execution_summary("run-1")["run_usage"]["responses"] == 2
        assert outcome.usage["requests"]["execute"]["used"] == 1
        assert outcome.usage["requests"]["conclude"]["used"] == 1
        assert outcome.usage["runtime"]["cli_version"] == "2.1.310"
        assert outcome.usage["runtime"]["capability"] is True
        assert provider_key not in json.dumps(events)
    finally:
        store.close()


def test_all_sdk_stages_treat_at_paths_and_slash_commands_as_verbatim_data(tmp_path):
    sdk = FakeSDK([execute(), conclude({"status": "inconclusive", "summary": "offline"})])
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=sdk, cli_probe=lambda: ("2.1.310", ""))
    outcome = asyncio.run(run(runtime, service(tmp_path), []))
    assert outcome.status == "completed"
    assert all(options.verbatim_prompts is True for options in sdk.stage_options())


def test_a_cli_that_cannot_preserve_verbatim_data_is_not_ready(tmp_path):
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=FakeSDK([]), cli_probe=lambda: ("2.1.247", ""))
    assert runtime.readiness().reason == "cli_verbatim_unsupported"


def test_raw_sdk_exception_text_never_enters_durable_events(tmp_path):
    secret = "fake-api-key-and-private-model-text"
    class CrashingSDK(FakeSDK):
        def query(self, **kwargs):
            raise RuntimeError(secret)
    runtime = ClaudeCodePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
                                   sdk=CrashingSDK([]), cli_probe=lambda: ("2.1.310", ""))
    events = []
    outcome = asyncio.run(run(runtime, service(tmp_path), events))
    assert outcome.reason == "sdk_error"
    assert secret not in json.dumps(events)
    assert any(event.get("error") == "RuntimeError" for event in events)
