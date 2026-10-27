"""All preflight traffic here is a fake, never a real runner/model."""
import asyncio
from types import SimpleNamespace

import pytest

from audit.config import PocSettings
from audit.poc_readiness import PocReadinessService, normalize_poc_mode
from audit.poc_runner import PocRunnerUnavailable


class Client:
    def __init__(self):
        self.calls = 0
        self.delay = 0
        self.healthy = True
        self.closed = 0

    async def health(self):
        self.calls += 1
        await asyncio.sleep(self.delay)
        if not self.healthy:
            raise PocRunnerUnavailable("private internal URL and token must not leak")
        return {"ok": True, "capabilities": {"python": True, "browser": False, "verification_contexts": True, "identity_preconditions": True, "idempotent_jobs": True, "idempotent_http_jobs": True, "idempotent_browser_jobs": True}, "token": "private"}

    async def aclose(self):
        self.closed += 1


@pytest.mark.parametrize("policy,task,expected", [
    ({"mode": "off", "enabled": True}, {"require_poc": True}, ("off", False)),
    ({"enabled": False}, {"require_poc": True}, ("required", True)),
    ({"enabled": True}, {"require_poc": False}, ("auto", True)),
    ({"enabled": False}, {}, ("off", True)),
    ({}, {}, ("off", True)),
])
def test_legacy_mode_uses_actual_frozen_gate(policy, task, expected):
    assert normalize_poc_mode({"poc_policy": policy, "task_spec": task}) == expected


@pytest.mark.parametrize("mode,profile,enabled,url,reason", [
    ("off", "lab30", True, "http://runner", "disabled"),
    ("auto", "unknown", True, "http://runner", "unsupported_target"),
    ("required", "lab30", False, "http://runner", "disabled"),
    ("auto", "lab30", True, "", "runner_unconfigured"),
])
def test_obvious_unavailability_never_contacts_runner(mode, profile, enabled, url, reason):
    def forbidden():
        raise AssertionError("No client should be created")
    service = PocReadinessService(SimpleNamespace(poc=PocSettings(enabled=enabled, runner_url=url)), client_factory=forbidden)
    result = asyncio.run(service.check(profile, mode=mode))
    assert not result["available"] and result["reason"] == reason
    assert result["capabilities"]["supported_targets"] == ["lab30"]


def test_health_cache_coalesces_and_fresh_bypasses_cached_answers():
    async def scenario():
        client = Client()
        client.delay = .01
        service = PocReadinessService(SimpleNamespace(poc=PocSettings(runner_url="http://private", runner_token="private")), client_factory=lambda: client)
        first, second = await asyncio.gather(service.check("lab30"), service.check("lab30", mode="required", fresh=True))
        assert first["available"] and second["mode"] == "required"
        assert client.calls == 1
        await service.check("lab30")
        assert client.calls == 1
        await service.check("lab30", fresh=True)
        assert client.calls == 2
        client.healthy = False
        unhealthy = await service.check("lab30", fresh=True)
        assert unhealthy["reason"] == "runner_unhealthy"
        assert "private" not in str(unhealthy)
        assert client.closed == 3
    asyncio.run(scenario())


def test_health_timeout_is_bounded_and_failures_have_short_cache():
    async def scenario():
        client = Client()
        client.delay = 1
        clock = [0.0]
        service = PocReadinessService(SimpleNamespace(poc=PocSettings(runner_url="http://runner")), client_factory=lambda: client, clock=lambda: clock[0], timeout=.01)
        assert (await service.check("lab30"))["reason"] == "runner_unhealthy"
        clock[0] = 4.9
        await service.check("lab30")
        assert client.calls == 1
        clock[0] = 5.1
        await service.check("lab30")
        assert client.calls == 2
    asyncio.run(scenario())


def test_lab30_is_a_supported_target():
    """Lab30 shop joins Lab30: profile/target pair must not be refused offline."""
    async def scenario():
        client = Client()
        service = PocReadinessService(
            SimpleNamespace(poc=PocSettings(runner_url="http://runner")),
            client_factory=lambda: client,
        )
        # lab30 profile + lab30 target reaches the runner health check instead of
        # being rejected as unsupported; unknown profile is still rejected.
        lab30 = await service.check("lab30", target="lab30")
        assert lab30["reason"] == "ready"
        unknown = await service.check("some-other-lab", target="lab30")
        assert unknown["reason"] == "unsupported_target"
    asyncio.run(scenario())


@pytest.mark.parametrize('missing', [
    'verification_contexts', 'identity_preconditions', 'idempotent_jobs',
    'idempotent_http_jobs', 'idempotent_browser_jobs',
])
def test_missing_required_runner_capability_requests_upgrade(missing):
    class OldClient(Client):
        async def health(self):
            health = await super().health()
            health['capabilities'].pop(missing)
            return health
    client = OldClient()
    service = PocReadinessService(SimpleNamespace(poc=PocSettings(runner_url='http://runner')),
                                  client_factory=lambda: client)
    result = asyncio.run(service.check('lab30', mode='auto'))
    assert not result['available'] and result['reason'] == 'runner_upgrade_required'
    assert '重建 poc-runner' in result['message']
    assert result['capabilities'][missing] is False
