"""App wiring with a temporary Store and ASGI; no lifespan or upstream calls."""
from __future__ import annotations

import asyncio

import httpx
import pytest

from audit import app as app_module
from audit.config import ModelConfig, Settings
from audit.poc_model_gateway import PROTOCOL_VERSION


@pytest.mark.parametrize("enabled", [False, True])
def test_services_share_gateway_with_store_and_mount_internal_routes(tmp_path, monkeypatch, enabled):
    def forbidden(*args, **kwargs):
        raise AssertionError("App wiring must not read .env, run lifespan or contact a model")

    monkeypatch.setattr(app_module, "find_env_file", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
    monkeypatch.setenv("POC_CLAUDE_GATEWAY_ENABLED", "1" if enabled else "0")
    monkeypatch.setenv("POC_CLAUDE_UPSTREAM_URL", "https://model.invalid/anthropic")
    monkeypatch.setenv("POC_CLAUDE_UPSTREAM_API_KEY", "offline-provider-key")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    state = app_module.Services(Settings(
        data_dir=data_dir,
        model=ModelConfig(model="offline-model", base_url="https://model.invalid/v1", api_key="offline-key"),
    ))
    monkeypatch.setattr(app_module.app.state, "services", state, raising=False)
    try:
        assert state.poc_gateway is state.store._poc_model_gateway
        assert state.poc_gateway.store is state.store
        assert state.store.path == str(data_dir / "audit.db")

        async def exercise():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_module.app),
                                         base_url="http://host.invalid") as client:
                health = await client.get("/api/internal/poc-gateway/health")
                assert health.status_code == 200
                assert health.json() == {
                    "ready": enabled, "reason": "ready" if enabled else "disabled",
                    "protocol_version": PROTOCOL_VERSION, "upstream_configured": True,
                }
                for path in ("/v1/messages", "/v1/messages/count_tokens"):
                    result = await client.post("/api/internal/poc-gateway" + path,
                                               json={"model": "offline-model", "messages": []})
                    assert result.status_code == (401 if enabled else 400)
                    assert result.json()["error"]["code"] == (
                        "poc_gateway_capability_rejected" if enabled else "poc_gateway_unavailable")
                    assert "offline-provider-key" not in result.text

        asyncio.run(exercise())
    finally:
        state.store.close()
