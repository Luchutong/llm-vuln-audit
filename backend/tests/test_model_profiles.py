"""Saved provider profiles must stay independent, private, and audit-safe.

These tests call the endpoint functions directly on a real temporary SQLite store.
They deliberately avoid TestClient so the assertions exercise the same service state
that the lifespan hook creates without starting an HTTP server or a background audit.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

from audit import app as app_module
from audit.config import ModelConfig, Settings
from audit.schemas import ModelProfileCreateRequest, ModelProfileUpdateRequest


def _request_for(state: app_module.Services) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))


def _profile(payload: dict, profile_id: str) -> dict:
    return next(item for item in payload["model_profiles"] if item["id"] == profile_id)


def _create_pending_run(state: app_module.Services, run_id: str = "profile-lock-run") -> None:
    """Create only the durable record needed for the active-run edit guard."""
    state.store.create_run({
        "id": run_id,
        "snapshot_id": "snapshot-for-lock-test",
        "snapshot_name": "lock-test.zip",
        "scope": ["index.php"],
        "prompt_id": "planner-v2",
        "prompt_label": "项目级 Planner",
        "prompt_text": "",
        "model": state.settings.model.label,
        "budgets": {"responses": 1, "tools": 0, "seconds": 30},
        "agent_policy": {},
        "task_spec": None,
        "created_at": "2026-10-15T00:00:00+00:00",
    })


@pytest.fixture
def profile_context(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    environment = ModelConfig(
        model="environment-model",
        base_url="https://environment.example/v1",
        api_key="environment-secret-for-test",
    )
    state = app_module.Services(Settings(data_dir=data_dir, model=environment))
    context = SimpleNamespace(
        state=state,
        request=_request_for(state),
        data_dir=data_dir,
        environment=environment,
        closed=False,
    )
    try:
        yield context
    finally:
        if not context.closed:
            state.store.close()


def test_profile_endpoints_keep_each_provider_connection_and_key_private(profile_context):
    """A saved profile owns its model, endpoint and encrypted credential together."""
    context = profile_context
    api_key = "stored-provider-key-3bb4c299-8e66-4a45-a310-unique"
    created = asyncio.run(app_module.create_model_profile(
        context.request,
        ModelProfileCreateRequest(
            label="独立供应商",
            model="provider-b-chat",
            base_url="https://provider-b.example/api/v1",
            api_key=api_key,
        ),
    ))

    saved = next(item for item in created["model_profiles"] if item["credential_source"] == "stored")
    assert saved["model"] == "provider-b-chat"
    assert saved["base_url"] == "https://provider-b.example/api/v1"
    assert saved["api_key_configured"] is True
    assert "api_key_secret" not in saved
    assert api_key not in json.dumps(created)

    stored = context.state.store.get_model_profile(saved["id"], include_secret=True)
    assert stored is not None
    assert stored["api_key_secret"] != api_key
    assert context.state.vault.decrypt(stored["api_key_secret"]) == api_key

    selected = asyncio.run(app_module.select_model_profile(context.request, saved["id"]))
    assert selected["selected_profile_id"] == saved["id"]
    assert context.state.settings.model.model == "provider-b-chat"
    assert context.state.settings.model.base_url == "https://provider-b.example/api/v1"
    assert context.state.settings.model.api_key == api_key
    assert api_key not in json.dumps(selected)

    # Omitting api_key while editing must retain the encrypted credential, while
    # model and Base URL can move together to a different provider endpoint.
    before_secret = stored["api_key_secret"]
    updated = asyncio.run(app_module.update_model_profile(
        context.request,
        saved["id"],
        ModelProfileUpdateRequest(
            label="独立供应商 · 新端点",
            model="provider-b-reasoner",
            base_url="https://reasoning.provider-b.example/v2",
        ),
    ))
    visible = _profile(updated, saved["id"])
    assert visible["model"] == "provider-b-reasoner"
    assert visible["base_url"] == "https://reasoning.provider-b.example/v2"
    assert "api_key_secret" not in visible
    assert api_key not in json.dumps(updated)
    reloaded = context.state.store.get_model_profile(saved["id"], include_secret=True)
    assert reloaded is not None and reloaded["api_key_secret"] == before_secret
    assert context.state.settings.model.model == "provider-b-reasoner"
    assert context.state.settings.model.base_url == "https://reasoning.provider-b.example/v2"
    assert context.state.settings.model.api_key == api_key


def test_selected_profile_survives_restart_with_its_own_connection(profile_context):
    """The selected independent provider remains active after a local restart."""
    context = profile_context
    api_key = "restart-provider-key-65a46e09-unique"
    created = asyncio.run(app_module.create_model_profile(
        context.request,
        ModelProfileCreateRequest(
            label="重启持久化供应商",
            model="restart-model",
            base_url="https://restart-provider.example/v1",
            api_key=api_key,
        ),
    ))
    profile_id = next(item["id"] for item in created["model_profiles"] if item["credential_source"] == "stored")
    asyncio.run(app_module.select_model_profile(context.request, profile_id))

    context.state.store.close()
    context.closed = True
    restarted = app_module.Services(Settings(data_dir=context.data_dir, model=context.environment))
    try:
        selected = restarted.store.selected_model_profile()
        assert selected is not None and selected["id"] == profile_id
        assert restarted.settings.model.model == "restart-model"
        assert restarted.settings.model.base_url == "https://restart-provider.example/v1"
        assert restarted.settings.model.api_key == api_key
        payload = asyncio.run(app_module.get_config(_request_for(restarted)))
        assert payload["selected_profile_id"] == profile_id
        assert api_key not in json.dumps(payload)
        assert "api_key_secret" not in _profile(payload, profile_id)
    finally:
        restarted.store.close()


def test_profile_selection_is_locked_while_an_audit_is_pending(profile_context):
    """An audit cannot silently switch to another provider after it was queued."""
    context = profile_context
    created = asyncio.run(app_module.create_model_profile(
        context.request,
        ModelProfileCreateRequest(
            label="备用供应商",
            model="backup-model",
            base_url="https://backup-provider.example/v1",
            api_key="backup-provider-key-unique",
        ),
    ))
    profile_id = next(item["id"] for item in created["model_profiles"] if item["credential_source"] == "stored")
    _create_pending_run(context.state)

    with pytest.raises(HTTPException) as raised:
        asyncio.run(app_module.select_model_profile(context.request, profile_id))

    assert raised.value.status_code == 409
    assert "审计" in str(raised.value.detail)
    selected = context.state.store.selected_model_profile()
    assert selected is not None and selected["credential_source"] == "environment"


@pytest.mark.parametrize("base_url", [
    "https://user:password@provider.example/v1",
    "https://provider.example/a\npath",
    "https://provider.example:invalid/v1",
    "https://provider.example/v1?token=value",
])
def test_saved_profile_rejects_unsafe_or_invalid_provider_urls(base_url):
    with pytest.raises(ValidationError):
        ModelProfileCreateRequest(label="供应商", model="provider-model", base_url=base_url, api_key="key")


def test_model_config_redacts_url_credentials_as_well_as_api_key():
    config = ModelConfig(
        model="environment-model",
        base_url="https://operator:url-secret@provider.example/v1?token=query-secret",
        api_key="model-api-secret",
    )
    public = json.dumps(config.public())
    error = config.redact(
        "connection to https://operator:url-secret@provider.example/v1?token=query-secret failed: model-api-secret"
    )
    assert "url-secret" not in public and "query-secret" not in public and "model-api-secret" not in public
    assert "url-secret" not in error and "query-secret" not in error and "model-api-secret" not in error
    assert "https://provider.example/v1" in error


def test_invalid_profile_key_is_redacted_from_fastapi_validation_response():
    invalid_key = "synthetic-key-must-not-return\n"
    with pytest.raises(ValidationError) as raised:
        ModelProfileCreateRequest(
            label="供应商",
            model="provider-model",
            base_url="https://provider.example/v1",
            api_key=invalid_key,
        )
    response = asyncio.run(app_module.redact_model_key_validation_error(
        SimpleNamespace(),
        RequestValidationError(raised.value.errors()),
    ))
    body = response.body.decode("utf-8")
    assert invalid_key not in body
    assert "[redacted]" in body
