"""Run records freeze a public provider identity without persisting credentials."""
from __future__ import annotations

import asyncio
import json
import sqlite3
from types import SimpleNamespace

import pytest

from audit import app as app_module
from audit.config import ModelConfig, Settings
from audit.db import Store
from audit.schemas import CreateRunRequest


TASK = {
    "objective": "追踪入口参数经过认证边界到敏感文件操作的跨文件路径。",
    "success_criteria": "保存至少一条带有原始源码行号的目标相关发现，或说明已规划路径为何不可达。",
    "max_iterations": 2,
    "max_total_attempts": 8,
    "max_planner_rounds": 2,
    "max_workers": 1,
    "stop_on_achieved": True,
    "require_poc": False,
}


def _request_for(state: app_module.Services) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))


def _queue_run(state: app_module.Services) -> dict:
    """Queue through the API function with a small immutable project-map stand-in."""
    state.repository.get_snapshot = lambda snapshot_id: {
        "id": snapshot_id,
        "name": "frozen-source.zip",
        "files": [{"path": "index.php", "is_php": True, "excluded": False}],
    }
    state.repository.build_project_map = lambda snapshot_id, scope: {
        "files": [{"path": "index.php"}],
        "stats": {"files": 1},
    }
    payload = CreateRunRequest(snapshot_id="snapshot-frozen", task=TASK)
    return asyncio.run(app_module.create_run(_request_for(state), payload))


def test_new_run_freezes_selected_profile_and_worker_uses_it_after_restart(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    environment = ModelConfig(
        model="environment-model",
        base_url="https://environment.example/v1",
        api_key="environment-key-for-run-snapshot",
    )
    state = app_module.Services(Settings(data_dir=data_dir, model=environment))
    saved_key = "stored-profile-key-never-in-a-run"
    state_closed = False
    try:
        environment_profile = state.store.selected_model_profile(include_secret=True)
        assert environment_profile is not None
        saved = state.store.create_model_profile(
            label="独立审计供应商",
            model="frozen-provider-model",
            base_url="https://provider.example/api/v1",
            api_key_secret=state.vault.encrypt(saved_key),
        )
        app_module._activate_profile(state, saved)

        created = _queue_run(state)
        expected = {
            "profile_id": saved["id"],
            "model": "frozen-provider-model",
            "base_url": "https://provider.example/api/v1",
        }
        assert created["model_profile"] == expected
        assert saved_key not in json.dumps(created)
        raw = state.store._row("SELECT model_profile FROM runs WHERE id = ?", (created["id"],))
        assert raw is not None
        assert saved_key not in raw["model_profile"]
        assert "api_key" not in raw["model_profile"]

        # Simulate a restart whose currently selected profile has changed outside
        # the normal active-run API guard. The queued run must still resolve the
        # frozen profile rather than the newly selected environment connection.
        state.store.select_model_profile(environment_profile["id"])
        state.store.close()
        state_closed = True
        restarted = app_module.Services(Settings(data_dir=data_dir, model=environment))
        try:
            assert restarted.settings.model.model == "environment-model"
            frozen = restarted.store.get_run(created["id"])
            assert frozen is not None and frozen["model_profile"] == expected
            config = restarted.worker._model_for_run(frozen)
            assert config.model == expected["model"]
            assert config.base_url == expected["base_url"]
            assert config.api_key == saved_key

            # A completed run may release its profile. Its public snapshot remains
            # in both persistence and the normal run API after profile deletion.
            restarted.store.update_run(created["id"], status="completed")
            assert restarted.store.delete_model_profile(saved["id"])
            historical = restarted.store.get_run(created["id"])
            assert historical is not None and historical["model_profile"] == expected
            with pytest.raises(RuntimeError, match="Frozen model profile is unavailable"):
                restarted.worker._model_for_run(historical)
        finally:
            restarted.store.close()
    finally:
        if not state_closed:
            state.store.close()


def test_run_snapshot_strips_url_credentials_and_never_returns_api_key(tmp_path):
    secret_in_url = "url-user-secret"
    model_key = "environment-api-key-never-in-a-run"
    original_url = f"https://operator:{secret_in_url}@environment.example/v1?token=query-secret"
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    state = app_module.Services(Settings(
        data_dir=data_dir,
        model=ModelConfig(
            model="environment-model",
            base_url=original_url,
            api_key=model_key,
        ),
    ))
    try:
        created = _queue_run(state)
        profile = created["model_profile"]
        assert profile["model"] == "environment-model"
        assert profile["base_url"] == "https://environment.example/v1"
        assert secret_in_url not in json.dumps(created)
        assert model_key not in json.dumps(created)

        # The environment profile may use a legacy compatibility URL at runtime,
        # but neither the config catalogue nor the public run snapshot can expose
        # its user-info or query string.
        config_payload = asyncio.run(app_module.get_config(_request_for(state)))
        assert secret_in_url not in json.dumps(config_payload)
        assert "query-secret" not in json.dumps(config_payload)
        environment_profile = next(item for item in config_payload["model_profiles"] if item["selected"])
        assert environment_profile["base_url"] == "https://environment.example/v1"

        # The worker resolves credentials by profile id and retains the original
        # in-memory endpoint. A public snapshot must not accidentally strip a
        # compatibility query parameter from the actual connection.
        resolved = state.worker._model_for_run(created)
        assert resolved.base_url == original_url
        assert resolved.api_key == model_key
    finally:
        state.store.close()


def test_existing_sqlite_runs_gain_an_empty_profile_snapshot(tmp_path):
    path = tmp_path / "legacy-audit.db"
    connection = sqlite3.connect(path)
    try:
        connection.executescript("""
            CREATE TABLE runs (
                id TEXT PRIMARY KEY,
                snapshot_id TEXT NOT NULL,
                snapshot_name TEXT NOT NULL,
                scope TEXT NOT NULL,
                prompt_id TEXT NOT NULL,
                prompt_label TEXT NOT NULL,
                prompt_text TEXT NOT NULL,
                model TEXT NOT NULL,
                budgets TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                error TEXT
            );
            INSERT INTO runs (id, snapshot_id, snapshot_name, scope, prompt_id, prompt_label,
                              prompt_text, model, budgets, status, created_at)
            VALUES ('legacy-run', 's1', 'legacy.zip', '[]', 'P1', 'P1', '', 'legacy-model', '{}', 'completed', '2026-10-15T00:00:00+00:00');
        """)
        connection.commit()
    finally:
        connection.close()

    store = Store(path)
    try:
        names = {row["name"] for row in store._rows("PRAGMA table_info(runs)")}
        assert "model_profile" in names
        legacy = store.get_run("legacy-run")
        assert legacy is not None
        assert legacy["model_profile"] == {}
    finally:
        store.close()
