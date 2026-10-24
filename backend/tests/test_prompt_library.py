"""The prompt library: add a draft, edit it, and refuse to rewrite anything already quoted.

The edit rules are the point.  A built-in is refreshed from the release, and a text a run
already used is frozen into that run's record, so "modify" cannot mean "mutate in place"
for either: the caller derives a new version and the chain stays readable.
"""
from __future__ import annotations

import asyncio

import pytest

from audit.db import Store, now
from audit.source import SourceRepository
from tests.test_goal_tasks import import_project, run_payload


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "source-data")


def draft(store, prompt_id: str = "custom-1", **overrides) -> dict:
    record = {
        "id": prompt_id,
        "label": "自写版本",
        "phase": "custom",
        "text": "阅读当前单元并给出结论。",
        "reason": "第一版",
        "issues": ["漏报"],
        "parent_id": None,
        "created_at": now(),
    }
    record.update(overrides)
    store.add_prompt(record)
    return store.get_prompt(prompt_id)


def builtin(store, prompt_id: str = "builtin-1") -> dict:
    store.upsert_builtin_prompt({
        "id": prompt_id,
        "label": "内置版本",
        "phase": "builtin",
        "text": "内置正文。",
        "reason": "",
        "issues": [],
        "created_at": now(),
    })
    return store.get_prompt(prompt_id)


def test_a_draft_can_be_edited_in_place(store):
    draft(store)

    updated = store.update_prompt("custom-1", {
        "label": "改过的标签",
        "text": "新的正文。",
        "reason": "补上证据链要求",
        "issues": ["漏报", "误报"],
    })

    assert updated["label"] == "改过的标签"
    assert updated["text"] == "新的正文。"
    assert updated["reason"] == "补上证据链要求"
    assert updated["issues"] == ["漏报", "误报"]
    assert updated["id"] == "custom-1"


def test_editing_an_unknown_prompt_raises(store):
    with pytest.raises(KeyError):
        store.update_prompt("nope", {"label": "x", "text": "y"})


def test_a_builtin_cannot_be_edited(store):
    builtin(store)
    with pytest.raises(ValueError, match="内置提示词"):
        store.update_prompt("builtin-1", {"label": "x", "text": "y"})
    assert store.get_prompt("builtin-1")["text"] == "内置正文。"


def test_a_prompt_a_run_already_quoted_cannot_be_edited(store, repository):
    draft(store)
    snapshot = import_project(repository)
    store.add_snapshot(snapshot)
    payload = run_payload(snapshot, "run-quoting-a-prompt", ["public/index.php"])
    payload["prompt_id"] = "custom-1"
    payload["prompt_label"] = "自写版本"
    payload["prompt_text"] = "阅读当前单元并给出结论。"
    store.create_run(payload)

    with pytest.raises(ValueError, match="已被 1 次审计引用"):
        store.update_prompt("custom-1", {"label": "x", "text": "y"})
    assert store.get_prompt("custom-1")["text"] == "阅读当前单元并给出结论。"


def test_the_listing_reports_how_many_runs_used_each_prompt(store, repository):
    draft(store)
    builtin(store)
    snapshot = import_project(repository)
    store.add_snapshot(snapshot)
    payload = run_payload(snapshot, "run-using-custom", ["public/index.php"])
    payload["prompt_id"] = "custom-1"
    payload["prompt_text"] = "阅读当前单元并给出结论。"
    store.create_run(payload)

    usage = {item["id"]: item["used_by_runs"] for item in store.list_prompts()}
    assert usage == {"custom-1": 1, "builtin-1": 0}


def test_a_derived_version_keeps_its_parent(store):
    draft(store)
    store.add_prompt({
        "id": "custom-2",
        "label": "第二版",
        "phase": "custom",
        "text": "新的正文。",
        "reason": "补上证据链要求",
        "issues": [],
        "parent_id": "custom-1",
        "created_at": now(),
    })

    child = store.get_prompt("custom-2")
    assert child["parent_id"] == "custom-1"
    # The parent is untouched: a new version never rewrites what it grew out of.
    assert store.get_prompt("custom-1")["text"] == "阅读当前单元并给出结论。"


def test_the_endpoint_forwards_both_the_edit_and_the_reason_it_is_refused(tmp_path):
    """The page needs a 409 with words it can show, not a silent no-op."""
    from types import SimpleNamespace

    from fastapi import HTTPException

    from audit import app as app_module
    from audit.config import ModelConfig, Settings
    from audit.schemas import PromptUpdateRequest

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    services = app_module.Services(Settings(
        data_dir=data_dir,
        model=ModelConfig(model="test-model", base_url="http://127.0.0.1:1/v1", api_key="test-key"),
    ))
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=services)))
    try:
        created = asyncio.run(app_module.create_prompt(request, app_module.PromptCreateRequest(
            label="自写版本", text="第一版正文。", reason="", issues=[],
        )))
        edited = asyncio.run(app_module.update_prompt(
            request, created["id"], PromptUpdateRequest(label="改过", text="第二版正文。", reason="原因", issues=["漏报"]),
        ))
        assert edited["label"] == "改过"
        assert edited["text"] == "第二版正文。"

        with pytest.raises(HTTPException) as missing:
            asyncio.run(app_module.update_prompt(
                request, "does-not-exist", PromptUpdateRequest(label="x", text="y"),
            ))
        assert missing.value.status_code == 404

        with pytest.raises(HTTPException) as readonly:
            asyncio.run(app_module.update_prompt(
                request, "P0", PromptUpdateRequest(label="x", text="y"),
            ))
        assert readonly.value.status_code == 409
        assert "内置" in str(readonly.value.detail)
    finally:
        services.store.close()

