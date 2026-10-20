"""The upload and run API bind conversations to projects, not to archive bytes."""
from __future__ import annotations

import asyncio
import io
import zipfile
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.datastructures import UploadFile

from audit import app as app_module
from audit.config import ModelConfig, Settings
from audit.schemas import CreateRunRequest, TaskSpec


def _zip(files: dict[str, str], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for path, body in files.items():
            archive.writestr(path, body)
    return buffer.getvalue()


def _request(state: app_module.Services) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))


@pytest.fixture
def state(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    settings = Settings(
        data_dir=data_dir,
        model=ModelConfig(model="test-model", base_url="http://127.0.0.1:1/v1", api_key="test-key"),
    )
    services = app_module.Services(settings)
    yield services
    services.store.close()


def _upload(state, data: bytes, name: str = "app.zip") -> dict:
    upload = UploadFile(filename=name, file=io.BytesIO(data))
    return asyncio.run(app_module.create_snapshot(_request(state), upload))


PROJECT = {
    "index.php": "<?php echo 1;\n",
    "includes/auth.php": "<?php function login() { return 1; }\n",
}


def test_the_same_archive_twice_reuses_the_snapshot_and_the_project(state):
    data = _zip(PROJECT)

    first = _upload(state, data)
    second = _upload(state, data)

    assert first["snapshot_reused"] is False
    assert first["project_id"]
    assert second["snapshot_reused"] is True
    assert second["id"] == first["id"]
    assert second["project_id"] == first["project_id"]
    assert second["project"] == first["project"]


def test_the_same_tree_with_different_archive_bytes_is_the_same_project(state):
    first = _upload(state, _zip(PROJECT, compression=zipfile.ZIP_DEFLATED))
    second = _upload(state, _zip(PROJECT, compression=zipfile.ZIP_STORED))

    assert second["snapshot_reused"] is False
    assert second["id"] != first["id"]
    assert second["project_id"] == first["project_id"]
    assert second["project_reused"] is True
    assert second["project"]["snapshot_count"] == 2


def test_a_changed_text_file_creates_a_new_project(state):
    first = _upload(state, _zip(PROJECT))
    changed = {**PROJECT, "includes/auth.php": "<?php function login() { return 2; }\n"}
    second = _upload(state, _zip(changed))

    assert second["project_id"] != first["project_id"]


def test_create_run_request_requires_exactly_one_scope():
    task = TaskSpec(objective="审计这个项目中的全部入口与危险操作", success_criteria="给出可复现的漏洞结论")

    with pytest.raises(ValidationError):
        CreateRunRequest(snapshot_id="s", project_id="p", task=task)
    with pytest.raises(ValidationError):
        CreateRunRequest(task=task)
    assert CreateRunRequest(snapshot_id="s", task=task).snapshot_id == "s"
    assert CreateRunRequest(project_id="p", task=task).project_id == "p"


def test_an_omitted_acceptance_freezes_the_platform_default():
    """The start screen asks only for the objective.

    The second editable text box is gone, so the client omits ``success_criteria``; the
    frozen task spec therefore carries the model default, not an empty string and not a
    client-side duplicate of the wording.
    """
    created = CreateRunRequest(snapshot_id="s", task={"objective": "审计这个项目中的全部入口与危险操作"})

    assert created.task.success_criteria == TaskSpec(
        objective="审计这个项目中的全部入口与危险操作"
    ).success_criteria
    assert "原始行号证据" in created.task.success_criteria


def test_project_endpoints_report_the_ledger_and_counter(state):
    uploaded = _upload(state, _zip(PROJECT))

    listed = asyncio.run(app_module.list_projects(_request(state)))
    detail = asyncio.run(app_module.get_project(_request(state), uploaded["project_id"]))

    assert [item["id"] for item in listed] == [uploaded["project_id"]]
    assert listed[0]["snapshot_count"] == 1
    assert detail["findings"] == []
    assert detail["snapshots"][0]["id"] == uploaded["id"]


def test_unknown_project_is_404(state):
    with pytest.raises(HTTPException) as failure:
        asyncio.run(app_module.get_project(_request(state), "missing"))
    assert failure.value.status_code == 404
