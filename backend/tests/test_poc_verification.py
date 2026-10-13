"""POC delivery and human-verification gates without a live server or model."""
from __future__ import annotations

import asyncio
import json
from io import BytesIO
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, UploadFile

from audit import app as app_module


class FakeStore:
    def __init__(self, category: str = "sqli"):
        self.finding = {
            "id": "finding-1",
            "run_id": "run-1",
            "unit_id": "unit-1",
            "category": category,
            "poc": {
                "filename": "poc.py",
                "language": "python",
                "script": "#!/usr/bin/env python3\nprint('original artifact')\n",
            },
        }
        self.records: list[dict] = []
        self.verdict: str | None = None

    def get_finding(self, finding_id: str):
        return self.finding if finding_id == self.finding["id"] else None

    def add_verification(self, record: dict) -> None:
        self.records.append(record)

    def record_verification(self, record: dict) -> None:
        self.records.append(record)
        self.verdict = record["verdict"]

    def set_finding_verdict(self, finding_id: str, verdict: str) -> None:
        assert finding_id == self.finding["id"]
        self.verdict = verdict


class FakeBus:
    def __init__(self):
        self.events: list[tuple] = []

    def emit(self, *args) -> None:
        self.events.append(args)


@pytest.fixture
def state(tmp_path, monkeypatch):
    store = FakeStore()
    fake_state = SimpleNamespace(
        store=store,
        settings=SimpleNamespace(evidence_dir=tmp_path / "evidence"),
        bus=FakeBus(),
    )
    fake_state.settings.evidence_dir.mkdir()
    monkeypatch.setattr(app_module, "services", lambda request: fake_state)
    return fake_state


def record(**overrides) -> str:
    payload = {
        "verdict": "confirmed",
        "execution_status": "success",
        "target_version": "DVWA 2.5",
        "command": "python poc.py http://127.0.0.1:4280",
        "normal_observation": "The normal input rendered as text.",
        "attack_observation": "The attack input produced the documented difference.",
        "modified_script": "#!/usr/bin/env python3\nprint('original artifact')\n",
        "browser_execution": False,
    }
    payload.update(overrides)
    return json.dumps(payload)


def upload(name: str, content: bytes = b"evidence") -> UploadFile:
    return UploadFile(filename=name, file=BytesIO(content))


def test_poc_download_is_the_unmodified_model_artifact(state):
    response = asyncio.run(app_module.download_poc(object(), "finding-1"))
    assert response.body.decode("utf-8") == state.store.finding["poc"]["script"]
    assert not response.body.startswith(b"<?php")


def test_confirmation_requires_a_successful_run_and_leaves_no_orphan_upload(state):
    with pytest.raises(HTTPException) as raised:
        asyncio.run(app_module.add_verification(
            object(), "finding-1", record(execution_status="syntax_error"), [upload("failure.txt")]
        ))
    assert raised.value.status_code == 400
    assert not state.store.records
    assert list(state.settings.evidence_dir.iterdir()) == []


def test_confirmation_requires_control_observations_and_attachment(state):
    with pytest.raises(HTTPException) as missing_control:
        asyncio.run(app_module.add_verification(
            object(), "finding-1", record(normal_observation=""), [upload("proof.txt")]
        ))
    assert missing_control.value.status_code == 400

    with pytest.raises(HTTPException) as missing_attachment:
        asyncio.run(app_module.add_verification(object(), "finding-1", record(), []))
    assert missing_attachment.value.status_code == 400

    with pytest.raises(HTTPException) as empty_attachment:
        asyncio.run(app_module.add_verification(object(), "finding-1", record(), [upload("empty.log", b"")]))
    assert empty_attachment.value.status_code == 400
    assert list(state.settings.evidence_dir.iterdir()) == []
    assert not state.store.records


def test_rejection_and_xss_confirmation_cannot_bypass_the_reproducibility_gate(state):
    with pytest.raises(HTTPException) as rejected:
        asyncio.run(app_module.add_verification(
            object(), "finding-1", record(verdict="rejected", attack_observation=""), []
        ))
    assert rejected.value.status_code == 400

    state.store.finding["category"] = "xss_r"
    with pytest.raises(HTTPException) as xss:
        asyncio.run(app_module.add_verification(
            object(), "finding-1", record(), [upload("browser.log")]
        ))
    assert xss.value.status_code == 400
    assert not state.store.records


def test_multipart_record_must_be_an_object_before_any_file_is_saved(state):
    with pytest.raises(HTTPException) as raised:
        asyncio.run(app_module.add_verification(object(), "finding-1", "[]", [upload("proof.txt")]))
    assert raised.value.status_code == 400
    assert list(state.settings.evidence_dir.iterdir()) == []


def test_valid_confirmation_keeps_duplicate_named_attachments_distinct(state):
    result = asyncio.run(app_module.add_verification(
        object(), "finding-1", record(), [upload("run.log", b"one"), upload("run.log", b"two")]
    ))
    assert result is state.store.finding
    assert state.store.verdict == "confirmed"
    saved = state.store.records[0]["files"]
    assert len(saved) == 2
    assert saved[0]["stored"] != saved[1]["stored"]
    assert (state.settings.evidence_dir / saved[0]["stored"]).read_bytes() == b"one"
    assert (state.settings.evidence_dir / saved[1]["stored"]).read_bytes() == b"two"
