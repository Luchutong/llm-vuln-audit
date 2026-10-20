"""POC delivery and automatic verification without a live server or model.

There is no review endpoint any more: verification rows are written by the POC agent
inside the worker.  What remains to pin on the HTTP surface is that the model's POC
downloads byte-for-byte, that the human route is really gone (not merely unused), and
that reading a finding returns its verification records as plain read-only data.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from audit import app as app_module


class FakeStore:
    def __init__(self):
        self.finding = {
            "id": "finding-1",
            "run_id": "run-1",
            "unit_id": "unit-1",
            "category": "sqli",
            "poc": {
                "filename": "poc.py",
                "language": "python",
                "script": "#!/usr/bin/env python3\nprint('original artifact')\n",
            },
            "verification_status": "verified",
            "verification_verdict": "confirmed",
            "verifications": [{
                "id": "v1",
                "source": "poc_agent",
                "status": "verified",
                "verdict": "confirmed",
                "execution_status": "success",
                "target": {"name": "dvwa", "security": "low"},
                "agent": {"jobs": ["job-1"]},
                "artifacts": [{"name": "out.txt", "path": "v1-out.txt"}],
            }],
        }

    def get_finding(self, finding_id: str):
        return self.finding if finding_id == self.finding["id"] else None


@pytest.fixture
def state(monkeypatch):
    value = SimpleNamespace(store=FakeStore())
    monkeypatch.setattr(app_module, "services", lambda request: value)
    return value


def test_poc_download_is_the_unmodified_model_artifact(state):
    response = asyncio.run(app_module.download_poc(object(), "finding-1"))
    assert response.body.decode("utf-8") == state.store.finding["poc"]["script"]
    assert not response.body.startswith(b"<?php")


def test_there_is_no_endpoint_that_accepts_a_human_verdict():
    routes = {
        (getattr(route, "path", ""), method)
        for route in app_module.app.routes
        for method in (getattr(route, "methods", None) or ())
    }
    assert not [item for item in routes if item[0].endswith("/verifications")]
    assert ("/api/findings/{finding_id}", "GET") in routes


def test_reading_a_finding_returns_its_verification_records_read_only(state):
    found = asyncio.run(app_module.get_finding(object(), "finding-1"))

    assert found["verification_status"] == "verified"
    record = found["verifications"][0]
    assert record["source"] == "poc_agent"
    assert record["status"] == "verified"
    assert record["target"]["security"] == "low"
    assert record["agent"]["jobs"] == ["job-1"]
