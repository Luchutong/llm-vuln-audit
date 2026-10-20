"""The runner's HTTP observation must report the response, not a follow-up request.

An open redirect is proven by the first 3xx and its ``Location``.  Following that header
either replaces the evidence with the target's answer or, for an external host, fails on
the isolated network -- which is exactly what happened in run 538f47d9: a 302 to
``//evil.com`` was reported as almost certainly a 200 DVWA page.  These tests pin the
semantics with a real ``httpx.Client`` and a mock transport, so no container is needed.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

runner = importlib.import_module("poc_runner.runner")

PATH = "/vulnerabilities/open_redirect/source/low.php?redirect=//evil.com"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def observe(monkeypatch, location: str, *, status: int = 302, body: bytes = b"moved"):
    """Run one observation through a mock target and return (result, requested URLs)."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        headers = {"Location": location} if location else {}
        return httpx.Response(status, headers=headers, content=body)

    client = httpx.Client(
        base_url=runner.DVWA_URL,
        follow_redirects=False,
        transport=httpx.MockTransport(handler),
    )
    monkeypatch.setattr(runner, "_dvwa_client", lambda: client)
    result = runner._observe_sync(runner.HttpRequest(target="dvwa", path=PATH))
    return result, seen


@pytest.mark.parametrize("location", ["//evil.com", "https://evil.com/next", "info.php?id=1"])
def test_a_redirect_is_reported_not_followed(monkeypatch, location):
    """Protocol-relative, absolute and directory-relative targets all stay one request."""
    result, seen = observe(monkeypatch, location)

    assert seen == [f"{runner.DVWA_URL}{PATH}"], "runner followed a redirect it should only report"
    assert result["status"] == 302
    assert result["headers"]["location"] == location
    assert result["redirects"] == [location]


def test_a_normal_response_has_no_redirects(monkeypatch):
    result, seen = observe(monkeypatch, "", status=200, body="<html>ok</html>".encode())

    assert seen == [f"{runner.DVWA_URL}{PATH}"]
    assert result["status"] == 200
    assert result["redirects"] == []
    assert "location" not in result["headers"]


def test_protocol_relative_path_is_still_refused_at_the_entrypoint(monkeypatch):
    """Not following redirects must not loosen the allowlist on the requested path."""
    with pytest.raises(HTTPException) as error:
        runner._observe_sync(runner.HttpRequest(target="dvwa", path="//evil.com"))
    assert error.value.status_code == 400


def test_a_large_body_is_previewed_and_marked(monkeypatch):
    payload = ("中文观测" * 8000).encode("utf-8")
    result, seen = observe(monkeypatch, "", status=200, body=payload)

    assert len(seen) == 1
    assert result["truncated"] is True
    assert len(result["body"].encode("utf-8")) <= runner.BODY_PREVIEW
