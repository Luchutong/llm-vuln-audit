import asyncio
import json

import httpx
import pytest

from audit.poc_runner import (
    MAX_JSON_BYTES,
    PocRunnerClient,
    PocRunnerError,
    PocRunnerUnavailable,
    artifact_manifest,
)


def _client(handler, *, token="secret-token", base_url="http://runner:8080") -> PocRunnerClient:
    return PocRunnerClient(base_url, token, transport=httpx.MockTransport(handler))


def _run(client: PocRunnerClient, coro_factory):
    async def main():
        try:
            return await coro_factory()
        finally:
            await client.aclose()

    return asyncio.run(main())


def test_health_sends_bearer_token_and_parses_json():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["path"] = request.url.path
        return httpx.Response(200, json={"ok": True, "capabilities": {"php": True}})

    client = _client(handler)
    result = _run(client, client.health)

    assert result["ok"] is True
    assert seen == {"auth": "Bearer secret-token", "path": "/healthz"}


def test_connection_failure_maps_to_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = _client(handler)
    with pytest.raises(PocRunnerUnavailable):
        _run(client, client.target_status)


def test_timeout_maps_to_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    client = _client(handler)
    with pytest.raises(PocRunnerUnavailable):
        _run(client, client.prepare_target)


def test_unconfigured_runner_never_opens_a_connection():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("transport must not be used")

    client = PocRunnerClient("", "token", transport=httpx.MockTransport(handler))
    with pytest.raises(PocRunnerUnavailable):
        asyncio.run(client.health())


def test_runner_client_never_uses_environment_proxies():
    # A developer's HTTP(S)_PROXY must not capture private runner traffic; the real service
    # answered 502 for prepare until trust_env was disabled.
    client = PocRunnerClient("http://runner:8080", "secret-token")
    try:
        assert client._http().trust_env is False
    finally:
        asyncio.run(client.aclose())


def test_rejection_is_sanitized_and_truncated():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"detail": "bad script secret-token " + "x" * 800})

    client = _client(handler)
    with pytest.raises(PocRunnerError) as excinfo:
        _run(client, lambda: client.run_job(target="lab30", language="php", script="<?php echo 1;"))

    message = str(excinfo.value)
    assert "secret-token" not in message
    assert len(message) < 500


def test_oversized_response_is_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{" + b" " * (MAX_JSON_BYTES + 10) + b"}")

    client = _client(handler)
    with pytest.raises(PocRunnerError):
        _run(client, client.health)


def test_non_object_json_is_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps([1, 2, 3]).encode())

    client = _client(handler)
    with pytest.raises(PocRunnerError):
        _run(client, client.target_status)


def test_artifact_fetch_returns_bytes():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/jobs/abc123/artifacts/out.txt"
        return httpx.Response(200, content=b"evidence")

    client = _client(handler)
    assert _run(client, lambda: client.fetch_artifact("abc123", "out.txt")) == b"evidence"


def test_artifact_names_cannot_escape_the_job_directory():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("transport must not be used")

    client = _client(handler)
    with pytest.raises(PocRunnerError):
        asyncio.run(client.fetch_artifact("abc123", "../../etc/passwd"))


def test_unknown_language_is_rejected_before_the_request():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("transport must not be used")

    client = _client(handler)
    with pytest.raises(PocRunnerError):
        _run(client, lambda: client.run_job(target="lab30", language="bash", script="id"))


def test_job_payload_is_bounded_and_complete():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"job_id": "j1", "status": "finished", "exit_code": 0})

    client = _client(handler)
    result = _run(
        client,
        lambda: client.run_job(
            target="lab30",
            language="PHP",
            script="<?php echo 'x';",
            timeout_seconds=900,
            artifacts=[f"a{i}" for i in range(20)],
        ),
    )

    assert result["job_id"] == "j1"
    assert seen["language"] == "php"
    assert seen["timeout_seconds"] == 120
    assert len(seen["artifacts"]) == 8


def test_artifact_manifest_keeps_only_safe_entries():
    manifest = artifact_manifest(
        {
            "artifacts": [
                {"name": "out.txt", "sha256": "abc", "size": 3},
                {"name": "../escape", "sha256": "x", "size": 1},
                "not-a-dict",
            ]
        }
    )
    assert manifest == [{"name": "out.txt", "sha256": "abc", "size": 3}]


def test_context_lifecycle_and_identity_contract():
    seen = []
    def handler(request):
        seen.append((request.method, request.url.path, dict(request.url.params), json.loads(request.content) if request.content else None))
        payload = json.loads(request.content) if request.content else {}
        return httpx.Response(200, json={'ok': True, 'context_id': 'stable-context',
                                        'job_id': payload.get('job_id', '')})
    client = _client(handler)
    async def exercise():
        await client.create_context(run_id='r1', finding_id='f1', context_id='stable-context')
        await client.prepare_target(context_id='stable-context', identity='bob', expected_role='customer', expected_state={'balance': '100.00'})
        await client.target_status(context_id='stable-context', identity='guest')
        await client.run_job(target='lab30', language='python', script='print(1)', context_id='stable-context', identity='bob', job_id='stable-job')
        await client.http_observe(target='lab30', method='GET', path='/', context_id='stable-context', identity='guest')
        await client.browser_check(target='lab30', path='/', context_id='stable-context', identity='admin')
        await client.close_context('stable-context')
    _run(client, exercise)
    assert seen[0][3] == {'target':'lab30', 'run_id':'r1', 'finding_id':'f1', 'context_id':'stable-context'}
    assert seen[1][3]['expected_state'] == {'balance':'100.00'}
    assert seen[2][2] == {'context_id':'stable-context', 'identity':'guest'}
    assert seen[3][3]['job_id'] == 'stable-job'
    assert seen[3][3]['identity'] == 'bob'
    assert seen[4][3]['identity'] == 'guest'
    assert seen[5][3]['identity'] == 'admin'
    assert seen[6][:2] == ('DELETE', '/v1/verification-contexts/stable-context')


def test_context_status_reads_state_without_closing_and_404_means_closed():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        return httpx.Response(200, json={'context_id': 'ctx-1', 'state': 'closing', 'pending_jobs': 1})

    client = _client(handler)
    status = _run(client, lambda: client.context_status('ctx-1'))
    assert seen == [('GET', '/v1/verification-contexts/ctx-1')]
    assert status['state'] == 'closing' and status['pending_jobs'] == 1

    missing = _client(lambda _: httpx.Response(404, json={'detail': 'unknown verification context'}))
    assert _run(missing, lambda: missing.context_status('gone')) == {
        'context_id': 'gone', 'state': 'closed', 'pending_jobs': 0, 'was_unknown': True}


def test_busy_context_has_explicit_status_code():
    from audit.poc_runner import PocRunnerBusy
    client = _client(lambda _: httpx.Response(409, json={'detail':'target busy'}))
    with pytest.raises(PocRunnerBusy) as error:
        _run(client, lambda: client.create_context(run_id='r', finding_id='f'))
    assert error.value.status_code == 409


@pytest.mark.parametrize('tool', ['run_job', 'http_observe', 'browser_check'])
def test_all_submissions_send_host_ids_and_reject_mismatched_replies(tool):
    def handler(request):
        payload = json.loads(request.content)
        assert payload['job_id'] == 'host-job' and payload['context_id'] == 'host-context'
        return httpx.Response(200, json={'job_id': 'other-job', 'context_id': 'host-context'})
    client = _client(handler)
    arguments = {'target': 'lab30', 'job_id': 'host-job', 'context_id': 'host-context'}
    arguments.update({'language': 'python', 'script': 'print(1)'} if tool == 'run_job' else {'path': '/'})
    if tool == 'http_observe':
        arguments['method'] = 'GET'
    with pytest.raises(PocRunnerError, match='preserve the host job id'):
        _run(client, lambda: getattr(client, tool)(**arguments))
