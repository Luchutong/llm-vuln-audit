"""Offline HTTP/SSE integration: temporary SQLite, ASGI and mock upstream only."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from audit.db import Store
from audit.poc_model_gateway import PROTOCOL_VERSION, PocModelGateway, router
from tests.test_goal_tasks import run_payload


PREFIX = "/api/internal/poc-gateway"
MODEL = "claude-offline-test"
PROVIDER_KEY = "provider-secret-never-in-sdk"
MESSAGE = {"model": MODEL, "max_tokens": 20,
           "messages": [{"role": "user", "content": "private prompt"}]}
REPLY = {"id": "msg_offline", "type": "message", "role": "assistant", "model": MODEL,
         "content": [{"type": "text", "text": "offline result"}], "stop_reason": "end_turn",
         "stop_sequence": None, "usage": {"input_tokens": 3, "output_tokens": 2}}


@pytest.fixture
def harness(tmp_path):
    stores = []

    def build(handler=None, *, stage_limit=3, response_limit=100, clock=None, **kwargs):
        store = Store(tmp_path / f"gateway-{len(stores)}.sqlite")
        stores.append(store)
        payload = run_payload({"id": "offline-snapshot", "name": "Offline"}, "run", [])
        payload["run_limits"] = {"responses": response_limit, "tools": 50, "seconds": 1800}
        store.create_run(payload)
        run = store.claim_next_run()
        epoch = run["execution_epoch"]
        for stage in ("execute", "conclude"):
            assert store.open_poc_request_stage("run", stage, stage_limit, epoch)["ok"]
        seen = []

        async def upstream(request):
            seen.append(request)
            if handler:
                result = handler(request)
                if hasattr(result, "__await__"):
                    result = await result
                return result
            return httpx.Response(200, json=REPLY)

        gateway = PocModelGateway(
            store, enabled=True, upstream_url="https://model.invalid/anthropic",
            upstream_api_key=PROVIDER_KEY, transport=httpx.MockTransport(upstream),
            **({"clock": clock} if clock else {}), **kwargs,
        )
        app = FastAPI()
        app.state.services = SimpleNamespace(poc_gateway=gateway)
        app.include_router(router, prefix=PREFIX)
        token = gateway.issue_capability("run", epoch, "execute", MODEL, "context-1", "finding-1")

        async def request(body=None, *, path="/v1/messages", token_value=token, headers=None, **options):
            auth = {"x-api-key": token_value} if token_value is not None else {}
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://host.invalid") as client:
                return await client.post(PREFIX + path, json=MESSAGE if body is None else body,
                                         headers={**auth, **(headers or {})}, **options)

        return SimpleNamespace(store=store, run=run, epoch=epoch, gateway=gateway, app=app,
                               token=token, request=request, seen=seen)

    yield build
    for store in stores:
        store.close()


def quota(h, stage="execute"):
    return h.store.poc_request_quota("run", h.epoch)[stage]["used"]


def test_provider_rejection_has_safe_host_diagnostics_and_no_reflected_credentials(harness):
    h = harness(lambda request: httpx.Response(429, json={'type': 'error', 'error': {
        'type': 'rate_limit_error', 'code': 'AccountQuotaExceeded',
        'message': PROVIDER_KEY + ' private prompt'}}))
    assert asyncio.run(h.request()).status_code == 429
    diagnostic = h.gateway.diagnostics_for_capability(h.token)[-1]
    assert diagnostic['http_status'] == 429
    assert diagnostic['provider_error_code'] == 'AccountQuotaExceeded'
    saved = h.store.list_events('run')
    assert any(e['kind'] == 'poc_gateway_error' for e in saved)
    assert PROVIDER_KEY not in json.dumps(saved) and 'private prompt' not in json.dumps(saved)
    assert quota(h) == 1


def test_host_adapter_keeps_diagnostics_after_capability_cleanup(harness):
    from audit.runtimes.claude_poc import StorePocRequestGateway
    h = harness(lambda request: httpx.Response(503, json={'type': 'error', 'error': {'type': 'api_error'}}))
    h.store._poc_model_gateway = h.gateway
    adapter = StorePocRequestGateway(h.store)
    token = adapter.issue_capability(run_id='run', epoch=h.epoch, stage='execute', model=MODEL,
                                     context_id='ctx', finding_id='finding')
    asyncio.run(h.request(token_value=token))
    before = adapter.stage_diagnostics(run_id='run', epoch=h.epoch, stage='execute')
    adapter.revoke_capability(token)
    assert before and before[-1]['http_status'] == 503
    assert adapter.stage_diagnostics(run_id='run', epoch=h.epoch, stage='execute') == before
    assert h.gateway.diagnostics_for_capability(token) == []


def test_sse_error_and_non_json_upstream_failure_remain_diagnosable(harness):
    body = 'event: error\ndata: ' + json.dumps({'type': 'error', 'error': {
        'type': 'overloaded_error', 'message': PROVIDER_KEY, 'code': {'unexpected': 'shape'}}}) + '\n\n'
    h = harness(lambda request: httpx.Response(200, content=body, headers={'content-type': 'text/event-stream'}))
    assert asyncio.run(h.request(body={**MESSAGE, 'stream': True})).status_code == 200
    diagnostic = h.gateway.diagnostics_for_capability(h.token)[-1]
    assert diagnostic['code'] == 'upstream_stream_error' and diagnostic['http_status'] == 200
    assert diagnostic['provider_error_type'] == 'overloaded_error'
    assert diagnostic['provider_error_code'] == 'unknown'
    assert PROVIDER_KEY not in json.dumps(h.store.list_events('run'))


@pytest.mark.parametrize('streaming,code', [(True, 'invalid_event_stream'), (False, 'upstream_error_envelope')])
def test_http_200_is_not_enough_to_hide_a_protocol_or_provider_error(harness, streaming, code):
    response = httpx.Response(200, json={'type': 'error', 'error': {'type': 'invalid_request_error'}})
    h = harness(lambda request: response)
    asyncio.run(h.request(body={**MESSAGE, 'stream': streaming}))
    assert h.gateway.diagnostics_for_capability(h.token)[-1]['code'] == code
    h = harness(lambda request: httpx.Response(502, text=PROVIDER_KEY, headers={'content-type': 'text/html'}))
    asyncio.run(h.request())
    assert h.gateway.diagnostics_for_capability(h.token)[-1]['http_status'] == 502
    assert PROVIDER_KEY not in json.dumps(h.store.list_events('run'))


def test_default_disabled_readiness_and_health_are_offline(harness, monkeypatch):
    h = harness()
    for name in ("POC_CLAUDE_GATEWAY_ENABLED", "POC_CLAUDE_UPSTREAM_URL", "POC_CLAUDE_UPSTREAM_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    disabled = PocModelGateway.from_environ(h.store)
    assert disabled.readiness() == {"ready": False, "reason": "disabled",
        "protocol_version": PROTOCOL_VERSION, "upstream_configured": False}
    h.app.state.services = SimpleNamespace(poc_gateway=disabled)

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=h.app), base_url="http://host.invalid") as client:
            health = await client.get(PREFIX + "/health")
            assert health.json() == disabled.readiness()
        assert (await h.request()).status_code == 400

    asyncio.run(exercise())
    assert h.seen == [] and quota(h) == 0
    with pytest.raises(ValueError):
        disabled.issue_capability("run", h.epoch, "execute", MODEL, "ctx", "finding")


@pytest.mark.parametrize("url", ["https://user:secret@model.invalid", "https://model.invalid?key=secret",
                                  "https://model.invalid/#secret", "file:///tmp/model", "https://model.invalid:bad"])
def test_invalid_fixed_upstream_configuration_is_not_ready(harness, url):
    h = harness()
    gateway = PocModelGateway(h.store, enabled=True, upstream_url=url, upstream_api_key=PROVIDER_KEY)
    result = gateway.readiness()
    assert not result["ready"] and result["reason"] == "invalid_upstream_configuration"
    assert "secret" not in json.dumps(result) and PROVIDER_KEY not in json.dumps(result)


def test_capability_hashes_credentials_and_authenticates_before_admission(harness):
    h = harness()
    assert h.token not in h.gateway._capabilities
    assert h.token not in repr(h.gateway._capabilities)

    async def exercise():
        for token in (None, "unrelated", PROVIDER_KEY):
            response = await h.request(token_value=token)
            assert response.status_code == 401 and response.json()["type"] == "error"
        assert (await h.request(headers={"authorization": "Bearer unrelated"})).status_code == 401
        assert (await h.request(token_value=None, headers={"authorization": "Bearer " + h.token})).status_code == 200

    asyncio.run(exercise())
    assert len(h.seen) == quota(h) == 1


def test_json_request_forwards_fixed_upstream_and_server_credentials_only(harness):
    h = harness()
    headers = {"authorization": "Bearer " + h.token, "cookie": "user-session=secret",
               "x-run-id": "other-run", "x-poc-stage": "conclude", "x-upstream-url": "https://evil.invalid",
               "anthropic-version": "2023-06-01", "anthropic-beta": "interleaved-thinking-2025-05-14"}
    result = asyncio.run(h.request(headers=headers))
    assert result.status_code == 200 and result.json() == REPLY
    upstream = h.seen[0]
    assert str(upstream.url) == "https://model.invalid/anthropic/v1/messages"
    assert upstream.headers["x-api-key"] == PROVIDER_KEY
    assert upstream.headers["anthropic-beta"] == headers["anthropic-beta"]
    assert not {"authorization", "cookie", "x-run-id", "x-poc-stage", "x-upstream-url"} & set(upstream.headers)
    assert h.token not in str(upstream.headers)
    assert json.loads(upstream.content) == MESSAGE
    assert quota(h) == 1 and quota(h, "conclude") == 0
    public = json.dumps(h.store.list_events("run"))
    assert "private prompt" not in public and "offline result" not in public
    assert PROVIDER_KEY not in public and h.token not in public


def test_model_mismatch_and_invalid_body_are_not_admitted(harness):
    h = harness()

    async def exercise():
        for body in ({**MESSAGE, "model": "different-model"}, [], {**MESSAGE, "stream": "true"}):
            assert (await h.request(body)).status_code == 400
        assert (await h.request(path="/v1/messages?upstream=https://evil.invalid")).status_code == 400
        assert (await h.request(headers={"unrelated": "x" * 17000})).status_code == 400

    asyncio.run(exercise())
    assert h.seen == [] and quota(h) == 0


def test_cli_beta_query_is_accepted_but_never_forwarded(harness):
    """Claude Code's Bearer requests go to ``/v1/messages?beta=true``.

    The marker selects a client protocol mode; it must not change admission and must not
    reach the fixed upstream URL.
    """
    h = harness()
    result = asyncio.run(h.request(path="/v1/messages?beta=true"))
    assert result.status_code == 200 and result.json() == REPLY
    assert quota(h) == 1 and len(h.seen) == 1
    assert str(h.seen[0].url) == "https://model.invalid/anthropic/v1/messages"
    assert h.seen[0].url.query == b""

    token_result = asyncio.run(h.request(path="/v1/messages/count_tokens?beta=true"))
    assert token_result.status_code == 200 and len(h.seen) == 2
    # Token counting never spends a generation request.
    assert quota(h) == 1


def test_other_query_parameters_stay_rejected_before_authentication(harness):
    h = harness()

    async def exercise():
        for path in ("/v1/messages?upstream=https://evil.invalid",
                     "/v1/messages?beta=false", "/v1/messages?beta=true&x=1"):
            response = await h.request(path=path)
            assert response.status_code == 400
            assert response.json()["error"]["code"] == "poc_gateway_route_rejected"

    asyncio.run(exercise())
    assert h.seen == [] and quota(h) == 0


@pytest.mark.parametrize("deactivate", ["revoke", "expire", "old_epoch", "pause", "stop"])
def test_inactive_capability_cannot_send_messages_or_count_tokens(harness, deactivate):
    current = [100.0]
    h = harness(clock=lambda: current[0])
    if deactivate == "revoke":
        h.gateway.revoke_capability(h.token)
    elif deactivate == "expire":
        current[0] += 301
    elif deactivate == "old_epoch":
        h.store._write("UPDATE run_execution_state SET claim_epoch=claim_epoch+1 WHERE run_id='run'")
    elif deactivate == "pause":
        h.store._write("UPDATE runs SET status='paused' WHERE id='run'")
    else:
        h.store._write("UPDATE run_execution_state SET phase='ended' WHERE run_id='run'")

    async def exercise():
        for path in ("/v1/messages", "/v1/messages/count_tokens"):
            assert (await h.request(path=path)).status_code == 401

    asyncio.run(exercise())
    assert h.seen == [] and quota(h) == 0


def test_each_retry_reenters_admission_and_quota_refusal_is_not_retryable(harness):
    h = harness(stage_limit=2)

    async def exercise():
        return [await h.request() for _ in range(5)]

    replies = asyncio.run(exercise())
    assert [reply.status_code for reply in replies] == [200, 200, 400, 400, 400]
    assert all(reply.json()["error"]["code"] == "poc_gateway_admission_refused" for reply in replies[2:])
    assert len(h.seen) == quota(h) == 2
    assert h.gateway.refusal_for_capability(h.token) == {
        "reason": "quota_exhausted", "stage": "execute", "epoch": h.epoch,
        "limit": 2, "used": 2, "remaining": 0,
    }


def test_count_tokens_does_not_consume_stage_or_global_inference_budget(harness):
    def handler(request):
        return httpx.Response(200, json={"input_tokens": 4} if request.url.path.endswith("count_tokens") else REPLY)

    h = harness(handler, response_limit=1)
    # Execute keeps the conclusion's allowance reserved. Use the conclusion's
    # own capability to exercise the shared one-response ceiling directly.
    token = h.gateway.issue_capability("run", h.epoch, "conclude", MODEL, "context-1", "finding-1")

    async def exercise():
        for _ in range(3):
            count = await h.request(path="/v1/messages/count_tokens", token_value=token)
            assert count.status_code == 200 and count.json() == {"input_tokens": 4}
        assert quota(h, "conclude") == 0
        assert (await h.request(token_value=token)).status_code == 200
        assert (await h.request(token_value=token)).status_code == 400

    asyncio.run(exercise())
    assert len(h.seen) == 4 and quota(h, "conclude") == 1 and quota(h) == 0
    assert h.store.execution_summary("run")["run_usage"]["responses"] == 1
    assert h.gateway.refusal_for_capability(token)["reason"] == "run_budget_exhausted"


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            if callable(chunk):
                chunk = chunk()
            yield chunk
            await asyncio.sleep(0)

    async def aclose(self):
        self.closed = True


class DelayedChunks(Chunks):
    def __init__(self, sequence):
        super().__init__([])
        self.sequence = sequence
        self.reads = 0

    async def __aiter__(self):
        for delay, chunk in self.sequence:
            self.reads += 1
            await asyncio.sleep(delay)
            yield chunk


STOP = b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
PING = b'event: ping\ndata: {"type":"ping"}\n\n'


@pytest.mark.parametrize('outcome', ['healthy', 'idle', 'run_deadline'])
def test_persistent_queue_stream_uses_run_window_and_keeps_idle_protection(harness, outcome):
    sequence = [(.015, PING)] * 4 + [(0, STOP)] if outcome == 'healthy' else [(0, PING), (1, STOP)]
    stream = DelayedChunks(sequence)
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream),
                request_timeout_seconds=.02, stream_idle_timeout_seconds=.03 if outcome == 'idle' else .5)
    scope = 'b' * 64
    h.store.open_poc_request_stage('run', 'execute@' + scope, 10, h.epoch)
    token = h.gateway.issue_capability('run', h.epoch, 'execute', MODEL, 'queue-1', 'queue-1',
        quota_scope=scope, session_policy='session-queue-v1', ttl_seconds=.05 if outcome == 'run_deadline' else 1)
    response = asyncio.run(h.request({**MESSAGE, 'stream': True}, token_value=token))
    if outcome == 'healthy':
        assert response.content.endswith(STOP)
        assert b'poc_gateway_stream_aborted' not in response.content
        assert h.gateway.diagnostics_for_capability(token) == []
    else:
        assert b'poc_gateway_stream_aborted' in response.content
        code = 'stream_idle_timeout' if outcome == 'idle' else 'stream_run_deadline'
        assert h.gateway.diagnostics_for_capability(token)[-1]['code'] == code
    assert stream.closed
    assert h.store.poc_request_quota('run', h.epoch)['execute@' + scope]['used'] == 1


def test_gateway_request_and_idle_timeouts_are_independently_configurable(harness, monkeypatch):
    h = harness()
    assert h.gateway._timeout == 180 and h.gateway._idle_timeout == 120
    monkeypatch.setenv('POC_CLAUDE_REQUEST_SECONDS', '240')
    monkeypatch.setenv('POC_CLAUDE_STREAM_IDLE_SECONDS', '100')
    gateway = PocModelGateway.from_environ(h.store)
    assert gateway._timeout == 240 and gateway._idle_timeout == 100
    with pytest.raises(ValueError):
        PocModelGateway(h.store, stream_idle_timeout_seconds=float('nan'))


def test_active_stream_may_last_longer_than_the_idle_window(harness):
    stream = DelayedChunks([(.012, PING)] * 10 + [(0, STOP)])
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream),
                request_timeout_seconds=1, stream_idle_timeout_seconds=.1)
    response = asyncio.run(h.request({**MESSAGE, 'stream': True}))
    assert response.content.endswith(STOP) and b'poc_gateway_stream_aborted' not in response.content
    assert h.gateway.diagnostics_for_capability(h.token) == []
    assert stream.closed and quota(h) == 1


def test_per_chunk_liveness_never_rebuilds_the_run_summary(harness, monkeypatch):
    """The relay's liveness probe must read the status column, not the summary.

    ``get_run`` rebuilds ``execution_summary``, which fans out a query per finding.
    Running it twice per relayed chunk capped POC model output at a few events per
    second regardless of how fast the provider streamed, so the relay now uses the
    cheap ``run_status`` probe for every chunk.
    """
    stream = DelayedChunks([(0, PING)] * 30 + [(0, STOP)])
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream),
                request_timeout_seconds=5, stream_idle_timeout_seconds=5)
    calls = {'summary': 0, 'status': 0}
    original_status = h.store.run_status

    def counting_status(run_id):
        calls['status'] += 1
        return original_status(run_id)

    def forbidden_summary(run_id):
        calls['summary'] += 1
        raise AssertionError('get_run must not run inside the stream relay')

    monkeypatch.setattr(h.store, 'get_run', forbidden_summary)
    monkeypatch.setattr(h.store, 'run_status', counting_status)
    response = asyncio.run(h.request({**MESSAGE, 'stream': True}))
    assert response.content.endswith(STOP)
    assert b'poc_gateway_stream_aborted' not in response.content
    assert calls['summary'] == 0
    assert calls['status'] >= 30
    assert quota(h) == 1


def test_message_stop_finishes_even_when_upstream_does_not_close_the_socket(harness):
    # CRLF framing and the terminal JSON may cross network chunk boundaries.
    stop = STOP.replace(b'\n', b'\r\n')
    stream = DelayedChunks([(0, stop[:25]), (0, stop[25:]), (1, b'late private provider detail')])
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream),
                request_timeout_seconds=.3, stream_idle_timeout_seconds=.1)
    response = asyncio.run(h.request({**MESSAGE, 'stream': True}))
    assert response.content == stop and stream.reads == 2
    assert stream.closed and quota(h) == 1
    assert not h.gateway.diagnostics_for_capability(h.token)


@pytest.mark.parametrize('failure', ['idle', 'total', 'incomplete', 'connection'])
def test_stream_errors_preserve_the_actual_cause_and_received_progress(harness, failure):
    if failure == 'idle':
        stream = DelayedChunks([(0, PING), (1, STOP)])
        request_seconds, idle_seconds, expected = .5, .05, 'stream_idle_timeout'
    elif failure == 'total':
        stream = DelayedChunks([(.01, PING)] * 50)
        request_seconds, idle_seconds, expected = .1, .5, 'stream_request_timeout'
    elif failure == 'connection':
        class Broken(Chunks):
            async def __aiter__(self):
                yield PING
                raise httpx.ReadError(PROVIDER_KEY)
        stream = Broken([])
        request_seconds, idle_seconds, expected = 1, 1, 'stream_connection_error'
    else:
        stream = Chunks([PING])
        request_seconds, idle_seconds, expected = 1, 1, 'stream_incomplete'
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream),
                request_timeout_seconds=request_seconds, stream_idle_timeout_seconds=idle_seconds)
    response = asyncio.run(h.request({**MESSAGE, 'stream': True}))
    assert b'poc_gateway_stream_aborted' in response.content
    assert stream.closed and quota(h) == 1
    diagnostic = h.gateway.diagnostics_for_capability(h.token)[-1]
    assert diagnostic['code'] == expected
    assert diagnostic['received_bytes'] >= len(PING) and diagnostic['events_received'] >= 1
    assert diagnostic['last_event_type'] == 'ping'
    assert diagnostic['http_status'] == 200
    assert PROVIDER_KEY not in json.dumps(h.store.list_events('run'))


def test_silent_stream_is_released_promptly_after_context_revocation(harness):
    stream = DelayedChunks([(10, STOP)])
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream))

    async def exercise():
        request = asyncio.create_task(h.request({**MESSAGE, 'stream': True}))
        while not stream.reads:
            await asyncio.sleep(.001)
        h.gateway.revoke_capability(h.token)
        return await asyncio.wait_for(request, .8)

    response = asyncio.run(exercise())
    assert b'poc_gateway_stream_aborted' in response.content
    assert stream.closed and quota(h) == 1
    assert h.gateway.diagnostics_for_capability(h.token) == []


def test_request_duration_cannot_exceed_its_capability_stage_window(harness):
    clock = [0.]
    stream = DelayedChunks([(0, PING), (1, STOP)])
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream),
                clock=lambda: clock[0], request_timeout_seconds=1, stream_idle_timeout_seconds=1)
    token = h.gateway.issue_capability('run', h.epoch, 'execute', MODEL, 'ctx', 'finding', ttl_seconds=.05)
    response = asyncio.run(h.request({**MESSAGE, 'stream': True}, token_value=token))
    assert b'poc_gateway_stream_aborted' in response.content
    assert h.gateway.diagnostics_for_capability(token)[-1]['code'] == 'stream_request_timeout'
    assert stream.closed and quota(h) == 1


def test_request_timeout_is_clamped_to_the_remaining_audit_time(harness, monkeypatch):
    stream = DelayedChunks([(0, PING), (1, STOP)])
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream),
                request_timeout_seconds=1, stream_idle_timeout_seconds=1)
    original = h.store.execution_summary
    def remaining(run_id):
        summary = original(run_id)
        summary['run_remaining']['seconds'] = .05
        return summary
    monkeypatch.setattr(h.store, 'execution_summary', remaining)
    response = asyncio.run(h.request({**MESSAGE, 'stream': True}))
    assert b'poc_gateway_stream_aborted' in response.content
    diagnostic = h.gateway.diagnostics_for_capability(h.token)[-1]
    assert diagnostic['code'] == 'stream_request_timeout' and diagnostic['elapsed_seconds'] < .5
    assert stream.closed and quota(h) == 1


def test_sse_is_forwarded_with_bounded_body_and_no_credentials(harness):
    chunks = Chunks([b"event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
                     b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"])
    h = harness(lambda request: httpx.Response(200, headers={"content-type": "text/event-stream", "set-cookie": "secret=value"}, stream=chunks))
    result = asyncio.run(h.request({**MESSAGE, "stream": True}))
    assert result.status_code == 200 and result.headers["content-type"].startswith("text/event-stream")
    assert result.content == b"".join(chunks.chunks)
    assert "set-cookie" not in result.headers and chunks.closed
    assert quota(h) == 1


def test_stream_revocation_and_response_overflow_terminate_without_retry(harness):
    h = None

    def revoke():
        h.gateway.revoke_capability(h.token)
        return b"data: should-not-reach-client\n\n"

    chunks = Chunks([b"data: first\n\n", revoke])
    h = harness(lambda request: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=chunks))
    result = asyncio.run(h.request({**MESSAGE, "stream": True}))
    assert b"data: first" in result.content and b"poc_gateway_stream_aborted" in result.content
    assert b"should-not-reach-client" not in result.content and chunks.closed and quota(h) == 1
    overflow = harness(lambda request: httpx.Response(200, headers={"content-type": "text/event-stream"},
                                                   stream=Chunks([b"x" * 100])), max_response_bytes=50)
    result = asyncio.run(overflow.request({**MESSAGE, "stream": True}))
    assert b"poc_gateway_stream_aborted" in result.content and b"x" * 100 not in result.content


@pytest.mark.parametrize("failure", ["network", "timeout", "redirect", "bad_json", "oversize", "oversize_headers"])
def test_upstream_failure_is_bounded_counted_and_never_leaks_provider_detail(harness, failure):
    async def handler(request):
        if failure == "network":
            raise httpx.ConnectError(PROVIDER_KEY + " private prompt", request=request)
        if failure == "timeout":
            await asyncio.sleep(0.05)
            return httpx.Response(200, json=REPLY)
        if failure == "redirect":
            return httpx.Response(307, headers={"location": "https://evil.invalid/" + PROVIDER_KEY})
        if failure == "bad_json":
            return httpx.Response(200, headers={"content-type": "application/json"}, content=PROVIDER_KEY)
        if failure == "oversize_headers":
            return httpx.Response(200, headers={"x-secret": "x" * 17000}, json=REPLY)
        return httpx.Response(200, json={"secret": PROVIDER_KEY, "large": "x" * 10000})

    h = harness(handler, max_response_bytes=2000, request_timeout_seconds=0.01 if failure == "timeout" else 2)
    result = asyncio.run(h.request())
    assert result.status_code == 400 and result.json()["type"] == "error"
    assert PROVIDER_KEY not in result.text and "private prompt" not in result.text
    assert len(h.seen) == quota(h) == 1


def test_provider_retry_status_still_requires_a_new_durable_admission(harness):
    h = harness(lambda request: httpx.Response(503, json={"type": "error", "error": {"message": PROVIDER_KEY}}), stage_limit=1)

    async def exercise():
        first = await h.request()
        assert first.status_code == 503 and PROVIDER_KEY not in first.text
        second = await h.request()
        assert second.status_code == 400 and second.json()["error"]["code"] == "poc_gateway_admission_refused"

    asyncio.run(exercise())
    assert len(h.seen) == quota(h) == 1


def test_request_body_limit_precedes_admission(harness):
    h = harness(max_request_bytes=100)
    result = asyncio.run(h.request({**MESSAGE, "messages": [{"role": "user", "content": "x" * 500}]}))
    assert result.status_code == 400 and result.json()["error"]["code"] == "poc_gateway_request_too_large"
    assert h.seen == [] and quota(h) == 0


def test_duplicate_model_keys_are_canonicalized_and_non_json_numbers_are_rejected(harness):
    h = harness()

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=h.app), base_url="http://host.invalid") as client:
            headers = {"x-api-key": h.token, "content-type": "application/json"}
            duplicate = b'{"model":"unscoped-model","model":"' + MODEL.encode() + b'","messages":[],"max_tokens":1}'
            result = await client.post(PREFIX + "/v1/messages", content=duplicate, headers=headers)
            assert result.status_code == 200
            for invalid in (b'{"model":"' + MODEL.encode() + b'","max_tokens":NaN}',
                            b'{"model":"' + MODEL.encode() + b'","content":"\\ud800"}'):
                result = await client.post(PREFIX + "/v1/messages", content=invalid, headers=headers)
                assert result.status_code == 400

    asyncio.run(exercise())
    assert len(h.seen) == quota(h) == 1
    assert h.seen[0].content.count(b'"model"') == 1
    assert b"unscoped-model" not in h.seen[0].content


def test_concurrent_http_requests_cannot_exceed_durable_admission(harness):
    async def handler(request):
        await asyncio.sleep(0)
        return httpx.Response(200, json=REPLY)

    h = harness(handler, stage_limit=3)

    async def exercise():
        return await asyncio.gather(*(h.request() for _ in range(20)))

    results = asyncio.run(exercise())
    assert sum(result.status_code == 200 for result in results) == 3
    assert sum(result.status_code == 400 for result in results) == 17
    assert len(h.seen) == quota(h) == 3


# --- frozen generation verification -------------------------------------------------


def generation_token(h, max_output_tokens=4096, thinking="disabled"):
    return h.gateway.issue_capability(
        "run", h.epoch, "execute", MODEL, "context-1", "finding-1",
        max_output_tokens=max_output_tokens, thinking=thinking)


def test_generation_cap_and_thinking_are_verified_from_the_forwarded_body(harness):
    h = harness()
    token = generation_token(h)

    accepted = asyncio.run(h.request(token_value=token))
    assert accepted.status_code == 200
    assert json.loads(h.seen[-1].content) == MESSAGE
    assert quota(h) == 1

    def refused(body):
        result = asyncio.run(h.request(body, token_value=token))
        assert result.status_code == 400
        assert result.json()["error"]["code"].startswith("poc_gateway_")
        return result.json()["error"]["code"]

    assert refused({**MESSAGE, "max_tokens": 8192}) == "poc_gateway_output_cap_exceeded"
    assert refused({k: v for k, v in MESSAGE.items() if k != "max_tokens"}) == "poc_gateway_output_cap_missing"
    assert refused({**MESSAGE, "max_tokens": "20"}) == "poc_gateway_output_cap_missing"
    assert refused({**MESSAGE, "thinking": {"type": "enabled", "budget_tokens": 1024}}) \
        == "poc_gateway_thinking_rejected"
    # A non-dict thinking field cannot be proven disabled either.
    assert refused({**MESSAGE, "thinking": "disabled"}) == "poc_gateway_thinking_rejected"

    # Refusals happen before durable admission: no quota, no upstream call.
    assert quota(h) == 1
    assert len(h.seen) == 1

    observed = h.gateway.generation_for_capability(token)
    assert observed["configured"] == {"max_output_tokens": 4096, "thinking": "disabled"}
    assert observed["requests"] == 1
    assert observed["max_tokens"] == [20]
    assert observed["thinking_observed"] == ["absent"]


def test_generation_records_an_explicitly_disabled_thinking_block(harness):
    h = harness()
    token = generation_token(h, max_output_tokens=1024, thinking="")
    body = {**MESSAGE, "thinking": {"type": "disabled"}}
    assert asyncio.run(h.request(body, token_value=token)).status_code == 200
    observed = h.gateway.generation_for_capability(token)
    assert observed["max_tokens"] == [20]
    assert observed["thinking_observed"] == ["disabled"]


def test_provider_default_capability_inspects_and_records_nothing(harness):
    h = harness()
    body = {**MESSAGE, "max_tokens": 65536, "thinking": {"type": "enabled", "budget_tokens": 2048}}
    assert asyncio.run(h.request(body, token_value=h.token)).status_code == 200
    assert h.gateway.generation_for_capability(h.token) == {}
    assert quota(h) == 1


def test_capability_binding_rejects_an_invalid_generation_request(harness):
    h = harness()
    for binding in ({"max_output_tokens": -1}, {"max_output_tokens": 65537},
                    {"max_output_tokens": "4096"}, {"thinking": "enabled"}):
        with pytest.raises(ValueError):
            h.gateway.issue_capability("run", h.epoch, "execute", MODEL, "c", "f", **binding)


# --- rate-limited stream progress metadata ------------------------------------------

START = (b'event: message_start\ndata: {"type":"message_start","message":{"id":"m1",'
         b'"usage":{"input_tokens":11,"cache_read_input_tokens":4}}}\n\n')
DELTA = (b'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,'
         b'"delta":{"type":"text_delta","text":"private prompt text"}}\n\n')
USAGE = b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":7}}\n\n'


def stream_events(h):
    return [event for event in h.store.list_events(h.run["id"]) if event["kind"] == "poc_gateway_stream"]


def test_stream_end_metadata_reports_bytes_types_and_usage_without_text(harness):
    stream = Chunks([START, DELTA, USAGE, STOP])
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream))
    response = asyncio.run(h.request({**MESSAGE, "stream": True}))
    assert response.status_code == 200 and b"message_stop" in response.content

    events = stream_events(h)
    assert [event["payload"]["state"] for event in events] == ["end"]
    end = events[0]["payload"]
    assert end["completed"] is True and "code" not in end
    assert end["received_bytes"] == len(START + DELTA + USAGE + STOP)
    assert end["events_received"] == 4 and end["content_events"] == 3
    assert end["event_types"] == {"content_block_delta": 1, "message_delta": 1,
                                  "message_start": 1, "message_stop": 1}
    assert end["usage"] == {"input_tokens": 11, "cache_read_input_tokens": 4, "output_tokens": 7}
    assert isinstance(end["first_event_seconds"], (int, float))
    # Only metadata: no prompt or generated text may reach the durable log.
    assert "private prompt text" not in json.dumps(events)


def test_ping_only_streams_do_not_claim_progress(harness, monkeypatch):
    from audit import poc_model_gateway as module
    monkeypatch.setattr(module, "_STREAM_PROGRESS_SECONDS", 0.0)
    stream = Chunks([PING, PING, PING, STOP])
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream))
    asyncio.run(h.request({**MESSAGE, "stream": True}))
    states = [event["payload"]["state"] for event in stream_events(h)]
    assert states == ["end"]
    end = stream_events(h)[0]["payload"]
    assert end["content_events"] == 0 and end["event_types"] == {"ping": 3, "message_stop": 1}


def test_stream_progress_is_rate_limited_and_records_counts(harness, monkeypatch):
    from audit import poc_model_gateway as module
    monkeypatch.setattr(module, "_STREAM_PROGRESS_SECONDS", 0.0)
    stream = Chunks([START, DELTA, DELTA, USAGE, STOP])
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream))
    asyncio.run(h.request({**MESSAGE, "stream": True}))
    events = [event["payload"] for event in stream_events(h)]
    assert events[-1]["state"] == "end" and events[-1]["completed"] is True
    progress = [event for event in events if event["state"] == "progress"]
    assert progress and all(event["completed"] is False for event in progress)
    assert progress[0]["content_events"] >= 1
    assert [event["elapsed_seconds"] for event in progress] == sorted(
        event["elapsed_seconds"] for event in progress)
    assert len(events) <= module._STREAM_PROGRESS_MAX


def test_aborted_stream_records_an_end_event_with_its_cause(harness):
    stream = DelayedChunks([(0, START), (1, STOP)])
    h = harness(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=stream),
                stream_idle_timeout_seconds=.03)
    response = asyncio.run(h.request({**MESSAGE, "stream": True}))
    assert b"poc_gateway_stream_aborted" in response.content
    events = stream_events(h)
    assert len(events) == 1 and events[0]["payload"]["state"] == "end"
    assert events[0]["payload"]["completed"] is False
    assert events[0]["payload"]["code"] == "stream_idle_timeout"
