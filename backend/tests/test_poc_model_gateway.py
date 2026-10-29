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
