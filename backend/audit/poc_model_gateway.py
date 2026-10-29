"""Capability-scoped Anthropic HTTP gateway for the POC SDK subprocess.

Only this host-side service sees the provider key. Every actual Messages request,
including SDK retries, obtains durable admission before a fixed upstream is called.
Capabilities are process-local and store only token hashes; restarting the process
invalidates every outstanding subprocess credential.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse


PROTOCOL_VERSION = "anthropic-messages-v1"
_MESSAGES = "/v1/messages"
_COUNT_TOKENS = "/v1/messages/count_tokens"
_STAGES = {"execute", "conclude"}
_MAX_CAPABILITIES = 4096
_MAX_HEADERS = 16 * 1024
_SAFE_HEADER = re.compile(r"[A-Za-z0-9,._ -]+\Z")


@dataclass(frozen=True, repr=False)
class _Capability:
    run_id: str
    epoch: int
    stage: str
    model: str
    context_id: str
    finding_id: str
    deadline: float
    quota_scope: str = ""


def _error(code: str, message: str, status: int = 400) -> JSONResponse:
    # Admission refusals use 400: the SDK must not turn exhausted quotas into an
    # endless 429/5xx retry loop. Messages never include upstream exception text.
    return JSONResponse(
        {"type": "error", "error": {
            "type": "invalid_request_error", "message": message, "code": code,
        }}, status_code=status, headers={"cache-control": "no-store"},
    )


class PocModelGateway:
    def __init__(
        self, store, *, enabled: bool = False, upstream_url: str = "",
        upstream_api_key: str = "", transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        request_timeout_seconds: float = 60.0,
        max_request_bytes: int = 2 * 1024 * 1024,
        max_response_bytes: int = 16 * 1024 * 1024,
    ):
        self.store = store
        self.enabled = bool(enabled)
        self._upstream_url = str(upstream_url).strip().rstrip("/")
        self._upstream_api_key = str(upstream_api_key).strip()
        self._transport = transport
        self._clock = clock
        if not math.isfinite(request_timeout_seconds) or not 0 < request_timeout_seconds <= 600:
            raise ValueError("Gateway timeout must be between zero and 600 seconds")
        if min(max_request_bytes, max_response_bytes) < 1:
            raise ValueError("Gateway body limits must be positive")
        self._timeout = float(request_timeout_seconds)
        self._max_request = int(max_request_bytes)
        self._max_response = int(max_response_bytes)
        self._capabilities: dict[str, _Capability] = {}
        self._refusals: dict[str, dict] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_environ(cls, store) -> "PocModelGateway":
        return cls(
            store,
            enabled=os.environ.get("POC_CLAUDE_GATEWAY_ENABLED", "0").strip().lower() in {"1", "true", "yes"},
            upstream_url=os.environ.get("POC_CLAUDE_UPSTREAM_URL", ""),
            upstream_api_key=os.environ.get("POC_CLAUDE_UPSTREAM_API_KEY", ""),
        )

    def readiness(self) -> dict:
        """Configuration inspection only; never contacts the upstream."""
        configured = bool(self._upstream_url and self._upstream_api_key)
        valid = self._valid_upstream()
        reason = ("disabled" if not self.enabled else
                  "upstream_not_configured" if not configured else
                  "invalid_upstream_configuration" if not valid else "ready")
        return {"ready": reason == "ready", "reason": reason,
                "protocol_version": PROTOCOL_VERSION, "upstream_configured": configured}

    def _valid_upstream(self) -> bool:
        try:
            url = urlsplit(self._upstream_url)
            _ = url.port
            return bool(
                url.scheme in {"http", "https"} and url.hostname and not url.username
                and not url.password and not url.query and not url.fragment
                and not any(ch.isspace() or ord(ch) < 32 for ch in self._upstream_url)
                and self._upstream_api_key
                and len(self._upstream_api_key) <= 4096
                and not any(ord(ch) < 32 or ord(ch) > 126 for ch in self._upstream_api_key)
            )
        except ValueError:
            return False

    def issue_capability(
        self, run_id: str, epoch: int, stage: str, model: str,
        context_id: str, finding_id: str, ttl_seconds: float = 300,
        quota_scope: str = "",
    ) -> str:
        if not self.readiness()["ready"]:
            raise ValueError("POC model gateway is not ready")
        if stage not in _STAGES or type(epoch) is not int or epoch < 0:
            raise ValueError("Invalid POC capability scope")
        if any(not isinstance(value, str) or not value or len(value) > 256
               or any(ord(ch) < 32 for ch in value)
               for value in (run_id, model, context_id, finding_id)):
            raise ValueError("POC capability identifiers must be bounded nonempty strings")
        if not math.isfinite(ttl_seconds) or not 0 < ttl_seconds <= 3600:
            raise ValueError("POC capability TTL must be between zero and 3600 seconds")
        if not self._run_allowed(run_id, epoch):
            raise ValueError("POC capability execution is inactive")
        if quota_scope and not re.fullmatch(r"[0-9a-f]{64}", quota_scope):
            raise ValueError("Invalid attempt quota scope")
        now = self._clock()
        capability = _Capability(run_id, epoch, stage, model, context_id, finding_id, now + ttl_seconds, quota_scope)
        with self._lock:
            self._capabilities = {key: value for key, value in self._capabilities.items()
                                  if value.deadline > now}
            self._refusals = {key: value for key, value in self._refusals.items()
                              if key in self._capabilities}
            if len(self._capabilities) >= _MAX_CAPABILITIES:
                raise ValueError("POC gateway capability capacity reached")
            token = secrets.token_urlsafe(32)
            self._capabilities[self._digest(token)] = capability
        return token

    def revoke_capability(self, token: str) -> None:
        with self._lock:
            self._capabilities.pop(self._digest(token), None)
            self._refusals.pop(self._digest(token), None)

    def refusal_for_capability(self, token: str) -> dict:
        """Host-only structured admission failure; read before revoking the token."""
        with self._lock:
            return dict(self._refusals.get(self._digest(token), {}))

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _run_allowed(self, run_id: str, epoch: int) -> bool:
        # A pause can allow existing tool publication while quiescing. New model
        # requests stop immediately, even during that transition.
        run = self.store.get_run(run_id)
        return bool(run and run.get("status") == "running"
                    and self.store.execution_write_allowed(run_id, epoch))

    def _active(self, digest: str, capability: _Capability) -> bool:
        with self._lock:
            current = self._capabilities.get(digest)
            if current is not capability or capability.deadline <= self._clock():
                self._capabilities.pop(digest, None)
                return False
        return self._run_allowed(capability.run_id, capability.epoch)

    def _authenticate(self, request: Request) -> tuple[str, _Capability] | None:
        authorization = request.headers.get("authorization", "")
        api_key = request.headers.get("x-api-key", "")
        token = authorization[7:] if authorization.startswith("Bearer ") else api_key
        if not token or len(token) > 256 or (authorization and authorization != "Bearer " + token):
            return None
        if api_key and api_key != token:
            return None
        digest = self._digest(token)
        with self._lock:
            capability = self._capabilities.get(digest)
        return (digest, capability) if capability is not None and self._active(digest, capability) else None

    async def handle(self, request: Request, path: str) -> Response:
        if not self.readiness()["ready"]:
            return _error("poc_gateway_unavailable", "POC model gateway is not enabled and configured.")
        # The real CLI sends Bearer credentials to ``/v1/messages?beta=true``.  That
        # marker is a client-side protocol switch, not part of admission: it is accepted
        # verbatim and never forwarded upstream.  Every other query still makes the route
        # ambiguous and is refused before authentication.
        if path not in {_MESSAGES, _COUNT_TOKENS} or request.method != "POST" \
                or request.url.query not in {"", "beta=true"}:
            return _error("poc_gateway_route_rejected", "Unsupported POC gateway route.")
        if sum(len(key) + len(value) for key, value in request.scope.get("headers", ())) > _MAX_HEADERS:
            return _error("poc_gateway_headers_too_large", "Request headers exceed the gateway limit.")
        authenticated = self._authenticate(request)
        if authenticated is None:
            return _error("poc_gateway_capability_rejected", "Missing, expired or inactive POC capability.", 401)
        digest, capability = authenticated
        client = None
        response = None
        handed_off = False
        deadline = time.monotonic() + self._timeout
        try:
            async with asyncio.timeout(self._timeout):
                if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                    return _error("poc_gateway_invalid_body", "The gateway accepts application/json only.")
                raw = bytearray()
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > self._max_request:
                        return _error("poc_gateway_request_too_large", "Request body exceeds the gateway limit.")
                    raw.extend(chunk)
                try:
                    body = json.loads(raw)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    return _error("poc_gateway_invalid_body", "The request must contain a JSON object.")
                if not isinstance(body, dict) or body.get("model") != capability.model:
                    return _error("poc_gateway_model_rejected", "The request model does not match its capability.")
                if "stream" in body and type(body["stream"]) is not bool:
                    return _error("poc_gateway_invalid_body", "The stream option must be a boolean.")
                streaming = path == _MESSAGES and body.get("stream") is True
                if path == _COUNT_TOKENS and body.get("stream"):
                    return _error("poc_gateway_invalid_body", "Token counting does not support streaming.")
                try:
                    # Canonicalizing removes duplicate-key ambiguity between our
                    # model check and an upstream's JSON parser. It also rejects
                    # Python's permissive NaN/Infinity and malformed Unicode.
                    payload = json.dumps(body, ensure_ascii=False, allow_nan=False,
                                         separators=(",", ":")).encode("utf-8")
                except (ValueError, UnicodeEncodeError, RecursionError):
                    return _error("poc_gateway_invalid_body", "The request must contain valid JSON values.")
                if len(payload) > self._max_request:
                    return _error("poc_gateway_request_too_large", "Request body exceeds the gateway limit.")
                headers = {"content-type": "application/json", "accept": "text/event-stream" if streaming else "application/json",
                           "x-api-key": self._upstream_api_key, "anthropic-version": "2023-06-01",
                           "user-agent": "vuln-audit-poc-gateway/1", "accept-encoding": "identity"}
                for name, limit in (("anthropic-version", 32), ("anthropic-beta", 1024)):
                    value = request.headers.get(name)
                    if value:
                        if len(value) > limit or not _SAFE_HEADER.fullmatch(value):
                            return _error("poc_gateway_invalid_headers", "Invalid Anthropic protocol header.")
                        headers[name] = value
                if not self._active(digest, capability):
                    return _error("poc_gateway_capability_rejected", "The POC capability is no longer active.")
                # No client run, stage or context header participates in admission.
                if path == _MESSAGES:
                    stage_key = capability.stage + ("@" + capability.quota_scope if capability.quota_scope else "")
                    admission = self.store.reserve_poc_request(capability.run_id, stage_key, capability.epoch)
                    if not admission.get("granted"):
                        with self._lock:
                            self._refusals.setdefault(digest, {
                                "reason": str(admission.get("reason") or "unavailable"),
                                "stage": capability.stage, "epoch": capability.epoch,
                                **{key: admission[key] for key in ("limit", "used", "remaining") if key in admission},
                            })
                        return _error("poc_gateway_admission_refused", "POC request admission refused: " + str(admission.get("reason") or "unavailable"))
                client = httpx.AsyncClient(
                    transport=self._transport, follow_redirects=False, trust_env=False,
                    timeout=httpx.Timeout(self._timeout), limits=httpx.Limits(max_connections=1),
                )
                upstream_request = client.build_request("POST", self._upstream_url + path, headers=headers, content=payload)
                response = await client.send(upstream_request, stream=True)
                if sum(len(key) + len(value) for key, value in response.headers.raw) > _MAX_HEADERS:
                    return _error("poc_gateway_response_rejected", "Upstream response headers exceed the gateway limit.")
                if 300 <= response.status_code < 400:
                    return _error("poc_gateway_redirect_rejected", "Upstream redirects are not permitted.")
                if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                    return _error("poc_gateway_response_rejected", "Encoded upstream responses are not permitted.")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if streaming and response.is_success:
                    if content_type != "text/event-stream":
                        return _error("poc_gateway_response_rejected", "The upstream did not return an Anthropic event stream.")
                    handed_off = True
                    return StreamingResponse(
                        self._stream(response, client, digest, capability, deadline),
                        status_code=response.status_code, media_type="text/event-stream",
                        headers={"cache-control": "no-store", "x-accel-buffering": "no"},
                    )
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    if not self._active(digest, capability):
                        return _error("poc_gateway_capability_rejected", "The POC capability is no longer active.")
                    if len(data) + len(chunk) > self._max_response:
                        return _error("poc_gateway_response_too_large", "Upstream response exceeds the gateway limit.")
                    data.extend(chunk)
                if content_type != "application/json":
                    return _error("poc_gateway_response_rejected", "The upstream did not return Anthropic JSON.")
                try:
                    parsed = json.loads(data)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    return _error("poc_gateway_response_rejected", "The upstream returned invalid JSON.")
                if not isinstance(parsed, dict):
                    return _error("poc_gateway_response_rejected", "The upstream returned invalid Anthropic JSON.")
                if not response.is_success:
                    # Provider error text may contain reflected credentials or full
                    # prompts. Preserve retry status without disclosing that text.
                    return _error("poc_gateway_upstream_error", "The model upstream rejected the request.", response.status_code)
                return Response(bytes(data), status_code=response.status_code, media_type="application/json",
                                headers={"cache-control": "no-store"})
        except (httpx.HTTPError, TimeoutError):
            return _error("poc_gateway_upstream_unavailable", "The model upstream could not complete the request.")
        finally:
            if not handed_off:
                if response is not None:
                    await response.aclose()
                if client is not None:
                    await client.aclose()

    async def _stream(self, response, client, digest, capability, deadline):
        used = 0
        iterator = response.aiter_bytes().__aiter__()
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self._active(digest, capability):
                    raise TimeoutError
                try:
                    chunk = await asyncio.wait_for(iterator.__anext__(), timeout=remaining)
                except StopAsyncIteration:
                    break
                used += len(chunk)
                if used > self._max_response or not self._active(digest, capability):
                    raise TimeoutError
                yield chunk
        except (httpx.HTTPError, TimeoutError):
            event = {"type": "error", "error": {"type": "invalid_request_error",
                     "message": "POC gateway stream terminated.", "code": "poc_gateway_stream_aborted"}}
            yield b"event: error\ndata: " + json.dumps(event, separators=(",", ":")).encode() + b"\n\n"
        finally:
            await response.aclose()
            await client.aclose()


router = APIRouter()


def _gateway(request: Request) -> PocModelGateway | None:
    services = getattr(request.app.state, "services", None)
    return (getattr(services, "poc_gateway", None)
            or getattr(getattr(request.app.state, "audit", None), "poc_gateway", None))


@router.get("/health")
async def gateway_health(request: Request):
    gateway = _gateway(request)
    if gateway is None:
        return {"ready": False, "reason": "unavailable", "protocol_version": PROTOCOL_VERSION,
                "upstream_configured": False}
    return gateway.readiness()


@router.post(_MESSAGES)
async def gateway_messages(request: Request):
    gateway = _gateway(request)
    return await gateway.handle(request, _MESSAGES) if gateway else _error("poc_gateway_unavailable", "POC model gateway is unavailable.")


@router.post(_COUNT_TOKENS)
async def gateway_count_tokens(request: Request):
    gateway = _gateway(request)
    return await gateway.handle(request, _COUNT_TOKENS) if gateway else _error("poc_gateway_unavailable", "POC model gateway is unavailable.")
