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
_ERROR_TYPES = {'authentication_error', 'permission_error', 'not_found_error', 'rate_limit_error',
                'invalid_request_error', 'api_error', 'overloaded_error', 'timeout_error'}
_ERROR_CODES = {'AccountQuotaExceeded', 'insufficient_quota', 'quota_exceeded', 'rate_limit_exceeded',
                'invalid_api_key', 'context_length_exceeded', 'RequestBurstTooFast'}
_STREAM_EVENTS = {'message_start', 'message_delta', 'message_stop', 'content_block_start',
                  'content_block_delta', 'content_block_stop', 'ping', 'error'}
# Stream metadata is rate limited: a long generation must not turn the durable event
# log into a per-chunk transcript, and pings alone never count as progress.
_STREAM_PROGRESS_SECONDS = 5.0
_STREAM_PROGRESS_MAX = 120
# Keepalive and completion frames are not generation progress.
_NON_PROGRESS_EVENTS = ('ping', 'message_stop')
_USAGE_FIELDS = ('input_tokens', 'output_tokens', 'cache_creation_input_tokens', 'cache_read_input_tokens')


def _content_events(types: dict) -> int:
    return sum(count for name, count in types.items() if name not in _NON_PROGRESS_EVENTS)


def _stream_usage(value) -> dict:
    """Only numeric token counters, never message content or provider extensions."""
    if not isinstance(value, dict):
        return {}
    return {name: value[name] for name in _USAGE_FIELDS
            if type(value.get(name)) is int and 0 <= value[name] <= 10_000_000}


class _StreamFailure(Exception):
    def __init__(self, code):
        self.code = code


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
    session_policy: str = ""
    # Frozen generation policy for this capability.  ``0``/``""`` mean the provider
    # default: nothing is verified, which is what a historical run sends.
    max_output_tokens: int = 0
    thinking: str = ""


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
        request_timeout_seconds: float = 180.0,
        stream_idle_timeout_seconds: float = 120.0,
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
        if not math.isfinite(stream_idle_timeout_seconds) or not 0 < stream_idle_timeout_seconds <= 600:
            raise ValueError('Gateway stream idle timeout must be between zero and 600 seconds')
        if min(max_request_bytes, max_response_bytes) < 1:
            raise ValueError("Gateway body limits must be positive")
        self._timeout = float(request_timeout_seconds)
        self._idle_timeout = float(stream_idle_timeout_seconds)
        self._max_request = int(max_request_bytes)
        self._max_response = int(max_response_bytes)
        self._capabilities: dict[str, _Capability] = {}
        self._refusals: dict[str, dict] = {}
        self._diagnostics: dict[str, list[dict]] = {}
        self._generation: dict[str, dict] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_environ(cls, store) -> "PocModelGateway":
        return cls(
            store,
            enabled=os.environ.get("POC_CLAUDE_GATEWAY_ENABLED", "0").strip().lower() in {"1", "true", "yes"},
            upstream_url=os.environ.get("POC_CLAUDE_UPSTREAM_URL", ""),
            upstream_api_key=os.environ.get("POC_CLAUDE_UPSTREAM_API_KEY", ""),
            request_timeout_seconds=float(os.environ.get('POC_CLAUDE_REQUEST_SECONDS', '180')),
            stream_idle_timeout_seconds=float(os.environ.get('POC_CLAUDE_STREAM_IDLE_SECONDS', '120')),
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
        session_policy: str = "",
        max_output_tokens: int = 0,
        thinking: str = "",
    ) -> str:
        if not self.readiness()["ready"]:
            raise ValueError("POC model gateway is not ready")
        if stage not in _STAGES or type(epoch) is not int or epoch < 0:
            raise ValueError("Invalid POC capability scope")
        if any(not isinstance(value, str) or not value or len(value) > 256
               or any(ord(ch) < 32 for ch in value)
               for value in (run_id, model, context_id, finding_id)):
            raise ValueError("POC capability identifiers must be bounded nonempty strings")
        if session_policy not in {"", "session-queue-v1"} or (session_policy and (stage != "execute" or not quota_scope)):
            raise ValueError("Invalid persistent queue capability")
        if type(max_output_tokens) is not int or not 0 <= max_output_tokens <= 65536:
            raise ValueError("Invalid POC capability output limit")
        if thinking not in {"", "disabled"}:
            raise ValueError("Invalid POC capability thinking policy")
        ttl_limit = 14400 if session_policy else 3600
        if not math.isfinite(ttl_seconds) or not 0 < ttl_seconds <= ttl_limit:
            raise ValueError(f"POC capability TTL must be between zero and {ttl_limit} seconds")
        if not self._run_allowed(run_id, epoch):
            raise ValueError("POC capability execution is inactive")
        if quota_scope and not re.fullmatch(r"[0-9a-f]{64}", quota_scope):
            raise ValueError("Invalid attempt quota scope")
        now = self._clock()
        capability = _Capability(run_id, epoch, stage, model, context_id, finding_id, now + ttl_seconds,
                                 quota_scope, session_policy, max_output_tokens, thinking)
        with self._lock:
            self._capabilities = {key: value for key, value in self._capabilities.items()
                                  if value.deadline > now}
            self._refusals = {key: value for key, value in self._refusals.items()
                              if key in self._capabilities}
            self._generation = {key: value for key, value in self._generation.items()
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
            self._diagnostics.pop(self._digest(token), None)
            self._generation.pop(self._digest(token), None)

    def diagnostics_for_capability(self, token: str) -> list[dict]:
        with self._lock:
            return [dict(item) for item in self._diagnostics.get(self._digest(token), [])]

    def generation_for_capability(self, token: str) -> dict:
        """What upstream requests really carried, verified by this gateway only."""
        with self._lock:
            return dict(self._generation.get(self._digest(token), {}))

    def _diagnose(self, digest, capability, code, *, http_status=None, provider=None, timing=None):
        """Persist allowlisted metadata, never upstream text, prompts or credentials."""
        error = provider.get('error') if isinstance(provider, dict) else None
        error = error if isinstance(error, dict) else {}
        kind = error.get('type')
        provider_code = error.get('code')
        diagnostic = dict(stage=capability.stage, code=code, http_status=http_status,
            provider_error_type=kind if isinstance(kind, str) and kind in _ERROR_TYPES else 'unknown',
            provider_error_code=provider_code if isinstance(provider_code, str) and provider_code in _ERROR_CODES else 'unknown')
        if timing:
            diagnostic.update({key: timing[key] for key in ('elapsed_seconds', 'idle_seconds', 'received_bytes',
                'events_received', 'last_event_type', 'request_timeout_seconds', 'stream_idle_timeout_seconds') if key in timing})
        with self._lock:
            # A late HTTP response cannot restore a revoked capability or publish facts.
            if self._capabilities.get(digest) is not capability:
                return
            self._diagnostics[digest] = (self._diagnostics.get(digest, []) + [diagnostic])[-16:]
        if self._run_allowed(capability.run_id, capability.epoch):
            self.store.append_event(capability.run_id, None, 'poc_gateway_error', {
                **diagnostic, 'role': 'poc', 'runtime': 'claude_sdk', 'finding_id': capability.finding_id,
                'context_id': capability.context_id, 'execution_epoch': capability.epoch})

    def refusal_for_capability(self, token: str) -> dict:
        """Host-only structured admission failure; read before revoking the token."""
        with self._lock:
            return dict(self._refusals.get(self._digest(token), {}))

    def _check_generation(self, digest, capability: _Capability, body: dict):
        """Enforce the frozen output cap and thinking policy on the real request.

        A missing or oversized ``max_tokens`` is a protocol error the host reports,
        never something it silently rewrites.  A ``provider_default`` capability
        (empty values) is not inspected and records nothing, exactly like a run that
        predates this policy.
        """
        if not capability.max_output_tokens and capability.thinking != "disabled":
            return None
        max_tokens = body.get("max_tokens")
        if capability.max_output_tokens:
            if type(max_tokens) is not int or max_tokens < 1:
                self._diagnose(digest, capability, 'output_cap_missing')
                return _error("poc_gateway_output_cap_missing",
                              "The host bounds POC output; the request must declare a positive max_tokens.")
            if max_tokens > capability.max_output_tokens:
                self._diagnose(digest, capability, 'output_cap_exceeded')
                return _error("poc_gateway_output_cap_exceeded",
                              "The request exceeds the frozen POC output limit.")
        thinking = body.get("thinking")
        kind = thinking.get("type") if isinstance(thinking, dict) else None
        # An absent field is the CLI's own way of saying "not enabled"; anything
        # present that is not an explicit ``disabled`` block is unproven and refused.
        if capability.thinking == "disabled" and thinking is not None and kind != "disabled":
            self._diagnose(digest, capability, 'thinking_rejected')
            return _error("poc_gateway_thinking_rejected",
                          "The host disabled thinking for this POC stage.")
        self._record_generation(digest, capability, max_tokens, kind)
        return None

    def _record_generation(self, digest, capability: _Capability, max_tokens, thinking) -> None:
        with self._lock:
            if self._capabilities.get(digest) is not capability:
                return
            current = self._generation.get(digest) or {
                "configured": {"max_output_tokens": capability.max_output_tokens,
                               "thinking": capability.thinking or "provider_default"},
                "requests": 0, "max_tokens": [], "thinking_observed": []}
            current["requests"] = int(current.get("requests") or 0) + 1
            if type(max_tokens) is int:
                values = current.setdefault("max_tokens", [])
                if max_tokens not in values:
                    values.append(max_tokens)
                    del values[:-8]
            observed = thinking if isinstance(thinking, str) and thinking else "absent"
            values = current.setdefault("thinking_observed", [])
            if observed not in values:
                values.append(observed)
                del values[:-8]
            self._generation[digest] = current

    def _stream_event(self, capability: _Capability, state: str, *, elapsed, bytes_received,
                      events, content_events, types, first_event, usage, completed, code=None):
        """Durable, rate-limited stream metadata; never model text or headers."""
        if not self._run_allowed(capability.run_id, capability.epoch):
            return
        payload = {
            "role": "poc", "runtime": "claude_sdk", "state": state, "stage": capability.stage,
            "finding_id": capability.finding_id, "context_id": capability.context_id,
            "execution_epoch": capability.epoch, "elapsed_seconds": round(elapsed, 3),
            "received_bytes": int(bytes_received), "events_received": int(events),
            "content_events": max(0, int(content_events)),
            "event_types": {name: int(count) for name, count in sorted(types.items())},
            "usage": dict(usage), "completed": bool(completed),
        }
        if first_event is not None:
            payload["first_event_seconds"] = round(first_event, 3)
        if code:
            payload["code"] = code
        self.store.append_event(capability.run_id, None, 'poc_gateway_stream', payload)

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _run_allowed(self, run_id: str, epoch: int) -> bool:
        # A pause can allow existing tool publication while quiescing. New model
        # requests stop immediately, even during that transition.
        #
        # This runs once or more per relayed chunk, so it must not build the run
        # summary: ``get_run`` fans out a query per finding (tens of milliseconds
        # on a mature run) and would cap the relay far below the provider's rate.
        status_of = getattr(self.store, "run_status", None)
        if status_of is not None:
            active = status_of(run_id) == "running"
        else:
            run = self.store.get_run(run_id)
            active = bool(run and run.get("status") == "running")
        return active and self.store.execution_write_allowed(run_id, epoch)

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
        started = time.monotonic()
        window = max(0., capability.deadline - self._clock())
        # A healthy interactive queue stream may outlive the old single-request
        # total timeout. Idle/connect protection and the run deadline still apply.
        deadline = started + (window if capability.session_policy else min(self._timeout, window))
        try:
            async with asyncio.timeout_at(deadline) as timeout:
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
                if path == _MESSAGES:
                    # Verify the generation metadata before admission: a run that
                    # froze an output cap must never spend a request the host did not
                    # actually bound, and a refusal is a named protocol error.
                    refusal = self._check_generation(digest, capability, body)
                    if refusal is not None:
                        return refusal
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
                # Admission and stream time use the same remaining run/stage window;
                # a longer per-request timeout must never enlarge an audit budget.
                summary = self.store.execution_summary(capability.run_id) or {}
                remaining_seconds = (summary.get('run_remaining') or {}).get('seconds')
                if isinstance(remaining_seconds, (int, float)):
                    deadline = min(deadline, time.monotonic() + max(0., remaining_seconds))
                    timeout.reschedule(deadline)
                stage_seconds = (summary.get('workflow') or {}).get('stage_remaining_seconds')
                if isinstance(stage_seconds, (int, float)):
                    deadline = min(deadline, time.monotonic() + max(0., stage_seconds))
                    timeout.reschedule(deadline)
                client = httpx.AsyncClient(
                    transport=self._transport, follow_redirects=False, trust_env=False,
                    timeout=httpx.Timeout(self._timeout, connect=min(10., self._timeout), read=self._idle_timeout),
                    limits=httpx.Limits(max_connections=1),
                )
                upstream_request = client.build_request("POST", self._upstream_url + path, headers=headers, content=payload)
                response = await client.send(upstream_request, stream=True)
                if not response.is_success:
                    self._diagnose(digest, capability, 'upstream_http_error', http_status=response.status_code)
                if sum(len(key) + len(value) for key, value in response.headers.raw) > _MAX_HEADERS:
                    self._diagnose(digest, capability, 'upstream_headers_too_large', http_status=response.status_code)
                    return _error("poc_gateway_response_rejected", "Upstream response headers exceed the gateway limit.")
                if 300 <= response.status_code < 400:
                    return _error("poc_gateway_redirect_rejected", "Upstream redirects are not permitted.")
                if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                    self._diagnose(digest, capability, 'unsupported_content_encoding', http_status=response.status_code)
                    return _error("poc_gateway_response_rejected", "Encoded upstream responses are not permitted.")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if streaming and response.is_success:
                    if content_type != "text/event-stream":
                        self._diagnose(digest, capability, 'invalid_event_stream', http_status=response.status_code)
                        return _error("poc_gateway_response_rejected", "The upstream did not return an Anthropic event stream.")
                    handed_off = True
                    return StreamingResponse(
                        self._stream(response, client, digest, capability, deadline, started=started),
                        status_code=response.status_code, media_type="text/event-stream",
                        headers={"cache-control": "no-store", "x-accel-buffering": "no"},
                    )
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    if not self._active(digest, capability):
                        return _error("poc_gateway_capability_rejected", "The POC capability is no longer active.")
                    if len(data) + len(chunk) > self._max_response:
                        self._diagnose(digest, capability, 'upstream_body_too_large', http_status=response.status_code)
                        return _error("poc_gateway_response_too_large", "Upstream response exceeds the gateway limit.")
                    data.extend(chunk)
                if content_type != "application/json":
                    self._diagnose(digest, capability, 'invalid_content_type', http_status=response.status_code)
                    return _error("poc_gateway_response_rejected", "The upstream did not return Anthropic JSON.")
                try:
                    parsed = json.loads(data)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    self._diagnose(digest, capability, 'invalid_json', http_status=response.status_code)
                    return _error("poc_gateway_response_rejected", "The upstream returned invalid JSON.")
                if not isinstance(parsed, dict):
                    self._diagnose(digest, capability, 'invalid_json_shape', http_status=response.status_code)
                    return _error("poc_gateway_response_rejected", "The upstream returned invalid Anthropic JSON.")
                if response.is_success and parsed.get('type') == 'error':
                    self._diagnose(digest, capability, 'upstream_error_envelope', http_status=response.status_code, provider=parsed)
                if not response.is_success:
                    # Provider error text may contain reflected credentials or full
                    # prompts. Preserve retry status without disclosing that text.
                    self._diagnose(digest, capability, 'upstream_rejected', http_status=response.status_code, provider=parsed)
                    return _error("poc_gateway_upstream_error", "The model upstream rejected the request.", response.status_code)
                return Response(bytes(data), status_code=response.status_code, media_type="application/json",
                                headers={"cache-control": "no-store"})
        except (httpx.HTTPError, TimeoutError) as exc:
            self._diagnose(digest, capability, 'upstream_timeout' if isinstance(exc, (httpx.TimeoutException, TimeoutError)) else 'upstream_connection_error')
            return _error("poc_gateway_upstream_unavailable", "The model upstream could not complete the request.")
        finally:
            if not handed_off:
                if response is not None:
                    await response.aclose()
                if client is not None:
                    await client.aclose()

    async def _stream(self, response, client, digest, capability, deadline, *, started=None):
        used = 0
        pending = b''
        started = started if started is not None else time.monotonic()
        last_chunk = time.monotonic()
        events_received = 0
        last_event = ''
        types: dict[str, int] = {}
        usage: dict[str, int] = {}
        first_event = None
        progress_sent = 0
        last_progress = started
        ended = False

        def pulse(state, *, code=None):
            nonlocal ended, progress_sent, last_progress
            now = time.monotonic()
            last_progress = now
            if state == 'end':
                ended = True
            else:
                progress_sent += 1
            # Read-only check: expiry handling belongs to the loop above, and pruning
            # here would also drop the diagnostics this very stream still owes.
            with self._lock:
                if self._capabilities.get(digest) is not capability:
                    return
            self._stream_event(capability, state, elapsed=now - started, bytes_received=used,
                               events=events_received, content_events=_content_events(types),
                               types=types, first_event=first_event, usage=usage,
                               completed=state == 'end' and code is None, code=code)

        iterator = response.aiter_bytes().__aiter__()
        reader = None
        try:
            while True:
                if not self._active(digest, capability):
                    raise _StreamFailure('stream_context_stopped')
                try:
                    reader = asyncio.create_task(iterator.__anext__())
                    while not reader.done():
                        remaining = deadline - time.monotonic()
                        idle_remaining = self._idle_timeout - (time.monotonic() - last_chunk)
                        if remaining <= 0:
                            raise _StreamFailure('stream_run_deadline' if capability.session_policy else 'stream_request_timeout')
                        if idle_remaining <= 0:
                            raise _StreamFailure('stream_idle_timeout')
                        if not self._active(digest, capability):
                            raise _StreamFailure('stream_context_stopped')
                        await asyncio.wait({reader}, timeout=min(.25, remaining, idle_remaining))
                    chunk = await reader
                except StopAsyncIteration:
                    raise _StreamFailure('stream_incomplete') from None
                used += len(chunk)
                last_chunk = time.monotonic()
                if not self._active(digest, capability):
                    raise _StreamFailure('stream_context_stopped')
                if time.monotonic() >= deadline:
                    raise _StreamFailure('stream_run_deadline' if capability.session_policy else 'stream_request_timeout')
                if used > self._max_response:
                    raise _StreamFailure('stream_response_too_large')
                # Inspect only bounded SSE frames; persist metadata from error frames only.
                pending = (pending + chunk).replace(b'\r\n', b'\n')
                frames = pending.split(b'\n\n')
                pending = frames.pop()[-65536:]
                completed = False
                for frame in frames:
                    if len(frame) > 65536:
                        continue
                    data = b'\n'.join(line[5:].lstrip() for line in frame.splitlines() if line.startswith(b'data:'))
                    try:
                        message = json.loads(data)
                    except (ValueError, UnicodeDecodeError, RecursionError):
                        continue
                    if isinstance(message, dict):
                        kind = message.get('type')
                        events_received += 1
                        last_event = kind if isinstance(kind, str) and kind in _STREAM_EVENTS else 'unknown'
                        types[last_event] = types.get(last_event, 0) + 1
                        if first_event is None:
                            first_event = last_chunk - started
                        if last_event == 'message_start' and isinstance(message.get('message'), dict):
                            usage.update(_stream_usage(message['message'].get('usage')))
                        elif last_event == 'message_delta':
                            usage.update(_stream_usage(message.get('usage')))
                        if kind == 'error':
                            self._diagnose(digest, capability, 'upstream_stream_error', http_status=response.status_code, provider=message)
                            completed = True  # The actual provider error is already forwarded.
                        elif kind == 'message_stop':
                            completed = True
                # Rate-limited metadata only: bytes, event types, timing and usage.
                # Keepalive pings alone are not generation progress and stay silent.
                if (_content_events(types) > 0 and progress_sent < _STREAM_PROGRESS_MAX
                        and time.monotonic() - last_progress >= _STREAM_PROGRESS_SECONDS):
                    pulse('progress')
                yield chunk
                # Anthropic message_stop completes the response; persistent upstream
                # connections need not close their HTTP socket before we can finish.
                if completed:
                    pulse('end')
                    return
        except (_StreamFailure, httpx.HTTPError, TimeoutError) as exc:
            code = (exc.code if isinstance(exc, _StreamFailure) else
                    'stream_idle_timeout' if isinstance(exc, httpx.ReadTimeout) else
                    'stream_request_timeout' if isinstance(exc, (httpx.TimeoutException, TimeoutError)) else 'stream_connection_error')
            if not ended:
                pulse('end', code=code)
            self._diagnose(digest, capability, code, http_status=response.status_code, timing={
                'elapsed_seconds': round(time.monotonic() - started, 3),
                'idle_seconds': round(time.monotonic() - last_chunk, 3), 'received_bytes': used,
                'events_received': events_received, 'last_event_type': last_event,
                'request_timeout_seconds': round(deadline - started, 3), 'stream_idle_timeout_seconds': self._idle_timeout})
            event = {"type": "error", "error": {"type": "invalid_request_error",
                     "message": "POC gateway stream terminated.", "code": "poc_gateway_stream_aborted"}}
            yield b"event: error\ndata: " + json.dumps(event, separators=(",", ":")).encode() + b"\n\n"
        finally:
            if reader is not None:
                if not reader.done():
                    reader.cancel()
                await asyncio.gather(reader, return_exceptions=True)
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
