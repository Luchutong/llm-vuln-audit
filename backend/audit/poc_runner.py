"""HTTP client for the isolated POC runner.

The audit process never executes a POC script.  Every execution request leaves this
process as an ordinary HTTP call to the ``poc-runner`` container, which has no host
mounts, no published port and no route to the model endpoint.

Two error kinds matter to the caller:

* :class:`PocRunnerUnavailable` -- the runner is missing, down or too slow.  A run may
  continue and record ``environment_unavailable``.
* :class:`PocRunnerError` -- the runner answered and refused the request (bad script,
  disallowed path, oversized artifact).  Message text is bounded and stripped of the
  bearer token before it can reach durable state.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

import httpx

DEFAULT_TIMEOUT = 10.0
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 5 * 1024 * 1024
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TARGET = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


class PocRunnerUnavailable(RuntimeError):
    """The runner cannot be reached; this is an environment condition, not a verdict."""


class PocRunnerError(RuntimeError):
    """The runner rejected a request or returned a malformed response."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class PocRunnerBusy(PocRunnerError):
    """A target lease is occupied; callers may wait within their own budget."""


def _segment(value: object, name: str) -> str:
    text = str(value or "")
    if not _SAFE_SEGMENT.fullmatch(text):
        raise PocRunnerError(f"invalid {name}")
    return text


def _target(value: object) -> str:
    text = str(value or "")
    if not _TARGET.fullmatch(text):
        raise PocRunnerError("invalid target")
    return text


class PocRunnerClient:
    def __init__(
        self,
        base_url: str,
        token: str = "",
        *,
        timeout: float = DEFAULT_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = (base_url or "").strip().rstrip("/")
        self.token = token or ""
        self.timeout = timeout
        self._transport = transport
        self._client = client
        self._owns_client = client is None

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url or "http://unconfigured",
                timeout=self.timeout,
                transport=self._transport,
                follow_redirects=False,
                # The runner lives on a private Docker network.  Honouring a developer's
                # HTTP(S)_PROXY would send internal traffic (and its bearer token) to a
                # corporate or local proxy, which answers 502 instead of the runner.
                trust_env=False,
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "PocRunnerClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def _redact(self, text: str) -> str:
        if self.token:
            text = text.replace(self.token, "[redacted]")
        return text[:400]

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _error_detail(self, response: httpx.Response, body: bytes) -> str:
        detail = ""
        try:
            payload = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            for key in ("detail", "error", "message"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    detail = value.strip()
                    break
        if not detail:
            detail = body.decode("utf-8", "replace").strip()
        detail = " ".join(detail.split())
        return self._redact(detail) if detail else "no detail"

    async def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict | None = None,
        timeout: float | None = None,
        max_bytes: int = MAX_JSON_BYTES,
    ) -> tuple[httpx.Response, bytes]:
        if not self.configured:
            raise PocRunnerUnavailable("POC runner is not configured")
        started = self._http()
        try:
            async with started.stream(
                method,
                path,
                json=payload,
                headers=self._headers(),
                timeout=timeout if timeout is not None else self.timeout,
            ) as response:
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > max_bytes:
                        raise PocRunnerError("POC runner response exceeds the size limit")
                    body.extend(chunk)
                return response, bytes(body)
        except httpx.TimeoutException as exc:
            raise PocRunnerUnavailable("POC runner timed out") from exc
        except httpx.HTTPError as exc:
            # Connection, DNS or protocol failures.  The exception text may contain the
            # internal endpoint; only the type is worth keeping.
            raise PocRunnerUnavailable(f"POC runner is unreachable ({type(exc).__name__})") from exc

    async def _json(
        self,
        method: str,
        path: str,
        *,
        payload: dict | None = None,
        timeout: float | None = None,
        max_bytes: int = MAX_JSON_BYTES,
    ) -> dict:
        response, body = await self._request(
            method, path, payload=payload, timeout=timeout, max_bytes=max_bytes
        )
        if response.status_code >= 400:
            detail = await self._error_detail(response, body)
            error = PocRunnerBusy if response.status_code == 409 else PocRunnerError
            raise error(f"POC runner rejected the request ({response.status_code}): {detail}", status_code=response.status_code)
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise PocRunnerError("POC runner returned a non-JSON response") from exc
        if not isinstance(parsed, dict):
            raise PocRunnerError("POC runner returned an unexpected response shape")
        return parsed

    async def _job_submission(self, path: str, *, payload: dict, timeout: float) -> dict:
        result = await self._json("POST", path, payload=payload, timeout=timeout)
        if payload.get("job_id") and result.get("job_id") != payload["job_id"]:
            raise PocRunnerError("POC runner did not preserve the host job id")
        if payload.get("context_id") and result.get("context_id") != payload["context_id"]:
            raise PocRunnerError("POC runner job belongs to another verification context")
        return result

    # ---- target lifecycle -------------------------------------------------------

    async def health(self) -> dict:
        return await self._json("GET", "/healthz", timeout=min(self.timeout, 5.0))

    async def create_context(self, target: str = "lab30", *, run_id: str, finding_id: str, context_id: str = "") -> dict:
        payload = {"target": _target(target), "run_id": run_id, "finding_id": finding_id}
        if context_id:
            payload["context_id"] = _segment(context_id, "context id")
        return await self._json("POST", "/v1/verification-contexts", payload=payload)

    async def close_context(self, context_id: str) -> dict:
        return await self._json("DELETE", f"/v1/verification-contexts/{quote(_segment(context_id, 'context id'))}")

    async def context_status(self, context_id: str) -> dict:
        """Read one context without changing it.

        An unknown id means the runner never created it or has already swept it, so no
        job can still be running under it: report it as closed rather than as an error.
        """
        ident = _segment(context_id, "context id")
        try:
            return await self._json("GET", f"/v1/verification-contexts/{quote(ident)}", timeout=min(self.timeout, 10.0))
        except PocRunnerError as exc:
            if exc.status_code == 404:
                return {"context_id": ident, "state": "closed", "pending_jobs": 0, "was_unknown": True}
            raise

    async def prepare_target(
        self, target: str = "lab30", *, reset: bool = False, context_id: str = "", identity: str = "alice", expected_role: str | None = None, expected_state: dict | None = None
    ) -> dict:
        name = _target(target)
        return await self._json(
            "POST",
            f"/v1/targets/{quote(name)}/prepare",
            payload={"reset": bool(reset), "context_id": context_id, "identity": identity, "expected_role": expected_role, "expected_state": expected_state},
            timeout=max(self.timeout, 90.0),
        )

    async def target_status(self, target: str = "lab30", *, context_id: str = "", identity: str = "alice") -> dict:
        name = _target(target)
        query = f"?context_id={quote(context_id)}&identity={quote(identity)}" if context_id else ""
        return await self._json("GET", f"/v1/targets/{quote(name)}/status{query}")

    # ---- jobs -------------------------------------------------------------------

    async def run_job(
        self,
        *,
        target: str,
        language: str,
        script: str,
        timeout_seconds: int = 30,
        artifacts: list[str] | None = None,
        context_id: str = "",
        identity: str = "alice",
        job_id: str = "",
    ) -> dict:
        name = _target(target)
        lang = str(language or "").casefold()
        if lang not in {"php", "python"}:
            raise PocRunnerError("unsupported POC language")
        if not isinstance(script, str) or not script.strip():
            raise PocRunnerError("empty POC script")
        seconds = max(1, min(120, int(timeout_seconds or 30)))
        return await self._job_submission(
            "/v1/jobs",
            payload={
                "target": name,
                "language": lang,
                "script": script,
                "timeout_seconds": seconds,
                "artifacts": [str(item) for item in (artifacts or [])][:8],
                "context_id": context_id,
                "identity": identity,
                "job_id": _segment(job_id, "job id") if job_id else "",
            },
            # The job itself may take the whole budget; leave room for upload and
            # artifact copying so a slow script is not misreported as a dead runner.
            timeout=seconds + 30.0,
        )

    async def get_job(self, job_id: str) -> dict:
        return await self._json("GET", f"/v1/jobs/{quote(_segment(job_id, 'job id'))}")

    async def diagnostics(self, job_id: str, cursor: str = "") -> dict:
        """One bounded page of correlated server diagnostics for a job.

        ``available: false`` carries a distinct reason (capability, pending, expired,
        collector failure); it never means "the request produced no errors".
        """
        ident = _segment(job_id, "job id")
        if not isinstance(cursor, str) or not re.fullmatch(r"[0-9]{0,9}", cursor):
            raise PocRunnerError("invalid diagnostics cursor")
        query = f"?cursor={quote(cursor)}" if cursor else ""
        return await self._json("GET", f"/v1/jobs/{quote(ident)}/diagnostics{query}",
                                timeout=min(self.timeout, 10.0))


    async def fetch_artifact(self, job_id: str, name: str) -> bytes:
        ident = _segment(job_id, "job id")
        artifact = _segment(name, "artifact name")
        response, body = await self._request(
            "GET",
            f"/v1/jobs/{quote(ident)}/artifacts/{quote(artifact)}",
            max_bytes=MAX_ARTIFACT_BYTES,
        )
        if response.status_code >= 400:
            detail = await self._error_detail(response, body)
            raise PocRunnerError(f"artifact unavailable ({response.status_code}): {detail}")
        return body

    # ---- observation helpers ----------------------------------------------------

    async def http_observe(
        self,
        *,
        target: str,
        method: str,
        path: str,
        body: str | None = None,
        headers: dict[str, str] | None = None,
        context_id: str = "",
        identity: str = "alice",
        job_id: str = "",
    ) -> dict:
        return await self._job_submission(
            "/v1/http",
            payload={
                "target": _target(target),
                "method": str(method or "GET").upper(),
                "path": str(path or "/"),
                "body": body or "",
                "headers": dict(headers or {}),
                "job_id": _segment(job_id, "job id") if job_id else "",
                "context_id": context_id,
                "identity": identity,
            },
            timeout=max(self.timeout, 45.0),
        )

    async def browser_check(
        self,
        *,
        target: str,
        path: str,
        script: str | None = None,
        wait_ms: int = 1000,
        context_id: str = "",
        identity: str = "alice",
        job_id: str = "",
    ) -> dict:
        return await self._job_submission(
            "/v1/browser/check",
            payload={
                "target": _target(target),
                "path": str(path or "/"),
                "script": script or "",
                "wait_ms": max(0, min(10000, int(wait_ms or 0))),
                "job_id": _segment(job_id, "job id") if job_id else "",
                "context_id": context_id,
                "identity": identity,
            },
            timeout=max(self.timeout, 60.0),
        )


def artifact_manifest(job: dict) -> list[dict[str, Any]]:
    """Normalise the runner's artifact list for durable storage."""
    items = job.get("artifacts")
    if not isinstance(items, list):
        return []
    clean = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not _SAFE_SEGMENT.fullmatch(name):
            continue
        clean.append(
            {
                "name": name,
                "sha256": str(item.get("sha256") or ""),
                "size": int(item.get("size") or 0),
            }
        )
    return clean
