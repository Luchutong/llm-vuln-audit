"""Correlated server diagnostics for controlled HTTP observations.

Two rules keep this channel trustworthy:

* Only the runner mints the correlation id.  It is written as a request header on
  the single request ``http_observe`` sends, so a model cannot choose it, and an
  externally supplied header of the same name is dropped before the request leaves
  the runner.
* The runner never reads shop logs, the database or the container's stdout.  It
  asks the separate internal collector, which only knows the entries the PHP
  observer wrote for that exact request id.

Nothing here is proof of a vulnerability: an empty page and a missing diagnostic
are different observations, and the caller must keep them apart.
"""
from __future__ import annotations

import re
import secrets
from typing import Any

import httpx

REQUEST_HEADER = "X-Verification-Request-Id"
REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
CURSOR = re.compile(r"^[0-9]{0,9}$")
PAGE_ITEMS = 20
PAGE_BYTES = 8 * 1024
MAX_ITEM_TEXT = 500
MAX_ITEMS_PER_REQUEST = 20
# A job whose log line never arrived within the window is reported as expired,
# not as "no errors".  Keep this below the job TTL so an expired window is still
# answerable while the job record exists.
WINDOW_SECONDS = 600.0


def new_request_id() -> str:
    return secrets.token_hex(16)


def valid_request_id(value: object) -> bool:
    return isinstance(value, str) and bool(REQUEST_ID.fullmatch(value))


def public_item(raw: Any, *, request_id: str, index: int) -> dict | None:
    """Sanitise one collector entry; the model sees a bounded, path-free record."""
    if not isinstance(raw, dict):
        return None
    message = " ".join(str(raw.get("message") or "").split())[:MAX_ITEM_TEXT]
    kind = str(raw.get("kind") or "")
    if not message or kind not in {"php_error", "php_warning", "php_notice", "php_fatal"}:
        return None
    line = raw.get("line")
    return {
        "diagnostic_id": f"{request_id[:8]}-{index}",
        "request_id": request_id,
        "kind": kind,
        "message": message,
        "source_path": str(raw.get("source_path") or "")[:200],
        "line": line if type(line) is int and line > 0 else 0,
    }


class DiagnosticsClient:
    """Minimal client for the internal collector; one bounded page per call."""

    def __init__(self, base_url: str = "", token: str = "", *, timeout: float = 5.0,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.base_url = (base_url or "").strip().rstrip("/")
        self.token = token or ""
        self.timeout = timeout
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.token)

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url or "http://unconfigured",
                timeout=self.timeout,
                transport=self._transport,
                follow_redirects=False,
                # The collector lives on a private Docker network; a developer proxy
                # would answer instead of it (and would see the bearer token).
                trust_env=False,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def fetch(self, request_id: str, cursor: str = "") -> dict:
        """Return the collector's page for one request id.

        Raises httpx/transport errors; the caller maps them to ``collector_unavailable``
        instead of pretending the request produced no PHP errors.
        """
        response = await self._http().get(
            "/v1/diagnostics",
            params={"request_id": request_id, "cursor": cursor, "wait": "2"},
            headers={"Accept": "application/json", "Authorization": f"Bearer {self.token}"},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("collector returned an unexpected shape")
        return payload


def sanitise_page(payload: dict, *, request_id: str) -> dict:
    """Keep only the fields the host contract promises, in page order."""
    items: list[dict] = []
    for index, raw in enumerate(payload.get("items") or []):
        item = public_item(raw, request_id=request_id, index=index)
        if item is not None:
            items.append(item)
    return {
        "seen": bool(payload.get("seen")),
        "items": items,
        "next_cursor": str(payload.get("next_cursor") or "") if CURSOR.fullmatch(str(payload.get("next_cursor") or "")) else "",
        "truncated": bool(payload.get("truncated")),
    }


def render_lines(items: list[dict]) -> str:
    """Deterministic text for the host evidence channel (no host paths, no bodies)."""
    return "\n".join(
        f"{item.get('kind')}: {item.get('message')}"
        + (f" ({item.get('source_path')}:{item.get('line')})" if item.get("source_path") else "")
        for item in items
    )
