"""Internal diagnostics collector for the Lab30 web tier.

The PHP observer appends one JSON line per controlled request to a volume shared with
this service.  The collector only ever answers "what did the observer record for this
request id", page-bounded and token-protected; it cannot read the shop's files, talk to
its database or execute anything.

Run standalone on the internal ``poc-control`` network::

    DIAGNOSTICS_TOKEN=... python -I collector.py
"""
from __future__ import annotations

import hmac
import json
import os
import re
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

TOKEN = (os.environ.get("DIAGNOSTICS_TOKEN") or "").strip()
FILE = Path(os.environ.get("DIAGNOSTICS_FILE") or "/var/log/shop-diag/diagnostics.jsonl")
PORT = int(os.environ.get("DIAGNOSTICS_PORT") or 8091)
PAGE_ITEMS = 20
PAGE_BYTES = 8 * 1024
MAX_TEXT = 500
MAX_TRACKED = 512
MAX_FILE_BYTES = 4 * 1024 * 1024
REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
KIND = re.compile(r"^[a-z_]{3,24}$")


class Store:
    """Tail the append-only JSONL file into a bounded request-id index."""

    def __init__(self, path: Path = FILE) -> None:
        self.path = path
        self.offset = 0
        self.entries: OrderedDict[str, list[dict]] = OrderedDict()
        self.records = 0
        self.lock = threading.Lock()

    def refresh(self) -> None:
        with self.lock:
            try:
                size = self.path.stat().st_size
            except OSError:
                return
            if size < self.offset:
                # Rotated or truncated: nothing read so far can be trusted to match.
                self.offset, self.entries = 0, OrderedDict()
            if size == self.offset:
                return
            try:
                with self.path.open("rb") as handle:
                    handle.seek(self.offset)
                    chunk = handle.read(min(size - self.offset, MAX_FILE_BYTES))
            except OSError:
                return
            complete = chunk.rfind(b"\n")
            if complete < 0:
                return
            chunk = chunk[: complete + 1]
            self.offset += len(chunk)
            for raw in chunk.splitlines():
                try:
                    record = json.loads(raw.decode("utf-8", "replace"))
                except ValueError:
                    continue
                self._add(record)

    def _add(self, record: object) -> None:
        if not isinstance(record, dict):
            return
        request_id = str(record.get("request_id") or "")
        if not REQUEST_ID.fullmatch(request_id):
            return
        items = self.entries.setdefault(request_id, [])
        self.entries.move_to_end(request_id)
        while len(self.entries) > MAX_TRACKED:
            self.entries.popitem(last=False)
        self.records += 1
        for error in record.get("errors") or []:
            if len(items) >= PAGE_ITEMS:
                return
            if not isinstance(error, dict):
                continue
            message = " ".join(str(error.get("message") or "").split())[:MAX_TEXT]
            kind = str(error.get("kind") or "")
            if not message or not KIND.fullmatch(kind):
                continue
            line = error.get("line")
            items.append({
                "kind": kind, "message": message,
                "source_path": _relative(str(error.get("source_path") or "")),
                "line": line if type(line) is int and line > 0 else 0,
            })

    def page(self, request_id: str, cursor: str, wait: float) -> dict:
        deadline = time.monotonic() + wait
        while True:
            self.refresh()
            with self.lock:
                if request_id in self.entries:
                    items, seen = list(self.entries[request_id]), True
                    break
            if time.monotonic() >= deadline:
                items, seen = [], False
                break
            time.sleep(0.1)
        start = int(cursor or "0")
        page: list[dict] = []
        size = 0
        for item in items[start:]:
            payload = json.dumps(item, ensure_ascii=False).encode()
            if page and size + len(payload) > PAGE_BYTES:
                break
            page.append(item)
            size += len(payload)
        next_index = start + len(page)
        return {
            "ok": True, "seen": seen, "items": page,
            "next_cursor": str(next_index) if next_index < len(items) else "",
            "truncated": next_index < len(items),
        }


def _relative(path: str) -> str:
    """Never echo a container path: keep the part below the shop document root."""
    for prefix in ("/var/www/shop/", "/var/www/"):
        if path.startswith(prefix):
            return path[len(prefix):][:200]
    return os.path.basename(path)[:200] if "/" in path else path[:200]


STORE = Store()


class Handler(BaseHTTPRequestHandler):
    server_version = "shop-diagnostics"
    sys_version = ""

    def log_message(self, *_args) -> None:  # never log request paths or ids
        return

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler naming
        url = urlsplit(self.path)
        if url.path == "/healthz":
            self._send(200, {"ok": bool(TOKEN)})
            return
        if url.path != "/v1/diagnostics":
            self._send(404, {"ok": False, "error": "not_found"})
            return
        authorization = self.headers.get("Authorization", "")
        if not TOKEN or not hmac.compare_digest(authorization, f"Bearer {TOKEN}"):
            self._send(401, {"ok": False, "error": "unauthorized"})
            return
        query = parse_qs(url.query)
        request_id = (query.get("request_id") or [""])[0]
        cursor = (query.get("cursor") or [""])[0]
        if not REQUEST_ID.fullmatch(request_id) or not re.fullmatch(r"[0-9]{0,9}", cursor):
            self._send(400, {"ok": False, "error": "invalid_request"})
            return
        try:
            wait = max(0.0, min(3.0, float((query.get("wait") or ["0"])[0])))
        except ValueError:
            wait = 0.0
        self._send(200, STORE.page(request_id, cursor, wait))


def main() -> None:
    if not TOKEN:
        raise SystemExit("DIAGNOSTICS_TOKEN is required")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
