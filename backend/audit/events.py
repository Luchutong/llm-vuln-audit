"""Durable events with a live fan-out.

Every event is written to SQLite first and published second, so the log is the source
of truth and the live channel is allowed to be lossy: a subscriber that falls behind
recovers by replaying from the last id it saw.
"""
from __future__ import annotations

import asyncio
from typing import Any

from .db import Store

QUEUE_SIZE = 256


class EventBus:
    def __init__(self, store: Store):
        self._store = store
        self._subscribers: dict[str, set[asyncio.Queue]] = {}

    def emit(self, run_id: str, unit_id: str | None, kind: str, payload: Any) -> dict:
        event = self._store.append_event(run_id, unit_id, kind, payload)
        for queue in tuple(self._subscribers.get(run_id, ())):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # The SSE handler replays from the durable log, so dropping is safe.
                pass
        return event

    def subscribe(self, run_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        self._subscribers.setdefault(run_id, set()).add(queue)
        return queue

    def unsubscribe(self, run_id: str, queue: asyncio.Queue) -> None:
        subscribers = self._subscribers.get(run_id)
        if not subscribers:
            return
        subscribers.discard(queue)
        if not subscribers:
            self._subscribers.pop(run_id, None)
