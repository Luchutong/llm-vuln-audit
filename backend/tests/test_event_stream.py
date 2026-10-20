"""The SSE cursor follows the durable log even when live notifications are lost."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from audit import app as app_module
from audit.db import Store, now
from audit.events import EventBus, QUEUE_SIZE


class ObservedBus(EventBus):
    """Expose when the stream is idle without sleeping or starting an audit worker."""

    def __init__(self, store: Store):
        super().__init__(store)
        self.waiting = asyncio.Event()
        self.queue = None

    def subscribe(self, run_id: str) -> asyncio.Queue:
        queue = super().subscribe(run_id)
        get = queue.get

        async def observed_get():
            self.waiting.set()
            return await get()

        queue.get = observed_get
        self.queue = queue
        return queue


class StreamRequest:
    def __init__(self, state, headers=None):
        self.app = SimpleNamespace(state=SimpleNamespace(services=state))
        self.headers = headers or {}
        self.disconnected = False

    async def is_disconnected(self):
        return self.disconnected


@pytest.fixture
def state(tmp_path):
    store = Store(tmp_path / "audit.db")
    for run_id in ("run-a", "run-b"):
        store.create_run({
            "id": run_id,
            "snapshot_id": "snapshot",
            "snapshot_name": "source.zip",
            "scope": [],
            "scope_mode": "snapshot",
            "prompt_id": "planner-v2",
            "prompt_label": "Planner",
            "prompt_text": "",
            "model": "test-model",
            "budgets": {"responses": 24, "tools": 96, "seconds": 1800},
            "created_at": now(),
        })
    value = SimpleNamespace(store=store, bus=ObservedBus(store))
    yield value
    store.close()


async def stream(state, *, after=0, headers=None):
    request = StreamRequest(state, headers)
    response = await app_module.stream_events(request, "run-a", after=after)
    assert response.media_type == "text/event-stream"
    assert response.headers["cache-control"] == "no-cache"
    assert response.headers["x-accel-buffering"] == "no"
    return request, response.body_iterator


async def next_event(iterator):
    while True:
        frame = await anext(iterator)
        if frame.startswith(":"):
            continue
        cursor, data = frame.strip().split("\n")
        event = json.loads(data.removeprefix("data: "))
        assert cursor == f"id: {event['id']}"
        return event


async def events(iterator, count):
    return [await next_event(iterator) for _ in range(count)]


def emit(state, run_id="run-a", **payload):
    return state.bus.emit(run_id, None, "tool_result", {"preview": "源码调用结果", **payload})


def test_slow_live_consumer_recovers_more_than_a_full_queue_and_batch(state):
    async def exercise():
        seed = emit(state)
        _, iterator = await stream(state)
        try:
            assert (await next_event(iterator))["id"] == seed["id"]
            pending = asyncio.create_task(next_event(iterator))
            await asyncio.wait_for(state.bus.waiting.wait(), timeout=1)
            first_live = emit(state)
            assert (await asyncio.wait_for(pending, timeout=1))["id"] == first_live["id"]

            # The client is now paused during live delivery, after initial replay.
            # Overflow the 256-slot notification queue and the 500-event DB batch.
            expected = [emit(state, turn=index) for index in range(QUEUE_SIZE * 3 + 13)]
            assert state.bus.queue.qsize() == QUEUE_SIZE
            received = await asyncio.wait_for(events(iterator, len(expected)), timeout=3)
            assert [item["id"] for item in received] == [item["id"] for item in expected]
            assert all(item["payload"]["preview"] == "源码调用结果" for item in received)
        finally:
            await iterator.aclose()
        assert "run-a" not in state.bus._subscribers

    asyncio.run(exercise())


def test_duplicate_and_stale_notifications_do_not_repeat_events(state):
    async def exercise():
        seed = emit(state)
        _, iterator = await stream(state)
        try:
            assert (await next_event(iterator))["id"] == seed["id"]
            pending = asyncio.create_task(next_event(iterator))
            await asyncio.wait_for(state.bus.waiting.wait(), timeout=1)
            first_live = emit(state)
            assert (await asyncio.wait_for(pending, timeout=1))["id"] == first_live["id"]
            state.bus.queue.put_nowait(first_live)
            state.bus.queue.put_nowait(seed)
            expected = emit(state)
            assert (await asyncio.wait_for(next_event(iterator), timeout=1))["id"] == expected["id"]
        finally:
            await iterator.aclose()

    asyncio.run(exercise())


def test_notification_replays_all_durable_rows_before_the_notified_event(state):
    async def exercise():
        seed = emit(state)
        _, iterator = await stream(state)
        try:
            assert (await next_event(iterator))["id"] == seed["id"]
            pending = asyncio.create_task(next_event(iterator))
            await asyncio.wait_for(state.bus.waiting.wait(), timeout=1)
            # Persisted rows can survive a lost notification or another process.
            missed = state.store.append_event("run-a", None, "tool_call", {"tool": "read_source"})
            notified = emit(state)
            assert (await asyncio.wait_for(pending, timeout=1))["id"] == missed["id"]
            assert (await asyncio.wait_for(next_event(iterator), timeout=1))["id"] == notified["id"]
        finally:
            await iterator.aclose()

    asyncio.run(exercise())


def test_heartbeat_replays_rows_without_any_live_notification(state, monkeypatch):
    monkeypatch.setattr(app_module, "SSE_HEARTBEAT_SECONDS", 0.01)

    async def exercise():
        seed = emit(state)
        _, iterator = await stream(state)
        try:
            assert (await next_event(iterator))["id"] == seed["id"]
            pending = asyncio.create_task(anext(iterator))
            await asyncio.wait_for(state.bus.waiting.wait(), timeout=1)
            missed = state.store.append_event("run-a", None, "run_completed", {"goal_status": "met"})
            assert await asyncio.wait_for(pending, timeout=1) == ": ping\n\n"
            assert (await asyncio.wait_for(next_event(iterator), timeout=1))["id"] == missed["id"]
        finally:
            await iterator.aclose()

    asyncio.run(exercise())


def test_reconnect_uses_last_event_id_and_preserves_gaps_from_other_runs(state):
    async def exercise():
        expected = []
        for turn in range(6):
            expected.append(emit(state, turn=turn))
            emit(state, "run-b", turn=turn)
        _, original = await stream(state)
        delivered = await events(original, 2)
        await original.aclose()
        cursor = delivered[-1]["id"]
        assert [event["id"] for event in delivered] == [event["id"] for event in expected[:2]]

        # A valid Last-Event-ID overrides a conflicting query cursor.
        _, resumed = await stream(state, after=expected[-1]["id"], headers={"last-event-id": str(cursor)})
        try:
            replayed = await asyncio.wait_for(events(resumed, len(expected) - 2), timeout=1)
            assert [event["id"] for event in replayed] == [event["id"] for event in expected[2:]]
            assert all(event["run_id"] == "run-a" for event in replayed)
            assert all(right["id"] - left["id"] > 1 for left, right in zip(replayed, replayed[1:]))
        finally:
            await resumed.aclose()

    asyncio.run(exercise())


@pytest.mark.parametrize("headers", [{}, {"last-event-id": "invalid"}, {"last-event-id": "-1"}])
def test_query_cursor_is_used_without_a_valid_last_event_id(state, headers):
    async def exercise():
        previous = emit(state)
        expected = emit(state)
        _, iterator = await stream(state, after=previous["id"], headers=headers)
        try:
            assert (await asyncio.wait_for(next_event(iterator), timeout=1))["id"] == expected["id"]
        finally:
            await iterator.aclose()

    asyncio.run(exercise())


def test_disconnected_stream_unsubscribes(state):
    async def exercise():
        seed = emit(state)
        request, iterator = await stream(state)
        assert (await next_event(iterator))["id"] == seed["id"]
        request.disconnected = True
        with pytest.raises(StopAsyncIteration):
            await anext(iterator)
        assert "run-a" not in state.bus._subscribers

    asyncio.run(exercise())
