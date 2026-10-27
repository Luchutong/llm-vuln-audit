import asyncio
import threading
import time
from types import SimpleNamespace

import pytest

from audit import agent, worker as worker_module
from audit.config import ModelConfig
from audit.db import Store
from audit.events import EventBus
from audit.health import ModelHealth
from audit.metrics import comparable_runs
from audit.runtime import AgentPolicy
from audit.schemas import Check, UnitAnalysis
from audit.worker import AuditWorker
from tests.code_model import ModelFactory, code


class Repository:
    def get_context(self, snapshot_id, unit):
        return {"excerpts": [], "unresolved_dependencies": []}

    def get_snapshot(self, snapshot_id):
        return {"files": [{"path": "a.php", "line_count": 3}]}


def add_run(store, run_id, count=1):
    store.create_run({
        "id": run_id, "snapshot_id": "s1", "snapshot_name": "demo.zip", "scope": ["a.php"],
        "prompt_id": "P2", "prompt_label": "P2", "prompt_text": "审计", "model": "test",
        "budgets": {"responses": 8, "tools": 16, "seconds": 10},
        "agent_policy": AgentPolicy().snapshot(), "created_at": run_id,
    }, [{"id": str(n), "file_path": "a.php", "symbol": "<top-level>", "start_line": 1, "end_line": 3,
         "priority": 0, "kind": "top_level", "slice_index": 1, "slice_count": 1,
         "cleaned_lines": [{"number": 1, "text": "<?php echo 'ok';"}]} for n in range(count)])


def make_worker(store):
    return AuditWorker(settings=SimpleNamespace(worker="test", model=ModelConfig(model="test")),
                       store=store, repository=Repository(), bus=EventBus(store), health=ModelHealth())


def good_outcome():
    check = Check(conclusion="no_candidate", reasoning="已读代码无输入")
    analysis = UnitAnalysis(summary="完成", sqli=check, xss_r=check, command_injection=check)
    return {"analysis": analysis, "checks": analysis.by_category(), "usage": {"requests": 1, "tool_calls": 0},
            "seen": [], "incomplete": None, "error": None}


def request_timeout_outcome():
    return {
        "analysis": None,
        "checks": {},
        "verdicts": {},
        "usage": {"requests": 1, "tool_calls": 0},
        "seen": [],
        "incomplete": "request_timeout",
        "error": "模型请求超过 30.0s；不重复同一网络请求",
        "status": None,
        "result": {"terminal_reason": "request_timeout"},
    }


@pytest.mark.parametrize("incomplete", [False, True])
def test_legacy_unit_lifecycle_and_internal_events_share_one_invocation(tmp_path, monkeypatch, incomplete):
    store = Store(tmp_path / "audit.db")
    add_run(store, "legacy-invocation", count=2)
    worker = make_worker(store)

    async def controlled(**kwargs):
        for event in (
            {"kind": "model_request", "attempt": 1, "request_index": 1},
            {"kind": "tool_call", "tool": "read_source", "call_id": "tool-0001", "request_index": 1},
            {"kind": "tool_result", "tool": "read_source", "call_id": "tool-0001", "request_index": 1},
            {"kind": "agent_terminal", "request_index": 1},
        ):
            kwargs["on_event"](event)
        return request_timeout_outcome() if incomplete else good_outcome()

    monkeypatch.setattr(worker_module, "audit_unit", controlled)
    try:
        asyncio.run(worker._execute(store.claim_next_run()))
        events = store.list_events("legacy-invocation", limit=1000)
        units = {}
        for event in events:
            if event["unit_id"] is not None:
                units.setdefault(event["unit_id"], []).append(event)
        assert len(units) == 2
        invocations = []
        for activity in units.values():
            ids = {event["payload"]["agent_invocation_id"] for event in activity}
            assert len(ids) == 1
            invocations.extend(ids)
            assert {event["kind"] for event in activity} >= {
                "unit_started", "model_request", "tool_call", "tool_result", "agent_terminal",
                "unit_incomplete" if incomplete else "unit_completed",
            }
        assert len(set(invocations)) == 2
    finally:
        store.close()


def test_cancel_interrupts_a_pending_model_request_and_preserves_checkpoint(tmp_path, monkeypatch):
    store = Store(tmp_path / "audit.db")
    add_run(store, "run1", count=2)
    worker = make_worker(store)
    started, release = threading.Event(), threading.Event()

    def pending(messages):
        """A provider call that is still in flight when the cancel arrives.

        The loop runs on a worker thread, which is where a real request waits, so blocking
        here is what makes "interrupt a pending request" a real claim rather than a claim
        about an already-answered one.
        """
        started.set()
        release.wait(10)
        # Whatever this returns is never delivered: the unit is already cancelled by the
        # time the request it belongs to would have been answered.
        return code("pass")

    monkeypatch.setattr(agent, "build_code_model", ModelFactory({"explore": [pending]}))

    async def exercise():
        try:
            await worker.start()
            for _ in range(500):
                if started.is_set():
                    break
                await asyncio.sleep(0.002)
            assert started.is_set(), "请求从未发出，取消测的不是在途请求"
            store.request_cancel("run1")
            worker.cancel("run1")
            for _ in range(50):
                if not worker.status["busy"]:
                    break
                await asyncio.sleep(0.002)
            assert not worker.status["busy"], "cancel must not wait for the request timeout"
            assert worker.status["alive"]
            units = store.list_run_units("run1")
            assert units[0]["status"] == "incomplete" and units[1]["status"] == "skipped"
            assert units[0]["seen"]
            assert units[0]["result"]["phase"] == "explore"
            assert store.get_run("run1")["status"] == "cancelled"
            events = store.list_events("run1")
            assert any(e["kind"] == "tool_call" for e in events)
            assert any(e["kind"] == "unit_checkpoint" for e in events)
            assert any(e["kind"] == "run_cancelled" for e in events)
            await worker.stop()
        finally:
            # The loop's thread is still inside the scripted step; `asyncio.run` joins the
            # thread pool on its way out, so it has to be let go before this coroutine ends.
            release.set()

    try:
        asyncio.run(exercise())
    finally:
        store.close()


def test_an_unexpected_unit_exception_does_not_kill_the_worker_or_next_run(tmp_path, monkeypatch):
    store = Store(tmp_path / "audit.db")
    add_run(store, "run1", count=2)
    add_run(store, "run2")
    worker = make_worker(store)
    calls = 0
    async def controlled(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("unexpected unit failure")
        return good_outcome()
    monkeypatch.setattr(worker_module, "audit_unit", controlled)
    async def exercise():
        await worker.start()
        for _ in range(50):
            if store.get_run("run2")["status"] == "completed":
                break
            await asyncio.sleep(0.002)
        assert store.get_run("run1")["status"] == "failed"
        assert [u["status"] for u in store.list_run_units("run1")] == ["incomplete", "skipped"]
        assert store.get_run("run2")["status"] == "completed"
        assert worker.status["alive"]
        await worker.stop()
    try:
        asyncio.run(exercise())
    finally:
        store.close()


def test_a_single_transient_failure_does_not_end_the_run(tmp_path, monkeypatch):
    """One exhausted 429/timeout is noise: the remaining units still get audited."""
    store = Store(tmp_path / "audit.db")
    add_run(store, "run1", count=3)
    worker = make_worker(store)
    calls = 0

    async def flaky(**kwargs):
        nonlocal calls
        calls += 1
        return request_timeout_outcome() if calls == 1 else good_outcome()

    monkeypatch.setattr(worker_module, "audit_unit", flaky)
    try:
        asyncio.run(worker._execute(store.claim_next_run()))
        assert store.get_run("run1")["status"] == "completed"
        kinds = [event["kind"] for event in store.list_events("run1", limit=1000)]
        assert "run_inconclusive" not in kinds
        assert "run_failed" not in kinds
    finally:
        store.close()


def test_request_timeouts_trip_the_model_failure_abort(tmp_path, monkeypatch):
    store = Store(tmp_path / "audit.db")
    add_run(store, "run1", count=4)
    worker = make_worker(store)

    async def timeout(**kwargs):
        return request_timeout_outcome()

    monkeypatch.setattr(worker_module, "audit_unit", timeout)

    async def exercise():
        await worker.start()
        try:
            for _ in range(200):
                if store.get_run("run1")["status"] in {"inconclusive", "failed", "completed"}:
                    break
                await asyncio.sleep(0.002)
            # The endpoint never answered, so nothing was disproved: `inconclusive`.
            assert store.get_run("run1")["status"] == "inconclusive"
            assert [unit["status"] for unit in store.list_run_units("run1")] == [
                "failed", "failed", "failed", "skipped",
            ]
            assert worker.health.snapshot()["status"] == "tripped"
            # Two records carry this kind: the store's durable terminal event
            # (reason = code+message) and the live announcement (reason = code).
            stopped = [event for event in store.list_events("run1", limit=1000)
                       if event["kind"] == "run_inconclusive" and "error" in event["payload"]]
            assert stopped and "连续失败 3 次" in stopped[0]["payload"]["error"]
        finally:
            await worker.stop()

    try:
        asyncio.run(exercise())
    finally:
        store.close()


def test_an_open_breaker_settles_inconclusive_instead_of_failing(tmp_path, monkeypatch):
    """A run that never reached the provider was not audited, so it did not fail."""
    store = Store(tmp_path / "audit.db")
    add_run(store, "run1")
    worker = make_worker(store)
    worker.health.trip("credentials rejected", status=401)
    monkeypatch.setattr(worker_module, "HEALTH_WAIT_CEILING", 0.05)
    monkeypatch.setattr(worker_module, "HEALTH_POLL_SECONDS", 0.01)
    try:
        asyncio.run(worker._execute(store.claim_next_run()))
        run = store.get_run("run1")
        assert run["status"] == "inconclusive"
        events = store.list_events("run1", limit=1000)
        stopped = [event for event in events
                   if event["kind"] == "run_inconclusive" and "error" in event["payload"]]
        assert stopped and stopped[0]["payload"]["reason"] == "model_unavailable"
        assert "模型熔断" in stopped[0]["payload"]["error"]
        assert not [unit for unit in store.list_run_units("run1") if unit["status"] == "running"]
    finally:
        store.close()


def test_a_short_breaker_window_is_waited_out_not_aborted(tmp_path, monkeypatch):
    store = Store(tmp_path / "audit.db")
    add_run(store, "run1")
    worker = make_worker(store)
    # A 60-second cooldown in miniature: still open now, expired before the ceiling.
    worker.health.state.open_until = time.time() + 0.05
    monkeypatch.setattr(worker_module, "HEALTH_POLL_SECONDS", 0.01)
    assert asyncio.run(worker._wait_for_model()) is True
    assert not worker.health.is_open()
    store.close()


def test_shutdown_keeps_named_interruption_instead_of_user_cancellation(tmp_path, monkeypatch):
    store = Store(tmp_path / "audit.db")
    add_run(store, "run1")
    worker = make_worker(store)
    async def exercise():
        waiting = asyncio.Event()
        async def controlled(**kwargs):
            waiting.set()
            await asyncio.Event().wait()
        monkeypatch.setattr(worker_module, "audit_unit", controlled)
        await worker.start()
        await asyncio.wait_for(waiting.wait(), 1)
        await worker.stop()
        assert store.get_run("run1")["status"] == "interrupted"
        assert store.get_run("run1")["error"] == "server_shutdown"
    try:
        asyncio.run(exercise())
    finally:
        store.close()


def test_persisted_policy_prevents_mixing_legacy_and_new_experiments(tmp_path):
    store = Store(tmp_path / "audit.db")
    try:
        add_run(store, "run1")
        current = store.get_run("run1")
        assert current["agent_policy"] == AgentPolicy().snapshot()
        older = {**current, "agent_policy": {"version": "legacy"}}
        assert comparable_runs([current, older])["comparable"] is False
        assert "Agent 执行策略不同" in comparable_runs([current, older])["reasons"]
    finally:
        store.close()
