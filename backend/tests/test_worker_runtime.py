import asyncio
from types import SimpleNamespace

from audit import agent, worker as worker_module
from audit.config import ModelConfig
from audit.db import Store
from audit.events import EventBus
from audit.health import ModelHealth
from audit.metrics import comparable_runs
from audit.runtime import AgentPolicy
from audit.schemas import Check, UnitAnalysis
from audit.worker import AuditWorker
from pydantic_ai.models.function import FunctionModel


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


def test_cancel_interrupts_a_pending_model_request_and_preserves_checkpoint(tmp_path, monkeypatch):
    store = Store(tmp_path / "audit.db")
    add_run(store, "run1", count=2)
    worker = make_worker(store)
    async def exercise():
        waiting = asyncio.Event()
        async def model(messages, info):
            waiting.set()
            await asyncio.Event().wait()
        monkeypatch.setattr(agent, "build_model", lambda config: FunctionModel(model))
        await worker.start()
        await asyncio.wait_for(waiting.wait(), timeout=1)
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


def test_request_timeouts_trip_the_model_failure_abort(tmp_path, monkeypatch):
    store = Store(tmp_path / "audit.db")
    add_run(store, "run1", count=3)
    worker = make_worker(store)

    async def timeout(**kwargs):
        return request_timeout_outcome()

    monkeypatch.setattr(worker_module, "audit_unit", timeout)

    async def exercise():
        await worker.start()
        for _ in range(100):
            if store.get_run("run1")["status"] == "failed":
                break
            await asyncio.sleep(0.002)
        run = store.get_run("run1")
        assert run["status"] == "failed"
        assert "连续失败阈值" in run["error"]
        assert [unit["status"] for unit in store.list_run_units("run1")] == ["failed", "failed", "skipped"]
        assert worker.health.snapshot()["fails"] == 2
        await worker.stop()

    try:
        asyncio.run(exercise())
    finally:
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
