"""Regression tests for user-defined, multi-worker source goals.

These tests exercise the durable queue rather than a live model.  Goal tasks must
remain distinct from the fixed SQLi/XSS/command-injection experiment: workers claim
one frozen source unit at a time, the store owns retries and terminal state, and a
goal can only become unreachable after that queue has drained.
"""
from __future__ import annotations

import asyncio
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from audit import worker as worker_module
from audit.config import ModelConfig
from audit.db import Store, now
from audit.events import EventBus
from audit.health import ModelHealth
from audit.metrics import summarise
from audit.runtime import AgentPolicy
from audit.schemas import AttributionRequest, CreateRunRequest
from audit.worker import AuditWorker


TASK_SPEC = {
    "objective": "找出所选 PHP 源码中可由用户输入触发的危险执行路径。",
    "success_criteria": "至少保存一处带原始行号证据的目标相关发现。",
    "max_iterations": 2,
    "max_total_attempts": 12,
    "max_workers": 3,
    "stop_on_achieved": True,
    "require_poc": True,
}


class Repository:
    """Only the goal finding path needs a snapshot from this test repository."""

    def get_snapshot(self, snapshot_id: str) -> dict:
        return {"files": [{"path": "a.php", "line_count": 8}]}


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


def unit(number: int) -> dict:
    return {
        "id": f"unit-{number}",
        "file_path": "a.php",
        "symbol": f"target_{number}",
        "kind": "function",
        "start_line": number,
        "end_line": number,
        "priority": 0,
        "slice_index": 1,
        "slice_count": 1,
        "cleaned_lines": [{"number": number, "text": "<?php echo $_GET['x'];"}],
    }


def create_goal_run(
    store: Store,
    *,
    run_id: str = "goal-run",
    count: int = 1,
    max_iterations: int = 2,
    max_total_attempts: int = 12,
    max_workers: int = 3,
    claim: bool = True,
) -> dict:
    task = {
        **TASK_SPEC,
        "max_iterations": max_iterations,
        "max_total_attempts": max_total_attempts,
        "max_workers": max_workers,
    }
    store.create_run(
        {
            "id": run_id,
            "snapshot_id": "snapshot-1",
            "snapshot_name": "target.zip",
            "scope": ["a.php"],
            "prompt_id": "P2",
            "prompt_label": "test prompt",
            "prompt_text": "只作为测试占位的提示词。",
            "model": "test-model",
            "budgets": {"responses": 8, "tools": 16, "seconds": 30},
            "agent_policy": AgentPolicy().snapshot(),
            "task_spec": task,
            "created_at": "2026-10-14T00:00:00+00:00",
        },
        [unit(index) for index in range(1, count + 1)],
    )
    if not claim:
        run = store.get_run(run_id)
        assert run is not None and run["status"] == "pending"
        return run
    run = store.claim_next_run()
    assert run is not None and run["status"] == "running"
    return run


def test_existing_goal_database_is_migrated_with_a_total_attempt_cap(tmp_path):
    """Older goal-task databases gain a safe cap before any worker can claim work."""
    path = tmp_path / "legacy-goal.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE task_goals (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            objective TEXT NOT NULL,
            success_criteria TEXT NOT NULL,
            max_iterations INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            attempts INTEGER NOT NULL DEFAULT 0,
            terminal_reason TEXT,
            reached_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        INSERT INTO task_goals (id, run_id, objective, success_criteria, max_iterations, created_at, updated_at)
        VALUES ('legacy-goal', 'legacy-run', '旧目标', '旧验收条件', 2, '2026-10-14T00:00:00+00:00', '2026-10-14T00:00:00+00:00');
        """
    )
    connection.close()

    migrated = Store(path)
    try:
        goal = migrated.get_task_goal("legacy-run")
        assert goal is not None
        assert goal["max_total_attempts"] == 24
    finally:
        migrated.close()


def test_legacy_task_spec_receives_the_same_public_total_attempt_default(store):
    """The frozen JSON of old task runs stays usable after the schema addition."""
    legacy_task = {key: value for key, value in TASK_SPEC.items() if key != "max_total_attempts"}
    store.create_run(
        {
            "id": "legacy-task-run",
            "snapshot_id": "snapshot-1",
            "snapshot_name": "target.zip",
            "scope": ["a.php"],
            "prompt_id": "goal-task",
            "prompt_label": "目标任务执行器",
            "prompt_text": "",
            "model": "test-model",
            "budgets": {"responses": 8, "tools": 16, "seconds": 30},
            "agent_policy": AgentPolicy().snapshot(),
            "task_spec": legacy_task,
            "created_at": "2026-10-14T00:00:00+00:00",
        },
        [unit(1)],
    )

    run = store.get_run("legacy-task-run")
    goal = store.get_task_goal("legacy-task-run")
    assert run is not None and run["task_spec"]["max_total_attempts"] == 24
    assert run["task_spec"]["require_poc"] is True
    assert goal is not None and goal["max_total_attempts"] == 24


def make_worker(store: Store) -> AuditWorker:
    return AuditWorker(
        settings=SimpleNamespace(worker="goal-test-worker", model=ModelConfig(model="test")),
        store=store,
        repository=Repository(),
        bus=EventBus(store),
        health=ModelHealth(),
    )


def task_result(outcome: str, *, next_focus: str = "") -> dict:
    return {
        "outcome": outcome,
        "result": {
            "outcome": outcome,
            "summary": "已检查当前冻结源码单元。",
            "reasoning": "这是受控测试返回的结构化结论。",
            "next_focus": next_focus,
            "missing_context": [],
            "finding": None,
        },
        "usage": {"requests": 1, "tool_calls": 0, "input_tokens": 0, "output_tokens": 0},
        "seen": [],
        "seen_exact": True,
        "error": None,
        "status": None,
        "terminal_reason": "completed",
    }


def test_goal_task_request_uses_the_dedicated_executor_without_a_legacy_prompt():
    request = CreateRunRequest(
        snapshot_id="snapshot-1",
        scope=["a.php"],
        task=TASK_SPEC,
    )
    assert request.prompt_id is None
    assert request.task is not None and request.task.objective == TASK_SPEC["objective"]
    assert request.task.require_poc is True

    with pytest.raises(ValidationError, match="prompt_id is required"):
        CreateRunRequest(snapshot_id="snapshot-1", scope=["a.php"])
    with pytest.raises(ValidationError, match="prompt_id must be omitted"):
        CreateRunRequest(snapshot_id="snapshot-1", scope=["a.php"], prompt_id="P2", task=TASK_SPEC)


def test_goal_task_api_creation_uses_dedicated_executor_without_prompt_lookup(store):
    """Creating a target run must not accidentally load the fixed three-category prompt."""
    from audit.app import create_run

    frozen_unit = {**unit(1), "start_byte": 0}
    snapshot = {
        "id": "snapshot-1",
        "name": "target.zip",
        "files": [{"path": "a.php", "excluded": False}],
        "units": [frozen_unit],
    }
    state = SimpleNamespace(
        repository=SimpleNamespace(get_snapshot=lambda _snapshot_id: snapshot),
        store=store,
        settings=SimpleNamespace(model=SimpleNamespace(label="test-model")),
        worker=SimpleNamespace(notify=lambda: None),
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))
    payload = CreateRunRequest(snapshot_id="snapshot-1", scope=["a.php"], task=TASK_SPEC)

    created = asyncio.run(create_run(request, payload))

    assert created["prompt_id"] == "goal-task"
    assert created["prompt_label"] == "目标任务执行器"
    assert created["prompt_text"] == ""
    assert created["task_spec"]["objective"] == TASK_SPEC["objective"]
    assert store.get_task_goal(created["id"]) is not None


def test_goal_task_is_rejected_from_fixed_prompt_experiments_and_attribution(store):
    """Fixed-category evaluation endpoints cannot silently reinterpret a task finding."""
    from audit.app import add_attribution, experiments

    run = create_goal_run(store)
    state = SimpleNamespace(store=store)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))

    with pytest.raises(HTTPException) as experiment_error:
        asyncio.run(experiments(request, run_ids=run["id"]))
    assert experiment_error.value.status_code == 400
    assert "Goal-driven" in str(experiment_error.value.detail)

    with pytest.raises(HTTPException) as attribution_error:
        asyncio.run(
            add_attribution(
                request,
                run["id"],
                AttributionRequest(
                    file_path="a.php",
                    category="sqli",
                    kind="false_positive",
                ),
            )
        )
    assert attribution_error.value.status_code == 409


def goal_finding(run_id: str, unit_id: str) -> dict:
    """A fully persistable finding, so resolve_task_work can test its transaction."""
    return {
        "id": uuid4().hex,
        "run_id": run_id,
        "unit_id": unit_id,
        "fingerprint": f"task-goal:{unit_id}",
        "category": "task_goal",
        "title": "目标已达成",
        "severity": "high",
        "summary": "可复核的目标相关发现。",
        "evidence": [{"path": "a.php", "start_line": 1, "end_line": 1}],
        "input_source": "$_GET['x']",
        "propagation": "参数传入危险调用",
        "dangerous_operation": "危险调用",
        "protection": "未看到有效防护",
        "preconditions": ["请求包含 x 参数"],
        "missing_context": [],
        "poc": None,
        "remediation": "使用安全 API 并校验输入。",
        "validation_state": "candidate",
        "validation_errors": [],
        "verdict": None,
        "created_at": now(),
    }


def test_goal_run_dispatches_to_task_executor_not_legacy_audit(store, monkeypatch):
    """A task_spec is a mode switch; it must never produce the fixed checklist."""
    run = create_goal_run(store)
    worker = make_worker(store)
    calls: list[dict] = []

    async def legacy_audit_must_not_run(**_kwargs):
        raise AssertionError("goal task must not call audit_unit")

    async def pursue(**kwargs):
        calls.append(kwargs)
        return task_result("no_evidence")

    monkeypatch.setattr(worker_module, "audit_unit", legacy_audit_must_not_run)
    monkeypatch.setattr(worker_module, "pursue_task_work", pursue)

    asyncio.run(worker._execute(run))

    assert len(calls) == 1
    assert calls[0]["task"]["objective"] == TASK_SPEC["objective"]
    assert store.get_run(run["id"])["status"] == "unreachable"
    assert store.get_task_goal(run["id"])["status"] == "unreachable"


def test_goal_run_uses_a_bounded_multiworker_pool(store, monkeypatch):
    """The task-level pool runs in parallel but never exceeds max_workers."""
    run = create_goal_run(store, count=5, max_workers=2)
    worker = make_worker(store)
    active = 0
    peak = 0
    calls: list[str] = []

    async def pursue(**kwargs):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        calls.append(kwargs["unit"]["unit_id"])
        await asyncio.sleep(0.01)
        active -= 1
        return task_result("no_evidence")

    monkeypatch.setattr(worker_module, "pursue_task_work", pursue)
    asyncio.run(worker._execute(run))

    assert peak == 2
    assert len(calls) == 5
    assert len(set(calls)) == 5
    assert store.get_run(run["id"])["status"] == "unreachable"


def test_concurrent_goal_workers_claim_each_work_item_once(store):
    """The durable claim transaction is the only assignment authority for a worker pool."""
    run = create_goal_run(store, count=5)

    def claim(slot: int):
        return store.claim_next_task_work(run["id"], f"worker-{slot}")

    with ThreadPoolExecutor(max_workers=12) as pool:
        claimed = list(pool.map(claim, range(12)))

    assigned = [item for item in claimed if item is not None]
    assert len(assigned) == 5
    assert len({item["id"] for item in assigned}) == 5
    assert len({item["unit_id"] for item in assigned}) == 5
    assert {item["state"] for item in assigned} == {"running"}


def test_continue_requeues_once_then_exhausts_the_work_item(store):
    """A worker cannot turn repeated "continue" into an unbounded agent loop."""
    run = create_goal_run(store, max_iterations=2)

    first = store.claim_next_task_work(run["id"], "worker-1")
    assert first is not None
    reopened = store.resolve_task_work(
        first["id"],
        outcome="continue",
        result={"summary": "继续沿调用链检查", "next_focus": "检查调用方"},
        usage={"requests": 1},
        seen=[],
    )
    assert reopened is not None
    assert reopened["state"] == "open"
    assert reopened["attempt"] == 1
    assert reopened["focus"] == "检查调用方"

    second = store.claim_next_task_work(run["id"], "worker-2")
    assert second is not None and second["id"] == first["id"]
    exhausted = store.resolve_task_work(
        second["id"],
        outcome="continue",
        result={"summary": "仍需继续", "next_focus": "无更多可用方向"},
        usage={"requests": 1},
        seen=[],
    )
    assert exhausted is not None
    assert exhausted["state"] == "exhausted"
    assert exhausted["attempt"] == 2
    assert exhausted["result"]["terminal_reason"] == "attempts_exhausted"
    assert [entry["attempt"] for entry in exhausted["attempt_history"]] == [1, 2]


def test_retryable_model_failures_exhaust_to_inconclusive_not_unreachable(store):
    """An unavailable model cannot serve as evidence that the source goal is absent."""
    run = create_goal_run(store, max_iterations=2)

    first = store.claim_next_task_work(run["id"], "worker-1")
    assert first is not None
    reopened = store.resolve_task_work(
        first["id"],
        outcome="continue",
        result={
            "summary": "模型端暂时没有返回结构化结论。",
            "next_focus": "恢复后重新完成当前源码方向的判定。",
            "terminal_reason": "model_error",
        },
        usage={"requests": 1},
        seen=[],
        error="ModelHTTPError: temporary outage",
    )
    assert reopened is not None and reopened["state"] == "open"

    second = store.claim_next_task_work(run["id"], "worker-2")
    assert second is not None
    blocked = store.resolve_task_work(
        second["id"],
        outcome="continue",
        result={
            "summary": "模型端仍没有返回结构化结论。",
            "next_focus": "恢复后重新完成当前源码方向的判定。",
            "terminal_reason": "model_error",
        },
        usage={"requests": 1},
        seen=[],
        error="ModelHTTPError: temporary outage",
    )

    assert blocked is not None
    assert blocked["state"] == "blocked"
    assert blocked["result"]["terminal_reason"] == "model_error"
    assert blocked["result"]["retry_exhausted"] is True
    settled = store.settle_task_goal_if_idle(run["id"])
    assert settled is not None and settled["status"] == "inconclusive"


def test_task_total_attempt_cap_reserves_concurrent_leases_and_closes_queue(store):
    """A global cap bounds the pool even when several workers claim at once."""
    run = create_goal_run(store, count=5, max_iterations=3, max_total_attempts=2)

    def claim(slot: int):
        return store.claim_next_task_work(run["id"], f"worker-{slot}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        claimed = [item for item in pool.map(claim, range(8)) if item is not None]

    assert len(claimed) == 2
    assert len({item["id"] for item in claimed}) == 2
    work = store.list_task_work_items(run["id"])
    assert [item["state"] for item in work] == ["running", "running", "skipped", "skipped", "skipped"]
    assert all("最大尝试次数 2" in (item["error"] or "") for item in work[2:])

    for item in claimed:
        resolved = store.resolve_task_work(
            item["id"],
            outcome="no_evidence",
            result={"summary": "当前源码单元没有目标相关证据", "reasoning": "测试结论"},
            usage={"requests": 1},
            seen=[],
        )
        assert resolved is not None

    settled = store.settle_task_goal_if_idle(run["id"])
    assert settled is not None
    assert settled["status"] == "unreachable"
    assert settled["attempts"] == 2
    assert settled["max_total_attempts"] == 2
    assert "任务级最大尝试次数 2 已耗尽" in settled["terminal_reason"]


def test_total_attempt_cap_after_a_retryable_failure_is_inconclusive(store):
    """A global cap cannot convert an untried provider retry into source absence."""
    run = create_goal_run(store, max_iterations=3, max_total_attempts=1)
    work = store.claim_next_task_work(run["id"], "worker-1")
    assert work is not None
    reopened = store.resolve_task_work(
        work["id"],
        outcome="continue",
        result={
            "summary": "模型端没有返回结构化结论。",
            "next_focus": "恢复后重新完成当前源码方向的判定。",
            "terminal_reason": "model_error",
        },
        usage={"requests": 1},
        seen=[],
        error="ModelHTTPError: temporary outage",
    )
    assert reopened is not None and reopened["state"] == "open"

    assert store.claim_next_task_work(run["id"], "worker-2") is None
    blocked = store.get_task_work_item(work["id"])
    assert blocked is not None and blocked["state"] == "blocked"
    assert "未取得可用模型结论" in (blocked["error"] or "")

    settled = store.settle_task_goal_if_idle(run["id"])
    assert settled is not None and settled["status"] == "inconclusive"


def test_cancellation_retracts_a_premature_unreachable_goal_conclusion(store):
    """A cancellation racing final settlement never leaves an absence claim behind."""
    run = create_goal_run(store, max_total_attempts=2)
    work = store.claim_next_task_work(run["id"], "worker-1")
    assert work is not None
    store.resolve_task_work(
        work["id"],
        outcome="no_evidence",
        result={"summary": "当前源码单元没有目标相关证据", "reasoning": "测试结论"},
        usage={"requests": 1},
        seen=[],
    )
    settled = store.settle_task_goal_if_idle(run["id"])
    assert settled is not None and settled["status"] == "unreachable"

    store.abandon_task_work(run["id"], "Run cancelled")

    goal = store.get_task_goal(run["id"])
    assert goal is not None
    assert goal["status"] == "inconclusive"
    assert goal["terminal_reason"] == "Run cancelled"


def test_cancelling_an_active_goal_pool_leaves_no_unreachable_conclusion(store, monkeypatch):
    """Cancelling the outer run stops all slots and makes unfinished work reviewable."""
    run = create_goal_run(store, count=3, max_workers=2, claim=False)
    worker = make_worker(store)

    async def pursue(**_kwargs):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(worker_module, "pursue_task_work", pursue)

    async def exercise():
        await worker.start()
        await asyncio.wait_for(started.wait(), timeout=1)
        store.request_cancel(run["id"])
        worker.cancel(run["id"])
        for _ in range(100):
            if not worker.status["busy"]:
                break
            await asyncio.sleep(0.002)
        assert not worker.status["busy"]
        await worker.stop()

    started = asyncio.Event()
    asyncio.run(exercise())

    assert store.get_run(run["id"])["status"] == "cancelled"
    goal = store.get_task_goal(run["id"])
    assert goal is not None and goal["status"] == "inconclusive"
    assert {item["state"] for item in store.list_task_work_items(run["id"])} <= {"blocked", "skipped"}


def test_achieved_goal_commits_finding_marks_goal_and_skips_unclaimed_work(store):
    """Goal success is one transaction: no later worker may claim an old open item."""
    run = create_goal_run(store, count=3)
    claimed = store.claim_next_task_work(run["id"], "worker-1")
    assert claimed is not None

    resolved = store.resolve_task_work(
        claimed["id"],
        outcome="achieved",
        result={"summary": "找到了带行号证据的目标路径", "reasoning": "测试结论"},
        usage={"requests": 1},
        seen=[{"path": "a.php", "start_line": 1, "end_line": 1}],
        finding=goal_finding(run["id"], claimed["unit_id"]),
        stop_on_achieved=True,
        goal_reason="第一项已满足验收条件",
    )

    assert resolved is not None and resolved["goal_met"] is True
    goal = store.get_task_goal(run["id"])
    assert goal is not None
    assert goal["status"] == "met"
    assert goal["reached_by"] == claimed["id"]
    work = store.list_task_work_items(run["id"])
    assert [item["state"] for item in work] == ["done", "skipped", "skipped"]
    assert store.claim_next_task_work(run["id"], "late-worker") is None
    assert len(store.list_findings(run["id"])) == 1
    assert [item["status"] for item in store.list_run_units(run["id"])] == ["completed", "skipped", "skipped"]


def test_goal_can_collect_remaining_work_when_stop_on_achieved_is_disabled(store):
    """`stop_on_achieved=False` keeps the queue live for additional evidence."""
    run = create_goal_run(store, count=2)
    first = store.claim_next_task_work(run["id"], "worker-1")
    assert first is not None
    resolved = store.resolve_task_work(
        first["id"],
        outcome="achieved",
        result={"summary": "第一处带证据的目标路径", "reasoning": "测试结论"},
        usage={"requests": 1},
        seen=[{"path": "a.php", "start_line": 1, "end_line": 1}],
        finding=goal_finding(run["id"], first["unit_id"]),
        stop_on_achieved=False,
    )
    assert resolved is not None and resolved["goal_met"] is True
    assert [item["state"] for item in store.list_task_work_items(run["id"])] == ["done", "open"]

    remaining = store.claim_next_task_work(run["id"], "worker-2")
    assert remaining is not None
    store.resolve_task_work(
        remaining["id"],
        outcome="no_evidence",
        result={"summary": "未发现第二处", "reasoning": "测试结论"},
        usage={"requests": 1},
        seen=[],
        stop_on_achieved=False,
    )
    settled = store.settle_task_goal_if_idle(run["id"])
    assert settled is not None and settled["status"] == "met"


def test_goal_task_metrics_do_not_apply_the_fixed_vulnerability_truth_matrix():
    """A custom objective cannot manufacture SQLi/XSS/command-injection negatives."""
    metrics = summarise(
        {"task_spec": TASK_SPEC, "scope": ["a.php"]},
        [{"unit_id": "unit-1", "file_path": "a.php", "symbol": "target", "status": "completed"}],
        [],
        [{"file_path": "a.php", "category": "sqli", "vulnerable": False, "independently_verified": True}],
    )

    assert metrics["evaluation"] is None
    assert metrics["truth_status"] == "goal_task_not_comparable"
