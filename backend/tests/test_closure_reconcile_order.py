"""Replay the 7f00e97c closure failure without a model, runner or live database.

The historical run remains an immutable observation.  These cases reproduce its
ordering problem with one settled-but-blocked business direction and seven unread
deployment/fixture paths in a temporary project.  Explicitly skipping deployment
files does not resolve the separate unfinished business direction.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from audit import worker as worker_module
from audit.config import ModelConfig, PocSettings
from audit.db import Store
from audit.events import EventBus
from audit.execution_state import DEFAULT_RUN_LIMITS
from audit.health import ModelHealth
from audit.runtime import StopAudit
from audit.source import SourceRepository
from audit.worker import AuditWorker
from tests.test_goal_tasks import TASK, _conclusion_finding, make_zip, proposal, run_payload


RESIDUAL_PATHS = (
    "bin/lab", "bin/package.py", "compose.yaml", "docker/apache.conf",
    "docker/entrypoint.sh", "docker/php.ini", "fixtures/server.py",
)


@pytest.fixture
def replay(tmp_path):
    stores = []

    def create(*, mode="off", standing=False, enabled=None, worker_cap=8):
        enabled = mode != "off" if enabled is None else enabled
        store = Store(tmp_path / f"{len(stores)}.db")
        stores.append(store)
        repository = SourceRepository(tmp_path / f"sources-{len(stores)}")
        files = {"public/index.php": "<?php\n$id = $_GET['id'];\n$query = $id;\nrun_query($query);\n"}
        files.update({path: "# offline deployment fixture\n" for path in RESIDUAL_PATHS})
        snapshot = repository.import_zip(make_zip(files), "closure-replay.zip")
        store.add_snapshot(snapshot)
        task = {**TASK, "completion_policy": "coverage_review", "baseline_policy": "fresh",
                "stop_on_achieved": False, "max_planner_rounds": 8, "max_total_attempts": worker_cap}
        payload = run_payload(snapshot, "closure-replay", list(files), task)
        payload.update(project_mode="project", poc_policy={"mode": mode, "enabled": enabled})
        store.create_run(payload)
        project_map = repository.build_project_map(snapshot["id"], set(files))
        # Freeze the same coverage obligation as the observed run, including the
        # extensionless deployment entrypoint.  This is not a benchmark answer.
        for item in project_map["files"]:
            if item["path"] in RESIDUAL_PATHS:
                item["language"] = "config"
        store.create_planner_session(payload["id"], "closure-session", task["max_planner_rounds"], project_map)
        run = store.claim_next_run()
        plan = store.begin_planner_round(run["id"], "closure-session")
        store.finish_planner_round(run["id"], plan["id"], goal_state="continue",
            basis_summary="回放已保存发现但残余业务方向尚未结算的前沿。", tasks=[proposal("business-residual")])
        claimed = store.claim_ready_task(run["id"], "replay-worker")
        store.resolve_task_attempt(claimed["id"], "replay-worker", outcome="blocked",
            result={"summary": "小批结果已保存，仍需核对剩余业务数据流。",
                    "remaining_work": ["public/index.php: 进一步核对尚未结算的查询参数传播。"],
                    "missing_context": []},
            usage={"requests": 1, "tool_calls": 1},
            seen=[{"path": "public/index.php", "start_line": 1, "end_line": 4}],
            error="当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务")
        if standing:
            store.add_finding(_conclusion_finding(run))
        settings = SimpleNamespace(worker="closure-replay", model=ModelConfig(model="offline"),
                                   poc=PocSettings(enabled=enabled))
        worker = AuditWorker(settings=settings, store=store, repository=repository,
                             bus=EventBus(store), health=ModelHealth())
        assert store.coverage_review(run["id"])["pending_paths"] == sorted(RESIDUAL_PATHS)
        return store, run, worker

    yield create
    for store in stores:
        store.close()


def decision(**fields):
    return {"decision": {"goal_state": "continue", "basis_summary": "按宿主缺口复核剩余源码方向。", **fields},
            "usage": {"requests": 1, "tool_calls": 0}, "terminal_reason": "completed", "error": None}


def forbid(*_args, **_kwargs):
    pytest.fail("闭环回放不得访问真实模型、runner，或越过停止边界")


def install_noop_planner(monkeypatch):
    async def plan(**_kwargs):
        return decision()

    monkeypatch.setattr(worker_module, "plan_audit_frontier", plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", forbid)


def test_unchanged_blocker_does_not_preempt_a_later_explicit_deployment_skip(replay, monkeypatch):
    store, run, worker = replay()
    rounds = []

    async def plan(**kwargs):
        rounds.append(kwargs["round_no"])
        assert store.task_queue_state(run["id"])["blocked"] == 1
        pending = kwargs["run_context"]["coverage_review"]["pending_paths"]
        if kwargs["round_no"] == 2:
            return decision()  # One ineffective repair is not permission to hide gaps.
        return decision(coverage_review=[{"path": path, "action": "skip",
            "reason": "该部署或测试夹具不参与本次商城请求链，明确排除并保留覆盖限制。"} for path in pending])

    monkeypatch.setattr(worker_module, "plan_audit_frontier", plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", forbid)
    asyncio.run(worker._execute(run))

    assert rounds[:2] == [2, 3]
    review = store.coverage_review(run["id"])
    assert review["pending_total"] == 0
    assert {item["path"] for item in review["skips"]} == set(RESIDUAL_PATHS)
    assert store.task_queue_state(run["id"])["blocked"] == 1
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.execution_summary(run["id"])["stop_reason"]["code"] == "unresolved_blockers"
    assert len(rounds) < 8


def test_blocked_and_deferred_directions_still_allow_a_later_gap_review(replay, monkeypatch):
    store, run, worker = replay()
    plan = store.begin_planner_round(run["id"], "closure-session")
    store.finish_planner_round(run["id"], plan["id"], goal_state="continue",
        basis_summary="保留尚未开始但明确延期的独立业务方向。", tasks=[proposal("deferred-direction")])
    plan = store.begin_planner_round(run["id"], "closure-session")
    store.finish_planner_round(run["id"], plan["id"], goal_state="continue",
        basis_summary="延期方向等待业务前提，不代表已经检查。",
        updates=[{"task_key": "deferred-direction", "action": "defer",
                  "rationale_summary": "本次保留该未执行方向，等前提确认后再派发。"}])
    assert store.task_queue_state(run["id"])["counts"] == {"blocked": 1, "deferred": 1}
    rounds = []

    async def plan(**kwargs):
        rounds.append(kwargs["round_no"])
        if len(rounds) == 1:
            return decision()
        assert store.has_event(run["id"], "coverage_review_requested")
        return decision(coverage_review=[{"path": path, "action": "skip",
            "reason": "该部署或测试夹具不参与商城业务链，明确保留排除理由。"}
            for path in kwargs["run_context"]["coverage_review"]["pending_paths"]])

    monkeypatch.setattr(worker_module, "plan_audit_frontier", plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", forbid)
    asyncio.run(worker._execute(run))

    assert rounds[:2] == [4, 5]
    assert store.coverage_review(run["id"])["pending_total"] == 0
    # Terminal cleanup cancels an unstarted deferred task; it must not relabel
    # it as completed or manufacture a Worker attempt to settle it.
    assert store.task_queue_state(run["id"])["counts"] == {"blocked": 1, "cancelled": 1}
    deferred = next(item for item in store.list_tasks(run["id"]) if item["task_key"] == "deferred-direction")
    assert deferred["attempts"] == 0
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.execution_summary(run["id"])["stop_reason"]["code"] == "unresolved_blockers"
    assert store.get_task_goal(run["id"])["attempts"] == 1


def test_worker_cap_does_not_prevent_readonly_coverage_review(replay, monkeypatch):
    store, run, worker = replay(worker_cap=1)
    rounds = []

    async def plan(**kwargs):
        rounds.append(kwargs["round_no"])
        assert store.has_event(run["id"], "coverage_review_requested")
        return decision(coverage_review=[{"path": path, "action": "skip",
            "reason": "该部署或测试夹具不参与商城业务链，明确保留排除理由。"}
            for path in kwargs["run_context"]["coverage_review"]["pending_paths"]])

    monkeypatch.setattr(worker_module, "plan_audit_frontier", plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", forbid)
    asyncio.run(worker._execute(run))

    assert rounds == [2]
    assert store.coverage_review(run["id"])["pending_total"] == 0
    assert store.get_task_goal(run["id"])["attempts"] == 1
    assert store.task_queue_state(run["id"])["blocked"] == 1
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.execution_summary(run["id"])["stop_reason"]["code"] == "worker_attempt_limit"


@pytest.mark.parametrize("mode", ["auto", "required"])
def test_standing_is_verified_before_blocked_or_unresolved_gap_closure(replay, monkeypatch, mode):
    store, run, worker = replay(mode=mode, standing=True)
    attempts = []
    install_noop_planner(monkeypatch)

    async def verify(self, run_id, findings, verified_for, *, should_stop=None, **_kwargs):
        assert not should_stop()
        assert store.get_run(run_id)["status"] == "running"
        for finding in findings:
            key = str(finding.get("project_finding_id") or finding["id"])
            revision = int(finding.get("project_revision") or finding.get("revision") or 1)
            if verified_for.get(key, 0) >= revision:
                continue
            attempts.append((key, revision))
            verified_for[key] = revision
            store.set_finding_verification_state(finding["id"], "inconclusive", "uncertain")
            self.bus.emit(run_id, finding["id"], "poc_verification_started", {"offline_replay": True})
        return {"attempted": len(attempts), "verified": 0, "inconclusive": len(attempts)}

    monkeypatch.setattr(worker_module.PocVerifier, "verify_standing", verify)
    asyncio.run(worker._execute(run))

    assert attempts == [("finding-1", 1)]
    assert store.has_event(run["id"], "poc_verification_started")
    assert store.get_finding("finding-1")["verification_status"] == "inconclusive"
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.task_queue_state(run["id"])["blocked"] == 1
    assert store.coverage_review(run["id"])["pending_total"] == len(RESIDUAL_PATHS)
    kinds = [item["kind"] for item in store.list_events(run["id"])]
    assert kinds.index("poc_verification_started") < kinds.index("coverage_review_requested")
    assert kinds.index("poc_verification_started") < kinds.index("goal_inconclusive")
    assert store.execution_summary(run["id"])["stop_reason"]["code"] == "unresolved_blockers"


@pytest.mark.parametrize("standing,mode,enabled", [(False, "auto", True), (True, "off", False), (True, "off", True)])
def test_no_standing_or_disabled_poc_never_starts_verification(replay, monkeypatch, standing, mode, enabled):
    # A configured server can freeze enabled=True even when this run explicitly
    # selected mode=off.  The run's mode must still prevent verification.
    store, run, worker = replay(mode=mode, standing=standing, enabled=enabled)
    install_noop_planner(monkeypatch)
    monkeypatch.setattr(worker_module.PocVerifier, "verify_standing", forbid)

    asyncio.run(worker._execute(run))

    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert not store.has_event(run["id"], "poc_verification_started")
    assert not store.list_run_verification_jobs(run["id"])


def test_required_runner_unavailable_remains_inconclusive(replay, monkeypatch):
    store, run, worker = replay(mode="required", standing=True)
    install_noop_planner(monkeypatch)
    attempts = []

    async def unavailable(*args, **kwargs):
        attempts.append(True)
        raise StopAudit("environment_unavailable", "离线模拟：隔离验证环境不可用")

    monkeypatch.setattr(worker_module.PocVerifier, "verify_standing", unavailable)
    asyncio.run(worker._execute(run))

    assert attempts == [True]
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.execution_summary(run["id"])["stop_reason"]["code"] == "environment_unavailable"
    assert store.get_finding("finding-1")["verification_status"] == "unverified"


@pytest.mark.parametrize("status", ["paused", "cancelled"])
def test_pause_or_cancel_is_observed_before_new_closure_work(replay, monkeypatch, status):
    store, run, worker = replay(mode="auto", standing=True)
    if status == "paused":
        store.update_run(run["id"], status="paused")
        worker.pause(run["id"])
    else:
        store.terminate_execution(run["id"], "cancelled", {"code": "user_cancelled", "message": "离线取消"})
    monkeypatch.setattr(worker_module, "plan_audit_frontier", forbid)
    monkeypatch.setattr(worker_module.PocVerifier, "verify_standing", forbid)

    asyncio.run(worker._execute(run))

    assert store.get_run(run["id"])["status"] == status
    assert store.get_finding("finding-1")["verification_status"] == "unverified"
    assert not store.has_event(run["id"], "poc_verification_started")


@pytest.mark.parametrize("dimension", ["responses", "seconds"])
def test_closure_verification_obeys_exhausted_shared_budget(replay, monkeypatch, dimension):
    store, run, worker = replay(mode="auto", standing=True)
    limits = {**DEFAULT_RUN_LIMITS, "responses": 1, "seconds": 30}
    store._write("UPDATE run_execution_state SET limits=?, responses_used=?, active_elapsed_ms=? WHERE run_id=?",
        (json.dumps(limits), 1 if dimension == "responses" else 0, 30000 if dimension == "seconds" else 0, run["id"]))
    monkeypatch.setattr(worker_module, "plan_audit_frontier", forbid)
    monkeypatch.setattr(worker_module.PocVerifier, "verify_standing", forbid)

    asyncio.run(worker._execute(run))

    assert store.get_run(run["id"])["status"] == "inconclusive"
    reason = store.execution_summary(run["id"])["stop_reason"]
    assert (reason["code"], reason["dimension"]) == ("run_budget_exhausted", dimension)
    assert store.get_finding("finding-1")["verification_status"] == "unverified"
    assert not store.has_event(run["id"], "poc_verification_started")
