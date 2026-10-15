"""Pausing a run without giving up the work it has already done.

A pause is the reversible sibling of a cancel, and the whole point is what it does *not*
do: nothing is abandoned, no plan is thrown away, and the round number is where it was.
An attempt already in flight is allowed to finish and commit, because a pause that cut a
model call short would leave an attempt recorded with no outcome -- and that is exactly
the state a resume cannot continue from.

The trap this file exists for is one line of the running loop: a status that was not
``running`` used to mean "this run was cancelled", so parking a run would have abandoned
its frontier and emitted a cancellation.  ``resume`` would then have nothing to continue
from, and the button would look like it destroys work.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from audit.app import pause_run, resume_run
from audit.db import Store
from audit.events import EventBus
from audit.source import SourceRepository
from tests.test_goal_tasks import (
    TASK,
    create_planner_run,
    import_project,
    make_worker,
    proposal,
    run_payload,
    worker_outcome,
)


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "source-data")


def queued_run(store: Store, repository: SourceRepository, *, run_id: str = "queued-run") -> dict:
    """A run that exists and has a session but has never been claimed."""
    snapshot = import_project(repository)
    store.add_snapshot(snapshot)
    scope = ["public/index.php", "src/auth.php", "src/files.php"]
    store.create_run(run_payload(snapshot, run_id, scope, TASK))
    project_map = repository.build_project_map(snapshot["id"], set(scope))
    store.create_planner_session(run_id, f"planner:{run_id}", TASK["max_planner_rounds"], project_map)
    return store.get_run(run_id)


def run_events(store: Store, run_id: str) -> list[str]:
    return [str(item["kind"]) for item in store.list_events(run_id)]


def task_states(store: Store, run_id: str) -> dict[str, str]:
    return {item["task_key"]: item["state"] for item in store.list_tasks(run_id)}


def api(state) -> SimpleNamespace:
    """The `request` shape `services()` reads, without standing up the whole app."""
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=state)))


def services(store: Store) -> SimpleNamespace:
    return SimpleNamespace(
        store=store,
        bus=EventBus(store),
        # `_run_id` is None because no run is executing in these tests: that is the branch
        # the endpoints take for a run this worker does not own, which is where a paused
        # run always is.
        worker=SimpleNamespace(
            pause=lambda *_args: None,
            cancel=lambda *_args, **_kwargs: None,
            notify=lambda: None,
            _run_id=None,
        ),
    )


def pause_inside_the_round(store: Store, run: dict, worker) -> dict:
    """Exactly what the endpoint does, from a place that proves the timing."""
    store.request_pause(run["id"])
    worker.pause(run["id"])
    return {
        "goal_state": "continue",
        "basis_summary": "派发入口与文件操作两个方向。",
        "next_action": "读取两个方向。",
        "missing_context": [],
        "tasks": [proposal("entry-flow"), proposal("file-operation", path="src/files.php")],
        "updates": [],
    }


def test_a_pause_parks_the_run_with_its_frontier_intact(store, repository, monkeypatch):
    """The queued directions are still queued, and no cancellation was announced.

    This is the assertion that fails if "the status is no longer running" is allowed to
    mean "cancelled": every task would come back cancelled, the goal inconclusive, and a
    resume would have nothing left to run.
    """
    from audit import worker as worker_module

    run, _ = create_planner_run(store, repository)
    worker = make_worker(store, repository)
    rounds: list[int] = []

    async def fake_plan(**kwargs):
        rounds.append(int(kwargs["round_no"]))
        return {
            "decision": pause_inside_the_round(store, run, worker),
            "usage": {"requests": 1, "tool_calls": 0, "input_tokens": 5, "output_tokens": 4},
            "error": None, "status": None, "terminal_reason": "completed",
        }

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    asyncio.run(worker._execute(run))

    assert store.get_run(run["id"])["status"] == "paused"
    # The round that was in flight when the pause arrived is committed, not discarded.
    assert rounds == [1]
    assert task_states(store, run["id"]) == {"entry-flow": "ready", "file-operation": "ready"}
    assert all(int(item["attempts"]) == 0 for item in store.list_tasks(run["id"]))
    goal = store.get_task_goal(run["id"])
    session = store.get_planner_session(run["id"])
    assert goal["status"] == "open"
    assert session["current_round"] == 1
    kinds = run_events(store, run["id"])
    assert "run_paused" in kinds
    assert "run_cancelled" not in kinds
    assert "goal_inconclusive" not in kinds
    # A paused run has not finished, so nothing may record that it did.
    assert not store.get_run(run["id"])["finished_at"]


def test_an_attempt_in_flight_finishes_before_the_run_parks(store, repository, monkeypatch):
    """The pause is observed at the boundary, so the attempt's outcome is committed."""
    from audit import worker as worker_module

    run, _ = create_planner_run(store, repository, task=dict(TASK, max_workers=1))
    worker = make_worker(store, repository)
    started: list[str] = []

    async def fake_plan(**kwargs):
        return {
            "decision": {
                "goal_state": "continue", "basis_summary": "派发入口方向。",
                "next_action": "读取入口。", "missing_context": [],
                "tasks": [proposal("entry-flow")] if kwargs["round_no"] == 1 else [],
                "updates": [],
            },
            "usage": {"requests": 1, "tool_calls": 0, "input_tokens": 5, "output_tokens": 4},
            "error": None, "status": None, "terminal_reason": "completed",
        }

    async def fake_pursue(**kwargs):
        started.append(kwargs["planner_task"]["task_key"])
        # The user clicks pause while this attempt is running.
        store.request_pause(run["id"])
        worker.pause(run["id"])
        return worker_outcome("blocked")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))

    assert started == ["entry-flow"]
    assert store.get_run(run["id"])["status"] == "paused"
    # Settled, with its attempt on record: an attempt that ran has an outcome.
    settled = store.list_tasks(run["id"])[0]
    assert settled["state"] != "running" and int(settled["attempts"]) == 1
    assert [item["attempt"] for item in store.list_task_attempts(settled["id"])] == [1]
    kinds = run_events(store, run["id"])
    assert "planner_task_started" in kinds and "run_paused" in kinds
    assert "run_cancelled" not in kinds


def test_resuming_continues_the_round_it_stopped_at(store, repository, monkeypatch):
    """Resume is a re-claim, not a fresh start: the next round number is 2, not 1.

    The frontier, the session and the round number were never touched while the run was
    parked, which is what makes this true.
    """
    from audit import worker as worker_module

    run, _ = create_planner_run(store, repository)
    worker = make_worker(store, repository)
    rounds: list[int] = []

    async def fake_plan(**kwargs):
        rounds.append(int(kwargs["round_no"]))
        decision = pause_inside_the_round(store, run, worker) if kwargs["round_no"] == 1 else {
            "goal_state": "continue", "basis_summary": "继续上一回合的前沿。",
            "next_action": "读取已排队方向。", "missing_context": [], "tasks": [], "updates": [],
        }
        return {
            "decision": decision,
            "usage": {"requests": 1, "tool_calls": 0, "input_tokens": 5, "output_tokens": 4},
            "error": None, "status": None, "terminal_reason": "completed",
        }

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)

    async def fake_pursue(**_kwargs):
        return worker_outcome("blocked")

    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))
    assert store.get_run(run["id"])["status"] == "paused"
    # What `_loop` does in its `finally` when a run stops: the flag belongs to one
    # execution, so the resumed run must not inherit a set one.
    worker._pauses.pop(run["id"], None)

    assert store.resume_run(run["id"]) is True
    assert store.get_run(run["id"])["status"] == "pending"

    claimed = store.claim_next_run()
    assert claimed is not None and claimed["id"] == run["id"]
    assert claimed["status"] == "running"
    # `started_at` is when the run first began; a resume does not restart that clock.
    assert claimed["started_at"] == run["started_at"]

    asyncio.run(worker._execute(claimed))

    # Round 1 was the paused one; the resumed execution picks up at round 2 instead of
    # planning the run over from the beginning.
    assert rounds[:2] == [1, 2]
    assert store.get_planner_session(run["id"])["current_round"] >= 2
    # And the resumed execution does not announce a second beginning.
    assert run_events(store, run["id"]).count("run_started") == 1


def test_a_paused_run_cannot_be_resumed_once_its_goal_has_settled(store, repository):
    run, _ = create_planner_run(store, repository)
    store.request_pause(run["id"])
    assert store.get_run(run["id"])["status"] == "paused"
    store.finalize_goal(run["id"], "inconclusive", "测试用：目标已结算。")

    assert store.resume_run(run["id"]) is False
    assert store.get_run(run["id"])["status"] == "paused"


def test_the_endpoints_park_and_release_a_run_that_has_not_started(store, repository):
    """A queued run is pausable, and resuming it puts it back where a claim will find it."""
    run = queued_run(store, repository)
    state = services(store)
    request = api(state)

    paused = asyncio.run(pause_run(request, run["id"]))
    assert paused["status"] == "paused"
    assert "run_pause_requested" in run_events(store, run["id"])
    assert store.get_run(run["id"])["status"] == "paused"
    # A paused run is not claimable; that is the whole mechanism for a queued one.
    assert store.claim_next_run() is None

    resumed = asyncio.run(resume_run(request, run["id"]))
    assert resumed["status"] == "pending"
    assert "run_resumed" in run_events(store, run["id"])
    claimed = store.claim_next_run()
    assert claimed is not None and claimed["id"] == run["id"]


def test_pausing_something_that_is_not_active_is_refused(store, repository):
    run = queued_run(store, repository, run_id="settled-run")
    store.update_run(run["id"], status="completed", finished_at="2026-01-01T00:00:00+00:00")
    request = api(services(store))

    with pytest.raises(HTTPException) as paused:
        asyncio.run(pause_run(request, run["id"]))
    assert paused.value.status_code == 409
    # A run that is not paused cannot be resumed either.
    with pytest.raises(HTTPException) as resumed:
        asyncio.run(resume_run(request, run["id"]))
    assert resumed.value.status_code == 409
    with pytest.raises(HTTPException) as missing:
        asyncio.run(pause_run(request, "no-such-run"))
    assert missing.value.status_code == 404


def test_a_paused_run_can_still_be_cancelled(store, repository):
    """Pausing to look at a run and then throwing it away must not require resuming it.

    Cancel is the escalation, and it behaves the same here as for a queued run: the
    frontier is abandoned and the run is settled.  Pause is the reversible one; this is
    the test that the reversible one does not become a trap.
    """
    from audit.app import cancel_run

    run = queued_run(store, repository, run_id="cancelled-while-paused")
    request = api(services(store))
    asyncio.run(pause_run(request, run["id"]))
    assert store.get_run(run["id"])["status"] == "paused"

    cancelled = asyncio.run(cancel_run(request, run["id"]))

    assert cancelled["status"] == "cancelled"
    assert cancelled["finished_at"]
    kinds = run_events(store, run["id"])
    assert "run_cancelled" in kinds
    assert store.get_task_goal(run["id"])["status"] == "inconclusive"
    assert store.resume_run(run["id"]) is False


def test_a_legacy_run_is_parked_rather_than_abandoned(store, repository):
    """The retired per-file queue gets the same treatment: a pause is not a cancel.

    This is the branch a historical database reaches, so it is the one branch no other
    test in this suite would notice a regression in -- and it used to read "the status is
    not running" as "cancelled" and skip every unit still queued.
    """
    snapshot = import_project(repository)
    store.add_snapshot(snapshot)
    payload = run_payload(snapshot, "legacy-run", ["public/index.php", "src/files.php"], TASK)
    payload["task_spec"] = None
    store.create_run(payload, units=[{
        "id": "unit-1", "file_path": "src/files.php", "symbol": "", "start_line": 1,
        "end_line": 5, "priority": 1,
    }])
    claimed = store.claim_next_run()
    store.request_pause(claimed["id"])
    worker = make_worker(store, repository)
    worker._pauses[claimed["id"]] = asyncio.Event()

    asyncio.run(worker._execute(store.get_run(claimed["id"])))

    assert store.get_run(claimed["id"])["status"] == "paused"
    units = store.list_run_units(claimed["id"])
    assert [item["status"] for item in units] == ["pending"]
    kinds = run_events(store, claimed["id"])
    assert "run_paused" in kinds
    assert "run_cancelled" not in kinds


def test_a_restart_says_the_run_was_paused_rather_than_in_flight(store, repository):
    """Nothing in this process can resume a paused run, so a restart interrupts it.

    Calling that "in flight" would be wrong twice over: the run had deliberately stopped,
    and its frontier was never half-executed.
    """
    run = queued_run(store, repository, run_id="run-paused")
    store.request_pause(run["id"])
    assert store.get_run(run["id"])["status"] == "paused"
    # A parked run still holds an unfinished frontier, so it keeps a model-profile switch
    # blocked rather than looking idle.
    assert store.active_run_count() == 1

    store.interrupt_stale_runs()

    repaired = store.get_run(run["id"])
    assert repaired["status"] == "interrupted"
    assert "paused" in str(repaired["error"])
    assert store.resume_run(run["id"]) is False
    assert store.get_task_goal(run["id"])["status"] == "inconclusive"
    assert store.active_run_count() == 0


def test_resuming_before_the_round_finishes_hands_the_run_back(store, repository, monkeypatch):
    """Pause then resume mid-round is an ordinary click, and must not read as a cancel.

    ``request_pause`` flips the status the moment it lands, so the resume button is live
    while the round already in flight is still finishing -- and ``resume`` returns the run
    to the claim queue right away.  For as long as this pass keeps working, then, the run
    reads ``pending``: a status the running loop used to answer with an abandoned frontier
    and a ``run_cancelled``, cancelling a run the user had just restarted.  The pass has to
    hand it back instead, and the claim that follows must continue rather than restart.
    """
    from audit import worker as worker_module

    run, _ = create_planner_run(store, repository)
    worker = make_worker(store, repository)
    rounds: list[int] = []

    async def plan_while_the_user_resumes(**kwargs):
        rounds.append(int(kwargs["round_no"]))
        # The user pauses and, seeing the button, resumes before this round has finished.
        store.request_pause(run["id"])
        worker.pause(run["id"])
        assert store.resume_run(run["id"]) is True
        return {
            "decision": {
                "goal_state": "continue",
                "basis_summary": "派发入口与文件操作两个方向。",
                "next_action": "读取两个方向。",
                "missing_context": [],
                "tasks": [proposal("entry-flow"), proposal("file-operation", path="src/files.php")],
                "updates": [],
            },
            "usage": {"requests": 1, "tool_calls": 0, "input_tokens": 5, "output_tokens": 4},
            "error": None, "status": None, "terminal_reason": "completed",
        }

    monkeypatch.setattr(worker_module, "plan_audit_frontier", plan_while_the_user_resumes)
    asyncio.run(worker._execute(run))

    assert rounds == [1]
    assert store.get_run(run["id"])["status"] == "pending"
    # Handed back with everything the round committed: the queue, not a cancellation.
    assert task_states(store, run["id"]) == {"entry-flow": "ready", "file-operation": "ready"}
    assert store.get_task_goal(run["id"])["status"] == "open"
    assert not store.get_run(run["id"])["finished_at"]
    kinds = run_events(store, run["id"])
    assert "run_cancelled" not in kinds
    assert "goal_inconclusive" not in kinds

    # The claim the loop makes next is an ordinary continuation, not a fresh start.
    worker._pauses.pop(run["id"], None)
    claimed = store.claim_next_run()
    assert claimed["id"] == run["id"] and claimed["status"] == "running"

    async def keep_planning(**kwargs):
        rounds.append(int(kwargs["round_no"]))
        # An empty plan is legal while the frontier is non-empty: the two directions are
        # still queued, and re-dispatching them is exactly what must not happen here.
        return {
            "decision": {
                "goal_state": "continue",
                "basis_summary": "前沿仍有未读方向，本轮不再派发。",
                "next_action": "等待前沿结算。",
                "missing_context": [],
                "tasks": [],
                "updates": [],
            },
            "usage": {"requests": 1, "tool_calls": 0, "input_tokens": 5, "output_tokens": 4},
            "error": None, "status": None, "terminal_reason": "completed",
        }

    monkeypatch.setattr(worker_module, "plan_audit_frontier", keep_planning)
    asyncio.run(worker._execute(claimed))

    assert rounds[:2] == [1, 2]
    assert store.get_planner_session(run["id"])["current_round"] >= 2
