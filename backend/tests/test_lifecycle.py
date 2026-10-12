"""The rules that keep an unfinished run from being read as a finished one.

These are the two places where a run's outcome is decided by something other than the
model: a cancel, and a server restart. Both must leave the run reporting *unfinished*
rather than quietly presenting whatever it happened to get through as the whole answer.
"""
import asyncio
from types import SimpleNamespace

import pytest

from audit.db import Store
from audit.metrics import summarise
from audit.worker import AuditWorker

UNIT_COLUMNS = ("file_path", "symbol", "start_line", "end_line", "priority")


def make_unit(unit_id: str, path: str = "a.php") -> dict:
    return {
        "id": unit_id,
        "file_path": path,
        "symbol": "<top-level>",
        "start_line": 1,
        "end_line": 10,
        "priority": 0,
    }


@pytest.fixture
def store(tmp_path):
    store = Store(tmp_path / "audit.db")
    yield store
    store.close()


def make_run(store: Store, run_id: str = "run1", units: list[dict] | None = None) -> str:
    units = units or [make_unit("u1"), make_unit("u2"), make_unit("u3")]
    store.create_run(
        {
            "id": run_id,
            "snapshot_id": "snap1",
            "snapshot_name": "snap.zip",
            "scope": ["a.php"],
            "prompt_id": "p2",
            "prompt_label": "P2",
            "prompt_text": "…",
            "model": "test-model",
            "budgets": {"responses": 8, "tools": 16, "seconds": 300},
            "created_at": "2026-01-01T00:00:00+00:00",
        },
        units,
    )
    return run_id


def set_status(store: Store, run_id: str, unit_id: str, status: str) -> None:
    store._write(
        "UPDATE run_units SET status = ? WHERE run_id = ? AND unit_id = ?", (status, run_id, unit_id)
    )


def statuses(store: Store, run_id: str) -> dict[str, str]:
    return {u["unit_id"]: u["status"] for u in store.list_run_units(run_id)}


def test_restart_marks_the_run_and_its_units_unfinished(store):
    run_id = make_run(store)
    store._write("UPDATE runs SET status = 'running' WHERE id = ?", (run_id,))
    set_status(store, run_id, "u1", "completed")
    set_status(store, run_id, "u2", "running")
    # u3 stays pending: the queue never got to it.

    assert store.interrupt_stale_runs() == 1

    run = store.get_run(run_id)
    assert run["status"] == "interrupted"
    assert run["error"] and "restart" in run["error"].lower()
    assert statuses(store, run_id) == {"u1": "completed", "u2": "incomplete", "u3": "skipped"}


def test_a_restarted_run_reports_no_negative_conclusions(store):
    """The point of the statuses: an interrupted unit must not read as "no vulnerability"."""
    run_id = make_run(store)
    store._write("UPDATE runs SET status = 'running' WHERE id = ?", (run_id,))
    set_status(store, run_id, "u1", "completed")
    set_status(store, run_id, "u2", "running")
    store.interrupt_stale_runs()

    units = store.list_run_units(run_id)
    findings = store.list_findings(run_id)
    metrics = summarise(store.get_run(run_id), units, findings, [])

    assert metrics["completed_units"] == 1
    assert metrics["incomplete_units"] == 2
    assert metrics["pending_units"] == 0, "an interrupted run must not still look like it is about to run"
    assert metrics["candidates"] == 0


def test_a_finished_run_is_left_alone(store):
    run_id = make_run(store)
    store._write("UPDATE runs SET status = 'completed' WHERE id = ?", (run_id,))
    for unit_id in ("u1", "u2", "u3"):
        set_status(store, run_id, unit_id, "completed")

    assert store.interrupt_stale_runs() == 0
    assert store.get_run(run_id)["status"] == "completed"
    assert set(statuses(store, run_id).values()) == {"completed"}


def test_cancel_does_not_touch_runs_that_already_ended(store):
    run_id = make_run(store)
    store._write("UPDATE runs SET status = 'completed' WHERE id = ?", (run_id,))
    store.request_cancel(run_id)
    assert store.get_run(run_id)["status"] == "completed", "cancel must not rewrite a finished run"

    other = make_run(store, "run2")
    store.request_cancel(other)
    assert store.get_run(other)["status"] == "cancelled"


def test_an_orphaned_running_unit_is_swept_even_without_a_running_run(store):
    """A run cancelled and then hard-killed leaves a unit nothing will ever come back for."""
    run_id = make_run(store)
    store.request_cancel(run_id)
    set_status(store, run_id, "u2", "running")

    store.interrupt_stale_runs()

    assert statuses(store, run_id)["u2"] == "incomplete"
    assert store.get_run(run_id)["status"] == "cancelled", "an already-cancelled run keeps its status"


def test_starting_the_worker_is_what_clears_stale_runs(store):
    """The sweep only helps if boot actually reaches it.

    `interrupt_stale_runs` is one line inside `AuditWorker.start`, which is itself called
    from the app's lifespan. Every test above calls the store method directly, so nothing
    would notice if the call were dropped from the startup path — and the run would sit at
    `running` forever, which reads as "still working on it".
    """
    run_id = make_run(store)
    store._write("UPDATE runs SET status = 'running' WHERE id = ?", (run_id,))
    set_status(store, run_id, "u2", "running")

    worker = AuditWorker(
        settings=SimpleNamespace(worker="test-worker"),
        store=store,
        repository=None,
        bus=None,
        health=None,
    )

    async def boot_and_stop() -> None:
        await worker.start()
        await worker.stop()

    asyncio.run(boot_and_stop())

    assert store.get_run(run_id)["status"] == "interrupted"
    assert statuses(store, run_id) == {"u1": "skipped", "u2": "incomplete", "u3": "skipped"}


def test_a_second_boot_is_a_no_op(store):
    run_id = make_run(store)
    store._write("UPDATE runs SET status = 'running' WHERE id = ?", (run_id,))
    set_status(store, run_id, "u2", "running")

    assert store.interrupt_stale_runs() == 1
    before = statuses(store, run_id)
    assert store.interrupt_stale_runs() == 0
    assert statuses(store, run_id) == before
