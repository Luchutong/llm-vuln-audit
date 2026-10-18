"""Which runs count as an optimisation round.

The exported report carries the P0 → P1 → P2 comparison, and it is assembled from whatever
runs happen to share the snapshot. That makes the selection rule load-bearing: a scratch
version created to try one thing, or a re-run of a version already in the table, must not
become an extra "round" — the first would misstate the experiment, the second would turn the
comparison into "the latest attempt against the others".
"""
from types import SimpleNamespace

import pytest

from audit.app import _round_comparison
from audit.db import Store

UNITS = [{"id": "u1", "file_path": "a.php", "symbol": "<top-level>",
          "start_line": 1, "end_line": 10, "priority": 0}]


@pytest.fixture
def state(tmp_path):
    store = Store(tmp_path / "audit.db")
    yield SimpleNamespace(store=store)
    store.close()


def add_prompt(store, prompt_id, phase, label=None):
    store.add_prompt({
        "id": prompt_id, "label": label or prompt_id, "phase": phase,
        "text": "…", "reason": "", "issues": [], "parent_id": None,
        "created_at": "2026-01-01T00:00:00+00:00",
    })


def add_run(store, run_id, prompt_id, created_at, snapshot="snap1"):
    store.create_run(
        {
            "id": run_id, "snapshot_id": snapshot, "snapshot_name": "snap.zip",
            "scope": ["a.php"], "prompt_id": prompt_id, "prompt_label": prompt_id,
            "prompt_text": "…", "model": "test-model",
            "budgets": {"responses": 8, "tools": 16, "seconds": 300},
            "created_at": created_at,
        },
        UNITS,
    )
    return run_id


def selected(state, run):
    result = _round_comparison(state, run)
    return [entry["run"]["prompt_id"] for entry in result["runs"]]


def test_the_three_versions_of_the_experiment_are_the_three_rounds(state):
    store = state.store
    for prompt_id in ("P0", "P1", "P2"):
        add_prompt(store, prompt_id, prompt_id)
    add_run(store, "r0", "P0", "2026-01-01T00:00:00+00:00")
    add_run(store, "r1", "P1", "2026-01-01T01:00:00+00:00")
    add_run(store, "r2", "P2", "2026-01-01T02:00:00+00:00")
    comparison = _round_comparison(state, store.get_run("r2"))
    assert [entry["run"]["prompt_id"] for entry in comparison["runs"]] == ["P0", "P1", "P2"]
    assert [item["prompt_id"] for item in comparison["paired_comparisons"]] == ["P1", "P2"]
    assert all(not item["comparable"] for item in comparison["paired_comparisons"])


def test_an_ad_hoc_version_is_not_a_fourth_round(state):
    # This is exactly what a scratch run looks like: a copy of P2, created in the UI to
    # probe one behaviour. Counting it would make the report claim four rounds.
    store = state.store
    for prompt_id in ("P0", "P1", "P2"):
        add_prompt(store, prompt_id, prompt_id)
    add_prompt(store, "scratch", "custom", "scratch 打断测试用")
    add_run(store, "r0", "P0", "2026-01-01T00:00:00+00:00")
    add_run(store, "r1", "P1", "2026-01-01T01:00:00+00:00")
    add_run(store, "r2", "P2", "2026-01-01T02:00:00+00:00")
    add_run(store, "rs", "scratch", "2026-01-01T03:00:00+00:00")
    assert selected(state, store.get_run("rs")) == ["P0", "P1", "P2"]


def test_a_re_run_of_one_version_replaces_it_rather_than_adding_a_round(state):
    store = state.store
    for prompt_id in ("P0", "P1", "P2"):
        add_prompt(store, prompt_id, prompt_id)
    add_run(store, "r0", "P0", "2026-01-01T00:00:00+00:00")
    add_run(store, "r1", "P1", "2026-01-01T01:00:00+00:00")
    add_run(store, "r2a", "P2", "2026-01-01T02:00:00+00:00")
    add_run(store, "r2b", "P2", "2026-01-01T03:00:00+00:00")
    rounds = _round_comparison(state, store.get_run("r2b"))["runs"]
    assert [entry["run"]["id"] for entry in rounds] == ["r0", "r1", "r2b"]


def test_runs_from_another_snapshot_stay_out_of_the_comparison(state):
    store = state.store
    for prompt_id in ("P0", "P1"):
        add_prompt(store, prompt_id, prompt_id)
    add_run(store, "r0", "P0", "2026-01-01T00:00:00+00:00")
    add_run(store, "other", "P1", "2026-01-01T01:00:00+00:00", snapshot="snap2")
    add_run(store, "r1", "P1", "2026-01-01T02:00:00+00:00")
    assert selected(state, store.get_run("r1")) == ["P0", "P1"]
