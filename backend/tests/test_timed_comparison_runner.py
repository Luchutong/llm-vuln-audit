"""Deterministic fixed-time orchestration and durable cancellation regressions.

All children, clocks, archives and provider credentials are offline fixtures. No
live experiment, user database, model endpoint or Lab30 service is touched.
"""
from __future__ import annotations

import asyncio
import copy
import io
import json
from pathlib import Path
import time
import zipfile

import pytest

from audit import full_comparison as comparison
from audit.db import Store
from audit.source import SourceRepository
from tests.test_full_comparison import IDS, FakeProcess, request, runner
from tests.test_goal_tasks import run_payload
from tests.test_project_findings import _finding


class Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def use_clock(runner, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(runner, "_clock", clock)
    monkeypatch.setattr(runner, "_check_frozen", lambda *args: None)
    return clock


def fake_attempts(runner, monkeypatch, clock, durations, *, valid=True):
    records = []

    async def attempt(ident, trial, output, work, model, *, deadline, batch_deadline):
        index = len(records)
        seconds = durations[index % len(durations)]
        records.append({"prompt_id": trial["prompt_id"], "start": clock(),
                        "deadline": deadline, "batch_deadline": batch_deadline,
                        "audit_limit_seconds": output["audit_limit_seconds"],
                        "frozen_audit_seconds": runner._record(ident)["manifest"]["run_limits"]["seconds"]})
        clock.advance(seconds)
        output.update(status="finished", evaluation_status="valid" if valid else "invalid",
                      usage={"requests": 1, "tool_calls": 2, "total_tokens": 5},
                      duration_seconds=seconds, wall_elapsed_seconds=seconds,
                      audit_elapsed_seconds=min(seconds, output["audit_limit_seconds"]),
                      stop_reason={"code": "run_budget_exhausted" if valid else "offline_infrastructure"},
                      finished_at=comparison.now(),
                      score={"TP": 0, "D": 0, "U": 0, "FP": 0, "FN": 30,
                             "precision": None, "recall": 0, "f1": 0} if valid else None)

    monkeypatch.setattr(runner, "_attempt", attempt)
    return records


def test_nine_full_slots_plus_shared_freeze_finish_within_two_hours(runner, monkeypatch):
    clock = use_clock(runner, monkeypatch)
    original_validate = comparison.validate_assets
    freeze_checks = []

    def frozen_assets(*args, **kwargs):
        # Two initial integrity passes are part of the FIRST batch wall clock.
        freeze_checks.append(1)
        clock.advance(90)
        return original_validate(*args, **kwargs)

    monkeypatch.setattr(comparison, "validate_assets", frozen_assets)
    records = fake_attempts(runner, monkeypatch, clock, [780])

    async def scenario():
        began = clock()
        created = runner.start(request(repeats=3, ids=IDS))
        await runner._task
        final = runner.get(created["id"])
        assert len(records) == 9
        assert clock() - began == 7200
        assert final["status"] == "completed"
        assert final["summary"]["complete_rounds"] == [1, 2, 3]
        assert all(row["frozen_audit_seconds"] == row["audit_limit_seconds"] == 720 for row in records)
        assert all(row["deadline"] - row["start"] == 780 for row in records)
        assert final["progress"]["timing"]["initial_batch"]["elapsed_seconds"] == 7200

    asyncio.run(scenario())
    assert len(freeze_checks) == 2


def test_early_finish_does_not_transfer_unused_time_to_later_trials(runner, monkeypatch):
    clock = use_clock(runner, monkeypatch)
    records = fake_attempts(runner, monkeypatch, clock, [100, 780, 300, 780, 780, 780, 780, 780, 780])

    async def scenario():
        created = runner.start(request(repeats=3, ids=IDS))
        await runner._task
        assert len(records) == 9
        assert all(record["deadline"] - record["start"] == 780 for record in records)
        assert all(record["audit_limit_seconds"] == 720 for record in records)
        assert runner.get(created["id"])["status"] == "completed"

    asyncio.run(scenario())


def test_exhausted_first_batch_leaves_not_started_trials_without_zero_scores(runner, monkeypatch):
    clock = use_clock(runner, monkeypatch)
    records = fake_attempts(runner, monkeypatch, clock, [780])

    async def scenario():
        created = runner.start(request(repeats=3, ids=IDS))
        # Simulate a frozen startup stalled almost to the batch deadline before
        # the scheduler is first allowed to claim a paid trial.
        clock.advance(7000)
        await runner._task
        final = runner.get(created["id"])
        assert records == []
        assert final["status"] == "partial"
        assert all(t["status"] == t["evaluation_status"] == "not_started" for t in final["trials"])
        assert all(t["score"] is None and not t["attempts"] for t in final["trials"])
        assert final["summary"]["complete_rounds"] == []
        assert all(v["metrics"]["f1"]["mean"] is None for v in final["summary"]["variants"])
        assert final["progress"]["timing"]["initial_batch"]["remaining_seconds"] == 200

    asyncio.run(scenario())


def test_retry_has_independent_batch_after_elapsed_startup_and_cannot_reset_initial_deadline(runner, monkeypatch):
    clock = use_clock(runner, monkeypatch)
    records = fake_attempts(runner, monkeypatch, clock, [10], valid=False)

    async def scenario():
        created = runner.start(request())
        await runner._task
        first = runner.get(created["id"])
        initial = copy.deepcopy(first["progress"]["timing"]["initial_batch"])
        target = first["trials"][0]["id"]
        runner.retry(created["id"], target)
        clock.advance(.01)  # Scheduling is never literally instantaneous.
        await runner._task
        final = runner.get(created["id"])
        assert len(records) == 3
        assert len(final["trials"][0]["attempts"]) == 2
        assert final["trials"][0]["retry_count"] == 1
        timing = final["progress"]["timing"]
        assert timing["initial_batch"] == initial
        retry_batch = timing["batches"][-1]
        assert retry_batch["kind"] == "retry" and retry_batch["wall_seconds"] == 780
        assert retry_batch["id"] != initial["id"]
        assert retry_batch["trial_ids"] == [target]
        assert records[-1]["frozen_audit_seconds"] == 720
        assert final["summary"]["actual_total_usage"]["total_tokens"]["known_total"] == 15
        with pytest.raises(comparison.ExperimentError, match="一次"):
            runner.retry(created["id"], target)

    asyncio.run(scenario())


def create_partial_archive(work, *, run_id="offline-durable", status="cancelled"):
    work.mkdir(parents=True, exist_ok=True)
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w") as archive:
        archive.writestr("app/index.php", "<?php\n" + "echo $_GET['x'];\n" * 15)
    snapshot = SourceRepository(work).import_zip(memory.getvalue(), "offline.zip")
    store = Store(work / "audit.db")
    try:
        store.add_snapshot(snapshot)
        store.create_run(run_payload(snapshot, run_id, ["app/index.php"]))
        store.claim_next_run()
        for index in range(13):
            evidence = [{"path": "app/index.php", "start_line": index + 2, "end_line": index + 2}]
            finding = {**_finding(path="app/index.php", evidence=evidence), "run_id": run_id,
                       "fingerprint": f"offline-distinct-{index}", "unit_id": f"unit-{index}"}
            store.add_finding(finding)
            store.append_event(run_id, None, "finding_created", {"id": finding["id"], "evidence": evidence})
        store.append_event(run_id, None, "model_response", {
            "input_tokens": 11, "output_tokens": 7, "token_usage_complete": True})
        # Legacy trial usage without run_limits is recorded on unit invocations;
        # this archive fixture uses a durable total run limit to track requests.
        store._write("UPDATE run_execution_state SET limits=?,responses_used=1,tools_used=4 WHERE run_id=?",
                     (json.dumps({"responses": 256, "tools": 2048, "seconds": 720}), run_id))
        store.terminate_execution(run_id, status, {"code": "user_cancelled" if status == "cancelled" else "worker_exit_without_terminal"})
    finally:
        store.close()
    return run_id, snapshot


@pytest.mark.parametrize("broken", [None, '{"run":', json.dumps({"run": None, "findings": [], "usage": {}}),
                                    json.dumps({"run": {"id": "offline-durable"}, "findings": None, "usage": None})])
def test_missing_corrupt_or_incomplete_result_recovers_thirteen_findings_without_mutation(tmp_path, broken):
    work = tmp_path / "attempt"
    run_id, snapshot = create_partial_archive(work)
    if broken is not None:
        (work / "result.json").write_text(broken)
    before = {str(p.relative_to(work)): p.read_bytes() for p in work.rglob("*") if p.is_file()}
    result = comparison.FullComparisonRunner._load_result(work, run_id)
    assert len(result["findings"]) == 13
    assert result["run"]["status"] == "cancelled"
    assert result["stop_reason"]["code"] == "user_cancelled"
    assert result["usage"]["requests"] == 1 and result["usage"]["total_tokens"] == 18
    assert result["read_coverage"]["read_lines"] == 13
    assert comparison.classify_result(result, 0)[0] == "invalid"
    after = {str(p.relative_to(work)): p.read_bytes() for p in work.rglob("*") if p.is_file()}
    assert before == after


def test_silent_stdout_pulses_then_watchdog_keeps_durable_partial_results(runner, monkeypatch):
    clock = use_clock(runner, monkeypatch)
    real_wait_for = asyncio.wait_for
    calls = []
    pulses = []
    original_pulse = runner._pulse

    def pulse(*args):
        pulses.append(clock())
        original_pulse(*args)

    async def spawn(*args, **kwargs):
        work = Path(args[args.index("--data-dir") + 1])
        run_id, _ = create_partial_archive(work)
        proc = FakeProcess(hold=True)
        proc.stdout.feed_data((json.dumps({"kind": "run_created", "run_id": run_id}) + "\n").encode())
        calls.append({"process": proc, "work": work})
        return proc

    async def advance_silent_read(awaitable, timeout):
        if getattr(getattr(awaitable, "cr_code", None), "co_name", None) == "readline" and calls and not calls[-1]["process"].stdout._buffer:
            awaitable.close()
            clock.advance(timeout)
            raise asyncio.TimeoutError
        return await real_wait_for(awaitable, timeout)

    monkeypatch.setattr(runner, "_pulse", pulse)
    monkeypatch.setattr(comparison.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(comparison.asyncio, "wait_for", advance_silent_read)

    async def scenario():
        created = runner.start(request(run_limits={"responses": 256, "tools": 2048, "seconds": 30}))
        await runner._task
        final = runner.get(created["id"])
        assert pulses and len(calls) == 2
        assert final["status"] == "partial"
        for trial, call in zip(final["trials"], calls):
            attempt = trial["attempts"][0]
            assert attempt["evaluation_status"] == "invalid"
            assert attempt["score"] is None
            assert attempt["stop_reason"]["code"] == "trial_lifecycle_timeout"
            assert attempt["usage"]["requests"] == 1 and attempt["usage"]["total_tokens"] == 18
            assert call["process"].terminated
            assert len(runner.trial_detail(final["id"], trial["id"])["findings"]) == 13
            store = Store.open_readonly(call["work"] / "audit.db")
            try:
                assert store.get_run(attempt["run_id"])["status"] == "cancelled"
            finally:
                store.close()
        assert final["summary"]["complete_rounds"] == []
        assert final["summary"]["actual_total_usage"]["total_tokens"]["known_total"] == 36

    asyncio.run(scenario())


@pytest.mark.parametrize("kill_hangs", [False, True])
def test_term_then_kill_cleanup_has_bounded_waits(kill_hangs):
    class StubbornProcess:
        returncode = None
        terminated = killed = False

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True
            self.returncode = -9

        async def communicate(self):
            if self.killed and not kill_hangs:
                return b"", b""
            await asyncio.Event().wait()

        async def wait(self):
            return self.returncode

    process = StubbornProcess()
    started = time.monotonic()
    asyncio.run(comparison.FullComparisonRunner._terminate(process, timeout=.03))
    assert time.monotonic() - started < .2
    assert process.terminated and process.killed and process.returncode == -9


def test_explicit_cancel_recovers_thirteen_candidates_without_promoting_result(runner, monkeypatch):
    calls = []

    async def spawn(*args, **kwargs):
        work = Path(args[args.index("--data-dir") + 1])
        run_id, _ = create_partial_archive(work)
        proc = FakeProcess(hold=True)
        proc.stdout.feed_data((json.dumps({"kind": "run_created", "run_id": run_id}) + "\n").encode())
        calls.append({"process": proc, "work": work})
        return proc

    monkeypatch.setattr(comparison.asyncio, "create_subprocess_exec", spawn)

    async def scenario():
        created = runner.start(request())
        while runner._process is None:
            await asyncio.sleep(0)
        final = await runner.cancel(created["id"])
        assert final["status"] == "cancelled" and len(calls) == 1
        trial = final["trials"][0]
        assert trial["evaluation_status"] == "invalid" and trial["score"] is None
        assert trial["usage"]["total_tokens"] == 18
        assert len(runner.trial_detail(final["id"], trial["id"])["findings"]) == 13
        assert calls[0]["process"].terminated
        assert final["trials"][1]["attempts"] == []
        assert final["trials"][1]["status"] == final["trials"][1]["evaluation_status"] == "not_started"
        assert final["trials"][1]["can_retry"] is True
        assert final["trials"][1]["score"] is None
        assert final["summary"]["complete_rounds"] == []
        assert all(row["metrics"]["f1"]["mean"] is None for row in final["summary"]["variants"])
        store = Store.open_readonly(calls[0]["work"] / "audit.db")
        try:
            assert store.get_run(trial["run_id"])["status"] == "cancelled"
        finally:
            store.close()

    asyncio.run(scenario())


def test_cleanup_reaping_cannot_add_wait_after_its_total_allowance(monkeypatch):
    clock = Clock()
    waits = []

    class SilentReapingProcess:
        returncode = None
        terminated = killed = False

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True
            self.returncode = -9

        async def communicate(self):
            await asyncio.Event().wait()

        async def wait(self):
            await asyncio.Event().wait()

    async def time_out(awaitable, timeout):
        awaitable.close()
        waits.append(timeout)
        clock.advance(timeout)
        raise asyncio.TimeoutError

    process = SilentReapingProcess()
    monkeypatch.setattr(comparison.asyncio, "wait_for", time_out)

    async def scenario():
        loop = asyncio.get_running_loop()
        original_time = loop.time
        loop.time = clock
        try:
            await comparison.FullComparisonRunner._terminate(process, timeout=.03)
        finally:
            loop.time = original_time

    asyncio.run(scenario())
    assert process.terminated and process.killed
    assert sum(waits) <= .030001



def test_not_started_slot_can_be_retried_exactly_once_without_an_initial_attempt(runner, monkeypatch):
    clock = use_clock(runner, monkeypatch)
    records = fake_attempts(runner, monkeypatch, clock, [10], valid=False)

    async def scenario():
        created = runner.start(request())
        clock.advance(7000)
        await runner._task
        initial = runner.get(created["id"])
        target = initial["trials"][0]
        assert target["evaluation_status"] == "not_started" and target["can_retry"]
        assert not target["attempts"]
        deadline = initial["progress"]["timing"]["initial_batch"]["deadline_at"]
        runner.retry(created["id"], target["id"])
        clock.advance(.01)
        await runner._task
        final = runner.get(created["id"])
        assert len(records) == 1
        retried = final["trials"][0]
        assert retried["retry_count"] == 1 and len(retried["attempts"]) == 1
        assert retried["attempts"][0]["attempt_no"] == 1
        assert retried["attempts"][0]["batch_kind"] == "retry"
        assert not retried["can_retry"]
        assert final["progress"]["timing"]["initial_batch"]["deadline_at"] == deadline
        with pytest.raises(comparison.ExperimentError, match="一次"):
            runner.retry(created["id"], target["id"])

    asyncio.run(scenario())



@pytest.mark.parametrize("interrupted", [False, True])
def test_cancel_after_score_during_cleanup_retains_cost_but_clears_all_grades(runner, monkeypatch, interrupted):
    from tests.test_full_comparison import fake_children
    calls = fake_children(monkeypatch)
    cleaning = asyncio.Event()
    original_terminate = runner._terminate
    original_attempt = runner._attempt
    captured = []

    async def attempt(*args, **kwargs):
        captured.append(args[2])
        await original_attempt(*args, **kwargs)

    async def cleanup(process, *, timeout):
        if process is not None and not cleaning.is_set():
            # _attempt classified and scored its result before this finally-await.
            assert captured[-1]["evaluation_status"] == "valid"
            assert captured[-1]["score"] is not None
            cleaning.set()
            await asyncio.Event().wait()
        await original_terminate(process, timeout=timeout)

    monkeypatch.setattr(runner, "_attempt", attempt)
    monkeypatch.setattr(runner, "_terminate", cleanup)

    async def scenario():
        created = runner.start(request())
        await asyncio.wait_for(cleaning.wait(), 5)
        final = await runner.cancel(created["id"], interrupted=interrupted)
        expected = "interrupted" if interrupted else "cancelled"
        reason = "interrupted" if interrupted else "user_cancelled"
        assert final["status"] == expected
        trial = final["trials"][0]
        active = trial["attempts"][0]
        for item in (trial, active):
            assert item["status"] == expected
            assert item["evaluation_status"] == "invalid"
            assert item["score"] is None
            assert item["stop_reason"]["code"] == reason
            assert item["usage"]["total_tokens"] == 5
        assert final["summary"]["complete_rounds"] == []
        assert all(row["metrics"]["f1"]["mean"] is None for row in final["summary"]["variants"])
        assert final["summary"]["actual_total_usage"]["total_tokens"]["known_total"] == 5
        assert len(calls) == 1

    asyncio.run(scenario())
