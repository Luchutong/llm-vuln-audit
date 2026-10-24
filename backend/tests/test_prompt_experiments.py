"""The prompt-variant comparison, driven from the app instead of a shell.

The comparison itself is ``scripts/lab30_compare.py``; these tests pin the parts the app
owns: refusing an experiment that cannot run, recording exactly what the child printed,
and settling the row when the child is cancelled or fails.
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import sys

import pytest

from audit import prompt_experiments
from audit.config import ModelConfig, Settings
from audit.db import Store


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def settings(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return Settings(
        data_dir=data_dir,
        model=ModelConfig(model="test-model", base_url="http://127.0.0.1:1/v1", api_key="test-key"),
    )


def fake_script(tmp_path: pathlib.Path, *, code: str = "", sleep: int = 0) -> pathlib.Path:
    """A stand-in for the comparison script: same argument, same two artefacts."""
    path = tmp_path / "fake_compare.py"
    path.write_text(
        "import json, pathlib, sys, time\n"
        f"time.sleep({sleep})\n"
        "out = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])\n"
        "print('=== P0-lite ===', flush=True)\n"
        "print('    TP=1 FP=0 FN=2 P=1.000 R=0.333', flush=True)\n"
        "out.write_text('# comparison', encoding='utf-8')\n"
        "out.with_suffix('.json').write_text(json.dumps([{'variant': 'P0-lite'}]), encoding='utf-8')\n"
        + (f"print({code!r}, flush=True)\nraise SystemExit(3)\n" if code else ""),
        encoding="utf-8",
    )
    return path


def prepare(monkeypatch, tmp_path, script: pathlib.Path) -> None:
    monkeypatch.setattr(prompt_experiments, "SCRIPT", script)
    monkeypatch.setattr(prompt_experiments, "SOURCE_ZIP", script)


def test_the_catalogue_matches_the_variants_that_will_run():
    items = prompt_experiments.catalog()
    assert [item["id"] for item in items] == list(prompt_experiments.DEFAULT_ORDER)
    assert all(item["prompt"].strip() for item in items)
    assert all(item["focus"].strip() for item in items)


def test_an_unconfigured_model_is_refused_before_anything_is_stored(store, tmp_path):
    settings = Settings(data_dir=tmp_path, model=ModelConfig())
    runner = prompt_experiments.ExperimentRunner(store, settings)
    with pytest.raises(prompt_experiments.ExperimentError, match="尚未配置模型"):
        runner.start(["P0-lite", "P1-lite"], 1, None)
    assert store.list_prompt_experiments() == []


def test_two_variants_are_required_to_call_it_a_comparison(store, settings, monkeypatch, tmp_path):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path))
    runner = prompt_experiments.ExperimentRunner(store, settings)
    with pytest.raises(prompt_experiments.ExperimentError, match="至少选择两个版本"):
        runner.start(["P0-lite"], 1, None)


def test_only_one_experiment_runs_at_a_time(store, settings, monkeypatch, tmp_path):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path))
    runner = prompt_experiments.ExperimentRunner(store, settings)
    store.add_prompt_experiment({
        "id": "already-running",
        "created_at": "2026-01-01T00:00:00+00:00",
        "status": "running",
        "variants": ["P0-lite", "P1-lite"],
    })
    with pytest.raises(prompt_experiments.ExperimentError, match="已有一个对比实验在运行"):
        runner.start(["P0-lite", "P1-lite"], 1, None)


def test_a_finished_experiment_records_what_the_script_wrote(store, settings, monkeypatch, tmp_path):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path))
    runner = prompt_experiments.ExperimentRunner(store, settings)

    async def scenario() -> dict:
        started = runner.start(["P0-lite", "P1-lite"], 2, "sqli")
        await runner._task
        return runner.get(started["id"])

    finished = asyncio.run(scenario())
    assert finished["status"] == "completed"
    assert finished["variants"] == ["P0-lite", "P1-lite"]
    assert finished["units_limit"] == 2
    assert finished["scenario"] == "sqli"
    assert finished["rows"] == [{"variant": "P0-lite"}]
    assert finished["progress"]["done"] == [{"variant": "P0-lite", "TP": 1, "FP": 0, "FN": 2}]
    assert runner.running() is None


def test_a_failing_script_settles_as_failed_rather_than_staying_running(
    store, settings, monkeypatch, tmp_path
):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path, code="模型调用失败"))
    runner = prompt_experiments.ExperimentRunner(store, settings)

    async def scenario() -> dict:
        started = runner.start(["P0-lite", "P1-lite"], 1, None)
        await runner._task
        return runner.get(started["id"])

    failed = asyncio.run(scenario())
    assert failed["status"] == "failed"
    assert "退出码 3" in failed["error"]
    assert runner.running() is None


def test_cancelling_terminates_the_child_and_keeps_the_row(store, settings, monkeypatch, tmp_path):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path, sleep=60))
    runner = prompt_experiments.ExperimentRunner(store, settings)

    async def scenario() -> dict:
        started = runner.start(["P0-lite", "P1-lite"], 1, None)
        await asyncio.sleep(0.5)
        cancelled = await runner.cancel(started["id"])
        await asyncio.wait_for(runner._task, timeout=20)
        return cancelled

    stopped = asyncio.run(scenario())
    assert stopped["status"] == "cancelled"
    assert stopped["error"] == "已取消"
    assert runner.running() is None


def test_store_round_trips_an_experiment(store):
    store.add_prompt_experiment({
        "id": "abc123",
        "created_at": "2026-02-02T00:00:00+00:00",
        "status": "running",
        "variants": ["P0-basic", "P1-evidence"],
        "units_limit": 0,
        "scenario": None,
        "model": "m",
        "budgets": {"responses": 12},
        "log_path": "/tmp/run.log",
        "report_path": "/tmp/comparison.md",
    })
    assert [item["id"] for item in store.list_prompt_experiments()] == ["abc123"]
    store.update_prompt_experiment("abc123", status="completed", rows=[{"variant": "x"}])
    row = store.get_prompt_experiment("abc123")
    assert row["status"] == "completed"
    assert row["rows"] == [{"variant": "x"}]
    assert json.loads(json.dumps(row["budgets"])) == {"responses": 12}
    assert store.get_prompt_experiment("missing") is None


def test_restart_settles_stale_experiments_without_spawning(store, settings, monkeypatch):
    store.add_prompt_experiment({"id": "interrupted", "created_at": "2026-01-01", "status": "running"})
    def forbidden_spawn(*args, **kwargs):
        pytest.fail("startup/read must not create a model subprocess")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden_spawn)
    runner = prompt_experiments.ExperimentRunner(store, settings)
    assert runner.running() is None
    assert runner.get("interrupted")["status"] == "failed"
    assert runner.list()[0]["finished_at"]


def test_immediate_cancel_never_starts_a_child(store, settings, monkeypatch, tmp_path):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path))
    def forbidden_spawn(*args, **kwargs):
        pytest.fail("a cancelled experiment must not start a subprocess")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden_spawn)
    runner = prompt_experiments.ExperimentRunner(store, settings)
    async def scenario():
        started = runner.start(["P0-lite", "P1-lite"], 1, None)
        result = await runner.cancel(started["id"])
        await asyncio.sleep(0)
        assert result["status"] == "cancelled"
        assert runner._task.done()
    asyncio.run(scenario())


def test_shutdown_before_spawn_settles_task_before_store_closes(store, settings, monkeypatch, tmp_path):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path))
    def forbidden_spawn(*args, **kwargs):
        pytest.fail("shutdown must prevent queued subprocess startup")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden_spawn)
    runner = prompt_experiments.ExperimentRunner(store, settings)
    async def scenario():
        started = runner.start(["P0-lite", "P1-lite"], 1, None)
        await runner.shutdown()
        assert runner.get(started["id"])["status"] == "cancelled"
        assert runner._task.done()
        with pytest.raises(prompt_experiments.ExperimentError, match="关闭"):
            runner.start(["P0-lite", "P1-lite"], 1, None)
    asyncio.run(scenario())


def test_shutdown_reaps_an_active_process_before_returning(store, settings, monkeypatch, tmp_path):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path, sleep=60))
    original_spawn = asyncio.create_subprocess_exec
    processes = []
    async def scenario():
        spawned = asyncio.Event()
        async def capture_spawn(*args, **kwargs):
            process = await original_spawn(*args, **kwargs)
            processes.append(process)
            spawned.set()
            return process
        monkeypatch.setattr(asyncio, "create_subprocess_exec", capture_spawn)
        runner = prompt_experiments.ExperimentRunner(store, settings)
        started = runner.start(["P0-lite", "P1-lite"], 1, None)
        await spawned.wait()
        await asyncio.wait_for(runner.shutdown(), 5)
        assert runner._task.done()
        assert processes[0].returncode is not None
        assert runner.get(started["id"])["status"] == "cancelled"
        assert runner.running() is None
    asyncio.run(scenario())


def test_selected_model_and_source_are_frozen_before_start_yields(
    store, settings, monkeypatch, tmp_path
):
    script = fake_script(tmp_path)
    prepare(monkeypatch, tmp_path, script)
    original_spawn = asyncio.create_subprocess_exec
    environments = []
    async def capture_spawn(*args, **kwargs):
        environments.append(kwargs["env"])
        return await original_spawn(*args, **kwargs)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture_spawn)
    monkeypatch.setenv("LAB30_SOURCE_ZIP", str(script))
    runner = prompt_experiments.ExperimentRunner(store, settings)
    async def scenario():
        started = runner.start(["P0-lite", "P1-lite"], 1, None)
        settings.model = ModelConfig(model="another-model", base_url="http://127.0.0.1:1/other", api_key="different")
        monkeypatch.setenv("LAB30_SOURCE_ZIP", "/missing/source.zip")
        await runner._task
        assert runner.get(started["id"])["model"].startswith("test-model")
    asyncio.run(scenario())
    assert environments[0]["LLM_MODEL"] == "test-model"
    assert environments[0]["LLM_API_KEY"] == "test-key"
    assert environments[0]["LAB30_SOURCE_ZIP"] == str(script.resolve())


def test_spawn_window_cancellation_reaps_the_child(store, settings, monkeypatch, tmp_path):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path, sleep=60))
    original_spawn = asyncio.create_subprocess_exec
    processes = []
    async def scenario():
        spawning = asyncio.Event()
        finish_spawn = asyncio.Event()
        async def delayed_spawn(*args, **kwargs):
            process = await original_spawn(*args, **kwargs)
            processes.append(process)
            spawning.set()
            await finish_spawn.wait()
            return process
        monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_spawn)
        runner = prompt_experiments.ExperimentRunner(store, settings)
        started = runner.start(["P0-lite", "P1-lite"], 1, None)
        await spawning.wait()
        cancelling = asyncio.create_task(runner.cancel(started["id"]))
        await asyncio.sleep(0)
        finish_spawn.set()
        await asyncio.wait_for(cancelling, 5)
        assert processes[0].returncode is not None
        assert runner.get(started["id"])["status"] == "cancelled"
    asyncio.run(scenario())


def test_read_failure_terminates_the_running_child(store, settings, monkeypatch, tmp_path):
    script = fake_script(tmp_path)
    script.write_text("import time\nprint('x' * 1000000, flush=True)\ntime.sleep(60)\n", encoding="utf-8")
    prepare(monkeypatch, tmp_path, script)
    original_spawn = asyncio.create_subprocess_exec
    processes = []
    async def capture_spawn(*args, **kwargs):
        process = await original_spawn(*args, **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture_spawn)
    runner = prompt_experiments.ExperimentRunner(store, settings)
    async def scenario():
        started = runner.start(["P0-lite", "P1-lite"], 1, None)
        await asyncio.wait_for(runner._task, 5)
        assert runner.get(started["id"])["status"] == "failed"
        assert processes[0].returncode is not None
    asyncio.run(scenario())


def test_budget_ceiling_is_applied_and_actual_allowance_is_stored(
    store, settings, monkeypatch, tmp_path
):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path))
    runner = prompt_experiments.ExperimentRunner(store, settings)
    async def scenario():
        row = runner.start(["P0-lite", "P1-lite"], 1, None, {"responses": 999999, "seconds": -1})
        assert row["budgets"] == {"responses": 256, "tools": 20, "seconds": 30}
        await runner.cancel(row["id"])
    asyncio.run(scenario())


def test_child_logs_and_errors_do_not_expose_the_frozen_model_credentials(
    store, settings, monkeypatch, tmp_path
):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path, code="failed with test-key"))
    runner = prompt_experiments.ExperimentRunner(store, settings)
    async def scenario():
        row = runner.start(["P0-lite", "P1-lite"], 1, None)
        settings.model = ModelConfig(model="other", base_url="http://127.0.0.1:1", api_key="other-key")
        await runner._task
        finished = runner.get(row["id"])
        assert "test-key" not in json.dumps(finished)
        assert "[redacted]" in pathlib.Path(finished["log_path"]).read_text()
    asyncio.run(scenario())


@pytest.mark.parametrize("budget", [{"responses": True}, {"seconds": "5"}, {"unbounded": 1}])
def test_invalid_budget_is_refused_before_an_experiment_is_recorded(
    store, settings, monkeypatch, tmp_path, budget
):
    prepare(monkeypatch, tmp_path, fake_script(tmp_path))
    runner = prompt_experiments.ExperimentRunner(store, settings)
    with pytest.raises(prompt_experiments.ExperimentError, match="预算"):
        runner.start(["P0-lite", "P1-lite"], 1, None, budget)
    assert runner.list() == []
