"""Isolated full-comparison orchestration: real temp stores, fake child processes.

No test starts a model, POC, live service, or the user's audit database.
"""
from __future__ import annotations

import asyncio
import copy
import csv
import io
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from audit import full_comparison as comparison
from audit.config import ModelConfig, Settings
from audit.db import Store, now
from audit.schemas import PromptExperimentRequest
from audit.source import SourceRepository
from audit.worker_strategies import builtin_worker_strategies

ROOT = Path(__file__).resolve().parents[2]
BUNDLED = ROOT / "llm-vuln-audit-feat-lab30-shop/llm-vuln-audit-feat-lab30-shop/lab30-shop-1.0.0-source.zip"
IDS = [f"worker-w{i}-v1" for i in range(3)]


@pytest.fixture
def runner(tmp_path, monkeypatch):
    monkeypatch.setenv("LAB30_SOURCE_ZIP", str(BUNDLED))
    settings = Settings(data_dir=tmp_path / "data", model=ModelConfig(
        model="offline-test", base_url="http://127.0.0.1:1/v1", api_key="offline-secret"))
    settings.data_dir.mkdir()
    store = Store(settings.db_path)
    for prompt in builtin_worker_strategies():
        store.upsert_builtin_prompt(prompt)
    value = comparison.FullComparisonRunner(store, settings)
    monkeypatch.setattr(value, "_code_identity", lambda: {"commit": "offline-fixture", "dirty": False, "files": {}})
    yield value
    store.close()


def request(*, repeats=1, ids=None, **overrides):
    ids = ids or IDS[:2]
    return PromptExperimentRequest(protocol="lab30-full-v2", prompt_ids=ids,
                                   baseline_prompt_id=ids[0], repeats=repeats, **overrides)


class FakeProcess:
    def __init__(self, *, code=0, hold=False):
        self.returncode = None
        self.code = code
        self.terminated = False
        self.killed = False
        self.stdout = asyncio.StreamReader()
        if not hold:
            self.stdout.feed_eof()

    async def wait(self):
        if self.returncode is None:
            self.returncode = self.code
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self.stdout.feed_eof()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.stdout.feed_eof()

    async def communicate(self):
        return b"", b""


def fake_children(monkeypatch, *, infra=False, hold=False):
    calls = []
    async def spawn(*args, **kwargs):
        args = list(args)
        output = Path(args[args.index("--output") + 1])
        prompt = args[args.index("--prompt-id") + 1]
        proc = FakeProcess(hold=hold)
        result = {"run": {"id": f"run-{output.parent.name}-{prompt}", "status": "inconclusive", "snapshot_id": "snapshot"},
                  "findings": [], "stop_reason": {"code": "run_budget_exhausted"},
                  "usage": {"requests": 1, "tool_calls": 2, "input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
                  "duration_seconds": 1, "infra_error": {"code": "model_unavailable"} if infra else None}
        output.write_text(json.dumps(result))
        calls.append({"prompt": prompt, "args": args, "kwargs": kwargs, "process": proc, "result": result})
        return proc
    monkeypatch.setattr(comparison.asyncio, "create_subprocess_exec", spawn)
    return calls


def test_freezes_actual_prompts_assets_model_and_budgets_before_execution(runner, monkeypatch):
    calls = fake_children(monkeypatch)
    async def scenario():
        payload = request(budgets={"responses": 12})
        created = runner.start(payload)
        manifest = copy.deepcopy(created["manifest"])
        payload.budgets["responses"] = 1
        runner.settings.model = ModelConfig(model="changed", base_url="http://127.0.0.1:2", api_key="changed-secret")
        runner.store._write("UPDATE prompts SET text='later edit' WHERE id=?", (IDS[0],))
        await runner._task
        final = runner.get(created["id"])
        assert final["manifest"] == manifest
        assert final["manifest"]["model"]["model"] == "offline-test"
        assert final["manifest"]["budgets"]["responses"] == 12
        assert final["manifest"]["task_spec"]["completion_policy"] == "coverage_review"
        assert final["manifest"]["task_spec"]["orchestration_policy"] == "host-queue-v1"
        assert final["manifest"]["task_spec"]["workflow_policy"] == "discovery_first"
        assert final["manifest"]["closure_policy"] == {"version": "coverage-review-v1"}
        assert final["manifest"]["variants"][0]["text"] != "later edit"
        assert all(call["kwargs"]["env"]["LLM_MODEL"] == "offline-test" for call in calls)
        assert all(call["kwargs"]["env"]["LLM_API_KEY"] == "offline-secret" for call in calls)
        encoded = json.dumps(final)
        assert "offline-secret" not in encoded and "changed-secret" not in encoded
        folder = runner._directory(created["id"])
        assert (folder / "frozen/source.zip").read_bytes() == BUNDLED.read_bytes()
        assert runner.store.get_prompt(IDS[0])["used_by_experiments"] == 1
    asyncio.run(scenario())


def test_rotation_is_serial_all_nine_trials_and_valid_budget_exhaustion_counts(runner, monkeypatch):
    calls = fake_children(monkeypatch)
    async def scenario():
        created = runner.start(request(repeats=3, ids=IDS))
        await runner._task
        final = runner.get(created["id"])
        assert [x["prompt"] for x in calls] == IDS + IDS[1:] + IDS[:1] + IDS[2:] + IDS[:2]
        assert len({x["args"][x["args"].index("--data-dir") + 1] for x in calls}) == 9
        assert final["status"] == "completed", [t.get("error") for t in final["trials"]]
        assert all(t["evaluation_status"] == "valid" for t in final["trials"])
        assert all(t["score"]["FN"] == 30 and t["score"]["f1"] == 0 for t in final["trials"])
        assert final["summary"]["complete_rounds"] == [1, 2, 3]
        assert final["summary"]["actual_total_usage"]["total_tokens"]["known_total"] == 45
        assert all(x["process"].returncode == 0 and not x["process"].terminated for x in calls)
    asyncio.run(scenario())


def test_wrong_source_is_refused_before_record_or_process(runner, tmp_path, monkeypatch):
    wrong = tmp_path / "wrong.zip"
    wrong.write_bytes(b"not the benchmark source")
    monkeypatch.setenv("LAB30_SOURCE_ZIP", str(wrong))
    calls = fake_children(monkeypatch)
    async def scenario():
        with pytest.raises(comparison.ExperimentError, match="数据不可用"):
            runner.start(request())
    asyncio.run(scenario())
    assert calls == [] and runner.store.list_prompt_experiments() == []


def test_cancel_before_scheduling_never_spawns_a_paid_child(runner, monkeypatch):
    calls = fake_children(monkeypatch)
    async def scenario():
        created = runner.start(request())
        final = await runner.cancel(created["id"])
        assert final["status"] == "cancelled"
        assert not any(t["attempts"] for t in final["trials"])
    asyncio.run(scenario())
    assert calls == []


def test_cancel_during_spawn_reaps_the_spawned_process_and_keeps_cancelled(runner, monkeypatch):
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        process = FakeProcess(hold=True)
        async def spawn(*args, **kwargs):
            entered.set()
            await release.wait()
            return process
        monkeypatch.setattr(comparison.asyncio, "create_subprocess_exec", spawn)
        created = runner.start(request())
        await entered.wait()
        cancelling = asyncio.create_task(runner.cancel(created["id"]))
        await asyncio.sleep(0)
        release.set()
        final = await asyncio.wait_for(cancelling, 2)
        assert process.terminated and process.returncode is not None
        assert final["status"] == "cancelled"
        assert final["trials"][0]["evaluation_status"] == "invalid"
        assert final["trials"][1]["attempts"] == []
    asyncio.run(scenario())


def test_only_once_explicit_retry_preserves_both_attempts_and_cost(runner, monkeypatch):
    calls = fake_children(monkeypatch, infra=True)
    async def scenario():
        created = runner.start(request())
        await runner._task
        final = runner.get(created["id"])
        target = final["trials"][0]["id"]
        assert final["status"] == "partial" and len(calls) == 2
        runner.retry(created["id"], target)
        await runner._task
        final = runner.get(created["id"])
        assert len(final["trials"][0]["attempts"]) == 2 and len(calls) == 3
        assert final["summary"]["actual_total_usage"]["total_tokens"]["known_total"] == 15
        encoded, _, _ = runner.report(created["id"], "csv")
        with zipfile.ZipFile(io.BytesIO(encoded)) as archive:
            exported = list(csv.DictReader(io.StringIO(archive.read("trials.csv").decode("utf-8-sig"))))
        assert len(exported) == 3
        history = [x for x in exported if x["trial_id"] == target]
        assert [x["attempt_no"] for x in history] == ["1", "2"]
        assert [x["effective_attempt"] for x in history] == ["False", "True"]
        assert all(x["total_tokens"] == "5" for x in history)
        with pytest.raises(comparison.ExperimentError, match="一次"):
            runner.retry(created["id"], target)
    asyncio.run(scenario())


def test_valid_low_score_cannot_be_replaced_by_retry(runner, monkeypatch):
    fake_children(monkeypatch)
    async def scenario():
        created = runner.start(request())
        await runner._task
        target = runner.get(created["id"])["trials"][0]
        assert target["score"]["f1"] == 0
        with pytest.raises(comparison.ExperimentError, match="有效低分"):
            runner.retry(created["id"], target["id"])
    asyncio.run(scenario())


def test_retry_after_restart_cannot_use_different_model_or_tampered_assets(runner, monkeypatch):
    fake_children(monkeypatch, infra=True)
    async def scenario():
        created = runner.start(request())
        await runner._task
        target = runner.get(created["id"])["trials"][0]["id"]
        other = comparison.FullComparisonRunner(runner.store, Settings(data_dir=runner.settings.data_dir,
            model=ModelConfig(model="other", base_url="http://127.0.0.1:2", api_key="offline")))
        with pytest.raises(comparison.ExperimentError, match="原模型"):
            other.retry(created["id"], target)
        path = runner._directory(created["id"]) / "frozen/anchors.json"
        anchors = json.loads(path.read_text())
        anchors["vulnerabilities"][0]["scoring_locations"][0]["line_sha256"] = "0" * 64
        path.write_text(json.dumps(anchors))
        with pytest.raises((ValueError, comparison.ExperimentError), match="摘要"):
            runner.retry(created["id"], target)
    asyncio.run(scenario())


@pytest.mark.parametrize("code,result,expected", [
    (0, {"run": {"status": "inconclusive"}, "stop_reason": {"code": "run_budget_exhausted"}}, "valid"),
    (0, {"run": {"status": "failed", "error": "Model output was not valid"}}, "valid"),
    (0, {"run": {"status": "failed", "error": "ReadTimeout"}}, "valid"),
    (0, {"run": {"status": "failed", "error": "Context length exceeded"}}, "valid"),
    (0, {"run": {"status": "failed", "error": "Connection refused"}}, "valid"),
    (0, {"run": {"status": "failed"}, "infra_error": {"code": "model_unavailable", "status": 401}}, "invalid"),
    (0, {"run": {"status": "completed", "error": "rate limit / unauthorized are source findings"}}, "valid"),
    (0, {"run": {"status": "cancelled"}}, "invalid"),
    (0, {"run": {"status": "interrupted"}}, "invalid"),
    (1, {"run": {"status": "completed"}}, "invalid"),
    (0, {"infra_error": {"code": "trial_process_error"}}, "invalid"),
])
def test_result_classification_keeps_model_failures_but_not_infra(code, result, expected):
    result = copy.deepcopy(result)
    if "run" in result:
        result["run"]["id"] = "offline-run"
    assert comparison.classify_result(result, code)[0] == expected


def test_missing_terminal_run_is_corrupt_not_valid_zero_score():
    assert comparison.classify_result({}, 0)[0] == "invalid"


def test_shutdown_stops_running_child_preserves_partial_cost_and_cannot_resume(runner, monkeypatch):
    calls = fake_children(monkeypatch, hold=True)
    async def scenario():
        created = runner.start(request())
        async def wait_until_spawned():
            while not calls:
                await asyncio.sleep(0)
        await asyncio.wait_for(wait_until_spawned(), 2)
        await runner.shutdown()
        final = runner.get(created["id"])
        assert final["status"] == "interrupted"
        assert calls[0]["process"].terminated
        assert final["trials"][0]["evaluation_status"] == "invalid"
        assert final["summary"]["actual_total_usage"]["total_tokens"]["known_total"] == 5
        assert len(calls) == 1
        with pytest.raises(comparison.ExperimentError):
            runner.retry(created["id"], final["trials"][0]["id"])
    asyncio.run(scenario())


def test_active_full_experiment_blocks_duplicate_start(runner, monkeypatch):
    calls = fake_children(monkeypatch)
    async def scenario():
        created = runner.start(request())
        with pytest.raises(comparison.ExperimentError, match="已有实验"):
            runner.start(request())
        await runner._task
        assert runner.get(created["id"])["status"] == "completed"
    asyncio.run(scenario())
    assert len(calls) == 2


def test_retry_refuses_changed_disk_manifest_even_with_unchanged_assets(runner, monkeypatch):
    fake_children(monkeypatch, infra=True)
    async def scenario():
        created = runner.start(request())
        await runner._task
        row = runner.get(created["id"])
        manifest_path = runner._directory(created["id"]) / "manifest.json"
        disk = json.loads(manifest_path.read_text())
        disk["variants"][0]["text"] += " changed after freeze"
        manifest_path.write_text(json.dumps(disk))
        with pytest.raises(comparison.ExperimentError):
            runner.retry(created["id"], row["trials"][0]["id"])
    asyncio.run(scenario())


def test_missing_frozen_truth_never_spawns_and_releases_experiment_lock(runner, monkeypatch):
    calls = fake_children(monkeypatch)
    async def scenario():
        created = runner.start(request())
        (runner._directory(created["id"]) / "frozen/truth.json").unlink()
        await runner._task
        final = runner.get(created["id"])
        assert final["status"] not in comparison.ACTIVE
        assert runner.store.running_prompt_experiment() is None
    asyncio.run(scenario())
    assert calls == []


def test_archive_missing_database_does_not_create_it_and_scope_is_strict(runner, monkeypatch):
    fake_children(monkeypatch)
    async def scenario():
        created = runner.start(request())
        await runner._task
        return runner.get(created["id"])
    row = asyncio.run(scenario())
    trial = row["trials"][0]
    work = runner._directory(row["id"]) / "trials" / trial["id"] / "attempt-1"
    before = sorted(str(p.relative_to(work)) for p in work.rglob("*"))
    with pytest.raises(FileNotFoundError):
        with runner.archive(row["id"], trial["id"]):
            pytest.fail("missing archive was opened")
    assert not (work / "audit.db").exists()
    assert sorted(str(p.relative_to(work)) for p in work.rglob("*")) == before
    with pytest.raises(LookupError):
        runner.trial_detail(row["id"], "../" + trial["id"])
    with pytest.raises(LookupError):
        runner.trial_detail(row["id"], trial["id"], 99)


def _prepare_archive(runner, row, trial):
    attempt = trial["attempts"][-1]
    work = runner._directory(row["id"]) / "trials" / trial["id"] / "attempt-1"
    repository = SourceRepository(work)
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w") as archive:
        archive.writestr("app/index.php", "<?php\necho 1;\n")
    snapshot = repository.import_zip(memory.getvalue(), "isolated.zip")
    store = Store(work / "audit.db")
    store.add_snapshot(snapshot)
    store.create_run({"id": attempt["run_id"], "snapshot_id": snapshot["id"], "snapshot_name": "isolated.zip",
        "scope": ["app/index.php"], "prompt_id": "offline", "prompt_label": "Isolated report",
        "prompt_text": "offline", "model": "offline", "budgets": {"responses": 24, "tools": 96, "seconds": 1800},
        "created_at": now()})
    store.update_run(attempt["run_id"], status="completed", finished_at=now())
    store.close()
    return work, snapshot


def test_archive_readonly_sources_and_both_trial_report_formats(runner, monkeypatch):
    fake_children(monkeypatch)
    async def scenario():
        created = runner.start(request())
        await runner._task
        return runner.get(created["id"])
    row = asyncio.run(scenario())
    trial = row["trials"][0]
    work, snapshot = _prepare_archive(runner, row, trial)
    with runner.archive(row["id"], trial["id"]) as (store, _, _, _):
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            store._db.execute("CREATE TABLE forbidden(x)")
    detail = runner.trial_detail(row["id"], trial["id"])
    assert detail["snapshot"]["id"] == snapshot["id"]
    source = runner.source(row["id"], trial["id"], "app/index.php", 1, 2)
    assert "echo 1" in str(source)
    bundle, mime, name = runner.trial_report(row["id"], trial["id"], "json")
    assert json.loads(bundle)["run"]["id"] == trial["run_id"]
    markdown, mime, name = runner.trial_report(row["id"], trial["id"], "markdown")
    assert mime.startswith("text/markdown") and markdown.startswith(b"#")


def test_trial_lookup_never_falls_back_across_experiments(runner, monkeypatch):
    fake_children(monkeypatch)
    async def scenario():
        a = runner.start(request())
        await runner._task
        b = runner.start(request())
        await runner._task
        return runner.get(a["id"]), runner.get(b["id"])
    a, b = asyncio.run(scenario())
    own, foreign = a["trials"][0], b["trials"][0]
    _prepare_archive(runner, a, own)
    assert runner.trial_detail(a["id"], own["id"])["run"] is not None
    with pytest.raises(LookupError):
        runner.trial_detail(b["id"], own["id"])
    with pytest.raises(FileNotFoundError):
        runner.trial_detail(b["id"], foreign["id"])


def test_csv_export_contains_diagnostics_and_matches_server_summary(runner, monkeypatch):
    fake_children(monkeypatch)
    async def scenario():
        created = runner.start(request())
        await runner._task
        return runner.get(created["id"])
    row = asyncio.run(scenario())
    encoded, mime, filename = runner.report(row["id"], "csv")
    with zipfile.ZipFile(io.BytesIO(encoded)) as archive:
        assert set(archive.namelist()) == {"summary.csv", "trials.csv", "truth_matrix.csv", "cvss_common.csv", "execution_diagnostics.csv"}
        matrix = archive.read("truth_matrix.csv").decode("utf-8-sig")
        assert len(matrix.splitlines()) == 61
        assert "open_redirect" in matrix
        diagnostics = list(csv.DictReader(io.StringIO(archive.read("execution_diagnostics.csv").decode("utf-8-sig"))))
        for actual, expected in zip(diagnostics, row["summary"]["execution_diagnostics"]):
            assert actual["trial_id"] == expected["trial_id"]
            assert actual["stop_reason"] == expected["stop_reason"]
            assert json.loads(actual["missed_diagnostics"]) == expected["missed_diagnostics"]
        summary = list(csv.DictReader(io.StringIO(archive.read("summary.csv").decode("utf-8-sig"))))
        for actual, expected in zip(summary, row["summary"]["variants"]):
            assert actual["audit_elapsed_seconds_n"] == str(expected["metrics"]["audit_elapsed_seconds"]["n"])
    md, mime, filename = runner.report(row["id"], "markdown")
    assert "POC" in md.decode() and "初步结果" in md.decode()
    assert "完整耗时秒" in md.decode() and "自身 MAE" in md.decode()


def test_planner_context_host_error_is_not_an_effective_low_score():
    validity, reason = comparison.classify_result({"run": {"id": "run", "status": "failed"},
        "stop_reason": {"code": "planner_context_error"}}, 0)
    assert (validity, reason) == ("invalid", "planner_context_error")


def test_report_uses_percentage_points_for_both_delta_mean_and_sd(runner, monkeypatch):
    fake_children(monkeypatch)
    async def scenario():
        created = runner.start(request())
        await runner._task
        return runner.get(created["id"])
    row = asyncio.run(scenario())
    variant = row["summary"]["variants"][1]
    variant["paired_deltas"]["f1"].update(mean=.1, sample_std=.1, n=3, values=[
        {"round_index": i + 1, "value": value, "gained_truth_ids": ["01"], "lost_truth_ids": ["02"]}
        for i, value in enumerate((.1, .2, 0))])
    variant["paired_deltas"]["recall"].update(mean=-.1, sample_std=.1, n=3)
    rendered = comparison.markdown_report(row)
    assert "上升 10.0 个百分点" in rendered
    assert "标准差 10.000 个百分点" in rendered
    assert "增检 01" in rendered and "丢失 02" in rendered
    assert "ΔRecall" in rendered and "召回" in rendered and "下降" in rendered
    with zipfile.ZipFile(io.BytesIO(comparison.csv_archive(row))) as archive:
        exported = list(csv.DictReader(io.StringIO(archive.read("summary.csv").decode("utf-8-sig"))))
    selected = next(x for x in exported if x["prompt_id"] == IDS[1])
    assert float(selected["delta_f1_pp_mean"]) == 10
    assert float(selected["delta_f1_pp_sample_std"]) == 10
    assert selected["delta_f1_pp_n"] == "3"
    assert float(selected["delta_recall_pp_mean"]) == -10


@pytest.mark.parametrize("legacy", [False, True])
def test_batch_exports_preserve_unknown_costs_and_legacy_batch_scope(runner, monkeypatch, legacy):
    fake_children(monkeypatch)

    async def scenario():
        created = runner.start(request())
        await runner._task
        return runner.get(created["id"])

    row = asyncio.run(scenario())
    if legacy:
        row["manifest"].pop("time_policy")
        row["progress"] = {}
    for index, trial in enumerate(row["trials"]):
        attempt = trial["attempts"][0]
        if legacy:
            attempt.pop("batch_kind")
            attempt.pop("batch_id")
        attempt.update(usage={"requests": 3, "tool_calls": 0, "known_total_tokens": 7} if index == 0 else {},
                       wall_elapsed_seconds=2 if index == 0 else None,
                       audit_elapsed_seconds=1 if index == 0 else None,
                       duration_seconds=None)
    row["summary"] = runner._summary(row["manifest"], row["trials"], runner._directory(row["id"]))
    kind = "legacy" if legacy else "initial"
    batch = row["summary"]["batch_usage"][kind]
    assert batch["attempts"] == 2
    assert all(batch[key] is None for key in ("requests", "tool_calls", "wall_elapsed_seconds", "audit_elapsed_seconds", "total_tokens"))
    assert batch["known_totals"]["requests"] == {"known_total": 3, "known_attempts": 1, "attempts": 2}
    assert batch["known_totals"]["tool_calls"]["known_total"] == 0
    assert batch["known_totals"]["tool_calls"]["known_attempts"] == 1
    assert batch["known_total_tokens"] == 7
    if legacy:
        assert set(row["summary"]["batch_usage"]) == {"legacy"}
    markdown = comparison.markdown_report(row)
    assert all(f"| {trial['id']} | 1 | {kind} |" in markdown for trial in row["trials"])
    if legacy:
        assert "历史实验保持其原始冻结预算" in markdown
        assert "每试次最多 720 秒" not in markdown
    with zipfile.ZipFile(io.BytesIO(comparison.csv_archive(row))) as archive:
        exported = list(csv.DictReader(io.StringIO(archive.read("trials.csv").decode("utf-8-sig"))))
    assert {attempt["batch_kind"] for attempt in exported} == {kind}
    assert exported[1]["wall_elapsed_seconds"] == exported[1]["audit_elapsed_seconds"] == ""
    assert exported[1]["requests"] == exported[1]["tool_calls"] == ""
    if legacy:
        assert all(item["batch_started_at"] == item["batch_deadline_at"] == "" for item in exported)
    else:
        batch = row["progress"]["timing"]["initial_batch"]
        assert all(item["batch_started_at"] == batch["started_at"] for item in exported)
        assert all(item["batch_deadline_at"] == batch["deadline_at"] for item in exported)
        assert all(float(item["batch_wall_elapsed_seconds"]) == batch["elapsed_seconds"] for item in exported)
