"""Full trial isolation/lifecycle, with the production coordinator and no provider."""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
from pathlib import Path
import zipfile

import pytest

from audit.comparison_trial import _atomic_json, _infrastructure_failure, _usage, execute_trial
from audit.comparison_results import LiveStats, _read_coverage, collect_trial, recover_trial
from audit.config import ModelConfig
from audit.db import Store
from audit.execution_state import CURRENT_EXECUTION
from audit.runtime import AgentPolicy
from audit.worker import AuditWorker
from audit.worker_strategies import builtin_worker_strategies


CONFIG = ModelConfig(model="frozen-test", base_url="https://model.invalid/v1", api_key="offline-private-key", thinking="enabled")


def manifest(tmp_path):
    root = tmp_path / "frozen"
    root.mkdir(exist_ok=True)
    source = io.BytesIO()
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("src/a.php", "<?php\nfunction handle() {\n echo $_GET['x'];\n}\n")
    content = source.getvalue()
    (root / "source.zip").write_bytes(content)
    return {
        "_root": str(root), "files": {"source": "source.zip"},
        "source_sha256": hashlib.sha256(content).hexdigest(),
        "model": {"model": CONFIG.model, "base_url": CONFIG.public_base_url(), "thinking": CONFIG.thinking},
        "agent_policy": AgentPolicy().snapshot(),
        "variants": builtin_worker_strategies(),
        "task_spec": {"objective": "完整检查项目中的可达安全漏洞", "success_criteria": "遍历相关方向并记录可核查源码结论",
                      "require_poc": False, "stop_on_achieved": False, "max_workers": 1},
        "budgets": {"responses": 4, "tools": 6, "seconds": 30},
        "run_limits": {"responses": 5, "tools": 8, "seconds": 30},
    }


class OfflineWorker(AuditWorker):
    captured = []

    async def _execute_body(self, run):
        # Calling the real _execute entrypoint must bind durable run admission.
        execution = CURRENT_EXECUTION.get()
        assert execution is not None and execution.run_id == run["id"]
        assert not self.settings.poc.enabled
        assert run["project_baseline"] == []
        assert run["scope_mode"] == "snapshot" and run["scope"] == []
        assert self._model_for_run(run) == CONFIG
        assert run["poc_policy"]["mode"] == "off"
        assert run["task_spec"]["stop_on_achieved"] is False
        assert run["model_profile"]["thinking"] == "enabled"
        execution.admit("responses")
        self.bus.emit(run["id"], None, "model_response", {
            "input_tokens": 11, "output_tokens": 7, "token_usage_complete": True,
        })
        self.bus.emit(run["id"], None, "agent_phase", {"phase": "task_execute", "role": "worker"})
        self.bus.emit(run["id"], None, "tool_result", {"seen": [
            {"path": "src/a.php", "start_line": 1, "end_line": 3},
            {"path": "src/a.php", "start_line": 3, "end_line": 4},
        ]})
        self.captured.append(run)
        self.store.terminate_execution(run["id"], "inconclusive", {"code": "offline_fixture", "message": "No model invoked"})


def test_isolated_trial_uses_shared_creation_and_real_budget_context(tmp_path):
    frozen = manifest(tmp_path)
    records = []
    outcomes = []
    for index in range(2):
        result = asyncio.run(execute_trial(frozen, frozen["variants"][index], tmp_path / f"trial-{index}", CONFIG, records.append, OfflineWorker))
        assert result["infra_error"] is None, result
        run = result["run"]
        assert run["worker_strategy"]["id"] == frozen["variants"][index]["id"]
        assert run["budgets"] == frozen["budgets"]
        assert run["run_limits"] == frozen["run_limits"]
        assert run["task_spec"]["workflow_policy"] == "legacy"
        assert run["task_spec"]["orchestration_policy"] == "rounds-v1"
        assert not run["execution_summary"].get("workflow")
        assert run["status"] == "inconclusive"
        assert result["usage"]["requests"] == 1
        assert result["usage"]["total_tokens"] == 18
        assert result["usage"]["token_usage_complete"]
        assert result["read_coverage"]["read_lines"] == 4
        assert result["read_coverage"]["read_files"] == 1
        store = Store(tmp_path / f"trial-{index}" / "audit.db")
        try:
            assert len(store.list_runs()) == 1
            assert len(store.list_snapshots()) == 1
            assert not store.list_findings(run["id"])
        finally:
            store.close()
        outcomes.append(result)
    assert outcomes[0]["run"]["id"] != outcomes[1]["run"]["id"]
    assert outcomes[0]["snapshot"]["id"] != outcomes[1]["snapshot"]["id"]
    assert sum(item["kind"] == "run_created" for item in records) == 2
    assert all(item["kind"] in {"run_created", "audit_started", "phase", "heartbeat"} for item in records)
    assert all(item.get("audit_started_at") for item in records if item["kind"] == "audit_started")
    assert CONFIG.api_key not in json.dumps([records, outcomes])


def test_new_manifest_uses_host_queue_without_adopting_interactive_full_limits(tmp_path):
    frozen = manifest(tmp_path)
    frozen['task_spec'].update(completion_policy='coverage_review', orchestration_policy='host-queue-v1',
                             workflow_policy='discovery_first', review_policy='batch-v1')
    frozen['run_limits']['seconds'] = 720
    result = asyncio.run(execute_trial(frozen, frozen['variants'][0], tmp_path / 'new-policy', CONFIG, lambda _: None, OfflineWorker))
    assert result['infra_error'] is None, result
    assert result['run']['task_spec']['orchestration_policy'] == 'host-queue-v1'
    assert result['run']['run_limits'] == frozen['run_limits']
    assert result['run']['execution_summary']['workflow']['version'] == 'host-queue-v1'


def test_trial_refuses_existing_database_instead_of_reusing_findings(tmp_path):
    frozen = manifest(tmp_path)
    data_dir = tmp_path / "trial"
    data_dir.mkdir()
    existing = Store(data_dir / "audit.db")
    existing.close()
    result = asyncio.run(execute_trial(frozen, frozen["variants"][0], data_dir, CONFIG, worker_factory=OfflineWorker))
    assert result["run"] is None
    assert result["infra_error"]["code"] == "trial_setup_error"
    assert "already contains" in result["infra_error"]["message"]


@pytest.mark.parametrize("change", [{"source_sha256": "wrong"}, {"files": {"source": "../elsewhere.zip"}},
                                      {"model": {"model": "different"}}])
def test_preflight_checks_frozen_source_and_model(tmp_path, change):
    frozen = {**manifest(tmp_path), **change}
    result = asyncio.run(execute_trial(frozen, builtin_worker_strategies()[0], tmp_path / "trial", CONFIG, worker_factory=OfflineWorker))
    assert result["run"] is None and result["infra_error"]
    assert not (tmp_path / "trial" / "audit.db").exists()


def test_cancellation_keeps_actual_partial_run_and_unknown_tokens(tmp_path):
    frozen = manifest(tmp_path)

    class WaitingWorker(AuditWorker):
        async def _execute_body(self, run):
            CURRENT_EXECUTION.get().admit("responses")
            self.bus.emit(run["id"], None, "model_request", {"phase": "task_execute"})
            self.bus.emit(run["id"], None, "agent_phase", {"phase": "task_execute"})
            await asyncio.Event().wait()

    async def scenario():
        started = asyncio.Event()
        job = asyncio.create_task(execute_trial(frozen, frozen["variants"][0], tmp_path / "trial", CONFIG,
                                               lambda item: started.set() if item["kind"] == "phase" else None,
                                               WaitingWorker))
        # The phase event follows admission, so cancellation cannot race setup.
        await asyncio.wait_for(started.wait(), timeout=5)
        job.cancel()
        return await job

    result = asyncio.run(scenario())
    assert result["cancelled"]
    assert result["run"]["status"] == "cancelled"
    assert result["usage"]["requests"] == 1
    assert result["usage"]["total_tokens"] is None
    assert not result["usage"]["token_usage_complete"]


def test_unknown_tokens_do_not_become_zero_and_partial_usage_is_preserved():
    usage = _usage({"usage": {"requests": 2, "tool_calls": 3}}, [
        {"kind": "model_response", "payload": {"input_tokens": 10, "output_tokens": 4, "token_usage_complete": True}},
    ])
    assert usage["total_tokens"] is None and usage["input_tokens"] is None
    assert usage["known_total_tokens"] == 14
    assert usage["tool_calls"] == 3


@pytest.mark.parametrize("field", ["sha256", "text_sha256"])
def test_trial_refuses_strategy_text_digest_mismatch_before_database(tmp_path, field):
    frozen = manifest(tmp_path)
    strategy = {**frozen["variants"][0], field: "wrong"}
    result = asyncio.run(execute_trial(frozen, strategy, tmp_path / "trial", CONFIG, worker_factory=OfflineWorker))
    assert result["run"] is None
    assert field in result["infra_error"]["message"]
    assert not (tmp_path / "trial" / "audit.db").exists()


def test_trial_keeps_original_source_archive_name(tmp_path):
    frozen = {**manifest(tmp_path), "source_name": "lab30-shop-original.zip"}
    result = asyncio.run(execute_trial(frozen, frozen["variants"][0], tmp_path / "trial", CONFIG, worker_factory=OfflineWorker))
    assert not result["infra_error"], result
    assert result["snapshot"]["name"] == "lab30-shop-original.zip"


@pytest.mark.parametrize("run_status", ["failed", "inconclusive"])
@pytest.mark.parametrize("provider", [
    {"status": 401}, {"status": 402}, {"status": 403}, {"status": 404},
    {"status": 429}, {"status": 500}, {"status": 503}, {"status": 599},
    {"provider_error_type": "APIConnectionError"}, {"provider_error_type": "ConnectError"},
    {"provider_error_type": "ConnectTimeout"},
])
def test_unrecovered_explicit_provider_failure_invalidates_failed_or_inconclusive(run_status, provider):
    event = {"kind": "planner_agent_terminal", "payload": {"reason": "model_error", **provider}}
    failure = _infrastructure_failure({"status": run_status}, [event])
    assert failure and failure["code"] == "model_unavailable"


@pytest.mark.parametrize("latest_reason", ["completed", "invalid_output", "budget", "run_budget_exhausted", "timeout", "request_timeout"])
def test_old_provider_error_does_not_discard_subsequent_execution_result(latest_reason):
    events = [
        {"kind": "planner_agent_terminal", "payload": {"reason": "model_error", "status": 503}},
        {"kind": "task_agent_terminal", "payload": {"reason": latest_reason}},
    ]
    assert _infrastructure_failure({"status": "inconclusive"}, events) is None


@pytest.mark.parametrize("status", [None, 400, 408, 422, 600])
def test_ambiguous_or_usage_provider_failure_does_not_invalidate_trial(status):
    event = {"kind": "planner_agent_terminal", "payload": {
        "reason": "model_error", "status": status, "provider_error_type": "APITimeoutError"}}
    assert _infrastructure_failure({"status": "inconclusive"}, [event]) is None


def test_run_total_budget_stop_takes_precedence_over_last_provider_error():
    run = {"status": "inconclusive", "execution_summary": {"stop_reason": {"code": "run_budget_exhausted", "dimension": "responses"}}}
    events = [{"kind": "planner_agent_terminal", "payload": {"reason": "model_error", "status": 503}}]
    assert _infrastructure_failure(run, events) is None
    assert _infrastructure_failure({"status": "completed"}, events) is None


def test_two_disconnected_planner_rounds_preserve_inconclusive_and_mark_infrastructure(tmp_path):
    frozen = manifest(tmp_path)

    class DisconnectedPlannerWorker(AuditWorker):
        async def _execute_body(self, run):
            for _ in range(2):
                CURRENT_EXECUTION.get().admit("responses")
                self.bus.emit(run["id"], None, "planner_agent_terminal", {
                    "reason": "model_error", "status": 503,
                    "provider_error_type": "InternalServerError", "error": "Model endpoint unavailable",
                })
            self.store.terminate_execution(run["id"], "inconclusive", {"code": "goal_inconclusive", "message": "Two Planner rounds unavailable"})

    result = asyncio.run(execute_trial(frozen, frozen["variants"][0], tmp_path / "trial", CONFIG, worker_factory=DisconnectedPlannerWorker))
    assert result["run"]["status"] == "inconclusive"
    assert result["usage"]["requests"] == 2
    assert result["infra_error"]["code"] == "model_unavailable"


def test_atomic_result_write_replaces_complete_json(tmp_path):
    path = tmp_path / "nested" / "result.json"
    _atomic_json(path, {"old": True})
    _atomic_json(path, {"run": {"status": "completed"}})
    assert json.loads(path.read_text()) == {"run": {"status": "completed"}}
    assert list(path.parent.glob(".trial-*")) == []


# Real finding_created events contain an evidence list, unlike the older tool
# result envelope. This was absent from the original fake-worker fixtures.
def add_real_finding(worker, run):
    from tests.test_project_findings import _finding
    evidence = [{"path": "src/a.php", "start_line": 2, "end_line": 3}]
    finding = {**_finding(path="src/a.php", evidence=evidence), "run_id": run["id"]}
    worker.store.add_finding(finding)
    worker.bus.emit(run["id"], None, "finding_created", {
        "id": finding["id"], "title": finding["title"], "evidence": evidence,
    })
    CURRENT_EXECUTION.get().admit("responses")
    worker.bus.emit(run["id"], None, "model_response", {
        "input_tokens": 11, "output_tokens": 7, "token_usage_complete": True,
    })
    return finding


@pytest.mark.parametrize("ending", ["normal", "budget", "cancel"])
def test_genuine_finding_list_survives_all_terminal_paths_and_readonly_recovery(tmp_path, ending):
    frozen = manifest(tmp_path)

    class FindingWorker(AuditWorker):
        async def _execute_body(self, run):
            add_real_finding(self, run)
            if ending == "cancel":
                raise asyncio.CancelledError
            self.store.terminate_execution(run["id"], "inconclusive", {
                "code": "run_budget_exhausted" if ending == "budget" else "unresolved_blockers",
                "dimension": "seconds" if ending == "budget" else None,
            })

    directory = tmp_path / "trial"
    result = asyncio.run(execute_trial(frozen, frozen["variants"][0], directory, CONFIG, worker_factory=FindingWorker))
    assert result["infra_error"] is None
    assert len(result["findings"]) == 1
    assert result["read_coverage"]["read_lines"] == 2
    assert result["usage"]["total_tokens"] == 18
    assert result["audit_started_at"]
    assert result["audit_elapsed_seconds"] >= 0
    if ending == "cancel":
        assert result["cancelled"] and result["run"]["status"] == "cancelled"
    if ending == "budget":
        assert result["stop_reason"]["code"] == "run_budget_exhausted"
    original = (directory / "audit.db").read_bytes()
    # Recovery ignores any result file, including truncated JSON left by a crash.
    (directory / "result.json").write_text('{"run":')
    recovered = recover_trial(directory)
    assert recovered["run"]["status"] == result["run"]["status"]
    assert recovered["findings"] == result["findings"]
    assert recovered["usage"] == result["usage"]
    assert recovered["read_coverage"] == result["read_coverage"]
    assert recovered["recovered_from_archive"] is True
    assert (directory / "audit.db").read_bytes() == original


def test_coverage_supports_lists_dicts_and_ignores_invalid_ranges():
    snapshot = {"files": [{"path": "a.php", "line_count": 8, "kind": "text"}]}
    events = [
        {"kind": "finding_created", "payload": {"evidence": [{"path": "a.php", "start_line": 2, "end_line": 4}]}},
        {"kind": "tool_result", "payload": {"evidence": {"reviewed_ranges": [{"path": "a.php", "start_line": 4, "end_line": 6}]}}},
        {"payload": {"seen": [{"path": "a.php", "start_line": True, "end_line": 3},
                               {"path": ["bad"], "start_line": 1, "end_line": 2}]}},
        {"payload": ["legacy malformed payload"]},
        {"payload": {"evidence": "unusable"}},
    ]
    assert _read_coverage(snapshot, events)["read_lines"] == 5


def test_optional_coverage_exception_does_not_erase_durable_facts(tmp_path, monkeypatch):
    from audit import comparison_results
    frozen = manifest(tmp_path)

    class FindingWorker(OfflineWorker):
        async def _execute_body(self, run):
            add_real_finding(self, run)
            self.store.terminate_execution(run["id"], "inconclusive", {"code": "run_budget_exhausted"})

    def broken(*args):
        raise AttributeError("private source or credentials must not leak")

    monkeypatch.setattr(comparison_results, "_read_coverage", broken)
    result = asyncio.run(execute_trial(frozen, frozen["variants"][0], tmp_path / "trial", CONFIG, worker_factory=FindingWorker))
    assert result["run"] and len(result["findings"]) == 1
    assert result["usage"]["total_tokens"] == 18
    assert result["read_coverage"] is None
    assert result["infra_error"] is None
    assert any(item["code"] == "read_coverage_unavailable" for item in result["warnings"])
    assert "private source" not in json.dumps(result["warnings"])


def test_missing_archive_recovery_never_creates_files(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(FileNotFoundError):
        recover_trial(missing)
    assert not missing.exists()
    existing = tmp_path / "empty"
    existing.mkdir()
    with pytest.raises(FileNotFoundError):
        recover_trial(existing)
    assert not list(existing.iterdir())


def test_readonly_recovery_missing_snapshot_metadata_preserves_facts(tmp_path):
    frozen = manifest(tmp_path)
    directory = tmp_path / "trial"
    original = asyncio.run(execute_trial(frozen, frozen["variants"][0], directory, CONFIG, worker_factory=OfflineWorker))
    (directory / "snapshots" / original["snapshot"]["id"] / "index.json").unlink()
    result = recover_trial(directory)
    assert result["run"] == original["run"]
    assert result["usage"] == original["usage"]
    assert result["read_coverage"] is None
    assert any(item["code"] == "snapshot_index_unavailable" for item in result["warnings"])


def test_live_stats_only_consumes_new_events_and_preserves_unknown_usage():
    stats = LiveStats({"files": [{"path": "a.php", "line_count": 5}]})
    first = {"id": 10, "kind": "model_response", "created_at": "first", "payload": {
        "input_tokens": 10, "output_tokens": 4, "token_usage_complete": True,
    }}
    stats.consume([first])
    assert stats.usage({"usage": {"requests": 1}})["total_tokens"] == 14
    stats.consume([first, {"id": 11, "kind": "agent_phase", "created_at": "second", "payload": {"phase": "planner"}}])
    assert stats.usage({"usage": {"requests": 2}})["total_tokens"] is None
    assert stats.usage({"usage": {"requests": 2}})["known_total_tokens"] == 14
    stats.consume([{"id": 12, "kind": "model_response", "payload": {
        "input_tokens": 8, "output_tokens": 2, "token_usage_complete": True,
    }}])
    assert stats.usage({"usage": {"requests": 2}})["total_tokens"] == 24
    assert stats.last_event_id == 12 and stats.last_event_at == "second" and stats.phase == "planner"


def test_heartbeat_continues_during_silent_worker_and_progress_failure_is_optional(tmp_path):
    frozen = manifest(tmp_path)
    records = []

    class SilentWorker(AuditWorker):
        async def _execute_body(self, run):
            add_real_finding(self, run)
            self.bus.emit(run["id"], None, "agent_phase", {"phase": "planner_waiting"})
            await asyncio.sleep(2.1)
            self.store.terminate_execution(run["id"], "inconclusive", {"code": "fixture"})

    def callback(item):
        records.append(item)
        if item["kind"] == "phase":
            raise RuntimeError("UI consumer unavailable")

    result = asyncio.run(execute_trial(frozen, frozen["variants"][0], tmp_path / "trial", CONFIG, callback, SilentWorker))
    beats = [item for item in records if item["kind"] == "heartbeat"]
    assert len(beats) >= 2
    assert beats[-1]["audit_elapsed_seconds"] >= 2
    assert beats[-1]["finding_count"] == 1
    assert beats[-1]["usage"]["total_tokens"] == 18
    assert beats[-1]["last_event_id"] > 0 and beats[-1]["last_event_at"]
    assert beats[-1]["heartbeat_at"]
    assert result["run"] and len(result["findings"]) == 1 and result["infra_error"] is None
    assert CONFIG.api_key not in json.dumps(records)
    assert any(item["code"] == "progress_unavailable" for item in result["warnings"])



def test_incorrect_complete_flag_without_token_counts_cannot_manufacture_zero_tokens():
    value = _usage({"usage": {"requests": 1}}, [{"kind": "model_response", "payload": {"token_usage_complete": True}}])
    assert value["total_tokens"] is None
    assert value["token_usage_complete"] is False



def test_production_budget_monitor_preserves_findings_and_fences_late_write(tmp_path):
    from audit.runtime import StopAudit
    frozen = manifest(tmp_path)
    observed = []

    class BudgetWorker(AuditWorker):
        async def _execute_body(self, run):
            finding = add_real_finding(self, run)
            # Advance only the durable claim clock; no real 30-second wait/model.
            self.store._active_clocks[run["id"]] -= 31
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                with pytest.raises(StopAudit):
                    self.store.add_finding({**finding, "id": "late", "fingerprint": "late"})
                observed.append("fenced")
                raise

    result = asyncio.run(execute_trial(frozen, frozen["variants"][0], tmp_path / "trial", CONFIG, worker_factory=BudgetWorker))
    assert result["cancelled"] is False
    assert result["run"]["status"] == "inconclusive"
    assert result["stop_reason"]["code"] == "run_budget_exhausted"
    assert result["stop_reason"]["dimension"] == "seconds"
    assert len(result["findings"]) == 1 and result["usage"]["total_tokens"] == 18
    assert observed == ["fenced"]
