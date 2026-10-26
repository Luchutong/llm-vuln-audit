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
    assert all(set(item) <= {"kind", "event", "run_id", "snapshot_id", "phase", "role", "task_id"} for item in records)
    assert CONFIG.api_key not in json.dumps([records, outcomes])


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
