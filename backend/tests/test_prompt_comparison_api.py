"""HTTP contracts for strategy libraries and scoped full-audit experiment artefacts."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from audit import app as app_module
from audit.config import ModelConfig, Settings
from audit.db import Store, now
from audit.prompt_experiments import ExperimentError, ExperimentRunner
from audit.worker_strategies import builtin_worker_strategies


class FakeFull:
    def __init__(self):
        self.calls = []
        self.fail_retry = False

    def trial_detail(self, *args):
        self.calls.append(("detail", args))
        if args[1] == "missing":
            raise LookupError(args[1])
        return {"trial": {"id": args[1]}, "run": None, "findings": []}

    def source(self, *args):
        self.calls.append(("source", args))
        return {"path": args[2], "lines": [{"number": args[3], "text": "source"}]}

    def events(self, *args):
        self.calls.append(("events", args))
        return {"events": [], "remaining": 0}

    def trial_report(self, *args):
        self.calls.append(("trial_report", args))
        return b"{}", "application/json", "trial.json"

    def report(self, *args):
        self.calls.append(("report", args))
        return b"report", "application/zip" if args[1] == "csv" else "text/markdown", "report.zip" if args[1] == "csv" else "report.md"

    def retry(self, *args):
        self.calls.append(("retry", args))
        if self.fail_retry:
            raise ExperimentError("不能替换有效低分结果")
        return {"id": args[0], "protocol": "lab30-full-v2", "status": "running", "trials": []}


class FakeExperiments:
    def __init__(self):
        self.full = FakeFull()
        self.calls = []

    def start_full(self, payload):
        self.calls.append(("full", payload.model_dump()))
        return {"id": "created", "protocol": payload.protocol, "status": "running"}

    def start(self, *args):
        self.calls.append(("legacy", args))
        return {"id": "legacy", "protocol": "legacy_unit_v1", "status": "running"}

    def get(self, ident):
        return {"id": ident, "protocol": "legacy_unit_v1" if ident == "legacy" else "lab30-full-v2", "status": "running"}

    async def cancel(self, ident):
        return {"id": ident, "protocol": "lab30-full-v2", "status": "cancelled", "trials": []}


@pytest.fixture
def api(tmp_path, monkeypatch):
    store = Store(tmp_path / "audit.db")
    for prompt in builtin_worker_strategies():
        store.upsert_builtin_prompt(prompt)
    store.add_prompt({"id": "legacy", "label": "历史全文", "text": "旧版指令", "created_at": now()})
    state = SimpleNamespace(store=store, prompt_experiments=FakeExperiments())
    monkeypatch.setattr(app_module.app.state, "services", state, raising=False)
    client = TestClient(app_module.app)
    yield client, state
    client.close()
    store.close()


def test_startup_retains_three_original_strategies_and_adds_versioned_improvements(tmp_path):
    state = app_module.Services(Settings(data_dir=tmp_path, model=ModelConfig()))
    try:
        prompts = state.store.list_prompts()
        strategies = [item for item in prompts if item["kind"] == "worker_strategy"]
        assert {item["id"] for item in strategies} == {"worker-w0-v1", "worker-w1-v1", "worker-w2-v1", "worker-w1-v2", "worker-w2-v2"}
        assert all(item["contract_version"] == "worker-strategy-v1" and item["builtin"] for item in strategies)
        assert any(item["id"] == "P0" for item in prompts)
    finally:
        state.store.close()


def test_strategy_create_filter_and_derivation_contract(api):
    client, _ = api
    listed = client.get("/api/prompts?kind=worker_strategy")
    assert listed.status_code == 200 and len(listed.json()) == 5
    assert client.get("/api/prompts?kind=legacy").json()[0]["id"] == "legacy"
    assert client.get("/api/prompts?kind=unrecognized").status_code == 400
    created = client.post("/api/prompts", json={"label": "自定义策略", "text": "核对已有防护的适用范围。",
                                                   "kind": "worker_strategy", "parent_id": "worker-w1-v1"})
    assert created.status_code == 200
    assert created.json()["kind"] == "worker_strategy"
    assert created.json()["contract_version"] == "worker-strategy-v1"
    assert created.json()["parent_id"] == "worker-w1-v1"
    legacy = client.post("/api/prompts", json={"label": "仍支持旧版", "text": "旧版正文"})
    assert legacy.status_code == 200 and legacy.json()["kind"] == "legacy"


@pytest.mark.parametrize("changes, status", [
    ({"parent_id": "missing"}, 404), ({"parent_id": "legacy"}, 400),
    ({"contract_version": "worker-strategy-v999"}, 400), ({"text": " "}, 400),
    ({"kind": "legacy", "contract_version": "worker-strategy-v1"}, 400),
])
def test_strategy_creation_rejects_cross_protocol_or_invalid_parent(api, changes, status):
    client, _ = api
    response = client.post("/api/prompts", json={"label": "策略", "text": "审计策略正文", "kind": "worker_strategy", **changes})
    assert response.status_code == status


def test_full_and_legacy_creation_dispatch_are_both_supported(api):
    client, state = api
    response = client.post("/api/prompt-experiments", json={"protocol": "lab30-full-v2",
        "prompt_ids": ["worker-w0-v1", "worker-w1-v1"], "baseline_prompt_id": "worker-w0-v1", "repeats": 3})
    assert response.status_code == 201
    assert state.prompt_experiments.calls[-1][0] == "full"
    assert response.json()["protocol"] == "lab30-full-v2"
    legacy = client.post("/api/prompt-experiments", json={"variants": ["P0-basic", "P1-evidence"], "units_limit": 2})
    assert legacy.status_code == 201 and state.prompt_experiments.calls[-1][0] == "legacy"
    invalid = client.post("/api/prompt-experiments", json={"protocol": "lab30-full-v2",
        "prompt_ids": ["worker-w0-v1", "worker-w1-v1"], "baseline_prompt_id": "worker-w0-v1", "units_limit": 2})
    assert invalid.status_code == 422


def test_experiment_referenced_strategy_is_readonly_and_usage_is_public(api):
    client, state = api
    prompt = client.post("/api/prompts", json={"label": "待引用策略", "text": "核查读过的源码风险。", "kind": "worker_strategy"}).json()
    state.store.add_full_prompt_experiment({"id": "e" * 16, "created_at": now(), "status": "completed",
        "variants": [prompt["id"]], "manifest": {"variants": [prompt]}, "trials": []})
    listed = client.get("/api/prompts?kind=worker_strategy").json()
    referenced = next(item for item in listed if item["id"] == prompt["id"])
    assert referenced["used_by_runs"] == 0 and referenced["used_by_experiments"] == 1
    edited = client.put(f"/api/prompts/{prompt['id']}", json={"label": "改写", "text": "不同正文"})
    assert edited.status_code == 409
    assert client.delete(f"/api/prompts/{prompt['id']}").status_code == 409
    assert state.store.get_prompt(prompt["id"])["text"] == prompt["text"]


def test_scoped_trial_routes_match_frontend_query_and_preserve_attempt(api):
    client, state = api
    prefix = "/api/prompt-experiments/experiment/trials/trial"
    assert client.get(prefix + "?attempt=1").status_code == 200
    assert state.prompt_experiments.full.calls[-1] == ("detail", ("experiment", "trial", 1))
    assert client.get(prefix + "/source?path=src/a.php&start_line=8&end_line=15&attempt=2").status_code == 200
    assert state.prompt_experiments.full.calls[-1] == ("source", ("experiment", "trial", "src/a.php", 8, 15, 2))
    assert client.get(prefix + "/events?after=7&limit=50&attempt=1").json() == {"events": [], "remaining": 0}
    assert state.prompt_experiments.full.calls[-1] == ("events", ("experiment", "trial", 7, 50, 1))
    report = client.get(prefix + "/report?format=json&attempt=1")
    assert report.status_code == 200 and "attachment" in report.headers["content-disposition"]
    assert state.prompt_experiments.full.calls[-1] == ("trial_report", ("experiment", "trial", "json", 1))
    assert client.get(prefix + "/source?path=src/a.php&start_line=8&end_line=7").status_code == 400
    assert client.get(prefix + "/events?limit=501").status_code == 422
    assert client.get(prefix + "?attempt=3").status_code == 422
    assert client.get(prefix + "/report?format=zip").status_code == 400
    assert client.get("/api/prompt-experiments/experiment/trials/missing").status_code == 404


def test_retry_cancel_and_partial_full_report_return_complete_experiment(api):
    client, state = api
    retried = client.post("/api/prompt-experiments/experiment/trials/trial/retry")
    assert retried.status_code == 200 and retried.json()["id"] == "experiment" and "trials" in retried.json()
    cancelled = client.post("/api/prompt-experiments/experiment/cancel")
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled" and "trials" in cancelled.json()
    report = client.get("/api/prompt-experiments/experiment/report?format=csv")
    assert report.status_code == 200 and report.headers["content-type"] == "application/zip"
    assert state.prompt_experiments.full.calls[-1] == ("report", ("experiment", "csv"))
    assert client.get("/api/prompt-experiments/legacy/report?format=markdown").status_code == 409
    state.prompt_experiments.full.fail_retry = True
    assert client.post("/api/prompt-experiments/experiment/trials/trial/retry").status_code == 409


def test_actual_trial_source_events_and_report_read_only_isolated_database(tmp_path, monkeypatch):
    from audit.comparison_trial import execute_trial
    from tests.test_comparison_trial import CONFIG, OfflineWorker, manifest

    frozen = manifest(tmp_path)
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    store = Store(data_dir / "audit.db")
    settings = Settings(data_dir=data_dir, model=CONFIG)
    experiments = ExperimentRunner(store, settings)
    ident, trial_id = "a" * 16, "b" * 16
    work = data_dir / "prompt-experiments" / ident / "trials" / trial_id / "attempt-1"
    result = asyncio.run(execute_trial(frozen, frozen["variants"][0], work, CONFIG, worker_factory=OfflineWorker))
    assert not result["infra_error"], result
    store.add_full_prompt_experiment({"id": ident, "created_at": now(), "status": "completed",
        "variants": [item["id"] for item in frozen["variants"]], "manifest": frozen,
        "trials": [{"id": trial_id, "round_index": 1, "prompt_id": frozen["variants"][0]["id"],
                    "status": "completed", "evaluation_status": "valid", "attempts": [{"id": "attempt", "attempt_no": 1,
                    "run_id": result["run"]["id"], "score": None, "read_coverage": result["read_coverage"]}]}]})
    state = SimpleNamespace(store=store, settings=settings, prompt_experiments=experiments)
    monkeypatch.setattr(app_module.app.state, "services", state, raising=False)
    client = TestClient(app_module.app)
    try:
        prefix = f"/api/prompt-experiments/{ident}/trials/{trial_id}"
        detail = client.get(prefix)
        assert detail.status_code == 200, detail.text
        assert detail.json()["run"]["id"] == result["run"]["id"]
        source = client.get(prefix + "/source?path=src/a.php&start_line=2&end_line=3")
        assert source.status_code == 200 and source.json()["lines"][0]["number"] == 2
        events = client.get(prefix + "/events?limit=1")
        assert events.status_code == 200 and len(events.json()["events"]) == 1
        assert client.get(prefix + "/report?format=json").status_code == 200
        markdown = client.get(prefix + "/report?format=markdown")
        assert markdown.status_code == 200, markdown.text
        assert client.get(f"/api/runs/{result['run']['id']}").status_code == 404
        (work / "audit.db").unlink()
        assert client.get(prefix).status_code == 404
        assert not (work / "audit.db").exists()
    finally:
        client.close()
        store.close()
