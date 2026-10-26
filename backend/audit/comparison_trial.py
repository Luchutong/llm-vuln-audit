"""One isolated full-project Prompt trial, using the production audit coordinator.

The parent freezes public configuration and passes credentials via LLM_* environment
variables.  This module does not load .env, construct Services, seed a library, or read
benchmark truth.  Its database is never shared with another trial.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import signal
import tempfile
import time
from types import SimpleNamespace

from .config import ModelConfig, PocSettings, Settings
from .db import Store
from .events import EventBus
from .health import ModelHealth
from .projects import ensure_project
from .schemas import CreateRunRequest
from .source import SourceRepository
from .worker import AuditWorker
from .worker_strategies import freeze_worker_strategy


class _ProgressBus(EventBus):
    def __init__(self, store, callback):
        super().__init__(store)
        self.callback = callback

    def emit(self, run_id, unit_id, kind, payload):
        event = super().emit(run_id, unit_id, kind, payload)
        if self.callback is not None and kind in {
            "agent_phase", "planner_round_started", "planner_worker_started",
            "worker_strategy_bound", "run_completed", "run_failed", "goal_inconclusive",
        }:
            # Only public routing/phase metadata crosses stdout; never source or model
            # outputs, arguments, credentials, or private reasoning.
            self.callback({
                "kind": "phase", "event": kind, "run_id": run_id,
                "phase": payload.get("phase") or kind,
                "role": payload.get("role"), "task_id": payload.get("task_id"),
            })
        return event


def _all_events(store: Store, run_id: str) -> list[dict]:
    events = []
    after = 0
    while batch := store.list_events(run_id, after=after, limit=1000):
        events.extend(batch)
        after = batch[-1]["id"]
    return events


def _usage(run: dict | None, events: list[dict]) -> dict:
    actual = (run or {}).get("usage") or {}
    requests = int(actual.get("requests") or 0)
    responses = [item.get("payload") or {} for item in events if item.get("kind") == "model_response"]
    known_input = sum(item["input_tokens"] for item in responses if type(item.get("input_tokens")) is int)
    known_output = sum(item["output_tokens"] for item in responses if type(item.get("output_tokens")) is int)
    complete = len(responses) == requests and all(item.get("token_usage_complete") is True for item in responses)
    return {
        "requests": requests, "tool_calls": int(actual.get("tool_calls") or 0),
        "input_tokens": known_input if complete else None,
        "output_tokens": known_output if complete else None,
        "total_tokens": known_input + known_output if complete else None,
        "known_input_tokens": known_input, "known_output_tokens": known_output,
        "known_total_tokens": known_input + known_output,
        "token_usage_complete": complete,
    }


def _infrastructure_failure(run: dict | None, events: list[dict]) -> dict | None:
    """Only explicit terminal provider outages invalidate a trial, not poor output."""
    if not run or run.get("status") not in {"failed", "inconclusive"}:
        return None
    reason = (run.get("execution_summary") or {}).get("stop_reason") or {}
    if reason.get("code") == "run_budget_exhausted":
        return None
    terminals = [event.get("payload") or {} for event in events
                 if event.get("kind") in {"task_agent_terminal", "planner_agent_terminal"}]
    # Two failed Planner decisions can settle as inconclusive before the passive
    # breaker trips.  Inspect the latest terminal, not the latest error: a later
    # successful/rejected/budget-ended pass must not be erased by an earlier outage.
    if not terminals or terminals[-1].get("reason") != "model_error":
        return None
    last = terminals[-1]
    status = last.get("status")
    provider_type = last.get("provider_error_type")
    if (type(status) is int and (status in {401, 402, 403, 404, 429} or 500 <= status < 600)) or provider_type in {
        "APIConnectionError", "ConnectError", "ConnectTimeout",
    }:
        return {"code": "model_unavailable", "status": status,
                "provider_error_type": provider_type,
                "message": str(last.get("error") or "Frozen model endpoint unavailable")[:600]}
    return None


def _read_coverage(snapshot: dict | None, events: list[dict]) -> dict:
    files = {item["path"]: item["line_count"] for item in (snapshot or {}).get("files") or []
             if item.get("kind", "text") == "text"}
    intervals: set[tuple[str, int, int]] = set()
    for event in events:
        payload = event.get("payload") or {}
        for ref in [*(payload.get("seen") or []), *((payload.get("evidence") or {}).get("reviewed_ranges") or [])]:
            if not isinstance(ref, dict):
                continue
            path, start, end = ref.get("path"), ref.get("start_line"), ref.get("end_line")
            if path in files and type(start) is int and type(end) is int and 1 <= start <= end <= files[path]:
                intervals.add((path, start, end))
    merged = []
    for path, start, end in sorted(intervals):
        if merged and merged[-1][0] == path and start <= merged[-1][2] + 1:
            merged[-1] = (path, merged[-1][1], max(merged[-1][2], end))
        else:
            merged.append((path, start, end))
    read_lines = sum(end - start + 1 for _, start, end in merged)
    read_files = len({path for path, _, _ in merged})
    total_lines = sum(files.values())
    return {"read_files": read_files, "total_files": len(files), "read_lines": read_lines,
            "total_lines": total_lines, "file_ratio": read_files / len(files) if files else None,
            "line_ratio": read_lines / total_lines if total_lines else None}


def _source_path(manifest: dict) -> Path:
    root = Path(manifest.get("_root") or ".").resolve()
    relative = (manifest.get("files") or {}).get("source")
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("Frozen source must be a manifest-relative file")
    source = (root / relative).resolve()
    if not source.is_relative_to(root):
        raise ValueError("Frozen source escapes experiment directory")
    return source


async def execute_trial(
    manifest: dict,
    variant: dict,
    data_dir: Path,
    config: ModelConfig,
    on_progress=None,
    worker_factory=AuditWorker,
) -> dict:
    """Execute one fresh trial and always return its actual durable terminal state."""
    from .app import create_audit_run

    started = time.monotonic()
    store = None
    run = None
    snapshot = None
    worker = None
    infra_error = None
    cancelled = False
    events = []
    findings = []
    try:
        text_hash = hashlib.sha256(str(variant.get("text") or "").encode()).hexdigest()
        for key in ("sha256", "text_sha256"):
            if key in variant and variant[key] != text_hash:
                raise ValueError(f"Frozen strategy {key} does not match its text")
        strategy = freeze_worker_strategy(variant)
        source = _source_path(manifest)
        content = source.read_bytes()
        expected_hash = str(manifest.get("source_sha256") or "")
        if not expected_hash or hashlib.sha256(content).hexdigest() != expected_hash:
            raise ValueError("Frozen source SHA-256 does not match manifest")
        model = manifest.get("model") or {}
        if isinstance(model, dict):
            if model.get("model") and model["model"] != config.model:
                raise ValueError("Frozen model differs from trial credentials")
            if model.get("base_url") and model["base_url"] != config.public_base_url():
                raise ValueError("Frozen endpoint differs from trial credentials")
            if model.get("thinking") and model["thinking"] != config.thinking:
                raise ValueError("Frozen thinking setting differs from trial configuration")
        if not config.configured:
            raise ValueError("Frozen model credentials are unavailable")
        trial_data = Path(data_dir).resolve()
        trial_data.mkdir(parents=True, exist_ok=True)
        if (trial_data / "audit.db").exists():
            raise ValueError("Trial data directory already contains a database; use a new attempt")
        settings = Settings(data_dir=trial_data, model=config, poc=PocSettings(enabled=False, browser=False))
        store = Store(settings.db_path)
        repository = SourceRepository(trial_data)
        bus = _ProgressBus(store, on_progress)
        health = ModelHealth()
        snapshot = repository.import_zip(content, str(manifest.get("source_name") or source.name))
        store.add_snapshot(snapshot)
        ensure_project(store, snapshot)
        frozen_policy = manifest.get("agent_policy")
        # The creation helper freezes the same production policy by default. The
        # parent records its exact value in the manifest; reject incompatible builds.
        if frozen_policy:
            from .runtime import AgentPolicy
            if frozen_policy != AgentPolicy().snapshot():
                raise ValueError("Frozen host AgentPolicy differs from this executor build")
        worker = worker_factory(
            settings=settings, store=store, repository=repository, bus=bus, health=health,
            resolve_model_profile=lambda _snapshot: config,
        )
        # No background _loop is started: it would reclaim/recover this new trial.
        # The shared run creator may notify, but only this function claims its run.
        worker.notify = lambda: None
        state = SimpleNamespace(settings=settings, store=store, repository=repository, bus=bus, health=health, worker=worker)
        request = CreateRunRequest(
            snapshot_id=snapshot["id"], task=manifest["task_spec"],
            budgets=manifest["budgets"], run_limits=manifest["run_limits"], poc_mode="off",
        )
        if request.task.stop_on_achieved or request.task.max_workers != 1 or request.task.scenario is not None or request.task.require_poc:
            raise ValueError("Full comparison requires one worker, full scope, no early stop and no required POC")
        run = await create_audit_run(state, request, worker_strategy=strategy)
        if on_progress is not None:
            on_progress({"kind": "run_created", "run_id": run["id"], "snapshot_id": snapshot["id"]})
        claimed = store.claim_next_run()
        if claimed is None or claimed["id"] != run["id"]:
            raise RuntimeError("Isolated trial could not claim its newly created audit")
        run = claimed
        await worker._execute(claimed)
    except asyncio.CancelledError:
        cancelled = True
        if store is not None and run is not None:
            current = store.get_run(run["id"])
            if current and current.get("status") in {"pending", "running", "paused"}:
                store.terminate_execution(run["id"], "cancelled", {"code": "user_cancelled", "message": "Prompt trial cancelled"})
    except Exception as exc:
        infra_error = {"code": "trial_setup_error" if run is None else "trial_process_error",
                       "message": config.redact(f"{type(exc).__name__}: {exc}")[:800]}
        if store is not None and run is not None:
            current = store.get_run(run["id"])
            if current and current.get("status") in {"pending", "running", "paused"}:
                store.terminate_execution(run["id"], "failed", {"code": "worker_exit_without_terminal", "message": infra_error["message"]})
    finally:
        if store is not None:
            try:
                if run is not None:
                    run = store.get_run(run["id"]) or run
                    findings = store.list_findings(run["id"])
                    events = _all_events(store, run["id"])
            finally:
                store.close()
    summary = (run or {}).get("execution_summary") or {}
    stop_reason = summary.get("stop_reason") or {"code": "cancelled" if cancelled else (run or {}).get("status", "setup_failed")}
    return {
        "run": run, "findings": findings,
        "snapshot": {key: snapshot.get(key) for key in ("id", "name", "archive_sha256", "content_key", "project_id")} if snapshot else None,
        "usage": _usage(run, events), "duration_seconds": round(time.monotonic() - started, 3),
        "read_coverage": _read_coverage(snapshot, events),
        "stop_reason": stop_reason, "cancelled": cancelled,
        "infra_error": infra_error or _infrastructure_failure(run, events),
    }


def _atomic_json(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=".trial-", encoding="utf-8", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


async def _main(args) -> int:
    manifest_path = Path(args.manifest).resolve()
    config = ModelConfig.from_environ(dict(os.environ))
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["_root"] = str(manifest_path.parent)
        variant = next(item for item in manifest["variants"] if item["id"] == args.prompt_id)
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        installed = []
        for signum in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(signum, task.cancel)
                installed.append(signum)
            except (NotImplementedError, RuntimeError):
                pass
        try:
            result = await execute_trial(
                manifest, variant, Path(args.data_dir), config,
                on_progress=lambda item: print(json.dumps(item, ensure_ascii=False), flush=True),
            )
        finally:
            for signum in installed:
                loop.remove_signal_handler(signum)
    except Exception as exc:
        result = {"run": None, "findings": [], "infra_error": {
            "code": "trial_setup_error", "message": config.redact(f"{type(exc).__name__}: {exc}")[:800],
        }}
    _atomic_json(Path(args.output), result)
    return 1 if result.get("infra_error") else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--prompt-id", required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--output", required=True)
    return asyncio.run(_main(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
