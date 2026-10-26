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
from datetime import datetime, timezone
import signal
import tempfile
import time
from types import SimpleNamespace

from .config import ModelConfig, PocSettings, Settings
from .comparison_results import (LiveStats, _all_events, _usage, _read_coverage,
                                 _infrastructure_failure, audit_elapsed_seconds, collect_trial, recover_trial)
from .execution_state import comparison_deadline
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
    deadline_monotonic: float | None = None,
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
    heartbeat_task = None
    facts = None
    warnings = []

    def progress(payload):
        if on_progress is None:
            return
        try:
            on_progress(payload)
        except Exception as exc:
            warnings.append({"code": "progress_unavailable", "message": type(exc).__name__})

    async def heartbeat(stats):
        while True:
            try:
                current = store.get_run(run["id"])
                stats.refresh(store, run["id"])
                count = store._row("SELECT COUNT(*) AS n FROM findings WHERE run_id=?", (run["id"],))
                coverage = None
                try:
                    coverage = stats.coverage()
                except Exception as exc:
                    warnings.append({"code": "read_coverage_unavailable", "message": type(exc).__name__})
                progress({
                    "kind": "heartbeat", "run_id": run["id"],
                    "phase": stats.phase or ((current or {}).get("execution_summary") or {}).get("phase"),
                    "usage": stats.usage(current), "finding_count": int(count["n"]),
                    "read_coverage": coverage, "audit_started_at": (current or {}).get("started_at"),
                    "audit_elapsed_seconds": audit_elapsed_seconds(current),
                    "last_event_id": stats.last_event_id, "last_event_at": stats.last_event_at,
                    "heartbeat_at": datetime.now(timezone.utc).isoformat(),
                })
            except Exception as exc:
                warnings.append({"code": "heartbeat_unavailable", "message": type(exc).__name__})
            await asyncio.sleep(2)
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
        health = ModelHealth()
        snapshot = repository.import_zip(content, str(manifest.get("source_name") or source.name))
        stats = LiveStats(snapshot)
        bus = _ProgressBus(store, progress)
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
        progress({"kind": "run_created", "run_id": run["id"], "snapshot_id": snapshot["id"]})
        claimed = store.claim_next_run()
        if claimed is None or claimed["id"] != run["id"]:
            raise RuntimeError("Isolated trial could not claim its newly created audit")
        run = claimed
        progress({"kind": "audit_started", "run_id": run["id"],
                  "audit_started_at": run["started_at"], "audit_elapsed_seconds": 0.0})
        heartbeat_task = asyncio.create_task(heartbeat(stats))
        with comparison_deadline(deadline_monotonic):
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
        if heartbeat_task is not None:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass
        if store is not None:
            try:
                if run is not None:
                    facts = collect_trial(store, run["id"], snapshot)
            finally:
                store.close()
    facts = facts or {
        "run": run, "findings": [], "snapshot": None, "usage": {}, "read_coverage": None,
        "stop_reason": {"code": "cancelled" if cancelled else "setup_failed"},
        "warnings": [], "audit_started_at": None, "audit_elapsed_seconds": 0.0,
    }
    facts["warnings"].extend(warnings)
    facts.update({"duration_seconds": round(time.monotonic() - started, 3),
                  "cancelled": cancelled,
                  "infra_error": infra_error or facts.get("infra_error")})
    return facts


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
                deadline_monotonic=args.deadline_monotonic,
            )
        finally:
            for signum in installed:
                loop.remove_signal_handler(signum)
    except Exception as exc:
        try:
            result = recover_trial(Path(args.data_dir))
        except Exception:
            result = {"run": None, "findings": [], "warnings": []}
        result["infra_error"] = {
            "code": "trial_setup_error" if result.get("run") is None else "trial_process_error",
            "message": config.redact(f"{type(exc).__name__}: {exc}")[:800],
        }
    _atomic_json(Path(args.output), result)
    return 1 if result.get("infra_error") else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--prompt-id", required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--deadline-monotonic", type=float, default=None)
    return asyncio.run(_main(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
