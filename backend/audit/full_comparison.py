"""Persisted, isolated full-audit comparisons. Only an explicit start/retry spends tokens."""
from __future__ import annotations

import asyncio
import contextlib
import csv
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from .config import DEFAULT_BUDGETS, clamp_budgets
from .db import Store, now
from .prompt_evaluation import (DEFAULT_ANCHORS_PATH, DEFAULT_TRUTH_PATH,
                                evaluate_v2, summarise_trials, validate_assets)
from .prompt_experiments import ExperimentError, SOURCE_ZIP
from .worker_strategies import worker_host_contract, freeze_worker_strategy
from .runtime import AgentPolicy

PROTOCOL = "lab30-full-v2"
ROOT = Path(__file__).resolve().parents[2]
ACTIVE = {"preparing", "running", "cancelling"}
TIME_POLICY = "fixed-time-v1"
EXPERIMENT_SECONDS = 7200
TRIAL_SECONDS = 720
SLOT_OVERHEAD_SECONDS = 60
SHARED_OVERHEAD_SECONDS = 180
CLEANUP_SECONDS = 15
OBJECTIVE = "在规定时间内对完整源码尽可能发现有源码证据支持的可操作漏洞，合理安排审计优先级，不要找到第一处就停止。逐项提供根因、原始源码证据、影响与触发条件，并记录尚未覆盖的方向；不要求在时间窗口内穷尽源码。"


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _public(value):
    if isinstance(value, dict):
        return {k: _public(v) for k, v in value.items()
                if not k.startswith("_") and k not in {"log_path", "report_path"}}
    if isinstance(value, list):
        return [_public(v) for v in value]
    return value


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _batch_kind(manifest, attempt):
    if attempt.get("batch_kind") in {"initial", "retry"}:
        return attempt["batch_kind"]
    return "unknown" if manifest.get("time_policy", {}).get("version") == TIME_POLICY else "legacy"


def classify_result(result: dict, returncode: int) -> tuple[str, str]:
    """Budget/model-output failures are observations, not conveniently discarded trials."""
    if returncode or result.get("infra_error"):
        return "invalid", str(result.get("infra_error") or f"child_exit_{returncode}")
    run = result.get("run") or {}
    if not isinstance(run, dict) or not run.get("id") or run.get("status") not in {
        "completed", "inconclusive", "unreachable", "failed", "cancelled", "interrupted", "pending", "running", "paused",
    }:
        return "invalid", "missing_terminal_result"
    reason = result.get("stop_reason") or (run.get("execution_summary") or {}).get("stop_reason") or {}
    if run.get("status") in {"cancelled", "interrupted", "pending", "running", "paused"}:
        return "invalid", str(reason.get("code") or run.get("status"))
    # Provider failures arrive as structured infra_error from the child. Neither
    # model prose nor an ambiguous timeout proves an infrastructure outage.
    if reason.get("code") in {"batch_deadline_exceeded", "experiment_deadline_exceeded", "trial_lifecycle_timeout", "planner_context_error"}:
        return "invalid", reason["code"]
    if reason.get("code") == "worker_exit_without_terminal":
        return "invalid", "executor_error"
    return "valid", str(reason.get("code") or run.get("status") or "finished")


class FullComparisonRunner:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings
        self._task = None
        self._process = None
        self._closed = False
        self._model = {}
        self._clock = time.monotonic
        self._batch_clocks = {}
        self._archive_cache = {}

    def _new_batch(self, kind, trial_ids, seconds, *, started=None, started_at=None):
        started = self._clock() if started is None else started
        started_at = started_at or now()
        batch = {"id": uuid_hex(), "kind": kind, "trial_ids": trial_ids,
            "started_at": started_at, "deadline_at": (datetime.fromisoformat(started_at) + timedelta(seconds=seconds)).isoformat(),
            "wall_seconds": seconds, "status": "running", "finished_at": None}
        self._batch_clocks[batch["id"]] = (started, started + seconds)
        return batch

    def _batch_remaining(self, batch):
        if batch["id"] in self._batch_clocks:
            return self._batch_clocks[batch["id"]][1] - self._clock()
        return (datetime.fromisoformat(batch["deadline_at"]) - datetime.now(timezone.utc)).total_seconds()

    def _timing_projection(self, progress):
        timing = copy.deepcopy(progress.get("timing") or {})
        for batch in timing.get("batches") or []:
            if batch.get("finished_at"):
                elapsed = max(0, (datetime.fromisoformat(batch["finished_at"]) - datetime.fromisoformat(batch["started_at"])).total_seconds())
            else:
                elapsed = max(0, batch["wall_seconds"] - self._batch_remaining(batch))
            batch.update(elapsed_seconds=round(elapsed, 3), remaining_seconds=round(max(0, batch["wall_seconds"] - elapsed), 3))
        initial = next((b for b in timing.get("batches", []) if b["kind"] == "initial"), None)
        if initial:
            timing["initial_batch"] = copy.deepcopy(initial)
        return timing

    def _progress(self, ident, **fields):
        row = self._record(ident)
        self.store.update_prompt_experiment(ident, progress={**row.get("progress", {}), **fields})

    def _finish_batch(self, ident, batch_id, status, reason=None):
        row = self._record(ident)
        timing = row.get("progress", {}).get("timing") or {}
        for batch in timing.get("batches", []):
            if batch["id"] == batch_id and not batch.get("finished_at"):
                elapsed = max(0, batch["wall_seconds"] - self._batch_remaining(batch))
                batch.update(status=status, finished_at=(datetime.fromisoformat(batch["started_at"]) + timedelta(seconds=elapsed)).isoformat(), stop_reason=reason)
        timing["active_batch_id"] = None
        self._progress(ident, timing=timing)

    def _directory(self, ident: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{16}", ident):
            raise LookupError(ident)
        base = (Path(self.settings.data_dir) / "prompt-experiments").resolve()
        target = (base / ident).resolve()
        if not target.is_relative_to(base):
            raise LookupError(ident)
        return target

    def _record(self, ident: str) -> dict:
        row = self.store.get_prompt_experiment(ident)
        if row is None or row.get("protocol") != PROTOCOL:
            raise LookupError(ident)
        return row

    def get(self, ident: str) -> dict:
        row = self._record(ident)
        for trial in row["trials"]:
            for attempt in trial.get("attempts") or []:
                self._hydrate_attempt(ident, trial, attempt)
            if trial.get("attempts"):
                for key in ("usage", "read_coverage", "audit_elapsed_seconds", "wall_elapsed_seconds", "audit_started_at", "warnings"):
                    if key in trial["attempts"][-1]:
                        trial[key] = trial["attempts"][-1][key]
            trial["can_retry"], trial["retry_reason"] = self._retry_eligibility(row, trial)
        if row.get("manifest"):
            row["summary"] = self._summary(row["manifest"], row["trials"], self._directory(ident))
        row["progress"]["timing"] = self._timing_projection(row["progress"])
        return _public(row)

    def _retry_eligibility(self, row, trial):
        if row["status"] in ACTIVE:
            return False, "请先等待当前批次结束"
        if row["manifest"].get("time_policy", {}).get("version") != TIME_POLICY:
            return False, "历史预算实验只读，请创建新的限时实验"
        if trial.get("evaluation_status") not in {"invalid", "not_started"}:
            return False, "不能替换有效低分或其他有效成绩"
        if int(trial.get("retry_count", 0)) >= 1 or len(trial.get("attempts", [])) >= 2:
            return False, "每个逻辑试次只允许显式补跑一次"
        return True, ""

    def _hydrate_attempt(self, ident, trial, attempt):
        """Project durable facts without changing historical status or result files."""
        if not attempt.get("run_id"):
            return
        work = self._directory(ident) / "trials" / trial["id"] / f"attempt-{int(attempt['attempt_no'])}"
        try:
            signature = tuple((p.stat().st_mtime_ns, p.stat().st_size) if p.exists() else None
                for p in (work / "audit.db", work / "audit.db-wal", work / "snapshots"))
            key = (ident, trial["id"], attempt["attempt_no"])
            cached = self._archive_cache.get(key)
            if cached and cached[0] == signature:
                recovered = cached[1]
            else:
                from .comparison_results import recover_trial
                recovered = recover_trial(work, attempt["run_id"])
                self._archive_cache[key] = (signature, recovered)
        except (OSError, sqlite3.Error, ValueError, TypeError):
            return
        if (recovered.get("run") or {}).get("id") != attempt["run_id"]:
            attempt.setdefault("warnings", []).append({"code": "run_unavailable", "message": "隔离数据库中已不存在该运行，保留已有用量"})
            return
        for name in ("usage", "read_coverage", "audit_elapsed_seconds", "audit_started_at", "warnings"):
            if name in recovered:
                attempt[name] = recovered[name]
        if not attempt.get("stop_reason") and recovered.get("stop_reason"):
            attempt["stop_reason"] = recovered["stop_reason"]
        end = attempt.get("finished_at") or now()
        if attempt.get("created_at"):
            elapsed = max(0, (datetime.fromisoformat(end) - datetime.fromisoformat(attempt["created_at"])).total_seconds())
            attempt["wall_elapsed_seconds"] = round(elapsed, 3)
        attempt["recovered_from_archive"] = True

    def start(self, payload) -> dict:
        batch_started, batch_started_at = self._clock(), now()
        if self._closed or self.store.running_prompt_experiment() or (self._task and not self._task.done()):
            raise ExperimentError("已有实验在执行或服务正在关闭，请等待执行结束。")
        model = self.settings.model
        if not model.configured:
            raise ExperimentError("请先配置可用模型连接。")
        variants = []
        if (not 2 <= len(payload.prompt_ids) <= 5 or len(set(payload.prompt_ids)) != len(payload.prompt_ids)
                or payload.baseline_prompt_id not in payload.prompt_ids):
            raise ExperimentError("请选择二至五个不同策略及其中一个正式基线。")
        for ident in payload.prompt_ids:
            prompt = self.store.get_prompt(ident)
            if prompt is None:
                raise ExperimentError(f"策略不存在：{ident}")
            try:
                variant = freeze_worker_strategy(prompt)
            except ValueError as exc:
                raise ExperimentError(str(exc)) from exc
            variant = {key: variant.get(key) for key in (
                "id", "label", "text", "reason", "parent_id", "kind", "contract_version", "text_sha256")}
            variant["sha256"] = variant["text_sha256"]
            variants.append(variant)
        supplied = payload.budgets or {}
        if set(supplied) - set(DEFAULT_BUDGETS):
            raise ExperimentError("预算只接受 responses、tools、seconds。")
        if any(type(value) is not int for value in supplied.values()):
            raise ExperimentError("预算必须是整数。")
        audit_seconds = payload.run_limits.seconds
        if (getattr(payload, "experiment_wall_seconds", EXPERIMENT_SECONDS) != EXPERIMENT_SECONDS
                or audit_seconds > TRIAL_SECONDS
                or len(variants) * payload.repeats * (audit_seconds + SLOT_OVERHEAD_SECONDS) + SHARED_OVERHEAD_SECONDS > EXPERIMENT_SECONDS):
            raise ExperimentError("首次批次最多两小时；请缩短单次时限或减少策略与轮次。")
        source = Path(os.environ.get("LAB30_SOURCE_ZIP") or SOURCE_ZIP)
        try:
            assets = validate_assets(source)
            if (assets["truth_count"] != 30 or assets["class_count"] != 22
                    or assets["source_archive_sha256"] != "67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c"):
                raise ValueError("lab30-full-v2 固定使用正式 Lab30 ZIP、30 项真值与 22 类")
        except (ValueError, OSError, zipfile.BadZipFile) as exc:
            raise ExperimentError(f"Lab30 正式评分数据不可用：{exc}") from exc
        ident = uuid_hex()
        directory = self._directory(ident)
        frozen = directory / "frozen"
        frozen.mkdir(parents=True)
        try:
            for origin, name in ((source, "source.zip"), (DEFAULT_TRUTH_PATH, "truth.json"),
                                 (DEFAULT_ANCHORS_PATH, "anchors.json")):
                target = frozen / name
                target.write_bytes(Path(origin).read_bytes())
            # Validate the copied bytes too, closing the source-read race before execution.
            assets = validate_assets(frozen / "source.zip", frozen / "truth.json", frozen / "anchors.json")
            effective_budgets = clamp_budgets({"seconds": audit_seconds, **supplied})
            effective_budgets["seconds"] = min(effective_budgets["seconds"], audit_seconds)
            manifest = {
                "protocol": PROTOCOL, "scoring_protocol": "lab30-v2", "created_at": now(),
                "variants": variants, "baseline_prompt_id": payload.baseline_prompt_id,
                "repeats": payload.repeats, "model": {"model": model.model,
                    "base_url": model.public_base_url(), "thinking": model.thinking},
                "budgets": effective_budgets, "run_limits": payload.run_limits.model_dump(),
                "task_spec": {"objective": OBJECTIVE,
                    "success_criteria": "在宿主规定的时间内尽可能挖掘并保存有已读源码证据的漏洞，同时记录未覆盖方向；不要求穷尽，不能找到第一条就停止。",
                    "max_iterations": 3, "max_planner_rounds": 24, "max_total_attempts": 64,
                    "max_workers": 1, "stop_on_achieved": False, "require_poc": False},
                "poc_mode": "off", "assets": assets, "source_sha256": _hash(frozen / "source.zip"),
                "source_name": source.name,
                "files": {"source": "frozen/source.zip", "truth": "frozen/truth.json", "anchors": "frozen/anchors.json"},
                "host_contract_sha256": hashlib.sha256(worker_host_contract().encode()).hexdigest(),
                "host_contract": worker_host_contract(),
                "agent_policy": AgentPolicy().snapshot(),
                "generation": {"worker_max_tokens": 4096, "planner_max_tokens": AgentPolicy().planner_max_tokens,
                    "temperature": None, "top_p": None, "seed": None,
                    "sampling_note": "未显式发送的采样参数采用供应商默认，不宣称确定性复现。",
                    "extra_body": model.extra_body()},
                "code": self._code_identity(),
                "time_policy": {"version": TIME_POLICY, "audit_seconds": audit_seconds,
                    "trial_wall_seconds": audit_seconds + SLOT_OVERHEAD_SECONDS,
                    "experiment_wall_seconds": EXPERIMENT_SECONDS, "shared_overhead_seconds": SHARED_OVERHEAD_SECONDS,
                    "timing_basis": "claim_to_terminal", "retry_scope": "separate_batch"},
            }
            order = [payload.prompt_ids[r % len(variants):] + payload.prompt_ids[:r % len(variants)]
                     for r in range(payload.repeats)]
            manifest["order"] = order
            _write_json(directory / "manifest.json", manifest)
        except Exception as exc:
            import shutil
            shutil.rmtree(directory)
            raise ExperimentError(f"冻结实验条件失败：{exc}") from exc
        trials = [{"id": uuid_hex(), "round_index": r + 1, "prompt_id": prompt_id,
                   "status": "pending", "evaluation_status": "pending", "attempts": [],
                   "score": None, "usage": {}, "duration_seconds": None}
                  for r, ids in enumerate(order) for prompt_id in ids]
        self.store.add_full_prompt_experiment({"id": ident, "created_at": now(), "status": "running",
            "variants": payload.prompt_ids, "model": model.label, "budgets": effective_budgets,
            "manifest": manifest, "trials": trials, "summary": self._summary(manifest, trials, directory)})
        batch = self._new_batch("initial", [t["id"] for t in trials], EXPERIMENT_SECONDS,
                                started=batch_started, started_at=batch_started_at)
        self._progress(ident, phase="preparing", timing={"active_batch_id": batch["id"], "batches": [batch]})
        self._model[ident] = model
        self._task = asyncio.create_task(self._execute(ident, [t["id"] for t in trials], model, batch["id"]))
        return self.get(ident)

    @staticmethod
    def _code_identity() -> dict:
        try:
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
            dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip())
        except (OSError, subprocess.SubprocessError):
            commit, dirty = "unavailable", None
        package = ROOT / "backend/audit"
        hashes = {str(path.relative_to(package)): _hash(path) for path in sorted(package.rglob("*"))
                  if path.is_file() and path.suffix in {".py", ".yaml"}}
        return {"commit": commit, "dirty": dirty, "files": hashes}

    def _check_frozen(self, manifest, directory):
        if manifest.get("code", {}).get("files") != self._code_identity()["files"]:
            raise ExperimentError("审计或评分代码已变化，请恢复冻结版本后补跑，或创建新实验。")
        try:
            if json.loads((directory / "manifest.json").read_text()) != manifest:
                raise ValueError("磁盘执行清单与冻结记录不一致")
            actual = validate_assets(directory / "frozen/source.zip", directory / "frozen/truth.json",
                                     directory / "frozen/anchors.json")
            if actual != manifest["assets"]:
                raise ValueError("评分资产与冻结记录不一致")
        except (ValueError, OSError, zipfile.BadZipFile) as exc:
            raise ExperimentError(f"冻结评分资产校验失败：{exc}") from exc

    def _summary(self, manifest, trials, directory):
        # The persisted matrix already freezes the public truth catalogue. Keep
        # cleanup/progress usable even when an archive is lost; only the scorer
        # reads the full frozen answer, after the separate integrity gate.
        previous = self.store.get_prompt_experiment(directory.name)
        catalogue = ((previous or {}).get("summary") or {}).get("truth_matrix") or []
        truth = {"vulnerabilities": [{k: row[k] for k in ("id", "title", "class")} for row in catalogue]} if catalogue else json.loads((directory / "frozen/truth.json").read_text())
        result = summarise_trials(manifest["variants"], trials, manifest["repeats"], manifest["baseline_prompt_id"], truth)
        attempts = [a for trial in trials for a in trial.get("attempts", [])]
        result["actual_total_usage"] = {}
        for key in ("requests", "tool_calls", "input_tokens", "output_tokens", "total_tokens"):
            values = [a.get("usage", {}).get(key) for a in attempts]
            known = sum(value is not None for value in values)
            observed = sum(value if value is not None else a.get("usage", {}).get("known_" + key, 0)
                           or 0 for value, a in zip(values, attempts))
            result["actual_total_usage"][key] = {"known_total": observed, "known_attempts": known,
                "attempts": len(attempts), "total": observed if known == len(attempts) else None}
        result["batch_usage"] = {}
        kinds = {"initial", "retry"} if manifest.get("time_policy", {}).get("version") == TIME_POLICY else {"legacy"}
        for kind in sorted(kinds | {_batch_kind(manifest, a) for a in attempts}):
            selected = [a for a in attempts if _batch_kind(manifest, a) == kind]
            batch_usage = {"attempts": len(selected), "known_totals": {}}
            for key in ("wall_elapsed_seconds", "audit_elapsed_seconds", "requests", "tool_calls", "total_tokens"):
                if key == "wall_elapsed_seconds":
                    values = [a.get(key, a.get("duration_seconds")) for a in selected]
                elif key == "audit_elapsed_seconds":
                    values = [a.get(key) for a in selected]
                else:
                    values = [(a.get("usage") or {}).get(key) for a in selected]
                known = sum(value is not None for value in values)
                observed = round(sum(value if value is not None else
                    ((a.get("usage") or {}).get("known_" + key) or 0)
                    for value, a in zip(values, selected)), 3)
                batch_usage[key] = observed if known == len(selected) else None
                batch_usage["known_totals"][key] = {"known_total": observed,
                    "known_attempts": known, "attempts": len(selected)}
            batch_usage["known_total_tokens"] = batch_usage["known_totals"]["total_tokens"]["known_total"]
            result["batch_usage"][kind] = batch_usage
        return result

    def _save(self, ident, trials, **fields):
        row = self._record(ident)
        if row["status"] not in ACTIVE:
            return
        if "progress" in fields:
            fields["progress"] = {**row.get("progress", {}), **fields["progress"]}
        self.store.update_prompt_experiment(ident, trials=trials,
            summary=self._summary(row["manifest"], trials, self._directory(ident)), **fields)

    def _environment(self, model):
        permitted = ("PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY",
                     "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")
        env = {key: os.environ[key] for key in permitted if key in os.environ}
        env.update({"PYTHONPATH": str(ROOT / "backend"), "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
                    "LLM_MODEL": model.model, "LLM_BASE_URL": model.base_url,
                    "LLM_API_KEY": model.api_key, "LLM_THINKING": model.thinking,
                    "LAB30_SEED": "0"})
        return env

    async def _execute(self, ident, trial_ids, model, batch_id):
        row = self._record(ident)
        trials, manifest = row["trials"], row["manifest"]
        directory = self._directory(ident)
        batch = next(b for b in row["progress"]["timing"]["batches"] if b["id"] == batch_id)
        batch_deadline = self._batch_clocks[batch_id][1]
        slot_seconds = manifest["time_policy"]["trial_wall_seconds"]
        try:
            for trial_id in trial_ids:
                if self._record(ident)["status"] != "running":
                    break
                required_time = slot_seconds if batch["kind"] == "initial" else manifest["run_limits"]["seconds"] + CLEANUP_SECONDS
                if self._batch_remaining(batch) < required_time:
                    for pending_id in trial_ids[trial_ids.index(trial_id):]:
                        pending = next(t for t in trials if t["id"] == pending_id)
                        pending.update(status="not_started", evaluation_status="not_started", score=None,
                            stop_reason={"code": "insufficient_batch_time", "message": "批次剩余时间不足完整等时窗口与收尾，未启动"})
                    self._save(ident, trials)
                    break
                trial = next(t for t in trials if t["id"] == trial_id)
                attempt_no = len(trial["attempts"]) + 1
                work = directory / "trials" / trial_id / f"attempt-{attempt_no}"
                work.mkdir(parents=True)
                attempt = {"id": uuid_hex(), "attempt_no": attempt_no, "status": "running",
                    "evaluation_status": "pending", "created_at": now(), "usage": {}, "score": None,
                    "batch_id": batch_id, "batch_kind": batch["kind"], "audit_limit_seconds": manifest["run_limits"]["seconds"]}
                slot_deadline = min(self._clock() + slot_seconds, batch_deadline)
                trial["attempts"].append(attempt)
                trial.update(status="running", evaluation_status="pending", score=None,
                             run_id=None, snapshot_id=None, usage={}, read_coverage={},
                             duration_seconds=None, stop_reason=None, error="")
                self._save(ident, trials, progress={"trial_id": trial_id, "round_index": trial["round_index"],
                    "current": trial["prompt_id"], "phase": "preparing", "tail": [], "live": {}})
                try:
                    self._check_frozen(manifest, directory)
                    await self._attempt(ident, trial, attempt, work, model, deadline=slot_deadline, batch_deadline=batch_deadline)
                except asyncio.CancelledError:
                    interrupted = self._record(ident).get("progress", {}).get("interrupt_requested") is True
                    reason = {"code": "interrupted" if interrupted else "user_cancelled",
                              "message": "服务停止，试次已中断" if interrupted else "用户取消试次"}
                    attempt.update(status="interrupted" if interrupted else "cancelled", evaluation_status="invalid",
                                   score=None, stop_reason=reason, error=reason["message"], finished_at=now())
                    trial.update({k: v for k, v in attempt.items() if k not in {"id", "attempt_no", "created_at"}})
                    self._save(ident, trials)
                    raise
                except Exception as exc:
                    attempt.update(status="finished", evaluation_status="invalid", score=None,
                                   error=model.redact(str(exc)), finished_at=now())
                trial.update({k: v for k, v in attempt.items() if k not in {"id", "attempt_no", "created_at"}})
                self._save(ident, trials)
            current = self._record(ident)
            if current["status"] == "running":
                status = "completed" if all(t["evaluation_status"] == "valid" for t in trials) else "partial"
                self._save(ident, trials, status=status, finished_at=now(), progress={"phase": "ended"})
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            # A coordinator/filesystem error must release the shared experiment
            # slot. It must never silently resume paid work after a restart.
            for trial in trials:
                if trial["status"] == "running":
                    trial.update(status="interrupted", evaluation_status="invalid", score=None)
                    if trial["attempts"]:
                        trial["attempts"][-1].update(status="interrupted", evaluation_status="invalid", score=None)
            self.store.update_prompt_experiment(ident, trials=trials, status="interrupted", finished_at=now(),
                error=model.redact(f"实验调度中断：{exc}"))
        finally:
            await self._terminate(self._process, timeout=max(0.05, min(CLEANUP_SECONDS, batch_deadline - self._clock())))
            self._process = None
            current = self._record(ident)
            batch_status = current["status"] if current["status"] != "cancelling" else (
                "interrupted" if current["progress"].get("interrupt_requested") else "cancelled")
            self._finish_batch(ident, batch_id, batch_status)

    async def _attempt(self, ident, trial, attempt, work, model, *, deadline, batch_deadline):
        started = self._clock()
        work_deadline = min(deadline, batch_deadline) - CLEANUP_SECONDS
        args = [sys.executable, "-u", "-m", "audit.comparison_trial", "--manifest",
                str(self._directory(ident) / "manifest.json"), "--prompt-id", trial["prompt_id"],
                "--data-dir", str(work), "--output", str(work / "result.json"),
                "--deadline-monotonic", str(work_deadline)]
        process = None
        spawning = asyncio.create_task(asyncio.create_subprocess_exec(*args, cwd=ROOT,
            env=self._environment(model), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT))
        tail = []
        try:
            try:
                process = await asyncio.wait_for(asyncio.shield(spawning), max(.001, work_deadline - self._clock()))
            except asyncio.CancelledError:
                try:
                    process = await asyncio.wait_for(asyncio.shield(spawning), max(.001, min(2, deadline - self._clock())))
                except asyncio.TimeoutError:
                    pass
                raise
            self._process = process
            with (work / "run.log").open("w", encoding="utf-8") as log:
                while True:
                    remaining = work_deadline - self._clock()
                    if remaining <= 0:
                        raise TimeoutError("trial lifecycle deadline")
                    try:
                        raw = await asyncio.wait_for(process.stdout.readline(), min(2, remaining))
                    except asyncio.TimeoutError:
                        self._pulse(ident, trial, attempt, started)
                        continue
                    if not raw:
                        break
                    line = model.redact(raw.decode("utf-8", "replace").rstrip())
                    log.write(line + "\n")
                    log.flush()
                    tail = (tail + [line])[-40:]
                    try:
                        event = json.loads(line)
                    except ValueError:
                        event = {}
                    if not isinstance(event, dict):
                        event = {}
                    if event.get("kind") == "run_created":
                        attempt.update(run_id=event.get("run_id"), snapshot_id=event.get("snapshot_id"))
                        trial.update(run_id=attempt["run_id"], snapshot_id=attempt["snapshot_id"])
                    if event.get("kind") in {"heartbeat", "audit_started"}:
                        for key in ("usage", "read_coverage", "audit_started_at", "audit_elapsed_seconds", "last_event_id", "last_event_at", "heartbeat_at", "finding_count"):
                            if key in event:
                                attempt[key] = event[key]
                    current = self._record(ident)
                    if current["status"] in ACTIVE:
                        current_trials = current["trials"]
                        target = next(t for t in current_trials if t["id"] == trial["id"])
                        target.update(run_id=attempt.get("run_id"), snapshot_id=attempt.get("snapshot_id"))
                        target["attempts"][-1].update(attempt)
                        previous_live = current["progress"].get("live") or {}
                        live = {**previous_live, **{key: event[key] for key in (
                            "run_id", "phase", "usage", "finding_count", "read_coverage", "audit_started_at", "audit_elapsed_seconds", "last_event_id", "last_event_at", "heartbeat_at") if key in event}}
                        self.store.update_prompt_experiment(ident, trials=current_trials, progress={**current["progress"],
                            "trial_id": trial["id"], "round_index": trial["round_index"], "current": trial["prompt_id"],
                            "phase": event.get("phase") or current["progress"].get("phase", "running"), "tail": tail, "live": live})
            code = await asyncio.wait_for(process.wait(), max(.001, work_deadline - self._clock()))
            result_path = work / "result.json"
            result = self._load_result(work, attempt.get("run_id"))
            validity, reason = classify_result(result, code)
            attempt.update(status="finished", evaluation_status=validity, stop_reason=result.get("stop_reason") or {"code": reason},
                error=model.redact(str(result.get("infra_error") or (result.get("run") or {}).get("error") or "")),
                usage=result.get("usage") or {}, duration_seconds=round(self._clock() - started, 3),
                wall_elapsed_seconds=round(self._clock() - started, 3),
                read_coverage=result.get("read_coverage"), warnings=result.get("warnings") or [],
                audit_elapsed_seconds=result.get("audit_elapsed_seconds"), audit_started_at=result.get("audit_started_at"),
                run_id=(result.get("run") or {}).get("id", attempt.get("run_id")),
                snapshot_id=(result.get("run") or {}).get("snapshot_id", attempt.get("snapshot_id")), finished_at=now())
            if validity == "valid":
                base = self._directory(ident) / "frozen"
                attempt["score"] = evaluate_v2(json.loads((base / "truth.json").read_text()),
                    result.get("findings") or [], json.loads((base / "anchors.json").read_text()))
                if self._clock() > work_deadline:
                    raise TimeoutError("scoring exceeded lifecycle deadline")
        except (TimeoutError, asyncio.TimeoutError) as exc:
            code = "experiment_deadline_exceeded" if batch_deadline <= deadline else "trial_lifecycle_timeout"
            attempt.update(status="finished", evaluation_status="invalid", score=None,
                stop_reason={"code": code, "message": "批次或试次生命周期到限"}, error=str(exc), finished_at=now())
        finally:
            # A spawn cancelled at the boundary still belongs to us and must be reaped.
            if process is None:
                if spawning.done() and not spawning.cancelled() and spawning.exception() is None:
                    process = spawning.result()
                elif not spawning.done():
                    try:
                        process = await asyncio.wait_for(asyncio.shield(spawning), max(.001, min(2, deadline - self._clock())))
                    except (TimeoutError, asyncio.TimeoutError):
                        spawning.add_done_callback(self._reap_late_spawn)
            await self._terminate(process, timeout=max(.05, min(CLEANUP_SECONDS, deadline - self._clock())))
            self._process = None
            # SIGTERM lets the child save its partial ledger and usage. Preserve
            # those costs on cancellation or pipe failure, without scoring it.
            attempt["duration_seconds"] = attempt["wall_elapsed_seconds"] = round(self._clock() - started, 3)
            if attempt.get("evaluation_status") != "valid":
                with contextlib.suppress(OSError, sqlite3.Error, ValueError, TypeError):
                    partial = self._load_result(work, attempt.get("run_id"))
                    attempt.update(usage=partial.get("usage") or attempt.get("usage") or {},
                        read_coverage=partial.get("read_coverage"), warnings=partial.get("warnings") or [],
                        audit_started_at=partial.get("audit_started_at"), audit_elapsed_seconds=partial.get("audit_elapsed_seconds"),
                        run_id=(partial.get("run") or {}).get("id", attempt.get("run_id")),
                        snapshot_id=(partial.get("run") or {}).get("snapshot_id", attempt.get("snapshot_id")))
                    if not attempt.get("stop_reason"):
                        attempt["stop_reason"] = partial.get("stop_reason")

    def _pulse(self, ident, trial, attempt, started):
        attempt["wall_elapsed_seconds"] = round(self._clock() - started, 3)
        row = self._record(ident)
        live = {**(row["progress"].get("live") or {}), "wall_elapsed_seconds": attempt["wall_elapsed_seconds"], "parent_updated_at": now()}
        self._progress(ident, live=live)

    @staticmethod
    def _load_result(work, run_id=None):
        result = {}
        try:
            candidate = json.loads((work / "result.json").read_text())
            if isinstance(candidate, dict):
                result = candidate
        except (OSError, ValueError):
            pass
        if (not isinstance(result.get("run"), dict) or not result["run"].get("id")
                or (run_id is not None and result["run"]["id"] != run_id)
                or not isinstance(result.get("usage"), dict) or not isinstance(result.get("findings"), list)):
            from .comparison_results import recover_trial
            try:
                recovered = recover_trial(work, run_id)
                # An executor exception stays invalid, even if the SQLite facts survived.
                if result.get("infra_error"):
                    recovered["infra_error"] = result["infra_error"]
                return recovered
            except (OSError, sqlite3.Error, ValueError, TypeError):
                result.setdefault("infra_error", {"code": "result_unavailable", "message": "子进程未保存可读取的运行结果"})
        return result

    @staticmethod
    def _reap_late_spawn(task):
        if not task.cancelled() and task.exception() is None:
            asyncio.create_task(FullComparisonRunner._terminate(task.result(), timeout=CLEANUP_SECONDS))

    @staticmethod
    async def _terminate(process, *, timeout=CLEANUP_SECONDS):
        if process is None:
            return
        loop = asyncio.get_running_loop()
        cutoff = loop.time() + max(0, timeout)
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            remaining = cutoff - loop.time()
            if remaining > 0:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(process.communicate(), min(10, remaining * 2 / 3))
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                remaining = cutoff - loop.time()
                if remaining > 0:
                    with contextlib.suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(process.communicate(), remaining)
        remaining = cutoff - loop.time()
        if remaining > 0:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(process.wait(), remaining)

    async def cancel(self, ident, *, interrupted=False):
        row = self._record(ident)
        if row["status"] not in ACTIVE:
            return self.get(ident)
        self.store.update_prompt_experiment(ident, status="cancelling", progress={**row["progress"],
            "cancel_requested": True, "interrupt_requested": interrupted})
        if self._task and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        row = self._record(ident)
        for trial in row["trials"]:
            if trial["status"] == "running":
                reason = {"code": "interrupted" if interrupted else "user_cancelled",
                          "message": "服务停止，试次已中断" if interrupted else "用户取消试次"}
                trial.update(status="interrupted" if interrupted else "cancelled", evaluation_status="invalid",
                             score=None, stop_reason=reason)
                if trial["attempts"]:
                    trial["attempts"][-1].update(status=trial["status"], evaluation_status="invalid",
                                                 score=None, stop_reason=reason)
            elif trial["status"] == "pending" and not trial.get("attempts"):
                trial.update(status="not_started", evaluation_status="not_started", score=None,
                    stop_reason={"code": "interrupted" if interrupted else "user_cancelled", "message": "批次停止时尚未启动"})
        self.store.update_prompt_experiment(ident, status="interrupted" if interrupted else "cancelled", finished_at=now(),
            trials=row["trials"], summary=self._summary(row["manifest"], row["trials"], self._directory(ident)))
        batch_id = row.get("progress", {}).get("timing", {}).get("active_batch_id")
        if batch_id:
            self._finish_batch(ident, batch_id, "interrupted" if interrupted else "cancelled")
        return self.get(ident)

    async def shutdown(self):
        self._closed = True
        row = self.store.running_prompt_experiment()
        if row and row.get("protocol") == PROTOCOL:
            await self.cancel(row["id"], interrupted=True)

    def retry(self, ident, trial_id):
        row = self._record(ident)
        if self._closed or self.store.running_prompt_experiment() or (self._task and not self._task.done()):
            raise ExperimentError("请先等待当前实验停止。")
        trial = next((t for t in row["trials"] if t["id"] == trial_id), None)
        if trial is None:
            raise LookupError(trial_id)
        eligible, reason = self._retry_eligibility(row, trial)
        if not eligible:
            raise ExperimentError(reason)
        model = self._model.get(ident, self.settings.model)
        frozen = row["manifest"]["model"]
        if not model.configured or {"model": model.model, "base_url": model.public_base_url(), "thinking": model.thinking} != frozen:
            raise ExperimentError("无法恢复原模型配置，请恢复相同模型、端点和 thinking 后补跑。")
        self._check_frozen(row["manifest"], self._directory(ident))
        trial["retry_count"] = int(trial.get("retry_count", 0)) + 1
        batch = self._new_batch("retry", [trial_id], row["manifest"]["time_policy"]["trial_wall_seconds"])
        timing = row.get("progress", {}).get("timing") or {"batches": []}
        timing.setdefault("batches", []).append(batch)
        timing["active_batch_id"] = batch["id"]
        self.store.update_prompt_experiment(ident, status="running", finished_at=None, trials=row["trials"],
            progress={**row.get("progress", {}), "timing": timing, "phase": "preparing", "live": {}, "cancel_requested": False})
        self._task = asyncio.create_task(self._execute(ident, [trial_id], model, batch["id"]))
        return self.get(ident)

    def _trial(self, ident, trial_id, attempt_no=None):
        row = self._record(ident)
        trial = next((t for t in row["trials"] if t["id"] == trial_id), None)
        if trial is None or not re.fullmatch(r"[a-f0-9]{16}", trial_id):
            raise LookupError(trial_id)
        attempts = trial.get("attempts") or []
        selected = next((a for a in attempts if a["attempt_no"] == attempt_no), None) if attempt_no else (attempts[-1] if attempts else None)
        if attempt_no and selected is None:
            raise LookupError(attempt_no)
        return row, trial, selected

    @contextlib.contextmanager
    def archive(self, ident, trial_id, attempt_no=None):
        row, trial, attempt = self._trial(ident, trial_id, attempt_no)
        if not attempt or not attempt.get("run_id"):
            raise FileNotFoundError("试次尚未保存运行记录")
        work = self._directory(ident) / "trials" / trial_id / f"attempt-{int(attempt['attempt_no'])}"
        if not work.resolve().is_relative_to(self._directory(ident)):
            raise LookupError(trial_id)
        store = Store.open_readonly(work / "audit.db")
        try:
            yield store, work, trial, attempt
        finally:
            store.close()

    def trial_detail(self, ident, trial_id, attempt_no=None):
        _, trial, attempt = self._trial(ident, trial_id, attempt_no)
        if not attempt or not attempt.get("run_id"):
            return {"trial": _public(trial), "run": None, "findings": [], "events": [],
                    "score": None, "source_available": False, "snapshot": None, "event_cursor": 0, "has_earlier": False}
        self._hydrate_attempt(ident, trial, attempt)
        with self.archive(ident, trial_id, attempt_no) as (store, work, _, attempt):
            # archive() reads the unmodified record; retain the hydrated projection.
            _, _, projected_attempt = self._trial(ident, trial_id, attempt_no)
            self._hydrate_attempt(ident, trial, projected_attempt)
            attempt = projected_attempt
            run = store.get_run(attempt["run_id"])
            if run is None:
                raise FileNotFoundError("隔离运行记录已不存在")
            snapshot = store.get_snapshot(run["snapshot_id"])
            events = store.list_events_before(run["id"], limit=100)
            return {"trial": _public(trial), "attempt": _public(attempt), "run": run,
                "findings": store.list_findings(run["id"]), "events": events,
                "event_cursor": events[-1]["id"] if events else 0,
                "has_earlier": bool(events and store.count_events_before(run["id"], events[0]["id"])),
                "score": attempt.get("score"), "source_available": (work / "snapshots").is_dir(),
                "read_coverage": attempt.get("read_coverage") or {},
                "snapshot": {k: snapshot.get(k) for k in ("id", "name", "file_count")} if snapshot else None}

    def source(self, ident, trial_id, path, start, end, attempt_no=None):
        from .source import SourceRepository
        with self.archive(ident, trial_id, attempt_no) as (store, work, _, attempt):
            if not (work / "snapshots").is_dir():
                raise FileNotFoundError("试次冻结源码已不存在")
            run = store.get_run(attempt["run_id"])
            repo = SourceRepository(work)
            result = repo.read_source(run["snapshot_id"], path, start, end)
            snapshot = repo.get_snapshot(run["snapshot_id"])
            record = next((f for f in snapshot["files"] if f["path"] == path), {})
            result["line_count"] = record.get("line_count")
            return result

    def events(self, ident, trial_id, after=0, limit=100, attempt_no=None, *, before=None):
        if before is not None and after:
            raise ValueError("before 与 after 不能同时使用")
        with self.archive(ident, trial_id, attempt_no) as (store, _, _, attempt):
            if before is not None:
                events = store.list_events_before(attempt["run_id"], before=before, limit=limit)
                remaining = store.count_events_before(attempt["run_id"], events[0]["id"]) if events else 0
            else:
                events = store.list_events(attempt["run_id"], after, limit)
                remaining = max(0, store.count_events(attempt["run_id"], after) - len(events))
            return {"events": events,
                    "remaining": remaining, "has_earlier": bool(events and store.count_events_before(attempt["run_id"], events[0]["id"])),
                    "event_cursor": events[-1]["id"] if events else after}

    def trial_report(self, ident, trial_id, format="json", attempt_no=None):
        from .app import _run_bundle
        from .report import render_markdown, render_json
        from types import SimpleNamespace
        with self.archive(ident, trial_id, attempt_no) as (store, _, _, attempt):
            bundle = _run_bundle(SimpleNamespace(store=store), attempt["run_id"])
            if format == "markdown":
                return render_markdown(bundle).encode(), "text/markdown; charset=utf-8", f"trial-{trial_id}.md"
            return render_json(bundle).encode(), "application/json", f"trial-{trial_id}.json"

    def report(self, ident, format="markdown"):
        row = self.get(ident)
        if format == "json":
            return json.dumps(row, ensure_ascii=False, indent=2).encode(), "application/json", f"comparison-{ident}.json"
        if format == "csv":
            return csv_archive(row), "application/zip", f"comparison-{ident}-csv.zip"
        return markdown_report(row).encode(), "text/markdown; charset=utf-8", f"comparison-{ident}.md"


def uuid_hex():
    import uuid
    return uuid.uuid4().hex[:16]


def _number(value, *, percent=False):
    return "—" if value is None else f"{value * 100:.1f}%" if percent else f"{value:.3f}"


def _stat(value, *, percent=False):
    """One display unit for both the mean and sample standard deviation."""
    mean, deviation = value.get("mean"), value.get("sample_std")
    unit = (lambda number: _number(number, percent=percent))
    return f"{unit(mean)} ± {unit(deviation)}（n={value.get('n', 0)}）"


def _cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def markdown_report(row):
    manifest, summary = row["manifest"], row.get("summary") or {}
    lines = ["# Lab30 多版本 Prompt 限时源码审计对比", "", f"实验：{row['id']} · 状态：{row['status']}",
        "", "本报告为官方清单匹配，不等同于漏洞已通过 POC 验证；不提供现实误报率或整体 Accuracy。",
        f"共同有效轮次：{summary.get('complete_round_count', 0)}/{manifest['repeats']}。"
        + ("有效数据不足三轮，以下为初步结果。" if summary.get("preliminary", True) else "仅描述本靶场本次实验，不宣称统计显著。"),
        "", "## 冻结条件", "", f"协议：{row['protocol']} / {manifest['scoring_protocol']}；POC：关闭。",
        f"模型：{manifest['model']['model']}；thinking：{manifest['model']['thinking']}。",
        f"每次 Agent 执行预算：{json.dumps(manifest['budgets'])}；每试次共享预算：{json.dumps(manifest['run_limits'])}。",
        f"正式基线：{manifest['baseline_prompt_id']}。", "", "## 效果总览", "",
        "| 版本 | TP 均值 | D 均值 | U 均值 | FN 均值 | Precision | Recall | F1 | ΔF1（百分点） | ΔRecall（百分点） |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for variant in summary.get("variants", []):
        m = variant["metrics"]
        deltas = [variant["paired_deltas"][key] for key in ("f1", "recall")]
        lines.append("| " + " | ".join([str(variant.get("label") or variant["id"]),
            *[_stat(m[k]) for k in ("TP", "D", "U", "FN")],
            *[_stat(m[k], percent=True) for k in ("precision", "recall", "f1")],
            *["—" if delta["mean"] is None else f"{delta['mean'] * 100:+.1f} ± {_number(None if delta['sample_std'] is None else delta['sample_std'] * 100)}（n={delta['n']}）"
              for delta in deltas]]) + " |")
    lines += ["", "各项为逐轮均值 ± 样本标准差及有效 n；单轮标准差不可计算。Precision 无预测时未定义，不按 0 填充。",
        "D 为仍重复主张的报告；U 为未匹配官方清单的候选，不代表已证伪。", "", "## 逐轮记录", "",
        "| 轮次 | 策略 | 试次 ID | 状态 | 有效性 | TP | D | U | FN | F1 | 停止原因 |",
        "|---|---|---|---|---|---:|---:|---:|---:|---:|---|"]
    for trial in row["trials"]:
        score = trial.get("score") or {}
        reason = trial.get("stop_reason") or {}
        lines.append("| " + " | ".join([str(trial["round_index"]), trial["prompt_id"], trial["id"], trial["status"], trial["evaluation_status"],
            *[str(score.get(k, "—")) for k in ("TP", "D", "U", "FN")], _number(score.get("f1"), percent=True),
            _cell(reason.get("code", "—"))]) + " |")
    policy = manifest.get("time_policy") or {}
    lines += ["", "## 时间政策与批次消耗", "",
        (f"时间政策 {policy['version']}：每试次最多 {policy['audit_seconds']} 秒审计，完整生命周期最多 {policy['trial_wall_seconds']} 秒；"
         f"首次批次含准备和收尾最多 {policy['experiment_wall_seconds']} 秒，补跑单独计时。"
         if policy else "历史实验保持其原始冻结预算，不按新限时政策重算。"),
        "提前完成或先触及请求／工具上限时，以实际耗时和停止原因解释；不宣称运行满窗口。", "",
        "| 批次 | 开始 | 截止 | 结束 | 完整耗时秒 | 状态 |", "|---|---|---|---|---:|---|"]
    timing = row.get("progress", {}).get("timing") or {}
    for batch in timing.get("batches", []):
        lines.append("| " + " | ".join([batch["kind"] + " " + batch["id"], batch["started_at"], batch["deadline_at"],
            batch.get("finished_at") or "—", _number(batch.get("elapsed_seconds")), batch["status"]]) + " |")
    lines += ["", "| 试次 | 执行次数 | 批次 | 审计耗时秒 | 完整耗时秒 | 已知 tokens | 停止原因 |",
        "|---|---:|---|---:|---:|---:|---|"]
    for trial in row["trials"]:
        for attempt in trial.get("attempts", []):
            usage = attempt.get("usage") or {}
            tokens = usage.get("total_tokens") if usage.get("total_tokens") is not None else usage.get("known_total_tokens")
            lines.append("| " + " | ".join([trial["id"], str(attempt["attempt_no"]), _batch_kind(manifest, attempt),
                _number(attempt.get("audit_elapsed_seconds")), _number(attempt.get("wall_elapsed_seconds", attempt.get("duration_seconds"))),
                _number(tokens), _cell((attempt.get("stop_reason") or {}).get("code", "—"))]) + " |")
    lines += ["", "## 资源与 CVSS（相同共同轮次）", "",
        "| 版本 | 请求 | 工具调用 | tokens | 耗时秒 | tokens/TP | CVSS 可评分覆盖 | CVSS MAE | 等级一致率 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for variant in summary.get("variants", []):
        m = variant["metrics"]
        lines.append("| " + " | ".join([_cell(variant.get("label") or variant["id"]),
            *[_stat(m[key]) for key in ("requests", "tool_calls", "total_tokens", "duration_seconds", "tokens_per_tp")],
            _stat(m["cvss_coverage"], percent=True), _stat(m["cvss_mae"]),
            _stat(m["cvss_severity_agreement"], percent=True)]) + " |")
    lines += ["", "CVSS 单独统计，不参与挖掘 F1。各版本交集中的可评分漏洞进一步对照如下；空交集不计算 MAE。", "",
        "| 轮次 | 共同可评分真值 | 策略 | CVSS MAE | 等级一致率 |", "|---|---|---|---:|---:|"]
    for common in summary.get("cvss_common_rounds", []):
        for prompt_id, value in common["variants"].items():
            lines.append(f"| {common['round_index']} | {', '.join(common['truth_ids']) or '—'} | {prompt_id} | "
                         f"{_number(value['score_mae'])} | {_number(value['severity_accuracy'], percent=True)} |")
    lines += ["", "## 30 项命中矩阵", "", "| 真值 | 类别 | " + " | ".join(v["id"] for v in manifest["variants"]) + " |",
        "|---|---|" + "---:|" * len(manifest["variants"]) ]
    for item in summary.get("truth_matrix", []):
        lines.append("| " + " | ".join([_cell(f"{item['id']} {item['title']}"), item["class"],
            *[f"{item['variants'][v['id']]['hits']}/{item['variants'][v['id']]['total']}" for v in manifest["variants"]]]) + " |")
    lines += ["", "## 22 类覆盖", "", "| 类别 | " + " | ".join(v["id"] for v in manifest["variants"]) + " |",
              "|---|" + "---:|" * len(manifest["variants"])]
    for item in summary.get("class_coverage", []):
        lines.append("| " + " | ".join([item["class"], *[
            f"{item['variants'][v['id']]['detected']}/{item['variants'][v['id']]['total']}（{_number(item['variants'][v['id']]['recall'], percent=True)}）"
            for v in manifest["variants"]]]) + " |")
    lines += ["", "## 配对变化与策略", ""]
    for variant in summary.get("variants", []):
        if variant["id"] == manifest["baseline_prompt_id"]:
            continue
        change = variant["paired_deltas"]["f1"]
        recall_change = variant["paired_deltas"]["recall"]
        if change["mean"] is None:
            lines.append(f"- {variant['id']}：没有共同有效轮次，暂不判断优劣。")
        else:
            direction = "上升" if change["mean"] > 0 else "下降" if change["mean"] < 0 else "持平"
            lines.append(f"- {variant['id']} 相对基线 F1 {direction} {abs(change['mean']) * 100:.1f} 个百分点；"
                         f"配对数 {change['n']}，样本标准差 {_number(None if change['sample_std'] is None else change['sample_std'] * 100)} 个百分点。")
            lines.append(f"  Recall 变化：{recall_change['mean'] * 100:+.1f} 个百分点。")
            if change["mean"] > 0 and recall_change["mean"] < 0:
                lines.append("  F1 上升伴随召回下降，存在取舍，不能表述为全面提升。")
            for point in change.get("values", []):
                lines.append(f"  - 第 {point['round_index']} 轮：{point['value'] * 100:+.1f} 个百分点；"
                    f"增检 {', '.join(point.get('gained_truth_ids', [])) or '无'}；"
                    f"丢失 {', '.join(point.get('lost_truth_ids', [])) or '无'}。")
            values = [x["value"] for x in change.get("values", [])]
            if values and min(values) < 0 < max(values):
                lines.append("  各轮变化方向不一致，不能解释为稳定提升。")
    for variant in manifest["variants"]:
        fence = "~" * max(6, 1 + max((len(m.group()) for m in re.finditer(r"~+", variant["text"])), default=0))
        lines += ["", f"### {variant['label']}", "", variant.get("reason") or "", "",
            f"正文 SHA-256：{variant['sha256']}", "", fence + "text", variant["text"], fence]
    lines += ["", "## 审计与评分摘要", "", "```json", json.dumps({"assets": manifest["assets"], "code": manifest["code"],
        "actual_total_usage": summary.get("actual_total_usage"), "batch_usage": summary.get("batch_usage")}, ensure_ascii=False, indent=2), "```", ""]
    return "\n".join(lines)


def csv_archive(row):
    def table(headers, rows):
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(headers)
        for values in rows:
            writer.writerow([("'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@")) else value) for value in values])
        return "\ufeff" + stream.getvalue()
    summary = row.get("summary") or {}
    names = ("TP", "D", "U", "FP", "FN", "precision", "recall", "f1")
    metrics = (*names, "requests", "tool_calls", "input_tokens", "output_tokens", "total_tokens",
               "duration_seconds", "tokens_per_tp", "cvss_coverage", "cvss_mae", "cvss_severity_agreement")
    stat_names = ("mean", "sample_std", "n")
    summary_rows = []
    for variant in summary.get("variants", []):
        summary_rows.append([variant["id"], summary["complete_round_count"],
            *[variant["metrics"][key][stat] for key in metrics for stat in stat_names],
            *[(variant["paired_deltas"][key][stat] if stat == "n" else
               None if variant["paired_deltas"][key][stat] is None else variant["paired_deltas"][key][stat] * 100)
              for key in ("f1", "recall") for stat in stat_names]])
    usage_names = ("requests", "tool_calls", "input_tokens", "output_tokens", "total_tokens", "known_total_tokens")
    trial_rows = []
    batches = {batch["id"]: batch for batch in (row.get("progress", {}).get("timing") or {}).get("batches", [])}
    for trial in row["trials"]:
        attempts = trial.get("attempts") or [trial]
        for index, attempt in enumerate(attempts):
            reason = attempt.get("stop_reason") or {}
            batch = batches.get(attempt.get("batch_id"), {})
            trial_rows.append([trial["id"], trial["round_index"], trial["prompt_id"],
                attempt.get("attempt_no"), index == len(attempts) - 1,
                attempt["status"], attempt["evaluation_status"], attempt.get("run_id"), attempt.get("snapshot_id"),
                *[(attempt.get("score") or {}).get(key) for key in names],
                *[(attempt.get("usage") or {}).get(key) for key in usage_names], attempt.get("duration_seconds"),
                reason.get("code"), attempt.get("error"), attempt.get("batch_id"), _batch_kind(row["manifest"], attempt),
                attempt.get("audit_started_at"), attempt.get("audit_elapsed_seconds"),
                attempt.get("wall_elapsed_seconds", attempt.get("duration_seconds")),
                *[batch.get(key) for key in ("started_at", "deadline_at", "finished_at", "elapsed_seconds")]])
    tables = {"summary.csv": table(["prompt_id", "cohort_n",
            *[f"{key}_{stat}" for key in metrics for stat in stat_names],
            *[f"delta_{key}_pp_{stat}" for key in ("f1", "recall") for stat in stat_names]], summary_rows),
        "trials.csv": table(["trial_id", "round", "prompt_id", "attempt_no", "effective_attempt", "status",
            "evaluation_status", "run_id", "snapshot_id", *names, *usage_names, "duration_seconds", "stop_reason", "error",
            "batch_id", "batch_kind", "audit_started_at", "audit_elapsed_seconds", "wall_elapsed_seconds",
            "batch_started_at", "batch_deadline_at", "batch_finished_at", "batch_wall_elapsed_seconds"], trial_rows),
        "truth_matrix.csv": table(["truth_id", "title", "class", "prompt_id", "hits", "total"],
        [[t["id"], t["title"], t["class"], p, cell["hits"], cell["total"]] for t in summary.get("truth_matrix", []) for p, cell in t["variants"].items()])}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for filename, content in tables.items():
            archive.writestr(filename, content)
    return stream.getvalue()
