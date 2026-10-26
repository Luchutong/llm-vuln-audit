"""Persisted, isolated full-audit comparisons. Only an explicit start/retry spends tokens."""
from __future__ import annotations

import asyncio
import contextlib
import csv
import hashlib
import io
import json
import os
import re
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
OBJECTIVE = "对所选完整源码进行全量白盒漏洞审计，穷尽由实际源码支持的可操作漏洞，不要找到第一处就停止。逐项提供根因、原始源码证据、影响与触发条件；没有证据的方向保留为排查记录。"


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
        return _public(self._record(ident))

    def start(self, payload) -> dict:
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
            effective_budgets = clamp_budgets(supplied)
            manifest = {
                "protocol": PROTOCOL, "scoring_protocol": "lab30-v2", "created_at": now(),
                "variants": variants, "baseline_prompt_id": payload.baseline_prompt_id,
                "repeats": payload.repeats, "model": {"model": model.model,
                    "base_url": model.public_base_url(), "thinking": model.thinking},
                "budgets": effective_budgets, "run_limits": payload.run_limits.model_dump(),
                "task_spec": {"objective": OBJECTIVE,
                    "success_criteria": "穷尽所选源码的漏洞风险并记录尚未覆盖的方向，所有漏洞均须由已读源码支持；不能找到第一条就停止。",
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
        self._model[ident] = model
        self._task = asyncio.create_task(self._execute(ident, [t["id"] for t in trials], model))
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
        return result

    def _save(self, ident, trials, **fields):
        row = self._record(ident)
        if row["status"] not in ACTIVE:
            return
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

    async def _execute(self, ident, trial_ids, model):
        row = self._record(ident)
        trials, manifest = row["trials"], row["manifest"]
        directory = self._directory(ident)
        try:
            for trial_id in trial_ids:
                if self._record(ident)["status"] != "running":
                    break
                trial = next(t for t in trials if t["id"] == trial_id)
                attempt_no = len(trial["attempts"]) + 1
                work = directory / "trials" / trial_id / f"attempt-{attempt_no}"
                work.mkdir(parents=True)
                attempt = {"id": uuid_hex(), "attempt_no": attempt_no, "status": "running",
                    "evaluation_status": "pending", "created_at": now(), "usage": {}, "score": None}
                trial["attempts"].append(attempt)
                trial.update(status="running", evaluation_status="pending", score=None,
                             run_id=None, snapshot_id=None, usage={}, read_coverage={},
                             duration_seconds=None, stop_reason=None, error="")
                self._save(ident, trials, progress={"trial_id": trial_id, "round_index": trial["round_index"],
                    "current": trial["prompt_id"], "phase": "preparing", "tail": []})
                try:
                    self._check_frozen(manifest, directory)
                    await self._attempt(ident, trial, attempt, work, model)
                except asyncio.CancelledError:
                    attempt.update(status="cancelled", evaluation_status="invalid", error="执行已取消", finished_at=now())
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
            await self._terminate(self._process)
            self._process = None

    async def _attempt(self, ident, trial, attempt, work, model):
        args = [sys.executable, "-u", "-m", "audit.comparison_trial", "--manifest",
                str(self._directory(ident) / "manifest.json"), "--prompt-id", trial["prompt_id"],
                "--data-dir", str(work), "--output", str(work / "result.json")]
        process = None
        spawning = asyncio.create_task(asyncio.create_subprocess_exec(*args, cwd=ROOT,
            env=self._environment(model), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT))
        started = time.monotonic()
        # The production executor enforces the run deadline. This outer watchdog
        # also reaps a child that loses its event loop or terminal bookkeeping.
        deadline = started + self._record(ident)["manifest"]["run_limits"]["seconds"] + 60
        tail = []
        try:
            try:
                process = await asyncio.shield(spawning)
            except asyncio.CancelledError:
                process = await spawning
                raise
            self._process = process
            with (work / "run.log").open("w", encoding="utf-8") as log:
                while raw := await asyncio.wait_for(process.stdout.readline(), max(0.1, deadline - time.monotonic())):
                    line = model.redact(raw.decode("utf-8", "replace").rstrip())
                    log.write(line + "\n")
                    log.flush()
                    tail = (tail + [line])[-40:]
                    try:
                        event = json.loads(line)
                    except ValueError:
                        event = {}
                    if event.get("kind") == "run_created":
                        attempt.update(run_id=event.get("run_id"), snapshot_id=event.get("snapshot_id"))
                        trial.update(run_id=attempt["run_id"], snapshot_id=attempt["snapshot_id"])
                    current = self._record(ident)
                    if current["status"] in ACTIVE:
                        current_trials = current["trials"]
                        target = next(t for t in current_trials if t["id"] == trial["id"])
                        target.update(run_id=attempt.get("run_id"), snapshot_id=attempt.get("snapshot_id"))
                        target["attempts"][-1].update(attempt)
                        self.store.update_prompt_experiment(ident, trials=current_trials, progress={
                            "trial_id": trial["id"], "round_index": trial["round_index"], "current": trial["prompt_id"],
                            "phase": event.get("phase", "running"), "tail": tail})
            code = await asyncio.wait_for(process.wait(), max(0.1, deadline - time.monotonic()))
            result_path = work / "result.json"
            result = json.loads(result_path.read_text()) if result_path.is_file() else {"infra_error": "子进程没有保存运行结果"}
            validity, reason = classify_result(result, code)
            attempt.update(status="finished", evaluation_status=validity, stop_reason=result.get("stop_reason") or {"code": reason},
                error=model.redact(str(result.get("infra_error") or (result.get("run") or {}).get("error") or "")),
                usage=result.get("usage") or {}, duration_seconds=result.get("duration_seconds", round(time.monotonic() - started, 3)),
                read_coverage=result.get("read_coverage") or {},
                run_id=(result.get("run") or {}).get("id", attempt.get("run_id")),
                snapshot_id=(result.get("run") or {}).get("snapshot_id", attempt.get("snapshot_id")), finished_at=now())
            if validity == "valid":
                base = self._directory(ident) / "frozen"
                attempt["score"] = evaluate_v2(json.loads((base / "truth.json").read_text()),
                    result.get("findings") or [], json.loads((base / "anchors.json").read_text()))
        finally:
            await self._terminate(process)
            self._process = None
            # SIGTERM lets the child save its partial ledger and usage. Preserve
            # those costs on cancellation or pipe failure, without scoring it.
            if attempt.get("status") != "finished":
                attempt["duration_seconds"] = round(time.monotonic() - started, 3)
                with contextlib.suppress(OSError, ValueError, TypeError):
                    partial = json.loads((work / "result.json").read_text())
                    attempt.update(usage=partial.get("usage") or {},
                        read_coverage=partial.get("read_coverage") or {},
                        run_id=(partial.get("run") or {}).get("id", attempt.get("run_id")),
                        snapshot_id=(partial.get("run") or {}).get("snapshot_id", attempt.get("snapshot_id")),
                        stop_reason=partial.get("stop_reason"))

    @staticmethod
    async def _terminate(process):
        if process is None:
            return
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                await asyncio.wait_for(process.communicate(), 10)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                await process.communicate()
        await process.wait()

    async def cancel(self, ident, *, interrupted=False):
        row = self._record(ident)
        if row["status"] not in ACTIVE:
            return self.get(ident)
        self.store.update_prompt_experiment(ident, status="cancelling", progress={**row["progress"], "cancel_requested": True})
        if self._task and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        row = self._record(ident)
        for trial in row["trials"]:
            if trial["status"] == "running":
                trial.update(status="interrupted" if interrupted else "cancelled", evaluation_status="invalid")
                if trial["attempts"]:
                    trial["attempts"][-1].update(status=trial["status"], evaluation_status="invalid")
        self.store.update_prompt_experiment(ident, status="interrupted" if interrupted else "cancelled", finished_at=now(),
            trials=row["trials"], summary=self._summary(row["manifest"], row["trials"], self._directory(ident)))
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
        if trial.get("evaluation_status") != "invalid" or len(trial["attempts"]) >= 2:
            raise ExperimentError("仅允许补跑一次无效试次，不能替换有效低分结果。")
        model = self._model.get(ident, self.settings.model)
        frozen = row["manifest"]["model"]
        if not model.configured or {"model": model.model, "base_url": model.public_base_url(), "thinking": model.thinking} != frozen:
            raise ExperimentError("无法恢复原模型配置，请恢复相同模型、端点和 thinking 后补跑。")
        self._check_frozen(row["manifest"], self._directory(ident))
        self.store.update_prompt_experiment(ident, status="running", finished_at=None)
        self._task = asyncio.create_task(self._execute(ident, [trial_id], model))
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
                    "score": None, "source_available": False, "snapshot": None}
        with self.archive(ident, trial_id, attempt_no) as (store, work, _, attempt):
            run = store.get_run(attempt["run_id"])
            if run is None:
                raise FileNotFoundError("隔离运行记录已不存在")
            snapshot = store.get_snapshot(run["snapshot_id"])
            return {"trial": _public(trial), "attempt": _public(attempt), "run": run,
                "findings": store.list_findings(run["id"]), "events": store.list_events(run["id"], limit=100),
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

    def events(self, ident, trial_id, after=0, limit=100, attempt_no=None):
        with self.archive(ident, trial_id, attempt_no) as (store, _, _, attempt):
            events = store.list_events(attempt["run_id"], after, limit)
            return {"events": events,
                    "remaining": max(0, store.count_events(attempt["run_id"], after) - len(events))}

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
    lines = ["# Lab30 多版本 Prompt 完整审计对比", "", f"实验：{row['id']} · 状态：{row['status']}",
        "", "本报告为官方清单匹配，不等同于漏洞已通过 POC 验证；不提供现实误报率或整体 Accuracy。",
        f"共同有效轮次：{summary.get('complete_round_count', 0)}/{manifest['repeats']}。"
        + ("有效数据不足三轮，以下为初步结果。" if summary.get("preliminary", True) else "仅描述本靶场本次实验，不宣称统计显著。"),
        "", "## 冻结条件", "", f"协议：{row['protocol']} / {manifest['scoring_protocol']}；POC：关闭。",
        f"模型：{manifest['model']['model']}；thinking：{manifest['model']['thinking']}。",
        f"每次调用预算：{json.dumps(manifest['budgets'])}；每次运行总预算：{json.dumps(manifest['run_limits'])}。",
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
        "actual_total_usage": summary.get("actual_total_usage")}, ensure_ascii=False, indent=2), "```", ""]
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
    for trial in row["trials"]:
        attempts = trial.get("attempts") or [trial]
        for index, attempt in enumerate(attempts):
            reason = attempt.get("stop_reason") or {}
            trial_rows.append([trial["id"], trial["round_index"], trial["prompt_id"],
                attempt.get("attempt_no"), index == len(attempts) - 1,
                attempt["status"], attempt["evaluation_status"], attempt.get("run_id"), attempt.get("snapshot_id"),
                *[(attempt.get("score") or {}).get(key) for key in names],
                *[(attempt.get("usage") or {}).get(key) for key in usage_names], attempt.get("duration_seconds"),
                reason.get("code"), attempt.get("error")])
    tables = {"summary.csv": table(["prompt_id", "cohort_n",
            *[f"{key}_{stat}" for key in metrics for stat in stat_names],
            *[f"delta_{key}_pp_{stat}" for key in ("f1", "recall") for stat in stat_names]], summary_rows),
        "trials.csv": table(["trial_id", "round", "prompt_id", "attempt_no", "effective_attempt", "status",
            "evaluation_status", "run_id", "snapshot_id", *names, *usage_names, "duration_seconds", "stop_reason", "error"], trial_rows),
        "truth_matrix.csv": table(["truth_id", "title", "class", "prompt_id", "hits", "total"],
        [[t["id"], t["title"], t["class"], p, cell["hits"], cell["total"]] for t in summary.get("truth_matrix", []) for p, cell in t["variants"].items()])}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for filename, content in tables.items():
            archive.writestr(filename, content)
    return stream.getvalue()
