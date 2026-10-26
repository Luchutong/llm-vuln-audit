"""Run the Lab30 prompt-variant comparison from the app instead of only from a shell.

The comparison itself already exists as ``scripts/lab30_compare.py``: same frozen source,
same executor, same budgets, only the worker role text changes, and findings are scored by
location against the official ground truth.  Re-implementing that here would create a
second definition of "recall" that could drift from the one the written report quotes, so
this module *drives the existing script* and records what it produced.

Each experiment is a child process:

* it gets its own ``AUDIT_DATA_DIR`` so its imported snapshot is not mixed into the
  library the user browses, and
* it gets the model connection of the currently selected profile, so a run in the UI and a
  run in a terminal cannot silently use two different models.

Only one experiment may run at a time.  They call a real model and cost real tokens, so an
accidental double click must not double the bill.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Callable

from .db import now
from .config import clamp_budgets
from .prompt_variants import DEFAULT_ORDER, VARIANTS

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "lab30_compare.py"
SOURCE_ZIP = (
    PROJECT_ROOT
    / "llm-vuln-audit-feat-lab30-shop"
    / "llm-vuln-audit-feat-lab30-shop"
    / "lab30-shop-1.0.0-source.zip"
)

# What each variant asks the model to establish, in the words the person reading the
# comparison needs.  The prompt text itself lives in ``prompt_variants``; this is the
# catalogue entry, not a second definition.
CATALOG: tuple[dict, ...] = (
    {
        "id": "P0-lite",
        "phase": "消融",
        "label": "只报标题和行号",
        "focus": "最弱基线：不要求任何证据链，用来观察「不做要求」时的检出与误报。",
    },
    {
        "id": "P1-lite",
        "phase": "消融",
        "label": "要求指出输入与防护",
        "focus": "只要求说明输入来源和已有防护，不要求传播路径与危险操作。",
    },
    {
        "id": "P0-basic",
        "phase": "基础",
        "label": "要求危险操作行号",
        "focus": "要求给出危险操作所在原始行号，但不要求把链路写全。",
    },
    {
        "id": "P1-evidence",
        "phase": "优化",
        "label": "强制输入→传播→危险操作",
        "focus": "链上任一段无法指出就不算漏洞，并要求判断已有防护是否真正覆盖该路径。",
    },
    {
        "id": "P2-crossfile",
        "phase": "优化",
        "label": "跨文件补读 + 触发前提",
        "focus": "在 P1 之上要求补读 include 与被调函数、写明触发前提与 POC 前后对照。",
    },
)
CATALOG_BY_ID = {item["id"]: item for item in CATALOG}

SCENARIOS = ("sqli", "xss_r", "command_injection")
DEFAULT_BUDGETS = {"responses": 12, "tools": 20, "seconds": 420}
_TAIL_LINES = 40
_STAGE = re.compile(r"^=== (?P<variant>[A-Za-z0-9_-]+) ===\s*$")
_SCORED = re.compile(r"^\s+TP=(?P<tp>\d+) FP=(?P<fp>\d+) FN=(?P<fn>\d+)")


class ExperimentError(RuntimeError):
    """A request the runner refuses, with the message the UI should show."""


def catalog() -> list[dict]:
    """The variants, in the order the report presents them, with their prompt text."""
    items = []
    for variant_id in DEFAULT_ORDER:
        entry = dict(CATALOG_BY_ID[variant_id])
        entry["prompt"] = VARIANTS[variant_id]
        items.append(entry)
    return items


def _environment(settings) -> dict[str, str]:
    """The child gets the selected profile's connection.

    ``load_env_file`` never overrides a real environment variable, so whatever is set here
    wins over ``.env``.  ``PYTHONIOENCODING`` matters on Windows: the child prints Chinese
    progress lines through a pipe, and the default console codec would raise instead.
    """
    model = settings.model
    env = dict(os.environ)
    env.update({
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "LLM_MODEL": model.model,
        "LLM_BASE_URL": model.base_url,
        "LLM_API_KEY": model.api_key,
        "LLM_THINKING": model.thinking,
    })
    return env


class ExperimentRunner:
    """Owns the single in-flight child process and everything it writes."""

    def __init__(self, store, settings):
        self.store = store
        self.settings = settings
        self._task: asyncio.Task | None = None
        self._process: asyncio.subprocess.Process | None = None
        self._active_id: str | None = None
        self._closed = False
        # An interrupted comparison must not restart a paid model call implicitly, nor
        # permanently occupy the single experiment slot after the app restarts.
        self.store.fail_interrupted_prompt_experiments()
        # Import lazily: the full runner shares ExperimentError and asset paths.
        from .full_comparison import FullComparisonRunner
        self.full = FullComparisonRunner(store, settings)

    # -- queries ---------------------------------------------------------------
    def running(self) -> dict | None:
        return self.store.running_prompt_experiment()

    def list(self, limit: int = 20) -> list[dict]:
        return [self.get(row["id"]) for row in self.store.list_prompt_experiments(limit=limit)]

    def get(self, experiment_id: str) -> dict:
        row = self.store.get_prompt_experiment(experiment_id)
        if row is None:
            raise LookupError(experiment_id)
        if row.get("protocol") == "lab30-full-v2":
            return self.full.get(experiment_id)
        return row

    def start_full(self, payload) -> dict:
        if self._closed:
            raise ExperimentError("服务正在关闭，不能启动对比实验。")
        return self.full.start(payload)

    # -- lifecycle -------------------------------------------------------------
    def start(
        self,
        variants: list[str],
        units_limit: int,
        scenario: str | None,
        budgets: dict | None = None,
    ) -> dict:
        if self._closed:
            raise ExperimentError("服务正在关闭，不能启动对比实验。")
        if not SCRIPT.is_file():
            raise ExperimentError("缺少对比脚本 scripts/lab30_compare.py，无法在界面中运行。")
        source_zip = Path(os.environ.get("LAB30_SOURCE_ZIP") or SOURCE_ZIP)
        if not source_zip.is_file():
            raise ExperimentError("缺少随仓库提供的 Lab30 源码包，无法运行对比。")
        chosen = [item for item in DEFAULT_ORDER if item in set(variants)]
        if len(chosen) < 2:
            raise ExperimentError("至少选择两个版本才能对比。")
        if scenario is not None and scenario not in SCENARIOS:
            raise ExperimentError(f"未知场景：{scenario}")
        if not self.settings.model.configured:
            raise ExperimentError("尚未配置模型连接：请先在「工作空间设置」中配置并选中一个档案。")
        if self.running() is not None or (self._task is not None and not self._task.done()):
            raise ExperimentError("已有一个对比实验在运行，请等待它结束或先取消。")
        if units_limit < 0:
            raise ExperimentError("单元上限不能为负数。")

        if budgets is not None and (not isinstance(budgets, dict) or set(budgets) - set(DEFAULT_BUDGETS)):
            raise ExperimentError("预算只支持 responses、tools 和 seconds。")
        if any(type(value) is not int for value in (budgets or {}).values()):
            raise ExperimentError("预算必须是整数。")
        budgets = clamp_budgets({**DEFAULT_BUDGETS, **(budgets or {})})
        experiment_id = uuid.uuid4().hex[:16]
        workdir = Path(self.settings.data_dir) / "prompt-experiments" / experiment_id
        workdir.mkdir(parents=True, exist_ok=True)
        report = workdir / "comparison.md"
        log = workdir / "run.log"
        # Freeze the selected model and source before yielding to the event loop. A
        # profile switch after POST must not change what this experiment executes.
        child_env = self._child_env(workdir)
        child_env["LAB30_SOURCE_ZIP"] = str(source_zip.resolve())
        args = [
            sys.executable, "-u", str(SCRIPT),
            "--variants", *chosen,
            "--limit", str(units_limit),
            "--responses", str(budgets["responses"]),
            "--tools", str(budgets["tools"]),
            "--seconds", str(budgets["seconds"]),
            "--output", str(report),
        ]
        if scenario:
            args += ["--scenario", scenario]
        self.store.add_prompt_experiment({
            "id": experiment_id,
            "created_at": now(),
            "status": "running",
            "variants": chosen,
            "units_limit": units_limit,
            "scenario": scenario,
            "model": self.settings.model.label,
            "log_path": str(log),
            "report_path": str(report),
            "budgets": budgets,
        })
        self._active_id = experiment_id
        self._task = asyncio.create_task(self._run(
            experiment_id, args, workdir, log, child_env, self.settings.model.redact,
        ))
        return self.get(experiment_id)

    async def cancel(self, experiment_id: str) -> dict:
        row = self.get(experiment_id)
        if row.get("protocol") == "lab30-full-v2":
            return await self.full.cancel(experiment_id)
        if row["status"] != "running":
            return row
        task = self._task if self._active_id == experiment_id else None
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self.store.update_prompt_experiment(
            experiment_id, status="cancelled", finished_at=now(), error="已取消"
        )
        return self.get(experiment_id)

    async def shutdown(self) -> None:
        self._closed = True
        await self.full.shutdown()
        task = self._task
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        # A task cancelled before its first instruction never enters its finally block.
        if self._active_id is not None:
            row = self.get(self._active_id)
            if row["status"] == "running":
                self.store.update_prompt_experiment(
                    self._active_id, status="cancelled", finished_at=now(), error="服务关闭时中断"
                )

    @staticmethod
    async def _terminate(process: asyncio.subprocess.Process | None) -> None:
        if process is None:
            return
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                # Drain output even after a malformed/oversized line. Waiting without
                # draining PIPE can hang forever with a full subprocess buffer.
                await asyncio.wait_for(process.communicate(), timeout=10)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                await process.communicate()
        await process.wait()

    # -- the child -------------------------------------------------------------
    async def _run(
        self, experiment_id: str, args: list[str], workdir: Path, log: Path,
        child_env: dict[str, str], redact: Callable[[object], str],
    ) -> None:
        tail: list[str] = []
        finished: list[dict] = []
        current: str | None = None
        process: asyncio.subprocess.Process | None = None
        terminal: dict = {}
        try:
            if self.get(experiment_id)["status"] != "running":
                return
            # Shield creation so cancellation in the spawn window cannot lose the
            # process handle. We then reap it before releasing the experiment slot.
            spawning = asyncio.create_task(asyncio.create_subprocess_exec(
                *args,
                cwd=str(PROJECT_ROOT),
                env=child_env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            ))
            try:
                process = await asyncio.shield(spawning)
            except asyncio.CancelledError:
                process = await spawning
                raise
            self._process = process
            assert process.stdout is not None
            with log.open("w", encoding="utf-8") as handle:
                while True:
                    raw = await process.stdout.readline()
                    if not raw:
                        break
                    line = redact(raw.decode("utf-8", "replace").rstrip("\r\n"))
                    handle.write(line + "\n")
                    handle.flush()
                    tail.append(line)
                    del tail[:-_TAIL_LINES]
                    match = _STAGE.match(line)
                    if match:
                        current = match.group("variant")
                    scored = _SCORED.match(line)
                    if scored and current:
                        finished.append({
                            "variant": current,
                            "TP": int(scored.group("tp")),
                            "FP": int(scored.group("fp")),
                            "FN": int(scored.group("fn")),
                        })
                        current = None
                    self.store.update_prompt_experiment(experiment_id, progress={
                        "current": current,
                        "done": finished,
                        "tail": tail,
                    })
            code = await process.wait()
            # A cancelled experiment was already settled by ``cancel``.
            if self.get(experiment_id)["status"] != "running":
                return
            if code != 0:
                terminal = dict(
                    status="failed", finished_at=now(),
                    error=f"对比脚本退出码 {code}；最后输出：{tail[-1] if tail else '（无输出）'}",
                )
                return
            rows_path = Path(self.get(experiment_id)["report_path"]).with_suffix(".json")
            rows = json.loads(rows_path.read_text(encoding="utf-8")) if rows_path.is_file() else []
            terminal = dict(
                status="completed", finished_at=now(),
                rows=rows,
                progress={"current": None, "done": finished, "tail": tail},
            )
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            terminal = dict(status="cancelled", finished_at=now(), error="对比已中断")
        except Exception as exc:  # a failed experiment must never take the app down
            terminal = dict(
                status="failed", finished_at=now(),
                error=redact(f"{type(exc).__name__}: {exc}"),
            )
        finally:
            await self._terminate(process)
            if terminal and self.get(experiment_id)["status"] == "running":
                self.store.update_prompt_experiment(experiment_id, **terminal)
            self._process = None

    def _child_env(self, workdir: Path) -> dict[str, str]:
        env = _environment(self.settings)
        # Its own data directory: the snapshot this child imports must not appear in the
        # library the user browses, and its snapshot ids must not collide with real runs.
        env["AUDIT_DATA_DIR"] = str(workdir / "audit-data")
        if not env.get("LAB30_SOURCE_ZIP"):
            env["LAB30_SOURCE_ZIP"] = str(SOURCE_ZIP)
        return env
