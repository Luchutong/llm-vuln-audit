"""SQLite persistence: runs, frozen unit queues, findings, verifications, events.

One process holds one connection guarded by a lock. Events are append-only and carry
a monotonic id, which is the cursor the SSE endpoint resumes from.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS snapshots (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    archive_sha256 TEXT NOT NULL,
    source TEXT NOT NULL,
    file_count INTEGER NOT NULL DEFAULT 0,
    unit_count INTEGER NOT NULL DEFAULT 0,
    warning_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    snapshot_name TEXT NOT NULL,
    scope TEXT NOT NULL,
    prompt_id TEXT NOT NULL,
    prompt_label TEXT NOT NULL,
    prompt_text TEXT NOT NULL,
    model TEXT NOT NULL,
    budgets TEXT NOT NULL,
    agent_policy TEXT,
    task_spec TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS run_units (
    run_id TEXT NOT NULL,
    unit_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    symbol TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    status TEXT NOT NULL,
    result TEXT,
    error TEXT,
    usage TEXT,
    seen TEXT,
    finished_at TEXT,
    -- The unit exactly as it was frozen when the run was created, cleaned slice included.
    -- The queue must be self-contained: the text handed to the model cannot depend on the
    -- snapshot index being re-read, or two runs over "the same snapshot" could differ.
    unit_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (run_id, unit_id)
);
CREATE INDEX IF NOT EXISTS idx_run_units_status ON run_units(run_id, status, ordinal);

-- Goal mode follows the same durable-queue shape as ARTEX: the goal is the
-- coordinator's source of truth, while workers only claim and resolve one work item.
-- The legacy run_units queue remains unchanged so historic three-category experiments
-- stay reproducible.
CREATE TABLE IF NOT EXISTS task_goals (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    objective TEXT NOT NULL,
    success_criteria TEXT NOT NULL,
    max_iterations INTEGER NOT NULL,
    max_total_attempts INTEGER NOT NULL DEFAULT 24,
    status TEXT NOT NULL DEFAULT 'open',
    attempts INTEGER NOT NULL DEFAULT 0,
    terminal_reason TEXT,
    reached_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_goals_run ON task_goals(run_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_task_goals_one_per_run ON task_goals(run_id);

CREATE TABLE IF NOT EXISTS task_work_items (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    unit_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    summary TEXT NOT NULL,
    focus TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'open',
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    claimed_by TEXT,
    claimed_at TEXT,
    result TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE (run_id, goal_id, unit_id)
);
CREATE INDEX IF NOT EXISTS idx_task_work_claim ON task_work_items(run_id, goal_id, state, priority DESC, ordinal);

-- Work rows carry the latest state for scheduling.  This append-only log keeps the
-- evidence, usage and worker identity for every pass, so an exhausted task can be
-- reviewed instead of merely asserted.
CREATE TABLE IF NOT EXISTS task_work_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    work_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    worker_id TEXT,
    outcome TEXT NOT NULL,
    state TEXT NOT NULL,
    result TEXT NOT NULL,
    usage TEXT,
    seen TEXT NOT NULL DEFAULT '[]',
    error TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (work_id, attempt)
);
CREATE INDEX IF NOT EXISTS idx_task_work_attempts_work ON task_work_attempts(work_id, attempt);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    unit_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence TEXT NOT NULL,
    input_source TEXT NOT NULL,
    propagation TEXT NOT NULL,
    dangerous_operation TEXT NOT NULL,
    protection TEXT NOT NULL,
    preconditions TEXT NOT NULL,
    missing_context TEXT NOT NULL,
    poc TEXT NOT NULL,
    remediation TEXT NOT NULL,
    validation_state TEXT NOT NULL DEFAULT 'candidate',
    validation_errors TEXT NOT NULL DEFAULT '[]',
    verdict TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (run_id, unit_id, category)
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id, created_at);

CREATE TABLE IF NOT EXISTS verifications (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    execution_status TEXT NOT NULL,
    verdict TEXT NOT NULL,
    original_script TEXT NOT NULL,
    modified_script TEXT NOT NULL,
    modification_notes TEXT NOT NULL,
    target_version TEXT NOT NULL,
    command TEXT NOT NULL,
    expected_result TEXT NOT NULL,
    normal_observation TEXT NOT NULL,
    attack_observation TEXT NOT NULL,
    browser_execution INTEGER NOT NULL DEFAULT 0,
    notes TEXT NOT NULL,
    files TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_verifications_finding ON verifications(finding_id, created_at);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    unit_id TEXT,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, id);

CREATE TABLE IF NOT EXISTS prompts (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    issues TEXT NOT NULL DEFAULT '[]',
    parent_id TEXT,
    builtin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS truths (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    category TEXT NOT NULL,
    vulnerable INTEGER NOT NULL,
    independently_verified INTEGER NOT NULL DEFAULT 0,
    verification_basis TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    UNIQUE (snapshot_id, file_path, category)
);

CREATE TABLE IF NOT EXISTS attributions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    category TEXT NOT NULL,
    kind TEXT NOT NULL,
    cause TEXT NOT NULL DEFAULT '',
    check_item TEXT NOT NULL DEFAULT '',
    finding_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attributions_run ON attributions(run_id, created_at);

CREATE TABLE IF NOT EXISTS model_health (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    model TEXT NOT NULL DEFAULT '',
    fails INTEGER NOT NULL DEFAULT 0,
    trips INTEGER NOT NULL DEFAULT 0,
    open_until REAL NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    last_at REAL NOT NULL DEFAULT 0
);
"""

RUN_TERMINAL = ("completed", "unreachable", "inconclusive", "cancelled", "interrupted", "failed")
UNIT_INCOMPLETE = ("incomplete", "failed", "skipped")
DEFAULT_TASK_MAX_TOTAL_ATTEMPTS = 24

# A worker may ask for another source-analysis direction (a genuine ``continue``),
# or it may be unable to obtain a usable model result at all.  Both retry through
# the same durable work row, but exhausting the latter cannot prove the requested
# source property is absent.  Keep it as a blocked observation so the coordinator
# reaches ``inconclusive`` rather than ``unreachable``.
TASK_RETRY_FAILURE_REASONS = frozenset(
    {"model_error", "request_timeout", "timeout", "budget", "invalid_output"}
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _loads(value: Any, fallback: Any) -> Any:
    if value in (None, ""):
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(SCHEMA)
            self._migrate()

    # Additive migrations so a database written by an earlier build keeps working.
    _ADDED_COLUMNS = {
        "run_units": {"unit_json": "TEXT NOT NULL DEFAULT '{}'"},
        "runs": {"agent_policy": "TEXT", "task_spec": "TEXT"},
        "task_goals": {
            "max_total_attempts": f"INTEGER NOT NULL DEFAULT {DEFAULT_TASK_MAX_TOTAL_ATTEMPTS}"
        },
    }

    def _migrate(self) -> None:
        for table, columns in self._ADDED_COLUMNS.items():
            existing = {row["name"] for row in self._rows(f"PRAGMA table_info({table})")}
            for name, declaration in columns.items():
                if name not in existing:
                    self._db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _rows(self, sql: str, params: Iterable = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, tuple(params)).fetchall()

    def _row(self, sql: str, params: Iterable = ()) -> sqlite3.Row | None:
        rows = self._rows(sql, params)
        return rows[0] if rows else None

    def _write(self, sql: str, params: Iterable = ()) -> None:
        with self._lock:
            self._db.execute(sql, tuple(params))

    # --- snapshots ---------------------------------------------------------

    def add_snapshot(self, snapshot: dict) -> None:
        self._write(
            "INSERT OR REPLACE INTO snapshots (id, name, created_at, archive_sha256, source,"
            " file_count, unit_count, warning_count) VALUES (?,?,?,?,?,?,?,?)",
            (
                snapshot["id"],
                snapshot["name"],
                snapshot["created_at"],
                snapshot["archive_sha256"],
                snapshot["source"],
                len(snapshot.get("files", [])),
                len(snapshot.get("units", [])),
                len(snapshot.get("warnings", [])),
            ),
        )

    def list_snapshots(self) -> list[dict]:
        return [dict(row) for row in self._rows("SELECT * FROM snapshots ORDER BY created_at DESC")]

    def get_snapshot(self, snapshot_id: str) -> dict | None:
        row = self._row("SELECT * FROM snapshots WHERE id = ?", (snapshot_id,))
        return dict(row) if row else None

    # --- runs --------------------------------------------------------------

    def create_run(self, run: dict, units: list[dict]) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.execute(
                    "INSERT INTO runs (id, snapshot_id, snapshot_name, scope, prompt_id, prompt_label,"
                    " prompt_text, model, budgets, status, created_at, agent_policy, task_spec) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        run["id"],
                        run["snapshot_id"],
                        run["snapshot_name"],
                        _dumps(run["scope"]),
                        run["prompt_id"],
                        run["prompt_label"],
                        run["prompt_text"],
                        run["model"],
                        _dumps(run["budgets"]),
                        "pending",
                        run["created_at"],
                        _dumps(run["agent_policy"]) if run.get("agent_policy") else None,
                        _dumps(run["task_spec"]) if run.get("task_spec") else None,
                    ),
                )
                self._db.executemany(
                    "INSERT INTO run_units (run_id, unit_id, ordinal, file_path, symbol, start_line,"
                    " end_line, priority, status, unit_json) VALUES (?,?,?,?,?,?,?,?, 'pending', ?)",
                    [
                        (
                            run["id"],
                            unit["id"],
                            index,
                            unit["file_path"],
                            unit["symbol"],
                            unit["start_line"],
                            unit["end_line"],
                            unit["priority"],
                            _dumps(unit),
                        )
                        for index, unit in enumerate(units)
                    ],
                )
                task = run.get("task_spec") or None
                if task:
                    goal_id = uuid.uuid4().hex
                    created_at = now()
                    self._db.execute(
                        "INSERT INTO task_goals (id, run_id, objective, success_criteria, max_iterations, max_total_attempts, status,"
                        " attempts, created_at, updated_at) VALUES (?,?,?,?,?,?,'open',0,?,?)",
                        (
                            goal_id,
                            run["id"],
                            task["objective"],
                            task["success_criteria"],
                            int(task["max_iterations"]),
                            int(task.get("max_total_attempts", DEFAULT_TASK_MAX_TOTAL_ATTEMPTS)),
                            created_at,
                            created_at,
                        ),
                    )
                    self._db.executemany(
                        "INSERT INTO task_work_items (id, run_id, goal_id, unit_id, ordinal, summary, priority,"
                        " state, max_attempts, created_at) VALUES (?,?,?,?,?,?,?,'open',?,?)",
                        [
                            (
                                uuid.uuid4().hex,
                                run["id"],
                                goal_id,
                                unit["id"],
                                index,
                                f"分析 {unit['file_path']}:{unit['start_line']}-{unit['end_line']}（{unit['symbol']}）",
                                int(unit["priority"]),
                                int(task["max_iterations"]),
                                created_at,
                            )
                            for index, unit in enumerate(units)
                        ],
                    )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def _run_dict(self, row: sqlite3.Row) -> dict:
        run = dict(row)
        run["scope"] = _loads(run.get("scope"), [])
        run["budgets"] = _loads(run.get("budgets"), {})
        run["agent_policy"] = _loads(run.get("agent_policy"), {"version": "legacy"})
        task_spec = _loads(run.get("task_spec"), None)
        # Task runs created before the total-cap field was introduced still have a
        # durable goal row migrated with this default. Reflect the same frozen value
        # in their public TaskSpec so the worker, report and UI agree.
        if isinstance(task_spec, dict):
            task_spec.setdefault("max_total_attempts", DEFAULT_TASK_MAX_TOTAL_ATTEMPTS)
            task_spec.setdefault("require_poc", True)
        run["task_spec"] = task_spec
        counts = self._row(
            "SELECT COUNT(*) AS total,"
            " SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed"
            " FROM run_units WHERE run_id = ?",
            (run["id"],),
        )
        run["total_units"] = int(counts["total"] or 0) if counts else 0
        run["completed_units"] = int(counts["completed"] or 0) if counts else 0
        usage = self._row(
            "SELECT COALESCE(SUM(json_extract(usage, '$.requests')), 0) AS requests,"
            " COALESCE(SUM(json_extract(usage, '$.tool_calls')), 0) AS tool_calls,"
            " COALESCE(SUM(json_extract(usage, '$.input_tokens')), 0) AS input_tokens,"
            " COALESCE(SUM(json_extract(usage, '$.output_tokens')), 0) AS output_tokens"
            " FROM run_units WHERE run_id = ? AND usage IS NOT NULL",
            (run["id"],),
        )
        run["usage"] = {
            "requests": int(usage["requests"] or 0) if usage else 0,
            "tool_calls": int(usage["tool_calls"] or 0) if usage else 0,
            "input_tokens": int(usage["input_tokens"] or 0) if usage else 0,
            "output_tokens": int(usage["output_tokens"] or 0) if usage else 0,
        }
        return run

    def list_runs(self) -> list[dict]:
        return [self._run_dict(row) for row in self._rows("SELECT * FROM runs ORDER BY created_at DESC")]

    def get_run(self, run_id: str) -> dict | None:
        row = self._row("SELECT * FROM runs WHERE id = ?", (run_id,))
        return self._run_dict(row) if row else None

    def update_run(self, run_id: str, **fields: Any) -> None:
        allowed = {"status", "started_at", "finished_at", "error"}
        updates = {name: value for name, value in fields.items() if name in allowed}
        if not updates:
            return
        clause = ", ".join(f"{name} = ?" for name in updates)
        self._write(f"UPDATE runs SET {clause} WHERE id = ?", (*updates.values(), run_id))

    def claim_next_run(self) -> dict | None:
        """Atomically move the oldest pending run to running."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT id FROM runs WHERE status = 'pending' ORDER BY created_at LIMIT 1"
                ).fetchone()
                if row is None:
                    self._db.execute("COMMIT")
                    return None
                self._db.execute(
                    "UPDATE runs SET status = 'running', started_at = ? WHERE id = ?",
                    (now(), row["id"]),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.get_run(row["id"])

    def request_cancel(self, run_id: str) -> None:
        # Running runs are stopped by the worker; pending runs never start.
        self._write(
            "UPDATE runs SET status = 'cancelled', finished_at = ? WHERE id = ? AND status IN ('pending','running')",
            (now(), run_id),
        )

    def interrupt_stale_runs(self) -> int:
        """Repair work left unresolved by a process that stopped between writes."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                stale = [row["id"] for row in self._db.execute("SELECT id FROM runs WHERE status = 'running'")]
                if stale:
                    marks = ",".join("?" for _ in stale)
                    self._db.execute(
                        f"UPDATE runs SET status = 'interrupted', finished_at = ?,"
                        f" error = 'Server restarted while this run was in flight'"
                        f" WHERE id IN ({marks})",
                        (now(), *stale),
                    )
                    # Whatever was still queued will never run: the worker that owned the queue
                    # is gone. Leaving it `pending` would keep it listed as "about to start" in a
                    # run that has already finished, and `pending` is one of the unresolved
                    # statuses that keeps a truth sample out of the confusion matrix.
                    self._db.execute(
                        f"UPDATE run_units SET status = 'skipped', error = 'Run interrupted before this unit started',"
                        f" finished_at = ? WHERE run_id IN ({marks}) AND status = 'pending'",
                        (now(), *stale),
                    )
                # Sweep every unit still marked running, not only those of the runs just
                # interrupted: a run cancelled and then hard-killed leaves the same orphan, and
                # nothing will ever come back to move it.
                self._db.execute(
                    "UPDATE run_units SET status = 'incomplete', error = 'Run interrupted by server restart',"
                    " finished_at = ? WHERE status = 'running'",
                    (now(),),
                )
                # A cancel/failure state can be committed just before the process dies. Repair
                # its still-pending queue on the next boot so terminal runs never retain work
                # that no worker will claim.
                self._db.execute(
                    "UPDATE run_units SET status = 'skipped', error = 'Run ended before this unit started',"
                    " finished_at = ? WHERE status = 'pending' AND run_id IN ("
                    "SELECT id FROM runs WHERE status IN ('cancelled', 'interrupted', 'failed', 'completed', 'unreachable', 'inconclusive'))",
                    (now(),),
                )
                # Goal-mode workers claim a separate durable work queue. A restart must
                # repair it in lockstep with run_units so no terminal run retains an
                # open/running intent that a future worker could accidentally revive.
                self._db.execute(
                    "UPDATE task_work_items SET state = 'blocked', error = 'Run interrupted by server restart',"
                    " finished_at = ? WHERE state = 'running'",
                    (now(),),
                )
                self._db.execute(
                    "UPDATE task_work_items SET state = 'skipped', error = 'Run ended before this work item started',"
                    " finished_at = ? WHERE state = 'open' AND run_id IN ("
                    "SELECT id FROM runs WHERE status IN ('cancelled', 'interrupted', 'failed', 'completed', 'unreachable', 'inconclusive'))",
                    (now(),),
                )
                self._db.execute(
                    "UPDATE task_goals SET status = 'inconclusive',"
                    " terminal_reason = '运行在目标完成前被中断或终止', updated_at = ? "
                    "WHERE (status = 'open' AND run_id IN ("
                    "SELECT id FROM runs WHERE status IN ('cancelled', 'interrupted', 'failed', 'completed', 'unreachable', 'inconclusive'))) "
                    "OR (status IN ('unreachable', 'inconclusive') AND run_id IN ("
                    "SELECT id FROM runs WHERE status IN ('cancelled', 'interrupted', 'failed')))",
                    (now(),),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            return len(stale)

    # --- run units ---------------------------------------------------------

    def list_run_units(self, run_id: str) -> list[dict]:
        rows = self._rows("SELECT * FROM run_units WHERE run_id = ? ORDER BY ordinal", (run_id,))
        return [self._unit_dict(row) for row in rows]

    # The frozen slice text is only needed to run a unit, not to list it: a run over a large
    # snapshot would otherwise ship megabytes of cleaned source into every API response.
    HEAVY_UNIT_FIELDS = ("cleaned_lines", "omissions")

    def _unit_dict(self, row: sqlite3.Row, *, full: bool = False) -> dict:
        unit = dict(row)
        unit["result"] = _loads(unit.get("result"), None)
        unit["usage"] = _loads(unit.get("usage"), None)
        unit["seen"] = _loads(unit.get("seen"), [])
        frozen = _loads(unit.pop("unit_json", None), {}) or {}
        if not full:
            for name in self.HEAVY_UNIT_FIELDS:
                frozen.pop(name, None)
        # Columns win: they are the queue's own record of ordering and status.
        unit = {**frozen, **unit}
        return unit

    def get_run_unit(self, run_id: str, unit_id: str) -> dict | None:
        row = self._row("SELECT * FROM run_units WHERE run_id = ? AND unit_id = ?", (run_id, unit_id))
        return self._unit_dict(row, full=True) if row else None

    def next_pending_unit(self, run_id: str) -> dict | None:
        row = self._row(
            "SELECT * FROM run_units WHERE run_id = ? AND status = 'pending' ORDER BY ordinal LIMIT 1",
            (run_id,),
        )
        return self._unit_dict(row, full=True) if row else None

    def mark_unit_running(self, run_id: str, unit_id: str) -> None:
        self._write(
            "UPDATE run_units SET status = 'running' WHERE run_id = ? AND unit_id = ?", (run_id, unit_id)
        )

    def checkpoint_unit(self, run_id: str, unit_id: str, *, result: Any, usage: Any, seen: Any) -> None:
        self._write(
            "UPDATE run_units SET result = ?, usage = ?, seen = ? WHERE run_id = ? AND unit_id = ? AND status = 'running'",
            (_dumps(result), _dumps(usage), _dumps(seen), run_id, unit_id),
        )

    def finish_unit(
        self,
        run_id: str,
        unit_id: str,
        status: str,
        *,
        result: Any = None,
        usage: Any = None,
        seen: Any = None,
        error: str | None = None,
    ) -> None:
        self._write(
            "UPDATE run_units SET status = ?, result = ?, usage = ?, seen = ?, error = ?, finished_at = ?"
            " WHERE run_id = ? AND unit_id = ?",
            (
                status,
                _dumps(result) if result is not None else None,
                _dumps(usage) if usage is not None else None,
                _dumps(seen or []),
                error,
                now(),
                run_id,
                unit_id,
            ),
        )

    def abandon_pending_units(self, run_id: str, reason: str) -> None:
        # The current unit and its remaining queue must transition together. With
        # autocommit enabled, two ordinary writes could strand a terminal run with
        # `pending` units if the process stopped after the first one.
        with self._lock:
            self._db.execute("BEGIN")
            try:
                ended_at = now()
                self._db.execute(
                    "UPDATE run_units SET status = 'incomplete', error = ?, finished_at = ?"
                    " WHERE run_id = ? AND status = 'running'",
                    (reason, ended_at, run_id),
                )
                self._db.execute(
                    "UPDATE run_units SET status = 'skipped', error = ?, finished_at = ?"
                    " WHERE run_id = ? AND status = 'pending'",
                    (reason, ended_at, run_id),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    # --- goal-task queue --------------------------------------------------

    @staticmethod
    def _goal_dict(row: sqlite3.Row) -> dict:
        return dict(row)

    @staticmethod
    def _task_work_dict(row: sqlite3.Row) -> dict:
        work = dict(row)
        work["result"] = _loads(work.get("result"), None)
        return work

    def list_task_goals(self, run_id: str) -> list[dict]:
        rows = self._rows("SELECT * FROM task_goals WHERE run_id = ? ORDER BY created_at", (run_id,))
        return [self._goal_dict(row) for row in rows]

    def get_task_goal(self, run_id: str) -> dict | None:
        row = self._row("SELECT * FROM task_goals WHERE run_id = ? ORDER BY created_at LIMIT 1", (run_id,))
        return self._goal_dict(row) if row else None

    def list_task_work_items(self, run_id: str) -> list[dict]:
        rows = self._rows(
            "SELECT * FROM task_work_items WHERE run_id = ? ORDER BY ordinal, created_at", (run_id,)
        )
        work_items = [self._task_work_dict(row) for row in rows]
        for work in work_items:
            work["attempt_history"] = self.list_task_work_attempts(work["id"])
        return work_items

    def get_task_work_item(self, work_id: str) -> dict | None:
        row = self._row("SELECT * FROM task_work_items WHERE id = ?", (work_id,))
        if row is None:
            return None
        work = self._task_work_dict(row)
        work["attempt_history"] = self.list_task_work_attempts(work_id)
        return work

    def list_task_work_attempts(self, work_id: str) -> list[dict]:
        rows = self._rows(
            "SELECT * FROM task_work_attempts WHERE work_id = ? ORDER BY attempt, id", (work_id,)
        )
        attempts: list[dict] = []
        for row in rows:
            attempt = dict(row)
            attempt["result"] = _loads(attempt.get("result"), {})
            attempt["usage"] = _loads(attempt.get("usage"), None)
            attempt["seen"] = _loads(attempt.get("seen"), [])
            attempts.append(attempt)
        return attempts

    def claim_next_task_work(self, run_id: str, worker_id: str) -> dict | None:
        """Atomically lease one open goal-task work item to a named worker.

        The conditional lookup and transition share a SQLite write transaction.  This
        is the important boundary for the worker pool: two asyncio tasks may wake at
        the same time, but only one can receive a particular intent.  The same
        transaction reserves one of the task-wide attempt slots for the lease, so a
        concurrent pool cannot overshoot the frozen total-attempt cap.
        """
        work_id: str | None = None
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                goal = self._db.execute(
                    "SELECT g.id, g.status, g.attempts, g.max_total_attempts FROM task_goals AS g "
                    "JOIN runs AS r ON r.id = g.run_id "
                    "WHERE g.run_id = ? AND r.status = 'running' ORDER BY g.created_at LIMIT 1",
                    (run_id,),
                ).fetchone()
                if goal is None or goal["status"] not in ("open", "met"):
                    self._db.execute("COMMIT")
                    return None
                active = self._db.execute(
                    "SELECT COUNT(*) AS total FROM task_work_items WHERE goal_id = ? AND state = 'running'",
                    (goal["id"],),
                ).fetchone()
                attempts_in_play = int(goal["attempts"] or 0) + int(active["total"] or 0)
                max_total_attempts = int(goal["max_total_attempts"] or 0)
                if attempts_in_play >= max_total_attempts:
                    # Do not leave rows open after the task-wide cap has already
                    # been reserved by settled or in-flight attempts.  Any running
                    # rows still get to persist their result; once they finish,
                    # settle_task_goal_if_idle decides unreachable vs inconclusive.
                    ended_at = now()
                    retry_blocked = []
                    for pending in self._db.execute(
                        "SELECT id, unit_id, result FROM task_work_items "
                        "WHERE run_id = ? AND goal_id = ? AND state = 'open'",
                        (run_id, goal["id"]),
                    ).fetchall():
                        prior = _loads(pending["result"], {}) or {}
                        if str(prior.get("terminal_reason") or "") in TASK_RETRY_FAILURE_REASONS:
                            retry_blocked.append(pending)

                    # A normal `continue` can be bounded by the task-wide search
                    # cap. A row whose only prior result was a provider/output/
                    # budget failure cannot: it was waiting to retry an execution
                    # problem, not asking for another source direction. Keep those
                    # rows blocked so their task resolves inconclusive.
                    retry_reason = (
                        f"任务级最大尝试次数 {max_total_attempts} 已达到；"
                        "上一次未取得可用模型结论，不能据此判定目标不可达"
                    )
                    if retry_blocked:
                        self._db.executemany(
                            "UPDATE task_work_items SET state = 'blocked', error = ?, finished_at = ? "
                            "WHERE id = ? AND state = 'open'",
                            [(retry_reason, ended_at, pending["id"]) for pending in retry_blocked],
                        )
                        self._db.executemany(
                            "UPDATE run_units SET status = 'incomplete', error = ?, finished_at = ? "
                            "WHERE run_id = ? AND unit_id = ? AND status = 'pending'",
                            [
                                (retry_reason, ended_at, run_id, pending["unit_id"])
                                for pending in retry_blocked
                            ],
                        )

                    reason = f"任务级最大尝试次数 {max_total_attempts} 已达到，未领取工作项停止"
                    self._db.execute(
                        "UPDATE task_work_items SET state = 'skipped', error = ?, finished_at = ? "
                        "WHERE run_id = ? AND goal_id = ? AND state = 'open'",
                        (reason, ended_at, run_id, goal["id"]),
                    )
                    self._db.execute(
                        "UPDATE run_units SET status = 'skipped', error = ?, finished_at = ? "
                        "WHERE run_id = ? AND status = 'pending' AND unit_id IN ("
                        "SELECT unit_id FROM task_work_items WHERE run_id = ? AND goal_id = ? AND state = 'skipped')",
                        (reason, ended_at, run_id, run_id, goal["id"]),
                    )
                    self._db.execute("COMMIT")
                    return None
                row = self._db.execute(
                    "SELECT w.id, w.unit_id FROM task_work_items AS w "
                    "JOIN task_goals AS g ON g.id = w.goal_id "
                    "JOIN runs AS r ON r.id = w.run_id "
                    "WHERE w.run_id = ? AND w.state = 'open' "
                    "AND w.goal_id = ? AND g.status IN ('open', 'met') AND r.status = 'running' "
                    "ORDER BY w.priority DESC, w.ordinal, w.created_at LIMIT 1",
                    (run_id, goal["id"]),
                ).fetchone()
                if row is None:
                    self._db.execute("COMMIT")
                    return None
                claimed_at = now()
                self._db.execute(
                    "UPDATE task_work_items SET state = 'running', claimed_by = ?, claimed_at = ? "
                    "WHERE id = ? AND state = 'open'",
                    (worker_id, claimed_at, row["id"]),
                )
                self._db.execute(
                    "UPDATE run_units SET status = 'running' WHERE run_id = ? AND unit_id = ? "
                    "AND status = 'pending'",
                    (run_id, row["unit_id"]),
                )
                work_id = str(row["id"])
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.get_task_work_item(work_id) if work_id else None

    def resolve_task_work(
        self,
        work_id: str,
        *,
        outcome: str,
        result: dict | None,
        usage: dict | None,
        seen: list | None,
        error: str | None = None,
        finding: dict | None = None,
        stop_on_achieved: bool = True,
        goal_reason: str | None = None,
    ) -> dict | None:
        """Resolve a leased work item, its evidence and goal transition atomically.

        In particular, an achieved result cannot be committed while leaving its goal
        open.  The same transaction persists the finding, closes the work item,
        records the attempt, marks the goal met and (when configured) skips work that
        has not started yet.
        """
        if outcome not in {"achieved", "continue", "no_evidence", "blocked"}:
            raise ValueError(f"unsupported task outcome: {outcome}")
        if outcome == "achieved" and finding is None:
            raise ValueError("achieved task work requires a validated finding")

        goal_met = False
        finding_id: str | None = None
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM task_work_items WHERE id = ?", (work_id,)
                ).fetchone()
                if row is None or row["state"] != "running":
                    self._db.execute("COMMIT")
                    return None
                goal = self._db.execute(
                    "SELECT status FROM task_goals WHERE id = ? AND run_id = ?",
                    (row["goal_id"], row["run_id"]),
                ).fetchone()
                if goal is None:
                    raise RuntimeError("task work has no owning goal")

                attempt = int(row["attempt"] or 0) + 1
                stored_result = dict(result or {})
                stored_result["outcome"] = outcome
                stored_result["attempt"] = attempt
                state = "done"
                unit_status = "completed"
                focus = row["focus"] or ""
                finished_at: str | None = now()
                claimed_by: str | None = row["claimed_by"]
                claimed_at: str | None = row["claimed_at"]
                stored_error = error

                if outcome == "continue":
                    next_focus = str(stored_result.get("next_focus") or "").strip()
                    if attempt < int(row["max_attempts"]):
                        state = "open"
                        unit_status = "pending"
                        focus = next_focus or focus
                        finished_at = None
                        claimed_by = None
                        claimed_at = None
                    else:
                        failure_reason = str(stored_result.get("terminal_reason") or "")
                        if failure_reason in TASK_RETRY_FAILURE_REASONS:
                            state = "blocked"
                            unit_status = "incomplete"
                            stored_result["retry_exhausted"] = True
                            stored_error = stored_error or (
                                f"工作项在 {failure_reason} 后达到最大重试次数，无法据此判定目标不可达"
                            )
                        else:
                            state = "exhausted"
                            stored_result["terminal_reason"] = "attempts_exhausted"
                            stored_error = stored_error or "工作项已达到最大尝试次数"
                elif outcome == "blocked":
                    state = "blocked"
                    unit_status = "incomplete"
                    stored_error = stored_error or str(
                        stored_result.get("terminal_reason") or "工作项缺少继续分析所需的上下文"
                    )

                # A different in-flight worker can reach the goal while this one is
                # waiting on a model response.  Do not revive its queue item on the
                # way out: retain the attempt log, but close the lease with the same
                # stop decision that skipped work which had not started yet.
                if goal["status"] == "met" and stop_on_achieved:
                    state = "skipped"
                    unit_status = "skipped"
                    stored_error = stored_error or "目标已满足，执行中的工作项停止"

                if finding is not None:
                    self._insert_finding(finding)
                    finding_id = str(finding["id"])

                self._db.execute(
                    "UPDATE task_work_items SET state = ?, attempt = ?, focus = ?, claimed_by = ?, claimed_at = ?,"
                    " result = ?, error = ?, finished_at = ? WHERE id = ?",
                    (
                        state,
                        attempt,
                        focus,
                        claimed_by,
                        claimed_at,
                        _dumps(stored_result),
                        stored_error,
                        finished_at,
                        work_id,
                    ),
                )
                self._db.execute(
                    "UPDATE run_units SET status = ?, result = ?, usage = ?, seen = ?, error = ?, finished_at = ?"
                    " WHERE run_id = ? AND unit_id = ?",
                    (
                        unit_status,
                        _dumps(stored_result),
                        _dumps(usage) if usage is not None else None,
                        _dumps(seen or []),
                        stored_error,
                        finished_at,
                        row["run_id"],
                        row["unit_id"],
                    ),
                )
                self._db.execute(
                    "UPDATE task_goals SET attempts = attempts + 1, updated_at = ? WHERE id = ?",
                    (now(), row["goal_id"]),
                )
                self._db.execute(
                    "INSERT INTO task_work_attempts (work_id, run_id, goal_id, attempt, worker_id, outcome,"
                    " state, result, usage, seen, error, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        work_id,
                        row["run_id"],
                        row["goal_id"],
                        attempt,
                        row["claimed_by"],
                        outcome,
                        state,
                        _dumps(stored_result),
                        _dumps(usage) if usage is not None else None,
                        _dumps(seen or []),
                        stored_error,
                        now(),
                    ),
                )
                if outcome == "achieved":
                    goal_met = bool(
                        self._db.execute(
                            "UPDATE task_goals SET status = 'met', terminal_reason = ?, reached_by = ?, updated_at = ? "
                            "WHERE id = ? AND run_id = ? AND status = 'open'",
                            (
                                goal_reason or stored_result.get("summary") or "已取得有证据的目标发现",
                                work_id,
                                now(),
                                row["goal_id"],
                                row["run_id"],
                            ),
                        ).rowcount
                    )
                    if goal_met and stop_on_achieved:
                        ended_at = now()
                        self._db.execute(
                            "UPDATE task_work_items SET state = 'skipped', error = ?, finished_at = ? "
                            "WHERE run_id = ? AND goal_id = ? AND state = 'open'",
                            ("目标已满足，未领取工作项停止", ended_at, row["run_id"], row["goal_id"]),
                        )
                        self._db.execute(
                            "UPDATE run_units SET status = 'skipped', error = ?, finished_at = ? "
                            "WHERE run_id = ? AND status = 'pending' AND unit_id IN ("
                            "SELECT unit_id FROM task_work_items WHERE run_id = ? AND goal_id = ? AND state = 'skipped')",
                            (
                                "目标已满足，未领取工作项停止",
                                ended_at,
                                row["run_id"],
                                row["run_id"],
                                row["goal_id"],
                            ),
                        )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        resolved = self.get_task_work_item(work_id)
        if resolved is not None:
            resolved["goal_met"] = goal_met
            resolved["finding_id"] = finding_id
        return resolved

    def settle_task_goal_if_idle(self, run_id: str) -> dict | None:
        """Close a goal only after its complete shared queue has stopped moving."""
        goal_id: str | None = None
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                goal = self._db.execute(
                    "SELECT * FROM task_goals WHERE run_id = ? ORDER BY created_at LIMIT 1", (run_id,)
                ).fetchone()
                if goal is None:
                    self._db.execute("COMMIT")
                    return None
                active = self._db.execute(
                    "SELECT COUNT(*) AS total FROM task_work_items WHERE goal_id = ? "
                    "AND state IN ('open', 'running')",
                    (goal["id"],),
                ).fetchone()
                if int(active["total"] or 0):
                    self._db.execute("COMMIT")
                    return None

                goal_id = str(goal["id"])
                if goal["status"] == "open":
                    blocked = self._db.execute(
                        "SELECT COUNT(*) AS total FROM task_work_items WHERE goal_id = ? AND state = 'blocked'",
                        (goal_id,),
                    ).fetchone()
                    if int(blocked["total"] or 0):
                        status = "inconclusive"
                        reason = "一个或多个工作项因缺少上下文或执行失败而阻塞"
                    elif int(goal["attempts"] or 0) >= int(goal["max_total_attempts"] or 0):
                        status = "unreachable"
                        reason = (
                            f"任务级最大尝试次数 {goal['max_total_attempts']} 已耗尽，"
                            "仍未满足验收条件"
                        )
                    else:
                        status = "unreachable"
                        reason = "所有已规划工作项均已完成，仍未满足验收条件"
                    self._db.execute(
                        "UPDATE task_goals SET status = ?, terminal_reason = ?, updated_at = ? WHERE id = ?",
                        (status, reason, now(), goal_id),
                    )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.get_task_goal(run_id) if goal_id else None

    def abandon_task_work(self, run_id: str, reason: str) -> None:
        """Stop a goal-task queue after cancellation or a terminal worker failure."""
        with self._lock:
            self._db.execute("BEGIN")
            try:
                ended_at = now()
                self._db.execute(
                    "UPDATE task_goals SET status = 'inconclusive', terminal_reason = ?, updated_at = ? "
                    "WHERE run_id = ? AND status IN ('open', 'unreachable', 'inconclusive')",
                    (reason, ended_at, run_id),
                )
                self._db.execute(
                    "UPDATE task_work_items SET state = 'blocked', error = ?, finished_at = ? "
                    "WHERE run_id = ? AND state = 'running'",
                    (reason, ended_at, run_id),
                )
                self._db.execute(
                    "UPDATE task_work_items SET state = 'skipped', error = ?, finished_at = ? "
                    "WHERE run_id = ? AND state = 'open'",
                    (reason, ended_at, run_id),
                )
                self._db.execute(
                    "UPDATE run_units SET status = 'incomplete', error = ?, finished_at = ? "
                    "WHERE run_id = ? AND status = 'running' AND unit_id IN ("
                    "SELECT unit_id FROM task_work_items WHERE run_id = ?)",
                    (reason, ended_at, run_id, run_id),
                )
                self._db.execute(
                    "UPDATE run_units SET status = 'skipped', error = ?, finished_at = ? "
                    "WHERE run_id = ? AND status = 'pending' AND unit_id IN ("
                    "SELECT unit_id FROM task_work_items WHERE run_id = ?)",
                    (reason, ended_at, run_id, run_id),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    # --- findings ----------------------------------------------------------

    def _insert_finding(self, finding: dict) -> None:
        """Insert a finding while the caller owns ``_lock`` and maybe a transaction."""
        self._db.execute(
            "INSERT OR REPLACE INTO findings (id, run_id, unit_id, fingerprint, category, title, severity,"
            " summary, evidence, input_source, propagation, dangerous_operation, protection, preconditions,"
            " missing_context, poc, remediation, validation_state, validation_errors, verdict, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                finding["id"],
                finding["run_id"],
                finding["unit_id"],
                finding["fingerprint"],
                finding["category"],
                finding["title"],
                finding["severity"],
                finding["summary"],
                _dumps(finding["evidence"]),
                finding["input_source"],
                finding["propagation"],
                finding["dangerous_operation"],
                finding["protection"],
                _dumps(finding["preconditions"]),
                _dumps(finding["missing_context"]),
                _dumps(finding["poc"]),
                finding["remediation"],
                finding.get("validation_state", "candidate"),
                _dumps(finding.get("validation_errors", [])),
                finding.get("verdict"),
                finding["created_at"],
            ),
        )

    def add_finding(self, finding: dict) -> None:
        with self._lock:
            self._insert_finding(finding)

    def _finding_dict(self, row: sqlite3.Row) -> dict:
        finding = dict(row)
        for name in ("evidence", "preconditions", "missing_context", "validation_errors"):
            finding[name] = _loads(finding.get(name), [])
        finding["poc"] = _loads(finding.get("poc"), None)
        finding["verifications"] = self.list_verifications(finding["id"])
        # A finding carries no location of its own: it belongs to a unit, and the unit
        # knows the file. `line` is the first line the finding actually cites, so
        # "locate it in the source" lands on the evidence rather than the unit header.
        unit = self._row(
            "SELECT file_path, symbol, start_line, end_line FROM run_units WHERE run_id = ? AND unit_id = ?",
            (finding["run_id"], finding["unit_id"]),
        )
        finding["file_path"] = unit["file_path"] if unit else ""
        finding["symbol"] = unit["symbol"] if unit else ""
        finding["unit_start_line"] = unit["start_line"] if unit else 0
        finding["unit_end_line"] = unit["end_line"] if unit else 0
        finding["line"] = min(
            (ref.get("start_line", 0) for ref in finding["evidence"]),
            default=finding["unit_start_line"],
        )
        return finding

    def list_findings(self, run_id: str) -> list[dict]:
        rows = self._rows("SELECT * FROM findings WHERE run_id = ? ORDER BY created_at", (run_id,))
        return [self._finding_dict(row) for row in rows]

    def get_finding(self, finding_id: str) -> dict | None:
        row = self._row("SELECT * FROM findings WHERE id = ?", (finding_id,))
        return self._finding_dict(row) if row else None

    def set_finding_verdict(self, finding_id: str, verdict: str | None) -> None:
        self._write("UPDATE findings SET verdict = ? WHERE id = ?", (verdict, finding_id))

    # --- verifications -----------------------------------------------------

    def _insert_verification(self, record: dict) -> None:
        """Insert while the caller owns ``_lock`` (and optionally a transaction)."""
        self._db.execute(
            "INSERT INTO verifications (id, finding_id, created_at, execution_status, verdict,"
            " original_script, modified_script, modification_notes, target_version, command,"
            " expected_result, normal_observation, attack_observation, browser_execution, notes, files)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                record["id"],
                record["finding_id"],
                record["created_at"],
                record["execution_status"],
                record["verdict"],
                record["original_script"],
                record["modified_script"],
                record["modification_notes"],
                record["target_version"],
                record["command"],
                record["expected_result"],
                record["normal_observation"],
                record["attack_observation"],
                1 if record["browser_execution"] else 0,
                record["notes"],
                _dumps(record.get("files", [])),
            ),
        )

    def add_verification(self, record: dict) -> None:
        with self._lock:
            self._insert_verification(record)

    def record_verification(self, record: dict) -> None:
        """Commit the verification and the finding's current verdict together."""
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._insert_verification(record)
                self._db.execute("UPDATE findings SET verdict = ? WHERE id = ?", (record["verdict"], record["finding_id"]))
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def list_verifications(self, finding_id: str) -> list[dict]:
        rows = self._rows(
            "SELECT * FROM verifications WHERE finding_id = ? ORDER BY created_at", (finding_id,)
        )
        result = []
        for row in rows:
            record = dict(row)
            record["browser_execution"] = bool(record["browser_execution"])
            record["files"] = _loads(record.get("files"), [])
            result.append(record)
        return result

    def latest_verdict(self, finding_id: str) -> str | None:
        row = self._row(
            "SELECT verdict FROM verifications WHERE finding_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (finding_id,),
        )
        return row["verdict"] if row else None

    # --- events ------------------------------------------------------------

    def append_event(self, run_id: str, unit_id: str | None, kind: str, payload: Any) -> dict:
        with self._lock:
            cursor = self._db.execute(
                "INSERT INTO events (run_id, unit_id, kind, payload, created_at) VALUES (?,?,?,?,?)",
                (run_id, unit_id, kind, _dumps(payload), now()),
            )
            event_id = int(cursor.lastrowid or 0)
        return {
            "id": event_id,
            "run_id": run_id,
            "unit_id": unit_id,
            "kind": kind,
            "payload": payload,
            "created_at": now(),
        }

    def list_events(self, run_id: str, after: int = 0, limit: int = 500) -> list[dict]:
        rows = self._rows(
            "SELECT * FROM events WHERE run_id = ? AND id > ? ORDER BY id LIMIT ?", (run_id, after, limit)
        )
        events = []
        for row in rows:
            event = dict(row)
            event["payload"] = _loads(event.get("payload"), {})
            events.append(event)
        return events

    def count_events(self, run_id: str, after: int = 0) -> int:
        row = self._row("SELECT COUNT(*) AS total FROM events WHERE run_id = ? AND id > ?", (run_id, after))
        return int(row["total"] or 0) if row else 0

    # --- prompts -----------------------------------------------------------

    def upsert_builtin_prompt(self, prompt: dict) -> None:
        self._write(
            "INSERT INTO prompts (id, label, phase, text, reason, issues, parent_id, builtin, created_at)"
            " VALUES (?,?,?,?,?,?,?,1,?) ON CONFLICT(id) DO NOTHING",
            (
                prompt["id"],
                prompt["label"],
                prompt.get("phase", ""),
                prompt["text"],
                prompt.get("reason", ""),
                _dumps(prompt.get("issues", [])),
                prompt.get("parent_id"),
                prompt["created_at"],
            ),
        )

    def add_prompt(self, prompt: dict) -> None:
        self._write(
            "INSERT INTO prompts (id, label, phase, text, reason, issues, parent_id, builtin, created_at)"
            " VALUES (?,?,?,?,?,?,?,0,?)",
            (
                prompt["id"],
                prompt["label"],
                prompt.get("phase", ""),
                prompt["text"],
                prompt.get("reason", ""),
                _dumps(prompt.get("issues", [])),
                prompt.get("parent_id"),
                prompt["created_at"],
            ),
        )

    def list_prompts(self) -> list[dict]:
        rows = self._rows("SELECT * FROM prompts ORDER BY builtin DESC, phase, created_at")
        prompts = []
        for row in rows:
            prompt = dict(row)
            prompt["issues"] = _loads(prompt.get("issues"), [])
            prompt["builtin"] = bool(prompt["builtin"])
            prompts.append(prompt)
        return prompts

    def get_prompt(self, prompt_id: str) -> dict | None:
        row = self._row("SELECT * FROM prompts WHERE id = ?", (prompt_id,))
        if not row:
            return None
        prompt = dict(row)
        prompt["issues"] = _loads(prompt.get("issues"), [])
        prompt["builtin"] = bool(prompt["builtin"])
        return prompt

    # --- truths ------------------------------------------------------------

    def replace_truths(self, snapshot_id: str, samples: list[dict]) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.execute("DELETE FROM truths WHERE snapshot_id = ?", (snapshot_id,))
                self._db.executemany(
                    "INSERT INTO truths (id, snapshot_id, file_path, category, vulnerable,"
                    " independently_verified, verification_basis, evidence, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            sample["id"],
                            snapshot_id,
                            sample["file_path"],
                            sample["category"],
                            1 if sample["vulnerable"] else 0,
                            1 if sample["independently_verified"] else 0,
                            sample["verification_basis"],
                            _dumps(sample["evidence"]),
                            now(),
                        )
                        for sample in samples
                    ],
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def list_truths(self, snapshot_id: str) -> list[dict]:
        rows = self._rows("SELECT * FROM truths WHERE snapshot_id = ? ORDER BY file_path", (snapshot_id,))
        truths = []
        for row in rows:
            truth = dict(row)
            truth["vulnerable"] = bool(truth["vulnerable"])
            truth["independently_verified"] = bool(truth["independently_verified"])
            truth["evidence"] = _loads(truth.get("evidence"), [])
            truths.append(truth)
        return truths

    # --- attributions ------------------------------------------------------

    def add_attribution(self, record: dict) -> None:
        self._write(
            "INSERT INTO attributions (id, run_id, file_path, category, kind, cause, check_item,"
            " finding_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                record["id"],
                record["run_id"],
                record["file_path"],
                record["category"],
                record["kind"],
                record["cause"],
                record["check_item"],
                record.get("finding_id"),
                record["created_at"],
            ),
        )

    def list_attributions(self, run_id: str) -> list[dict]:
        return [
            dict(row)
            for row in self._rows("SELECT * FROM attributions WHERE run_id = ? ORDER BY created_at", (run_id,))
        ]

    # --- model health ------------------------------------------------------

    def save_health(self, model: str, state: Any) -> None:
        self._write(
            "INSERT INTO model_health (id, model, fails, trips, open_until, last_error, last_at)"
            " VALUES (1,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET model=excluded.model,"
            " fails=excluded.fails, trips=excluded.trips, open_until=excluded.open_until,"
            " last_error=excluded.last_error, last_at=excluded.last_at",
            (model, state.fails, state.trips, state.open_until, state.last_error, state.last_at),
        )

    def load_health(self) -> dict | None:
        row = self._row("SELECT * FROM model_health WHERE id = 1")
        return dict(row) if row else None
