"""SQLite persistence: runs, frozen unit queues, findings, verifications, events.

One process holds one connection guarded by a lock. Events are append-only and carry
a monotonic id, which is the cursor the SSE endpoint resumes from.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from .evidence import seen_ranges
from .finding_policy import is_vulnerability_finding

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
    -- A run records the selected provider identity, never its credential.  The
    -- profile can later be deleted without erasing this audit trail.
    model_profile TEXT NOT NULL DEFAULT '{}',
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

-- Planner v2 mirrors ARTEX's durable exploration frontier while keeping the
-- white-box application self-contained in SQLite.  A run owns one planner session;
-- the planner appends immutable revisions and workers atomically claim only ready
-- multi-file tasks.  No row in this group is tied to a source slice.
CREATE TABLE IF NOT EXISTS planner_project_maps (
    run_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS planner_sessions (
    run_id TEXT PRIMARY KEY,
    goal_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    current_round INTEGER NOT NULL DEFAULT 0,
    max_rounds INTEGER NOT NULL,
    current_plan_id TEXT,
    current_revision INTEGER NOT NULL DEFAULT 0,
    terminal_state TEXT,
    terminal_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_planner_sessions_goal ON planner_sessions(goal_id, status);

CREATE TABLE IF NOT EXISTS planner_plans (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    round_no INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'planning',
    goal_state TEXT,
    basis_summary TEXT NOT NULL DEFAULT '',
    next_action TEXT NOT NULL DEFAULT '',
    missing_context TEXT NOT NULL DEFAULT '[]',
    task_snapshot TEXT NOT NULL DEFAULT '[]',
    updates TEXT NOT NULL DEFAULT '[]',
    usage TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE (run_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_planner_plans_run ON planner_plans(run_id, revision);

CREATE TABLE IF NOT EXISTS planner_tasks (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    plan_id TEXT,
    task_key TEXT NOT NULL,
    title TEXT NOT NULL,
    objective TEXT NOT NULL,
    acceptance_criteria TEXT NOT NULL,
    rationale_summary TEXT NOT NULL,
    context_spec TEXT NOT NULL DEFAULT '{}',
    dependencies TEXT NOT NULL DEFAULT '[]',
    session_id TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    state TEXT NOT NULL DEFAULT 'pending',
    max_attempts INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    claimed_by TEXT,
    claimed_at TEXT,
    result TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE (run_id, task_key)
);
CREATE INDEX IF NOT EXISTS idx_planner_tasks_claim ON planner_tasks(run_id, state, priority DESC, created_at);

CREATE TABLE IF NOT EXISTS planner_task_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    plan_id TEXT,
    attempt INTEGER NOT NULL,
    worker_id TEXT,
    session_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    state TEXT NOT NULL,
    result TEXT NOT NULL,
    usage TEXT,
    seen TEXT NOT NULL DEFAULT '[]',
    error TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (task_id, attempt)
);
CREATE INDEX IF NOT EXISTS idx_planner_task_attempts_task ON planner_task_attempts(task_id, attempt);

-- What the Planner has already had answered: reconnaissance briefs, directory listings,
-- search hits.  A row is written once and its content columns are never updated (see
-- ``Store.set_investigation_status``): the round prompt tells the Planner "you already
-- asked this in round N" and replays the answer verbatim, so re-asking costs nothing and
-- cannot drift from what was really observed.
CREATE TABLE IF NOT EXISTS planner_investigations (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    goal_id TEXT NOT NULL DEFAULT '',
    plan_id TEXT,
    round_no INTEGER NOT NULL DEFAULT 0,
    revision INTEGER NOT NULL DEFAULT 1,
    kind TEXT NOT NULL DEFAULT 'recon',
    tool TEXT NOT NULL DEFAULT '',
    topic TEXT NOT NULL,
    topic_key TEXT NOT NULL,
    args TEXT NOT NULL DEFAULT '{}',
    payload TEXT NOT NULL DEFAULT '{}',
    payload_bytes INTEGER NOT NULL DEFAULT 0,
    files_read TEXT NOT NULL DEFAULT '[]',
    usage TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active',
    reason TEXT,
    superseded_by TEXT,
    created_at TEXT NOT NULL
);
-- One active record per topic, exactly like ARTEX's single-active-retest index: a
-- re-ask that is not a revision reuses the row, and a revision must supersede first.
CREATE UNIQUE INDEX IF NOT EXISTS uq_inv_active
    ON planner_investigations(run_id, topic_key) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_planner_investigations_run ON planner_investigations(run_id, created_at);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    unit_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    category TEXT NOT NULL,
    finding_kind TEXT NOT NULL DEFAULT '',
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

-- API key ciphertext is encrypted before it reaches this table.  The Fernet key
-- is stored separately in the local data directory and never in SQLite or an API
-- response.  Environment-backed profiles retain an empty ciphertext.
CREATE TABLE IF NOT EXISTS model_profiles (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    model TEXT NOT NULL,
    base_url TEXT NOT NULL DEFAULT '',
    api_key_secret TEXT NOT NULL DEFAULT '',
    credential_source TEXT NOT NULL DEFAULT 'stored',
    ordinal INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_model_profiles_ordinal ON model_profiles(ordinal, created_at);

CREATE TABLE IF NOT EXISTS model_selection (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    selected_profile_id TEXT,
    updated_at TEXT NOT NULL
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

# A white-box worker may reuse another worker's *durable public trace*, but never
# its provider transcript or hidden reasoning.  These are the event kinds whose
# payloads are deliberately bounded and reviewable in the UI as well.
PLANNER_WORKER_TRACE_KINDS = frozenset(
    {
        "planner_context_prepared",
        "tool_call",
        "tool_result",
        "task_assessment",
        "task_agent_terminal",
    }
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


# Coverage feedback is a bounded navigation aid for the Planner, not a second project
# map: it must fit in every round's prompt and answer exactly one question -- which
# goal-relevant areas has nobody read yet.
MAX_COVERAGE_PATHS = 40
MAX_COVERAGE_MODULES = 12
MAX_COVERAGE_ATTEMPTS = 200
# Findings carry their citations as one flat string (``path:start-end; path:line``),
# so the path half is parsed rather than read from a structured field. Only the path
# matters here and an unrecognised one is harmless: the caller intersects with the
# frozen file set.
_COVERAGE_CITATION = re.compile(r"(?P<path>[\w./\\-]+)[ \t]*[:：][ \t]*\d")
# ``seen_ranges`` merges a worker's reads; ``exact=True`` means the unit itself is not
# counted, so the placeholder unit below is never read.
_COVERAGE_UNIT = {"file_path": "", "start_line": 0, "end_line": 0}

# A pinned investigation is what the run already knows.  ``status`` is the only thing
# about it that may still move, and only between these values.
INVESTIGATION_STATUSES = ("active", "superseded", "retracted")
MAX_INVESTIGATION_TOPIC = 500
# How many pinned records a round prompt may carry.  The prompt names the rest by count:
# the full text stays one ``get_investigation`` call away.
MAX_PROMPT_INVESTIGATIONS = 12

# The declared file set of one Planner task, carried into the Planner's context as a
# bounded set.  It is what the duplicate guard compares proposals against; the refs
# themselves stay in ``context_spec``.
MAX_TASK_FILES = 24

# Task states a Planner ``reopen`` update may act on: the direction has stopped producing
# evidence and has a conclusion worth correcting.  A task that is still pending or ready has
# nothing to correct yet, and a running one is owned by a worker.
REOPENABLE_TASK_STATES = ("completed", "blocked", "exhausted", "cancelled", "skipped")

# The third axis of a finding, orthogonal to ``validation_state`` (is the evidence sound?)
# and ``verdict`` (did a human reproduce it?): is this conclusion still standing?  Nothing
# is ever deleted -- a withdrawn conclusion keeps its row, its verifications and its text,
# so "this was concluded and later withdrawn" stays readable.
FINDING_DISPOSITIONS = ("open", "superseded", "retracted", "duplicate", "contested")
# Dispositions under which a conclusion no longer stands: it keeps its row, its text and
# its verifications, and it still appears in the report, but it is not evidence a run may
# close on.  ``contested`` is deliberately not one of them: a contest records the Planner
# disagreeing with a verdict a human already recorded, and a human verdict is terminal, so
# the conclusion stays standing until the human revisits it.
WITHDRAWN_FINDING_DISPOSITIONS = ("retracted", "duplicate", "superseded")
# SQL form of the same predicate, so the one place that filters in a query cannot drift
# from the one place that filters in Python.  The values are internal literals.
_WITHDRAWN_SQL = "(" + ", ".join(f"'{item}'" for item in WITHDRAWN_FINDING_DISPOSITIONS) + ")"
# A human verdict is terminal.  The Planner may still disagree, but only visibly.
HUMAN_DECIDED_VERDICTS = ("confirmed", "rejected")
# How many earlier revisions of one finding slot are kept verbatim in
# ``superseded_summary``.  Older ones are dropped from the snapshot, not from history: the
# attempt rows in ``planner_task_attempts`` are the durable record.
MAX_SUPERSEDED_SUMMARIES = 4
#
# Where this stops, deliberately.  The reference model (ARTEX) carries a global asset graph
# -- anchors, spawns, derived_from/yields/proves/covers edges and a per-asset ownership tree
# -- plus a ``prove_goal`` closure that lets its planner mark a goal done.  None of that is
# here: our scope is the whole frozen snapshot rather than a graph of assets, so lineage is
# one column (``derived_from_finding_id``) and closure stays with the host in
# ``finalize_goal``, which is the boundary that keeps a worker's "I found nothing" from
# becoming a project-wide negative.  The one thing borrowed around that boundary is timing,
# not authority: the host runs a Planner round *before* it closes on a standing conclusion
# (see ``_execute_planner_task``), so the conclusion a run ends on is one the Planner was
# shown and could still withdraw.  ``finalize_goal`` itself is unchanged -- it still decides,
# and it still refuses a goal met with nothing standing behind it.  Retests are not a
# cross-table session either: the ``verifications`` table plus these columns already separate
# "what a reviewer reproduced" from "what the run still claims", without new conversation
# infrastructure.

# Events the report reads back to explain what the Planner was told: per-round reading
# coverage, and the reconnaissance brief (or the reason there is none).
PLANNER_OBSERVATION_KINDS = (
    "planner_coverage_prepared",
    "recon_brief_prepared",
    "recon_terminal",
    "recon_skipped",
)


def _cited_paths(findings: Any) -> set[str]:
    """Extract the cited paths from a persisted ``findings`` array."""
    if not isinstance(findings, list):
        return set()
    found: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        text = finding.get("evidence")
        if not isinstance(text, str):
            continue
        for match in _COVERAGE_CITATION.finditer(text.replace("`", "")):
            path = match.group("path").replace("\\", "/")
            while path.startswith("./"):
                path = path[2:]
            if path:
                found.add(path)
    return found


def _compact_source_observations(result: dict) -> list[dict]:
    """Carry bounded ruled-out paths and source facts into later audit work."""
    observations = [item for item in result.get("observations") or [] if isinstance(item, dict)]
    observations.extend(
        item for item in result.get("findings") or []
        if isinstance(item, dict) and not is_vulnerability_finding(item)
    )
    compact = []
    for item in observations[:8]:
        evidence = item.get("evidence") or ""
        compact.append({
            "title": str(item.get("title") or "")[:240],
            "kind": str(item.get("kind") or item.get("finding_kind") or "source_observation")[:120],
            "summary": str(item.get("summary") or "")[:1200],
            "evidence": evidence[:2000] if isinstance(evidence, str) else evidence[:8] if isinstance(evidence, list) else "",
        })
    return compact


def _public_base_url(value: object) -> str:
    """Return the non-secret, display-safe part of a provider endpoint."""
    raw = str(value or "").strip().rstrip("/")
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    # URL user-info and query strings can contain credentials.  A run snapshot
    # must remain safe to return from the normal run APIs and report exporters.
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def _model_profile_snapshot(value: object) -> dict:
    """Keep only the public identity needed to reproduce a run's provider.

    This is intentionally also used on reads.  It protects the API if an old
    local database was hand-edited or a pre-release build wrote extra fields
    into the JSON column.
    """
    if not isinstance(value, dict):
        return {}
    profile_id = str(value.get("profile_id") or value.get("id") or "").strip()
    model = str(value.get("model") or "").strip()
    base_url = _public_base_url(value.get("base_url"))
    if not (profile_id or model or base_url):
        return {}
    return {
        "profile_id": profile_id,
        "model": model,
        "base_url": base_url,
    }


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
        "runs": {
            "agent_policy": "TEXT",
            "task_spec": "TEXT",
            "model_profile": "TEXT NOT NULL DEFAULT '{}'",
            # "snapshot" means the whole immutable snapshot is in scope and the run
            # stores no explicit file list.  Older rows default to "explicit" so their
            # frozen scope keeps its original meaning.
            "scope_mode": "TEXT NOT NULL DEFAULT 'explicit'",
        },
        "task_goals": {
            "max_total_attempts": f"INTEGER NOT NULL DEFAULT {DEFAULT_TASK_MAX_TOTAL_ATTEMPTS}"
        },
        "findings": {
            "finding_kind": "TEXT NOT NULL DEFAULT ''",
            # A finding occupies one slot per (run, unit, category), and a re-run of that
            # slot keeps the row: ``revision`` counts how many conclusions that slot has
            # held, ``superseded_summary`` keeps what the earlier ones said, and
            # ``derived_from_finding_id`` records which finding a later one grew out of.
            # Rewriting the row in place would change its ``id``, orphaning the human
            # ``verifications`` that reference it -- which is exactly what used to happen.
            "revision": "INTEGER NOT NULL DEFAULT 1",
            "superseded_summary": "TEXT",
            "derived_from_finding_id": "TEXT",
            "disposition": "TEXT NOT NULL DEFAULT 'open'",
            "disposition_reason": "TEXT",
            "disposition_by": "TEXT",
            "disposition_at": "TEXT",
        },
        # How many times a settled direction has been re-opened for correction, per task and
        # per run.  Counted in the database rather than read back out of events: the counters
        # are what the host enforces its reopen budget with.  ``planner_sessions.current_revision``
        # is a different counter -- it numbers plans, not corrections.
        "planner_tasks": {"revisions": "INTEGER NOT NULL DEFAULT 0"},
        "planner_sessions": {"task_reopens": "INTEGER NOT NULL DEFAULT 0"},
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

    def create_run(self, run: dict, units: list[dict] | None = None) -> None:
        """Persist a run and its durable goal.

        ``units`` remains optional only so an older SQLite record can still be read
        during a rolling local upgrade.  New Planner runs deliberately pass no units:
        slicing is an importer implementation detail and must never become a worker
        queue or an implied audit-coverage claim.
        """
        units = list(units or [])
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.execute(
                    "INSERT INTO runs (id, snapshot_id, snapshot_name, scope, scope_mode, prompt_id, prompt_label,"
                    " prompt_text, model, model_profile, budgets, status, created_at, agent_policy, task_spec) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        run["id"],
                        run["snapshot_id"],
                        run["snapshot_name"],
                        _dumps(run["scope"]),
                        str(run.get("scope_mode") or "explicit"),
                        run["prompt_id"],
                        run["prompt_label"],
                        run["prompt_text"],
                        run["model"],
                        _dumps(_model_profile_snapshot(run.get("model_profile"))),
                        _dumps(run["budgets"]),
                        "pending",
                        run["created_at"],
                        _dumps(run["agent_policy"]) if run.get("agent_policy") else None,
                        _dumps(run["task_spec"]) if run.get("task_spec") else None,
                    ),
                )
                if units:
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
                    # Planner v2 creates no file/slice work items here.  The first
                    # Planner round receives a project map and decides the initial
                    # frontier; subsequent rounds may add, defer or retire tasks.
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def _run_dict(self, row: sqlite3.Row) -> dict:
        run = dict(row)
        run["scope"] = _loads(run.get("scope"), [])
        run["scope_mode"] = str(run.get("scope_mode") or "explicit")
        run["budgets"] = _loads(run.get("budgets"), {})
        run["agent_policy"] = _loads(run.get("agent_policy"), {"version": "legacy"})
        run["model_profile"] = _model_profile_snapshot(_loads(run.get("model_profile"), {}))
        task_spec = _loads(run.get("task_spec"), None)
        # Task runs created before the total-cap field was introduced still have a
        # durable goal row migrated with this default. Reflect the same frozen value
        # in their public TaskSpec so the worker, report and UI agree.
        if isinstance(task_spec, dict):
            task_spec.setdefault("max_total_attempts", DEFAULT_TASK_MAX_TOTAL_ATTEMPTS)
            task_spec.setdefault("max_planner_rounds", 8)
            task_spec.setdefault("require_poc", False)
        run["task_spec"] = task_spec
        planner_session = self._row("SELECT run_id FROM planner_sessions WHERE run_id = ?", (run["id"],))
        if planner_session is not None:
            counts = self._row(
                "SELECT COUNT(*) AS total,"
                " SUM(CASE WHEN state = 'completed' THEN 1 ELSE 0 END) AS completed"
                " FROM planner_tasks WHERE run_id = ?",
                (run["id"],),
            )
            # Run-level consumption includes the main Planner as well as worker
            # attempts.  Omitting Planner usage makes a project with a rich planning
            # phase look artificially cheap in the UI and exported report.
            usage = self._row(
                "SELECT COALESCE(SUM(json_extract(usage, '$.requests')), 0) AS requests,"
                " COALESCE(SUM(json_extract(usage, '$.tool_calls')), 0) AS tool_calls,"
                " COALESCE(SUM(json_extract(usage, '$.input_tokens')), 0) AS input_tokens,"
                " COALESCE(SUM(json_extract(usage, '$.output_tokens')), 0) AS output_tokens"
                " FROM ("
                " SELECT usage FROM planner_task_attempts WHERE run_id = ? AND usage IS NOT NULL"
                " UNION ALL"
                " SELECT usage FROM planner_plans WHERE run_id = ? AND usage IS NOT NULL"
                " )",
                (run["id"], run["id"]),
            )
            run["total_tasks"] = int(counts["total"] or 0) if counts else 0
            run["completed_tasks"] = int(counts["completed"] or 0) if counts else 0
            run["total_units"] = 0
            run["completed_units"] = 0
        else:
            counts = self._row(
                "SELECT COUNT(*) AS total,"
                " SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed"
                " FROM run_units WHERE run_id = ?",
                (run["id"],),
            )
            run["total_units"] = int(counts["total"] or 0) if counts else 0
            run["completed_units"] = int(counts["completed"] or 0) if counts else 0
            run["total_tasks"] = 0
            run["completed_tasks"] = 0
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
                    # ``started_at`` records when the run first began, not when the worker
                    # last picked it up: a resumed run keeps the original, so "how long has
                    # this been going" survives a pause rather than restarting at zero.
                    "UPDATE runs SET status = 'running', started_at = COALESCE(started_at, ?) WHERE id = ?",
                    (now(), row["id"]),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.get_run(row["id"])

    def request_cancel(self, run_id: str) -> None:
        # Running runs are stopped by the worker; pending and paused runs never start.
        # A paused run is cancellable on purpose: pausing is how a user parks work to look
        # at it, and having to resume it first in order to throw it away would be a trap.
        self._write(
            "UPDATE runs SET status = 'cancelled', finished_at = ?"
            " WHERE id = ? AND status IN ('pending','running','paused')",
            (now(), run_id),
        )

    def request_pause(self, run_id: str) -> None:
        """Park a run at its next boundary without giving up its frontier.

        One-way on purpose.  ``paused`` is not a state a worker may leave by noticing
        that the flag it was set with has gone away: a run parked here keeps every
        planner task, every attempt and its current round, and only an explicit
        ``resume_run`` puts it back in the queue.  ``finished_at`` is left untouched --
        the run has not finished, so a report that says otherwise would be wrong.
        """
        self._write(
            "UPDATE runs SET status = 'paused' WHERE id = ? AND status IN ('pending','running')",
            (run_id,),
        )

    def resume_run(self, run_id: str) -> bool:
        """Return a paused run to the queue its worker claims from, or report why not.

        ``claim_next_run`` only ever claims ``pending``, so resuming is exactly this one
        transition: the frontier, the Planner session and its round number were never
        touched, and the next claim continues from them instead of re-planning.  A run
        whose goal or session has since settled is not resumable -- continuing it would
        restart work under a settled goal.
        """
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                run = self._db.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()
                if run is None or run["status"] != "paused":
                    self._db.execute("ROLLBACK")
                    return False
                goal = self._db.execute(
                    "SELECT status FROM task_goals WHERE run_id = ?", (run_id,)
                ).fetchone()
                if goal is not None and goal["status"] != "open":
                    self._db.execute("ROLLBACK")
                    return False
                self._db.execute("UPDATE runs SET status = 'pending' WHERE id = ?", (run_id,))
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return True

    def interrupt_stale_runs(self) -> int:
        """Repair work left unresolved by a process that stopped between writes."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                stale = [
                    (row["id"], row["status"])
                    for row in self._db.execute(
                        "SELECT id, status FROM runs WHERE status IN ('running','paused')"
                    )
                ]
                if stale:
                    stale_ids = [run_id for run_id, _ in stale]
                    marks = ",".join("?" for _ in stale_ids)
                    self._db.execute(
                        f"UPDATE runs SET status = 'interrupted', finished_at = ?,"
                        f" error = 'Server restarted while this run was in flight'"
                        f" WHERE id IN ({marks}) AND status = 'running'",
                        (now(), *stale_ids),
                    )
                    # A paused run is interrupted too, and for the same reason: the pause
                    # flag lives in the worker's memory, so nothing on this server will
                    # ever resume it.  It is a different sentence for the reader, though --
                    # "in flight" would be a lie about a run that had deliberately stopped,
                    # and its frontier is intact rather than half-executed.
                    self._db.execute(
                        f"UPDATE runs SET status = 'interrupted', finished_at = ?,"
                        f" error = 'Server restarted while this run was paused'"
                        f" WHERE id IN ({marks}) AND status = 'paused'",
                        (now(), *stale_ids),
                    )
                    # Whatever was still queued will never run: the worker that owned the queue
                    # is gone. Leaving it `pending` would keep it listed as "about to start" in a
                    # run that has already finished, and `pending` is one of the unresolved
                    # statuses that keeps a truth sample out of the confusion matrix.
                    self._db.execute(
                        f"UPDATE run_units SET status = 'skipped', error = 'Run interrupted before this unit started',"
                        f" finished_at = ? WHERE run_id IN ({marks}) AND status = 'pending'",
                        (now(), *stale_ids),
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
                # Planner v2 owns a separate dynamic frontier.  A server restart
                # cannot leave leased multi-file tasks marked running, nor let a
                # terminal run show ready work that no worker will ever claim.
                self._db.execute(
                    "UPDATE planner_tasks SET state = 'blocked', error = 'Run interrupted by server restart',"
                    " updated_at = ?, finished_at = ? WHERE state = 'running'",
                    (now(), now()),
                )
                self._db.execute(
                    "UPDATE planner_tasks SET state = 'cancelled', error = 'Run ended before this Planner task started',"
                    " updated_at = ?, finished_at = ? WHERE state IN ('pending','ready','deferred') AND run_id IN ("
                    "SELECT id FROM runs WHERE status IN ('cancelled', 'interrupted', 'failed', 'completed', 'unreachable', 'inconclusive'))",
                    (now(), now()),
                )
                self._db.execute(
                    "UPDATE planner_sessions SET status = 'cancelled', terminal_state = 'inconclusive',"
                    " terminal_reason = '运行在 Planner 完成前被中断或终止', updated_at = ? WHERE run_id IN ("
                    "SELECT id FROM runs WHERE status IN ('cancelled', 'interrupted', 'failed'))"
                    " AND status NOT IN ('completed', 'cancelled')",
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
            return len(stale_ids) if stale else 0

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
        findings: list[dict] | None = None,
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
        finding_records = list(findings or ([] if finding is None else [finding]))
        if outcome == "achieved" and (
            not finding_records or any(
                item.get("validation_state") != "candidate" or not is_vulnerability_finding(item)
                for item in finding_records
            )
        ):
            raise ValueError("achieved task work requires a validated vulnerability finding")

        goal_met = False
        finding_ids: list[str] = []
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

                for finding_record in finding_records:
                    written = self._insert_finding(finding_record)
                    finding_ids.append(str(written["finding_id"]))

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
            resolved["finding_id"] = finding_ids[0] if finding_ids else None
            resolved["finding_ids"] = finding_ids
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

    # --- planner v2: project graph, revisions and dynamic frontier ---------

    @staticmethod
    def _planner_session_dict(row: sqlite3.Row | None) -> dict | None:
        return dict(row) if row is not None else None

    @staticmethod
    def _planner_plan_dict(row: sqlite3.Row) -> dict:
        value = dict(row)
        for key, fallback in (
            ("missing_context", []), ("task_snapshot", []), ("updates", []),
        ):
            value[key] = _loads(value.get(key), fallback)
        value["usage"] = _loads(value.get("usage"), None)
        return value

    @staticmethod
    def _planner_task_dict(row: sqlite3.Row) -> dict:
        value = dict(row)
        value["context_spec"] = _loads(value.get("context_spec"), {})
        value["dependencies"] = _loads(value.get("dependencies"), [])
        value["result"] = _loads(value.get("result"), None)
        return value

    @staticmethod
    def _planner_attempt_dict(row: sqlite3.Row) -> dict:
        value = dict(row)
        value["result"] = _loads(value.get("result"), {})
        value["usage"] = _loads(value.get("usage"), None)
        value["seen"] = _loads(value.get("seen"), [])
        return value

    def create_planner_session(
        self,
        run_id: str,
        session_id: str,
        max_rounds: int,
        project_map: dict,
    ) -> dict:
        """Freeze the project map and create the run's one Planner session."""
        if max_rounds < 1:
            raise ValueError("max_rounds must be positive")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                goal = self._db.execute(
                    "SELECT id FROM task_goals WHERE run_id = ? ORDER BY created_at LIMIT 1", (run_id,)
                ).fetchone()
                if goal is None:
                    raise ValueError("Planner session requires a goal-driven run")
                stamp = now()
                self._db.execute(
                    "INSERT OR IGNORE INTO planner_project_maps (run_id, snapshot_id, scope, payload, created_at) "
                    "SELECT id, snapshot_id, scope, ?, ? FROM runs WHERE id = ?",
                    (_dumps(project_map), stamp, run_id),
                )
                self._db.execute(
                    "INSERT OR IGNORE INTO planner_sessions (run_id, goal_id, session_id, status, current_round, max_rounds, "
                    "current_revision, created_at, updated_at) VALUES (?,?,?,'pending',0,?,0,?,?)",
                    (run_id, goal["id"], session_id, int(max_rounds), stamp, stamp),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        session = self.get_planner_session(run_id)
        if session is None:
            raise RuntimeError("planner session was not persisted")
        return session

    def get_planner_session(self, run_id: str) -> dict | None:
        return self._planner_session_dict(
            self._row("SELECT * FROM planner_sessions WHERE run_id = ?", (run_id,))
        )

    def get_project_map(self, run_id: str) -> dict | None:
        row = self._row("SELECT payload FROM planner_project_maps WHERE run_id = ?", (run_id,))
        return _loads(row["payload"], None) if row else None

    def list_plans(self, run_id: str) -> list[dict]:
        return [
            self._planner_plan_dict(row)
            for row in self._rows("SELECT * FROM planner_plans WHERE run_id = ? ORDER BY revision", (run_id,))
        ]

    def list_tasks(self, run_id: str, *, include_attempts: bool = True) -> list[dict]:
        rows = self._rows(
            "SELECT * FROM planner_tasks WHERE run_id = ? ORDER BY priority DESC, created_at, id", (run_id,)
        )
        tasks = [self._planner_task_dict(row) for row in rows]
        if include_attempts:
            for task in tasks:
                task["attempt_history"] = self.list_task_attempts(task["id"])
        return tasks

    def get_planner_task(self, task_id: str) -> dict | None:
        row = self._row("SELECT * FROM planner_tasks WHERE id = ?", (task_id,))
        if row is None:
            return None
        task = self._planner_task_dict(row)
        task["attempt_history"] = self.list_task_attempts(task_id)
        return task

    def list_task_attempts(self, task_id: str) -> list[dict]:
        return [
            self._planner_attempt_dict(row)
            for row in self._rows(
                "SELECT * FROM planner_task_attempts WHERE task_id = ? ORDER BY attempt, id", (task_id,)
            )
        ]

    def planner_coverage(self, run_id: str, project_map: dict | None = None) -> dict:
        """Host-computed reading coverage of the frozen snapshot.

        Each round the Planner has to decide between dispatching more evidence
        directions and converging.  That decision needs one fact the durable task
        summaries do not carry: which parts of the project nobody has read yet.  The
        answer is derived here from the host's own records -- the persisted worker
        ``seen`` ledgers and the frozen project map -- never from model prose, and it
        stays bounded so it can be attached to every round.

        Dependency trees are counted separately instead of being folded into the module
        ranking: ``vendor``/``node_modules`` would otherwise dominate the "unread
        module" list while saying nothing about this project's own code.

        ``project_map`` may be passed by a caller that already has the frozen map in
        hand; it is a multi-megabyte structure on a real project and re-reading it here
        would double the per-round cost of a round that already loaded it.
        """
        if project_map is None:
            project_map = self.get_project_map(run_id) or {}
        known = {
            row["path"]: row
            for row in (project_map.get("files") or [])
            if isinstance(row, dict) and isinstance(row.get("path"), str)
        }
        rows = self._rows(
            "SELECT seen, result FROM planner_task_attempts WHERE run_id = ? ORDER BY id DESC LIMIT ?",
            (run_id, MAX_COVERAGE_ATTEMPTS),
        )
        reads: list[dict] = []
        cited: set[str] = set()
        for row in rows:
            seen = _loads(row["seen"], [])
            if isinstance(seen, list):
                reads.extend(item for item in seen if isinstance(item, dict))
            result = _loads(row["result"], {})
            if isinstance(result, dict):
                cited.update(_cited_paths(result.get("findings")))

        read_paths = {path for path, _, _ in seen_ranges(_COVERAGE_UNIT, reads, exact=True)}
        read_paths &= set(known)
        dependency_paths = {path for path, row in known.items() if row.get("dependency_tree")}

        modules: dict[str, dict] = {}
        for path, row in known.items():
            if row.get("dependency_tree"):
                continue
            module = str(row.get("module") or ".")
            bucket = modules.setdefault(module, {"total": 0, "unread": 0})
            bucket["total"] += 1
            if path not in read_paths:
                bucket["unread"] += 1
        unread_hot_modules = [
            {"module": module, "unread": bucket["unread"], "total": bucket["total"]}
            for module, bucket in modules.items()
            if bucket["unread"]
        ]
        unread_hot_modules.sort(key=lambda item: (-item["unread"], -item["total"], item["module"]))

        stats = project_map.get("stats") or {}
        total = int(stats.get("files") or len(known) or 0)
        return {
            "files_total": total,
            "files_read": len(read_paths),
            "files_with_findings": len(cited & set(known)),
            "coverage_ratio": round(len(read_paths) / total, 4) if total else 0.0,
            "read_paths": sorted(read_paths)[:MAX_COVERAGE_PATHS],
            "unread_hot_modules": unread_hot_modules[:MAX_COVERAGE_MODULES],
            "dependency_tree_total": len(dependency_paths),
            "dependency_tree_read": len(read_paths & dependency_paths),
            "notice": (
                "覆盖统计来自已持久化的 worker 读记录与冻结项目图，不是安全结论，也不能作为 finding 证据；"
                f"read_paths 最多列 {MAX_COVERAGE_PATHS} 条，unread_hot_modules 最多列 {MAX_COVERAGE_MODULES} 个，"
                f"最近 {MAX_COVERAGE_ATTEMPTS} 次尝试之外的读记录未计入。"
            ),
        }

    def list_planner_observations(self, run_id: str, *, limit: int = 60) -> list[dict]:
        """The Planner's host-computed per-round observations, oldest first.

        Coverage and reconnaissance are round-scoped observations, so they live in the
        event log -- already the durable, ordered record of a run -- rather than in
        tables of their own.  Selecting them back by kind keeps the report to one
        bounded query instead of paging through every event of a long run.
        """
        placeholders = ",".join("?" * len(PLANNER_OBSERVATION_KINDS))
        rows = self._rows(
            f"SELECT kind, payload FROM events WHERE run_id = ? AND kind IN ({placeholders})"
            " ORDER BY id DESC LIMIT ?",
            (run_id, *PLANNER_OBSERVATION_KINDS, limit),
        )
        observations = []
        for row in reversed(rows):
            payload = _loads(row["payload"], {})
            observations.append({
                "kind": row["kind"],
                "round": payload.get("round") if isinstance(payload, dict) else None,
                "payload": payload,
            })
        return observations

    # --- pinned investigations -------------------------------------------------------
    # The Planner asks the same question more than once -- across rounds it has no memory
    # of having asked it at all.  These rows are that memory: written once, replayed
    # verbatim, and never rewritten.  Only their disposition may still change.

    @staticmethod
    def investigation_topic_key(topic: str) -> str:
        """Content key for "the same question, asked again".

        Normalized, because a round asks its question in freshly generated prose: the
        reuse decision has to survive whitespace and case, not word-for-word repetition.
        """
        normalized = " ".join(str(topic or "").split()).casefold()[:MAX_INVESTIGATION_TOPIC]
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]

    def _investigation_dict(self, row: sqlite3.Row, *, include_payload: bool) -> dict:
        return {
            "id": row["id"],
            "run_id": row["run_id"],
            "goal_id": row["goal_id"],
            "plan_id": row["plan_id"],
            "round_no": row["round_no"],
            "revision": row["revision"],
            "kind": row["kind"],
            "tool": row["tool"],
            "topic": row["topic"],
            "topic_key": row["topic_key"],
            "args": _loads(row["args"], {}),
            # The payload is the answer.  It stays out of listings so a prompt or a
            # run API response cannot grow with research the caller did not ask for.
            "payload": _loads(row["payload"], {}) if include_payload else None,
            "payload_bytes": row["payload_bytes"],
            "files_read": _loads(row["files_read"], []),
            "usage": _loads(row["usage"], {}),
            "status": row["status"],
            "reason": row["reason"],
            "superseded_by": row["superseded_by"],
            "created_at": row["created_at"],
        }

    def record_investigation(self, record: dict) -> dict:
        """Insert one pinned investigation.  Write-once.

        A blind INSERT, deliberately: replacing the row would change its id, and every
        later reader of "what this run already knows" -- the round prompt, the report --
        would then be reading a record that no longer matches what happened.  Two active
        records for one topic are impossible (``uq_inv_active``), so a genuine revision
        has to supersede the old row first; that is what turns "this was revised" into a
        recorded fact instead of a silent overwrite.
        """
        payload = record.get("payload")
        rendered = payload if isinstance(payload, str) else _dumps(payload if payload is not None else {})
        investigation_id = str(record.get("id") or uuid.uuid4().hex)
        self._write(
            "INSERT INTO planner_investigations (id, run_id, goal_id, plan_id, round_no, revision,"
            " kind, tool, topic, topic_key, args, payload, payload_bytes, files_read, usage, status, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',?)",
            (
                investigation_id,
                str(record.get("run_id") or ""),
                str(record.get("goal_id") or ""),
                record.get("plan_id"),
                int(record.get("round_no") or 0),
                int(record.get("revision") or 1),
                str(record.get("kind") or "recon"),
                str(record.get("tool") or ""),
                str(record.get("topic") or "")[:MAX_INVESTIGATION_TOPIC],
                str(record.get("topic_key") or self.investigation_topic_key(str(record.get("topic") or ""))),
                _dumps(record.get("args") or {}),
                rendered,
                len(rendered.encode("utf-8")),
                _dumps(record.get("files_read") or []),
                _dumps(record.get("usage") or {}),
                str(record.get("created_at") or now()),
            ),
        )
        return self.get_investigation(investigation_id) or {}

    def get_investigation(self, investigation_id: str, *, include_payload: bool = True) -> dict | None:
        row = self._row("SELECT * FROM planner_investigations WHERE id = ?", (investigation_id,))
        return self._investigation_dict(row, include_payload=include_payload) if row else None

    def current_investigation(self, run_id: str, topic_key: str) -> dict | None:
        """The active record for one topic, payload included: this is the reuse hit."""
        row = self._row(
            "SELECT * FROM planner_investigations WHERE run_id = ? AND topic_key = ? AND status = 'active'",
            (run_id, topic_key),
        )
        return self._investigation_dict(row, include_payload=True) if row else None

    def set_investigation_status(
        self, investigation_id: str, status: str, *, reason: str | None = None,
        superseded_by: str | None = None,
    ) -> None:
        """The only update path, and it touches disposition columns alone.

        A pinned record is what the run already knows; the single thing that may still
        change is whether it stands.  Keeping the write surface this narrow is what makes
        "the answer was replayed, not regenerated" checkable instead of conventional.
        """
        if status not in INVESTIGATION_STATUSES:
            raise ValueError(f"unknown investigation status: {status!r}")
        self._write(
            "UPDATE planner_investigations SET status = ?, reason = ?, superseded_by = ? WHERE id = ?",
            (status, (reason or None), superseded_by, investigation_id),
        )

    def list_investigations(
        self, run_id: str, *, limit: int | None = None, include_payload: bool = False,
        status: str | None = None,
    ) -> list[dict]:
        """Pinned records oldest first; ``limit`` keeps the most recent ones."""
        where = "run_id = ?"
        params: list[Any] = [run_id]
        if status:
            where += " AND status = ?"
            params.append(status)
        if limit:
            rows = self._rows(
                f"SELECT * FROM planner_investigations WHERE {where} ORDER BY created_at DESC, id DESC LIMIT ?",
                (*params, int(limit)),
            )
            rows = list(reversed(rows))
        else:
            rows = self._rows(f"SELECT * FROM planner_investigations WHERE {where} ORDER BY created_at, id", params)
        return [self._investigation_dict(row, include_payload=include_payload) for row in rows]

    def investigation_overview(self, run_id: str, *, limit: int = MAX_PROMPT_INVESTIGATIONS) -> dict:
        """Bounded, payload-free view of what the run has already pinned."""
        by_status = {
            row["status"]: int(row["total"])
            for row in self._rows(
                "SELECT status, COUNT(*) AS total FROM planner_investigations WHERE run_id = ? GROUP BY status",
                (run_id,),
            )
        }
        return {
            "total": sum(by_status.values()),
            "by_status": by_status,
            "recent": self.list_investigations(run_id, limit=limit, include_payload=False),
            "notice": (
                "这些调查的结果已经固定在库里；同一个话题再问会直接返回原记录，不会重新执行。"
                "这里只列最近若干条且不含正文，需要全文时用 get_investigation。"
            ),
        }

    def list_planner_findings(self, run_id: str, *, limit: int = 200) -> list[dict]:
        """Compact view of every persisted conclusion in this run.

        The Planner's main job after the first round is to not repeat the run, and it is
        memoryless between rounds: without this list it re-dispatches directions whose
        findings are already in the database.  Citations are summarised to their paths --
        the finding's own evidence text stays the authoritative record.
        """
        rows = self._rows(
            "SELECT id, unit_id, category, finding_kind, title, severity, summary, evidence,"
            " validation_state, verdict, disposition, disposition_reason, revision,"
            " derived_from_finding_id, created_at FROM findings WHERE run_id = ?"
            " ORDER BY created_at, id LIMIT ?",
            (run_id, int(limit)),
        )
        return [
            {
                "id": row["id"],
                "unit_id": row["unit_id"],
                "category": row["category"],
                "finding_kind": row["finding_kind"],
                "title": row["title"],
                "severity": row["severity"],
                "summary": row["summary"],
                "validation_state": row["validation_state"],
                "verdict": row["verdict"],
                # The third axis travels with the other two, and so does how many times this
                # slot changed its mind: a round that sees revision 2 knows a correction
                # already happened here and does not need to ask for a third.
                "disposition": row["disposition"],
                "disposition_reason": row["disposition_reason"],
                "revision": int(row["revision"] or 1),
                "derived_from_finding_id": row["derived_from_finding_id"],
                "paths": sorted(_cited_paths([{"evidence": row["evidence"]}]))[:6],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def list_planner_context(self, run_id: str, *, project_map: dict | None = None) -> dict:
        """Return the compact, durable state a new Planner round may inspect."""
        goal = self.get_task_goal(run_id)
        tasks = self.list_tasks(run_id, include_attempts=False)
        compact_tasks = []
        for task in tasks:
            result = task.get("result") or {}
            spec = task.get("context_spec") if isinstance(task.get("context_spec"), dict) else {}
            # The paths this direction asked for, as a set rather than as refs: it is what a
            # later round's "am I proposing the same thing again?" question is asked against,
            # and a settled task's refs are otherwise not carried into the Planner's context.
            declared = [
                str(ref.get("path") or "")
                for ref in (spec.get("source_refs") or [])
                if isinstance(ref, dict)
            ]
            declared += [str(path or "") for path in (spec.get("scope_paths") or [])]
            compact_tasks.append({
                "task_key": task["task_key"],
                # Findings are stored against the task's durable id, and a round that wants
                # to withdraw one has to name the task it belongs to; both sides need this
                # to be able to say "this conclusion came from that direction".
                "id": task["id"],
                "title": task["title"],
                "objective": task["objective"],
                "state": task["state"],
                "priority": task["priority"],
                "attempts": task["attempts"],
                "max_attempts": task["max_attempts"],
                "revisions": int(task.get("revisions") or 0),
                "dependencies": task["dependencies"],
                "context_spec": task["context_spec"],
                "files": sorted({path for path in declared if path})[:MAX_TASK_FILES],
                "summary": result.get("summary") if isinstance(result, dict) else "",
                "basis_summary": result.get("reasoning") if isinstance(result, dict) else "",
                "observations": _compact_source_observations(result) if isinstance(result, dict) else [],
                "missing_context": result.get("missing_context", []) if isinstance(result, dict) else [],
                "error": task.get("error"),
            })
        return {
            "goal": goal,
            "planner": self.get_planner_session(run_id),
            # The frozen project map is passed to the Planner separately each round;
            # echoing it here would deserialize a whole-project structure for nothing.
            "tasks": compact_tasks,
            "plans": self.list_plans(run_id)[-4:],
            # Kept out of ``project_map`` on purpose: this is a bounded, host-computed
            # view of what has been read, not another copy of the whole map.
            "coverage": self.planner_coverage(run_id, project_map),
            # What the round must not redo: conclusions already in the database, and
            # questions already answered (see ``planner_investigations``).
            "findings": self.list_planner_findings(run_id),
            "investigations": self.investigation_overview(run_id),
        }

    @staticmethod
    def _public_worker_trace_payload(kind: str, payload: Any) -> dict:
        """Project an event into an explicitly reviewable peer-worker handoff.

        Event rows can contain operational metadata that is useful to the UI but
        unnecessarily large for an agent.  More importantly, this projection makes
        the boundary clear: peer workers receive only tool arguments/results and the
        model's source-grounded assessment, never a provider message transcript.
        """
        data = payload if isinstance(payload, dict) else {}
        if kind == "tool_call":
            return {key: data.get(key) for key in ("tool", "args", "phase", "attempt") if key in data}
        if kind == "tool_result":
            value = {
                key: data.get(key)
                for key in ("tool", "status", "new_lines", "preview", "phase", "attempt")
                if key in data
            }
            if isinstance(value.get("preview"), str):
                value["preview"] = value["preview"][:1600]
            return value
        if kind == "task_assessment":
            value = {
                key: data.get(key)
                for key in (
                    "outcome", "summary", "rationale", "next_focus", "missing_context",
                    "evidence", "terminal_reason", "attempt",
                )
                if key in data
            }
            if "observations" in data:
                value["observations"] = _compact_source_observations({"observations": data.get("observations")})
            return value
        if kind == "planner_context_prepared":
            return {
                key: data.get(key)
                for key in ("paths", "excerpts", "unresolved_dependencies", "limitations", "attempt")
                if key in data
            }
        return {
            key: data.get(key)
            for key in ("outcome", "reason", "summary", "attempt", "terminal_reason")
            if key in data
        }

    def get_planner_dependency_handoffs(self, task_id: str) -> list[dict]:
        """Return bounded completion summaries for the task's declared dependencies.

        Dependencies are more than a scheduling barrier: their settled result is
        handed to the dependent worker as an untrusted lead.  The worker must still
        read source before citing it as evidence.
        """
        row = self._row(
            "SELECT run_id, dependencies FROM planner_tasks WHERE id = ?", (task_id,)
        )
        if row is None:
            return []
        dependencies = [str(key) for key in _loads(row["dependencies"], []) if str(key)]
        if not dependencies:
            return []
        placeholders = ",".join("?" for _ in dependencies)
        rows = self._rows(
            "SELECT task_key, title, state, result, error FROM planner_tasks "
            f"WHERE run_id = ? AND task_key IN ({placeholders})",
            (row["run_id"], *dependencies),
        )
        by_key = {str(item["task_key"]): item for item in rows}
        handoffs: list[dict] = []
        for task_key in dependencies:
            item = by_key.get(task_key)
            if item is None:
                continue
            result = _loads(item["result"], {})
            result = result if isinstance(result, dict) else {}
            findings = []
            for finding in result.get("findings") or []:
                if not isinstance(finding, dict) or not is_vulnerability_finding(finding):
                    continue
                findings.append({
                    key: finding.get(key)
                    for key in ("title", "kind", "severity", "summary", "evidence")
                    if finding.get(key) not in (None, "")
                })
            handoffs.append({
                "task_key": task_key,
                "title": item["title"],
                "state": item["state"],
                "outcome": result.get("outcome"),
                "summary": result.get("summary") or "",
                "rationale": result.get("reasoning") or "",
                "next_focus": result.get("next_focus") or "",
                "missing_context": result.get("missing_context") or [],
                "findings": findings[:8],
                "observations": _compact_source_observations(result),
                "error": item["error"],
            })
        return handoffs

    def search_planner_worker_traces(
        self,
        run_id: str,
        *,
        exclude_task_id: str,
        query: str,
        limit: int = 8,
    ) -> list[dict]:
        """Search durable public traces from peer Planner tasks in the same run."""
        needle = str(query).strip().casefold()
        if not needle:
            raise ValueError("query is required")
        if len(needle) > 240:
            raise ValueError("query is too long")
        kinds = tuple(sorted(PLANNER_WORKER_TRACE_KINDS))
        placeholders = ",".join("?" for _ in kinds)
        rows = self._rows(
            "SELECT e.id, e.unit_id, e.kind, e.payload, e.created_at, t.task_key, t.title "
            "FROM events AS e JOIN planner_tasks AS t ON t.id = e.unit_id AND t.run_id = e.run_id "
            f"WHERE e.run_id = ? AND e.unit_id != ? AND e.kind IN ({placeholders}) "
            "ORDER BY e.id DESC LIMIT 240",
            (run_id, exclude_task_id, *kinds),
        )
        matches: list[dict] = []
        for row in rows:
            trace = self._public_worker_trace_payload(str(row["kind"]), _loads(row["payload"], {}))
            searchable = json.dumps(
                {"task_key": row["task_key"], "title": row["title"], "kind": row["kind"], "trace": trace},
                ensure_ascii=False,
                sort_keys=True,
            ).casefold()
            if needle not in searchable:
                continue
            matches.append({
                "event_id": int(row["id"]),
                "task_key": row["task_key"],
                "title": row["title"],
                "kind": row["kind"],
                "created_at": row["created_at"],
                "trace": trace,
            })
            if len(matches) >= max(1, min(int(limit), 16)):
                break
        return matches

    def get_planner_worker_trace(
        self,
        run_id: str,
        *,
        exclude_task_id: str,
        task_key: str,
        event_ids: list[int] | None = None,
        limit: int = 12,
    ) -> list[dict]:
        """Return selected public trace entries for one peer task in the same run."""
        task = self._row(
            "SELECT id, task_key, title FROM planner_tasks WHERE run_id = ? AND task_key = ?",
            (run_id, str(task_key).strip()),
        )
        if task is None or str(task["id"]) == exclude_task_id:
            return []
        kinds = tuple(sorted(PLANNER_WORKER_TRACE_KINDS))
        kind_placeholders = ",".join("?" for _ in kinds)
        params: list[Any] = [run_id, task["id"], *kinds]
        where = (
            f"e.run_id = ? AND e.unit_id = ? AND e.kind IN ({kind_placeholders})"
        )
        selected = [int(value) for value in (event_ids or [])[:24] if isinstance(value, int) or str(value).isdigit()]
        if selected:
            id_placeholders = ",".join("?" for _ in selected)
            where += f" AND e.id IN ({id_placeholders})"
            params.extend(selected)
        rows = self._rows(
            "SELECT e.id, e.kind, e.payload, e.created_at FROM events AS e WHERE "
            + where + " ORDER BY e.id DESC LIMIT ?",
            (*params, max(1, min(int(limit), 24))),
        )
        return [
            {
                "event_id": int(row["id"]),
                "task_key": task["task_key"],
                "title": task["title"],
                "kind": row["kind"],
                "created_at": row["created_at"],
                "trace": self._public_worker_trace_payload(str(row["kind"]), _loads(row["payload"], {})),
            }
            for row in rows
        ]

    def begin_planner_round(self, run_id: str, session_id: str) -> dict | None:
        """Reserve exactly one serialized Planner round and create its draft plan."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                session = self._db.execute(
                    "SELECT s.*, g.status AS goal_status, r.status AS run_status FROM planner_sessions AS s "
                    "JOIN task_goals AS g ON g.id = s.goal_id JOIN runs AS r ON r.id = s.run_id "
                    "WHERE s.run_id = ?", (run_id,)
                ).fetchone()
                if session is None or session["session_id"] != session_id:
                    self._db.execute("COMMIT")
                    return None
                if session["run_status"] != "running" or session["goal_status"] != "open":
                    self._db.execute("COMMIT")
                    return None
                if int(session["current_round"]) >= int(session["max_rounds"]):
                    self._db.execute(
                        "UPDATE planner_sessions SET status = 'reviewing', terminal_state = 'inconclusive', "
                        "terminal_reason = ?, updated_at = ? WHERE run_id = ?",
                        ("Planner 回合预算已耗尽", now(), run_id),
                    )
                    self._db.execute("COMMIT")
                    return None
                round_no = int(session["current_round"]) + 1
                revision = int(session["current_revision"]) + 1
                plan_id = uuid.uuid4().hex
                stamp = now()
                self._db.execute(
                    "INSERT INTO planner_plans (id, run_id, goal_id, session_id, round_no, revision, status, created_at) "
                    "VALUES (?,?,?,?,?,?,'planning',?)",
                    (plan_id, run_id, session["goal_id"], session_id, round_no, revision, stamp),
                )
                self._db.execute(
                    "UPDATE planner_sessions SET status = 'planning', current_round = ?, current_revision = ?, "
                    "current_plan_id = ?, updated_at = ? WHERE run_id = ?",
                    (round_no, revision, plan_id, stamp, run_id),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        row = self._row("SELECT * FROM planner_plans WHERE id = ?", (plan_id,))
        return self._planner_plan_dict(row) if row else None

    def _refresh_planner_task_states_tx(self, run_id: str, goal_id: str, stamp: str) -> None:
        """Move dependency-satisfied tasks into the frontier inside an owner transaction."""
        rows = self._db.execute(
            "SELECT id, task_key, state, dependencies FROM planner_tasks WHERE run_id = ? AND goal_id = ?",
            (run_id, goal_id),
        ).fetchall()
        states = {row["task_key"]: row["state"] for row in rows}
        for row in rows:
            if row["state"] != "pending":
                continue
            dependencies = _loads(row["dependencies"], [])
            missing = [key for key in dependencies if key not in states]
            failed = [key for key in dependencies if states.get(key) in {"blocked", "cancelled", "exhausted", "skipped"}]
            if missing:
                self._db.execute(
                    "UPDATE planner_tasks SET state = 'blocked', error = ?, updated_at = ?, finished_at = ? WHERE id = ?",
                    (f"依赖任务不存在：{', '.join(missing[:4])}", stamp, stamp, row["id"]),
                )
            elif failed:
                self._db.execute(
                    "UPDATE planner_tasks SET state = 'blocked', error = ?, updated_at = ?, finished_at = ? WHERE id = ?",
                    (f"依赖未形成可用结论：{', '.join(failed[:4])}", stamp, stamp, row["id"]),
                )
            elif all(states.get(key) == "completed" for key in dependencies):
                self._db.execute(
                    "UPDATE planner_tasks SET state = 'ready', updated_at = ? WHERE id = ?",
                    (stamp, row["id"]),
                )

    def finish_planner_round(
        self,
        run_id: str,
        plan_id: str,
        *,
        goal_state: str,
        basis_summary: str,
        next_action: str = "",
        missing_context: list[str] | None = None,
        tasks: list[dict] | None = None,
        updates: list[dict] | None = None,
        usage: dict | None = None,
        error: str | None = None,
        reopen_attempts: int = 1,
    ) -> list[dict]:
        """Commit a Planner decision and its validated frontier mutation atomically."""
        tasks = list(tasks or [])
        updates = list(updates or [])
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                plan = self._db.execute("SELECT * FROM planner_plans WHERE id = ? AND run_id = ?", (plan_id, run_id)).fetchone()
                session = self._db.execute("SELECT * FROM planner_sessions WHERE run_id = ?", (run_id,)).fetchone()
                if plan is None or session is None or plan["status"] != "planning":
                    raise ValueError("Planner round is not an active draft")
                stamp = now()
                goal_id = str(session["goal_id"])
                existing = {
                    row["task_key"]: row
                    for row in self._db.execute("SELECT * FROM planner_tasks WHERE run_id = ?", (run_id,)).fetchall()
                }
                proposed_keys = {str(item.get("task_key") or "") for item in tasks}
                known_keys = set(existing) | proposed_keys
                # Keep Store safe even when it is called outside the model-facing
                # validator (for example by a maintenance import). A circular set of
                # dependencies would otherwise remain pending forever with no worker
                # eligible to break the tie.
                graph = {
                    key: [str(dep) for dep in _loads(row["dependencies"], []) if str(dep)]
                    for key, row in existing.items()
                }
                for task in tasks:
                    task_key = str(task.get("task_key") or "")
                    if not task_key:
                        raise ValueError("Planner task has no task_key")
                    deps = list(dict.fromkeys(str(item) for item in task.get("dependencies") or [] if str(item)))
                    unknown = [key for key in deps if key not in known_keys]
                    if unknown or task_key in deps:
                        raise ValueError(f"Planner task dependencies are invalid for {task_key}")
                    prior = existing.get(task_key)
                    if prior is None or prior["state"] in {"pending", "ready", "deferred"}:
                        graph[task_key] = deps
                visiting: set[str] = set()
                visited: set[str] = set()

                def visit(key: str) -> None:
                    if key in visited:
                        return
                    if key in visiting:
                        raise ValueError(f"Planner task dependencies contain a cycle at {key}")
                    visiting.add(key)
                    for dependency in graph.get(key, []):
                        visit(dependency)
                    visiting.remove(key)
                    visited.add(key)

                for key in graph:
                    visit(key)
                for task in tasks:
                    task_key = str(task.get("task_key") or "")
                    if not task_key:
                        raise ValueError("Planner task has no task_key")
                    deps = list(dict.fromkeys(str(item) for item in task.get("dependencies") or [] if str(item)))
                    unknown = [key for key in deps if key not in known_keys]
                    if unknown or task_key in deps:
                        raise ValueError(f"Planner task dependencies are invalid for {task_key}")
                    context_spec = {
                        "source_refs": task.get("source_refs") or [],
                        "scope_paths": task.get("scope_paths") or [],
                        "target_symbols": task.get("target_symbols") or [],
                        "query_hints": task.get("query_hints") or [],
                    }
                    prior = existing.get(task_key)
                    if prior is None:
                        task_id = uuid.uuid4().hex
                        task_session = f"{session['session_id']}:task:{task_id[:10]}"
                        state = "pending" if deps else "ready"
                        self._db.execute(
                            "INSERT INTO planner_tasks (id, run_id, goal_id, plan_id, task_key, title, objective, "
                            "acceptance_criteria, rationale_summary, context_spec, dependencies, session_id, priority, state, "
                            "max_attempts, attempts, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)",
                            (
                                task_id, run_id, goal_id, plan_id, task_key, str(task.get("title") or task_key),
                                str(task.get("objective") or ""), str(task.get("acceptance_criteria") or ""),
                                str(task.get("rationale_summary") or ""), _dumps(context_spec), _dumps(deps), task_session,
                                int(task.get("priority") or 50), state,
                                int(task.get("max_attempts") or self._db.execute(
                                    "SELECT max_iterations FROM task_goals WHERE id = ?", (goal_id,)
                                ).fetchone()["max_iterations"]), stamp, stamp,
                            ),
                        )
                    elif prior["state"] in {"pending", "ready", "deferred"}:
                        self._db.execute(
                            "UPDATE planner_tasks SET plan_id = ?, title = ?, objective = ?, acceptance_criteria = ?, "
                            "rationale_summary = ?, context_spec = ?, dependencies = ?, priority = ?, state = CASE "
                            "WHEN state = 'deferred' THEN 'pending' ELSE state END, error = CASE WHEN state = 'deferred' THEN NULL ELSE error END, "
                            "finished_at = CASE WHEN state = 'deferred' THEN NULL ELSE finished_at END, updated_at = ? WHERE id = ?",
                            (
                                plan_id, str(task.get("title") or task_key), str(task.get("objective") or ""),
                                str(task.get("acceptance_criteria") or ""), str(task.get("rationale_summary") or ""),
                                _dumps(context_spec), _dumps(deps), int(task.get("priority") or 50), stamp, prior["id"],
                            ),
                        )
                for update in updates:
                    task_key = str(update.get("task_key") or "")
                    action = str(update.get("action") or "")
                    row = existing.get(task_key)
                    if row is None:
                        continue
                    # A disposition update moves a conclusion's standing and touches no task
                    # state at all, so a direction that happens to be running right now can
                    # still have a conclusion from an earlier attempt withdrawn.
                    if action in {"retract", "duplicate"}:
                        self._apply_finding_disposition_tx(run_id, str(row["id"]), update, stamp)
                        continue
                    if row["state"] == "running":
                        continue
                    if action == "cancel" and row["state"] in {"pending", "ready", "deferred"}:
                        self._db.execute(
                            "UPDATE planner_tasks SET state = 'cancelled', error = ?, updated_at = ?, finished_at = ? WHERE id = ?",
                            (str(update.get("rationale_summary") or "Planner cancelled task"), stamp, stamp, row["id"]),
                        )
                    elif action == "defer" and row["state"] in {"pending", "ready"}:
                        self._db.execute(
                            "UPDATE planner_tasks SET state = 'deferred', error = ?, updated_at = ? WHERE id = ?",
                            (str(update.get("rationale_summary") or "Planner deferred task"), stamp, row["id"]),
                        )
                    elif action == "reprioritize" and row["state"] in {"pending", "ready", "deferred"}:
                        priority = int(update.get("priority") or row["priority"])
                        self._db.execute(
                            "UPDATE planner_tasks SET priority = ?, updated_at = ? WHERE id = ?",
                            (priority, stamp, row["id"]),
                        )
                    elif action == "reopen" and row["state"] in REOPENABLE_TASK_STATES:
                        # Re-opening a settled direction so it is investigated again.  The
                        # earlier attempts stay exactly where they are: the attempt sequence
                        # is this design's record of how a conclusion was reached and
                        # replaced, and a correction that overwrote it would destroy the
                        # evidence that the correction happened at all.  Only the durable
                        # state moves, and the attempt allowance is *extended* -- a revision
                        # is not a retry, so it must not be paid for out of the retry budget.
                        self._db.execute(
                            "UPDATE planner_tasks SET state = 'pending', revisions = revisions + 1,"
                            " error = NULL, finished_at = NULL, max_attempts = max_attempts + ?,"
                            " updated_at = ? WHERE id = ?",
                            (int(reopen_attempts), stamp, row["id"]),
                        )
                        # The shared goal budget is what `claim_ready_task` exhausts every
                        # pending task against, so a revision that did not extend it would be
                        # re-opened and killed in the same breath.
                        self._db.execute(
                            "UPDATE task_goals SET max_total_attempts = COALESCE(max_total_attempts, 0) + ?,"
                            " updated_at = ? WHERE id = ?",
                            (int(reopen_attempts), stamp, goal_id),
                        )
                        self._db.execute(
                            "UPDATE planner_sessions SET task_reopens = COALESCE(task_reopens, 0) + 1 WHERE run_id = ?",
                            (run_id,),
                        )
                self._refresh_planner_task_states_tx(run_id, goal_id, stamp)
                self._db.execute(
                    "UPDATE planner_plans SET status = ?, goal_state = ?, basis_summary = ?, next_action = ?, "
                    "missing_context = ?, task_snapshot = ?, updates = ?, usage = ?, error = ?, finished_at = ? WHERE id = ?",
                    (
                        "failed" if error else "completed", goal_state, basis_summary, next_action,
                        _dumps(missing_context or []), _dumps(tasks), _dumps(updates),
                        _dumps(usage) if usage is not None else None, error, stamp, plan_id,
                    ),
                )
                session_state = "failed" if error else "dispatching"
                self._db.execute(
                    "UPDATE planner_sessions SET status = ?, updated_at = ? WHERE run_id = ?",
                    (session_state, stamp, run_id),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.list_tasks(run_id)

    def apply_plan(self, run_id: str, plan_id: str, tasks: list[dict], updates: list[dict]) -> list[dict]:
        """Compatibility spelling for callers that pre-compute a Planner decision."""
        return self.finish_planner_round(
            run_id, plan_id, goal_state="continue", basis_summary="Planner applied a validated frontier update.",
            tasks=tasks, updates=updates,
        )

    def claim_ready_task(self, run_id: str, worker_id: str) -> dict | None:
        """Atomically lease one ready multi-file task and reserve global worker budget."""
        task_id: str | None = None
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                session = self._db.execute(
                    "SELECT s.goal_id, g.status AS goal_status, g.attempts, g.max_total_attempts, r.status AS run_status "
                    "FROM planner_sessions AS s JOIN task_goals AS g ON g.id = s.goal_id "
                    "JOIN runs AS r ON r.id = s.run_id WHERE s.run_id = ?", (run_id,)
                ).fetchone()
                if session is None or session["goal_status"] != "open" or session["run_status"] != "running":
                    self._db.execute("COMMIT")
                    return None
                stamp = now()
                self._refresh_planner_task_states_tx(run_id, str(session["goal_id"]), stamp)
                running = self._db.execute(
                    "SELECT COUNT(*) AS count FROM planner_tasks WHERE run_id = ? AND state = 'running'", (run_id,)
                ).fetchone()["count"]
                if int(session["attempts"] or 0) + int(running or 0) >= int(session["max_total_attempts"]):
                    reason = f"worker 共享尝试上限 {session['max_total_attempts']} 已耗尽"
                    self._db.execute(
                        "UPDATE planner_tasks SET state = 'exhausted', error = ?, updated_at = ?, finished_at = ? "
                        "WHERE run_id = ? AND state IN ('pending','ready')",
                        (reason, stamp, stamp, run_id),
                    )
                    self._db.execute("COMMIT")
                    return None
                row = self._db.execute(
                    "SELECT id FROM planner_tasks WHERE run_id = ? AND state = 'ready' "
                    "ORDER BY priority DESC, created_at, id LIMIT 1", (run_id,)
                ).fetchone()
                if row is None:
                    self._db.execute("COMMIT")
                    return None
                self._db.execute(
                    "UPDATE planner_tasks SET state = 'running', claimed_by = ?, claimed_at = ?, updated_at = ? "
                    "WHERE id = ? AND state = 'ready'",
                    (worker_id, stamp, stamp, row["id"]),
                )
                task_id = str(row["id"])
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.get_planner_task(task_id) if task_id else None

    def resolve_task_attempt(
        self,
        task_id: str,
        worker_id: str,
        *,
        outcome: str,
        result: dict,
        usage: dict | None,
        seen: list[dict] | None,
        error: str | None = None,
        terminal_reason: str | None = None,
    ) -> dict | None:
        """Settle one worker pass without letting a worker settle the whole goal."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT * FROM planner_tasks WHERE id = ?", (task_id,)).fetchone()
                if row is None or row["state"] != "running" or row["claimed_by"] != worker_id:
                    self._db.execute("COMMIT")
                    return None
                goal = self._db.execute("SELECT * FROM task_goals WHERE id = ?", (row["goal_id"],)).fetchone()
                if goal is None:
                    raise RuntimeError("Planner task has no goal")
                attempt = int(row["attempts"] or 0) + 1
                stored_result = dict(result or {})
                stored_result["outcome"] = outcome
                stored_result["attempt"] = attempt
                reason = terminal_reason or str(stored_result.get("terminal_reason") or "")
                state = "completed"
                finished_at: str | None = now()
                stored_error = error
                if outcome == "continue":
                    if attempt < int(row["max_attempts"]):
                        state = "ready"
                        finished_at = None
                    elif reason in TASK_RETRY_FAILURE_REASONS:
                        state = "blocked"
                        stored_error = stored_error or "模型或执行预算耗尽，不能据此排除目标"
                    else:
                        state = "exhausted"
                        stored_error = stored_error or "该审计方向已达到每任务最大尝试次数"
                elif outcome == "blocked":
                    state = "blocked"
                    stored_error = stored_error or "任务缺少继续审计所需上下文"
                elif outcome not in {"achieved", "no_evidence"}:
                    state = "blocked"
                    stored_error = stored_error or f"未知 worker 结果：{outcome}"
                stamp = now()
                self._db.execute(
                    "UPDATE planner_tasks SET state = ?, attempts = ?, claimed_by = NULL, claimed_at = NULL, result = ?, "
                    "error = ?, updated_at = ?, finished_at = ? WHERE id = ?",
                    (state, attempt, _dumps(stored_result), stored_error, stamp, finished_at, task_id),
                )
                self._db.execute(
                    "UPDATE task_goals SET attempts = attempts + 1, updated_at = ? WHERE id = ?",
                    (stamp, row["goal_id"]),
                )
                self._db.execute(
                    "INSERT INTO planner_task_attempts (task_id, run_id, goal_id, plan_id, attempt, worker_id, session_id, "
                    "outcome, state, result, usage, seen, error, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        task_id, row["run_id"], row["goal_id"], row["plan_id"], attempt, worker_id,
                        row["session_id"], outcome, state, _dumps(stored_result),
                        _dumps(usage) if usage is not None else None, _dumps(seen or []), stored_error, stamp,
                    ),
                )
                self._refresh_planner_task_states_tx(row["run_id"], row["goal_id"], stamp)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.get_planner_task(task_id)

    def task_queue_state(self, run_id: str) -> dict:
        rows = self._rows(
            "SELECT state, COUNT(*) AS count FROM planner_tasks WHERE run_id = ? GROUP BY state", (run_id,)
        )
        counts = {row["state"]: int(row["count"] or 0) for row in rows}
        return {
            "counts": counts,
            "active": sum(counts.get(state, 0) for state in ("pending", "ready", "running", "deferred")),
            "ready": counts.get("ready", 0),
            "running": counts.get("running", 0),
            "blocked": counts.get("blocked", 0),
            "terminal": sum(counts.get(state, 0) for state in ("completed", "blocked", "exhausted", "cancelled", "skipped")),
            "total": sum(counts.values()),
        }

    def planner_needed(self, run_id: str) -> bool:
        session = self.get_planner_session(run_id)
        goal = self.get_task_goal(run_id)
        if session is None or goal is None or goal.get("status") != "open":
            return False
        state = self.task_queue_state(run_id)
        return int(session.get("current_round") or 0) == 0 or (state["ready"] == 0 and state["running"] == 0)

    def finalize_goal(
        self,
        run_id: str,
        state: str,
        basis_summary: str,
        missing_context: list[str] | None = None,
    ) -> dict:
        """Host-enforced terminal state for the only goal in a Planner run."""
        if state not in {"met", "unreachable", "inconclusive"}:
            raise ValueError("unsupported Planner terminal state")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                goal = self._db.execute("SELECT * FROM task_goals WHERE run_id = ?", (run_id,)).fetchone()
                session = self._db.execute("SELECT * FROM planner_sessions WHERE run_id = ?", (run_id,)).fetchone()
                if goal is None or session is None:
                    raise ValueError("Planner run has no goal/session")
                queue = self.task_queue_state(run_id)
                if state == "met":
                    # "Standing" means valid evidence that nobody has withdrawn.  A finding
                    # the Planner retracted, replaced or marked as a duplicate is still in
                    # the database -- and still in the report -- but it is not something to
                    # close a run on.
                    candidates = self._db.execute(
                        "SELECT finding_kind, category, severity FROM findings WHERE run_id = ? AND validation_state = 'candidate'"
                        f" AND disposition NOT IN {_WITHDRAWN_SQL}",
                        (run_id,),
                    ).fetchall()
                    if not any(is_vulnerability_finding(dict(item)) for item in candidates):
                        raise ValueError("Planner cannot mark a goal met without a validated vulnerability finding")
                elif state == "unreachable":
                    if queue["active"] or queue["blocked"] or not queue["total"]:
                        raise ValueError("unreachable requires exhausted evidence paths without blockers")
                stamp = now()
                reason = basis_summary
                if missing_context:
                    reason = f"{basis_summary}；缺失上下文：{'；'.join(str(item) for item in missing_context[:8])}"
                self._db.execute(
                    "UPDATE task_goals SET status = ?, terminal_reason = ?, updated_at = ? WHERE id = ?",
                    (state, reason, stamp, goal["id"]),
                )
                self._db.execute(
                    "UPDATE planner_sessions SET status = 'completed', terminal_state = ?, terminal_reason = ?, updated_at = ? "
                    "WHERE run_id = ?",
                    (state, reason, stamp, run_id),
                )
                if state == "met":
                    self._db.execute(
                        "UPDATE planner_tasks SET state = 'cancelled', error = ?, updated_at = ?, finished_at = ? "
                        "WHERE run_id = ? AND state IN ('pending','ready','deferred')",
                        ("目标已达成，未启动任务停止", stamp, stamp, run_id),
                    )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        result = self.get_task_goal(run_id)
        if result is None:
            raise RuntimeError("goal disappeared during finalization")
        return result

    def abandon_planner_tasks(self, run_id: str, reason: str) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                stamp = now()
                self._db.execute(
                    "UPDATE planner_tasks SET state = 'blocked', error = ?, updated_at = ?, finished_at = ? "
                    "WHERE run_id = ? AND state = 'running'", (reason, stamp, stamp, run_id),
                )
                self._db.execute(
                    "UPDATE planner_tasks SET state = 'cancelled', error = ?, updated_at = ?, finished_at = ? "
                    "WHERE run_id = ? AND state IN ('pending','ready','deferred')", (reason, stamp, stamp, run_id),
                )
                self._db.execute(
                    "UPDATE task_goals SET status = 'inconclusive', terminal_reason = ?, updated_at = ? "
                    "WHERE run_id = ? AND status = 'open'", (reason, stamp, run_id),
                )
                self._db.execute(
                    "UPDATE planner_sessions SET status = 'cancelled', terminal_state = 'inconclusive', "
                    "terminal_reason = ?, updated_at = ? WHERE run_id = ?", (reason, stamp, run_id),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    # --- findings ----------------------------------------------------------

    def _insert_finding(self, finding: dict) -> dict:
        """Write one conclusion into its slot.

        Returns ``{"action": "created"|"superseded", "finding_id": ..., "revision": n}``.
        The stored id is returned rather than assumed: on the replacement path the row
        keeps the id it already had, so the caller's freshly generated one names nothing.

        A finding owns exactly one slot per ``(run_id, unit_id, category)``.  Re-running
        that direction produces the same slot again, and the row is *reused* rather than
        replaced: its ``id`` survives (so the human ``verifications`` bound to it are not
        orphaned), its ``verdict`` survives (a reviewer's decision is not the audit's to
        discard), and what it used to say is snapshotted into ``superseded_summary``
        before the new text lands.  Deleting and re-inserting the row would silently lose
        all three, which is what ``INSERT OR REPLACE`` did.

        Called with ``_lock`` held and possibly inside a transaction.
        """
        existing = self._db.execute(
            "SELECT id, title, severity, summary, evidence, validation_state, validation_errors,"
            " disposition, disposition_reason, disposition_by, revision, superseded_summary, created_at"
            " FROM findings WHERE run_id = ? AND unit_id = ? AND category = ?",
            (finding["run_id"], finding["unit_id"], finding["category"]),
        ).fetchone()
        if existing is None:
            self._db.execute(
                "INSERT INTO findings (id, run_id, unit_id, fingerprint, category, finding_kind, title, severity,"
                " summary, evidence, input_source, propagation, dangerous_operation, protection, preconditions,"
                " missing_context, poc, remediation, validation_state, validation_errors, verdict, created_at,"
                " revision, disposition, derived_from_finding_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    finding["id"],
                    finding["run_id"],
                    finding["unit_id"],
                    finding["fingerprint"],
                    finding["category"],
                    finding.get("finding_kind", ""),
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
                    1,
                    "open",
                    finding.get("derived_from_finding_id"),
                ),
            )
            return {"action": "created", "finding_id": str(finding["id"]), "revision": 1}
        previous = _loads(existing["superseded_summary"], [])
        if not isinstance(previous, list):
            previous = []
        # The revision this one replaces, kept whole enough to explain a change of mind:
        # what it claimed, whether the evidence held up, and any disposition the Planner
        # or a reviewer had given it.  A new conclusion re-opens the slot, because the
        # disposition describes the content that was just replaced -- the fact that it was
        # once withdrawn lives on in here rather than as a stale flag on live text.
        previous.append({
            "revision": int(existing["revision"] or 1),
            "title": existing["title"],
            "severity": existing["severity"],
            "summary": existing["summary"],
            "evidence": _loads(existing["evidence"], []),
            "validation_state": existing["validation_state"],
            "validation_errors": _loads(existing["validation_errors"], []),
            "disposition": existing["disposition"],
            "disposition_reason": existing["disposition_reason"],
            "disposition_by": existing["disposition_by"],
            "replaced_at": now(),
        })
        self._db.execute(
            "UPDATE findings SET fingerprint = ?, finding_kind = ?, title = ?, severity = ?, summary = ?,"
            " evidence = ?, input_source = ?, propagation = ?, dangerous_operation = ?, protection = ?,"
            " preconditions = ?, missing_context = ?, poc = ?, remediation = ?, validation_state = ?,"
            " validation_errors = ?, revision = revision + 1, superseded_summary = ?, disposition = 'open',"
            " disposition_reason = NULL, disposition_by = NULL, disposition_at = NULL,"
            " derived_from_finding_id = COALESCE(?, derived_from_finding_id) WHERE id = ?",
            (
                finding["fingerprint"],
                finding.get("finding_kind", ""),
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
                _dumps(previous[-MAX_SUPERSEDED_SUMMARIES:]),
                finding.get("derived_from_finding_id"),
                existing["id"],
            ),
        )
        return {
            "action": "superseded",
            "finding_id": str(existing["id"]),
            "revision": int(existing["revision"] or 1) + 1,
        }

    def _apply_finding_disposition_tx(self, run_id: str, task_id: str, update: dict, stamp: str) -> None:
        """Move one finding's disposition inside the round's transaction.

        Only the disposition columns move: the conclusion's text, its evidence and its
        review history are left exactly as they are, so a withdrawal is recorded rather
        than erased.  The row stays in the database and in the report.

        A verdict a human recorded is terminal, so ``retract`` and ``duplicate`` cannot
        take such a conclusion out of the run: the same intent is written as a contest
        instead, and the finding keeps standing as evidence the goal can close on.  That
        rule lives here rather than in the model-facing validator so that every caller --
        including a maintenance import -- gets it.
        """
        key = str(update.get("finding_key") or "")
        row = self._db.execute(
            "SELECT id, unit_id, verdict FROM findings WHERE id = ? AND run_id = ?", (key, run_id)
        ).fetchone()
        if row is None or str(row["unit_id"]) != str(task_id):
            # A finding of another direction is not this update's to move.  The validator
            # refuses this before it reaches the store; the check is repeated because the
            # store is also called outside the model path.
            return
        wanted = "duplicate" if str(update.get("action")) == "duplicate" else "retracted"
        contested = str(row["verdict"] or "") in HUMAN_DECIDED_VERDICTS
        disposition = "contested" if contested else wanted
        related = str(update.get("related_finding_key") or "")
        # Lineage is only recorded when it points at a conclusion that exists: a dangling
        # "derived from" would be worse than none at all.
        if contested or not related:
            source = None
        elif self._db.execute(
            "SELECT 1 FROM findings WHERE id = ? AND run_id = ?", (related, run_id)
        ).fetchone():
            source = related
        else:
            source = None
        self._db.execute(
            "UPDATE findings SET disposition = ?, disposition_reason = ?, disposition_by = 'planner',"
            " disposition_at = ?, derived_from_finding_id = COALESCE(?, derived_from_finding_id)"
            " WHERE id = ?",
            (disposition, str(update.get("rationale_summary") or ""), stamp, source, key),
        )

    def set_finding_disposition(
        self,
        finding_id: str,
        disposition: str,
        reason: str,
        *,
        by: str = "planner",
        derived_from_finding_id: str | None = None,
    ) -> dict | None:
        """Move a conclusion's disposition without touching a byte of its content.

        Only the disposition columns move -- the same column-level setter shape ARTEX uses
        for findings.  A withdrawn conclusion keeps its row, its text and its verifications,
        so the withdrawal is recorded rather than erased.  A disposition a human already
        decided through a verification is handled by the caller, not here.
        """
        if disposition not in FINDING_DISPOSITIONS:
            raise ValueError(f"unsupported finding disposition: {disposition}")
        with self._lock:
            row = self._db.execute("SELECT id FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if row is None:
                return None
            self._db.execute(
                "UPDATE findings SET disposition = ?, disposition_reason = ?, disposition_by = ?,"
                " disposition_at = ?, derived_from_finding_id = COALESCE(?, derived_from_finding_id)"
                " WHERE id = ?",
                (disposition, reason, by, now(), derived_from_finding_id, finding_id),
            )
        return self.get_finding(finding_id)

    def add_finding(self, finding: dict) -> dict:
        """Persist one conclusion into its slot.

        Returns ``{"action", "finding_id", "revision"}``; see ``_insert_finding``.
        """
        with self._lock:
            return self._insert_finding(finding)

    def _finding_dict(self, row: sqlite3.Row) -> dict:
        finding = dict(row)
        for name in ("evidence", "preconditions", "missing_context", "validation_errors", "superseded_summary"):
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
        planner_task = None
        if unit is None:
            planner_task = self._row(
                "SELECT id, task_key, title, context_spec FROM planner_tasks WHERE run_id = ? AND id = ?",
                (finding["run_id"], finding["unit_id"]),
            )
        if unit is not None:
            finding["file_path"] = unit["file_path"]
            finding["symbol"] = unit["symbol"]
            finding["unit_start_line"] = unit["start_line"]
            finding["unit_end_line"] = unit["end_line"]
            finding["task_id"] = None
        elif planner_task is not None:
            context_spec = _loads(planner_task["context_spec"], {})
            source_refs = context_spec.get("source_refs") if isinstance(context_spec, dict) else []
            anchor = next((item for item in source_refs or [] if isinstance(item, dict) and item.get("path")), {})
            first_evidence = next((item for item in finding["evidence"] if item.get("path")), {})
            finding["file_path"] = first_evidence.get("path") or anchor.get("path") or ""
            finding["symbol"] = planner_task["title"]
            finding["unit_start_line"] = int(anchor.get("start_line") or first_evidence.get("start_line") or 0)
            finding["unit_end_line"] = int(anchor.get("end_line") or first_evidence.get("end_line") or 0)
            finding["task_id"] = planner_task["id"]
            finding["task_key"] = planner_task["task_key"]
        else:
            finding["file_path"] = ""
            finding["symbol"] = ""
            finding["unit_start_line"] = 0
            finding["unit_end_line"] = 0
            finding["task_id"] = None
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

    def has_event(self, run_id: str, kind: str) -> bool:
        """Whether this run has already emitted an event of this kind.

        The host uses this to tell a run's *first* execution from a resumed one.  The
        setup events describe a beginning -- a resumed run has already had one, and a
        second ``run_started`` would read in the timeline as a run that began twice.
        """
        row = self._row("SELECT 1 AS present FROM events WHERE run_id = ? AND kind = ? LIMIT 1", (run_id, kind))
        return row is not None

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

    # --- saved model profiles ---------------------------------------------

    @staticmethod
    def _profile_dict(row: sqlite3.Row, *, include_secret: bool = False) -> dict:
        profile = dict(row)
        profile["api_key_configured"] = bool(profile.get("api_key_secret"))
        if not include_secret:
            # Environment variables are allowed to retain a compatibility URL in
            # process memory, but profiles are returned to a browser.  Sanitize
            # every public row so an old local database cannot disclose user-info
            # or query-string credentials through the catalogue endpoint.
            profile["base_url"] = _public_base_url(profile.get("base_url"))
            profile.pop("api_key_secret", None)
        return profile

    def list_model_profiles(self) -> list[dict]:
        rows = self._rows("SELECT * FROM model_profiles ORDER BY ordinal, created_at, id")
        return [self._profile_dict(row) for row in rows]

    def get_model_profile(self, profile_id: str, *, include_secret: bool = False) -> dict | None:
        row = self._row("SELECT * FROM model_profiles WHERE id = ?", (profile_id,))
        return self._profile_dict(row, include_secret=include_secret) if row is not None else None

    def selected_model_profile(self, *, include_secret: bool = False) -> dict | None:
        row = self._row(
            "SELECT profile.* FROM model_selection AS selection "
            "JOIN model_profiles AS profile ON profile.id = selection.selected_profile_id "
            "WHERE selection.id = 1",
        )
        return self._profile_dict(row, include_secret=include_secret) if row is not None else None

    def select_model_profile(self, profile_id: str) -> dict:
        profile = self.get_model_profile(profile_id, include_secret=True)
        if profile is None:
            raise ValueError("model profile does not exist")
        self._write(
            "INSERT INTO model_selection (id, selected_profile_id, updated_at) VALUES (1,?,?) "
            "ON CONFLICT(id) DO UPDATE SET selected_profile_id=excluded.selected_profile_id, updated_at=excluded.updated_at",
            (profile_id, now()),
        )
        return profile

    def create_model_profile(
        self,
        *,
        label: str,
        model: str,
        base_url: str,
        api_key_secret: str = "",
        credential_source: str = "stored",
    ) -> dict:
        profile_id = uuid.uuid4().hex
        stamp = now()
        ordinal_row = self._row("SELECT COALESCE(MAX(ordinal), -1) + 1 AS ordinal FROM model_profiles")
        ordinal = int(ordinal_row["ordinal"] or 0) if ordinal_row else 0
        self._write(
            "INSERT INTO model_profiles (id, label, model, base_url, api_key_secret, credential_source, ordinal, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (profile_id, label, model, base_url, api_key_secret, credential_source, ordinal, stamp, stamp),
        )
        profile = self.get_model_profile(profile_id, include_secret=True)
        if profile is None:  # pragma: no cover - SQLite insert above is atomic
            raise RuntimeError("model profile was not persisted")
        return profile

    def update_model_profile(
        self,
        profile_id: str,
        *,
        label: str,
        model: str,
        base_url: str,
        api_key_secret: str | None = None,
        credential_source: str | None = None,
    ) -> dict:
        current = self.get_model_profile(profile_id, include_secret=True)
        if current is None:
            raise ValueError("model profile does not exist")
        secret = current["api_key_secret"] if api_key_secret is None else api_key_secret
        source = current["credential_source"] if credential_source is None else credential_source
        self._write(
            "UPDATE model_profiles SET label = ?, model = ?, base_url = ?, api_key_secret = ?, credential_source = ?, "
            "updated_at = ? WHERE id = ?",
            (label, model, base_url, secret, source, now(), profile_id),
        )
        updated = self.get_model_profile(profile_id, include_secret=True)
        if updated is None:  # pragma: no cover - guarded above
            raise RuntimeError("model profile disappeared during update")
        return updated

    def delete_model_profile(self, profile_id: str) -> bool:
        with self._lock:
            cursor = self._db.execute("DELETE FROM model_profiles WHERE id = ?", (profile_id,))
        return bool(cursor.rowcount)

    def ensure_environment_model_profile(self, model: str, base_url: str) -> dict | None:
        """Seed or refresh the non-secret profile backed by ``LLM_*`` variables."""
        default_model = str(model or "").strip()
        # Never persist credentials embedded in a legacy environment endpoint.
        # Services keeps the original environment URL only in memory for clients
        # that require a compatibility query parameter.
        default_base_url = _public_base_url(base_url)
        environment = self._row(
            "SELECT * FROM model_profiles WHERE credential_source = 'environment' ORDER BY created_at LIMIT 1"
        )
        if default_model:
            label = f"环境变量 · {default_model}"
            if environment is None:
                profile = self.create_model_profile(
                    label=label,
                    model=default_model,
                    base_url=default_base_url,
                    credential_source="environment",
                )
            else:
                profile = self.update_model_profile(
                    environment["id"], label=label, model=default_model, base_url=default_base_url,
                    credential_source="environment",
                )
        elif environment is not None:
            # Normalize any pre-profile database row even when the environment
            # configuration was later removed.
            profile = self.update_model_profile(
                environment["id"],
                label=environment["label"],
                model=environment["model"],
                base_url=_public_base_url(environment["base_url"]),
                credential_source="environment",
            )
        else:
            profile = None

        selected = self.selected_model_profile(include_secret=True)
        if selected is None:
            choices = self.list_model_profiles()
            if profile is not None:
                selected = self.select_model_profile(profile["id"])
            elif choices:
                selected = self.select_model_profile(choices[0]["id"])
        return selected

    def active_run_count(self) -> int:
        # A paused run counts as active: it holds an unfinished frontier and will be
        # continued, so treating it as idle would let a model-profile switch land under
        # work that is about to resume.
        row = self._row("SELECT COUNT(*) AS total FROM runs WHERE status IN ('pending','running','paused')")
        return int(row["total"] or 0) if row else 0

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
