"""Read-only Prompt trial facts and append-aware live metrics.

No service construction, model configuration, migrations, or benchmark truth are
needed to inspect a child database. Optional metrics cannot erase durable facts.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re

from .db import Store


def _all_events(store: Store, run_id: str) -> list[dict]:
    events = []
    after = 0
    while batch := store.list_events(run_id, after=after, limit=1000):
        events.extend(batch)
        after = batch[-1]["id"]
    return events


def _ranges(payload: dict):
    """Both legacy reviewed_ranges dictionaries and finding evidence lists exist."""
    seen = payload.get("seen")
    if isinstance(seen, list):
        yield from seen
    evidence = payload.get("evidence")
    if isinstance(evidence, dict):
        reviewed = evidence.get("reviewed_ranges")
        if isinstance(reviewed, list):
            yield from reviewed
    elif isinstance(evidence, list):
        yield from evidence


class LiveStats:
    """Consume each event once; heartbeats never rescan model-response history."""
    def __init__(self, snapshot: dict | None = None):
        self.files = {
            item["path"]: item["line_count"]
            for item in (snapshot or {}).get("files") or []
            if isinstance(item, dict) and isinstance(item.get("path"), str)
            and type(item.get("line_count")) is int and item["line_count"] >= 0
            and item.get("kind", "text") == "text"
        }
        self.intervals: set[tuple[str, int, int]] = set()
        self.last_event_id = 0
        self.last_event_at = None
        self.phase = None
        self.response_count = 0
        self.complete_responses = 0
        self.known_input = 0
        self.known_output = 0

    def consume(self, events: list[dict]) -> None:
        for event in events:
            ident = event.get("id")
            if type(ident) is int:
                if ident <= self.last_event_id:
                    continue
                self.last_event_id = ident
            self.last_event_at = event.get("created_at") or self.last_event_at
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            if event.get("kind") == "model_response":
                self.response_count += 1
                self.complete_responses += (payload.get("token_usage_complete") is True
                                            and all(type(payload.get(field)) is int and payload[field] >= 0
                                                    for field in ("input_tokens", "output_tokens")))
                for field, attr in (("input_tokens", "known_input"), ("output_tokens", "known_output")):
                    if type(payload.get(field)) is int and payload[field] >= 0:
                        setattr(self, attr, getattr(self, attr) + payload[field])
            if event.get("kind") == "agent_phase":
                self.phase = payload.get("phase") or self.phase
            elif event.get("kind") in {"planner_round_started", "planner_worker_started"}:
                self.phase = event["kind"]
            for ref in _ranges(payload):
                if not isinstance(ref, dict):
                    continue
                path, start, end = ref.get("path"), ref.get("start_line"), ref.get("end_line")
                if (isinstance(path, str) and path in self.files and type(start) is int
                        and type(end) is int and 1 <= start <= end <= self.files[path]):
                    self.intervals.add((path, start, end))

    def refresh(self, store: Store, run_id: str) -> None:
        while batch := store.list_events(run_id, after=self.last_event_id, limit=1000):
            self.consume(batch)

    def usage(self, run: dict | None) -> dict:
        actual = (run or {}).get("usage") or {}
        requests = int(actual.get("requests") or 0)
        complete = self.response_count == requests and self.complete_responses == self.response_count
        return {
            "requests": requests, "tool_calls": int(actual.get("tool_calls") or 0),
            "input_tokens": self.known_input if complete else None,
            "output_tokens": self.known_output if complete else None,
            "total_tokens": self.known_input + self.known_output if complete else None,
            "known_input_tokens": self.known_input, "known_output_tokens": self.known_output,
            "known_total_tokens": self.known_input + self.known_output,
            "token_usage_complete": complete,
        }

    def coverage(self) -> dict:
        merged = []
        for path, start, end in sorted(self.intervals):
            if merged and merged[-1][0] == path and start <= merged[-1][2] + 1:
                merged[-1] = (path, merged[-1][1], max(merged[-1][2], end))
            else:
                merged.append((path, start, end))
        read_lines = sum(end - start + 1 for _, start, end in merged)
        read_files = len({path for path, _, _ in merged})
        total_lines = sum(self.files.values())
        return {"read_files": read_files, "total_files": len(self.files), "read_lines": read_lines,
                "total_lines": total_lines, "file_ratio": read_files / len(self.files) if self.files else None,
                "line_ratio": read_lines / total_lines if total_lines else None}


def _usage(run: dict | None, events: list[dict]) -> dict:
    stats = LiveStats()
    stats.consume(events)
    return stats.usage(run)


def _read_coverage(snapshot: dict | None, events: list[dict]) -> dict:
    stats = LiveStats(snapshot)
    stats.consume(events)
    return stats.coverage()


def _infrastructure_failure(run: dict | None, events: list[dict]) -> dict | None:
    """Only explicit terminal provider outages invalidate a trial, not poor output."""
    if not run or run.get("status") not in {"failed", "inconclusive"}:
        return None
    reason = (run.get("execution_summary") or {}).get("stop_reason") or {}
    if reason.get("code") == "run_budget_exhausted":
        return None
    terminals = [event.get("payload") or {} for event in events
                 if event.get("kind") in {"task_agent_terminal", "planner_agent_terminal"}
                 and isinstance(event.get("payload"), dict)]
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


def audit_elapsed_seconds(run: dict | None) -> float:
    if not run or not run.get("started_at"):
        return 0.0
    # A child owns one uninterrupted claim. Wall time also captures a process killed
    # between persistent budget ticks; never infer resumed historical run activity.
    try:
        started = datetime.fromisoformat(run["started_at"].replace("Z", "+00:00"))
        ended = datetime.fromisoformat(run["finished_at"].replace("Z", "+00:00")) if run.get("finished_at") else datetime.now(timezone.utc)
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        if ended.tzinfo is None:
            ended = ended.replace(tzinfo=timezone.utc)
        return round(max(0.0, (ended - started).total_seconds()), 3)
    except (TypeError, ValueError):
        usage = (run.get("execution_summary") or {}).get("run_usage") or {}
        return round(float(usage.get("seconds") or 0), 3)


def _warning(code: str, exc: Exception) -> dict:
    # Exceptions can contain values from archived source. Keep public diagnostics
    # structural, without reflecting source text or credentials to stdout.
    return {"code": code, "message": f"{type(exc).__name__}: optional trial metric unavailable"}


def collect_trial(store: Store, run_id: str, snapshot: dict | None = None) -> dict:
    """Collect durable facts first; independently guard every derived metric."""
    warnings = []
    run = store.get_run(run_id)
    if run is None:
        return {"run": None, "findings": [], "snapshot": None, "usage": {}, "read_coverage": None,
                "stop_reason": {}, "warnings": [{"code": "run_unavailable", "message": "Archived run does not exist"}],
                "audit_started_at": None, "audit_elapsed_seconds": 0.0, "infra_error": None}
    findings = store.list_findings(run_id)
    snapshot = snapshot or store.get_snapshot(run["snapshot_id"])
    try:
        events = _all_events(store, run_id)
    except Exception as exc:
        events = []
        warnings.append(_warning("events_unavailable", exc))
    result = {
        "run": run, "findings": findings,
        "snapshot": {key: snapshot.get(key) for key in ("id", "name", "archive_sha256", "content_key", "project_id", "file_count")} if snapshot else None,
        "stop_reason": (run.get("execution_summary") or {}).get("stop_reason") or {"code": run.get("status", "unknown")},
        "warnings": warnings, "audit_started_at": run.get("started_at"),
        "audit_elapsed_seconds": audit_elapsed_seconds(run),
    }
    if result["snapshot"] is not None and result["snapshot"].get("file_count") is None:
        result["snapshot"]["file_count"] = len((snapshot or {}).get("files") or [])
    for key, function in (("usage", lambda: _usage(run, events)),
                          ("read_coverage", lambda: _read_coverage(snapshot, events) if snapshot and isinstance(snapshot.get("files"), list) else None),
                          ("infra_error", lambda: _infrastructure_failure(run, events))):
        try:
            result[key] = function()
        except Exception as exc:
            result[key] = None
            warnings.append(_warning(key + "_unavailable", exc))
    return result


def recover_trial(data_dir: Path, run_id: str | None = None) -> dict:
    """Read an existing child database and immutable index without creating files.

    Missing/unreadable archives raise an exception for the parent to classify. This
    function never reads or repairs result.json: that file can be absent or corrupt.
    """
    root = Path(data_dir).resolve(strict=True)
    store = Store.open_readonly(root / "audit.db")
    try:
        if run_id is None:
            row = store._row("SELECT id FROM runs ORDER BY created_at DESC LIMIT 1")
            run_id = row["id"] if row else None
        if run_id is None:
            return {"run": None, "findings": [], "snapshot": None, "usage": {}, "read_coverage": None,
                    "stop_reason": {}, "warnings": [{"code": "run_unavailable", "message": "Archive has no run"}],
                    "audit_started_at": None, "audit_elapsed_seconds": 0.0, "infra_error": None}
        run = store.get_run(run_id)
        snapshot = store.get_snapshot(run["snapshot_id"]) if run else None
        index_warning = None
        if snapshot and re.fullmatch(r"[a-f0-9]{32}", snapshot["id"]):
            index = (root / "snapshots" / snapshot["id"] / "index.json").resolve()
            try:
                if not index.is_relative_to(root):
                    raise ValueError("Snapshot metadata escapes archive")
                payload = json.loads(index.read_text(encoding="utf-8"))
                if not isinstance(payload, dict) or payload.get("id") != snapshot["id"]:
                    raise ValueError("Snapshot metadata identifier differs")
                snapshot = {**snapshot, "files": payload.get("files")}
            except Exception as exc:
                index_warning = _warning("snapshot_index_unavailable", exc)
        result = collect_trial(store, run_id, snapshot)
        if index_warning:
            result["warnings"].append(index_warning)
        result["recovered_from_archive"] = True
        return result
    finally:
        store.close()
