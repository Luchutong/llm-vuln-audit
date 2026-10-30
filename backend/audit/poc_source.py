"""Bounded white-box source context for POC verification.

A verification used to receive only the finding's summary, coordinates and stored
POC, with no way to read the code it was asked to exercise.  This module preloads a
small, host-chosen window from the *frozen snapshot the finding came from* and exposes
one read-only tool for bounded follow-up reads.

It never uses the project's newest ZIP, the host filesystem, the audit database or the
answer directory, and it never guesses a path: a coordinate that cannot be resolved in
the snapshot is reported as ``source_unavailable`` instead of being approximated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

PROGRESS_POLICY = "bounded-evidence-v1"

# Enough coordinates for a finding's own evidence list plus the primary sink line;
# beyond this the budget is spent on window content rather than more entry points.
MAX_EVIDENCE_RANGES = 8
# Ranges closer than this are merged so an overlapping evidence pair is read once.
MERGE_GAP = 4
# Rough per-line JSON framing (number key, quotes, commas) counted against the caps.
LINE_OVERHEAD = 12


def progress_policy_snapshot() -> dict:
    """The parameters a new run freezes next to ``progress_policy``."""
    limits = SourceLimits()
    progress = ProgressLimits()
    return {
        "version": PROGRESS_POLICY,
        "initial_bytes": limits.initial_bytes,
        "initial_files": limits.initial_files,
        "context_lines": limits.context_lines,
        "read_lines": limits.read_lines,
        "read_bytes": limits.read_bytes,
        "read_calls": limits.read_calls,
        **progress.public(),
    }


@dataclass(frozen=True)
class ProgressLimits:
    """Frozen bounds for the checkpoint/continue/recovery state machine.

    These are caps, not grants: a checkpoint never adds requests, jobs or time, and
    every experiment still passes the original stage and run admission gates.
    """

    # Completed experiment jobs before the host stops the item for a checkpoint.
    checkpoint_experiments: int = 2
    # Bounded continuations per item.  Each one re-arms exactly one batch.
    continues: int = 2
    # Elapsed-item reminder; a reminder alone is never a failure.
    item_warning_seconds: int = 600
    # Read-only recovery after a broken stream, taken from the item's own window.
    recovery_seconds: float = 60.0
    recovery_requests: int = 3
    cleanup_seconds: float = 10.0

    @classmethod
    def from_params(cls, params: dict | None) -> "ProgressLimits":
        if not isinstance(params, dict):
            return cls()
        defaults = cls()

        def bounded(key: str, default: int, low: int, high: int) -> int:
            value = params.get(key)
            return default if type(value) is not int else max(low, min(high, value))

        return cls(
            checkpoint_experiments=bounded("checkpoint_experiments", defaults.checkpoint_experiments, 1, 8),
            continues=bounded("continues", defaults.continues, 0, 4),
            item_warning_seconds=bounded("item_warning_seconds", defaults.item_warning_seconds, 30, 3600),
            recovery_seconds=float(bounded("recovery_seconds", int(defaults.recovery_seconds), 5, 180)),
            recovery_requests=bounded("recovery_requests", defaults.recovery_requests, 1, 6),
            cleanup_seconds=float(bounded("cleanup_seconds", int(defaults.cleanup_seconds), 1, 60)),
        )

    def public(self) -> dict:
        return {
            "checkpoint_experiments": self.checkpoint_experiments,
            "continues": self.continues,
            "item_warning_seconds": self.item_warning_seconds,
            "recovery_seconds": int(self.recovery_seconds),
            "recovery_requests": self.recovery_requests,
            "cleanup_seconds": int(self.cleanup_seconds),
        }


@dataclass(frozen=True)
class SourceLimits:
    # Whole first batch: at most 24 KiB of UTF-8 across at most four files.
    initial_bytes: int = 24 * 1024
    initial_files: int = 4
    # Extra context around each declared evidence range, in original line numbers.
    context_lines: int = 20
    # One tool read: at most 200 lines and 16 KiB of source text.
    read_lines: int = 200
    read_bytes: int = 16 * 1024
    read_calls: int = 12

    @classmethod
    def from_params(cls, params: dict | None) -> "SourceLimits":
        """Rebuild the frozen limits, clamping corrupt values instead of widening them."""
        if not isinstance(params, dict):
            return cls()
        defaults = cls()

        def bounded(key: str, default: int, low: int, high: int) -> int:
            value = params.get(key)
            if type(value) is not int:
                return default
            return max(low, min(high, value))

        return cls(
            initial_bytes=bounded("initial_bytes", defaults.initial_bytes, 4096, 96 * 1024),
            initial_files=bounded("initial_files", defaults.initial_files, 1, 8),
            context_lines=bounded("context_lines", defaults.context_lines, 0, 80),
            read_lines=bounded("read_lines", defaults.read_lines, 20, 400),
            read_bytes=bounded("read_bytes", defaults.read_bytes, 2048, 64 * 1024),
            read_calls=bounded("read_calls", defaults.read_calls, 1, 32),
        )

    def public(self) -> dict:
        return {
            "initial_bytes": self.initial_bytes,
            "initial_files": self.initial_files,
            "context_lines": self.context_lines,
            "read_lines": self.read_lines,
            "read_bytes": self.read_bytes,
            "read_calls": self.read_calls,
        }


def _line_number(value) -> int | None:
    # Booleans are ints in Python; a boolean line number is a model mistake and must be
    # rejected rather than silently becoming line 1.
    if type(value) is int and value >= 1:
        return value
    return None


def _release(text: str) -> tuple[int, ...]:
    match = re.search(r"\d+(?:\.\d+)+", str(text or ""))
    if not match:
        return ()
    parts = [int(part) for part in match.group(0).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _encode_size(text: str) -> int:
    return len(str(text or "").encode("utf-8"))


class PocSourceProvider:
    """One finding's bounded view of its own frozen source snapshot.

    ``read`` is the only entry point the model reaches (through the tool service);
    ``initial_context`` is rendered into the execute prompt by the host.
    """

    def __init__(
        self,
        repository,
        snapshot_id: str,
        *,
        finding: dict,
        target_version: str = "",
        limits: SourceLimits | None = None,
    ) -> None:
        self.repository = repository
        self.snapshot_id = str(snapshot_id or "")
        self.finding = finding if isinstance(finding, dict) else {}
        self.target_version = str(target_version or "")
        self.limits = limits or SourceLimits()
        self.reads: list[dict] = []
        self.bytes_read = 0
        self.calls = 0
        self._snapshot: dict | None = None
        self._reason = ""
        self._initial: dict | None = None
        self._load()

    def _load(self) -> None:
        if not self.snapshot_id:
            self._reason = "missing_snapshot"
            return
        try:
            snapshot = self.repository.get_snapshot(self.snapshot_id)
        except (FileNotFoundError, ValueError, OSError):
            snapshot = None
        if not isinstance(snapshot, dict):
            snapshot = None
        self._snapshot = snapshot
        if snapshot is None:
            self._reason = "snapshot_unavailable"

    @property
    def available(self) -> bool:
        return self._snapshot is not None

    @property
    def snapshot_name(self) -> str:
        return str((self._snapshot or {}).get("name") or "")

    @property
    def archive_version(self) -> str:
        match = re.search(r"\d+(?:\.\d+)+", self.snapshot_name)
        return match.group(0) if match else ""

    @property
    def applicability(self) -> str:
        """Whether the archived source is known to describe the running target."""
        archive, target = _release(self.archive_version), _release(self.target_version)
        if not archive or not target:
            return "unknown"
        return "match" if archive == target else "mismatch"

    # --- first batch ------------------------------------------------------------

    def _candidate_ranges(self) -> list[dict]:
        candidates: list[dict] = []
        primary = self.finding.get("primary_location")
        if isinstance(primary, dict):
            path = str(primary.get("path") or "")
            line = _line_number(primary.get("line"))
            if path and line:
                candidates.append({"path": path, "start": line, "end": line,
                                   "purpose": "primary_location"})
        evidence = self.finding.get("evidence")
        if isinstance(evidence, list):
            for item in evidence[:MAX_EVIDENCE_RANGES]:
                if not isinstance(item, dict):
                    continue
                path = str(item.get("path") or "")
                start = _line_number(item.get("start_line"))
                end = _line_number(item.get("end_line")) or start
                if path and start:
                    candidates.append({"path": path, "start": start,
                                       "end": max(start, end), "purpose": "evidence"})
        return candidates

    def _expanded(self, item: dict) -> tuple[int, int]:
        """Grow a declared range by context lines, staying within one tool read."""
        start = max(1, item["start"] - self.limits.context_lines)
        end = item["end"] + self.limits.context_lines
        if end - start + 1 > self.limits.read_lines:
            if item["end"] - item["start"] + 1 > self.limits.read_lines:
                # The evidence range alone exceeds one read; keep its beginning and let
                # the model continue from ``next_start``.
                start, end = item["start"], item["start"] + self.limits.read_lines - 1
            else:
                start = max(1, item["end"] - self.limits.read_lines + 1)
                end = item["end"]
        return start, end

    @staticmethod
    def _merge(ranges: list[dict]) -> list[dict]:
        ordered = sorted(ranges, key=lambda item: (item["start"], item["end"]))
        merged: list[dict] = []
        for item in ordered:
            if merged and item["start"] <= merged[-1]["end"] + MERGE_GAP:
                merged[-1]["end"] = max(merged[-1]["end"], item["end"])
                if item["purpose"] not in merged[-1]["purposes"]:
                    merged[-1]["purposes"].append(item["purpose"])
                continue
            merged.append({"start": item["start"], "end": item["end"],
                           "purposes": [item["purpose"]]})
        return merged

    def initial_context(self) -> dict:
        if self._initial is not None:
            return self._initial
        base = {
            "policy": PROGRESS_POLICY,
            "available": self.available,
            "reason": self._reason,
            "snapshot_id": self.snapshot_id,
            "snapshot_name": self.snapshot_name,
            "archive_version": self.archive_version,
            "target_version": self.target_version,
            "applicability": self.applicability,
            "limits": self.limits.public(),
            "files": [],
            "unavailable": [],
            "omitted_files": 0,
            "omitted_ranges": 0,
            "bytes": 0,
            "truncated": False,
        }
        if not self.available:
            self._initial = base
            return base
        by_path: dict[str, list[dict]] = {}
        for item in self._candidate_ranges():
            start, end = self._expanded(item)
            by_path.setdefault(item["path"], []).append(
                {"start": start, "end": end, "purpose": item["purpose"]}
            )
        used = 0
        truncated = False
        for path, ranges in by_path.items():
            if len(base["files"]) >= self.limits.initial_files:
                base["omitted_files"] += 1
                continue
            entry = {
                "path": path,
                "sha256": "",
                "start_line": 0,
                "end_line": 0,
                "lines": [],
                "ranges": [],
            }
            for merged in self._merge(ranges):
                if used >= self.limits.initial_bytes - 256:
                    base["omitted_ranges"] += 1
                    truncated = True
                    continue
                try:
                    window = self.repository.read_source(
                        self.snapshot_id, path, merged["start"], merged["end"],
                    )
                except (FileNotFoundError, ValueError, OSError):
                    # One unreadable coordinate never hides the rest of the finding.
                    base["omitted_ranges"] += 1
                    continue
                kept, next_start = [], None
                for line in window.get("lines") or []:
                    size = _encode_size(line.get("text")) + LINE_OVERHEAD
                    if used + size > self.limits.initial_bytes:
                        truncated = True
                        next_start = line.get("number")
                        break
                    used += size
                    kept.append(line)
                if not kept:
                    base["omitted_ranges"] += 1
                    continue
                entry["sha256"] = entry["sha256"] or str(window.get("sha256") or "")
                if not entry["lines"]:
                    entry["start_line"] = kept[0]["number"]
                entry["end_line"] = kept[-1]["number"]
                entry["lines"].extend(kept)
                entry["ranges"].append({
                    "start_line": window.get("start_line"),
                    "end_line": kept[-1]["number"],
                    "purposes": merged["purposes"],
                    "truncated": bool(window.get("truncated")) or next_start is not None,
                    "next_start": next_start or window.get("next_start"),
                })
            if entry["lines"]:
                base["files"].append(entry)
            else:
                reason = "file_not_in_snapshot"
                base["unavailable"].append({"path": path, "reason": reason})
        base["bytes"] = used
        base["truncated"] = truncated or bool(base["omitted_files"] or base["omitted_ranges"])
        if not base["files"] and not base["unavailable"]:
            base["available"] = False
            base["reason"] = "no_evidence_coordinates"
        self._initial = base
        return base

    # --- read-only follow-up ----------------------------------------------------

    def read(self, path, start_line=1, end_line=120) -> dict:
        if not self.available:
            return {"ok": False, "error": "source_unavailable",
                    "reason": self._reason or "source_unavailable", "snapshot_id": self.snapshot_id,
                    "message": "本次验证没有可用的冻结源码快照；不要猜测路径或使用其它版本。"}
        if not isinstance(path, str) or not path.strip():
            return {"ok": False, "error": "invalid_path",
                    "message": "path 必须是快照内的非空相对路径。"}
        # Rejected before any read: bool line numbers, reversed or out-of-range windows.
        if (isinstance(start_line, bool) or isinstance(end_line, bool)
                or type(start_line) is not int or type(end_line) is not int):
            return {"ok": False, "error": "invalid_range",
                    "message": "行号必须是整数，布尔值不接受。"}
        if start_line < 1 or end_line < start_line:
            return {"ok": False, "error": "invalid_range",
                    "message": "start_line 必须 >= 1 且 end_line 不小于 start_line。"}
        if end_line - start_line + 1 > self.limits.read_lines:
            return {"ok": False, "error": "invalid_range",
                    "message": f"单次最多读取 {self.limits.read_lines} 行，请缩小窗口。"}
        if self.calls >= self.limits.read_calls:
            return {"ok": False, "error": "source_read_budget_exhausted",
                    "reads_remaining": 0, "read_budget": self.limits.read_calls,
                    "message": "本项的源码补读次数已用完；使用已读内容发布或如实说明缺口。"}
        try:
            window = self.repository.read_source(self.snapshot_id, path, start_line, end_line)
        except FileNotFoundError:
            return {"ok": False, "error": "source_unavailable", "reason": "file_not_in_snapshot",
                    "path": path, "message": "该路径不在冻结快照中；不要猜测其它路径或版本。"}
        except ValueError as exc:
            message = str(exc)
            if "start line exceeds" in message:
                return {"ok": False, "error": "invalid_range", "path": path,
                        "message": "起始行超出文件长度。"}
            return {"ok": False, "error": "source_unavailable", "reason": "unreadable",
                    "path": path, "message": message[:300]}
        lines, used, truncated = [], 0, bool(window.get("truncated"))
        next_start = window.get("next_start")
        for line in window.get("lines") or []:
            size = _encode_size(line.get("text")) + LINE_OVERHEAD
            if used + size > self.limits.read_bytes:
                truncated, next_start = True, line.get("number")
                break
            used += size
            lines.append(line)
        if not lines:
            return {"ok": False, "error": "invalid_range", "path": path,
                    "message": "该窗口没有可返回的行。"}
        actual_end = lines[-1]["number"]
        self.calls += 1
        self.bytes_read += used
        self.reads.append({"path": window.get("path"), "start_line": window.get("start_line"),
                           "end_line": actual_end, "bytes": used})
        return {
            "ok": True,
            "snapshot_id": window.get("snapshot_id"),
            "path": window.get("path"),
            "sha256": window.get("sha256"),
            "start_line": window.get("start_line"),
            "end_line": actual_end,
            "lines": lines,
            "truncated": truncated,
            "next_start": next_start,
            "applicability": self.applicability,
            "reads_remaining": self.limits.read_calls - self.calls,
            "read_budget": self.limits.read_calls,
        }

    def snapshot(self) -> dict:
        """Host record of what source this finding actually received and read."""
        return {
            "policy": PROGRESS_POLICY,
            "available": self.available,
            "reason": self._reason,
            "snapshot_id": self.snapshot_id,
            "archive_version": self.archive_version,
            "target_version": self.target_version,
            "applicability": self.applicability,
            "initial_bytes": int((self._initial or {}).get("bytes") or 0),
            "initial_files": len((self._initial or {}).get("files") or []),
            "read_calls": self.calls,
            "read_budget": self.limits.read_calls,
            "bytes_read": self.bytes_read,
            "reads": self.reads[-16:],
            "reads_omitted": max(0, len(self.reads) - 16),
        }
