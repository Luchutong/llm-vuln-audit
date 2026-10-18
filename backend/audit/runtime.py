"""Finite execution policy and the exact source text delivered to the model."""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field

from pydantic_ai.usage import RunUsage


@dataclass(frozen=True)
class AgentPolicy:
    version: str = "whitebox-2"
    request_seconds: float = 60.0
    tool_seconds: float = 5.0
    exploration_fraction: float = 0.55
    repeated_calls: int = 2
    no_progress_calls: int = 3
    tool_bytes: int = 16 * 1024
    source_bytes: int = 64 * 1024
    history_bytes: int = 192 * 1024

    def snapshot(self) -> dict:
        return asdict(self)


class StopAudit(Exception):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


@dataclass
class Execution:
    budgets: dict
    policy: AgentPolicy
    emit: object
    started: float = field(default_factory=time.monotonic)
    usage: RunUsage = field(default_factory=RunUsage)
    attempts: int = 0
    tools: int = 0
    corrections: int = 0
    phase: str = "prepare"
    phases: dict = field(default_factory=dict)

    @property
    def deadline(self) -> float:
        return self.started + self.budgets["seconds"]

    def remaining(self, deadline: float | None = None) -> float:
        return min(self.deadline, deadline or self.deadline) - time.monotonic()

    def enter(self, phase: str, **details) -> None:
        self.phase = phase
        self.phases.setdefault(phase, {"model_attempts": 0, "tool_calls": 0})
        self.emit({"kind": "agent_phase", "phase": phase, **details, "remaining_seconds": round(max(0, self.remaining()), 2)})

    def before_model(self, *, deadline: float, limit: int, correction: bool) -> float:
        if self.remaining(deadline) <= 0:
            raise StopAudit("timeout", "单元或当前阶段的墙钟预算已到期")
        if self.attempts >= min(limit, self.budgets["responses"]):
            raise StopAudit("budget", "模型请求预算已用尽（包括纠正与失败请求）")
        if correction:
            # The Agent limits corrections per output; this execution-wide count is
            # observational only. Shared response/time budgets bound retries across phases.
            self.corrections += 1
            self.emit({"kind": "model_retry", "phase": self.phase, "corrections": self.corrections})
        self.attempts += 1
        self.phases[self.phase]["model_attempts"] += 1
        self.emit({"kind": "model_request", "phase": self.phase, "attempt": self.attempts})
        return min(self.policy.request_seconds, self.remaining(deadline))

    def before_tool(self) -> None:
        if self.remaining() <= 0:
            raise StopAudit("timeout", "单元墙钟预算已到期")
        if self.tools >= self.budgets["tools"]:
            raise StopAudit("budget", "工具尝试预算已用尽")
        self.tools += 1
        self.phases[self.phase]["tool_calls"] += 1

    def snapshot(self) -> dict:
        return {
            "requests": self.usage.requests,
            "tool_calls": self.tools,
            "input_tokens": self.usage.input_tokens,
            "output_tokens": self.usage.output_tokens,
            "model_attempts": self.attempts,
            "corrections": self.corrections,
            "elapsed_seconds": round(time.monotonic() - self.started, 3),
            "phases": self.phases,
        }


@dataclass
class SourceLedger:
    """Keep full lines only, with a byte limit; never re-read omitted tool output."""

    max_bytes: int
    lines: dict = field(default_factory=dict)
    bytes_used: int = 0

    def offer(self, path: str, lines: list[dict], max_bytes: int) -> tuple[str, int, bool]:
        """Offer full lines and report whether the global ledger reached capacity.

        A per-tool reply may be shortened while the ledger still has room, in which case
        the caller can ask a narrower follow-up.  ``ledger_full`` means no unseen source
        line could be retained at all, so further exploration would no longer be
        evidence-preserving and must switch to a verdict.
        """
        pieces: list[str] = []
        used = 0
        added = 0
        ledger_full = False
        for line in lines:
            number, source = int(line["number"]), line["text"]
            rendered = f"{path}:{number} | {source}\n"
            size = len(rendered.encode("utf-8"))
            key = (path, number, source)
            request_full = used + size > max_bytes
            ledger_full = ledger_full or (key not in self.lines and self.bytes_used + size > self.max_bytes)
            if request_full or ledger_full:
                pieces.append("[源码返回被截断；未显示的行没有登记为已读，请缩小范围补读]\n")
                break
            pieces.append(rendered)
            used += size
            if key not in self.lines:
                self.lines[key] = rendered
                self.bytes_used += size
                added += 1
        return "".join(pieces), added, ledger_full

    def line_records(self, path: str) -> list[dict]:
        """Return exactly the source lines that entered this ledger for one file.

        The initial unit is rendered separately from tool output.  Using this method for
        that rendering makes the display and the provenance record the same set of
        lines; a line cannot be visible to the model but absent from evidence checking.
        """
        return [
            {"number": number, "text": source}
            for known_path, number, source in sorted(self.lines, key=lambda item: (item[0], item[1], item[2]))
            if known_path == path
        ]

    def replay(self, *, exclude: set[tuple[str, int, str]] | None = None) -> str:
        """Replay only text the model has actually received.

        ``exclude`` lets the initial unit be shown in its compact presentation once,
        while host-prepared cross-file context is appended without duplicating it.
        """
        excluded = exclude or set()
        return "".join(rendered for key, rendered in self.lines.items() if key not in excluded)

    def reads(self) -> list[dict]:
        # Evidence validation merges adjacent lines without ever filling a gap.
        return [{"path": path, "start_line": number, "end_line": number} for path, number, _ in self.lines]


def history_size(messages) -> int:
    from pydantic_ai.messages import ModelMessagesTypeAdapter

    return len(ModelMessagesTypeAdapter.dump_json(messages))


def canonical_call(name: str, args: dict) -> str:
    normalised = dict(args)
    if isinstance(normalised.get("path"), str):
        path = normalised["path"].replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        normalised["path"] = path
    return name + ":" + json.dumps(normalised, sort_keys=True, ensure_ascii=False)
