"""Finite execution policy and the exact source text delivered to the model."""
from __future__ import annotations

import dataclasses
import json
import time
from dataclasses import asdict, dataclass, field


@dataclass
class Usage:
    """What a run spent, as the API reports it.

    Counted here rather than borrowed from the agent library: the numbers are this
    repository's contract (``GET /runs/{id}``, the terminal events, the frontend's
    usage chips) and must not follow some framework's own accounting around.  A request
    is counted when it is answered; failures are counted by ``before_model``.
    """

    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    def add(self, *, requests: int = 0, input_tokens: int = 0, output_tokens: int = 0) -> None:
        self.requests += requests
        self.input_tokens += input_tokens or 0
        self.output_tokens += output_tokens or 0


@dataclass(frozen=True)
class AgentPolicy:
    version: str = "whitebox-2"
    # Wall clock one model request may take, applied both to the HTTP client and to the
    # surrounding wait.  It is a safety net against a hung connection, not a latency
    # target, and it has to clear what a decisive request actually costs: measured
    # against the provider in use, the request that publishes a round's decision took
    # 36-59s, so a 60s ceiling cut the one request the round exists to produce (live run
    # a3308f69: rounds 1 and 3 died in planner_publish with request_timeout at exactly
    # 60.0s, and the run ended failed with zero tasks).  What bounds cost is the run's
    # own seconds budget and the phase deadlines; this only bounds a single stall.
    request_seconds: float = 180.0
    tool_seconds: float = 5.0
    # Share of the wall-clock budget the exploration phase may use before the model is
    # asked to stop reading and decide.  High on purpose: the phase should end because
    # the response/tool allowance ran out (which the model can see and reason about),
    # not because a clock the model cannot see cut it off mid-thought.
    exploration_fraction: float = 0.85
    repeated_calls: int = 2
    no_progress_calls: int = 3
    tool_bytes: int = 16 * 1024
    source_bytes: int = 64 * 1024
    history_bytes: int = 192 * 1024
    # Reconnaissance is a Planner tool with its own bounded budget.  Its requests and
    # its source reads are deliberately kept out of the Planner execution and out of a
    # worker's evidence ledger, so a recon brief can never become a finding's evidence.
    recon_enabled: bool = True
    recon_responses: int = 6
    recon_tools: int = 10
    recon_seconds: float = 90.0
    recon_fraction: float = 0.25
    recon_brief_bytes: int = 8 * 1024
    recon_max_read_lines: int = 120
    recon_scan_files: int = 300
    # --- Planner round ------------------------------------------------------------
    # The Planner holds the same read-only tools a worker does, but under its own caps.
    # Its read records are throttling/awareness only and never reach evidence validation
    # (the same boundary recon.py draws for its own ledger).
    planner_read_lines: int = 200
    planner_search_limit: int = 40
    planner_source_bytes: int = 64 * 1024
    planner_max_tokens: int = 8192
    # A reading window longer than this is clamped by the host validator, not rejected.
    planner_ref_max_lines: int = 400
    # Corrections allowed per Execution phase before the phase ends as invalid_output.
    output_corrections: int = 2
    # Model requests the decision phase may spend on tool calls before the host withdraws
    # the tools and asks for the decision alone.  The Planner's tools are there so it can
    # confirm a fact before committing to a reading window, not so it can keep browsing:
    # a live run spent every request of three rounds on tool calls and never published the
    # one thing the round exists to produce.
    decision_confirmations: int = 2
    # Rounds the host may discard and re-plan after the Planner failed to produce a usable
    # decision, before it falls back to the durable frontier or settles the goal.
    planner_decision_retries: int = 1
    # New reconnaissance requests a round may start; a repeated question is answered from
    # the pinned investigation instead and costs nothing.
    recon_calls_per_round: int = 2
    # Bytes of host-prefetched situation (tasks, findings, coverage, pinned investigations)
    # folded into every Planner prompt.  Prefetched rather than tool-fetched: a tool call
    # costs a response and can be skipped, and a Planner that forgets what already ran
    # re-dispatches it.
    planner_pinned_bytes: int = 16 * 1024
    # --- Code actions ---------------------------------------------------------------
    # A phase's model loop lets the model write Python that calls this run's own read-only
    # tools, so one model request can carry a whole reading loop instead of one call.
    # These three bound what the interpreter hands back; the response, tool and
    # wall-clock budgets above still bound the work itself.
    # Bytes of one code step's printed output.  Everything the model prints is its own
    # next observation, and printing what it wants to see is the point of the format, so
    # this is generous -- but a code block can print the same tool reply many times over.
    code_output_bytes: int = 24 * 1024
    # Wall clock one code block may run.  The interpreter applies this with a thread
    # pool, which cannot stop a thread that has already started: this is the point where
    # the host stops *waiting* for a code block, not the point where it stops running.
    code_seconds: int = 30
    # Bytes of one code action kept in the durable agent_code event.  The code is an
    # action, recorded the way tool_call is, but a long reading loop is not worth the
    # whole event budget: the tool_call events it produces carry the substance.
    code_bytes: int = 4 * 1024
    # File-set overlap at or above this marks a proposal as a duplicate of a settled
    # direction that already has an open finding.
    duplicate_overlap_threshold: float = 0.8
    # Re-opening a settled task to correct its conclusion.  A revision is not a retry: it
    # extends the attempt allowance instead of spending it.
    task_reopens: int = 2
    run_reopens: int = 8
    reopen_attempts: int = 1

    def snapshot(self) -> dict:
        return asdict(self)


def policy_from_snapshot(policy: dict | None) -> AgentPolicy:
    """Rebuild a stored policy, ignoring keys this build does not know about.

    The snapshot was written by whatever build created the run.  After a rollback the
    stored dict can carry fields this build has no argument for, and a bare
    ``AgentPolicy(**policy)`` would then raise TypeError for every historical run.
    """
    known = {item.name for item in dataclasses.fields(AgentPolicy)}
    return AgentPolicy(**{key: value for key, value in (policy or {}).items() if key in known})


class StopAudit(Exception):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def allowed_paths_for_run(run: dict) -> set[str] | None:
    """Return the run's frozen file policy, or ``None`` for "the whole snapshot".

    This is the single place that decides between an explicit file list and an
    unrestricted snapshot scope.  Every caller must go through it: rebuilding the
    set from ``run["scope"]`` alone silently turns a whole-snapshot run into an empty
    policy, which makes every tool call fail as out-of-scope.
    """
    if str(run.get("scope_mode") or "explicit") == "snapshot":
        return None
    return set(run.get("scope") or [])


@dataclass
class Execution:
    budgets: dict
    policy: AgentPolicy
    emit: object
    started: float = field(default_factory=time.monotonic)
    usage: Usage = field(default_factory=Usage)
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

    def before_model(self, *, deadline: float, limit: int, correction: bool, reason: str | None = None) -> float:
        if self.remaining(deadline) <= 0:
            raise StopAudit("timeout", "单元或当前阶段的墙钟预算已到期")
        if self.attempts >= min(limit, self.budgets["responses"]):
            raise StopAudit("budget", "模型请求预算已用尽（包括纠正与失败请求）")
        if correction:
            if self.corrections >= self.policy.output_corrections:
                # The last rejection is what actually ended the round; carrying it here
                # is the only place it survives, since no retry event follows.
                raise StopAudit(
                    "invalid_output",
                    "本单元的输出纠正重试已用尽" + (f"；最后一次拒绝：{reason[:300]}" if reason else ""),
                )
            self.corrections += 1
            # The rejection reason is the only record of *why* the previous output was
            # refused, and a round that dies here dies for the whole run.  Without it
            # the event log shows a retry with no way to tell a bad line range from a
            # dependency cycle.
            self.emit({
                "kind": "model_retry",
                "phase": self.phase,
                "corrections": self.corrections,
                "reason": (reason or "")[:400] or None,
            })
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


def canonical_call(name: str, args: dict) -> str:
    normalised = dict(args)
    if isinstance(normalised.get("path"), str):
        path = normalised["path"].replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        normalised["path"] = path
    return name + ":" + json.dumps(normalised, sort_keys=True, ensure_ascii=False)
