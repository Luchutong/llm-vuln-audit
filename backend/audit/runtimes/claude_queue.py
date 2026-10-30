"""A host-owned verification queue driven by one interactive Claude SDK client.

The SDK owns model iteration. The host sends one claimed item at a time, rebinds
the runner service between responses, and commits each publication immediately.
SQLite attempts/jobs and the existing gateway remain the only durable ledgers.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import replace
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .claude_poc import (
    CONCLUDE_STAGE, EXECUTE_STAGE, ClaudeCodePocRuntime, EvidenceRefTable,
    PocRuntimeOutcome, PocRuntimeUnavailable, _StageToolExecution,
    _is_result_message, _sdk_version, _usage_from_result, host_check,
)
from ..poc_agent import (
    evidence_errors, execute_instructions, run_stored_poc, stored_poc_preflight,
)
from ..poc_source import PROGRESS_POLICY, ProgressLimits
from ..runtime import StopAudit

QUEUE_POLICY = "session-queue-v1"
CONTINUE_TOOL = "continue_verification"
# Tools that submit a real runner job.  Everything else (navigation, identity checks,
# source/diagnostics reads) stays available at a read-only checkpoint.
EXPERIMENT_TOOLS = frozenset({"run_poc", "http_observe", "browser_check"})
# ``target_prepare`` changes account state, so a checkpoint withdraws it as well even
# though it never submits a job; it is not part of the experiment count or fingerprint.
SIDE_EFFECT_TOOLS = EXPERIMENT_TOOLS | {"target_prepare"}
READONLY_TOOLS = frozenset({
    "get_verification_tasks", "get_verification_evidence", "publish_verification",
    "continue_verification", "read_verification_source", "read_verification_diagnostics",
    "resolve_target", "target_status", "url_encode", "save_artifact",
})
# Stream failures that may still be recovered read-only from the jobs that finished.
RECOVERABLE_REASONS = frozenset({"sdk_api_error", "stream_connection_error", "missing_result_message"})


class Publication(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    finding_id: str
    context_id: str
    revision: int = Field(ge=1)
    status: Literal["verified", "rejected", "inconclusive"]
    summary: str = Field(min_length=1, max_length=4000)
    normal_observation: str = Field(default="", max_length=4000)
    attack_observation: str = Field(default="", max_length=8000)
    browser_execution: bool = False
    evidence_notes: str = Field(default="", max_length=4000)
    modification_notes: str = Field(default="", max_length=4000)
    jobs: list[str] = Field(default_factory=list, max_length=16)
    normal_refs: list[str] = Field(default_factory=list, max_length=16)
    attack_refs: list[str] = Field(default_factory=list, max_length=16)


QUEUE_CONTRACT = """
本会话直接调用 MCP 工具并传 JSON 参数，不编写宿主 Python 动作代码。以下发布规则取代旧的两阶段说明。
你通过同一会话逐项处理宿主的 POC 队列。每次消息只授权当前 finding_id、revision、context_id。
历史会话仅供导航，旧 Cookie、作业、证据编号不得用于当前项目。宿主负责领取和切换任务，禁止自行切换上下文。
用 get_verification_tasks 查看任务列表；调用 get_verification_evidence 获取本项真实作业的证据编号。
有足够观测后立即调用 publish_verification 逐项发布，收到 ok=true 后停止实验并结束当前响应，等待下一项。
verified/rejected 必须有当前上下文的成功作业、正常和攻击观测及对应原文引用；XSS 仍需攻击侧浏览器执行证据。
HTTP 状态及退出码不代表漏洞成立；失败、前提不符、证据不足使用 inconclusive，不能据此否定漏洞。
宿主拒绝发布时按原因修正，最多两次；不能伪造证据。作业额度耗尽或前提不符时发布已有事实和限制。
单项耗时提醒不构成否决，也不停止本项。请求、工具和时间硬上限属于整个运行及当前 POC 阶段。
任务完成后立即发布，不等队列清空才集中汇总。不要输出推理正文或凭据。
"""

PROGRESS_CONTRACT = """
本项按检查点推进：自上个检查点累计完成 2 个实验作业、出现未声明目的的精确重复、提醒后长期没有新作业/补读/发布、
或作业额度与 POC 发布窗口临近时，宿主会把本项切为只读检查点，并在工具返回中附带 checkpoint
（含已完成作业、宿主观测、已展示的 evidence_ref_id 与缺口）。检查点不赠送请求、作业或时间。
检查点期间仍可补读源码、读取诊断、读取证据表并发布；新的副作用必须调用 continue_verification，
给出 checkpoint_id、未解决的具体假设、已读依据、下一次最小实验及预期能区分的结果。每次继续只授权一个小批，
最多再完成 2 个作业就再次检查，每个检查点最多继续 2 次；同一假设不得反复解锁。
没有新的判别方向时，直接发布现有结论或写明具体限制的 inconclusive。完全相同的请求/脚本不会被重复执行，只能引用原作业。
宿主只登记事实；正常/攻击的角色划分、根因与影响判断必须由你引用证据后给出。
"""


class Continuation(BaseModel):
    """A declared reason to leave a read-only checkpoint.

    The host does not evaluate the prose; it records it next to the checkpoint so a
    later reader can tell a new discriminating experiment from an unlocked retry.
    """

    model_config = ConfigDict(extra="forbid", strict=True)
    checkpoint_id: str = Field(min_length=4, max_length=16)
    hypothesis: str = Field(min_length=8, max_length=600)
    basis: str = Field(min_length=8, max_length=800)
    next_experiment: str = Field(min_length=8, max_length=600)
    expected_result: str = Field(min_length=8, max_length=600)


class ClaudeQueuePocRuntime(ClaudeCodePocRuntime):
    """Persistent client; all AnyIO scopes open and close in the actor's one task."""

    HEARTBEAT_SECONDS = 2.

    def __init__(self, *, tasks=(), **kwargs):
        super().__init__(**kwargs)
        self._tasks = [dict(item) for item in tasks]
        self._commands = asyncio.Queue()
        self._actor = None
        self._stage_tokens = {}
        self._tool_lock = asyncio.Lock()
        self._published = None
        self._publication = None
        self._publish_errors = 0
        self._refs = None
        self._query_failed = False
        self._queue_id = ""
        self._queue_deadline = time.monotonic() + self.limits.max_seconds
        self._result_seen = False
        self._cost_total = 0.
        self._cost_contiguous = True
        self._client = None
        self._host_interrupt = ""
        # Bounded-evidence progress state.  It is reset per item in ``_bind`` and never
        # extends any of the run, stage, job, identity, context or evidence gates.
        self._item_state = "closed"
        self._item_started = 0.
        self._experiment_deadline = self._queue_deadline
        self._checkpoint = None
        self._checkpoints = []
        self._checkpoint_seq = 0
        self._experiments_since_checkpoint = 0
        self._seen_experiments = {}
        self._completed_jobs = []
        self._continues = []
        self._continues_used = 0
        self._retry_granted = False
        self._used_directions = set()
        self._last_progress_at = 0.
        self._progress_counts = {}
        self._stream_error = ""
        self._recovery = {}
        # Finding whose recorded POC the host already ran (or skipped) in this runtime.
        # A checkpoint continuation rebinds the same item; re-executing the script would
        # spend another job and repeat its side effects without new evidence.
        self._stored_poc_finding = ""

    # -- progress policy ---------------------------------------------------------

    @property
    def _progress_enabled(self) -> bool:
        """Only the frozen policy name enables the state machine; old runs are unchanged."""
        policy = self._service.policy if self._service is not None else {}
        return str((policy or {}).get("progress_policy") or "") == PROGRESS_POLICY

    def _progress_limits(self) -> ProgressLimits:
        policy = self._service.policy if self._service is not None else {}
        return ProgressLimits.from_params((policy or {}).get("progress_params"))

    def _reset_progress(self) -> None:
        now = time.monotonic()
        self._item_started = now
        self._last_progress_at = now
        self._checkpoint = None
        self._checkpoints = []
        self._checkpoint_seq = 0
        self._experiments_since_checkpoint = 0
        self._seen_experiments = {}
        self._completed_jobs = []
        self._continues = []
        self._continues_used = 0
        self._retry_granted = False
        self._used_directions = set()
        self._progress_counts = {"jobs": 0, "source_reads": 0, "diagnostics_reads": 0, "evidence_reads": 0}
        self._stream_error = ""
        self._recovery = {}
        self._item_state = "experiment"
        self._experiment_deadline = self._progress_deadline(now)

    def _progress_deadline(self, now: float) -> float:
        """Stop new side effects early enough to publish and clean up inside the window."""
        if not self._progress_enabled:
            return self._queue_deadline
        limits = self._progress_limits()
        window = max(0., self._queue_deadline - now)
        recovery = min(limits.recovery_seconds, window * .1)
        cleanup = min(limits.cleanup_seconds, window * .05)
        return self._queue_deadline - recovery - cleanup

    def _allowance(self) -> dict:
        allowance = getattr(self.gateway, "experiment_allowance", None)
        if allowance is None:
            return {"responses": 2 ** 31 - 1, "tools": 2 ** 31 - 1}
        value = allowance(run_id=self._run_id) or {}
        return {"responses": int(value.get("responses") or 0), "tools": int(value.get("tools") or 0)}

    def _fingerprint(self, name: str, args: dict) -> str:
        """Exact experiment identity: same request, identity and context, or nothing.

        There is deliberately no fuzzy comparison: two scripts that differ by one byte,
        or the same path under another identity, are different experiments.
        """
        identity = str(args.get("identity") or (self._service.default_identity if self._service else "") or "")
        context = str(self._service.context_id if self._service is not None else "")
        if name == "http_observe":
            key = ["http", identity, context, str(args.get("method") or "GET").upper(),
                   str(args.get("path") or ""), str(args.get("body") or ""),
                   str(args.get("content_type") or "")]
        elif name == "run_poc":
            script = args.get("script")
            digest = hashlib.sha256(script.encode("utf-8")).hexdigest() if isinstance(script, str) else ""
            key = ["script", identity, context, str(args.get("language") or ""), digest,
                   sorted(str(item) for item in args.get("artifacts") or [])]
        else:
            key = ["browser", identity, context, str(args.get("path") or ""),
                   str(args.get("script") or ""), str(args.get("wait_ms") or 0)]
        return hashlib.sha256(json.dumps(key, ensure_ascii=False).encode("utf-8")).hexdigest()

    def _completed(self, job: dict | None) -> bool:
        if not isinstance(job, dict) or not job.get("job_id"):
            return False
        result = job.get("result") if isinstance(job.get("result"), dict) else {}
        status = str(result.get("execution_status") or result.get("status") or "")
        return status not in {"", "submitting", "running", "queued", "unknown", "unresolved"}

    def _host_observations(self) -> list[dict]:
        """Facts about finished jobs; interpretation is never part of a checkpoint."""
        items = []
        for job in self._completed_jobs[-4:]:
            result = job.get("result") if isinstance(job.get("result"), dict) else {}
            fact = {
                "job_id": str(job.get("job_id") or "")[:64],
                "kind": str(job.get("kind") or "")[:16],
                "identity": str(job.get("identity") or "")[:32],
                "status": str(result.get("execution_status") or result.get("status") or "")[:32],
            }
            if job.get("kind") == "http":
                fact.update(method=str(result.get("request", {}).get("method") or job.get("request", {}).get("method") or "")[:8] if isinstance(result.get("request"), dict) else "",
                            path=str(job.get("request", {}).get("path") or "")[:300],
                            http_status=result.get("http_status") if type(result.get("http_status")) is int else None)
            elif job.get("kind") == "script":
                fact.update(exit_code=job.get("exit_code") if type(job.get("exit_code")) is int else None,
                            timed_out=bool(result.get("timed_out")))
            elif job.get("kind") == "browser":
                fact.update(dialogs=len(result.get("dialogs") or []),
                            console_errors=len(result.get("console_errors") or []))
            diagnostics = job.get("diagnostics") if isinstance(job.get("diagnostics"), dict) else None
            if diagnostics is not None:
                fact["diagnostics"] = {"available": bool(diagnostics.get("available")),
                                       "reason": str(diagnostics.get("reason") or "")[:40],
                                       "items": len(diagnostics.get("items") or [])}
            items.append(fact)
        return items

    def _unpublished_reason(self) -> str | None:
        """Why this item has no conclusion yet, in the host's own words.

        A progress pulse must never look like a verdict: until ``publish_verification``
        commits, the page says what is actually missing rather than implying success.
        """
        if self._published is not None or self._service is None:
            return None
        if self._stream_error:
            return "模型流已中断，已完成实验保留，等待宿主只读回收。"
        if not self._completed_jobs:
            return "尚无已完成的实验作业。"
        if self._refs is None or len(self._refs) == 0:
            return f"已完成 {len(self._completed_jobs)} 个实验，尚未读取可引用证据。"
        return f"已完成 {len(self._completed_jobs)} 个实验，尚未调用 publish_verification。"

    def _missing_evidence(self) -> list[str]:
        gaps = []
        service = self._service
        if service is None:
            return ["条目已关闭"]
        if not self._completed_jobs:
            gaps.append("尚无已完成的实验作业")
        if self._refs is None or len(self._refs) == 0:
            gaps.append("没有可引用的证据原文")
        if service.submission_unresolved:
            gaps.append("存在未确认作业，只能查询原作业，不能重交")
        remaining = max(0, service.max_jobs - len(service.jobs))
        if remaining <= 1:
            gaps.append(f"作业额度仅剩 {remaining} 个")
        unavailable = [job for job in self._completed_jobs
                       if isinstance(job.get("diagnostics"), dict)
                       and job["diagnostics"].get("available") is False]
        if unavailable:
            reasons = sorted({str(job["diagnostics"].get("reason") or "") for job in unavailable})
            gaps.append("服务端诊断不可用：" + "、".join(reason for reason in reasons if reason)[:120])
        gaps.append("未标注正常/攻击角色的作业只能称为观测，不能算完整对照")
        return gaps[:6]

    def _can_continue(self) -> bool:
        limits = self._progress_limits()
        if self._continues_used >= limits.continues:
            return False
        if self._service is None:
            return False
        if self._service.max_jobs - len(self._service.jobs) <= 1:
            return False
        if self._experiment_deadline - time.monotonic() <= 5:
            return False
        allowance = self._allowance()
        return allowance["responses"] >= 1 and allowance["tools"] >= 3

    def _take_checkpoint(self, reason: str, *, always: bool = False) -> dict | None:
        """Freeze the item's facts and switch it to read-only.

        The checkpoint embeds only host facts, the evidence ids it has now displayed
        (so a later publication may cite exactly those) and the host-visible gaps.  It
        never asserts a role, a root cause or a verdict.
        """
        if self._service is None:
            return None
        if not always and self._item_state == "checkpoint" and self._checkpoint is not None:
            return self._checkpoint
        self._checkpoint_seq += 1
        refs = self._refs or EvidenceRefTable.build(self._service)
        public = refs.public()
        # Whatever the checkpoint shows may be published, and nothing else may be.
        self._refs = EvidenceRefTable(
            [refs.resolve(item["evidence_ref_id"]) for item in public], refs.displayed, refs.truncated)
        limits = self._progress_limits()
        checkpoint = {
            "checkpoint_id": f"cp-{self._checkpoint_seq}",
            "state": "checkpoint",
            **self._binding(),
            "reason": str(reason)[:40],
            "completed_experiments": len(self._completed_jobs),
            "job_ids": [str(job.get("job_id") or "")[:64] for job in self._completed_jobs[-16:]],
            "new_observations": self._host_observations(),
            "interpretation": {"provided": False,
                               "note": "宿主只登记实际作业与原文；解释与角色划分须由你引用证据后给出。"},
            "evidence_ref_ids": [str(item.get("evidence_ref_id") or "")[:32] for item in public[:16]],
            "missing_evidence": self._missing_evidence(),
            "next_action": "continue_verification" if self._can_continue() else "publish",
            "continues_remaining": max(0, limits.continues - self._continues_used),
            "experiments_allowed_on_continue": limits.checkpoint_experiments,
        }
        self._checkpoint = checkpoint
        self._checkpoints = (self._checkpoints + [checkpoint])[-8:]
        self._experiments_since_checkpoint = 0
        self._retry_granted = False
        self._item_state = "checkpoint"
        self._emit("poc_queue_checkpoint",
                   **{key: value for key, value in checkpoint.items() if key != "state"})
        return checkpoint

    def _checkpoint_view(self, checkpoint: dict | None = None) -> dict | None:
        checkpoint = self._checkpoint if checkpoint is None else checkpoint
        if checkpoint is None:
            return None
        keys = ("checkpoint_id", "state", "finding_id", "revision", "context_id", "reason",
                "completed_experiments", "job_ids", "new_observations", "interpretation",
                "evidence_ref_ids", "missing_evidence", "next_action", "continues_remaining",
                "experiments_allowed_on_continue")
        return {key: checkpoint.get(key) for key in keys}

    def _checkpoint_field(self) -> dict:
        view = self._checkpoint_view()
        return {"checkpoint": view} if view is not None else {}

    def _attach(self, reply: str, checkpoint: dict | None) -> str:
        if checkpoint is None:
            return reply
        try:
            value = json.loads(reply)
        except (TypeError, ValueError):
            return reply
        if not isinstance(value, dict):
            return reply
        value["checkpoint"] = self._checkpoint_view(checkpoint)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    def _admit_experiment(self, name: str, args: dict) -> dict | None:
        """Refuse a new side effect with the checkpoint attached, or admit it."""
        if self._item_state == "checkpoint":
            return {"ok": False, "error": "checkpoint_readonly",
                    "message": "本项已进入只读检查点：可补读源码/诊断、读取证据并发布；"
                               "新的实验须先用 continue_verification 声明判别目的。",
                    "tools": sorted(READONLY_TOOLS), **self._checkpoint_field()}
        if self._item_state != "experiment":
            return None
        if self._experiment_deadline - time.monotonic() <= 0:
            self._take_checkpoint("publish_window")
            return {"ok": False, "error": "checkpoint_readonly",
                    "message": "POC 窗口已进入发布预留，不再启动新实验；请发布现有结论或写明缺口。",
                    **self._checkpoint_field()}
        if name not in EXPERIMENT_TOOLS:
            return None
        fingerprint = self._fingerprint(name, args)
        if fingerprint in self._seen_experiments and not self._retry_granted:
            self._take_checkpoint("duplicate_experiment")
            return {"ok": False, "error": "duplicate_experiment",
                    "message": "该实验与已执行作业完全相同。只能引用原作业；如确有必要重试，"
                               "先用 continue_verification 说明新的判别目的。",
                    "duplicate_of": self._seen_experiments[fingerprint],
                    **self._checkpoint_field()}
        if self._service.max_jobs - len(self._service.jobs) <= 1:
            self._take_checkpoint("job_limit_near")
            return {"ok": False, "error": "checkpoint_readonly",
                    "message": "作业额度临近上限，保留最后一个额度给明确的补证；请先检查能否发布。",
                    **self._checkpoint_field()}
        return None

    def _note_experiment(self, name: str, args: dict, value: dict) -> dict | None:
        """Count a finished job and checkpoint once the batch is complete."""
        job_id = str(value.get("job_id") or "") if isinstance(value, dict) else ""
        job = next((item for item in self._service.jobs if str(item.get("job_id") or "") == job_id), None)
        if not self._completed(job):
            return None
        self._seen_experiments.setdefault(self._fingerprint(name, args), job_id)
        if any(item.get("job_id") == job_id for item in self._completed_jobs):
            return None
        self._completed_jobs.append(job)
        self._experiments_since_checkpoint += 1
        self._progress_counts["jobs"] = self._progress_counts.get("jobs", 0) + 1
        self._last_progress_at = time.monotonic()
        if self._experiments_since_checkpoint >= self._progress_limits().checkpoint_experiments:
            return self._take_checkpoint("experiments")
        return None

    def _continue(self, args: dict) -> str:
        try:
            data = Continuation.model_validate(args).model_dump()
        except ValidationError as exc:
            return self._reply(ok=False, error="invalid_continuation",
                               errors=[f"{'.'.join(map(str, error['loc']))}: {error['type']}"
                                       for error in exc.errors()][:8],
                               message="继续检查点需要 checkpoint_id、未解决假设、已读依据、"
                                       "下一次最小实验和预期能区分的结果。")
        checkpoint = self._checkpoint
        if self._item_state != "checkpoint" or checkpoint is None:
            return self._reply(ok=False, error="not_checkpointed",
                               message="当前不在检查点；直接执行实验或发布，无需继续工具。")
        if data["checkpoint_id"] != checkpoint["checkpoint_id"]:
            return self._reply(ok=False, error="unknown_checkpoint", **self._checkpoint_field(),
                               message="只能针对当前检查点继续；旧的检查点不能解锁新的实验。")
        binding = self._binding()
        if any(checkpoint.get(key) != binding[key] for key in ("finding_id", "revision", "context_id")):
            return self._reply(ok=False, error="binding_changed",
                               message="授权任务已改变，不能沿用旧检查点。")
        limits = self._progress_limits()
        if self._continues_used >= limits.continues:
            return self._reply(ok=False, error="continuation_limit", **self._checkpoint_field(),
                               message="本项的继续次数已用完；请发布现有结论或写明具体限制。")
        if self._experiment_deadline - time.monotonic() <= 5:
            return self._reply(ok=False, error="no_time", **self._checkpoint_field(),
                               message="POC 窗口不足以支持新的实验与发布，请直接发布现有结论。")
        allowance = self._allowance()
        if allowance["responses"] < 1 or allowance["tools"] < 3:
            return self._reply(ok=False, error="quota_reserved", **self._checkpoint_field(),
                               message="剩余请求或工具额度已被发布与终审保留，不能恢复实验。")
        if self._service.max_jobs - len(self._service.jobs) <= 1:
            return self._reply(ok=False, error="job_limit", **self._checkpoint_field(),
                               message="作业额度不足以再做一个有意义的补证；请发布现有结论。")
        direction = " ".join(f"{data['hypothesis']} {data['next_experiment']}".split()).casefold()
        if direction in self._used_directions:
            return self._reply(ok=False, error="repeated_direction", **self._checkpoint_field(),
                               message="同一假设与实验组合已用过，不能再次解锁；请发布或提出新的判别方向。")
        self._used_directions.add(direction)
        self._continues_used += 1
        self._continues.append({
            "checkpoint_id": data["checkpoint_id"],
            "hypothesis": data["hypothesis"][:300],
            "basis": data["basis"][:300],
            "next_experiment": data["next_experiment"][:300],
            "expected_result": data["expected_result"][:300],
        })
        self._continues = self._continues[-4:]
        self._experiments_since_checkpoint = 0
        self._retry_granted = True
        self._item_state = "experiment"
        self._stage = EXECUTE_STAGE
        self._last_progress_at = time.monotonic()
        self._emit("poc_queue_continued", checkpoint_id=data["checkpoint_id"],
                   continues_remaining=max(0, limits.continues - self._continues_used),
                   experiments=limits.checkpoint_experiments,
                   hypothesis=data["hypothesis"][:300], basis=data["basis"][:300],
                   next_experiment=data["next_experiment"][:300],
                   expected_result=data["expected_result"][:300],
                   message="已按声明恢复实验；完成这一小批后再次检查。")
        return self._reply(ok=True, checkpoint_id=data["checkpoint_id"],
                           experiments=limits.checkpoint_experiments,
                           continues_remaining=max(0, limits.continues - self._continues_used),
                           message="已恢复实验。按声明执行最小补证；本批结束会再次检查。")

    def _note_progress(self, name: str, value: dict) -> None:
        """Reads that add evidence count as business progress; heartbeats never do."""
        if not isinstance(value, dict) or value.get("error") or value.get("ok") is False:
            return
        key = {"read_verification_source": "source_reads",
               "read_verification_diagnostics": "diagnostics_reads",
               "get_verification_evidence": "evidence_reads"}.get(name)
        if key is None:
            return
        if name == "read_verification_diagnostics" and value.get("available") is not True:
            return
        self._progress_counts[key] = self._progress_counts.get(key, 0) + 1
        self._last_progress_at = time.monotonic()

    def _progress_snapshot(self) -> dict:
        if self._service is None or not self._progress_enabled:
            return {}
        return {
            "policy": PROGRESS_POLICY,
            "state": self._item_state,
            "experiments": len(self._completed_jobs),
            "counts": dict(self._progress_counts),
            "checkpoints": [self._checkpoint_view(item) for item in self._checkpoints[-3:]],
            "continues": [dict(item) for item in self._continues[-2:]],
            "recovery": dict(self._recovery),
            "stream_error": self._stream_error,
        }

    def _options(self, stage, server, system_prompt):
        # No execute/conclude process split or per-item turn/time ceiling. Actual
        # requests still obtain atomic admission in the controlled gateway.
        options = super()._options(stage, server, system_prompt)
        options.max_turns = None
        options.include_partial_messages = True
        return options

    def _emit(self, kind, **fields):
        # Tool ordinals restart for an item; its context supplies a stable trace
        # scope so two findings' identical tool numbers cannot be paired together.
        if self._service is not None:
            fields.setdefault("agent_invocation_id", "poc-queue-" + self._service.context_id)
            fields.setdefault("context_id", self._service.context_id)
        super()._emit(kind, **fields)

    def _environment(self, stage=None):
        # The process credential is bound to the run/epoch/queue, never a previous
        # finding's context. Only the host-bound tool service can access the runner.
        env = super()._environment(None)
        generation = self.limits.generation()
        if generation.bounded:
            # One long-lived client serves the whole batch, so the session keeps the
            # experiment cap; a read-only recovery stage gets the publish cap.
            env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] = str(generation.output_tokens(stage or EXECUTE_STAGE))
        if self._service is None:
            return env
        issuer = getattr(self.gateway, "issue_capability", None)
        if stage == CONCLUDE_STAGE:
            # Only the bounded read-only recovery opens this stage; its capability
            # lives exactly as long as the recovery deadline it was granted.
            self._revoke_stage_capability(CONCLUDE_STAGE)
            if issuer is not None:
                deadline = min(getattr(self, "_stage_deadline", float("inf")),
                               getattr(self, "_attempt_deadline", float("inf")))
                seconds = deadline - time.monotonic()
                if seconds > 0:
                    token = issuer(run_id=self._run_id, epoch=self._epoch, stage=CONCLUDE_STAGE,
                        model=self.limits.model, context_id=self._service.context_id,
                        finding_id=str(self._service.finding.get("id") or ""),
                        ttl_seconds=min(14400., seconds),
                        **self._capability_generation(CONCLUDE_STAGE))
                    self._stage_tokens[CONCLUDE_STAGE] = token
                    env["ANTHROPIC_AUTH_TOKEN"] = token
            return env
        if not self._stage_tokens.get(EXECUTE_STAGE):
            if issuer is not None:
                token = issuer(run_id=self._run_id, epoch=self._epoch, stage=EXECUTE_STAGE,
                    model=self.limits.model, context_id=self._queue_id, finding_id=self._queue_id,
                    ttl_seconds=min(14400., max(.001, self._attempt_deadline - time.monotonic())),
                    session_policy=QUEUE_POLICY, **self._capability_generation(EXECUTE_STAGE))
                self._stage_tokens[EXECUTE_STAGE] = token
        token = self._stage_tokens.get(EXECUTE_STAGE)
        if token:
            env["ANTHROPIC_AUTH_TOKEN"] = token
        return env

    def _build_mcp_server(self):
        sdk = self._sdk
        tools = []
        from .claude_poc import POC_TOOLS, _tool_schema
        specs = [(s.name, s.description, _tool_schema(s)) for s in POC_TOOLS]
        specs += [
            ("get_verification_tasks", "分页查看宿主队列及当前授权任务。", {"type": "object", "properties": {
                "offset": {"type": "integer", "minimum": 0, "default": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": 25, "default": 25}}, "additionalProperties": False}),
            ("get_verification_evidence", "读取当前上下文的作业原文、前提及可引用证据 ID。", {"type": "object", "properties": {}, "additionalProperties": False}),
            ("publish_verification", "校验并立即保存当前任务结论；成功后收回实验工具。", Publication.model_json_schema()),
        ]
        if self._progress_enabled:
            specs.append((CONTINUE_TOOL,
                          "检查点是只读的；用一次声明的判别目的解锁一小批实验（不赠送请求、作业或时间）。",
                          Continuation.model_json_schema()))
        for name, description, schema in specs:
            async def handler(args, _name=name):
                reply = await self.call_tool(_name, args)
                return {"content": [{"type": "text", "text": reply}]}
            tools.append(sdk.tool(name, description, schema)(handler))
        return sdk.create_sdk_mcp_server(name="poc", version="1.1.0", tools=tools)

    async def call_tool(self, name, args):
        async with self._tool_lock:
            if self._stopped() or self._service is None or self._stage == "closed":
                return self._reply(ok=False, error="context_stopped")
            if name in {"publish_verification", "get_verification_evidence", "get_verification_tasks",
                        CONTINUE_TOOL}:
                execution = self._service.execution
                execution.before_tool()
                call_id = f"poc-tool-{execution.tools:04d}"
                self._emit("tool_call", tool=name, call_id=call_id,
                           span_id=f"execute:{call_id}", phase="execute", args={
                               k: args[k] for k in ("finding_id", "context_id", "revision", "status",
                                                    "offset", "limit", "checkpoint_id") if k in args})
                try:
                    if name == "publish_verification":
                        reply = self._publish(args)
                    elif name == CONTINUE_TOOL:
                        reply = self._continue(dict(args or {}))
                    elif name == "get_verification_tasks":
                        offset, limit = args.get("offset", 0), args.get("limit", 25)
                        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 25:
                            reply = self._reply(ok=False, error="invalid_pagination")
                        else:
                            reply = self._reply(ok=True, current=self._binding(), items=self._tasks[offset:offset + limit],
                                total=len(self._tasks), next_offset=offset + limit if offset + limit < len(self._tasks) else None)
                    else:
                        refs = EvidenceRefTable.build(self._service)
                        public = refs.public()
                        # Only actually displayed IDs may be published, including
                        # when the complete evidence table exceeded the reply budget.
                        self._refs = EvidenceRefTable(
                            [refs.resolve(r["evidence_ref_id"]) for r in public], refs.displayed, refs.truncated)
                        reply = self._reply(ok=True, current=self._binding(), evidence=public,
                            jobs=refs.displayed, preconditions=self._service.preconditions,
                            state_changes=self._service.state_changes, output_truncated=refs.truncated)
                        self._note_progress(name, {"ok": True})
                    self._emit("tool_result", tool=name, call_id=call_id,
                        span_id=f"execute:{call_id}", phase="execute",
                        status="ok" if json.loads(reply).get("ok") else "invalid_arguments", preview=reply[:1200])
                    return reply
                except BaseException:
                    self._emit("tool_result", tool=name, call_id=call_id,
                        span_id=f"execute:{call_id}", phase="execute", status="cancelled")
                    raise
            if self._published is not None or self._stage != EXECUTE_STAGE:
                return self._reply(ok=False, error="tools_withdrawn", message="请仅发布结论，实验工具已收回。")
            allowance = getattr(self.gateway, "experiment_allowance", None)
            if allowance is not None and name in {"run_poc", "http_observe", "browser_check", "target_prepare"}:
                remaining = allowance(run_id=self._run_id)
                if remaining['responses'] < 1 or remaining['tools'] < 3:
                    self._stage = "publish"
                    return self._reply(ok=False, error="publication_reserved",
                        message="保留读取证据与发布的最后额度。请提交已有观测；不执行新实验。")
            if self._progress_enabled and name in SIDE_EFFECT_TOOLS:
                refused = self._admit_experiment(name, dict(args or {}))
                if refused is not None:
                    if refused.get("error") == "duplicate_experiment":
                        self._emit("poc_queue_experiment_refused", tool=name,
                                   reason="duplicate_experiment",
                                   duplicate_of=refused.get("duplicate_of"),
                                   context_id=self._service.context_id)
                    return self._reply(**refused)
            reply = await super().call_tool(name, args)
            try:
                value = json.loads(reply)
            except (ValueError, TypeError):
                value = {}
            checkpoint = None
            if self._progress_enabled:
                self._note_progress(name, value)
                if name in EXPERIMENT_TOOLS:
                    checkpoint = self._note_experiment(name, dict(args or {}), value)
            if (len(self._service.jobs) >= self._service.max_jobs or self._service.submission_unresolved
                    or (value.get("precondition") or {}).get("ok") is False):
                self._stage = "publish"
            if checkpoint is not None:
                return self._attach(reply, checkpoint)
            return reply

    @staticmethod
    def _reply(**values):
        return json.dumps(values, ensure_ascii=False, separators=(",", ":"))

    def mark_task(self, finding_id, state, status=None):
        for item in self._tasks:
            if item.get("finding_id") == finding_id:
                item["state"] = state
                if status is not None:
                    item["status"] = status

    def _binding(self):
        finding = self._service.finding
        return dict(finding_id=str(finding.get("id") or ""), context_id=self._service.context_id,
                    revision=int(finding.get("project_revision") or finding.get("revision") or 1))

    def _publish(self, args):
        try:
            data = Publication.model_validate(args).model_dump()
        except ValidationError as exc:
            return self._reject([f"{'.'.join(map(str, e['loc']))}: {e['type']}" for e in exc.errors()][:16])
        if any(data[key] != value for key, value in self._binding().items()):
            return self._reject(["finding_id、revision 或 context_id 不属于当前授权任务"])
        if self._publication is not None:
            return self._reply(ok=data == self._publication, already_published=True,
                               error=None if data == self._publication else "publication_conflict")
        if self._publish_errors >= 3:
            return self._reply(ok=False, error="publication_corrections_exhausted")
        refs = self._refs or EvidenceRefTable([], {}, False)
        result, errors = self._build_result(data, refs)
        if not errors and result is not None:
            errors = evidence_errors(result, self._service)
            proposed = result.status, result.verdict
            checked = host_check(result, self._service)
            if (checked.status, checked.verdict) != proposed:
                errors = errors or ["宿主证据门禁未通过"]
        if errors or result is None:
            return self._reject(errors or ["无法解析结论"])
        # This callback uses record_automatic_verification_guarded, so the attempt,
        # revision and epoch are checked in the same transaction as the verdict.
        record = self._publisher(result, self._usage_snapshot(None))
        if not record:
            return self._reply(ok=False, error="publication_inactive")
        self._publication = data
        self._published = result
        self._stage = "published"
        self._item_state = "published"
        self.mark_task(data["finding_id"], "completed", result.status)
        self._emit("poc_queue_item_published", **self._binding(), status=result.status,
                   verification_id=record.get("id"), message="本项结论已保存，正在等待 SDK 完成当前响应。")
        return self._reply(ok=True, verification_id=record.get("id"), status=result.status,
                           message="已保存。停止实验，结束当前响应，等待宿主发送下一项。")

    def _reject(self, errors):
        self._publish_errors += 1
        self._emit("poc_runtime_conclusion_rejected", reason="host_check_rejected", errors=errors,
                   attempt=self._publish_errors, context_id=self._service.context_id)
        if self._publish_errors >= 3:
            self._stage = "publish"
        return self._reply(ok=False, error="publication_rejected", errors=errors,
                           corrections_remaining=max(0, 3 - self._publish_errors))

    async def verify(self, *, service, emit, run_id, epoch, publisher):
        if self._query_failed:
            return PocRuntimeOutcome("failed", None, "sdk_session_stopped", {})
        if self._actor is None:
            self._run_id, self._epoch = str(run_id), int(epoch or 0)
            self._queue_id = f"queue-{run_id[:32]}-{epoch}"
            self._attempt_deadline = self._queue_deadline
            self._actor = asyncio.create_task(self._serve())
        future = asyncio.get_running_loop().create_future()
        await self._commands.put((service, emit, publisher, future))
        started = time.monotonic()
        warned = False
        try:
            while not future.done():
                if service.should_stop and service.should_stop():
                    raise StopAudit("interrupted", "POC 队列所属运行已停止")
                if time.monotonic() >= self._attempt_deadline:
                    raise StopAudit("budget", "POC 队列整体时间预算已耗尽")
                done, _ = await asyncio.wait({future, self._actor}, timeout=min(
                    self.HEARTBEAT_SECONDS, max(.001, self._attempt_deadline - time.monotonic())))
                if self._actor in done and not future.done():
                    await self._actor
                    raise PocRuntimeUnavailable("sdk_session_closed")
                if not future.done():
                    # Publication is already durable (or its bounded corrections
                    # are exhausted). End the SDK response instead of paying for
                    # more narration; this never aborts an undecided experiment.
                    if (self._client is not None and not self._host_interrupt
                            and (self._published is not None or self._publish_errors >= 3)):
                        self._host_interrupt = "published" if self._published is not None else "publication_rejected"
                        try:
                            await asyncio.wait_for(self._client.interrupt(), timeout=min(
                                5., max(.001, self._attempt_deadline - time.monotonic())))
                        except Exception:
                            self._query_failed = True
                            self._execute_reason = "sdk_interrupt_error"
                            await self.aclose()
                            return PocRuntimeOutcome("completed" if self._published else "failed",
                                self._published, "completed" if self._published else "sdk_interrupt_error",
                                self._usage_snapshot(None))
                    elapsed = time.monotonic() - started
                    threshold = service.policy.get("item_warning_seconds") or service.policy.get("max_seconds") or 300
                    warned = warned or elapsed >= threshold
                    checkpoint = self._heartbeat_progress()
                    emit(dict(kind="poc_queue_heartbeat", elapsed_seconds=round(elapsed, 1),
                        soft_limit_exceeded=warned, published=self._published is not None,
                        jobs=len(service.jobs),
                        progress_state=self._item_state if self._progress_enabled else None,
                        checkpoint_id=(checkpoint or {}).get("checkpoint_id"),
                        checkpoint_reason=(checkpoint or {}).get("reason"),
                        message="SDK 正在处理当前任务；单项耗时仅提醒，不中止验证。"))
            return future.result()
        except BaseException:
            await self.aclose()
            raise

    async def _serve(self):
        future = None
        try:
            command = await self._commands.get()
            self._bind(command)
            future = command[3]
            self._readiness = self.readiness()
            self._emit("poc_runtime_readiness", **self._readiness.snapshot())
            if not self._readiness.ready:
                raise PocRuntimeUnavailable(self._readiness.reason)
            opened = self.gateway.open_stage(run_id=self._run_id, epoch=self._epoch,
                stage=EXECUTE_STAGE, limit=self.limits.execute_requests)
            if not opened.get("ok"):
                raise PocRuntimeUnavailable("quota_unavailable")
            server = self._build_mcp_server()
            options = self._options(EXECUTE_STAGE, server,
                execute_instructions(self._service) + QUEUE_CONTRACT
                + (PROGRESS_CONTRACT if self._progress_enabled else ""))
            host_tools = ["get_verification_tasks", "get_verification_evidence", "publish_verification"]
            if self._progress_enabled:
                host_tools.append(CONTINUE_TOOL)
            options.allowed_tools += [f"mcp__poc__{name}" for name in host_tools]
            client_type = getattr(self._sdk, "ClaudeSDKClient", None)
            if client_type is None:
                raise PocRuntimeUnavailable("interactive_sdk_missing")
            # Opening, receiving and closing happen in THIS task, as required by
            # the SDK's AnyIO cancel scopes, even when callers pause/cancel.
            pending = None
            async with client_type(options=options) as client:
                self._client = client
                while command is not None:
                    future = command[3]
                    reason = await self._run_item(client)
                    if reason in RECOVERABLE_REASONS and self._progress_enabled:
                        # A broken stream is not a verdict. Freeze the item's host
                        # facts, close the SDK below, and only then try the bounded
                        # read-only recovery inside the same item window.
                        self._stream_error = self._stream_error or reason
                        self._take_checkpoint("stream_error", always=True)
                        self._query_failed = True
                        pending = (command, reason)
                        break
                    outcome = PocRuntimeOutcome("completed" if self._published else "failed",
                        self._published, "completed" if self._published else reason, self._usage_snapshot(None))
                    self.mark_task(self._service.finding["id"], "completed",
                                   self._published.status if self._published else "inconclusive")
                    if not future.done():
                        future.set_result(outcome)
                    if self._query_failed:
                        break
                    command = await self._commands.get()
                    if command is not None:
                        self._bind(command)
            if pending is not None:
                await self._finish_recovery(*pending)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._query_failed = True
            self._execute_reason = (exc.reason if isinstance(exc, StopAudit) else
                "runtime_unavailable" if isinstance(exc, PocRuntimeUnavailable) else "sdk_error")
            self._emit("poc_runtime_error", stage="execute", code=self._execute_reason,
                       message="持续会话已停止，原作业及逐项已发布结果保留，不重放实验。")
            if future is not None and not future.done():
                future.set_result(PocRuntimeOutcome("completed" if self._published else "failed",
                    self._published, "completed" if self._published else self._execute_reason,
                    self._usage_snapshot(None)))
        finally:
            self._client = None
            self._stage = "closed"
            self._emit_generation_once(EXECUTE_STAGE)
            self._revoke_stage_capability(EXECUTE_STAGE)

    def _heartbeat_progress(self) -> dict | None:
        """Turn an idle item or the publish window into a read-only checkpoint.

        A reminder is never a failure and never grants anything; it only stops new
        side effects until the model declares a discriminating continuation or
        publishes what it already has.
        """
        if not self._progress_enabled or self._item_state != "experiment":
            return None
        now = time.monotonic()
        limits = self._progress_limits()
        if now >= self._experiment_deadline:
            return self._take_checkpoint("publish_window")
        idle = now - self._last_progress_at
        if (self._item_started and now - self._item_started >= limits.item_warning_seconds
                and idle >= limits.item_warning_seconds):
            return self._take_checkpoint("item_warning")
        return None

    async def _finish_recovery(self, command, reason):
        """Complete one broken item after its SDK transport is confirmed closed."""
        future = command[3]
        try:
            outcome = await self._recover_readonly(reason)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - never lose the saved checkpoint
            self._recovery = {"attempted": True, "original": reason, "published": False,
                              "reason": "recovery_error"}
            self._emit("poc_queue_recovery_failed", original_reason=reason,
                       error=type(exc).__name__, jobs=len(self._service.jobs),
                       message="只读回收异常结束；原作业与检查点已保存，结论保持未决。")
            outcome = PocRuntimeOutcome("failed", None, reason, self._usage_snapshot(None))
        self.mark_task(self._service.finding["id"], "completed",
                       self._published.status if self._published else "inconclusive")
        if not future.done():
            future.set_result(outcome)

    def _refused_recovery(self, skip: str, reason: str, **fields) -> PocRuntimeOutcome:
        service = self._service
        self._recovery = {"attempted": False, "reason": skip, "original": reason}
        self._emit("poc_queue_recovery_skipped", reason=skip, original_reason=reason,
                   jobs=len(service.jobs) if service is not None else 0,
                   checkpoint_id=(self._checkpoint or {}).get("checkpoint_id"), **fields,
                   message="未启动只读回收；检查点已保存，结论保持未决，不重放实验。")
        return PocRuntimeOutcome("failed", None, reason, self._usage_snapshot(None))

    async def _recover_readonly(self, reason: str) -> PocRuntimeOutcome:
        """One bounded conclusion-only recovery, inside the item's own window.

        It opens the durable ``conclude`` stage (first opener wins, never refreshed),
        so every recovery request still charges the run and workflow POC quotas and
        cannot borrow the review reserve.  Experiments are impossible here: there is
        no MCP server, no tool list and no target lease.
        """
        service = self._service
        if self._published is not None:
            # The conclusion was already committed before the stream broke; recovery
            # exists to save an undecided item, never to replace a decision.
            return PocRuntimeOutcome("completed", self._published, "completed",
                                     self._usage_snapshot(None))
        limits = self._progress_limits()
        started = time.monotonic()
        remaining = self._queue_deadline - started
        allowance = self._allowance()
        requests = min(int(limits.recovery_requests), int(allowance.get("responses") or 0),
                       int(self.limits.conclude_requests))
        if service is None:
            return self._refused_recovery("no_service", reason)
        if service.submission_unresolved:
            return self._refused_recovery("unresolved_job", reason)
        if remaining < 5:
            return self._refused_recovery("no_time", reason, remaining_seconds=round(remaining, 1))
        if requests < 1:
            return self._refused_recovery("no_quota", reason,
                                          responses=int(allowance.get("responses") or 0))
        deadline = started + min(float(limits.recovery_seconds), remaining)
        opened = self.gateway.open_stage(run_id=self._run_id, epoch=self._epoch,
                                         stage=CONCLUDE_STAGE, limit=requests)
        if not opened.get("ok"):
            return self._refused_recovery("stage_unavailable", reason, detail=opened.get("reason"))
        self._recovery = {"attempted": True, "original": reason, "requests": requests,
                          "seconds": round(deadline - started, 1), "published": False}
        self._emit("poc_queue_recovery_started", original_reason=reason, requests=requests,
                   seconds=round(deadline - started, 1), jobs=len(service.jobs),
                   checkpoint_id=(self._checkpoint or {}).get("checkpoint_id"),
                   message="会话流已确认关闭；只在原窗口内做一次只读结论回收，不启动实验。")
        previous = self.limits
        self.limits = replace(previous, conclude_requests=requests,
                              max_seconds=int(max(5, deadline - started)))
        self._stage = CONCLUDE_STAGE
        service.phase = CONCLUDE_STAGE
        service.execution.phase = CONCLUDE_STAGE
        result, why = None, ""
        try:
            refs = self._refs if self._refs is not None else EvidenceRefTable([], {}, False)
            result, why = await self._conclude(service, refs, started)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # noqa: BLE001 - recovery failure is an outcome
            why = "recovery_failed"
            self._emit("poc_queue_recovery_failed", original_reason=reason,
                       error=type(exc).__name__, jobs=len(service.jobs),
                       message="只读回收未能完成；已保存的作业、检查点与逐项结果保留。")
        finally:
            self.limits = previous
            self._stage = "checkpoint"
            self._revoke_stage_capability(CONCLUDE_STAGE)
        if self._published is not None:
            # A committed conclusion is never overwritten by a later recovery.
            return PocRuntimeOutcome("completed", self._published, "completed",
                                     self._usage_snapshot(None))
        if result is None:
            self._recovery.update(published=False, reason=why or reason)
            self._emit("poc_queue_recovery_failed", original_reason=reason,
                       reason=why or reason, jobs=len(service.jobs),
                       evidence_refs=len(self._refs) if self._refs is not None else 0,
                       message="只读回收没有产生可用结论；原错误保留，结论保持未决。")
            return PocRuntimeOutcome("failed", None, reason, self._usage_snapshot(None))
        record = self._publisher(result, self._usage_snapshot(None))
        if not record:
            self._recovery.update(published=False, reason="publication_inactive")
            self._emit("poc_queue_recovery_failed", original_reason=reason,
                       reason="publication_inactive", jobs=len(service.jobs),
                       message="回收结论未能写入；不覆盖已保存结果。")
            return PocRuntimeOutcome("failed", None, reason, self._usage_snapshot(None))
        self._published = result
        self._publication = None
        self._item_state = "published"
        self._recovery.update(published=True, reason="completed")
        self._emit("poc_queue_recovery_published", **self._binding(), status=result.status,
                   verification_id=record.get("id"), original_reason=reason,
                   message="只读回收已保存结论；原会话错误保留为触发原因。")
        return PocRuntimeOutcome("completed", result, "completed", self._usage_snapshot(None))

    def _bind(self, command):
        self._service, self._emit_cb, self._publisher, _ = command
        self._should_stop = self._service.should_stop
        self._stage = EXECUTE_STAGE
        self._published, self._publication, self._refs = None, None, None
        self._publish_errors = 0
        self._execute_reason = ""
        self._host_interrupt = ""
        self._result_seen = False
        self._diagnostics = []
        self._usage = {key: None for key in self._usage}
        admit_tool = getattr(self.gateway, "admit_tool", None)
        self._service.execution = _StageToolExecution(
            lambda event: self._emit(event['kind'], **{k: v for k, v in event.items() if k != 'kind'}),
            (lambda: admit_tool(run_id=self._run_id, epoch=self._epoch)) if admit_tool else None)
        self._service.phase = EXECUTE_STAGE
        self._service.execution.phase = EXECUTE_STAGE
        self.mark_task(self._service.finding["id"], "running")
        self._reset_progress()
        self._emit("poc_queue_item_started", **self._binding(),
                   remaining=sum(item.get("state") in {"pending", "running"} for item in self._tasks))

    async def _stored_poc_prompt(self) -> str:
        """Run the audit's own POC once before the model plans this item.

        The audit already produced an executable check; making the verifying agent
        rewrite it from scratch spent the item's wall clock on re-derivation.  The job
        still passes the ordinary tool, identity, job-limit and runner-precondition
        gates, and its reply is only a transcript to interpret, never evidence by itself.
        """
        if self._service is None or not stored_poc_preflight(self._service.policy or {}):
            return ""
        finding_id = str(self._service.finding.get("id") or "")
        if finding_id and finding_id == self._stored_poc_finding:
            return ""
        self._stored_poc_finding = finding_id
        reply = await run_stored_poc(
            self._service.finding, self._service,
            lambda event: self._emit(event["kind"], **{k: v for k, v in event.items() if k != "kind"}))
        if not reply:
            return ""
        return ("\n# 宿主已执行审计记录的 POC（一次，待验证假设，不是结论）\n"
                + reply[:12 * 1024]
                + "\n以上只是该脚本的一次真实执行结果。先判断正常侧与攻击侧差异是否足以支撑结论；"
                "成立时不必重写同一脚本，可直接补必要的对照并提交结论；"
                "不成立或前提不符时再设计最小新实验。")

    async def _run_item(self, client):
        prompt = (self._execute_prompt(self._service) + await self._stored_poc_prompt()
                  + "\n# 当前唯一授权任务\n"
                  + self._reply(**self._binding()) + "\n调用 publish_verification 立即保存本项，然后结束响应。")
        for correction in range(3):
            if self._stopped():
                raise StopAudit("interrupted", "POC 队列已停止")
            self._raise_if_quota_refused(EXECUTE_STAGE)
            request_started = time.monotonic()
            await client.query(prompt)
            final = None
            counters = {"text_chars": 0, "thinking_chars": 0, "tool_arg_chars": 0,
                        "text_events": 0, "thinking_events": 0, "tool_arg_events": 0}
            events = 0
            last_progress = 0.
            last_emitted = 0
            try:
                async for message in client.receive_response():
                    events += 1
                    if self._stopped():
                        raise StopAudit("interrupted", "POC 队列已停止")
                    if _is_result_message(message):
                        final = message
                    # Emit metadata only. Neither thinking deltas nor public prose can
                    # accidentally persist a credential or a second model transcript.
                    event = getattr(message, "event", None)
                    delta = event.get("delta") if isinstance(event, dict) else None
                    if isinstance(delta, dict):
                        kind = delta.get("type")
                        if kind == "text_delta":
                            counters["text_events"] += 1
                            counters["text_chars"] += len(str(delta.get("text") or ""))
                        elif kind == "thinking_delta":
                            counters["thinking_events"] += 1
                            counters["thinking_chars"] += len(str(delta.get("thinking") or ""))
                        elif kind == "input_json_delta":
                            counters["tool_arg_events"] += 1
                            counters["tool_arg_chars"] += len(str(delta.get("partial_json") or ""))
                    # Rate-limited generation metadata: counts and waits only, never
                    # the generated text or thinking body.
                    if events != last_emitted and time.monotonic() - last_progress >= 1:
                        last_emitted, last_progress = events, time.monotonic()
                        now = time.monotonic()
                        self._emit("poc_queue_progress", public_output_chars=counters["text_chars"],
                                   model_wait_seconds=round(now - request_started, 1),
                                   since_last_experiment_seconds=(
                                       None if not self._last_progress_at
                                       else round(now - self._last_progress_at, 1)),
                                   response_events=events, **counters,
                                   observations=len(self._completed_jobs),
                                   jobs=len(self._service.jobs) if self._service is not None else None,
                                   published=self._published is not None,
                                   unpublished_reason=self._unpublished_reason(),
                                   message="SDK 正在生成验证响应。")
            except (asyncio.CancelledError, StopAudit):
                raise
            except Exception as exc:  # noqa: BLE001 - a broken stream is data, not a verdict
                # A transport failure after the terminal result is only a bad exit
                # status; the result below is still classified normally. Anything
                # earlier keeps every finished job and lets the host recover
                # read-only instead of silently rejecting a broken experiment.
                if final is not None:
                    pass
                elif not self._progress_enabled:
                    raise
                else:
                    self._stream_error = "stream_connection_error"
                    self._emit("poc_runtime_error", stage="execute", code="stream_connection_error",
                               exception=type(exc).__name__, events=events,
                               public_output_chars=counters["text_chars"], jobs=len(self._service.jobs),
                               message="SDK 流已中断；已完成作业与观测保留，等待宿主只读回收。")
                    return "stream_connection_error"
            if final is None:
                if not self._progress_enabled:
                    raise PocRuntimeUnavailable("missing_result_message")
                self._stream_error = "missing_result_message"
                self._emit("poc_runtime_error", stage="execute", code="missing_result_message",
                           events=events, public_output_chars=counters["text_chars"],
                           jobs=len(self._service.jobs),
                           message="SDK 响应结束但没有终态结果；已完成作业与观测保留，等待宿主只读回收。")
                return "missing_result_message"
            usage = _usage_from_result(final)
            # Interactive ResultMessage.usage is per turn, but total_cost_usd
            # is cumulative for this CLI session. Charge its delta exactly once.
            total_cost = usage.get("cost_usd")
            if total_cost is None:
                self._cost_contiguous = False
            else:
                usage["cost_usd"] = (round(total_cost - self._cost_total, 6)
                    if self._cost_contiguous and total_cost >= self._cost_total else None)
                self._cost_total = total_cost
                self._cost_contiguous = True
            self._result_seen = True
            self._merge_usage(usage)
            self._emit("poc_runtime_usage", stage="execute", usage=usage,
                provider_model=self.limits.model, sdk_version=_sdk_version(),
                cost_usd=usage.get("cost_usd"), cumulative_cost_usd=total_cost,
                is_error=bool(getattr(final, "is_error", False)), session_policy=QUEUE_POLICY)
            if getattr(final, "is_error", False):
                if self._host_interrupt and getattr(final, 'terminal_reason', None) in {'aborted_tools', 'aborted_streaming'}:
                    return "completed" if self._published is not None else "conclusion_rejected"
                self._sdk_diagnostic(EXECUTE_STAGE, final)
                self._query_failed = True
                self._execute_reason = "sdk_api_error"
                return "sdk_api_error"
            if self._published is not None:
                return "completed"
            # A complete response that omitted publication gets two bounded,
            # read-only corrections in the SAME session; no side effects replay.
            self._stage = "publish"
            prompt = ("尚未发布本项。实验工具已收回；读取 get_verification_evidence 后调用 publish_verification，"
                      "证据不足提交 inconclusive。当前绑定：" + self._reply(**self._binding()))
        return "conclusion_rejected"

    def _usage_snapshot(self, stages=None):
        value = super()._usage_snapshot(stages)
        for unused in ('execute_turns', 'conclude_turns', 'conclude_requests', 'conclude_usd'):
            value['runtime'].pop(unused, None)
        value["runtime"].update(session_policy=QUEUE_POLICY, time_policy="run-budget",
                                publication="tool-commit", request_policy="shared-poc-stage",
                                cost_policy="sdk-session-estimate-delta", max_turns=None,
                                max_seconds_scope="queue-remaining-window")
        value["usage_status"] = "final" if self._result_seen else "awaiting_sdk_result"
        progress = self._progress_snapshot()
        if progress:
            value["progress"] = progress
        return value

    async def aclose(self):
        # Revoke first: cancellation can never allow a late tool or upstream write.
        self._stage = "closed"
        self._revoke_stage_capability(EXECUTE_STAGE)
        actor = self._actor
        if actor is None:
            return
        if not actor.done():
            actor.cancel()
        done, _ = await asyncio.wait({actor}, timeout=5)
        if not done:
            self._query_failed = True
            self._emit("poc_runtime_cleanup_failed", stage="execute", reason="sdk_cleanup_timeout",
                       message="会话尚未确认退出；已撤销工具与网关权限，不启动后续任务。")
            actor.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        else:
            try:
                await actor
            except (Exception, asyncio.CancelledError):
                pass
