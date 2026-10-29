"""The single Claude Agent SDK adapter for automatic POC verification.

The legacy POC agent owns a hand-written model loop: ``Execution``, ``PhaseGate``, a
code-action interpreter and a message history.  This module replaces *that loop only*.
The facts stay where they already are: ``PocToolService`` owns the runner client, the
job table, preconditions, artifacts and the evidence views, and the host still decides
whether a conclusion may be published.

Design boundaries, each of which is also a test:

* **One runtime per attempt.**  ``ClaudeCodePocRuntime`` never falls back to the legacy
  loop inside an attempt; a runtime failure ends the attempt with a named status and the
  caller may create a *new* attempt on another runtime.
* **Two fixed stages.**  The experiment stage sees the runner tools; the conclusion
  stage sees none of them and is given host-assembled facts plus stable evidence ids.
* **A hard request quota.**  Before an experiment starts, the host opens a separate
  request allowance for conclusion and experiment.  Every real upstream request (SDK
  retries, compaction and format corrections included) is reserved atomically through
  the injected gateway; exhaustion stops the SDK instead of returning a retryable error.
* **Host-owned evidence ids.**  The model returns ``evidence_ref_id`` values built from
  the segments the host displayed.  Ids for failed, foreign-context or undisplayed jobs
  do not resolve, so an excerpt cannot be paraphrased into "proof".
* **No hidden transcript.**  Only public stage progress, stop reasons, usage and the
  final ``ResultMessage.structured_output`` are bridged into durable events.  Thinking
  text, message bodies and session files are not stored.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit, urlunsplit

from ..poc_agent import (
    POC_TOOLS,
    _conclusion_jobs,
    _context_json,
    _finding_block,
    execute_instructions,
    host_check,
)
from ..poc_tool_service import PocToolService
from ..runtime import StopAudit
from ..schemas import PocEvidenceReference, PocVerificationResult
from ..toolkit import REQUIRED

RUNTIME_NAME = "claude_sdk"
EXECUTE_STAGE = "execute"
CONCLUDE_STAGE = "conclude"
# The conclusion owns these real requests: one answer, one SDK format correction and at
# most one semantic correction.  ``max_turns`` is an additional bound, never the reserve.
RESERVED_CONCLUDE_REQUESTS = 3
DEFAULT_EXECUTE_REQUESTS = 40
TOOL_NAMES = tuple(spec.name for spec in POC_TOOLS)
_EVIDENCE_REF = re.compile(r"^ev-[0-9a-f]{16}$")

# The structured conclusion is a host contract, not a rendering of Pydantic internals:
# evidence is chosen by host id, so the model never has to copy raw output.
CONCLUSION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["status", "summary"],
    "properties": {
        "status": {"type": "string", "enum": ["verified", "rejected", "inconclusive"]},
        "summary": {"type": "string", "maxLength": 4000},
        "normal_observation": {"type": "string", "maxLength": 4000},
        "attack_observation": {"type": "string", "maxLength": 8000},
        "browser_execution": {"type": "boolean"},
        "evidence_notes": {"type": "string", "maxLength": 4000},
        "modification_notes": {"type": "string", "maxLength": 4000},
        "jobs": {"type": "array", "maxItems": 16, "items": {"type": "string"}},
        "normal_refs": {"type": "array", "maxItems": 16, "items": {"type": "string"}},
        "attack_refs": {"type": "array", "maxItems": 16, "items": {"type": "string"}},
    },
}

# The conclusion stage has no tools, so the only thing it can produce is this document.
# It differs from the legacy ``CONCLUDE_INSTRUCTIONS`` on one point: evidence is selected
# by host id, never copied, so a paraphrase cannot become a citation.
CONCLUDE_CONTRACT = """你是 POC 自动验证 Agent 的结论阶段，所有工具都已收回。
只输出一个 JSON 对象，不写 Python/XML/final_answer，不生成推理正文，不重新实验。
字段：
- status: verified | rejected | inconclusive
- summary: 一句结论
- normal_observation / attack_observation: 这是对照实际观测，必须对应下方证据引用
- browser_execution: 是否有浏览器实际执行（XSS 的 verified 必须为 true）
- evidence_notes / modification_notes: 可选
- jobs: 支撑结论的真实 job_id 列表
- normal_refs / attack_refs: 证据引用 id 列表，只能使用“可用证据引用”中出现的 evidence_ref_id
verified/rejected 必须有 jobs 以及两侧观测与引用；未知 id、证据不可用的 job 一律被宿主拒绝。
verified 表示对照证明漏洞影响；rejected 表示有效实验明确否定当前结论；
失败、前提不符或证据不足均为 inconclusive；not_applicable/environment_unavailable 只由宿主决定。
successful HTTP 状态、退出码、省略标记、元数据或状态变化都不能替代实际影响与原文证据。
XSS 的攻击侧必须是浏览器 dialogs/evaluated 的引用。
宿主拒绝后只修正 JSON 中列出的问题；工具不会重新开放。"""


class PocRuntimeError(RuntimeError):
    """Base class for adapter failures that end this attempt (never a silent fallback)."""


class PocRuntimeUnavailable(PocRuntimeError):
    """The SDK, CLI, model, gateway or workspace is not usable on this host."""


class PocQuotaRefusal(PocRuntimeError):
    """A hard request quota refused an upstream request; the SDK must stop."""

    def __init__(self, reason: str, reservation: dict | None = None):
        super().__init__(reason)
        self.reason = reason
        self.reservation = dict(reservation or {})


class PocRequestGateway(Protocol):
    """The host's controlled Anthropic gateway, seen from the adapter.

    ``reserve`` is called once per real upstream request by the gateway process, not by
    this adapter.  Its refusal is final for the stage.
    """

    def open_stage(self, *, run_id: str, epoch: int, stage: str, limit: int) -> dict: ...

    def reserve(self, *, run_id: str, epoch: int, stage: str) -> dict: ...

    def snapshot(self, *, run_id: str, epoch: int) -> dict: ...


@dataclass
class MemoryPocRequestGateway:
    """In-process gateway with the same refusal semantics as the durable one.

    Tests and single-process development use it; production binds ``reserve``/``open``
    to ``Store.open_poc_request_stage`` and ``Store.reserve_poc_request`` so a restart
    cannot reset an allowance.
    """

    limits: dict[str, int] = field(default_factory=dict)
    _used: dict[tuple[str, int, str], int] = field(default_factory=dict)
    _refused: set[tuple[str, int, str]] = field(default_factory=set)
    _narrowed: list[dict] = field(default_factory=list)

    def open_stage(self, *, run_id: str, epoch: int, stage: str, limit: int) -> dict:
        key = (run_id, int(epoch), stage)
        existing = self.limits.get(key)
        if existing is None:
            self.limits[key] = limit
            existing = limit
        elif existing < limit:
            self._narrowed.append({"stage": stage, "requested": limit, "limit": existing})
        self._used.setdefault(key, 0)
        return {"ok": True, "stage": stage, "limit": existing, "used": self._used[key],
                "requested": limit, "narrowed": existing < limit}

    def reserve(self, *, run_id: str, epoch: int, stage: str) -> dict:
        key = (run_id, int(epoch), stage)
        limit = self.limits.get(key)
        if limit is None:
            return {"granted": False, "reason": "stage_not_open", "stage": stage,
                    "limit": 0, "used": 0, "remaining": 0}
        used = self._used.get(key, 0)
        if key in self._refused:
            return {"granted": False, "reason": "quota_refused", "stage": stage,
                    "limit": limit, "used": used, "remaining": max(0, limit - used)}
        if used >= limit:
            self._refused.add(key)
            return {"granted": False, "reason": "quota_exhausted", "stage": stage,
                    "limit": limit, "used": used, "remaining": 0}
        self._used[key] = used + 1
        return {"granted": True, "stage": stage, "limit": limit, "used": used + 1,
                "remaining": max(0, limit - used - 1)}

    def snapshot(self, *, run_id: str, epoch: int) -> dict:
        return {
            stage: {"limit": limit,
                    "used": self._used.get((run_id, int(epoch), stage), 0),
                    "remaining": max(0, limit - self._used.get((run_id, int(epoch), stage), 0)),
                    "refused": (run_id, int(epoch), stage) in self._refused}
            for (owner, opened_epoch, stage), limit in sorted(self.limits.items())
            if owner == run_id and opened_epoch == int(epoch)
        }

    def reserve_upstream_request(self, *, run_id: str, epoch: int, stage: str) -> int:
        """The gateway process calls this for one real request; returns its ordinal."""
        result = self.reserve(run_id=run_id, epoch=epoch, stage=stage)
        if not result.get("granted"):
            raise PocQuotaRefusal(str(result.get("reason") or "quota_exhausted"), result)
        return int(result.get("used") or 0)


@dataclass
class StorePocRequestGateway:
    """The durable gateway: ``poc_request_quota`` survives a backend restart.

    The first opener of ``(run, epoch, stage[, host scope])`` fixes the allowance;
    the host scope identifies a finding/ledger revision for new batch-review runs.
    Reopening never refreshes it; every request still charges the run/workflow.
    """

    store: Any
    scope: str = ""
    _tokens: dict[tuple[str, int, str], str] = field(default_factory=dict, init=False, repr=False)
    _refusals: dict[tuple[str, int, str], dict] = field(default_factory=dict, init=False, repr=False)

    def open_stage(self, *, run_id: str, epoch: int, stage: str, limit: int) -> dict:
        return self.store.open_poc_request_stage(run_id, stage + ("@" + self.scope if self.scope else ""), limit, epoch=epoch)

    def reserve(self, *, run_id: str, epoch: int, stage: str) -> dict:
        return self.store.reserve_poc_request(run_id, stage + ("@" + self.scope if self.scope else ""), epoch=epoch)

    def snapshot(self, *, run_id: str, epoch: int) -> dict:
        values = self.store.poc_request_quota(run_id, epoch=epoch)
        if not self.scope:
            return {k: v for k, v in values.items() if "@" not in k}
        return {k.split("@", 1)[0]: v for k, v in values.items() if k.endswith("@" + self.scope)}

    def check_readiness(self) -> dict:
        service = getattr(self.store, "_poc_model_gateway", None)
        return service.readiness() if service is not None else {
            "ready": False, "reason": "gateway_service_missing",
        }

    def issue_capability(self, **binding) -> str:
        service = getattr(self.store, "_poc_model_gateway", None)
        if service is None:
            raise PocRuntimeUnavailable("gateway_service_missing")
        token = service.issue_capability(**binding, **({"quota_scope": self.scope} if self.scope else {}))
        key = (binding["run_id"], binding["epoch"], binding["stage"])
        self._tokens[key] = token
        self._refusals.pop(key, None)
        return token

    def stage_refusal(self, *, run_id: str, epoch: int, stage: str) -> dict:
        key = (run_id, int(epoch), stage)
        token = self._tokens.get(key)
        service = getattr(self.store, "_poc_model_gateway", None)
        if token and service is not None:
            refusal = service.refusal_for_capability(token)
            if refusal:
                self._refusals[key] = refusal
        return self._refusals.get(key, {})

    def admit_tool(self, *, run_id: str, epoch: int) -> None:
        from ..execution_state import execution_role
        with execution_role("poc"):
            self.store.admit_execution(run_id, epoch, "tools")

    def revoke_capability(self, token: str) -> None:
        service = getattr(self.store, "_poc_model_gateway", None)
        if service is not None:
            # Cleanup deletes the capability registry entry. Preserve its trusted
            # refusal for the adapter's outer exception handler before revoking it.
            for key, issued in tuple(self._tokens.items()):
                if issued == token:
                    refusal = service.refusal_for_capability(token)
                    if refusal:
                        self._refusals[key] = refusal
                    self._tokens.pop(key, None)
            service.revoke_capability(token)


class _StageToolExecution:
    """The event/usage owner ``PocToolService`` expects when no legacy loop exists.

    It numbers calls, stamps the stage and delegates to the original host tool
    admission. The SDK owns its message loop; no second model ledger is created.
    """

    def __init__(self, emit: Callable[[dict], None], admit: Callable[[], None] | None = None) -> None:
        self._emit_callback = emit
        self._admit = admit
        self.tools = 0
        self.phase = EXECUTE_STAGE
        self.started = time.monotonic()

    def before_tool(self) -> None:
        if self._admit is not None:
            self._admit()
        self.tools += 1

    def emit(self, payload: dict) -> None:
        self._emit_callback(payload)

    def snapshot(self) -> dict:
        return {"tools": self.tools, "phase": self.phase,
                "elapsed_ms": round((time.monotonic() - self.started) * 1000)}


@dataclass(frozen=True)
class PocRuntimeReadiness:
    ready: bool
    reason: str
    message: str
    runtime: str = RUNTIME_NAME
    sdk_version: str = ""
    cli_version: str = ""
    model: str = ""
    gateway: str = ""
    workspace: str = ""
    capability: bool = False

    def snapshot(self) -> dict:
        return {
            "ready": self.ready, "reason": self.reason, "message": self.message,
            "runtime": self.runtime, "sdk_version": self.sdk_version,
            "cli_version": self.cli_version, "model": self.model,
            "gateway": self.gateway, "workspace": self.workspace,
            "capability": self.capability,
        }


@dataclass(frozen=True)
class PocRuntimeOutcome:
    """What one attempt produced; ``result`` is only set when the host accepted it."""

    status: str
    result: PocVerificationResult | None
    reason: str
    usage: dict = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceRef:
    """One host-displayed segment the model may cite by id."""

    ref_id: str
    job_id: str
    channel: str
    offset: int
    length: int
    sha256: str
    text: str

    def public(self, *, with_text: bool = True) -> dict:
        payload = {"evidence_ref_id": self.ref_id, "job_id": self.job_id,
                   "channel": self.channel, "offset": self.offset,
                   "length": self.length, "sha256": self.sha256}
        if with_text:
            payload["text"] = self.text
        return payload


class EvidenceRefTable:
    """Stable ids over the exact segments the host showed in the conclusion prompt.

    The table is built from ``_conclusion_jobs`` -- the same rendering, the same 24KiB
    budget, the same omission markers -- so "displayed" has one definition.  Only jobs
    the host considers usable evidence are registered: an id can never name a failed,
    timed-out or foreign-context job.
    """

    def __init__(self, refs: list[EvidenceRef], displayed: dict, truncated: bool):
        self._refs = {ref.ref_id: ref for ref in refs}
        self._order = [ref.ref_id for ref in refs]
        self.displayed = displayed
        self.truncated = truncated

    @classmethod
    def build(cls, service: PocToolService) -> "EvidenceRefTable":
        try:
            rendered = json.loads(_conclusion_jobs(service))
        except (TypeError, ValueError):
            rendered = {}
        items = rendered.get("items") if isinstance(rendered, dict) else None
        refs: list[EvidenceRef] = []
        seen: set[str] = set()
        for job in items or ():
            if not isinstance(job, dict) or job.get("evidence_usable") is not True:
                continue
            job_id = str(job.get("job_id") or "")
            channels = job.get("evidence_channels")
            if not job_id or not isinstance(channels, dict):
                continue
            for channel, rendered_channel in channels.items():
                segments = (rendered_channel or {}).get("segments") if isinstance(rendered_channel, dict) else None
                for segment in segments or ():
                    if not isinstance(segment, dict):
                        continue
                    text = str(segment.get("text") or "")
                    # The excerpt field is capped at 4000 characters; a prefix keeps the
                    # cited substring exact and contiguous, which the host still checks.
                    text = text[:4000]
                    if not text:
                        continue
                    offset = int(segment.get("offset") or 0)
                    digest = hashlib.sha256(
                        f"{service.context_id}|{job_id}|{channel}|{offset}|{hashlib.sha256(text.encode()).hexdigest()}".encode()
                    ).hexdigest()
                    ref_id = f"ev-{digest[:16]}"
                    if ref_id in seen:
                        continue
                    seen.add(ref_id)
                    refs.append(EvidenceRef(
                        ref_id=ref_id, job_id=job_id, channel=str(channel), offset=offset,
                        length=len(text), sha256=hashlib.sha256(text.encode()).hexdigest(),
                        text=text,
                    ))
        return cls(refs, rendered if isinstance(rendered, dict) else {},
                   bool(rendered.get("output_truncated")) if isinstance(rendered, dict) else False)

    def resolve(self, ref_id: str) -> EvidenceRef | None:
        if not isinstance(ref_id, str) or not _EVIDENCE_REF.match(ref_id):
            return None
        return self._refs.get(ref_id)

    def __len__(self) -> int:
        return len(self._order)

    def public(self, limit: int = 24 * 1024) -> list[dict]:
        """Bounded host view; text is what the model reasons over, bytes still count."""
        payload: list[dict] = []
        total = 0
        for ref_id in self._order:
            item = self._refs[ref_id].public()
            size = len(json.dumps(item, ensure_ascii=False).encode())
            if total + size > limit:
                break
            total += size
            payload.append(item)
        return payload


def _tool_schema(spec) -> dict:
    """Translate the declared host tool surface into the SDK's JSON Schema shape."""
    kinds = {"string": "string", "integer": "integer", "number": "number",
             "boolean": "boolean", "array": "array", "object": "object", "any": None}
    properties: dict[str, Any] = {}
    required: list[str] = []
    for name, arg in spec.args.items():
        kind = kinds.get(arg.value_type or arg.type, "string")
        declared: dict[str, Any] = {"description": arg.prompt_description()}
        if kind is not None:
            declared["type"] = kind
        if arg.item_type:
            declared["items"] = {"type": kinds.get(arg.item_type, "string")}
        if arg.minimum is not None:
            declared["minimum"] = arg.minimum
        if arg.maximum is not None:
            declared["maximum"] = arg.maximum
        if arg.max_length is not None:
            declared["maxLength"] = arg.max_length
        if arg.max_items is not None:
            declared["maxItems"] = arg.max_items
        if arg.default is REQUIRED:
            required.append(name)
        else:
            declared["default"] = arg.default
        properties[name] = declared
    schema: dict[str, Any] = {"type": "object", "properties": properties,
                              "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema


@dataclass(frozen=True)
class ClaudePocLimits:
    """Frozen deployment input for the adapter; nothing here comes from a run request."""

    model: str = ""
    gateway_url: str = ""
    workspace: str = ""
    sdk_version: str = ""
    cli_version: str = ""
    capability_token: str = ""
    execute_turns: int = 24
    conclude_turns: int = 4
    execute_requests: int = DEFAULT_EXECUTE_REQUESTS
    conclude_requests: int = RESERVED_CONCLUDE_REQUESTS
    max_seconds: int = 300
    execute_usd: float | None = None
    conclude_usd: float | None = None

    @classmethod
    def from_environ(cls, environ: dict[str, str] | None = None) -> "ClaudePocLimits":
        env = dict(os.environ if environ is None else environ)

        def _int(name: str, default: int, low: int, high: int) -> int:
            raw = str(env.get(name) or "").strip()
            if not raw:
                return default
            try:
                value = int(raw)
            except ValueError as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if not low <= value <= high:
                raise ValueError(f"{name} must be between {low} and {high}")
            return value

        def _float(name: str) -> float | None:
            raw = str(env.get(name) or "").strip()
            if not raw:
                return None
            try:
                value = float(raw)
            except ValueError as exc:
                raise ValueError(f"{name} must be a number") from exc
            return value if value > 0 else None

        return cls(
            model=str(env.get("POC_CLAUDE_MODEL") or "").strip(),
            gateway_url=str(env.get("POC_CLAUDE_GATEWAY_URL") or "").strip().rstrip("/"),
            workspace=str(env.get("POC_CLAUDE_WORKSPACE") or "").strip(),
            sdk_version=str(env.get("POC_CLAUDE_SDK_VERSION") or "").strip(),
            cli_version=str(env.get("POC_CLAUDE_CLI_VERSION") or "").strip(),
            capability_token=str(env.get("POC_CLAUDE_CAPABILITY_TOKEN") or "").strip(),
            execute_turns=_int("POC_CLAUDE_EXECUTE_TURNS", 24, 2, 200),
            conclude_turns=_int("POC_CLAUDE_CONCLUDE_TURNS", 4, 1, 20),
            execute_requests=_int("POC_CLAUDE_EXECUTE_REQUESTS", DEFAULT_EXECUTE_REQUESTS, 1, 512),
            conclude_requests=_int("POC_CLAUDE_CONCLUDE_REQUESTS", RESERVED_CONCLUDE_REQUESTS, 3, 16),
            max_seconds=_int("POC_CLAUDE_MAX_SECONDS", 300, 30, 3600),
            execute_usd=_float("POC_CLAUDE_EXECUTE_USD"),
            conclude_usd=_float("POC_CLAUDE_CONCLUDE_USD"),
        )

    def snapshot(self) -> dict:
        """Public, credential-free deployment facts frozen with a run."""
        return {
            "runtime": RUNTIME_NAME, "model": self.model,
            "gateway": _public_url(self.gateway_url), "workspace": bool(self.workspace),
            "sdk_version": self.sdk_version, "cli_version": self.cli_version,
            "execute_turns": self.execute_turns, "conclude_turns": self.conclude_turns,
            "execute_requests": self.execute_requests,
            "conclude_requests": self.conclude_requests,
            "max_seconds": self.max_seconds,
            "execute_usd": self.execute_usd, "conclude_usd": self.conclude_usd,
            "capability": bool(self.capability_token),
        }


def _public_url(value: str) -> str:
    try:
        parts = urlsplit(str(value or ""))
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        authority = host + (f":{parts.port}" if parts.port is not None else "")
        return urlunsplit((parts.scheme, authority, parts.path, "", ""))
    except ValueError:
        return ""


def _sdk_version() -> str:
    try:
        return importlib.metadata.version("claude-agent-sdk")
    except importlib.metadata.PackageNotFoundError:
        return ""


class ClaudeCodePocRuntime:
    """The one adapter that may drive the experiment and conclusion stages.

    The SDK is imported lazily.  ``sdk`` and ``cli_probe`` are injectable so the host's
    guarantees (stage separation, quota refusal, evidence ids, no fallback) can be tested
    without the binary, a model, or network access.
    """

    runtime_name = RUNTIME_NAME

    def __init__(
        self,
        *,
        limits: ClaudePocLimits,
        gateway: PocRequestGateway,
        sdk: Any | None = None,
        cli_probe: Callable[[], tuple[str, str]] | None = None,
    ) -> None:
        self.limits = limits
        self.gateway = gateway
        self._sdk = sdk
        self._cli_probe = cli_probe
        # Readiness resolves and probes the executable that _options passes back to
        # the SDK.  Otherwise the SDK may use its bundled CLI after we checked an
        # unrelated system installation.
        self._resolved_cli_path = ""
        self._service: PocToolService | None = None
        self._emit_cb: Callable[[dict], None] = lambda _event: None
        self._should_stop: Callable[[], bool] | None = None
        self._stage = "prepared"
        self._run_id = ""
        self._epoch = 0
        self._execute_reason = ""
        self._readiness: PocRuntimeReadiness | None = None
        self._usage: dict[str, Any] = {"input_tokens": None, "output_tokens": None,
                                       "cache_read_tokens": None, "cache_write_tokens": None,
                                       "cost_usd": None, "turns": None}

    # -- readiness ---------------------------------------------------------------

    def readiness(self) -> PocRuntimeReadiness:
        sdk = self._load_sdk()
        if sdk is None:
            return PocRuntimeReadiness(
                ready=False, reason="sdk_missing", model=self.limits.model,
                gateway=_public_url(self.limits.gateway_url),
                capability=bool(self.limits.capability_token),
                message="claude-agent-sdk 未安装或无法导入；本 attempt 不会回退到旧模型循环。",
            )
        version = _sdk_version()
        if self.limits.sdk_version and version != self.limits.sdk_version:
            return PocRuntimeReadiness(False, "sdk_version_mismatch", f"SDK 版本 {version or 'unknown'} 与冻结值不符",
                                       sdk_version=version, model=self.limits.model,
                                       gateway=_public_url(self.limits.gateway_url),
                                       capability=bool(self.limits.capability_token))
        if not self.limits.model:
            return PocRuntimeReadiness(False, "model_unconfigured", "POC_CLAUDE_MODEL 未配置",
                                       sdk_version=version)
        if not self.limits.gateway_url.startswith(("http://", "https://")):
            return PocRuntimeReadiness(False, "gateway_unconfigured",
                                       "必须配置受控 Anthropic 协议网关（POC_CLAUDE_GATEWAY_URL）",
                                       sdk_version=version, model=self.limits.model)
        if not self.limits.workspace:
            return PocRuntimeReadiness(False, "workspace_unconfigured",
                                       "必须指定隔离的空工作目录（POC_CLAUDE_WORKSPACE）",
                                       sdk_version=version, model=self.limits.model,
                                       gateway=_public_url(self.limits.gateway_url))
        workspace = Path(self.limits.workspace).resolve()
        if not workspace.is_dir():
            return PocRuntimeReadiness(False, "workspace_missing", "隔离工作目录不存在",
                                       sdk_version=version, model=self.limits.model,
                                       gateway=_public_url(self.limits.gateway_url),
                                       workspace=str(workspace))
        if (workspace / ".git").exists() or str(workspace) == str(Path.cwd().resolve()):
            return PocRuntimeReadiness(False, "workspace_not_isolated",
                                       "SDK 不能在项目根目录启动；请使用空任务目录",
                                       sdk_version=version, model=self.limits.model,
                                       gateway=_public_url(self.limits.gateway_url),
                                       workspace=str(workspace))
        if self._cli_probe is not None:
            cli_version, cli_error = self._cli_probe()
        else:
            self._resolved_cli_path = self._resolve_cli_path(sdk)
            cli_version, cli_error = self._probe_cli(self._resolved_cli_path)
        if cli_error:
            return PocRuntimeReadiness(False, cli_error, "Claude Code CLI 不可用：" + cli_error,
                                       sdk_version=version, model=self.limits.model,
                                       gateway=_public_url(self.limits.gateway_url),
                                       workspace=str(workspace))
        if self.limits.cli_version and cli_version != self.limits.cli_version:
            return PocRuntimeReadiness(False, "cli_version_mismatch",
                                       f"CLI 版本 {cli_version} 与冻结值 {self.limits.cli_version} 不符",
                                       sdk_version=version, cli_version=cli_version,
                                       model=self.limits.model,
                                       gateway=_public_url(self.limits.gateway_url),
                                       workspace=str(workspace))
        cli_parts = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+][\w.-]+)?", cli_version)
        if not cli_parts or tuple(map(int, cli_parts.groups())) < (2, 1, 248):
            return PocRuntimeReadiness(
                False, "cli_verbatim_unsupported", "CLI 需至少 2.1.248，才能禁止提示中的文件展开与命令分派",
                sdk_version=version, cli_version=cli_version, model=self.limits.model,
                gateway=_public_url(self.limits.gateway_url), workspace=str(workspace),
            )
        check_gateway = getattr(self.gateway, "check_readiness", None)
        if check_gateway is not None:
            try:
                gateway_state = check_gateway()
            except Exception:  # noqa: BLE001 - readiness never exposes deployment secrets
                gateway_state = {"ready": False, "reason": "gateway_unavailable",
                                 "message": "受控网关配置不可用"}
            if not gateway_state.get("ready"):
                return PocRuntimeReadiness(
                    False, str(gateway_state.get("reason") or "gateway_unavailable"),
                    str(gateway_state.get("message") or "受控网关尚未就绪"),
                    sdk_version=version, cli_version=cli_version,
                    model=self.limits.model, gateway=_public_url(self.limits.gateway_url),
                    workspace=str(workspace), capability=bool(self.limits.capability_token),
                )
        return PocRuntimeReadiness(True, "ready", "SDK、CLI、模型、网关与隔离目录均已就绪",
                                   sdk_version=version, cli_version=cli_version,
                                   model=self.limits.model,
                                   gateway=_public_url(self.limits.gateway_url),
                                   workspace=str(workspace),
                                   capability=bool(self.limits.capability_token) or callable(
                                       getattr(self.gateway, "issue_capability", None)))

    def _load_sdk(self) -> Any | None:
        if self._sdk is not None:
            return self._sdk
        try:
            import claude_agent_sdk  # type: ignore[import-not-found]
        except Exception:  # noqa: BLE001 - readiness reports the absence, it does not raise
            return None
        self._sdk = claude_agent_sdk
        return self._sdk

    @staticmethod
    def _resolve_cli_path(sdk: Any) -> str:
        """Prefer the wheel's CLI, then explicitly pin a discovered system CLI.

        This follows the SDK's bundled-first policy without constructing a
        transport or starting an agent.  Passing the result as ``cli_path`` makes
        the checked executable and the executed executable identical.
        """
        package_file = getattr(sdk, "__file__", None)
        if package_file:
            name = "claude.exe" if os.name == "nt" else "claude"
            bundled = Path(package_file).resolve().parent / "_bundled" / name
            if bundled.is_file():
                return str(bundled)
        return shutil.which("claude") or ""

    @staticmethod
    def _probe_cli(binary: str = "claude") -> tuple[str, str]:
        if not binary:
            return "", "cli_missing"
        path = shutil.which(binary)
        if not path:
            return "", "cli_missing"
        try:
            completed = subprocess.run(
                [path, "--version"], capture_output=True, text=True, timeout=10,
                env={key: value for key, value in os.environ.items()
                     if key in {"PATH", "HOME", "LANG", "LC_ALL"}},
            )
        except (OSError, subprocess.SubprocessError):
            return "", "cli_unavailable"
        if completed.returncode != 0:
            return "", "cli_unavailable"
        output = completed.stdout.strip().splitlines()[0] if completed.stdout.strip() else ""
        version = re.search(r"(?<![\w.])\d+\.\d+\.\d+(?:[-+][\w.-]+)?", output)
        if version is None:
            return "", "cli_version_unknown"
        return version.group(0), ""

    # -- events ------------------------------------------------------------------

    def _emit(self, kind: str, **fields) -> None:
        payload = {"kind": kind, "runtime": RUNTIME_NAME, "finding_id":
                   (self._service.finding.get("id") if self._service is not None else None)}
        payload.update(fields)
        self._emit_cb(payload)

    # -- gateway -----------------------------------------------------------------

    def reserve_upstream_request(self, stage: str) -> int:
        """Called by the controlled gateway for each real request; refusal is final."""
        result = self.gateway.reserve(run_id=self._run_id, epoch=self._epoch, stage=stage)
        if not result.get("granted"):
            raise PocQuotaRefusal(str(result.get("reason") or "quota_exhausted"), result)
        return int(result.get("used") or 0)

    def _open_stages(self) -> dict | None:
        opened = self.gateway.open_stage(
            run_id=self._run_id, epoch=self._epoch, stage=CONCLUDE_STAGE,
            limit=self.limits.conclude_requests,
        )
        if not opened.get("ok"):
            self._emit("poc_runtime_stage_unavailable", stage=CONCLUDE_STAGE,
                       reason=opened.get("reason"))
            return None
        opened = self.gateway.open_stage(
            run_id=self._run_id, epoch=self._epoch, stage=EXECUTE_STAGE,
            limit=self.limits.execute_requests,
        )
        if not opened.get("ok"):
            self._emit("poc_runtime_stage_unavailable", stage=EXECUTE_STAGE,
                       reason=opened.get("reason"))
            return None
        return self.gateway.snapshot(run_id=self._run_id, epoch=self._epoch)

    # -- tools -------------------------------------------------------------------

    async def call_tool(self, name: str, args: dict) -> Any:
        """The MCP handler body; the SDK registration is only a transport.

        The experiment tools do not exist in the conclusion stage: a call that arrives
        there is refused and recorded, never executed.  Every handler still goes through
        ``PocToolService.call``, so the runner contract and job facts have one owner.
        """
        if self._stage != EXECUTE_STAGE or self._service is None:
            self._emit("poc_runtime_tool_withdrawn", tool=str(name)[:64],
                       stage=self._stage, reason="tools_withdrawn")
            return json.dumps({"ok": False, "error": "tools_withdrawn",
                               "message": "结论阶段不开放实验工具。"}, ensure_ascii=False)
        return await self._service.call(name, dict(args or {}))

    def _build_mcp_server(self) -> Any:
        sdk = self._sdk
        builder = getattr(sdk, "create_sdk_mcp_server", None)
        tool_factory = getattr(sdk, "tool", None)
        if builder is None or tool_factory is None:
            raise PocRuntimeUnavailable("mcp_builder_missing")

        tools = []
        for spec in POC_TOOLS:
            async def handler(args, _name=spec.name):
                text = await self.call_tool(_name, args)
                return {"content": [{"type": "text", "text": text}]}
            tools.append(tool_factory(spec.name, spec.description, _tool_schema(spec))(handler))
        return builder(name="poc", version="1.0.0", tools=tools)

    def _options(self, stage: str, server: Any | None, system_prompt: str) -> dict:
        kwargs: dict[str, Any] = {
            "model": self.limits.model,
            # Each stage's rules are an explicit system prompt; the SDK never falls back
            # to Claude Code's own default prompt for this role.
            "system_prompt": system_prompt,
            "cwd": self.limits.workspace,
            "tools": [],
            # Finding and runner text are data, even when they contain @/path or
            # /commands. Never let the CLI expand them into host file access.
            "verbatim_prompts": True,
            "strict_mcp_config": True,
            "mcp_servers": {"poc": server} if stage == EXECUTE_STAGE and server is not None else {},
            "allowed_tools": [f"mcp__poc__{name}" for name in TOOL_NAMES] if stage == EXECUTE_STAGE else [],
            "permission_mode": "dontAsk",
            "setting_sources": [],
            "extra_args": {"no-session-persistence": None},
            "max_turns": self.limits.execute_turns if stage == EXECUTE_STAGE else self.limits.conclude_turns,
            "env": self._environment(stage),
            "cli_path": str(Path(__file__).with_name("claude_cli.py")),
        }
        budget = self.limits.execute_usd if stage == EXECUTE_STAGE else self.limits.conclude_usd
        if budget is not None:
            kwargs["max_budget_usd"] = budget
        if stage == CONCLUDE_STAGE:
            kwargs["output_format"] = {"type": "json_schema", "schema": CONCLUSION_SCHEMA}
        factory = getattr(self._sdk, "ClaudeAgentOptions", None)
        if factory is None:
            raise PocRuntimeUnavailable("sdk_options_missing")
        return factory(**kwargs)

    def _environment(self, stage: str | None = None) -> dict[str, str]:
        env = {
            # Every request goes through the host's controlled gateway, and the SDK is
            # not given the real upstream credential: only a short-lived capability.
            "ANTHROPIC_BASE_URL": self.limits.gateway_url,
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_AUTOUPDATER": "1",
            # Keep SDK state inside the task's isolated directory, and keep auto memory
            # off: neither may outlive the attempt.  ``setting_sources=[]`` does not
            # replace a config directory, so the path is explicit as well.
            "CLAUDE_CONFIG_DIR": str(Path(self.limits.workspace) / ".claude"),
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
            "CLAUDE_CODE_SKIP_PROMPT_HISTORY": "1",
            "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
            "AUDIT_POC_CLAUDE_REAL_CLI": self._resolved_cli_path,
        }
        issuer = getattr(self.gateway, "issue_capability", None)
        token = self.limits.capability_token
        if issuer is not None and stage is not None and self._service is not None:
            self._revoke_stage_capability(stage)
            seconds = max(.1, getattr(self, "_attempt_deadline", time.monotonic() + self.limits.max_seconds) - time.monotonic())
            token = issuer(run_id=self._run_id, epoch=self._epoch, stage=stage, model=self.limits.model,
                           context_id=self._service.context_id, finding_id=str(self._service.finding.get("id") or ""),
                           ttl_seconds=seconds)
            self._stage_tokens[stage] = token
        if token:
            env["ANTHROPIC_AUTH_TOKEN"] = token
        return env

    def _revoke_stage_capability(self, stage: str) -> None:
        tokens = getattr(self, "_stage_tokens", {})
        token = tokens.pop(stage, None)
        revoker = getattr(self.gateway, "revoke_capability", None)
        if token and revoker is not None:
            revoker(token)

    # -- staged execution --------------------------------------------------------

    async def verify(
        self,
        *,
        service: PocToolService,
        emit: Callable[[dict], None],
        run_id: str,
        epoch: int,
    ) -> PocRuntimeOutcome:
        """Run both fixed stages for one prepared finding.  Never falls back."""
        self._service = service
        self._emit_cb = emit
        self._should_stop = service.should_stop
        self._run_id = str(run_id)
        self._epoch = int(epoch or 0)
        self._stage_tokens: dict[str, str] = {}
        # The service's tool trace needs an event owner in both runtimes; here the
        # adapter supplies a stage-aware one instead of the legacy loop's Execution.
        admit_tool = getattr(self.gateway, "admit_tool", None)
        execution = _StageToolExecution(
            emit, (lambda: admit_tool(run_id=self._run_id, epoch=self._epoch)) if admit_tool else None,
        )
        service.execution = execution
        service.phase = EXECUTE_STAGE
        started = time.monotonic()
        self._attempt_deadline = started + self.limits.max_seconds
        readiness = self.readiness()
        self._readiness = readiness
        self._emit("poc_runtime_readiness", **readiness.snapshot())
        if not readiness.ready:
            self._emit("poc_runtime_unavailable", reason=readiness.reason,
                       message=readiness.message)
            return PocRuntimeOutcome("unavailable", None, "runtime_unavailable",
                                     {"runtime": self.limits.snapshot(), "readiness": readiness.snapshot()})
        stages = self._open_stages()
        if stages is None:
            return PocRuntimeOutcome("unavailable", None, "quota_unavailable",
                                     {"runtime": self.limits.snapshot()})
        self._emit("poc_runtime_quota_opened", stages=stages)
        # The conclusion's requests must exist before any experiment runs; with none
        # left there is nothing to conclude from, so the attempt is deferred instead of
        # producing side effects that cannot be reported.
        if (int((stages.get(CONCLUDE_STAGE) or {}).get("remaining") or 0) < 1
                or int((stages.get(EXECUTE_STAGE) or {}).get("remaining") or 0) < 1):
            self._emit("poc_runtime_deferred", reason="quota_insufficient", stages=stages)
            return PocRuntimeOutcome("deferred", None, "quota_deferred",
                                     self._usage_snapshot(stages))

        execute_reason = "completed"
        self._stage = EXECUTE_STAGE
        service.phase = EXECUTE_STAGE
        execution.phase = EXECUTE_STAGE
        try:
            server = self._build_mcp_server()
            await self._run_stage(
                stage=EXECUTE_STAGE, server=server,
                prompt=self._execute_prompt(service),
                system_prompt=execute_instructions(service),
                deadline=started + self.limits.max_seconds * 0.75,
            )
        except PocQuotaRefusal as exc:
            execute_reason = "quota_exhausted"
            self._emit("poc_runtime_quota_refused", stage=EXECUTE_STAGE,
                       reason=exc.reason, reservation=exc.reservation)
        except PocRuntimeUnavailable as exc:
            self._emit("poc_runtime_unavailable", reason=str(exc), stage=EXECUTE_STAGE)
            return PocRuntimeOutcome("unavailable", None, "runtime_unavailable",
                                     self._usage_snapshot(stages))
        except StopAudit as exc:
            execute_reason = str(exc.reason or "interrupted")
            self._execute_reason = execute_reason
            self._emit("poc_runtime_stage_stopped", stage=EXECUTE_STAGE, reason=execute_reason,
                       message=str(exc)[:300])
            # Local execution-stage turn/time limits may leave a reserved conclusion
            # available. Run, workflow and cancellation refusals end the attempt;
            # opening a new SDK stage must never bypass their boundary.
            if execute_reason not in {"budget", "turn_limit"}:
                status = "cancelled" if execute_reason in {"interrupted", "cancelled"} else "failed"
                return PocRuntimeOutcome(status, None, execute_reason, self._usage_snapshot(stages))
        except asyncio.CancelledError:
            self._emit("poc_runtime_cancelled", stage=EXECUTE_STAGE)
            raise
        except Exception as exc:  # noqa: BLE001 - an SDK crash is an attempt outcome
            execute_reason = "sdk_error"
            self._emit("poc_runtime_stage_failed", stage=EXECUTE_STAGE,
                       error=type(exc).__name__, message="SDK 阶段执行失败，原始异常正文未保存。")
        if self._stopped():
            self._emit("poc_runtime_cancelled", stage=EXECUTE_STAGE, reason="interrupted")
            return PocRuntimeOutcome("cancelled", None, "interrupted", self._usage_snapshot(stages))
        if execute_reason == "sdk_error":
            return PocRuntimeOutcome("failed", None, "sdk_error", self._usage_snapshot(stages))
        self._emit("poc_runtime_stage_finished", stage=EXECUTE_STAGE, reason=execute_reason,
                   jobs=len(service.jobs), elapsed_seconds=round(time.monotonic() - started, 3))
        if time.monotonic() >= started + self.limits.max_seconds:
            self._emit("poc_runtime_stage_stopped", stage=CONCLUDE_STAGE, reason="budget",
                       message="实验阶段用尽本次验证预算，结论阶段未启动")
            return PocRuntimeOutcome("failed", None, "budget", self._usage_snapshot(stages))

        # The experiment's outcome never decides the conclusion's availability: its
        # requests were reserved before the experiment started.
        self._execute_reason = execute_reason
        self._stage = CONCLUDE_STAGE
        service.phase = CONCLUDE_STAGE
        execution.phase = CONCLUDE_STAGE
        refs = EvidenceRefTable.build(service)
        try:
            result, reason = await self._conclude(service, refs, started)
        except PocQuotaRefusal as exc:
            self._emit("poc_runtime_quota_refused", stage=CONCLUDE_STAGE,
                       reason=exc.reason, reservation=exc.reservation)
            return PocRuntimeOutcome("quota_exhausted", None, "quota_exhausted",
                                     self._usage_snapshot(stages))
        except asyncio.CancelledError:
            self._emit("poc_runtime_cancelled", stage=CONCLUDE_STAGE)
            raise
        except PocRuntimeUnavailable as exc:
            self._emit("poc_runtime_unavailable", reason=str(exc), stage=CONCLUDE_STAGE)
            return PocRuntimeOutcome("unavailable", None, "runtime_unavailable",
                                     self._usage_snapshot(stages))
        except Exception as exc:  # noqa: BLE001
            self._emit("poc_runtime_stage_failed", stage=CONCLUDE_STAGE,
                       error=type(exc).__name__, message="SDK 阶段执行失败，原始异常正文未保存。")
            return PocRuntimeOutcome("failed", None, "conclusion_failed",
                                     self._usage_snapshot(stages))
        status = "completed" if result is not None else "conclusion_rejected"
        if reason.startswith("stopped:"):
            status = "cancelled" if self._stopped() or reason == "stopped:interrupted" else "failed"
        elif reason == "interrupted":
            status = "cancelled"
        self._emit("poc_runtime_conclusion", status=result.status if result else None,
                   verdict=result.verdict if result else None, reason=reason,
                   jobs=len(service.jobs), evidence_refs=len(refs),
                   elapsed_seconds=round(time.monotonic() - started, 3))
        self._emit("poc_runtime_stage_finished", stage=CONCLUDE_STAGE, reason=reason,
                   jobs=len(service.jobs))
        return PocRuntimeOutcome(status, result, reason, self._usage_snapshot(stages))

    def _stopped(self) -> bool:
        return bool(self._should_stop is not None and self._should_stop())

    def _raise_if_quota_refused(self, stage: str) -> None:
        """Translate the gateway's durable refusal, never SDK response text.

        A real HTTP gateway cannot raise a Python exception inside the SDK process.
        The durable stage ledger is the trusted signal that lets the experiment stop
        while keeping the separately reserved conclusion available.
        """
        stage_refusal = getattr(self.gateway, "stage_refusal", None)
        if stage_refusal is not None:
            refusal = stage_refusal(run_id=self._run_id, epoch=self._epoch, stage=stage)
            if refusal:
                reason = str(refusal.get("reason") or "gateway_refused")
                if reason in {"quota_exhausted", "quota_refused"}:
                    raise PocQuotaRefusal(reason, refusal)
                if reason == "stale_epoch":
                    reason = "interrupted"
                if reason in {"run_budget_exhausted", "stage_budget_exhausted", "batch_deadline_exceeded",
                              "timeout", "interrupted", "cancelled"}:
                    raise StopAudit(reason, "受控网关已停止本阶段的上游请求")
                raise PocRuntimeUnavailable("gateway_refused")
        snapshot = self.gateway.snapshot(run_id=self._run_id, epoch=self._epoch)
        state = snapshot.get(stage) or {}
        if state.get("refused"):
            raise PocQuotaRefusal(str(state.get("reason") or "quota_exhausted"), state)

    async def _run_stage(self, *, stage: str, server: Any | None, prompt: str,
                         system_prompt: str, deadline: float) -> dict:
        try:
            return await self._run_stage_inner(
                stage=stage, server=server, prompt=prompt,
                system_prompt=system_prompt, deadline=deadline,
            )
        finally:
            revoke = getattr(self, "_revoke_stage_capability", None)
            if revoke is not None:
                revoke(stage)

    async def _run_stage_inner(self, *, stage: str, server: Any | None, prompt: str,
                               system_prompt: str, deadline: float) -> dict:
        remaining = deadline - time.monotonic()
        if self._stopped():
            raise StopAudit("interrupted", "POC 所属执行代次已停止")
        if remaining <= 0:
            raise StopAudit("budget", "阶段剩余时间不足")
        self._raise_if_quota_refused(stage)
        options = self._options(stage, server, system_prompt)
        started = time.monotonic()
        self._emit("poc_runtime_stage", stage=stage, status="started",
                   turns_limit=options.get("max_turns") if isinstance(options, dict)
                   else getattr(options, "max_turns", None))
        query = getattr(self._sdk, "query", None)
        if query is None:
            raise PocRuntimeUnavailable("sdk_query_missing")
        summary: dict[str, Any] = {"stage": stage, "messages": 0, "result": None, "error": ""}

        async def consume() -> None:
            # Keep iteration and aclose in one task: SDK transports may own AnyIO
            # scopes whose cleanup must run in the task that opened them.
            stream = query(prompt=prompt, options=options)
            try:
                async for message in stream:
                    if self._stopped():
                        raise StopAudit("interrupted", "POC 所属执行代次已停止")
                    summary["messages"] += 1
                    if _is_result_message(message):
                        summary["result"] = message
                    elif _is_error_message(message):
                        summary["error"] = type(message).__name__
            except Exception as exc:
                # The official SDK yields its terminal error ResultMessage and
                # then raises ResultError for the CLI's nonzero exit. Classify
                # that same result below so ordinary stage limits can use their
                # reserved conclusion. A transport error after a successful frame
                # or an exception without a matching final result still fails closed.
                final = summary.get("result")
                result_error = getattr(self._sdk, "ResultError", None)
                matches = (
                    isinstance(result_error, type) and isinstance(exc, result_error)
                    and final is not None and bool(getattr(final, "is_error", False))
                    and getattr(exc, "subtype", None) == getattr(final, "subtype", None)
                    and getattr(exc, "terminal_reason", None) == getattr(final, "terminal_reason", None)
                )
                if not matches:
                    raise
            finally:
                aclose = getattr(stream, "aclose", None)
                if aclose is not None:
                    await aclose()

        reader = asyncio.create_task(consume())
        try:
            while not reader.done():
                if self._stopped():
                    raise StopAudit("interrupted", "POC 所属执行代次已停止")
                self._raise_if_quota_refused(stage)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StopAudit("budget", "阶段剩余时间不足")
                # Check cancellation even when the SDK is waiting on its first byte,
                # a tool call or retry backoff and yields no public messages.
                await asyncio.wait({reader}, timeout=min(0.1, remaining))
            await reader
            self._raise_if_quota_refused(stage)
        except BaseException as exc:
            if not reader.done():
                reader.cancel()
            # A broken transport must not hold a target lease forever. Cleanup
            # still belongs to the reader task; do not aclose its AnyIO scope here.
            done, _ = await asyncio.wait({reader}, timeout=2)
            if not done:
                self._stage = "closed"
                reader.add_done_callback(lambda task: None if task.cancelled() else task.exception())
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise PocRuntimeUnavailable("sdk_cleanup_timeout") from None
            try:
                await reader
            except BaseException:
                pass
            # An HTTP quota error may surface as an SDK exception or an error result;
            # only the ledger is allowed to reclassify it as an exhausted stage.
            if isinstance(exc, Exception) and not self._stopped():
                self._raise_if_quota_refused(stage)
            raise
        final = summary.get("result")
        turns = _known(getattr(final, "num_turns", None))
        subtype = str(getattr(final, "subtype", "") or "")
        terminal_reason = str(getattr(final, "terminal_reason", "") or "")
        stop_reason = str(getattr(final, "stop_reason", "") or "")
        is_error = bool(getattr(final, "is_error", False))
        usage = _usage_from_result(final)
        self._merge_usage(usage)
        self._emit("poc_runtime_usage", stage=stage, usage=usage,
                   cost_usd=usage.get("cost_usd"), provider_model=self.limits.model,
                   sdk_version=_sdk_version(), elapsed_seconds=round(time.monotonic() - started, 3),
                   turns=turns, subtype=subtype, is_error=is_error,
                   terminal_reason=terminal_reason[:64], stop_reason=stop_reason[:64],
                   messages=summary.get("messages"), result_missing=final is None)
        if final is None:
            raise PocRuntimeUnavailable("missing_result_message")
        if terminal_reason in {"aborted_streaming", "aborted_tools"}:
            raise StopAudit("interrupted", "SDK 阶段已取消")
        if terminal_reason == "max_turns":
            raise StopAudit("turn_limit", "SDK 阶段达到轮次上限")
        if is_error:
            if subtype == "error_max_turns":
                raise StopAudit("turn_limit", "SDK 阶段达到轮次上限")
            if subtype == "error_max_budget_usd":
                raise StopAudit("budget", "SDK 阶段达到费用上限")
            raise StopAudit("sdk_error", f"SDK 报告错误（{subtype or 'error'}）")
        summary["subtype"] = subtype
        return summary

    # -- conclusion --------------------------------------------------------------

    def _execute_prompt(self, service: PocToolService) -> str:
        return (
            "# 待验证的源码结论\n"
            + _finding_block(service.finding)
            + "\n# 靶场（宿主已准备）\n"
            + _context_json(service.prepared, 4 * 1024)
            + "\n# 限额\n"
            + json.dumps({
                "language": ["php", "python"],
                "max_script_bytes": service.max_script_bytes,
                "max_jobs": service.max_jobs,
                "job_timeout_seconds": service.job_seconds,
            }, ensure_ascii=False)
            + "\n调用 resolve_target 取得源码路径到 HTTP 路径的映射。"
        )

    def _conclusion_prompt(self, service: PocToolService, refs: EvidenceRefTable) -> str:
        return (
            "# 待验证的源码结论\n"
            + _finding_block(service.finding)
            + "\n# 执行阶段实际发生的作业（宿主记录）\n"
            + json.dumps(refs.displayed, ensure_ascii=False, separators=(",", ":"))
            + "\n# 可用证据引用（宿主编号；只能引用这里出现的 evidence_ref_id）\n"
            + json.dumps(refs.public(), ensure_ascii=False, separators=(",", ":"))
            + "\n# 实验前提与状态变化\n"
            + _context_json({
                "preconditions": service.preconditions,
                "state_changes": service.state_changes,
                "preconditions_omitted": service.preconditions_omitted,
            }, 4 * 1024)
            + "\n# 产物\n"
            + json.dumps({"names": sorted(service.artifacts),
                          "omitted": service.artifacts_omitted}, ensure_ascii=False)
            + "\n现在提交 JSON：normal_refs/attack_refs 填 evidence_ref_id；"
            "jobs 只能填上面出现过的 job_id；不要复制正文，宿主会用 id 还原原文。"
        )

    async def _conclude(self, service: PocToolService, refs: EvidenceRefTable,
                        started: float) -> tuple[PocVerificationResult | None, str]:
        prompt = self._conclusion_prompt(service, refs)
        deadline = started + self.limits.max_seconds
        diagnostics = ""
        format_retries = 0
        semantic_retries = 0
        attempt = 0
        while attempt < self.limits.conclude_requests:
            attempt += 1
            if self._stopped():
                return None, "interrupted"
            text = prompt
            if diagnostics:
                text = prompt + "\n# 宿主上一次拒绝的原因（只修正 JSON，不要重新实验）\n" + diagnostics
            try:
                stage = await self._run_stage(
                    stage=CONCLUDE_STAGE, server=None, prompt=text,
                    system_prompt=CONCLUDE_CONTRACT, deadline=deadline,
                )
            except StopAudit as exc:
                return None, f"stopped:{exc.reason}"
            payload = _structured_output(stage.get("result"))
            # ``subtype=success`` alone is not proof of an answer: a run that hit the
            # turn ceiling or was refused is a format failure, not a conclusion.
            if payload is None or stage.get("subtype") != "success":
                format_retries += 1
                diagnostics = "没有可读取的 structured_output；请按给定 JSON Schema 重新提交。"
                self._emit("poc_runtime_conclusion_rejected", attempt=attempt,
                           reason="missing_structured_output")
                if format_retries > 1:
                    break
                continue
            result, errors = self._build_result(payload, refs)
            if errors:
                format_retries += 1
                diagnostics = "；".join(errors)[:2000]
                self._emit("poc_runtime_conclusion_rejected", attempt=attempt,
                           reason="evidence_ref_rejected", errors=errors)
                if format_retries > 1:
                    break
                continue
            assert result is not None
            proposed = (result.status, result.verdict)
            checked = host_check(result, service)
            if (checked.status, checked.verdict) == proposed:
                return checked, "completed"
            # ``host_check`` downgraded a deterministic claim: give exactly one bounded
            # semantic correction, counted as a real request by the gateway.
            semantic_retries += 1
            diagnostics = checked.evidence_notes[:2000]
            self._emit("poc_runtime_conclusion_rejected", attempt=attempt,
                       reason="host_check_rejected", status=result.status)
            if semantic_retries > 1:
                break
        # Exhausted the reserved requests without an acceptable conclusion.  Existing
        # jobs are preserved; nothing deterministic is published.
        return None, "conclusion_rejected"

    def _build_result(self, payload: dict, refs: EvidenceRefTable
                      ) -> tuple[PocVerificationResult | None, list[str]]:
        errors: list[str] = []
        status = str(payload.get("status") or "").strip()
        if status not in {"verified", "rejected", "inconclusive"}:
            errors.append(f"status 无效：{status or 'empty'}")
        jobs: list[str] = []
        for value in payload.get("jobs") or ():
            job_id = str(value or "").strip()
            if not job_id:
                continue
            if job_id not in {str(job.get("job_id") or "") for job in (self._service.jobs if self._service else [])}:
                errors.append(f"未知作业引用：{job_id}")
                continue
            jobs.append(job_id)
        def resolve(name: str) -> list[PocEvidenceReference]:
            resolved: list[PocEvidenceReference] = []
            for value in payload.get(name) or ():
                ref = refs.resolve(str(value or ""))
                if ref is None:
                    errors.append(f"不可引用的 evidence_ref_id：{value}")
                    continue
                resolved.append(PocEvidenceReference(job_id=ref.job_id, channel=ref.channel,
                                                     excerpt=ref.text))
            return resolved

        normal = resolve("normal_refs")
        attack = resolve("attack_refs")
        if payload.get("normal_refs") and not normal:
            errors.append("normal_refs 全部不可解析")
        if payload.get("attack_refs") and not attack:
            errors.append("attack_refs 全部不可解析")
        if errors:
            return None, errors
        try:
            result = PocVerificationResult.model_validate({
                "status": status,
                "summary": str(payload.get("summary") or "")[:4000],
                "normal_observation": str(payload.get("normal_observation") or "")[:4000],
                "attack_observation": str(payload.get("attack_observation") or "")[:8000],
                "browser_execution": bool(payload.get("browser_execution")),
                "evidence_notes": str(payload.get("evidence_notes") or "")[:4000],
                "modification_notes": str(payload.get("modification_notes") or "")[:4000],
                "jobs": jobs[:16],
                "normal_evidence": [item.model_dump() for item in normal[:16]],
                "attack_evidence": [item.model_dump() for item in attack[:16]],
            })
        except Exception as exc:  # noqa: BLE001 - shape errors are a format correction
            return None, [f"结论 JSON 不符合宿主 schema：{type(exc).__name__}"]
        return result, []

    # -- usage -------------------------------------------------------------------

    def _merge_usage(self, usage: dict) -> None:
        for field_name in ("input_tokens", "output_tokens", "cache_read_tokens",
                           "cache_write_tokens", "turns"):
            value = usage.get(field_name)
            if value is None:
                continue
            current = self._usage.get(field_name)
            self._usage[field_name] = value if current is None else current + value
        cost = usage.get("cost_usd")
        if cost is not None:
            current = self._usage.get("cost_usd")
            self._usage["cost_usd"] = round(cost if current is None else current + cost, 6)

    def _usage_snapshot(self, stages: dict | None) -> dict:
        if self._run_id:
            stages = self.gateway.snapshot(run_id=self._run_id, epoch=self._epoch)
        runtime = self.limits.snapshot()
        if self._readiness is not None:
            runtime.update(sdk_version=self._readiness.sdk_version,
                           cli_version=self._readiness.cli_version,
                           capability=self._readiness.capability)
        return {
            "runtime": runtime,
            "usage": dict(self._usage),
            "requests": stages or {},
            # Why the experiment stopped, when it was not a clean finish.  A conclusion
            # may still be published from the jobs that did run; this records that the
            # experiment was cut short instead of letting it pass as complete.
            "execute_reason": self._execute_reason,
        }


def _known(value: Any) -> int | None:
    """Unknown usage stays unknown; a missing counter must never become zero."""
    return value if type(value) is int and value >= 0 else None


def _usage_from_result(message: Any) -> dict:
    raw = getattr(message, "usage", None)
    raw = raw if isinstance(raw, dict) else {}
    return {
        "input_tokens": _known(raw.get("input_tokens")),
        "output_tokens": _known(raw.get("output_tokens")),
        "cache_read_tokens": _known(raw.get("cache_read_input_tokens") or raw.get("cache_read_tokens")),
        "cache_write_tokens": _known(raw.get("cache_creation_input_tokens") or raw.get("cache_write_tokens")),
        "turns": _known(getattr(message, "num_turns", None)),
        "cost_usd": _known_float(getattr(message, "total_cost_usd", None)),
    }


def _known_float(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _is_result_message(message: Any) -> bool:
    if type(message).__name__ == "ResultMessage":
        return True
    return str(getattr(message, "type", "") or "") == "result"


def _is_error_message(message: Any) -> bool:
    return type(message).__name__ in {"ProcessError", "CLINotFoundError", "CLIConnectionError"}


def _structured_output(message: Any) -> dict | None:
    """Only the final result message's structured output may become a candidate."""
    if message is None:
        return None
    value = getattr(message, "structured_output", None)
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None
