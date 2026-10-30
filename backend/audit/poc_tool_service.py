"""Runner-facing tool service for POC verification.

This module owns exactly what one experiment must leave behind: the isolated runner
client, the durable job table, identity preconditions, artifacts and bounded tool
replies.  It deliberately does not own a model loop, a message history or a phase gate,
so a host driving these tools from a different agent loop reuses this class directly
instead of re-implementing the runner contract.

``PocDeps`` in ``poc_agent`` adds the legacy code-action loop's dispatcher on top; the
job table here remains the single source of truth for what really ran.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, quote_plus

from .poc_runner import PocRunnerClient, PocRunnerError, PocRunnerUnavailable
from .runtime import StopAudit
from .tool_errors import classify_failure, public_value

MAX_TOOL_REPLY = 16 * 1024
MAX_SCRIPT = 32 * 1024


def _clip(value: Any, per_string: int, max_items: int) -> Any:
    """Copy a tool reply with every string shortened to ``per_string`` bytes.

    UTF-8 is cut on a byte boundary and decoded with ``ignore`` so a Chinese body cannot
    produce a lone surrogate or a half-written escape once it is serialized.
    """
    if isinstance(value, str):
        raw = value.encode("utf-8")
        if len(raw) <= per_string:
            return value
        return raw[:per_string].decode("utf-8", "ignore") + "\n[宿主截断]"
    if isinstance(value, dict):
        return {
            str(key): _clip(item, per_string, max_items)
            for key, item in list(value.items())[:max_items]
        }
    if isinstance(value, (list, tuple)):
        return [_clip(item, per_string, max_items) for item in list(value)[:max_items]]
    return value


@dataclass
class PocToolService:
    """Host-side implementation of the POC runner tools.

    A service constructed without an ``execution`` is still fully usable: it emits
    nothing and records the same facts in the same places.
    """

    client: PocRunnerClient
    policy: dict
    target: str
    finding: dict
    # The host's event/usage owner.  ``Any`` keeps this module free of the legacy
    # code-action loop's Execution type; the adapter that owns one sets it.
    execution: Any = None
    prepared: dict = field(default_factory=dict)
    jobs: list[dict] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    artifacts: dict[str, bytes] = field(default_factory=dict)
    observations: list[dict] = field(default_factory=list)
    browser_available: bool = True
    runner_error: str = ""
    job_seconds: int = 30
    max_jobs: int = 8
    max_script_bytes: int = MAX_SCRIPT
    should_stop: Any = None
    on_job: Any = None
    on_job_fact: Any = None
    withdraw_on_job_limit: bool = False
    context_id: str = ""
    # The identity the host actually prepared for this context.  Tools default to it
    # instead of a hardcoded "alice": after a lab reset alice may no longer be a
    # customer, and a host that succeeded with bob must not hand the model a prompt
    # that pushes it back onto a mismatched account.
    default_identity: str = "alice"
    # Host-bound frozen snapshot view (``poc_source.PocSourceProvider``).  ``None`` on
    # historical policies, where the tool reports ``source_unavailable`` and the prompt
    # carries no preloaded window.
    source: Any = None
    preconditions: list[dict] = field(default_factory=list)
    state_changes: list[dict] = field(default_factory=list)
    job_scripts: dict[str, str] = field(default_factory=dict)
    submission_unresolved: bool = False
    # Context hygiene: this state is replayed in the conclude prompt and in every later
    # request of the phase, so an unbounded list of near-identical snapshots or artifacts
    # would eat the window that the summary compressor then has to pay to reclaim.
    max_preconditions: int = 12
    max_observations: int = 12
    max_artifact_bytes: int = 2 * 1024 * 1024
    preconditions_omitted: int = 0
    artifacts_omitted: int = 0
    _precondition_seen: set = field(default_factory=set, repr=False)
    # Counters for a host that drives the tools without an Execution (the SDK
    # adapter).  They number calls and measure elapsed time only; they are not a
    # second usage ledger.
    phase: str = "poc_execute"
    tool_calls: int = 0
    started_at: float = field(default_factory=time.monotonic)

    @property
    def last_script(self) -> str:
        return self.scripts[-1] if self.scripts else ""

    def _emit(self, payload: dict) -> None:
        """Host hook for the durable event stream.

        The service records facts whether or not anyone is watching; a host adapter that
        owns an ``Execution`` attaches it here instead of the service importing one.
        """
        execution = self.execution
        if execution is not None:
            execution.emit(payload)

    def _reply(self, payload: Any) -> str:
        """Serialize a tool reply so the model always receives valid JSON.

        The model's only view of the runner is these strings, and it is told to parse
        them with ``json.loads``.  Cutting the already-serialized text (what this used to
        do) left a half-written object, so the parse failed on the very reply that was
        meant to explain what happened.  The payload is therefore clipped field by field;
        ``host_truncated`` is a separate marker from the runner's own ``truncated``, which
        describes the script's output rather than the host's budget.
        """
        if isinstance(payload, dict):
            payload = {**payload, "ok": payload.get("ok") is not False and not bool(payload.get("error"))
                       and (payload.get("precondition") or {}).get("ok") is not False
                       and payload.get("status") != "precondition_failed"}
        text = json.dumps(payload, ensure_ascii=False, default=str)
        if len(text.encode("utf-8")) <= MAX_TOOL_REPLY:
            return text
        for per_string, max_items in ((4096, 50), (1024, 30), (256, 16)):
            clipped = _clip(payload, per_string, max_items)
            if isinstance(clipped, dict) and "host_truncated" not in clipped:
                clipped = {**clipped, "host_truncated": True}
            text = json.dumps(clipped, ensure_ascii=False, default=str)
            if len(text.encode("utf-8")) <= MAX_TOOL_REPLY:
                return text
        return json.dumps({
            "ok": False,
            "host_truncated": True,
            "error": "tool_reply_too_large",
            "message": "工具返回超出宿主限额，正文已省略；请缩小查询范围后重试。",
        }, ensure_ascii=False)

    async def call(self, name: str, args: dict) -> str:
        """Dispatch one tool call and pair it with a durable result.

        The pairing belongs to the host, not to a model loop: whichever loop drives
        these tools, a call with no matching result looks like a hung tool in the
        trace.  The service keeps its own counters when no ``Execution`` is attached.
        """
        if self.should_stop is not None and self.should_stop():
            raise StopAudit("interrupted", "POC 所属执行代次已停止")
        if name in {"target_status", "target_prepare", "run_poc", "http_observe", "browser_check"}:
            # An omitted identity means "the account the host prepared", not "alice".
            # Only a missing/empty value is filled: an invalid type still has to reach
            # the tool's own validation and be rejected.
            if args.get("identity") is None or args.get("identity") == "":
                args["identity"] = self.default_identity
        execution = self.execution
        if execution is not None:
            execution.before_tool()
            call_id = f"poc-tool-{execution.tools:04d}"
            phase = execution.phase
            turn = execution.tools
            started_elapsed_ms = round((time.monotonic() - execution.started) * 1000)
        else:
            self.tool_calls += 1
            call_id = f"poc-tool-{self.tool_calls:04d}"
            phase = self.phase
            turn = self.tool_calls
            started_elapsed_ms = round((time.monotonic() - self.started_at) * 1000)
        # Pair every call with a result even when the phase is cancelled: the durable
        # trace is read to tell a runner failure from a model mistake, and a call with no
        # result looks like a hung tool.
        span_id = f"{phase}:{call_id}"
        started = time.monotonic()
        self._emit({
            "kind": "tool_call",
            "tool": name,
            "args": public_value(args),
            "turn": turn,
            "call_id": call_id,
            "span_id": span_id,
            "phase": phase,
            "started_elapsed_ms": started_elapsed_ms,
        })
        status = "ok"
        error_type = ""
        text = ""
        detail: dict = {}
        failure: dict = {}
        try:
            handler = getattr(self, f"_{name}", None)
            if handler is None:
                status = "unknown_tool"
                text = self._reply({"error": "unknown_tool", "tool": name})
            else:
                text = await handler(args)
                detail = json.loads(text)
                if isinstance(detail, dict) and (detail.get("error") or detail.get("ok") is False):
                    status = "precondition_failed" if detail.get("precondition", {}).get("ok") is False else "invalid_arguments"
                if self.should_stop is not None and self.should_stop():
                    raise StopAudit("interrupted", "拒绝已停止 POC 的迟到工具结果")
        except asyncio.CancelledError:
            status = "cancelled"
            raise
        except StopAudit as exc:
            status = "cancelled" if exc.reason in {"cancelled", "interrupted"} else "execution_incomplete"
            failure = {"error_code": exc.reason, "error": str(exc), "hint": "保留原作业记录，查询完成状态；不要重复提交。"}
            raise
        except PocRunnerUnavailable as exc:
            status = "runner_unavailable"
            error_type = type(exc).__name__
            self.runner_error = str(exc)[:400]
            self._emit({"kind": "poc_runner_unavailable", "error": self.runner_error})
            text = self._reply({"error": "runner_unavailable", "message": self.runner_error})
            failure = {"error_code": "runner_unavailable", "error": self.runner_error, "hint": "检查隔离 runner；未确认的作业只能查询，不能重交。"}
            raise StopAudit("environment_unavailable", "POC runner 不可用，停止本次自动验证") from exc
        except PocRunnerError as exc:
            status = "runner_rejected"
            error_type = type(exc).__name__
            self._emit({"kind": "poc_runner_rejected", "error": str(exc)[:400]})
            text = self._reply({"error": "runner_rejected", "message": str(exc)[:400]})
            failure = {"error_code": "runner_rejected", "error": str(exc)[:400], "hint": "按 runner 返回原因核对上下文、身份和参数。"}
        except Exception as exc:
            # Hand the failure to the interpreter (which shows it as the step's
            # observation) but leave a paired result in the durable trace first.
            status = "error"
            error_type = type(exc).__name__
            failure = classify_failure(exc).fields()
            raise
        finally:
            result = {
                "kind": "tool_result",
                "tool": name,
                "status": status,
                "new_lines": 0,
                "chars": len(text),
                "preview": text[:1200],
                "usage": execution.snapshot() if execution is not None else {},
                "call_id": call_id,
                "span_id": span_id,
                "phase": phase,
                "duration_ms": round((time.monotonic() - started) * 1000),
            }
            if isinstance(detail, dict):
                if detail.get("error") or detail.get("ok") is False:
                    result.update(error_code=detail.get("error") or "precondition_failed",
                                  error=detail.get("message") or detail.get("precondition", {}).get("reason") or detail.get("error") or "实验前提不符",
                                  hint="核对身份和实验前提；必要时人工重置商城后重新检查。" if status == "precondition_failed" else "按工具声明修正后再调用。")
                result.update(context_id=self.context_id, identity=args.get("identity") or self.default_identity,
                              jobs_used=len(self.jobs), max_jobs=self.max_jobs,
                              jobs_remaining=max(0, self.max_jobs - len(self.jobs)))
                if name in {"run_poc", "browser_check"} and detail.get("job_id"):
                    result.update(execution_status=("timeout" if detail.get("timed_out") else "success" if detail.get("exit_code") == 0 else "failed"),
                                  exit_code=detail.get("exit_code"), timed_out=bool(detail.get("timed_out")))
                if name == "http_observe":
                    result["http_status"] = detail.get("status") if isinstance(detail.get("status"), int) else None
                    if detail.get("job_id"):
                        result.update(execution_status=detail.get("execution_status") or ("failed" if detail.get("error") else "success"),
                                      exit_code=detail.get("exit_code"), timed_out=bool(detail.get("timed_out")))
            if error_type:
                result["error_type"] = error_type
            result.update(failure)
            result = public_value(result)
            self._emit(result)
        if (self.withdraw_on_job_limit and isinstance(detail, dict)
                and (detail.get("precondition") or {}).get("ok") is False
                and (detail.get("precondition") or {}).get("reason") == "required_account_state_mismatch"):
            raise StopAudit("precondition_failed", "必要账号状态前提不符，停止新实验并如实提交已有证据与局限。")
        if (self.withdraw_on_job_limit and name in {"run_poc", "http_observe", "browser_check"}
                and len(self.jobs) >= self.max_jobs):
            raise StopAudit("job_limit", "本条发现的作业额度已用尽，工具收回并进入结论阶段。")
        return text

    # --- tools -----------------------------------------------------------------

    async def _url_encode(self, args: dict) -> str:
        value, form = args.get("value"), args.get("form", False)
        if not isinstance(value, str) or len(value) > 8192 or type(form) is not bool:
            return self._reply({"error": "invalid_arguments", "message": "value必须是<=8192字符的字符串，form必须是布尔值。"})
        return self._reply({"encoded": quote_plus(value, safe="") if form else quote(value, safe="")})

    async def _read_verification_diagnostics(self, args: dict) -> str:
        """Read the server-side diagnostics the host can prove belong to one job.

        Only jobs submitted in this context are addressable, and only an ``http`` job can
        have a trustworthy correlation id.  An unavailable collector or a pending log
        line is reported as such; it is never turned into "no errors".
        """
        job_id = args.get("job_id")
        job = next((item for item in self.jobs
                    if isinstance(job_id, str) and str(item.get("job_id") or "") == job_id), None)
        if job is None:
            return self._reply({
                "available": False, "reason": "unknown_job",
                "message": "只能查询本次验证中已提交的作业；未知作业不会重新执行。",
            })
        if job.get("kind") != "http":
            return self._reply({
                "available": False, "reason": "capability_unavailable", "job_id": job_id,
                "job_kind": job.get("kind"),
                "message": "只有受控 HTTP 观测带有宿主关联 ID；脚本与浏览器作业的诊断不受支持。",
            })
        cursor = args.get("cursor", "")
        if not isinstance(cursor, str):
            return self._reply({"available": False, "reason": "invalid_arguments", "message": "cursor 必须为字符串。"})
        reply = await self._job_diagnostics(job_id, cursor)
        stored = job.get("diagnostics")
        if isinstance(stored, dict):
            stored["last_read"] = {"available": reply.get("available"),
                                   "reason": reply.get("reason", ""), "items": len(reply.get("items") or [])}
        return self._reply(reply)

    async def _job_diagnostics(self, job_id: str, cursor: str = "") -> dict:
        """One bounded diagnostics page; runner failures become reasons, not verdicts."""
        fetch = getattr(self.client, "diagnostics", None)
        if fetch is None:
            # A client without the capability is an old/injected runner: report the gap
            # instead of assuming the request produced no PHP errors.
            return {"available": False, "reason": "capability_unavailable", "job_id": job_id,
                    "message": "本次验证的 runner 客户端不支持诊断读取。"}
        try:
            reply = await fetch(job_id, cursor)
        except PocRunnerUnavailable:
            return {"available": False, "reason": "collector_unavailable", "job_id": job_id,
                    "message": "runner 不可达，无法读取该作业的诊断；缺省不等于没有错误。"}
        except PocRunnerError as exc:
            reason = "unknown_job" if exc.status_code == 404 else "capability_unavailable"
            return {"available": False, "reason": reason, "job_id": job_id,
                    "message": "runner 无法提供该作业的诊断。"}
        items = []
        for raw in (reply.get("items") or [])[:20]:
            if not isinstance(raw, dict) or not raw.get("message"):
                continue
            items.append({
                "diagnostic_id": str(raw.get("diagnostic_id") or "")[:64],
                "kind": str(raw.get("kind") or "")[:24],
                "message": str(raw.get("message"))[:500],
                "source_path": str(raw.get("source_path") or "")[:200],
                "line": raw.get("line") if type(raw.get("line")) is int else 0,
            })
        if reply.get("available") is not True:
            return {"available": False, "reason": str(reply.get("reason") or "capability_unavailable"),
                    "job_id": job_id, "message": str(reply.get("message") or "")[:300]}
        return {"available": True, "job_id": job_id, "context_id": self.context_id,
                "target_version": str(reply.get("target_version") or "")[:64],
                "items": items, "next_cursor": str(reply.get("next_cursor") or "")[:16],
                "truncated": bool(reply.get("truncated"))}

    async def _read_verification_source(self, args: dict) -> str:
        """Read a bounded window of this finding's frozen snapshot.

        The snapshot is chosen by the host when the record is built; a ``path`` argument
        can only name a file inside it.  There is no host filesystem, archive or answer
        access behind this tool.
        """
        if self.source is None:
            return self._reply({
                "error": "source_unavailable", "reason": "policy_disabled",
                "message": "本次验证策略未开放源码补读；按提示中的结论与已有观测继续。",
            })
        reply = self.source.read(args.get("path"), args.get("start_line", 1), args.get("end_line", 120))
        return self._reply(reply)

    async def _resolve_target(self, args: dict) -> str:
        finding = self.finding
        if args.get("finding_id") != finding.get("id"):
            return self._reply({"error": "invalid_arguments", "message": "finding_id 必须与当前发现一致。"})
        path = str(finding.get("file_path") or next((item.get("path") for item in finding.get("evidence") or [] if isinstance(item, dict)), "") or "")
        return self._reply({
            "finding_id": finding.get("id"),
            "source_path": path,
            "target": self.target,
            "base_url": self.prepared.get("base_url") or "",
            "login": {"path": "/auth/login.php", "username_env": "LAB30_USER", "password_env": "LAB30_PASSWORD", "user": self.prepared.get("user") or self.default_identity},
            "version": self.prepared.get("version") or "",
            "context_id": self.context_id,
            "identities": ["guest", "alice", "bob", "operator", "admin"],
            "http_path_hint": _http_path_for(path),
            "note": "源码 app/public 对应商城根 /；src 内部文件没有直接 HTTP 路由，须按源码调用关系确定入口。",
        })

    async def _target_status(self, args: dict) -> str:
        result = await self.client.target_status(self.target, context_id=self.context_id, identity=args.get("identity", "alice"))
        self._remember_state(result)
        return self._reply(result)

    async def _target_prepare(self, args: dict) -> str:
        expected = args.get("expected_state", {})
        if (not isinstance(expected, dict) or set(expected) - {"balance", "tier", "nickname", "homepage", "id"}
                or any(type(value) not in {str, int, float, bool, type(None)} for value in expected.values())):
            return self._reply({"error": "invalid_expected_state", "message": "expected_state仅允许balance/tier/nickname/homepage/id标量字段；role由所选identity检查。"})
        result = await self.client.prepare_target(
            self.target, reset=False, context_id=self.context_id, identity=args.get("identity", "alice"),
            expected_state=args.get("expected_state") or None,
        )
        self.prepared = result
        self._remember_state(result)
        return self._reply(result)

    def _remember_state(self, result: dict) -> None:
        precondition = result.get("precondition")
        if isinstance(precondition, dict):
            identity = str(result.get("identity") or precondition.get("identity") or "")
            actual = precondition.get("actual") if isinstance(precondition.get("actual"), dict) else {}
            # Dedupe on the facts a later decision would read, not on the whole dict: the
            # runner's snapshot carries volatile fields, so repeated status checks used to
            # add entries that told the model nothing new.
            signature = (
                identity, bool(precondition.get("ok")), str(precondition.get("reason") or ""),
                str(actual.get("role") or ""), str(actual.get("balance") or ""),
                str(actual.get("tier") or ""), str(actual.get("nickname") or ""),
                str(actual.get("homepage") or ""),
            )
            if signature not in self._precondition_seen:
                self._precondition_seen.add(signature)
                self.preconditions.append({"identity": identity, **precondition})
                if len(self.preconditions) > self.max_preconditions:
                    dropped = len(self.preconditions) - self.max_preconditions
                    del self.preconditions[:dropped]
                    self.preconditions_omitted += dropped
        for change in result.get("state_changes") or []:
            if change not in self.state_changes:
                self.state_changes.append(change)

    def _artifact_bytes(self) -> int:
        return sum(len(payload) for payload in self.artifacts.values())

    def store_artifact(self, name: str, payload: bytes) -> bool:
        """Keep an artifact only while the phase stays inside its total artifact budget."""
        if self._artifact_bytes() + len(payload) > self.max_artifact_bytes:
            self.artifacts_omitted += 1
            return False
        self.artifacts[name] = payload
        return True

    def _job_error(self, args: dict, kind: str) -> dict | None:
        """Reject local contract errors before reserving any remote experiment."""
        identity = args.get("identity")
        if identity is None or identity == "":
            identity = self.default_identity
        if not isinstance(identity, str) or identity not in {"guest", "alice", "bob", "operator", "admin"}:
            return {"error": "invalid_identity", "message": "请选择已配置身份。"}
        if kind in {"http", "browser"}:
            path = args.get("path")
            if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
                    or len(path) > 2048 or any(ord(char) < 32 for char in path)
                    or any(item in path.partition("?")[0] for item in ("..", "\\", "\x00", "://"))):
                return {"error": "invalid_path", "message": "path 必须是靶场内的绝对路径。"}
        if kind == "http":
            if not isinstance(args.get("method", "GET"), str) or args.get("method", "GET").upper() not in {"GET", "POST"}:
                return {"error": "invalid_method", "message": "method 必须为 GET 或 POST。"}
            for key in ("body", "content_type"):
                if key in args and not isinstance(args[key], str):
                    return {"error": "invalid_arguments", "message": f"{key} 必须为字符串。"}
            if len(args.get("body", "")) > 256 * 1024:
                return {"error": "body_too_large"}
        elif kind == "browser":
            wait = args.get("wait_ms", 1000)
            if type(wait) is not int or not 0 <= wait <= 10000:
                return {"error": "invalid_wait_ms"}
            script = args.get("script", "")
            if not isinstance(script, str) or len(script) > 8192:
                return {"error": "invalid_script"}
        else:
            seconds = args.get("timeout_seconds", self.job_seconds)
            if type(seconds) is not int or not 1 <= seconds <= 120:
                return {"error": "invalid_timeout_seconds"}
            artifacts = args.get("artifacts", [])
            if (not isinstance(artifacts, list) or len(artifacts) > 8 or any(
                not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", item)
                or item in {".", ".."} for item in artifacts)):
                return {"error": "invalid_artifacts"}
        return None

    def _job_event(self, kind: str, record: dict, **fields) -> None:
        if self.execution is not None:
            self._emit({
                "kind": kind, "job_id": record["job_id"], "job_kind": record["kind"],
                "context_id": record.get("context_id", self.context_id),
                "identity": record.get("identity") or self.default_identity,
                "language": record.get("request", {}).get("language", ""),
                "duration_ms": record.get("duration_ms", 0),
                "timed_out": bool(record.get("result", {}).get("timed_out")),
                "truncated": bool(record.get("result", {}).get("truncated")),
                "jobs_used": len(self.jobs), "max_jobs": self.max_jobs,
                "jobs_remaining": max(0, self.max_jobs - len(self.jobs)), **fields,
            })

    def _persist_job(self, record: dict) -> None:
        if self.on_job_fact is not None:
            self.on_job_fact(record)

    async def _submit_job(self, kind: str, args: dict, submit) -> tuple[dict, int]:
        """Reserve a shared slot before I/O; accepted/failed/unknown all consume it."""
        if self.submission_unresolved:
            raise StopAudit("submission_unresolved", "上一作业执行状态未确认，只能查询原作业，不重复提交。")
        if len(self.jobs) >= self.max_jobs:
            record = {"job_id": "", "kind": kind, "context_id": self.context_id,
                      "identity": args.get("identity", "alice")}
            self._job_event("poc_job_rejected", record, status="rejected", reason="job_limit")
            return {"error": "job_limit", "message": f"本 finding 最多执行 {self.max_jobs} 个作业", "jobs_used": len(self.jobs)}, -1
        job_id = uuid.uuid4().hex
        record = {"job_id": job_id, "kind": kind, "context_id": self.context_id,
                  "identity": args.get("identity", "alice"), "request": dict(args),
                  "result": {"status": "submitting"}, "exit_code": None}
        index = len(self.jobs)
        self.jobs.append(record)
        if self.on_job:
            self.on_job(job_id)
        self._job_event("poc_job_started", record, status="submitting")
        try:
            try:
                result = await submit(job_id)
            except (PocRunnerUnavailable, asyncio.TimeoutError):
                # Submission may already execute. Never retry its side effects.
                try:
                    result = await asyncio.wait_for(self.client.get_job(job_id), timeout=5)
                except (PocRunnerError, PocRunnerUnavailable, asyncio.TimeoutError):
                    result = {"job_id": job_id, "status": "unknown", "exit_code": None}
            if not isinstance(result, dict):
                raise PocRunnerError("POC runner returned an unexpected job shape")
            # The HTTP client enforces echoed ids and contexts at its protocol
            # boundary; retain the reservation id when an injected client omits it.
            result = {"job_id": job_id, "context_id": self.context_id, **result}
            if result.get("context_id") != self.context_id:
                raise PocRunnerError("POC runner job belongs to another verification context")
            status = result.get("execution_status", result.get("status", "finished"))
            if not isinstance(status, str):
                status = "finished"
            record.update(job_id=result["job_id"], host_job_id=job_id, result=dict(result),
                          exit_code=result.get("exit_code"), duration_ms=result.get("duration_ms", 0),
                          precondition=result.get("precondition") or {}, postcondition=result.get("postcondition") or {},
                          state_changes=result.get("state_changes") or [])
            self._remember_state(result)
            if status in {"submitting", "running", "queued", "unknown", "unresolved"}:
                self.submission_unresolved = True
                self._job_event("poc_job_finished", record, status=status, reason="submission_unresolved")
                raise StopAudit("submission_unresolved", "原作业执行状态未确认，保留未决结果，不重复执行。")
            self._job_event("poc_job_finished", record, status=status, exit_code=result.get("exit_code"),
                            reason=result.get("error") or "", http_status=result.get("http_status", result.get("status")) if kind == "http" else None)
            return result, index
        except asyncio.CancelledError:
            self.submission_unresolved = True
            record.update(result={"status": "unknown", "error": "submission_cancelled"}, exit_code=None)
            self._job_event("poc_job_finished", record, status="unknown", reason="submission_cancelled")
            raise
        except PocRunnerError as exc:
            # A malformed/oversized reply can arrive after the action executed.
            # Only an explicit 4xx is a confirmed refusal; never retry unknown work.
            confirmed_refusal = exc.status_code is not None and 400 <= exc.status_code < 500
            status = "rejected" if confirmed_refusal else "unknown"
            self.submission_unresolved = not confirmed_refusal
            record.update(result={"status": status, "error": str(exc)[:400]}, exit_code=None)
            self._job_event("poc_job_finished", record, status=status,
                            reason="runner_rejected" if confirmed_refusal else "submission_unresolved")
            raise
        finally:
            # Facts survive a missing conclusion, cancellation or exhausted model
            # quota. The callback cannot publish a vulnerability verdict.
            self._persist_job(record)

    async def _run_poc(self, args: dict) -> str:
        error = self._job_error(args, "script")
        if error:
            return self._reply(error)
        language = str(args.get("language") or "").casefold()
        script = args.get("script")
        if not isinstance(script, str) or not script.strip():
            return self._reply({"error": "empty_script"})
        if len(script.encode("utf-8")) > self.max_script_bytes:
            return self._reply({"error": "script_too_large", "limit": self.max_script_bytes})
        if language not in {"php", "python"}:
            return self._reply({"error": "unsupported_language", "allowed": ["php", "python"]})
        requested = [str(item) for item in (args.get("artifacts") or [])][:8]
        timeout = max(1, min(120, self.job_seconds, int(args.get("timeout_seconds") or self.job_seconds)))
        job, slot = await self._submit_job("script", args, lambda job_id: self.client.run_job(
            target=self.target, language=language, script=script,
            timeout_seconds=timeout, artifacts=requested, job_id=job_id,
            context_id=self.context_id, identity=args.get("identity", "alice"),
        ))
        if job.get("ok") is False or job.get("error"):
            return self._reply(job)
        job_id = str(job.get("job_id") or "")
        if self.should_stop is not None and self.should_stop():
            raise StopAudit("interrupted", "拒绝已停止 POC 的迟到作业结果")
        self.scripts.append(script)
        self.job_scripts[job_id] = script
        artifacts = []
        for item in job.get("artifacts") or []:
            name = str(item.get("name") or "")
            if not name:
                continue
            try:
                payload = await self.client.fetch_artifact(job_id, name)
            except (PocRunnerUnavailable, PocRunnerError):
                continue
            stored_name = f"{job_id}-{name}"
            if not self.store_artifact(stored_name, payload):
                artifacts.append({"name": stored_name, "original_name": name, "job_id": job_id,
                                  "size": len(payload), "error": "artifact_budget_exceeded"})
                continue
            artifacts.append({
                "name": stored_name,
                "original_name": name,
                "job_id": job_id,
                "sha256": item.get("sha256") or hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            })
        record = {
            "job_id": job_id,
            "kind": "script",
            "context_id": job.get("context_id") or "",
            "identity": args.get("identity", "alice"),
            "precondition": job.get("precondition") or {},
            "postcondition": job.get("postcondition") or {},
            "state_changes": job.get("state_changes") or [],
            "request": {
                "target": self.target,
                "language": language,
                "script_sha256": hashlib.sha256(script.encode("utf-8")).hexdigest(),
                "script": script,
                "timeout_seconds": timeout,
                "artifacts": requested,
            },
            "result": {
                "status": job.get("status"),
                "exit_code": job.get("exit_code"),
                "duration_ms": job.get("duration_ms"),
                "stdout": str(job.get("stdout") or "")[:8192],
                "stderr": str(job.get("stderr") or "")[:4096],
                "truncated": bool(job.get("truncated")),
                "timed_out": bool(job.get("timed_out")),
            },
            "exit_code": job.get("exit_code"),
            "duration_ms": job.get("duration_ms"),
            "artifacts": artifacts,
        }
        self.jobs[slot] = record
        self._persist_job(record)
        return self._reply(record["result"] | {
            "job_id": job_id,
            "context_id": record["context_id"],
            "precondition": record["precondition"],
            "postcondition": record["postcondition"],
            "state_changes": record["state_changes"],
            "artifacts": artifacts,
            "job_number": len(self.jobs),
        })

    async def _http_observe(self, args: dict) -> str:
        error = self._job_error(args, "http")
        if error:
            return self._reply(error)
        path = args["path"]
        result, slot = await self._submit_job("http", args, lambda job_id: self.client.http_observe(
            target=self.target, method=args.get("method", "GET"), path=path,
            body=args.get("body", ""),
            headers={"Content-Type": args.get("content_type", "application/x-www-form-urlencoded")}
            if args.get("body", "") else None,
            context_id=self.context_id, identity=args.get("identity", "alice"), job_id=job_id,
        ))
        if result.get("ok") is False or result.get("error"):
            return self._reply(result)
        method = str(args.get("method") or "GET").upper()
        # The runner sends exactly one request and does not follow redirects, so the
        # status and Location below describe the response the vulnerable code produced.
        # Keeping the headers (not just the flattened redirect list) is what lets the
        # conclusion cite the raw Location value.
        record = {
            "kind": "http",
            "job_id": result["job_id"],
            "method": method,
            "path": path,
            "status": result.get("http_status", result.get("status")),
            "execution_status": result.get("execution_status") or (
                result.get("status") if isinstance(result.get("status"), str) else "finished"
            ),
            "exit_code": result.get("exit_code", 0),
            "timed_out": bool(result.get("timed_out")),
            "error": result.get("error") or "",
            "url": str(result.get("url") or "")[:500],
            "headers": {
                str(key): str(value)[:2048]
                for key, value in (result.get("headers") or {}).items()
                if isinstance(key, str)
            },
            "redirects": result.get("redirects") or [],
            "body": str(result.get("body") or "")[:8192],
            "truncated": bool(result.get("truncated")),
            "followed_redirects": False,
            "identity": args.get("identity", "alice"),
            "context_id": self.context_id,
            "precondition": result.get("precondition") or {},
            "postcondition": result.get("postcondition") or {},
            "state_changes": result.get("state_changes") or [],
        }
        self.observations.append(record)
        if len(self.observations) > self.max_observations:
            del self.observations[:-self.max_observations]
        if result.get("job_id"):
            # Host-fetched once, bounded, and stored with the job: the evidence table may
            # cite it, and it must not depend on the model asking for it later.
            diagnostics = await self._job_diagnostics(str(result["job_id"]))
            record["diagnostics"] = diagnostics
            self.jobs[slot] = {
                "job_id": result["job_id"], "kind": "http", "context_id": result.get("context_id") or "",
                "identity": args.get("identity", "alice"), "precondition": result.get("precondition") or {},
                "request": {"method": method, "path": path},
                "result": {**record, "http_status": record["status"], "status": record["execution_status"]},
                "exit_code": result.get("exit_code", 0), "duration_ms": result.get("duration_ms", 0),
                "diagnostics": diagnostics,
            }
            self._persist_job(self.jobs[slot])
        self._emit({
            "kind": "poc_http_observed", "method": method,
            "path": path, "status": record["status"],
            "location": record["headers"].get("location", ""),
        })
        return self._reply(record | {"diagnostics": {
            "available": record["diagnostics"].get("available"),
            "reason": record["diagnostics"].get("reason", ""),
            "item_count": len(record["diagnostics"].get("items") or []),
        }})

    async def _browser_check(self, args: dict) -> str:
        if not bool(self.policy.get("browser", True)):
            return self._reply({
                "error": "browser_disabled",
                "message": "该运行未启用浏览器；XSS 类结论只能记为 inconclusive。",
            })
        error = self._job_error(args, "browser")
        if error:
            return self._reply(error)
        result, slot = await self._submit_job("browser", args, lambda job_id: self.client.browser_check(
            target=self.target, path=args["path"], script=args.get("script", ""),
            wait_ms=args.get("wait_ms", 1000), context_id=self.context_id,
            identity=args.get("identity", "alice"), job_id=job_id,
        ))
        if result.get("ok") is False or result.get("error"):
            return self._reply(result)
        if not result.get("available", False):
            self.browser_available = False
            return self._reply({"error": "browser_unavailable", "message": "runner 未安装浏览器"})
        job_id = str(result.get("job_id") or "")
        if self.should_stop is not None and self.should_stop():
            raise StopAudit("interrupted", "拒绝已停止 POC 的迟到浏览器结果")
        artifacts = []
        for item in result.get("artifacts") or []:
            name = str(item.get("name") or "")
            if not name:
                continue
            try:
                payload = await self.client.fetch_artifact(job_id, name)
            except (PocRunnerUnavailable, PocRunnerError):
                continue
            stored_name = f"{job_id}-{name}"
            if not self.store_artifact(stored_name, payload):
                artifacts.append({"name": stored_name, "original_name": name, "job_id": job_id,
                                  "size": len(payload), "error": "artifact_budget_exceeded"})
                continue
            artifacts.append({
                "name": stored_name,
                "original_name": name,
                "job_id": job_id,
                "sha256": item.get("sha256") or hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            })
        record = {
            "job_id": job_id,
            "kind": "browser",
            "context_id": result.get("context_id") or "",
            "identity": args.get("identity", "alice"),
            "precondition": result.get("precondition") or {},
            "postcondition": result.get("postcondition") or {},
            "state_changes": result.get("state_changes") or [],
            "request": {"path": str(args.get("path") or ""), "wait_ms": args.get("wait_ms", 1000)},
            "result": {
                "status": result.get("execution_status") or result.get("status") or ("failed" if result.get("error") else "finished"),
                "timed_out": bool(result.get("timed_out")),
                "available": True,
                "error": result.get("error") or "",
                "title": str(result.get("title") or "")[:500],
                "url": str(result.get("url") or "")[:500],
                "dialogs": [str(item)[:500] for item in result.get("dialogs") or []][:20],
                "console_errors": [str(item)[:500] for item in result.get("console_errors") or []][:20],
                "body_text": str(result.get("body_text") or "")[:4000],
                "evaluated": str(result.get("evaluated") or "")[:2000],
            },
            "exit_code": result.get("exit_code", 0 if not result.get("error") else None),
            "duration_ms": result.get("duration_ms", 0),
            "artifacts": artifacts,
        }
        self.jobs[slot] = record
        self._persist_job(record)
        return self._reply(record["result"] | {"job_id": job_id, "artifacts": artifacts,
                           "exit_code": record["exit_code"], "context_id": record["context_id"],
                           "precondition": record["precondition"], "postcondition": record["postcondition"],
                           "state_changes": record["state_changes"]})

    async def _save_artifact(self, args: dict) -> str:
        name = str(args.get("filename") or "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name) or name in {".", ".."}:
            return self._reply({"error": "invalid_name"})
        payload = str(args.get("content") or "").encode("utf-8")
        if len(payload) > 64 * 1024:
            return self._reply({"error": "too_large", "limit": 65536})
        name = "derived-" + name
        if not self.store_artifact(name, payload):
            return self._reply({"error": "artifact_budget_exceeded", "limit": self.max_artifact_bytes,
                                "message": "本 finding 的产物总量已达上限；请保留结论所需的最小证据。"})
        return self._reply({
            "name": name,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })


def _http_path_for(source_path: str) -> str:
    """Map the Lab30 public document root; internal source is not a web endpoint."""
    text = str(source_path or "").replace("\\", "/").strip("/")
    parts = text.split("/")
    if ".." in parts:
        return "/"
    if "public" in parts:
        text = "/".join(parts[parts.index("public") + 1:])
    if text in {"index.php", "health.php"} or text.startswith(("auth/", "catalog/", "orders/", "wallet/", "account/", "ops/", "partner/", "support/", "content/")):
        return "/" + text
    return "/"
