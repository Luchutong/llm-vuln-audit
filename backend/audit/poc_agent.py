"""The POC agent: turn one source finding into an executable check in Lab30 shop.

The agent runs in two phases.  ``poc_execute`` is free to adapt the recorded POC and
run it through the isolated runner; ``poc_conclude`` has the tools withdrawn and must
answer with a :class:`PocVerificationResult`.  The host then fact-checks that answer
against the runner's own job records before anything is written as a verdict, so a
model that claims success without a successful job cannot publish one.
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

from .agent import build_code_model
from .codemodel import ModelCallFailed, PhaseGate
from .config import ModelConfig
from .executor import attach_phase, build_agent, drive_phase, prompt_templates
from .poc_runner import PocRunnerClient, PocRunnerError, PocRunnerUnavailable
from .runtime import AgentPolicy, Execution, StopAudit
from .structured_output import drive_structured_phase
from .worker_strategies import canonical_vulnerability_type
from .schemas import PocVerificationResult
from .toolkit import Arg, FinalAnswerTool, ToolSpec, build_tools, spec
from .tool_errors import public_value, classify_failure

MAX_TOOL_REPLY = 16 * 1024
MAX_SCRIPT = 32 * 1024
STOPWORDS = frozenset({
    "admin", "password", "error", "true", "false", "http", "https", "html", "body",
    "div", "span", "function", "return", "echo", "print", "with", "this", "that",
    "from", "have", "will", "your", "which", "there", "their", "about", "after",
    "before", "using", "user", "users", "input", "output", "response", "request",
})
_TOKEN = re.compile(r"[A-Za-z0-9_.:/-]{4,}")


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


POC_TOOLS: tuple[ToolSpec, ...] = (
    spec(
        "url_encode", "Encode a URL query/form value in memory, without network or filesystem access.",
        output_format="json", value=Arg("string", "需要编码的单个参数值，最多8192字符。", max_length=8192),
        form=Arg("boolean", "true 按表单规则将空格编码为+，false 编码为%20。", False),
    ),
    spec(
        "resolve_target",
        "Return the executable mapping for this finding: the Lab30 base URL, credential environment variable names, "
        "and the HTTP path that corresponds to the finding's source file. "
        "This is host data; it does not prove anything.",
        output_format="json",
        finding_id=Arg("string", "本次验证的 finding id（必须与提示中的一致）。"),
    ),
    spec(
        "target_status",
        "Return target reachability, authentication state and version.",
        output_format="json",
        identity=Arg("string", "guest、alice、bob、operator 或 admin。省略时使用宿主准备的身份。", ""),
    ),
    spec(
        "target_prepare",
        "Check a configured Lab30 identity in this verification context without resetting data. "
        "A changed role blocks that identity; report missing preconditions instead of guessing credentials.",
        output_format="json",
        identity=Arg("string", "guest、alice、bob、operator 或 admin。省略时使用宿主准备的身份。", ""),
        expected_state=Arg("object", "仅允许balance/tier/nickname/homepage/id的标量前提；角色由identity校验，不要传role。默认空对象。", {}),
    ),
    spec(
        "run_poc",
        "Execute a POC script inside the isolated runner and return bounded stdout/stderr, exit code "
        "and artifact metadata. The script may reach only the Lab30 base URL. It must log in itself: "
        "the runner does not inject cookies into scripts.",
        output_format="json",
        language=Arg("string", "php 或 python。"),
        script=Arg("string", "完整脚本内容（<= 32 KiB）。"),
        timeout_seconds=Arg("integer", "执行超时（秒），1-120。默认 30。", 30, minimum=1, maximum=120),
        artifacts=Arg("array", "脚本写出的、需要取回的相对文件名列表（<= 8 个）。默认空列表。", [], item_type="string", max_items=8),
        identity=Arg("string", "脚本 LAB30_USER/PASSWORD 对应的已配置身份。省略时使用宿主准备的身份；无鉴权对照选 guest。", ""),
    ),
    spec(
        "http_observe",
        "Send one GET/POST to an allowlisted Lab30 path through the isolated runner and return status, "
        "redirects and a bounded body preview. Use it for server-side checks; use browser_check for "
        "anything that depends on JavaScript executing.",
        output_format="json",
        path=Arg("string", "Lab30 内的绝对路径，例如 /auth/login.php 或 /catalog/detail.php?id=1。"),
        method=Arg("string", "GET 或 POST。默认 GET。", "GET"),
        body=Arg("string", "POST 请求体（application/x-www-form-urlencoded）。默认空串。", ""),
        content_type=Arg("string", "POST 的 Content-Type。默认 application/x-www-form-urlencoded。", "application/x-www-form-urlencoded"),
        identity=Arg("string", "独立会话身份：guest、alice、bob、operator 或 admin。省略时使用宿主准备的身份。", ""),
    ),
    spec(
        "browser_check",
        "Load an allowlisted Lab30 path in Chromium, wait, and return title, alert dialogs, console "
        "errors, body text, and a screenshot artifact. Required for XSS conclusions.",
        output_format="json",
        path=Arg("string", "Lab30 内的绝对路径。"),
        wait_ms=Arg("integer", "加载后等待毫秒数，0-10000。默认 1000。", 1000, minimum=0, maximum=10000),
        script=Arg("string", "可选：在页面中求值的 JavaScript，用于构造触发条件。默认空串。", ""),
        identity=Arg("string", "独立会话身份：guest、alice、bob、operator 或 admin。省略时使用宿主准备的身份。", ""),
    ),
    spec(
        "save_artifact",
        "Keep a small textual observation (<= 64 KiB) as an evidence artifact. Use it for derived "
        "analysis, not for replacing raw runner output.",
        output_format="json",
        filename=Arg("string", "安全的文件名，例如 normal.txt。"),
        content=Arg("string", "要保存的文本内容。"),
    ),
)


@dataclass
class PocDeps:
    """The POC agent's dispatcher and everything it must leave behind."""

    client: PocRunnerClient
    policy: dict
    target: str
    finding: dict
    execution: Execution | None = None
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

    @property
    def last_script(self) -> str:
        return self.scripts[-1] if self.scripts else ""

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
        if self.should_stop is not None and self.should_stop():
            raise StopAudit("interrupted", "POC 所属执行代次已停止")
        if name in {"target_status", "target_prepare", "run_poc", "http_observe", "browser_check"}:
            # An omitted identity means "the account the host prepared", not "alice".
            # Only a missing/empty value is filled: an invalid type still has to reach
            # the tool's own validation and be rejected.
            if args.get("identity") is None or args.get("identity") == "":
                args["identity"] = self.default_identity
        execution = self.execution
        execution.before_tool()
        # Pair every call with a result even when the phase is cancelled: the durable
        # trace is read to tell a runner failure from a model mistake, and a call with no
        # result looks like a hung tool.
        call_id = f"poc-tool-{execution.tools:04d}"
        span_id = f"{execution.phase}:{call_id}"
        started = time.monotonic()
        execution.emit({
            "kind": "tool_call",
            "tool": name,
            "args": public_value(args),
            "turn": execution.tools,
            "call_id": call_id,
            "span_id": span_id,
            "phase": execution.phase,
            "started_elapsed_ms": round((started - execution.started) * 1000),
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
            execution.emit({"kind": "poc_runner_unavailable", "error": self.runner_error})
            text = self._reply({"error": "runner_unavailable", "message": self.runner_error})
            failure = {"error_code": "runner_unavailable", "error": self.runner_error, "hint": "检查隔离 runner；未确认的作业只能查询，不能重交。"}
            raise StopAudit("environment_unavailable", "POC runner 不可用，停止本次自动验证") from exc
        except PocRunnerError as exc:
            status = "runner_rejected"
            error_type = type(exc).__name__
            execution.emit({"kind": "poc_runner_rejected", "error": str(exc)[:400]})
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
                "usage": execution.snapshot(),
                "call_id": call_id,
                "span_id": span_id,
                "phase": execution.phase,
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
            execution.emit(result)
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
            self.execution.emit({
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
            self.jobs[slot] = {
                "job_id": result["job_id"], "kind": "http", "context_id": result.get("context_id") or "",
                "identity": args.get("identity", "alice"), "precondition": result.get("precondition") or {},
                "request": {"method": method, "path": path},
                "result": {**record, "http_status": record["status"], "status": record["execution_status"]},
                "exit_code": result.get("exit_code", 0), "duration_ms": result.get("duration_ms", 0),
            }
            self._persist_job(self.jobs[slot])
        self.execution.emit({
            "kind": "poc_http_observed", "method": method,
            "path": path, "status": record["status"],
            "location": record["headers"].get("location", ""),
        })
        return self._reply(record)

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


def _tokens(text: str) -> set[str]:
    return {
        token.casefold()
        for token in _TOKEN.findall(str(text or ""))
        if len(token) >= 4 and token.casefold() not in STOPWORDS
    }


def _is_xss(finding: dict) -> bool:
    cause = canonical_vulnerability_type(finding.get("vulnerability_type"))
    if cause in {"xss_r", "xss_s"}:
        return True
    if cause not in {"", "unknown", "other"}:
        return False
    haystack = " ".join(
        str(finding.get(key) or "")
        for key in ("category", "title", "summary", "dangerous_operation", "finding_kind")
    ).casefold()
    # 标准分类名 "Cross-Site Scripting" 不含子串 "xss"，必须单独匹配，
    # 否则 host_check 不会强制浏览器弹窗证据，纯 HTTP 反射可能被误判为 verified。
    return "xss" in haystack or "cross-site scripting" in haystack


def _successful_script(job: dict) -> bool:
    return (
        job.get("kind") == "script"
        and str(job.get("result", {}).get("status") or "") == "finished"
        and job.get("exit_code") == 0
        and not job.get("result", {}).get("timed_out")
    )


def successful_job(job: dict) -> bool:
    """An experiment completed; this alone never establishes a vulnerability."""
    result = job.get("result") or {}
    if (type(job.get("exit_code")) is not int or job.get("exit_code") != 0 or result.get("timed_out") or result.get("error")
            or (job.get("precondition") or {}).get("ok") is not True):
        return False
    if job.get("kind") == "http":
        return (result.get("execution_status", result.get("status")) == "finished"
                and type(result.get("http_status")) is int and 100 <= result["http_status"] <= 599)
    return _successful_script(job) or _successful_browser(job) is not None


def _successful_browser(job: dict) -> dict | None:
    if job.get("kind") != "browser" or job.get("exit_code") != 0:
        return None
    result = job.get("result") or {}
    if not result.get("available") or result.get("error") or result.get("timed_out") or result.get("status") != "finished":
        return None
    return result


def _runner_text(job: dict) -> str:
    result = job.get("result") or {}
    pieces = [str(result.get("stdout") or ""), str(result.get("stderr") or "")]
    if job.get("kind") == "browser":
        pieces.extend(str(item) for item in result.get("dialogs") or [])
        pieces.append(str(result.get("body_text") or ""))
        pieces.append(str(result.get("evaluated") or ""))
    pieces.extend(str(item.get("name") or "") for item in job.get("artifacts") or [])
    return "\n".join(pieces)


def _evidence_channel(job: dict, channel: str) -> str:
    result = job.get("result") or {}
    if job.get("kind") == "http":
        if channel in {"body", "body_text"}:
            return str(result.get("body") or "")
        if channel == "headers":
            return "\n".join(f"{key}: {value}" for key, value in sorted((result.get("headers") or {}).items()))
        return ""
    allowed = {"stdout", "stderr"} if job.get("kind") == "script" else {"body_text", "dialogs", "evaluated"}
    if channel not in allowed:
        return ""
    value = result.get(channel)
    return "\n".join(str(item) for item in value) if isinstance(value, list) else str(value or "")


def host_check(result: PocVerificationResult, deps: PocDeps) -> PocVerificationResult:
    """Accept only exact, paired citations to successful jobs in this experiment."""
    notes: list[str] = []
    by_id = {str(job.get("job_id") or ""): job for job in deps.jobs if job.get("job_id")}

    def usable(job: dict) -> bool:
        return (
            bool(deps.context_id) and job.get("context_id") == deps.context_id
            and (job.get("precondition") or {}).get("ok") is True
            and not (job.get("result") or {}).get("timed_out")
            and not (job.get("result") or {}).get("error")
            and successful_job(job)
        )

    if result.status in {"not_applicable", "environment_unavailable"}:
        result.status, result.verdict = "inconclusive", "uncertain"
        notes.append("模型自报的环境结论由宿主覆盖为 inconclusive")

    supporting: list[dict] = []
    if result.status in {"verified", "rejected"}:
        if not result.jobs:
            notes.append("缺少成功作业支撑：jobs 必须明确引用本次验证的成功作业")
        for ident in result.jobs:
            job = by_id.get(ident)
            if job is None:
                notes.append(f"未知作业引用：{ident}")
            elif not usable(job):
                notes.append(f"作业 {ident} 未成功、身份前提未核实或不属于本次上下文")
            else:
                supporting.append(job)
        if not supporting:
            notes.append("缺少成功作业支撑")
        for label, observation, references in (
            ("正常侧", result.normal_observation, result.normal_evidence),
            ("攻击侧", result.attack_observation, result.attack_evidence),
        ):
            if not observation.strip() or not references:
                notes.append(f"{label}缺少观测或原文证据引用")
            for ref in references:
                job = by_id.get(ref.job_id)
                if ref.job_id not in result.jobs or job is None or not usable(job):
                    notes.append(f"{label}引用的作业 {ref.job_id} 不可作为成功证据")
                elif not ref.excerpt.strip() or ref.excerpt not in _evidence_channel(job, ref.channel):
                    notes.append(f"{label}原文片段不在作业 {ref.job_id} 的 {ref.channel} 中")
        if result.status == "verified" and _is_xss(deps.finding):
            attack_browser = [by_id[ref.job_id] for ref in result.attack_evidence
                              if ref.job_id in by_id and usable(by_id[ref.job_id])
                              and ref.channel in {"dialogs", "evaluated"}]
            if not result.browser_execution or not any(
                (job.get("result") or {}).get("dialogs") or (job.get("result") or {}).get("evaluated")
                for job in attack_browser
            ):
                notes.append("XSS 结论缺少攻击侧浏览器执行证据")

    # Never replace a cited successful script with the last (possibly failed) attempt.
    cited = [ref.job_id for ref in result.attack_evidence] + list(result.jobs)
    selected = next((ident for ident in cited if ident in deps.job_scripts
                     and ident in by_id and usable(by_id[ident])), None)
    result.adapted_script = deps.job_scripts[selected] if selected else ""
    if notes and result.status in {"verified", "rejected"}:
        result.status, result.verdict = "inconclusive", "uncertain"
        result.adapted_script = ""
    if notes:
        result.evidence_notes = ("；".join(notes) + ("\n" + result.evidence_notes if result.evidence_notes else ""))[:4000]
    return result


EXECUTE_INSTRUCTIONS = """你是 POC 自动验证 Agent，只在隔离的 Lab30 拾光商城靶场中，
为一条已有原始源码证据的漏洞执行最小、可复核的正常侧与攻击侧对照。

工具契约：
- run_poc、http_observe、browser_check 共享 max_jobs 作业总额；失败或状态未确认的提交也占额。
  请求超时由宿主查询原作业；状态未确认时停止实验，不自行重复提交相同副作用。
- 工具是普通 Python 函数，返回 JSON 字符串；使用 json.loads(...) 再取字段。
- URL参数使用 url_encode(value=...) 内存编码工具，不在宿主解释器导入 urllib；表单值使用 form=true。
- 你的动作解释器只能做内存计算，不能联网、读写文件、启动进程；没有源码工具。
- run_poc 把脚本交给隔离 runner，只有脚本内部可用 urllib/curl 访问 LAB30_URL。
- http_observe 恰好发送一个请求，不跟随重定向；首个 3xx 与 Location 本身就是观测。
- browser_check 复用 runner 的会员会话；XSS 必须观察到弹窗或页面求值结果，HTTP 反射不算执行。
- 脚本不继承 HTTP/浏览器的 CookieJar，必须自行登录。目标映射以 resolve_target 的主机与路径为准。
- 各工具的 identity 可选 guest/alice/bob/operator/admin；省略时使用宿主准备的身份。凭据通过该身份的 LAB30_USER/PASSWORD 提供，禁止猜密码。
- 每次执行前宿主核对实际角色。precondition_failed 表示前提不符，不能拿高权限会话冒充普通会员。
- 会话彼此隔离，但数据库和文件仍共享；同一 finding 内前序实验可能改变角色、余额等状态，必须核实本实验必要前提。

脚本登录模板（这是交给 run_poc 的脚本内容，不是你的动作代码块）：
```python
import os, urllib.request, urllib.parse, urllib.error, http.cookiejar
BASE = os.environ["LAB30_URL"].rstrip("/")
jar = http.cookiejar.CookieJar()
login = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
login.open(BASE + "/auth/login.php", timeout=10).read()
login.open(BASE + "/auth/login.php", timeout=10, data=urllib.parse.urlencode({
    "username": os.environ["LAB30_USER"], "password": os.environ["LAB30_PASSWORD"],
}).encode()).read()
member = login.open(BASE + "/orders/index.php", timeout=10)
assert member.status == 200 and "/auth/login.php" not in member.url, "会员登录未生效"
print("MEMBER_SESSION", member.status)
# 后续请求继续使用同一个 CookieJar；正常输入和攻击输入依据任务中给出的源码构造。
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
observe = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)
```

Lab30 实际运行约定：
- 登录 POST 只有 username/password，没有登录 CSRF 字段；会员页未认证可能返回 401 或 302。
  必须先确认会话生效，不把登录页、401、403或脚本成功退出当成漏洞影响。
- 业务表单可能有名为 csrf 的字段；需要时先 GET 对应表单，从真实 HTML 取值再 POST。
  参数、方法、路由与权限前提都以本条发现的源码为准，不假定所有页面同一规则。
- 普通会员身份通常是 alice，也可能是 bob；以宿主准备的提示为准。bob、operator、admin 是靶场提供的其他测试身份。
  若需要角色对照，分开会话；不能用管理员成功访问的结果冒充普通会员越权。
- 商城没有安全等级切换流程。源码 app/public 对应 Web 根目录；app/src 的文件不能直接访问。
- /catalog/、/orders/、/wallet/、/account/、/ops/、/partner/、/support/、/content/ 为业务入口。
- HTTPError 中的状态码、响应头和正文仍是有效观测；捕获并打印，尤其是 401/403/404。
- SQL 注入核对结果行、字段或条件差异；命令执行核对只会由攻击产生的唯一标记；
  XSS 核对浏览器实际执行；不能凭常见字符串或成功响应作 verified。
- 按源码中的引号、HTML上下文、编码与请求方法构造最小 payload；无效时最多尝试不同的最小变体。
- 始终打印并保留正常侧和攻击侧的原始输出；观测说明必须对应实际 stdout、作业或浏览器结果。
- target_prepare 只刷新会员会话，不重置商城数据。宿主可能在 finding 之间自行复位靶场。
- 不读取答案、不猜内部标记、不编造执行结果。信息不足时交回 inconclusive。
- 探索结束调用 final_answer("探索结束")；验证结论下一阶段单独提交。
- 不输出隐藏思维链或长篇内部推理。
"""

IDENTITY_RULES = """身份决策：
- 宿主已用 {identity} 完成初始准备（见“靶场”块的 identity/identity_attempts）。
- 该身份返回 identity_or_role_mismatch 或 identity_preparation_failed 时，普通会员结论先改用 bob；
  bob 同样不符时按前提缺失如实报告，禁止猜密码，也不得改用特权身份冒充。
- 只有源码明确要求 operator 或 admin 时才使用特权身份；不得用特权身份成功证明普通会员越权。
- target_prepare 的 expected_state.balance 可写 100 或 "100.00"，两者等价；只声明源码真正要求的前提。
"""


def execute_instructions(deps: PocDeps) -> str:
    return EXECUTE_INSTRUCTIONS + "\n" + IDENTITY_RULES.format(identity=deps.default_identity)

CONCLUDE_INSTRUCTIONS = """你是 POC 自动验证 Agent 的结论阶段，所有工具都已收回。
仅按宿主记录输出一个完整 JSON 对象，不写 Python/XML/final_answer，不生成推理正文。
verified/rejected 必须提供 jobs、normal_observation、attack_observation、normal_evidence、attack_evidence。
证据格式为 {"job_id":"真实作业ID","channel":"输出通道","excerpt":"原文片段"}。
脚本可引用 stdout/stderr，HTTP 可引用 body/headers，浏览器可引用 body_text/dialogs/evaluated。
headers 原文格式为每行“header-name: value”，按字段名排序；body_text 仅作为旧HTTP引用别名。
两侧可引用同一个成功作业。成功完成HTTP并不证明漏洞成立，状态码、退出码不能替代实际影响与正常/攻击对照。
XSS 必须引用攻击侧浏览器 dialogs/evaluated 的真实执行证据，HTTP反射不是浏览器执行。
未知、非零退出、超时、错误上下文及身份前提未核实的作业不能支撑确定性结论。
verified 表示对照证明漏洞影响；rejected 表示有效实验明确否定当前结论；失败、前提不符或证据不足均为 inconclusive。
not_applicable/environment_unavailable仅由宿主决定。adapted_script留空，宿主仅从支撑结论的成功作业补齐。
summary只写一句结论，evidence_notes简短说明局限，不重复整份作业输出。
示例：{"status":"inconclusive","summary":"对照证据不足，保留待验证","jobs":[],"normal_evidence":[],"attack_evidence":[]}
字段契约由宿主提供；只输出JSON。"""

def _bound(text: str, limit: int) -> str:
    raw = str(text or "")
    if len(raw.encode("utf-8")) <= limit:
        return raw
    return raw.encode("utf-8")[:limit].decode("utf-8", "ignore") + "\n[已截断]"


def _finding_block(finding: dict) -> str:
    payload = {
        key: finding.get(key)
        for key in (
            "id", "title", "category", "severity", "file_path", "symbol", "summary",
            "evidence", "input_source", "propagation", "dangerous_operation",
            "protection", "preconditions", "missing_context", "poc", "remediation",
        )
    }
    return _bound(json.dumps(payload, ensure_ascii=False, indent=2), 12 * 1024)


def execute_prompt(finding: dict, deps: PocDeps, policy: dict) -> str:
    return (
        "# 待验证的源码结论\n"
        + _finding_block(finding)
        + "\n# 靶场（宿主已准备）\n"
        + _bound(json.dumps(deps.prepared, ensure_ascii=False), 4 * 1024)
        + "\n# 限额\n"
        + json.dumps({
            "language": ["php", "python"],
            "max_script_bytes": deps.max_script_bytes,
            "max_jobs": deps.max_jobs,
            "job_timeout_seconds": deps.job_seconds,
            "browser": bool(policy.get("browser", True)),
        }, ensure_ascii=False)
        + "\n调用 resolve_target 取得源码路径到 HTTP 路径的映射。"
    )


def conclude_prompt(finding: dict, deps: PocDeps) -> str:
    jobs = []
    for job in deps.jobs:
        result = dict(job.get("result") or {})
        result.pop("script", None)
        jobs.append({
            "job_id": job.get("job_id"),
            "kind": job.get("kind"),
            "exit_code": job.get("exit_code"),
            "context_id": job.get("context_id"),
            "identity": job.get("identity"),
            "precondition": job.get("precondition"),
            "state_changes": job.get("state_changes"),
            "request": {
                "path": (job.get("request") or {}).get("path"),
                "language": (job.get("request") or {}).get("language"),
                "script_sha256": (job.get("request") or {}).get("script_sha256"),
            },
            "result": result,
            "artifacts": [item.get("name") for item in job.get("artifacts") or []],
        })
    return (
        "# 待验证的源码结论\n"
        + _finding_block(finding)
        + "\n# 执行阶段实际发生的作业（宿主记录）\n"
        + _bound(json.dumps(jobs, ensure_ascii=False, indent=2), 24 * 1024)
        + "\n# 实验前提与状态变化\n"
        + _bound(json.dumps({
            "preconditions": deps.preconditions, "state_changes": deps.state_changes,
            "preconditions_omitted": deps.preconditions_omitted,
        }, ensure_ascii=False), 4 * 1024)
        + "\n# 其他观测（http_observe）\n"
        + _bound(json.dumps(deps.observations[-6:], ensure_ascii=False), 8 * 1024)
        + "\n# 产物\n"
        + json.dumps({"names": sorted(deps.artifacts), "omitted": deps.artifacts_omitted}, ensure_ascii=False)
        + "\n现在只输出一个完整JSON对象提交结论。jobs 只能引用上面出现过的"
        " job_id；normal_evidence/attack_evidence 复制成功作业输出的原文片段；adapted_script 留空。"
    )


async def run_poc_agent(
    *,
    finding: dict,
    deps: PocDeps,
    config: ModelConfig,
    on_event=None,
    agent_invocation_id: str | None = None,
) -> tuple[PocVerificationResult | None, str]:
    """Drive execute + conclude for one finding.  Returns ``(result, reason)``.

    ``reason`` describes why *no conclusion was published*; a published answer, including
    the host-accepted ``inconclusive``, is ``completed`` even when the execution phase
    itself stopped early (its own stop label is reported separately in
    ``poc_execution_finished``).  Mixing the two used to make a usable verdict look like a
    failed run: a conclusion phase that published after an exhausted exploration budget
    inherited ``budget`` as the whole agent's reason.
    """
    emit = on_event or (lambda event: None)
    if deps.should_stop is not None and deps.should_stop():
        return None, "interrupted"
    budgets = {
        "responses": max(2, int(deps.policy.get("max_steps", 8))) + 3,
        "tools": max(4, int(deps.policy.get("max_jobs", 8)) * 3 + 12),
        "seconds": max(1, int(deps.policy.get("max_seconds", 300))),
    }
    allowance = deps.policy.get("max_responses")
    if type(allowance) is int:
        # A discovery-first invocation gets only the remaining POC allocation.
        # Its execution phase must leave all three publication responses intact.
        if allowance < 4:
            raise StopAudit("stage_budget_exhausted", "剩余额度不足以执行并发布 POC 结论")
        budgets["responses"] = min(budgets["responses"], allowance)
    execution = Execution(
        budgets,
        AgentPolicy(code_seconds=budgets["seconds"] + 5),
        emit,
        agent_invocation_id=agent_invocation_id or uuid.uuid4().hex,
    )
    deps.execution = execution
    deps.withdraw_on_job_limit = True
    loop = asyncio.get_running_loop()
    agent = None
    model = None
    reason = "completed"

    execution.enter("poc_execute")
    # Reserve the last responses for the conclusion phase.  Without this cap an
    # exploratory loop can consume the shared budget and the agent is forced to end
    # with `budget`, even though it did collect usable observations.
    execute_gate = PhaseGate(
        execution=execution,
        loop=loop,
        dispatch=deps.call,
        deadline=execution.started + budgets["seconds"] * 0.75,
        limit=max(1, budgets["responses"] - 3),
        callback_seconds=min(budgets["seconds"], deps.job_seconds + 40),
        output_model=None,
    )
    try:
        model = build_code_model(
            config, gate=execute_gate,
            max_tokens=max(512, int(deps.policy.get("max_tokens") or AgentPolicy().poc_max_tokens)),
        )
        agent = build_agent(
            model=model,
            gate=execute_gate,
            tools=build_tools(
                POC_TOOLS,
                execute_gate,
                final_answer=FinalAnswerTool(
                    execute_gate,
                    description='结束探索阶段。answer 任意字符串即可；验证结论在下一阶段提交。',
                ),
            ),
            instructions=execute_instructions(deps),
            max_steps=max(1, int(deps.policy.get("max_steps", 8))),
            name="poc",
            # The audit template talks about a frozen snapshot and its navigation tools;
            # this agent has neither, and a model told to use them spends its steps on
            # imports that cannot exist here.
            templates=prompt_templates("poc"),
        )
        await drive_phase(
            agent,
            execute_gate,
            execute_prompt(finding, deps, deps.policy),
            max_steps=max(1, int(deps.policy.get("max_steps", 8))),
        )
    except StopAudit as exc:
        if exc.reason in {"run_budget_exhausted", "stage_budget_exhausted", "interrupted", "cancelled"}:
            raise
        reason = exc.reason
    except ModelCallFailed as exc:
        reason = exc.reason
        execution.emit({"kind": "poc_execution_failed", "reason": str(exc)[:400]})
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # A broken phase must not fail the audit run.
        reason = "agent_error"
        execution.emit({"kind": "poc_execution_failed", "reason": type(exc).__name__})

    # The execution phase's own stop label, kept apart from the conclusion's: the agent
    # may still publish a verdict after an exhausted exploration budget, and that verdict
    # is what the record should call the outcome.
    execution.emit({
        "kind": "poc_execution_finished",
        "reason": reason,
        "jobs": len(deps.jobs),
        "scripts": len(deps.scripts),
    })

    if reason == "environment_unavailable":
        return None, reason

    if agent is None or model is None:
        return None, reason
    if execution.remaining() <= 1:
        execution.emit({
            "kind": "poc_conclusion_failed",
            "reason": "timeout",
            "message": "结论阶段开始前运行已到期",
        })
        return None, "timeout"

    # ``None`` means "the conclusion loop ended without an exception": only then can a
    # missing publication be labelled a format failure rather than a budget/timeout one.
    conclusion_reason: str | None = None
    execution.enter("poc_conclude")
    conclude_gate = PhaseGate(
        execution=execution,
        loop=loop,
        dispatch=deps.call,
        deadline=execution.deadline,
        limit=execution.attempts + 1 + execution.policy.output_corrections,
        callback_seconds=min(budgets["seconds"], deps.job_seconds + 40),
        output_model=PocVerificationResult,
        validate=lambda value: host_check(value, deps),
    )
    try:
        await drive_structured_phase(
            model, conclude_gate, CONCLUDE_INSTRUCTIONS,
            conclude_prompt(finding, deps) + "\n# JSON字段契约\n" + json.dumps(
                PocVerificationResult.model_json_schema(), ensure_ascii=False, separators=(",", ":"),
            ), max_steps=1 + execution.policy.output_corrections,
        )
    except StopAudit as exc:
        if exc.reason in {"run_budget_exhausted", "stage_budget_exhausted", "interrupted", "cancelled"}:
            raise
        conclusion_reason = exc.reason
        execution.emit({
            "kind": "poc_conclusion_failed",
            "reason": exc.reason,
            "message": str(exc)[:400],
        })
    except ModelCallFailed as exc:
        conclusion_reason = exc.reason
        execution.emit({
            "kind": "poc_conclusion_failed",
            "reason": exc.reason,
            "message": str(exc)[:400],
        })
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        conclusion_reason = "agent_error"
        execution.emit({
            "kind": "poc_conclusion_failed",
            "reason": "agent_error",
            "message": type(exc).__name__,
        })

    if conclude_gate.published is not None:
        # An ``inconclusive`` the host accepted is a conclusion, not a failure: the host
        # checked it against the runner's records and recorded it as what it is.
        return conclude_gate.published, "completed"
    if conclusion_reason is None:
        # The loop returned without publishing and without raising: it used its steps
        # (including the library's last-chance request) and never handed anything in.
        conclusion_reason = "invalid_output"
        execution.emit({
            "kind": "poc_conclusion_failed",
            "reason": conclusion_reason,
            "message": "结论阶段结束，但没有提交可校验的 final_answer",
        })
    return None, conclusion_reason
