"""The POC agent: turn one source finding into an executable check in DVWA.

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

from .agent import build_code_model
from .codemodel import ModelCallFailed, PhaseGate
from .config import ModelConfig
from .executor import attach_phase, build_agent, drive_phase, prompt_templates
from .poc_runner import PocRunnerClient, PocRunnerError, PocRunnerUnavailable
from .runtime import AgentPolicy, Execution, StopAudit
from .schemas import PocVerificationResult
from .toolkit import Arg, FinalAnswerTool, ToolSpec, build_tools, spec

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
        "resolve_target",
        "Return the executable mapping for this finding: the DVWA base URL, login credentials, "
        "current security level, and the HTTP path that corresponds to the finding's source file. "
        "This is host data; it does not prove anything.",
        finding_id=Arg("string", "本次验证的 finding id（必须与提示中的一致）。"),
    ),
    spec(
        "target_status",
        "Return target reachability, authentication state, security level and version.",
    ),
    spec(
        "target_prepare",
        "Reset the DVWA database, log in and set the security level. The host runs this once before "
        "the agent starts; call it again only when the target state was disturbed.",
        reset=Arg("boolean", "是否重置数据库。默认 True。", True),
    ),
    spec(
        "run_poc",
        "Execute a POC script inside the isolated runner and return bounded stdout/stderr, exit code "
        "and artifact metadata. The script may reach only the DVWA base URL. It must log in itself: "
        "the runner does not inject cookies into scripts.",
        language=Arg("string", "php 或 python。"),
        script=Arg("string", "完整脚本内容（<= 32 KiB）。"),
        timeout_seconds=Arg("integer", "执行超时（秒），1-120。默认 30。", 30),
        artifacts=Arg("array", "脚本写出的、需要取回的相对文件名列表（<= 8 个）。默认空列表。", []),
    ),
    spec(
        "http_observe",
        "Send one GET/POST to an allowlisted DVWA path through the isolated runner and return status, "
        "redirects and a bounded body preview. Use it for server-side checks; use browser_check for "
        "anything that depends on JavaScript executing.",
        path=Arg("string", "DVWA 内的绝对路径，例如 /login.php 或 /vulnerabilities/sqli/?id=1。"),
        method=Arg("string", "GET 或 POST。默认 GET。", "GET"),
        body=Arg("string", "POST 请求体（application/x-www-form-urlencoded）。默认空串。", ""),
        content_type=Arg("string", "POST 的 Content-Type。默认 application/x-www-form-urlencoded。", "application/x-www-form-urlencoded"),
    ),
    spec(
        "browser_check",
        "Load an allowlisted DVWA path in Chromium, wait, and return title, alert dialogs, console "
        "errors, body text, and a screenshot artifact. Required for XSS conclusions.",
        path=Arg("string", "DVWA 内的绝对路径。"),
        wait_ms=Arg("integer", "加载后等待毫秒数，0-10000。默认 1000。", 1000),
        script=Arg("string", "可选：在页面中求值的 JavaScript，用于构造触发条件。默认空串。", ""),
    ),
    spec(
        "save_artifact",
        "Keep a small textual observation (<= 64 KiB) as an evidence artifact. Use it for derived "
        "analysis, not for replacing raw runner output.",
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
            "host_truncated": True,
            "error": "tool_reply_too_large",
            "message": "工具返回超出宿主限额，正文已省略；请缩小查询范围后重试。",
        }, ensure_ascii=False)

    async def call(self, name: str, args: dict) -> str:
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
            "args": args,
            "turn": execution.tools,
            "call_id": call_id,
            "span_id": span_id,
            "phase": execution.phase,
            "started_elapsed_ms": round((started - execution.started) * 1000),
        })
        status = "ok"
        error_type = ""
        text = ""
        try:
            handler = getattr(self, f"_{name}", None)
            if handler is None:
                status = "unknown_tool"
                text = self._reply({"error": "unknown_tool", "tool": name})
            else:
                text = await handler(args)
        except asyncio.CancelledError:
            status = "cancelled"
            raise
        except StopAudit:
            status = "cancelled"
            raise
        except PocRunnerUnavailable as exc:
            status = "runner_unavailable"
            error_type = type(exc).__name__
            self.runner_error = str(exc)[:400]
            execution.emit({"kind": "poc_runner_unavailable", "error": self.runner_error})
            text = self._reply({"error": "runner_unavailable", "message": self.runner_error})
        except PocRunnerError as exc:
            status = "runner_rejected"
            error_type = type(exc).__name__
            execution.emit({"kind": "poc_runner_rejected", "error": str(exc)[:400]})
            text = self._reply({"error": "runner_rejected", "message": str(exc)[:400]})
        except Exception as exc:
            # Hand the failure to the interpreter (which shows it as the step's
            # observation) but leave a paired result in the durable trace first.
            status = "error"
            error_type = type(exc).__name__
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
            if error_type:
                result["error_type"] = error_type
            execution.emit(result)
        return text

    # --- tools -----------------------------------------------------------------

    async def _resolve_target(self, args: dict) -> str:
        finding = self.finding
        path = str(finding.get("file_path") or "")
        return self._reply({
            "finding_id": finding.get("id"),
            "source_path": path,
            "target": self.target,
            "base_url": self.prepared.get("base_url") or "",
            "login": {"username": "admin", "password": "password"},
            "security": self.prepared.get("security") or "low",
            "version": self.prepared.get("version") or "",
            "http_path_hint": _http_path_for(path),
            "note": "上传源码树的根目录对应 DVWA 根 /；先按 http_path_hint 打开同一功能。",
        })

    async def _target_status(self, args: dict) -> str:
        return self._reply(await self.client.target_status(self.target))

    async def _target_prepare(self, args: dict) -> str:
        result = await self.client.prepare_target(
            self.target, reset=bool(args.get("reset", True))
        )
        self.prepared = result
        return self._reply(result)

    async def _run_poc(self, args: dict) -> str:
        if len(self.jobs) >= self.max_jobs:
            return self._reply({"error": "job_limit", "message": f"本 finding 最多执行 {self.max_jobs} 个作业"})
        language = str(args.get("language") or "").casefold()
        script = args.get("script")
        if not isinstance(script, str) or not script.strip():
            return self._reply({"error": "empty_script"})
        if len(script.encode("utf-8")) > self.max_script_bytes:
            return self._reply({"error": "script_too_large", "limit": self.max_script_bytes})
        if language not in {"php", "python"}:
            return self._reply({"error": "unsupported_language", "allowed": ["php", "python"]})
        requested = [str(item) for item in (args.get("artifacts") or [])][:8]
        timeout = max(1, min(120, int(args.get("timeout_seconds") or self.job_seconds)))
        job = await self.client.run_job(
            target=self.target,
            language=language,
            script=script,
            timeout_seconds=timeout,
            artifacts=requested,
        )
        job_id = str(job.get("job_id") or "")
        self.scripts.append(script)
        artifacts = []
        for item in job.get("artifacts") or []:
            name = str(item.get("name") or "")
            if not name:
                continue
            try:
                payload = await self.client.fetch_artifact(job_id, name)
            except (PocRunnerUnavailable, PocRunnerError):
                continue
            self.artifacts[name] = payload
            artifacts.append({
                "name": name,
                "sha256": item.get("sha256") or hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            })
        record = {
            "job_id": job_id,
            "kind": "script",
            "request": {
                "target": self.target,
                "language": language,
                "script_sha256": hashlib.sha256(script.encode("utf-8")).hexdigest(),
                "script": script[:4096],
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
        self.jobs.append(record)
        self.execution.emit({
            "kind": "poc_job_started",
            "job_id": job_id,
            "language": language,
            "script_bytes": len(script.encode("utf-8")),
        })
        self.execution.emit({
            "kind": "poc_job_finished",
            "job_id": job_id,
            "exit_code": job.get("exit_code"),
            "status": job.get("status"),
            "duration_ms": job.get("duration_ms"),
            "truncated": bool(job.get("truncated")),
        })
        return self._reply(record["result"] | {
            "job_id": job_id,
            "artifacts": artifacts,
            "job_number": len(self.jobs),
        })

    async def _http_observe(self, args: dict) -> str:
        path = str(args.get("path") or "")
        result = await self.client.http_observe(
            target=self.target,
            method=str(args.get("method") or "GET"),
            path=path,
            body=str(args.get("body") or ""),
            headers={"Content-Type": str(args.get("content_type") or "application/x-www-form-urlencoded")}
            if str(args.get("body") or "")
            else None,
        )
        method = str(args.get("method") or "GET").upper()
        # The runner sends exactly one request and does not follow redirects, so the
        # status and Location below describe the response the vulnerable code produced.
        # Keeping the headers (not just the flattened redirect list) is what lets the
        # conclusion cite the raw Location value.
        record = {
            "kind": "http",
            "method": method,
            "path": path,
            "status": result.get("status"),
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
        }
        self.observations.append(record)
        self.execution.emit({
            "kind": "poc_http_observed", "method": method,
            "path": path, "status": result.get("status"),
            "location": record["headers"].get("location", ""),
        })
        return self._reply(record)

    async def _browser_check(self, args: dict) -> str:
        if not bool(self.policy.get("browser", True)):
            return self._reply({
                "error": "browser_disabled",
                "message": "该运行未启用浏览器；XSS 类结论只能记为 inconclusive。",
            })
        if len(self.jobs) >= self.max_jobs:
            return self._reply({"error": "job_limit", "message": f"本 finding 最多执行 {self.max_jobs} 个作业"})
        result = await self.client.browser_check(
            target=self.target,
            path=str(args.get("path") or ""),
            script=str(args.get("script") or ""),
            wait_ms=int(args.get("wait_ms") or 1000),
        )
        if not result.get("available", False):
            self.browser_available = False
            return self._reply({"error": "browser_unavailable", "message": "runner 未安装浏览器"})
        job_id = str(result.get("job_id") or "")
        artifacts = []
        for item in result.get("artifacts") or []:
            name = str(item.get("name") or "")
            if not name:
                continue
            try:
                payload = await self.client.fetch_artifact(job_id, name)
            except (PocRunnerUnavailable, PocRunnerError):
                continue
            self.artifacts[name] = payload
            artifacts.append({
                "name": name,
                "sha256": item.get("sha256") or hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            })
        record = {
            "job_id": job_id,
            "kind": "browser",
            "request": {"path": str(args.get("path") or ""), "wait_ms": int(args.get("wait_ms") or 1000)},
            "result": {
                "status": "finished" if not result.get("error") else "failed",
                "available": True,
                "error": result.get("error") or "",
                "title": str(result.get("title") or "")[:500],
                "url": str(result.get("url") or "")[:500],
                "dialogs": [str(item)[:500] for item in result.get("dialogs") or []][:20],
                "console_errors": [str(item)[:500] for item in result.get("console_errors") or []][:20],
                "body_text": str(result.get("body_text") or "")[:4000],
                "evaluated": str(result.get("evaluated") or "")[:2000],
            },
            "exit_code": 0 if not result.get("error") else 1,
            "duration_ms": 0,
            "artifacts": artifacts,
        }
        self.jobs.append(record)
        self.execution.emit({
            "kind": "poc_job_finished",
            "job_id": job_id,
            "kind_detail": "browser",
            "dialogs": len(record["result"]["dialogs"]),
            "status": record["result"]["status"],
        })
        return self._reply(record["result"] | {"job_id": job_id, "artifacts": artifacts})

    async def _save_artifact(self, args: dict) -> str:
        name = str(args.get("filename") or "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name) or name in {".", ".."}:
            return self._reply({"error": "invalid_name"})
        payload = str(args.get("content") or "").encode("utf-8")
        if len(payload) > 64 * 1024:
            return self._reply({"error": "too_large", "limit": 65536})
        self.artifacts[name] = payload
        return self._reply({
            "name": name,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })


def _http_path_for(source_path: str) -> str:
    """A best-effort mapping from a source file to the DVWA URL that exercises it."""
    text = str(source_path or "").replace("\\", "/").strip("/")
    match = re.match(r"vulnerabilities/([^/]+)/", text)
    if match:
        return f"/vulnerabilities/{match.group(1)}/"
    if text in {"login.php", "setup.php", "security.php", "index.php"}:
        return f"/{text}"
    return "/"


def _tokens(text: str) -> set[str]:
    return {
        token.casefold()
        for token in _TOKEN.findall(str(text or ""))
        if len(token) >= 4 and token.casefold() not in STOPWORDS
    }


def _is_xss(finding: dict) -> bool:
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
    )


def _successful_browser(job: dict) -> dict | None:
    if job.get("kind") != "browser":
        return None
    result = job.get("result") or {}
    if not result.get("available") or result.get("error"):
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


def host_check(result: PocVerificationResult, deps: PocDeps) -> PocVerificationResult:
    """Refuse a conclusion the runner's own records do not support.

    Returns the (possibly downgraded) result rather than raising: the agent is not asked
    to re-run an experiment because of a bookkeeping mismatch, and the durable record must
    say what the host actually accepted.  Reasons are appended to ``evidence_notes``.
    """
    notes: list[str] = []
    jobs = deps.jobs
    by_id = {str(job.get("job_id") or ""): job for job in jobs if job.get("job_id")}
    referenced = [by_id[ident] for ident in result.jobs if ident in by_id]
    script_jobs = [job for job in jobs if job.get("kind") == "script"]
    browser_jobs = [job for job in jobs if job.get("kind") == "browser"]
    ok_script = [job for job in script_jobs if _successful_script(job)]
    ok_browser = [job for job in browser_jobs if _successful_browser(job)]
    downgraded = False

    def downgrade(reason: str) -> None:
        nonlocal downgraded
        downgraded = True
        notes.append(reason)

    if result.status == "not_applicable" or result.status == "environment_unavailable":
        # The host, not the model, owns these two verdicts.
        notes.append("模型自报的 not_applicable/environment_unavailable 被宿主覆盖为 inconclusive")
        result.status = "inconclusive"
        result.verdict = "uncertain"

    if result.status == "verified":
        if not ok_script and not ok_browser:
            downgrade("verified 缺少成功作业支撑")
        if not (result.attack_observation or "").strip():
            downgrade("verified 缺少攻击侧观测")
        if _is_xss(deps.finding):
            markers = [
                item for item in ok_browser
                if (item.get("result", {}).get("dialogs") or item.get("result", {}).get("evaluated"))
            ]
            if not result.browser_execution or not markers:
                downgrade("XSS 结论缺少带对话框/求值标记的浏览器作业")
        if result.attack_observation:
            observed = _tokens(" ".join(_runner_text(job) for job in referenced or jobs))
            claimed = _tokens(result.attack_observation)
            if claimed and not (claimed & observed):
                downgrade("攻击侧观测与 runner 输出没有共同的关键 token")
    elif result.status == "rejected":
        if not ok_script and not ok_browser:
            downgrade("rejected 缺少一次成功执行")
        if not (result.normal_observation or "").strip() or not (result.attack_observation or "").strip():
            downgrade("rejected 需要正常侧与攻击侧两组观测")
        if result.attack_observation:
            observed = _tokens(" ".join(_runner_text(job) for job in referenced or jobs))
            claimed = _tokens(result.attack_observation)
            if claimed and not (claimed & observed):
                downgrade("攻击侧观测与 runner 输出没有共同的关键 token")

    if result.adapted_script and deps.last_script and result.adapted_script != deps.last_script:
        result.adapted_script = deps.last_script
        notes.append("adapted_script 已替换为实际执行的最后一份脚本")
    elif not result.adapted_script and deps.last_script and result.status in {"verified", "rejected"}:
        result.adapted_script = deps.last_script
        notes.append("adapted_script 由宿主按实际执行的最后一份脚本补齐")

    if downgraded and result.status in {"verified", "rejected"}:
        result.status = "inconclusive"
        result.verdict = "uncertain"
    if notes:
        prefix = "；".join(notes)
        result.evidence_notes = (prefix + ("\n" + result.evidence_notes if result.evidence_notes else ""))[:4000]
    return result


EXECUTE_INSTRUCTIONS = """你是 POC 自动验证 Agent 的执行阶段。你的任务是在隔离的本地 DVWA 靶场中，
为一条已经由源码审计得出的漏洞编写并实际执行最小 POC，取得正常侧与攻击侧的对照观测。

工具契约：
- 这里的工具是普通 Python 函数，直接调用；**返回值一律是 JSON 字符串**。用 `import json` 和
  `json.loads(...)` 取字段，不要对返回值直接调用 `.get()`（那是 str，会报错）。
- 你自己的解释器只能做内存计算：不能联网、不能读写文件、不能启动进程。真正接触靶场的只有
  run_poc / http_observe / browser_check 三个工具，它们由宿主转发给隔离 runner。
- 这里没有源码工具：`read_source`、`search_code`、`list_tree` 都不存在，`from tools import ...`
  会直接失败。待验证的源码结论已经完整写在任务消息里。

访问语义：
- run_poc：脚本在隔离容器里执行，只有脚本内部可以使用标准库 urllib / curl 等网络能力。
  脚本必须自己登录 DVWA：GET /login.php 读取 `name='user_token' value='...'`，再 POST
  username=admin、password=password、Login=Login、user_token=...。只准访问 http://dvwa。
- http_observe：宿主代发**恰好一个**请求，**不跟随重定向**。返回首个响应的 status、url、
  headers（含 location）、redirects、body；`redirects` 只记录这个 Location，不代表它被访问过。
  开放重定向类漏洞的证据就是首个 3xx 与它发出的 Location，不要试图把它"跟完"。
- browser_check：在隔离浏览器中加载页面，返回对话框、console 错误与截图。XSS 类结论必须
  用它观察到弹窗或页面求值结果；仅凭 HTTP 响应中的字符串不能算验证成功。

标准库登录与两种 opener 的写法（这是交给 run_poc 的脚本内容，不是你的动作代码块）：

```python
import urllib.request, urllib.error, urllib.parse, http.cookiejar, re

BASE = "http://dvwa"
jar = http.cookiejar.CookieJar()

# 登录用会跟随重定向的 opener：登录成功后 DVWA 返回 302 到 index.php。
login = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
html = login.open(BASE + "/login.php", timeout=10).read().decode("utf-8", "replace")
token = re.search(r"name='user_token'\\s+value='([^']+)'", html).group(1)
login.open(BASE + "/login.php", timeout=10, data=urllib.parse.urlencode({
    "username": "admin", "password": "password", "Login": "Login", "user_token": token,
}).encode()).read()

# 观测用禁止重定向的 opener，并与登录共用同一个 CookieJar。
# handler 必须在 build_opener 时传入；事后再 add_handler 不会覆盖默认的跳转 handler。
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
observe = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)

def location(path):
    try:
        response = observe.open(BASE + path, timeout=10)
        return response.status, response.headers.get("Location")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Location")

print("CONTROL", location("/vulnerabilities/open_redirect/source/low.php?redirect=info.php%3Fid%3D1"))
print("ATTACK", location("/vulnerabilities/open_redirect/source/low.php?redirect=%2F%2Fevil.com"))
```

规则：
- 先做正常请求（例如 id=1），再做攻击请求；两者输出都要保留，作为对照。
- 每次执行都要把真正的命令行输出当作证据，不要编造；失败就换一种最小写法重试。

适配要点（历史实测中反复导致验证失败的四种写法，必须避开）：
- 登录自检：脚本每次请求后要确认已经处于登录态（例如 /index.php 响应含 Logout 或目标页面的
  表单/功能链接）。登录失败或把登录页当结果输出时不要硬跑攻击，先修正登录再重试；
  "脚本成功退出"不等于"验证成功"。
- 对照优先：判断漏洞靠正常侧与攻击侧的**差异**，不是靠攻击响应里出现任何字符串。
  SQLi 看结果行数/字段/报错的变化或唯一标记；命令注入看唯一回显标记
  （例如 PWNED_$(id -u) 这种专属字符串，不要 grep "root"、"/bin/sh" 等常见词，避免正常侧误命中）；
  XSS 必须用 browser_check 观察到弹窗或页面求值，HTTP 反射出来的 payload 不算。
- payload 上下文：攻击 payload 必须适配目标页面的上下文（SQL 语句中的引号闭合、HTML 属性/标签
  位置、URL 编码规则）。不确定时先发一次正常请求观察回显结构，再构造 payload；一次不成立就换
  最小变体（如引号配对、注释符、编码方式），不要在一个错误 payload 上反复重试。
- 结果自证：脚本要把正常侧与攻击侧的原始输出都打印出来，作为 attack_observation 里可以核对
  的 token；观测里必须出现脚本真实输出的内容，不要凭假设复述。
- 探索阶段结束时调用 final_answer("探索结束")；验证结论在下一阶段单独提交。
- 不要输出隐藏思维链或逐步推理，代码块之外不要写长篇散文。
"""

CONCLUDE_INSTRUCTIONS = """你是 POC 自动验证 Agent 的结论阶段。执行阶段已经结束，**所有工具都已收回**：
run_poc、http_observe、browser_check 都不再可用，你的解释器也没有网络能力（`import urllib`
会失败）。不要再尝试执行脚本或访问靶场，只能根据宿主列出的作业记录与脚本提交结论。

状态定义：
- verified：至少一个成功作业复现了漏洞，并且攻击侧观测指向实际影响（SQL 数据回显、命令输出、
  文件读取、弹窗执行等）。
- rejected：执行成功，但正常侧与攻击侧结果一致，或攻击载荷没有产生预期影响。
- inconclusive：证据不足、作业失败、超时、或观测无法判定。不要把"没跑通"写成 verified。
- not_applicable / environment_unavailable：这两个是宿主预检的结论，你不要自行使用。

提交协议：本阶段唯一的动作，是在一个代码块里调用 `final_answer(一个普通 dict)`。不要构造宿主的
`PocVerificationResult` 类（解释器里没有这个类，写了只会得到 NameError），也不要把 JSON 或书面报告
直接写在代码块外面——代码块之外的内容不会被执行，也不会被当成结论。字段名照抄下面示例，`jobs`
只能引用宿主列出的 job id：

<code>
final_answer({
    "status": "inconclusive",
    "verdict": "uncertain",
    "summary": "攻击请求与正常请求返回了相同的页面，无法判定影响",
    "normal_observation": "id=1 返回了一条用户记录",
    "attack_observation": "id=1' OR '1'='1 返回了相同的页面",
    "browser_execution": False,
    "adapted_script": "",
    "modification_notes": "",
    "command": "",
    "evidence_notes": "job-1 exit_code=0；对照输出见 stdout",
    "artifacts": [],
    "jobs": ["job-1"]
})
</code>

字段要求：
- summary 用一句话说明结论；verified/rejected 必须同时给出 normal_observation 与 attack_observation。
- attack_observation 必须能在作业 stdout/stderr、浏览器对话框或产物名中找到对应 token；不能只复述
  假设。http_observe 的单次观测可以写进 evidence_notes，但它不是成功作业，不能单独支撑 verified。
- adapted_script 不用重复填写：宿主会按实际执行的最后一份脚本补齐（该脚本已列在任务消息里）。
- 宿主会按 job id 与退出码核对；没有成功作业支撑的 verified 会被降级为 inconclusive。

只输出一个代码块，里面调用一次 final_answer；代码块之外只写一句话的 Thought，不要写散文。"""


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
        + "\n# 实际执行的最后一份脚本\n"
        + _bound(deps.last_script, 12 * 1024)
        + "\n# 其他观测（http_observe）\n"
        + _bound(json.dumps(deps.observations[-6:], ensure_ascii=False), 8 * 1024)
        + "\n# 产物\n"
        + json.dumps(sorted(deps.artifacts), ensure_ascii=False)
        + "\n现在在一个代码块里调用 final_answer(普通 dict) 提交结论。jobs 只能引用上面出现过的"
        " job_id；adapted_script 留空即可，宿主会用上面这份脚本补齐。"
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
    budgets = {
        "responses": max(2, int(deps.policy.get("max_steps", 8))) + 3,
        "tools": max(4, int(deps.policy.get("max_jobs", 8)) * 3 + 12),
        "seconds": max(30, int(deps.policy.get("max_seconds", 300))),
    }
    execution = Execution(
        budgets,
        AgentPolicy(),
        emit,
        agent_invocation_id=agent_invocation_id or uuid.uuid4().hex,
    )
    deps.execution = execution
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
        output_model=None,
    )
    try:
        model = build_code_model(config, gate=execute_gate, max_tokens=4096)
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
            instructions=EXECUTE_INSTRUCTIONS,
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
        output_model=PocVerificationResult,
        validate=lambda value: host_check(value, deps),
    )
    try:
        attach_phase(
            agent,
            tools=build_tools(
                (),
                conclude_gate,
                final_answer=FinalAnswerTool.for_model(
                    conclude_gate, PocVerificationResult, "POC 自动验证结论"
                ),
            ),
            gate=conclude_gate,
            model=model,
            # Without these the loop kept the exploration rules ("write and run a script")
            # while every tool had been withdrawn, and spent the conclusion's steps on
            # imports the interpreter refuses.  The role template loses the HTTP example
            # and the execution tutorial with them; the instructions say exactly how to
            # submit the verdict.
            instructions=CONCLUDE_INSTRUCTIONS,
            templates=prompt_templates("poc_conclude"),
        )
        await drive_phase(
            agent,
            conclude_gate,
            conclude_prompt(finding, deps),
            max_steps=2 + execution.policy.output_corrections,
            reset=True,
        )
    except StopAudit as exc:
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
