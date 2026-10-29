"""The POC agent: turn one source finding into an executable check in Lab30 shop.

The agent runs in two phases.  ``poc_execute`` is free to adapt the recorded POC and
run it through the isolated runner; ``poc_conclude`` has the tools withdrawn and must
answer with a :class:`PocVerificationResult`.  The host then fact-checks that answer
against the runner's own job records before anything is written as a verdict, so a
model that claims success without a successful job cannot publish one.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from typing import Any

from .agent import build_code_model
from .codemodel import ModelCallFailed, PhaseGate
from .config import ModelConfig
from .executor import build_agent, drive_phase, prompt_templates
from .poc_runner import PocRunnerError, PocRunnerUnavailable
from .runtime import AgentPolicy, Execution, StopAudit
from .structured_output import drive_structured_phase
from .worker_strategies import canonical_vulnerability_type
from .schemas import PocVerificationResult
from .toolkit import Arg, FinalAnswerTool, ToolSpec, build_tools, spec
from .tool_errors import public_value, classify_failure

from .poc_tool_service import (  # noqa: F401 - public compatibility surface
    MAX_SCRIPT,
    MAX_TOOL_REPLY,
    PocToolService,
    _clip,
    _http_path_for,
)

STOPWORDS = frozenset({
    "admin", "password", "error", "true", "false", "http", "https", "html", "body",
    "div", "span", "function", "return", "echo", "print", "with", "this", "that",
    "from", "have", "will", "your", "which", "there", "their", "about", "after",
    "before", "using", "user", "users", "input", "output", "response", "request",
})
_TOKEN = re.compile(r"[A-Za-z0-9_.:/-]{4,}")


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


class PocDeps(PocToolService):
    """The legacy code-action loop's view of :class:`PocToolService`.

    Dispatch lives on the service, so one runner contract serves both the legacy
    loop and the Claude SDK adapter.  This name is kept because callers, tests and
    type annotations refer to it; it adds no behaviour of its own.
    """


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


def _evidence_channels(job: dict) -> tuple[str, ...]:
    if job.get("kind") == "http":
        return ("body", "headers", "body_text")
    if job.get("kind") == "script":
        return ("stdout", "stderr")
    if job.get("kind") == "browser":
        return ("body_text", "dialogs", "evaluated")
    return ()


def _evidence_channel(job: dict, channel: str) -> str:
    result = job.get("result") or {}
    if job.get("kind") == "http":
        if channel in {"body", "body_text"}:
            return str(result.get("body") or "")
        if channel == "headers":
            return "\n".join(f"{key}: {value}" for key, value in sorted((result.get("headers") or {}).items()))
        return ""
    if channel not in _evidence_channels(job):
        return ""
    value = result.get(channel)
    return "\n".join(str(item) for item in value) if isinstance(value, list) else str(value or "")


def _usable_evidence_job(job: dict, deps: PocDeps) -> bool:
    return (
        bool(deps.context_id) and job.get("context_id") == deps.context_id
        and (job.get("precondition") or {}).get("ok") is True
        and not (job.get("result") or {}).get("timed_out")
        and not (job.get("result") or {}).get("error")
        and successful_job(job)
    )


def evidence_errors(result: PocVerificationResult, deps: PocDeps) -> list[str]:
    """Diagnose a deterministic verdict without changing the submitted candidate."""
    notes: list[str] = []
    by_id = {str(job.get("job_id") or ""): job for job in deps.jobs if job.get("job_id")}
    supporting: list[dict] = []
    if result.status in {"verified", "rejected"}:
        if not result.jobs:
            notes.append("缺少成功作业支撑：jobs 必须明确引用本次验证的成功作业")
        for ident in result.jobs:
            job = by_id.get(ident)
            if job is None:
                notes.append(f"未知作业引用：{ident}")
            elif not _usable_evidence_job(job, deps):
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
                if ref.job_id not in result.jobs or job is None or not _usable_evidence_job(job, deps):
                    notes.append(f"{label}引用的作业 {ref.job_id} 不可作为成功证据")
                elif ref.channel not in _evidence_channels(job):
                    notes.append(f"{label}作业 {ref.job_id} 的 {ref.channel} 不是有效输出通道（仅 {'/'.join(_evidence_channels(job))}）")
                elif not ref.excerpt.strip() or ref.excerpt not in _evidence_channel(job, ref.channel):
                    notes.append(f"{label}原文片段不在作业 {ref.job_id} 的 {ref.channel} 中")
        if result.status == "verified" and _is_xss(deps.finding):
            attack_browser = [by_id[ref.job_id] for ref in result.attack_evidence
                              if ref.job_id in by_id and _usable_evidence_job(by_id[ref.job_id], deps)
                              and ref.channel in {"dialogs", "evaluated"}]
            if not result.browser_execution or not any(
                (job.get("result") or {}).get("dialogs") or (job.get("result") or {}).get("evaluated")
                for job in attack_browser
            ):
                notes.append("XSS 结论缺少攻击侧浏览器执行证据")
    return notes


def host_check(result: PocVerificationResult, deps: PocDeps) -> PocVerificationResult:
    """Fail closed on invalid evidence, including callers outside the publication loop."""
    notes = evidence_errors(result, deps)
    by_id = {str(job.get("job_id") or ""): job for job in deps.jobs if job.get("job_id")}
    if result.status in {"not_applicable", "environment_unavailable"}:
        result.status, result.verdict = "inconclusive", "uncertain"
        notes.append("模型自报的环境结论由宿主覆盖为 inconclusive")

    # Never replace a cited successful script with the last (possibly failed) attempt.
    cited = [ref.job_id for ref in result.attack_evidence] + list(result.jobs)
    selected = next((ident for ident in cited if ident in deps.job_scripts
                     and ident in by_id and _usable_evidence_job(by_id[ident], deps)), None)
    result.adapted_script = deps.job_scripts[selected] if selected else ""
    if notes and result.status in {"verified", "rejected"}:
        result.status, result.verdict = "inconclusive", "uncertain"
        result.adapted_script = ""
        result.summary = "宿主证据校验未通过，当前结论无法确定。"
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
excerpt 必须复制该 job 的对应通道内一段短且连续的原文，保留原始字符与换行。
不要添加 .../省略号，不要删去中间行后拼接，不要改写HTML、引号或转义；可用多个引用分别引用不同片段。
state_changes/precondition/postcondition 是宿主状态元数据，不能写成 stdout/body_text 等通道中的原文。
宿主拒绝引用后，只修正 JSON 中的引用或改为 inconclusive；工具不会重新开放，不重复实验。
headers 原文格式为每行“header-name: value”，按字段名排序；body_text 仅作为旧HTTP引用别名。
两侧可引用同一个成功作业。成功完成HTTP并不证明漏洞成立，状态码、退出码不能替代实际影响与正常/攻击对照。
XSS 必须引用攻击侧浏览器 dialogs/evaluated 的真实执行证据，HTTP反射不是浏览器执行。
未知、非零退出、超时、错误上下文及身份前提未核实的作业不能支撑确定性结论。
verified 表示对照证明漏洞影响；rejected 表示有效实验明确否定当前结论；失败、前提不符或证据不足均为 inconclusive。
not_applicable/environment_unavailable仅由宿主决定。adapted_script留空，宿主仅从支撑结论的成功作业补齐。
summary只写一句结论，evidence_notes简短说明局限，不重复整份作业输出。
示例：{"status":"inconclusive","summary":"对照证据不足，保留待验证","jobs":[],"normal_evidence":[],"attack_evidence":[]}
字段契约由宿主提供；只输出JSON。"""

def _context_json(value: Any, limit: int) -> str:
    """Bound metadata structurally, without cutting a serialized JSON document."""
    text = json.dumps(value, ensure_ascii=False)
    if len(text.encode("utf-8")) <= limit:
        return text
    for size, items in ((2048, 16), (512, 8), (128, 4), (32, 2)):
        text = json.dumps({"host_truncated": True, "data": _clip(value, size, items)}, ensure_ascii=False)
        if len(text.encode("utf-8")) <= limit:
            return text
    return json.dumps({"host_truncated": True, "data_omitted": True})


def _output_segments(text: str, byte_limit: int) -> dict:
    """Keep exact, separate raw-output windows; omission markers are never evidence."""
    encoded = text.encode("utf-8")
    if byte_limit <= 0:
        segments = []
    elif len(encoded) <= byte_limit:
        segments = [{"offset": 0, "text": text}] if text else []
    else:
        first = encoded[:byte_limit // 2].decode("utf-8", "ignore")
        last = encoded[-(byte_limit // 2):].decode("utf-8", "ignore")
        segments = [{"offset": 0, "text": first}, {"offset": len(text) - len(last), "text": last}]
    return {
        "segments": segments, "total_characters": len(text),
        "omitted_characters": len(text) - sum(len(part["text"]) for part in segments),
    }


def _conclusion_jobs(deps: PocDeps) -> str:
    """Share the existing 24KiB across jobs instead of hiding later experiments."""
    for output_bytes in (16384, 8192, 4096, 2048, 1024, 512, 256, 128, 64, 0):
        jobs = []
        for job in deps.jobs:
            result = job.get("result") or {}
            precondition = job.get("precondition") or {}
            channels = {
                # At the tightest level omit bulky pages before browser execution
                # proof. Never drop every dialog just because there are 32 pages.
                channel: _output_segments(_evidence_channel(job, channel), output_bytes or (
                    128 if job.get("kind") == "browser" and channel in {"dialogs", "evaluated"} else 0
                ))
                for channel in _evidence_channels(job)
                if not (job.get("kind") == "http" and channel == "body_text")
                and _evidence_channel(job, channel)
            }
            jobs.append({
                "job_id": job.get("job_id"), "kind": job.get("kind"),
                "context_id": job.get("context_id"), "identity": job.get("identity"),
                "exit_code": job.get("exit_code"), "evidence_usable": _usable_evidence_job(job, deps),
                "precondition": {
                    "ok": precondition.get("ok"),
                    "reason": str(precondition.get("reason") or "")[:128],
                },
                "result": {key: _clip(result.get(key), 256, 8) for key in (
                    "status", "execution_status", "http_status", "timed_out", "error", "truncated",
                ) if key in result},
                "request": {key: _clip((job.get("request") or {})[key], 256, 8)
                            for key in ("path", "language", "script_sha256")
                            if (job.get("request") or {}).get(key) is not None},
                "evidence_channels": channels,
            })
        text = json.dumps({
            "items": jobs, "total": len(jobs), "omitted_jobs": 0,
            "output_truncated": not output_bytes or any(
                channel["omitted_characters"] for job in jobs for channel in job["evidence_channels"].values()
            ),
        }, ensure_ascii=False, separators=(",", ":"))
        if len(text.encode("utf-8")) <= 24 * 1024:
            return text
    # Job IDs are host-generated, and policy permits at most 32 jobs. This only
    # handles malformed external metadata; never shorten an ID or imply success.
    return json.dumps({"items": [{"job_id": job.get("job_id"), "kind": job.get("kind"),
                                "evidence_usable": False} for job in deps.jobs],
                       "total": len(deps.jobs), "omitted_jobs": 0,
                       "output_truncated": True, "metadata_unavailable": True}, ensure_ascii=False)


def _finding_block(finding: dict) -> str:
    payload = {
        key: finding.get(key)
        for key in (
            "id", "title", "category", "vulnerability_type", "severity", "file_path", "symbol", "summary",
            "evidence", "input_source", "propagation", "dangerous_operation",
            "protection", "preconditions", "missing_context", "poc", "remediation",
        )
    }
    return _context_json(payload, 12 * 1024)


def execute_prompt(finding: dict, deps: PocDeps, policy: dict) -> str:
    return (
        "# 待验证的源码结论\n"
        + _finding_block(finding)
        + "\n# 靶场（宿主已准备）\n"
        + _context_json(deps.prepared, 4 * 1024)
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
    return (
        "# 待验证的源码结论\n"
        + _finding_block(finding)
        + "\n# 执行阶段实际发生的作业（宿主记录）\n"
        + _conclusion_jobs(deps)
        + "\n证据仅从 evidence_usable=true 的作业 evidence_channels 中复制。每个 segments[].text "
        "都是对应通道的连续原文；offset 为字符位置，omitted_characters 表示未展示的字符数。"
        "不要把分开的 segments 拼成一个 excerpt，也不要把省略标记、元数据或状态变化当成输出。"
        + "\n# 实验前提与状态变化\n"
        + _context_json({
            "preconditions": deps.preconditions, "state_changes": deps.state_changes,
            "preconditions_omitted": deps.preconditions_omitted,
        }, 4 * 1024)
        + "\n# 其他观测（http_observe）\n"
        + json.dumps({"count": len(deps.observations), "note": "HTTP 原文已列入上述作业，不重复展开。"}, ensure_ascii=False)
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
    rejected_conclusion: PocVerificationResult | None = None

    def validate_conclusion(value: PocVerificationResult) -> PocVerificationResult:
        nonlocal rejected_conclusion
        errors = evidence_errors(value, deps)
        if errors:
            # Keep a separate, fail-closed diagnostic result. Refusing the original
            # candidate lets the existing JSON correction loop spend its reserved
            # responses; it never reopens the execution phase or submits another job.
            rejected_conclusion = host_check(value.model_copy(deep=True), deps)
            execution.emit({
                "kind": "poc_evidence_rejected", "phase": "poc_conclude",
                "errors": errors[:12], "jobs": list(value.jobs),
            })
            raise ValueError(
                "证据引用未通过校验。excerpt须为对应job/channel中短且连续的逐字原文，"
                "不得添加省略号或拼接。脚本仅stdout/stderr，HTTP仅body/headers（旧别名body_text），"
                "浏览器仅body_text/dialogs/evaluated；state_changes不是输出通道。"
                "无原文支撑时改为inconclusive。具体问题：" + "；".join(errors)
            )
        return host_check(value.model_copy(deep=True), deps)

    execution.enter("poc_conclude")
    conclude_gate = PhaseGate(
        execution=execution,
        loop=loop,
        dispatch=deps.call,
        deadline=execution.deadline,
        limit=execution.attempts + 1 + execution.policy.output_corrections,
        callback_seconds=min(budgets["seconds"], deps.job_seconds + 40),
        output_model=PocVerificationResult,
        validate=validate_conclusion,
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
    if rejected_conclusion is not None:
        # Even when all corrections fail, retain the actual jobs and diagnosis as
        # inconclusive history. No rejected deterministic claim can be published.
        rejected_conclusion.evidence_notes = (
            rejected_conclusion.evidence_notes
            + f"\n结论纠正未完成（{conclusion_reason}），保留原作业与校验诊断。"
        )[:4000]
        return rejected_conclusion, conclusion_reason
    return None, conclusion_reason
