"""Tool failures and public diagnostics, separate from source availability."""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any


_SECRET = re.compile(r"(?i)(authorization|api[_-]?key|access[_-]?token|password|cookie|secret)")
_SECRET_NAME = r"(?:authorization|password|api[_-]?key|access[_-]?token|cookie|secret)"
_QUOTED_VALUES = re.compile(
    r"(?P<prefix>[\"']?" + _SECRET_NAME + r"[\"']?\s*[=:]\s*)"
    r"(?P<quote>[\"'])(?:\\.|(?!(?P=quote)).)*(?P=quote)", re.I | re.S,
)
_VALUES = re.compile(r"(?i)(bearer\s+)[^\s\"']+|\bsk-[A-Za-z0-9_-]{12,}|([\"']?" + _SECRET_NAME + r"[\"']?\s*[=:]\s*)[^\s,;}\]\"']+")


def public_value(value: Any, *, key: str = "", depth: int = 0) -> Any:
    """Retain useful real argument shapes without persisting credentials or huge scripts."""
    if _SECRET.search(key):
        return "[redacted]"
    if depth > 6:
        return "[depth limited]"
    if isinstance(value, dict):
        return {str(k): public_value(v, key=str(k), depth=depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, (list, tuple)):
        return [public_value(v, depth=depth + 1) for v in value[:40]]
    if isinstance(value, str):
        value = _QUOTED_VALUES.sub(lambda m: m.group("prefix") + m.group("quote") + "[redacted]" + m.group("quote"), value)
        return _VALUES.sub(lambda m: (m.group(1) or m.group(2) or "") + "[redacted]", value)[:4000]
    return value if value is None or type(value) in {bool, int, float} else f"<{type(value).__name__}>"


@dataclass(frozen=True)
class ToolFailure:
    code: str
    error: str
    hint: str
    cacheable: bool = False

    def fields(self) -> dict:
        return {"error_code": self.code, "error": public_value(self.error), "hint": self.hint}


def classify_failure(exc: BaseException) -> ToolFailure:
    reason = f"{type(exc).__name__}: {str(exc)[:300]}"
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return ToolFailure("timeout", reason, "只读查询可以按相同参数显式重试一次；每次仍消耗预算。")
    if isinstance(exc, FileNotFoundError):
        return ToolFailure("path_not_found", reason, "先用 find_files 或 list_tree 核对快照实际路径；这只表示该路径缺失，不表示代码安全。", True)
    if "binary file is registered" in str(exc).lower():
        return ToolFailure("context_missing", reason, "该文件是快照中的二进制资源，不能作为文本补读；请从源码归档下载原始字节，不要修改参数反复读取。", True)
    if isinstance(exc, PermissionError) or any(word in str(exc).lower() for word in ("outside", "frozen scope", "stay inside", "scope denied", "path traversal", "absolute path")):
        return ToolFailure("scope_denied", reason, "仅使用当前冻结范围内的快照相对路径；不要猜测或绕过范围。")
    if "integrity check failed" in str(exc).lower():
        return ToolFailure("internal_error", reason, "快照完整性校验失败，保留未决状态并检查源码存储。")
    if any(word in str(exc) for word in ("没有可用的项目索引", "没有提供快照", "没有固定调查记录")):
        return ToolFailure("context_missing", reason, "当前运行缺少必要上下文，请保留未决状态并记录具体缺失项。")
    if isinstance(exc, (TypeError, ValueError)):
        return ToolFailure("invalid_arguments", reason, "按工具声明的参数类型、范围和默认值修正；用法错误不等于缺失源码。")
    if isinstance(exc, OSError):
        return ToolFailure("context_missing", reason, "读取环境暂时不可用；保留未决状态，不推断漏洞或安全结论。")
    return ToolFailure("internal_error", reason, "宿主工具异常，保留现有证据并报告未决原因。")


def note_tool_result(execution, key: str, failure: ToolFailure | None) -> None:
    """Count failures and subsequent successful recovery by phase and query."""
    if not hasattr(execution, "tool_diagnostics"):
        execution.tool_diagnostics = {}
        execution.pending_tool_errors = {}
    counts = execution.tool_diagnostics.setdefault(execution.phase, {})
    pending = execution.pending_tool_errors
    identity = (execution.phase, key)
    if failure:
        counts.setdefault(failure.code, {"errors": 0, "recovered": 0})["errors"] += 1
        pending[identity] = failure.code
    elif category := pending.pop(identity, None):
        counts[category]["recovered"] += 1
