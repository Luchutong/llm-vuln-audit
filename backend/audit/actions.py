"""Project-owned action extraction; model prose is never a durable diagnostic."""
from __future__ import annotations

import ast
import io
import re
import token
import tokenize
from dataclasses import dataclass

from smolagents.local_python_executor import check_import_authorized


@dataclass(frozen=True)
class ActionIssue(ValueError):
    category: str
    hint: str

    def __str__(self) -> str:
        return f"{self.category}: {self.hint}"


HINTS = {
    "no_code_block": "请只输出一个完整的 <code>Python 动作</code> 或 ```python 代码块；最终结果在块内调用 final_answer(...)。",
    "ambiguous_code_blocks": "检测到多个代码块；请合并为一个 Python 动作块，不会自动拼接执行。",
    "incomplete_code": "动作代码块没有闭合；请重新提交完整代码块，不会自动补造缺失代码。",
}


def _protected_ranges(body: str) -> list[tuple[int, int]]:
    """Locate Python strings/comments before looking for transport terminators."""
    lines = body.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    protected = []
    try:
        for item in tokenize.generate_tokens(io.StringIO(body).readline):
            if item.type in {tokenize.STRING, tokenize.COMMENT} or token.tok_name.get(item.type, "").startswith("FSTRING"):
                protected.append((offsets[item.start[0] - 1] + item.start[1], offsets[item.end[0] - 1] + item.end[1]))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        # A closing XML transport tag is not Python; preceding string tokens are
        # still sufficient to avoid treating their contents as transport syntax.
        pass
    return protected


def extract_action(text: str, finish_reason: str | None = None,
                   transport_tags: tuple[str, str] | None = None) -> tuple[str | None, dict, ActionIssue | None]:
    """Accept one action; Python string contents never become a second container."""
    xml_pairs = [("<code>", "</code>")]
    if transport_tags and transport_tags not in xml_pairs:
        xml_pairs.append(transport_tags)
    open_pattern = "|".join(re.escape(pair[0]) for pair in xml_pairs)
    opening = re.compile(open_pattern + r"|^```(?:python|py)?[^\S\n]*\n", re.M | re.I)
    blocks = []
    counts = {"xml_blocks": 0, "markdown_blocks": 0, "closed_blocks": 0}
    cursor = 0
    incomplete = False
    omitted = False
    while match := opening.search(text, cursor):
        is_markdown = match.group().startswith("```")
        kind = "markdown_blocks" if is_markdown else "xml_blocks"
        counts[kind] += 1
        end_marker = next((close for start, close in xml_pairs if start.lower() == match.group().lower()), None)
        body = text[match.end():]
        protected = _protected_ranges(body)
        closing = re.compile(r"^```[^\S\n]*(?:$|\n)" if is_markdown else re.escape(end_marker), re.M | re.I)
        close = next((candidate for candidate in closing.finditer(body)
                      if not any(start <= candidate.start() < end for start, end in protected)), None)
        if close is not None:
            blocks.append(body[:close.start()].strip())
            counts["closed_blocks"] += 1
            cursor = match.end() + close.end()
            continue
        # A provider may strip the requested stop marker, but never complete Python.
        try:
            complete = finish_reason != "length" and bool(ast.parse(body.strip()).body)
        except SyntaxError:
            complete = False
        if complete:
            blocks.append(body.strip())
            omitted = True
        else:
            incomplete = True
        break
    if omitted:
        counts["closing_tag_omitted"] = True
    category = "ambiguous_code_blocks" if len(blocks) > 1 else "incomplete_code" if incomplete else "no_code_block" if not blocks else None
    if category:
        return None, counts, ActionIssue(category, HINTS[category])
    return blocks[0], counts, None


def check_action(code: str, authorized_imports: list[str], diagnostics: dict) -> None:
    """Validate the entire block before any host tool can produce side effects."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        diagnostics.update(syntax_line=exc.lineno, syntax_offset=exc.offset)
        raise ActionIssue("invalid_python", f"第 {exc.lineno} 行、第 {exc.offset} 列：{exc.msg}。请重交完整 Python；循环必须含冒号和缩进体。") from None
    for node in ast.walk(tree):
        imports = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module or ""] if isinstance(node, ast.ImportFrom) else []
        for module in imports:
            if not module or (isinstance(node, ast.ImportFrom) and node.level) or not check_import_authorized(module, authorized_imports):
                diagnostics["syntax_line"] = node.lineno
                label = "Import from" if isinstance(node, ast.ImportFrom) else "Import of"
                raise ActionIssue("unauthorized_import", f"{label} {module} is not allowed. 第 {node.lineno} 行；宿主仅允许 {', '.join(sorted(authorized_imports))}；网络、文件和进程操作请放进 runner 脚本。")
