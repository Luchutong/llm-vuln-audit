"""Syntax navigation signals. None of these decide exploitability or safety."""
from __future__ import annotations

import re

CALLS = {"function_call_expression", "member_call_expression", "scoped_call_expression", "nullsafe_member_call_expression"}


def php_signals(nodes, content: bytes) -> list[dict]:
    signals = {}

    def text(node):
        return content[node.start_byte:node.end_byte].decode("utf-8", "replace") if node else ""

    def add(node, risk, operation):
        line = node.start_point.row + 1
        signals[(line, risk, operation)] = dict(line=line, risk=risk, operation=operation,
            end_line=node.end_point.row + 1, source="php-syntax-v2")

    for node in nodes:
        if node.type in CALLS:
            callee = node.child_by_field_name("function") or node.child_by_field_name("name")
            name = text(callee).casefold().lstrip("\\")
            if node.type == "function_call_expression" and callee and callee.type not in {"name", "qualified_name"}:
                add(node, "code_execution", "dynamic_call")
            if name in {"md5", "sha1", "crypt", "hash"}:
                add(node, "weak_crypto", "hash_usage_review")
            if name in {"gettraceasstring", "getmessage", "print_r", "var_dump", "phpinfo"}:
                add(node, "info_disclosure", "diagnostic_output_review")
            if name in {"eval", "assert", "create_function", "call_user_func", "call_user_func_array"}:
                add(node, "code_execution", "code_dispatch_review")
            if name in {"simplexml_load_string", "simplexml_load_file", "loadxml"}:
                add(node, "xxe", "xml_parse_review")
            # A real SQL mutation literal nominates a request-origin review. It
            # does not assert that the route is authenticated or lacks CSRF checks.
            if name in {"prepare", "query", "exec"} and re.search(
                r"['\"]\s*(?:UPDATE|INSERT|DELETE|REPLACE|MERGE)\b", text(node), re.I
            ):
                add(node, "csrf", "state_change_origin_review")
        elif node.type == "subscript_expression":
            raw = text(node)
            if re.match(r"\$_COOKIE\s*\[", raw):
                add(node, "auth_bypass", "client_cookie_identity_review")
            elif re.match(r"\$_SERVER\s*\[\s*['\"]HTTP_(?:X_|AUTHORIZATION|REMOTE_USER)", raw, re.I):
                add(node, "auth_bypass", "client_header_identity_review")
        elif node.type in {"include_expression", "include_once_expression", "require_expression", "require_once_expression"}:
            # Static dependencies are already in the include graph. Only variable
            # expressions nominate file-inclusion review; callers establish control.
            if "$" in text(node):
                add(node, "lfi", "variable_include_review")
    return [signals[key] for key in sorted(signals)]
