#!/usr/bin/env python3
import sys
from pathlib import Path

out = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\diag.txt")
lines = []
try:
    import tree_sitter
    lines.append(f"tree_sitter={tree_sitter.__version__}")
    import tree_sitter_php as t
    lang = t.language_php()
    lines.append(f"lang_type={type(lang)}")
    lines.append(f"abi_version={getattr(lang, 'version', 'n/a')}")
    from tree_sitter import Language, Parser
    p = Parser(Language(lang))
    # Stress test: parse the same buffer many times.
    buf = b"<?php\n" + b"$x = 1;\n" * 500
    for i in range(200):
        tr = p.parse(buf)
        _ = tr.root_node.named_child_count
    lines.append("stress_200=ok")
except Exception as exc:  # noqa: BLE001
    lines.append(f"ERROR={type(exc).__name__}: {exc}")

out.write_text("\n".join(lines), encoding="utf-8")
