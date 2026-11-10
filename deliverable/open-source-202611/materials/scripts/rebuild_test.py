#!/usr/bin/env python3
import sys
import zipfile
from pathlib import Path

REPO = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit")
sys.path.insert(0, str(REPO / "backend"))
from audit.source import SourceRepository  # noqa: E402
from tree_sitter import Language, Parser  # noqa: E402
import tree_sitter_php  # noqa: E402

ZIP = REPO / "data" / "part-c-import" / "phpmyfaq-4.1.1-audit.zip"
OUT = REPO / "data" / "part-c-import" / "rebuild.txt"
PHP_EXT = {".php", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phps", ".inc", ".phtml"}

z = zipfile.ZipFile(ZIP)
php = sorted(n for n in z.namelist() if Path(n).suffix.lower() in PHP_EXT)
sr = SourceRepository(r"C:\pmf_audit")

total = 0
for i in range(0, 8926):
    # Recreate the parser before every file to avoid reused-parser native state.
    sr.parser = Parser(Language(tree_sitter_php.language_php()))
    name = php[i]
    content = z.read(name)
    units, syntax, errors = sr._index(content, name, "audit", "snap")
    total += len(units)
OUT.write_text(f"reached=8926 total_units={total} DONE", encoding="utf-8")
