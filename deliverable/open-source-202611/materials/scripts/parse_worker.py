#!/usr/bin/env python3
"""Parse a range of PHP entries from the frozen ZIP in an isolated process."""
import sys
import zipfile
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_php

ZIP = r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\phpmyfaq-4.1.1-audit.zip"
PROG = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\progress.txt")
PHP_EXT = {".php", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phps", ".inc", ".phtml"}

start = int(sys.argv[1])
end = int(sys.argv[2])

z = zipfile.ZipFile(ZIP)
php = sorted(n for n in z.namelist() if Path(n).suffix.lower() in PHP_EXT)
parser = Parser(Language(tree_sitter_php.language_php()))

with PROG.open("w", encoding="utf-8") as fh:
    fh.write(f"total_php={len(php)} range={start}:{end}\n")
    fh.flush()
    for idx in range(start, min(end, len(php))):
        name = php[idx]
        content = z.read(name)
        tree = parser.parse(content)
        _ = tree.root_node.type
        fh.write(f"{idx}\t{name}\n")
        fh.flush()
    fh.write("DONE\n")
