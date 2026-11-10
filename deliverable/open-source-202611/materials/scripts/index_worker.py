#!/usr/bin/env python3
"""Run the real SourceRepository._index over a range of entries in isolation."""
import sys
import zipfile
from pathlib import Path

REPO = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit")
sys.path.insert(0, str(REPO / "backend"))

from audit.source import SourceRepository  # noqa: E402

ZIP = REPO / "data" / "part-c-import" / "phpmyfaq-4.1.1-audit.zip"
PROG = REPO / "data" / "part-c-import" / "index_progress.txt"
PHP_EXT = {".php", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phps", ".inc", ".phtml"}

start = int(sys.argv[1])
end = int(sys.argv[2])
digest = "audit"

z = zipfile.ZipFile(ZIP)
php = sorted(n for n in z.namelist() if Path(n).suffix.lower() in PHP_EXT)
sr = SourceRepository(r"C:\pmf_audit")

total_units = 0
with PROG.open("w", encoding="utf-8") as fh:
    fh.write(f"total_php={len(php)} range={start}:{end}\n")
    fh.flush()
    for idx in range(start, min(end, len(php))):
        name = php[idx]
        content = z.read(name)
        units, syntax, errors = sr._index(content, name, digest, "snap")
        total_units += len(units)
        fh.write(f"{idx}\t{name}\tunits={len(units)}\terrors={len(errors)}\n")
        fh.flush()
    fh.write(f"DONE total_units={total_units}\n")
