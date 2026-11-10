#!/usr/bin/env python3
import sys
import zipfile
from pathlib import Path

REPO = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit")
sys.path.insert(0, str(REPO / "backend"))
from audit.source import SourceRepository  # noqa: E402

ZIP = REPO / "data" / "part-c-import" / "phpmyfaq-4.1.1-audit.zip"
OUT = REPO / "data" / "part-c-import" / "mem.txt"
PHP_EXT = {".php", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phps", ".inc", ".phtml"}

try:
    import psutil
    have = True
except ImportError:
    have = False

z = zipfile.ZipFile(ZIP)
php = sorted(n for n in z.namelist() if Path(n).suffix.lower() in PHP_EXT)
sr = SourceRepository(r"C:\pmf_audit")
proc = psutil.Process() if have else None

lines = [f"psutil={have}"]
for i in range(0, 595):
    name = php[i]
    content = z.read(name)
    units, syntax, errors = sr._index(content, name, "audit", "snap")
    if i % 50 == 0:
        if have:
            rss = proc.memory_info().rss / (1024 * 1024)
            lines.append(f"i={i} rss_mib={rss:.1f}")
        else:
            lines.append(f"i={i} (no psutil)")
if have:
    lines.append(f"final rss_mib={proc.memory_info().rss/(1024*1024):.1f}")
OUT.write_text("\n".join(lines), encoding="utf-8")
