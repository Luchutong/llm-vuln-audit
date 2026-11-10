#!/usr/bin/env python3
import zipfile
from pathlib import Path

ZIP = r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\phpmyfaq-4.1.1-audit.zip"
PHP_EXT = {".php", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phps", ".inc", ".phtml"}
z = zipfile.ZipFile(ZIP)
php = sorted(n for n in z.namelist() if Path(n).suffix.lower() in PHP_EXT)
out = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\which.txt")
out.write_text("\n".join(f"{i}  {php[i]}  size={z.getinfo(php[i]).file_size}" for i in range(593, 598)), encoding="utf-8")
