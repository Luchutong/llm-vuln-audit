#!/usr/bin/env python3
"""Run production SourceRepository.import_zip on the Lab30 archive."""
import json
import sys
from pathlib import Path

REPO = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit")
sys.path.insert(0, str(REPO / "backend"))

from audit.source import SourceRepository  # noqa: E402

ZIP = REPO / "data" / "part-c-import" / "lab30-app-audit.zip"
STORAGE = Path(r"C:\lab30_audit")

data = ZIP.read_bytes()
repo = SourceRepository(STORAGE)
snap = repo.import_zip(data, ZIP.name)

out = REPO / "data" / "part-c-import" / "snapshot_lab30.json"
out.write_text(json.dumps(snap, ensure_ascii=False), encoding="utf-8")

print("snapshot_id=", snap["id"])
print("stats=", json.dumps(snap["stats"], ensure_ascii=False))
print("units=", len(snap["units"]))
print("warnings=", len(snap["warnings"]))
