#!/usr/bin/env python3
"""Run the production SourceRepository.import_zip on the frozen archive."""
import json
import sys
from pathlib import Path

REPO = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit")
sys.path.insert(0, str(REPO / "backend"))

from audit.source import SourceRepository  # noqa: E402

ZIP = REPO / "data" / "part-c-import" / "phpmyfaq-4.1.1-audit.zip"
# Short root to stay under the Windows 260-char MAX_PATH limit for deep vendor trees.
STORAGE = Path(r"C:\pmf_audit")

data = ZIP.read_bytes()
repo = SourceRepository(STORAGE)
snap = repo.import_zip(data, ZIP.name)

# Persist the full snapshot for downstream analysis (inside ignored data/).
full = REPO / "data" / "part-c-import" / "snapshot_full.json"
full.write_text(json.dumps(snap, ensure_ascii=False), encoding="utf-8")

print("snapshot_id=", snap["id"])
print("archive_sha256=", snap["archive_sha256"])
print("stats=", json.dumps(snap["stats"], ensure_ascii=False))
print("warnings_count=", len(snap["warnings"]))
for w in snap["warnings"][:15]:
    print("  WARN:", w)
print("units_count=", len(snap["units"]))
print("excluded_files_listed=", len(snap["excluded_files"]))
print("skipped_files=", json.dumps(snap["skipped_files"], ensure_ascii=False))
# Parse error summary
pe = [f["path"] for f in snap["files"] if f.get("parse_errors")]
print("files_with_parse_errors=", len(pe))
for p in pe[:10]:
    print("  PARSE:", p)
# Dependency tree flag check
dt = [f["path"] for f in snap["files"] if f.get("dependency_tree")]
print("dependency_tree_flagged=", len(dt))
# How many PHP files sit under src/libs
libs_php = [f["path"] for f in snap["files"] if f["is_php"] and "/libs/" in ("/" + f["path"])]
print("php_files_under_libs=", len(libs_php))
