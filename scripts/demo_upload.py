#!/usr/bin/env python3
"""Upload a snapshot and print the audit units generated for the demo scope.

Usage: demo_upload.py <base-url> <zip-path> [file-path-filter ...]
"""
import json
import sys
from pathlib import Path

import httpx

base = sys.argv[1].rstrip("/")
archive = Path(sys.argv[2])
filters = sys.argv[3:]

with httpx.Client(base_url=base, timeout=180) as client:
    with archive.open("rb") as handle:
        response = client.post("/api/snapshots", files={"file": (archive.name, handle, "application/zip")})
    if response.status_code >= 400:
        print("upload failed:", response.status_code, response.text[:600])
        raise SystemExit(1)
    snapshot = response.json()

print(f"snapshot id       : {snapshot['id']}")
print(f"archive sha256    : {snapshot['archive_sha256']}")
print(f"files / units     : {len(snapshot['files'])} / {len(snapshot['units'])}")
excluded = [f for f in snapshot["files"] if f["excluded"]]
print(f"excluded files    : {len(excluded)}")
for item in excluded[:6]:
    print(f"   - {item['path']}  ({item['exclude_reason']})")
if snapshot.get("warnings"):
    print("warnings:")
    for warning in snapshot["warnings"][:5]:
        print(f"   - {warning}")

php = [f for f in snapshot["files"] if f.get("is_php")]
parse_errors = [f for f in php if f.get("parse_errors")]
print(f"php files         : {len(php)}（其中 {len(parse_errors)} 个存在语法解析错误）")

print("\n--- units in the demo scope ---")
for unit in snapshot["units"]:
    if filters and not any(unit["file_path"].endswith(f) for f in filters):
        continue
    print(
        f"{unit['id'][:10]}  {unit['file_path']}:{unit['start_line']}-{unit['end_line']}"
        f"  [{unit['kind']}] {unit['symbol']}  slice {unit['slice_index']}/{unit['slice_count']}"
        f"  priority={unit['priority']}"
        f"{'  PARSE-INCOMPLETE' if unit['parse_incomplete'] else ''}"
    )

print("\n--- units in the demo scope that have NO dangerous-API hint (must still be queued) ---")
zero = [u for u in snapshot["units"] if u["priority"] == 0]
print(f"count = {len(zero)}")
for unit in zero[:8]:
    print(f"   {unit['file_path']}:{unit['start_line']}-{unit['end_line']} [{unit['kind']}] {unit['symbol']}")

Path("/tmp/snapshot_id.txt").write_text(snapshot["id"])
print(f"\nsnapshot id saved to /tmp/snapshot_id.txt")
