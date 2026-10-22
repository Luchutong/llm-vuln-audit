#!/usr/bin/env python3
"""Verify every lab30-shop ground-truth entry against the actual lab source ZIP.

Checks, for each of the 30 vulnerabilities:
  1. `location[].path` resolves to a real file inside the ZIP (with or without the
     `lab30-shop/` archive prefix);
  2. every cited line exists and is non-empty;
  3. `entry_point.file` + `entry_point.line` resolve to a real line;
  4. `exploitation_path.sink` / `propagation` are not silently empty.

Usage:
    python verify_lab30_dataset.py <source.zip> <ground_truth.json>
Exit code 0 = all entries verified; 1 = at least one mismatch.
"""
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path, PurePosixPath

from cvss31 import assessment


def load_names(zf: zipfile.ZipFile) -> dict[str, list[str]]:
    """Map suffix paths -> full archive names, so `app/...` matches `lab30-shop/app/...`."""
    mapping: dict[str, list[str]] = {}
    for name in zf.namelist():
        if name.endswith("/"):
            continue
        parts = PurePosixPath(name).parts
        for i in range(len(parts)):
            suffix = "/".join(parts[i:])
            mapping.setdefault(suffix, []).append(name)
    return mapping


def line_of(zf: zipfile.ZipFile, archive_name: str, line: int) -> str | None:
    text = zf.read(archive_name).decode("utf-8", errors="replace").splitlines()
    if 1 <= line <= len(text):
        return text[line - 1].rstrip()
    return None


def main() -> int:
    zip_path, truth_path = sys.argv[1], sys.argv[2]
    truth = json.loads(Path(truth_path).read_text(encoding="utf-8"))
    entries = truth["vulnerabilities"] if isinstance(truth, dict) else truth
    zf = zipfile.ZipFile(zip_path)
    names = load_names(zf)

    ok = 0
    cvss_checked = 0
    problems: list[str] = []
    with open(zip_path, "rb") as source:
        archive_hash = hashlib.file_digest(source, "sha256").hexdigest()
    for vuln in entries:
        vid = vuln["id"]
        expected_hash = (vuln.get("assessment") or {}).get("source_archive_sha256")
        if expected_hash and expected_hash != archive_hash:
            problems.append(f"{vid}: CVSS 评分绑定的源码 SHA-256 与 ZIP 不一致")
        if vuln.get("cvss") is not None:
            try:
                assessment(vuln["cvss"])
                cvss_checked += 1
            except ValueError as exc:
                problems.append(f"{vid}: {exc}")
        # 1) every cited location must exist
        for loc in vuln.get("location", vuln.get("locations", [])):
            rel = loc["path"].replace("\\", "/")
            matches = names.get(rel) or names.get(f"lab30-shop/{rel}")
            if not matches:
                problems.append(f"{vid}: location path not found in ZIP: {rel}")
                continue
            content = line_of(zf, matches[0], int(loc.get("line", 0) or 0))
            if content is None:
                problems.append(f"{vid}: location line out of range: {rel}:{loc.get('line')}")
            elif not content.strip():
                problems.append(f"{vid}: cited line is empty: {rel}:{loc.get('line')}")
            else:
                ok += 1
        # 2) entry point must resolve
        ep = vuln.get("entry_point") or {}
        if ep.get("file"):
            rel = str(ep["file"]).replace("\\", "/")
            matches = names.get(rel) or names.get(f"lab30-shop/{rel}")
            if not matches:
                problems.append(f"{vid}: entry_point file not found: {rel}")
            else:
                content = line_of(zf, matches[0], int(ep.get("line", 0) or 0))
                if content is None:
                    problems.append(f"{vid}: entry_point line out of range: {rel}:{ep.get('line')}")
                else:
                    ok += 1
        # 3) exploitation path must be populated
        xp = vuln.get("exploitation_path") or {}
        if "exploitation_path" in vuln and not (xp.get("input") and xp.get("propagation") and xp.get("sink")):
            problems.append(f"{vid}: exploitation_path incomplete (input/propagation/sink)")

    zf.close()
    print(f"已核对的行级定位: {ok} 处")
    if problems:
        print(f"发现 {len(problems)} 处问题:")
        for p in problems:
            print(" -", p)
        return 1
    print(f"全部 {len(entries)} 项漏洞的路径、行号及已有入口/利用路径均与源码一致。")
    print(f"CVSS 3.1 基础分与向量已校验 {cvss_checked}/{len(entries)} 条。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
