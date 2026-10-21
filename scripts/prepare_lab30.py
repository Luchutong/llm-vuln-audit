#!/usr/bin/env python3
"""Package the 30-challenge lab into a benchmark ZIP for the white-box audit workbench.

The ZIP is importable through ``/api/snapshots`` (or ``SourceRepository.import_zip``)
and contains the 30 challenge files, the two cross-file helpers, and the manifest that
``scripts/lab_rounds.py`` reads for scoring.  The manifest is documentation and grading
metadata; the importer treats it as a non-PHP file.

Usage: prepare_lab30.py [--output demo/lab30-benchmark.zip]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import sys
import zipfile

LAB_ROOT = pathlib.Path(__file__).resolve().parents[1] / "demo" / "lab30"


def build_zip(root: pathlib.Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            # Skip scratch/dot directories such as the runner's local audit data.
            if path.is_file() and not any(part.startswith(".") for part in path.relative_to(root).parts):
                archive.writestr(path.relative_to(root).as_posix(), path.read_bytes())
    return buffer.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=LAB_ROOT.parent / "lab30-benchmark.zip",
    )
    args = parser.parse_args(argv)

    manifest_path = LAB_ROOT / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    challenges = manifest["challenges"]
    helpers = manifest.get("helpers", [])
    for item in challenges:
        if not (LAB_ROOT / item["file"]).is_file():
            raise SystemExit(f"挑战文件缺失：{item['file']}")
    for item in helpers:
        if not (LAB_ROOT / item).is_file():
            raise SystemExit(f"helper 缺失：{item}")

    data = build_zip(LAB_ROOT)
    args.output.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"挑战数：{len(challenges)}，helper：{len(helpers)}")
    print(f"输出：{args.output}")
    print(f"SHA-256：{digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
