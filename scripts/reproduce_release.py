#!/usr/bin/env python3
"""Verify checked-in Lab30 assets and replay an archived score, without services."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "deliverable/lab30-closure-2026-10-30"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="Optional writable destination for replayed score JSON")
    args = parser.parse_args()
    manifest = json.loads((ARCHIVE / "reproduction-manifest.json").read_text())
    for name, expected in manifest["files"].items():
        path = ROOT / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit(f"Missing or changed reproduction asset: {name}")
    archive = next(name for name in manifest["files"] if name.endswith(".zip"))
    subprocess.run([
        sys.executable, str(ROOT / "scripts/verify_lab30_dataset.py"), str(ROOT / archive),
        str(ROOT / "datasets/lab30-shop/ground_truth.json"), "--protocol", "lab30-v2",
    ], check=True)
    with tempfile.TemporaryDirectory(prefix="vuln-audit-replay-") as directory:
        output = args.out.resolve() if args.out else Path(directory) / "score.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            sys.executable, str(ROOT / "scripts/score_dataset.py"), "--protocol", "lab30-v2",
            "--findings", str(ARCHIVE / "findings.json"), "--check-severity", "--check-cvss",
            "--out", str(output),
        ], check=True, stdout=subprocess.DEVNULL)
        score = json.loads(output.read_text())
        actual = {key: score.get(key) for key in manifest["expected"]}
        if actual != manifest["expected"]:
            raise SystemExit("Archived score differs from the frozen manifest")
        print(json.dumps({
            "scope": manifest["scope"], "run_id": manifest["run_id"],
            "assets_verified": len(manifest["files"]), "score": actual,
            "model_requests": 0, "runner_jobs": 0, "database_required": False,
        }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
