#!/usr/bin/env python3
"""Physical line counts per directory for the P3 engineering-scale table.

Counts blank lines and comments (physical lines), filters by extension and skips
dependency directories. Mirrors the numbers printed in
``deliverable/open-source-2026-11/data/P3_代码规模统计.md``.
"""
from __future__ import annotations

import collections
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ["backend", "frontend/src", "labs/lab30", "poc_runner"]
LANG = {
    ".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".js": "JavaScript", ".mjs": "JavaScript", ".css": "CSS",
    ".php": "PHP", ".html": "HTML", ".svg": "SVG",
}
SKIP = {"node_modules", ".venv", "dist", "build", "__pycache__", ".mypy_cache", ".pytest_cache"}


def main() -> int:
    grand = [0, 0, 0]
    per_lang: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    print(f"{'目录':<18}{'代码文件':>8}{'总行数':>10}{'空行':>8}")
    for rel in TARGETS:
        root = ROOT / rel
        files = lines = blanks = 0
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in LANG:
                continue
            if SKIP & set(path.parts):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            files += 1
            lines += len(content)
            blanks += sum(1 for line in content if not line.strip())
            bucket = per_lang[LANG[path.suffix.lower()]]
            bucket[0] += 1
            bucket[1] += len(content)
        print(f"{rel:<18}{files:>8}{lines:>10}{blanks:>8}")
        grand[0] += files
        grand[1] += lines
        grand[2] += blanks
    print(f"{'合计':<18}{grand[0]:>8}{grand[1]:>10}{grand[2]:>8}")
    print("\n按语言：")
    for lang, (files, lines) in sorted(per_lang.items(), key=lambda item: -item[1][1]):
        print(f"  {lang:<14}{files:>6} 文件 {lines:>8} 行 ({lines / grand[1] * 100:.1f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
