"""Stateless project navigation: the listings a model needs before it can read.

``list_tree``, ``find_files`` and ``file_summary`` are deterministic projections of the
frozen index — no model, no ledger, no budget, no IO.  They used to live inside
``recon.py``; the Planner now offers the same three tools, and two copies of a path
normalizer and a truncation rule drift apart the moment one of them is fixed.  Both
callers build one ``ProjectIndex`` from the same frozen project map, so a listing can
never describe a project the other one does not see.

Nothing here is evidence: a listing names paths and line counts and nothing else.
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field

# Navigation is cheap, so its listings stay far smaller than a project map.
MAX_LISTED_DIRECTORIES = 60
MAX_LISTED_FILES = 60


def clean_path(value: object) -> str:
    """Normalize a model-supplied project-relative path, refusing escapes."""
    if value is not None and not isinstance(value, str):
        raise TypeError("path must be a snapshot-relative string")
    path = (value or "").strip().replace("\\", "/")
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        raise ValueError("path must stay inside the frozen project; absolute paths are not allowed")
    if path in {"", "."}:
        return ""
    parts = [part for part in path.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts):
        raise ValueError("path must stay inside the frozen project")
    return "/".join(parts)


def matches(pattern: str, path: str) -> bool:
    """Match a file path by glob, or by substring when the pattern has no wildcard."""
    cleaned = str(pattern or "").strip().strip("/").lstrip("./").casefold()
    if not cleaned:
        raise ValueError("pattern is required")
    if len(cleaned) > 200:
        raise ValueError("pattern exceeds 200 characters")
    candidate = path.casefold()
    if any(char in cleaned for char in "*?["):
        if fnmatch.fnmatchcase(candidate, cleaned):
            return True
        return cleaned.startswith("**/") and fnmatch.fnmatchcase(candidate, cleaned[3:])
    return cleaned in candidate


def bounded(payload: object, limit: int) -> str:
    """Serialize navigation output under a byte cap without ever emitting invalid JSON."""
    def render(value: object) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    text = render(payload)
    if len(text.encode("utf-8")) <= limit or not isinstance(payload, dict):
        return text
    # Navigation output is a handful of bounded lists beside short scalar fields, so
    # halving the longest list converges in a few passes.  The guard makes that a
    # guarantee.
    trimmed = {key: list(value) if isinstance(value, list) else value for key, value in payload.items()}
    trimmed["truncated"] = True
    for _attempt in range(16):
        text = render(trimmed)
        if len(text.encode("utf-8")) <= limit:
            return text
        longest = max(
            (key for key, value in trimmed.items() if isinstance(value, list) and value),
            key=lambda key: len(trimmed[key]),
            default=None,
        )
        if longest is None:
            break
        trimmed[longest] = trimmed[longest][: max(1, len(trimmed[longest]) // 2)]
    return render({"truncated": True, "notice": "导航工具输出超过单次上限，请缩小范围后重试。"})


@dataclass
class ProjectIndex:
    """The frozen map, arranged so a listing needs one pass and no lookups."""

    directories: list[str] = field(default_factory=list)
    files_by_path: dict = field(default_factory=dict)
    binary_paths: set = field(default_factory=set)
    symbols_by_path: dict = field(default_factory=dict)

    @classmethod
    def from_map(cls, project_map: dict, repository=None, snapshot_id: str = "") -> "ProjectIndex":
        """Build the index both the Planner and reconnaissance navigate.

        The symbol outline comes from the repository's PHP syntax index, which only a
        snapshot id can address.  Callers without one (a historical run, a unit test)
        still get every path-level tool; only the outline is empty.
        """
        symbols = repository.syntax_index(snapshot_id) if repository is not None and snapshot_id else {}
        return cls(
            directories=list(project_map.get("directories") or []),
            files_by_path={str(item.get("path")): item for item in project_map.get("files") or []},
            binary_paths={str(item.get("path")) for item in project_map.get("binary_files") or []},
            symbols_by_path=symbols,
        )

    def listing(self, args: dict) -> str:
        base = clean_path(args.get("path"))
        try:
            depth = int(args.get("depth") or 2)
        except (TypeError, ValueError):
            depth = 2
        depth = max(1, min(depth, 3))
        prefix = f"{base}/" if base else ""
        if base and base not in self.directories and not any(path.startswith(prefix) for path in self.files_by_path):
            raise FileNotFoundError(f"snapshot directory not found: {base}")
        # One pass over the files, attributing each file to every displayed ancestor
        # bucket it sits under, so ``files_below`` is a real subtree count.
        counts: dict[str, int] = {}
        here: list[dict] = []
        for path, record in sorted(self.files_by_path.items()):
            if not path.startswith(prefix):
                continue
            parts = path[len(prefix):].split("/")
            if len(parts) == 1:
                here.append({
                    "path": path,
                    "lines": record.get("line_count"),
                    "language": record.get("language"),
                    "roles": list(record.get("roles") or [])[:4],
                    "dependency_tree": bool(record.get("dependency_tree")),
                })
                continue
            for take in range(1, min(len(parts), depth + 1)):
                name = "/".join(parts[:take])
                counts[name] = counts.get(name, 0) + 1
        names = sorted({
            "/".join(directory[len(prefix):].split("/")[:depth])
            for directory in self.directories
            if directory.startswith(prefix) and len(directory) > len(prefix)
        })
        binaries = sorted(
            path for path in self.binary_paths
            if path.startswith(prefix) and "/" not in path[len(prefix):]
        )
        payload = {
            "path": base or ".",
            "child_directories": [
                {"path": prefix + name, "files_below": counts.get(name, 0)} for name in names[:MAX_LISTED_DIRECTORIES]
            ],
            "files_here": here[:MAX_LISTED_FILES],
            "binary_files_here": [{"path": path, "readable": False} for path in binaries[:20]],
            "truncated": len(names) > MAX_LISTED_DIRECTORIES or len(here) > MAX_LISTED_FILES,
            "notice": "files_below 是该目录子树下的可读文本文件数；二进制文件只登记不可读。",
        }
        return bounded(payload, 6 * 1024)

    def find(self, args: dict) -> str:
        pattern = str(args.get("pattern") or "")
        limit = min(40, max(1, int(args.get("limit") or 20)))
        found = [
            {
                "path": path,
                "lines": record.get("line_count"),
                "language": record.get("language"),
                "roles": list(record.get("roles") or [])[:4],
                "module": record.get("module"),
                "symbols": len(self.symbols_by_path.get(path, {}).get("functions") or [])
                + len(self.symbols_by_path.get(path, {}).get("classes") or []),
            }
            for path, record in sorted(self.files_by_path.items())
            if matches(pattern, path)
        ]
        unreadable = sorted(path for path in self.binary_paths if matches(pattern, path))
        return bounded({
            "pattern": pattern,
            "matches": found[:limit],
            "match_count": len(found),
            "binary_matches": unreadable[:10],
            "truncated": len(found) > limit,
            "notice": "这里只列路径；确认内容必须读取原始行。",
        }, 6 * 1024)

    def summary(self, args: dict) -> str:
        path = clean_path(args.get("path"))
        record = self.files_by_path.get(path)
        if record is None:
            raise FileNotFoundError("path is not a readable text file in the frozen project")
        outline = self.symbols_by_path.get(path) or {}
        functions = [
            {"symbol": item.get("symbol"), "start_line": item.get("start_line"), "end_line": item.get("end_line")}
            for item in (outline.get("functions") or [])[:24]
        ]
        classes = [
            {"name": item.get("name"), "start_line": item.get("start_line"), "end_line": item.get("end_line")}
            for item in (outline.get("classes") or [])[:12]
        ]
        return bounded({
            "path": path,
            "language": record.get("language"),
            "line_count": record.get("line_count"),
            "roles": record.get("roles") or [],
            "dependencies": bool(record.get("dependency_tree")),
            "symbols": {"functions": functions, "classes": classes},
            "notice": "符号大纲来自 PHP 语法索引；其它语言没有符号索引，请直接读取原始行。",
        }, 4 * 1024)
