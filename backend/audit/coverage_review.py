"""Source-based completion checks, independent of benchmark answers or model prose."""
from __future__ import annotations

SOURCE_LANGUAGES = frozenset({
    "php", "javascript", "typescript", "vue", "svelte", "python", "ruby", "go", "java", "kotlin",
    "csharp", "rust", "c", "cpp", "swift", "scala", "perl", "lua", "r", "html", "template",
    "json", "yaml", "toml", "config", "xml", "sql", "shell", "powershell", "batch",
})


def required_paths(project_map: dict) -> set[str]:
    """First-party source and configuration need a read or an explicit exclusion.

    Dependency trees remain available to tools but do not dominate closure. Static
    assets and documentation are not silently called server-side coverage. Unknown
    text entries marked as source/entrypoints by the frozen index are included too.
    """
    paths = {
        row["path"] for row in project_map.get("files") or []
        if isinstance(row, dict) and isinstance(row.get("path"), str) and not row.get("dependency_tree")
        and (row.get("is_php") or row.get("language") in SOURCE_LANGUAGES
             or set(row.get("roles") or []) & {"entrypoint", "source", "configuration", "config"})
    }
    known = {row.get("path"): row for row in project_map.get("files") or [] if isinstance(row, dict)}
    paths.update(row["path"] for row in project_map.get("entrypoints") or []
                 if isinstance(row, dict) and row.get("path") in known and not known[row["path"]].get("dependency_tree"))
    return paths


def review_state(project_map: dict, read_paths: set[str], skips: dict[str, dict]) -> dict:
    needed = required_paths(project_map)
    omitted = {path: item for path, item in skips.items() if path in needed}
    read = needed & read_paths
    pending = sorted(needed - read - set(omitted))
    return {"version": "coverage-review-v1", "total": len(needed), "pending_total": len(pending),
            "pending_paths": pending, "read_paths": sorted(read), "reviewed_paths": sorted(read | set(omitted)),
            "skips": [omitted[path] for path in sorted(omitted)], "complete": not pending,
            "notice": "已读只表示宿主记录过读取，不证明每行或每种风险已审计；跳过项保留理由，不是安全结论。"}
