"""Progressive knowledge routing for worker tasks.

The shape follows AutoCVE's finding-skill router (small pure selection, resources
loaded on demand), but this is an independent implementation written for this project.
Only reviewed method hints are bundled; every selected resource carries its version,
hash and byte size so a run can record exactly what the model was shown.  A hint is
never source evidence and never widens the audit scope.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MANIFEST_VERSION = "autocve-knowledge/v1"
KNOWLEDGE_DIR = Path(__file__).with_name("knowledge")
DEFAULT_MAX_BYTES = 6 * 1024
MAX_RESOURCES = 4


@dataclass(frozen=True)
class KnowledgeRef:
    id: str
    version: str
    title: str
    sha256: str
    bytes: int
    body: str
    reason: str = ""


@dataclass(frozen=True)
class KnowledgeSelection:
    refs: tuple[KnowledgeRef, ...] = ()
    diagnostics: tuple[dict, ...] = ()
    total_bytes: int = 0
    manifest_version: str = MANIFEST_VERSION

    def prompt(self) -> str:
        if not self.refs:
            return ""
        lines = [
            "# 审计知识提示（宿主按任务路由，方法提示不是源码证据）",
            "以下资料只说明检查方法；任何结论仍必须由你实际读取的当前源码行号支撑。",
        ]
        for ref in self.refs:
            lines.append(f"## {ref.title}（{ref.id}@{ref.version}，sha256:{ref.sha256[:16]}）")
            lines.append(ref.body.strip())
        return "\n".join(lines)

    def snapshot(self) -> dict:
        return {
            "manifest_version": self.manifest_version,
            "refs": [
                {"id": ref.id, "version": ref.version, "sha256": ref.sha256,
                 "bytes": ref.bytes, "reason": ref.reason}
                for ref in self.refs
            ],
            "total_bytes": self.total_bytes,
            "diagnostics": list(self.diagnostics),
        }


def _load_manifest(directory: Path) -> tuple[dict, list[dict]]:
    path = directory / "manifest.json"
    if not path.is_file():
        return {}, [{"code": "manifest_missing", "path": str(path)}]
    try:
        manifest = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        return {}, [{"code": "manifest_unreadable", "path": str(path),
                     "error": f"{type(exc).__name__}: {exc}"}]
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        return {}, [{"code": "manifest_version_mismatch",
                     "expected": MANIFEST_VERSION,
                     "actual": manifest.get("manifest_version")}]
    return manifest, []


def _score(entry: dict, languages: set[str], frameworks: set[str],
           checkpoints: list[str]) -> int:
    language = str(entry.get("language") or "any").casefold()
    if language not in {"any", ""} and language not in languages:
        return -1
    entry_frameworks = {str(item).casefold() for item in entry.get("frameworks") or []}
    if entry_frameworks and not (entry_frameworks & frameworks):
        return -1
    score = 1
    if language and language != "any" and language in languages:
        score += 2
    if entry_frameworks & frameworks:
        score += 2
    tags = [str(item).casefold() for item in entry.get("tags") or []]
    haystack = " ".join(checkpoints).casefold()
    if tags and any(tag and tag in haystack for tag in tags):
        score += 3
    return score


def _reason(entry: dict, languages: set[str], frameworks: set[str]) -> str:
    """Explain in the run record why a resource was selected."""
    parts = []
    language = str(entry.get("language") or "").casefold()
    if language and language != "any":
        parts.append(f"language:{language}")
    matched = {str(item).casefold() for item in entry.get("frameworks") or []} & frameworks
    if matched:
        parts.append("framework:" + ",".join(sorted(matched)))
    return ";".join(parts) or "shared"


def languages_for_paths(paths: Iterable[str]) -> set[str]:
    """Infer the languages a task touches from its file extensions."""
    from ...source import LANGUAGE_BY_EXTENSION  # local: source imports this package's siblings

    found: set[str] = set()
    for path in paths:
        if not isinstance(path, str):
            continue
        suffix = Path(path).suffix.casefold()
        language = LANGUAGE_BY_EXTENSION.get(suffix)
        if language:
            found.add(language.casefold())
    return found


def route(
    *,
    languages: Iterable[str] = (),
    frameworks: Iterable[str] = (),
    checkpoints: Iterable[str] = (),
    max_bytes: int = DEFAULT_MAX_BYTES,
    directory: Path | None = None,
) -> KnowledgeSelection:
    """Select the smallest useful set of reviewed hints for one work item.

    Selection is deterministic: score desc, then id.  A resource whose bytes or hash no
    longer match the manifest is reported and skipped rather than silently trusted.
    """
    base = directory or KNOWLEDGE_DIR
    manifest, diagnostics = _load_manifest(base)
    if not manifest:
        return KnowledgeSelection(diagnostics=tuple(diagnostics))
    languages_set = {str(item).casefold() for item in languages if item}
    frameworks_set = {str(item).casefold() for item in frameworks if item}
    checkpoint_list = [str(item) for item in checkpoints if item]
    scored = []
    for entry in manifest.get("entries") or []:
        if not isinstance(entry, dict) or not entry.get("id"):
            diagnostics.append({"code": "entry_malformed", "entry": str(entry)[:120]})
            continue
        score = _score(entry, languages_set, frameworks_set, checkpoint_list)
        if score < 0:
            continue
        scored.append((-score, str(entry["id"]), entry))
    scored.sort(key=lambda item: (item[0], item[1]))

    refs: list[KnowledgeRef] = []
    total = 0
    for _, _, entry in scored:
        if len(refs) >= MAX_RESOURCES:
            diagnostics.append({"code": "resource_count_capped",
                                "id": entry["id"], "cap": MAX_RESOURCES})
            continue
        path = base / str(entry.get("file") or "")
        try:
            body = path.read_text("utf-8")
        except OSError as exc:
            diagnostics.append({"code": "resource_missing", "id": entry["id"],
                                "path": str(path), "error": f"{type(exc).__name__}: {exc}"})
            continue
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        declared = str(entry.get("sha256") or "")
        if declared and digest != declared:
            diagnostics.append({"code": "resource_hash_mismatch", "id": entry["id"],
                                "declared": declared, "actual": digest})
            continue
        size = len(body.encode("utf-8"))
        if size != int(entry.get("bytes") or size):
            diagnostics.append({"code": "resource_size_mismatch", "id": entry["id"],
                                "declared": entry.get("bytes"), "actual": size})
            continue
        if total + size > max_bytes:
            diagnostics.append({"code": "resource_over_bytes", "id": entry["id"],
                                "bytes": size, "remaining": max_bytes - total})
            continue
        refs.append(KnowledgeRef(
            id=str(entry["id"]), version=str(entry.get("version") or ""),
            title=str(entry.get("title") or entry["id"]), sha256=digest, bytes=size,
            body=body,
            reason=_reason(entry, languages_set, frameworks_set),
        ))
        total += size
    return KnowledgeSelection(refs=tuple(refs), diagnostics=tuple(diagnostics),
                              total_bytes=total,
                              manifest_version=str(manifest.get("manifest_version") or MANIFEST_VERSION))
