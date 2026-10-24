"""Make the bundled Lab30 shop available as a ready-to-audit project.

The repository ships the Lab30 shop source, and the isolated POC runner can only verify
against ``lab30`` targets.  Without this, a fresh install starts with an empty library: the
new-audit form has nothing to select, and any archive a user happens to have uploaded
(e.g. old DVWA samples) is a target the runner reports as ``not_applicable``.  Seeding the
built-in target on startup removes that gap; it is idempotent and never fatal.
"""
from __future__ import annotations

import hashlib
import logging
import os
import pathlib

logger = logging.getLogger(__name__)

# Where the bundled archive may live, relative to the repository root.  The first match
# wins; an explicit ``LAB30_SOURCE_ZIP`` overrides both.
LAB30_ZIP_CANDIDATES: tuple[str, ...] = (
    "llm-vuln-audit-feat-lab30-shop/llm-vuln-audit-feat-lab30-shop/lab30-shop-1.0.0-source.zip",
    "labs/lab30/lab30-shop-1.0.0-source.zip",
    "demo/lab30-shop-1.0.0-source.zip",
)
LAB30_SNAPSHOT_NAME = "lab30-shop-1.0.0-source.zip"
# ``0``/``false``/``no`` turns seeding off for hosts that want an empty library.
_TRUTHY = {"1", "true", "yes", "on"}


def repository_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


def find_lab30_zip(root: pathlib.Path | None = None) -> pathlib.Path | None:
    """The bundled Lab30 archive, or None when this checkout does not carry it."""
    override = (os.environ.get("LAB30_SOURCE_ZIP") or "").strip()
    if override:
        candidate = pathlib.Path(override)
        return candidate if candidate.is_file() else None
    base = root or repository_root()
    for relative in LAB30_ZIP_CANDIDATES:
        candidate = base / relative
        if candidate.is_file():
            return candidate
    return None


def seeding_enabled() -> bool:
    return (os.environ.get("LAB30_SEED") or "1").strip().casefold() in _TRUTHY


def ensure_lab30_snapshot(store, repository, *, path: pathlib.Path | None = None) -> dict | None:
    """Import the bundled Lab30 source once and bind it to its project.

    Idempotent by archive digest, so a restart (or a user who uploaded the same file
    earlier) reuses the existing snapshot rather than creating a second project.  Returns
    the ``{"snapshot": ..., "project": ..., "created": bool}`` result, or None when the
    archive is unavailable.
    """
    archive = path or find_lab30_zip()
    if archive is None:
        return None
    try:
        data = archive.read_bytes()
    except OSError as exc:
        logger.warning("内置 Lab30 源码包不可读，跳过自动登记：%s", exc)
        return None
    digest = hashlib.sha256(data).hexdigest()
    existing = store.get_snapshot_by_archive_sha256(digest)
    if existing is not None:
        project = store.get_project(existing["project_id"]) if existing.get("project_id") else None
        if project is None:
            # Bind a snapshot that predates projects, exactly like the upload path does.
            from .projects import ensure_project

            snapshot = dict(repository.get_snapshot(existing["id"]))
            project, _ = ensure_project(store, snapshot)
            existing = store.get_snapshot(existing["id"])
        return {"snapshot": existing, "project": project, "created": False}

    from .projects import ensure_project

    snapshot = repository.import_zip(data, LAB30_SNAPSHOT_NAME)
    store.add_snapshot(snapshot)
    project, _ = ensure_project(store, snapshot)
    logger.info(
        "已登记内置 Lab30 靶场：snapshot=%s project=%s（%s 个文件）",
        snapshot["id"], project["id"], snapshot.get("file_count"),
    )
    return {"snapshot": snapshot, "project": project, "created": True}
