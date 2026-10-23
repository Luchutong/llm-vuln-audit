"""Project identity: one project per body of source text, not per uploaded archive.

A run used to be bound to one snapshot, and every upload minted a new snapshot UUID even
when the bytes were an identical re-zip of the same tree.  That made two audits of the
same project strangers to each other: the second one re-dispatched directions the first
had already settled and re-found the same vulnerabilities.

The identity is therefore a *content key* over the indexed text files -- path plus each
file's own SHA-256 -- rather than over the archive.  Re-zipping, reordering entries or
changing compression does not change which project this is; changing one indexed text
file does.  Binary files are deliberately excluded: the audit only reads text, so an
image swap is not a new project.

``archive_sha256`` stays on the snapshot as provenance.  A byte-identical upload can
reuse that snapshot outright, and a re-zipped upload becomes a second snapshot under the
same project.
"""
from __future__ import annotations

import hashlib
import unicodedata
import uuid
from typing import Iterable

PROJECT_CONTENT_SCHEMA = 1

# Recognise the fixture by a set of implementation-specific files under one app root,
# never by the ZIP filename or a generic login page. Both full and app-only ZIPs work.
_LAB30_FILES = {
    "VERSION", "src/bootstrap.php", "src/setup.php", "public/health.php",
    "public/auth/login.php", "public/orders/index.php", "public/wallet/withdraw.php",
    "public/ops/template-render.php", "public/partner/token.php",
}


def _normal_path(path: str) -> str:
    return unicodedata.normalize("NFC", str(path or ""))


def project_content_key(files: Iterable[dict]) -> str:
    """Stable key over every indexed text file: sorted ``path\\0sha256`` lines.

    Returns a hex digest.  A snapshot with no text files still gets a deterministic key;
    the run API refuses such a snapshot before it can become a project.
    """
    entries: list[str] = []
    for item in files or []:
        if not isinstance(item, dict) or item.get("kind") != "text":
            continue
        path = _normal_path(item.get("path") or "")
        digest = str(item.get("sha256") or "")
        if not path or not digest:
            continue
        entries.append(f"{path}\0{digest}")
    # Path sort, not archive order: the key must not depend on how the ZIP was built.
    entries.sort()
    body = f"v{PROJECT_CONTENT_SCHEMA}\n" + "\n".join(entries)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def project_target_profile(files: Iterable[dict]) -> str:
    """Which runnable fixture this project maps onto, or ``unknown``.

    Only ``lab30`` is supported by the POC runner; anything else is reported as
    ``unknown`` and its findings are recorded as ``not_applicable`` for automatic
    execution rather than pretending a target exists.
    """
    paths = {
        _normal_path(item.get("path") or "").casefold()
        for item in files or []
        if isinstance(item, dict) and item.get("path")
    }
    for path in paths:
        suffix = "public/auth/login.php"
        if path.endswith(suffix):
            root = path[:-len(suffix)]
            if all(root + item.casefold() in paths for item in _LAB30_FILES):
                return "lab30"
    return "unknown"


def project_name(snapshot: dict) -> str:
    """A human-facing name derived from the uploaded archive, without its extension."""
    raw = str(snapshot.get("name") or "").replace("\\", "/").rsplit("/", 1)[-1]
    stripped = True
    while stripped:
        stripped = False
        for suffix in (".zip", ".tar", ".gz", ".tgz"):
            if raw.casefold().endswith(suffix):
                raw = raw[: -len(suffix)]
                stripped = True
                break
    cleaned = raw.strip()
    return cleaned[:120] or "未命名项目"


def ensure_project(store, snapshot: dict) -> tuple[dict, bool]:
    """Bind a snapshot to its content-key project, creating the project if needed.

    Returns ``(project, created)``.  The snapshot row gains ``content_key`` and
    ``project_id``; when this is a second snapshot of an existing project, the project
    keeps its original name, origin timestamps and creation order.
    """
    content_key = snapshot.get("content_key") or project_content_key(snapshot.get("files") or [])
    target_profile = project_target_profile(snapshot.get("files") or [])
    existing = store.get_project_by_content_key(content_key)
    created = existing is None
    if created:
        stamp = snapshot.get("created_at") or None
        project = {
            "id": uuid.uuid4().hex,
            "content_key": content_key,
            "name": project_name(snapshot),
            "target_profile": target_profile,
            "content_schema": PROJECT_CONTENT_SCHEMA,
            "created_at": stamp,
        }
        store.add_project(project)
        existing = store.get_project_by_content_key(content_key)
    if existing is None:  # pragma: no cover - add_project just wrote it
        raise RuntimeError("project disappeared after it was created")
    store.attach_snapshot_project(
        snapshot["id"],
        existing["id"],
        content_key,
        target_profile,
        created_at=snapshot.get("created_at"),
    )
    snapshot["content_key"] = content_key
    snapshot["project_id"] = existing["id"]
    snapshot["target_profile"] = target_profile
    return store.get_project(existing["id"]) or existing, created


def ensure_projects(store, repository) -> int:
    """Backfill projects and refresh derived target profiles of existing snapshots.

    Idempotent and best-effort: a snapshot whose directory has been removed (a test
    fixture, a pruned data dir) is skipped rather than stopping the server.  Returns the
    number of snapshots that were bound in this pass.
    """
    bound = 0
    for row in store.list_snapshots():
        try:
            snapshot = dict(repository.get_snapshot(row["id"]))
        except (FileNotFoundError, ValueError, KeyError):
            continue
        if row.get("project_id"):
            profile = project_target_profile(snapshot.get("files") or [])
            if row.get("target_profile") != profile:
                store.refresh_target_profile(row["id"], profile)
        else:
            ensure_project(store, snapshot)
            bound += 1
    return bound
