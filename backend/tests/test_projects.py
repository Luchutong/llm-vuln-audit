"""Project identity is a content key, not an archive hash.

Two uploads of the same tree may differ in bytes (re-zipped, different entry order,
different compression) and must still be the same project; one changed text file must be
a different project.  Binary files are excluded because the audit never reads them.
"""
from __future__ import annotations

import hashlib
import uuid

import pytest

from audit.db import Store
from audit.project_findings import canonical_fingerprint, sink_similarity
from audit.projects import (
    ensure_project,
    project_content_key,
    project_name,
    project_target_profile,
)


def _file(path: str, body: str = "", *, kind: str = "text") -> dict:
    return {
        "path": path,
        "kind": kind,
        "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
    }


def _snapshot(files: list[dict], name: str = "project.zip") -> dict:
    return {
        "id": uuid.uuid4().hex,
        "name": name,
        "created_at": "2026-10-20T00:00:00+00:00",
        "archive_sha256": uuid.uuid4().hex,
        "source": "upload",
        "files": files,
        "units": [],
        "warnings": [],
        "content_key": project_content_key(files),
        "target_profile": project_target_profile(files),
    }


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


def test_content_key_ignores_entry_order_and_archive_bytes():
    one = [_file("src/a.php", "a"), _file("index.php", "i")]
    two = list(reversed(one))

    assert project_content_key(one) == project_content_key(two)


def test_content_key_changes_with_text_and_not_with_binary():
    base = [_file("a.php", "one"), _file("logo.png", "x", kind="binary")]

    changed_text = [_file("a.php", "two"), _file("logo.png", "x", kind="binary")]
    changed_binary = [_file("a.php", "one"), _file("logo.png", "y", kind="binary")]

    assert project_content_key(base) != project_content_key(changed_text)
    # The audit reads text only, so an image swap is still the same project.
    assert project_content_key(base) == project_content_key(changed_binary)


def test_removed_dvwa_profile_is_unknown_even_with_markers():
    core = [
        _file("login.php", "l"),
        _file("setup.php", "s"),
        _file("security.php", "x"),
        _file("vulnerabilities/sqli/index.php", "q"),
    ]
    assert project_target_profile(core) == "unknown"
    with_marker = core + [_file("includes/DVWApage.inc.php", "p")]
    assert project_target_profile(with_marker) == "unknown"
    only_pages = [_file("login.php"), _file("setup.php"), _file("security.php")]
    assert project_target_profile(only_pages) == "unknown"


def test_project_name_strips_archive_suffix_only():
    assert project_name({"name": "uploads/DVWA-master.zip"}) == "DVWA-master"
    assert project_name({"name": "plain.tar.gz"}) == "plain"
    assert project_name({"name": ""}) == "未命名项目"


def test_ensure_project_reuses_the_same_row_for_identical_content(store):
    files = [_file("index.php", "<?php echo 1;")]
    first_snapshot, second_snapshot = _snapshot(files), _snapshot(files)
    store.add_snapshot(first_snapshot)
    store.add_snapshot(second_snapshot)
    first, created = ensure_project(store, first_snapshot)
    second, created_again = ensure_project(store, second_snapshot)

    assert created is True and created_again is False
    assert first["id"] == second["id"]
    assert store.get_project(first["id"])["snapshot_count"] == 2


def test_ensure_project_keeps_original_name_and_creation_order(store):
    original, _ = ensure_project(store, _snapshot([_file("a.php", "a")], name="first.zip"))
    same_content, _ = ensure_project(store, _snapshot([_file("a.php", "a")], name="renamed.zip"))

    assert same_content["id"] == original["id"]
    assert same_content["name"] == "first"


def test_same_symbol_sink_similarity_drives_the_merge_fallback():
    left = "unserialize($_POST['data'])"
    right = "调用 unserialize 处理 $_POST['data']"
    assert sink_similarity(left, right) >= 0.6
    assert sink_similarity(left, "echo 常量字符串") < 0.6


def test_canonical_fingerprint_is_stable_across_wording_and_case():
    one = canonical_fingerprint("src/A.php", "handle", "  Unserialize( $_POST['x'] ) ")
    two = canonical_fingerprint("src/A.php", "handle", "unserialize( $_POST['x'] )")
    different = canonical_fingerprint("src/A.php", "other", "unserialize( $_POST['x'] )")

    assert one == two
    assert one != different
