"""The bundled Lab30 shop is registered on startup, once, and never fatally.

The POC runner only verifies ``lab30`` targets, so a library that does not contain one is
a broken default: the new-audit form has nothing to pick and any archive the user happens
to have is a target the runner refuses.  These tests pin the three properties that matter:
it seeds, it does not seed twice, and a missing archive is not an error.
"""
from __future__ import annotations

import pathlib

import pytest

from audit import app as app_module
from audit import lab_seed
from audit.config import ModelConfig, Settings
from audit.projects import ensure_project
from audit.db import Store
from audit.source import SourceRepository


PROJECT = pathlib.Path(__file__).resolve().parents[2]
BUNDLED = PROJECT / lab_seed.LAB30_ZIP_CANDIDATES[0]


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "data")


def test_the_repository_ships_the_archive_this_seeds():
    assert BUNDLED.is_file(), f"内置靶场缺失：{BUNDLED}"


def test_seeding_registers_a_ready_to_audit_lab30_project(store, repository):
    result = lab_seed.ensure_lab30_snapshot(store, repository, path=BUNDLED)
    assert result is not None and result["created"] is True
    snapshot, project = result["snapshot"], result["project"]
    assert snapshot["name"] == lab_seed.LAB30_SNAPSHOT_NAME
    assert project["target_profile"] == "lab30"
    assert len(repository.get_snapshot(snapshot["id"])["files"]) > 40
    # The dropdown the user sees is filled from the store, so the row has to be there.
    assert [item["id"] for item in store.list_snapshots()] == [snapshot["id"]]


def test_seeding_twice_reuses_the_same_snapshot_and_project(store, repository):
    first = lab_seed.ensure_lab30_snapshot(store, repository, path=BUNDLED)
    second = lab_seed.ensure_lab30_snapshot(store, repository, path=BUNDLED)
    assert first is not None and second is not None
    assert second["created"] is False
    assert second["snapshot"]["id"] == first["snapshot"]["id"]
    assert second["project"]["id"] == first["project"]["id"]
    assert len(store.list_snapshots()) == 1


def test_an_uploaded_identical_archive_is_not_replaced(store, repository):
    """A user who uploaded the same file first must not end up with two projects."""
    data = BUNDLED.read_bytes()
    uploaded = repository.import_zip(data, "my-lab30.zip")
    store.add_snapshot(uploaded)
    ensure_project(store, uploaded)

    result = lab_seed.ensure_lab30_snapshot(store, repository, path=BUNDLED)
    assert result is not None
    assert result["created"] is False
    assert result["snapshot"]["id"] == uploaded["id"]
    assert len(store.list_snapshots()) == 1


def test_an_existing_snapshot_without_a_project_is_bound_and_reused(store, repository):
    uploaded = repository.import_zip(BUNDLED.read_bytes(), "old-lab30.zip")
    store.add_snapshot(uploaded)

    result = lab_seed.ensure_lab30_snapshot(store, repository, path=BUNDLED)

    assert result is not None and result["created"] is False
    assert result["snapshot"]["id"] == uploaded["id"]
    assert result["snapshot"]["project_id"] == result["project"]["id"]
    assert result["project"]["target_profile"] == "lab30"
    assert len(store.list_snapshots()) == 1


def test_a_missing_archive_is_skipped_rather_than_raised(store, repository, tmp_path):
    missing = tmp_path / "not-there.zip"
    assert lab_seed.ensure_lab30_snapshot(store, repository, path=missing) is None
    assert store.list_snapshots() == []


def test_seeding_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("LAB30_SEED", "0")
    assert lab_seed.seeding_enabled() is False
    monkeypatch.setenv("LAB30_SEED", "1")
    assert lab_seed.seeding_enabled() is True


def test_the_archive_path_can_be_overridden(monkeypatch, tmp_path):
    override = tmp_path / "custom.zip"
    override.write_bytes(b"not a real zip")
    monkeypatch.setenv("LAB30_SOURCE_ZIP", str(override))
    assert lab_seed.find_lab30_zip() == override
    monkeypatch.setenv("LAB30_SOURCE_ZIP", str(tmp_path / "absent.zip"))
    assert lab_seed.find_lab30_zip() is None


def test_startup_registers_the_bundled_target(tmp_path, monkeypatch):
    """The drop-down is filled from the store, so the wiring itself has to run."""
    monkeypatch.setenv("LAB30_SEED", "1")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    services = app_module.Services(
        Settings(
            data_dir=data_dir,
            model=ModelConfig(model="test-model", base_url="http://127.0.0.1:1/v1", api_key="test-key"),
        )
    )
    try:
        assert services.lab30 is not None and services.lab30["created"] is True
        projects = services.store.list_projects()
        assert [item["id"] for item in projects] == [services.lab30["project"]["id"]]
    finally:
        services.store.close()


def test_startup_stays_quiet_when_seeding_is_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("LAB30_SEED", "0")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    services = app_module.Services(
        Settings(
            data_dir=data_dir,
            model=ModelConfig(model="test-model", base_url="http://127.0.0.1:1/v1", api_key="test-key"),
        )
    )
    try:
        assert services.lab30 is None
        assert services.store.list_projects() == []
    finally:
        services.store.close()
