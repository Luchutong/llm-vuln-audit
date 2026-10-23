"""Shared test wiring.

Startup registers the bundled Lab30 shop as a ready-to-audit project, which is the right
production default but makes every test that builds ``Services`` depend on what happens to
be checked out next to the repository.  Tests pin ``LAB30_SEED=0`` so a data directory
starts empty unless a test asks for the bundled target itself.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_bundled_target(monkeypatch):
    monkeypatch.setenv("LAB30_SEED", "0")
