#!/usr/bin/env python3
"""Deterministic, model-free reproduction of the Lab30 full-audit terminal failure.

Context
-------
Two full Lab30 audit runs (``--scenario all --poc-mode auto``) on stock main
bc12280 both terminated with::

    ValueError: Planner situation ceiling cannot hold the required closure facts

The failure is raised by ``_bound_situation`` in ``backend/audit/agent.py``
(default ceiling ``AgentPolicy.planner_pinned_bytes = 16 * 1024`` in
``backend/audit/runtime.py``).  This script rebuilds the exact Planner
situation from the persisted run state and replays the same binding logic,
without any model/API calls, so the exception and its byte accounting can be
inspected deterministically.

Usage (from the repository root, inside the backend venv)::

    cp data/audit.db /tmp/audit_diag.db        # never touch the live DB
    backend/.venv/bin/python \
        deliverable/lab30-validation-2026-10-26/02-full-audit/framework-defect/reproduce_planner_ceiling.py \
        /tmp/audit_diag.db b2c46d270da6450e901354f68992f942 b857d53e39ac4dc28fc93ff93ec9aab5
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from audit.db import Store  # noqa: E402
from audit.agent import (  # noqa: E402
    _bound_situation,
    _planner_situation,
    _situation_bytes,
)

CEILING = 16 * 1024

# Blocks _bound_situation is structurally allowed to shrink/drop.
TRIMMABLE = {
    "settled",
    "findings",
    "observations",
    "project_findings",
    "frontier",
    "blockers",
    "goal",
}


def main(db_path: str, run_ids: list[str]) -> int:
    store = Store(db_path)
    exit_code = 0
    for rid in run_ids:
        print(f"\n{'=' * 72}\nrun {rid}\n{'=' * 72}")
        situation = _planner_situation(store.list_planner_context(rid))
        print(f"situation bytes before binding: {_situation_bytes(situation)}")
        untrimmed = 0
        for key, value in situation.items():
            raw = _situation_bytes(value)
            tag = "TRIMMABLE" if key in TRIMMABLE else "PROTECTED"
            if tag == "PROTECTED":
                untrimmed += raw
            count = len(value) if isinstance(value, (list, dict)) else "-"
            print(f"  {key:30s} {tag:9s} items={str(count):>4}  bytes={raw}")
        print(f"protected (never trimmed) subtotal: {untrimmed} bytes "
              f"vs {CEILING} byte ceiling -> overflow of {untrimmed - CEILING} bytes")
        try:
            bounded = _bound_situation(dict(situation), limit=CEILING)
            print(f"bound OK: {_situation_bytes(bounded)} bytes")
        except ValueError as exc:
            exit_code = 1
            print(f"REPRODUCED: {type(exc).__name__}: {exc}")
    return exit_code


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1], sys.argv[2:]))
