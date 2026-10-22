#!/usr/bin/env python3
"""Register the three scenario-limited prompts (S-sqli / S-xss / S-cmd) as custom versions.

They live in ``backend/audit/prompts.py: SCENARIO_PROMPTS`` next to the built-in
P0/P1/P2 evolution, but are deliberately not part of ``BUILTIN_PROMPTS``: the built-in
list tells the two optimisation rounds' story, while the scenario versions are seeded
into a running instance through this script so they ride the exact same
``POST /api/prompt-runs`` pipeline as everything else.  Registration is idempotent --
a version whose label already exists is skipped, so re-running never duplicates rows.

Usage: register_scenarios.py <base-url>        (default http://127.0.0.1:8899)
"""
from __future__ import annotations

import sys
from pathlib import Path

import httpx

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from audit.prompts import scenario_prompt_records  # noqa: E402  (path set above)


def main() -> int:
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899").rstrip("/")
    # trust_env=False keeps a system-wide HTTP proxy from intercepting a request that
    # targets this very machine -- with a proxy on, 127.0.0.1 calls come back as 502.
    with httpx.Client(base_url=base, timeout=30, trust_env=False) as client:
        existing = client.get("/api/prompts")
        existing.raise_for_status()
        known_labels = {row["label"] for row in existing.json()}

        registered, skipped = [], []
        for record in scenario_prompt_records():
            if record["label"] in known_labels:
                skipped.append(record["label"])
                continue
            response = client.post(
                "/api/prompts",
                json={
                    "label": record["label"],
                    "text": record["text"],
                    "reason": record["reason"],
                    "issues": [],
                    "parent_id": None,
                },
            )
            response.raise_for_status()
            row = response.json()
            registered.append(f"{row['label']} (id={row['id']})")

    for item in registered:
        print(f"已注册: {item}")
    for item in skipped:
        print(f"已存在，跳过: {item}")
    if not registered and not skipped:
        print("没有可注册的场景版本。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
