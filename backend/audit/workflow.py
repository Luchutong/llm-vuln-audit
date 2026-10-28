"""Frozen discovery-first allocation, separate from the global safety budget."""
from __future__ import annotations

VERSION = "discovery-first-v1"
STAGES = ("discovery", "poc", "review")


def freeze_workflow(run: dict, limits: dict) -> dict:
    if (run.get("task_spec") or {}).get("workflow_policy") != "discovery_first":
        return {}
    total = int(limits["responses"])
    review = min(max(0, total - 1), (total * 3 + 63) // 64)
    policy = run.get("poc_policy") or {}
    enabled = policy.get("mode") != "off" and bool(policy.get("enabled"))
    poc = min(total // 4, max(0, total - review - 1)) if enabled else 0
    planner_rounds = int((run.get("task_spec") or {}).get("max_planner_rounds") or 24)
    return {
        "version": VERSION, "stage": "discovery",
        "limits": {"discovery": total - review - poc, "poc": poc, "review": review},
        "used": {stage: 0 for stage in STAGES}, "transferred": 0,
        "review_reserved_seconds": min(60.0, float(limits["seconds"]) * .05),
        "review_reserved_rounds": min(max(0, planner_rounds - 1), max(1, review // 2)) if review else 0,
        "discovery_stop": None,
    }


def workflow_view(value: dict, *, remaining_seconds: float | None = None) -> dict:
    if not value:
        return {}
    result = {**value, "limits": dict(value["limits"]), "used": dict(value["used"])}
    result["remaining"] = {
        stage: max(0, result["limits"][stage] - result["used"][stage]) for stage in STAGES
    }
    if remaining_seconds is not None:
        result["stage_remaining_seconds"] = max(0., remaining_seconds - (
            result["review_reserved_seconds"] if result["stage"] != "review" else 0
        ))
    return result
