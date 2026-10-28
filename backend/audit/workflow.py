"""Frozen discovery-first allocation, separate from the global safety budget."""
from __future__ import annotations

VERSION = "discovery-first-v1"
STAGES = ("discovery", "poc", "review")


def freeze_workflow(run: dict, limits: dict) -> dict:
    task_spec = run.get("task_spec") or {}
    if task_spec.get("workflow_policy") != "discovery_first":
        return {}
    total = int(limits["responses"])
    policy = run.get("poc_policy") or {}
    enabled = policy.get("mode") != "off" and bool(policy.get("enabled"))
    explicit = task_spec.get("workflow_limits")
    if isinstance(explicit, dict):
        review = int(explicit.get("review") or 0)
        poc = int(explicit.get("poc") or 0)
        if review < 1 or poc < 0 or (poc and not enabled) or review + poc > total - 1:
            # The API validates this already; a direct Store call must fail loudly
            # instead of silently rewriting the caller's quotas.
            raise ValueError("workflow_limits do not fit the frozen run budget")
        discovery = total - review - poc
        source = "explicit"
    else:
        review = min(max(0, total - 1), (total * 3 + 63) // 64)
        poc = min(total // 4, max(0, total - review - 1)) if enabled else 0
        discovery = total - review - poc
        source = "derived"
    planner_rounds = int(task_spec.get("max_planner_rounds") or 24)
    return {
        "version": VERSION, "stage": "discovery", "source": source,
        "limits": {"discovery": discovery, "poc": poc, "review": review},
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
