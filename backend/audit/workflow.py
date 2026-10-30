"""Frozen discovery-first allocation, separate from the global safety budget."""
from __future__ import annotations

from .context_config import env_float

VERSION = "discovery-first-v1"
STAGES = ("discovery", "poc", "review")
HOST_QUEUE = "host-queue-v1"
# Discovery and POC share one wall clock.  Reserving only the review window let
# discovery consume the whole budget and then stop exactly when the POC gate
# (``remaining > review_reserved``) forbade it from starting, so the validation
# stage was unreachable no matter how much request quota it had.  The freeze
# therefore carves a POC window out of the same clock; it is a floor, not a
# ceiling -- whatever is left after review still goes to POC.
POC_WINDOW_SHARE = env_float("AUDIT_POC_WINDOW_SHARE", 0.35, 0.0, 0.8)


def host_queue(run: dict) -> bool:
    return (run.get("task_spec") or {}).get("orchestration_policy") == HOST_QUEUE


def poc_window_seconds(total_seconds: float, share: float | None = None) -> float:
    """Seconds discovery must leave on the clock for the POC stage.

    The window is a share of the whole run, capped at half of it and never so
    large that discovery gets less than three minutes.  A zero share disables
    the reservation and restores the previous behaviour.
    """
    total = max(0.0, float(total_seconds or 0))
    ratio = POC_WINDOW_SHARE if share is None else float(share)
    if total <= 0 or ratio <= 0:
        return 0.0
    return round(min(total * ratio, total * 0.5, max(0.0, total - 180.0)), 3)


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
        poc_requested = enabled or (host_queue(run) and policy.get("mode") in {"auto", "required"})
        if review < 1 or poc < 0 or (poc and not poc_requested) or review + poc > total - 1:
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
    # Rounds and responses are different units: the review quota pays for responses,
    # not for planner rounds, so a large review quota must never reserve almost every
    # round.  Reserve a quarter of the rounds, capped by the review quota (at most one
    # review decision per round) and by the last round, which stays available.
    review_rounds = max(1, min(planner_rounds // 4, review))
    return {
        "version": HOST_QUEUE if host_queue(run) else VERSION, "stage": "discovery", "source": source,
        "limits": {"discovery": discovery, "poc": poc, "review": review},
        "used": {stage: 0 for stage in STAGES}, "transferred": 0,
        "review_reserved_seconds": min(60.0, float(limits["seconds"]) * .05),
        "poc_reserved_seconds": poc_window_seconds(limits["seconds"]) if poc else 0.0,
        "review_reserved_rounds": 0 if host_queue(run) else (min(max(0, planner_rounds - 1), review_rounds) if review else 0),
        "discovery_stop": None,
    }


def stage_poc_window(value: dict) -> float:
    """The part of the clock that still belongs to the POC stage.

    Only discovery reserves it: once the stage has switched, the window *is*
    the stage's remaining time and must not be subtracted a second time.
    Historical workflow rows without the field keep the old behaviour.
    """
    if value.get("stage") != "discovery":
        return 0.0
    if int(value.get("limits", {}).get("poc", 0)) <= int(value.get("used", {}).get("poc", 0)):
        return 0.0
    return max(0.0, float(value.get("poc_reserved_seconds") or 0.0))


def workflow_view(value: dict, *, remaining_seconds: float | None = None) -> dict:
    if not value:
        return {}
    result = {**value, "limits": dict(value["limits"]), "used": dict(value["used"])}
    result["remaining"] = {
        stage: max(0, result["limits"][stage] - result["used"][stage]) for stage in STAGES
    }
    window = stage_poc_window(result)
    result["poc_reserved_seconds"] = window
    if remaining_seconds is not None:
        # Every non-review stage stops early enough to leave the frozen review window
        # intact.  The host queue has no reserved *rounds*, but it still needs reserved
        # *seconds*, otherwise its POC stage may spend the review deadline.  Discovery
        # additionally leaves the POC window: without it the POC gate below could never
        # open.
        reserved = (result["review_reserved_seconds"] if result["stage"] != "review" else 0.)
        result["stage_remaining_seconds"] = max(0., remaining_seconds - reserved - window)
    return result
