"""Explicit stage quotas partition the frozen run budget without widening it."""
import pytest
from pydantic import ValidationError

from audit.schemas import CreateRunRequest
from audit.workflow import freeze_workflow


def run(*, task=None, poc="auto", responses=400):
    task_spec = {"workflow_policy": "discovery_first", "max_planner_rounds": 24, **(task or {})}
    return {"task_spec": task_spec, "poc_policy": {"mode": poc, "enabled": poc != "off"}}, {
        "responses": responses, "tools": 2048, "seconds": 1800}


def request(*, poc_mode="auto", **task):
    payload = {
        "snapshot_id": "snapshot-1",
        "run_limits": {"responses": 400, "tools": 2048, "seconds": 1800},
        "poc_mode": poc_mode,
        "task": {"objective": "审计这个项目里的全部漏洞方向并结算未决方向", **task},
    }
    return CreateRunRequest.model_validate(payload)


def test_review_reservation_scales_with_rounds_not_with_review_responses():
    # Regression: the previous formula divided the *response* quota by two and used it
    # as a *round* count, so review=100 over 40 rounds reserved 39 rounds and closed
    # discovery at its first idle round.
    def reserved(review, rounds):
        payload, limits = run(task={"workflow_limits": {"discovery": 100, "poc": 60, "review": review},
                                    "max_planner_rounds": rounds}, responses=500)
        return freeze_workflow(payload, limits)["review_reserved_rounds"]

    assert reserved(100, 40) == 10
    assert reserved(12, 40) == 10   # Same reservation: the response count cannot buy rounds.
    assert reserved(1, 40) == 1     # One response pays for at most one review round.
    assert reserved(12, 24) == 6
    assert reserved(12, 2) == 1     # The last round is never reserved.
    assert reserved(12, 1) == 0


def test_explicit_quotas_are_frozen_and_the_remainder_goes_to_discovery():
    payload, limits = run(task={"workflow_limits": {"discovery": 300, "poc": 60, "review": 20}})
    workflow = freeze_workflow(payload, limits)
    assert workflow["source"] == "explicit"
    assert workflow["limits"] == {"discovery": 320, "poc": 60, "review": 20}
    assert sum(workflow["limits"].values()) == limits["responses"]


def test_derived_allocation_is_unchanged_when_no_quotas_are_given():
    payload, limits = run(task={})
    workflow = freeze_workflow(payload, limits)
    assert workflow["source"] == "derived"
    assert workflow["limits"] == {"discovery": 281, "poc": 100, "review": 19}


def test_explicit_poc_quota_requires_poc_enabled():
    payload, limits = run(task={"workflow_limits": {"discovery": 300, "poc": 10, "review": 20}}, poc="off")
    with pytest.raises(ValueError, match="workflow_limits"):
        freeze_workflow(payload, limits)


def test_new_fixed_allocation_is_not_rewritten_by_unavailable_auto_runtime():
    payload, limits = run(task={"orchestration_policy": "host-queue-v1",
                               "workflow_limits": {"discovery": 320, "poc": 60, "review": 20}})
    payload['poc_policy']['enabled'] = False
    frozen = freeze_workflow(payload, limits)
    assert frozen['source'] == 'explicit'
    assert frozen['limits'] == {'discovery': 320, 'poc': 60, 'review': 20}


def test_explicit_quotas_cannot_consume_the_whole_budget():
    payload, limits = run(task={"workflow_limits": {"discovery": 1, "poc": 0, "review": 400}})
    with pytest.raises(ValueError, match="workflow_limits"):
        freeze_workflow(payload, limits)


def test_explicit_quotas_must_fit_the_requested_run_limit():
    with pytest.raises(ValidationError, match="workflow_limits must not exceed"):
        request(completion_policy="coverage_review",
                workflow_limits={"discovery": 300, "poc": 60, "review": 41})


def test_poc_quota_is_rejected_when_the_request_turns_poc_off():
    with pytest.raises(ValidationError, match="workflow_limits.poc"):
        request(completion_policy="coverage_review", poc_mode="off",
                workflow_limits={"discovery": 320, "poc": 10, "review": 20})


def test_explicit_legacy_policy_cannot_carry_attempt_quotas():
    with pytest.raises(ValidationError, match="discovery_first"):
        request(completion_policy="coverage_review", workflow_policy="legacy",
                workflow_limits={"discovery": 320, "poc": 60, "review": 20})


def test_quota_is_accepted_when_coverage_review_selects_the_workflow_itself():
    parsed = request(completion_policy="coverage_review",
                     workflow_limits={"discovery": 320, "poc": 60, "review": 20})
    assert parsed.task.workflow_limits.review == 20
    assert parsed.task.workflow_policy == "legacy"  # app.py still upgrades the omitted policy


def test_a_goal_run_cannot_carry_stage_quotas():
    with pytest.raises(ValidationError, match="discovery_first"):
        request(workflow_limits={"discovery": 320, "poc": 60, "review": 20})
