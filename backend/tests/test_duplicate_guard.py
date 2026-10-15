"""The duplicate guard is a guardrail, not the mechanism, and it is pinned as one.

Re-dispatching a direction the run has already concluded is the failure this whole design
is about, and ARTEX prevents it with a state machine plus a per-round picture of the graph:
a settled intent is not in the frontier at all.  Our frontier is the same kind of gate and
every round now gets the same kind of picture, so what is left for a similarity check is the
residual case -- a proposal that re-reads exactly the files of a settled direction whose
conclusions are already in the database.  That case, its threshold, and its two exits are
what this file pins.  Anything wider (text similarity, a proposal that overlaps but has not
been concluded) is deliberately not refused.
"""
from __future__ import annotations

import json

import pytest
from pydantic_ai import ModelRetry

from audit import agent
from audit.runtime import AgentPolicy
from audit.schemas import PlannerDecision

PROJECT_MAP = {
    "stats": {},
    "architecture": {},
    "files": [
        {"path": "public/index.php", "line_count": 3},
        {"path": "src/bootstrap.php", "line_count": 4},
        {"path": "src/auth.php", "line_count": 6},
        {"path": "config/app.yaml", "line_count": 2},
    ],
}


def decision(*, key: str, files: list[str], scope: list[str] | None = None) -> PlannerDecision:
    return PlannerDecision.model_validate({
        "goal_state": "continue",
        "basis_summary": "项目图显示入口包含 bootstrap。",
        "next_action": "让 worker 读取相关文件。",
        "missing_context": [],
        "tasks": [{
            "task_key": key,
            "title": "入口到敏感操作的路径",
            "objective": "读取这些文件，确认请求数据如何到达敏感操作。",
            "acceptance_criteria": "结论必须引用原始源码行号。",
            "rationale_summary": "与项目图相关。",
            "source_refs": [
                {"path": path, "start_line": 1, "end_line": 2, "reason": "read"} for path in files
            ],
            "scope_paths": scope or [],
            "target_symbols": [],
            "dependencies": [],
            "query_hints": [],
            "priority": 50,
        }],
        "updates": [],
    })


SETTLED = {
    "task_key": "entry-read",
    "state": "completed",
    "files": ["public/index.php", "src/bootstrap.php"],
}
CONCLUSION = [{"id": "f-1", "paths": ["public/index.php", "src/bootstrap.php"]}]


def validate(decision_value, *, prior=None, findings=None, policy=None):
    return agent._validate_planner_decision(
        decision_value,
        PROJECT_MAP,
        [SETTLED] if prior is None else prior,
        policy=policy or AgentPolicy(),
        findings=CONCLUSION if findings is None else findings,
    )


def test_the_same_files_as_a_concluded_direction_are_refused_with_both_exits():
    """The residual case, refused -- and the refusal has to teach the two ways out."""
    with pytest.raises(ModelRetry) as excinfo:
        validate(decision(key="entry-read-again", files=["public/index.php", "src/bootstrap.php"]))

    message = str(excinfo.value)
    assert "entry-read" in message
    assert "Jaccard 1.00" in message
    # Exit one: the recorded conclusion is wrong.
    assert "updates" in message and "reopen" in message
    # Exit two: it really is a different direction, and the way to say so is the extra file.
    assert "没有覆盖的文件" in message


def test_a_proposal_that_is_not_near_identical_is_left_alone():
    """Half-overlapping directions are ordinary work, and the guard must not touch them."""
    # Two of four files in common: 2/4 = 0.5, below the 0.8 threshold.
    validate(decision(
        key="auth-path", files=["public/index.php", "src/auth.php", "config/app.yaml"],
    ))
    # One of the settled pair plus a new file: 1/3.
    validate(decision(key="auth-only", files=["src/auth.php"]))


def test_reading_the_same_files_is_allowed_until_they_have_concluded_something():
    """Overlap alone is not duplication: the settled direction has to have produced a result.

    Otherwise a blocked or empty attempt would lock its files away from every later round --
    and "read this again, properly" is exactly what a second attempt at a dead end is for.
    """
    validate(
        decision(key="retry-read", files=["public/index.php", "src/bootstrap.php"]),
        findings=[],
    )
    validate(
        decision(key="retry-read", files=["public/index.php", "src/bootstrap.php"]),
        findings=[{"id": "f-2", "paths": ["config/app.yaml"]}],
    )


def test_only_settled_directions_are_compared_and_a_resubmission_is_not_a_duplicate():
    """A live direction is not a duplicate target, and re-submitting one is a different act.

    A pending or running task's files are covered by the frontier gate rather than by this
    check, and a proposal that keeps its own task_key is re-submitting that direction, not
    inventing a second one -- the settled-task branch refuses that case on its own terms.
    """
    running = {**SETTLED, "state": "running"}
    validate(
        decision(key="other", files=["public/index.php", "src/bootstrap.php"]),
        prior=[running],
    )
    # An open task the Planner re-proposes under its own key is its own decision to make.
    pending = {**SETTLED, "state": "pending"}
    validate(
        decision(key="entry-read", files=["public/index.php", "src/bootstrap.php"]),
        prior=[pending],
    )


def test_a_duplicate_direction_can_be_withdrawn_by_adding_a_file_it_missed():
    """The exit the refusal names must actually work, or the round has nowhere to go."""
    narrow = decision(key="entry-read-again", files=["public/index.php", "src/bootstrap.php"])
    with pytest.raises(ModelRetry):
        validate(narrow)

    widened = decision(
        key="entry-read-again",
        files=["public/index.php", "src/bootstrap.php", "src/auth.php", "config/app.yaml"],
    )
    assert validate(widened) is not None


def test_the_threshold_is_policy_not_a_literal():
    """The bar is a policy value: at 0.6 this proposal is refused, at 1.0 it is not."""
    proposal = decision(key="mostly-same", files=["public/index.php", "src/bootstrap.php", "src/auth.php"])
    # 2 of 3 shared with the settled pair = 0.67.
    with pytest.raises(ModelRetry):
        validate(proposal, policy=AgentPolicy(duplicate_overlap_threshold=0.6))
    assert validate(proposal, policy=AgentPolicy(duplicate_overlap_threshold=1.0)) is not None


def test_the_scope_paths_count_towards_the_file_set():
    """A direction that names its files as scope instead of refs is the same direction."""
    with pytest.raises(ModelRetry):
        validate(decision(
            key="scope-only", files=[],
            scope=["public/index.php", "src/bootstrap.php"],
        ))


def test_the_situation_shows_the_file_sets_the_guard_compares():
    """The round is given what it is judged on, so the guard is avoidable rather than a trap."""
    situation = agent._planner_situation({
        "goal": {}, "findings": [], "tasks": [
            {
                "task_key": "entry-read", "state": "completed", "title": "入口",
                "files": ["public/index.php", "src/bootstrap.php"], "result": {"summary": "结论"},
            },
        ],
    })

    settled = situation["settled"][0]
    assert settled["files"] == ["public/index.php", "src/bootstrap.php"]
    assert json.loads(agent._planner_json(situation))["settled"][0]["files"][1] == "src/bootstrap.php"
