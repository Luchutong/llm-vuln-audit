"""Offline closure and duplicate-claim regressions, using temporary stores only."""
import asyncio
import copy
import time

import pytest
from pydantic import ValidationError

from audit import worker as worker_module
from audit.coverage_review import required_paths
from audit.project_findings import exact_run_identity
from audit.execution_state import comparison_deadline, execution_context
from audit.runtime import StopAudit
from audit.schemas import PlannerDecision, TaskSpec
from tests.test_goal_tasks import (
    TASK, _conclusion_finding, create_planner_run, make_worker, proposal, repository, store, worker_outcome,
)


def run_with_policy(store, repository, **changes):
    return create_planner_run(store, repository, task={**TASK, "max_planner_rounds": 8,
        "completion_policy": "coverage_review", "stop_on_achieved": False, **changes})[0]


def skip_paths(store, run, paths):
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    store.finish_planner_round(run["id"], plan["id"], goal_state="continue", basis_summary="明确当前未执行方向及适用限制。",
        coverage_review=[{"path": path, "action": "skip", "reason": "该方向留待单独审计，本次不声明已经检查或安全。"} for path in paths])


def test_policy_is_additive_and_skip_is_structured():
    assert TaskSpec.model_validate(TASK).completion_policy == "goal"
    assert TaskSpec.model_validate({**TASK, "completion_policy": "coverage_review"}).completion_policy == "coverage_review"
    with pytest.raises(ValidationError):
        TaskSpec.model_validate({**TASK, "completion_policy": "invented"})
    with pytest.raises(ValidationError):
        PlannerDecision.model_validate({"basis_summary": "检验跳过路径。", "coverage_review": [{"path": True, "reason": "无效路径不能获得豁免。"}]})


def test_only_first_party_source_and_configuration_are_required():
    project = {"files": [
        {"path": "api/handler.php", "is_php": True}, {"path": "client/main.js", "language": "javascript"},
        {"path": "config.ini", "language": "config"}, {"path": "README.md", "language": "markdown"},
        {"path": "logo.svg", "language": "xml", "dependency_tree": True},
        {"path": "vendor/helper.php", "is_php": True, "dependency_tree": True},
    ]}
    assert required_paths(project) == {"api/handler.php", "client/main.js", "config.ini"}


def test_exact_identity_never_reuses_a_fuzzy_truncated_or_casefolded_sink():
    finding = {"vulnerability_type": "sqli", "primary_location": {"path": "src/query.php", "line": 4},
               "dangerous_operation": "prefix " * 100 + "$_GET['A']"}
    assert exact_run_identity(finding) != exact_run_identity({**finding, "dangerous_operation": "prefix " * 100 + "$_GET['a']"})


def test_met_cannot_cancel_ready_or_deferred_directions(store, repository):
    run = run_with_policy(store, repository)
    skip_paths(store, run, store.coverage_review(run["id"])["pending_paths"])
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    store.finish_planner_round(run["id"], plan["id"], goal_state="continue", basis_summary="保留尚待执行的独立方向。", tasks=[proposal("pending-flow")])
    store.add_finding(_conclusion_finding(run))
    for state in ("ready", "deferred"):
        store._write("UPDATE planner_tasks SET state=? WHERE run_id=?", (state, run["id"]))
        with pytest.raises(ValueError, match="所有已派发方向"):
            store.finalize_goal(run["id"], "met", "已有发现但不允许丢弃剩余任务。")
        assert store.list_tasks(run["id"])[0]["state"] == state
        assert store.get_run(run["id"])["status"] == "running"


def test_skip_paths_are_validated_atomically_and_survive_readback(store, repository):
    run = run_with_policy(store, repository)
    pending = store.coverage_review(run["id"])["pending_paths"]
    with pytest.raises(ValueError, match="冻结源码路径"):
        skip_paths(store, run, [pending[0], "../outside.php"])
    assert not store.has_event(run["id"], "coverage_review_recorded")
    assert store.coverage_review(run["id"])["pending_paths"] == pending
    # The rejected draft is a draft, not a source of accepted exclusions.
    plan = store.list_plans(run["id"])[-1]
    store.finish_planner_round(run["id"], plan["id"], goal_state="continue", basis_summary="撤回无效的跳过列表。")
    skip_paths(store, run, pending)
    review = store.coverage_review(run["id"])
    assert review["complete"] and review["pending_total"] == 0
    assert len(review["skips"]) == len(pending)
    assert store.get_run(run["id"])["execution_summary"]["coverage_review"] == review
    store.add_finding(_conclusion_finding(run))
    store.finalize_goal(run["id"], "met", "覆盖复核完成，跳过项均作为限制保留。")
    assert store.get_final_summary(run["id"])["execution"]["coverage_review"]["skips"] == review["skips"]


def test_late_coverage_decision_is_fenced_before_any_exclusion_write(store, repository):
    run = run_with_policy(store, repository)
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    epoch = store.execution_summary(run["id"])["claim_epoch"]
    with execution_context(store, run["id"], epoch), comparison_deadline(time.monotonic() - 1):
        with pytest.raises(StopAudit):
            store.finish_planner_round(run["id"], plan["id"], goal_state="met", basis_summary="迟到决策不得写入。",
                coverage_review=[{"path": "src/auth.php", "reason": "迟到的跳过理由不能覆盖截止终态。"}])
    assert not store.has_event(run["id"], "coverage_review_recorded")


def decision(**fields):
    return {"decision": {"goal_state": "continue", "basis_summary": "基于宿主缺口复核源码方向。", **fields},
            "terminal_reason": "completed", "error": None, "usage": {"requests": 1, "tool_calls": 0}}


def test_worker_continues_after_early_met_then_records_explicit_exclusions(store, repository, monkeypatch):
    run = run_with_policy(store, repository)
    rounds = []
    paths_run = []

    async def plan(**args):
        rounds.append(args["round_no"])
        pending = args["run_context"]["coverage_review"]["pending_paths"]
        if len(rounds) == 1:
            return decision(tasks=[proposal("entry")])
        if len(rounds) == 2:
            return decision(goal_state="met")  # Must be refused while source gaps remain.
        if len(rounds) == 3:
            assert "src/auth.php" in pending
            return decision(tasks=[proposal("auth", path="src/auth.php", end=2)])
        return decision(goal_state="met", coverage_review=[{"path": path, "action": "skip",
            "reason": "该剩余方向列为限制，留待独立审计，不声明已经检查。"} for path in pending])

    async def pursue(**args):
        path = args["planner_task"]["context_spec"]["source_refs"][0]["path"]
        paths_run.append(path)
        finding = {"title": "文件名缺少路径边界", "kind": "vulnerability", "summary": "请求输入未经路径约束即交给文件操作。",
            "vulnerability_type": "path_traversal", "primary_location": {"path": "public/index.php", "line": 4},
            "evidence": "public/index.php:4-4", "dangerous_operation": "readfile($path)", "preconditions": []}
        return worker_outcome("achieved" if len(paths_run) == 1 else "no_evidence",
            finding=finding if len(paths_run) == 1 else None,
            seen=[{"path": path, "start_line": 1, "end_line": 4 if path == "public/index.php" else 2}])

    monkeypatch.setattr(worker_module, "plan_audit_frontier", plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", pursue)
    asyncio.run(make_worker(store, repository)._execute(run))
    assert paths_run == ["public/index.php", "src/auth.php"]
    assert len(rounds) == 4
    assert store.get_run(run["id"])["status"] == "completed"
    assert store.coverage_review(run["id"])["complete"]
    assert store.has_event(run["id"], "planner_terminal_deferred")


def test_unaddressed_source_gaps_end_bounded_and_inconclusive(store, repository, monkeypatch):
    run = run_with_policy(store, repository)
    store.add_finding(_conclusion_finding(run))
    calls = []

    async def plan(**args):
        calls.append(args["round_no"])
        return decision(goal_state="met")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", plan)
    asyncio.run(make_worker(store, repository)._execute(run))
    assert 1 <= len(calls) <= 3
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.coverage_review(run["id"])["pending_total"] == 3


def test_context_fault_finishes_draft_without_model_retry_or_fact_loss(store, repository, monkeypatch):
    run = run_with_policy(store, repository)
    store.add_finding(_conclusion_finding(run))

    async def plan(**args):
        return {"decision": None, "terminal_reason": "planner_context_error", "error": "Synthetic projection fault", "usage": {"requests": 0}}

    monkeypatch.setattr(worker_module, "plan_audit_frontier", plan)
    asyncio.run(make_worker(store, repository)._execute(run))
    assert store.get_run(run["id"])["status"] == "failed"
    assert store.execution_summary(run["id"])["stop_reason"]["code"] == "planner_context_error"
    assert len(store.list_plans(run["id"])) == 1
    assert store.list_plans(run["id"])[0]["status"] != "planning"
    assert len(store.list_findings(run["id"])) == 1


@pytest.mark.parametrize("difference", [None, "preconditions", "primary_location", "vulnerability_type", "dangerous_operation"])
def test_only_exact_same_run_claims_are_marked_duplicate(store, repository, difference):
    run = run_with_policy(store, repository)
    first = {**_conclusion_finding(run, "first"), "vulnerability_type": "path_traversal",
             "primary_location": {"path": "public/index.php", "line": 4}}
    second = {**copy.deepcopy(first), "id": "second", "unit_id": "unit-2", "fingerprint": "second", "title": "相同风险的另一表述"}
    if difference == "preconditions":
        second[difference] = ["另一种身份和对象条件"]
    elif difference == "primary_location":
        second[difference] = {"path": "src/files.php", "line": 4}
    elif difference == "vulnerability_type":
        second[difference] = "lfi"
    elif difference == "dangerous_operation":
        second[difference] = "include($path)"
    store.add_finding(first)
    store.add_finding(second)
    store.link_finding_project("first", "same-ledger", 1)
    store.link_finding_project("second", "same-ledger", 1)
    result = store.classify_run_duplicate(run["id"], "second")
    if difference is None or difference == "preconditions":
        # A different precondition wording is an assumption, not a second claim:
        # the same type at the same sink is the same vulnerability.
        assert result["disposition"] == "duplicate"
        assert store.get_finding("second")["derived_from_finding_id"] == "first"
    else:
        assert result["candidate_ids"] == ["first"]
        assert store.get_finding("second")["disposition"] == "open"
    assert len(store.list_findings(run["id"])) == 2
    assert store.get_finding("second")["evidence"] == second["evidence"]


def test_a_blocked_direction_does_not_suppress_the_coverage_review(store, repository, monkeypatch):
    """Unread paths stay reviewable while another direction is stuck.

    Gating the gap review on an empty blocker list made one blocked task hide every
    path nobody had read for the rest of the run: the Planner was never told the gaps
    existed, so it could neither dispatch them nor exclude them with a reason.
    """
    run = run_with_policy(store, repository, max_workers=1)
    store.add_finding(_conclusion_finding(run))
    rounds = []
    blocked_at_review = []

    requests_seen = 0

    async def plan(**args):
        nonlocal requests_seen
        rounds.append(args["round_no"])
        state = store.task_queue_state(run["id"])
        requests_now = len([event for event in store.list_events(run["id"], limit=1000)
                            if event["kind"] == "coverage_review_requested"])
        if not store.list_tasks(run["id"]):
            # The first round dispatches the direction that will get stuck.  Only a
            # later, freshly requested round can be the gap review this test is about.
            requests_seen = requests_now
            return decision(tasks=[proposal("entry")])
        if requests_now <= requests_seen:
            return decision(goal_state="continue")
        requests_seen = requests_now
        blocked_at_review.append((state["blocked"], dict(state["counts"])))
        pending = args["run_context"]["coverage_review"]["pending_paths"]
        return decision(goal_state="met", coverage_review=[
            {"path": path, "action": "skip",
             "reason": "该方向因缺少前提暂时受阻，列为限制，不声明已经检查。"}
            for path in pending
        ])

    async def pursue(**args):
        return worker_outcome("blocked")

    monkeypatch.setattr(worker_module, "plan_audit_frontier", plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", pursue)
    asyncio.run(make_worker(store, repository)._execute(run))

    # Coverage was reviewed, but the stuck direction was never resolved: the run
    # closes honestly as inconclusive rather than pretending the frontier is done.
    assert store.get_run(run["id"])["status"] == "inconclusive"
    assert store.execution_summary(run["id"])["stop_reason"]["code"] == "unresolved_blockers"
    assert blocked_at_review and blocked_at_review[0][0] > 0, (blocked_at_review, rounds)
    assert store.has_event(run["id"], "coverage_review_requested")
    assert store.has_event(run["id"], "coverage_review_recorded")
    assert store.coverage_review(run["id"])["pending_total"] == 0


def test_a_rewritten_evidence_range_is_still_the_same_claim(store, repository):
    run = run_with_policy(store, repository)
    first = {**_conclusion_finding(run, "first"), "vulnerability_type": "path_traversal",
             "primary_location": {"path": "public/index.php", "line": 4}}
    second = {**copy.deepcopy(first), "id": "second", "unit_id": "unit-2",
              "fingerprint": "second", "category": "path_traversal",
              "title": "路径参数未受限", "evidence": [{"path": "public/index.php", "start_line": 3, "end_line": 4}],
              "cvss": 7.5, "poc": "GET /?path=../../etc/passwd"}
    store.add_finding(first)
    store.add_finding(second)
    store.link_finding_project("first", "same-ledger", 1)
    store.link_finding_project("second", "same-ledger", 1)

    result = store.classify_run_duplicate(run["id"], "second")

    assert result["disposition"] == "duplicate"
    assert result["identity_tier"] == 2
    assert store.get_finding("first")["disposition"] == "open"


def test_a_different_non_empty_input_source_is_not_merged(store, repository):
    run = run_with_policy(store, repository)
    first = {**_conclusion_finding(run, "first"), "vulnerability_type": "path_traversal",
             "primary_location": {"path": "public/index.php", "line": 4}, "input_source": "GET path"}
    second = {**copy.deepcopy(first), "id": "second", "unit_id": "unit-2", "fingerprint": "second",
              "input_source": "POST avatar", "evidence": [{"path": "public/index.php", "start_line": 3, "end_line": 4}]}
    store.add_finding(first)
    store.add_finding(second)
    store.link_finding_project("first", "same-ledger", 1)
    store.link_finding_project("second", "same-ledger", 1)

    result = store.classify_run_duplicate(run["id"], "second")

    assert result["candidate_ids"] == ["first"]
    assert store.get_finding("second")["disposition"] == "open"
