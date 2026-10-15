"""What a run may do to a conclusion it has already written down.

Three axes are involved and they must not be confused with one another.  The evidence
check says whether the citations held up.  The human verdict says whether the weakness
reproduces.  Standing -- the disposition -- says whether the run still claims the
conclusion at all.  A conclusion can be a perfectly well-evidenced candidate that the
Planner later retracted, and none of these moves may erase anything: ARTEX writes a
follow-up rather than an update (blind INSERT plus column-level setters, soft delete with
a reason), and this file pins the same shape here.

The failure this replaced is concrete.  Re-running a direction used to go through
``INSERT OR REPLACE``, which gave the slot a new ``id``: every human verification bound to
the old row became an orphan and the reviewer's verdict vanished, so re-running a
direction silently threw away the review of it.
"""
from __future__ import annotations

import asyncio

import pytest
from pydantic_ai import ModelRetry

from audit import agent, metrics, report
from audit.db import (
    MAX_SUPERSEDED_SUMMARIES,
    WITHDRAWN_FINDING_DISPOSITIONS,
    Store,
)
from audit.runtime import AgentPolicy
from audit.schemas import PlannerDecision
from audit.source import SourceRepository
from tests.test_goal_tasks import TASK, create_planner_run, proposal


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "source-data")


def dispatch_one(store, run, key: str = "entry-flow") -> dict:
    """Publish one direction and hand back its durable row."""
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    assert plan is not None
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue",
        basis_summary="先建立入口方向。", tasks=[proposal(key)],
    )
    return next(item for item in store.list_tasks(run["id"]) if item["task_key"] == key)


def settle(store, run, key: str = "entry-flow") -> None:
    claimed = store.claim_ready_task(run["id"], "worker-1")
    assert claimed is not None and claimed["task_key"] == key
    store.resolve_task_attempt(
        claimed["id"], "worker-1", outcome="no_evidence",
        result={"summary": "本方向没有形成可用结论。", "reasoning": "只基于 worker 读过的原始源码。"},
        usage={"requests": 1}, seen=[{"path": "public/index.php", "start_line": 1, "end_line": 4}],
    )


def conclusion(run, task_id: str, **overrides) -> dict:
    """A finding record shaped the way the worker builds one."""
    record = {
        "id": overrides.pop("id", "finding-1"),
        "run_id": run["id"],
        "unit_id": task_id,
        "fingerprint": overrides.pop("fingerprint", "fp-1"),
        "category": "task_goal_vulnerability",
        "finding_kind": "vulnerability",
        "title": "未经规范化的文件名拼接",
        "severity": "high",
        "summary": "请求参数传入文件处理函数后与上传目录拼接并交给 readfile。",
        "evidence": [{"path": "public/index.php", "start_line": 4, "end_line": 4}],
        "input_source": "$_GET['path']",
        "propagation": "入口 handle 调用将 path 传入文件处理函数。",
        "dangerous_operation": "readfile('/srv/uploads/' . $path)",
        "protection": "认证检查不等于路径规范化。",
        "preconditions": ["已通过认证的请求能够调用该入口。"],
        "missing_context": [],
        "poc": None,
        "remediation": "在文件操作前规范化路径并限制在允许目录内。",
        "validation_state": "candidate",
        "validation_errors": [],
        "verdict": None,
        "created_at": overrides.pop("created_at", "2026-01-01T00:00:00+00:00"),
    }
    record.update(overrides)
    return record


def round_with(store, run, **updates) -> None:
    """Commit a Planner round that only carries `updates`."""
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    assert plan is not None
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue",
        basis_summary="更正已有结论的处置状态。", tasks=[], updates=[updates],
    )


def verification(store, finding_id: str) -> dict:
    return store.add_verification({
        "id": f"v-{finding_id}",
        "finding_id": finding_id,
        "created_at": "2026-01-02T00:00:00+00:00",
        "execution_status": "executed",
        "verdict": "confirmed",
        "original_script": "<?php echo 1;",
        "modified_script": "",
        "modification_notes": "",
        "target_version": "php8",
        "command": "php poc.php",
        "expected_result": "读到了目录外的文件",
        "normal_observation": "拒绝",
        "attack_observation": "读到了 /etc/passwd",
        "browser_execution": None,
        "notes": "",
        "files": [],
    })


# --- re-running a direction -------------------------------------------------


def test_re_running_a_direction_reuses_its_slot_instead_of_replacing_the_row(store, repository):
    """The slot is a slot, not a row to be deleted and re-created."""
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)

    first = store.add_finding(conclusion(run, task["id"]))
    assert first["action"] == "created" and first["revision"] == 1
    verification(store, first["finding_id"])
    store.set_finding_verdict(first["finding_id"], "confirmed")

    second = store.add_finding(conclusion(
        run, task["id"], title="路径拼接缺少规范化", summary="重跑后收窄为：缺少规范化，而非缺少鉴权。",
    ))

    assert second["action"] == "superseded"
    assert second["finding_id"] == first["finding_id"]
    assert second["revision"] == 2
    row = store.get_finding(first["finding_id"])
    assert row["title"] == "路径拼接缺少规范化"
    assert row["revision"] == 2
    # Identity, review history and the time the conclusion first existed all survive.
    assert row["created_at"] == "2026-01-01T00:00:00+00:00"
    assert row["verdict"] == "confirmed"
    assert [item["id"] for item in row["verifications"]] == [f"v-{first['finding_id']}"]
    assert len(store.list_findings(run["id"])) == 1


def test_the_replaced_version_is_archived_rather_than_lost(store, repository):
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    store.add_finding(conclusion(run, task["id"]))
    store.add_finding(conclusion(run, task["id"], summary="第二版结论：结论收窄到规范化问题。"))

    archived = store.get_finding("finding-1")["superseded_summary"]
    assert len(archived) == 1
    assert archived[0]["revision"] == 1
    assert archived[0]["summary"].startswith("请求参数传入文件处理函数")
    assert archived[0]["validation_state"] == "candidate"
    assert archived[0]["replaced_at"]


def test_the_archive_keeps_the_recent_versions_and_drops_the_oldest(store, repository):
    """A slot re-run many times must not grow the row without bound."""
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    for index in range(MAX_SUPERSEDED_SUMMARIES + 2):
        store.add_finding(conclusion(run, task["id"], summary=f"第 {index + 1} 版结论。"))

    row = store.get_finding("finding-1")
    assert row["revision"] == MAX_SUPERSEDED_SUMMARIES + 2
    assert [item["revision"] for item in row["superseded_summary"]] == [
        row["revision"] - index for index in range(MAX_SUPERSEDED_SUMMARIES, 0, -1)
    ]


# --- retracting, marking duplicate, contesting ------------------------------


def test_retracting_a_conclusion_keeps_its_row_its_text_and_its_evidence(store, repository):
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    written = store.add_finding(conclusion(run, task["id"]))
    verification(store, written["finding_id"])

    moved = store.set_finding_disposition(
        written["finding_id"], "retracted", "重跑证明该入口只接受白名单文件名。", by="planner",
    )

    assert moved is not None and moved["disposition"] == "retracted"
    assert moved["disposition_reason"] == "重跑证明该入口只接受白名单文件名。"
    assert moved["disposition_by"] == "planner"
    assert moved["disposition_at"]
    # Soft delete: nothing about the conclusion itself moved.
    assert moved["title"] == "未经规范化的文件名拼接"
    assert moved["evidence"] == [{"path": "public/index.php", "start_line": 4, "end_line": 4}]
    assert [item["id"] for item in moved["verifications"]] == [f"v-{written['finding_id']}"]


def test_a_round_can_take_back_a_conclusion_of_a_direction_it_already_settled(store, repository):
    """The direction being settled is exactly the case this exists for."""
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    written = store.add_finding(conclusion(run, task["id"]))

    round_with(
        store, run, task_key="entry-flow", action="retract", finding_key=written["finding_id"],
        rationale_summary="重跑证明该入口只接受白名单文件名。",
    )

    row = store.get_finding(written["finding_id"])
    assert row["disposition"] == "retracted"
    assert row["disposition_by"] == "planner"
    assert row["disposition_reason"] == "重跑证明该入口只接受白名单文件名。"


def test_a_conclusion_can_be_marked_duplicate_of_another_one(store, repository):
    run, _ = create_planner_run(store, repository)
    first = dispatch_one(store, run)
    second = dispatch_one(store, run, "sink-flow")
    settle(store, run)
    primary = store.add_finding(conclusion(run, first["id"], id="finding-a", fingerprint="fp-a"))
    repeated = store.add_finding(conclusion(
        run, second["id"], id="finding-b", fingerprint="fp-b", summary="同一处拼接的另一种写法。",
    ))

    round_with(
        store, run, task_key="sink-flow", action="duplicate", finding_key="finding-b",
        related_finding_key="finding-a", rationale_summary="两条结论指向同一处拼接。",
    )

    row = store.get_finding("finding-b")
    assert row["disposition"] == "duplicate"
    # Lineage is kept only because the target exists; both rows stay.
    assert row["derived_from_finding_id"] == "finding-a"
    assert store.get_finding("finding-a")["disposition"] == "open"
    assert sorted(item["id"] for item in store.list_findings(run["id"])) == ["finding-a", "finding-b"]
    assert primary["finding_id"] == "finding-a" and repeated["finding_id"] == "finding-b"


def test_lineage_is_never_written_to_a_conclusion_that_does_not_exist(store, repository):
    """A dangling "derived from" is worse than no lineage at all."""
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    store.add_finding(conclusion(run, task["id"]))

    round_with(
        store, run, task_key="entry-flow", action="duplicate", finding_key="finding-1",
        related_finding_key="finding-that-never-existed", rationale_summary="疑似重复。",
    )

    row = store.get_finding("finding-1")
    assert row["disposition"] == "duplicate"
    assert row["derived_from_finding_id"] is None


def test_a_human_verdict_is_terminal_so_a_round_can_only_contest_it(store, repository):
    """The disagreement is recorded; the conclusion keeps standing.

    Recording it as a withdrawal instead would let a Planner undo a person's reproduction
    result, and -- because a withdrawn conclusion no longer closes a goal -- would leave a
    run unable to finish on evidence a human had already confirmed.
    """
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    written = store.add_finding(conclusion(run, task["id"], verdict="confirmed"))

    round_with(
        store, run, task_key="entry-flow", action="retract", finding_key=written["finding_id"],
        rationale_summary="人工结论可能基于被修改过的环境。",
    )

    row = store.get_finding(written["finding_id"])
    assert row["disposition"] == "contested"
    assert row["verdict"] == "confirmed"
    assert row["disposition"] not in WITHDRAWN_FINDING_DISPOSITIONS
    # Still enough to close the run on.
    assert store.finalize_goal(run["id"], "met", "有已核验且未被撤回的结论。")["status"] == "met"


def test_a_withdrawn_conclusion_cannot_close_the_goal(store, repository):
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    written = store.add_finding(conclusion(run, task["id"]))

    round_with(
        store, run, task_key="entry-flow", action="retract", finding_key=written["finding_id"],
        rationale_summary="重跑证明该入口只接受白名单文件名。",
    )

    with pytest.raises(ValueError, match="without a validated source finding"):
        store.finalize_goal(run["id"], "met", "以现有结论收束。")
    assert store.get_task_goal(run["id"])["status"] == "open"


def test_a_new_conclusion_re_opens_a_slot_that_was_withdrawn(store, repository):
    """The disposition describes the text it was written about, not the slot forever."""
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    store.add_finding(conclusion(run, task["id"]))
    store.set_finding_disposition("finding-1", "retracted", "重跑证明该入口只接受白名单文件名。")

    store.add_finding(conclusion(run, task["id"], summary="第二次重跑：确实缺少规范化。"))

    row = store.get_finding("finding-1")
    assert row["disposition"] == "open"
    assert row["disposition_reason"] is None and row["disposition_at"] is None
    archived = row["superseded_summary"][0]
    assert archived["disposition"] == "retracted"
    assert archived["disposition_reason"] == "重跑证明该入口只接受白名单文件名。"


def test_no_path_removes_a_finding_row(store, repository):
    """Every disposition keeps the row: an audit that erases is not an audit."""
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    # Two slots of the same direction: the slot key is (run, direction, category), so the
    # pair has to differ in category to be two conclusions rather than two versions of one.
    kept = store.add_finding(conclusion(
        run, task["id"], id="finding-a", fingerprint="fp-a", category="task_goal_vulnerability",
    ))
    marked = store.add_finding(conclusion(
        run, task["id"], id="finding-b", fingerprint="fp-b", category="task_goal_weakness",
    ))

    round_with(
        store, run, task_key="entry-flow", action="retract", finding_key="finding-b",
        rationale_summary="该结论不成立。",
    )
    store.set_finding_disposition("finding-a", "duplicate", "与另一条重复。", derived_from_finding_id="finding-b")

    rows = {item["id"]: item for item in store.list_findings(run["id"])}
    assert set(rows) == {"finding-a", "finding-b"}
    assert rows["finding-a"]["disposition"] == "duplicate"
    assert rows["finding-b"]["disposition"] == "retracted"
    assert kept["finding_id"] == "finding-a" and marked["finding_id"] == "finding-b"


# --- what the model is allowed to ask for -----------------------------------


def validate(decision, *, findings, priors=None):
    return agent._validate_planner_decision(
        decision,
        {"stats": {}, "architecture": {}, "files": [{"path": "public/index.php", "line_count": 4}]},
        priors if priors is not None else [
            {"task_key": "entry-flow", "state": "completed", "revisions": 0,
             "files": ["public/index.php"], "dependencies": []},
        ],
        policy=AgentPolicy(),
        findings=findings,
    )


def finding_entry(finding_id: str = "finding-1", unit_id: str = "task-1") -> dict:
    return {"id": finding_id, "unit_id": unit_id, "paths": ["public/index.php"]}


def disposition_decision(**update) -> PlannerDecision:
    return PlannerDecision.model_validate({
        "goal_state": "continue",
        "basis_summary": "更正一条已有结论的处置状态。",
        "next_action": "记录撤回。",
        "missing_context": [],
        "tasks": [],
        "updates": [{"task_key": "entry-flow", "rationale_summary": "该结论不成立。", **update}],
    })


def settled_prior(task_id: str = "task-1") -> dict:
    return {
        "task_key": "entry-flow", "id": task_id, "state": "completed", "revisions": 0,
        "files": ["public/index.php"], "dependencies": [],
    }


def test_a_withdrawal_must_name_the_conclusion_it_withdraws():
    decision = disposition_decision(action="retract")
    with pytest.raises(ModelRetry, match="必须带 finding_key"):
        validate(decision, findings=[finding_entry()], priors=[settled_prior()])


def test_a_withdrawal_cannot_name_a_conclusion_this_run_never_wrote():
    decision = disposition_decision(action="retract", finding_key="finding-404")
    with pytest.raises(ModelRetry, match="不在本次运行的结论里"):
        validate(decision, findings=[finding_entry()], priors=[settled_prior()])


def test_a_withdrawal_cannot_reach_into_another_directions_conclusion():
    """Otherwise "the answer was wrong" would mean "make the answer I did not get go away"."""
    decision = disposition_decision(action="retract", finding_key="finding-1")
    with pytest.raises(ModelRetry, match="不属于任务 entry-flow"):
        validate(
            decision,
            findings=[finding_entry(unit_id="task-other")],
            priors=[settled_prior("task-1")],
        )


def test_a_duplicate_must_say_which_conclusion_it_duplicates():
    decision = disposition_decision(action="duplicate", finding_key="finding-1")
    with pytest.raises(ModelRetry, match="必须带 related_finding_key"):
        validate(decision, findings=[finding_entry()], priors=[settled_prior()])


def test_a_conclusion_cannot_be_a_duplicate_of_itself():
    decision = disposition_decision(
        action="duplicate", finding_key="finding-1", related_finding_key="finding-1",
    )
    with pytest.raises(ModelRetry, match="不能与自己重复"):
        validate(decision, findings=[finding_entry()], priors=[settled_prior()])


def test_a_disposition_the_round_could_act_on_passes_validation():
    """The guard refuses malformed intents, not the intent itself."""
    decision = disposition_decision(
        action="duplicate", finding_key="finding-1", related_finding_key="finding-2",
    )
    validate(
        decision,
        findings=[finding_entry(), finding_entry("finding-2")],
        priors=[settled_prior()],
    )


# --- report and metrics -----------------------------------------------------


def withdrawn_row(**overrides) -> dict:
    row = conclusion({"id": "run-1"}, "task-1", id="finding-1", fingerprint="fp-1")
    row.pop("run_id", None)
    row.pop("unit_id", None)
    row.update({
        "disposition": "retracted",
        "disposition_reason": "重跑证明该入口只接受白名单文件名。",
        "disposition_by": "planner",
        "revision": 2,
        "superseded_summary": [{
            "revision": 1,
            "title": "第一版：缺少鉴权",
            "summary": "入口未做鉴权检查。",
            "evidence": [{"path": "public/index.php", "start_line": 1, "end_line": 4}],
            "validation_state": "candidate",
            "disposition": "open",
            "disposition_reason": None,
            "replaced_at": "2026-01-03T00:00:00+00:00",
        }],
        "derived_from_finding_id": None,
    })
    row.update(overrides)
    return row


def test_the_report_states_why_a_conclusion_no_longer_counts():
    lines = "\n".join(report._finding_block(withdrawn_row(), 1))
    assert "已被 Planner 撤回" in lines
    assert "重跑证明该入口只接受白名单文件名" in lines
    assert "当前为第 2 版" in lines
    # The archived version is what makes "this changed its story" visible at all.
    assert "此前版本" in lines
    assert "第一版：缺少鉴权" in lines


def test_an_untouched_conclusion_gets_no_standing_boilerplate():
    row = withdrawn_row(disposition="open", revision=1, superseded_summary=[])
    lines = "\n".join(report._finding_block(row, 1))
    assert "结论状态" not in lines and "此前版本" not in lines


def test_the_report_lists_a_withdrawn_conclusion_apart_from_the_ones_that_count():
    standing, withdrawn = report._split_by_standing([withdrawn_row(), withdrawn_row(id="finding-2", disposition="open", revision=1)])
    assert [item["id"] for item in standing] == ["finding-2"]
    assert [item["id"] for item in withdrawn] == ["finding-1"]
    section = "\n".join(report._withdrawn_section(withdrawn))
    assert report.WITHDRAWN_HEADING in section
    assert "finding-1" in section or "未经规范化的文件名拼接" in section
    assert report._withdrawn_section([]) == []


def test_metrics_count_a_withdrawn_conclusion_separately():
    run = {"id": "run-1", "task_spec": None, "scope": []}
    rows = [withdrawn_row(id="finding-1"), withdrawn_row(id="finding-2", disposition="open", revision=1)]
    summary = metrics.summarise(run, [], rows, [])
    assert summary["withdrawn_findings"] == 1
    assert summary["candidates"] == 1 and summary["candidate_findings"] == 1


# --- the run says so while it happens ---------------------------------------


def planner_run(store, repository, monkeypatch, *, rounds):
    """Drive `_execute` with a scripted Planner and a scripted worker.

    The window these tests live in is worth stating: a worker only builds findings on
    ``achieved``, and a validated candidate lets the host close the goal on the spot, so
    the rounds in which a Planner can act on a conclusion are the ones where the
    conclusion did *not* satisfy the goal.  A finding that failed the evidence check is
    exactly that -- recorded, listed in the Planner's own situation, and not enough to
    close the run.

    ``closing_run`` below is the other half of that: what happens when the conclusion does
    hold up, and the run is therefore about to be closed on it.
    """
    from audit import worker as worker_module
    from tests.test_goal_tasks import make_worker, worker_outcome

    run, _ = create_planner_run(store, repository)
    worker = make_worker(store, repository)
    pursued: list[int] = []
    seen = [{"path": "public/index.php", "start_line": 1, "end_line": 4}]

    async def fake_plan(**kwargs):
        decision = rounds(kwargs, store.list_findings(run["id"]))
        return {
            "decision": decision,
            "usage": {"requests": 1, "tool_calls": 1, "input_tokens": 5, "output_tokens": 4},
            "error": None, "status": None, "terminal_reason": "completed",
        }

    async def fake_pursue(**_kwargs):
        pursued.append(1)
        # The first pass cites a line it never read, so its conclusion is recorded but
        # rejected; the second pass cites what it did read.
        evidence = "src/files.php:5-5" if len(pursued) == 1 else "public/index.php:4-4"
        return worker_outcome("achieved", finding={
            "title": "入口把请求参数拼进文件路径",
            "kind": "vulnerability",
            "severity": "high",
            "summary": f"第 {len(pursued)} 版结论：入口路径未做规范化。",
            "evidence": evidence,
            "input_source": "$_GET['path']",
            "propagation": "入口 handle 调用将 path 传入文件处理函数。",
            "dangerous_operation": "readfile('/srv/uploads/' . $path)",
            "protection": "认证检查不等于路径规范化。",
            "preconditions": "已通过认证的请求能够调用该入口。",
            "poc": None,
            "remediation": "在文件操作前规范化路径。",
        }, seen=seen)

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))
    return run, pursued


def test_a_rerun_of_the_same_direction_is_announced_as_a_replacement(store, repository, monkeypatch):
    """The slot keeps its identity and the run says the conclusion was replaced."""

    def rounds(kwargs, findings):
        if kwargs["round_no"] == 1:
            return {
                "goal_state": "continue", "basis_summary": "入口需要单独验证。",
                "next_action": "派发入口方向。", "missing_context": [],
                "tasks": [proposal("entry-flow")], "updates": [],
            }
        if kwargs["round_no"] == 2:
            return {
                "goal_state": "continue", "basis_summary": "上一轮的结论引用了没读过的行。",
                "next_action": "重跑入口方向。", "missing_context": [], "tasks": [],
                "updates": [{
                    "task_key": "entry-flow", "action": "reopen",
                    "rationale_summary": "该结论引用的行窗口属于另一个函数。",
                }],
            }
        return {
            "goal_state": "unreachable", "basis_summary": "重跑后仍无可用证据。",
            "next_action": "", "missing_context": [], "tasks": [], "updates": [],
        }

    run, pursued = planner_run(store, repository, monkeypatch, rounds=rounds)

    assert len(pursued) == 2
    findings = store.list_findings(run["id"])
    assert len(findings) == 1 and findings[0]["revision"] == 2
    assert findings[0]["validation_state"] == "candidate"
    assert findings[0]["superseded_summary"][0]["validation_state"] == "invalid_evidence"
    events = store.list_events(run["id"])
    superseded = next(item for item in events if item["kind"] == "finding_superseded")
    assert superseded["payload"]["finding_id"] == findings[0]["id"]
    assert superseded["payload"]["revision"] == 2
    assert superseded["payload"]["previous_revision"] == 1
    assert [item["kind"] for item in events].count("planner_task_reopened") == 1


def test_a_run_takes_back_a_conclusion_it_no_longer_stands_behind(store, repository, monkeypatch):
    """A withdrawal is announced, keeps the row, and spreads to report and metrics."""
    seen_keys: list[str] = []

    def rounds(kwargs, findings):
        if kwargs["round_no"] == 1:
            return {
                "goal_state": "continue", "basis_summary": "入口需要单独验证。",
                "next_action": "派发入口方向。", "missing_context": [],
                "tasks": [proposal("entry-flow")], "updates": [],
            }
        seen_keys.extend(item["id"] for item in findings)
        # Nothing else is dispatchable and the only conclusion does not hold, so the run
        # closes as inconclusive rather than claiming the objective is absent.
        return {
            "goal_state": "inconclusive", "basis_summary": "该结论站不住，且没有其它可派发的方向。",
            "next_action": "", "missing_context": [], "tasks": [],
            "updates": [{
                "task_key": "entry-flow", "action": "retract", "finding_key": findings[0]["id"],
                "rationale_summary": "重跑证明该入口只接受白名单文件名。",
            }],
        }

    run, pursued = planner_run(store, repository, monkeypatch, rounds=rounds)

    assert len(pursued) == 1
    # The Planner is shown the very conclusion it is asked to judge: a round cannot move
    # the disposition of something it was never told about.
    assert seen_keys == [store.list_findings(run["id"])[0]["id"]]
    findings = store.list_findings(run["id"])
    assert len(findings) == 1
    row = findings[0]
    assert row["disposition"] == "retracted"
    assert row["disposition_by"] == "planner"
    assert "白名单" in row["disposition_reason"]
    # Soft delete all the way through: the conclusion is still there to be read, with the
    # reason its citations were thrown out.
    assert row["title"] == "入口把请求参数拼进文件路径"
    assert row["summary"].startswith("第 1 版结论")
    assert row["validation_state"] == "invalid_evidence" and row["validation_errors"]
    events = store.list_events(run["id"])
    retracted = next(item for item in events if item["kind"] == "finding_retracted")
    assert retracted["payload"]["requested_action"] == "retract"
    assert retracted["payload"]["disposition"] == "retracted"
    assert retracted["payload"]["finding_id"] == row["id"]
    # And it no longer appears among the conclusions that count.
    standing, withdrawn = report._split_by_standing(store.list_findings(run["id"]))
    assert standing == [] and [item["id"] for item in withdrawn] == [row["id"]]


def closing_run(store, repository, monkeypatch, *, rounds, task: dict | None = None):
    """Drive ``_execute`` to the moment the host is ready to close on a conclusion.

    Every attempt cites a line it actually read, so what comes back is a candidate the host
    would close the run on.  The scripted rounds below therefore see the run's pre-closure
    review: a candidate used to end the run the instant it was written, which left the
    Planner with no round in which to correct the very conclusion the run was closed on.

    Returns the run, the directions the workers were given, and -- for every Planner round
    -- the ids of the conclusions that round was shown.
    """
    from audit import worker as worker_module
    from tests.test_goal_tasks import make_worker, worker_outcome

    run, _ = create_planner_run(store, repository, task=task)
    worker = make_worker(store, repository)
    pursued: list[str] = []
    shown: list[list[str]] = []

    async def fake_plan(**kwargs):
        shown.append([str(item["id"]) for item in kwargs["run_context"]["findings"]])
        return {
            "decision": rounds(kwargs),
            "usage": {"requests": 1, "tool_calls": 1, "input_tokens": 5, "output_tokens": 4},
            "error": None, "status": None, "terminal_reason": "completed",
        }

    async def fake_pursue(**kwargs):
        key = str(kwargs["planner_task"]["task_key"])
        pursued.append(key)
        return worker_outcome("achieved", finding={
            "title": "入口把请求参数拼进文件路径",
            "kind": "vulnerability",
            "severity": "high",
            "summary": f"{key} 方向：入口路径未做规范化。",
            "evidence": "public/index.php:4-4",
            "input_source": "$_GET['path']",
            "propagation": "入口 handle 调用将 path 传入文件处理函数。",
            "dangerous_operation": "readfile('/srv/uploads/' . $path)",
            "protection": "认证检查不等于路径规范化。",
            "preconditions": "已通过认证的请求能够调用该入口。",
            "poc": None,
            "remediation": "在文件操作前规范化路径。",
        }, seen=[{"path": "public/index.php", "start_line": 1, "end_line": 4}])

    monkeypatch.setattr(worker_module, "plan_audit_frontier", fake_plan)
    monkeypatch.setattr(worker_module, "pursue_planner_task", fake_pursue)
    asyncio.run(worker._execute(run))
    return run, pursued, shown


def entry_flow_round(**_overrides) -> dict:
    """Round one: send the worker at the entry direction."""
    return {
        "goal_state": "continue", "basis_summary": "入口需要单独验证。",
        "next_action": "派发入口方向。", "missing_context": [],
        "tasks": [proposal("entry-flow")], "updates": [], **_overrides,
    }


def test_the_host_reviews_a_standing_conclusion_before_it_closes(store, repository, monkeypatch):
    """The conclusion a run is closed on is shown to the Planner once before it closes."""

    def rounds(kwargs):
        if kwargs["round_no"] == 1:
            return entry_flow_round()
        return {
            "goal_state": "met", "basis_summary": "入口结论成立，可以收束。",
            "next_action": "", "missing_context": [], "tasks": [], "updates": [],
        }

    run, pursued, shown = closing_run(store, repository, monkeypatch, rounds=rounds)

    assert pursued == ["entry-flow"]
    # Two rounds, not one: the second exists only to look at what the first produced.
    assert len(shown) == 2
    findings = store.list_findings(run["id"])
    assert len(findings) == 1
    assert shown[1] == [findings[0]["id"]]
    assert findings[0]["validation_state"] == "candidate"
    assert store.get_task_goal(run["id"])["status"] == "met"
    assert store.get_run(run["id"])["status"] == "completed"


def test_a_review_round_can_take_back_the_conclusion_the_run_would_close_on(store, repository, monkeypatch):
    """A standing conclusion is not exempt from correction just because it ends the run."""

    def rounds(kwargs):
        if kwargs["round_no"] == 1:
            return entry_flow_round()
        finding_id = kwargs["run_context"]["findings"][0]["id"]
        return {
            "goal_state": "inconclusive", "basis_summary": "该入口只接受白名单文件名，这条结论不成立。",
            "next_action": "", "missing_context": [], "tasks": [],
            "updates": [{
                "task_key": "entry-flow", "action": "retract", "finding_key": finding_id,
                "rationale_summary": "重跑证明该入口只接受白名单文件名。",
            }],
        }

    run, pursued, _ = closing_run(store, repository, monkeypatch, rounds=rounds)

    assert pursued == ["entry-flow"]
    row = store.list_findings(run["id"])[0]
    assert row["disposition"] == "retracted" and row["disposition_by"] == "planner"
    # The evidence was never in question -- only the run's standing behind it changed.
    assert row["validation_state"] == "candidate"
    # And the run did not close as a success on a conclusion it had just withdrawn.
    assert store.get_task_goal(run["id"])["status"] == "inconclusive"
    assert store.get_run(run["id"])["status"] == "inconclusive"
    kinds = [item["kind"] for item in store.list_events(run["id"])]
    assert kinds.count("finding_retracted") == 1
    assert "run_completed" not in kinds


def test_a_review_round_can_reopen_the_direction_it_is_unsure_about(store, repository, monkeypatch):
    """The rerun lands in the same slot and the run then closes on the corrected result."""

    def rounds(kwargs):
        if kwargs["round_no"] == 1:
            return entry_flow_round()
        if kwargs["round_no"] == 2:
            return {
                "goal_state": "continue", "basis_summary": "这条结论的行窗口对不上，重跑入口方向。",
                "next_action": "重跑入口方向。", "missing_context": [], "tasks": [],
                "updates": [{
                    "task_key": "entry-flow", "action": "reopen",
                    "rationale_summary": "结论引用的行窗口属于另一个函数。",
                }],
            }
        return {
            "goal_state": "met", "basis_summary": "重跑后的结论站得住。",
            "next_action": "", "missing_context": [], "tasks": [], "updates": [],
        }

    run, pursued, _ = closing_run(store, repository, monkeypatch, rounds=rounds)

    # The reopened direction really was investigated again, after the run had a conclusion.
    assert pursued == ["entry-flow", "entry-flow"]
    findings = store.list_findings(run["id"])
    assert len(findings) == 1 and findings[0]["revision"] == 2
    assert findings[0]["validation_state"] == "candidate"
    assert store.get_task_goal(run["id"])["status"] == "met"
    kinds = [item["kind"] for item in store.list_events(run["id"])]
    assert kinds.count("planner_task_reopened") == 1
    assert kinds.count("finding_superseded") == 1


def test_queued_directions_are_not_started_once_a_conclusion_satisfies_the_goal(store, repository, monkeypatch):
    """stop_on_achieved still stops queued work -- it stops it one review later, not never."""

    def rounds(kwargs):
        if kwargs["round_no"] == 1:
            return {
                "goal_state": "continue", "basis_summary": "两个方向都要看。",
                "next_action": "先派入口方向。", "missing_context": [],
                "tasks": [
                    {**proposal("entry-flow"), "priority": 90},
                    proposal("file-operation", path="src/files.php", end=5),
                ],
                "updates": [],
            }
        return {
            "goal_state": "met", "basis_summary": "入口结论成立。",
            "next_action": "", "missing_context": [], "tasks": [], "updates": [],
        }

    run, pursued, _ = closing_run(
        store, repository, monkeypatch, rounds=rounds, task={**TASK, "max_workers": 1}
    )

    assert pursued == ["entry-flow"]
    queued = next(item for item in store.list_tasks(run["id"]) if item["task_key"] == "file-operation")
    assert queued["state"] == "cancelled" and queued["attempts"] == 0
    assert store.get_task_goal(run["id"])["status"] == "met"


def test_a_review_that_asks_for_a_queued_direction_releases_it(store, repository, monkeypatch):
    """A review that names work is read as "the run is not finished", so that work runs."""

    def rounds(kwargs):
        if kwargs["round_no"] == 1:
            return {
                "goal_state": "continue", "basis_summary": "两个方向都要看。",
                "next_action": "先派入口方向。", "missing_context": [],
                "tasks": [
                    {**proposal("entry-flow"), "priority": 90},
                    proposal("file-operation", path="src/files.php", end=5),
                ],
                "updates": [],
            }
        if kwargs["round_no"] == 2:
            return {
                "goal_state": "continue", "basis_summary": "文件操作方向还没跑，本轮让它跑。",
                "next_action": "重提文件操作方向。", "missing_context": [],
                "tasks": [{
                    **proposal("file-operation", path="src/files.php", end=5),
                    "rationale_summary": "带着入口方向的结论重跑它。",
                }],
                "updates": [],
            }
        return {
            "goal_state": "met", "basis_summary": "两个方向都已有结论。",
            "next_action": "", "missing_context": [], "tasks": [], "updates": [],
        }

    run, pursued, _ = closing_run(
        store, repository, monkeypatch, rounds=rounds, task={**TASK, "max_workers": 1}
    )

    assert pursued == ["entry-flow", "file-operation"]
    assert store.get_task_goal(run["id"])["status"] == "met"
