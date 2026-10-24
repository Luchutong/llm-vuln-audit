"""The Planner's cross-check of automatic POC verdicts.

Two independent readings of the same runner output are stronger than one, so a verified
conclusion only counts towards closure once a *different* agent has recorded its own
reading of the observations the host captured.  These tests pin the three parts of that:
the review is stored per revision, a stale or invented review is refused, and the closure
gate really refuses to close until the cross-check happened.
"""
from __future__ import annotations

import sqlite3

import pytest

from audit.db import Store
from tests.test_finding_disposition import (
    conclusion,
    create_planner_run,
    dispatch_one,
    settle,
)
from audit.source import SourceRepository


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "source-data")


def verified_finding(store, run, task):
    record = conclusion(run, task["id"])
    store.add_finding(record)
    store.set_finding_verification_state(record["id"], "verified", "confirmed")
    return store.get_finding(record["id"]) or record


def review(finding, **overrides) -> dict:
    record = {
        "finding_id": finding["id"],
        "revision": int(finding.get("revision") or 1),
        "decision": "confirmed",
        "rationale_summary": "攻击侧读到 /etc/passwd 而正常侧被拒绝，观测确实支撑该结论。",
    }
    record.update(overrides)
    return record


def test_a_verified_conclusion_is_pending_until_a_round_reads_it(store, repository):
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    finding = verified_finding(store, run, task)

    pending = store.unreviewed_verified_findings(run["id"])
    assert [item["id"] for item in pending] == [finding["id"]]

    stored = store.record_verification_reviews(run["id"], [review(finding)], plan_id="plan-1")
    assert len(stored) == 1 and stored[0]["decision"] == "confirmed"
    assert store.unreviewed_verified_findings(run["id"]) == []
    assert [item["finding_id"] for item in store.list_verification_reviews(run["id"])] == [finding["id"]]


def test_a_stale_or_invented_review_is_refused_rather_than_stored(store, repository):
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    finding = verified_finding(store, run, task)

    stored = store.record_verification_reviews(run["id"], [
        review(finding, revision=99, rationale_summary="用过期修订号自称复核过。"),
        review(finding, finding_id="does-not-exist"),
        review(finding, decision="looks-fine"),
        review(finding, rationale_summary="   "),
    ])
    assert stored == []
    assert len(store.unreviewed_verified_findings(run["id"])) == 1


def test_an_unverified_conclusion_is_not_gated(store, repository):
    """Only verified verdicts need a second reading; a static conclusion is unaffected."""
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    record = conclusion(run, task["id"], id="finding-plain")
    store.add_finding(record)

    assert store.unreviewed_verified_findings(run["id"]) == []
    stored = store.record_verification_reviews(run["id"], [review(record)])
    assert stored == []


def test_closure_refuses_a_verified_conclusion_nobody_cross_checked(store, repository):
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    finding = verified_finding(store, run, task)

    with pytest.raises(ValueError, match="未经 Planner 比对核实"):
        store.finalize_goal(run["id"], "met", "隔离环境已复现。", require_reviewed=True)

    store.record_verification_reviews(run["id"], [review(finding)], plan_id="plan-1")
    settled = store.finalize_goal(run["id"], "met", "隔离环境已复现，且已比对核实。", require_reviewed=True)
    assert settled["status"] == "met"


def test_the_gate_is_opt_in_so_plain_source_runs_close_as_before(store, repository):
    """A run with no POC verdict must not acquire a review requirement from nowhere."""
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    record = conclusion(run, task["id"], id="finding-plain-2")
    store.add_finding(record)

    settled = store.finalize_goal(run["id"], "met", "静态证据已足够。")
    assert settled["status"] == "met"


def test_the_review_captures_the_observations_it_was_based_on(store, repository):
    """The durable row keeps what the round read, not just the word it answered with."""
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    finding = verified_finding(store, run, task)
    store.add_verification({
        "id": "v-1",
        "finding_id": finding["id"],
        "created_at": "2026-01-02T00:00:00+00:00",
        "execution_status": "executed",
        "verdict": "confirmed",
        "original_script": "<?php echo 1;",
        "modified_script": "",
        "modification_notes": "",
        "target_version": "php8",
        "command": "php poc.php",
        "expected_result": "读到了目录外的文件",
        "normal_observation": "拒绝访问",
        "attack_observation": "读到了 /etc/passwd",
        "browser_execution": False,
        "notes": "job-1 exit_code=0",
        "files": [],
        "status": "verified",
    })

    stored = store.record_verification_reviews(run["id"], [review(finding, verification_id="v-1")])
    assert stored[0]["observed_attack"] == "读到了 /etc/passwd"
    assert stored[0]["observed_normal"] == "拒绝访问"


def test_the_review_reaches_the_finding_the_page_renders(store, repository):
    """A review only the Planner can see is not a defence the grader can inspect."""
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    finding = verified_finding(store, run, task)
    store.record_verification_reviews(run["id"], [review(finding)], plan_id="plan-1")

    rendered = store.get_finding(finding["id"])
    assert [(item["decision"], item["rationale"]) for item in rendered["verification_reviews"]] == [
        ("confirmed", "攻击侧读到 /etc/passwd 而正常侧被拒绝，观测确实支撑该结论。")
    ]


def test_a_contested_verdict_cannot_close_a_goal(store, repository):
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    finding = verified_finding(store, run, task)
    store.record_verification_reviews(run["id"], [review(finding, decision="contested")])
    with pytest.raises(ValueError, match="without a validated"):
        store.finalize_goal(run["id"], "met", "不能以质疑中的结论收束。", require_reviewed=True)


def test_an_independent_confirmed_finding_can_still_close_after_another_is_contested(store, repository):
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    first = verified_finding(store, run, task)
    store.record_verification_reviews(run["id"], [review(first, decision="contested")])
    second = conclusion(run, "independent-task", id="second-finding", fingerprint="second-fingerprint")
    store.add_finding(second)
    store.set_finding_verification_state(second["id"], "verified", "confirmed")
    store.record_verification_reviews(run["id"], [review(second)])
    assert store.finalize_goal(run["id"], "met", "独立证据已核实。", require_reviewed=True)["status"] == "met"


def test_new_verification_of_same_revision_requires_a_new_review(store, repository):
    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    finding = verified_finding(store, run, task)
    def put(ident, stamp, status="verified"):
        store.add_verification({
            "id": ident, "finding_id": finding["id"], "created_at": stamp,
            "status": status, "verdict": "confirmed" if status == "verified" else "uncertain",
            "execution_status": "success", "original_script": "", "modified_script": "",
            "modification_notes": "", "target_version": "fixture", "command": "", "expected_result": "",
            "normal_observation": "normal", "attack_observation": ident,
            "browser_execution": False, "notes": "fixture", "files": [],
        })
    put("proof-one", "2026-01-01")
    assert store.record_verification_reviews(run["id"], [review(finding, verification_id="proof-one")])
    put("failed-later", "2026-01-02", "inconclusive")
    assert store.unreviewed_verified_findings(run["id"]) == []
    assert store.verification_records([finding])[0]["verification_id"] == "proof-one"
    put("proof-two", "2026-01-03")
    pending = store.unreviewed_verified_findings(run["id"])
    assert pending[0]["verification_id"] == "proof-two"
    assert not store.record_verification_reviews(run["id"], [review(finding, verification_id="proof-one")])
    assert store.record_verification_reviews(run["id"], [review(finding, verification_id="proof-two")])
    assert store.unreviewed_verified_findings(run["id"]) == []
    # Re-reading a new proof must not erase what an earlier round reviewed.
    saved = store.verification_reviews_for(run["id"], finding["id"])
    assert {item["verification_id"]: item["observed_attack"] for item in saved} == {
        "proof-one": "proof-one", "proof-two": "proof-two",
    }


@pytest.mark.parametrize("has_verification_id", [False, True])
def test_old_review_index_upgrade_preserves_history_and_is_repeatable(tmp_path, has_verification_id):
    path = tmp_path / "old-audit.db"
    with sqlite3.connect(path) as connection:
        column = "verification_id TEXT NOT NULL DEFAULT ''," if has_verification_id else ""
        connection.executescript(f"""
            CREATE TABLE verification_reviews (
                id TEXT PRIMARY KEY, {column}
                run_id TEXT NOT NULL, plan_id TEXT, finding_id TEXT NOT NULL,
                revision INTEGER NOT NULL, decision TEXT NOT NULL, rationale TEXT NOT NULL,
                observed_normal TEXT NOT NULL DEFAULT '', observed_attack TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX idx_verification_reviews_unique
                ON verification_reviews(run_id, finding_id, revision);
            INSERT INTO verification_reviews
                (id,run_id,finding_id,revision,decision,rationale,created_at)
                VALUES ('old-review','run','finding',1,'confirmed','original review','2026-01-01');
        """)
    for start in range(2):
        upgraded = Store(path)
        try:
            old = upgraded.list_verification_reviews("run")[0]
            assert old["id"] == "old-review" and old["verification_id"] == ""
            indexes = {row["name"] for row in upgraded._rows("PRAGMA index_list(verification_reviews)")}
            assert "idx_verification_reviews_unique" not in indexes
            assert [row["name"] for row in upgraded._rows("PRAGMA index_info(idx_verification_reviews_proof)")] == [
                "run_id", "finding_id", "revision", "verification_id",
            ]
            if start == 0:
                upgraded._write(
                    "INSERT INTO verification_reviews"
                    " (id,run_id,finding_id,revision,verification_id,decision,rationale,created_at)"
                    " VALUES ('new-review','run','finding',1,'proof-two','confirmed','new proof','2026-01-02')"
                )
                with pytest.raises(sqlite3.IntegrityError):
                    upgraded._write(
                        "INSERT INTO verification_reviews"
                        " (id,run_id,finding_id,revision,verification_id,decision,rationale,created_at)"
                        " VALUES ('duplicate','run','finding',1,'proof-two','confirmed','duplicate','2026-01-03')"
                    )
            assert {item["id"] for item in upgraded.list_verification_reviews("run")} == {
                "old-review", "new-review",
            }
        finally:
            upgraded.close()


def test_late_execution_epoch_cannot_write_a_review(store, repository):
    from audit.execution_state import execution_context
    from audit.runtime import StopAudit

    run, _ = create_planner_run(store, repository)
    task = dispatch_one(store, run)
    settle(store, run)
    finding = verified_finding(store, run, task)
    old_epoch = run["execution_epoch"]
    store.request_pause(run["id"])
    store.quiesce_execution(run["id"])
    assert store.resume_run(run["id"])
    resumed = store.claim_next_run()
    assert resumed["execution_epoch"] != old_epoch
    with execution_context(store, run["id"], old_epoch):
        with pytest.raises(StopAudit, match="迟到"):
            store.record_verification_reviews(run["id"], [review(finding)], plan_id="old-round")
    assert store.list_verification_reviews(run["id"]) == []
    with execution_context(store, run["id"], resumed["execution_epoch"]):
        assert store.record_verification_reviews(run["id"], [review(finding)], plan_id="new-round")
