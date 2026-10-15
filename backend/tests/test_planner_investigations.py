"""Pinned investigations: written once, replayed verbatim, never rewritten.

The Planner re-plans from scratch every round, so without these rows the same question
gets asked again and answered again -- paying for reconnaissance twice and, worse,
planning the second round against an answer that may differ from the one the first round
acted on.  A pinned record is the run's memory of what it already found out, so the
properties that matter are all about not rewriting it.
"""
from __future__ import annotations

import sqlite3

import pytest

from audit.db import (
    INVESTIGATION_STATUSES,
    MAX_INVESTIGATION_TOPIC,
    Store,
    now,
)


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


def record(topic: str, payload: dict, **overrides) -> dict:
    return {
        "run_id": "run-1",
        "goal_id": "goal-1",
        "plan_id": "plan-1",
        "round_no": 2,
        "kind": "recon",
        "tool": "investigate_project",
        "topic": topic,
        "payload": payload,
        "files_read": ["src/bootstrap.php"],
        "usage": {"requests": 2},
        "created_at": now(),
        **overrides,
    }


def test_a_record_is_written_once_and_read_back_verbatim(store):
    stored = store.record_investigation(
        record("这个项目应该从哪里开始读？", {"summary": "入口包含 bootstrap，数据库访问集中在 db()。"})
    )

    assert stored["status"] == "active"
    assert stored["revision"] == 1
    assert stored["payload"]["summary"].startswith("入口包含 bootstrap")
    assert stored["files_read"] == ["src/bootstrap.php"]
    assert stored["payload_bytes"] > 0

    hit = store.current_investigation("run-1", stored["topic_key"])
    assert hit is not None
    # Reuse is the payload coming back unchanged, so the round plans against what was
    # really observed rather than against a regenerated answer.
    assert hit["payload"] == stored["payload"]
    assert hit["id"] == stored["id"]


def test_the_same_topic_cannot_be_pinned_twice_while_it_is_active(store):
    """``uq_inv_active`` is the gate: a re-ask reuses, and only a revision may replace."""
    store.record_investigation(record("从入口到数据库的路径", {"summary": "第一次"}))

    with pytest.raises(sqlite3.IntegrityError):
        store.record_investigation(record("从入口到数据库的路径", {"summary": "第二次"}))


def test_a_revision_supersedes_the_old_row_and_leaves_its_content_untouched(store):
    """Correction appends; the replaced record stays readable exactly as it was.

    That is what lets a report say "round 3 planned against this, round 5 against that"
    instead of silently showing only the latest answer.
    """
    first = store.record_investigation(record("从入口到数据库的路径", {"summary": "第一次"}))
    store.set_investigation_status(first["id"], "superseded", reason="第一次只读了入口", superseded_by="inv-2")
    second = store.record_investigation(
        record("从入口到数据库的路径", {"summary": "第二次，补读了 bootstrap"}, revision=2)
    )

    assert second["revision"] == 2
    assert store.current_investigation("run-1", first["topic_key"])["id"] == second["id"]
    kept = store.get_investigation(first["id"])
    assert kept["status"] == "superseded"
    assert kept["reason"] == "第一次只读了入口"
    assert kept["superseded_by"] == "inv-2"
    # Content columns are not part of the update surface, so the old answer is intact.
    assert kept["payload"] == {"summary": "第一次"}
    assert kept["topic"] == "从入口到数据库的路径"
    assert kept["round_no"] == 2
    assert kept["revision"] == 1


def test_only_the_declared_statuses_are_writable(store):
    stored = store.record_investigation(record("话题", {"summary": "x"}))
    with pytest.raises(ValueError):
        store.set_investigation_status(stored["id"], "deleted")
    store.set_investigation_status(stored["id"], "retracted", reason="结论被撤回")
    assert store.get_investigation(stored["id"])["status"] == "retracted"
    assert INVESTIGATION_STATUSES == ("active", "superseded", "retracted")
    # A retracted record frees the topic for a fresh pin rather than blocking it.
    assert store.current_investigation("run-1", stored["topic_key"]) is None
    store.record_investigation(record("话题", {"summary": "重新调查的结果"}))
    assert store.current_investigation("run-1", stored["topic_key"])["payload"]["summary"] == "重新调查的结果"


def test_a_topic_key_survives_whitespace_and_case(store):
    """The second round writes its question in fresh prose; reuse must not need repetition."""
    first = store.investigation_topic_key("Where does the request reach the database?")
    assert first == store.investigation_topic_key("  where   does the request\nreach the DATABASE?  ")
    assert first != store.investigation_topic_key("Where does the request reach the filesystem?")
    assert store.investigation_topic_key("x" * (MAX_INVESTIGATION_TOPIC + 50)) == store.investigation_topic_key(
        "x" * MAX_INVESTIGATION_TOPIC
    )


def test_a_listing_carries_no_payload_and_the_overview_counts_each_status(store):
    kept = store.record_investigation(record("第一个话题", {"summary": "长正文" * 50}))
    store.record_investigation(record("第二个话题", {"summary": "另一段正文"}))
    store.set_investigation_status(kept["id"], "superseded", reason="已被取代")

    listed = store.list_investigations("run-1")
    assert [item["topic"] for item in listed] == ["第一个话题", "第二个话题"]
    # A listing feeds prompts and run responses, so the正文 stays behind
    # ``get_investigation`` and cannot make either grow with research nobody asked for.
    assert all(item["payload"] is None for item in listed)

    overview = store.investigation_overview("run-1")
    assert overview["total"] == 2
    assert overview["by_status"] == {"active": 1, "superseded": 1}
    assert [item["topic"] for item in overview["recent"]] == ["第一个话题", "第二个话题"]
    assert overview["recent"][0]["status"] == "superseded"
    # ``recent`` is newest-last, the order a round prompt reads.
    assert store.list_investigations("run-1", limit=1)[0]["topic"] == "第二个话题"
