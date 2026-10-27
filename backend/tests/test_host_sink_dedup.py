"""Offline host deduplication uses typed coordinates and an unambiguous sink."""
import copy

import pytest

from audit.project_findings import pick_run_merge_candidate, sink_similarity
from tests.test_goal_tasks import TASK, _conclusion_finding, create_planner_run, repository, store


def claim(name, *, sink="readfile user controlled path", path="public/index.php", line=4,
          vulnerability_type="path_traversal", **fields):
    return {
        "id": name, "vulnerability_type": vulnerability_type,
        "primary_location": {"path": path, "line": line},
        "dangerous_operation": sink, **fields,
    }


def persisted_claim(store, run, name, **changes):
    value = {**_conclusion_finding(run, name), **claim(name, **changes),
             "unit_id": f"unit-{name}", "category": f"claim-{name}"}
    store.add_finding(value)
    # Matching typed coordinates work even when the legacy project ledger assigned
    # different rows to two rewritten claims. Raw source findings stay separate.
    store.link_finding_project(name, f"ledger-{name}", 1)
    return value


@pytest.mark.parametrize(("sink", "expected"), [
    ("readfile user controlled path response", True),
    ("readfile user controlled input file", False),
    ("render html template", False),
])
def test_threshold_is_shared_with_ledger_sink_similarity(sink, expected):
    candidate = claim("existing")
    incoming = claim("new", sink=sink)
    assert (sink_similarity(incoming["dangerous_operation"], candidate["dangerous_operation"]) >= 0.6) is expected
    assert (pick_run_merge_candidate(incoming, [candidate]) is candidate) is expected


def test_exact_threshold_is_inclusive():
    incoming = claim("new", sink="alpha beta gamma delta")
    candidate = claim("existing", sink="alpha beta gamma epsilon")
    assert sink_similarity(incoming["dangerous_operation"], candidate["dangerous_operation"]) == 0.6
    assert pick_run_merge_candidate(incoming, [candidate]) is candidate


def test_two_threshold_passing_candidates_remain_ambiguous():
    incoming = claim("new", sink="readfile user controlled path response")
    first = claim("one")
    second = claim("two", sink="readfile user controlled path output")
    assert pick_run_merge_candidate(incoming, [first, second]) is None


@pytest.mark.parametrize("changes", [
    {"path": "src/files.php"}, {"line": 5}, {"vulnerability_type": "lfi"},
    {"vulnerability_type": "unknown"},
])
def test_other_coordinate_or_type_never_merges(changes):
    assert pick_run_merge_candidate(claim("new"), [claim("existing", **changes)]) is None


def test_canonical_type_aliases_share_coordinates():
    incoming = claim("new", vulnerability_type="sql_injection")
    candidate = claim("existing", vulnerability_type="sqli")
    assert pick_run_merge_candidate(incoming, [candidate]) is candidate


def test_input_and_precondition_prose_is_not_an_extra_equality_gate():
    incoming = claim("new", input_source="请求路径参数", preconditions=["已登录会员"])
    candidate = claim("existing", input_source="GET path", preconditions=["authenticated user"])
    assert pick_run_merge_candidate(incoming, [candidate]) is candidate


def test_reworded_unique_sink_marks_duplicate_and_keeps_source_history(store, repository):
    run, _ = create_planner_run(store, repository, task=TASK)
    first = persisted_claim(store, run, "first")
    second = persisted_claim(store, run, "second", sink="readfile user controlled path response",
                             input_source="用户提供的路径", preconditions=["已登录会员"])

    result = store.classify_run_duplicate(run["id"], "second")

    assert result["disposition"] == "duplicate"
    assert result["identity_tier"] == 2
    assert result["related_finding_id"] == "first"
    assert result["sink_similarity"] >= 0.6
    assert store.get_finding("first")["disposition"] == "open"
    saved = store.get_finding("second")
    assert saved["derived_from_finding_id"] == "first"
    for field in ("dangerous_operation", "input_source", "preconditions", "evidence"):
        assert saved[field] == second[field]
    assert len(store.list_findings(run["id"])) == 2
    assert first["id"] != saved["id"]


def test_ambiguous_successful_sinks_emit_only_a_review_candidate(store, repository):
    run, _ = create_planner_run(store, repository, task=TASK)
    persisted_claim(store, run, "first")
    persisted_claim(store, run, "second", sink="readfile user controlled path output")
    persisted_claim(store, run, "third", sink="readfile user controlled path response")

    result = store.classify_run_duplicate(run["id"], "third")

    assert set(result["candidate_ids"]) == {"first", "second"}
    assert "disposition" not in result
    assert store.get_finding("third")["disposition"] == "open"
    assert not store.has_event(run["id"], "finding_duplicate")


def test_withdrawn_candidate_does_not_make_one_open_sink_ambiguous(store, repository):
    run, _ = create_planner_run(store, repository, task=TASK)
    persisted_claim(store, run, "first")
    persisted_claim(store, run, "withdrawn", sink="readfile user controlled path output")
    store.set_finding_disposition("withdrawn", "retracted", "已撤回的历史主张。")
    persisted_claim(store, run, "new", sink="readfile user controlled path response")

    result = store.classify_run_duplicate(run["id"], "new")

    assert result["disposition"] == "duplicate"
    assert result["related_finding_id"] == "first"


def test_same_sink_at_two_coordinates_is_not_deduplicated_even_with_one_ledger(store, repository):
    run, _ = create_planner_run(store, repository, task=TASK)
    persisted_claim(store, run, "first")
    persisted_claim(store, run, "second", line=5)
    store.link_finding_project("second", "ledger-first", 1)

    result = store.classify_run_duplicate(run["id"], "second")

    assert result["candidate_ids"] == ["first"]
    assert store.get_finding("second")["disposition"] == "open"


def test_exact_duplicates_keep_the_first_tier_without_fuzzy_changes(store, repository):
    run, _ = create_planner_run(store, repository, task=TASK)
    first = persisted_claim(store, run, "first")
    second = {**copy.deepcopy(first), "id": "second", "unit_id": "unit-second", "fingerprint": "second"}
    store.add_finding(second)
    store.link_finding_project("second", "ledger-second", 1)

    result = store.classify_run_duplicate(run["id"], "second")

    assert result["disposition"] == "duplicate"
    assert result.get("identity_tier", 1) == 1
