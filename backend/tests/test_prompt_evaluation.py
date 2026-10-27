"""Offline v2 scoring fixtures: no network, model, live database or POC."""
from __future__ import annotations

import copy
import itertools
import json
from pathlib import Path

import pytest

from audit.prompt_evaluation import (DEFAULT_ANCHORS_PATH, DEFAULT_TRUTH_PATH,
                                     evaluate_v2, summarise_trials, validate_assets)

ROOT = Path(__file__).resolve().parents[2]


def assets():
    truths = {"vulnerabilities": [
        {"id": "A", "class": "sqli", "title": "A", "location": [{"path": "app/x.php", "line": 10}], "cvss": {"base_score": 7.5}},
        {"id": "B", "class": "sqli", "title": "B", "location": [{"path": "app/x.php", "line": 10}], "cvss": {"base_score": 7.5}},
        {"id": "C", "class": "xss_r", "title": "C", "location": [{"path": "app/x.php", "line": 40}], "cvss": {"base_score": 6.1}},
    ]}
    anchors = {"protocol": "lab30-v2", "archive_root": "lab30-shop", "vulnerabilities": [
        {"id": "A", "class": "sqli", "scoring_locations": [{"path": "app/x.php", "line": n} for n in (10, 20)]},
        {"id": "B", "class": "sqli", "scoring_locations": [{"path": "app/x.php", "line": 10}]},
        {"id": "C", "class": "xss_r", "scoring_locations": [{"path": "app/x.php", "line": 40}]},
    ]}
    return truths, anchors


def finding(ident, line, typ="sqli", **kwargs):
    return {"id": ident, "kind": "vulnerability", "vulnerability_type": typ,
            "primary_location": {"path": "lab30-shop/app/x.php", "line": line}, **kwargs}


def test_maximum_matching_avoids_greedy_loss_and_array_order():
    truth, anchors = assets()
    rows = [finding("f1", 10), finding("f2", 20)]
    expected = [("A", "f2"), ("B", "f1")]
    for predictions in itertools.permutations(rows):
        for truths in itertools.permutations(truth["vulnerabilities"]):
            score = evaluate_v2({"vulnerabilities": list(truths)}, list(predictions), anchors)
            assert score["TP"] == 2
            assert [(m["truth_id"], m["finding_id"]) for m in score["matches"]] == expected


def test_duplicates_unmatched_and_zero_precision_are_not_confused():
    truth, anchors = assets()
    score = evaluate_v2(truth, [finding("f1", 10), finding("f2", 20), finding("f3", 10), finding("f4", 30)], anchors)
    assert {k: score[k] for k in ("TP", "D", "U", "FP", "FN")} == {"TP": 2, "D": 1, "U": 1, "FP": 2, "FN": 1}
    assert score["precision"] == .5 and score["recall"] == 2 / 3 and score["f1"] == 4 / 7
    empty = evaluate_v2(truth, [], anchors)
    assert empty["precision"] is None and empty["recall"] == empty["f1"] == 0


def test_same_line_different_root_causes_and_type_mismatch():
    truth, anchors = assets()
    truth["vulnerabilities"][1]["class"] = anchors["vulnerabilities"][1]["class"] = "mass_assignment"
    rows = [finding("sql", 10), finding("mass", 10, "mass_assignment")]
    assert evaluate_v2(truth, rows, anchors)["TP"] == 2
    mismatch = evaluate_v2(truth, [finding("bad", 10, "ssrf")], anchors)
    assert mismatch["TP"] == 0 and mismatch["U"] == 1
    assert mismatch["diagnostics"][0]["reason"] == "type_mismatch"
    assert set(mismatch["diagnostics"][0]["expected_types"]) == {"sqli", "mass_assignment"}


@pytest.mark.parametrize("location", [
    {"path": "other/app/x.php", "line": 10}, {"path": "x.php", "line": 10},
    {"path": "app/X.php", "line": 10}, {"path": "../app/x.php", "line": 10},
    {"path": "/app/x.php", "line": 10}, {"path": "app/x.php", "line": True},
    {"path": "app/x.php", "line": "10"}, {"path": "app/x.php", "line": 0},
])
def test_suffix_basename_unsafe_paths_and_bool_lines_cannot_match(location):
    truth, anchors = assets()
    score = evaluate_v2(truth, [finding("bad", 10, primary_location=location)], anchors)
    assert score["TP"] == 0 and score["U"] == 1


def test_wide_evidence_cannot_replace_primary_location_and_withdrawn_are_excluded():
    truth, anchors = assets()
    rows = [finding("wide", 99, evidence="app/x.php:1-100"),
            finding("withdrawn", 10, disposition="retracted"),
            finding("duplicate", 10, disposition="duplicate"),
            finding("history", 10, disposition="superseded"),
            finding("investigation", 10, kind="investigation"),
            finding("invalid", 10, validation_state="invalid_evidence")]
    score = evaluate_v2(truth, rows, anchors)
    assert score["findings"] == 1 and score["TP"] == 0
    assert score["excluded_invalid"][0]["finding_id"] == "invalid"


def test_rating_uses_host_cvss_and_does_not_change_matched_prediction():
    truth, anchors = assets()
    rows = [finding("f1", 10, cvss={"base_score": 6.5}), finding("f2", 20)]
    score = evaluate_v2(truth, rows, anchors)
    assert score["cvss_evaluation"]["score_mae"] == 1
    assert score["cvss_evaluation"]["scoring_coverage"] == .5
    assert score["cvss_evaluation"]["missing_reported"] == 1
    before = [(x["truth_id"], x["finding_id"]) for x in score["matches"]]
    rows[0]["cvss"] = {"base_score": 7.5}
    rows[1]["cvss"] = {"base_score": 1}
    assert [(x["truth_id"], x["finding_id"]) for x in evaluate_v2(truth, rows, anchors)["matches"]] == before


def trial(round_index, prompt, f1, *, valid=True, precision=None, usage=None):
    return {"id": f"{prompt}-{round_index}", "round_index": round_index, "prompt_id": prompt,
            "evaluation_status": "valid" if valid else "invalid",
            "score": {"TP": 0, "D": 0, "U": 0, "FN": 30, "precision": precision, "recall": f1, "f1": f1,
                      "truth_results": [{"id": "A", "class": "sqli", "detected": f1 > .5, "finding_id": "f"}]},
            "usage": usage or {}, "duration_seconds": 10}


def test_paired_mean_sample_sd_and_null_precision_counts():
    trials = [trial(r + 1, "W0", f, precision=None if r == 0 else f) for r, f in enumerate((.4, .5, .6))]
    trials += [trial(r + 1, "W1", f, precision=f) for r, f in enumerate((.5, .7, .6))]
    summary = summarise_trials([{"id": "W0"}, {"id": "W1"}], trials, 3, "W0")
    assert summary["complete_rounds"] == [1, 2, 3] and not summary["preliminary"]
    a, b = summary["variants"]
    assert a["metrics"]["f1"]["mean"] == pytest.approx(.5)
    assert a["metrics"]["f1"]["sample_std"] == pytest.approx(.1)
    assert a["metrics"]["precision"]["n"] == 2
    assert b["paired_f1"]["mean"] == pytest.approx(.1)
    assert b["paired_f1"]["sample_std"] == pytest.approx(.1)
    assert [x["value"] for x in b["paired_f1"]["values"]] == pytest.approx([.1, .2, 0])
    assert summary["truth_matrix"][0]["variants"]["W0"]["hits"] == 1
    assert summary["truth_matrix"][0]["variants"]["W1"]["hits"] == 2


def test_incomplete_round_excluded_for_all_not_best_score_or_per_variant():
    variants = [{"id": "W0"}, {"id": "W1"}, {"id": "W2"}]
    rows = [trial(r, p, .1 * r, valid=not (r == 2 and p == "W2")) for r in (1, 2, 3) for p in ("W0", "W1", "W2")]
    summary = summarise_trials(variants, rows, 3, "W0")
    assert summary["complete_rounds"] == [1, 3] and summary["preliminary"]
    assert all(v["metrics"]["f1"]["n"] == 2 for v in summary["variants"])
    with pytest.raises(ValueError, match="重复"):
        summarise_trials(variants, rows + [rows[0]], 3, "W0")


def test_missing_tokens_not_zero_and_zero_tp_cost_missing():
    rows = [trial(1, p, 0, usage={"total_tokens": None}) for p in ("a", "b")]
    summary = summarise_trials([{"id": "a"}, {"id": "b"}], rows, 1, "a")
    metric = summary["variants"][0]["metrics"]["total_tokens"]
    assert metric["n"] == 0 and metric["mean"] is None
    assert summary["variants"][0]["metrics"]["tokens_per_tp"]["mean"] is None
    assert summary["actual_total_usage"]["total_tokens"]["known_trials"] == 0


def test_valid_budget_exhausted_counts_invalid_infrastructure_does_not():
    rows = [trial(1, p, 0) for p in ("a", "b")]
    rows[0]["status"] = "failed"
    rows[0]["termination_reason"] = "run_budget_exhausted"
    summary = summarise_trials([{"id": "a"}, {"id": "b"}], rows, 3, "a")
    assert summary["complete_rounds"] == [1]
    assert summary["variants"][0]["metrics"]["f1"]["mean"] == 0
    rows[0]["evaluation_status"] = "invalid"
    summary = summarise_trials([{"id": "a"}, {"id": "b"}], rows, 3, "a")
    assert not summary["complete_rounds"]
    assert all(v["metrics"]["f1"]["n"] == 0 for v in summary["variants"])


def test_paired_changes_identify_gained_and_lost_truths_without_union_scoring():
    rows = [trial(1, "base", .4), trial(1, "new", .6)]
    rows[0]["score"]["truth_results"] = [{"id": "A", "detected": True}, {"id": "B", "detected": False}]
    rows[1]["score"]["truth_results"] = [{"id": "A", "detected": False}, {"id": "B", "detected": True}]
    summary = summarise_trials([{"id": "base"}, {"id": "new"}], rows, 3, "base")
    change = summary["variants"][1]["paired_f1"]["values"][0]
    assert change["gained_truth_ids"] == ["B"] and change["lost_truth_ids"] == ["A"]


def test_common_cvss_denominator_is_intersection_and_missing_is_not_zero():
    rows = [trial(1, "a", .4), trial(1, "b", .6)]
    def rated(ident, error, label=True):
        return {"truth_id": ident, "cvss_status": "compared", "cvss_score_error": error, "severity_ok": label}
    rows[0]["score"]["matches"] = [rated("A", 1), rated("B", 2)]
    rows[1]["score"]["matches"] = [rated("A", 0, False), {"truth_id": "B", "cvss_status": "missing_reported"}]
    summary = summarise_trials([{"id": "a"}, {"id": "b"}], rows, 3, "a")
    common = summary["cvss_common_rounds"][0]
    assert common["truth_ids"] == ["A"] and common["total"] == 1
    assert common["variants"]["a"]["score_mae"] == 1
    assert common["variants"]["b"]["score_mae"] == 0
    assert common["variants"]["b"]["severity_accuracy"] == 0
    assert common["paired_deltas"]["b"]["score_mae"] == -1
    assert summary["cvss_paired_deltas"]["b"]["score_mae"]["mean"] == -1
    assert summary["variants"][1]["metrics"]["cvss_common_delta_mae"]["mean"] == -1
    assert summary["variants"][1]["metrics"]["cvss_common_mae"]["mean"] == 0


def test_explanatory_candidates_never_change_exact_matching():
    truth, anchors = assets()
    rows = [finding("same-file", 99), finding("covered", 99, "xss_r", evidence=[
        {"path": "lab30-shop/app/x.php", "start_line": 40, "end_line": 40}])]
    score = evaluate_v2(truth, rows, anchors)
    assert score["TP"] == 0 and score["U"] == 2
    diagnostics = {item["truth_id"]: item for item in score["missed_diagnostics"]}
    assert diagnostics["A"]["reason"] == "primary_location_mismatch"
    assert diagnostics["C"]["reason"] == "evidence_anchor_primary_mismatch"
    assert all(item["affects_score"] is False for item in diagnostics.values())
    wrong_type = evaluate_v2(truth, [finding("wrong", 10, "rfi")], anchors)
    assert wrong_type["TP"] == 0
    assert wrong_type["missed_diagnostics"][0]["reason"] == "type_mismatch"
    assert evaluate_v2(truth, [], anchors)["missed_diagnostics"][0]["reason"] == "no_related_candidate"


def test_disposition_counts_remain_separate_from_asserted_score_duplicates():
    truth, anchors = assets()
    score = evaluate_v2(truth, [finding("a", 20), finding("b", 20), finding("c", 20, disposition="duplicate")], anchors)
    assert score["duplicate_statistics"] == {"still_asserted": 1, "resolved": 1}
    assert score["TP"] == 1 and score["D"] == 1


def test_empty_common_cvss_and_missing_clocks_do_not_fabricate_comparison():
    rows = [trial(1, "a", .4), trial(1, "b", .6)]
    rows[0].update(audit_elapsed_seconds=120, wall_elapsed_seconds=135, audit_budget_utilization=1/6,
                   stop_reason={"code": "goal_met"}, coverage_gaps=["src/account.php"])
    summary = summarise_trials([{"id": "a"}, {"id": "b"}], rows, 1, "a")
    assert summary["cvss_common_rounds"][0]["total"] == 0
    assert summary["cvss_paired_deltas"]["b"]["score_mae"]["n"] == 0
    assert summary["variants"][0]["metrics"]["audit_elapsed_seconds"]["mean"] == 120
    assert summary["variants"][1]["metrics"]["audit_elapsed_seconds"]["mean"] is None
    assert summary["variants"][0]["metrics"]["duration_seconds"]["mean"] == 10
    assert summary["execution_diagnostics"][0]["coverage_gaps"] == ["src/account.php"]


def test_duplicate_anchor_ids_and_class_mismatch_are_rejected():
    truth, anchors = assets()
    wrong = copy.deepcopy(anchors)
    wrong["vulnerabilities"].append(wrong["vulnerabilities"][0])
    with pytest.raises(ValueError, match="一一对应"):
        evaluate_v2(truth, [], wrong)
    anchors["vulnerabilities"][0]["class"] = "ssrf"
    with pytest.raises(ValueError, match="类别"):
        evaluate_v2(truth, [], anchors)


def test_unknown_cause_is_retained_as_unmatched_not_silently_dropped():
    truth, anchors = assets()
    score = evaluate_v2(truth, [finding("other", 10, "an unknown label")], anchors)
    assert score["findings"] == 1 and score["U"] == 1 and score["TP"] == 0
    assert score["diagnostics"][0]["vulnerability_type"] == "unknown"


def test_real_30_truths_22_classes_all_line_digests_and_source_hash_checked(tmp_path):
    archive = ROOT / "llm-vuln-audit-feat-lab30-shop/llm-vuln-audit-feat-lab30-shop/lab30-shop-1.0.0-source.zip"
    result = validate_assets(archive)
    assert result["truth_count"] == 30 and result["class_count"] == 22
    truth = json.loads(DEFAULT_TRUTH_PATH.read_text())
    anchors = json.loads(DEFAULT_ANCHORS_PATH.read_text())
    assert validate_assets(archive, truth, anchors)["truth_count"] == 30
    changed = copy.deepcopy(truth)
    changed["vulnerabilities"][0]["title"] += "changed"
    with pytest.raises(ValueError, match="真值内容"):
        validate_assets(archive, changed, anchors)
    changed = copy.deepcopy(anchors)
    changed["vulnerabilities"][0]["scoring_locations"][0]["line_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="评分行摘要"):
        validate_assets(archive, truth, changed)
    wrong_zip = tmp_path / "bad.zip"
    wrong_zip.write_bytes(b"wrong")
    with pytest.raises(ValueError, match="源码 ZIP"):
        validate_assets(wrong_zip)


def test_every_truth_can_score_once_and_zero_cvss_truth_is_not_removed():
    truth = json.loads(DEFAULT_TRUTH_PATH.read_text())
    anchors = json.loads(DEFAULT_ANCHORS_PATH.read_text())
    rows = [{"id": f"f-{a['id']}", "kind": "vulnerability", "vulnerability_type": a["class"],
             "primary_location": {"path": a["scoring_locations"][0]["path"], "line": a["scoring_locations"][0]["line"]}}
            for a in anchors["vulnerabilities"]]
    score = evaluate_v2(truth, rows, anchors)
    assert score["TP"] == 30 and score["FN"] == score["FP"] == 0
    assert score["f1"] == score["recall"] == score["precision"] == 1
    assert len(score["class_coverage"]) == 22
    assert next(x for x in score["truth_results"] if x["id"] == "08")["detected"]
