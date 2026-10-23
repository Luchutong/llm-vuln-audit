"""Exercise the offline evaluator against API/export shapes and CVSS 3.1."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import score_dataset as scorer
from cvss31 import assessment, parse_vector, roundup, score_value, severity

SQL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
CMD = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
ZERO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N"


def truth(vector=SQL, score=7.5):
    return {"vulnerabilities": [{"id": "01", "title": "SQL 注入", "type": "SQL 注入", "scenario": "sqli",
                                "location": [{"path": "app/a.php", "line": 4}],
                                "cvss": {"version": "3.1", "base_score": score, "base_vector": vector}}]}


def finding(**overrides):
    return {"id": "f1", "finding_kind": "vulnerability", "title": "SQL injection", "severity": "high",
            "evidence": [{"path": "lab30-shop/app/a.php", "start_line": 3, "end_line": 6}], **overrides}


@pytest.mark.parametrize("score,expected", [(0, "none"), (.1, "low"), (3.9, "low"), (4, "medium"),
                                            (6.9, "medium"), (7, "high"), (8.9, "high"), (9, "critical"), (10, "critical")])
def test_cvss_severity_boundaries(score, expected):
    assert severity(score) == expected


@pytest.mark.parametrize("score", [-.1, 10.1, 7.55, "nan", "Infinity", True, None, {}])
def test_invalid_scores_are_not_coerced_into_ratings(score):
    with pytest.raises(ValueError):
        score_value(score)


@pytest.mark.parametrize("vector,score", [(SQL, 7.5), (XSS, 6.1), (CMD, 7.2), (ZERO, 0.0),
                                          ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4)])
def test_base_score_matches_known_lab_vectors(vector, score):
    assert assessment({"vector": vector})["base_score"] == score


def test_roundup_removes_float_noise_and_rounds_up_not_to_nearest():
    assert roundup(4.02) == 4.1
    assert roundup(4.0) == 4.0
    assert roundup(0.1 + 0.2) == 0.3


@pytest.mark.parametrize("vector", [SQL.replace("3.1", "3.0"), SQL.replace("3.1", "4.0"),
                                     SQL + "/AV:N", SQL + "/E:Z", SQL + "/AT:N", SQL.replace("/PR:N", "")])
def test_invalid_or_other_version_vectors_are_rejected(vector):
    with pytest.raises(ValueError):
        parse_vector(vector)


def test_full_vector_uses_base_not_temporal_or_environmental_score():
    result = assessment({"version": "3.1", "base_score": 7.5, "temporal_score": 6.9, "environmental_score": 3.2,
                         "vector": SQL + "/E:U/RL:O/RC:U/CR:L/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"})
    assert result["base_score"] == 7.5
    assert result["base_vector"] == SQL


def test_vector_order_is_irrelevant_but_contradictory_scores_or_vectors_fail():
    reversed_vector = "CVSS:3.1/" + "/".join(reversed(SQL.split("/")[1:]))
    assert assessment({"vector": reversed_vector})["base_vector"] == SQL
    with pytest.raises(ValueError, match="不一致"):
        assessment({"base_score": 9.8, "base_vector": SQL})
    with pytest.raises(ValueError, match="不一致"):
        assessment({"base_vector": SQL, "vector": XSS})


def test_dataset_retains_all_official_scores_metrics_and_assessment_boundaries():
    dataset = json.loads((ROOT / "datasets/lab30-shop/ground_truth.json").read_text(encoding="utf-8"))
    normalised = scorer.normalise_truth(dataset)
    assert dataset["provenance"]["commit"] == "30364ecd8f1c7c8c10e3f2e66107dfc38ecd1434"
    expected = [7.5, 6.1, 7.2, 6.5, 5.3, 7.2, 7.2, 0.0, 2.7, 5.3, 5.4, 4.9, 4.9, 3.1, 4.3,
                6.5, 4.3, 5.3, 6.5, 5.3, 8.1, 4.3, 4.9, 7.2, 6.1, 5.3, 7.2, 3.5, 7.2, 7.1]
    assert [item["cvss"]["base_score"] for item in normalised] == expected
    for item in dataset["vulnerabilities"]:
        assert len(item["cvss"]["metrics"]) == 22
        assert item["cvss"]["temporal_assessed"] is False
        assert item["cvss"]["environmental_assessed"] is False
        assert item["assessment"]["method"] == "static_source_review"
        assert item["severity"] == severity(item["cvss"]["base_score"])


def test_official_answers_array_without_severity_is_accepted_and_scenario_selected():
    payload = [{"id": "23", "type": "跨文件 SQL 注入", "locations": [{"path": "app/a.php", "line": 4}],
                "cvss": {"base_vector": SQL}},
               {"id": "11", "type": "存储型 XSS", "locations": [{"path": "other.php", "line": 1}],
                "cvss": {"base_vector": XSS}}]
    report = scorer.evaluate(payload, [finding()], scenario="sqli", check_severity=True)
    assert (report["truths"], report["TP"], report["FN"]) == (1, 1, 0)
    assert report["matches"][0]["severity_expected"] == "high"
    assert report["severity_evaluation"]["accuracy"] == 1


def test_qualitative_rating_comes_from_cvss_not_obsolete_severity():
    payload = truth()
    payload["vulnerabilities"][0]["severity"] = "critical"
    report = scorer.evaluate(payload, [finding()], check_severity=True, check_cvss=True)
    match = report["matches"][0]
    assert match["severity_ok"] is True
    assert match["cvss_status"] == "missing_reported"
    assert report["cvss_evaluation"]["score_mae"] is None


def test_actual_api_findings_structured_evidence_and_worker_exports_match():
    rows = [finding(), finding(id="f2", finding_kind="source_observation"),
            finding(id="f3", disposition="retracted"), finding(id="f4", disposition="duplicate"),
            {"kind": "vulnerability", "title": "Worker result", "severity": "medium", "evidence": "else.php:1-3"}]
    selected = scorer.finding_rows({"findings": rows, "source_observations": [finding()]})
    report = scorer.evaluate(truth(), selected)
    assert (report["TP"], report["FP"], report["FN"]) == (1, 1, 0)
    assert scorer.finding_rows({"findings": [], "results": [finding()]}) == []
    assert scorer.line_hit("lab30-shop/app/a.php:6-3", "app/a.php", 4)
    assert not scorer.same_location("", "a.php")
    assert not scorer.same_location("someapp/a.php", "app/a.php")


def test_score_and_vector_comparisons_are_independent():
    source = truth("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.9)
    # The same score can encode different impacts; the metrics must still disagree.
    reported = {"vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N"}
    report = scorer.evaluate(source, [finding(cvss=reported)], check_cvss=True)
    match = report["matches"][0]
    assert match["cvss_score_ok"] is True
    assert match["cvss_vector_ok"] is False
    assert report["cvss_evaluation"]["metrics"]["C"]["accuracy"] == 0
    assert report["cvss_evaluation"]["score_mae"] == 0


def test_missing_invalid_and_valid_numeric_scores_have_explicit_denominators():
    source = truth()
    source["vulnerabilities"] *= 3
    source["vulnerabilities"] = [copy.deepcopy(item) for item in source["vulnerabilities"]]
    for index, item in enumerate(source["vulnerabilities"]):
        item["id"] = str(index)
        item["location"][0]["line"] = 4 + index * 10
    reports = [finding(evidence="app/a.php:4", cvss={"base_score": 7.4}),
               finding(evidence="app/a.php:14", severity="high"),
               finding(evidence="app/a.php:24", cvss={"version": "4.0", "base_score": 7.5})]
    report = scorer.evaluate(source, reports, check_cvss=True)
    summary = report["cvss_evaluation"]
    assert (summary["compared"], summary["missing_reported"], summary["invalid_reported"]) == (1, 1, 1)
    assert summary["score_mae"] == .1
    assert summary["score_accuracy"] == 0
    assert summary["vector_compared"] == 0
    assert report["TP"] == 3 and report["f1"] == 1


def test_zero_cvss_does_not_remove_a_truth_and_zero_recall_has_zero_f1():
    source = truth(ZERO, 0)
    empty = scorer.evaluate(source, [])
    assert (empty["FN"], empty["recall"], empty["f1"]) == (1, 0, 0)
    assert empty["precision"] is None
    found = scorer.evaluate(source, [finding(severity="low")], check_severity=True, check_cvss=True)
    assert found["TP"] == 1
    assert found["matches"][0]["severity_expected"] == "none"
    assert found["matches"][0]["severity_ok"] is False


def test_cvss_disagreement_does_not_change_detection_metrics_and_exact_match_works():
    wrong = scorer.evaluate(truth(), [finding(severity="critical", cvss={"base_score": 4.0})], check_severity=True, check_cvss=True)
    assert (wrong["TP"], wrong["FP"], wrong["FN"]) == (1, 0, 0)
    assert wrong["severity_evaluation"]["accuracy"] == 0
    assert wrong["cvss_evaluation"]["score_mae"] == 3.5
    exact = scorer.evaluate(truth(), [finding(cvss={"base_vector": SQL, "base_score": 7.5})], check_cvss=True)
    assert exact["cvss_evaluation"]["score_accuracy"] == 1
    assert exact["cvss_evaluation"]["vector_accuracy"] == 1


def test_legacy_custom_truth_can_still_be_evaluated_without_implying_cvss():
    payload = truth()
    item = payload["vulnerabilities"][0]
    del item["cvss"]
    item["severity"] = "高"
    report = scorer.evaluate(payload, [finding()], check_severity=True, check_cvss=True)
    assert report["rating_standard"] == "mixed/legacy"
    assert report["matches"][0]["cvss_status"] == "missing_truth"
    assert report["severity_evaluation"]["accuracy"] == 1


def test_live_api_loader_reads_current_export_shape_without_model_calls(monkeypatch):
    def read(url, timeout):
        assert url == "http://localhost:8899/api/runs/example" and timeout == 60
        return io.BytesIO(json.dumps({"findings": [finding()]}).encode())
    monkeypatch.setattr(scorer.urllib.request, "urlopen", read)
    assert scorer.load_findings(SimpleNamespace(findings=None, api="http://localhost:8899/", run="example"))[0]["id"] == "f1"


def test_cli_writes_cvss_report_for_realistic_export(tmp_path, capsys):
    source = tmp_path / "truth.json"
    source.write_text(json.dumps(truth()))
    findings = tmp_path / "run.json"
    findings.write_text(json.dumps({"findings": [finding(cvss={"base_vector": SQL})]}))
    output = tmp_path / "report.json"
    assert scorer.main(["--truth", str(source), "--findings", str(findings), "--check-severity", "--check-cvss", "--out", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["rating_standard"] == "CVSS:3.1"
    assert report["cvss_evaluation"]["score_mae"] == 0
    assert "CVSS 3.1 Base 7.5" in capsys.readouterr().out


def test_invalid_truth_stops_scoring_instead_of_falling_back_to_old_rating(tmp_path, capsys):
    payload = truth(score=9.8)
    source = tmp_path / "bad.json"
    source.write_text(json.dumps(payload))
    findings = tmp_path / "run.json"
    findings.write_text("[]")
    with pytest.raises(SystemExit) as caught:
        scorer.main(["--truth", str(source), "--findings", str(findings), "--out", str(tmp_path / "score.json")])
    assert caught.value.code == 2
    assert "不一致" in capsys.readouterr().err
    assert not (tmp_path / "score.json").exists()
