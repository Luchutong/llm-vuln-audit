"""The shared calculator against a pinned, independent CVSS 3.1 implementation.

``fixtures/cvss31_reference_2592.json`` holds the Base score of every one of the 2,592
legal Base-metric combinations, computed with the PyPI package ``cvss==3.6``
(``CVSS3(vector).base_score``).  The fixture stores scores only, in the documented
axis order, so a mismatch names the exact vector instead of diffing a blob.
"""
from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from audit.cvss31 import BASE, VALUES, assessment, base_score, parse_vector, severity

DATA = Path(__file__).resolve().parent / "fixtures" / "cvss31_reference_2592.json"
ROOT = Path(__file__).resolve().parents[2]

REFERENCE = json.loads(DATA.read_text(encoding="utf-8"))


def combinations():
    order = REFERENCE["order"]
    assert tuple(order["metrics"]) == BASE
    assert order["values"] == {key: VALUES[key] for key in BASE}
    vectors = [
        "CVSS:3.1/" + "/".join(f"{key}:{value}" for key, value in zip(BASE, combo))
        for combo in itertools.product(*(order["values"][key] for key in BASE))
    ]
    assert len(vectors) == len(REFERENCE["scores"]) == 2592
    return zip(vectors, REFERENCE["scores"])


def test_reference_fixture_provenance_is_pinned():
    provenance = REFERENCE["provenance"]
    assert provenance["package"] == "cvss"
    assert provenance["version"] == "3.6"
    assert provenance["method"] == "CVSS3(vector).base_score"
    assert provenance["combinations"] == 2592
    assert len(set(REFERENCE["scores"])) > 10
    assert 0.0 in REFERENCE["scores"] and 10.0 in REFERENCE["scores"]


def test_every_base_metric_combination_matches_pinned_reference():
    mismatches = []
    for vector, expected in combinations():
        actual = base_score(parse_vector(vector))
        if actual != expected:
            mismatches.append((vector, expected, actual))
    assert not mismatches, f"first mismatches: {mismatches[:5]}"


def test_reference_scores_are_canonical_and_banded_consistently():
    for vector, expected in combinations():
        result = assessment({"base_vector": vector})
        assert result["base_score"] == expected
        assert result["base_vector"] == vector
        assert result["metrics"] == parse_vector(vector)
        assert result["severity"] == severity(expected)


def test_supplied_score_cannot_override_the_vector():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    with pytest.raises(ValueError, match="不一致"):
        assessment({"base_vector": vector, "base_score": 0.0})


def test_official_lab_vectors_recompute_from_metrics_including_zero():
    dataset = json.loads((ROOT / "datasets/lab30-shop/ground_truth.json").read_text(encoding="utf-8"))
    vulnerabilities = dataset["vulnerabilities"]
    assert len(vulnerabilities) == 30
    zero = []
    for item in vulnerabilities:
        source = item["cvss"]
        computed = assessment({"base_vector": source["base_vector"]})
        assert computed["base_score"] == source["base_score"], item["id"]
        assert computed["base_vector"] == source["base_vector"], item["id"]
        assert computed["metrics"] == {key: source["metrics"][key] for key in BASE}, item["id"]
        # Recomputing from metrics alone gives exactly the same rating.
        from_metrics = base_score({key: source["metrics"][key] for key in BASE})
        assert from_metrics == source["base_score"], item["id"]
        if source["base_score"] == 0.0:
            zero.append(item["id"])
    assert zero == ["08"]


@pytest.mark.parametrize("vector", [
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/AV:N",      # duplicate metric
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N",                # missing metric
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:Z",            # invalid value
])
def test_malformed_vectors_are_rejected(vector):
    with pytest.raises(ValueError):
        parse_vector(vector)


def test_temporal_metric_is_validated_but_never_substituted_for_base():
    metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:U")
    assert metrics["E"] == "U"
    assert base_score(metrics) == 7.5


@pytest.mark.parametrize("version", ["3.0", "4.0", "2.0", ""])
def test_other_cvss_versions_are_rejected(version):
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    with pytest.raises(ValueError):
        assessment({"version": version, "base_vector": vector})


@pytest.mark.parametrize("score,band", [
    (0.0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"),
    (6.9, "medium"), (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical"),
])
def test_four_positive_bands_and_zero_are_distinct(score, band):
    assert severity(score) == band


def test_assessment_never_accepts_a_label_as_a_score():
    with pytest.raises(ValueError):
        assessment({"version": "3.1", "severity": "critical"})
    assert assessment(None) is None
