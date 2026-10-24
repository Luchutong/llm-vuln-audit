"""The defence score: every component is a rate the host can point at, or it is missing.

The failure mode this guards against is a comfortable number: a score that silently treats a
switched-off defence as "full marks", or that folds an unmeasured benchmark into the total.
"""
from __future__ import annotations

from audit import defence


def candidate(validation_state: str = "candidate", **overrides) -> dict:
    return {"id": "f", "validation_state": validation_state, **overrides}


def experiment_row(variant: str, resistance, chain) -> dict:
    return {
        "variant": variant,
        "injection": {"resistance_rate": resistance},
        "discipline": {"chain_rate": chain},
    }


def test_every_component_is_a_rate_of_something_measured():
    findings = [
        candidate("candidate"),
        candidate("candidate"),
        candidate("invalid_evidence"),
        candidate("observation"),
    ]
    reviews = [{"decision": "confirmed"}, {"decision": "contested"}]

    result = defence.summarise(
        findings,
        {"verified": 3, "rejected": 1, "inconclusive": 0, "unverified": 9},
        reviews,
        {"id": "exp-1", "rows": [experiment_row("P0-lite", 0.333, 1.0),
                                 experiment_row("P1-evidence", 1.0, 0.5)]},
    )

    values = {item["key"]: item["value"] for item in result["components"]}
    # ``observation`` rows are investigation records, not conclusions: they leave the ratio.
    assert values["evidence"] == round(2 / 3, 4)
    assert values["poc"] == 0.75
    assert values["review"] == 0.5
    assert values["injection"] == round((0.333 + 1.0) / 2, 4)
    assert values["chain"] == 0.75
    assert result["missing"] == []
    assert result["denominator_weight"] == 1.0


def test_a_switched_off_defence_is_missing_not_perfect():
    result = defence.summarise([candidate()], {"unverified": 4}, [], None)

    assert [item["key"] for item in result["components"] if item["value"] is None] == [
        "poc", "review", "injection", "chain",
    ]
    # Only the evidence component is left, so the total is that rate -- not a number that
    # rewards the run for having nothing to check.
    assert result["score"] == 1.0
    assert result["denominator_weight"] == 0.2
    assert result["missing"] == ["poc", "review", "injection", "chain"]


def test_an_empty_run_has_no_score_rather_than_zero():
    result = defence.summarise([], {}, [], None)
    assert result["score"] is None
    assert len(result["missing"]) == 5


def test_the_benchmark_half_says_where_it_came_from():
    result = defence.summarise(
        [candidate()],
        None,
        [],
        {"id": "exp-42", "finished_at": "2026-01-01T00:00:00+00:00",
         "rows": [experiment_row("P0-basic", 0.667, 0.5)]},
    )
    assert result["benchmark"]["experiment_id"] == "exp-42"
    assert result["benchmark"]["variants"] == ["P0-basic"]
    values = {item["key"]: item["value"] for item in result["components"]}
    assert values["injection"] == 0.667
    assert values["chain"] == 0.5


def test_an_experiment_without_rows_contributes_nothing():
    result = defence.summarise([candidate()], None, [], {"id": "exp-empty", "rows": []})
    assert "injection" in result["missing"] and "chain" in result["missing"]
    assert result["benchmark"]["experiment_id"] == "exp-empty"
