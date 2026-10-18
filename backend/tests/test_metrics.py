"""What a finished unit is allowed to mean.

The confusion matrix is the part of the report most likely to be quoted, so the rule it
rests on has to hold: a unit that ran out of budget, failed, or explicitly said it could
not see enough is an unfinished observation. Folding any of those into a negative would
let the report claim a true negative the model never asserted — or, worse, book its
honesty as a missed detection.
"""
from audit.metrics import paired_prompt_comparisons, summarise

RUN = {"id": "r1", "scope": ["vuln.php", "safe.php"], "snapshot_id": "s1"}


def truth(file_path, category, vulnerable=True, verified=True):
    return {
        "file_path": file_path,
        "category": category,
        "vulnerable": vulnerable,
        "independently_verified": verified,
    }


def unit(unit_id, file_path, status="completed", conclusions=None):
    return {
        "unit_id": unit_id,
        "file_path": file_path,
        "symbol": "<top-level>",
        "status": status,
        "error": None,
        "result": {"conclusions": conclusions or {}} if conclusions is not None else None,
    }


def finding(unit_id, file_path, category):
    return {
        "id": f"f-{unit_id}-{category}",
        "unit_id": unit_id,
        "category": category,
        "validation_state": "candidate",
        "fingerprint": f"{unit_id}-{category}",
    }


def evaluate(units, findings, truths):
    metrics = summarise(RUN, units, findings, truths)
    return metrics["evaluation"]


def test_a_confident_negative_is_a_true_negative():
    units = [unit("u1", "safe.php", conclusions={"sqli": "no_candidate"})]
    evaluation = evaluate(units, [], [truth("safe.php", "sqli", vulnerable=False)])
    assert (evaluation["TP"], evaluation["FP"], evaluation["FN"], evaluation["TN"]) == (0, 0, 0, 1)


def test_a_candidate_on_a_vulnerable_sample_is_a_true_positive():
    units = [unit("u1", "vuln.php", conclusions={"sqli": "candidate"})]
    evaluation = evaluate(units, [finding("u1", "vuln.php", "sqli")], [truth("vuln.php", "sqli")])
    assert (evaluation["TP"], evaluation["FN"]) == (1, 0)
    assert evaluation["sample_results"] == [
        {
            "file_path": "vuln.php",
            "category": "sqli",
            "vulnerable": True,
            "resolved": True,
            "predicted_vulnerable": True,
        }
    ]


def test_a_candidate_on_a_safe_sample_is_a_false_positive():
    units = [unit("u1", "safe.php", conclusions={"sqli": "candidate"})]
    evaluation = evaluate(units, [finding("u1", "safe.php", "sqli")], [truth("safe.php", "sqli", vulnerable=False)])
    assert (evaluation["FP"], evaluation["TN"]) == (1, 0)


def test_f1_is_zero_when_recall_is_zero_and_truth_positives_exist():
    evaluation = evaluate(
        [unit("u1", "vuln.php", conclusions={"sqli": "no_candidate"})],
        [],
        [truth("vuln.php", "sqli")],
    )
    assert evaluation["precision"] is None
    assert evaluation["recall"] == 0
    assert evaluation["f1"] == 0


def test_missing_context_is_not_a_false_negative():
    units = [unit("u1", "vuln.php", conclusions={"sqli": "insufficient_context"})]
    evaluation = evaluate(units, [], [truth("vuln.php", "sqli")])
    assert evaluation["FN"] == 0
    assert evaluation["TP"] == 0
    assert len(evaluation["unresolved"]) == 1
    assert "insufficient_context" in evaluation["unresolved"][0]["reason"]


def test_missing_context_is_not_a_true_negative_either():
    units = [unit("u1", "safe.php", conclusions={"sqli": "insufficient_context"})]
    evaluation = evaluate(units, [], [truth("safe.php", "sqli", vulnerable=False)])
    assert evaluation["TN"] == 0
    assert len(evaluation["unresolved"]) == 1


def test_missing_context_about_one_category_does_not_excuse_the_others():
    # The unit could not judge SQL injection but did clear the other two: only the sqli
    # sample is set aside, because only that conclusion was withheld.
    units = [
        unit(
            "u1",
            "vuln.php",
            conclusions={"sqli": "insufficient_context", "xss_r": "no_candidate", "command_injection": "no_candidate"},
        )
    ]
    truths = [
        truth("vuln.php", "sqli"),
        truth("vuln.php", "xss_r", vulnerable=False),
        truth("vuln.php", "command_injection", vulnerable=False),
    ]
    evaluation = evaluate(units, [], truths)
    assert evaluation["TN"] == 2
    assert evaluation["FN"] == 0
    assert [item["category"] for item in evaluation["unresolved"]] == ["sqli"]


def test_a_partially_settled_unit_stays_unresolved_for_every_category():
    # Settlement runs one category per call, so a timeout can leave two conclusions stored
    # on a unit that is still `failed`. Those conclusions are worth keeping in the record,
    # but the unit did not finish: none of its categories may be scored, least of all the
    # one it never got to.
    units = [
        unit(
            "u1",
            "vuln.php",
            status="failed",
            conclusions={"sqli": "candidate", "command_injection": "no_candidate"},
        )
    ]
    truths = [truth("vuln.php", "sqli"), truth("vuln.php", "command_injection", vulnerable=False)]
    evaluation = evaluate(units, [], truths)
    assert (evaluation["TP"], evaluation["FP"], evaluation["FN"], evaluation["TN"]) == (0, 0, 0, 0)
    assert len(evaluation["unresolved"]) == 2


def test_an_unfinished_unit_outranks_a_withheld_conclusion():
    # Both reasons apply; the report should name the one a reader can act on first — the
    # unit never finished, so its conclusion was never going to arrive.
    units = [unit("u1", "vuln.php", status="incomplete", conclusions=None)]
    evaluation = evaluate(units, [], [truth("vuln.php", "sqli")])
    assert evaluation["FN"] == 0
    assert "未完成" in evaluation["unresolved"][0]["reason"]


def test_a_completed_unit_with_no_stored_result_does_not_crash_the_metrics():
    # Rows written before `result` existed parse to None. That is a miss, not a crash, and
    # it must not be mistaken for a stored `insufficient_context` either.
    units = [unit("u1", "vuln.php", conclusions=None)]
    evaluation = evaluate(units, [], [truth("vuln.php", "sqli")])
    assert evaluation["FN"] == 1
    assert evaluation["unresolved"] == []


def test_an_unverified_truth_is_excluded_rather_than_counted():
    units = [unit("u1", "vuln.php", conclusions={"sqli": "no_candidate"})]
    metrics = summarise(RUN, units, [], [truth("vuln.php", "sqli", verified=False)])
    assert metrics["truth_status"] == "truth_set_not_verified"
    assert metrics["evaluation"] is None


def test_no_truth_set_means_uncomputable():
    metrics = summarise(RUN, [unit("u1", "vuln.php")], [], [])
    assert metrics["truth_status"] == "no_truth_set"
    assert metrics["evaluation"] is None


def test_a_candidate_outside_the_truth_set_is_named_rather_than_scored():
    # The truth set covers sqli on this file; the candidate is an XSS on the same file.
    # It cannot be a hit (no truth says so) and it cannot be a false alarm (no truth says
    # the combination is safe), so it is neither — but a reader counting four candidates
    # against a six-sample matrix needs to be told where the fourth went.
    units = [unit("u1", "vuln.php", conclusions={"sqli": "candidate", "xss_r": "candidate"})]
    evaluation = evaluate(
        units,
        [finding("u1", "vuln.php", "sqli"), finding("u1", "vuln.php", "xss_r")],
        [truth("vuln.php", "sqli")],
    )
    assert (evaluation["TP"], evaluation["FP"]) == (1, 0)
    assert [item["category"] for item in evaluation["unmatched_candidates"]] == ["xss_r"]
    assert evaluation["unmatched_candidates"][0]["reason"] == "该文件的这一类没有真值样本"


def test_a_candidate_on_a_file_with_no_truth_sample_says_so_differently():
    # "the truth set skipped this category" and "this file was never a truth sample" are
    # different holes in the benchmark, and only the second one suggests the sample set
    # itself is incomplete.
    units = [unit("u1", "other.php", conclusions={"sqli": "candidate"})]
    evaluation = evaluate(units, [finding("u1", "other.php", "sqli")], [truth("vuln.php", "sqli")])
    assert evaluation["unmatched_candidates"][0]["reason"] == "该文件不在真值样本集内"


def test_the_same_unmatched_combination_is_listed_once():
    # Duplicate candidates for one weakness are one observation everywhere else in the
    # report; the unmatched table must not become the place where they multiply.
    units = [unit("u1", "other.php", conclusions={"sqli": "candidate"})]
    evaluation = evaluate(
        units,
        [finding("u1", "other.php", "sqli"), {**finding("u1", "other.php", "sqli"), "id": "f2"}],
        [truth("vuln.php", "sqli")],
    )
    assert len(evaluation["unmatched_candidates"]) == 1


def test_paired_prompt_comparison_uses_only_the_same_resolved_samples():
    samples = [
        truth("vuln.php", "sqli"),
        truth("safe.php", "sqli", vulnerable=False),
        truth("pending.php", "sqli"),
    ]
    run = {**RUN, "scope": ["vuln.php", "safe.php", "pending.php"]}
    baseline = summarise(
        run,
        [
            unit("b1", "vuln.php", conclusions={"sqli": "no_candidate"}),
            unit("b2", "safe.php", conclusions={"sqli": "no_candidate"}),
            unit("b3", "pending.php", status="incomplete"),
        ],
        [],
        samples,
    )
    improved = summarise(
        run,
        [
            unit("i1", "vuln.php", conclusions={"sqli": "candidate"}),
            unit("i2", "safe.php", conclusions={"sqli": "no_candidate"}),
            unit("i3", "pending.php", status="incomplete"),
        ],
        [finding("i1", "vuln.php", "sqli")],
        samples,
    )
    comparison = paired_prompt_comparisons(
        [
            {"run": {"prompt_id": "P0"}, "metrics": baseline},
            {"run": {"prompt_id": "P1"}, "metrics": improved},
        ],
        runs_comparable=True,
    )[0]

    assert comparison["comparable"] is True
    assert comparison["common_samples"] == 2
    assert comparison["baseline"]["f1"] == 0
    assert comparison["current"]["f1"] == 1
    assert comparison["delta_percentage_points"]["f1_pp"] == 100


def test_paired_comparison_withholds_improvement_for_incompatible_runs():
    samples = [truth("vuln.php", "sqli")]
    metrics = summarise(
        RUN,
        [unit("u1", "vuln.php", conclusions={"sqli": "candidate"})],
        [finding("u1", "vuln.php", "sqli")],
        samples,
    )
    comparison = paired_prompt_comparisons(
        [
            {"run": {"prompt_id": "P0"}, "metrics": metrics},
            {"run": {"prompt_id": "P1"}, "metrics": metrics},
        ],
        runs_comparable=False,
    )[0]

    assert comparison["comparable"] is False
    assert comparison["baseline"] is None
    assert comparison["current"] is None
    assert comparison["delta_percentage_points"]["f1_pp"] is None
    assert comparison["reason"] == "运行条件不可比"


def test_paired_comparison_withholds_metrics_when_candidates_lack_truth_labels():
    samples = [truth("vuln.php", "sqli")]
    metrics = summarise(
        RUN,
        [unit("u1", "vuln.php", conclusions={"sqli": "candidate", "xss_r": "candidate"})],
        [finding("u1", "vuln.php", "sqli"), finding("u1", "vuln.php", "xss_r")],
        samples,
    )
    comparison = paired_prompt_comparisons(
        [
            {"run": {"prompt_id": "P0"}, "metrics": metrics},
            {"run": {"prompt_id": "P1"}, "metrics": metrics},
        ],
        runs_comparable=True,
    )[0]

    assert comparison["comparable"] is False
    assert comparison["common_samples"] == 1
    assert comparison["unmatched_candidates"] == {"P0": 1, "P1": 1}
    assert comparison["reason"] == "存在未标注候选（P0=1、P1=1）"
