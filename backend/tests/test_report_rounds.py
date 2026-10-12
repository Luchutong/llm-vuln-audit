"""The optimisation rounds as they appear in the exported report.

The report is the graded artefact and it travels on its own, so the P0 → P1 → P2 story has
to be inside it: which versions exist, why each one changed, and — when the runs are not
actually comparable — a line saying so instead of a table the reader will over-read.
"""
from audit.report import _cell, _prompt_rounds


def run(prompt_id, label, **over):
    entry = {
        "id": f"run-{prompt_id}",
        "prompt_id": prompt_id,
        "prompt_label": label,
        "status": "completed",
        "completed_units": 6,
        "total_units": 6,
    }
    entry.update(over)
    return entry


def metrics(candidates=3, confirmed=2, evaluation=None):
    return {"candidates": candidates, "confirmed": confirmed, "evaluation": evaluation}


def bundle(rounds, prompts, current="P2"):
    return {
        "run": run(current, "P2 第二轮优化"),
        "rounds": rounds,
        "prompts": prompts,
    }


COMPARABLE = {"comparable": True, "reasons": [], "notes": []}
EVAL = {
    "TP": 3, "FP": 0, "FN": 0, "TN": 3, "precision": 1.0, "recall": 1.0,
    "eligible": 6, "unresolved": [],
}


def test_a_comparable_set_gets_the_table_and_no_warning():
    rounds = {
        **COMPARABLE,
        "runs": [
            {"run": run("P0", "P0 初始版"), "metrics": metrics(candidates=1, evaluation=EVAL)},
            {"run": run("P2", "P2 第二轮优化"), "metrics": metrics(candidates=3, evaluation=EVAL)},
        ],
    }
    text = "\n".join(_prompt_rounds(bundle(rounds, [])))
    assert "不可直接对比" not in text
    assert "| P0 初始版（`P0`） | completed | 6/6 | 6 | 1 |" in text
    assert "| P2 第二轮优化（`P2`） | completed | 6/6 | 6 | 3 |" in text
    # Same denominator on every row, so the mismatch warning stays out of the way.
    assert "可判定样本数不同" not in text


def test_rounds_that_resolved_different_numbers_of_samples_say_so():
    # The failure this guards against: an unfinished unit takes its sample out of the
    # denominator, so a round can print Precision=1.0 over four samples next to one printing
    # 1.0 over six, and a TP that falls 2 → 1 reads as "the prompt got worse" when nothing
    # about the prompt changed.
    rounds = {
        **COMPARABLE,
        "runs": [
            {"run": run("P0", "P0 初始版"), "metrics": metrics(evaluation={**EVAL, "TP": 2, "eligible": 6,
                                                                           "unresolved": [{"file_path": "a.php"}]})},
            {"run": run("P1", "P1 第一轮优化"), "metrics": metrics(evaluation={**EVAL, "TP": 1, "eligible": 6,
                                                                           "unresolved": [{"file_path": "a.php"}, {"file_path": "b.php"}]})},
            {"run": run("P2", "P2 第二轮优化"), "metrics": metrics(evaluation=EVAL)},
        ],
    }
    text = "\n".join(_prompt_rounds(bundle(rounds, [])))
    assert "**各轮的可判定样本数不同**" in text
    assert "P0=5、P1=4、P2=6" in text
    assert "否则轮次之间的差值会被当成提示词质量的差值" in text
    # ...and the number that makes the row readable is in the row itself.
    assert "| 4（未决 2） |" in text


def test_an_incomparable_set_says_so_before_the_numbers():
    rounds = {
        "comparable": False,
        "reasons": ["模型不同"],
        "notes": ["完成单元数不同（6/6 与 3/6）：候选数差异可能来自覆盖率，而不是提示词的改动"],
        "runs": [
            {"run": run("P0", "P0 初始版"), "metrics": metrics(candidates=1, evaluation=EVAL)},
            {"run": run("P1", "P1 第一轮优化"), "metrics": metrics(candidates=1, evaluation=EVAL)},
        ],
    }
    text = "\n".join(_prompt_rounds(bundle(rounds, [])))
    assert "**这些运行目前不可直接对比**" in text
    assert "模型不同" in text
    assert "不能用来声称提示词改进" in text
    assert "注意：完成单元数不同" in text


def test_missing_metrics_are_printed_as_uncomputable_not_zero():
    # A run without a verified truth set has no confusion matrix. Printing 0 would read as
    # "measured zero false negatives", which is a claim the run cannot support.
    rounds = {**COMPARABLE, "runs": [{"run": run("P0", "P0 初始版"), "metrics": metrics(evaluation=None)}]}
    text = "\n".join(_prompt_rounds(bundle(rounds, [])))
    assert "无法计算" in text


def test_the_other_versions_carry_their_reason_and_full_text():
    prompts = [
        {"id": "P0", "label": "P0 初始版", "reason": "初始四段式", "issues": ["未强调跨文件"], "text": "P0 全文"},
        {"id": "P1", "label": "P1 第一轮优化", "parent_id": "P0", "reason": "补跨文件要求", "issues": ["漏报入口"], "text": "P1 全文"},
        {"id": "P2", "label": "P2 第二轮优化", "reason": "当前版本", "issues": [], "text": "P2 全文"},
    ]
    rounds = {
        **COMPARABLE,
        "runs": [
            {"run": run("P0", "P0 初始版"), "metrics": metrics(evaluation=EVAL)},
            {"run": run("P2", "P2 第二轮优化"), "metrics": metrics(evaluation=EVAL)},
        ],
    }
    text = "\n".join(_prompt_rounds(bundle(rounds, prompts)))
    assert "初始四段式" in text
    assert "未强调跨文件" in text
    assert "P0 全文" in text
    # The running version's text is printed in full in 4.2 already; repeating it here would
    # double the chapter without adding anything.
    assert "P2 全文" not in text
    assert "（`P2`，本轮未使用）" not in text


def test_a_metric_that_could_not_be_computed_is_named_not_printed_as_none():
    # Every sample unresolved: the matrix exists but has an empty denominator, so precision
    # and recall are stored as None. A running round is exactly this case, and `None` sitting
    # in a column of numbers reads as a rendering glitch at best.
    rounds = {
        **COMPARABLE,
        "runs": [
            {
                "run": run("P1", "P1 第一轮优化", status="running", completed_units=0),
                "metrics": metrics(
                    candidates=0,
                    confirmed=0,
                    evaluation={"TP": 0, "FP": 0, "FN": 0, "TN": 0, "precision": None, "recall": None,
                                "eligible": 6, "unresolved": [{"file_path": f"{n}.php"} for n in range(6)]},
                ),
            }
        ],
    }
    text = "\n".join(_prompt_rounds(bundle(rounds, [], current="P1")))
    assert "None" not in text
    assert "| 无法计算 | 无法计算 |" in text


def test_a_real_zero_is_not_mistaken_for_a_missing_metric():
    # 0.0 is a measurement — "no false positives" — and must survive the substitution that
    # turns None into 无法计算.
    assert _cell(0.0) == 0.0
    assert _cell(0) == 0
    assert _cell(None) == "无法计算"


def test_no_rounds_means_no_section():
    assert _prompt_rounds({"run": run("P0", "P0 初始版"), "rounds": {}, "prompts": []}) == []
