"""Coverage, de-duplication and truth-based evaluation.

Two rules shape everything here:

* A failed, timed-out or budget-exhausted unit is *not* evidence of absence. It is
  reported as incomplete and can never become a true negative.
* Recall, false negatives and true negatives are only computable on an independently
  verified truth subset. Ordinary uploaded projects report them as not computable.
"""
from __future__ import annotations

from .schemas import CATEGORIES

INCOMPLETE_STATUSES = ("incomplete", "failed", "skipped")
UNRESOLVED_STATUSES = ("pending", "running") + INCOMPLETE_STATUSES


def _round(value: float) -> float:
    return round(value, 6)


def summarise(
    run: dict,
    units: list[dict],
    findings: list[dict],
    truths: list[dict],
    *,
    tasks: list[dict] | None = None,
) -> dict:
    total_units = len(units)
    completed = [unit for unit in units if unit["status"] == "completed"]
    incomplete = [unit for unit in units if unit["status"] in INCOMPLETE_STATUSES]
    pending = [unit for unit in units if unit["status"] in ("pending", "running")]

    candidates = [f for f in findings if f.get("validation_state") == "candidate"]
    discarded = [f for f in findings if f.get("validation_state") != "candidate"]

    verified = [f for f in candidates if f.get("verifications")]
    confirmed = [f for f in candidates if f.get("verdict") == "confirmed"]
    rejected = [f for f in candidates if f.get("verdict") == "rejected"]
    uncertain = [f for f in candidates if f.get("verdict") == "uncertain"]
    awaiting = [f for f in candidates if not f.get("verdict")]

    # Repeated candidates for the same weakness collapse to one observation.
    distinct: dict[str, str] = {}
    for finding in candidates:
        distinct.setdefault(finding["fingerprint"], finding["id"])

    metrics = {
        "candidates": len(distinct),
        "candidate_findings": len(candidates),
        "discarded_candidates": len(discarded),
        "confirmed": len(confirmed),
        "rejected": len(rejected),
        "uncertain": len(uncertain),
        "awaiting_verification": len(awaiting),
        "audit_coverage": _round(len(completed) / total_units) if total_units else 0.0,
        "verification_coverage": _round(len(verified) / len(candidates)) if candidates else 0.0,
        "total_units": total_units,
        "completed_units": len(completed),
        "incomplete_units": len(incomplete),
        "pending_units": len(pending),
    }

    # Planner v2 has no static per-file queue. Its meaningful progress measure is
    # the durable task frontier, so do not present a task count as source coverage.
    # ``tasks is not None`` distinguishes the new API bundle from historical goal
    # records which used the former work-item queue.
    if run.get("task_spec") and tasks is not None:
        state_counts: dict[str, int] = {}
        for item in tasks:
            state = str(item.get("state") or "unknown")
            state_counts[state] = state_counts.get(state, 0) + 1
        total_tasks = len(tasks)
        terminal_states = {"completed", "exhausted", "blocked", "cancelled", "skipped"}
        terminal_tasks = sum(count for state, count in state_counts.items() if state in terminal_states)
        active_tasks = sum(state_counts.get(state, 0) for state in ("pending", "ready", "running"))
        metrics.update({
            # Keep the old field for older clients, but its value is deliberately
            # task-frontier completion in this mode, not a claim about file coverage.
            "audit_coverage": _round(terminal_tasks / total_tasks) if total_tasks else 0.0,
            "total_units": 0,
            "completed_units": 0,
            "incomplete_units": 0,
            "pending_units": 0,
            "total_tasks": total_tasks,
            "completed_tasks": state_counts.get("completed", 0),
            "terminal_tasks": terminal_tasks,
            "active_tasks": active_tasks,
            "blocked_tasks": state_counts.get("blocked", 0),
            "task_states": state_counts,
            "task_coverage": _round(terminal_tasks / total_tasks) if total_tasks else 0.0,
            "truth_status": "planner_goal_not_comparable",
            "evaluation": None,
        })
        return metrics

    # A custom objective does not make the fixed SQLi/XSS/command-injection
    # checklist disappear from historic truth data.  It does make that matrix
    # inapplicable: treating a goal finding as one of those categories would invent
    # false positives or, worse, bank an unexplored category as a true negative.
    if run.get("task_spec"):
        evaluation, truth_status = None, "goal_task_not_comparable"
    else:
        scope = set(run.get("scope") or [])
        scoped_truths = [t for t in truths if t["file_path"] in scope]
        evaluation, truth_status = _evaluate(scoped_truths, units, candidates, run)
    metrics["truth_status"] = truth_status
    metrics["evaluation"] = evaluation
    return metrics


def _evaluate(truths: list[dict], units: list[dict], candidates: list[dict], run: dict):
    if not truths:
        return None, "no_truth_set"

    eligible = [t for t in truths if t.get("independently_verified")]
    if not eligible:
        return None, "truth_set_not_verified"

    units_by_file: dict[str, list[dict]] = {}
    for unit in units:
        units_by_file.setdefault(unit["file_path"], []).append(unit)

    # A sample counts as detected when any stored candidate covers its file and category.
    found: set[tuple[str, str]] = set()
    for finding in candidates:
        unit = next((u for u in units if u["unit_id"] == finding["unit_id"]), None)
        if unit is not None:
            found.add((unit["file_path"], finding["category"]))

    TP = FP = FN = TN = 0
    unresolved: list[dict] = []
    for sample in eligible:
        key = (sample["file_path"], sample["category"])
        file_units = units_by_file.get(sample["file_path"], [])
        detected = key in found

        if detected:
            if sample["vulnerable"]:
                TP += 1
            else:
                FP += 1
            continue

        # No candidate. Absence only counts when every unit of that file finished.
        if not file_units:
            unresolved.append({**_sample_ref(sample), "reason": "该文件不在本次审计范围内"})
            continue
        unfinished = [u for u in file_units if u["status"] in UNRESOLVED_STATUSES]
        if unfinished:
            unresolved.append(
                {
                    **_sample_ref(sample),
                    "reason": f"该文件有 {len(unfinished)} 个单元未完成，不能判为阴性",
                    "units": [
                        {"unit_id": u["unit_id"], "symbol": u["symbol"], "status": u["status"], "error": u.get("error")}
                        for u in unfinished[:6]
                    ],
                }
            )
            continue

        # A unit can finish and still say "what I was shown is not enough to decide". The spec
        # puts missing context in the same family as a budget that ran out: an unfinished
        # state, never a negative. Counting it as FN would convert the model's own honesty
        # into a missed detection, and counting it as TN would bank a negative it never
        # claimed, so the sample is set aside instead.
        blind = [u for u in file_units if _conclusion(u, sample["category"]) == "insufficient_context"]
        if blind:
            unresolved.append(
                {
                    **_sample_ref(sample),
                    "reason": f"该文件有 {len(blind)} 个单元结论为「缺少上下文」（insufficient_context），不判为阴性",
                    "units": [
                        {"unit_id": u["unit_id"], "symbol": u["symbol"], "status": u["status"], "error": u.get("error")}
                        for u in blind[:6]
                    ],
                }
            )
            continue

        if sample["vulnerable"]:
            FN += 1
        else:
            TN += 1

    # The loop above runs from truth sample to candidate. A candidate whose file×category
    # combination has no truth sample at all cannot be scored in either direction: there is
    # no basis to call it a hit, and calling it a false alarm would need a truth sample
    # saying that combination is safe. It is still a finding the reader sees in 6.3, so it
    # gets named here rather than dropping out of the accounting between the two views.
    truth_keys = {(t["file_path"], t["category"]) for t in eligible}
    truth_files = {t["file_path"] for t in eligible}
    unmatched: list[dict] = []
    seen_unmatched: set[tuple[str, str]] = set()
    for finding in candidates:
        unit = next((u for u in units if u["unit_id"] == finding["unit_id"]), None)
        if unit is None:
            continue
        key = (unit["file_path"], finding["category"])
        if key in truth_keys or key in seen_unmatched:
            continue
        seen_unmatched.add(key)
        unmatched.append(
            {
                "finding_id": finding.get("id"),
                "file_path": unit["file_path"],
                "category": finding["category"],
                "reason": (
                    "该文件的这一类没有真值样本"
                    if unit["file_path"] in truth_files
                    else "该文件不在真值样本集内"
                ),
            }
        )

    precision = TP / (TP + FP) if (TP + FP) else None
    recall = TP / (TP + FN) if (TP + FN) else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
    evaluation = {
        "TP": TP,
        "FP": FP,
        "FN": FN,
        "TN": TN,
        "precision": _round(precision) if precision is not None else None,
        "recall": _round(recall) if recall is not None else None,
        "f1": _round(f1) if f1 is not None else None,
        "unresolved": unresolved,
        "unmatched_candidates": unmatched,
        "eligible": len(eligible),
        "total_samples": len(truths),
        "excluded_samples": [
            _sample_ref(t) for t in truths if not t.get("independently_verified")
        ],
    }
    return evaluation, "evaluated"


def _sample_ref(sample: dict) -> dict:
    return {"file_path": sample["file_path"], "category": sample["category"], "vulnerable": sample["vulnerable"]}


def _conclusion(unit: dict, category: str) -> str | None:
    """What this unit concluded for one category, or None if it never said.

    `result` is the stored structured output; a unit still queued has none, and an old row
    written before this field existed parses to None rather than blowing up the metrics.
    """
    result = unit.get("result") or {}
    conclusions = result.get("conclusions") or {}
    value = conclusions.get(category)
    return value if isinstance(value, str) else None


def comparable_runs(runs: list[dict]) -> dict:
    """Decide whether runs may be compared with each other.

    The spec requires identical snapshot, scope, model and budgets before any
    measured improvement may be claimed.
    """
    if len(runs) < 2:
        return {"comparable": False, "reasons": ["至少需要两个运行才能对比"], "notes": []}
    reasons: list[str] = []
    first = runs[0]
    for other in runs[1:]:
        if other["snapshot_id"] != first["snapshot_id"]:
            reasons.append("快照不同")
        if sorted(other["scope"]) != sorted(first["scope"]):
            reasons.append("审计范围不同")
        if other["model"] != first["model"]:
            reasons.append("模型不同")
        if other["budgets"] != first["budgets"]:
            reasons.append("预算不同")
        if other.get("agent_policy", {"version": "legacy"}) != first.get("agent_policy", {"version": "legacy"}):
            reasons.append("Agent 执行策略不同")
        if other.get("task_spec") != first.get("task_spec"):
            reasons.append("目标任务定义不同")

    # Coverage is not a precondition — how much of the queue a run gets through is part of
    # what is being measured. But it is a trap when reading the table: a run that finished
    # 5 of 6 units will find more than one that finished 2, whatever the prompt says, so
    # say so next to the numbers instead of leaving the reader to notice.
    notes: list[str] = []
    for other in runs[1:]:
        if other.get("completed_units") != first.get("completed_units"):
            notes.append(
                f"完成单元数不同（{first.get('completed_units')}/{first.get('total_units')} 与 "
                f"{other.get('completed_units')}/{other.get('total_units')}）：候选数差异可能来自覆盖率，"
                "而不是提示词的改动"
            )
        if other.get("status") != "completed":
            notes.append(f"有运行未正常结束（{other.get('id', '')[:8]}：{other.get('status')}），其候选数不完整")
    return {"comparable": not reasons, "reasons": sorted(set(reasons)), "notes": sorted(set(notes))}


def prompt_diffs(runs: list[dict]) -> list[dict]:
    """One entry per run describing which prompt it used and how it differs."""
    diffs = []
    for run in runs:
        previous = None
        for other in runs:
            if other["created_at"] < run["created_at"] and other["prompt_id"] == run["prompt_id"]:
                previous = other
        diffs.append(
            {
                "run_id": run["id"],
                "prompt_id": run["prompt_id"],
                "prompt_label": run["prompt_label"],
                "model": run["model"],
                "created_at": run["created_at"],
                "changed_from": previous["id"] if previous else None,
            }
        )
    return diffs


def category_set() -> tuple[str, ...]:
    return tuple(CATEGORIES)
