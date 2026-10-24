"""One score for "how much of what this run claims survived its own defences".

The three defence mechanisms this project added are measured on different things, so a single
number is only honest if every component is a rate the host can point at:

* ``evidence`` -- of the vulnerability conclusions the run produced, how many passed the
  host's source-evidence validator.  A conclusion whose citations cannot be re-read is not
  a finding, so this is the first line.
* ``poc`` -- of the conclusions the isolated runner actually attempted, how many came back
  ``verified``.  ``rejected`` and ``inconclusive`` both count against it.
* ``review`` -- of the Planner cross-checks, how many confirmed the runner's verdict instead
  of contesting it.  This is the second reader of the same observations.
* ``injection`` / ``chain`` -- measured on the Lab30 benchmark, not on this run: the
  canary files' resistance rate, and the share of reported findings that carried the whole
  ``input -> propagation -> sink`` chain.  They describe the prompts, so they are shown as
  benchmark context and carry the experiment they came from.

Weights are equal on purpose.  The point is to put the five rates side by side and let the
missing ones show up as missing; pretending the weighting was optimised would be a claim
this project never tested.  Because components can be unavailable (POC switched off, no
verdict to review, no benchmark run yet), the score normalises over the available weights
and reports exactly which components were left out.
"""
from __future__ import annotations

COMPONENTS: tuple[tuple[str, str, float, str], ...] = (
    ("evidence", "证据校验通过率", 0.2, "run"),
    ("poc", "POC 验证通过率", 0.2, "run"),
    ("review", "Planner 复核通过率", 0.2, "run"),
    ("injection", "注入抵抗率", 0.2, "benchmark"),
    ("chain", "证据链完整率", 0.2, "benchmark"),
)

# Conclusions the run actually produced (as opposed to investigation records).
_CONCLUSION_STATES = ("candidate", "invalid_evidence", "invalid_finding")
# Verdicts that mean "the runner tried".  ``unverified``/``not_applicable`` mean it did not.
_ATTEMPTED = ("verified", "rejected", "inconclusive")


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def evidence_component(findings: list[dict]) -> tuple[float | None, str]:
    conclusions = [
        item for item in findings
        if str(item.get("validation_state") or "") in _CONCLUSION_STATES
    ]
    if not conclusions:
        return None, "本次运行没有漏洞候选"
    passed = sum(
        1 for item in conclusions if str(item.get("validation_state") or "") == "candidate"
    )
    return _rate(passed, len(conclusions)), f"{passed}/{len(conclusions)} 条候选通过源码证据校验"


def poc_component(summary: dict | None) -> tuple[float | None, str]:
    summary = summary or {}
    attempted = sum(int(summary.get(status) or 0) for status in _ATTEMPTED)
    if not attempted:
        return None, "本次运行没有执行自动验证"
    verified = int(summary.get("verified") or 0)
    return _rate(verified, attempted), f"{verified}/{attempted} 次自动验证判为已验证"


def review_component(reviews: list[dict]) -> tuple[float | None, str]:
    if not reviews:
        return None, "没有需要核实的自动验证结论"
    confirmed = sum(1 for item in reviews if str(item.get("decision")) == "confirmed")
    return _rate(confirmed, len(reviews)), f"{confirmed}/{len(reviews)} 条复核确认观测支持结论"


def benchmark_components(experiment: dict | None) -> dict[str, tuple[float | None, str]]:
    """Mean of the prompt benchmark's two defence rates, with the experiment they came from."""
    rows = (experiment or {}).get("rows") or []
    if not rows:
        return {
            "injection": (None, "还没有完成的 Prompt 对比实验"),
            "chain": (None, "还没有完成的 Prompt 对比实验"),
        }
    resistance = [
        row["injection"]["resistance_rate"] for row in rows
        if (row.get("injection") or {}).get("resistance_rate") is not None
    ]
    chain = [
        row["discipline"]["chain_rate"] for row in rows
        if (row.get("discipline") or {}).get("chain_rate") is not None
    ]
    label = f"{len(rows)} 个版本的基准均值"
    return {
        "injection": (
            round(sum(resistance) / len(resistance), 4) if resistance else None,
            f"{label}；注入 canary 被报告的占比" if resistance else "实验未记录注入抵抗",
        ),
        "chain": (
            round(sum(chain) / len(chain), 4) if chain else None,
            f"{label}；报告中写全输入→传播→危险操作的占比" if chain else "实验未记录证据链完整率",
        ),
    }


def summarise(
    findings: list[dict],
    verification_summary: dict | None,
    reviews: list[dict],
    experiment: dict | None,
) -> dict:
    """The five rates, the normalised total, and what was left out of it."""
    measured = {
        "evidence": evidence_component(findings),
        "poc": poc_component(verification_summary),
        "review": review_component(reviews),
        **benchmark_components(experiment),
    }
    components = []
    for key, label, weight, source in COMPONENTS:
        value, detail = measured[key]
        components.append({
            "key": key,
            "label": label,
            "weight": weight,
            "value": value,
            "source": source,
            "detail": detail,
        })
    available = [item for item in components if item["value"] is not None]
    total_weight = round(sum(item["weight"] for item in available), 4)
    score = None
    if total_weight:
        score = round(
            sum(item["value"] * item["weight"] for item in available) / total_weight, 4
        )
    return {
        "score": score,
        "components": components,
        "missing": [item["key"] for item in components if item["value"] is None],
        "denominator_weight": total_weight,
        "benchmark": {
            "experiment_id": (experiment or {}).get("id"),
            "finished_at": (experiment or {}).get("finished_at"),
            "variants": [row.get("variant") for row in ((experiment or {}).get("rows") or [])],
        },
        "note": (
            "总分按可用成分的权重归一化；缺失项在 missing 中列出，不以 0 分代入。"
            "defence 相关三个成分来自本次运行，injection/chain 来自最近一次完成的 Prompt 对比实验。"
        ),
    }
