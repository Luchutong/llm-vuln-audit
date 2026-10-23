"""CVSS v3.1 Base scores, using FIRST's equations and integer Roundup.

CVSS is owned by FIRST and used by permission. Reference:
https://www.first.org/cvss/v3.1/specification-document
Temporal and Environmental metrics are validated but never substituted for Base.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
import math

BASE = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
VALUES = {
    "AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC",
    "C": "NLH", "I": "NLH", "A": "NLH",
    "E": "XHFPU", "RL": "XUWTO", "RC": "XCRU", "CR": "XHML",
    "IR": "XHML", "AR": "XHML", "MAV": "XNALP", "MAC": "XLH",
    "MPR": "XNLH", "MUI": "XNR", "MS": "XUC", "MC": "XNLH",
    "MI": "XNLH", "MA": "XNLH",
}


def score_value(value: object) -> float:
    """Accept only finite scores from 0.0 to 10.0 with at most one decimal."""
    try:
        number = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("CVSS 基础分必须为 0.0–10.0 的数值") from exc
    if not number.is_finite() or not 0 <= number <= 10 or number * 10 != (number * 10).to_integral_value():
        raise ValueError("CVSS 基础分必须为 0.0–10.0，至多一位小数")
    return float(number)


def severity(score: object) -> str:
    number = score_value(score)
    if number == 0:
        return "none"
    if number < 4:
        return "low"
    if number < 7:
        return "medium"
    if number < 9:
        return "high"
    return "critical"


def parse_vector(vector: str) -> dict[str, str]:
    if not isinstance(vector, str) or not vector.startswith("CVSS:3.1/"):
        raise ValueError("仅支持 CVSS:3.1 向量")
    metrics: dict[str, str] = {}
    for token in vector.split("/")[1:]:
        parts = token.split(":")
        if len(parts) != 2:
            raise ValueError(f"无效 CVSS 指标：{token}")
        key, value = parts
        if key not in VALUES or len(value) != 1 or value not in VALUES[key] or key in metrics:
            raise ValueError(f"无效或重复 CVSS 指标：{token}")
        metrics[key] = value
    missing = set(BASE) - metrics.keys()
    if missing:
        raise ValueError(f"CVSS 向量缺少基础指标：{', '.join(sorted(missing))}")
    return metrics


def roundup(value: float) -> float:
    # FIRST Appendix A: remove floating-point noise before rounding up to 0.1.
    integer = math.floor(value * 100000 + 0.5)
    return integer / 100000 if integer % 10000 == 0 else (integer // 10000 + 1) / 10


def base_score(metrics: dict[str, str]) -> float:
    changed = metrics["S"] == "C"
    impact_values = {"N": 0, "L": 0.22, "H": 0.56}
    iss = 1 - math.prod(1 - impact_values[metrics[key]] for key in ("C", "I", "A"))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}
    exploitability = (8.22 * {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
                      * {"L": 0.77, "H": 0.44}[metrics["AC"]]
                      * privileges[metrics["PR"]] * {"N": 0.85, "R": 0.62}[metrics["UI"]])
    return roundup(min((1.08 if changed else 1) * (impact + exploitability), 10))


def assessment(value: object) -> dict | None:
    """Normalise a cvss object, verifying an explicit score against its vector.

    A missing Base score may be computed from a valid vector. A qualitative label
    alone is never promoted to a numeric score. Source vectors and assessment
    context remain in the dataset; this projection is used in score reports.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("cvss 必须为对象")
    if str(value.get("version", "3.1")) != "3.1":
        raise ValueError("仅支持 CVSS 3.1，不能混用其他版本")
    vectors = [value[key] for key in ("base_vector", "vector") if value.get(key) is not None]
    parsed = [parse_vector(vector) for vector in vectors]
    metrics = {key: parsed[0][key] for key in BASE} if parsed else {}
    if any(any(item[key] != metrics[key] for key in BASE) for item in parsed[1:]):
        raise ValueError("CVSS 基础向量与完整向量不一致")
    score = score_value(value["base_score"]) if value.get("base_score") is not None else None
    if metrics:
        computed = base_score(metrics)
        if score is not None and score != computed:
            raise ValueError(f"CVSS 基础分 {score:.1f} 与向量计算值 {computed:.1f} 不一致")
        score = computed
    if score is None:
        raise ValueError("cvss 缺少 base_score 或可计算的 CVSS 3.1 向量")
    return {
        "version": "3.1", "score_basis": "Base", "base_score": score,
        "base_vector": "CVSS:3.1/" + "/".join(f"{key}:{metrics[key]}" for key in BASE) if metrics else None,
        "metrics": metrics, "severity": severity(score),
    }
