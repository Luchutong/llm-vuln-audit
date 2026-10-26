#!/usr/bin/env python3
"""Evaluate Lab30 findings by source location, with CVSS v3.1 Base ratings.

Accepts the enriched ground_truth.json or feat/lab30-shop's answers.json array.
Detection TP/FP/FN stay independent of severity and CVSS agreement. Qualitative
severity is compared to the CVSS Base rating; a label never implies a numeric
score. --check-cvss reports numeric error and Base metric agreement when supplied.
Only the standard library and the adjacent cvss31.py helper are required.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path, PurePosixPath

from cvss31 import BASE, assessment

SCENARIOS = ("sqli", "xss_r", "command_injection")
SCENARIO_TYPES = {
    "SQL 注入": "sqli", "跨文件 SQL 注入": "sqli", "二次 SQL 注入": "sqli",
    "反射型 XSS": "xss_r", "HTML 属性注入型 XSS": "xss_r",
    "命令注入": "command_injection", "跨文件命令注入": "command_injection",
}
EVIDENCE_ENTRY = re.compile(r"([^;:\n]+):(\d+)(?:-(\d+))?")
SEVERITY_NAMES = {"极高": "critical", "严重": "critical", "高": "high", "中": "medium", "低": "low", "无": "none"}


def parse_evidence(evidence: object) -> list[tuple[str, int, int]]:
    """Accept worker citation strings and the API/export's structured ranges."""
    if isinstance(evidence, str):
        return [(match[1].strip().replace("\\", "/"), min(int(match[2]), int(match[3] or match[2])),
                 max(int(match[2]), int(match[3] or match[2]))) for match in EVIDENCE_ENTRY.finditer(evidence)]
    refs = []
    for item in evidence if isinstance(evidence, list) else []:
        if isinstance(item, str):
            refs.extend(parse_evidence(item))
        elif isinstance(item, dict) and item.get("path"):
            try:
                start = int(item.get("start_line", item.get("line", 0)))
                end = int(item.get("end_line", start))
            except (ValueError, TypeError):
                continue
            if start > 0 and end > 0:
                refs.append((str(item["path"]).replace("\\", "/"), min(start, end), max(start, end)))
    return refs


def parts(path: str) -> tuple[str, ...]:
    return tuple(part for part in PurePosixPath(path.replace("\\", "/")).parts if part not in ("", "."))


def same_location(a: str, b: str) -> bool:
    """Ignore archive prefixes, while comparing complete path components."""
    pa, pb = parts(a), parts(b)
    return bool(pa and pb) and (pa == pb or (len(pa) < len(pb) and pb[-len(pa):] == pa)
                               or (len(pb) < len(pa) and pa[-len(pb):] == pb))


def line_hit(evidence: object, truth_path: str, truth_line: int) -> bool:
    return any(same_location(path, truth_path) and start <= truth_line <= end
               for path, start, end in parse_evidence(evidence))


def normalise_severity(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip().casefold()
    return SEVERITY_NAMES.get(value, value)


def normalise_truth(payload: object) -> list[dict]:
    rows = payload.get("vulnerabilities") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError("真值必须为答案数组或含 vulnerabilities 的对象")
    result, seen = [], set()
    for item in rows:
        if not isinstance(item, dict) or not item.get("id"):
            raise ValueError("每条真值必须包含 id")
        ident = str(item["id"])
        if ident in seen:
            raise ValueError(f"真值 id 重复：{ident}")
        seen.add(ident)
        locations = item.get("location", item.get("locations"))
        if not isinstance(locations, list) or not locations:
            raise ValueError(f"真值 {ident} 缺少源码位置")
        for loc in locations:
            if not isinstance(loc, dict) or not loc.get("path") or int(loc.get("line", 0)) < 1:
                raise ValueError(f"真值 {ident} 包含无效源码位置")
        try:
            cvss = assessment(item.get("cvss"))
        except ValueError as exc:
            raise ValueError(f"真值 {ident}：{exc}") from exc
        result.append({**item, "id": ident, "title": item.get("title") or item.get("type") or ident,
                       "location": locations, "cvss": cvss,
                       "scenario": item.get("scenario", SCENARIO_TYPES.get(item.get("type"))),
                       "severity": cvss["severity"] if cvss else normalise_severity(item.get("severity")),
                       "severity_basis": "CVSS:3.1/Base" if cvss else "legacy severity"})
    return result


def finding_rows(payload: object) -> list[dict]:
    if isinstance(payload, dict):
        payload = payload.get("findings") if "findings" in payload else payload.get("results")
    if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
        raise ValueError("审计结果必须为 findings/results 数组或发现数组")
    result = []
    for item in payload:
        kind = str(item.get("finding_kind") or item.get("kind") or "").strip().casefold()
        vulnerability = kind == "vulnerability" if kind else item.get("category") in SCENARIOS
        if vulnerability and item.get("disposition", "open") not in {"retracted", "duplicate", "superseded"}:
            result.append(item)
    return result


def load_findings(args: argparse.Namespace) -> list[dict]:
    if args.findings:
        return finding_rows(json.loads(Path(args.findings).read_text(encoding="utf-8")))
    if not (args.api and args.run):
        raise ValueError("需要 --findings <file> 或 --api <base> --run <run_id> 之一")
    with urllib.request.urlopen(f"{args.api.rstrip('/')}/api/runs/{args.run}", timeout=60) as response:
        return finding_rows(json.loads(response.read().decode("utf-8")))


def compare_rating(finding: dict, truth: dict, check_severity: bool, check_cvss: bool) -> dict:
    reported, error = None, None
    try:
        reported = assessment(finding.get("cvss"))
    except ValueError as exc:
        error = str(exc)
    label = normalise_severity(finding.get("severity"))
    if label is None and reported:
        label = reported["severity"]
    expected = truth["cvss"]
    result = {"severity_expected": truth["severity"], "severity_reported": label,
              "severity_basis": truth["severity_basis"],
              "severity_ok": label == truth["severity"] if check_severity and truth["severity"] is not None else None,
              "cvss_expected": expected, "cvss_reported": reported, "cvss_error": error,
              "cvss_status": "not_checked", "cvss_score_ok": None, "cvss_score_error": None,
              "cvss_score_delta": None, "cvss_vector_ok": None, "cvss_metrics": None}
    if check_cvss:
        result["cvss_status"] = ("missing_truth" if expected is None else "invalid_reported" if error else
                                 "missing_reported" if reported is None else "compared")
        if result["cvss_status"] == "compared":
            delta = round(reported["base_score"] - expected["base_score"], 1)
            result.update(cvss_score_ok=delta == 0, cvss_score_error=abs(delta), cvss_score_delta=delta)
            if expected["metrics"] and reported["metrics"]:
                result["cvss_metrics"] = {key: {"expected": expected["metrics"][key], "reported": reported["metrics"][key],
                                               "ok": expected["metrics"][key] == reported["metrics"][key]} for key in BASE}
                result["cvss_vector_ok"] = all(metric["ok"] for metric in result["cvss_metrics"].values())
    return result


def ratio(numerator: int | float, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def class_coverage(truths: list[dict], matched_ids: set[str]) -> dict:
    """Per-class detection matrix: which of the dataset's classes the audit covered."""
    coverage: dict[str, dict] = {}
    for vuln in truths:
        cls = str(vuln.get("class") or "uncategorized")
        entry = coverage.setdefault(cls, {"total": 0, "detected": 0, "missed": 0,
                                          "detected_ids": [], "missed_ids": []})
        entry["total"] += 1
        if vuln["id"] in matched_ids:
            entry["detected"] += 1
            entry["detected_ids"].append(vuln["id"])
        else:
            entry["missed"] += 1
            entry["missed_ids"].append(vuln["id"])
    return coverage


def evaluate(truth_payload: object, findings: list[dict], *, scenario: str | None = None,
             klass: str | None = None, check_severity: bool = False,
             check_cvss: bool = False) -> dict:
    truths = normalise_truth(truth_payload)
    if scenario:
        truths = [item for item in truths if item["scenario"] == scenario]
    if klass:
        truths = [item for item in truths if item.get("class") == klass]
    if not truths:
        raise ValueError(f"场景 {scenario or 'all'}/类别 {klass or 'all'} 在数据集中没有真值条目")
    findings = finding_rows(findings)
    matched_truth, matched_findings, matches = set(), set(), []
    for index, finding in enumerate(findings):
        hit = next((vuln for vuln in truths if vuln["id"] not in matched_truth and
                    any(line_hit(finding.get("evidence"), loc["path"], int(loc["line"])) for loc in vuln["location"])), None)
        if hit is None:
            continue
        matched_truth.add(hit["id"])
        matched_findings.add(index)
        matches.append({"truth_id": hit["id"], "truth": f"{hit['id']} {hit['title']}",
                        "finding_id": finding.get("id"), "finding": finding.get("title"),
                        **compare_rating(finding, hit, check_severity, check_cvss)})
    missing = [item for item in truths if item["id"] not in matched_truth]
    missed = [f"{v['id']} {v['title']}（真值位置: {'; '.join(loc['path'] + ':' + str(loc['line']) for loc in v['location'])}）" for v in missing]
    fp = [item.get("title") or (item.get("summary") or "")[:60] for index, item in enumerate(findings) if index not in matched_findings]
    tp = len(matches)
    compared = [item for item in matches if item["cvss_status"] == "compared"]
    vectors = [item for item in compared if item["cvss_vector_ok"] is not None]
    severity_compared = [item for item in matches if item["severity_ok"] is not None]
    return {
        "scope": scenario or "all", "class_scope": klass, "truths": len(truths), "findings": len(findings),
        "rating_standard": "CVSS:3.1" if all(item["cvss"] for item in truths) else "mixed/legacy",
        "score_basis": "Base", "TP": tp, "FP": len(fp), "FN": len(missed),
        "precision": ratio(tp, tp + len(fp)), "recall": ratio(tp, len(truths)),
        "f1": ratio(2 * tp, 2 * tp + len(fp) + len(missed)),
        "severity_evaluation": {"checked": check_severity, "compared": len(severity_compared),
                                "correct": sum(item["severity_ok"] for item in severity_compared),
                                "accuracy": ratio(sum(item["severity_ok"] for item in severity_compared), len(severity_compared))},
        "cvss_evaluation": {
            "checked": check_cvss, "compared": len(compared),
            "scoring_coverage": ratio(len(compared), tp),
            "missing_truth": sum(item["cvss_status"] == "missing_truth" for item in matches),
            "missing_reported": sum(item["cvss_status"] == "missing_reported" for item in matches),
            "invalid_reported": sum(item["cvss_status"] == "invalid_reported" for item in matches),
            "score_accuracy": ratio(sum(item["cvss_score_ok"] for item in compared), len(compared)),
            "score_mae": ratio(sum(item["cvss_score_error"] for item in compared), len(compared)),
            "vector_compared": len(vectors),
            "vector_accuracy": ratio(sum(item["cvss_vector_ok"] for item in vectors), len(vectors)),
            "metrics": {key: {"compared": len(vectors), "correct": sum(item["cvss_metrics"][key]["ok"] for item in vectors),
                              "accuracy": ratio(sum(item["cvss_metrics"][key]["ok"] for item in vectors), len(vectors))} for key in BASE},
        },
        "matches": matches, "missed": missed,
        "class_coverage": class_coverage(truths, matched_truth),
        "missed_details": [{"id": item["id"], "title": item["title"], "location": item["location"], "cvss": item["cvss"]} for item in missing],
        "false_positives": fp,
    }


def print_report(report: dict) -> None:
    print(f"评分范围: {report['scope']} · 真值 {report['truths']} 项 · agent 结论 {report['findings']} 条")
    print(f"评级口径: {report['rating_standard']} / Base（只比较基础分，不使用时序分或环境分替代）")
    print(f"TP={report['TP']}  FP={report['FP']}  FN={report['FN']}")
    for label, key in (("precision", "precision"), ("recall", "recall"), ("F1", "f1")):
        print(f"{label}={report[key]:.4f}" if report[key] is not None else f"{label}=n/a")
    if report.get("class_coverage"):
        print("\n类别覆盖（检出/总数）:")
        for cls, cov in report["class_coverage"].items():
            note = f"  漏: {', '.join(cov['missed_ids'])}" if cov["missed_ids"] else ""
            print(f"  {cls:<26} {cov['detected']}/{cov['total']}{note}")
    if report["matches"]:
        print("\n命中明细:")
        for item in report["matches"]:
            expected = item["cvss_expected"]
            extra = f" · CVSS 3.1 Base {expected['base_score']:.1f} ({expected['severity']})" if expected else ""
            if item["severity_ok"] is False:
                extra += f" [severity 不符: 期望 {item['severity_expected']}, 报出 {item['severity_reported']}]"
            if item["cvss_status"] == "compared":
                extra += f" [CVSS 报出 {item['cvss_reported']['base_score']:.1f}, 绝对误差 {item['cvss_score_error']:.1f}]"
            elif item["cvss_status"] != "not_checked":
                extra += f" [CVSS: {item['cvss_status']}{': ' + item['cvss_error'] if item['cvss_error'] else ''}]"
            print(f"  - {item['truth']}{extra}")
    if report["cvss_evaluation"]["checked"]:
        summary = report["cvss_evaluation"]
        print(f"\nCVSS 基础分对比: {summary['compared']} 条；缺失 {summary['missing_reported']} 条；无效 {summary['invalid_reported']} 条")
        print(f"CVSS MAE={summary['score_mae']:.4f}" if summary["score_mae"] is not None else "CVSS MAE=n/a（没有可比较的数值评分）")
    for title, items in (("漏报", report["missed"]), ("多报（无对应真值）", report["false_positives"])):
        if items:
            print(f"\n{title}:")
            for item in items:
                print(f"  - {item}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--truth", help="ground_truth.json 或新版 answers.json（默认随仓库定位）")
    parser.add_argument("--protocol", choices=("legacy_unit_v1", "lab30-v2"), default="legacy_unit_v1", help="默认保留旧版证据范围评分；正式实验显式选择 lab30-v2")
    parser.add_argument("--anchors", help="lab30-v2 冻结评分锚点 JSON（默认随仓库定位）")
    parser.add_argument("--api", help="审计实例基址，如 http://127.0.0.1:8899")
    parser.add_argument("--run", help="run id（与 --api 搭配）")
    parser.add_argument("--findings", help="导出的 run bundle / findings JSON 文件")
    parser.add_argument("--scenario", choices=SCENARIOS, help="只评某个分场景（与 --class 互斥使用，默认全量 30 项）")
    parser.add_argument("--class", dest="klass", help="只评某个粗粒度类别（如 path_traversal / auth_bypass），默认全量")
    parser.add_argument("--check-severity", action="store_true", help="将文字等级与 CVSS 3.1 基础分对应的等级比较")
    parser.add_argument("--check-cvss", action="store_true", help="比较 cvss.base_score / 基础向量；缺失不从文字等级猜分")
    parser.add_argument("--out", help="明细 JSON 输出路径（默认写数据集目录）")
    args = parser.parse_args(argv)
    truth_path = Path(args.truth) if args.truth else Path(__file__).resolve().parents[1] / "datasets/lab30-shop/ground_truth.json"
    try:
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        if args.protocol == "lab30-v2":
            if args.scenario or args.klass:
                raise ValueError("lab30-v2 正式评分必须使用完整真值，类别筛选仅用于结果展示")
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
            from audit.prompt_evaluation import DEFAULT_ANCHORS_PATH, evaluate_v2
            anchors = json.loads(Path(args.anchors or DEFAULT_ANCHORS_PATH).read_text(encoding="utf-8"))
            report = evaluate_v2(truth, load_findings(args), anchors)
        else:
            report = evaluate(truth, load_findings(args), scenario=args.scenario,
                              klass=args.klass,
                              check_severity=args.check_severity, check_cvss=args.check_cvss)
        report["truth_file"] = str(truth_path)
        if isinstance(truth, dict):
            report["truth_provenance"] = truth.get("provenance")
        print_report(report)
        out = Path(args.out) if args.out else truth_path.parent / f"score_{args.scenario or args.klass or 'all'}.json"
        encoded = json.dumps(report, ensure_ascii=False, indent=2)
        try:
            out.write_text(encoded, encoding="utf-8")
        except OSError:
            if args.out:
                raise
            out = Path(f"score_{args.scenario or args.klass or 'all'}.json")
            out.write_text(encoded, encoding="utf-8")
        print(f"\n明细已写入: {out}")
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
