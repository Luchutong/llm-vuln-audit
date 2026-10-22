#!/usr/bin/env python3
"""Score an audit run's findings against the lab30-shop ground-truth dataset.

This is the offline scorer the dataset README describes: it compares agent findings
with ``datasets/lab30-shop/ground_truth.json`` and reports TP/FP/FN, precision, recall
and F1, plus the miss detail needed to compare prompt versions.

Two things it must get right, both established by measurement:

1. **Path normalisation.**  A snapshot imported from ``lab30-shop-1.0.0-source.zip``
   keeps the archive's top-level directory, so agent evidence reads
   ``lab30-shop/app/public/catalog/index.php`` while the dataset says
   ``app/public/catalog/index.php``.  Exact string matching scores a perfect run
   0/39.  Paths are therefore matched component-wise as suffixes of each other.
2. **Line intersection.**  A truth ``location`` is a single line; a finding cites
   ``path:start-end`` windows.  A hit is a same-path window that contains or
   overlaps the truth line.

Findings come from either a live instance (``--api`` + ``--run``) or an exported
run bundle / findings list (``--findings``).  Stdlib only, no project imports.

Usage:
    score_dataset.py --api http://127.0.0.1:8899 --run <run_id> [--scenario sqli]
    score_dataset.py --findings run.json [--truth ground_truth.json] [--scenario sqli]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path, PurePosixPath

SCENARIOS = ("sqli", "xss_r", "command_injection")
EVIDENCE_ENTRY = re.compile(r"([^;:]+):(\d+)(?:-(\d+))?")


def parse_evidence(evidence: str) -> list[tuple[str, int, int]]:
    """Parse ``path:start-end; path:line`` citations into (path, start, end) triples."""
    out: list[tuple[str, int, int]] = []
    for match in EVIDENCE_ENTRY.finditer(evidence or ""):
        path = match.group(1).strip().replace("\\", "/")
        start = int(match.group(2))
        end = int(match.group(3) or start)
        out.append((path, min(start, end), max(start, end)))
    return out


def parts(path: str) -> tuple[str, ...]:
    return tuple(part for part in PurePosixPath(path.replace("\\", "/")).parts if part not in ("", "."))


def same_location(a: str, b: str) -> bool:
    """True when both paths point at the same file regardless of archive prefixes."""
    pa, pb = parts(a), parts(b)
    return pa == pb or (len(pa) < len(pb) and pb[-len(pa):] == pa) or (len(pb) < len(pa) and pa[-len(pb):] == pb)


def line_hit(evidence: str, truth_path: str, truth_line: int) -> bool:
    return any(
        same_location(path, truth_path) and start <= truth_line <= end
        for path, start, end in parse_evidence(evidence)
    )


def load_findings(args: argparse.Namespace) -> list[dict]:
    if args.findings:
        payload = json.loads(open(args.findings, encoding="utf-8").read())
        if isinstance(payload, dict):
            payload = payload.get("findings") or payload.get("results") or []
        return [f for f in payload if f.get("kind") == "vulnerability"]
    if not (args.api and args.run):
        sys.exit("需要 --findings <file> 或 --api <base> --run <run_id> 之一")
    with urllib.request.urlopen(f"{args.api.rstrip('/')}/api/runs/{args.run}", timeout=60) as response:
        bundle = json.loads(response.read().decode("utf-8"))
    return [f for f in bundle.get("findings") or [] if f.get("kind") == "vulnerability"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--truth", default=None, help="ground_truth.json 路径（默认随仓库定位）")
    parser.add_argument("--api", default=None, help="审计实例基址，如 http://127.0.0.1:8899")
    parser.add_argument("--run", default=None, help="run id（与 --api 搭配）")
    parser.add_argument("--findings", default=None, help="导出的 run bundle / findings JSON 文件")
    parser.add_argument("--scenario", choices=SCENARIOS, default=None, help="只评某个分场景（默认全量 30 项）")
    parser.add_argument("--check-severity", action="store_true", help="命中后额外核对 severity 是否一致")
    parser.add_argument("--out", default=None, help="明细 JSON 输出路径（默认写数据集目录；容器内只读时必须指定）")
    args = parser.parse_args()

    default_truth = Path(__file__).resolve().parents[1] / "datasets" / "lab30-shop" / "ground_truth.json"
    truth_path = Path(args.truth) if args.truth else default_truth
    truth = json.loads(truth_path.read_text(encoding="utf-8"))

    truths = truth["vulnerabilities"]
    if args.scenario:
        truths = [v for v in truths if v.get("scenario") == args.scenario]
    if not truths:
        sys.exit(f"场景 {args.scenario} 在数据集中没有真值条目")

    findings = load_findings(args)
    matched_truth: set[str] = set()
    matched_findings: set[int] = set()
    matches: list[dict] = []

    for finding in findings:
        hit = None
        for vuln in truths:
            if vuln["id"] in matched_truth:
                continue
            if any(line_hit(finding.get("evidence", ""), loc["path"], int(loc["line"])) for loc in vuln["location"]):
                hit = vuln
                break
        if hit is not None:
            matched_truth.add(hit["id"])
            matched_findings.add(id(finding))
            severity_ok = None
            if args.check_severity:
                severity_ok = finding.get("severity") == hit.get("severity")
            matches.append({
                "truth": f"{hit['id']} {hit['title']}",
                "severity_expected": hit.get("severity"),
                "severity_reported": finding.get("severity"),
                "severity_ok": severity_ok,
                "finding": finding.get("title"),
            })

    tp = len(matches)
    fn = [f"{v['id']} {v['title']}（真值位置: {'; '.join(l['path'] + ':' + str(l['line']) for l in v['location'])}）"
          for v in truths if v["id"] not in matched_truth]
    fp = [f.get("title") or (f.get("summary") or "")[:60] for f in findings if id(f) not in matched_findings]
    precision = tp / (tp + len(fp)) if (tp + len(fp)) else None
    recall = tp / (tp + len(fn)) if (tp + len(fn)) else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None

    scope = f"场景 {args.scenario}" if args.scenario else "全量"
    print(f"评分范围: {scope} · 真值 {len(truths)} 项 · agent 结论 {len(findings)} 条")
    print(f"TP={tp}  FP={len(fp)}  FN={len(fn)}")
    print(f"precision={precision:.4f}" if precision is not None else "precision=n/a")
    print(f"recall={recall:.4f}" if recall is not None else "recall=n/a")
    print(f"F1={f1:.4f}" if f1 is not None else "F1=n/a")
    if matches:
        print("\n命中明细:")
        for m in matches:
            extra = ""
            if m["severity_ok"] is False:
                extra = f"  [severity 不符: 期望 {m['severity_expected']}, 报出 {m['severity_reported']}]"
            print(f"  - {m['truth']}{extra}")
    if fn:
        print("\n漏报:")
        for item in fn:
            print(f"  - {item}")
    if fp:
        print("\n多报（无对应真值）:")
        for item in fp:
            print(f"  - {item}")

    report = {
        "scope": args.scenario or "all",
        "truths": len(truths),
        "findings": len(findings),
        "TP": tp,
        "FP": len(fp),
        "FN": len(fn),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "matches": matches,
        "missed": fn,
        "false_positives": fp,
    }
    if args.out:
        out = Path(args.out)
    elif args.scenario:
        out = truth_path.parent / f"score_{args.scenario}.json"
    else:
        out = truth_path.parent / "score_all.json"
    try:
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        # 数据集目录只读（例如容器内镜像层）；退回当前工作目录，明细仍然可取。
        out = Path(f"score_{args.scenario or 'all'}.json")
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n明细已写入: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
