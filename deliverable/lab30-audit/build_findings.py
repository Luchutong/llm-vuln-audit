#!/usr/bin/env python3
"""Build the evaluator's findings bundle from the independent audit conclusions.

The previous revision of this script read ``ground_truth.json`` directly, which made
any score produced from its output circular (the answer key graded against itself).
It now loads ``audit_findings.json`` -- the standalone white-box audit written from a
line-by-line read of the bound source archive (sha256 67fd87e9...) -- and only
validates/reshapes it into the evaluator's findings schema. Nothing here invents
locations or ratings; edit the audit file to change conclusions.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
AUDIT = HERE / "audit_findings.json"
OUT = HERE / "findings.json"


def main() -> int:
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    findings = []
    for item in audit["findings"]:
        # 最小结构校验：评测按证据行匹配，缺证据或无 CVSS 都会让覆盖面失真。
        for field in ("id", "title", "severity", "evidence", "cvss"):
            if not item.get(field):
                raise SystemExit(f"审计结论 {item.get('id', '?')} 缺少字段: {field}")
        for ref in item["evidence"]:
            if not ref.get("path") or int(ref.get("start_line", 0)) < 1:
                raise SystemExit(f"审计结论 {item['id']} 存在无效证据位置: {ref}")
        findings.append({
            "id": item["id"],
            "kind": "vulnerability",
            "finding_kind": "vulnerability",
            "title": item["title"],
            "type": item["type"],
            "class": item.get("class"),
            "cwe": item.get("cwe"),
            "severity": item["severity"],
            "route": item.get("route"),
            "evidence": item["evidence"],
            "cvss": item["cvss"],
            "description": item.get("description"),
            "attack_input": item.get("attack_input"),
            "normal_input": item.get("normal_input"),
            "expected_result": item.get("expected_result"),
            "impact": item.get("impact"),
            "remediation": item.get("remediation"),
        })
    bundle = {"findings": findings, "count": len(findings)}
    OUT.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {OUT} with {len(findings)} findings from {AUDIT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
