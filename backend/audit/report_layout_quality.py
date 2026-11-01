"""Validate a delivery view without rerating immutable historical fact quality."""
from __future__ import annotations

import re


def evaluate(doc, markdown):
    entries = doc.get("canonical_findings") or []
    identities = [e["canonical_id"] for e in entries]
    numbers = doc.get("numbering") or {}
    refs = {(ref["finding_id"], int(ref.get("revision") or 1)) for e in entries for ref in e.get("source_record_refs") or []}
    refs.update((e["current_claim_ref"]["finding_id"], int(e["current_claim_ref"].get("revision") or 1)) for e in entries)
    attempts = {a.get("verification_id"): a for a in doc.get("verification_attempts") or []}
    needed = {r.get("evidence_id") for e in entries for r in e["frozen_claim"].get("evidence") or []}
    sources = {s.get("evidence_id"): s for s in doc.get("source_evidence") or []}
    def ref(item):
        value = item.get("finding_ref") or {}
        return value.get("finding_id"), int(value.get("revision") or 1)
    checks = {
        "scope_matches": identities == doc.get("scope", {}).get("canonical_ids"),
        "unique_identity": len(identities) == len(set(identities)),
        "counts": doc["counts"]["canonical"] == len(entries) and all(
            doc["counts"].get(state) == sum(e.get("final_disposition") == state for e in entries)
            for state in ("accepted", "pending", "contested")),
        "numbering": set(numbers) == set(identities) and len(set(numbers.values())) == len(numbers),
        "attempt_ownership": all(ref(a) in refs for a in attempts.values()),
        "review_ownership": all(ref(r) in refs and r.get("verification_id") in attempts
                                and ref(r) == ref(attempts[r["verification_id"]]) for r in doc.get("reviews") or []),
        "source_closure": not (set(sources) - needed),
        "missing_source_disclosed": not (needed - set(sources)) or "未冻结源码片段" in markdown or doc["view"] == "audit",
        "no_empty_poc_sentence": "POC 执行：。" not in markdown,
        "no_object_repr": not re.search(r"<(?:object|[A-Za-z_]+ object) at 0x", markdown),
    }
    fence = None
    tables_ok = True
    headings = []
    anchors = []
    for line in markdown.splitlines():
        marker = re.match(r"^(`{3,}|~{3,})(.*)$", line)
        if marker:
            if fence is None:
                fence = marker[1]
            elif marker[1] == fence and not marker[2].strip():
                fence = None
            continue
        if fence:
            continue
        if line.startswith("|"):
            tables_ok = tables_ok and line.count("|") == 7
        heading = re.match(r"^(#{1,6}) (.*)$", line)
        if heading:
            headings.append(heading[2])
        anchors.extend(re.findall(r'<a id="([^"]+)"></a>', line))
    checks.update(fences=fence is None, narrow_tables=tables_ok, unique_anchors=len(anchors) == len(set(anchors)))
    sections = {"audit": {"结果与完成性", "漏洞清单", "覆盖与未完成工作", "后续行动", "限制与追溯"},
                "finding": {"影响与受影响位置", "利用前提", "根因与源码证据", "复现与实际验证", "终审结论与限制", "CVSS 3.1 依据", "修复建议与复测", "来源与附件"},
                "accepted": {f"终审接受（{doc['counts']['accepted']}）"},
                "vulnerabilities": {f"{label}（{doc['counts'][key]}）" for key, label in
                                    (("accepted", "终审接受"), ("pending", "待终审"), ("contested", "存疑或排除"))}}
    checks["sections"] = sections[doc["view"]] <= set(headings)
    if doc["view"] in {"vulnerabilities", "accepted"}:
        checks["detail_anchors"] = {number.lower() for number in numbers.values()} <= set(anchors)
    if doc["view"] == "accepted":
        checks["accepted_scope"] = all(e.get("final_disposition") == "accepted" for e in entries)
    return {"schema_version": "render-quality/v1", "view": doc["view"], "counts": doc["counts"], "checks": checks,
            "passed": all(checks.values()), "failed_checks": [key for key, passed in checks.items() if not passed]}
