"""Recomputable publish gates for the final report.

Three layers, as in the plan:

1. structure and version -- IDs unique, record-to-canonical mapping closed, every
   unresolved item has an owner, counts recomputable from the canonical list;
2. evidence and statistics -- excerpts resolve against the snapshot, verification and
   review references point at exact versions, ratings carry host provenance, and the
   rendered summary agrees with the facts;
3. interpretation quality -- conflicts and suspected duplicates are disclosed, an
   accepted claim has its confirmed review, and the narrative cannot claim more than the
   facts support.

The result is one of ``releasable_final``, ``releasable_partial`` or
``review_required``.  A failed structural/evidence/interpretation check is never
softened into "partial": partial means the report is honest but incomplete, not that the
host ignored a defect.
"""
from __future__ import annotations

import re

from .report_final import SECTION_TITLES

QUALITY_VERSION = "report-quality/v1"
RELEASABLE_FINAL = "releasable_final"
RELEASABLE_PARTIAL = "releasable_partial"
REVIEW_REQUIRED = "review_required"

FATAL = "fatal"
DEGRADED = "degraded"

COUNT_KEYS = (
    ("原始记录", "raw_records"),
    ("有效记录", "valid_records"),
    ("规范结论", "canonical"),
    ("已接受漏洞", "accepted"),
    ("待终审", "pending"),
    ("存疑或排除", "contested"),
)
_DICT_REPR = re.compile(r"\{'[^'\n]*'\s*:")
_NARRATIVE_COUNT = re.compile(r"(\d+)\s*(?:个|条)?\s*(?:已接受)?(?:漏洞|有效发现)")


class _Gate:
    def __init__(self) -> None:
        self.layers = {"structure": [], "evidence": [], "interpretation": []}
        self.failed_objects: list[dict] = []

    def check(self, layer: str, name: str, ok: bool, detail: str = "",
              severity: str = FATAL, objects: list[str] | None = None) -> None:
        self.layers[layer].append({
            "check": name, "ok": bool(ok), "severity": severity,
            "detail": detail, "objects": list(objects or [])[:20],
        })
        if not ok:
            for ref in (objects or [""])[:20]:
                self.failed_objects.append({"check": name, "severity": severity,
                                            "object": ref, "detail": detail})

    def failed(self) -> list[str]:
        return [item["check"] for layer in self.layers.values() for item in layer if not item["ok"]]

    def fatal_failed(self) -> bool:
        return any(item["severity"] == FATAL for layer in self.layers.values() for item in layer
                   if not item["ok"])

    def degraded_failed(self) -> bool:
        return any(item["severity"] == DEGRADED for layer in self.layers.values() for item in layer
                   if not item["ok"])


def _ids_unique(values: list[str]) -> tuple[bool, list[str]]:
    seen, duplicates = set(), []
    for value in values:
        if value in seen:
            duplicates.append(value)
        seen.add(value)
    return not duplicates, duplicates


def _structure(gate: _Gate, facts: dict) -> None:
    canonical = facts.get("canonical_findings") or []
    counts = facts.get("counts") or {}
    coverage = facts.get("coverage") or {}
    attempts = facts.get("verification_attempts") or []
    reviews = facts.get("reviews") or []
    records = (facts.get("appendix") or {}).get("records") or []

    gate.check("structure", "schema_version", facts.get("schema_version") == "final-review/v1",
               f"schema={facts.get('schema_version')}")
    provenance = facts.get("provenance") or {}
    for key in ("run_id", "snapshot_id", "source_hash", "input_hash", "renderer_version", "template_hash"):
        gate.check("structure", f"provenance_{key}", bool(provenance.get(key)),
                   f"{key} 缺失", objects=[provenance.get("run_id") or ""])

    ok, duplicates = _ids_unique([str(item["canonical_id"]) for item in canonical])
    gate.check("structure", "canonical_ids_unique", ok, f"重复：{duplicates}", objects=duplicates)
    evidence_ids = [item["evidence_id"] for item in facts.get("source_evidence") or []]
    ok, duplicates = _ids_unique(evidence_ids)
    gate.check("structure", "evidence_ids_unique", ok, f"重复：{duplicates}", objects=duplicates)
    ok, duplicates = _ids_unique([str(item.get("verification_id")) for item in attempts])
    gate.check("structure", "verification_ids_unique", ok, f"重复：{duplicates}", objects=duplicates)
    ok, duplicates = _ids_unique([str(item.get("review_id")) for item in reviews])
    gate.check("structure", "review_ids_unique", ok, f"重复：{duplicates}", objects=duplicates)

    mapping_errors = []
    for entry in canonical:
        refs = entry.get("source_record_refs") or []
        ids = [item["finding_id"] for item in refs]
        current = entry["current_claim_ref"]["finding_id"]
        if ids.count(current) != 1 or sum(1 for item in refs if item.get("current")) != 1:
            mapping_errors.append(entry["canonical_id"])
    gate.check("structure", "record_mapping_closed", not mapping_errors,
               "每条规范结论必须恰有一个当前记录", objects=mapping_errors)
    mapped = sum(len(item.get("source_record_refs") or []) for item in canonical)
    gate.check("structure", "valid_records_mapped", mapped == int(counts.get("valid_records") or 0),
               f"映射 {mapped} 条，有效记录 {counts.get('valid_records')} 条",
               objects=[item["canonical_id"] for item in canonical[:1]])
    by_finding = {item["finding_id"]: item["canonical_id"] for item in records}
    missing_owner = [item["finding_id"] for item in records
                     if item.get("validation_state") == "candidate"
                     and not item.get("disposition") in {"retracted", "duplicate", "superseded"}
                     and not by_finding.get(item["finding_id"])]
    gate.check("structure", "appendix_owner_complete", not missing_owner,
               "附录记录缺少规范归属", objects=missing_owner)

    dispositions = [item["final_disposition"] for item in canonical]
    gate.check("structure", "counts_recomputable",
               int(counts.get("canonical") or 0) == len(canonical)
               and int(counts.get("accepted") or 0) == dispositions.count("accepted")
               and int(counts.get("pending") or 0) == dispositions.count("pending")
               and int(counts.get("contested") or 0) == dispositions.count("contested")
               and int(counts.get("accepted") or 0) + int(counts.get("pending") or 0)
               + int(counts.get("contested") or 0) == len(canonical),
               "数量无法从规范清单复算")
    final_counts = coverage.get("final_review") or {}
    gate.check("structure", "coverage_counts_agree",
               final_counts.get("accepted") == counts.get("accepted")
               and final_counts.get("pending") == counts.get("pending")
               and final_counts.get("contested") == counts.get("contested"),
               "覆盖节与汇总节数量不一致")
    gate.check("structure", "verification_denominator",
               int((coverage.get("verification") or {}).get("total") or 0) == len(canonical),
               "验证分母与规范结论数不一致")

    batch = facts.get("review_batch") or {}
    batch_ids = [item["item_id"] for item in batch.get("item_refs") or []]
    gate.check("structure", "review_batch_items_match",
               sorted(batch_ids) == sorted(str(item["canonical_id"]) for item in canonical),
               "批次项与规范结论集合不一致")
    decisions = batch.get("decisions") or []
    decided_ids = [item.get("item_id") for item in decisions]
    gate.check("structure", "review_batch_complete",
               "review_batches" not in facts or (
                   len(decided_ids) == len(set(decided_ids)) and set(decided_ids) == set(batch_ids)
                   and not batch.get("unresolved_items")),
               "尚有未逐项提交终审处置的结论，报告保持阶段性", severity=DEGRADED)
    ok, duplicates = _ids_unique(batch_ids)
    gate.check("structure", "review_batch_ids_unique", ok, f"重复：{duplicates}", objects=duplicates)

    attempt_ids = {str(item.get("verification_id")) for item in attempts}
    review_refs = []
    for review in reviews:
        ref = review.get("finding_ref") or {}
        matched = [item for item in records
                   if item["finding_id"] == ref.get("finding_id")
                   and int(item.get("revision") or 0) == int(ref.get("revision") or 0)]
        if not matched:
            review_refs.append(str(review.get("review_id")))
        verification_id = str(review.get("verification_id") or "")
        if verification_id and verification_id not in attempt_ids:
            review_refs.append(str(review.get("review_id")))
    gate.check("structure", "review_refs_current", not review_refs,
               "复核引用未指向当前记录版本或已有验证", objects=review_refs)

    action_items = facts.get("action_items") or []
    canonical_ids = {str(item["canonical_id"]) for item in canonical}
    orphan = [str(item.get("object")) for item in action_items
              if item.get("object") and str(item["object"]) not in canonical_ids]
    gate.check("structure", "action_items_sourced", not orphan,
               "补证动作引用了不存在的规范结论", objects=orphan)
    open_ids = {str(item["canonical_id"]) for item in canonical
                if item["final_disposition"] != "accepted"}
    covered = {str(item.get("object")) for item in action_items if item.get("kind") == "complete_claim"}
    gate.check("structure", "open_items_have_action", open_ids <= covered,
               "存在未接受但没有补证动作的结论", objects=sorted(open_ids - covered))


def _evidence(gate: _Gate, facts: dict) -> None:
    canonical = facts.get("canonical_findings") or []
    entries = {item["evidence_id"]: item for item in facts.get("source_evidence") or []}
    refs = [(entry["canonical_id"], ref) for entry in canonical
            for ref in entry["frozen_claim"]["evidence"]]
    missing = [f"{owner}:{ref['evidence_id']}" for owner, ref in refs
               if ref["evidence_id"] not in entries]
    gate.check("evidence", "evidence_entries_present", not missing,
               "证据引用没有对应的宿主观测条目", objects=missing)
    unavailable = [f"{owner}:{ref['evidence_id']}" for owner, ref in refs
                   if ref["evidence_id"] in entries and not entries[ref["evidence_id"]].get("available")]
    gate.check("evidence", "source_excerpts_readable", not unavailable,
               "源码片段未能在快照中读取；正文标注为不可用，报告降级为阶段报告",
               severity=DEGRADED, objects=unavailable)
    empty_excerpt = [ref["evidence_id"] for ref in entries.values()
                     if ref.get("available") and not ref.get("excerpt")]
    gate.check("evidence", "source_excerpts_nonempty", not empty_excerpt,
               "读取成功但片段为空", objects=empty_excerpt)
    no_evidence = [entry["canonical_id"] for entry in canonical
                   if not entry["frozen_claim"]["evidence"]]
    gate.check("evidence", "claims_have_evidence", not no_evidence,
               "结论没有原始源码证据引用", objects=no_evidence)

    attempts = {str(item.get("verification_id")): item for item in facts.get("verification_attempts") or []}
    ref_errors = []
    for entry in canonical:
        claim = entry["frozen_claim"]
        verification_id = str(claim.get("verification_id") or "")
        if verification_id and verification_id not in attempts:
            ref_errors.append(entry["canonical_id"])
            continue
        if not verification_id:
            continue
        attempt = attempts[verification_id]
        if int((attempt.get("finding_ref") or {}).get("revision") or 0) != int(claim["revision"]):
            ref_errors.append(entry["canonical_id"])
    gate.check("evidence", "claim_verification_refs", not ref_errors,
               "结论引用的验证记录缺失或版本不符", objects=ref_errors)

    accepted_gaps = []
    for entry in canonical:
        if entry["final_disposition"] != "accepted":
            continue
        if entry.get("acceptance_basis") == "static_review" and entry.get("final_batch_review"):
            continue
        claim = entry["frozen_claim"]
        attempt = attempts.get(str(claim.get("verification_id") or ""))
        # POC records carry the schema verdict (confirmed/rejected/uncertain); a few
        # older rows used the execution word "verified" for the same claim.
        if attempt is None or attempt.get("verdict") not in {"confirmed", "verified"} \
                or attempt.get("execution_status") not in {"success"} \
                or not attempt.get("normal_evidence") or not attempt.get("attack_evidence") \
                or not attempt.get("job_refs"):
            accepted_gaps.append(entry["canonical_id"])
    gate.check("evidence", "accepted_have_full_verification", not accepted_gaps,
               "已接受结论缺少正常侧、攻击侧证据或作业记录", objects=accepted_gaps)

    rating_gaps = []
    for entry in canonical:
        claim = entry["frozen_claim"]
        assessment = entry.get("frozen_cvss_assessment") or {}
        if claim.get("cvss") and not assessment.get("engine_version"):
            rating_gaps.append(entry["canonical_id"])
        if claim.get("cvss") and not str(claim.get("rating_text") or "").strip():
            rating_gaps.append(entry["canonical_id"])
    gate.check("evidence", "ratings_carry_host_provenance", not rating_gaps,
               "评分缺少宿主引擎来源或文本", objects=rating_gaps)


def _rendered_counts(markdown: str) -> dict[str, int]:
    found: dict[str, int] = {}
    for label, key in COUNT_KEYS:
        match = re.search(rf"^- {re.escape(label)}：\s*(\d+)\s*$", markdown, re.MULTILINE)
        if match:
            found[key] = int(match.group(1))
    return found


def _interpretation(gate: _Gate, facts: dict, markdown: str | None) -> None:
    canonical = facts.get("canonical_findings") or []
    counts = facts.get("counts") or {}

    conflict_errors = [entry["canonical_id"] for entry in canonical
                       if entry.get("conflicts") and entry["final_disposition"] != "contested"]
    gate.check("interpretation", "conflicts_disclosed", not conflict_errors,
               "存在冲突但仍被当成确定结论", objects=conflict_errors)

    reviews = facts.get("reviews") or []
    accepted_errors = []
    for entry in canonical:
        if entry["final_disposition"] != "accepted":
            continue
        if entry.get("acceptance_basis") == "static_review" and entry.get("final_batch_review"):
            continue
        claim = entry["frozen_claim"]
        matched = [review for review in reviews
                   if (review.get("finding_ref") or {}).get("finding_id") == claim["finding_id"]
                   and int((review.get("finding_ref") or {}).get("revision") or 0) == int(claim["revision"])
                   and str(review.get("verification_id") or "") == str(claim.get("verification_id") or "")
                   and review.get("decision") == "confirmed"]
        if not matched:
            accepted_errors.append(entry["canonical_id"])
    gate.check("interpretation", "accepted_have_confirmed_review", not accepted_errors,
               "已接受结论缺少同版本正式复核确认", objects=accepted_errors)

    duplicate_gaps = []
    pairs = {tuple(pair.get("canonical_ids") or [])
             for pair in (facts.get("appendix") or {}).get("duplicate_pairs") or []
             if len(pair.get("canonical_ids") or []) == 2}
    acted = {tuple(sorted((item.get("object"), item.get("other"))))
             for item in facts.get("action_items") or [] if item.get("kind") == "merge_review"}
    for entry in canonical:
        for suggestion in entry.get("merge_suggestions") or []:
            pair = tuple(sorted((entry["canonical_id"], suggestion["other_canonical_id"])))
            if pair not in pairs or pair not in acted:
                duplicate_gaps.append(entry["canonical_id"])
    gate.check("interpretation", "duplicates_disclosed", not duplicate_gaps,
               "疑似重复未同时出现在附录与补证动作中", objects=sorted(set(duplicate_gaps)))

    narrative = facts.get("narrative") or {}
    overclaims = []
    for key, value in narrative.items():
        text = value if isinstance(value, str) else "\n".join(str(item) for item in value if item)
        for match in _NARRATIVE_COUNT.finditer(text):
            if int(match.group(1)) > int(counts.get("accepted") or 0):
                overclaims.append(f"narrative.{key}:{match.group(0)}")
    gate.check("interpretation", "narrative_within_facts", not overclaims,
               "叙述声称的数量超过已接受漏洞数", objects=overclaims)

    if markdown is not None:
        rendered = _rendered_counts(markdown)
        missing = [key for _, key in COUNT_KEYS if key not in rendered]
        gate.check("interpretation", "rendered_counts_present", not missing,
                   "正文缺少可复算的数量行", objects=missing)
        mismatch = [key for key, value in rendered.items() if int(counts.get(key) or 0) != value]
        gate.check("interpretation", "rendered_counts_match_facts", not mismatch,
                   "正文数量与事实包不一致", objects=mismatch)
        gate.check("interpretation", "no_dict_repr", not _DICT_REPR.search(markdown),
                   "正文出现 Python 字典 repr")
        missing_sections = [title for title in SECTION_TITLES if f"## {title}" not in markdown]
        gate.check("interpretation", "required_sections_present", not missing_sections,
                   "缺少必要章节", objects=missing_sections)
        unavailable = [item["evidence_id"] for item in facts.get("source_evidence") or []
                       if not item.get("available")]
        gate.check("interpretation", "unavailable_excerpts_labelled",
                   not unavailable or "源码片段不可用" in markdown,
                   "不可用片段没有在正文说明", objects=unavailable)
    else:
        for name in ("rendered_counts_present", "rendered_counts_match_facts",
                     "no_dict_repr", "required_sections_present", "unavailable_excerpts_labelled"):
            gate.check("interpretation", name, True, "未渲染，跳过正文检查", severity=DEGRADED)


def evaluate(facts: dict, markdown: str | None = None) -> dict:
    """Recompute every gate from the fact package (and the rendered text when given)."""
    gate = _Gate()
    _structure(gate, facts)
    _evidence(gate, facts)
    _interpretation(gate, facts, markdown)

    outcome = facts.get("run_outcome") or {}
    counts = facts.get("counts") or {}
    complete = bool(outcome.get("audit_complete")) and not counts.get("pending") and not counts.get("contested")
    if gate.fatal_failed():
        publishability = REVIEW_REQUIRED
    elif complete and not gate.degraded_failed():
        publishability = RELEASABLE_FINAL
    else:
        publishability = RELEASABLE_PARTIAL
    return {
        "version": QUALITY_VERSION,
        "report_kind": "final" if complete else "stage",
        "publishability": publishability,
        "layers": gate.layers,
        "failed_checks": gate.failed(),
        "failed_objects": gate.failed_objects,
        "statistics": {
            "raw_records": counts.get("raw_records"),
            "valid_records": counts.get("valid_records"),
            "canonical": counts.get("canonical"),
            "accepted": counts.get("accepted"),
            "pending": counts.get("pending"),
            "contested": counts.get("contested"),
            "withdrawn": counts.get("withdrawn"),
            "observations": len(facts.get("observations") or []),
            "verification_attempts": len(facts.get("verification_attempts") or []),
            "reviews": len(facts.get("reviews") or []),
            "source_evidence": len(facts.get("source_evidence") or []),
            "action_items": len(facts.get("action_items") or []),
        },
        "recomputed": {
            "canonical": len(facts.get("canonical_findings") or []),
            "dispositions": {
                value: sum(1 for item in facts.get("canonical_findings") or []
                           if item["final_disposition"] == value)
                for value in ("accepted", "pending", "contested")
            },
        },
    }
