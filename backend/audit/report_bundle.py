"""Assemble the versioned final-review fact package (``FinalReviewBundle/v1``).

The report is rendered from this package alone.  Assembly is deterministic given the
run's frozen rows: the same database state produces the same ``input_hash`` and the same
document, and no rendering step consults a mutable ledger for a historical claim.

Source excerpts are read here, server-side, from the immutable snapshot.  A range that
cannot be read is recorded as unavailable with its reason; model-submitted code snippets
are never promoted to source evidence.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from . import final_review
from .finding_policy import is_vulnerability_finding
from .report_final import RENDERER_VERSION, SECTION_TITLES

SCHEMA_VERSION = "final-review/v1"
MAX_SNIPPET_LINES = 40
MAX_SOURCE_EVIDENCE = 400


def _template_hash() -> str:
    return hashlib.sha256("\n".join((RENDERER_VERSION, *SECTION_TITLES)).encode("utf-8")).hexdigest()[:16]


def _counts(all_records: list[dict], canonical: list[dict], valid: list[dict]) -> dict:
    def count(value: str) -> int:
        return sum(1 for item in canonical if item["final_disposition"] == value)

    return {
        "raw_records": len(all_records),
        "valid_records": len(valid),
        "canonical": len(canonical),
        "withdrawn": sum(1 for item in all_records if final_review.withdrawn(item)),
        "accepted": count(final_review.ACCEPTED),
        "pending": count(final_review.PENDING),
        "contested": count(final_review.CONTESTED),
    }


def _verification_counts(execution: dict, canonical: list[dict]) -> dict:
    summary = execution.get("verification") or {}
    if isinstance(summary, dict) and "total" in summary:
        return {
            "total": int(summary.get("total") or 0),
            "verified": int(summary.get("verified") or 0),
            "pending": int(summary.get("pending") or 0),
            "reviewed": int(summary.get("reviewed") or 0),
            "pending_review": int(summary.get("pending_review") or 0),
        }
    # A run row without execution state still reports the claims' own statuses rather
    # than zeros that would look like "everything checked".
    statuses = [entry["frozen_claim"]["verification_status"] for entry in canonical]
    return {
        "total": len(canonical),
        "verified": sum(1 for item in statuses if item == "verified"),
        "pending": sum(1 for item in statuses if item in {"", "unverified", "stale"}),
        "reviewed": 0,
        "pending_review": 0,
    }


def _coverage(execution: dict, canonical: list[dict], project_map: dict | None) -> dict:
    files = execution.get("coverage_review") or {}
    if files:
        total = int(files.get("total") or 0)
        read = len(files.get("read_paths") or [])
        reviewed = len(files.get("reviewed_paths") or [])
        skipped = len(files.get("skips") or [])
        pending = int(files.get("pending_total") or 0)
        complete = files.get("complete")
        skip_details = [
            {"path": item.get("path") or "", "reason": item.get("reason") or ""}
            for item in files.get("skips") or [] if isinstance(item, dict)
        ]
    else:
        # A fixed-workflow run has no coverage-review policy; its scope is still known
        # from the frozen project map, but "reviewed" is not claimed.
        total = len((project_map or {}).get("files") or [])
        read = reviewed = skipped = 0
        pending = None
        complete = None
        skip_details = []
    directions = execution.get("directions") or {}
    return {
        "files": {"total": total, "read": read, "reviewed": reviewed, "skipped": skipped,
                  "pending": pending, "complete": complete, "skip_details": skip_details},
        "directions": {
            "total": int(directions.get("total") or 0),
            "resolved": int(directions.get("resolved_total") or 0),
            "skipped": int(directions.get("skipped_total") or 0),
            "unsettled": int(directions.get("unsettled_total") or 0),
            "complete": directions.get("complete"),
            "required": int(directions.get("required_total", directions.get("total")) or 0),
            "advisory": int(directions.get("advisory_total") or 0),
        },
        "verification": _verification_counts(execution, canonical),
        "final_review": {
            "accepted": sum(1 for item in canonical if item["final_disposition"] == final_review.ACCEPTED),
            "pending": sum(1 for item in canonical if item["final_disposition"] == final_review.PENDING),
            "contested": sum(1 for item in canonical if item["final_disposition"] == final_review.CONTESTED),
        },
    }


def _provenance(run: dict, snapshot: dict, facts: dict) -> dict:
    execution = run.get("execution_summary") or {}
    frozen = json.dumps(
        {
            "run": run.get("id"),
            "status": run.get("status"),
            "snapshot": run.get("snapshot_id"),
            "canonical": [
                (item["canonical_id"], item["final_disposition"],
                 item["current_claim_ref"]["finding_id"], item["current_claim_ref"]["revision"],
                 item["current_claim_ref"]["project_revision"], item["assessment_revision"])
                for item in facts["canonical_findings"]
            ],
            "reviews": [(item["review_id"], item["decision"]) for item in facts["reviews"]],
        },
        ensure_ascii=False, sort_keys=True,
    )
    profile = run.get("model_profile") or {}
    return {
        "run_id": run.get("id") or "",
        "project_id": run.get("project_id") or "",
        "snapshot_id": run.get("snapshot_id") or "",
        "source_hash": snapshot.get("archive_sha256") or "",
        "schema_version": SCHEMA_VERSION,
        "policy_version": execution.get("policy_version") or "",
        "renderer_version": RENDERER_VERSION,
        "template_hash": _template_hash(),
        "frozen_at": run.get("finished_at") or run.get("created_at") or "",
        "generated_at": facts.get("generated_at") or "",
        "input_hash": hashlib.sha256(frozen.encode("utf-8")).hexdigest(),
        "model": profile.get("model") or run.get("model") or "",
        "model_profile_id": profile.get("id") or "",
        "continuation": {key: (run.get('task_spec') or {}).get('continuation', {}).get(key)
                         for key in ('parent_run_id', 'root_run_id', 'mode', 'parent_usage')}
                        if (run.get('task_spec') or {}).get('continuation') else None,
    }


def _run_outcome(run: dict, coverage: dict) -> dict:
    execution = run.get("execution_summary") or {}
    verification_pending = int(coverage["verification"]["pending"] or 0)
    return {
        "status": run.get("status") or "",
        "stop_reason": execution.get("stop_reason") or ({"code": run.get("error")} if run.get("error") else None),
        "coverage_complete": coverage["files"]["complete"],
        "directions_complete": coverage["directions"]["complete"],
        "verification_complete": verification_pending == 0,
        "audit_complete": bool(
            run.get("status") == "completed"
            and coverage["files"]["complete"]
            and coverage["directions"]["complete"]
            and verification_pending == 0
            and coverage["final_review"]["pending"] == 0
        ),
    }


def _narrative(bundle: dict) -> dict:
    value = bundle.get("report_narrative") or {}
    if not isinstance(value, dict):
        return {}
    return {key: item for key, item in value.items() if isinstance(item, (str, list))}


def _appendix(bundle: dict, all_records: list[dict], canonical: list[dict], facts: dict) -> dict:
    owner = {}
    for entry in canonical:
        for record in entry["source_record_refs"]:
            owner[record["finding_id"]] = entry["canonical_id"]
    records = [
        {
            "finding_id": item["id"],
            "canonical_id": owner.get(item["id"], ""),
            "revision": int(item.get("revision") or 1),
            "project_revision": int(item.get("project_revision") or 0),
            "title": item.get("title") or "",
            "validation_state": item.get("validation_state") or "",
            "disposition": item.get("disposition") or "open",
            "verification_status": item.get("verification_status") or "",
            "verification_verdict": item.get("verification_verdict") or "",
            "created_at": item.get("created_at") or "",
        }
        for item in all_records if is_vulnerability_finding(item)
    ]
    pairs, seen = [], set()
    for entry in canonical:
        for suggestion in entry["merge_suggestions"]:
            pair = tuple(sorted((entry["canonical_id"], suggestion["other_canonical_id"])))
            if pair in seen:
                continue
            seen.add(pair)
            pairs.append({"canonical_ids": list(pair), "basis": suggestion["basis"],
                          "action": suggestion["action"]})
    comparison_pairs, compared = [], set()
    by_id = {entry["canonical_id"]: entry for entry in canonical}
    for entry in canonical:
        for peer in entry.get("comparison_candidates", []):
            pair = tuple(sorted((entry["canonical_id"], peer["item_id"])))
            if pair in compared:
                continue
            compared.add(pair)
            left = entry.get("final_batch_review") or {}
            right = by_id[peer["item_id"]].get("final_batch_review") or {}
            distinct = (peer["item_id"] in (left.get("distinct_from") or [])
                        or entry["canonical_id"] in (right.get("distinct_from") or []))
            comparison_pairs.append({"canonical_ids": list(pair), "basis": peer["basis"],
                                     "status": "distinct" if distinct else "pending",
                                     "rationale": left.get("rationale") if distinct and peer["item_id"] in (left.get("distinct_from") or [])
                                                  else right.get("rationale") if distinct else "尚未明确判读是否具有不同根因。"})
    execution = (bundle.get("run") or {}).get("execution_summary") or {}
    tasks = [
        {"id": task.get("id"), "title": task.get("title"), "state": task.get("state"),
         "error": task.get("error") or ""}
        for task in (bundle.get("tasks") or [])[:300]
    ]
    return {
        "records": records,
        "duplicate_pairs": pairs,
        "comparison_pairs": comparison_pairs,
        "withdrawn": [item for item in records
                      if item["disposition"] in {"retracted", "duplicate", "superseded"}],
        "tasks": tasks,
        "usage": {
            "run_limits": execution.get("run_limits"),
            "run_usage": execution.get("run_usage"),
            "run_remaining": execution.get("run_remaining"),
            "context": execution.get("context") or {},
            "poc": execution.get("poc") or {},
            "workflow": execution.get("workflow") or {},
        },
        "artifacts": {
            "json": "result.json（含本事实包与质量结果）",
            "evidence_dir": "evidence/（POC 脚本、runner 产物、runner manifest）",
            "source": "源码片段由宿主从冻结快照读取，见 source_evidence",
        },
    }


def _limitations(facts: dict) -> list[str]:
    items = ["受阻、未执行、未读取的方向均不代表安全。"]
    if not facts["run_outcome"]["audit_complete"]:
        items.append("本次运行未同时满足完成状态、覆盖闭环与验证闭环，本报告为阶段报告。")
    counts = facts["counts"]
    if counts["pending"]:
        items.append(f"仍有 {counts['pending']} 条规范结论未获得正式确认，不计入已接受漏洞。")
    if counts["contested"]:
        items.append(f"仍有 {counts['contested']} 条规范结论存在冲突、反证或复核存疑，不计入已接受漏洞。")
    if any(entry["merge_suggestions"] for entry in facts["canonical_findings"]):
        items.append("跨台账存在疑似重复；报告只给出归并建议，未自动合并，来源记录全部保留。")
    missing = sum(1 for item in facts.get("source_evidence") or [] if not item.get("available"))
    if missing:
        items.append(f"{missing} 处源码引用未能在快照中读取或无可用片段，正文标注为不可用。")
    if facts["coverage"]["directions"]["unsettled"]:
        items.append(f"{facts['coverage']['directions']['unsettled']} 个审计方向尚未结算。")
    return items


def _action_items(facts: dict) -> list[dict]:
    items: list[dict] = []
    for entry in facts["canonical_findings"]:
        claim = entry["frozen_claim"]
        if entry["final_disposition"] == final_review.ACCEPTED:
            continue
        if entry["conflicts"]:
            items.append({"kind": "resolve_conflict", "object": entry["canonical_id"],
                          "title": claim["title"],
                          "action": "裁定当前主结论：保留有依据的一份，或明确标为存疑。"})
            continue
        status = claim["verification_status"]
        if status == "verified":
            action = ("对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id "
                      f"{claim['verification_id'] or '（空）'}。")
        elif status == "unverified":
            action = "完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。"
        else:
            action = f"处理动态验证结论 {status}：补证、重试或撤回，并保留原记录。"
        items.append({"kind": "complete_claim", "object": entry["canonical_id"],
                      "title": claim["title"], "action": action})
    seen: set[tuple[str, str]] = set()
    for entry in facts["canonical_findings"]:
        for suggestion in entry["merge_suggestions"]:
            pair = tuple(sorted((entry["canonical_id"], suggestion["other_canonical_id"])))
            if pair in seen:
                continue
            seen.add(pair)
            items.append({"kind": "merge_review", "object": pair[0], "other": pair[1],
                          "action": "确认这两条台账是否同一根因；归并需给出依据，不能仅按文件或类型合并。"})
    directions = facts["coverage"]["directions"]
    if directions["unsettled"]:
        items.append({"kind": "unsettled_directions", "count": directions["unsettled"],
                      "action": "逐个结算未决方向：读取、给出证据或明确 skip 理由。"})
    files = facts["coverage"]["files"]
    if files["pending"]:
        items.append({"kind": "unread_files", "count": files["pending"],
                      "action": "读取或带理由复核未覆盖文件。"})
    review = facts["coverage"]["verification"]
    if review["pending_review"]:
        items.append({"kind": "pending_reviews", "count": review["pending_review"],
                      "action": "对已验证结论完成正式复核；verified 不能替代终审。"})
    return items


def _evidence_stats(canonical: list[dict]) -> dict:
    total = sum(len(entry["frozen_claim"]["evidence"]) for entry in canonical)
    without = sum(1 for entry in canonical if not entry["frozen_claim"]["evidence"])
    return {"refs": total, "claims_without_evidence": without}


def build_final_review(
    bundle: dict,
    *,
    all_records: list[dict] | None = None,
    repository: Any | None = None,
    generated_at: str = "",
) -> dict:
    """Assemble the delivery facts from one run bundle. Pure apart from snapshot reads."""
    run = bundle.get("run") or {}
    findings = bundle.get("findings") or []
    all_records = list(all_records if all_records is not None else findings)
    # A finding row carries its evidence paths but not the run's snapshot id; the
    # snapshot is a frozen property of the run.  Copy rather than mutate the bundle so
    # every source citation can be resolved against the immutable archive.
    snapshot_id = str(run.get("snapshot_id") or "")
    if snapshot_id:
        all_records = [
            record if record.get("snapshot_id") else {**record, "snapshot_id": snapshot_id}
            for record in all_records
        ]
    execution = run.get("execution_summary") or {}

    canonical, valid = final_review.canonical_groups(all_records)
    final_review.merge_suggestions(canonical)
    coverage = _coverage(execution, canonical, bundle.get("project_map"))
    facts: dict = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "canonical_findings": canonical,
        "observations": final_review.observations(all_records),
        "verification_attempts": final_review.verification_attempts(all_records),
        "reviews": final_review.reviews(all_records),
        "coverage": coverage,
        "counts": _counts(all_records, canonical, valid),
        "narrative": _narrative(bundle),
        "review_batch": final_review.build_review_batch(
            str(run.get("id") or ""), execution.get("claim_epoch"), {"canonical_findings": canonical}
        ),
    }
    if bundle.get("review_snapshot") is not None:
        facts["review_batches"] = bundle["review_snapshot"]
        batch = facts["review_batch"]
        batch["version"] = "review-batches-v1"
        batch["decisions"] = [
            {**entry["final_batch_review"], "item_id": entry["canonical_id"],
             "finding_revision": entry["current_claim_ref"]["revision"]}
            for entry in canonical if entry.get("final_batch_review")
        ]
        decided = {item["item_id"] for item in batch["decisions"]}
        batch["unresolved_items"] = [item["item_id"] for item in batch["item_refs"] if item["item_id"] not in decided]
    facts["run_outcome"] = _run_outcome(run, coverage)
    facts["advisory_directions"] = [
        {key: direction.get(key) for key in ("id", "text", "paths", "state", "origin_task_key")}
        for task in bundle.get("tasks") or []
        for direction in (task.get("result") or {}).get("host_directions") or []
        if direction.get("requirement") == "advisory"
    ]
    facts["evidence_stats"] = _evidence_stats(canonical)
    facts["provenance"] = _provenance(run, bundle.get("snapshot") or {}, facts)
    if bundle.get("frozen_input_hash"):
        facts["provenance"]["input_hash"] = bundle["frozen_input_hash"]
        facts["provenance"]["immutable"] = True
    facts["appendix"] = _appendix(bundle, all_records, canonical, facts)
    facts["action_items"] = _action_items(facts)
    facts["source_evidence"] = bundle.get("frozen_source_evidence") or []
    if "frozen_source_evidence" not in bundle and repository is not None:
        attach_source_evidence(facts, repository)
    facts["limitations"] = _limitations(facts) + list(bundle.get("freeze_limitations") or [])
    from . import report_quality

    facts["quality_result"] = report_quality.evaluate(facts)
    return facts


def attach_source_evidence(facts: dict, repository: Any, *, limit: int = MAX_SOURCE_EVIDENCE) -> dict:
    """Add server-read excerpts for every cited evidence range.

    Excerpts come from the immutable snapshot through the repository's integrity-checked
    reader.  Every citation gets an entry so the evidence layer can be checked against
    the same reference set the claims use; over the export budget an entry is still
    present but explicitly marked unread instead of silently disappearing.
    """
    entries: dict[str, dict] = {}
    for entry in facts.get("canonical_findings") or []:
        for ref in entry["frozen_claim"]["evidence"]:
            if ref["evidence_id"] in entries:
                continue
            fact = {
                "evidence_id": ref["evidence_id"],
                "snapshot_id": ref["snapshot_id"],
                "path": ref["path"],
                "range": ref["range"],
                "content_hash": "",
                "read_proof": None,
                "excerpt": [],
                "available": False,
                "reason": "",
            }
            if len(entries) >= limit:
                fact["reason"] = f"本次导出证据条目超过上限（{limit}），未读取"
                entries[ref["evidence_id"]] = fact
                continue
            try:
                end = min(ref["range"]["end"], ref["range"]["start"] + MAX_SNIPPET_LINES - 1)
                read = repository.read_source(
                    ref["snapshot_id"], ref["path"], ref["range"]["start"], end
                )
                fact["excerpt"] = read.get("lines") or []
                fact["available"] = True
                fact["content_hash"] = read.get("sha256") or ""
                fact["truncated"] = end < ref["range"]["end"]
                fact["read_proof"] = {
                    "source": "snapshot",
                    "snapshot_id": ref["snapshot_id"],
                    "file_sha256": read.get("sha256") or "",
                    "from_line": read.get("start_line"),
                    "to_line": read.get("end_line"),
                    "lines": len(fact["excerpt"]),
                }
            except Exception as exc:  # noqa: BLE001 - an unreadable excerpt is a reported gap
                fact["reason"] = f"{type(exc).__name__}: {exc}"
            entries[ref["evidence_id"]] = fact
    facts["source_evidence"] = list(entries.values())
    return facts


def build_and_render(
    bundle: dict,
    *,
    all_records: list[dict] | None = None,
    repository: Any | None = None,
    generated_at: str = "",
) -> tuple[dict, str]:
    """Assemble facts, evaluate the publish gates against the rendered text, and return both.

    Layer-3 checks read the rendered document (it must not leak a dict repr, drop a
    required section, or claim more than the facts support).  The second render carries
    the final publishability line.
    """
    from .report_final import render_final_report
    from . import report_quality

    facts = build_final_review(
        bundle, all_records=all_records, repository=repository, generated_at=generated_at
    )
    markdown = render_final_report(facts)
    facts["quality_result"] = report_quality.evaluate(facts, markdown=markdown)
    return facts, render_final_report(facts)
