"""Deterministic, answer-isolated Lab30 v2 scoring and paired trial statistics.

Only the evaluator reads truth/anchors. A TP requires both a compatible root
cause and an exact, archive-root-aware primary source coordinate. This module
does not contact a model, run a POC, or mutate an audit database.
"""
from __future__ import annotations

import hashlib
import json
import math
import statistics
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .cvss31 import BASE, assessment

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TRUTH_PATH = PROJECT_ROOT / "datasets/lab30-shop/ground_truth.json"
DEFAULT_ANCHORS_PATH = PROJECT_ROOT / "datasets/lab30-shop/scoring_anchors_v2.json"
PROTOCOL = "lab30-v2"


def _canonical_type(value: object) -> str:
    from .worker_strategies import canonical_vulnerability_type
    return canonical_vulnerability_type(value)


def _payload(value: Any) -> tuple[dict, bytes]:
    if isinstance(value, (str, Path)):
        raw = Path(value).read_bytes()
        return json.loads(raw), raw
    if not isinstance(value, dict):
        raise ValueError("数据必须为 JSON 对象或 JSON 文件路径")
    return value, json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def canonical_json_hash(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _path(value: object, archive_root: str = "") -> str | None:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return None
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in ("", "..", ".") for x in value.split("/")) or ":" in value:
        return None
    text = p.as_posix()
    root = archive_root.strip("/")
    if root and text.startswith(root + "/"):
        text = text[len(root) + 1:]
    return text


def _location(value: object, root: str) -> tuple[str, int] | None:
    if not isinstance(value, dict):
        return None
    path, line = _path(value.get("path"), root), value.get("line")
    if path is None or type(line) is not int or line < 1:
        return None
    return path, line


def _anchors(truth_payload: dict, anchors_payload: dict) -> tuple[list[dict], dict[str, dict], str]:
    if anchors_payload.get("protocol") != PROTOCOL:
        raise ValueError("评分锚点协议必须为 lab30-v2")
    truths = truth_payload.get("vulnerabilities")
    rows = anchors_payload.get("vulnerabilities", anchors_payload.get("entries"))
    if not isinstance(truths, list) or not truths or not isinstance(rows, list):
        raise ValueError("真值和评分锚点必须包含 vulnerabilities 数组")
    expected_truth_hash = anchors_payload.get("truth_canonical_sha256")
    if expected_truth_hash and canonical_json_hash(truth_payload) != expected_truth_hash:
        raise ValueError("真值内容 SHA-256 与评分锚点不一致")
    ids = [str(x.get("id", "")) for x in truths]
    if any(not x for x in ids) or len(set(ids)) != len(ids):
        raise ValueError("真值 ID 缺失或重复")
    mapping = {str(x.get("id", "")): x for x in rows}
    if len(mapping) != len(rows) or set(mapping) != set(ids):
        raise ValueError("评分锚点必须与真值 ID 一一对应")
    root = str(anchors_payload.get("archive_root", ""))
    for truth in truths:
        anchor = mapping[str(truth["id"])]
        if anchor.get("class") != truth.get("class"):
            raise ValueError(f"{truth['id']}: 锚点类别与真值不符")
        locations = anchor.get("scoring_locations")
        if not isinstance(locations, list) or not locations or any(_location(x, root) is None for x in locations):
            raise ValueError(f"{truth['id']}: 无效评分定位")
    return sorted(truths, key=lambda x: str(x["id"])), mapping, root


def validate_assets(source_zip: str | Path, truth: Any = DEFAULT_TRUTH_PATH,
                    anchors: Any = DEFAULT_ANCHORS_PATH) -> dict:
    """Verify frozen provenance and *every* v2 source line before paid execution.

    The canonical truth digest allows an already loaded JSON object without
    relying on whitespace. File SHA-256 is additionally checked when available.
    """
    truth_payload, truth_raw = _payload(truth)
    anchors_payload, anchors_raw = _payload(anchors)
    truths, mapping, root = _anchors(truth_payload, anchors_payload)
    source_digest = hashlib.sha256(Path(source_zip).read_bytes()).hexdigest()
    expected_source = anchors_payload.get("source_archive_sha256")
    provenance_source = (truth_payload.get("provenance") or {}).get("source_archive_sha256")
    if not expected_source or expected_source != source_digest or (provenance_source and provenance_source != source_digest):
        raise ValueError("源码 ZIP SHA-256 与冻结的真值/评分锚点不一致")
    expected_truth = anchors_payload.get("truth_canonical_sha256")
    if not expected_truth or canonical_json_hash(truth_payload) != expected_truth:
        raise ValueError("真值内容 SHA-256 与评分锚点不一致")
    if isinstance(truth, (str, Path)) and anchors_payload.get("truth_file_sha256") != hashlib.sha256(truth_raw).hexdigest():
        raise ValueError("真值文件 SHA-256 与评分锚点不一致")
    checked = 0
    with zipfile.ZipFile(source_zip) as archive:
        members = archive.namelist()
        if len(set(members)) != len(members):
            raise ValueError("源码 ZIP 包含重复路径")
        for row in mapping.values():
            for loc in row["scoring_locations"]:
                path, line = _location(loc, root)
                full = f"{root}/{path}" if root else path
                if full not in members:
                    raise ValueError(f"{row['id']}: 评分源码不存在 {full}")
                lines = archive.read(full).decode("utf-8").splitlines()
                if line > len(lines) or not lines[line - 1].strip():
                    raise ValueError(f"{row['id']}: 评分行不存在或为空 {full}:{line}")
                digest = hashlib.sha256(lines[line - 1].encode()).hexdigest()
                if not loc.get("line_sha256") or loc["line_sha256"] != digest:
                    raise ValueError(f"{row['id']}: 评分行摘要不符 {full}:{line}")
                if not loc.get("rationale"):
                    raise ValueError(f"{row['id']}: 评分锚点缺少核验依据")
                checked += 1
    return {"protocol": PROTOCOL, "truth_count": len(truths), "class_count": len({x["class"] for x in truths}),
            "source_archive_sha256": source_digest, "truth_sha256": hashlib.sha256(truth_raw).hexdigest(),
            "truth_canonical_sha256": canonical_json_hash(truth_payload),
            "anchors_sha256": hashlib.sha256(anchors_raw).hexdigest(), "checked_locations": checked}


def _ratio(numerator: float, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _rating(finding: dict, truth: dict) -> dict:
    reported, error = None, None
    try:
        reported = assessment(finding.get("cvss"))
    except ValueError as exc:
        error = str(exc)
    expected = assessment(truth.get("cvss"))
    label = finding.get("severity")
    label = {"严重": "critical", "极高": "critical", "高": "high", "中": "medium", "低": "low", "无": "none"}.get(label, label)
    if not label and reported:
        label = reported["severity"]
    status = ("missing_truth" if expected is None else "invalid_reported" if error else
              "missing_reported" if reported is None else "compared")
    delta = round(reported["base_score"] - expected["base_score"], 1) if status == "compared" else None
    vector_ok = (all(reported["metrics"][key] == expected["metrics"][key] for key in BASE)
                 if status == "compared" and reported["metrics"] and expected["metrics"] else None)
    return {"cvss_expected": expected, "cvss_reported": reported, "cvss_error": error,
            "cvss_status": status, "cvss_score_delta": delta,
            "cvss_score_error": abs(delta) if delta is not None else None,
            "cvss_score_ok": delta == 0 if delta is not None else None,
            "cvss_vector_ok": vector_ok, "severity_expected": expected["severity"] if expected else truth.get("severity"),
            "severity_reported": label,
            "severity_ok": label == expected["severity"] if expected and label is not None else None}


def evaluate_v2(truth_payload: dict, findings: list[dict], anchors_payload: dict) -> dict:
    truths, anchors, root = _anchors(truth_payload, anchors_payload)
    excluded = [x for x in findings if isinstance(x, dict)
                and x.get("validation_state") in {"invalid_evidence", "invalid_finding", "invalid"}]
    findings = [x for x in findings if isinstance(x, dict)
                and str(x.get("finding_kind", x.get("kind", "vulnerability"))).lower() == "vulnerability"
                and x.get("disposition", "open") not in {"retracted", "duplicate", "superseded"}
                and x.get("validation_state") not in {"invalid_evidence", "invalid_finding", "invalid"}]
    # IDs are final tie breakers. Rating, text confidence and original array order
    # never select a more flattering matched prediction.
    def key(f: dict) -> tuple:
        loc = _location(f.get("primary_location"), root)
        return (*(loc or ("", 0)), str(f.get("id", "")), canonical_json_hash(f))
    predictions = sorted(findings, key=key)
    coordinates = {str(t["id"]): {_location(loc, root) for loc in anchors[str(t["id"])]["scoring_locations"]} for t in truths}
    edges: dict[int, list[str]] = {}
    diagnostics = []
    for idx, finding in enumerate(predictions):
        loc = _location(finding.get("primary_location"), root)
        typ = _canonical_type(finding.get("vulnerability_type"))
        at_location = [t for t in truths if loc is not None and loc in coordinates[str(t["id"])]]
        edges[idx] = [str(t["id"]) for t in at_location if typ == anchors[str(t["id"])]["class"]]
        if not edges[idx]:
            diagnostics.append({"finding_id": finding.get("id"), "reason": "invalid_primary_location" if loc is None
                                else "type_mismatch" if at_location else "unmatched_location",
                                "vulnerability_type": typ, "primary_location": finding.get("primary_location"),
                                "location_truth_ids": [str(t["id"]) for t in at_location],
                                "expected_types": sorted({anchors[str(t["id"])]["class"] for t in at_location})})
    owner: dict[str, int] = {}
    def augment(idx: int, seen: set[str]) -> bool:
        for ident in edges[idx]:
            if ident in seen:
                continue
            seen.add(ident)
            if ident not in owner or augment(owner[ident], seen):
                owner[ident] = idx
                return True
        return False
    for idx in range(len(predictions)):
        augment(idx, set())
    matched_indices = set(owner.values())
    matches, truth_results = [], []
    for truth in truths:
        ident = str(truth["id"])
        finding = predictions[owner[ident]] if ident in owner else None
        locs = anchors[ident]["scoring_locations"]
        row = {"id": ident, "truth_id": ident, "title": truth.get("title", ident), "class": anchors[ident]["class"],
               "detected": finding is not None, "finding_id": finding.get("id") if finding else None,
               "scoring_locations": locs, "location": truth.get("location", []),
               "primary_location": finding.get("primary_location") if finding else None}
        if finding is not None:
            match = {"truth_id": ident, "truth": f"{ident} {truth.get('title', ident)}", "finding_id": finding.get("id"),
                     "finding": finding.get("title"), "class": anchors[ident]["class"],
                     "primary_location": finding.get("primary_location"), **_rating(finding, truth)}
            matches.append(match)
            row["rating"] = {k: v for k, v in match.items() if k.startswith(("cvss_", "severity_"))}
        truth_results.append(row)
    duplicate = [f for i, f in enumerate(predictions) if i not in matched_indices and edges[i]]
    unmatched = [f for i, f in enumerate(predictions) if i not in matched_indices and not edges[i]]
    tp, d, u, fn = len(matches), len(duplicate), len(unmatched), len(truths) - len(matches)
    compared = [m for m in matches if m["cvss_status"] == "compared"]
    vectors = [m for m in compared if m["cvss_vector_ok"] is not None]
    labels = [m for m in matches if m["severity_ok"] is not None]
    class_coverage = {}
    for row in truth_results:
        c = class_coverage.setdefault(row["class"], {"total": 0, "detected": 0, "missed": 0, "detected_ids": [], "missed_ids": []})
        c["total"] += 1
        c["detected" if row["detected"] else "missed"] += 1
        c["detected_ids" if row["detected"] else "missed_ids"].append(row["id"])
    return {"protocol": PROTOCOL, "scope": "all", "class_scope": None, "truths": len(truths), "findings": len(predictions),
            "rating_standard": "CVSS:3.1", "score_basis": "Base", "TP": tp, "D": d, "U": u, "FP": d + u, "FN": fn,
            "precision": _ratio(tp, tp + d + u), "recall": tp / len(truths),
            "f1": 2 * tp / (2 * tp + d + u + fn), "matches": matches, "truth_results": truth_results,
            "duplicates": duplicate, "unmatched": unmatched, "diagnostics": diagnostics,
            "excluded_invalid": [{"finding_id": x.get("id"), "validation_state": x.get("validation_state"),
                                  "validation_errors": x.get("validation_errors", [])} for x in excluded],
            "false_positives": [x.get("title") or x.get("id") for x in duplicate + unmatched],
            "missed": [f"{x['id']} {x['title']}" for x in truth_results if not x["detected"]],
            "missed_details": [x for x in truth_results if not x["detected"]], "class_coverage": class_coverage,
            "severity_evaluation": {"checked": True, "compared": len(labels), "correct": sum(x["severity_ok"] for x in labels),
                                    "accuracy": _ratio(sum(x["severity_ok"] for x in labels), len(labels))},
            "cvss_evaluation": {"checked": True, "compared": len(compared), "scoring_coverage": _ratio(len(compared), tp),
                                "missing_truth": sum(x["cvss_status"] == "missing_truth" for x in matches),
                                "missing_reported": sum(x["cvss_status"] == "missing_reported" for x in matches),
                                "invalid_reported": sum(x["cvss_status"] == "invalid_reported" for x in matches),
                                "score_mae": _ratio(sum(x["cvss_score_error"] for x in compared), len(compared)),
                                "score_accuracy": _ratio(sum(x["cvss_score_ok"] for x in compared), len(compared)),
                                "vector_compared": len(vectors), "vector_accuracy": _ratio(sum(x["cvss_vector_ok"] for x in vectors), len(vectors))}}


def _number(value: object) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def metric(values: list[Any]) -> dict:
    valid = [float(v) for v in values if _number(v)]
    return {"mean": statistics.mean(valid) if valid else None,
            "sample_std": statistics.stdev(valid) if len(valid) > 1 else None, "n": len(valid), "values": values}


def summarise_trials(variants: list[dict], trials: list[dict], repeats: int,
                     baseline_prompt_id: str, truth_payload: dict | None = None) -> dict:
    """All variants share one complete-round set; never select best attempts."""
    ids = [str(v["id"]) for v in variants]
    if baseline_prompt_id not in ids or len(set(ids)) != len(ids):
        raise ValueError("基线必须属于不重复的策略版本")
    # The caller supplies one effective attempt per logical trial. Reject
    # ambiguous duplicate slots rather than silently keeping the best score.
    slots = {}
    for trial in trials:
        slot = (trial.get("round_index"), trial.get("prompt_id"))
        if slot in slots:
            raise ValueError("同一版本同一轮次存在重复有效试次槽位")
        slots[slot] = trial
    rounds = sorted({t.get("round_index") for t in trials if type(t.get("round_index")) is int})
    complete = [r for r in rounds if all((r, p) in slots and slots[r, p].get("evaluation_status") == "valid"
                                        and isinstance(slots[r, p].get("score"), dict) for p in ids)]
    score_metrics = ("TP", "D", "U", "FP", "FN", "precision", "recall", "f1")
    usage_metrics = ("requests", "tool_calls", "input_tokens", "output_tokens", "total_tokens")
    variant_rows = []
    for variant in variants:
        p = str(variant["id"])
        selected = [slots[r, p] for r in complete]
        metrics = {k: metric([x["score"].get(k) for x in selected]) for k in score_metrics}
        metrics.update({k: metric([(x.get("usage") or {}).get(k) for x in selected]) for k in usage_metrics})
        metrics["duration_seconds"] = metric([x.get("duration_seconds") for x in selected])
        metrics["tokens_per_tp"] = metric([((x.get("usage") or {}).get("total_tokens") / x["score"]["TP"]
                                           if x["score"].get("TP", 0) and _number((x.get("usage") or {}).get("total_tokens")) else None) for x in selected])
        for name, source in (("cvss_mae", "score_mae"), ("cvss_coverage", "scoring_coverage"), ("cvss_score_accuracy", "score_accuracy")):
            metrics[name] = metric([(x["score"].get("cvss_evaluation") or {}).get(source) for x in selected])
        metrics["cvss_severity_agreement"] = metric([(x["score"].get("severity_evaluation") or {}).get("accuracy") for x in selected])
        deltas = {}
        for name in ("f1", "recall"):
            values = []
            for r in complete:
                current, base = slots[r, p], slots[r, baseline_prompt_id]
                if not (_number(current["score"].get(name)) and _number(base["score"].get(name))):
                    continue
                current_hits = {str(x.get("id", x.get("truth_id"))) for x in current["score"].get("truth_results", []) if x.get("detected")}
                baseline_hits = {str(x.get("id", x.get("truth_id"))) for x in base["score"].get("truth_results", []) if x.get("detected")}
                values.append({"round_index": r, "trial_id": current.get("id"), "baseline_trial_id": base.get("id"),
                               "value": current["score"][name] - base["score"][name],
                               "gained_truth_ids": sorted(current_hits - baseline_hits),
                               "lost_truth_ids": sorted(baseline_hits - current_hits)})
            deltas[name] = {**metric([v["value"] for v in values]), "values": values, "unit": "ratio", "display_unit": "percentage_points"}
        variant_rows.append({**variant, "id": p, "metrics": metrics, "paired_deltas": deltas,
                             "paired_f1": deltas["f1"], "paired_recall": deltas["recall"],
                             "trial_ids": [x.get("id") for x in selected],
                             "valid_trials": sum(x.get("evaluation_status") == "valid" for x in trials if x.get("prompt_id") == p)})
    truths = (truth_payload or {}).get("vulnerabilities") or []
    if not truths:
        collected = {}
        for t in trials:
            for row in (t.get("score") or {}).get("truth_results", []):
                collected[str(row.get("id", row.get("truth_id")))] = row
        truths = list(collected.values())
    truth_matrix = []
    for truth in sorted(truths, key=lambda x: str(x["id"])):
        ident = str(truth["id"])
        by_variant = {}
        for p in ids:
            results = []
            for r in complete:
                t = slots[r, p]
                result = next((x for x in t["score"].get("truth_results", []) if str(x.get("id", x.get("truth_id"))) == ident), {})
                results.append({"round_index": r, "trial_id": t.get("id"), "detected": bool(result.get("detected")),
                                "finding_id": result.get("finding_id"), "primary_location": result.get("primary_location")})
            by_variant[p] = {"hits": sum(x["detected"] for x in results), "total": len(complete), "rounds": results}
        truth_matrix.append({"id": ident, "title": truth.get("title", ident), "class": truth.get("class", "unknown"),
                             "variants": by_variant})
    classes = []
    for cls in sorted({x["class"] for x in truth_matrix}):
        rows = [x for x in truth_matrix if x["class"] == cls]
        classes.append({"class": cls, "total": len(rows), "variants": {
            p: {"detected": sum(x["variants"][p]["hits"] for x in rows), "total": len(rows) * len(complete),
                "recall": _ratio(sum(x["variants"][p]["hits"] for x in rows), len(rows) * len(complete))} for p in ids}})
    common_cvss = []
    for r in complete:
        maps = {p: {str(m["truth_id"]): m for m in slots[r, p]["score"].get("matches", []) if m.get("cvss_status") == "compared"} for p in ids}
        common_ids = sorted(set.intersection(*(set(x) for x in maps.values()))) if maps else []
        common_cvss.append({"round_index": r, "truth_ids": common_ids, "total": len(common_ids),
                            "variants": {p: {"score_mae": _ratio(sum(maps[p][i]["cvss_score_error"] for i in common_ids), len(common_ids)),
                                             "severity_accuracy": _ratio(sum(maps[p][i].get("severity_ok") is True for i in common_ids), len(common_ids))} for p in ids}})
    total_usage = {k: {"known_total": sum((t.get("usage") or {}).get(k) for t in trials if _number((t.get("usage") or {}).get(k))),
                       "known_trials": sum(_number((t.get("usage") or {}).get(k)) for t in trials), "trials": len(trials)} for k in usage_metrics}
    return {"protocol": PROTOCOL, "baseline_prompt_id": baseline_prompt_id, "repeats": repeats,
            "complete_rounds": complete, "complete_round_count": len(complete), "preliminary": len(complete) < 3,
            "variants": variant_rows, "truth_matrix": truth_matrix, "class_coverage": classes,
            "cvss_common_rounds": common_cvss, "actual_total_usage": total_usage,
            "interpretation": "官方清单匹配指标；U 不表示已证伪漏洞；无安全负例，不提供 Accuracy/FPR。"}
