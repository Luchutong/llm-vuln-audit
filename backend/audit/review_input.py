"""Bounded review transport. Original facts remain available by exact-version reads."""
from __future__ import annotations

import hashlib
import json


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def verification_fact_availability(verification):
    """Distinguish persisted experiment facts from the agent's published conclusion."""
    agent = verification.get("agent") or {}
    jobs = agent.get("job_results") or []
    from .poc_agent import successful_job
    return {
        "jobs_total": len(jobs),
        "successful_jobs": sum(successful_job(job) for job in jobs if isinstance(job, dict)),
        "published_normal_observation": bool(verification.get("normal_observation")),
        "published_attack_observation": bool(verification.get("attack_observation")),
        "conclusion_missing": bool(jobs) and (
            agent.get("reason") not in {None, "", "completed"}
            or verification.get("status") == "inconclusive" and not (
                verification.get("normal_observation") and verification.get("attack_observation"))),
        "notice": "作业事实与 Agent 发布的观测分开记录；结论中断不代表没有执行观测。",
    }


def compact_observations(verification):
    """Keep both observations and literal references; job output is stored only once.

    The full jobs are still accessible through read_verification and downloads. Their
    hashes bind this projection to those bytes without repeating large stdout/bodies.
    """
    agent = verification.get("agent") or {}
    value = {key: verification.get(key) for key in (
        "id", "status", "verdict", "execution_status", "normal_observation", "attack_observation", "browser_execution")}
    value.update({key: agent.get(key) for key in (
        "context_id", "identity", "preconditions", "state_changes", "normal_evidence", "attack_evidence", "summary", "reason", "jobs")})
    jobs = agent.get("job_results") or []
    value["fact_availability"] = verification_fact_availability(verification)
    value["job_summaries"] = [
        {**{key: job.get(key) for key in ("job_id", "kind", "status", "context_id", "identity", "timed_out", "exit_code", "precondition")},
         "result": {key: (job.get("result") if isinstance(job.get("result"), dict) else {}).get(key)
                    for key in ("status", "execution_status", "exit_code", "http_status", "status_code", "timed_out", "error", "browser_execution")},
         "full_record_sha256": digest(encode(job))}
        for job in jobs if isinstance(job, dict)
    ]
    if jobs:
        value["full_jobs_reader"] = {"tool": "read_verification", "verification_id": verification.get("id"), "field": "agent"}
    return value


def source_input(item, repository):
    """Every citation is read; neither the number of refs nor long ranges imply failure."""
    result = {**item, "source_excerpts": [], "evidence_complete": True}
    refs = item["payload"].get("evidence") or []
    result["evidence_complete"] = bool(refs) and repository is not None
    for ref in refs:
        try:
            start, end = ref["range"]["start"], ref["range"]["end"]
            if type(start) is not int or type(end) is not int or start < 1 or end < start:
                raise ValueError("invalid citation range")
            cursor = start
            while cursor <= end:
                stop = min(end, cursor + 199)
                read = repository.read_source(ref["snapshot_id"], ref["path"], cursor, stop)
                actual = read.get("end_line", 0)
                if read.get("start_line") != cursor or actual < cursor or actual > stop:
                    raise ValueError("source range unavailable")
                result["source_excerpts"].append(read)
                if actual < stop and not read.get("truncated"):
                    raise ValueError("source citation exceeds file")
                cursor = actual + 1
        except Exception as exc:
            result["evidence_complete"] = False
            result.setdefault("source_errors", []).append({"evidence_id": ref.get("evidence_id"), "error": type(exc).__name__})
    return result


def field_values(item):
    values = {"payload." + key: value for key, value in item.get("payload", {}).items()}
    for key in ("source_excerpts", "source_errors"):
        if key in item:
            values[key] = item[key]
    return values


def comparison_groups(items):
    """Keep related claims in one review when capacity allows, without merging them."""
    by_id = {item["item_id"]: item for item in items}
    seen = set()
    for item in items:
        if item["item_id"] in seen:
            continue
        queue, group = [item["item_id"]], []
        while queue:
            ident = queue.pop(0)
            if ident in seen or ident not in by_id:
                continue
            seen.add(ident)
            current = by_id[ident]
            group.append(current)
            queue.extend(p["item_id"] for p in current.get("payload", {}).get("comparison_candidates", []))
        yield group


def bounded_item(item, limit=32000):
    """Replace large fields by exact manifests, retaining IDs and useful inline facts."""
    projected = {**item, "payload": dict(item.get("payload") or {})}
    paged = []
    for field, value in sorted(field_values(item).items(), key=lambda pair: len(encode(pair[1]).encode()), reverse=True):
        if len(encode(projected).encode()) <= limit and field not in item.get("required_read_fields", []):
            continue
        text = encode(value)
        paged.append({"field": field, "characters": len(text), "sha256": digest(text), "encoding": "json"})
        if field.startswith("payload."):
            projected["payload"].pop(field.removeprefix("payload."))
        else:
            projected.pop(field)
        projected.update(paged_fields=paged, review_input_omitted=True,
                         input_reader="read_review_input: follow next_offset to null for every paged field before acceptance")
    return projected


def fully_read(intervals, length):
    end = 0
    for start, stop in sorted(intervals):
        if start > end:
            return False
        end = max(end, stop)
    return end >= length


def access_complete(item):
    return all(fully_read((item.get("read_ranges") or {}).get(field["field"], []), field["characters"])
               for field in item.get("paged_fields", []))


def same_input(leased, current):
    if not current or leased["revision"] != current["revision"]:
        return False
    if leased.get("review_input_omitted") and not leased.get("paged_fields"):
        return False  # An old opaque omission lease must be repacked, not accepted.
    # Peer comparisons are dependencies of this decision, not of the claim's own
    # fact revision. Their changes expire the lease without invalidating a review
    # merely because a later review withdraws one of those peers.
    peers = current.get("payload", {}).get("comparison_candidates", [])
    part = next((p for p in leased.get("paged_fields", []) if p["field"] == "payload.comparison_candidates"), None)
    return (digest(encode(peers)) == part["sha256"] if part else
            leased.get("payload", {}).get("comparison_candidates", []) == peers)
