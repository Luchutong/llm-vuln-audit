#!/usr/bin/env python3
"""Sanitized replay of the observed LFI response differences.

The investigated run requested the same page endpoint three ways and got three
different bodies: a normal page, a traversal to a missing path, and a traversal to an
existing out-of-directory PHP file whose response stopped early.  That is a real,
reportable difference and nothing more: no server-side diagnostic and no included file
content was recorded, so the replay must keep the conclusion at "response difference"
instead of upgrading it to arbitrary file read or RCE.

Two properties make the replay safe to keep and share:

* **Sanitized.**  The fixture carries only structure: path, HTTP status, body length,
  footer presence, title, and allowlisted diagnostic facts.  Bodies, cookies, session
  ids, credentials, upstream hosts and user data never leave the database.
* **No answers.**  This tool reads only recorded POC jobs.  It never reads ground
  truth, scoring anchors, or any file under the answer set.

Usage::

    python scripts/replay_lfi_evidence.py --db data/audit.db --run-id <id> --export fixture.json
    python scripts/replay_lfi_evidence.py --fixture fixture.json --markdown-out replay.md --check

The database is opened read-only; no migration, runner, gateway or model call happens.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

VERSION = "lfi-replay-v1"
DEFAULT_ENDPOINT = "/content/page.php"
BASELINE_PAGES = ("", "home")
# Allowlisted diagnostic shapes: the same set `PocToolService._job_diagnostics` returns.
DIAGNOSTIC_REASONS = ("capability_unavailable", "collector_unavailable", "unknown_job", "other")
DIAGNOSTIC_KINDS = ("warning", "notice", "deprecated", "fatal", "error", "exception", "other")
_INCLUDE_HINT = re.compile(r"(?i)failed to open stream|include|require")
_FORBIDDEN = ("sessid", "cookie=", "authorization", "http://", "https://", "password", "token=")
_OBSERVATION_KEYS = {"kind", "path", "status", "body_chars", "has_footer", "title",
                     "error_recorded", "diagnostics"}


def _json(value):
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _page(path: str) -> str:
    try:
        return (parse_qs(urlsplit(path).query).get("page") or [""])[0]
    except ValueError:
        return ""


def _title(body: str) -> str:
    start = body.find("<title>")
    end = body.find("</title>", start + 7)
    return body[start + 7:end][:120] if start >= 0 and end > start else ""


def _status(result: dict):
    for key in ("http_status", "status"):
        value = result.get(key)
        if type(value) is int:
            return value
    return None


def _diagnostics(raw) -> dict:
    """Keep availability and structural error facts, never the message text."""
    if not isinstance(raw, dict):
        return {"status": "not_recorded"}
    if raw.get("available") is not True:
        reason = str(raw.get("reason") or "")
        return {"status": "unavailable", "reason": reason if reason in DIAGNOSTIC_REASONS else "other"}
    items = []
    for item in (raw.get("items") or [])[:20]:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "").lower()
        source = Path(str(item.get("source_path") or "")).name[:120]
        message = str(item.get("message") or "")
        items.append({
            "kind": kind if kind in DIAGNOSTIC_KINDS else "other",
            "source_file": source,
            "line": item.get("line") if type(item.get("line")) is int else 0,
            "include_related": bool(_INCLUDE_HINT.search(message)),
        })
    return {"status": "available", "items": items}


def observation(job: dict):
    """One HTTP job as sanitized structure; ``None`` for other job kinds."""
    if job.get("kind") != "http":
        return None
    request = _json(job.get("request"))
    result = _json(job.get("result"))
    path = str(request.get("path") or result.get("path") or "")
    if not path.startswith("/"):
        return None
    body = str(result.get("body") or "")
    return {
        "kind": "http",
        "path": path[:500],
        "status": _status(result),
        "body_chars": len(body),
        "has_footer": "</footer>" in body,
        "title": _title(body),
        "error_recorded": bool(result.get("error")),
        "diagnostics": _diagnostics(result.get("diagnostics")),
    }


def assert_sanitized(observations) -> None:
    """A fixture that leaks a session or an upstream host is not a replay input."""
    for item in observations:
        extra = set(item) - _OBSERVATION_KEYS
        if extra:
            raise ValueError(f"unsanitized observation fields: {sorted(extra)}")
        path = str(item.get("path") or "")
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("observation path must be a local absolute path")
        lowered = (path + " " + str(item.get("title") or "")).casefold()
        for needle in _FORBIDDEN:
            if needle in lowered:
                raise ValueError(f"observation still contains {needle!r}")


def collect(db_path: Path, run_id: str, finding_id: str | None = None) -> list[dict]:
    """Read recorded POC jobs without writing to the database."""
    uri = f"file:{db_path}?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    db.row_factory = sqlite3.Row
    try:
        query = "SELECT kind, request, result FROM poc_verification_jobs WHERE run_id = ?"
        params: list[object] = [run_id]
        if finding_id:
            query += " AND finding_id = ?"
            params.append(finding_id)
        query += " ORDER BY created_at"
        made = []
        for row in db.execute(query, params):
            item = observation({"kind": row["kind"], "request": row["request"], "result": row["result"]})
            if item is not None:
                made.append(item)
        return made
    finally:
        db.close()


def _dedupe(items):
    seen, made = set(), []
    for item in items:
        key = (item["path"], item.get("status"), item["body_chars"], item["has_footer"])
        if key not in seen:
            seen.add(key)
            made.append(item)
    return made


def _server_evidence(variants):
    items, unavailable, not_recorded = [], [], []
    for variant in variants:
        diagnostics = variant.get("diagnostics") or {"status": "not_recorded"}
        status = diagnostics.get("status")
        if status == "available":
            items.extend(diagnostics.get("items") or [])
        elif status == "unavailable":
            unavailable.append(diagnostics.get("reason") or "other")
        else:
            not_recorded.append(variant["path"])
    if items:
        return {"state": "diagnostics_recorded", "items": items,
                "correlated_errors": [item for item in items if item.get("include_related")]}
    if unavailable:
        return {"state": "diagnostics_unavailable", "reasons": sorted(set(unavailable)), "items": []}
    if not_recorded:
        return {"state": "diagnostics_not_recorded", "paths": not_recorded, "items": []}
    return {"state": "diagnostics_recorded", "items": []}


def replay(observations, *, endpoint: str = DEFAULT_ENDPOINT) -> dict:
    """Classify the observed differences and keep impact inside the evidence."""
    assert_sanitized(observations)
    observations = [item for item in observations if str(item.get("path") or "").startswith(endpoint)]
    observations = _dedupe(observations)
    baselines = [item for item in observations if _page(item["path"]) in BASELINE_PAGES]
    traversals = [item for item in observations if ".." in _page(item["path"])]
    baseline_sizes = sorted({item["body_chars"] for item in baselines})
    baseline = max(baselines, key=lambda item: item["body_chars"]) if baselines else None
    variants = []
    for item in traversals:
        delta = item["body_chars"] - baseline["body_chars"] if baseline else None
        changes = []
        if delta:
            changes.append("shorter_body" if delta < 0 else "longer_body")
        if baseline and baseline["has_footer"] and not item["has_footer"]:
            changes.append("footer_missing")
        if baseline and item.get("status") is not None and baseline.get("status") is not None \
                and item["status"] != baseline["status"]:
            changes.append("status_changed")
        variants.append({**item, "delta_chars": delta, "classification": changes or ["no_difference"]})
    server = _server_evidence(variants)
    gaps = []
    if not baseline:
        gaps.append("no_baseline_observation")
    if not variants:
        gaps.append("no_traversal_observation")
    if server["state"] != "diagnostics_recorded":
        gaps.append(server["state"])
    # The sanitized fixture keeps structure only, so it cannot establish that the
    # requested file's content was returned.  Replaying it must not pretend otherwise.
    gaps.append("sanitized_replay_has_no_body_content")
    if not server.get("correlated_errors"):
        gaps.append("no_correlated_server_error")
    changed = [item for item in variants if item["classification"] != ["no_difference"]]
    basis = "difference_only" if baseline and changed else "insufficient_observation"
    return {
        "version": VERSION,
        "endpoint": endpoint,
        "observation_count": len(observations),
        "baseline": {"path": baseline["path"], "status": baseline.get("status"),
                     "body_chars": baseline["body_chars"], "has_footer": baseline["has_footer"],
                     "sizes": baseline_sizes} if baseline else None,
        "variants": variants,
        "server_evidence": server,
        "gaps": gaps,
        "interruption": {
            "explained": bool(server.get("correlated_errors")),
            "reason": "correlated_server_diagnostic" if server.get("correlated_errors") else None,
        },
        "impact": {
            "level": "response_difference" if changed else "none_observed",
            "arbitrary_file_read": False,
            "remote_code_execution": False,
            "note": "响应差异本身不等于任意文件读取或代码执行；影响范围以实际证据为准。",
        },
        "conclusion": {"status": "inconclusive", "verdict": "uncertain", "basis": basis},
    }


def render_markdown(result: dict) -> str:
    lines = ["### LFI 脱敏回放", ""]
    baseline = result.get("baseline") or {}
    lines += [
        f"- 端点：`{result.get('endpoint')}`；去重后观测 {result.get('observation_count')} 条。",
        f"- 基线：`{baseline.get('path') or '—'}`，状态 {baseline.get('status')}，"
        f"{baseline.get('body_chars')} 字符，页脚 {'有' if baseline.get('has_footer') else '无'}。",
        "",
        "| 请求 | 状态 | 字符 | 相对基线 | 结构差异 |",
        "|---|---|---|---|---|",
    ]
    for item in result.get("variants") or []:
        lines.append(
            f"| `{item['path']}` | {item.get('status')} | {item['body_chars']} | "
            f"{item.get('delta_chars')} | {'、'.join(item.get('classification') or [])} |")
    server = result.get("server_evidence") or {}
    lines += [
        "",
        f"- 服务端诊断：{server.get('state')}（{len(server.get('items') or [])} 条）。",
        f"- 中断解释：{'是' if (result.get('interruption') or {}).get('explained') else '否'}。",
        f"- 证据缺口：{'、'.join(result.get('gaps') or []) or '无'}。",
        f"- 影响判定：{result['impact']['level']}；任意文件读取 {result['impact']['arbitrary_file_read']}；"
        f"代码执行 {result['impact']['remote_code_execution']}。",
        f"- 结论：{result['conclusion']['status']}（{result['conclusion']['basis']}）。",
        "",
    ]
    return "\n".join(lines)


def check(result: dict, observations=None) -> list[str]:
    """Contract failures that make the replay unusable as acceptance evidence."""
    problems = []
    if not result.get("baseline"):
        problems.append("missing baseline observation")
    if not result.get("variants"):
        problems.append("missing traversal observation")
    if result["impact"]["level"] not in {"response_difference", "none_observed"}:
        problems.append("impact escalated beyond the recorded evidence")
    if result["impact"]["arbitrary_file_read"] or result["impact"]["remote_code_execution"]:
        problems.append("replay claims an unproven impact")
    if result["conclusion"]["status"] != "inconclusive":
        problems.append("a difference-only replay cannot publish a verdict")
    if observations is not None:
        try:
            assert_sanitized(observations)
        except ValueError as exc:
            problems.append(str(exc))
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Replay sanitized LFI response differences without answers.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--db", type=Path, help="SQLite database, opened read-only")
    source.add_argument("--fixture", type=Path, help="previously exported sanitized observations")
    parser.add_argument("--run-id")
    parser.add_argument("--finding-id")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--export", type=Path, help="write the sanitized observations here")
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--check", action="store_true", help="exit non-zero when the contract breaks")
    args = parser.parse_args(argv)

    if args.fixture:
        fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
        observations = fixture.get("observations") or []
    elif args.run_id:
        observations = collect(args.db, args.run_id, args.finding_id)
    else:
        parser.error("--db requires --run-id")

    result = replay(observations, endpoint=args.endpoint)
    if args.export:
        # A fixture carries the replayed endpoint only: unrelated pages of the run would
        # add paths and titles without adding a checkable fact.
        exported = _dedupe([item for item in observations
                            if str(item.get("path") or "").startswith(args.endpoint)])
        assert_sanitized(exported)
        args.export.write_text(json.dumps({
            "version": VERSION, "endpoint": args.endpoint,
            "provenance": {"run_id": args.run_id, "finding_id": args.finding_id},
            "observations": exported}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.write_text(render_markdown(result), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.check:
        problems = check(result, observations)
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
