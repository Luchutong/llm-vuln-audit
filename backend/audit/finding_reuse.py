"""Small live identities and source-backed references instead of repeated reports.

Coordinates select comparisons, never prove two vulnerabilities equivalent. A worker
can explicitly corroborate an existing claim, or explain why a same-coordinate claim
is distinct. Neither action accepts a finding or changes its verification status.
"""
from __future__ import annotations

import hashlib
import json

from .finding_policy import is_vulnerability_finding
from .worker_strategies import canonical_vulnerability_type

POLICY = "finding-reuse-v1"


def enabled(task):
    return (task or {}).get("investigation_policy") == "bounded-v1" and (task or {}).get("workflow_policy") == "discovery_first"


def location(item):
    value = item.get("primary_location") or {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def coordinate(item):
    point = location(item)
    cause = canonical_vulnerability_type(item.get("vulnerability_type"))
    if not point.get("path") or type(point.get("line")) is not int or cause in {"", "unknown", "other"}:
        return None
    return cause, point["path"], point["line"]


def active(findings, run_id=""):
    return [f for f in findings or [] if isinstance(f, dict) and f.get("id")
            and (not run_id or f.get("run_id") == run_id) and is_vulnerability_finding(f)
            and f.get("validation_state") == "candidate" and f.get("disposition", "open") in {None, "", "open"}]


def registry(findings, run_id="", *, path="", line=None, cause="", offset=0, limit=64, max_bytes=8192, details=False):
    """A run-wide coordinate index; no large report, CVSS or POC bodies."""
    rows = active(findings, run_id)
    if path:
        rows = [f for f in rows if location(f).get("path") == path or str(location(f).get("path") or "").startswith(path.rstrip("/") + "/")]
    if line is not None:
        rows = [f for f in rows if location(f).get("line") == line]
    if cause:
        rows = [f for f in rows if canonical_vulnerability_type(f.get("vulnerability_type")) == canonical_vulnerability_type(cause)]
    rows.sort(key=lambda f: (str(location(f).get("path") or ""), location(f).get("line") or 0, str(f["id"])))
    result = dict(policy=POLICY, total=len(rows), items=[], next_offset=None,
                  notice="坐标相同仅表示需要对照；不同输入、危险操作或必要前提仍可独立报告。索引不是源码证据。")
    for item in rows[offset:offset + limit]:
        point = location(item)
        entry = dict(finding_id=item["id"], revision=int(item.get("revision") or 1),
                     vulnerability_type=canonical_vulnerability_type(item.get("vulnerability_type")),
                     primary_location=point, verification_status=item.get("verification_status", "unverified"))
        if details:
            entry.update({key: str(item.get(key) or "")[:240]
                          for key in ("input_source", "dangerous_operation", "preconditions")})
        candidate = {**result, "items": [*result["items"], entry]}
        if result["items"] and len(json.dumps(candidate, ensure_ascii=False).encode()) > max_bytes:
            break
        result["items"].append(entry)
    if offset + len(result["items"]) < len(rows):
        result["next_offset"] = offset + len(result["items"])
    result["index_sha256"] = hashlib.sha256(json.dumps([
        (f["id"], f.get("revision", 1), coordinate(f), f.get("verification_status")) for f in rows],
        ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    return result


def validate_references(task, references, findings, spans, *, run_id=""):
    if references and not enabled(task):
        raise ValueError("当前任务不支持 finding_references；不能用引用代替新漏洞证据")
    from .schemas import FindingReference
    from .role_policy import _read
    existing = {f["id"]: f for f in active(findings, run_id)}
    seen = set()
    values = []
    for raw in references or []:
        value = FindingReference.model_validate(raw).model_dump()
        ident = value["finding_id"]
        target = existing.get(ident)
        if not target or target.get("verification_status") == "rejected":
            raise ValueError("finding_references.finding_id 必须是当前运行仍有效的实际漏洞 ID；不接受撤回、重复别名或动态反证项")
        if ident in seen or value["revision"] != int(target.get("revision") or 1):
            raise ValueError("finding_references 必须唯一引用当前 revision；旧版本不能作为本次佐证")
        seen.add(ident)
        point = location(target)
        refs = value["evidence"]
        if not refs or not all(_read(ref, spans) for ref in refs) or not any(
                ref["path"] == point.get("path") and ref["start_line"] <= point.get("line", 0) <= ref["end_line"] for ref in refs):
            unread=[f"{r['path']}:{r['start_line']}-{r['end_line']}" for r in refs if not _read(r,spans)]
            raise ValueError(f"finding_references.evidence 须本次实际读取并覆盖所引用漏洞根因；本项 finding_id={ident}，"
                             f"根因={point.get('path')}:{point.get('line')}；未读引用={unread[:3]}。"
                             "请补读并引用根因的实际行，或省略该引用并保留未决；不能移动根因或扩大已读范围。")
        values.append(value)
    return values


def validate_novelty(task, incoming, existing, *, run_id=""):
    """Do not suppress same-location findings: require an explicit comparison."""
    if not enabled(task):
        return
    current = active(existing, run_id)
    batch_coordinates = set()
    for index, item in enumerate(incoming):
        key = coordinate(item)
        if key is not None and key in batch_coordinates and len(str(item.get("novelty_reason") or "").strip()) < 12:
            raise ValueError(f"findings[{index}] 在同一批重复根因坐标；相同漏洞只保留一份，独立输入／操作须用 novelty_reason 说明具体差异。")
        if key is not None:
            batch_coordinates.add(key)
        peers = [f for f in current if key is not None and coordinate(f) == key]
        if not peers:
            continue
        allowed = {f["id"] for f in peers}
        if item.get("related_finding_id") not in allowed or len(str(item.get("novelty_reason") or "").strip()) < 12:
            raise ValueError(f"findings[{index}] 对应已有根因坐标；相同漏洞请用 finding_references 只补充证据，"
                             "独立漏洞须填写 related_finding_id 和 novelty_reason，说明不同输入／操作／必要前提；"
                             "措辞、CVSS 或 POC payload 变化不是新漏洞。允许 ID：" + ",".join(sorted(allowed)))


CONTRACT = """# 已有漏洞复用与新发现增量
提交完整 finding 前先查当前运行根因索引；沿依赖发现新文件时可调用 lookup_findings，返回最新已提交的短索引。
若只是复现已有根因，不再重写 finding、CVSS、POC 或修复方案。使用 finding_references=[{finding_id,revision,evidence:[{path,start_line,end_line}],rationale}]，outcome=achieved 可仅携带引用。引用必须本次实际读取并覆盖根因；这不代表独立终审通过、动态验证成功或整个方向都已查完。
短引用已包含理由和证据时省略重复 observations。确需附带观察时用 finding_id 关联已有漏洞；finding_index 只索引本次完整 findings，不能索引 finding_references。findings 为空时不得填 finding_index=0。
本任务已有 pending 候选确被所引漏洞覆盖时，可用 candidate_updates status=supported、finding_id 指向同主定位且本次 finding_references 验证过的结论；不用 finding_index，也不能删掉其它 pending 候选。
同坐标仍可能有不同输入参数、危险操作或必要前提；确为独立漏洞时保留完整 finding，填写 related_finding_id 与 novelty_reason（至少12字的具体差异），交独立终审判读。不能按同文件、同分类或同修复措辞自动合并。
所有未决候选和仍需取证的方向继续保留。只改写标题、前提措辞、评分或 payload 不产生新发现；不要把重复 findings 改成无漏洞或制造新的 remaining_work。
"""


def reference_index(store, run_id):
    """Only committed, validated attempts contribute corroboration to final review."""
    result = {}
    seen = set()
    revisions = {f['id']: int(f['revision'] or 1) for f in store._rows('SELECT id,revision FROM findings WHERE run_id=?', (run_id,))}
    for row in store._rows("SELECT t.task_key,a.result FROM planner_task_attempts a JOIN planner_tasks t ON t.id=a.task_id"
                           " WHERE a.run_id=? AND a.attempt>0 ORDER BY a.created_at,a.id", (run_id,)):
        value = json.loads(row["result"] or "{}")
        if value.get("error") or value.get("terminal_reason") not in {None, "", "completed"}:
            continue
        for ref in value.get("finding_references") or []:
            if revisions.get(ref["finding_id"]) != ref["revision"]:
                continue  # Keep old attempts as history, not evidence for a changed claim.
            key = json.dumps(ref, ensure_ascii=False, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            result.setdefault(ref["finding_id"], []).append({**ref, "task_key": row["task_key"]})
    return result
