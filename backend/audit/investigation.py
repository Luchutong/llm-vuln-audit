"""Bounded progress accounting, independent of semantic finding deduplication."""
from __future__ import annotations

import hashlib
import json
import re

POLICY = "bounded-v1"
STALL_LIMIT = 2


def enabled(task):
    return (task or {}).get("investigation_policy") == POLICY


def valid_submission(result):
    return (result.get("outcome") in {"achieved", "no_evidence", "continue"}
            and result.get("terminal_reason", "completed") == "completed" and not result.get("error"))


def root_key(finding):
    """A novelty budget coordinate, never a declaration that two flaws are equal."""
    from .worker_strategies import canonical_vulnerability_type
    location = finding.get("primary_location") or {}
    if isinstance(location, str):
        try:
            location = json.loads(location)
        except ValueError:
            return None
    if not isinstance(location, dict):
        return None
    if not location.get("path") or type(location.get("line")) is not int:
        return None
    value = [canonical_vulnerability_type(finding.get("vulnerability_type")), location["path"], location["line"]]
    return hashlib.sha256(json.dumps(value, ensure_ascii=False).encode()).hexdigest()[:32]


def progress(previous, result, seen, previous_seen, known_findings):
    from .directions import has_new_source_evidence
    prior = previous.get("host_progress") or {}
    known = {key for f in known_findings if (key := root_key(f))}
    incoming = {key for f in result.get("findings") or [] if (key := root_key(f))}
    fresh = incoming - known
    new_evidence = has_new_source_evidence(seen or [], previous_seen)
    old = {c["candidate_id"]: c for c in previous.get("candidate_journal") or []}
    prior_settled = set(prior.get("settled_candidate_ids") or []) | {c["candidate_id"] for c in old.values() if c["status"] != "pending"}
    settled = [c["candidate_id"] for c in result.get("candidate_journal") or []
               if c["candidate_id"] in old and c["candidate_id"] not in prior_settled
               and old[c["candidate_id"]]["status"] == "pending" and c["status"] != "pending"]
    success = valid_submission(result)
    productive = success and bool(fresh or new_evidence or settled)
    stalls = 0 if productive else int(prior.get("stalled_passes") or 0) + int(success)
    return dict(policy=POLICY, conclusion_keys=sorted(known | incoming),
        successful_batches=int(prior.get("successful_batches") or 0)+int(productive),
        failed_attempts=int(prior.get("failed_attempts") or 0)+int(not productive),
        new_evidence=new_evidence, new_conclusions=len(fresh), settled_candidates=settled,
        settled_candidate_ids=sorted(prior_settled | set(settled)),
        productive=productive, stalled_passes=stalls)


def pause_reason(result):
    blocked = [c["candidate_id"] for c in result.get("candidate_journal") or []
               if c.get("status") == "pending" and c.get("blocked_on")]
    if blocked:
        return dict(code="candidate_external_dependency", candidates=blocked,
                    message="候选依赖缺失源码/运行配置/环境；保留未决并交回 Planner，不再重复领取")
    if int((result.get("host_progress") or {}).get("stalled_passes") or 0) >= STALL_LIMIT:
        return dict(code="no_investigation_progress", message="连续两次有效提交未增加源码、根因坐标或候选结算；保留结果并交回 Planner")
    return None


def linked_observations(result, journal, known_findings, spans):
    """Validate explicit owners instead of guessing risk semantics from prose."""
    from .role_policy import _read
    candidates = {c["candidate_id"]: c for c in journal}
    findings = result.get("findings") or []
    existing = {f["id"]: f for f in known_findings if f.get("id")
                and f.get("validation_state") == "candidate" and f.get("finding_kind") == "vulnerability"
                and f.get("disposition", "open") in {"open", "", None} and f.get("verification_status") != "rejected"}
    linked = set()
    for index, observation in enumerate(result.get("observations") or []):
        owners = [key for key in ("candidate_id", "finding_index", "finding_id") if observation.get(key) is not None]
        if not owners:
            continue
        if len(owners) != 1:
            raise ValueError(f"observations[{index}] 只能显式关联一个 candidate_id/finding_index/finding_id")
        owner = owners[0]
        if owner == "candidate_id":
            target = candidates.get(observation[owner])
        elif owner == "finding_id":
            target = existing.get(observation[owner])
        else:
            n = observation[owner]
            target = findings[n] if type(n) is int and 0 <= n < len(findings) else None
        location = (target or {}).get("primary_location") or {}
        if not location:
            raise ValueError(f"observations[{index}].{owner} 须指向实际有效候选或本次/本运行 finding")
        refs = [dict(path=location["path"], start_line=int(m[1]), end_line=int(m[2] or m[1])) for m in re.finditer(
            re.escape(location["path"]) + r":(\d+)(?:-(\d+))?(?!\d)", observation.get("evidence") or "")]
        if not any(r["start_line"] <= location["line"] <= r["end_line"] and _read(r, spans) for r in refs):
            raise ValueError(f"observations[{index}].evidence 须实际读取并覆盖所关联根因 {location['path']}:{location['line']}")
        linked.add(index)
    return linked


_BLOCKED_PATH = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9_./-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:php|py|js|jsx|ts|tsx|java|rb|go|rs|c|h|cc|cpp|sql|yml|yaml|json|ini|conf|sh|md|txt|html|xml)"
)
_LITERAL_HASH = re.compile(
    r"\b(?:md5|sha1|sha224|sha256|sha384|sha512|crc32|hash)\s*\(\s*(['\"])[^'\"]+\1",
    re.IGNORECASE,
)
# A gap described by a deployment or schema concept rather than a path is still inside
# the snapshot when the package ships that configuration or the DDL. The contract tells
# the worker to read those files; this keeps a false source block from pausing the task.
_SNAPSHOT_HINTS = (
    (("apache", "nginx", "docker", "compose", "https", "tls", "反向代理"),
     ("apache.conf", "nginx.conf", "compose.yaml", "docker/")),
    (("schema", "fixture", "migration", "迁移", "表结构", "唯一约束"),
     ("fixtures/", "schema", "migrations/", "setup.php")),
)


def blocked_context_error(item, file_lines):
    """Refuse a pending candidate whose missing context is inside the frozen snapshot.

    ``blocked_on`` is for context the snapshot does not contain, and a literal
    hash/encoding is not a runtime dependency. The contract already says both; this
    makes the host enforce them at publication time so a model that ignores the
    contract receives a correction instead of parking the task on a false gap.
    """
    if not item.get("blocked_on"):
        return None
    # Only the declared gap and next step, not the hypothesis: every candidate names
    # its own root-cause file there, and having read it is not a missing dependency.
    text = " ".join(
        [str(value) for value in item.get("missing_context") or []]
        + [str(item.get("next_step") or "")])
    read = {ref.get("path") for ref in item.get("evidence") or [] if isinstance(ref, dict)}
    frozen = [str(path) for path in (file_lines or {})]
    claims_missing_source = any(cue in text for cue in ("读取", "补读", "未读", "缺失", "缺少", "未提供"))
    for token in list(dict.fromkeys(t.strip("./") for t in _BLOCKED_PATH.findall(text))):
        if not claims_missing_source or not token:
            continue
        match = next((path for path in frozen
                      if path not in read and (path == token or path.endswith("/" + token))), None)
        if match:
            return (f"候选 {item.get('candidate_id')} 以 blocked_on={item['blocked_on']} 交出，"
                    f"但 {match} 已在冻结快照内且本轮未读；blocked_on 只用于快照之外的文件。"
                    "请在本轮读取该文件并更新候选。")
    lowered = text.lower()
    for cues, fragments in _SNAPSHOT_HINTS:
        if not any(cue in lowered for cue in cues):
            continue
        matching = [path for path in sorted(frozen)
                    if any(fragment in path.lower() for fragment in fragments)]
        if matching and not any(path in read for path in matching):
            return (f"候选 {item.get('candidate_id')} 以 blocked_on={item['blocked_on']} 交出，"
                    f"但其缺失的部署/表结构事实由冻结快照内的 {'、'.join(matching[:3])} 给出；"
                    "请在本轮读取这些文件并更新候选。")
    if item.get("blocked_on") in {"runtime", "environment"}:
        hashed = _LITERAL_HASH.search(text)
        if hashed:
            return (f"候选 {item.get('candidate_id')} 的下一步只依赖字面量 {hashed.group(0)}，"
                    "该值可用本地 Python 当场算出，不构成运行时/环境外部依赖。"
                    "请在本轮算出结果并把候选更新为 supported 或 excluded。")
    return None


WORKER_CONTRACT = """# 有界调查与明确交接
preconditions 必须是一个字符串，用分号连接条件；既有台账中的数组不是新 finding 的字段格式。
同一根因坐标改写措辞、CVSS 或前提不会获得新的调查进展额度；全部原始主张仍保存并独立审查，不因此自动合并漏洞。
pending 候选依赖当前快照缺失的源码、运行配置或环境时，填写 blocked_on=source|runtime|environment、missing_context 和具体 next_step；宿主保存已提交 finding 后暂停此任务，将未决项交回 Planner，不能反复重报已有漏洞。
字面量可离线计算的常量（哈希、编码、校验和、纯算术）必须在本轮用本地 Python 算出并写进候选或结论，不得以 blocked_on=runtime/environment 交出；blocked_on 只用于依赖冻结源码之外的文件、目标进程的实际状态或运行中的配置。
快照内的部署配置（apache/nginx/docker/compose）与表结构（schema/fixtures/setup.php）属于可读源码：先读取再判断，不得以 blocked_on=source 交出。
普通 pending 连续两次有效提交没有新增读取、根因坐标或候选结算时，宿主也会暂停；缺口不能改成安全或静默删除。
观察对应未决风险时填 candidate_id，先在 candidate_updates 保存实际操作坐标、缺口和下一步。尤其不能把可疑身份判断只写在笼统的安全边界观察里；发现条数用尽时先保存候选，不把它遗漏。
观察只是复述已有漏洞时填 finding_index（本次 findings 的零起始索引）或当前运行真实 finding_id，不重复主张。观察 evidence 必须实际读过并覆盖所关联根因；只允许一个关联。关联保持原结论/候选的审查与未决状态，不是排除风险的反证。
未关联观察的 follow_up=false 仍必须给出具体 disproof；候选、观察和风险信号都不能自行变成已接受漏洞。
"""

PLANNER_CONTRACT = """# 有界调查的调度交接
investigation_pause 是宿主保存成果后的交接，不是安全判断。candidate_external_dependency 只有取得缺少的具体源码/配置/环境事实才重开；no_investigation_progress 需要缩小到未决操作并给出新的取证步骤，不能重新派发已有根因的近义任务。
可由源码字面量加本地计算直接得出的常量（哈希、编码、校验和、算术）不构成外部依赖；此类暂停应重开任务要求 worker 当场计算，而不是把候选长期留作环境阻塞。
Worker 候选继续计入完整性缺口；无法获得外部前提时保持 blocked/inconclusive，不取消候选或改成 no_evidence。带 pending_candidates 的 blocked 任务只能在同一回合用同 task_key 的修订任务加 updates.reopen 推进，或保留阻塞。
方向结算读取 resolution_context：required 禁止 triage；supported 必须独立核对并提交真实 finding_ids，no_evidence 的 finding_ids 为空且保留 worker 源码反证；没有匹配结果就保留未决。
"""


def reference():
    """Synthetic checkpoints; examples never assert a project-specific verdict."""
    return dict(version=POLICY, rules=WORKER_CONTRACT,
        examples=[dict(case="外部前提缺失时保存并交接", candidate_updates=[dict(
            candidate_id="concurrent-update", status="pending", hypothesis="并发更新是否导致不一致仍需运行配置。",
            primary_location=dict(path="demo/wallet.php", line=8),
            evidence=[dict(path="demo/wallet.php", start_line=8, end_line=8)],
            missing_context=["冻结源码未提供实际事务隔离级别和连接事务设置。"],
            next_step="获取实际连接的事务配置并核对更新是否同一事务。", blocked_on="runtime")],
            observations=[dict(kind="security_boundary", title="待核对的事务边界", summary="运行前提未决，保留局部候选。",
                evidence="demo/wallet.php:8-8", follow_up=True, candidate_id="concurrent-update")]),
            dict(case="复述本次已提交发现", observation=dict(kind="data_flow", title="已有结论的传播路径",
                summary="此观察只补充 findings[0] 的来源与操作，不排除其它风险。", evidence="demo/query.php:4-4",
                follow_up=False, finding_index=0))],
        notice="demo 路径为格式示例，必须替换为当前实际读取的源码；关联对象必须存在，不能用标志隐藏独立风险。")
