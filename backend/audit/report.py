"""Markdown / JSON / evidence-package export.

The Markdown follows the six-chapter outline in docs/report-outline.md. Anything that
was not actually measured is written as 待实测 rather than filled with a plausible
number, and ordinary uploaded projects report recall/FN/TN as not computable.
"""
from __future__ import annotations
from .cvss_assessment import rating_text, rating_details_lines

import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .config import VERSION
from .db import WITHDRAWN_FINDING_DISPOSITIONS
from .finding_policy import is_vulnerability_finding, partition_findings, source_observations
from .project_findings import PROJECT_SYMBOL
from .runtime import AgentPolicy
from .schemas import CATEGORY_LABELS

NOT_MEASURED = "待实测"
NOT_COMPUTABLE = "无法计算"

CATEGORY_ORDER = ("sqli", "xss_r", "command_injection")

# `worker.py` records a settlement failure as "<cause> | 收尾阶段 <category> 判定失败: ...".
# Reading it back is how chapter 5 can say which categories ran out of wall clock instead of
# blaming "模型输出不稳定" in the abstract.
SETTLEMENT_FAILURE = re.compile(r"收尾阶段 ([a-z_]+) 判定失败")
# Interpret old experiment records using their old limits; never present these as
# the policy of the new executor. Historical reports remain reproducible.
SETTLE_CALL_SECONDS = 200.0
SETTLE_REQUEST_SECONDS = 90.0

# A whole project can be uploaded now, so any per-file listing in the report must be
# bounded; the JSON export carries the complete list.
MAX_REPORTED_PATHS = 40


def _scope_files(run: dict, project_map: dict) -> int:
    """Count the frozen scope, preferring the persisted project map.

    A whole-snapshot run freezes no path list at all, so ``run["scope"]`` is only the
    source of truth for historical records that were created from an explicit selection.
    """
    stats = (project_map or {}).get("stats") or {}
    if isinstance(stats.get("files"), int):
        return stats["files"]
    return len(run.get("scope") or [])


def _scope_label(run: dict, project_map: dict) -> str:
    """Describe the frozen scope in one line, for either generation of run record."""
    if str(run.get("scope_mode") or "explicit") == "snapshot":
        return f"上传项目整包快照，共 {_scope_files(run, project_map)} 个可读文件（含依赖目录与其它语言的文本文件）"
    return f"{_scope_files(run, project_map)} 个已冻结源码文件"


def _bounded_path_list(paths: list[str], limit: int = MAX_REPORTED_PATHS) -> str:
    """Inline at most ``limit`` paths; a whole snapshot's file list cannot fit in a report."""
    shown = "、".join(f"`{path}`" for path in paths[:limit]) or "—"
    if len(paths) > limit:
        shown += f"；其余 {len(paths) - limit} 个见 JSON 导出"
    return shown


def _recon_refs(refs: object, limit: int = 5) -> str:
    """Inline at most ``limit`` reconnaissance references, as path and line range."""
    items = [item for item in (refs or []) if isinstance(item, dict) and item.get("path")]
    shown = "；".join(
        f"`{item['path']}:{item.get('start_line', 1)}-{item.get('end_line', 1)}`"
        + (f"（{item['why']}）" if item.get("why") else "")
        for item in items[:limit]
    )
    if len(items) > limit:
        shown += f"；其余 {len(items) - limit} 条见事件日志"
    return shown or "—"


def _recon_areas(areas: object, limit: int = 5) -> str:
    """Inline at most ``limit`` reconnaissance layout areas, as path and role."""
    items = [item for item in (areas or []) if isinstance(item, dict) and item.get("path")]
    shown = "；".join(
        f"`{item['path']}`" + (f"（{item['role']}）" if item.get("role") else "")
        for item in items[:limit]
    )
    if len(items) > limit:
        shown += f"；其余 {len(items) - limit} 条见事件日志"
    return shown or "—"


def _md_cell(value: object) -> str:
    """One table cell: a pipe would end the row, and a newline would end the table."""
    return str(value if value not in (None, "") else "—").replace("|", "\\|").replace("\n", " ")


INVESTIGATION_KIND_LABELS = {
    "recon": "侦察简报",
    "navigation": "目录导航",
    "search": "代码检索",
}

INVESTIGATION_STATUS_LABELS = {
    "active": "有效",
    "superseded": "已被取代",
    "retracted": "已撤回",
}


def _investigation_block(investigations: dict) -> list[str]:
    """The pinned investigations, including the rows a later round replaced.

    Same boundary as the coverage table below it: a pinned answer is what the host handed
    the Planner, not a citation, and it stays out of the findings for the same reason.

    The superseded rows are printed on purpose.  Correcting an investigation leaves two
    rows behind, and a report that showed only the live one would make "this was
    investigated once and never questioned" and "this was investigated, then looked at
    again and changed its answer" read identically -- which is the whole thing the
    write-once pin exists to prevent.
    """
    records = list(investigations.get("recent") or [])
    total = int(investigations.get("total") or 0)
    if not records:
        return [
            "### 固定调查",
            "",
            "本次运行没有固定任何调查记录：Planner 与侦察要么没有发起调查，要么调查都没有产出可复用的答案。",
            "",
        ]
    by_status = investigations.get("by_status") or {}
    counts = "；".join(
        f"{INVESTIGATION_STATUS_LABELS.get(str(status), status)} {count}"
        for status, count in sorted(by_status.items())
    )
    doc = [
        "### 固定调查",
        "",
        "Planner 与侦察每完成一次调查，宿主都会把答案固定在库里：一次写入，正文此后不再改写。"
        "同一个话题再次被问到时直接返回原记录，而不是重新执行一遍；确需更正时先写下新记录，"
        "旧记录原文保留并标记为「已被取代」。这些记录是规划线索，与上面的覆盖统计一样不是 finding 证据。",
        "",
        f"共 {total} 条（{counts or '—'}）。",
        "",
        "| 话题 | 类型 | 工具 | 回合 | 版本 | 状态 | 覆盖的文件 | 固定于 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for record in records:
        doc.append(
            f"| {_md_cell(record.get('topic'))} | "
            f"{INVESTIGATION_KIND_LABELS.get(str(record.get('kind')), _md_cell(record.get('kind')))} | "
            f"`{_md_cell(record.get('tool'))}` | {_md_cell(record.get('round_no'))} | "
            f"{_md_cell(record.get('revision'))} | "
            f"{INVESTIGATION_STATUS_LABELS.get(str(record.get('status')), _md_cell(record.get('status')))} | "
            f"{_md_cell(_bounded_path_list(list(record.get('files_read') or []), limit=4))} | "
            f"{_md_cell(record.get('created_at'))} |"
        )
    doc.append("")
    if total > len(records):
        doc += [f"本节只列最近 {len(records)} 条；其余 {total - len(records)} 条见 JSON 导出。", ""]
    doc += _superseded_lines(records)
    return doc


def _superseded_lines(records: list[dict]) -> list[str]:
    """What replaced what, spelled out because the id alone says nothing to a reader."""
    replaced = [record for record in records if record.get("status") != "active"]
    if not replaced:
        return []
    known = {str(record.get("id")): record for record in records}
    doc = ["被取代或撤回的调查：", ""]
    for record in replaced:
        label = INVESTIGATION_STATUS_LABELS.get(str(record.get("status")), record.get("status"))
        line = f"- 「{_md_cell(record.get('topic'))}」（第 {record.get('round_no')} 回合，第 {record.get('revision')} 版）{label}"
        if record.get("reason"):
            line += f"：{_md_cell(record.get('reason'))}"
        successor = known.get(str(record.get("superseded_by") or ""))
        if successor is not None:
            line += (
                f"；由第 {successor.get('round_no')} 回合的第 {successor.get('revision')} 版"
                f"「{_md_cell(successor.get('topic'))}」接替"
            )
        elif record.get("superseded_by"):
            line += "；接替它的新记录不在本节列出的范围内"
        doc.append(line + "。")
    doc.append("")
    return doc


def _observation_block(observations: list[dict], investigations: dict | None = None) -> list[str]:
    """Render the host-computed navigation aids the Planner rounds were handed.

    Reading coverage and reconnaissance leads explain why a round dispatched what it
    did and why it eventually converged, so the report carries them.  The boundary is
    stated before the first number: neither is a source-backed finding, and a brief is
    a lead the workers still had to read for themselves.
    """
    investigations = investigations or {}
    doc = [
        "以下内容由宿主在每回合计算并记录，用于解释 Planner 的派发与收束判断；它们是导航线索，不是 finding 证据，也不构成安全结论。",
        "",
    ]
    if not observations and not investigations.get("recent"):
        return doc + ["本次运行没有覆盖统计或侦察记录。", ""]

    coverage = [item["payload"] for item in observations if item["kind"] == "planner_coverage_prepared"]
    if coverage:
        doc += [
            "### 读取覆盖",
            "",
            "| 回合 | 已读文本文件 | 覆盖率 | 含 finding 的文件 | 依赖树已读 | 未读的一线模块（前 3） |",
            "|---|---|---|---|---|---|",
        ]
        for payload in coverage:
            # The round stamps the envelope; the numbers the host computed are nested one
            # level down under `coverage`, which is the shape `plan_audit_frontier` emits.
            numbers = payload.get("coverage") or {}
            unread = [
                f"`{item.get('module')}`（{item.get('unread')}/{item.get('total')}）"
                for item in (numbers.get("unread_hot_modules") or [])[:3]
                if isinstance(item, dict)
            ]
            doc.append(
                f"| {payload.get('round', '—')} | "
                f"{numbers.get('files_read', 0)}/{numbers.get('files_total', 0)} | "
                f"{float(numbers.get('coverage_ratio') or 0) * 100:.1f}% | {numbers.get('files_with_findings', 0)} | "
                f"{numbers.get('dependency_tree_read', 0)}/{numbers.get('dependency_tree_total', 0)} | "
                f"{'、'.join(unread) or '—'} |"
            )
        doc.append("")

    doc += _investigation_block(investigations)

    brief_rounds = {
        item["payload"].get("round") for item in observations if item["kind"] == "recon_brief_prepared"
    }
    for item in observations:
        payload = item["payload"]
        round_no = payload.get("round", "—")
        if item["kind"] == "recon_brief_prepared":
            brief = payload.get("brief") or {}
            doc += [
                "",
                f"### 侦察简报（第 {round_no} 回合）",
                "",
                f"- 问题：{_cell(payload.get('question'))}",
                f"- 概要：{_cell(brief.get('summary'))}",
                f"- 布局：{_recon_areas(brief.get('layout'))}",
                f"- 入口候选：{_recon_refs(brief.get('entry_candidates'))}",
                f"- 数据存储：{_recon_refs(brief.get('data_stores'))}",
                f"- 安全边界：{_recon_refs(brief.get('security_boundaries'))}",
                f"- 首批阅读目标：{_recon_refs(brief.get('reading_plan'))}",
                f"- 实际读过的文件：{_bounded_path_list(list(brief.get('files_examined') or []), limit=10)}",
                f"- 未决问题：{'；'.join(str(text) for text in (brief.get('uncertainties') or [])[:4]) or '—'}",
                "",
            ]
        elif item["kind"] == "recon_skipped":
            doc.append(f"- 第 {round_no} 回合未进行侦察：`{payload.get('reason') or '—'}`。")
        elif item["kind"] == "recon_terminal" and (
            payload.get("reason") != "completed" or round_no not in brief_rounds
        ):
            doc.append(
                f"- 第 {round_no} 回合侦察未产出简报：`{payload.get('reason') or '—'}`"
                f"（{_cell(payload.get('error'))}）。该回合的规划只依据项目图与前序摘要。"
            )
    doc.append("")
    return doc


def _cell(value) -> object:
    """A metric that could not be computed, spelled out instead of printed as `None`.

    `summarise` stores None — not 0 — when the denominator is empty, so a bare dict lookup
    that finds the key still has nothing to print. `str(None)` in the middle of a metrics
    table reads as a rendering glitch, or worse, as a value; the report's own convention for
    "this was not computable" is 无法计算. Only None is replaced, so a genuine 0.0 survives.
    """
    return NOT_COMPUTABLE if value is None else value


def _evidence_text(evidence: list[dict]) -> str:
    if not evidence:
        return "（无行号引用）"
    return "、".join(f"`{item['path']}:{item['start_line']}-{item['end_line']}`" for item in evidence)


def _validation_text(finding: dict) -> str:
    """Say what actually happened to the citations, including the partial case."""
    problems = finding.get("validation_errors") or []
    if finding.get("validation_state") == "observation":
        return "排查依据（不作漏洞判定）"
    if finding.get("validation_state") == "invalid_finding":
        return "存在可核验引用，但未满足漏洞候选要求——" + "；".join(problems)
    if finding.get("validation_state") == "candidate":
        if not problems:
            return "通过"
        return "通过（但已剔除未通过校验的引用：" + "；".join(problems) + "）"
    return "未通过——" + ("；".join(problems) or "无可用引用")


# Standing is a third axis, beside the evidence check (did the citations hold up) and the
# automatic verification (does it reproduce in the isolated target).  A conclusion can be a
# well-evidenced candidate that the Planner later took back, and a verification result on it
# is not the Planner's to erase -- which is why ``rejected`` is not a withdrawal.  None of
# these states deletes anything: the row, its evidence, its archived revisions and its
# verification records all stay in the report, because "this run changed its mind" is itself
# a fact about the run.
DISPOSITION_LABELS = {
    "retracted": "已被 Planner 撤回",
    "duplicate": "被 Planner 判定为与另一条结论重复",
    "superseded": "已被后续结论取代",
    "contested": "历史存疑记录（旧版人工结论保留，本条结论按处置字段判定）",
}
DISPOSITION_BY_LABELS = {"planner": "Planner", "human": "人工（历史）"}
# An archived revision is a pointer back to what the run used to claim, not a second copy of
# the report; one paragraph per version is enough to see that the story changed.
ARCHIVED_SUMMARY_CHARS = 400


def _is_withdrawn(finding: dict) -> bool:
    return str(finding.get("disposition") or "open") in WITHDRAWN_FINDING_DISPOSITIONS


def _split_by_standing(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split conclusions into the ones that still stand and the ones taken back.

    A withdrawn conclusion is listed separately rather than dropped: it stops counting as
    something the run found, but a reader still needs to see it, both because the
    verification record it carries may outlive the withdrawal and because a run whose
    conclusions were quietly removed between rounds looks identical to a run that never had
    them.
    """
    return (
        [item for item in findings if not _is_withdrawn(item)],
        [item for item in findings if _is_withdrawn(item)],
    )


def _disposition_text(finding: dict) -> str:
    """How this conclusion's standing or its content changed; empty if neither did."""
    disposition = str(finding.get("disposition") or "open")
    revision = int(finding.get("revision") or 1)
    if disposition == "open" and revision <= 1:
        return ""
    parts: list[str] = []
    if disposition != "open":
        parts.append(DISPOSITION_LABELS.get(disposition, disposition))
        by = DISPOSITION_BY_LABELS.get(str(finding.get("disposition_by") or ""))
        if by:
            parts.append(f"由 {by} 标注")
        if finding.get("disposition_reason"):
            # The reason is a sentence a model or a person wrote, so it arrives with its own
            # full stop; joining it into a semicolon-separated line would double the mark.
            parts.append(f"理由：{str(finding['disposition_reason']).rstrip('。.')}")
        source = str(finding.get("derived_from_finding_id") or "")
        if source:
            parts.append(f"{'重复于' if disposition == 'duplicate' else '关联'} `{source[:8]}`")
    if revision > 1:
        parts.append(f"当前为第 {revision} 版，前 {revision - 1} 版的内容存档于下方")
    return "；".join(parts)


def _clip(text: str, limit: int = ARCHIVED_SUMMARY_CHARS) -> str:
    collapsed = " ".join(str(text or "").split())
    return collapsed if len(collapsed) <= limit else collapsed[:limit] + "……"


VERIFICATION_STATUS_LABELS = {
    "verified": "已验证",
    "rejected": "未通过",
    "inconclusive": "未决",
    "not_applicable": "不适用",
    "environment_unavailable": "环境不可用",
    "unverified": "未验证",
    "stale": "源码已变更",
}


def verification_status_label(value: object, verdict: object = "") -> str:
    """One status as the report writes it: a label, and the verdict when there is one."""
    status = str(value or "unverified")
    label = VERIFICATION_STATUS_LABELS.get(status, status)
    return f"{label}（{verdict}）" if verdict else label


def _finding_verification_label(finding: dict) -> str:
    status = str(finding.get("verification_status") or "unverified")
    verdict = finding.get("verification_verdict") or ""
    if status == "unverified" and not verdict:
        legacy = finding.get("verdict")
        return f"未自动验证（历史人工结论：{legacy}）" if legacy else "未自动验证"
    return verification_status_label(status, verdict)


def _verification_source(record: dict) -> str:
    return str(record.get("source") or "legacy_human")


def _automatic_verification_section(finding: dict, records: list[dict]) -> list[str]:
    """The POC agent's record: execution facts, not the model's prose alone."""
    lines = [
        "**自动验证记录**",
        "",
        "| 时间 | 状态 | 结论 | 目标 | 作业 | 说明 |",
        "|---|---|---|---|---|---|",
    ]
    for record in records:
        target = record.get("target") or {}
        target_text = " / ".join(
            part for part in (
                str(target.get("name") or ""),
                str(target.get("security") or ""),
                str(target.get("version") or ""),
            ) if part
        ) or "—"
        jobs = [str(item) for item in (record.get("agent") or {}).get("jobs") or []]
        lines.append(
            "| {created} | {status} | {verdict} | {target} | {jobs} | {notes} |".format(
                created=record.get("created_at") or "—",
                status=verification_status_label(record.get("status") or "unverified"),
                verdict=record.get("verdict") or "—",
                target=target_text.replace("|", "\\|"),
                jobs=("、".join(f"`{job}`" for job in jobs[:4]) or "—"),
                notes=(record.get("notes") or record.get("attack_observation") or "—").replace("|", "\\|").replace("\n", " "),
            )
        )
    lines.append("")
    for index, record in enumerate(records, 1):
        details = verification_details(finding, record)
        if details:
            lines += [f"第 {index} 条自动验证记录的补充说明：", ""] + details + [""]
    return lines


def _historical_verification_section(
    finding: dict, records: list[dict], *, legacy_labels: bool = False
) -> list[str]:
    """Human records kept read-only: the audit trail of an earlier process.

    ``legacy_labels`` reproduces the exact wording a historical (non-project) run's report
    was rendered with, so migrating the schema does not rewrite reports already exported.
    """
    if legacy_labels:
        heading = "**人工验证记录**"
        columns = "| 时间 | 执行状态 | 人工结论 | 命令 | 正常观测 | 攻击观测 |"
        details_prefix = "第 {index} 条验证记录的补充说明："
    else:
        heading = "**历史人工记录（只读）**"
        columns = "| 时间 | 执行状态 | 历史结论 | 命令 | 正常观测 | 攻击观测 |"
        details_prefix = "第 {index} 条历史记录的补充说明："
    lines = [
        heading,
        "",
        columns,
        "|---|---|---|---|---|---|",
    ]
    for record in records:
        lines.append(
            "| {created} | {status} | {verdict} | `{command}` | {normal} | {attack} |".format(
                created=record.get("created_at") or "—",
                status=record.get("execution_status") or "—",
                verdict=record.get("verdict") or "—",
                command=(record.get("command") or "—").replace("|", "\\|"),
                normal=(record.get("normal_observation") or "—").replace("|", "\\|"),
                attack=(record.get("attack_observation") or "—").replace("|", "\\|"),
            )
        )
    lines.append("")
    for index, record in enumerate(records, 1):
        details = verification_details(finding, record)
        if details:
            lines += [details_prefix.format(index=index), ""] + details + [""]
    return lines


def _verification_section(finding: dict, *, legacy_labels: bool = False) -> list[str]:
    records = list(finding.get("verifications") or [])
    automatic = [item for item in records if _verification_source(item) == "poc_agent"]
    historical = [item for item in records if _verification_source(item) != "poc_agent"]
    lines: list[str] = []
    if automatic and not legacy_labels:
        lines += _automatic_verification_section(finding, automatic)
    elif automatic:
        # A legacy run never produced automatic records; if one somehow carries them, the
        # old layout still lists them rather than dropping evidence on the floor.
        lines += _historical_verification_section(finding, automatic, legacy_labels=True)
    if historical:
        lines += _historical_verification_section(finding, historical, legacy_labels=legacy_labels)
    return lines


def _unverified_section(bundle: dict, findings: list[dict]) -> list[str]:
    """Say what was not checked, and that not-checked is not the same as absent."""
    pending = [
        item for item in findings
        if str(item.get("verification_status") or "unverified") != "verified"
    ]
    summary = bundle.get("verification_summary") or {}
    if not pending and not summary:
        return []
    counts = "；".join(
        f"{verification_status_label(name)} {summary[name]}"
        for name in ("verified", "rejected", "inconclusive", "not_applicable", "environment_unavailable", "unverified", "stale")
        if int(summary.get(name) or 0)
    )
    lines = ["**未验证与验证未通过的发现**", ""]
    lines.append(
        "自动验证覆盖情况：" + (counts or "尚无记录")
        + "。**未验证不等于排除**：它表示该结论还没有在隔离靶场中被实际执行，静态源码证据仍然成立。"
    )
    lines.append("")
    if pending:
        lines += ["| 发现 | 验证状态 | 说明 |", "|---|---|---|"]
        for item in pending:
            lines.append(
                "| {title} | {status} | {summary} |".format(
                    title=_md_cell(item.get("title")),
                    status=_md_cell(_finding_verification_label(item)),
                    summary=_md_cell(_pending_verification_reason(item)),
                )
            )
        lines.append("")
    return lines


def _pending_verification_reason(finding: dict) -> str:
    """Why this finding is not ``verified``, in the report's own words.

    The status already says it; the reason says what it means for the reader.  Collapsing
    every non-verified status into "not reproduced" would read a runner outage or a
    non-Lab30 target as evidence against the finding.
    """
    status = str(finding.get("verification_status") or "unverified")
    return {
        "rejected": "隔离靶场执行成功但未能复现；静态源码证据仍保留。",
        "inconclusive": "隔离靶场未能给出决定性结果。",
        "not_applicable": "目标不是受支持的 Lab30 商城环境，未执行自动验证。",
        "environment_unavailable": "隔离靶场不可用，未执行自动验证。",
        "stale": "源码或结论已变更，历史验证不再适用于当前版本。",
        "unverified": "尚未执行自动验证。",
    }.get(status, "尚未执行自动验证。")


def _carried_section(bundle: dict) -> list[str]:
    rows = bundle.get("carried_findings") or []
    if not rows:
        return []
    lines = [
        "### 项目既有发现（沿用）",
        "",
        "以下结论由同一项目的更早运行发现并记录，本次运行没有重新取证；它们不计入本次的新发现，"
        "但属于本项目已记录的漏洞面。标注为已验证的结论可直接支撑后续运行的收束。",
        "",
        "| 标题 | 位置 | 风险 | 项目版本 | 验证状态 | 原始运行 | 发现时间 |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        path = str(row.get("file_path") or "")
        symbol = str(row.get("symbol") or "")
        # Planner conclusions are filed under a sentinel symbol; it is an internal
        # identity key, not a location a reader should see.
        if symbol and symbol != PROJECT_SYMBOL:
            location = f"{path}:{symbol}" if path else symbol
        else:
            location = path or "—"
        lines.append(
            "| {title} | {path} | {severity} | {revision} | {status} | `{origin}` | {discovered} |".format(
                title=_md_cell(row.get("title")),
                path=_md_cell(location),
                severity=_md_cell(rating_text(row)),
                revision=row.get("run_relation_revision") or row.get("revision") or "—",
                status=_md_cell(verification_status_label(
                    row.get("verification_status"), row.get("verification_verdict")
                )),
                origin=row.get("origin_run_id") or row.get("last_run_id") or "—",
                discovered=row.get("discovered_at") or "—",
            )
        )
    lines.append("")
    return lines


def _narrative_sections(narrative: object) -> dict[str, list[str]]:
    """The Planner's prose, split by where the host renders it.

    The host never asks the model for counts: the narrative is placed beside facts the
    host computed, so a mistaken sentence cannot change what the report claims happened.
    """
    value = narrative if isinstance(narrative, dict) else {}
    summary = str(value.get("summary") or "").strip()
    conclusion = str(value.get("conclusion") or "").strip()
    limitations = [str(item).strip() for item in value.get("limitations") or [] if str(item).strip()]
    if not (summary or conclusion or limitations):
        return {"header": [], "conclusion": [], "limitations": []}
    header = [
        "## 结论摘要",
        "",
        "> 以下叙述由 Planner 生成，只总结本报告已列出的证据与验证结果，不构成新发现；"
        "统计、任务图与证据均由宿主从运行记录渲染。",
        "",
        summary or "—",
        "",
    ]
    conclusion_lines = ["**Planner 结论**", "", conclusion, ""] if conclusion else []
    limitation_lines: list[str] = []
    if limitations:
        limitation_lines = ["**Planner 声明的限制**", ""] + [f"- {item}" for item in limitations[:16]] + [""]
    return {"header": header, "conclusion": conclusion_lines, "limitations": limitation_lines}


def _archived_revision_lines(finding: dict) -> list[str]:
    """Show what earlier versions of this same conclusion claimed.

    Re-running a direction reuses its slot instead of replacing the row, so the earlier text
    is archived rather than lost.  Without it, a conclusion that changed its story between
    rounds -- quietly downgraded, narrowed to what the citations support, or withdrawn and
    then re-asserted -- would read exactly like one that always said this.
    """
    archived = finding.get("superseded_summary") or []
    if not isinstance(archived, list) or not archived:
        return []
    lines = ["**此前版本**", ""]
    for item in archived:
        if not isinstance(item, dict):
            continue
        label = f"第 {item.get('revision', '—')} 版"
        was = DISPOSITION_LABELS.get(str(item.get("disposition") or ""))
        header = f"- {label}（{item.get('replaced_at') or '—'} 被取代）"
        lines.append(f"{header}：{item.get('title') or '—'}")
        lines.append(f"  - 当时评级：{rating_text(item)}")
        lines.append(f"  - 当时的证据行号：{_evidence_text(item.get('evidence') or [])}")
        lines.append(
            "  - 当时的证据校验：" + ("通过" if item.get("validation_state") == "candidate" else "未通过")
        )
        if was:
            lines.append(
                f"  - 当时的处置：{was}（理由：{item.get('disposition_reason') or '—'}）"
            )
        if item.get("summary"):
            lines.append(f"  - 当时的判断依据：{_clip(item['summary'])}")
    lines.append("")
    return lines


def _standing_bullet(finding: dict) -> list[str]:
    """The 「结论状态」 bullet, or nothing when the conclusion is untouched."""
    text = _disposition_text(finding)
    return [f"- 结论状态：{text}"] if text else []


WITHDRAWN_HEADING = "### 已被 Planner 撤回 / 判为重复 / 存疑的结论（保留记录，不计入结论）"
WITHDRAWN_LEAD = (
    "下面这些结论的行、证据、存档版本与验证记录都保留着，只是不再计入本次运行的结论："
    "Planner 更正方向时把它们撤回了、判定为与另一条重复，或对已有历史人工结论的条目表示存疑。"
    "把它们从报告里删掉，会让「本次没有发现」和「本次把发现撤回了」看起来一模一样。"
)


def _withdrawn_section(withdrawn: list[dict], *, legacy_labels: bool = False) -> list[str]:
    """The third partition, rendered where a run can actually produce one."""
    if not withdrawn:
        return []
    doc = [WITHDRAWN_HEADING, "", WITHDRAWN_LEAD, ""]
    for index, finding in enumerate(withdrawn, 1):
        doc.extend(_finding_block(finding, index, legacy_labels=legacy_labels))
    return doc


def _finding_block(finding: dict, index: int, *, legacy_labels: bool = False) -> list[str]:
    if str(finding.get("category") or "").startswith("task_goal") or finding.get("finding_kind"):
        return _task_finding_block(finding, index, legacy_labels=legacy_labels)
    label = CATEGORY_LABELS.get(finding["category"], finding["category"])
    lines = [
        f"#### {index}. [{label}] {finding['title']}",
        "",
        f"- 风险等级：{rating_text(finding)}",
        f"- 证据行号：{_evidence_text(finding['evidence'])}",
        f"- 输入来源：{finding['input_source'] or '—'}",
        f"- 传播关系：{finding['propagation'] or '—'}",
        f"- 危险操作：{finding['dangerous_operation'] or '—'}",
        f"- 防护判断：{finding['protection'] or '—'}",
        f"- 触发前提：{'；'.join(finding['preconditions']) or '—'}",
        f"- 缺失信息：{'；'.join(finding['missing_context']) or '—'}",
        f"- 后端校验：{_validation_text(finding)}",
        f"- 自动验证结论：{_finding_verification_label(finding)}",
        *_standing_bullet(finding),
        "",
        "**判断依据**",
        "",
        finding["summary"] or "—",
        "",
    ]
    lines += rating_details_lines(finding)
    lines += _archived_revision_lines(finding)
    poc = finding.get("poc") or {}
    if poc:
        lines += [
            "**POC**",
            "",
            f"- 文件名：`{poc.get('filename', '—')}`",
            f"- 原始脚本：`evidence/{original_poc_name(finding, poc)}`（模型给出的原样版本，随证据包交付）",
            f"- 正常输入：`{poc.get('normal_input', '—')}`",
            f"- 攻击输入：`{poc.get('attack_input', '—')}`",
            f"- 预期结果：{poc.get('expected_result', '—')}",
            f"- 运行说明：{poc.get('instructions', '—')}",
            "",
            "```php",
            (poc.get("script") or "").rstrip(),
            "```",
            "",
        ]
    if finding["remediation"]:
        lines += ["**修复建议**", "", finding["remediation"], ""]
    if finding.get("verifications"):
        lines += _verification_section(finding, legacy_labels=legacy_labels)
    return lines


def _task_finding_block(finding: dict, index: int, *, legacy_labels: bool = False) -> list[str]:
    """Render a generic task result without inventing an attack-chain template."""
    kind = finding.get("finding_kind") or "source_observation"
    label = "漏洞候选" if is_vulnerability_finding(finding) else "排查记录"
    lines = [
        f"#### {index}. [{label} / {kind}] {finding['title']}",
        "",
        f"- 证据行号：{_evidence_text(finding.get('evidence') or [])}",
        f"- 证据校验：{_validation_text(finding)}",
        f"- 自动验证结论：{_finding_verification_label(finding)}",
        *_standing_bullet(finding),
    ]
    if finding.get("finding_kind") != "source_observation":
        lines.append(f"- 风险等级：{rating_text(finding)}")
    optional = (
        ("相关输入", finding.get("input_source")),
        ("数据或控制流", finding.get("propagation")),
        ("敏感操作", finding.get("dangerous_operation")),
        ("边界或防护", finding.get("protection")),
        ("前置条件", "；".join(finding.get("preconditions") or [])),
        ("缺失信息", "；".join(finding.get("missing_context") or [])),
    )
    lines.extend(f"- {label}：{value}" for label, value in optional if value)
    lines += ["", "**审计结论与依据**", "", finding.get("summary") or "—", ""]
    if is_vulnerability_finding(finding):
        lines += rating_details_lines(finding)
    lines += _archived_revision_lines(finding)
    poc = finding.get("poc") or {}
    if poc:
        lines += [
            "**POC（由 poc-runner 在隔离环境自动执行）**",
            "",
            f"- 文件名：`{poc.get('filename', '—')}`",
            f"- 原始脚本：`evidence/{original_poc_name(finding, poc)}`",
            f"- 运行说明：{poc.get('instructions', '—')}",
            "",
        ]
    if finding.get("remediation"):
        lines += ["**建议**", "", finding["remediation"], ""]
    if finding.get("verifications"):
        if legacy_labels:
            lines += _legacy_task_verification_lines(finding)
        else:
            lines += _verification_section(finding)
    return lines


def _legacy_task_verification_lines(finding: dict) -> list[str]:
    """The task-report verification tables exactly as historical exports wrote them."""
    records = list(finding.get("verifications") or [])
    if not records:
        return []
    poc = finding.get("poc") or {}
    if poc:
        lines = ["**POC 验证记录**", "", "| 时间 | 执行状态 | 人工结论 | 目标版本 | 说明 |", "|---|---|---|---|---|"]
        for record in records:
            lines.append(
                "| {created} | {status} | {verdict} | {version} | {notes} |".format(
                    created=record.get("created_at") or "—",
                    status=record.get("execution_status") or "—",
                    verdict=record.get("verdict") or "—",
                    version=(record.get("target_version") or "—").replace("|", "\\|"),
                    notes=(record.get("notes") or record.get("attack_observation") or "—").replace("|", "\\|"),
                )
            )
        lines.append("")
        return lines
    lines = ["**人工复核记录**", "", "| 时间 | 人工结论 | 复核环境或版本 | 说明 |", "|---|---|---|---|"]
    for record in records:
        lines.append(
            "| {created} | {verdict} | {version} | {notes} |".format(
                created=record.get("created_at") or "—",
                verdict=record.get("verdict") or "—",
                version=(record.get("target_version") or "—").replace("|", "\\|"),
                notes=(record.get("notes") or "—").replace("|", "\\|"),
            )
        )
    lines.append("")
    return lines


def _source_observation_section(bundle: dict, *, legacy_labels: bool = False) -> list[str]:
    records = bundle.get("source_observations") or []
    if not records:
        return []
    lines = [
        "### 排查记录（不计入漏洞）", "",
        f"共 {len(records)} 条源码观察、防护说明或待补充风险信息，保留为排查依据，不计入漏洞候选或漏洞确认数量，也不能据此判定整个项目安全。", "",
    ]
    findings = bundle.get("findings") or []
    if (bundle.get("run") or {}).get("status") == "completed" and not any(
        item.get("validation_state") == "candidate" and
        str(item.get("disposition") or "open") not in WITHDRAWN_FINDING_DISPOSITIONS
        for item in findings
    ):
        lines += ["本历史运行沿用原有达标状态；按当前漏洞口径，排查记录不能证明已发现漏洞。", ""]
    for index, record in enumerate(records, 1):
        lines.extend(_task_finding_block(record, index, legacy_labels=legacy_labels))
    return lines


def _partition_bundle(bundle: dict) -> dict:
    """Keep API and direct historical report exports on the same result boundary."""
    findings = bundle.get("findings") or []
    vulnerabilities, _ = partition_findings(findings)
    records = list(bundle.get("source_observations") or [])
    known_ids = {item.get("id") for item in records if item.get("id")}
    for record in source_observations(findings, bundle.get("tasks") or bundle.get("work_items") or []):
        if record.get("id") not in known_ids:
            records.append(record)
            known_ids.add(record.get("id"))
    return {**bundle, "findings": vulnerabilities, "source_observations": records}


def adapted_script_name(finding: dict, record: dict) -> str:
    """The name the adapted script travels under inside the evidence archive.

    Both the collector and the report need this string, and they must agree: a report that
    points the reader at a file the archive does not contain is worse than one that says
    nothing about it.
    """
    poc_name = safe_name((finding.get("poc") or {}).get("filename") or "poc.php")
    return f"{record['id'][:8]}-adapted-{poc_name}"


def original_poc_name(finding: dict, poc: dict) -> str:
    """The archive entry for the model's script exactly as the model wrote it.

    The collector and the report share this string. They used to disagree: the report printed
    only the script's own filename while the archive stored it under a finding-prefixed one,
    so the original POCs were in the bundle but unfindable from the report.
    """
    return f"poc_{finding['id'][:8]}_{safe_name(poc.get('filename') or 'poc.php')}"


def verification_details(finding: dict, record: dict) -> list[str]:
    """What the verification table cannot hold: environment, adaptation, attribution.

    The flow this module exists to demonstrate is preprocess → run → observe → attribute.
    A table cell fits the observation; the rest has to be printed beside it, or the exported
    report shows a verdict with no account of how the script reached it — and for reflected
    XSS, no trace that a browser ever ran the payload.
    """
    details: list[str] = []
    target = record.get("target") or {}
    if isinstance(target, dict) and target:
        described = " / ".join(
            part for part in (
                str(target.get("name") or ""),
                str(target.get("base_url") or ""),
                str(target.get("security") or ""),
                str(target.get("version") or ""),
            ) if part
        )
        if described:
            details.append(f"- 目标环境：{described}")
    if record.get("source") == "poc_agent":
        status = verification_status_label(record.get("status") or "unverified", record.get("verdict"))
        details.append(f"- 自动验证状态：{status}")
        jobs = [str(item) for item in (record.get("agent") or {}).get("jobs") or []]
        if jobs:
            details.append("- runner 作业：" + "、".join(f"`{job}`" for job in jobs[:8]))
        if record.get("command"):
            details.append(f"- 执行命令：`{record['command']}`")
    elif record.get("target_version"):
        details.append(f"- 目标环境：{record['target_version']}")
    if record.get("expected_result"):
        details.append(f"- 预期结果：{record['expected_result']}")
    if record.get("browser_execution"):
        details.append("- 浏览器执行证据：已提交（截图与日志见下方附件）")
    if record.get("modification_notes"):
        details.append(f"- 脚本适配与问题归因：{record['modification_notes']}")
    if record.get("modified_script"):
        # Bytes, not characters: the archive stores the encoded script, and the Chinese
        # comments make the two numbers differ enough that a reader checking one against
        # the other would think a file had gone missing.
        size = len(record["modified_script"].encode("utf-8"))
        details.append(
            f"- 适配后的脚本：`evidence/{adapted_script_name(finding, record)}`"
            f"（{size} 字节，随证据包交付）"
        )
    attachments = [item for item in (record.get("files") or []) if item.get("stored")]
    artifacts = [item for item in (record.get("artifacts") or []) if isinstance(item, dict) and item.get("path")]
    if attachments:
        listed = "、".join(f"`evidence/{item['stored']}`" for item in attachments)
        details.append(f"- 附件：{listed}")
    if artifacts:
        listed = "、".join(
            f"`evidence/{item['path']}`（sha256 `{str(item.get('sha256') or '')[:12]}…`）"
            for item in artifacts[:8]
        )
        details.append(f"- 运行产物：{listed}")
    if record.get("notes"):
        details.append(f"- 备注：{record['notes']}")
    return details


def _prompt_rounds(bundle: dict) -> list[str]:
    """The optimisation rounds: what changed, why, and what the numbers did.

    Two rounds are the point of the exercise (P0 → P1 → P2), and the comparison only means
    something under one snapshot, scope, model and set of budgets — so the comparability
    verdict is printed next to the table rather than left to the reader's memory.
    """
    run = bundle["run"]
    rounds = bundle.get("rounds") or {}
    prompts = {prompt["id"]: prompt for prompt in bundle.get("prompts") or []}
    entries = rounds.get("runs") or []
    if not entries:
        return []

    lines = ["#### 4.2.1 优化轮次与对比", ""]
    if not rounds.get("comparable", False):
        lines += [
            "**这些运行目前不可直接对比**，原因：" + "；".join(rounds.get("reasons") or ["未说明"]) + "。",
            "下表数字仅供定位，不能用来声称提示词改进。",
            "",
        ]
    lines += [
        "| Prompt 版本 | 状态 | 完成单元 | 可判定样本 | 候选数 | 已验证 | TP | FP | FN | TN | Precision | Recall |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    denominators: list[tuple[str, int | None]] = []
    for entry in entries:
        item = entry["run"]
        metrics = entry["metrics"]
        evaluation = metrics.get("evaluation") or {}
        unresolved = len(evaluation.get("unresolved") or [])
        resolvable = None if not evaluation else evaluation["eligible"] - unresolved
        denominators.append((item["prompt_id"], resolvable))
        shown = f"{_cell(resolvable)}" + (f"（未决 {unresolved}）" if unresolved else "")
        lines.append(
            f"| {item['prompt_label']}（`{item['prompt_id']}`） | {item['status']} | "
            f"{item.get('completed_units')}/{item.get('total_units')} | {shown} | {metrics['candidates']} | "
            f"{metrics['confirmed']} | {_cell(evaluation.get('TP'))} | {_cell(evaluation.get('FP'))} | "
            f"{_cell(evaluation.get('FN'))} | {_cell(evaluation.get('TN'))} | "
            f"{_cell(evaluation.get('precision'))} | {_cell(evaluation.get('recall'))} |"
        )
    lines.append("")
    # Precision and Recall are ratios, so two rounds that resolved different numbers of
    # samples are not comparable even when both print 1.0. Without this the reader sees TP
    # fall from 2 to 1 and reads it as "the prompt got worse", when what happened is that a
    # unit was left unfinished and its sample left the denominator.
    if len({value for _, value in denominators if value is not None}) > 1:
        lines += [
            "**各轮的可判定样本数不同**（"
            + "、".join(f"{pid}={_cell(value)}" for pid, value in denominators)
            + "），Precision 与 Recall 的分母因此不同，两个比值不能横向比较。"
            "样本没进矩阵的原因见 6.1（单元未完成）与 6.2（未决样本）："
            "完成单元数与可判定样本数要连起来读，否则轮次之间的差值会被当成提示词质量的差值。",
            "",
        ]
    for note in rounds.get("notes") or []:
        lines.append(f"- 注意：{note}")
    if rounds.get("notes"):
        lines.append("")

    # The running version's text is printed in full just above; repeating it here would
    # double the length of the chapter for no new information.
    others = [item for item in entries if item["run"]["prompt_id"] != run["prompt_id"]]
    for entry in others:
        item = entry["run"]
        prompt = prompts.get(item["prompt_id"]) or {}
        lines += [
            f"**{item['prompt_label']}**（`{item['prompt_id']}`，本轮未使用）",
            "",
            f"- 改动理由：{prompt.get('reason') or '—'}",
        ]
        issues = prompt.get("issues") or []
        lines.append(f"- 针对的问题：{'；'.join(issues) if issues else '—'}")
        if prompt.get("parent_id"):
            parent = prompts.get(prompt["parent_id"]) or {}
            lines.append(f"- 基于：{parent.get('label', prompt['parent_id'])}")
        lines += ["", "```text", (prompt.get("text") or "").rstrip(), "```", ""]
    return lines


def _defence_section(defence: dict | None) -> list[str]:
    """The defence rates behind this run's conclusions, and what was left out of them.

    A report that lists findings without saying how many conclusions its own validator
    rejected, or how many automatic verdicts a second agent contested, overstates itself.
    """
    if not defence or defence.get("score") is None:
        return []
    lines = [
        "### 防御与可信度评分",
        "",
        f"总分 **{defence['score']:.3f}**（按可用成分权重归一化，分母 {defence.get('denominator_weight')}）。",
        "",
        "| 成分 | 来源 | 权重 | 取值 | 说明 |",
        "|---|---|---:|---:|---|",
    ]
    for item in defence.get("components") or []:
        value = "缺失" if item.get("value") is None else f"{item['value']:.3f}"
        source = "本次运行" if item.get("source") == "run" else "基准实验"
        lines.append(
            f"| {_md_cell(item.get('label'))} | {source} | {item.get('weight')} | {value} "
            f"| {_md_cell(item.get('detail'))} |"
        )
    missing = defence.get("missing") or []
    if missing:
        lines += ["", f"未计入成分：{'、'.join(missing)}（缺失时不按 0 分代入）。"]
    benchmark = defence.get("benchmark") or {}
    if benchmark.get("experiment_id"):
        variants = "、".join(benchmark.get("variants") or []) or "未记录"
        lines += ["", f"基准来源：Prompt 对比实验 `{benchmark['experiment_id']}`（{variants}）。"]
    lines.append("")
    return lines


_CONTEXT_PHASE_LABELS = {
    "planner_explore": "规划取证", "planner_decision": "计划决策", "planner_publish": "提交计划",
    "planner_prepare": "准备规划", "recon_explore": "只读侦察", "task_prepare": "准备审计任务",
    "task_execute": "源码审计", "task_publish": "提交源码结论",
    "poc_prepare": "准备隔离靶场", "poc_execute": "POC 执行", "poc_conclude": "POC 结论",
}


def _seconds(value) -> str:
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return "—"
    return f"{seconds:.0f} 秒"


def _poc_statistics_section(run: dict) -> list[str]:
    """The host's own POC accounting, in the same object the page and JSON use.

    Kept separate from the model's narrative: host liveness, model waiting,
    experiment execution, publication and carried-over results are different facts
    and cannot be substituted for one another.
    """
    stats = ((run.get("execution_summary") or {}).get("poc_statistics")) or {}
    if not stats:
        return []
    model = stats.get("model") or {}
    host = stats.get("host") or {}
    experiments = stats.get("experiments") or {}
    conclusion = stats.get("conclusion") or {}
    recovery = stats.get("recovery") or {}
    continuation = stats.get("continuation") or {}
    waiting = model.get("waiting_seconds")
    lines = [
        "### POC 统计",
        "",
        "| 项目 | 事实 |",
        "|---|---|",
        f"| 模型请求 | {int(model.get('streams') or 0)} 次结束"
        f"{'，其中中断 ' + str(int(model.get('aborted') or 0)) + ' 次' if model.get('aborted') else ''}"
        f"；已接收 {_report_bytes(model.get('received_bytes'))} |",
        f"| 模型等待 | 最近一次响应已等待 {_seconds(waiting)}；首个事件 {_seconds(model.get('first_event_seconds'))} |",
        f"| 实验作业 | {int(experiments.get('jobs') or 0)} 次，累计 {_seconds((experiments.get('duration_ms') or 0) / 1000)}"
        f"；检查点 {int(experiments.get('checkpoints') or 0)} 次 |",
        f"| 重复/补证 | 重复实验被拒 {int(experiments.get('duplicates') or 0)} 次；补证继续 {int(experiments.get('supplements') or 0)} 次 |",
        f"| 恢复消耗 | 开始 {int(recovery.get('started') or 0)} 次、发布 {int(recovery.get('published') or 0)} 次，"
        f"共 {int(recovery.get('requests') or 0)} 个请求 |",
        f"| 发布 | 已发布 {int(conclusion.get('published') or 0)} 项；结论 "
        + ("、".join(f"{name} {count}" for name, count in sorted((conclusion.get('verdicts') or {}).items())) or "—")
        + " |",
        f"| 宿主心跳 | 最近心跳 {_seconds(host.get('heartbeat_age_seconds'))}前；心跳不代表模型有进展 |",
    ]
    if conclusion.get("unpublished_reason"):
        lines.append(f"| 尚未发布 | {_md_cell(str(conclusion['unpublished_reason']))} |")
    if continuation.get("inherited") or continuation.get("retested"):
        current_total = sum(int(count or 0) for count in (continuation.get("current_status") or {}).values())
        lines.append(
            f"| 沿用与本轮 | 沿用 {int(continuation.get('inherited') or 0)} 项（不构成本轮成果）；"
            f"本轮新增 {current_total} 项，其中复测 {int(continuation.get('retested') or 0)} 项 |")
    unfinished = stats.get("unfinished") or []
    if unfinished:
        lines += ["", f"未完成 {int(stats.get('unfinished_total') or 0)} 项，原因：", ""]
        for item in unfinished[:8]:
            lines.append(
                f"- {_md_cell(str(item.get('title') or item.get('finding_id') or '—'))}"
                f"（{_md_cell(str(item.get('state') or '—'))}）"
                + (f"：{_md_cell(str(item.get('reason')))}" if item.get("reason") else ""))
    lines += ["", f"{host.get('note') or ''} {model.get('note') or ''}".strip(), ""]
    return lines


def _report_bytes(value: object) -> str:
    try:
        size = int(value)
    except (TypeError, ValueError):
        return "—"
    if size <= 0:
        return "—"
    return f"{size / 1024:.1f} KiB" if size >= 1024 else f"{size} B"


def _context_section(run: dict) -> list[str]:
    """How close each phase came to the request ceiling, and what that cost.

    The ceiling is a host decision, not a provider one, so a run that ended because of it
    has to say which phase approached it and how much summarizing it took to stay under.
    Summaries are visibility only: they are never source evidence.
    """
    context = ((run.get("execution_summary") or {}).get("context")) or {}
    limit = int(context.get("history_bytes") or 0)
    if not limit:
        return []
    lines = [
        "### 上下文控制",
        "",
        "宿主按本次请求序列化后的 UTF-8 字节控制模型上下文；字节不等于 token。接近上限时，较早步骤会被模型摘要替代或按固定规则裁剪；摘要不是源码证据，不能作为发现证据或主定位。",
        "",
        "| 阶段 | 峰值请求 | 占上限 | 请求数 | 摘要请求 | 达到上限 |",
        "|---|---|---|---|---|---|",
    ]
    phases = context.get("phases") or {}
    for name in sorted(phases):
        entry = phases[name] or {}
        peak = int(entry.get("peak_request_bytes") or 0)
        share = f"{peak / limit:.0%}" if peak else "—"
        lines.append(
            f"| {_md_cell(_CONTEXT_PHASE_LABELS.get(name, name))} | {_report_bytes(peak)} | {share} "
            f"| {int(entry.get('requests') or 0)} | {int(entry.get('summary_requests') or 0)} "
            f"| {int(entry.get('limit_hits') or 0)} |"
        )
    if not phases:
        lines.append(
            f"| 全部阶段 | {_report_bytes(context.get('peak_request_bytes'))} | — | — "
            f"| {int(context.get('summary_requests') or 0)} | {int(context.get('limit_hits') or 0)} |"
        )
    sources = context.get("sources") or {}
    if sources:
        labels = {"history_bytes": "模型历史超过请求上限", "source_ledger": "已读源码账本超过上限",
                  "planner_pinned": "Planner 保护骨架超过上限"}
        lines += ["", "达到上限的位置：" + "；".join(
            f"{labels.get(name, name)} {count} 次" for name, count in sorted(sources.items())) + "。"]
    lines += [
        "",
        f"整次运行：摘要请求 {int(context.get('summary_requests') or 0)} 次、压缩 {int(context.get('compactions') or 0)} 次、"
        f"丢弃最旧步骤组 {int(context.get('dropped_groups') or 0)} 组；请求上限 {_report_bytes(limit)}。",
        "",
    ]
    return lines


def _render_legacy_task_markdown(bundle: dict) -> str:
    """Export a goal run as a general source-audit report.

    The legacy report is intentionally retained below for historical P0/P1/P2 records.
    A target task is a different product flow: it must not describe an uploaded project
    as a fixture or force every result through SQL/XSS/command-injection terminology.
    """
    run = bundle["run"]
    task = run.get("task_spec") or {}
    metrics = bundle["metrics"]
    findings = bundle.get("findings") or []
    goals = bundle.get("goals") or []
    work_items = bundle.get("work_items") or []
    goal = goals[0] if goals else {}
    # Standing is partitioned out first, so no withdrawn conclusion can be counted as
    # something this run found, whatever its evidence check said.
    standing, withdrawn = _split_by_standing(findings)
    candidates = [item for item in standing if item.get("validation_state") == "candidate"]
    rejected = [item for item in standing if item.get("validation_state") != "candidate"]
    state_counts: dict[str, int] = {}
    for item in work_items:
        state = str(item.get("state") or "unknown")
        state_counts[state] = state_counts.get(state, 0) + 1
    terminal_labels = {
        "completed": "已达成",
        "unreachable": "不可达",
        "inconclusive": "未决",
        "cancelled": "已取消",
        "interrupted": "已中断",
        "failed": "失败",
    }
    goal_status = terminal_labels.get(run.get("status"), str(run.get("status") or "—"))
    poc_rule = (
        "达成结果要求附带可人工复核的 POC；缺少 POC 的 achieved 输出会被要求纠正，不能达成目标。"
        if task.get("require_poc")
        else "本任务不强制漏洞候选附带 POC；安全防护和普通源码事实只保留为排查记录，不构成漏洞发现。"
    )
    doc: list[str] = [
        "# 项目源码目标审计报告",
        "",
        f"- 运行 ID：`{run['id']}`",
        f"- 源码快照：{run['snapshot_name']}（`{run['snapshot_id']}`）",
        f"- 运行状态：{goal_status}（`{run.get('status')}`）",
        f"- 模型：`{run['model']}`",
        f"- 范围：{_scope_label(run, bundle.get('project_map') or {})}",
        f"- 预算：每项 {run['budgets'].get('responses')} 次模型响应 / {run['budgets'].get('tools')} 次工具调用 / {run['budgets'].get('seconds')} 秒",
        f"- 生成时间：{bundle.get('generated_at') or datetime.now(timezone.utc).isoformat()}",
        "",
        "---",
        "",
        "## 1. 任务概述与边界",
        "",
        "本次为自定义目标任务。它不套用固定 SQL 注入 / XSS / 命令注入真值矩阵，也不把未完成的工作项解释为否定结论。",
        "",
        f"- 目标：{task.get('objective', '—')}",
        f"- 验收条件：{task.get('success_criteria', '—')}",
        f"- 每项最大轮次：{task.get('max_iterations', '—')} 次",
        f"- 任务总尝试上限：{task.get('max_total_attempts', '—')} 次并由所有 worker 共享",
        f"- 并发 worker 上限：{task.get('max_workers', '—')} 个",
        f"- 达成后停止：{'是' if task.get('stop_on_achieved') else '否'}",
        f"- POC 策略：{poc_rule}",
        "",
        # A whole-snapshot run freezes no path list at all, so the label is the only
        # accurate description; a historical explicit-scope run still lists its files.
        "范围内文件：" + (
            _bounded_path_list(list(run.get("scope") or []))
            or _scope_label(run, bundle.get("project_map") or {})
        ),
        "",
        "## 2. 执行方法与可追溯性",
        "",
        "任务先将上传项目的源码建立不可变快照。PHP 文件另有 tree-sitter 语法索引，"
        "其它语言按纯文本行索引；再由目标任务协调器把工作单元排入持久化队列。"
        "队列按目标文本中出现的文件路径和代码标识进行稳定排序，不使用固定三类漏洞的危险 API 优先级。",
        "",
        "worker 仅使用 `read_source`、`search_code`、`get_context` 三个只读工具，并受冻结范围约束。"
        "每次工具调用、结果状态、已读源码范围、worker、尝试轮次和用量都会先持久化，再通过 SSE 推送。",
        "",
        "模型输出的 reasoning 是简短、证据化的审计依据摘要，不保存或展示模型的隐藏思维链、供应商 thinking 内容或完整提示词。",
        "",
        "## 3. 目标协调与 worker 执行",
        "",
        "```mermaid",
        "flowchart LR",
        "  A[上传项目源码 ZIP] --> B[不可变快照与索引]",
        "  B --> C[目标排序与持久化工作队列]",
        "  C --> D[并发源码 worker]",
        "  D --> E[工具轨迹与审计依据摘要]",
        "  E --> F[证据校验与目标收束]",
        "  F --> G[结果与证据包]",
        "```",
        "",
        f"协调器目标状态：`{goal.get('status', '—')}`；累计尝试：{goal.get('attempts', 0)}/{goal.get('max_total_attempts', task.get('max_total_attempts', '—'))}；终止原因：{goal.get('terminal_reason') or '—'}。",
        "",
        "工作项状态：" + ("；".join(f"{name} {count}" for name, count in sorted(state_counts.items())) or "尚未建立"),
        "",
        "| 工作项 | 状态 | 轮次 | 最近结论 |",
        "|---|---|---|---|",
    ]
    for item in work_items:
        result = item.get("result") or {}
        doc.append(
            f"| {str(item.get('summary') or item.get('id') or '—').replace('|', '\\|')} | "
            f"{item.get('state', '—')} | {item.get('attempt', 0)}/{item.get('max_attempts', '—')} | "
            f"{str(result.get('summary') or item.get('error') or '—').replace('|', '\\|')} |"
        )
    if not work_items:
        doc.append("| — | — | — | 尚未创建 |")
    withdrawn_note = (
        f"另有 {len(withdrawn)} 条结论已被 Planner 撤回、判为重复或存疑，"
        "单列于本节末尾，不计入上面的数字；"
        if withdrawn
        else ""
    )
    doc += [
        "",
        "## 4. 审计结果与源码证据",
        "",
        f"已通过证据校验的目标发现：{len(candidates)} 条；未通过证据校验的记录：{len(rejected)} 条；"
        f"{withdrawn_note}"
        f"审计覆盖：{metrics.get('audit_coverage', 0)}。",
        "",
    ]
    if standing:
        for index, finding in enumerate(standing, 1):
            doc.extend(_finding_block(finding, index, legacy_labels=True))
    elif not withdrawn:
        doc += ["本次没有保存目标发现。请结合第 3 节的工作项状态和执行轨迹判断这是不可达、未决还是尚未开始。", ""]
    doc += _withdrawn_section(withdrawn, legacy_labels=True)
    doc += _source_observation_section(bundle, legacy_labels=True)
    doc += [
        "## 5. 结论限制与后续动作",
        "",
        "`unreachable` 仅表示所有已规划工作项在冻结范围内正常完成或耗尽次数，且没有上下文、模型或预算受阻项时仍未满足验收条件。"
        "运行时配置、动态 include、外部服务、超时、取消和中断都会保留为 `inconclusive`、`cancelled` 或 `interrupted`，不构成不存在的结论。",
        "",
        "源码切片和静态上下文不是完整调用图。对需要运行时验证的结果，应在授权环境中记录环境版本、对照输入、观测和附件；没有 POC 的源码结论通过书面人工复核确认或驳回。POC 只作为待验证工件，不会被本系统执行。",
        "",
        "## 6. 导出与复核",
        "",
        "本报告、`result.json` 与证据包共同包含冻结配置、工作项尝试历史、发现、人工复核记录和可复算统计。"
        "打开工作台的“执行轨迹”页可按源码单元、worker 和轮次展开工具调用及模型生成的审计依据摘要。",
        "",
    ]
    return "\n".join(doc)


def _render_task_markdown(bundle: dict) -> str:
    """Render the Planner-led audit report without reviving the old file queue."""
    run = bundle["run"]
    task = run.get("task_spec") or {}
    goal = bundle.get("goal") or next(iter(bundle.get("goals") or []), {})
    planner = bundle.get("planner") or {}
    project_map = bundle.get("project_map") or {}
    plans = bundle.get("plans") or []
    tasks = bundle.get("tasks") or []
    findings = bundle.get("findings") or []
    metrics = bundle.get("metrics") or {}
    # A conclusion the Planner took back stops counting as something this run found, but it
    # is still listed: the withdrawal is part of the run's record, not a reason to hide it.
    standing, withdrawn = _split_by_standing(findings)
    candidates = [item for item in standing if item.get("validation_state") == "candidate"]
    invalid = [item for item in standing if item.get("validation_state") != "candidate"]
    counts: dict[str, int] = {}
    for item in tasks:
        state = str(item.get("state") or "unknown")
        counts[state] = counts.get(state, 0) + 1

    def cell(value: object) -> str:
        return str(value or "—").replace("|", "\\|").replace("\n", " ")

    def task_source(item: dict) -> str:
        context = item.get("context_spec") or {}
        refs = context.get("source_refs") if isinstance(context, dict) else []
        rendered = []
        for ref in refs or []:
            if isinstance(ref, dict) and ref.get("path"):
                rendered.append(f"`{ref['path']}:{ref.get('start_line', 1)}-{ref.get('end_line', 1)}`")
        symbols = context.get("target_symbols") if isinstance(context, dict) else []
        if symbols:
            rendered.append("符号：" + "、".join(f"`{name}`" for name in symbols[:4]))
        scope_paths = context.get("scope_paths") if isinstance(context, dict) else []
        if scope_paths:
            rendered.append("范围：" + "、".join(f"`{path}`" for path in scope_paths[:6]))
        return "；".join(rendered) or "由项目图和 worker 工具补读确定"

    terminal_labels = {
        "completed": "已达成", "unreachable": "不可达", "inconclusive": "未决",
        "cancelled": "已取消", "interrupted": "已中断", "failed": "失败", "running": "执行中", "pending": "等待执行",
    }
    state_label = terminal_labels.get(str(run.get("status")), str(run.get("status") or "—"))
    poc_rule = (
        "严格模式：目标只能以 POC Agent 在隔离靶场中实际复现的结论收束。"
        if task.get("require_poc")
        else "非严格模式：未验证的结论仍可收束，但被自动验证判为未通过的结论不算；安全防护和普通源码事实只保留为排查记录。"
    )
    map_stats = project_map.get("stats") or {}
    doc: list[str] = [
        "# 项目级白盒审计报告",
        "",
        f"- 运行 ID：`{run['id']}`",
        f"- 源码快照：{run['snapshot_name']}（`{run['snapshot_id']}`）",
        f"- 状态：{state_label}（`{run.get('status')}`）",
        f"- 模型：`{run['model']}`",
        f"- 冻结范围：{_scope_label(run, project_map)}",
        f"- 预算：每个 Planner/worker 回合最多 {run['budgets'].get('responses')} 次模型响应、{run['budgets'].get('tools')} 次工具调用、{run['budgets'].get('seconds')} 秒",
        f"- 生成时间：{bundle.get('generated_at') or datetime.now(timezone.utc).isoformat()}",
        "",
    ]
    narrative = _narrative_sections(bundle.get("report_narrative"))
    doc += narrative["header"]
    doc += [
        "## 1. 目标与判定边界",
        "",
        f"- 审计目标：{task.get('objective', '—')}",
        f"- 验收条件：{task.get('success_criteria', '—')}",
        f"- 每个动态任务最大尝试：{task.get('max_iterations', '—')} 次",
        f"- 所有 worker 共享尝试上限：{task.get('max_total_attempts', '—')} 次",
        f"- Planner 回合上限：{task.get('max_planner_rounds', planner.get('max_rounds', '—'))} 次；并发 worker 上限：{task.get('max_workers', '—')} 个",
        f"- 达成后停止：{'是' if task.get('stop_on_achieved', True) else '否'}；POC 策略：{poc_rule}",
        f"- 目标状态：`{goal.get('status', '—')}`；累计 worker 尝试：{goal.get('attempts', 0)}/{goal.get('max_total_attempts', task.get('max_total_attempts', '—'))}；终止依据：{goal.get('terminal_reason') or '—'}",
        "",
        "`unreachable` 只表示已经由 Planner 列入前沿的证据方向全部结算、没有受阻上下文，且仍未满足验收条件。共享尝试或 Planner 回合耗尽、动态依赖、运行时配置缺失、取消和模型故障都保留为未决或中断，不构成否定结论。",
        "",
        "## 2. 项目图与执行模型",
        "",
        f"项目图冻结时记录：{map_stats.get('files', 0)} 个文件、{map_stats.get('symbols', 0)} 个符号、{map_stats.get('includes', 0)} 条静态 include 关系、{map_stats.get('calls', 0)} 个调用点、{map_stats.get('entrypoints', 0)} 个高置信入口候选；另有 {map_stats.get('low_confidence_roots', 0)} 个未解析静态根和 {map_stats.get('unresolved_includes', 0)} 条未解析 include 关系，均不等同于路由事实。",
        "",
        "```mermaid",
        "flowchart LR",
        "  A[项目源码 ZIP] --> B[不可变快照与项目图]",
        "  B --> C[主 Planner: 目标/项目图/反馈]",
        "  C --> D[动态跨文件任务图]",
        "  D --> E[并发 worker: 只读源码工具]",
        "  E --> F[证据校验与反馈]",
        "  F --> C",
        "  F --> G[目标收束与报告]",
        "```",
        "",
        "主 Planner 只使用项目图和已持久化的 worker 摘要来决定下一批跨文件方向；worker 仍必须通过 `read_source`、`search_code` 等只读工具读取原始源码行，才能形成可引用发现。依赖完成后的摘要会交接给后续任务，worker 也可检索其他 worker 的受限工具轨迹作为线索；二者都不是证据，不能替代本任务实际读取的源码行号。规划依据和 worker 审计依据均为简短、可复核摘要；不保存或展示隐藏思维链。",
        "",
    ]
    doc += _context_section(run)
    doc += _poc_statistics_section(run)
    doc += [
        "## 3. Planner 回合",
        "",
        "| 回合 | 版本 | 状态 | 建立依据摘要 | 下一步 | 任务数 |",
        "|---|---|---|---|---|---|",
    ]
    for plan in plans:
        snapshot = plan.get("task_snapshot") or []
        doc.append(
            f"| {plan.get('round_no', '—')} | {plan.get('revision', '—')} | {cell(plan.get('status'))} | "
            f"{cell(plan.get('basis_summary'))} | {cell(plan.get('next_action'))} | {len(snapshot)} |"
        )
    if not plans:
        doc.append("| — | — | 尚未开始 | — | — | 0 |")
    doc += [
        "",
        "## 4. 动态任务图与 worker 反馈",
        "",
        "任务状态：" + ("；".join(f"{name} {count}" for name, count in sorted(counts.items())) or "尚未建立"),
        "",
        "| 任务 | 状态 | 尝试 | 依赖 | 初始跨文件上下文 | 最近结果 |",
        "|---|---|---|---|---|---|",
    ]
    for item in tasks:
        result = item.get("result") or {}
        dependencies = "、".join(item.get("dependencies") or []) or "—"
        doc.append(
            f"| {cell(item.get('title') or item.get('task_key'))}（`{item.get('task_key', '—')}`） | "
            f"{cell(item.get('state'))} | {item.get('attempts', 0)}/{item.get('max_attempts', '—')} | "
            f"{cell(dependencies)} | {cell(task_source(item))} | {cell(result.get('summary') or item.get('error'))} |"
        )
        history = item.get("attempt_history") or []
        for attempt in history:
            attempt_result = attempt.get("result") or {}
            rationale = attempt_result.get("reasoning") or ""
            if rationale:
                doc.append(f"> `{item.get('task_key', '—')}` 第 {attempt.get('attempt', '—')} 次依据摘要：{rationale}")
    if not tasks:
        doc.append("| — | — | — | — | — | 尚无任务 |")
    withdrawn_note = (
        f"已被 Planner 撤回、判为重复或存疑的结论：{len(withdrawn)}（单列于本节末尾，不计入上面两项）；"
        if withdrawn
        else ""
    )
    doc += [
        "",
        "## 5. 发现与源码证据",
        "",
        f"证据校验通过的发现：{len(candidates)}；校验未通过的记录：{len(invalid)}；"
        f"{withdrawn_note}动态任务前沿结算进度：{metrics.get('task_coverage', 0)}。",
        "",
    ]
    doc += narrative["conclusion"]
    if standing:
        for index, finding in enumerate(standing, 1):
            doc.extend(_finding_block(finding, index))
    elif not withdrawn:
        doc += ["尚无已保存的源码发现。请结合 Planner 回合、任务状态与缺失上下文判断当前结果。", ""]
    doc += _unverified_section(bundle, candidates)
    doc += _carried_section(bundle)
    doc += _withdrawn_section(withdrawn)
    doc += _source_observation_section(bundle)
    doc += _defence_section(bundle.get("defence"))
    doc += ["## 6. 覆盖统计、固定调查与侦察简报", ""]
    doc.extend(
        _observation_block(bundle.get("observations") or [], bundle.get("investigations") or {})
    )
    doc += [
        "## 7. 可追溯性与后续复核",
        "",
        "每轮 Planner 决策、任务创建/更新、依赖交接、worker 领取、工具调用、返回摘要、已读源码范围和尝试结果都先写入 SQLite 事件日志，再通过 SSE 推送。工作台的执行轨迹可按 Planner、worker、任务和尝试展开查看。",
        "",
        "POC 由独立 POC Agent 在隔离的 `poc-runner` 容器中对本地 Lab30 商城靶场执行；审计主进程不执行任何上传源码或 POC 脚本。"
        "对运行时依赖、动态路由、反射、动态 include 或外部服务产生的缺失信息，应结合自动验证记录与缺失上下文补充，"
        "而不是将其解释为不存在。",
        "",
    ]
    if narrative["limitations"]:
        doc += narrative["limitations"]
    elif not narrative["header"]:
        doc += ["本次运行未产出 Planner 叙述；以上结论均由宿主按运行记录渲染。", ""]
    return "\n".join(doc)


def render_markdown(bundle: dict) -> str:
    facts = bundle.get("final_review")
    if facts:
        # New runs deliver the versioned final-review facts: seven fixed sections rendered
        # only from those facts, so page, Markdown, JSON and the evidence package cannot
        # drift. Old runs keep their historical layout because no facts are attached.
        from .report_final import render_final_report
        return bundle.get("report_markdown") or render_final_report(facts)
    host = bundle.get("run", {}).get("final_summary")
    if host:
        from .report_facts import render_host_summary
        # The frozen host summary is the narrative the model wrote at finalize time; the
        # defence score is computed from the run's own records, so it is appended by the
        # renderer instead of being frozen into that text.
        return "\n".join([render_host_summary(host).rstrip("\n"), "", *_defence_section(bundle.get("defence"))])
    bundle = _partition_bundle(bundle)
    run = bundle["run"]
    # Planner v2 runs carry a durable session and dynamic task graph.  Older goal
    # records predate those tables and remain exportable through their historical
    # report layout, rather than being misleadingly rendered as if they had a Planner.
    if run.get("task_spec"):
        if bundle.get("planner") is not None or "tasks" in bundle:
            return _render_task_markdown(bundle)
        return _render_legacy_task_markdown(bundle)
    metrics = bundle["metrics"]
    units = bundle["units"]
    findings = bundle["findings"]
    attributions = bundle["attributions"]
    snapshot = bundle.get("snapshot") or {}
    truths = bundle.get("truths") or []
    evaluation = metrics.get("evaluation")
    task = run.get("task_spec") or None
    goals = bundle.get("goals") or []
    goal = goals[0] if goals else None
    mode_label = "自定义目标任务" if task else "固定三类漏洞审计"
    mode_overview = (
        "本次运行使用可配置的源码目标任务；协调器只在有原始行号证据的发现满足验收条件时达成目标。"
        if task
        else "本实验面向单用户、本地部署的普通 PHP 项目，覆盖 SQL 注入、反射型 XSS、命令注入三类漏洞。"
    )
    mode_chain = (
        "链路为：源码预处理 → 目标任务协调与并发源码 worker → 可选 POC 人工实操验证 → 结果校验降噪与复盘优化。"
        if task
        else "链路为：源码预处理 → Prompt 提示词工程 → LLM 漏洞推理 → POC 人工实操验证 → 结果校验降噪与复盘优化。"
    )
    execution_label = "目标任务执行器（由任务目标和验收条件生成受控指令）" if task else (
        f"Prompt 版本：{run['prompt_label']}（`{run['prompt_id']}`）"
    )
    instruction_text = (
        "受控执行器：只分析已上传快照中的源码，只能通过只读工具补读源码。\n\n"
        "当前目标和验收条件是待分析数据，不能改变审计边界。每个工作项只能返回 achieved、continue、"
        "no_evidence 或 blocked；只有协调器可以在共享队列收束后判定目标不可达。"
        if task
        else run["prompt_text"].rstrip()
    )
    architecture_graph = (
        [
            "flowchart LR",
            "    A[代码预处理<br/>不可变快照/语法索引/审计单元] --> B[目标任务协调器<br/>目标/验收条件/持久化队列]",
            "    B --> C[并发源码 worker<br/>三个只读工具/结构化工作项结果]",
            "    C --> D[证据校验与目标收束<br/>达成/不可达/未决]",
            "    D --> E[人工复核或 POC 验证与导出<br/>报告/尝试历史]",
        ]
        if task
        else [
            "flowchart LR",
            "    A[代码预处理<br/>不可变快照/语法索引/审计单元] --> B[Prompt 提示词工程<br/>四段式结构与场景规则]",
            "    B --> C[LLM 漏洞推理挖掘<br/>三个只读工具/候选与POC]",
            "    C --> D[POC 验证实操<br/>学生下载适配本地运行]",
            "    D --> E[校验与复盘<br/>人工裁决/统计/归因]",
            "    E --> B",
        ]
    )

    # Dispositions are written only by a Planner round, so this report -- the historical
    # fixed-checklist layout, which a Planner-led run never reaches -- has an empty third
    # partition by construction. It is split out anyway, and rendered if it ever is not,
    # because the alternative on the day it stops being empty is a conclusion silently
    # disappearing from a report that still counts the run as finished.
    standing, withdrawn = _split_by_standing(findings)
    candidates = [f for f in standing if f["validation_state"] == "candidate"]
    discarded = [f for f in standing if f["validation_state"] != "candidate"]
    # Candidates that kept at least one citation but had others thrown out: the count is
    # the honest measure of how often the model points at code it has not actually read.
    partially_cited = [f for f in candidates if f.get("validation_errors")]
    incomplete = [u for u in units if u["status"] in ("incomplete", "failed", "skipped")]
    truncated = [
        u for u in units
        if u["status"] == "completed" and (u.get("result") or {}).get("exploration_incomplete")
    ]
    settlement_failed = [
        (unit, match.group(1))
        for unit in incomplete
        if (match := SETTLEMENT_FAILURE.search(unit.get("error") or ""))
    ]

    doc: list[str] = [
        "# 基于 LLM 辅助的 PHP 白盒漏洞挖掘实验报告",
        "",
        f"- 运行 ID：`{run['id']}`",
        f"- 快照：{run['snapshot_name']}（`{run['snapshot_id']}`）",
        f"- 执行器：{execution_label}",
        f"- 模型：`{run['model']}`",
        f"- 运行模式：{mode_label}",
        f"- 预算：{run['budgets'].get('responses')} 次模型响应 / {run['budgets'].get('tools')} 次工具调用 / {run['budgets'].get('seconds')} 秒",
        f"- 运行状态：{run['status']}",
        # From the bundle, not from the clock: the JSON export carries `generated_at`, and
        # the Markdown inside the evidence archive is rendered separately from the one
        # served over HTTP. Stamping each render with its own `now()` made two exports of
        # the same run differ, which is exactly what "统计可由导出数据复算" rules out.
        f"- 生成时间：{bundle.get('generated_at') or datetime.now(timezone.utc).isoformat()}",
        f"- 工具版本：v{VERSION}",
        "",
        "---",
        "",
        "## 1. 实验概述（目的、背景、实验边界）",
        "",
        mode_overview,
        mode_chain,
        "",
        f"- 待审计代码来源：{snapshot.get('source', run.get('snapshot_id'))}，归档哈希 `{snapshot.get('archive_sha256', '—')}`。",
        f"- 审计范围（运行开始后冻结，共 {_scope_files(run, bundle.get('project_map') or {})} 个文件）：",
        "",
    ]
    frozen_scope = list(run.get("scope") or [])
    for path in frozen_scope[:MAX_REPORTED_PATHS]:
        doc.append(f"  - `{path}`")
    if len(frozen_scope) > MAX_REPORTED_PATHS:
        doc.append(f"  - 其余 {len(frozen_scope) - MAX_REPORTED_PATHS} 个文件见 JSON 导出")
    if task:
        doc += [
            "",
            "- 目标任务配置：",
            f"  - 目标：{task.get('objective', '—')}",
            f"  - 验收条件：{task.get('success_criteria', '—')}",
            f"  - 每项最大轮次：{task.get('max_iterations', '—')}；任务总尝试上限：{task.get('max_total_attempts', '—')}；worker 上限：{task.get('max_workers', '—')}；达成后停止：{task.get('stop_on_achieved', True)}；达成时要求 POC：{task.get('require_poc', True)}。",
        ]
        if goal:
            doc.append(
                f"  - 目标状态：{goal.get('status', '—')}；累计尝试：{goal.get('attempts', 0)}；"
                f"终止原因：{goal.get('terminal_reason') or '—'}。"
            )
    doc += [
        "",
        f"- 审计单元总数：{metrics['total_units']}，其中完成 {metrics['completed_units']} 个，未完成 {metrics['incomplete_units']} 个。",
        "",
        "> 边界说明：历史固定样本只用于检验实验流程，不能据此宣称对未知 PHP 项目的检测能力。",
        "",
        "## 2. 传统漏洞挖掘与 LLM 辅助漏洞挖掘技术对比",
        "",
        "| 维度 | 传统源码审计/扫描器 | 本实验的 LLM 辅助方式 |",
        "|---|---|---|",
        "| 输入 | 全量源码或流量 | 固定清单切分后的审计单元 + 三个只读工具按需补读 |",
        "| 覆盖判定 | 规则/词法命中 | 全部函数、方法与顶层脚本均生成单元，危险 API 命中只影响排序 |",
        "| 输出 | 告警列表 | 候选漏洞 + 行号证据 + 传播关系 + 可运行 POC + 修复建议 |",
        "| 误报处理 | 人工逐条确认 | 后端证据校验 + 人工 POC 实操双层复筛 |",
        "| 结论来源 | 工具规则 | 模型候选与人工结论分别记录，人工结论为最终判据 |",
        "",
        f"本次未接入 Burp/AWVS 等传统扫描器做同场对照，因此对比表的实测数据为{NOT_MEASURED}。",
        "",
        "## 3. 系统总体架构（架构图 + 数据流向）",
        "",
        "### 3.1 架构图",
        "",
        "```mermaid",
        *architecture_graph,
        "```",
        "",
        "### 3.2 数据流向",
        "",
        "数据流：上传 ZIP → 生成不可变快照与语法索引 → 按函数/方法/顶层脚本切分审计单元（含切片规则与遗漏记录）",
        (
            "→ 用户选定范围并创建目标任务（范围、目标、验收条件与工作队列在此冻结）"
            "→ 协调器让多个 worker 原子领取源码工作项"
            if task
            else "→ 用户选定范围并创建运行（范围与 Prompt 全文在此冻结）→ 后台单 worker 逐个单元执行"
        ),
        "→ 事件先写 SQLite 再推送 SSE → 候选经证据校验后落库 → 人工上传验证记录 → 统计与导出。",
        "",
        (
            "目标任务的工作队列在运行开始后冻结；worker 可补读依赖代码，却不能扩大主审计范围。"
            "每次尝试、worker 身份、用量和已读行号均追加保存；只有队列排空才判为不可达。"
            if task
            else "队列在运行开始后冻结；Agent 只能补读依赖代码，不能扩大主审计范围。新增范围需要建立下一次运行。"
        ),
        "",
        "### 3.3 技术栈与部署形态",
        "",
        "| 层次 | 选型 | 在本实验中的职责 |",
        "|---|---|---|",
        "| 前端 | React + TypeScript + Vite + Tailwind CSS | 四标签工作台（概览 / 审计过程 / 发现与验证 / 实验报告），经 SSE 接收事件并支持断线按事件 ID 续传 |",
        (
            "| 后端 | Python 3.12 + FastAPI | REST 接口 + SSE 事件流；外层运行 worker 与 API 同进程，目标任务在一次运行内启动受上限约束的共享队列 worker pool |"
            if task
            else "| 后端 | Python 3.12 + FastAPI | REST 接口 + SSE 事件流；审计 worker 与 API 同进程、单 worker 串行消费队列 |"
        ),
        "| 存储 | SQLite（WAL） | 快照、运行、单元、候选、验证记录与事件日志；事件先落库再推送，重启后据此恢复 |",
        "| 模型调用 | PydanticAI（OpenAIChatModel） | Agent、工具调用、输出纠正重试、用量与限额均由框架提供，**不自行实现 LLM 调用框架** |",
        "| 源码索引 | tree-sitter PHP | 只用于定位函数/方法与语句边界，属预处理，不做完整污点分析 |",
        "| 部署 | Docker Compose | 历史环境以运行记录为准；当前动态验证使用独立的 Lab30 商城、数据库、合作服务与 runner |",
        "",
        "API Key 只从服务端环境变量读取，不下发浏览器、不写入快照、数据库与报告。",
        "",
        "### 3.4 代码结构与模块映射",
        "",
        "| 作业要求的模块 | 实现位置 | 职责 |",
        "|---|---|---|",
        "| 代码预处理 | `backend/audit/source.py` | 快照导入与安全校验、tree-sitter 索引、AuditUnit 切片与遗漏记录 |",
        (
            "| 目标任务协调 | `backend/audit/agent.py`、`schemas.py` | 冻结目标与验收条件、受控执行指令、结构化工作项结果与证据约束 |"
            if task
            else "| Prompt 提示词工程 | `backend/audit/prompts.py` | P0/P1/P2 四段式全文、三类漏洞判定规则、不可信输入约束 |"
        ),
        "| LLM 漏洞推理 | `backend/audit/agent.py` | PydanticAI Agent、三个只读工具、预算控制与无工具收尾 |",
        "| POC 校验入库 | `backend/audit/evidence.py` | 引用行号属于当前快照、且模型确实读过该代码 |",
        (
            "| 队列与生命周期 | `backend/audit/worker.py`、`db.py`、`events.py` | 固定审计队列与目标任务共享队列、原子领取、尝试历史、事件落库与 SSE、重启后收束残留工作 |"
            if task
            else "| 队列与生命周期 | `backend/audit/worker.py`、`db.py`、`events.py` | 单 worker 消费、事件落库与 SSE、重启后把残留运行标为 interrupted |"
        ),
        "| 统计与归因 | `backend/audit/metrics.py` | 覆盖与去重、真值集混淆矩阵、未完成与未决样本单列 |",
        "| 报告与证据包 | `backend/audit/report.py` | Markdown / JSON / 证据 zip 三种导出 |",
        "| API 与运行控制 | `backend/audit/app.py` | REST 接口、SSE 端点、创建/取消运行、两轮对比 |",
        "| 模型接入与熔断 | `backend/audit/config.py`、`health.py` | 环境变量读取、连接健康状态与熔断 |",
        "| 前端工作台 | `frontend/src/`（`views/` 六个视图 + `useEvents.ts`） | 四个标签页、事件流订阅与源码查看 |",
        "| 自检与演示脚本 | `scripts/` | 端到端演示、SSE 续传、验证闸门、UI 冒烟、两轮对比一致性校验 |",
        "",
        "### 3.5 当前实现状态",
        "",
        (
            "- **已跑通并留有记录**：源码准备 → 目标任务协调与并发 worker → 证据校验 → 候选入库 → 人工 POC 验证 → 统计与导出的端到端闭环；"
            "每轮的 worker、用量、已读行号和终态均可回放；Compose 三服务支持重启后将残留运行标为 `interrupted`。"
            if task
            else "- **已跑通并留有记录**：源码准备 → LLM 审计 → 候选入库 → 人工 POC 验证 → 统计与导出的端到端闭环；P0/P1/P2 三轮在同一快照、同一范围、同一模型与同一预算下的对比；Compose 三服务的起停、重启恢复（残留运行标为 `interrupted`，在途单元记未完成、排队单元记 `skipped`）。"
        ),
        "- **可复算的自检**：后端单元测试（快照导入、生命周期、事件、证据校验、统计口径、报告章节完整性）全部通过（`cd backend && uv run pytest tests/ -q`）；`scripts/` 下的自检脚本均在真实服务上执行过——SSE 断线续传无重复无空洞、人工验证闸门不放行执行失败的结论、UI 冒烟无控制台报错、两轮对比的 Markdown 与 `result.json` 一致。",
        "- **有意不做**：接入 Burp/AWVS 做同场对照（第 2 章对比表的实测列为待实测）；二次注入与存储型 XSS 等扩展场景；多用户与多实例部署——本实验是单用户本地工具。",
        "- **做了但未做对抗验证**：执行器将源码、任务文本和文件名作为不可信数据处理，尚未用专门的注入样本做过对抗性测试。",
        "",
        "## 4. 模块详细设计",
        "",
        "### 4.1 代码预处理模块",
        "",
        "- 数据源：上传 ZIP，保存不可变快照、来源、文件哈希与原始行号；拒绝路径穿越、符号链接、加密条目与超限解压。",
        f"- 文件索引：仅索引 `{'`, `'.join(['.php', '.inc', '.phtml'])}`；默认排除第三方依赖与生成目录，排除清单随快照返回并展示。",
        "- 清洗规则：仅作用于发送给模型的副本，省略空行与无关注释，保留安全相关注释、字符串、模板内容与控制逻辑；每行携带原始文件行号，省略内容记录在 omissions 中。",
        "- 切片规则：优先按函数/方法/顶层脚本切片，超长单元按语句边界拆分，每片不超过 200 行或 16 KiB，连续切片重叠 24 行。",
        "- 输入与输出：输入为上传的 ZIP；输出为快照（文件清单 + 每个文件的 SHA256 + 原始行号）、语法索引与 AuditUnit 清单（含切片规则与 omissions）。闭包归属其所属函数，单元 ID 位置稳定，同一函数重复切分不会改变已有单元的身份。",
        "",
        "### 4.2 目标任务与执行约束模块" if task else "### 4.2 Prompt 提示词工程模块",
        "",
        (
            "目标模式不复用固定 SQL 注入 / XSS / 命令注入 Prompt，以避免旧清单覆盖本次目标。"
            "执行器由冻结的目标、验收条件、源码单元和上一轮关注点构造受控指令："
            if task
            else f"本次使用的 Prompt 版本为 **{run['prompt_label']}**（`{run['prompt_id']}`），全文如下："
        ),
        "",
        "```text",
        instruction_text,
        "```",
        "",
        (
            f"输入与输出：输入为任务目标「{task.get('objective', '—')}」、验收条件和已读源码；"
            "输出为工作项结构化结果与下一关注点。任务文本、源码注释和文件名均不可信，不能改变只读审计边界。"
            if task
            else "四段式结构：审计角色 → 核心任务 → 漏洞判定标准 → 输出格式；三类漏洞各有专属判定规则。"
        ),
        (
            "累计的工作项轮次、worker 身份、用量、已读行号和终止原因随运行保存，供协调器与人工复核。"
            if task
            else "不可信输入约束固定附加在版本全文之后，用于抵御被审计代码中的提示词注入。"
        ),
        (
            ""
            if task
            else "输入与输出：输入是作业固定的四段式要求与三类漏洞判定规则；输出是可直接提交的 Prompt 全文，随运行冻结在运行记录里（本报告即引用该冻结副本）。操作方法：在「Prompt 与实验」页选择已有版本或新增自定义版本，再由所选版本创建运行；命令行等价入口为 `scripts/prompt_rounds.sh`。"
        ),
        "",
    ]
    if not task:
        doc += _prompt_rounds(bundle)
    doc += [
        "### 4.3 LLM 漏洞推理挖掘模块",
        "",
        (
            "目标协调器把冻结源码单元变成共享工作项；每个 worker 只处理一个方向并返回 achieved / continue / no_evidence / blocked。"
            "协调器在有证据的 achieved 时达成目标，在所有工作项结束后才判定 unreachable 或 inconclusive。"
            if task
            else "三级分层推理：语法结构 → 漏洞语义 → 实际风险。每单元固定检查三类漏洞，结论取 candidate / no_candidate / insufficient_context。"
        ),
        (
            f"每个工作项预算为 {run['budgets'].get('responses')} 次模型响应、{run['budgets'].get('tools')} 次工具调用、{run['budgets'].get('seconds')} 秒；"
            f"同一工作项最多按配置重试，任务总尝试上限为 {task.get('max_total_attempts', '—')} 次并由所有 worker 共享。"
            if task
            else f"每单元预算为 {run['budgets'].get('responses')} 次模型响应、{run['budgets'].get('tools')} 次工具调用、{run['budgets'].get('seconds')} 秒，输出纠正重试一次。"
        ),
        (
            f"本次执行策略：`{run.get('agent_policy', {}).get('version', 'legacy')}`。每轮独立记录补读、判定与输出纠正的总用量。"
            if task
            else f"本次执行策略：`{run.get('agent_policy', {}).get('version', 'legacy')}`。新策略将补读、判定、POC 与一次纠正共享总预算；旧策略的独立收尾预算只适用于历史记录。"
        ),
        (
            "模型、输出形状与单项预算失败保留其终止原因并在单项上有界重试；源码或环境上下文缺失记为 blocked。"
            "若任务总上限截断的是这类待重试项，也转为 blocked；两种情况都不被解释为目标不可达。"
            if task
            else "预算耗尽、解析失败与上下文缺失均保留为未完成状态，不计入阴性结论。"
        ),
        (
            "输入与输出：输入是任务目标、验收条件、冻结源码单元与已保存的下一关注点；输出是结构化工作项结果。"
            "achieved 必须附原始行号证据；漏洞目标可附 POC 与修复建议，结果与队列状态一起持久化。"
            if task
            else "输入与输出：输入是该单元的文件范围与行号区间、该类别的判定规则、以及 Prompt 全文；输出是结构化结论（candidate / no_candidate / insufficient_context），候选附原文件行号、输入来源、传播关系、危险操作、防护判断、触发前提、风险等级、POC 与修复建议。"
        ),
        (
            "工具只有 `read_source`、`search_code`、`get_context` 三个且均为只读。每个 worker 先补读静态上下文，"
            "再围绕当前目标与关注点探索；证据必须来自实际显示过的源码。模型与结构化输出失败只在该工作项内有界重试；"
            "仍无法得到结论时记为 blocked，使任务收束为 inconclusive 而非 unreachable。"
            if task
            else "工具只有 `read_source`、`search_code`、`get_context` 三个且均为只读。whitebox-2 先补读静态上下文；两次重复调用或连续三次未增加代码行时停止探索，回放实际显示的源码做无工具判定。判定与 POC 分开，每个类别完成即保存检查点。危险 API 命中只影响排序，不改变三类检查清单。"
        ),
        "",
        "### 4.4 POC 实操验证模块",
        "",
        (
            (
                "本任务配置要求 achieved 发现附可运行 POC（原文件行号、输入来源、传播关系、危险操作、防护判断、触发前提、风险等级、修复建议）；"
                "缺少 POC 的 achieved 输出会被要求纠正，不能达成目标。"
                if task.get("require_poc", True)
                else "本任务允许 achieved 发现省略 POC（例如仅核对源码事实），但仍必须保留原始行号证据和完整分析链。"
            )
            if task
            else "候选漏洞必须附可运行 POC（原文件行号、输入来源、传播关系、危险操作、防护判断、触发前提、风险等级、修复建议）。"
        ),
        "验证记录区分脚本执行状态与人工结论：执行失败、语法错误、连接失败、环境不匹配、单次未触发均不自动算作误报。确认或排除必须有成功执行、目标版本、命令和正常/攻击对照观测；确认还必须附可复核证据。",
        "XSS 需要浏览器执行证据，仅响应包含 payload 不足以确认。",
        "输入与输出：输入是候选自带的 POC 脚本与靶机环境；输出是人工验证记录——执行状态、人工结论、正常输入对照、攻击输入观测、浏览器证据、脚本适配说明与问题归因、附件。操作方法：在「发现与验证」页下载 POC，对 <http://127.0.0.1:4280> 实际运行后回填记录；脚本按原样跑不通时先做适配再运行，适配内容照实记录而不是直接判为排除。",
        "",
        "### 4.5 结果校验与复盘模块",
        "",
        "双层校验：后端证据校验（引用必须属于当前快照，且模型确实读过该代码）+ 人工 POC 实操复筛。",
        "重复候选按指纹去重；未完成单元单列，不作为阴性结果。",
        (
            "输入与输出：输入是目标、工作项尝试历史、候选与人工验证记录；输出是目标终态、覆盖率和可回放的队列证据。"
            "自定义目标不套用固定三类漏洞的混淆矩阵，全部随 `result.json` 交付以便复算。"
            if task
            else "输入与输出：输入是候选漏洞、人工验证记录与独立核验的真值集；输出是审计覆盖率与验证覆盖率、去重后的候选、混淆矩阵与 Precision/Recall/F1、未决样本、误漏报归因以及两轮对比表，全部随 `result.json` 交付以便复算。操作方法：在「实验报告」页录入真值集与失败归因，再导出 Markdown / JSON / 证据包。"
        ),
        "",
        "## 5. 方案缺陷与优化方向",
        "",
        (
            f"- 未完成单元 {len(incomplete)} 个，均单列于下方（见 6.1），未计入阴性结论。"
            if incomplete
            else "- 本次运行没有未完成的单元：每个单元都给出了结论，未完成状态一律单列（见 6.1）的规则本次未被触发。"
        ),
    ]
    # The measured form of the limitation the README warns about: the settlement phase asks
    # one category at a time, and on this endpoint a single category answer is slow enough to
    # run past its own request ceiling. Naming the units and the categories beats a generic
    # "模型输出不稳定" — the reader can go and look at exactly those units.
    if settlement_failed:
        doc += [
            f"- 其中 {len(settlement_failed)} 个是**收尾阶段未能作答**："
            + "、".join(
                f"`{unit['file_path']}`（{CATEGORY_LABELS.get(category, category)}）"
                for unit, category in settlement_failed[:6]
            )
            + "。收尾把已读到的代码回放给模型、按类别分次强制作答，"
            f"单次调用上限 {SETTLE_CALL_SECONDS:.0f} 秒、单次请求 {SETTLE_REQUEST_SECONDS:.0f} 秒；"
            "含 POC 脚本的类别作答在该端点上会超过单次请求上限，重试两次即触顶，"
            "因此这份历史记录中的单元未完成。"
            "当前 whitebox-2 已将判定与 POC 拆分、保留类别检查点，并严格共享总墙钟预算。"
            "新策略的效果需使用同策略、同模型与同预算重新实测，不能套用历史提升数值。",
        ]
    doc += [
        f"- 证据校验剔除的引用：{len(discarded)} 条候选的引用全部无法核实，另有 {len(partially_cited)} 条候选被剔除了部分引用"
        "（行号不属于快照，或落在该单元没读过的代码里）。",
        "  这些记录保留在 6.4 节。逐条剔除的不可核实引用已从候选证据里去掉、记在各自条目下：",
        "  一条候选只要还有可核对的引用就保留——否则会把一次真实发现变成漏报；引用全不可核实的才降级。",
        "  **混淆矩阵只统计证据通过校验的候选**，所以 FP 的含义是「有证据支持却与真值相反」，",
        "  不等于「模型没说过错话」。",
        "- 已知局限：动态 include 与动态调用无法静态解析；切片边界可能截断跨片数据流；",
        "  模型输出稳定性与 POC 环境差异（PHP 版本、数据库分支、登录角色与部署配置）仍会带来噪声。",
        f"- 未接入传统扫描器对照，第 2 章对比实测数据为{NOT_MEASURED}。",
        "框架层面的实现到哪一步、哪些是有意不做的，见 3.5；本节只记录本次运行实测到的问题与归因。",
        "",
        "## 6. 实验总结",
        "",
        f"- 本次运行覆盖 {metrics['total_units']} 个审计单元，完成 {metrics['completed_units']} 个（审计覆盖率 {metrics['audit_coverage']:.2%}）。",
        f"- 产出证据通过的发现 {len(candidates)} 条，其中已验证 {metrics['confirmed']} 条确认、{metrics['rejected']} 条排除、{metrics['uncertain']} 条不确定、{metrics['awaiting_verification']} 条待验证。",
        f"- 运行用量：{run['usage']['requests']} 次模型响应、{run['usage']['tool_calls']} 次工具调用、输入 {run['usage']['input_tokens']} tokens、输出 {run['usage']['output_tokens']} tokens。",
        "",
        "### 6.1 错误与未决样本（不视为阴性）",
        "",
    ]
    if incomplete:
        doc += ["| 单元 | 符号 | 文件 | 状态 | 原因 |", "|---|---|---|---|---|"]
        for unit in incomplete:
            doc.append(
                f"| `{unit['unit_id'][:12]}` | {unit['symbol']} | `{unit['file_path']}` | {unit['status']} | "
                f"{(unit.get('error') or '—').replace('|', chr(92) + '|')[:160]} |"
            )
    else:
        doc.append("无。")
    # A unit can also finish *with a verdict* after exploration was cut off: the settlement
    # phase forces the answer once the budget is gone, and that answer is stored like any
    # other. It is not in the table above — the unit is not unfinished — but leaving it out
    # entirely would hide the one thing a reader needs to weigh those verdicts: how often
    # the model wanted to keep reading and was not allowed to.
    if truncated:
        doc += [
            "",
            f"另有 {len(truncated)} 个单元在探索阶段被截断（预算耗尽或超时），随后的收尾阶段强制给出了结论，"
            "因此**仍计入统计**：结论是模型自己下的，引用行号也逐条核验过（见 6.2、6.3）。"
            "被截断只说明模型还想继续读，不等于它没有依据——真的没有依据时应答 insufficient_context，"
            "那类样本已在 6.2 中单列。此表列出这些单元供读者判断折扣：",
            "",
            "| 单元 | 文件 | 截断原因 | 结论 |",
            "|---|---|---|---|",
        ]
        for unit in truncated:
            conclusions = (unit.get("result") or {}).get("conclusions") or {}
            rendered = "、".join(f"{CATEGORY_LABELS.get(k, k)}={v}" for k, v in conclusions.items()) or "—"
            doc.append(
                f"| `{unit['unit_id'][:12]}` | `{unit['file_path']}` | "
                f"{(unit.get('result') or {}).get('exploration_incomplete')} | {rendered} |"
            )
    doc += ["", "### 6.2 统计口径", ""]
    if task:
        doc += [
            "- 本次为自定义目标任务，不套用固定 SQL 注入 / XSS / 命令注入真值矩阵，"
            "因此不计算 TP、FP、FN、TN、Precision、Recall 或 F1。",
            f"- 目标终态：{(goal or {}).get('status', '—')}；"
            f"累计尝试：{(goal or {}).get('attempts', 0)}/{(goal or {}).get('max_total_attempts', task.get('max_total_attempts', '—'))}；"
            f"原因：{(goal or {}).get('terminal_reason') or '—'}。",
            "- 目标是否达成由已验证的源码行号证据和持久化工作项历史复核，不能把单项未发现当作整体阴性。",
        ]
    elif evaluation:
        doc += [
            f"- 已知真值样本 {evaluation['total_samples']} 个，其中独立验证且有资格计入 {evaluation['eligible']} 个。",
            f"- 混淆矩阵：TP={evaluation['TP']}、FP={evaluation['FP']}、FN={evaluation['FN']}、TN={evaluation['TN']}。",
            f"- Precision={_cell(evaluation['precision'])}、Recall={_cell(evaluation['recall'])}、"
            f"F1={_cell(evaluation['f1'])}"
            + (
                # A recall of 1.0 printed above "1 sample set aside" invites the reader to
                # take it as "found everything". Say out loud what it is actually a ratio of.
                f"（分母为 {evaluation['eligible'] - len(evaluation['unresolved'])} 个可判定样本；"
                f"另有 {len(evaluation['unresolved'])} 个样本未决，既不进分母也不进分子）。"
                if evaluation["unresolved"]
                else "。"
            ),
            f"- 未决样本 {len(evaluation['unresolved'])} 个（已单列，不计入阴性）。",
            f"- 本轮产生 {len(candidates)} 条候选，其中 {len(evaluation['unmatched_candidates'])} 个"
            "文件×类别组合落在真值样本集之外，**无法判为命中或误报**：判命中缺真值支撑，判误报则需一条"
            "「该组合无漏洞」的真值——两者都没有。这些候选仍在 6.3 逐条列出并附验证结论，"
            "只是不参与 TP/FP。矩阵统计的是真值样本那一侧，两边条目数不同是正常的。",
            "- 计入矩阵的条件：该文件的所有单元都已完成，且没有单元就其类别声明缺少上下文"
            "（insufficient_context）。单元未完成或声明看不到足够代码，都只算观察未完成："
            "记为漏报等于把模型的诚实当成失误，记作真阴则等于凭空记一次正确否定，"
            "两种都会让 Precision 与 Recall 同时失真。",
            f"- 探索阶段被截断但随后被强制收尾并给出结论的单元（本次 {len(truncated)} 个，见 6.1）"
            "**计入矩阵**。这类单元并非「没有结论」：预算用尽后收尾阶段会带着已读到的代码强制作答，"
            "结论由模型自己给出，引用行号还要逐条核验；模型若确实缺少依据，应答 insufficient_context，"
            "那类样本按上一条规则单列。把「模型还想继续读」等同于「模型没有依据」，会让每一次"
            "预算截断都抹掉一个已经成立的观察，统计口径反而失真。",
        ]
        if evaluation["unresolved"]:
            doc += ["", "| 样本文件 | 类别 | 真值 | 未决原因 |", "|---|---|---|---|"]
            for item in evaluation["unresolved"]:
                doc.append(
                    f"| `{item['file_path']}` | {CATEGORY_LABELS.get(item['category'], item['category'])} | "
                    f"{'漏洞' if item['vulnerable'] else '无漏洞'} | {item['reason']} |"
                )
        if evaluation["unmatched_candidates"]:
            doc += ["", "| 候选 | 文件 | 类别 | 无法评分的原因 |", "|---|---|---|---|"]
            for item in evaluation["unmatched_candidates"]:
                doc.append(
                    f"| `{(item.get('finding_id') or '')[:8]}` | `{item['file_path']}` | "
                    f"{CATEGORY_LABELS.get(item['category'], item['category'])} | {item['reason']} |"
                )
    else:
        doc += [
            f"- 本项目未设置经独立验证的真值样本集，因此 Recall、FN、TN 均标注为**{NOT_COMPUTABLE}**。",
            "- 可计算的是候选数、人工结论分布、审计覆盖率与验证覆盖率。",
        ]
    doc += [
        "",
        "### 6.3 目标发现与验证依据" if task else "### 6.3 候选漏洞与验证依据",
        "",
    ]
    if candidates:
        for index, finding in enumerate(candidates, 1):
            doc += _finding_block(finding, index, legacy_labels=True)
    else:
        doc.append("本次运行未产生满足验收条件的目标发现。" if task else "本次运行未产生候选漏洞。")
    # Emitted even when empty, for the same reason as 6.5 below: an omitted section leaves a
    # hole in the outline (6.3 → 6.5) that reads as a chapter missing from the report rather
    # than one with nothing in it. The empty state also deserves its own sentence — "nothing
    # was discarded" means every citation the model gave checked out, which is not the same
    # as the check never having run.
    doc += [
        "### 6.4 引用全部无法核实的目标发现（保留记录，不计入目标）"
        if task else "### 6.4 引用全部无法核实的候选（保留记录，不计入候选）",
        "",
    ]
    if discarded:
        doc += [
            "这些候选引用的行号，要么不属于本快照，要么落在该单元从未读过的代码里，"
            "没有一条能核对，因此不作为候选计入统计。",
            "",
        ]
        for index, finding in enumerate(discarded, 1):
            doc += [
                f"{index}. **{finding['title']}**",
                f"   - 出处：`{finding['file_path']}`（{finding['symbol']}）",
            ]
            doc += [f"   - 无法核实的引用：{problem}" for problem in finding["validation_errors"]]
            doc.append("")
    elif candidates:
        doc += [
            "无。本次运行的每条候选都至少有一条引用通过了核验，因此没有整条被剔除的记录；"
            "被剔除掉部分引用的候选见 6.3 各自的条目与第 5 章的合计。",
            "",
        ]
    else:
        doc += [
            "本次运行未产生目标发现，因而也没有被剔除的目标发现。"
            if task else "本次运行未产生候选漏洞，因而也没有被剔除的候选。",
            "",
        ]
    # Unnumbered on purpose: a withdrawn conclusion only exists on a Planner-led run, which
    # is rendered by the task layouts above, so this block has no place in this chapter's
    # outline and would misnumber 6.5–6.7 as a chapter section for a run that has no Planner.
    doc += _withdrawn_section(withdrawn, legacy_labels=True)
    doc += _source_observation_section(bundle, legacy_labels=True)
    # Always emitted, even with nothing to attribute: an omitted section renumbers 6.6 and 6.7
    # and reads as if the chapter were missing from the outline rather than empty. Silence here
    # also hides the two very different reasons the table can be empty — no mistakes, or nobody
    # has sat down and written the review yet.
    doc += ["### 6.5 误报/漏报归因", ""]
    if attributions:
        doc += ["| 文件 | 类别 | 类型 | 归因 | 补强检查项 |", "|---|---|---|---|---|"]
        for item in attributions:
            doc.append(
                f"| `{item['file_path']}` | {CATEGORY_LABELS.get(item['category'], item['category'])} | {item['kind']} | "
                f"{item['cause'] or '—'} | {item['check_item'] or '—'} |"
            )
        doc.append("")
    elif evaluation and (evaluation["FP"] or evaluation["FN"]):
        doc += [
            f"本次运行有 {evaluation['FP']} 个误报、{evaluation['FN']} 个漏报，但尚未记录归因。"
            "这些样本的失败原因与对应检查项需要人工在验证之后逐条填写"
            "（`POST /api/runs/{id}/attributions`），本报告只呈现已记录的内容。",
            "",
        ]
    elif evaluation and (evaluation["TP"] or evaluation["TN"]):
        doc += [
            "本次运行未记录误报/漏报归因。混淆矩阵里 FP 与 FN 都是 0，"
            "但这不等于复盘已经做完：归因表是人写的，空表只说明还没人写，"
            "不说明没有值得写的地方。",
        ]
        # FP=FN=0 is not the same as "no defect was found in the pipeline". The defects
        # this run did surface are at the POC level — scripts that could not demonstrate a
        # real vulnerability as written — and they are written up per candidate in 6.3.
        # Leaving the reader with a bare empty table hides that work.
        unadapted = [
            item for item in candidates
            if not any(record.get("modification_notes") for record in item.get("verifications") or [])
        ]
        if len(unadapted) < len(candidates):
            doc += [
                "",
                f"与统计无关但同样需要复盘的是 POC 本身：本次 {len(candidates)} 条候选中，"
                f"{len(candidates) - len(unadapted)} 条的 POC **按原样运行无法证明漏洞成立**，"
                "经人工适配后确认。这些既不是误报（漏洞真实存在）也不进混淆矩阵，"
                "逐条的环境假设错误、脚本缺陷与归因写在 6.3 各候选的「人工验证记录」下——"
                "把「POC 没跑通」直接读成「漏洞不成立」，才是这条链路上最贵的一种误判。",
            ]
        doc.append("")
    else:
        doc += [
            (
                "本次为自定义目标任务，固定类别的误报/漏报归因和 Precision、Recall、F1 不适用；"
                "请结合目标、工作项尝试历史和人工验证记录复盘。"
                if task
                else f"本次运行未记录误报/漏报归因，且没有可对照的真值样本，"
                f"Precision、Recall、F1 均为**{NOT_COMPUTABLE}**，无从归因。"
            ),
            "",
        ]
    if truths:
        doc += ["### 6.6 真值样本集", "", "| 文件 | 类别 | 真值 | 独立验证 | 依据 |", "|---|---|---|---|---|"]
        for sample in truths:
            doc.append(
                f"| `{sample['file_path']}` | {CATEGORY_LABELS.get(sample['category'], sample['category'])} | "
                f"{'漏洞' if sample['vulnerable'] else '无漏洞'} | {'是' if sample['independently_verified'] else '否'} | "
                f"{sample['verification_basis'] or '—'} |"
            )
        doc.append("")
    doc += [
        "### 6.7 交付物",
        "",
        "- `report.md`：本报告。",
        "- `result.json`：本次运行的完整结构化结果（运行、单元、候选、验证、统计、归因）。",
        "- `evidence/`：验证记录的附件与 POC 脚本原件。",
        "",
        (
            "统计可由 `result.json` 复算：目标终态由 goals、工作项收束状态和 findings 中 validation_state=candidate 共同确定，"
            "覆盖率由 units 状态计数，尝试历史由 work_items[].attempt_history 复查。"
            if task
            else "统计可由 `result.json` 复算：候选数由 findings 中 validation_state=candidate 计数，"
            "覆盖率由 units 状态计数，混淆矩阵由 truths 与 candidates 交叉得到。"
        ),
        "",
    ]
    return "\n".join(doc)


def render_json(bundle: dict) -> str:
    value = dict(_partition_bundle(bundle))
    run = value.get("run") or {}
    # The policy the run froze, not the current one: an export must reproduce what was
    # actually allowed when the POC agent ran.
    value["verification_policy"] = run.get("poc_policy") or {}
    value.setdefault("project", None)
    value.setdefault("report_narrative", {})
    value.setdefault("carried_findings", [])
    findings = []
    for finding in value.get("findings") or []:
        item = dict(finding)
        item["verification"] = {
            "status": item.get("verification_status") or "unverified",
            "verdict": item.get("verification_verdict"),
            "records": list(item.get("verifications") or []),
        }
        findings.append(item)
    value["findings"] = findings
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def safe_name(value: str) -> str:
    """A filename that cannot escape the directory it is written into.

    Uploaded attachment names and model-supplied POC filenames are both attacker-adjacent
    strings: they arrive from outside this process. Only the basename survives, and the
    characters that make a path a path are stripped.
    """
    cleaned = Path(value.replace("\\", "/")).name.strip()[:120]
    return "".join(ch for ch in cleaned if ch.isprintable() and ch not in '/\\:*?"<>|') or "upload.bin"


def collect_evidence(bundle: dict, evidence_dir: Path) -> list[tuple[str, bytes]]:
    """What the archive carries besides the report: POC scripts and uploaded attachments.

    Both kinds are needed. Shipping only the human's attachments left the reader holding
    verification notes for a script that was not in the archive — and the POC scripts are
    collected from every finding, including the ones kept in 6.4 that do not count as
    candidates, because a rejected finding's script is exactly what a reviewer wants to
    re-run when questioning the rejection.
    """
    files: list[tuple[str, bytes]] = []
    bundle = _partition_bundle(bundle)
    for finding in [*(bundle.get("findings") or []), *(bundle.get("source_observations") or [])]:
        poc = finding.get("poc") or {}
        script = poc.get("script")
        if script:
            files.append((original_poc_name(finding, poc), script.encode("utf-8")))
        for record in finding.get("verifications") or []:
            # The adapted script is the artefact the verification flow produces, so it
            # travels next to the model's original rather than only inside result.json.
            if record.get("modified_script"):
                files.append((adapted_script_name(finding, record),
                              record["modified_script"].encode("utf-8")))
            for item in record.get("files") or []:
                stored = safe_name(item["stored"])
                path = Path(evidence_dir) / stored
                if path.is_file():
                    files.append((item["stored"], path.read_bytes()))
            # Runner artifacts are copied out of the isolated container as soon as the
            # verdict is recorded, so the archive does not depend on the runner's TTL.
            for item in record.get("artifacts") or []:
                stored = safe_name(str(item.get("path") or ""))
                path = Path(evidence_dir) / stored
                if stored and path.is_file():
                    files.append((stored, path.read_bytes()))
            if _verification_source(record) == "poc_agent":
                manifest = _runner_manifest(bundle, record)
                files.append((f"{record['id']}-runner-manifest.json",
                              json.dumps(manifest, ensure_ascii=False, indent=2, default=str).encode("utf-8")))
    return files


def _runner_manifest(bundle: dict, record: dict) -> dict:
    """What the isolated runner actually did, in a form a reviewer can re-check.

    The report states the verdict; this file is the machine-readable account behind it --
    target, limits, every job and the hash of every artifact -- so a reader does not have
    to trust either the model or this report.
    """
    jobs = [
        item for item in (bundle.get("verification_jobs") or [])
        if str(item.get("verification_id") or "") == str(record.get("id") or "")
    ]
    return {
        "schema": "poc-runner-manifest/v1",
        "verification_id": record.get("id"),
        "finding_id": record.get("finding_id"),
        "project_finding_id": record.get("project_finding_id"),
        "status": record.get("status"),
        "verdict": record.get("verdict"),
        "target": record.get("target") or {},
        "policy": (record.get("agent") or {}).get("policy") or {},
        "usage": (record.get("agent") or {}).get("usage") or {},
        "jobs": [
            {
                "job_id": item.get("job_id"),
                "kind": item.get("kind"),
                "exit_code": item.get("exit_code"),
                "duration_ms": item.get("duration_ms"),
                "request": item.get("request") or {},
                "result": {
                    key: (item.get("result") or {}).get(key)
                    for key in ("status", "exit_code", "duration_ms", "truncated", "timed_out")
                },
            }
            for item in jobs
        ],
        "artifacts": record.get("artifacts") or [],
        "generated_at": bundle.get("generated_at"),
    }


def render_zip(bundle: dict, evidence_files: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.md", render_markdown(bundle))
        archive.writestr("result.json", render_json(bundle))
        facts = bundle.get("final_review")
        if facts:
            # The machine-readable half of the same facts: a reviewer can recompute every
            # number in report.md from these two files without the database.
            archive.writestr("final-review.json",
                             json.dumps(facts, ensure_ascii=False, indent=2, default=str))
            archive.writestr("report-quality.json",
                             json.dumps(facts.get("quality_result") or {}, ensure_ascii=False,
                                        indent=2, default=str))
        for name, payload in evidence_files:
            archive.writestr(f"evidence/{name}", payload)
        archive.writestr(
            "evidence/README.txt",
            "本目录保存以下证据：\n"
            "  poc_<finding-id>_<filename>              模型给出的 POC 脚本原件；\n"
            "  <verification-id>-adapted-<filename>     POC Agent 在隔离runner中实际执行的最后一份脚本；\n"
            "  <verification-id>-runner-manifest.json   靶场、限额、每个作业的退出码与时间、产物哈希；\n"
            "  <verification-id>-<filename>             runner 产物（截图、日志、脚本输出）；\n"
            "  <verification-id>-<filename>             历史人工验证记录附带的附件（只读保留）。\n"
            "文件名前缀是发现 ID 或验证记录 ID，可在 report.md / result.json 中查到对应条目。\n",
        )
    return buffer.getvalue()
