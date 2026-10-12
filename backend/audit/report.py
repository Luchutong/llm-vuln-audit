"""Markdown / JSON / evidence-package export.

The Markdown follows the six-chapter outline in docs/report-outline.md. Anything that
was not actually measured is written as 待实测 rather than filled with a plausible
number, and ordinary uploaded projects report recall/FN/TN as not computable.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .agent import SETTLE_CALL_SECONDS, SETTLE_REQUEST_SECONDS
from .config import VERSION
from .schemas import CATEGORY_LABELS

NOT_MEASURED = "待实测"
NOT_COMPUTABLE = "无法计算"

CATEGORY_ORDER = ("sqli", "xss_r", "command_injection")

# `worker.py` records a settlement failure as "<cause> | 收尾阶段 <category> 判定失败: ...".
# Reading it back is how chapter 5 can say which categories ran out of wall clock instead of
# blaming "模型输出不稳定" in the abstract.
SETTLEMENT_FAILURE = re.compile(r"收尾阶段 ([a-z_]+) 判定失败")


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
    if finding.get("validation_state") == "candidate":
        if not problems:
            return "通过"
        return "通过（但已剔除未通过校验的引用：" + "；".join(problems) + "）"
    return "未通过——" + ("；".join(problems) or "无可用引用")


def _finding_block(finding: dict, index: int) -> list[str]:
    label = CATEGORY_LABELS.get(finding["category"], finding["category"])
    lines = [
        f"#### {index}. [{label}] {finding['title']}",
        "",
        f"- 风险等级：{finding['severity']}",
        f"- 证据行号：{_evidence_text(finding['evidence'])}",
        f"- 输入来源：{finding['input_source'] or '—'}",
        f"- 传播关系：{finding['propagation'] or '—'}",
        f"- 危险操作：{finding['dangerous_operation'] or '—'}",
        f"- 防护判断：{finding['protection'] or '—'}",
        f"- 触发前提：{'；'.join(finding['preconditions']) or '—'}",
        f"- 缺失信息：{'；'.join(finding['missing_context']) or '—'}",
        f"- 后端校验：{_validation_text(finding)}",
        f"- 人工结论：{finding.get('verdict') or '未裁决'}",
        "",
        "**判断依据**",
        "",
        finding["summary"] or "—",
        "",
    ]
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
        lines += ["**人工验证记录**", "", "| 时间 | 执行状态 | 人工结论 | 命令 | 正常观测 | 攻击观测 |", "|---|---|---|---|---|---|"]
        for record in finding["verifications"]:
            lines.append(
                "| {created} | {status} | {verdict} | `{command}` | {normal} | {attack} |".format(
                    created=record["created_at"],
                    status=record["execution_status"],
                    verdict=record["verdict"],
                    command=(record["command"] or "—").replace("|", "\\|"),
                    normal=(record["normal_observation"] or "—").replace("|", "\\|"),
                    attack=(record["attack_observation"] or "—").replace("|", "\\|"),
                )
            )
        lines.append("")
        for index, record in enumerate(finding["verifications"], 1):
            details = verification_details(finding, record)
            if details:
                lines += [f"第 {index} 条验证记录的补充说明：", ""] + details + [""]
    return lines


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
    if record.get("target_version"):
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
    if attachments:
        listed = "、".join(f"`evidence/{item['stored']}`" for item in attachments)
        details.append(f"- 附件：{listed}")
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


def render_markdown(bundle: dict) -> str:
    run = bundle["run"]
    metrics = bundle["metrics"]
    units = bundle["units"]
    findings = bundle["findings"]
    attributions = bundle["attributions"]
    snapshot = bundle.get("snapshot") or {}
    truths = bundle.get("truths") or []
    evaluation = metrics.get("evaluation")

    candidates = [f for f in findings if f["validation_state"] == "candidate"]
    discarded = [f for f in findings if f["validation_state"] != "candidate"]
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
        f"- Prompt 版本：{run['prompt_label']}（`{run['prompt_id']}`）",
        f"- 模型：`{run['model']}`",
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
        "本实验面向单用户、本地部署的普通 PHP 项目，覆盖 SQL 注入、反射型 XSS、命令注入三类漏洞。",
        "链路为：源码预处理 → Prompt 提示词工程 → LLM 漏洞推理 → POC 人工实操验证 → 结果校验降噪与复盘优化。",
        "",
        f"- 待审计代码来源：{snapshot.get('source', run.get('snapshot_id'))}，归档哈希 `{snapshot.get('archive_sha256', '—')}`。",
        f"- 审计范围（运行开始后冻结，共 {len(run.get('scope') or [])} 个文件）：",
        "",
    ]
    for path in run.get("scope") or []:
        doc.append(f"  - `{path}`")
    doc += [
        "",
        f"- 审计单元总数：{metrics['total_units']}，其中完成 {metrics['completed_units']} 个，未完成 {metrics['incomplete_units']} 个。",
        "",
        "> 边界说明：DVWA 六样本用于检验实验流程本身，不能据此宣称对未知 PHP 项目的检测能力。",
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
        "flowchart LR",
        "    A[代码预处理<br/>不可变快照/语法索引/审计单元] --> B[Prompt 提示词工程<br/>四段式结构与场景规则]",
        "    B --> C[LLM 漏洞推理挖掘<br/>三个只读工具/候选与POC]",
        "    C --> D[POC 验证实操<br/>学生下载适配本地运行]",
        "    D --> E[校验与复盘<br/>人工裁决/统计/归因]",
        "    E --> B",
        "```",
        "",
        "### 3.2 数据流向",
        "",
        "数据流：上传 ZIP → 生成不可变快照与语法索引 → 按函数/方法/顶层脚本切分审计单元（含切片规则与遗漏记录）",
        "→ 用户选定范围并创建运行（范围与 Prompt 全文在此冻结）→ 后台单 worker 逐个单元执行",
        "→ 事件先写 SQLite 再推送 SSE → 候选经证据校验后落库 → 人工上传验证记录 → 统计与导出。",
        "",
        "队列在运行开始后冻结；Agent 只能补读依赖代码，不能扩大主审计范围。新增范围需要建立下一次运行。",
        "",
        "### 3.3 技术栈与部署形态",
        "",
        "| 层次 | 选型 | 在本实验中的职责 |",
        "|---|---|---|",
        "| 前端 | React + TypeScript + Vite + Tailwind CSS | 四标签工作台（概览 / 审计过程 / 发现与验证 / 实验报告），经 SSE 接收事件并支持断线按事件 ID 续传 |",
        "| 后端 | Python 3.12 + FastAPI | REST 接口 + SSE 事件流；审计 worker 与 API 同进程、单 worker 串行消费队列 |",
        "| 存储 | SQLite（WAL） | 快照、运行、单元、候选、验证记录与事件日志；事件先落库再推送，重启后据此恢复 |",
        "| 模型调用 | PydanticAI（OpenAIChatModel） | Agent、工具调用、输出纠正重试、用量与限额均由框架提供，**不自行实现 LLM 调用框架** |",
        "| 源码索引 | tree-sitter PHP | 只用于定位函数/方法与语句边界，属预处理，不做完整污点分析 |",
        "| 部署 | Docker Compose（三服务） | `app` 审计应用、`db` 数据库、`dvwa` 靶机；靶机与 `demo/dvwa-source.zip` 由同一份源码构建 |",
        "",
        "API Key 只从服务端环境变量读取，不下发浏览器、不写入快照、数据库与报告。",
        "",
        "### 3.4 代码结构与模块映射",
        "",
        "| 作业要求的模块 | 实现位置 | 职责 |",
        "|---|---|---|",
        "| 代码预处理 | `backend/audit/source.py` | 快照导入与安全校验、tree-sitter 索引、AuditUnit 切片与遗漏记录 |",
        "| Prompt 提示词工程 | `backend/audit/prompts.py` | P0/P1/P2 四段式全文、三类漏洞判定规则、不可信输入约束 |",
        "| LLM 漏洞推理 | `backend/audit/agent.py` | PydanticAI Agent、三个只读工具、预算控制与无工具收尾 |",
        "| POC 校验入库 | `backend/audit/evidence.py` | 引用行号属于当前快照、且模型确实读过该代码 |",
        "| 队列与生命周期 | `backend/audit/worker.py`、`db.py`、`events.py` | 单 worker 消费、事件落库与 SSE、重启后把残留运行标为 interrupted |",
        "| 统计与归因 | `backend/audit/metrics.py` | 覆盖与去重、真值集混淆矩阵、未完成与未决样本单列 |",
        "| 报告与证据包 | `backend/audit/report.py` | Markdown / JSON / 证据 zip 三种导出 |",
        "| API 与运行控制 | `backend/audit/app.py` | REST 接口、SSE 端点、创建/取消运行、两轮对比 |",
        "| 模型接入与熔断 | `backend/audit/config.py`、`health.py` | 环境变量读取、连接健康状态与熔断 |",
        "| 前端工作台 | `frontend/src/`（`views/` 六个视图 + `useEvents.ts`） | 四个标签页、事件流订阅与源码查看 |",
        "| 自检与演示脚本 | `scripts/` | 端到端演示、SSE 续传、验证闸门、UI 冒烟、两轮对比一致性校验 |",
        "",
        "### 3.5 当前实现状态",
        "",
        "- **已跑通并留有记录**：源码准备 → LLM 审计 → 候选入库 → 人工 POC 验证 → 统计与导出的端到端闭环；P0/P1/P2 三轮在同一快照、同一范围、同一模型与同一预算下的对比；Compose 三服务的起停、重启恢复（残留运行标为 `interrupted`，在途单元记未完成、排队单元记 `skipped`）。",
        "- **可复算的自检**：后端单元测试（快照导入、生命周期、事件、证据校验、统计口径、报告章节完整性）全部通过（`cd backend && uv run pytest tests/ -q`）；`scripts/` 下的自检脚本均在真实服务上执行过——SSE 断线续传无重复无空洞、人工验证闸门不放行执行失败的结论、UI 冒烟无控制台报错、两轮对比的 Markdown 与 `result.json` 一致。",
        "- **有意不做**：接入 Burp/AWVS 做同场对照（第 2 章对比表的实测列为待实测）；二次注入与存储型 XSS 等扩展场景；多用户与多实例部署——本实验是单用户本地工具。",
        "- **做了但未做对抗验证**：Prompt 注入防御以固定附加的不可信输入约束实现，尚未用专门的注入样本做过对抗性测试。",
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
        "### 4.2 Prompt 提示词工程模块",
        "",
        f"本次使用的 Prompt 版本为 **{run['prompt_label']}**（`{run['prompt_id']}`），全文如下：",
        "",
        "```text",
        run["prompt_text"].rstrip(),
        "```",
        "",
        "四段式结构：审计角色 → 核心任务 → 漏洞判定标准 → 输出格式；三类漏洞各有专属判定规则。",
        "不可信输入约束固定附加在版本全文之后，用于抵御被审计代码中的提示词注入。",
        "输入与输出：输入是作业固定的四段式要求与三类漏洞判定规则；输出是可直接提交的 Prompt 全文，随运行冻结在运行记录里（本报告即引用该冻结副本）。操作方法：在「Prompt 与实验」页选择已有版本或新增自定义版本，再由所选版本创建运行；命令行等价入口为 `scripts/prompt_rounds.sh`。",
        "",
    ]
    doc += _prompt_rounds(bundle)
    doc += [
        "### 4.3 LLM 漏洞推理挖掘模块",
        "",
        "三级分层推理：语法结构 → 漏洞语义 → 实际风险。每单元固定检查三类漏洞，结论取 candidate / no_candidate / insufficient_context。",
        f"每单元预算为 {run['budgets'].get('responses')} 次模型响应、{run['budgets'].get('tools')} 次工具调用、{run['budgets'].get('seconds')} 秒，输出纠正重试一次。",
        "预算耗尽、解析失败与上下文缺失均保留为未完成状态，不计入阴性结论。",
        "输入与输出：输入是该单元的文件范围与行号区间、该类别的判定规则、以及 Prompt 全文；输出是结构化结论（candidate / no_candidate / insufficient_context），候选附原文件行号、输入来源、传播关系、危险操作、防护判断、触发前提、风险等级、POC 与修复建议。",
        "工具只有 `read_source`、`search_code`、`get_context` 三个且均为只读；同一参数的重复调用会被拒绝并回注预算提示，防止小模型反复发起同一次搜索而不下结论。危险 API 命中只影响单元排序，不改变「每个单元都检查三类漏洞」这条覆盖规则。",
        "",
        "### 4.4 POC 实操验证模块",
        "",
        "候选漏洞必须附可运行 POC（原文件行号、输入来源、传播关系、危险操作、防护判断、触发前提、风险等级、修复建议）。",
        "验证记录区分脚本执行状态与人工结论：执行失败、语法错误、连接失败、环境不匹配、单次未触发均不自动算作误报。",
        "XSS 需要浏览器执行证据，仅响应包含 payload 不足以确认。",
        "输入与输出：输入是候选自带的 POC 脚本与靶机环境；输出是人工验证记录——执行状态、人工结论、正常输入对照、攻击输入观测、浏览器证据、脚本适配说明与问题归因、附件。操作方法：在「发现与验证」页下载 POC，对 <http://127.0.0.1:4280> 实际运行后回填记录；脚本按原样跑不通时先做适配再运行，适配内容照实记录而不是直接判为排除。",
        "",
        "### 4.5 结果校验与复盘模块",
        "",
        "双层校验：后端证据校验（引用必须属于当前快照，且模型确实读过该代码）+ 人工 POC 实操复筛。",
        "重复候选按指纹去重；未完成单元单列，不作为阴性结果。",
        "输入与输出：输入是候选漏洞、人工验证记录与独立核验的真值集；输出是审计覆盖率与验证覆盖率、去重后的候选、混淆矩阵与 Precision/Recall/F1、未决样本、误漏报归因以及两轮对比表，全部随 `result.json` 交付以便复算。操作方法：在「实验报告」页录入真值集与失败归因，再导出 Markdown / JSON / 证据包。",
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
            "于是探索阶段的观察连同已判定的其余类别一起丢失。"
            "改进方向：按类别放宽单次请求上限（XSS 的作答最长），或让收尾在墙钟将尽时降级为"
            "「只判定、不给 POC」，并保留已判定类别的结论。",
        ]
    doc += [
        f"- 证据校验剔除的引用：{len(discarded)} 条候选的引用全部无法核实，另有 {len(partially_cited)} 条候选被剔除了部分引用"
        "（行号不属于快照，或落在该单元没读过的代码里）。",
        "  这些记录保留在 6.4 节。逐条剔除的不可核实引用已从候选证据里去掉、记在各自条目下：",
        "  一条候选只要还有可核对的引用就保留——否则会把一次真实发现变成漏报；引用全不可核实的才降级。",
        "  **混淆矩阵只统计证据通过校验的候选**，所以 FP 的含义是「有证据支持却与真值相反」，",
        "  不等于「模型没说过错话」。",
        "- 已知局限：动态 include 与动态调用无法静态解析；切片边界可能截断跨片数据流；",
        "  模型输出稳定性与 POC 环境差异（PHP 版本、数据库分支、DVWA 安全等级）仍会带来噪声。",
        f"- 未接入传统扫描器对照，第 2 章对比实测数据为{NOT_MEASURED}。",
        "框架层面的实现到哪一步、哪些是有意不做的，见 3.5；本节只记录本次运行实测到的问题与归因。",
        "",
        "## 6. 实验总结",
        "",
        f"- 本次运行覆盖 {metrics['total_units']} 个审计单元，完成 {metrics['completed_units']} 个（审计覆盖率 {metrics['audit_coverage']:.2%}）。",
        f"- 产出候选漏洞 {len(candidates)} 条，其中已验证 {metrics['confirmed']} 条确认、{metrics['rejected']} 条排除、{metrics['uncertain']} 条不确定、{metrics['awaiting_verification']} 条待验证。",
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
    if evaluation:
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
        "### 6.3 候选漏洞与验证依据",
        "",
    ]
    if candidates:
        for index, finding in enumerate(candidates, 1):
            doc += _finding_block(finding, index)
    else:
        doc.append("本次运行未产生候选漏洞。")
    # Emitted even when empty, for the same reason as 6.5 below: an omitted section leaves a
    # hole in the outline (6.3 → 6.5) that reads as a chapter missing from the report rather
    # than one with nothing in it. The empty state also deserves its own sentence — "nothing
    # was discarded" means every citation the model gave checked out, which is not the same
    # as the check never having run.
    doc += ["### 6.4 引用全部无法核实的候选（保留记录，不计入候选）", ""]
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
        doc += ["本次运行未产生候选漏洞，因而也没有被剔除的候选。", ""]
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
    elif evaluation["FP"] or evaluation["FN"]:
        doc += [
            f"本次运行有 {evaluation['FP']} 个误报、{evaluation['FN']} 个漏报，但尚未记录归因。"
            "这些样本的失败原因与对应检查项需要人工在验证之后逐条填写"
            "（`POST /api/runs/{id}/attributions`），本报告只呈现已记录的内容。",
            "",
        ]
    elif evaluation["TP"] or evaluation["TN"]:
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
            f"本次运行未记录误报/漏报归因，且没有可对照的真值样本，"
            f"Precision、Recall、F1 均为**{NOT_COMPUTABLE}**，无从归因。",
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
        "统计可由 `result.json` 复算：候选数由 findings 中 validation_state=candidate 计数，",
        "覆盖率由 units 状态计数，混淆矩阵由 truths 与 candidates 交叉得到。",
        "",
    ]
    return "\n".join(doc)


def render_json(bundle: dict) -> str:
    return json.dumps(bundle, ensure_ascii=False, indent=2, default=str)


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
    for finding in bundle.get("findings") or []:
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
    return files


def render_zip(bundle: dict, evidence_files: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.md", render_markdown(bundle))
        archive.writestr("result.json", render_json(bundle))
        for name, payload in evidence_files:
            archive.writestr(f"evidence/{name}", payload)
        archive.writestr(
            "evidence/README.txt",
            "本目录保存三类证据：\n"
            "  poc_<finding-id>_<filename>            模型给出的 POC 脚本原件（含 6.4 节保留但不计入统计的条目）；\n"
            "  <verification-id>-adapted-<filename>   人工适配环境后的脚本，与其适配说明（report.md 6.3）对应；\n"
            "  <verification-id>-<filename>           人工验证时上传的日志、截图等附件。\n"
            "文件名前缀是发现 ID 或验证记录 ID，可在 report.md / result.json 中查到对应条目。\n",
        )
    return buffer.getvalue()
