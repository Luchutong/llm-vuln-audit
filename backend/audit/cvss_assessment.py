"""Evidence-bound proposals; the host alone computes severity and score."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from .cvss31 import BASE, VALUES, assessment

ENGINE_VERSION = 'cvss31-base-1'
STATUSES = ('scored', 'needs_information', 'legacy_unrated', 'stale')
INSTRUCTION = '''
CVSS 3.1 基础评分由宿主计算。每条漏洞在 cvss_input 中填写 AV、AC、PR、UI、S、C、I、A。
每项为 {value: 指标值或null, rationale: 简短判断依据, evidence: [{path,start_line,end_line}]}。
只引用本次实际读过的原始源码；不确定时 value=null 并说明缺失信息，不猜默认值。
指标不足只影响评分状态；仍应保存已由源码证据支持的漏洞，不以未评分为由丢弃发现。
AV=N/A/L/P；AC=L/H；PR=N/L/H；UI=N/R；S=U/C；C/I/A=N/L/H。
按独立漏洞的直接影响评估：不默认串联其他漏洞、不使用教学口令消除权限前提。
PR是攻击前所需权限，不凭角色名称猜测；UI是另一名用户的参与；S是安全授权边界的改变，
跨文件/跨进程不等于S:C。C/I/A必须有可支持的影响依据，缺少信息不是N或H。
不要填写最终数字或等级；旧severity字段仅作兼容，不能覆盖宿主结果。
POC验证成功或失败不直接升降基础分。禁止读取靶场答案作为评分依据。
'''


def stamp():
    return datetime.now(timezone.utc).isoformat()


def propose(value, *, validate_refs=None, source='auto', snapshot_id=None, run_id=None, strict=False):
    """Keep useful findings when a proposal is malformed or partially unsupported.

    Automatic values require at least one source range checked against the worker's
    exact read ledger. Manual assessments allow explicitly labelled assumptions.
    """
    details, metrics, problems = {}, {}, []
    proposal = value if isinstance(value, dict) else {}
    for key in BASE:
        item = proposal.get(key)
        item = item if isinstance(item, dict) else {}
        raw = item.get('value')
        rationale = item.get('rationale')
        rationale = rationale.strip()[:2400] if isinstance(rationale, str) else ''
        refs = item.get('evidence')
        refs = refs if isinstance(refs, list) else []
        good, errors = [], []
        for ref in refs:
            if not isinstance(ref, dict):
                errors.append('引用格式无效'); continue
            path, start, end = ref.get('path'), ref.get('start_line'), ref.get('end_line')
            if not isinstance(path, str) or not path or type(start) is not int or type(end) is not int or start < 1 or end < start:
                errors.append('引用路径或行号无效'); continue
            clean = {'path': path, 'start_line': start, 'end_line': end}
            if snapshot_id:
                clean['snapshot_id'] = snapshot_id
            good.append(clean)
        if validate_refs and good:
            good, invalid = validate_refs(good)
            errors.extend(invalid)
        if snapshot_id:
            good = [{**ref, 'snapshot_id': snapshot_id} for ref in good]
        assumption = item.get('assumption') is True and source == 'manual'
        valid = isinstance(raw, str) and len(raw) == 1 and raw in VALUES[key] and bool(rationale)
        if not good and not assumption:
            valid = False
            errors.append('缺少可核实的源码引用或明确人工假设')
        if raw is None:
            errors.append('指标待补充')
        elif not isinstance(raw, str) or len(raw) != 1 or raw not in VALUES[key]:
            errors.append('指标取值无效')
        if not rationale:
            errors.append('缺少判断依据')
        if errors:
            valid = False
        details[key] = {'value': raw if valid else None, 'rationale': rationale, 'evidence': good,
                        'assumption': assumption, 'issues': errors}
        if valid:
            metrics[key] = raw
        else:
            problems.extend(f'{key}: {error}' for error in errors)
    if strict and problems:
        raise ValueError('；'.join(problems))
    cvss = assessment({'base_vector': 'CVSS:3.1/' + '/'.join(f'{key}:{metrics[key]}' for key in BASE)}) if len(metrics) == 8 else None
    return {'cvss': cvss, 'severity': cvss['severity'] if cvss else 'unknown',
            'cvss_assessment': {'status': 'scored' if cvss else 'needs_information', 'source': source,
                'assessment_revision': 1, 'conclusion_revision': 1, 'engine_version': ENGINE_VERSION,
                'metric_details': details, 'issues': problems, 'created_at': stamp(),
                'snapshot_id': snapshot_id, 'run_id': run_id}}


def normalise_record(record):
    item = copy.deepcopy(record)
    # All entry points (including old fixed-category output) use the same boundary.
    info = item.get('cvss_assessment')
    if not isinstance(info, dict):
        item['legacy_severity'] = item.get('legacy_severity') or item.get('severity')
        info = {'status': 'legacy_unrated', 'source': 'legacy', 'assessment_revision': 0,
                'conclusion_revision': item.get('revision', 1), 'metric_details': {}, 'issues': []}
    cvss = None
    if info.get('status') == 'scored':
        try:
            cvss = assessment(item.get('cvss'))
        except ValueError:
            pass
        if not cvss:
            info['status'] = 'needs_information'
    item.update(cvss=cvss, cvss_assessment=info, severity=cvss['severity'] if cvss else 'unknown')
    return item


def rating_text(finding):
    cvss = finding.get('cvss')
    if isinstance(cvss, dict) and cvss.get('base_score') is not None:
        return f"CVSS 3.1 Base {cvss['base_score']:.1f} ({cvss['severity']}) · {cvss.get('base_vector', '')}"
    old = finding.get('legacy_severity') or (finding.get('severity') if not finding.get('cvss_assessment') else None)
    return f'历史等级 {old}，未量化' if old else 'CVSS 3.1 待评分'


def rating_details_lines(finding):
    """Export the same evidence and provenance as the detail UI, including gaps."""
    info = finding.get('cvss_assessment') or {}
    if not info:
        return []

    def cell(value):
        return str(value if value is not None else '—').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('`', '&#96;').replace('\r', '').replace('\n', '<br>')

    status = {'scored': '已量化', 'needs_information': '待补充指标', 'legacy_unrated': '历史未量化', 'stale': '评分已失效'}
    source = {'auto': '自动指标，宿主计算', 'manual': '人工修订', 'legacy': '历史记录'}
    lines = ['**CVSS 3.1 评分依据**', '',
             f"- 状态：{status.get(info.get('status'), cell(info.get('status')))}；来源：{source.get(info.get('source'), cell(info.get('source')))}",
             f"- 评分版本：{cell(info.get('assessment_revision'))}；适用结论版本：{cell(info.get('conclusion_revision'))}；引擎：{cell(info.get('engine_version'))}"]
    for key, label in (('run_id', '来源任务'), ('snapshot_id', '来源 ZIP 快照'), ('created_at', '评分时间'), ('reason', '修订原因')):
        if info.get(key):
            lines.append(f'- {label}：{cell(info[key])}')
    details = info.get('metric_details') or {}
    if details:
        lines += ['', '| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |', '|---|---|---|---|---|']
        for key in BASE:
            item = details.get(key) or {}
            refs = [f"{ref.get('path')}:{ref.get('start_line')}-{ref.get('end_line')} (ZIP {ref.get('snapshot_id') or info.get('snapshot_id') or '来源不可用'})"
                    for ref in item.get('evidence') or [] if isinstance(ref, dict)]
            if item.get('assumption'):
                refs.append('人工假设')
            lines.append('| ' + ' | '.join(map(cell, (key, item.get('value') or '待补充', item.get('rationale') or '暂无依据', '；'.join(refs) or '来源不可用', '；'.join(item.get('issues') or []) or '—'))) + ' |')
    lines += ['', '评分、引用校验、自动验证和结论处置分别记录。', '']
    return lines
