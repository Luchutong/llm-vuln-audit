import { useEffect, useState } from 'react';
import { api, downloadUrl, errorText, post } from '../api';
import type { Evidence, Finding, RunDetail } from '../types';
import { SourceViewer } from '../components/SourceViewer';
import { Disclosure } from '../components/Disclosure';
import { LongContent } from '../components/LongContent';

const CATEGORY_LABELS: Record<string, string> = {
  sqli: 'SQL 注入',
  xss_r: '反射型 XSS',
  command_injection: '命令注入',
  task_goal: '目标发现',
};

function categoryLabel(category: string | null | undefined) {
  if (category?.startsWith('task_goal')) return '目标发现';
  return CATEGORY_LABELS[category ?? ''] ?? (category ? `任务类别：${category}` : '未标注类别');
}

function findingKindLabel(finding: Finding): string | null {
  if (!finding.finding_kind) return null;
  return `类型：${finding.finding_kind}`;
}

function isGenericSourceFinding(finding: Finding): boolean {
  return (finding.category.startsWith('task_goal') || Boolean(finding.finding_kind)) && !finding.poc;
}

function verdictLabel(finding: Finding, verdict: string | null | undefined): string {
  if (isGenericSourceFinding(finding)) {
    if (verdict === 'confirmed') return '确认结论';
    if (verdict === 'rejected') return '驳回结论';
    return '待定';
  }
  return VERDICT_LABELS[verdict ?? ''] ?? '未确定';
}

const EXECUTION_LABELS: Record<string, string> = {
  success: '执行成功，出现预期差异',
  syntax_error: '脚本语法错误',
  connection_failed: '无法连接目标',
  environment_mismatch: '环境不匹配',
  not_triggered: '执行成功但漏洞未触发',
  not_run: '未执行 / 仅静态阅读',
  other_error: '其他执行错误',
};

const VERDICT_LABELS: Record<string, string> = {
  confirmed: '确认漏洞',
  rejected: '排除（误报）',
  uncertain: '无法确定',
};

/**
 * Disposition is the third axis, beside "did the citations hold up" and "does it
 * reproduce": whether the run still stands behind this conclusion. Nothing here is ever
 * deleted — a withdrawn conclusion keeps its row, its evidence and its human verdict,
 * because "this run changed its mind" is itself part of the record.
 */
const DISPOSITION_LABELS: Record<string, string> = {
  retracted: '已被 Planner 撤回',
  duplicate: '被 Planner 判为重复',
  superseded: '已被后续结论取代',
  contested: 'Planner 对人工结论存疑',
};

function dispositionLabel(finding: Finding): string | null {
  const disposition = finding.disposition ?? 'open';
  return disposition === 'open' ? null : DISPOSITION_LABELS[disposition] ?? disposition;
}

const SOURCE_CONTEXT_LINES = 4;
const MAX_SOURCE_WINDOW_LINES = 400;
const MAX_EVIDENCE_LINES_PER_WINDOW = MAX_SOURCE_WINDOW_LINES - SOURCE_CONTEXT_LINES * 2;

interface EvidenceGroup {
  path: string;
  references: Evidence[];
}

interface EvidenceWindow {
  start: number;
  end: number;
  highlights: Evidence[];
}

function groupEvidence(references: Evidence[]): EvidenceGroup[] {
  const byPath = new Map<string, Evidence[]>();
  for (const reference of references) {
    const group = byPath.get(reference.path);
    if (group) group.push(reference);
    else byPath.set(reference.path, [reference]);
  }
  return [...byPath].map(([path, refs]) => ({ path, references: refs }));
}

/**
 * Keep every source request below the API's 400-line limit. Most findings need one
 * window, but split widely separated or unusually large cited ranges without ever
 * rendering a line from one file under the path of another.
 */
function evidenceWindows(references: Evidence[]): EvidenceWindow[] {
  const chunks: Evidence[] = [];
  for (const reference of references) {
    for (let start = reference.start_line; start <= reference.end_line; start += MAX_EVIDENCE_LINES_PER_WINDOW) {
      chunks.push({
        ...reference,
        start_line: start,
        end_line: Math.min(reference.end_line, start + MAX_EVIDENCE_LINES_PER_WINDOW - 1),
      });
    }
  }
  chunks.sort((left, right) => left.start_line - right.start_line || left.end_line - right.end_line);

  const windows: EvidenceWindow[] = [];
  for (const reference of chunks) {
    const start = Math.max(1, reference.start_line - SOURCE_CONTEXT_LINES);
    const end = reference.end_line + SOURCE_CONTEXT_LINES;
    const previous = windows.at(-1);
    const combinedEnd = previous ? Math.max(previous.end, end) : end;

    if (previous && start <= previous.end + 1 && combinedEnd - previous.start + 1 <= MAX_SOURCE_WINDOW_LINES) {
      previous.end = combinedEnd;
      previous.highlights.push(reference);
    } else {
      windows.push({ start, end, highlights: [reference] });
    }
  }
  return windows;
}

function evidenceRangeLabel(references: Evidence[]): string {
  return references.map((reference) => `${reference.start_line}-${reference.end_line}`).join('、');
}

function auditUnitLocation(finding: Pick<Finding, 'file_path' | 'unit_start_line' | 'unit_end_line' | 'task_id' | 'task_key'>): string {
  const source = `${finding.file_path}:${finding.unit_start_line}-${finding.unit_end_line}`;
  if (finding.task_id) {
    return `动态任务：${finding.task_key || finding.task_id.slice(0, 8)} · 来源：${source}`;
  }
  return `审计单元：${source}`;
}

/**
 * Findings and the human verification gate.
 *
 * A candidate here is a claim, not a final result. POC-bearing vulnerability candidates
 * need a reproducible execution record; a source fact such as a boundary or configuration
 * origin is instead accepted or rejected through a documented human code review.
 */
export function FindingsView({ detail, snapshotId, onChanged }: { detail: RunDetail; snapshotId: string; onChanged: () => void }) {
  const [selected, setSelected] = useState<string | null>(null);

  const findings = detail.findings;
  const current = findings.find((finding) => finding.id === selected) ?? findings[0] ?? null;

  if (!findings.length) {
    return <div className="empty">这次运行没有产生候选发现。<br />动态任务状态和审计依据请在「概览」与「执行轨迹」中查看。</div>;
  }

  return (
    <div className="finding-layout">
      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">候选发现</span>
          <span className="faint small">{findings.length}</span>
        </div>
        <div style={{ maxHeight: 620, overflowY: 'auto' }}>
          {findings.map((finding) => (
            <button
              key={finding.id}
              onClick={() => setSelected(finding.id)}
              aria-pressed={current?.id === finding.id}
              style={{
                display: 'block', width: '100%', textAlign: 'left', padding: '10px 14px',
                border: 'none', borderBottom: '1px solid var(--line-soft)', cursor: 'pointer',
                background: current?.id === finding.id ? 'var(--accent-soft)' : 'transparent',
              }}
            >
              <div className="row" style={{ flexWrap: 'wrap', marginBottom: 3 }}>
                <span className={`chip chip-${finding.validation_state}`}>
                  {finding.validation_state === 'candidate' ? '证据通过' : '证据不通过'}
                </span>
                <span className={`chip sev-${finding.severity}`}>{finding.severity}</span>
                {finding.verdict && <span className={`chip chip-${finding.verdict}`}>{verdictLabel(finding, finding.verdict)}</span>}
                {dispositionLabel(finding) && <span className="chip chip-paused">{dispositionLabel(finding)}</span>}
                {finding.revision > 1 && <span className="chip">第 {finding.revision} 版</span>}
              </div>
              <div className="small disclosure-preview" style={{ fontWeight: 500 }}>{finding.title}</div>
              <div className="faint small">{categoryLabel(finding.category)}</div>
              {findingKindLabel(finding) && <div className="faint small">{findingKindLabel(finding)}</div>}
              <div className="mono faint disclosure-preview" style={{ fontSize: 11.5 }}>
                {auditUnitLocation(finding)}
              </div>
            </button>
          ))}
        </div>
      </div>

      {current && <FindingDetail key={current.id} finding={current} snapshotId={snapshotId} onChanged={onChanged} />}
    </div>
  );
}

function FindingDetail({ finding, snapshotId, onChanged }: { finding: Finding; snapshotId: string; onChanged: () => void }) {
  const poc = finding.poc;
  const evidenceGroups = groupEvidence(finding.evidence);
  const genericSourceFinding = isGenericSourceFinding(finding);
  return (
    <div className="grid">
      <section className="panel" aria-label="发现详情">
        <div className="panel-head">
          <div>
            <div className="panel-title">{finding.title}</div>
            <div className="faint small">{categoryLabel(finding.category)}{finding.finding_kind ? ` · ${finding.finding_kind}` : ''}</div>
          </div>
          <div className="row">
            <span className={`chip sev-${finding.severity}`}>{finding.severity}</span>
            <span className={`chip chip-${finding.validation_state}`}>
              {finding.validation_state === 'candidate' ? '证据通过' : '证据不通过'}
            </span>
            {finding.verdict && <span className={`chip chip-${finding.verdict}`}>{verdictLabel(finding, finding.verdict)}</span>}
            {dispositionLabel(finding) && <span className="chip chip-paused">{dispositionLabel(finding)}</span>}
            {finding.revision > 1 && <span className="chip">第 {finding.revision} 版</span>}
          </div>
        </div>
        <div className="panel-body grid">
          <p className="small muted">引用校验、人工裁决与结论处置分别保留；Planner 的撤回或争议不会改写人工裁决。</p>
          <LongContent value={auditUnitLocation(finding)} label="审计来源" />
          <LongContent value={finding.summary} label={genericSourceFinding ? '审计依据' : '分析依据'} />
          {finding.validation_errors.length > 0 && (
            <Disclosure title={`引用校验说明（${finding.validation_errors.length}）`}>
              <div className="error-box">
                {finding.validation_state === 'candidate' ? '无法核实的引用已剔除，剩余引用支撑此候选。' : '引用全部无法核实，此候选不计入可信发现。'}
                <LongContent value={finding.validation_errors} label="引用校验问题" />
              </div>
            </Disclosure>
          )}
          <Disclosure title="数据流、前置条件与修复建议">
            <Chain label={genericSourceFinding ? '相关输入' : '输入来源'} value={finding.input_source} />
            <Chain label={genericSourceFinding ? '数据或控制流' : '传播路径'} value={finding.propagation} />
            <Chain label="敏感操作" value={finding.dangerous_operation} />
            <Chain label="边界或防护" value={finding.protection || '无'} />
            <Chain label="前置条件" value={finding.preconditions.join('；') || '无'} />
            <Chain label="缺失上下文" value={finding.missing_context.join('；') || '无'} />
            <Chain label="修复建议" value={finding.remediation} />
          </Disclosure>
        </div>
      </section>

      <section className="panel" aria-label="证据源码">
        <div className="panel-head">
          <span className="panel-title">证据源码</span>
          <span className="faint small">{evidenceGroups.length} 个文件 · {finding.evidence.length} 处引用</span>
        </div>
        <div className="panel-body">
          {evidenceGroups.length === 0 ? <div className="empty">没有可显示的已验证证据行。</div> : evidenceGroups.map((group) => {
            const windows = evidenceWindows(group.references);
            return (
              <Disclosure key={group.path} title={<span className="disclosure-heading"><span className="mono disclosure-preview">{group.path}</span><span className="faint small">{group.references.length} 处引用</span></span>}>
                <LongContent value={group.path} label="证据文件" />
                <LongContent value={evidenceRangeLabel(group.references)} label="证据行" />
                {windows.map((window, windowIndex) => (
                  <Disclosure key={`${window.start}-${window.end}-${windowIndex}`} title={`查看源码 ${window.start}–${window.end} 行`}>
                    <SourceViewer snapshotId={snapshotId} path={group.path} start={window.start} end={window.end} highlight={window.highlights} height={280} />
                  </Disclosure>
                ))}
              </Disclosure>
            );
          })}
        </div>
      </section>

      {poc && (
        <section className="panel" aria-label="POC 脚本">
          <div className="panel-head">
            <span className="panel-title">POC 脚本</span>
            <a className="btn" href={downloadUrl(`/findings/${finding.id}/poc`)} download>下载 POC</a>
          </div>
          <div className="panel-body">
            <Disclosure title={`查看 ${poc.filename}`}>
              <div className="grid detail-fields">
                <Chain label="正常输入（对照）" value={poc.normal_input} />
                <Chain label="攻击输入" value={poc.attack_input} />
                <Chain label="预期差异" value={poc.expected_result} />
                <Chain label="运行说明" value={poc.instructions} />
              </div>
              <LongContent value={poc.script} label="POC 脚本全文" />
            </Disclosure>
          </div>
        </section>
      )}

      <section className="panel" aria-label={genericSourceFinding ? '人工复核' : '人工验证'}>
        <div className="panel-head">
          <span className="panel-title">{genericSourceFinding ? '人工复核' : '人工验证'}</span>
          <span className="faint small">{finding.verifications.length} 条记录</span>
        </div>
        <div className="panel-body grid">
          {finding.verifications.length > 0 && <Disclosure title={`查看历史记录（${finding.verifications.length}）`}>
            {finding.verifications.map((record, index) => (
              <Disclosure key={record.id ?? index} title={<span className="disclosure-heading"><span className={`chip chip-${record.verdict}`}>{verdictLabel(finding, record.verdict)}</span><span className="faint small">{record.created_at?.slice(0, 19).replace('T', ' ')}</span></span>}>
                {!genericSourceFinding && <div className="small">{EXECUTION_LABELS[record.execution_status] ?? record.execution_status}{record.browser_execution ? ' · 含浏览器执行证据' : ''}</div>}
                <Chain label={genericSourceFinding ? '复核环境或版本' : '目标版本'} value={record.target_version || ''} />
                {!genericSourceFinding && <Chain label="执行命令" value={record.command || ''} />}
                <Chain label="攻击观测" value={record.attack_observation || ''} />
                <Chain label="对照观测" value={record.normal_observation || ''} />
                <Chain label="改动说明" value={record.modification_notes || ''} />
                <Chain label="备注" value={record.notes || ''} />
                {(record.files ?? []).length > 0 && <div className="row small">
                  <span>证据附件：</span>
                  {(record.files ?? []).map((file, fileIndex) => {
                    const item = typeof file === 'string' ? { name: file, url: '' } : file;
                    const url = item.url ?? (item.stored ? `/api/evidence/${item.stored}` : '');
                    return url
                      ? <a key={fileIndex} className="btn" href={url} target="_blank" rel="noreferrer">{item.name ?? item.filename ?? '附件'}</a>
                      : <span key={fileIndex} className="chip">{item.name ?? item.filename}</span>;
                  })}
                </div>}
              </Disclosure>
            ))}
          </Disclosure>}
          <Disclosure title={genericSourceFinding ? '记录一次人工复核' : '记录一次人工验证'}>
            <VerificationForm finding={finding} onRecorded={onChanged} />
          </Disclosure>
        </div>
      </section>
      <Lineage finding={finding} />
    </div>
  );
}

/** Archived revisions and Planner disposition never overwrite a human verdict. */
function Lineage({ finding }: { finding: Finding }) {
  const disposition = dispositionLabel(finding);
  const archived = finding.superseded_summary ?? [];
  if (!disposition && (finding.revision ?? 1) <= 1 && !archived.length) return null;
  return <section className="panel" aria-label="结论沿革">
    <div className="panel-head"><span className="panel-title">结论沿革</span><span className="chip">第 {finding.revision ?? 1} 版</span></div>
    <div className="panel-body grid">
      {disposition && <div className="row"><span className="chip chip-paused">{disposition}</span><span className="small muted">人工裁决仍独立保留</span></div>}
      <Disclosure title={`查看处置与历史版本（${archived.length}）`}>
        <Chain label="处置理由" value={finding.disposition_reason ?? ''} />
        <Chain label="标注者" value={finding.disposition_by === 'human' ? '人工' : finding.disposition_by === 'planner' ? 'Planner' : finding.disposition_by ?? ''} />
        <Chain label="处置时间" value={finding.disposition_at ?? ''} />
        <Chain label={finding.disposition === 'duplicate' ? '重复于' : '派生自'} value={finding.derived_from_finding_id ?? ''} />
        {archived.map((revision) => <Disclosure key={revision.revision} title={<span className="disclosure-heading"><span className="chip">第 {revision.revision} 版</span><span className="disclosure-preview">{revision.title}</span>{revision.disposition && revision.disposition !== 'open' && <span className="chip chip-paused">{DISPOSITION_LABELS[revision.disposition] ?? revision.disposition}</span>}</span>}>
          <Chain label="被取代时间" value={revision.replaced_at ?? ''} />
          <Chain label="历史标题" value={revision.title} />
          <Chain label="历史摘要" value={revision.summary} />
          <LongContent value={revision.evidence} label="历史源码引用" />
          <LongContent value={{ 严重性: revision.severity, 引用校验: revision.validation_state, 引用问题: revision.validation_errors, 处置: revision.disposition, 处置理由: revision.disposition_reason, 标注者: revision.disposition_by }} label="历史结论状态" />
        </Disclosure>)}
      </Disclosure>
    </div>
  </section>;
}

function Chain({ label, value }: { label: string; value: string }) {
  if (!value) return null;
  return <div className="field"><LongContent value={value} label={label} /></div>;
}

interface FormState {
  verdict: 'confirmed' | 'rejected' | 'uncertain';
  execution_status: string;
  command: string;
  target_version: string;
  normal_observation: string;
  attack_observation: string;
  modification_notes: string;
  modified_script: string;
  browser_execution: boolean;
  notes: string;
}

const blankForm = (finding: Finding): FormState => ({
  verdict: 'uncertain',
  execution_status: 'not_run',
  command: '',
  target_version: '',
  normal_observation: '',
  attack_observation: '',
  modification_notes: '',
  modified_script: finding.poc?.script ?? '',
  browser_execution: false,
  notes: '',
});

function VerificationForm({ finding, onRecorded }: { finding: Finding; onRecorded: () => void }) {
  const [form, setForm] = useState<FormState>(() => blankForm(finding));
  const [files, setFiles] = useState<File[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const genericSourceFinding = isGenericSourceFinding(finding);

  useEffect(() => {
    setForm(blankForm(finding));
    setFiles([]);
    setError(null);
    setDone(false);
  }, [finding.id]);

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) => setForm((current) => ({ ...current, [key]: value }));

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const body = new FormData();
      body.append('record', JSON.stringify(form));
      for (const file of files) body.append('files', file);
      await api(`/findings/${finding.id}/verifications`, { method: 'POST', body });
      setDone(true);
      onRecorded();
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="verification-form" onSubmit={(event) => { event.preventDefault(); void submit(); }}>
      <div className="field-label" style={{ marginBottom: 8 }}>
        {genericSourceFinding ? '记录一次复核' : '记录一次验证'}
      </div>

      <div className="grid form-grid">
        <label className="field">
          <span className="field-label">人工结论</span>
          <select value={form.verdict} onChange={(event) => set('verdict', event.target.value as FormState['verdict'])}>
            <option value="uncertain">{genericSourceFinding ? '待定' : '无法确定'}</option>
            {(!genericSourceFinding || finding.validation_state === 'candidate') && (
              <option value="confirmed">{genericSourceFinding ? '确认结论' : '确认漏洞'}</option>
            )}
            <option value="rejected">{genericSourceFinding ? '驳回结论' : '排除（误报）'}</option>
          </select>
        </label>
        {!genericSourceFinding && (
          <label className="field">
            <span className="field-label">执行状态</span>
            <select value={form.execution_status} onChange={(event) => set('execution_status', event.target.value)}>
              {Object.entries(EXECUTION_LABELS).map(([value, text]) => (
                <option key={value} value={value}>{text}</option>
              ))}
            </select>
          </label>
        )}
        <label className="field">
          <span className="field-label">{genericSourceFinding ? '复核环境或版本（可选）' : '目标版本'}</span>
          <input type="text" value={form.target_version} placeholder={genericSourceFinding ? '例如 commit ID、分支或复核环境' : '例如 版本号 / commit ID / 构建标识'} onChange={(event) => set('target_version', event.target.value)} />
        </label>
      </div>

      {!genericSourceFinding && (
        <>
          <label className="field">
            <span className="field-label">执行命令</span>
            <input type="text" className="mono" value={form.command} placeholder="填写实际执行命令及目标地址" onChange={(event) => set('command', event.target.value)} />
          </label>

          <div className="grid form-grid">
            <label className="field">
              <span className="field-label">正常输入的实际观测（确认或排除时必填）</span>
              <textarea rows={2} value={form.normal_observation} onChange={(event) => set('normal_observation', event.target.value)} />
            </label>
            <label className="field">
              <span className="field-label">攻击输入的实际观测（确认或排除时必填）</span>
              <textarea rows={2} value={form.attack_observation} onChange={(event) => set('attack_observation', event.target.value)} />
            </label>
          </div>

          <label className="field">
            <span className="field-label">对脚本做的适配改动与原因</span>
            <textarea rows={2} value={form.modification_notes} onChange={(event) => set('modification_notes', event.target.value)} />
          </label>

          <label className="field">
            <span className="field-label">实际运行的脚本（可与下发脚本不同）</span>
            <textarea rows={4} className="mono" value={form.modified_script} onChange={(event) => set('modified_script', event.target.value)} />
          </label>
        </>
      )}

      <label className="field">
        <span className="field-label">{genericSourceFinding ? '复核附件（可选）' : '证据附件（日志 / 截图）'}</span>
        <input type="file" multiple onChange={(event) => setFiles(Array.from(event.target.files ?? []))} />
        <span className="field-hint">
          {genericSourceFinding
            ? '可附代码评审记录、截图或其他能帮助复核结论的材料。'
            : finding.category === 'xss_r'
            ? '反射型 XSS 确认必须勾选浏览器执行证据并上传日志或截图。'
            : '确认漏洞需上传日志、截图或其他可复核证据；执行失败的输出也建议保留。'}
        </span>
      </label>

      {!genericSourceFinding && (
        <div className="field">
          <label className="checkbox">
            <input type="checkbox" checked={form.browser_execution} onChange={(event) => set('browser_execution', event.target.checked)} />
            已在真实浏览器中执行（XSS 必需）
          </label>
        </div>
      )}

      <label className="field">
        <span className="field-label">{genericSourceFinding ? '人工复核说明（确认或驳回时必填）' : '备注'}</span>
        <textarea rows={2} value={form.notes} onChange={(event) => set('notes', event.target.value)} />
      </label>

      {error && <div role="alert" className="error-box" style={{ marginBottom: 10 }}>{error}</div>}
      {done && !error && <div role="status" className="small" style={{ color: 'var(--ok)', marginBottom: 10 }}>已记录。</div>}

      <div className="row">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? '提交中…' : genericSourceFinding ? '提交复核记录' : '提交验证记录'}
        </button>
        <span className="field-hint">
          {genericSourceFinding
            ? '确认或驳回需要填写源码复核说明；可附代码评审记录、截图或其他证据。'
            : '确认或排除都需要成功执行、目标版本、命令和正常/攻击观测；确认还必须上传证据附件。'}
        </span>
      </div>
    </form>
  );
}
