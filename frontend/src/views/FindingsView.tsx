import { useEffect, useState } from 'react';
import { api, downloadUrl, errorText, post } from '../api';
import type { Evidence, Finding, RunDetail } from '../types';
import { SourceViewer } from '../components/SourceViewer';

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
    <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 14, alignItems: 'start' }}>
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
              <div className="small" style={{ fontWeight: 500 }}>{categoryLabel(finding.category)}</div>
              {findingKindLabel(finding) && <div className="faint small">{findingKindLabel(finding)}</div>}
              <div className="mono faint" style={{ fontSize: 11.5 }}>
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
      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="panel-title">{categoryLabel(finding.category)} · {finding.title}</div>
            <div className="mono faint small">{auditUnitLocation(finding)}{finding.finding_kind ? ` · ${finding.finding_kind}` : ''}</div>
          </div>
          <div className="row">
            <span className={`chip sev-${finding.severity}`}>{finding.severity}</span>
            <span className={`chip chip-${finding.validation_state}`}>
              {finding.validation_state === 'candidate' ? '证据校验通过' : '证据校验不通过'}
            </span>
            {dispositionLabel(finding) && <span className="chip chip-paused">{dispositionLabel(finding)}</span>}
            {finding.revision > 1 && <span className="chip">第 {finding.revision} 版</span>}
          </div>
        </div>

        {finding.validation_errors.length > 0 && (
          <div style={{ padding: '10px 16px' }}>
            <div className="error-box">
              {finding.validation_state === 'candidate'
                ? '模型给出的部分引用无法核实，已从证据中剔除；这条候选由剩下能核对的引用支撑：'
                : '这条候选的引用全部无法核实，因此不计入可信发现：'}
              <ul style={{ margin: '6px 0 0 18px', padding: 0 }}>
                {finding.validation_errors.map((problem, index) => <li key={index}>{problem}</li>)}
              </ul>
            </div>
          </div>
        )}

        <div style={{ padding: '12px 16px' }}>
          {genericSourceFinding ? (
            <>
              <Chain label="审计依据" value={finding.summary} />
              <Chain label="相关输入" value={finding.input_source} />
              <Chain label="数据或控制流" value={finding.propagation} />
              <Chain label="敏感操作" value={finding.dangerous_operation} />
              <Chain label="边界或防护" value={finding.protection} />
              <Chain label="前置条件" value={finding.preconditions.join('；')} />
              <Chain label="缺失上下文" value={finding.missing_context.join('；')} />
              <Chain label="建议" value={finding.remediation} />
            </>
          ) : (
            <>
              <Chain label="输入来源" value={finding.input_source} />
              <Chain label="传播路径" value={finding.propagation} />
              <Chain label="危险操作" value={finding.dangerous_operation} />
              <Chain label="防护判断" value={finding.protection || '无'} />
              <Chain label="触发前提" value={finding.preconditions.join('；') || '无'} />
              <Chain label="缺失上下文" value={finding.missing_context.join('；') || '无'} />
              <Chain label="分析依据" value={finding.summary} />
              <Chain label="修复建议" value={finding.remediation} />
            </>
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="panel-title">证据源码（高亮为证据行）</div>
            <div className="faint small">按证据文件分组；审计单元位置见上方</div>
          </div>
          <span className="faint small">
            {evidenceGroups.length} 个文件 · {finding.evidence.length} 处引用
          </span>
        </div>
        {evidenceGroups.length === 0 ? (
          <div className="empty">没有可显示的已验证证据行。</div>
        ) : evidenceGroups.map((group, groupIndex) => {
          const windows = evidenceWindows(group.references);
          return (
            <section
              key={group.path}
              style={{ padding: '12px 16px', borderBottom: groupIndex < evidenceGroups.length - 1 ? '1px solid var(--line-soft)' : undefined }}
            >
              <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap', marginBottom: 8 }}>
                <span className="mono small" style={{ overflowWrap: 'anywhere' }}>{group.path}</span>
                <span className="faint small">证据行：{evidenceRangeLabel(group.references)}</span>
              </div>
              {windows.map((window, windowIndex) => (
                <div key={`${window.start}-${window.end}-${windowIndex}`} style={{ marginTop: windowIndex ? 12 : 0 }}>
                  {windows.length > 1 && (
                    <div className="faint small" style={{ marginBottom: 4 }}>源码窗口：{window.start}-{window.end}</div>
                  )}
                  <div style={{ border: '1px solid var(--line-soft)', borderRadius: 6, overflow: 'hidden' }}>
                    <SourceViewer
                      snapshotId={snapshotId}
                      path={group.path}
                      start={window.start}
                      end={window.end}
                      highlight={window.highlights}
                      height={280}
                    />
                  </div>
                </div>
              ))}
            </section>
          );
        })}
      </div>

      {poc && (
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">POC 脚本</span>
            <a className="btn" href={downloadUrl(`/findings/${finding.id}/poc`)} download>
              下载 {poc.filename}
            </a>
          </div>
          <div style={{ padding: '12px 16px' }}>
            <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', marginBottom: 12 }}>
              <Chain label="正常输入（对照）" value={poc.normal_input} />
              <Chain label="攻击输入" value={poc.attack_input} />
              <Chain label="预期差异" value={poc.expected_result} />
              <Chain label="运行说明" value={poc.instructions} />
            </div>
            <pre className="tl-detail" style={{ maxHeight: 300 }}>{poc.script}</pre>
          </div>
        </div>
      )}

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">{genericSourceFinding ? '人工复核' : '人工验证'}</span>
          <span className="faint small">{finding.verifications.length} 条记录</span>
        </div>
        {finding.verifications.map((record, index) => (
          <div key={record.id ?? index} style={{ padding: '10px 16px', borderBottom: '1px solid var(--line-soft)' }}>
            <div className="row" style={{ flexWrap: 'wrap' }}>
              <span className={`chip chip-${record.verdict}`}>{verdictLabel(finding, record.verdict)}</span>
              {!genericSourceFinding && <span className="chip">{EXECUTION_LABELS[record.execution_status] ?? record.execution_status}</span>}
              {!genericSourceFinding && record.browser_execution && <span className="chip">含浏览器执行证据</span>}
              <span className="faint small">{record.created_at?.slice(0, 19)}</span>
            </div>
            {record.target_version && (
              <div className="small muted" style={{ marginTop: 6 }}>
                {genericSourceFinding ? '复核环境或版本' : '目标版本'}：{record.target_version}
              </div>
            )}
            {!genericSourceFinding && record.command && <div className="small muted">执行命令：<span className="mono">{record.command}</span></div>}
            {record.attack_observation && <div className="small" style={{ marginTop: 6 }}>攻击观测：{record.attack_observation}</div>}
            {record.normal_observation && <div className="small muted">对照观测：{record.normal_observation}</div>}
            {record.modification_notes && <div className="small muted">改动说明：{record.modification_notes}</div>}
            {record.notes && <div className="small muted">备注：{record.notes}</div>}
            {(record.files ?? []).length > 0 && (
              <div className="row small" style={{ marginTop: 6, flexWrap: 'wrap' }}>
                证据附件：
                {(record.files ?? []).map((file, fileIndex) => {
                  const item = typeof file === 'string' ? { name: file, url: '' } : file;
                  const url = item.url ?? (item.stored ? `/api/evidence/${item.stored}` : '');
                  return url
                    ? <a key={fileIndex} className="btn" href={url} target="_blank" rel="noreferrer">{item.name ?? item.filename ?? '附件'}</a>
                    : <span key={fileIndex} className="chip">{item.name ?? item.filename}</span>;
                })}
              </div>
            )}
          </div>
        ))}
        <VerificationForm finding={finding} onRecorded={onChanged} />
      </div>

      <Lineage finding={finding} />
    </div>
  );
}

/**
 * Where this conclusion came from and what happened to it.
 *
 * A re-run of the same direction reuses the slot rather than replacing the row, so the
 * earlier text is archived here instead of lost. Without this panel, a conclusion that
 * changed its story between rounds — narrowed to what the citations support, withdrawn
 * and then re-asserted — would read exactly like one that always said this.
 */
function Lineage({ finding }: { finding: Finding }) {
  const disposition = dispositionLabel(finding);
  const archived = finding.superseded_summary ?? [];
  if (!disposition && finding.revision <= 1 && !archived.length) return null;
  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <div className="panel-title">结论沿革</div>
          <div className="faint small">本条结论是第 {finding.revision} 版；此前内容与处置变更都保留在这里。</div>
        </div>
        {disposition && <span className="chip chip-paused">{disposition}</span>}
      </div>
      <div style={{ padding: '12px 16px' }}>
        {disposition && (
          <>
            <Chain label="处置理由" value={finding.disposition_reason ?? ''} />
            <Chain label="标注者" value={finding.disposition_by === 'human' ? '人工' : finding.disposition_by === 'planner' ? 'Planner' : ''} />
            <Chain
              label={finding.disposition === 'duplicate' ? '重复于' : '派生自'}
              value={finding.derived_from_finding_id ? finding.derived_from_finding_id.slice(0, 8) : ''}
            />
          </>
        )}
        {archived.map((revision) => (
          <div key={revision.revision} style={{ borderTop: '1px solid var(--line-soft)', paddingTop: 8, marginTop: 8 }}>
            <div className="row" style={{ flexWrap: 'wrap' }}>
              <span className="chip">第 {revision.revision} 版</span>
              {revision.disposition && revision.disposition !== 'open' && (
                <span className="chip chip-paused">{DISPOSITION_LABELS[revision.disposition] ?? revision.disposition}</span>
              )}
              <span className="faint small">{revision.replaced_at?.slice(0, 19)} 被取代</span>
            </div>
            <div className="small" style={{ marginTop: 5 }}>{revision.title}</div>
            {revision.summary && <div className="small muted">{revision.summary}</div>}
            <div className="mono faint" style={{ fontSize: 11.5, marginTop: 4 }}>
              {revision.evidence.map((item) => `${item.path}:${item.start_line}-${item.end_line}`).join('、') || '（无行号引用）'}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Chain({ label, value }: { label: string; value: string }) {
  if (!value) return null;
  return (
    <div className="field" style={{ marginBottom: 9 }}>
      <span className="field-label">{label}</span>
      <span className="small" style={{ overflowWrap: 'anywhere' }}>{value}</span>
    </div>
  );
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
    <div style={{ padding: '12px 16px' }}>
      <div className="field-label" style={{ marginBottom: 8 }}>
        {genericSourceFinding ? '记录一次复核' : '记录一次验证'}
      </div>

      <div className="grid" style={{ gridTemplateColumns: genericSourceFinding ? '1fr 1fr' : '1fr 1fr 1fr' }}>
        <div className="field">
          <span className="field-label">人工结论</span>
          <select value={form.verdict} onChange={(event) => set('verdict', event.target.value as FormState['verdict'])}>
            <option value="uncertain">{genericSourceFinding ? '待定' : '无法确定'}</option>
            {(!genericSourceFinding || finding.validation_state === 'candidate') && (
              <option value="confirmed">{genericSourceFinding ? '确认结论' : '确认漏洞'}</option>
            )}
            <option value="rejected">{genericSourceFinding ? '驳回结论' : '排除（误报）'}</option>
          </select>
        </div>
        {!genericSourceFinding && (
          <div className="field">
            <span className="field-label">执行状态</span>
            <select value={form.execution_status} onChange={(event) => set('execution_status', event.target.value)}>
              {Object.entries(EXECUTION_LABELS).map(([value, text]) => (
                <option key={value} value={value}>{text}</option>
              ))}
            </select>
          </div>
        )}
        <div className="field">
          <span className="field-label">{genericSourceFinding ? '复核环境或版本（可选）' : '目标版本'}</span>
          <input type="text" value={form.target_version} placeholder={genericSourceFinding ? '例如 commit ID、分支或复核环境' : '例如 版本号 / commit ID / 构建标识'} onChange={(event) => set('target_version', event.target.value)} />
        </div>
      </div>

      {!genericSourceFinding && (
        <>
          <div className="field">
            <span className="field-label">执行命令</span>
            <input type="text" className="mono" value={form.command} placeholder="例如 php poc.php http://target.example" onChange={(event) => set('command', event.target.value)} />
          </div>

          <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="field">
              <span className="field-label">正常输入的实际观测（确认或排除时必填）</span>
              <textarea rows={2} value={form.normal_observation} onChange={(event) => set('normal_observation', event.target.value)} />
            </div>
            <div className="field">
              <span className="field-label">攻击输入的实际观测（确认或排除时必填）</span>
              <textarea rows={2} value={form.attack_observation} onChange={(event) => set('attack_observation', event.target.value)} />
            </div>
          </div>

          <div className="field">
            <span className="field-label">对脚本做的适配改动与原因</span>
            <textarea rows={2} value={form.modification_notes} onChange={(event) => set('modification_notes', event.target.value)} />
          </div>

          <div className="field">
            <span className="field-label">实际运行的脚本（可与下发脚本不同）</span>
            <textarea rows={4} className="mono" value={form.modified_script} onChange={(event) => set('modified_script', event.target.value)} />
          </div>
        </>
      )}

      <div className="field">
        <span className="field-label">{genericSourceFinding ? '复核附件（可选）' : '证据附件（日志 / 截图）'}</span>
        <input type="file" multiple onChange={(event) => setFiles(Array.from(event.target.files ?? []))} />
        <span className="field-hint">
          {genericSourceFinding
            ? '可附代码评审记录、截图或其他能帮助复核结论的材料。'
            : finding.category === 'xss_r'
            ? '反射型 XSS 确认必须勾选浏览器执行证据并上传日志或截图。'
            : '确认漏洞需上传日志、截图或其他可复核证据；执行失败的输出也建议保留。'}
        </span>
      </div>

      {!genericSourceFinding && (
        <div className="field">
          <label className="checkbox">
            <input type="checkbox" checked={form.browser_execution} onChange={(event) => set('browser_execution', event.target.checked)} />
            已在真实浏览器中执行（XSS 必需）
          </label>
        </div>
      )}

      <div className="field">
        <span className="field-label">{genericSourceFinding ? '人工复核说明（确认或驳回时必填）' : '备注'}</span>
        <textarea rows={2} value={form.notes} onChange={(event) => set('notes', event.target.value)} />
      </div>

      {error && <div className="error-box" style={{ marginBottom: 10 }}>{error}</div>}
      {done && !error && <div className="small" style={{ color: 'var(--ok)', marginBottom: 10 }}>已记录。</div>}

      <div className="row">
        <button className="btn btn-primary" onClick={submit} disabled={busy}>
          {busy ? '提交中…' : genericSourceFinding ? '提交复核记录' : '提交验证记录'}
        </button>
        <span className="field-hint">
          {genericSourceFinding
            ? '确认或驳回需要填写源码复核说明；可附代码评审记录、截图或其他证据。'
            : '确认或排除都需要成功执行、目标版本、命令和正常/攻击观测；确认还必须上传证据附件。'}
        </span>
      </div>
    </div>
  );
}
