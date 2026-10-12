import { useEffect, useState } from 'react';
import { api, downloadUrl, errorText, post } from '../api';
import type { Category, Finding, RunDetail } from '../types';
import { SourceViewer } from '../components/SourceViewer';

const CATEGORY_LABELS: Record<Category, string> = {
  sqli: 'SQL 注入',
  xss_r: '反射型 XSS',
  command_injection: '命令注入',
};

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
 * Findings and the human verification gate.
 *
 * A candidate here is a claim, not a result. The gate exists so a claim only becomes a
 * confirmed vulnerability once a person has actually run the proof of concept against the
 * matching target and recorded what happened — including when it did not work, which is
 * recorded as `not_triggered` and stays out of the statistics rather than counting as a
 * false positive.
 */
export function FindingsView({ detail, snapshotId, onChanged }: { detail: RunDetail; snapshotId: string; onChanged: () => void }) {
  const [selected, setSelected] = useState<string | null>(null);

  const findings = detail.findings;
  const current = findings.find((finding) => finding.id === selected) ?? findings[0] ?? null;

  if (!findings.length) {
    return <div className="empty">这次运行没有产生候选发现。<br />单元级结论请在「概览」里查看。</div>;
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
                {finding.verdict && <span className={`chip chip-${finding.verdict}`}>{VERDICT_LABELS[finding.verdict]}</span>}
              </div>
              <div className="small" style={{ fontWeight: 500 }}>{CATEGORY_LABELS[finding.category]}</div>
              <div className="mono faint" style={{ fontSize: 11.5 }}>
                {finding.file_path}:{finding.line}
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
  return (
    <div className="grid">
      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="panel-title">{CATEGORY_LABELS[finding.category]} · {finding.title}</div>
            <div className="mono faint small">{finding.file_path}:{finding.line}</div>
          </div>
          <div className="row">
            <span className={`chip sev-${finding.severity}`}>{finding.severity}</span>
            <span className={`chip chip-${finding.validation_state}`}>
              {finding.validation_state === 'candidate' ? '证据校验通过' : '证据校验不通过'}
            </span>
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
          <Chain label="输入来源" value={finding.input_source} />
          <Chain label="传播路径" value={finding.propagation} />
          <Chain label="危险操作" value={finding.dangerous_operation} />
          <Chain label="防护判断" value={finding.protection || '无'} />
          <Chain label="触发前提" value={finding.preconditions.join('；') || '无'} />
          <Chain label="缺失上下文" value={finding.missing_context.join('；') || '无'} />
          <Chain label="分析依据" value={finding.summary} />
          <Chain label="修复建议" value={finding.remediation} />
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">原始源码（高亮为证据行）</span>
          <span className="faint small">
            {finding.evidence.map((ref) => `${ref.start_line}-${ref.end_line}`).join('、')}
          </span>
        </div>
        <SourceViewer
          snapshotId={snapshotId}
          path={finding.file_path}
          start={Math.max(1, finding.unit_start_line)}
          end={finding.unit_end_line}
          highlight={finding.evidence}
          height={280}
        />
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
          <span className="panel-title">人工验证</span>
          <span className="faint small">{finding.verifications.length} 条记录</span>
        </div>
        {finding.verifications.map((record, index) => (
          <div key={record.id ?? index} style={{ padding: '10px 16px', borderBottom: '1px solid var(--line-soft)' }}>
            <div className="row" style={{ flexWrap: 'wrap' }}>
              <span className={`chip chip-${record.verdict}`}>{VERDICT_LABELS[record.verdict]}</span>
              <span className="chip">{EXECUTION_LABELS[record.execution_status] ?? record.execution_status}</span>
              {record.browser_execution && <span className="chip">含浏览器执行证据</span>}
              <span className="faint small">{record.created_at?.slice(0, 19)}</span>
            </div>
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
      <div className="field-label" style={{ marginBottom: 8 }}>记录一次验证</div>

      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr 1fr' }}>
        <div className="field">
          <span className="field-label">人工结论</span>
          <select value={form.verdict} onChange={(event) => set('verdict', event.target.value as FormState['verdict'])}>
            <option value="uncertain">无法确定</option>
            <option value="confirmed">确认漏洞</option>
            <option value="rejected">排除（误报）</option>
          </select>
        </div>
        <div className="field">
          <span className="field-label">执行状态</span>
          <select value={form.execution_status} onChange={(event) => set('execution_status', event.target.value)}>
            {Object.entries(EXECUTION_LABELS).map(([value, text]) => (
              <option key={value} value={value}>{text}</option>
            ))}
          </select>
        </div>
        <div className="field">
          <span className="field-label">目标版本</span>
          <input type="text" value={form.target_version} placeholder="例如 DVWA 2.5 / commit a96943d" onChange={(event) => set('target_version', event.target.value)} />
        </div>
      </div>

      <div className="field">
        <span className="field-label">执行命令</span>
        <input type="text" className="mono" value={form.command} placeholder="php poc.php http://127.0.0.1:4280" onChange={(event) => set('command', event.target.value)} />
      </div>

      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="field">
          <span className="field-label">正常输入的实际观测</span>
          <textarea rows={2} value={form.normal_observation} onChange={(event) => set('normal_observation', event.target.value)} />
        </div>
        <div className="field">
          <span className="field-label">攻击输入的实际观测（确认漏洞时必填）</span>
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

      <div className="field">
        <span className="field-label">证据附件（日志 / 截图）</span>
        <input type="file" multiple onChange={(event) => setFiles(Array.from(event.target.files ?? []))} />
        <span className="field-hint">
          {finding.category === 'xss_r'
            ? '反射型 XSS 确认必须勾选浏览器执行证据并上传日志或截图。'
            : '执行失败的输出也请上传：它让这次失败可复核，而不是一句结论。'}
        </span>
      </div>

      <div className="field">
        <label className="checkbox">
          <input type="checkbox" checked={form.browser_execution} onChange={(event) => set('browser_execution', event.target.checked)} />
          已在真实浏览器中执行（XSS 必需）
        </label>
      </div>

      <div className="field">
        <span className="field-label">备注</span>
        <textarea rows={2} value={form.notes} onChange={(event) => set('notes', event.target.value)} />
      </div>

      {error && <div className="error-box" style={{ marginBottom: 10 }}>{error}</div>}
      {done && !error && <div className="small" style={{ color: 'var(--ok)', marginBottom: 10 }}>已记录。</div>}

      <div className="row">
        <button className="btn btn-primary" onClick={submit} disabled={busy}>
          {busy ? '提交中…' : '提交验证记录'}
        </button>
        <span className="field-hint">
          执行未成功时不能判定为「排除」；漏洞未触发请记为 not_triggered，它不计入假阳性。
        </span>
      </div>
    </div>
  );
}
