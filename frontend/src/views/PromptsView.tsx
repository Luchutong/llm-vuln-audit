import { useEffect, useState } from 'react';
import { api, errorText, post } from '../api';
import type { Experiment, Finding, Prompt, Run, RunDetail } from '../types';

const CATEGORY_LABELS: Record<string, string> = {
  sqli: 'SQL 注入',
  xss_r: '反射型 XSS',
  command_injection: '命令注入',
};

const DIFF_LABELS: Record<string, string> = {
  label: '标签',
  reason: '优化原因',
  issues: '针对的问题',
  parent_id: '父版本',
  text: '正文',
};

/** A metric that could not be computed is spelled out, never printed as `null`/`NaN`. */
function rate(value: number | null | undefined): string {
  return value === null || value === undefined ? '无法计算' : value.toFixed(2);
}

/**
 * Prompts and the two optimisation rounds.
 *
 * A prompt version is never edited in place: P1 and P2 are new rows that point at their
 * parent and record why the change was made. That is what makes the comparison honest —
 * the run keeps the prompt text it actually used, so a later edit cannot rewrite the
 * record of what produced a result.
 */
export function PromptsView({ prompts, onChanged }: { prompts: Prompt[]; onChanged: () => void }) {
  const [selected, setSelected] = useState<string | null>(prompts[0]?.id ?? null);
  const [error, setError] = useState<string | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [picked, setPicked] = useState<string[]>([]);
  const [experiment, setExperiment] = useState<Experiment | null>(null);

  useEffect(() => {
    api<Run[]>('/runs').then(setRuns).catch((exc) => setError(errorText(exc)));
  }, []);

  const current = prompts.find((prompt) => prompt.id === selected) ?? prompts[0] ?? null;
  // Caveats that do not block a comparison but change how the numbers should be read.
  const experimentNotes = experiment?.notes ?? [];

  const compare = async () => {
    if (picked.length < 2) return;
    try {
      const data = await api<Experiment>(`/experiments?run_ids=${picked.join(',')}`);
      setExperiment(data);
    } catch (exc) {
      setError(errorText(exc));
    }
  };

  return (
    <div className="grid">
      {error && <div className="error-box">{error}</div>}

      <div className="grid" style={{ gridTemplateColumns: '260px 1fr' }}>
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">Prompt 版本</span>
            <span className="faint small">{prompts.length}</span>
          </div>
          {prompts.map((prompt) => (
            <button
              key={prompt.id}
              onClick={() => setSelected(prompt.id)}
              style={{
                display: 'block', width: '100%', textAlign: 'left', padding: '10px 14px',
                border: 'none', borderBottom: '1px solid var(--line-soft)', cursor: 'pointer',
                background: current?.id === prompt.id ? 'var(--accent-soft)' : 'transparent',
              }}
            >
              <div className="small" style={{ fontWeight: 500 }}>{prompt.id} · {prompt.label}</div>
              <div className="faint" style={{ fontSize: 11.5 }}>
                {prompt.phase}{prompt.parent_id ? ` · 基于 ${prompt.parent_id}` : ''}
              </div>
            </button>
          ))}
          <NewPromptForm prompts={prompts} onChanged={onChanged} onSelect={setSelected} />
        </div>

        {current && (
          <div className="panel">
            <div className="panel-head">
              <div>
                <div className="panel-title">{current.id} · {current.label}</div>
                <div className="faint small">{current.created_at.slice(0, 19)} · 阶段 {current.phase}</div>
              </div>
            </div>
            <div style={{ padding: '12px 16px' }}>
              {current.reason && (
                <div className="field">
                  <span className="field-label">这一版的优化原因</span>
                  <span className="small">{current.reason}</span>
                </div>
              )}
              {current.issues.length > 0 && (
                <div className="field">
                  <span className="field-label">针对的问题</span>
                  <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
                    {current.issues.map((issue, index) => <li key={index}>{issue}</li>)}
                  </ul>
                </div>
              )}
              <div className="field">
                <span className="field-label">正文（运行时会原样使用这一段）</span>
                <pre className="tl-detail" style={{ maxHeight: 460 }}>{current.text}</pre>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">P0 → P1 → P2 对比</span>
          <button className="btn btn-primary" onClick={compare} disabled={picked.length < 2}>比较选中的运行</button>
        </div>
        <div style={{ padding: '12px 16px' }}>
          <div className="small muted" style={{ marginBottom: 10 }}>
            只有快照、范围、模型与预算都一致时才可比较；不一致会在这里说明原因，而不是照常给出对比数字。
          </div>
          <div style={{ maxHeight: 200, overflowY: 'auto' }}>
            {runs.map((run) => (
              <label key={run.id} className="checkbox" style={{ marginBottom: 4 }}>
                <input
                  type="checkbox"
                  checked={picked.includes(run.id)}
                  onChange={(event) =>
                    setPicked((current) =>
                      event.target.checked ? [...current, run.id] : current.filter((id) => id !== run.id),
                    )
                  }
                />
                <span className="mono small">{run.id.slice(0, 10)}</span>
                <span className="chip">{run.prompt_id}</span>
                <span className={`chip chip-${run.status}`}>{run.status}</span>
                <span className="faint small">{run.snapshot_name} · {run.created_at.slice(0, 16)}</span>
              </label>
            ))}
          </div>

          {experiment && (
            <div style={{ marginTop: 14 }}>
              <div className="row" style={{ marginBottom: 8 }}>
                <span className={`chip ${experiment.comparable ? 'chip-confirmed' : 'chip-failed'}`}>
                  {experiment.comparable ? '可比较' : '不可比较'}
                </span>
                {!experiment.comparable && (
                  <span className="small muted">{experiment.reasons.join('；')}</span>
                )}
              </div>
              {experimentNotes.length > 0 && (
                <div className="small" style={{ marginBottom: 8, color: 'var(--warn)' }}>
                  {experimentNotes.map((note, index) => <div key={index}>注意：{note}</div>)}
                </div>
              )}

              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ color: 'var(--ink-soft)', fontSize: 12 }}>
                    <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>运行</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>Prompt</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>候选</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>证据不通过</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>已确认</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>审计覆盖</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>未完成单元</th>
                    {/* Precision/Recall only exist where a verified truth set does. A run
                        without one shows 无法计算 rather than a 0 that would read as
                        "measured zero false negatives". */}
                    <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>精确率 / 召回率</th>
                  </tr>
                </thead>
                <tbody>
                  {experiment.runs.map(({ run, metrics }) => (
                    <tr key={run.id} style={{ borderTop: '1px solid var(--line-soft)' }}>
                      <td className="mono small" style={{ padding: '6px 8px' }}>{run.id.slice(0, 10)}</td>
                      <td style={{ padding: '6px 8px' }}><span className="chip">{run.prompt_id}</span></td>
                      <td style={{ padding: '6px 8px' }}>{metrics.candidates}</td>
                      <td style={{ padding: '6px 8px' }}>{metrics.discarded_candidates}</td>
                      <td style={{ padding: '6px 8px' }}>{metrics.confirmed}</td>
                      <td style={{ padding: '6px 8px' }}>{(metrics.audit_coverage * 100).toFixed(1)}%</td>
                      <td style={{ padding: '6px 8px' }}>{metrics.incomplete_units}</td>
                      <td style={{ padding: '6px 8px' }} className="mono small">
                        {rate(metrics.evaluation?.precision)} / {rate(metrics.evaluation?.recall)}
                        {metrics.evaluation && metrics.evaluation.unresolved.length > 0 && (
                          <span className="faint"> ({metrics.evaluation.unresolved.length} 未决未计入)</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <AttributionGaps runs={runs} />
    </div>
  );
}

function NewPromptForm({
  prompts,
  onChanged,
  onSelect,
}: {
  prompts: Prompt[];
  onChanged: () => void;
  onSelect: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ label: '', text: '', reason: '', issues: '', parent_id: '' });
  const [error, setError] = useState<string | null>(null);

  if (!open) {
    return (
      <div style={{ padding: 12 }}>
        <button className="btn" onClick={() => setOpen(true)} style={{ width: '100%' }}>新建 Prompt 版本</button>
      </div>
    );
  }

  const save = async () => {
    try {
      const created = await post<Prompt>('/prompts', {
        label: form.label,
        text: form.text,
        reason: form.reason,
        issues: form.issues.split('\n').map((line) => line.trim()).filter(Boolean),
        parent_id: form.parent_id || null,
      });
      setForm({ label: '', text: '', reason: '', issues: '', parent_id: '' });
      setOpen(false);
      onChanged();
      onSelect(created.id);
    } catch (exc) {
      setError(errorText(exc));
    }
  };

  const fillFrom = prompts.find((prompt) => prompt.id === form.parent_id);

  return (
    <div style={{ padding: 12 }}>
      <div className="field">
        <span className="field-label">标签</span>
        <input type="text" value={form.label} placeholder="P3 第三轮优化" onChange={(event) => setForm({ ...form, label: event.target.value })} />
      </div>
      <div className="field">
        <span className="field-label">基于哪一版</span>
        <select
          value={form.parent_id}
          onChange={(event) => {
            const parent = prompts.find((prompt) => prompt.id === event.target.value);
            setForm({ ...form, parent_id: event.target.value, text: parent ? parent.text : form.text });
          }}
        >
          <option value="">全新</option>
          {prompts.map((prompt) => <option key={prompt.id} value={prompt.id}>{prompt.id} · {prompt.label}</option>)}
        </select>
      </div>
      <div className="field">
        <span className="field-label">为什么改</span>
        <textarea rows={2} value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} />
      </div>
      <div className="field">
        <span className="field-label">针对哪些问题（每行一条）</span>
        <textarea rows={2} value={form.issues} onChange={(event) => setForm({ ...form, issues: event.target.value })} />
      </div>
      <div className="field">
        <span className="field-label">正文{fillFrom ? `（已复制 ${fillFrom.id}）` : ''}</span>
        <textarea rows={8} className="mono" value={form.text} onChange={(event) => setForm({ ...form, text: event.target.value })} />
      </div>
      {error && <div className="error-box" style={{ marginBottom: 8 }}>{error}</div>}
      <div className="row">
        <button className="btn btn-primary" onClick={save} disabled={!form.label || !form.text}>保存</button>
        <button className="btn" onClick={() => setOpen(false)}>取消</button>
      </div>
    </div>
  );
}

/**
 * Where the failures came from, across runs.
 *
 * Attributions are the only place the tool records *why* it was wrong rather than that it
 * was. Grouping them by the prompt's own checklist item is what turns a pile of mistakes
 * into a change to the next prompt version.
 */
function AttributionGaps({ runs }: { runs: Run[] }) {
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [runId, setRunId] = useState<string>('');

  useEffect(() => {
    if (!runId) {
      setDetail(null);
      return;
    }
    api<RunDetail>(`/runs/${runId}`).then(setDetail).catch(() => setDetail(null));
  }, [runId]);

  const attributions = detail?.attributions ?? [];
  const byCause = new Map<string, number>();
  for (const item of attributions) {
    const key = item.check_item || item.cause || '未标注';
    byCause.set(key, (byCause.get(key) ?? 0) + 1);
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">失败归因汇总</span>
        <select value={runId} onChange={(event) => setRunId(event.target.value)} style={{ width: 280 }}>
          <option value="">选择一次运行…</option>
          {runs.map((run) => <option key={run.id} value={run.id}>{run.id.slice(0, 10)} · {run.prompt_id}</option>)}
        </select>
      </div>
      {!runId ? (
        <div className="empty">选择一次运行，查看它的误报 / 漏报都归到了哪些检查项。</div>
      ) : attributions.length === 0 ? (
        <div className="empty">这次运行还没有归因记录。可在「发现与验证 → 实验报告」中录入。</div>
      ) : (
        <div style={{ padding: '12px 16px' }}>
          {Array.from(byCause.entries()).map(([key, count]) => (
            <div key={key} className="between" style={{ padding: '6px 0', borderBottom: '1px solid var(--line-soft)' }}>
              <span className="small">{key}</span>
              <span className="chip">{count} 条</span>
            </div>
          ))}
          <div className="small muted" style={{ marginTop: 10 }}>
            这些问题就是下一版 Prompt 要针对性强化/收紧的地方。
          </div>
        </div>
      )}
    </div>
  );
}
