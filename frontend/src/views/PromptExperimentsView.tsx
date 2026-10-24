import { useCallback, useEffect, useRef, useState } from 'react';
import { api, downloadUrl, errorText, post } from '../api';
import { Disclosure } from '../components/Disclosure';
import type { PromptExperiment, PromptExperimentRow, PromptVariant } from '../types';
import { localDate } from '../status';

/**
 * The multi-version prompt comparison, as a page instead of a shell command.
 *
 * What is being compared is fixed on purpose: same frozen source, same executor, same
 * budgets, only the worker role text changes.  The numbers come from the same script the
 * written report quotes, so the page cannot quietly disagree with the deliverable.
 */
const SCENARIO_LABELS: Record<string, string> = {
  '': '全部类别',
  sqli: 'SQL 注入',
  xss_r: '反射型 XSS',
  command_injection: '命令注入',
};

const STATUS_LABELS: Record<string, string> = {
  running: '运行中',
  completed: '已完成',
  failed: '失败',
  cancelled: '已取消',
};

function ratio(value: number | null | undefined): string {
  return value === null || value === undefined ? '—' : value.toFixed(3);
}

/** A defence number the course can quote: resist the injected canaries *and* keep the chain. */
function defenceScore(row: PromptExperimentRow): number | null {
  const resist = row.injection?.resistance_rate;
  const chain = row.discipline?.chain_rate;
  if (resist === null || resist === undefined || chain === null || chain === undefined) return null;
  return (resist + chain) / 2;
}

function injectionSummary(injection: PromptExperimentRow['injection']): string {
  const tested = injection.tested ?? injection.canaries;
  if (!tested || injection.resistance_rate === null) return '未测量';
  return `${injection.resisted}/${tested} 已测${injection.unmeasured ? ` · ${injection.unmeasured} 未测` : ''}`;
}

function signed(value: number | null): string {
  if (value === null) return '—';
  return `${value >= 0 ? '+' : ''}${value.toFixed(3)}`;
}

export function PromptExperimentsView() {
  const [variants, setVariants] = useState<PromptVariant[]>([]);
  const [selected, setSelected] = useState<string[]>(['P0-basic', 'P1-evidence', 'P2-crossfile']);
  const [limit, setLimit] = useState(6);
  const [scenario, setScenario] = useState('');
  const [history, setHistory] = useState<PromptExperiment[]>([]);
  const [current, setCurrent] = useState<PromptExperiment | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);
  const request = useRef<AbortController | null>(null);
  const activeExperiment = history.find((item) => item.status === 'running');
  const running = current?.status === 'running' || Boolean(activeExperiment);

  const load = useCallback(async (replacePending = true) => {
    if (!replacePending && request.current) return;
    request.current?.abort();
    const abort = new AbortController();
    request.current = abort;
    try {
      const [catalog, experiments] = await Promise.all([
        api<PromptVariant[]>('/prompt-experiments/variants', { signal: abort.signal }),
        api<PromptExperiment[]>('/prompt-experiments', { signal: abort.signal }),
      ]);
      if (!alive.current || abort.signal.aborted) return;
      setError(null);
      setVariants(catalog);
      setHistory(experiments);
      setCurrent((value) => {
        const id = value?.id;
        const tracked = id ? experiments.find((item) => item.id === id) : undefined;
        return tracked ?? experiments[0] ?? null;
      });
    } catch (exc) {
      if (alive.current && !abort.signal.aborted) setError(errorText(exc));
    } finally {
      if (request.current === abort) request.current = null;
    }
  }, []);

  useEffect(() => {
    alive.current = true;
    void load();
    return () => { alive.current = false; request.current?.abort(); };
  }, [load]);

  // A running experiment is a child process spending tokens; poll until it settles.
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => {
      if (!document.hidden) void load(false);
    }, 2500);
    return () => window.clearInterval(timer);
  }, [running, load]);

  const start = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const created = await post<PromptExperiment>('/prompt-experiments', {
        variants: selected,
        units_limit: limit,
        scenario: scenario || null,
      });
      setCurrent(created);
      void load();
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(false);
    }
  };

  const cancel = async () => {
    const target = activeExperiment ?? (current?.status === 'running' ? current : null);
    if (!target || busy) return;
    setBusy(true);
    try {
      setCurrent(await post<PromptExperiment>(`/prompt-experiments/${target.id}/cancel`, {}));
      void load();
    } catch (exc) {
      setError(`取消失败：${errorText(exc)}`);
    } finally {
      setBusy(false);
    }
  };

  const toggle = (id: string) => {
    setSelected((value) => (value.includes(id) ? value.filter((item) => item !== id) : [...value, id]));
  };

  const rows = current?.rows ?? [];
  const baseline = rows[0];
  const tail = current?.progress?.tail ?? [];
  const done = current?.progress?.done ?? [];
  const notice = current?.error;

  return (
    <div className="grid" style={{ gap: 14 }}>
      {error && <div className="error-box" role="alert">{error} <button className="text-button" onClick={() => void load()}>重试读取</button></div>}
      {activeExperiment && current?.id !== activeExperiment.id && <p className="small muted">另一个对比实验正在运行。<button className="text-button" onClick={() => setCurrent(activeExperiment)}>查看进行中的实验</button></p>}

      <section className="panel">
        <div className="panel-head">
          <span className="panel-title">对比设置</span>
          <span className="faint small">{selected.length} 个版本 · {limit === 0 ? '全部单元' : `前 ${limit} 个单元`} · {SCENARIO_LABELS[scenario]}</span>
        </div>
        <div style={{ padding: '12px 16px' }} className="grid">
          <div className="grid" style={{ gap: 6 }}>
            {variants.map((variant) => (
              <label key={variant.id} className="checkbox prompt-variant" style={{ marginBottom: 2 }}>
                <input type="checkbox" checked={selected.includes(variant.id)} onChange={() => toggle(variant.id)} disabled={running} />
                <span className="mono small" style={{ whiteSpace: 'nowrap' }}>{variant.id}</span>
                <span className="chip">{variant.phase}</span>
                <span className="small" style={{ whiteSpace: 'nowrap' }}>{variant.label}</span>
                <span className="faint small">{variant.focus}</span>
              </label>
            ))}
          </div>
          <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
            <label className="small">
              单元上限
              <input
                type="number"
                min={0}
                max={200}
                value={limit}
                disabled={running}
                onChange={(event) => setLimit(Math.max(0, Math.min(200, Number(event.target.value) || 0)))}
                style={{ width: 80, marginLeft: 6 }}
              />
            </label>
            <label className="small">
              类别
              <select value={scenario} disabled={running} onChange={(event) => setScenario(event.target.value)} style={{ marginLeft: 6 }}>
                {Object.entries(SCENARIO_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </select>
            </label>
            <button className="btn btn-primary" onClick={() => void start()} disabled={busy || running || selected.length < 2}>
              {running ? '对比进行中…' : '开始对比'}
            </button>
            {running && <button className="btn btn-danger" onClick={() => void cancel()} disabled={busy}>停止</button>}
            {current && current.status === 'completed' && <>
              <a className="btn" href={downloadUrl(`/prompt-experiments/${current.id}/report?format=markdown`)}>下载 Markdown</a>
              <a className="btn" href={downloadUrl(`/prompt-experiments/${current.id}/report?format=json`)}>下载 JSON</a>
            </>}
          </div>
          <p className="small muted" style={{ margin: 0 }}>
            这项对比会真实调用模型：每个单元一次请求。上限设为 0 表示跑完全部真值涉及的源码文件；默认只跑前 6 个单元，用来先确认连接与结果是否正常。
          </p>
          {!running && selected.length < 2 && <p className="small" style={{ color: 'var(--warn)', margin: 0 }}>至少选择两个版本。</p>}
        </div>
      </section>

      {current && (
        <section className="panel">
          <div className="panel-head">
            <span className="panel-title">本次对比 · {current.model || '未记录模型'}</span>
            <span className="row" style={{ gap: 8 }}>
              <span className={`chip chip-${current.status}`}>{STATUS_LABELS[current.status] ?? current.status}</span>
              <span className="faint small">{localDate(current.created_at)} · {current.variants.join(' / ')}{current.units_limit ? ` · 前 ${current.units_limit} 单元` : ''}{current.scenario ? ` · ${SCENARIO_LABELS[current.scenario]}` : ''}</span>
            </span>
          </div>
          <div style={{ padding: '12px 16px' }} className="grid">
            {notice && <div className={current.status === 'failed' ? 'error-box' : 'small muted'} role={current.status === 'failed' ? 'alert' : undefined}>{notice}</div>}
            {current.status === 'running' && <div className="small muted">正在运行 {current.progress?.current ?? '（准备快照）'}；已完成 {done.length} / {current.variants.length} 个版本。</div>}
            {rows.length > 0 && <>
              <div className="table-scroll">
                <table style={{ minWidth: 980 }}>
                  <thead>
                    <tr>
                      <th>版本</th>
                      <th>TP</th><th>FP</th><th>FN</th>
                      <th>精确率</th><th>召回率</th><th>F1</th>
                      <th>报告数</th><th>证据链完整率</th><th>注入抵抗</th><th>防御得分</th>
                      <th>Δ召回</th><th>Δ误报</th>
                      <th>请求</th><th>tokens</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => {
                      const score = row.score;
                      const recall = score?.recall ?? null;
                      const falsePositive = score?.FP ?? null;
                      return (
                        <tr key={row.variant}>
                          <td><span className="chip">{row.variant}</span></td>
                          <td>{score?.TP ?? '—'}</td>
                          <td>{score?.FP ?? '—'}</td>
                          <td>{score?.FN ?? '—'}</td>
                          <td>{ratio(score?.precision)}</td>
                          <td>{ratio(recall)}</td>
                          <td>{ratio(score?.f1)}</td>
                          <td>{row.discipline?.reported ?? '—'}</td>
                          <td>{ratio(row.discipline?.chain_rate)}</td>
                          <td>{row.injection ? injectionSummary(row.injection) : '—'}</td>
                          <td className="mono small">{ratio(defenceScore(row))}</td>
                          <td className="mono small">
                            {row === baseline ? '基准'
                              : recall !== null && baseline?.score?.recall !== null && baseline?.score?.recall !== undefined
                                ? signed(recall - baseline.score.recall) : '—'}
                          </td>
                          <td className="mono small">
                            {row === baseline ? '基准'
                              : falsePositive !== null && baseline?.score ? signed(falsePositive - baseline.score.FP) : '—'}
                          </td>
                          <td>{row.stats?.requests ?? '—'}</td>
                          <td>{row.stats?.tokens ?? '—'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {baseline && rows.length > 1 && <p className="small muted" style={{ margin: 0 }}>
                Δ 相对第一行 <span className="mono">{baseline.variant}</span>：召回率越高、误报越少越好。防御得分是「注入抵抗率」与「证据链完整率」的均值，用来把防护效果和检出效果分开看。
              </p>}
              <div className="small muted">
                扫描范围是真值涉及的源码文件（外加 3 个注入 canary），每个文件取一个单元，因此这组数字反映各版本的判定从严程度，不等于全站覆盖率；单次运行也不能当作总体准确率。注入抵抗只统计已完成的 canary；未测量不算失败，没有已测 canary 时不计算防御得分。
              </div>
            </>}
            {tail.length > 0 && <Disclosure title="运行日志（末尾）">
              <pre className="tl-detail" style={{ maxHeight: 260 }}>{tail.join('\n')}</pre>
            </Disclosure>}
          </div>
        </section>
      )}

      {variants.length > 0 && <section className="panel">
        <div className="panel-head"><span className="panel-title">版本正文</span><span className="faint small">宿主工具、证据校验与输出 schema 对所有版本一致</span></div>
        <div style={{ padding: '12px 16px' }} className="grid">
          {variants.map((variant) => (
            <Disclosure key={variant.id} title={`${variant.id} · ${variant.label}`}>
              <p className="small muted">{variant.focus}</p>
              <pre className="tl-detail" style={{ maxHeight: 320 }}>{variant.prompt}</pre>
            </Disclosure>
          ))}
        </div>
      </section>}

      <section className="panel">
        <div className="panel-head"><span className="panel-title">历史对比</span><span className="faint small">{history.length}</span></div>
        <div style={{ padding: '12px 16px' }} className="grid">
          {history.length === 0 && <div className="empty">还没有对比记录。选择两个以上版本后点「开始对比」。</div>}
          {history.map((item) => (
            <button
              key={item.id}
              className="records-prompt-row"
              onClick={() => setCurrent(item)}
              style={{ textAlign: 'left', cursor: 'pointer', background: current?.id === item.id ? 'var(--accent-soft)' : 'transparent', border: '1px solid var(--line-soft)', borderRadius: 8, padding: '8px 12px' }}
            >
              <span className={`chip chip-${item.status}`}>{STATUS_LABELS[item.status] ?? item.status}</span>{' '}
              <span className="small">{item.variants.join(' / ')}</span>{' '}
              <span className="faint small">
                {localDate(item.created_at)} · {item.units_limit ? `前 ${item.units_limit} 单元` : '全部单元'}
                {item.scenario ? ` · ${SCENARIO_LABELS[item.scenario]}` : ''} · {item.model || '未记录模型'}
                {item.rows.length > 0 ? ` · ${item.rows.length} 个版本有结果` : ''}
              </span>
            </button>
          ))}
        </div>
      </section>
    </div>
  );
}
