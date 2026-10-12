import { useEffect, useMemo, useState } from 'react';
import { api, errorText, post } from '../api';
import type { Prompt, Run, Snapshot, SnapshotSummary, Config } from '../types';

const DEMO_SCOPE = [
  'vulnerabilities/sqli/source/low.php',
  'vulnerabilities/sqli/source/impossible.php',
  'vulnerabilities/xss_r/source/low.php',
  'vulnerabilities/xss_r/source/impossible.php',
  'vulnerabilities/exec/source/low.php',
  'vulnerabilities/exec/source/impossible.php',
];

/**
 * Audit tasks: import a snapshot, choose the scope, start a run.
 *
 * The scope selector lists every indexed file exactly as the snapshot indexed it — the
 * same list the unit queue is built from — so what is audited is what was chosen, and
 * excluded third-party files are shown as excluded rather than quietly missing.
 */
export function TaskView({
  snapshots,
  prompts,
  config,
  onOpenRun,
  onChanged,
}: {
  snapshots: SnapshotSummary[];
  prompts: Prompt[];
  config: Config | null;
  onOpenRun: (runId: string) => void;
  onChanged: () => void;
}) {
  const [runs, setRuns] = useState<Run[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [scope, setScope] = useState<string[]>([]);
  const [promptId, setPromptId] = useState<string>('P2');
  const [budgets, setBudgets] = useState({ responses: 8, tools: 16, seconds: 300 });
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refreshRuns = () => {
    api<Run[]>('/runs').then(setRuns).catch((exc) => setError(errorText(exc)));
  };

  useEffect(() => {
    refreshRuns();
    const timer = window.setInterval(refreshRuns, 4000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!selected) {
      setSnapshot(null);
      return;
    }
    api<Snapshot>(`/snapshots/${selected}`)
      .then((data) => {
        setSnapshot(data);
        setScope(data.files.filter((file) => !file.excluded).map((file) => file.path));
      })
      .catch((exc) => setError(errorText(exc)));
  }, [selected]);

  const upload = async (file: File) => {
    setBusy(true);
    setError(null);
    try {
      const body = new FormData();
      body.append('file', file);
      const created = await api<Snapshot>('/snapshots', { method: 'POST', body });
      setNotice(`已导入 ${created.name}：${created.files.length} 个文件，${created.units.length} 个审计单元`);
      onChanged();
      setSelected(created.id);
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(false);
    }
  };

  const start = async () => {
    if (!selected || !scope.length) return;
    setBusy(true);
    setError(null);
    try {
      const run = await post<Run>('/runs', { snapshot_id: selected, scope, prompt_id: promptId, budgets });
      setNotice(`已创建运行 ${run.id.slice(0, 10)}：${run.total_units} 个单元`);
      refreshRuns();
      onOpenRun(run.id);
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(false);
    }
  };

  const indexed = snapshot?.files ?? [];
  const excluded = indexed.filter((file) => file.excluded);
  const units = useMemo(
    () => (snapshot?.units ?? []).filter((unit) => scope.includes(unit.file_path)),
    [snapshot, scope],
  );

  return (
    <div className="grid" style={{ gridTemplateColumns: '1fr', gap: 14 }}>
      {error && <div className="error-box">{error}</div>}
      {notice && <div className="panel" style={{ padding: '10px 14px', color: 'var(--ok)', fontSize: 13 }}>{notice}</div>}
      {config && !config.configured && (
        <div className="error-box">模型未配置完成，请先到「配置」页检查连接状态。</div>
      )}

      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">1 · 源码快照</span>
            <span className="faint small">{snapshots.length} 个快照</span>
          </div>
          <div style={{ padding: '12px 16px' }}>
            <div className="field">
              <span className="field-label">导入 ZIP</span>
              <input
                type="file"
                accept=".zip"
                disabled={busy}
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (file) upload(file);
                }}
              />
              <span className="field-hint">
                只索引 .php / .inc / .phtml；拒绝路径穿越、符号链接与压缩炸弹；导入后快照不可变。
              </span>
            </div>

            <div className="field">
              <span className="field-label">已导入的快照</span>
              <select value={selected ?? ''} onChange={(event) => setSelected(event.target.value || null)}>
                <option value="">请选择…</option>
                {snapshots.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}（{item.file_count} 文件 / {item.unit_count} 单元）
                  </option>
                ))}
              </select>
            </div>

            {snapshot && (
              <div className="small muted">
                <div>归档 SHA256 <span className="mono">{snapshot.archive_sha256.slice(0, 16)}…</span></div>
                <div>{snapshot.created_at.slice(0, 19)} · {snapshot.immutable ? '不可变' : '可变'}</div>
                {snapshot.warnings?.length > 0 && (
                  <div style={{ marginTop: 6 }}>
                    导入告警：
                    <ul style={{ margin: '4px 0 0 18px', padding: 0 }}>
                      {snapshot.warnings.map((warning, index) => <li key={index}>{warning}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">2 · 审计范围与预算</span>
            {snapshot && (
              <button className="btn" onClick={() => setScope(DEMO_SCOPE.filter((path) => indexed.some((file) => file.path === path)))}>
                选取 DVWA 六个演示样本
              </button>
            )}
          </div>
          <div style={{ padding: '12px 16px' }}>
            {!snapshot ? (
              <div className="empty">先选择一个快照。</div>
            ) : (
              <>
                <div className="field">
                  <span className="field-label">范围内的文件（{scope.length} / {indexed.filter((file) => !file.excluded).length}）</span>
                  <div style={{ maxHeight: 220, overflowY: 'auto', border: '1px solid var(--line)', borderRadius: 7, padding: 8 }}>
                    {indexed.filter((file) => !file.excluded).map((file) => (
                      <label key={file.path} className="checkbox" style={{ marginBottom: 3 }}>
                        <input
                          type="checkbox"
                          checked={scope.includes(file.path)}
                          onChange={(event) =>
                            setScope((current) =>
                              event.target.checked ? [...current, file.path] : current.filter((path) => path !== file.path),
                            )
                          }
                        />
                        <span className="mono small">{file.path}</span>
                        <span className="faint small">{file.line_count} 行</span>
                      </label>
                    ))}
                  </div>
                  <span className="field-hint">
                    选中 {scope.length} 个文件将生成 {units.length} 个审计单元（先按函数/方法/顶层脚本切片，超长再在语句边界切分）。
                  </span>
                </div>

                {excluded.length > 0 && (
                  <div className="field">
                    <span className="field-label">已排除的第三方文件（{excluded.length}）</span>
                    <div className="small faint" style={{ maxHeight: 90, overflowY: 'auto' }}>
                      {excluded.map((file) => (
                        <div key={file.path} className="mono">{file.path} — {file.exclude_reason}</div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="grid" style={{ gridTemplateColumns: '1fr 1fr 1fr' }}>
                  <div className="field">
                    <span className="field-label">Prompt</span>
                    <select value={promptId} onChange={(event) => setPromptId(event.target.value)}>
                      {prompts.map((prompt) => (
                        <option key={prompt.id} value={prompt.id}>{prompt.id} · {prompt.label}</option>
                      ))}
                    </select>
                  </div>
                  <div className="field">
                    <span className="field-label">模型响应上限</span>
                    <input type="number" min={1} value={budgets.responses} onChange={(event) => setBudgets({ ...budgets, responses: Number(event.target.value) })} />
                  </div>
                  <div className="field">
                    <span className="field-label">工具调用上限</span>
                    <input type="number" min={1} value={budgets.tools} onChange={(event) => setBudgets({ ...budgets, tools: Number(event.target.value) })} />
                  </div>
                </div>

                <div className="row">
                  <button className="btn btn-primary" onClick={start} disabled={busy || !scope.length}>
                    {busy ? '处理中…' : `开始审计（${units.length} 个单元）`}
                  </button>
                  <span className="field-hint">
                    队列在运行开始时冻结；预算耗尽、解析失败与缺上下文都记为未完成，不记为阴性。
                  </span>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">审计任务</span>
          <span className="faint small">每 4 秒刷新</span>
        </div>
        {runs.length === 0 ? (
          <div className="empty">还没有运行。</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ color: 'var(--ink-soft)', fontSize: 12 }}>
                <th style={{ textAlign: 'left', padding: '8px 14px', fontWeight: 500 }}>运行</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>状态</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>进度</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>Prompt</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>模型用量</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>开始时间</th>
                <th style={{ padding: '8px 14px' }} />
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.id} style={{ borderTop: '1px solid var(--line-soft)' }}>
                  <td style={{ padding: '8px 14px' }}>
                    <div className="mono small">{run.id.slice(0, 10)}</div>
                    <div className="faint" style={{ fontSize: 11.5 }}>{run.snapshot_name}</div>
                  </td>
                  <td style={{ padding: '8px 8px' }}><span className={`chip chip-${run.status}`}>{run.status}</span></td>
                  <td style={{ padding: '8px 8px' }} className="small">
                    {run.completed_units}/{run.total_units}
                  </td>
                  <td style={{ padding: '8px 8px' }} className="small">{run.prompt_id}</td>
                  <td style={{ padding: '8px 8px' }} className="small faint">
                    {run.usage.requests} 响应 / {run.usage.tool_calls} 工具
                  </td>
                  <td style={{ padding: '8px 8px' }} className="small faint">{run.created_at.slice(0, 19)}</td>
                  <td style={{ padding: '8px 14px' }}>
                    <button className="btn" onClick={() => onOpenRun(run.id)}>打开</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
