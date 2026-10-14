import { useEffect, useMemo, useState } from 'react';
import { api, errorText, post } from '../api';
import type { Prompt, Run, Snapshot, SnapshotSummary, Config, TaskSpec } from '../types';

const DEMO_SCOPE = [
  'vulnerabilities/sqli/source/low.php',
  'vulnerabilities/sqli/source/impossible.php',
  'vulnerabilities/xss_r/source/low.php',
  'vulnerabilities/xss_r/source/impossible.php',
  'vulnerabilities/exec/source/low.php',
  'vulnerabilities/exec/source/impossible.php',
];

type RunMode = 'audit' | 'goal';

const EMPTY_TASK_SPEC: TaskSpec = {
  objective: '',
  success_criteria: '',
  max_iterations: 3,
  max_total_attempts: 24,
  max_workers: 2,
  stop_on_achieved: true,
  require_poc: true,
};

function boundedNumber(value: string, minimum: number, maximum: number) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return minimum;
  return Math.max(minimum, Math.min(maximum, Math.trunc(parsed)));
}

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
  const [mode, setMode] = useState<RunMode>('audit');
  const [task, setTask] = useState<TaskSpec>(EMPTY_TASK_SPEC);
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
    const taskSpec = mode === 'goal'
      ? { ...task, objective: task.objective.trim(), success_criteria: task.success_criteria.trim() }
      : null;
    if (taskSpec && taskSpec.objective.length < 8) {
      setError('目标任务需要至少 8 个字符的任务目标。');
      return;
    }
    if (taskSpec && taskSpec.success_criteria.length < 8) {
      setError('目标任务需要至少 8 个字符的验收条件。');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const run = await post<Run>('/runs', {
        snapshot_id: selected,
        scope,
        budgets,
        ...(taskSpec ? { task: taskSpec } : { prompt_id: promptId }),
      });
      setNotice(`已创建${taskSpec ? '目标任务' : '审计运行'} ${run.id.slice(0, 10)}：${run.total_units} 个单元`);
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

                <div className="field">
                  <span className="field-label">运行模式</span>
                  <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                    <label
                      className="checkbox"
                      style={{ alignItems: 'flex-start', padding: 10, border: '1px solid var(--line)', borderRadius: 7, background: mode === 'audit' ? 'var(--accent-soft)' : 'var(--surface)' }}
                    >
                      <input type="radio" name="run-mode" checked={mode === 'audit'} onChange={() => setMode('audit')} />
                      <span>
                        <strong>三类漏洞审计</strong>
                        <span className="field-hint" style={{ display: 'block' }}>固定检查 SQL 注入、反射型 XSS 与命令注入。</span>
                      </span>
                    </label>
                    <label
                      className="checkbox"
                      style={{ alignItems: 'flex-start', padding: 10, border: '1px solid var(--line)', borderRadius: 7, background: mode === 'goal' ? 'var(--accent-soft)' : 'var(--surface)' }}
                    >
                      <input type="radio" name="run-mode" checked={mode === 'goal'} onChange={() => setMode('goal')} />
                      <span>
                        <strong>目标任务</strong>
                        <span className="field-hint" style={{ display: 'block' }}>按你定义的目标拆分工作项，由多个 worker 在轮次内探索。</span>
                      </span>
                    </label>
                  </div>
                </div>

                {mode === 'goal' && (
                  <div style={{ marginBottom: 12, padding: '12px', border: '1px solid var(--line)', borderRadius: 7, background: 'var(--surface-sunken)' }}>
                    <div className="field">
                      <span className="field-label">任务目标</span>
                      <textarea
                        rows={3}
                        value={task.objective}
                        placeholder="例如：追踪上传入口到文件写入路径，判断是否存在可由源码行号支持的任意文件写入。"
                        onChange={(event) => setTask((current) => ({ ...current, objective: event.target.value }))}
                      />
                    </div>
                    <div className="field">
                      <span className="field-label">验收条件</span>
                      <textarea
                        rows={2}
                        value={task.success_criteria}
                        placeholder="例如：给出至少一条完整数据流、原始源码引用与触发前提；否则说明遍历范围和不可达原因。"
                        onChange={(event) => setTask((current) => ({ ...current, success_criteria: event.target.value }))}
                      />
                    </div>
                    <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
                      <div className="field">
                        <span className="field-label">每个工作项最大轮次</span>
                        <input
                          type="number"
                          min={1}
                          max={8}
                          value={task.max_iterations}
                          onChange={(event) => setTask((current) => ({ ...current, max_iterations: boundedNumber(event.target.value, 1, 8) }))}
                        />
                        <span className="field-hint">1–8 次；耗尽后由协调器依据全部结果判定不可达或未决。</span>
                      </div>
                      <div className="field">
                        <span className="field-label">任务总尝试上限</span>
                        <input
                          type="number"
                          min={1}
                          max={128}
                          value={task.max_total_attempts}
                          onChange={(event) => setTask((current) => ({ ...current, max_total_attempts: boundedNumber(event.target.value, 1, 128) }))}
                        />
                        <span className="field-hint">1–128 次；全部 worker 的已结算与执行中尝试共享此上限。</span>
                      </div>
                      <div className="field">
                        <span className="field-label">并发 worker 数</span>
                        <input
                          type="number"
                          min={1}
                          max={4}
                          value={task.max_workers}
                          onChange={(event) => setTask((current) => ({ ...current, max_workers: boundedNumber(event.target.value, 1, 4) }))}
                        />
                        <span className="field-hint">1–4 个；每个 worker 领取不同源码工作项。</span>
                      </div>
                    </div>
                    <label className="checkbox">
                      <input
                        type="checkbox"
                        checked={task.stop_on_achieved}
                        onChange={(event) => setTask((current) => ({ ...current, stop_on_achieved: event.target.checked }))}
                      />
                      首个有证据的目标达成后停止尚未开始的工作项
                    </label>
                    <label className="checkbox" style={{ marginTop: 8 }}>
                      <input
                        type="checkbox"
                        checked={task.require_poc}
                        onChange={(event) => setTask((current) => ({ ...current, require_poc: event.target.checked }))}
                      />
                      达成目标时要求附带可人工复核的 POC
                    </label>
                    <div className="field-hint" style={{ marginTop: 8 }}>
                      面向漏洞审计时应保持勾选；仅核对源码事实的任务可关闭。目标任务使用独立的受控执行指令，避免固定三类漏洞 Prompt 改写当前目标。
                    </div>
                  </div>
                )}

                <div className="grid" style={{ gridTemplateColumns: mode === 'goal' ? '1fr 1fr' : '1fr 1fr 1fr' }}>
                  {mode === 'audit' && (
                    <div className="field">
                      <span className="field-label">Prompt</span>
                      <select value={promptId} onChange={(event) => setPromptId(event.target.value)}>
                        {prompts.map((prompt) => (
                          <option key={prompt.id} value={prompt.id}>{prompt.id} · {prompt.label}</option>
                        ))}
                      </select>
                    </div>
                  )}
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
                    {busy ? '处理中…' : mode === 'goal' ? `开始目标任务（${units.length} 个单元）` : `开始审计（${units.length} 个单元）`}
                  </button>
                  <span className="field-hint">
                    {mode === 'goal'
                      ? '工作项、单项轮次、总尝试上限和 worker 数会随运行冻结；目标达到、总尝试耗尽或协调器判定不可达后结束。'
                      : '队列在运行开始时冻结；预算耗尽、解析失败与缺上下文都记为未完成，不记为阴性。'}
                  </span>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">运行记录</span>
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
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>模式 / 目标</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>进度</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>执行器</th>
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
                  <td style={{ padding: '8px 8px', maxWidth: 260 }} className="small">
                    {run.task_spec ? (
                      <>
                        <span className="chip">目标任务</span>
                        <div className="faint" style={{ marginTop: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={run.task_spec.objective}>
                          {run.task_spec.objective}
                        </div>
                      </>
                    ) : <span className="faint">三类漏洞审计</span>}
                  </td>
                  <td style={{ padding: '8px 8px' }} className="small">
                    {run.completed_units}/{run.total_units}
                  </td>
                  <td style={{ padding: '8px 8px' }} className="small">
                    {run.task_spec ? '目标任务执行器' : run.prompt_id}
                  </td>
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
