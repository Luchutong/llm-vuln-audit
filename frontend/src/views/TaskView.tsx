import { useEffect, useMemo, useState } from 'react';
import { api, errorText, post } from '../api';
import type { Config, Run, Snapshot, SnapshotSummary, TaskSpec } from '../types';

const EMPTY_TASK_SPEC: TaskSpec = {
  objective: '',
  success_criteria: '',
  max_iterations: 3,
  max_total_attempts: 24,
  max_planner_rounds: 8,
  max_workers: 2,
  stop_on_achieved: true,
  require_poc: false,
};

function boundedNumber(value: string, minimum: number, maximum: number) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return minimum;
  return Math.max(minimum, Math.min(maximum, Math.trunc(parsed)));
}

/**
 * The primary, source-agnostic task flow.
 *
 * The user sees only the data that freezes into a goal-driven run: PHP archive, selected
 * source scope, objective / acceptance criteria, and bounded Planner/worker budgets.
 */
export function TaskView({
  snapshots,
  config,
  onOpenRun,
  onChanged,
}: {
  snapshots: SnapshotSummary[];
  config: Config | null;
  onOpenRun: (runId: string) => void;
  onChanged: () => void;
}) {
  const [runs, setRuns] = useState<Run[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [scope, setScope] = useState<string[]>([]);
  const [budgets, setBudgets] = useState({ responses: 8, tools: 16, seconds: 300 });
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
      setScope([]);
      return;
    }
    api<Snapshot>(`/snapshots/${selected}`)
      .then((data) => {
        setSnapshot(data);
        const defaultPhp = data.files.filter((file) => !file.excluded);
        // A library-only archive may legitimately place every PHP file below a
        // dependency directory. Mirror the server's fallback in that case so the
        // first usable task does not start with an empty, disabled scope selector.
        const initialScope = defaultPhp.length > 0
          ? defaultPhp
          : data.files.filter((file) => file.is_php === true);
        setScope(initialScope.map((file) => file.path));
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
      setNotice(`已导入 ${created.name}：${created.files.length} 个文件，${created.units?.length ?? 0} 个索引片段`);
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
    const taskSpec = {
      ...task,
      objective: task.objective.trim(),
      success_criteria: task.success_criteria.trim(),
    };
    if (taskSpec.objective.length < 8) {
      setError('请填写至少 8 个字符的审计目标。');
      return;
    }
    if (taskSpec.success_criteria.length < 8) {
      setError('请填写至少 8 个字符的验收条件。');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const run = await post<Run>('/runs', {
        snapshot_id: selected,
        scope,
        budgets,
        task: taskSpec,
      });
      setNotice(`已创建项目级审计 ${run.id.slice(0, 10)}：Planner 将先建立动态任务图`);
      refreshRuns();
      onOpenRun(run.id);
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(false);
    }
  };

  const indexed = snapshot?.files ?? [];
  const included = indexed.filter((file) => !file.excluded);
  const optionalPhp = indexed.filter((file) => file.excluded && file.is_php === true);
  const excluded = indexed.filter((file) => file.excluded && file.is_php !== true);
  const indexedSymbols = useMemo(
    () => (snapshot?.units ?? []).filter((unit) => scope.includes(unit.file_path)).length,
    [snapshot, scope],
  );

  const selectAll = () => setScope([...included, ...optionalPhp].map((file) => file.path));
  const clearScope = () => setScope([]);

  return (
    <div className="grid" style={{ gridTemplateColumns: '1fr', gap: 14 }}>
      {error && <div className="error-box">{error}</div>}
      {notice && <div className="panel" style={{ padding: '10px 14px', color: 'var(--ok)', fontSize: 13 }}>{notice}</div>}
      {config && !config.configured && (
        <div className="error-box">模型未配置完成，请先到「配置」页检查连接状态。</div>
      )}

      <div className="grid" style={{ gridTemplateColumns: 'minmax(300px, 1fr) minmax(400px, 1.35fr)' }}>
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">1 · PHP 源码压缩包</span>
            <span className="faint small">{snapshots.length} 个快照</span>
          </div>
          <div style={{ padding: '12px 16px' }}>
            <div className="field">
              <span className="field-label">导入 PHP 源码 ZIP</span>
              <input
                type="file"
                accept=".zip,application/zip,application/x-zip-compressed"
                disabled={busy}
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (file) upload(file);
                  event.currentTarget.value = '';
                }}
              />
              <span className="field-hint">
                可导入任意 PHP 项目源码；索引 .php、.php3–.php8、.phps、.inc、.phtml，以及带 PHP 开始标记的无扩展名或框架专用文件。导入会拒绝路径穿越、符号链接与压缩炸弹，快照随后保持不可变。
              </span>
            </div>

            <div className="field">
              <span className="field-label">已导入的源码快照</span>
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
                <div>{snapshot.created_at.slice(0, 19)} · {snapshot.immutable ? '不可变快照' : '可变快照'}</div>
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
            <span className="panel-title">2 · 源码审计范围</span>
            {snapshot && (
              <span className="row">
                <button className="btn" onClick={selectAll} disabled={included.length + optionalPhp.length === scope.length}>全选 PHP</button>
                <button className="btn" onClick={clearScope} disabled={!scope.length}>清空</button>
              </span>
            )}
          </div>
          <div style={{ padding: '12px 16px' }}>
            {!snapshot ? (
              <div className="empty">导入或选择一个 PHP 源码快照后，在此确定审计范围。</div>
            ) : (
              <>
                <div className="field">
                  <span className="field-label">默认范围内的文件（{scope.filter((path) => included.some((file) => file.path === path)).length} / {included.length}）</span>
                  <div style={{ maxHeight: 240, overflowY: 'auto', border: '1px solid var(--line)', borderRadius: 7, padding: 8 }}>
                    {included.map((file) => (
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
                    已选择 {scope.length} 个文件，索引包含 {indexedSymbols} 个函数、方法或顶层代码片段。Planner 会以整个项目图建立跨文件任务，而不会把这些片段逐个分发给 agent。
                  </span>
                </div>

                {optionalPhp.length > 0 && (
                  <div className="field">
                    <span className="field-label">可选纳入的 PHP 依赖或生成文件（{scope.filter((path) => optionalPhp.some((file) => file.path === path)).length} / {optionalPhp.length}）</span>
                    <div style={{ maxHeight: 150, overflowY: 'auto', border: '1px solid var(--line)', borderRadius: 7, padding: 8 }}>
                      {optionalPhp.map((file) => (
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
                          <span className="faint small">{file.line_count} 行 · {file.exclude_reason ?? '默认排除'}</span>
                        </label>
                      ))}
                    </div>
                    <span className="field-hint">这些文件默认不进入首次审计以节省预算；勾选后会和其他已选 PHP 文件一起冻结到本次范围。</span>
                  </div>
                )}

                {excluded.length > 0 && (
                  <div className="field">
                    <span className="field-label">未索引为 PHP 源码的文件（{excluded.length}）</span>
                    <div className="small faint" style={{ maxHeight: 90, overflowY: 'auto' }}>
                      {excluded.map((file) => (
                        <div key={file.path} className="mono">{file.path} — {file.exclude_reason}</div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="panel-title">3 · 目标与执行边界</div>
            <div className="faint small">主 Planner 先读取项目图并建立跨文件任务图，再把独立证据方向分派给多个 worker。</div>
          </div>
          <span className="chip">多 worker</span>
        </div>
        <div style={{ padding: '12px 16px' }}>
          <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <span className="field-label">审计目标</span>
              <textarea
                rows={4}
                value={task.objective}
                placeholder="例如：追踪上传入口到文件写入路径，判断是否存在可由源码行号支持的任意文件写入。"
                onChange={(event) => setTask((current) => ({ ...current, objective: event.target.value }))}
              />
            </div>
            <div className="field">
              <span className="field-label">验收条件</span>
              <textarea
                rows={4}
                value={task.success_criteria}
                placeholder="例如：给出完整数据流、原始源码引用和触发前提；如果未满足，说明覆盖范围和不可达依据。"
                onChange={(event) => setTask((current) => ({ ...current, success_criteria: event.target.value }))}
              />
            </div>
          </div>

          <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
            <div className="field">
              <span className="field-label">每个动态任务最大尝试</span>
              <input
                type="number"
                min={1}
                max={8}
                value={task.max_iterations}
                onChange={(event) => setTask((current) => ({ ...current, max_iterations: boundedNumber(event.target.value, 1, 8) }))}
              />
              <span className="field-hint">1–8 次；耗尽后由协调器结合已保存结果判断不可达或未决。</span>
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
              <span className="field-hint">1–128 次；所有 worker 共享这个总上限。</span>
            </div>
            <div className="field">
              <span className="field-label">Planner 最大回合</span>
              <input
                type="number"
                min={1}
                max={32}
                value={task.max_planner_rounds}
                onChange={(event) => setTask((current) => ({ ...current, max_planner_rounds: boundedNumber(event.target.value, 1, 32) }))}
              />
              <span className="field-hint">每轮根据项目图和 worker 反馈创建、更新或收束动态任务。</span>
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
              <span className="field-hint">1–4 个；每个 worker 领取一项跨文件审计方向。</span>
            </div>
            <div className="field">
              <span className="field-label">每项模型响应上限</span>
              <input
                type="number"
                min={1}
                value={budgets.responses}
                onChange={(event) => setBudgets((current) => ({ ...current, responses: boundedNumber(event.target.value, 1, 128) }))}
              />
              <span className="field-hint">用于一次 Planner 或 worker 回合的模型请求预算。</span>
            </div>
            <div className="field">
              <span className="field-label">每项工具调用上限</span>
              <input
                type="number"
                min={1}
                value={budgets.tools}
                onChange={(event) => setBudgets((current) => ({ ...current, tools: boundedNumber(event.target.value, 1, 256) }))}
              />
              <span className="field-hint">源码读取、搜索等调用受此上限约束。</span>
            </div>
            <div className="field">
              <span className="field-label">每项墙钟上限（秒）</span>
              <input
                type="number"
                min={1}
                value={budgets.seconds}
                onChange={(event) => setBudgets((current) => ({ ...current, seconds: boundedNumber(event.target.value, 1, 3600) }))}
              />
              <span className="field-hint">到时会记录当前状态，不把未完成视作否定结论。</span>
            </div>
          </div>

          <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
            <label className="checkbox" style={{ alignItems: 'flex-start' }}>
              <input
                type="checkbox"
                checked={task.stop_on_achieved}
                onChange={(event) => setTask((current) => ({ ...current, stop_on_achieved: event.target.checked }))}
              />
              <span>
                <strong>达成后停止</strong>
                <span className="field-hint" style={{ display: 'block' }}>首个有源码证据的目标达成后，跳过尚未开始的动态任务。</span>
              </span>
            </label>
            <label className="checkbox" style={{ alignItems: 'flex-start' }}>
              <input
                type="checkbox"
                checked={task.require_poc}
                onChange={(event) => setTask((current) => ({ ...current, require_poc: event.target.checked }))}
              />
              <span>
                <strong>达成时要求 POC</strong>
                <span className="field-hint" style={{ display: 'block' }}>漏洞验证任务可勾选；源码事实、配置和架构审计默认不要求 POC。</span>
              </span>
            </label>
          </div>

          <div className="row" style={{ alignItems: 'flex-start', flexWrap: 'wrap' }}>
            <button className="btn btn-primary" onClick={start} disabled={busy || !scope.length || (config !== null && !config.configured)}>
              {busy ? '处理中…' : `启动 Planner 审计（${scope.length} 个文件）`}
            </button>
            <span className="field-hint" style={{ maxWidth: 720 }}>
              目标、验收条件、范围、Planner/worker 边界与预算会随运行冻结。完成页保留项目图、任务图、工具调用和证据化依据摘要，供复核执行过程。
            </span>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">目标审计记录</span>
          <span className="faint small">每 4 秒刷新</span>
        </div>
        {runs.length === 0 ? (
          <div className="empty">还没有目标审计记录。</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ color: 'var(--ink-soft)', fontSize: 12 }}>
                <th style={{ textAlign: 'left', padding: '8px 14px', fontWeight: 500 }}>运行</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>状态</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>目标</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>进度</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>模型用量</th>
                <th style={{ textAlign: 'left', padding: '8px 8px', fontWeight: 500 }}>创建时间</th>
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
                  <td style={{ padding: '8px 8px', maxWidth: 320 }} className="small">
                    {run.task_spec ? (
                      <div className="faint" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={run.task_spec.objective}>
                        {run.task_spec.objective}
                      </div>
                    ) : <span className="faint">历史运行</span>}
                  </td>
                  <td style={{ padding: '8px 8px' }} className="small">{run.completed_tasks ?? 0}/{run.total_tasks ?? 0} 任务</td>
                  <td style={{ padding: '8px 8px' }} className="small faint">{run.usage.requests} 响应 / {run.usage.tool_calls} 工具</td>
                  <td style={{ padding: '8px 8px' }} className="small faint">{run.created_at.slice(0, 19)}</td>
                  <td style={{ padding: '8px 14px' }}><button className="btn" onClick={() => onOpenRun(run.id)}>查看结果</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
