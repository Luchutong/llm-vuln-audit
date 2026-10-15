import { useEffect, useRef, useState } from 'react';
import { api, errorText, post } from '../api';
import type { Budget, Config, Run, Snapshot, SnapshotSummary, TaskSpec } from '../types';

const EMPTY_TASK_SPEC: TaskSpec = {
  objective: '',
  success_criteria: '',
  max_iterations: 3,
  max_total_attempts: 64,
  max_planner_rounds: 24,
  max_workers: 2,
  stop_on_achieved: true,
  require_poc: false,
};

/** How many import-time entries a panel inlines before pointing at the full record. */
const LISTED_WARNINGS = 12;
const LISTED_SKIPPED = 20;
const LISTED_LANGUAGES = 10;

function boundedNumber(value: string, minimum: number, maximum: number) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return minimum;
  return Math.max(minimum, Math.min(maximum, Math.trunc(parsed)));
}

/**
 * The primary, source-agnostic task flow.
 *
 * There is no scope control: the whole uploaded archive is the audit scope, and what is
 * worth reading is a judgement the Planner makes from the project map -- not one the
 * uploader is asked to make before seeing any code. The user only supplies the data that
 * freezes into a goal-driven run: the archive, the objective / acceptance criteria, and
 * bounded Planner/worker budgets.
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
  const [budgets, setBudgets] = useState<Budget>({ responses: 24, tools: 96, seconds: 1800 });
  /** The server owns the allowance defaults; a second copy here would drift. */
  const seededBudgets = useRef(false);
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
      .then(setSnapshot)
      .catch((exc) => setError(errorText(exc)));
  }, [selected]);

  useEffect(() => {
    const defaults = config?.budget_limits?.defaults;
    // Adopt the server's defaults once, and only until the user touches the fields.
    if (!defaults || seededBudgets.current) return;
    seededBudgets.current = true;
    setBudgets(defaults);
  }, [config]);

  const upload = async (file: File) => {
    setBusy(true);
    setError(null);
    try {
      const body = new FormData();
      body.append('file', file);
      const created = await api<Snapshot>('/snapshots', { method: 'POST', body });
      const stats = created.stats ?? {};
      setNotice(
        `已导入 ${created.name}：${stats.files ?? created.files.length} 个文件（可读文本 ${stats.text_files ?? 0} 个）`,
      );
      onChanged();
      setSelected(created.id);
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(false);
    }
  };

  const start = async () => {
    if (!selected) return;
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

  const stats = snapshot?.stats ?? {};
  const languages = Object.entries(stats.languages ?? {});
  const skipped = snapshot?.skipped_files ?? [];
  const warnings = snapshot?.warnings ?? [];

  return (
    <div className="grid" style={{ gridTemplateColumns: '1fr', gap: 14 }}>
      {error && <div className="error-box">{error}</div>}
      {notice && <div className="panel" style={{ padding: '10px 14px', color: 'var(--ok)', fontSize: 13 }}>{notice}</div>}
      {config && !config.configured && (
        <div className="error-box">模型未配置完成，请先到「配置」页检查连接状态。</div>
      )}

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">1 · 项目源码压缩包</span>
          <span className="faint small">{snapshots.length} 个快照</span>
        </div>
        <div style={{ padding: '12px 16px' }}>
          <div className="grid" style={{ gridTemplateColumns: 'minmax(280px, 1fr) minmax(280px, 1fr)', gap: 12 }}>
            <div className="field">
              <span className="field-label">导入项目源码 ZIP</span>
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
                上传完整项目整包即审计范围，没有文件勾选步骤。PHP 用 tree-sitter 建语法索引，其它语言的文本文件按纯文本行索引并可读可搜、可作证据，二进制文件只登记不可读。导入会拒绝路径穿越、符号链接与超限归档；超出容量预算的单个条目会被跳过并记入告警，快照随后保持不可变。
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
              {snapshot && (
                <div className="small muted" style={{ marginTop: 6 }}>
                  <div>归档 SHA256 <span className="mono">{snapshot.archive_sha256.slice(0, 16)}…</span></div>
                  <div>{snapshot.created_at.slice(0, 19)} · {snapshot.immutable ? '不可变快照' : '可变快照'}</div>
                </div>
              )}
            </div>
          </div>

          {snapshot && (
            <div className="grid" style={{ marginTop: 12, gap: 10 }}>
              <div className="small">
                文件 {stats.files ?? snapshot.files.length} · 可读文本 {stats.text_files ?? 0} · 二进制 {stats.binary_files ?? 0} · 依赖/生成目录 {stats.dependency_tree_files ?? 0} · PHP 语法索引 {stats.php_files ?? 0}
                {typeof stats.skipped_count === 'number' && stats.skipped_count > 0 && (
                  <> · <span style={{ color: 'var(--warn, inherit)' }}>导入时跳过 {stats.skipped_count} 个</span></>
                )}
              </div>
              <div className="faint small">
                依赖目录与其它语言都在范围内：是否值得读由 Planner 按目标判断，不由上传者预先决定。
              </div>

              {languages.length > 0 && (
                <div className="field">
                  <span className="field-label">语言分布</span>
                  <div className="small faint">
                    {languages.slice(0, LISTED_LANGUAGES).map(([name, count]) => `${name} ${count}`).join(' · ')}
                    {languages.length > LISTED_LANGUAGES ? ` · 其余 ${languages.length - LISTED_LANGUAGES} 种见快照记录` : ''}
                  </div>
                </div>
              )}

              {warnings.length > 0 && (
                <div className="field">
                  <span className="field-label">导入告警（{warnings.length}）</span>
                  <ul className="small faint" style={{ margin: 0, paddingLeft: 18 }}>
                    {warnings.slice(0, LISTED_WARNINGS).map((warning, index) => <li key={index}>{warning}</li>)}
                  </ul>
                  {warnings.length > LISTED_WARNINGS && (
                    <span className="field-hint">其余 {warnings.length - LISTED_WARNINGS} 条见快照记录。</span>
                  )}
                </div>
              )}

              {skipped.length > 0 && (
                <div className="field">
                  <span className="field-label">被跳过、不在快照内的条目（{stats.skipped_count ?? skipped.length}）</span>
                  <div className="small faint mono" style={{ maxHeight: 120, overflowY: 'auto' }}>
                    {skipped.slice(0, LISTED_SKIPPED).map((item, index) => (
                      <div key={index}>{item.path} — {item.reason}</div>
                    ))}
                  </div>
                  {skipped.length > LISTED_SKIPPED && (
                    <span className="field-hint">其余 {skipped.length - LISTED_SKIPPED} 条见快照记录。</span>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="panel-title">2 · 目标与执行边界</div>
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
                max={512}
                value={task.max_total_attempts}
                onChange={(event) => setTask((current) => ({ ...current, max_total_attempts: boundedNumber(event.target.value, 1, 512) }))}
              />
              <span className="field-hint">1–512 次；所有 worker 共享这个总上限。更正重跑会另加一点额度。</span>
            </div>
            <div className="field">
              <span className="field-label">Planner 最大回合</span>
              <input
                type="number"
                min={1}
                max={128}
                value={task.max_planner_rounds}
                onChange={(event) => setTask((current) => ({ ...current, max_planner_rounds: boundedNumber(event.target.value, 1, 128) }))}
              />
              <span className="field-hint">1–128 轮；每轮根据项目图、本轮态势和 worker 反馈创建、更新或收束动态任务。</span>
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
                max={256}
                value={budgets.responses}
                onChange={(event) => setBudgets((current) => ({ ...current, responses: boundedNumber(event.target.value, 1, 256) }))}
              />
              <span className="field-hint">1–256 次；用于一次 Planner 或 worker 回合的模型请求预算。想提前停下用「暂停运行」。</span>
            </div>
            <div className="field">
              <span className="field-label">每项工具调用上限</span>
              <input
                type="number"
                min={1}
                max={2048}
                value={budgets.tools}
                onChange={(event) => setBudgets((current) => ({ ...current, tools: boundedNumber(event.target.value, 1, 2048) }))}
              />
              <span className="field-hint">1–2048 次；源码读取、搜索等调用受此上限约束。</span>
            </div>
            <div className="field">
              <span className="field-label">每项墙钟上限（秒）</span>
              <input
                type="number"
                min={1}
                max={14400}
                value={budgets.seconds}
                onChange={(event) => setBudgets((current) => ({ ...current, seconds: boundedNumber(event.target.value, 1, 14400) }))}
              />
              <span className="field-hint">1–14400 秒；到时会记录当前状态，不把未完成视作否定结论。</span>
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
            <button className="btn btn-primary" onClick={start} disabled={busy || !selected || (config !== null && !config.configured)}>
              {busy ? '处理中…' : '启动 Planner 审计'}
            </button>
            <span className="field-hint" style={{ maxWidth: 720 }}>
              目标、验收条件、整包快照范围、Planner/worker 边界与预算会随运行冻结。完成页保留项目图、任务图、每回合覆盖统计与固定调查、侦察简报、工具调用和证据化依据摘要，供复核执行过程。运行中可随时暂停并原样继续。
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
