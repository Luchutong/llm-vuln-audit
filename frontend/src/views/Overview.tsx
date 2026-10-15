import { scopeFileCount, scopeLabel } from '../types';
import type { AuditEvent, PlannerTask, RunDetail } from '../types';

const GOAL_LABELS: Record<string, string> = {
  open: '探索中', met: '已达成', unreachable: '不可达', inconclusive: '未决',
};

const TASK_LABELS: Record<string, string> = {
  pending: '等待依赖', ready: '待领取', running: '执行中', deferred: '已暂缓', completed: '已完成',
  exhausted: '方向耗尽', blocked: '受阻', cancelled: '已取消', skipped: '已跳过',
};

function references(task: PlannerTask) {
  const refs = task.context_spec?.source_refs ?? [];
  const scopePaths = task.context_spec?.scope_paths ?? [];
  const symbols = task.context_spec?.target_symbols ?? [];
  return {
    refs: refs.map((item) => `${item.path}:${item.start_line}-${item.end_line}`),
    scopePaths,
    symbols,
  };
}

function taskResult(task: PlannerTask) {
  const result = task.result;
  return result?.summary || task.error || '尚无 worker 结果';
}

function Stat({ value, label, note }: { value: string | number; label: string; note: string }) {
  return (
    <div className="stat">
      <strong>{value}</strong>
      <span>{label}</span>
      <small>{note}</small>
    </div>
  );
}

/** Project-level status: source slices are not displayed as a work queue. */
export function Overview({ detail, events }: { detail: RunDetail; events: AuditEvent[] }) {
  const { run, metrics } = detail;
  const planner = detail.planner;
  const goal = detail.goal ?? detail.goals?.[0];
  const projectMap = detail.project_map;
  const plans = detail.plans ?? [];
  const tasks = detail.tasks ?? [];
  const findings = detail.findings ?? [];
  const counts = tasks.reduce<Record<string, number>>((result, task) => {
    result[task.state] = (result[task.state] ?? 0) + 1;
    return result;
  }, {});
  const toolCalls = events.filter((event) => event.kind === 'tool_call').length;
  const plannerEvents = events.filter((event) => event.kind.startsWith('planner_')).length;
  const mapStats = projectMap?.stats ?? {};

  return (
    <div className="grid">
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(155px, 1fr))' }}>
        <Stat value={`${planner?.current_round ?? 0}/${planner?.max_rounds ?? run.task_spec?.max_planner_rounds ?? '—'}`} label="Planner 回合" note={`版本 ${planner?.current_revision ?? 0}`} />
        <Stat value={`${metrics.terminal_tasks ?? 0}/${metrics.total_tasks ?? tasks.length}`} label="已结算动态任务" note={`执行中 ${metrics.active_tasks ?? counts.running ?? 0}`} />
        <Stat value={findings.filter((item) => item.validation_state === 'candidate').length} label="证据化发现" note={`待复核 ${metrics.awaiting_verification}`} />
        <Stat value={toolCalls || run.usage.tool_calls} label="只读工具调用" note={`模型响应 ${run.usage.requests}`} />
        <Stat value={mapStats.files ?? scopeFileCount(run, projectMap)} label="项目图文件" note={`${mapStats.symbols ?? 0} 个符号`} />
        <Stat value={plannerEvents} label="Planner 轨迹事件" note="可在执行轨迹展开" />
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="panel-title">目标收束</div>
            <div className="faint small">主 Planner 维护跨文件任务图；worker 只能提交证据化结果和下一方向。</div>
          </div>
          <span className={`chip chip-${goal?.status ?? run.status}`}>{GOAL_LABELS[goal?.status ?? ''] ?? run.status}</span>
        </div>
        <div className="grid" style={{ padding: '12px 16px', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
          <div className="field"><span className="field-label">审计目标</span><span className="small">{run.task_spec?.objective ?? '—'}</span></div>
          <div className="field"><span className="field-label">验收条件</span><span className="small">{run.task_spec?.success_criteria ?? '—'}</span></div>
          <div className="field"><span className="field-label">当前状态</span><span className="small">{goal?.terminal_reason ?? planner?.terminal_reason ?? '尚在收集项目图或 worker 反馈。'}</span></div>
          <div className="field"><span className="field-label">边界</span><span className="small">{scopeLabel(run, projectMap)}；动态 include、路由和运行时配置会作为缺失上下文保留。</span></div>
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: 'minmax(300px, 1fr) minmax(420px, 1.6fr)' }}>
        <div className="panel">
          <div className="panel-head"><span className="panel-title">冻结项目图</span><span className="faint small">规划索引，不是发现证据</span></div>
          <div style={{ padding: '12px 16px' }} className="grid">
            <div className="small">文件 {mapStats.files ?? 0} · 符号 {mapStats.symbols ?? 0} · 静态 include {mapStats.includes ?? 0} · 调用点 {mapStats.calls ?? 0}</div>
            <div className="faint small">高置信入口 {mapStats.entrypoints ?? 0} · 低置信静态根 {mapStats.low_confidence_roots ?? 0} · 未解析 include {mapStats.unresolved_includes ?? 0}</div>
            <div className="field">
              <span className="field-label">高置信入口候选</span>
              {(projectMap?.entrypoints ?? []).length === 0 ? <span className="faint small">尚未记录。</span> : (
                <div className="small mono" style={{ maxHeight: 150, overflowY: 'auto' }}>
                  {(projectMap?.entrypoints ?? []).slice(0, 16).map((entry, index) => {
                    const value = entry as { path?: string; reason?: string; confidence?: string };
                    return <div key={index}>{String(value.path ?? entry)}{value.reason ? ` · ${value.reason}` : ''}{value.confidence ? ` · ${value.confidence}` : ''}</div>;
                  })}
                </div>
              )}
            </div>
            <div className="faint small">{projectMap?.limitations?.[0] ?? '静态图不能代替运行时调用图。'}</div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><span className="panel-title">Planner 回合</span><span className="faint small">每个版本均持久化，可回看调度依据</span></div>
          {plans.length === 0 ? <div className="empty">等待主 Planner 建立第一版任务图。</div> : (
            <div style={{ maxHeight: 290, overflowY: 'auto' }}>
              {plans.map((plan) => (
                <details key={plan.id} style={{ padding: '10px 14px', borderBottom: '1px solid var(--line-soft)' }}>
                  <summary className="row" style={{ cursor: 'pointer', flexWrap: 'wrap' }}>
                    <span className={`chip chip-${plan.status}`}>第 {plan.round_no} 回合</span>
                    <span className="small">{plan.basis_summary || '等待 Planner 返回依据摘要。'}</span>
                  </summary>
                  <div className="small" style={{ marginTop: 7 }}>
                    <div>目标建议：{plan.goal_state ?? 'continue'} · 下一步：{plan.next_action || '—'}</div>
                    {plan.error && <div style={{ color: 'var(--danger)' }}>错误：{plan.error}</div>}
                    {(plan.task_snapshot as { task_key?: string; title?: string }[]).length > 0 && <div className="faint" style={{ marginTop: 4 }}>本轮任务：{(plan.task_snapshot as { task_key?: string; title?: string }[]).map((item) => item.title || item.task_key).join('；')}</div>}
                  </div>
                </details>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div><div className="panel-title">动态任务图</div><div className="faint small">依赖满足后才进入 worker 队列；任务跨文件上下文由 Planner 指定并由工具补读。</div></div>
          <span className="faint small">{Object.entries(counts).map(([state, count]) => `${TASK_LABELS[state] ?? state} ${count}`).join(' · ') || '尚未建立'}</span>
        </div>
        {tasks.length === 0 ? <div className="empty">首轮 Planner 尚未提交任务。</div> : (
          <div style={{ maxHeight: 520, overflowY: 'auto' }}>
            {tasks.map((item) => {
              const source = references(item);
              return (
                <details key={item.id} style={{ padding: '10px 14px', borderBottom: '1px solid var(--line-soft)' }}>
                  <summary className="row" style={{ cursor: 'pointer', alignItems: 'flex-start', flexWrap: 'wrap' }}>
                    <span className={`chip chip-${item.state}`}>{TASK_LABELS[item.state] ?? item.state}</span>
                    <span className="small"><strong>{item.title}</strong> · {item.attempts}/{item.max_attempts} 次</span>
                    <span className="faint small">{taskResult(item)}</span>
                  </summary>
                  <div className="grid" style={{ marginTop: 9, gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
                    <div className="small"><span className="field-label">任务目标</span>{item.objective}</div>
                    <div className="small"><span className="field-label">初始上下文</span>{source.refs.length ? source.refs.map((ref) => <div className="mono" key={ref}>{ref}</div>) : '由高置信入口、引导文件或 Planner 查询线索组成'}{source.scopePaths.length > 0 && <div className="faint">范围：{source.scopePaths.join('、')}</div>}{source.symbols.length > 0 && <div className="faint">符号：{source.symbols.join('、')}</div>}</div>
                    <div className="small"><span className="field-label">依赖</span>{item.dependencies.length ? item.dependencies.join('、') : '无'}{item.error && <div style={{ color: 'var(--danger)', marginTop: 4 }}>{item.error}</div>}</div>
                  </div>
                  {(item.attempt_history ?? []).length > 0 && <div style={{ marginTop: 9 }}><span className="field-label">尝试历史</span>{item.attempt_history?.map((attempt) => <div className="small faint" key={`${attempt.attempt}-${attempt.created_at}`}>第 {attempt.attempt} 次 · {attempt.outcome ?? attempt.state ?? '—'} · {attempt.result?.summary ?? attempt.error ?? '—'}</div>)}</div>}
                </details>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
