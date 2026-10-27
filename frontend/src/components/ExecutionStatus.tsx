import type { RunDetail } from '../types';
import { activeExecutionCount, contextLine, executionPhase, executionSummary, POC_MODE_LABELS, pocReason, stopReason } from '../execution';
import { Disclosure } from './Disclosure';
import { LongContent } from './LongContent';
import '../execution.css';

export function ExecutionStatus({ detail }: { detail: RunDetail }) {
  const summary = executionSummary(detail);
  const reason = stopReason(summary);
  const budget = summary?.run_limits ?? detail.run.run_limits;
  const usage = summary?.run_usage;
  const remaining = summary?.run_remaining;
  const frozenMode = detail.run.poc_policy?.mode;
  const mode = summary?.poc.mode ?? detail.run.poc_mode ?? (frozenMode === 'off' || frozenMode === 'auto' || frozenMode === 'required' ? frozenMode : undefined);
  const context = contextLine(summary?.context);
  return <section className="execution-status" aria-label="执行预算与验证策略">
    {summary && <div className="execution-status-heading"><strong>{executionPhase(summary.phase)}</strong><span className="faint small">{activeExecutionCount(summary)} 个执行活跃 · {summary.blocked_task_ids.length} 个方向受阻</span></div>}
    {reason && <p className="execution-stop" role="status">{reason}{detail.run.status === 'inconclusive' ? '；本次未完成穷尽审计，已有结论已保存。' : ''}</p>}
    {budget ? <div className="execution-budget-grid">{([{ key: 'responses', label: '模型请求' }, { key: 'tools', label: '工具调用' }, { key: 'seconds', label: '活跃秒数' }] as const).map(({ key, label }) => <div key={key}><span className="faint small">整次{label}</span><strong>{usage ? Math.round(usage[key] * 10) / 10 : '—'} / {budget[key]}</strong>{remaining && <small>剩余 {Math.max(0, Math.round(remaining[key] * 10) / 10)}</small>}</div>)}</div> : <p className="small muted">历史运行未设置整次硬预算；沿用创建时的单次限制。</p>}
    <p className="small muted">单次执行：{detail.run.budgets.responses} 次模型请求 · {detail.run.budgets.tools} 次工具调用 · {detail.run.budgets.seconds} 秒。暂停继续不重置消耗。</p>
    {context && <p className="execution-context small">{context}</p>}
    {Array.isArray(summary?.active_executions) && summary.active_executions.length > 0 && <Disclosure title="当前执行角色与实际额度"><LongContent label="执行额度" value={summary.active_executions} /></Disclosure>}
    {mode && <p className="execution-poc small">POC：{POC_MODE_LABELS[mode]}{mode === 'off' ? '；仅进行源码审计。' : `；${summary?.poc.available ? '环境可用' : pocReason(summary?.poc.reason, summary?.poc.message)}`}</p>}
  </section>;
}

/** The host facts are authoritative even if the latest Planner draft said “complete”. */
export function HostSummary({ detail }: { detail: RunDetail }) {
  const summary = detail.run.final_summary;
  if (!summary) return null;
  return <section className="panel" aria-label="宿主阶段报告"><div className="panel-head"><span className="panel-title">宿主阶段报告</span><span className="chip">{summary.complete === true ? detail.run.task_spec?.scenario ? '穷尽完成' : '目标已达成' : '未完成 · 已保存阶段结果'}</span></div><div className="panel-body grid">
    <p className="small muted">以下为框架根据已保存证据生成的最终事实。Planner 历史叙述供追溯，下载报告包含此阶段结论。</p>
    <div className="execution-facts"><span>原始发现 {String(summary.raw_finding_count ?? 0)}</span><span>有效发现 {String(summary.valid_finding_count ?? 0)}</span><span>去重台账 {String(summary.ledger_group_count ?? 0)}</span></div>
    <LongContent label="停止原因" value={summary.stop_reason} />
    <LongContent label="覆盖与未决方向" value={summary.coverage} />
    <LongContent label="审计限制" value={summary.limitations} />
    <Disclosure title="查看阶段报告完整事实"><LongContent label="宿主阶段事实" value={summary} /></Disclosure>
  </div></section>;
}
