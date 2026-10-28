import type { ExecutionSummary, RunDetail, WorkflowStage } from '../types';
import { activeExecutionCount, contextLine, executionPhase, executionSummary, POC_MODE_LABELS, pocReason, stopReason, workflowFacts, workflowStopLabel, WORKFLOW_STAGE_LABELS } from '../execution';
import { Disclosure } from './Disclosure';
import { LongContent } from './LongContent';
import '../execution.css';

function count(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? String(Math.round(value * 10) / 10) : '—';
}

/** Only host counters are shown. Stage allocation is not a percentage of audit coverage. */
function WorkflowStatus({ facts }: { facts?: Partial<ExecutionSummary> | null }) {
  if (!facts) return null;
  const { workflow, directions, verification } = facts;
  if (!workflow && !directions && !verification) return null;
  return <div className="execution-workflow" aria-label="阶段配额与未决事项">
    {workflow?.version === 'discovery-first-v1' && <>
      <div className="execution-status-heading"><strong>先挖掘后验证</strong><span className="chip">当前阶段：{WORKFLOW_STAGE_LABELS[workflow.stage] ?? workflow.stage}</span></div>
      <div className="execution-stage-grid">{(['discovery', 'poc', 'review'] as WorkflowStage[]).map((stage) => <div key={stage} data-stage={stage} className={workflow.stage === stage ? 'is-current' : undefined}>
        <span className="small">{WORKFLOW_STAGE_LABELS[stage]}</span>
        <strong>已用 {count(workflow.used?.[stage])} / 配额 {count(workflow.limits?.[stage])}</strong>
        <small>剩余 {count(workflow.remaining?.[stage])} 次请求</small>
      </div>)}</div>
      <p className="small muted">静态阶段转入验证 {count(workflow.transferred)} 次请求；最终复核预留 {count(workflow.review_reserved_seconds)} 秒。
        {typeof workflow.stage_remaining_seconds === 'number' && <>当前阶段剩余最多 {count(workflow.stage_remaining_seconds)} 秒。</>}
        阶段配额表示成本额度，不代表源码覆盖率。</p>
      {workflow.discovery_stop && <p className="small muted">源码阶段停止原因：{workflowStopLabel(workflow.discovery_stop)}</p>}
    </>}
    {(directions || verification) && <div className="execution-facts execution-workflow-facts">
      {directions && <><span>未决方向 {count(directions.unsettled_total)}</span><span>待分配 {count(directions.pending_total)}</span><span>已分配未结算 {count(directions.assigned_total)}</span></>}
      {verification && <><span>待验证 {count(verification.pending)}</span><span>已验证 {count(verification.verified)}</span><span>正式复核 {count(verification.reviewed)}</span><span>待正式复核 {count(verification.pending_review)}</span></>}
    </div>}
  </div>;
}

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
    <WorkflowStatus facts={workflowFacts(detail)} />
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
    <WorkflowStatus facts={summary.execution} />
    <LongContent label="停止原因" value={summary.stop_reason} />
    <LongContent label="覆盖与未决方向" value={summary.coverage} />
    <LongContent label="审计限制" value={summary.limitations} />
    <Disclosure title="查看阶段报告完整事实"><LongContent label="宿主阶段事实" value={summary} /></Disclosure>
  </div></section>;
}
