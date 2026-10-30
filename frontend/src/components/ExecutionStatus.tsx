import type { ExecutionSummary, RunDetail, WorkflowStage } from '../types';
import { activeExecutionCount, contextLine, executionPhase, executionSummary, POC_MODE_LABELS, pocReason, pocRequestLimits, stopReason, workflowFacts, workflowStopLabel, WORKFLOW_STAGE_LABELS } from '../execution';
import { localDate } from '../status';
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
    {workflow && ['discovery-first-v1', 'host-queue-v1'].includes(workflow.version) && <>
      <div className="execution-status-heading"><strong>{workflow.version === 'host-queue-v1' ? '宿主调度 · 统一终审' : '先挖掘后验证'}</strong><span className="chip">当前阶段：{WORKFLOW_STAGE_LABELS[workflow.stage] ?? workflow.stage}</span>{workflow.source && <span className="chip">{workflow.source === 'explicit' ? '固定分配配额' : '自动分配配额'}</span>}</div>
      <div className="execution-stage-grid">{(['discovery', 'poc', 'review'] as WorkflowStage[]).map((stage) => <div key={stage} data-stage={stage} className={workflow.stage === stage ? 'is-current' : undefined}>
        <span className="small">{WORKFLOW_STAGE_LABELS[stage]}</span>
        <strong>已用 {count(workflow.used?.[stage])} / 配额 {count(workflow.limits?.[stage])}</strong>
        <small>剩余 {count(workflow.remaining?.[stage])} 次请求</small>
      </div>)}</div>
      <p className="small muted">静态阶段转入验证 {count(workflow.transferred)} 次请求；最终复核预留 {count(workflow.review_reserved_seconds)} 秒。
        {typeof workflow.stage_remaining_seconds === 'number' && <>当前阶段剩余最多 {count(workflow.stage_remaining_seconds)} 秒。</>}
        阶段配额表示成本额度，不代表源码覆盖率。</p>
      {workflow.discovery_stop && <p className="small muted">源码阶段停止原因：{workflowStopLabel(workflow.discovery_stop)}</p>}
      {workflow.review_reserve && <p className="small muted">待终审 {count(workflow.review_reserve.pending_items)} 项 · 预计 {count(workflow.review_reserve.estimated_batches)} 批 · 当前预留 {count(workflow.review_reserve.responses)} 次请求。
        按实际批次容量与运行中 Worker 调整；时间预留只控制新任务准入。
        {!workflow.review_reserve.funded && '固定或剩余额度不足，未完成项将保留待审。'}</p>}
    </>}
    {(directions || verification) && <div className="execution-facts execution-workflow-facts">
      {directions && <><span>{workflow?.version === 'host-queue-v1' ? '必做未决方向' : '未决方向'} {count(directions.unsettled_total)}</span><span>待分配 {count(directions.pending_total)}</span><span>已分配未结算 {count(directions.assigned_total)}</span>{typeof directions.advisory_total === 'number' && <span>后续建议 {count(directions.advisory_total)}（不阻止收束）</span>}</>}
      {verification && <><span>待验证 {count(verification.pending)}</span><span>已验证 {count(verification.verified)}</span><span>正式复核 {count(verification.reviewed)}</span><span>待正式复核 {count(verification.pending_review)}</span></>}
    </div>}
  </div>;
}

/** Model waiting, experiment progress and publication are separate facts. */
function PocStatisticsFacts({ stats }: { stats?: ExecutionSummary['poc_statistics'] }) {
  if (!stats) return null;
  const { host, model, experiments, conclusion, recovery, continuation, generation } = stats;
  const waiting = model?.waiting_seconds;
  const observations = experiments?.observations;
  return <div className="grid" aria-label="POC 统计">
    <div className="execution-facts">
      <span>等待模型响应 {waiting == null ? '—' : `${count(waiting)} 秒`}</span>
      <span>距上次实验 {experiments?.since_last_seconds == null ? '—' : `${count(experiments.since_last_seconds)} 秒`}</span>
      <span>已有 {count(experiments?.jobs ?? 0)} 个已执行实验{observations == null ? '' : `，${count(observations)} 个观测`}</span>
      <span>已发布 {count(conclusion?.published ?? 0)} 项</span>
    </div>
    {conclusion?.unpublished_reason && <p className="small muted">尚未发布及原因：{conclusion.unpublished_reason}</p>}
    <p className="small muted">
      模型流 {count(model?.streams ?? 0)} 次结束{model?.aborted ? `、${count(model.aborted)} 次中断` : ''} · 首个事件 {model?.first_event_seconds == null ? '—' : `${count(model.first_event_seconds)} 秒`}
      {generation ? ` · 生成文本 ${count(generation.text_chars ?? 0)} 字符、思考 ${count(generation.thinking_chars ?? 0)} 字符、工具参数 ${count(generation.tool_arg_chars ?? 0)} 字符（仅计数）` : ''}。
      HTTP 200 只表示响应头已到；ping/keepalive 不计入进展。
    </p>
    {host?.heartbeat_age_seconds != null && <p className="small muted">宿主心跳：{count(host.heartbeat_age_seconds)} 秒前{host.soft_limit_exceeded ? '；已超过耗时提醒' : ''}。心跳不代表模型有进展。</p>}
    <p className="small muted">
      检查点 {count(experiments?.checkpoints ?? 0)} 次 · 重复实验被拒 {count(experiments?.duplicates ?? 0)} 次 · 补证 {count(experiments?.supplements ?? 0)} 次 ·
      只读恢复 {count(recovery?.started ?? 0)} 次（{count(recovery?.requests ?? 0)} 个请求）
      {continuation && (continuation.inherited || continuation.retested)
        ? ` · 沿用 ${count(continuation.inherited ?? 0)} 项（不构成本轮成果），本轮复测 ${count(continuation.retested ?? 0)} 项`
        : ''}。
    </p>
    {(stats.unfinished?.length ?? 0) > 0 && <Disclosure title={`未完成 ${count(stats.unfinished_total ?? stats.unfinished?.length ?? 0)} 项`}>
      <div className="grid">{stats.unfinished?.map((item) => <div key={item.finding_id} className="small" style={{ overflowWrap: 'anywhere' }}>
        {item.title || item.finding_id} · {item.state}{item.reason ? ` · ${item.reason}` : ''}
      </div>)}</div>
    </Disclosure>}
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
    {summary?.poc_queue && <div className="grid" aria-label="POC 验证队列">
      <strong>持续会话验证队列 · {summary.poc_queue.total} 项</strong>
      <div className="execution-facts"><span>已发布 {count(summary.poc_queue.counts.completed ?? 0)}</span><span>执行中 {count((summary.poc_queue.counts.running ?? 0) + (summary.poc_queue.counts.claimed ?? 0))}</span><span>待执行 {count(summary.poc_queue.counts.pending ?? 0)}</span><span>延期／中断 {count((summary.poc_queue.counts.deferred ?? 0) + (summary.poc_queue.counts.interrupted ?? 0) + (summary.poc_queue.counts.unavailable ?? 0))}</span><span>复用 {count(summary.poc_queue.counts.reused ?? 0)}</span></div>
      {summary.poc_queue.heartbeat && <p className="small muted">最近心跳 {localDate(summary.poc_queue.heartbeat.at)} · 当前项已运行 {count(summary.poc_queue.heartbeat.elapsed_seconds)} 秒。心跳只说明宿主仍在运行，不代表模型有新进展。{summary.poc_queue.heartbeat.soft_limit_exceeded && '已超过耗时提醒，仍继续验证。'}</p>}
      <Disclosure title="逐项验证进度"><div className="grid">{summary.poc_queue.items.map(item => <div key={item.finding_id} className="small" style={{ overflowWrap: 'anywhere' }}>
        <strong>{item.title}</strong> · 版本 {item.revision} · {({ pending: '待执行', claimed: '已领取', running: '执行中', completed: '已发布', interrupted: '中断，保留原作业', unavailable: '暂不可用', deferred: '未执行，等待追加预算', reused: '复用原结果' } as Record<string, string>)[item.state] || item.state}
        {item.state === 'completed' && ` · ${({ verified: '已验证', rejected: '未通过', inconclusive: '未决' } as Record<string, string>)[item.status] || item.status}`}
      </div>)}{summary.poc_queue.omitted > 0 && <p className="small muted">另有 {summary.poc_queue.omitted} 项，详情见漏洞列表；上方计数包含全部项目。</p>}</div></Disclosure>
    </div>}
    <PocStatisticsFacts stats={summary?.poc_statistics} />
    <p className="small muted">源码 Agent 单次执行：{detail.run.budgets.responses} 次模型请求 · {detail.run.budgets.tools} 次工具调用 · {detail.run.budgets.seconds} 秒。暂停继续不重置消耗。</p>
    {context && <p className="execution-context small">{context}</p>}
    {Array.isArray(summary?.active_executions) && summary.active_executions.length > 0 && <Disclosure title="当前执行角色与实际额度"><LongContent label="执行额度" value={summary.active_executions} /></Disclosure>}
    {mode && <p className="execution-poc small">POC：{POC_MODE_LABELS[mode]}{mode === 'off' ? '；仅进行源码审计。' : `；${summary?.poc.available ? '环境可用' : pocReason(summary?.poc.reason, summary?.poc.message)}`}</p>}
    {mode !== 'off' && pocRequestLimits(detail.run.poc_policy) && <p className="small muted">{pocRequestLimits(detail.run.poc_policy)}</p>}
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
