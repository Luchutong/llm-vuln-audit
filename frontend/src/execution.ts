import type { Budget, Config, ExecutionContextStats, ExecutionSummary, PocMode, Run, RunDetail, WorkflowAllocation, WorkflowExecution, WorkflowStage } from './types';

export const DEFAULT_RUN_LIMITS: Budget = { responses: 256, tools: 2048, seconds: 1800 };
export const FALLBACK_RUN_BOUNDS = {
  min: { responses: 1, tools: 0, seconds: 30 },
  max: { responses: 4096, tools: 32768, seconds: 14400 },
};
export const POC_MODE_LABELS = { off: '关闭自动验证', auto: '环境可用时自动验证', required: '必须完成自动验证' };
const PHASE_LABELS: Record<string, string> = {
  pending: '等待执行', queued: '等待执行', planning: '规划审计', planner: '规划审计', running: '审计执行', exploring: '源码取证',
  worker: '源码取证', recon: '项目侦察', poc: '自动验证', verification: '自动验证',
  settling: '生成阶段报告', finalizing: '生成阶段报告', paused: '已暂停', completed: '执行结束',
  terminal: '执行结束', stopped: '执行结束', finished: '执行结束', ended: '执行结束',
  task_execute: '源码取证', task_decision: '整理源码结论', planner_explore: '规划取证方向',
  planner_decision: '整理审计计划', planner_publish: '提交审计计划', recon_explore: '项目侦察',
  recon_publish: '整理侦察结果', poc_execute: '自动验证', poc_conclude: '整理验证结论',
  task_prepare: '准备源码证据', task_publish: '提交源码结论', planner_prepare: '准备审计计划',
  prepare: '准备源码证据', explore: '源码取证', verdict: '整理源码结论',
};
const STOP_LABELS: Record<string, string> = {
  run_budget_exhausted: '整次审计预算已耗尽', budget_exhausted: '整次审计预算已耗尽',
  run_responses_exhausted: '整次模型请求额度已耗尽', run_tools_exhausted: '整次工具额度已耗尽',
  run_seconds_exhausted: '整次活跃时间已耗尽', deadline_exceeded: '整次活跃时间已耗尽',
  frontier_blocked: '审计方向仍有阻塞', no_progress: '未能继续取得证据',
  worker_exit_without_terminal: '执行未完成，已保存阶段报告', cancelled: '用户取消',
  user_cancelled: '用户取消', model_unavailable: '模型暂不可用',
};
const DIMENSIONS: Record<string, string> = { responses: '模型请求', tools: '工具调用', seconds: '活跃时间' };

/** Cloning carries frozen allowances, never prior usage, and always starts with POC off. */
export function draftRunLimits(seed?: Run, config?: Config | null): Budget {
  return { ...(seed?.run_limits ?? config?.run_budget_limits?.defaults ?? DEFAULT_RUN_LIMITS) };
}
export function executionSummary(detail: RunDetail): ExecutionSummary | null {
  return detail.execution_summary ?? detail.run.execution_summary ?? null;
}
/** A final host report can retain the facts even when an older response omits its live projection. */
export function workflowFacts(detail: RunDetail): Partial<ExecutionSummary> | null {
  return executionSummary(detail) ?? detail.run.final_summary?.execution ?? null;
}
export const WORKFLOW_STAGE_LABELS: Record<WorkflowStage, string> = {
  discovery: '源码规划与挖掘', poc: 'POC 验证', review: '验证复核与收束',
};
export function workflowStopLabel(stop?: WorkflowExecution['discovery_stop']): string {
  if (!stop) return '';
  if (typeof stop === 'object') return stop.basis || (stop.code ? workflowStopLabel(stop.code) : '源码阶段已结算');
  const labels: Record<string, string> = {
    settled: '源码阶段已结算', stage_budget_exhausted: '源码阶段额度已耗尽',
    discovery_budget_exhausted: '源码阶段额度已耗尽', met: '源码阶段验收已完成',
    inconclusive: '源码阶段仍有未决事项', unreachable: '源码阶段暂无可执行方向',
  };
  return labels[stop] ?? stop;
}
/** Preview only: execution always displays the server's frozen allocation and counters. */
export function draftWorkflowAllocation(responses: number, mode: PocMode): WorkflowAllocation {
  const total = Math.max(1, Math.floor(responses));
  const review = Math.min(total - 1, Math.ceil(total * 3 / 64));
  const poc = mode === 'off' ? 0 : Math.min(Math.floor(total / 4), Math.max(0, total - review - 1));
  return { discovery: total - review - poc, poc, review };
}
/** The request's quotas must partition an existing run budget; the server rejects the
 * same shapes, so catching them here keeps the user on the settings panel. */
export function workflowLimitsIssue(limits: WorkflowAllocation, responses: number, mode: PocMode): string | null {
  const total = Math.max(1, Math.floor(responses));
  if (limits.discovery < 1 || limits.review < 1) return '源码挖掘与最终复核各至少保留 1 次请求。';
  if (limits.poc < 0) return 'POC 验证配额不能为负。';
  if (mode === 'off' && limits.poc) return '关闭自动验证时 POC 配额必须为 0。';
  const sum = limits.discovery + limits.poc + limits.review;
  if (sum > total) return `三段合计 ${sum} 次，超过整次模型请求上限 ${total} 次。`;
  return null;
}
export function formatBytes(value?: number | null): string {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return '—';
  return value >= 1024 ? `${(value / 1024).toFixed(1)} KiB` : `${Math.round(value)} B`;
}

/** One line for the run summary: how close the window got, and what staying under cost. */
export function contextLine(context?: ExecutionContextStats | null): string {
  if (!context || typeof context.history_bytes !== 'number' || !context.history_bytes) return '';
  const parts = [`上下文峰值 ${formatBytes(context.peak_request_bytes)} / 上限 ${formatBytes(context.history_bytes)}`];
  if (context.compactions) parts.push(`触发压缩 ${context.compactions} 次`);
  if (context.summary_requests) parts.push(`摘要请求 ${context.summary_requests} 次`);
  if (context.limit_hits) parts.push(`达到上限 ${context.limit_hits} 次`);
  return parts.join(' · ');
}
export function executionPhase(phase: string): string { return PHASE_LABELS[phase] ?? phase; }
export function activeExecutionCount(summary: ExecutionSummary): number { return Array.isArray(summary.active_executions) ? summary.active_executions.length : summary.active_executions; }
export function stopReason(summary: ExecutionSummary | null): string {
  const stop = summary?.stop_reason;
  if (!stop) return '';
  return stop.message || `${STOP_LABELS[stop.code] ?? stop.code}${stop.dimension ? `（${DIMENSIONS[stop.dimension] ?? stop.dimension}）` : ''}`;
}
export function pocReason(reason?: string | null, message?: string | null): string {
  if (message) return message;
  const labels: Record<string, string> = {
    off: '本次已关闭自动验证，源码审计照常进行。', disabled: '本次已关闭自动验证，源码审计照常进行。',
    target_not_lab30: '该源码类型暂无可用的自动验证靶场，结论保留为未验证。',
    unsupported_target: '该源码类型暂无可用的自动验证靶场，结论保留为未验证。',
    environment_unavailable: '自动验证环境不可用，结论保留为未验证。',
    not_configured: '尚未配置自动验证环境，源码审计照常进行。',
    runner_unavailable: '隔离执行器不可用，结论保留为未验证。',
    runner_upgrade_required: '隔离执行器需要升级以支持独立验证上下文；源码审计仍可继续。',
    browser_unavailable: '浏览器验证环境不可用，结论保留为未验证。',
  };
  return labels[reason ?? ''] ?? reason ?? '尚未检查自动验证环境。';
}
