import type { Budget, Config, ExecutionSummary, Run, RunDetail } from './types';

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
    browser_unavailable: '浏览器验证环境不可用，结论保留为未验证。',
  };
  return labels[reason ?? ''] ?? reason ?? '尚未检查自动验证环境。';
}
