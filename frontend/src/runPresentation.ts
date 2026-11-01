import type { RunDetail, WorkflowStage } from './types';
import { executionSummary, pocReason, workflowFacts } from './execution.ts';
import type { FinalReviewFacts } from './finalReview';
import { runLabel } from './status.ts';

export function resultStatus(detail: RunDetail, facts: FinalReviewFacts | null): string {
  const { run } = detail;
  const incomplete = facts ? facts.run_outcome?.audit_complete === false || (facts.counts?.pending ?? 0) > 0 : run.final_summary?.complete === false;
  if (['completed', 'succeeded'].includes(run.status)) {
    if (incomplete) return '审计未完成';
    if (facts?.run_outcome?.audit_complete !== true) return '执行已结束';
  }
  return runLabel(run.status, (detail.goal ?? detail.goals?.[0])?.status);
}

export const RUN_STAGE_LABELS: Record<WorkflowStage, string> = { discovery: '源码审计', poc: 'POC 验证', review: '最终复核' };
export function runStage(detail: RunDetail): WorkflowStage | null {
  const facts = workflowFacts(detail);
  const stage = facts?.workflow?.stage;
  if (stage && stage in RUN_STAGE_LABELS) return stage;
  const phase = executionSummary(detail)?.phase ?? '';
  if (/^(poc|verification)(_|$)/.test(phase)) return 'poc';
  if (/^(review|finalizing|settling)$/.test(phase)) return 'review';
  if (/^(planning|planner|worker|recon|exploring|task|prepare|explore|verdict)(_|$)/.test(phase)) return 'discovery';
  return null;
}
export function displayCount(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? String(value) : '暂无数据';
}
export function sumCounts(...values: unknown[]): number | undefined {
  return values.every((value) => typeof value === 'number' && Number.isFinite(value) && value >= 0)
    ? (values as number[]).reduce((sum, value) => sum + value, 0) : undefined;
}
export function elapsedLabel(seconds: unknown): string {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds < 0) return '运行时间暂无数据';
  if (seconds < 60) return `已运行 ${Math.floor(seconds)} 秒`;
  if (seconds < 3600) return `已运行 ${Math.floor(seconds / 60)} 分钟`;
  return `已运行 ${Math.floor(seconds / 3600)} 小时 ${Math.floor(seconds % 3600 / 60)} 分钟`;
}
export function compactExecution(detail: RunDetail) {
  const summary = executionSummary(detail), facts = workflowFacts(detail), stage = runStage(detail);
  const mode = summary?.poc?.mode ?? detail.run.poc_mode ?? detail.run.poc_policy?.mode;
  const poc = summary?.poc;
  const pocLabel = mode === 'off' ? '自动验证未启用' : poc?.available === false ? pocReason(poc.reason ?? '', poc.message ?? '') || '验证环境不可用' : null;
  const active = detail.tasks?.filter((task) => task.state === 'running') ?? [];
  const queue = summary?.poc_queue;
  const current = queue?.items?.filter((item) => ['running', 'claimed'].includes(item.state)) ?? [];
  const titles = stage === 'poc' ? current.map((item) => item.title || '正在验证漏洞') : stage === 'review' ? [] : active.map((task) => task.title);
  const stats = summary?.poc_statistics;
  const published = stats?.conclusion?.published ?? queue?.counts?.completed;
  let progress = '';
  if (stage === 'poc') {
    progress = `已发布 ${displayCount(published)} 项`;
    if (typeof stats?.experiments?.observations === 'number' && stats.experiments.observations > 0 && published === 0) progress += ' · 已有实验观测，尚未发布';
    else if (typeof stats?.model?.waiting_seconds === 'number' && stats.model.waiting_seconds > 0) progress += ' · 等待模型响应';
  } else if (stage === 'review') progress = `已处理 ${displayCount(facts?.verification?.reviewed)} 项`;
  else if (stage === 'discovery') progress = `已结算 ${displayCount(detail.tasks?.filter((task) => task.state === 'completed').length)} 项排查`;
  return { stage, titles, progress, pocLabel, elapsed: elapsedLabel(summary?.run_usage?.seconds) };
}
