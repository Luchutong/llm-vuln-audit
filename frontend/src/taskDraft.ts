import type { TaskSpec } from './types';

export type CompletionPolicy = 'goal' | 'coverage_review';

/** Describe the frozen run rather than applying the new draft's defaults. */
export function frozenTaskPolicy(task?: Partial<TaskSpec> | null) {
  return {
    mode: task?.completion_policy === 'coverage_review' ? '全量覆盖复核' : `快速目标审计${task?.completion_policy ? '' : '（旧记录默认）'}`,
    baseline: task?.baseline_policy === 'fresh' ? '空白漏洞基线 · 本次独立取证' : `继承项目已有漏洞${task?.baseline_policy ? '' : '（旧记录默认）'}`,
    baselineDescription: task?.baseline_policy === 'fresh'
      ? '本轮未继承历史漏洞结论；共享项目台账与旧运行仍保留，本轮发现继续归入该源码项目。'
      : '本轮允许使用冻结的项目既有漏洞作为审计线索。',
    workflow: task?.orchestration_policy === 'host-queue-v1' ? '宿主按需调度 · 先挖掘后验证 · 统一终审' : task?.workflow_policy === 'discovery_first' ? '先源码挖掘，再分批验证与正式复核' : '共享预算调度（旧政策）',
  };
}

/** New interactive audits review the full source frontier. Historical tasks keep the
 * policy that was actually frozen, including the legacy goal default. */
export function draftTask(seed?: Partial<TaskSpec>): TaskSpec {
  return {
    objective: '', success_criteria: '', max_iterations: 3, max_total_attempts: 64,
    max_planner_rounds: 24, max_workers: 2, stop_on_achieved: false,
    completion_policy: 'coverage_review', workflow_policy: 'discovery_first', baseline_policy: 'fresh', require_poc: false, scenario: null,
    orchestration_policy: 'host-queue-v1', review_policy: 'batch-v1',
    ...seed,
    ...(seed && !seed.completion_policy ? { completion_policy: 'goal' as CompletionPolicy } : {}),
    ...(seed && !seed.baseline_policy ? { baseline_policy: 'inherit' as const } : {}),
    ...(seed && !seed.workflow_policy ? { workflow_policy: 'legacy' as const } : {}),
    ...(seed && !seed.orchestration_policy ? { orchestration_policy: 'rounds-v1' as const } : {}),
  };
}

export function taskWithPolicy(task: TaskSpec, policy: CompletionPolicy): TaskSpec {
  return { ...task, completion_policy: policy, stop_on_achieved: policy === 'coverage_review' ? false : true,
    workflow_policy: policy === 'coverage_review' ? 'discovery_first' : 'legacy',
    orchestration_policy: policy === 'coverage_review' ? 'host-queue-v1' : 'rounds-v1',
    review_policy: policy === 'coverage_review' ? 'batch-v1' : task.review_policy,
    baseline_policy: policy === 'coverage_review' ? 'fresh' : 'inherit' };
}

export function taskForStart(task: TaskSpec, objective: string, scopeSuffix = ''): Partial<TaskSpec> {
  const payload: Partial<TaskSpec> = {
    ...task, objective: objective + scopeSuffix,
    ...(task.completion_policy === 'coverage_review' ? { stop_on_achieved: false } : {}),
  };
  // Acceptance is frozen by the server for the explicit mode, never guessed from
  // the user's natural-language objective or a copied historical criterion.
  delete payload.success_criteria;
  // Stage quotas are chosen in the settings panel for this request; a cloned run's
  // frozen quotas must not leak into a different mode or budget.
  delete payload.workflow_limits;
  return payload;
}
