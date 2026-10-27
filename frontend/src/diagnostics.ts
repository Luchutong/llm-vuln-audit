import type { AuditEvent, Verification, VerificationJob } from './types';
import { normalizeTrace, scalar } from './trace.ts';
import type { TraceEntry } from './trace';

export const ROLE_LABELS: Record<string, string> = { planner: 'Planner', worker: 'Worker', recon: '侦察', poc: 'POC Agent', host: '运行服务' };
export const PHASE_LABELS: Record<string, string> = {
  task_prepare: '任务准备', task_execute: '源码审计', planner_prepare: '规划准备',
  planner_explore: '项目探索', planner_decision: '计划决策', planner_publish: '提交计划',
  recon_explore: '只读侦察', recon_publish: '提交侦察', poc_prepare: '验证准备',
  poc_execute: 'POC 执行', poc_conclude: '验证结论', lifecycle: '运行状态',
};
export const ERROR_LABELS: Record<string, string> = {
  invalid_arguments: '参数无效', path_not_found: '路径不存在', scope_denied: '超出读取范围',
  context_missing: '缺少上下文', timeout: '调用超时', retry_exhausted: '重试次数耗尽',
  internal_error: '内部异常', cancelled: '已取消', no_code_block: '没有可解析的代码块',
  ambiguous_code_blocks: '存在多个动作代码块', incomplete_code: '动作代码不完整',
  invalid_python: 'Python 语法错误', unauthorized_import: '模块不在允许导入范围',
  invalid_json: 'JSON 格式无效', empty_response: '模型未返回正文',
  truncated_output: '结构化输出被截断', invalid_output: '决策未通过校验',
};
const FAILED = new Set(['error', 'failed', 'timeout', 'invalid_arguments', 'path_not_found', 'scope_denied', 'context_missing', 'retry_exhausted', 'internal_error']);
const OK = new Set(['ok', 'success', 'completed']);

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

/** A successful call says nothing by itself about the script or vulnerability. */
export function toolOutcome(payload: Record<string, unknown> | undefined) {
  if (!payload) return null;
  const status = scalar(payload.status);
  const errorCode = scalar(payload.error_code ?? payload.error_type);
  const error = scalar(payload.error);
  const failed = status !== 'cancelled' && errorCode !== 'cancelled'
    && (FAILED.has(status) || Boolean(error) || Boolean(errorCode));
  const cached = payload.cached === true || payload.cache_hit === true || status === 'duplicate' || status === 'repeated';
  const exitCode = typeof payload.exit_code === 'number' ? payload.exit_code : null;
  const timedOut = payload.timed_out === true || payload.execution_status === 'timeout';
  const precondition = object(payload.precondition);
  const execution = precondition.ok === false ? 'precondition_failed' : scalar(payload.execution_status)
    || (status === 'precondition_failed' ? status : '');
  let executionText = timedOut ? '作业执行超时' : exitCode !== null ? (exitCode === 0 ? '脚本退出码 0' : `脚本执行失败 · 退出码 ${exitCode}`)
    : ({ success: '作业执行成功', completed: '作业执行完成', failed: '作业执行失败', error: '作业执行失败',
      environment_mismatch: '实验前提不符', precondition_failed: '实验前提不符', preconditions_failed: '实验前提不符',
      authentication_failed: '身份认证失败', state_mismatch: '账号状态不符',
      not_run: '作业未执行', cancelled: '作业已取消', inconclusive: '作业结果未决' } as Record<string, string>)[execution] || (execution ? `作业状态：${execution}` : '');
  const executionFailed = timedOut || exitCode !== null && exitCode !== 0 || ['failed', 'error', 'environment_mismatch', 'precondition_failed', 'preconditions_failed', 'authentication_failed', 'state_mismatch', 'cancelled'].includes(execution);
  if (timedOut && exitCode !== null) executionText += ` · 退出码 ${exitCode}`;
  return { failed, cached, executionFailed, executionText,
    callText: failed ? (ERROR_LABELS[errorCode || status] || '调用失败') : status === 'cancelled' ? '调用已取消' : OK.has(status) || cached ? '调用完成' : '调用已返回',
    errorCode, error, hint: scalar(payload.hint), retryable: payload.retryable === true,
    httpStatus: typeof payload.http_status === 'number' ? payload.http_status : null };
}

export interface DiagnosticIncident {
  key: string;
  role: string;
  phase: string;
  invocation: string;
  requestIndex: string;
  entries: TraceEntry[];
  recovery?: TraceEntry;
}

function diagnosticError(entry: TraceEntry): boolean {
  const kind = entry.event.kind;
  if (kind === 'agent_error_summary') return false;
  if (['agent_parse_error', 'agent_execution_error', 'agent_output_rejected', 'model_retry', 'model_error'].includes(kind)) return true;
  if (kind === 'agent_code') return Boolean(entry.payload.error);
  return kind === 'tool_result' && toolOutcome(entry.payload)?.failed === true;
}
function successfulAction(entry: TraceEntry): boolean {
  if (entry.event.kind === 'agent_code') return !entry.payload.error;
  if (['agent_terminal', 'task_agent_terminal', 'planner_agent_terminal', 'recon_terminal'].includes(entry.event.kind)) {
    return ['completed', 'success', 'submitted', 'final_answer'].includes(scalar(entry.payload.reason ?? entry.payload.terminal_reason));
  }
  return ['planner_round_committed', 'task_assessment', 'planner_assessment'].includes(entry.event.kind) && !entry.payload.error;
}

/** Full-history, request-level incidents; duplicate SSE frames and nested errors count once. */
export function diagnosticIncidents(events: AuditEvent[]): DiagnosticIncident[] {
  const entries = normalizeTrace(events);
  const incidents = new Map<string, DiagnosticIncident>();
  for (const entry of entries) {
    if (!diagnosticError(entry)) continue;
    const context = entry.context;
    // groupKey carries the legacy task attempt/recon invocation when no explicit ID exists.
    const invocation = JSON.stringify([context.run, context.role, context.invocationId || entry.groupKey]);
    const request = context.requestIndex || `event:${entry.event.id}`;
    const key = JSON.stringify([invocation, request]);
    const incident = incidents.get(key) ?? { key, role: context.role, phase: entry.phase,
      invocation, requestIndex: context.requestIndex, entries: [] };
    incident.entries.push(entry);
    incidents.set(key, incident);
  }
  for (const incident of incidents.values()) {
    const lastError = incident.entries.at(-1)!.event.id;
    incident.recovery = entries.find((entry) => {
      const c = entry.context;
      const same = JSON.stringify([c.run, c.role, c.invocationId || entry.groupKey]) === incident.invocation;
      if (!same || entry.event.id <= lastError || !successfulAction(entry)) return false;
      const request = c.requestIndex;
      if (entry.event.kind.endsWith('_terminal')) return true;
      return ![...incidents.values()].some((other) => other.invocation === incident.invocation
        && request && other.requestIndex === request && other.entries.some((failure) =>
          !['model_retry', 'model_error'].includes(failure.event.kind)));
    });
  }
  return [...incidents.values()];
}

export function diagnosticGroups(incidents: DiagnosticIncident[]) {
  const groups = new Map<string, { key: string; role: string; phase: string; errors: number; recovered: number }>();
  for (const incident of incidents) {
    const key = JSON.stringify([incident.role, incident.phase]);
    const group = groups.get(key) ?? { key, role: incident.role, phase: incident.phase, errors: 0, recovered: 0 };
    group.errors++; group.recovered += Number(Boolean(incident.recovery)); groups.set(key, group);
  }
  return [...groups.values()];
}

export function verificationExecution(record: Verification): string {
  const labels: Record<string, string> = { success: '作业执行成功', syntax_error: '脚本语法错误', connection_failed: '无法连接目标',
    environment_mismatch: '实验前提不符', precondition_failed: '实验前提不符', timeout: '作业执行超时',
    authentication_failed: '身份认证失败', state_mismatch: '账号状态不符',
    not_triggered: '执行完成，未观察到预期触发', not_run: '未执行', other_error: '作业执行失败' };
  return labels[record.execution_status ?? ''] || (record.execution_status ? `执行状态：${record.execution_status}` : '历史记录未保存执行状态');
}

export function verificationJobOutcome(job: VerificationJob): ReturnType<typeof toolOutcome> {
  const result = object(job.result);
  const http = object(result.response);
  const candidate = scalar(job.execution_status ?? result.execution_status ?? job.status ?? result.status);
  const execution = new Set(['success', 'completed', 'failed', 'error', 'precondition_failed', 'preconditions_failed', 'environment_mismatch', 'authentication_failed', 'state_mismatch', 'timeout', 'cancelled', 'not_run']);
  return toolOutcome({ ...result, status: 'ok', exit_code: job.exit_code ?? result.exit_code,
    execution_status: execution.has(candidate) ? candidate : undefined,
    precondition: job.precondition ?? result.precondition,
    timed_out: job.timed_out ?? result.timed_out,
    http_status: job.http_status ?? result.http_status ?? (job.kind === 'http' ? http.status ?? result.status : undefined) });
}
