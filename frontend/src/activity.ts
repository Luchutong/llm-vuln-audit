import type { AuditEvent, RunDetail } from './types';
import { normalizeTrace, pairToolCalls, scalar, shortText, traceRunState } from './trace.ts';
import type { ToolSpan, TraceContext, TraceEntry } from './trace';

interface ActivityBase {
  key: string;
  order: number;
  context: TraceContext;
  actor: string;
  taskTitle: string;
  createdAt: string;
}
export interface ActivityMessage extends ActivityBase {
  type: 'message';
  kind: string;
  title: string;
  text: string;
  secondary?: string;
  tone: 'neutral' | 'progress' | 'warning' | 'error';
  entry: TraceEntry;
}
export interface ActivityTool extends ActivityBase {
  type: 'tool';
  span: ToolSpan;
  status: 'running' | 'success' | 'warning' | 'error' | 'missing';
  label: string;
  subject: string;
  current: boolean;
  ownerKey: string;
}
export interface ActivityWaiting extends ActivityBase {
  type: 'waiting';
  text: string;
  entry: TraceEntry;
}
export type ActivityItem = ActivityMessage | ActivityTool | ActivityWaiting;
export interface ActivityToolGroup {
  type: 'tool-group';
  key: string;
  order: number;
  actor: string;
  taskTitle: string;
  tools: ActivityTool[];
}
export type ActivityDisplayItem = ActivityItem | ActivityToolGroup;

const FAILURE_STATUSES = new Set(['error', 'failed', 'timeout', 'invalid_arguments']);
const SUCCESS_STATUSES = new Set(['ok', 'success', 'completed']);
const TOOL_LABELS: Record<string, string> = {
  read_source: '读取源码', search_code: '检索代码', find_files: '查找文件', list_directory: '浏览目录',
  list_tree: '浏览目录', list_files: '浏览文件', get_file_outline: '查看文件结构', file_outline: '查看文件结构',
  get_symbol: '查看符号', lookup_symbol: '查找符号', get_project_map: '查看项目图',
  inspect_project: '查看项目结构', investigate_project: '调查项目',
  read_investigation: '读取已有调查', search_worker_traces: '检索已有审计记录',
  search_project_map: '检索项目图', get_task_results: '读取任务结果', get_coverage: '查看读取覆盖',
  get_investigation: '读取已有调查', file_summary: '查看文件结构', get_context: '补充源码上下文',
  search_peer_traces: '检索协作记录', get_peer_trace: '读取协作记录',
  resolve_target: '解析靶场目标', target_status: '查看靶场状态', target_prepare: '准备靶场环境',
  run_poc: '执行 POC', http_observe: 'HTTP 观测', browser_check: '浏览器验证',
  save_artifact: '保存证据',
};
const VERIFICATION_STATUS_LABELS: Record<string, string> = {
  verified: '已验证', rejected: '未通过', inconclusive: '未能判定', not_applicable: '不适用',
  environment_unavailable: '环境不可用', unverified: '待验证', stale: '源码已变更',
};
const TASK_END = /^(planner_task|task_work)_(completed|exhausted|blocked|cancelled|skipped|requeued|settled)$/;
const PLANNER_END = /^(planner_round_committed|planner_round_failed|planner_agent_terminal)$/;

function text(value: unknown): string { return typeof value === 'string' ? value.trim() : ''; }
function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
function summaryScope(entry: TraceEntry): string {
  const c = entry.context;
  return JSON.stringify([c.run, c.role === 'planner' ? 'planner' : 'task',
    c.role === 'planner' ? c.round || c.plan : c.task, c.role === 'planner' ? '' : c.attempt]);
}
function ownerKey(context: TraceContext): string {
  return JSON.stringify([context.run, context.role, context.task || context.session, context.attempt,
    context.role === 'planner' || context.role === 'recon' ? context.round || context.plan : '']);
}
function requestOwner(entry: TraceEntry): string {
  return JSON.stringify([entry.groupKey, entry.context.invocationId, entry.phaseKey]);
}
function requestKey(entry: TraceEntry): string {
  return JSON.stringify([requestOwner(entry), entry.context.requestIndex]);
}
function toolDescription(span: ToolSpan): { label: string; subject: string } {
  const args = record(span.call?.payload.args);
  const name = span.name;
  let subject = text(args.path) || text(args.file_path) || text(args.directory) || text(args.pattern)
    || text(args.query) || text(args.symbol) || text(args.question) || text(args.topic) || text(args.filename);
  if (name === 'run_poc') {
    const script = text(args.script);
    subject = [text(args.language) || '脚本', script ? `${new TextEncoder().encode(script).length} 字节` : '']
      .filter(Boolean).join(' · ');
  }
  if (name === 'http_observe') subject = [text(args.method) || 'GET', text(args.path)].filter(Boolean).join(' ');
  if (name === 'search_code' || name === 'search_project_map' || name === 'search_peer_traces') {
    const query = text(args.query) || text(args.pattern) || text(args.text) || text(args.symbol);
    const path = text(args.path) || text(args.file_path) || text(args.directory);
    subject = [query, path].filter(Boolean).join(' · ');
  }
  if (name === 'read_source' && subject) {
    const start = Number(args.start ?? args.start_line);
    const end = Number(args.end ?? args.end_line);
    if (Number.isSafeInteger(start) && start >= 1) {
      subject += `:${start}${Number.isSafeInteger(end) && end > start ? `–${end}` : ''}`;
    }
  }
  return { label: TOOL_LABELS[name] ?? (name ? `调用 ${name}` : '调用工具'), subject };
}
function base(entry: TraceEntry, taskNames: Map<string, string>): ActivityBase {
  const c = entry.context;
  const taskTitle = taskNames.get(c.task) || text(entry.payload.title)
    || (c.role === 'worker' ? '源码审计' : '');
  const actor = c.role === 'planner' ? '任务规划' : c.role === 'recon' ? '项目侦察'
    : c.role === 'poc' ? 'POC 验证' : c.role === 'worker' ? taskTitle : '运行状态';
  return { key: `activity:${entry.event.run_id}:${entry.event.id}`, order: entry.event.id, context: c,
    actor, taskTitle, createdAt: entry.event.created_at };
}

/** A deterministic, public activity view of the durable log; never a generated narration. */
export function projectActivity(events: AuditEvent[], detail: RunDetail | null): ActivityItem[] {
  const entries = normalizeTrace(events);
  const running = traceRunState(entries, detail?.run.status) === 'running';
  const taskNames = new Map<string, string>();
  for (const task of detail?.tasks ?? []) taskNames.set(task.id, task.title);
  for (const work of detail?.work_items ?? []) taskNames.set(work.id, work.summary || work.focus || '源码审计');
  for (const entry of entries) {
    if (entry.context.task && text(entry.payload.title) && !taskNames.has(entry.context.task)) {
      taskNames.set(entry.context.task, text(entry.payload.title));
    }
  }
  const formalSummaries = new Set(entries.filter((e) => ['task_assessment', 'planner_assessment'].includes(e.event.kind)).map(summaryScope));
  const ended = new Map<string, number>();
  for (const entry of entries) {
    if (TASK_END.test(entry.event.kind) || PLANNER_END.test(entry.event.kind) || ['task_agent_terminal', 'agent_terminal', 'recon_terminal'].includes(entry.event.kind)) {
      ended.set(ownerKey(entry.context), entry.event.id);
    }
  }
  const items: ActivityItem[] = [];
  const latestRequests = new Map<string, { invocation: string; request: string }>();
  const pending = new Map<string, TraceEntry>();
  for (const entry of entries) {
    const { event, payload, context } = entry;
    const kind = event.kind;
    const owner = ownerKey(context);
    if (['model_request', 'model_response', 'tool_call', 'agent_code', 'agent_parse_error', 'audit_progress'].includes(kind)) {
      latestRequests.set(owner, { invocation: context.invocationId || context.invocation, request: context.requestIndex });
    }
    if (kind === 'model_request') {
      // Calls by one actor are sequential. A retry supersedes its unanswered request.
      for (const [key, previous] of pending) if (ownerKey(previous.context) === owner) pending.delete(key);
      pending.set(requestKey(entry), entry);
      continue;
    }
    if (kind === 'model_response') {
      if (!pending.delete(requestKey(entry))) {
        const legacy = [...pending].filter(([, previous]) => requestOwner(previous) === requestOwner(entry)).at(-1);
        if (legacy) pending.delete(legacy[0]);
      }
      continue;
    }
    if (kind === 'model_retry' || kind === 'model_error' || kind === 'agent_parse_error'
      || TASK_END.test(kind) || PLANNER_END.test(kind)
      || ['task_agent_terminal', 'agent_terminal', 'recon_terminal'].includes(kind)) {
      for (const [key, previous] of pending) if (ownerKey(previous.context) === owner) pending.delete(key);
    }
    if (kind === 'tool_call' || kind === 'tool_result' || kind === 'agent_code') {
      if (kind !== 'tool_result') pending.delete(requestKey(entry));
      if (kind !== 'agent_code' || !text(payload.error)) continue;
    }
    let title = '', message = '', secondary = '';
    let tone: ActivityMessage['tone'] = 'neutral';
    if (kind === 'audit_progress') {
      pending.delete(requestKey(entry));
      message = text(payload.message); tone = 'progress';
    } else if (kind === 'agent_code') {
      title = '动作执行提示'; message = `执行动作遇到问题：${shortText(payload.error, 280)}`; tone = 'warning';
    } else if (kind === 'agent_parse_error') {
      // A reply with no code block is a format problem, not a failed action: saying
      // "code execution failed" here sent readers looking for an interpreter error that
      // never happened. The durable event is the log entry; the hint is not model text.
      const step = Number(payload.step ?? 0);
      title = '输出格式错误';
      message = `${Number.isSafeInteger(step) && step > 0 ? `第 ${step} 步` : '本条'}回复没有可解析的代码块；`
        + '已要求模型按格式重新提交。';
      secondary = '这不是代码执行失败；执行日志中保留了对应的解析事件。';
      tone = 'warning';
    } else if (kind === 'planner_assessment' || kind === 'planner_round_committed') {
      if (kind === 'planner_round_committed' && formalSummaries.has(summaryScope(entry))) continue;
      title = '审计计划'; message = text(payload.basis_summary) || text(payload.summary);
      secondary = text(payload.next_action) ? `下一步：${text(payload.next_action)}` : '';
    } else if (kind === 'task_assessment') {
      title = '审计依据'; message = text(payload.summary);
      const rationale = text(payload.rationale) || text(payload.reasoning);
      secondary = rationale && rationale !== message ? rationale : '';
      if (text(payload.next_focus)) secondary += `${secondary ? '\n' : ''}下一步：${text(payload.next_focus)}`;
    } else if (kind === 'planner_task_started' || kind === 'task_work_started' || kind === 'unit_started') {
      title = '开始排查'; message = text(payload.objective) || text(payload.summary) || taskNames.get(context.task) || '';
    } else if (kind === 'planner_task_completed' || kind === 'task_work_completed') {
      if (formalSummaries.has(summaryScope(entry))) continue;
      title = '排查完成'; message = text(payload.summary);
    } else if (kind === 'recon_brief_prepared') {
      title = '项目侦察'; message = text(record(payload.brief).summary) || text(payload.summary);
    } else if (kind === 'recon_started') {
      message = text(payload.question); tone = 'progress';
    } else if (kind === 'poc_agent_phase') {
      message = `准备隔离靶场：${text(payload.target) || 'dvwa'} · ${Number(payload.count ?? 0)} 条结论待验证`; tone = 'progress';
    } else if (kind === 'poc_verification_started') {
      title = '开始自动验证'; message = text(payload.title) || '对一条审计结论执行 POC。';
      secondary = text(payload.target) ? `目标：${text(payload.target)}` : '';
      tone = 'progress';
    } else if (kind === 'poc_job_started') {
      message = `隔离 runner 开始执行 ${text(payload.language) || '脚本'}`; tone = 'progress';
    } else if (kind === 'poc_job_finished') {
      const exit = payload.exit_code;
      const seconds = Number(payload.duration_ms ?? 0) / 1000;
      message = Number.isFinite(Number(exit)) ? `runner 作业结束 · 退出码 ${exit} · ${seconds.toFixed(1)}s`
        : `runner 作业结束 · ${text(payload.status) || '状态未知'}`;
      tone = exit === 0 ? 'neutral' : 'warning';
    } else if (kind === 'poc_http_observed') {
      title = '靶场 HTTP 观测';
      message = `${text(payload.method) || 'GET'} ${text(payload.path) || '/'} · HTTP ${text(payload.status) || '—'}`;
      tone = 'progress';
    } else if (kind === 'poc_verification_recorded') {
      const status = text(payload.status);
      title = '自动验证结论';
      message = `${VERIFICATION_STATUS_LABELS[status] ?? (status || '已记录')}：${text(payload.summary)}`;
      const jobs = Array.isArray(payload.jobs) ? payload.jobs.length : 0;
      const artifacts = Array.isArray(payload.artifacts) ? payload.artifacts.length : 0;
      secondary = [jobs ? `${jobs} 次 runner 作业` : '', artifacts ? `${artifacts} 份产物` : ''].filter(Boolean).join(' · ');
      tone = status === 'rejected' ? 'error' : status === 'verified' ? 'neutral' : 'warning';
    } else if (kind === 'poc_verification_skipped') {
      title = '跳过自动验证';
      message = text(payload.reason) === 'target_not_dvwa'
        ? `目标类型 ${text(payload.target_profile) || 'unknown'} 不是 DVWA，自动验证不适用。`
        : text(payload.reason) || '本次运行不需要自动验证。';
      tone = 'warning';
    } else if (kind === 'poc_verification_unavailable') {
      title = '自动验证环境不可用';
      message = text(payload.error) || text(payload.reason) || '隔离靶场不可用，相关结论保留为未验证。';
      tone = 'warning';
    } else if (kind === 'poc_execution_finished') {
      // Normal completion is not worth a row; an early stop is, because the conclusion
      // that follows is then based on whatever the execution phase managed to collect.
      const reason = text(payload.reason);
      if (reason && reason !== 'completed') {
        title = 'POC 执行阶段结束';
        message = `执行阶段以 ${reason} 结束；随后进入结论提交。`;
        secondary = `${Number(payload.jobs ?? 0)} 次 runner 作业 · ${Number(payload.scripts ?? 0)} 份脚本`;
        tone = 'warning';
      }
    } else if (kind === 'poc_conclusion_failed') {
      title = '结论生成失败';
      message = text(payload.message) || text(payload.reason) || '结论阶段没有提交可校验的结果。';
      tone = 'error';
    } else if (kind === 'project_finding_created' || kind === 'project_finding_rediscovered' || kind === 'project_finding_corrected') {
      const corrected = kind === 'project_finding_corrected';
      title = corrected ? '项目台账已更正' : kind === 'project_finding_created' ? '写入项目台账' : '项目台账再次命中';
      message = text(payload.title) || '项目级漏洞记录已更新。';
      secondary = corrected ? `修订版本 ${Number(payload.revision ?? 1)}；旧验证状态置为源码已变更` : '';
      tone = corrected ? 'warning' : 'neutral';
    } else if (kind === 'project_findings_baseline_frozen') {
      message = `载入项目台账 ${Number(payload.count ?? 0)} 条既有结论（已验证 ${Number(payload.verified ?? 0)} 条），本轮不重复派发。`;
    } else if (kind === 'carried_findings_recorded') {
      message = `沿用项目既有结论 ${Number(payload.count ?? 0)} 条，不计入本次新发现。`;
    } else if (kind === 'project_finding_retracted' || kind === 'project_finding_duplicate'
      || kind === 'project_finding_reopened' || kind === 'project_finding_disposition_changed') {
      title = '项目台账结论调整';
      message = text(payload.reason) || `台账结论状态更新为 ${text(payload.disposition) || text(payload.action)}。`;
      tone = kind === 'project_finding_reopened' ? 'progress' : 'warning';
    } else if (kind === 'project_finding_update_rejected') {
      title = '台账更新被拒绝';
      message = text(payload.reason) || 'Planner 的项目结论更新没有生效。'; tone = 'warning';
    } else if (kind === 'planner_kept_rejected_finding') {
      title = '自动验证未通过的结论仍被保留';
      message = `Planner 没有撤回 ${Number(payload.count ?? 0)} 条自动验证未通过的结论；它们不支撑目标达成。`;
      tone = 'warning';
    } else if (kind === 'report_narrative_committed') {
      title = 'Planner 结论摘要'; message = text(payload.summary);
      secondary = Number(payload.limitations ?? 0) ? `声明限制 ${Number(payload.limitations)} 条` : '';
    } else if (kind === 'model_retry') {
      title = '正在重试'; message = text(payload.reason) || '模型请求需要重试，将按已记录的执行策略继续。'; tone = 'warning';
    } else if (kind === 'model_error' || kind === 'planner_round_failed' || kind === 'run_failed') {
      title = '执行异常'; message = text(payload.error) || text(payload.reason) || text(payload.summary) || '执行未完成，请查看错误详情。'; tone = 'error';
    } else if (kind === 'planner_task_blocked' || kind === 'task_work_blocked') {
      title = '排查受阻'; message = text(payload.summary) || text(payload.terminal_reason) || '此方向缺少完成审计所需的上下文。'; tone = 'warning';
    } else if (kind === 'planner_task_exhausted' || kind === 'task_work_exhausted') {
      title = '本轮排查已结算'; message = text(payload.summary) || text(payload.terminal_reason) || '本方向的执行额度已用尽，结果保留为未决。'; tone = 'warning';
    } else if (kind === 'run_paused') {
      message = '审计已暂停，已完成的排查与执行位置已保存。';
    } else if (kind === 'run_resumed') {
      message = '审计已继续，将从保存的任务前沿接着执行。'; tone = 'progress';
    } else if (kind === 'run_cancelled' || kind === 'run_interrupted') {
      message = kind === 'run_cancelled' ? '审计已取消，已有记录仍可查看。' : '审计已中断，已有记录仍可查看。'; tone = 'warning';
    }
    if (!message && !secondary) continue;
    items.push({ ...base(entry, taskNames), type: 'message', kind, title, text: message, secondary: secondary || undefined, tone, entry });
  }
  // Pair against the complete history before display grouping or pagination.
  for (const span of pairToolCalls(entries)) {
    const entry = span.call ?? span.result!;
    const owner = ownerKey(span.context);
    const result = span.result?.payload;
    const statusText = scalar(result?.status);
    const latest = latestRequests.get(owner);
    const latestRequest = !latest || (latest.invocation === (span.context.invocationId || span.context.invocation)
      && latest.request === span.context.requestIndex);
    let status: ActivityTool['status'];
    if (!result) status = running && latestRequest && (ended.get(owner) ?? 0) < entry.event.id ? 'running' : 'missing';
    else if (FAILURE_STATUSES.has(statusText) || result.error || result.error_type) status = 'error';
    else status = SUCCESS_STATUSES.has(statusText) ? 'success' : 'warning';
    const current = running && latestRequest && (ended.get(owner) ?? 0) < entry.event.id;
    items.push({ ...base(entry, taskNames), key: `tool:${span.key}`, type: 'tool', span, status,
      ...toolDescription(span), current, ownerKey: owner });
  }
  if (running) for (const entry of pending.values()) {
    if ((ended.get(ownerKey(entry.context)) ?? 0) >= entry.event.id) continue;
    items.push({ ...base(entry, taskNames), type: 'waiting', text: '正在等待模型响应', entry });
  }
  return items.sort((a, b) => a.order - b.order);
}

/** Only consecutive successful historical operations by the same actor may be folded. */
export function groupCompletedTools(items: ActivityItem[], protectedKeys: ReadonlySet<string> = new Set()): ActivityDisplayItem[] {
  const result: ActivityDisplayItem[] = [];
  let pending: ActivityTool[] = [];
  const flush = () => {
    if (pending.length > 1) {
      const first = pending[0];
      result.push({ type: 'tool-group', key: `tools:${first.key}`, order: first.order,
        actor: first.actor, taskTitle: first.taskTitle, tools: pending });
    } else if (pending.length) result.push(pending[0]);
    pending = [];
  };
  for (const item of items) {
    const eligible = item.type === 'tool' && item.status === 'success' && !item.current && !protectedKeys.has(item.key);
    if (eligible) {
      if (pending.length && pending[0].ownerKey !== item.ownerKey) flush();
      pending.push(item);
    } else { flush(); result.push(item); }
  }
  flush();
  return result;
}

export function activityPage<T extends ActivityDisplayItem>(items: T[], limit = 50, protectedKeys: ReadonlySet<string> = new Set()): T[] {
  const count = Math.max(0, Math.floor(limit));
  if (!count) return [];
  const start = Math.max(0, items.length - count);
  return items.filter((item, index) => index >= start || protectedKeys.has(item.key) || item.type === 'waiting'
    || item.type === 'tool' && (item.current || item.status === 'running' || item.status === 'error')
    || item.type === 'message' && (item.tone === 'error' || item.tone === 'warning'));
}

export function activitySubject(value: string, limit = 180): string { return shortText(value, limit); }
