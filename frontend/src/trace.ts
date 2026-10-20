import type { AuditEvent } from './types';

export interface TraceContext {
  run: string;
  role: string;
  session: string;
  plan: string;
  round: string;
  task: string;
  taskKey: string;
  worker: string;
  attempt: string;
  invocation: string;
}

export interface TraceEntry {
  event: AuditEvent;
  payload: Record<string, unknown>;
  context: TraceContext;
  groupKey: string;
  phase: string;
  phaseKey: string;
}

export interface ToolSpan {
  key: string;
  call?: TraceEntry;
  result?: TraceEntry;
  context: TraceContext;
  name: string;
  durationMs: number | null;
}

export type TraceRow = { type: 'event'; key: string; entry: TraceEntry }
  | { type: 'tool'; key: string; span: ToolSpan };

export interface TracePhase {
  key: string;
  name: string;
  rows: TraceRow[];
}

export interface TraceGroup {
  key: string;
  context: TraceContext;
  phases: TracePhase[];
  entries: TraceEntry[];
  finished: boolean;
  lastId: number;
}

export interface TraceFilters {
  role: string;
  worker: string;
  task: string;
  attempt: string;
  kind: string;
}

export const EMPTY_TRACE_FILTERS: TraceFilters = {
  role: 'all', worker: 'all', task: 'all', attempt: 'all', kind: 'all',
};

export function payloadOf(event: AuditEvent): Record<string, unknown> {
  return event.payload !== null && typeof event.payload === 'object' && !Array.isArray(event.payload)
    ? event.payload as Record<string, unknown> : {};
}

/** Event payloads are untrusted JSON; objects must never become summary text. */
export function scalar(value: unknown): string {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
    ? String(value) : '';
}

export function shortText(value: unknown, max = 100): string {
  const text = scalar(value).replace(/\s+/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function first(...values: unknown[]): string {
  return values.map(scalar).find(Boolean) ?? '';
}

function roleOf(event: AuditEvent, payload: Record<string, unknown>): string {
  const explicit = first(event.actor_role, payload.role);
  if (explicit) return explicit;
  // Queuing is a host lifecycle event, before a Planner session exists.
  if (event.kind === 'planner_run_queued') return 'host';
  if (event.kind.startsWith('recon_')) return 'recon';
  if (event.task_id || payload.task_id || payload.work_id || event.unit_id
    || event.kind.startsWith('planner_task_') || event.kind.startsWith('task_work_')) return 'worker';
  if (event.kind.startsWith('planner_')) return 'planner';
  return 'host';
}

export function traceGroupKey(context: TraceContext): string {
  return JSON.stringify([
    context.run, context.role, context.session, context.plan, context.plan ? '' : context.round,
    context.task, context.worker, context.attempt, context.invocation,
  ]);
}

/** Normalize durable top-level context, with compatibility for historical payloads. */
export function normalizeTrace(events: AuditEvent[]): TraceEntry[] {
  const plannerContext = new Map<string, { session: string; plan: string; round: string }>();
  const reconInvocations = new Map<string, string>();
  const phases = new Map<string, { name: string; epoch: number }>();
  return [...events].sort((a, b) => a.id - b.id).map((event) => {
    const payload = payloadOf(event);
    const role = roleOf(event, payload);
    const previous = plannerContext.get(event.run_id);
    let session = first(event.session_id, payload.session_id);
    let plan = first(event.plan_id, payload.plan_id);
    let round = first(event.planner_round, payload.planner_round, ['planner', 'recon'].includes(role) ? payload.round : undefined);
    if (role === 'planner') {
      session ||= previous?.session ?? '';
      // A new legacy round without a plan ID still needs its own invocation scope.
      if (event.kind === 'planner_round_started' && !plan) plan = `round:${round || event.id}`;
      if (!plan && (!session || session === previous?.session)) plan = previous?.plan ?? '';
      if (!round && plan === previous?.plan) round = previous?.round ?? '';
      plannerContext.set(event.run_id, { session, plan, round });
    }
    let invocation = '';
    if (role === 'recon') {
      session ||= previous?.session ?? '';
      plan ||= previous?.plan ?? '';
      if (!round && plan === previous?.plan) round = previous?.round ?? '';
      const owner = JSON.stringify([event.run_id, session, plan]);
      if (event.kind === 'recon_started' || event.kind === 'recon_skipped') {
        reconInvocations.set(owner, `recon:${event.id}`);
      }
      // Multiple reconnaissance calls within one plan reset their tool/step IDs.
      invocation = reconInvocations.get(owner) ?? '';
    }
    const context: TraceContext = {
      run: event.run_id, role, session, plan, round,
      task: first(event.task_id, payload.task_id, payload.work_id, event.unit_id),
      taskKey: scalar(payload.task_key),
      worker: scalar(payload.worker_id),
      // Planner/recon model_request.attempt counts requests, not worker retries.
      attempt: first(event.attempt, ['planner', 'recon'].includes(role) && event.kind === 'model_request' ? undefined : payload.attempt),
      invocation,
    };
    const groupKey = traceGroupKey(context);
    const previousPhase = phases.get(groupKey);
    const phase = first(payload.phase) || previousPhase?.name
      || (role === 'planner' ? 'planner_prepare' : role === 'recon' ? 'recon_explore' : role === 'worker' ? 'task_prepare' : 'lifecycle');
    const epoch = previousPhase ? previousPhase.epoch + Number(previousPhase.name !== phase) : 0;
    phases.set(groupKey, { name: phase, epoch });
    return { event, payload, context, groupKey, phase, phaseKey: JSON.stringify([groupKey, phase, epoch]) };
  });
}

function invocationMatches(call: TraceEntry, result: TraceEntry): boolean {
  if (call.groupKey !== result.groupKey || call.phaseKey !== result.phaseKey) return false;
  const callSpan = scalar(call.payload.span_id);
  const resultSpan = scalar(result.payload.span_id);
  if (callSpan && resultSpan) return callSpan === resultSpan;
  const callId = scalar(call.payload.call_id);
  const resultId = scalar(result.payload.call_id);
  // Never guess a pairing for old records with no durable correlation ID.
  return !!callId && callId === resultId && call.phase === result.phase;
}

function duration(call?: TraceEntry, result?: TraceEntry): number | null {
  const saved = result?.payload.duration_ms;
  if (typeof saved === 'number' && Number.isFinite(saved) && saved >= 0) return saved;
  if (!call || !result) return null;
  const elapsed = Date.parse(result.event.created_at) - Date.parse(call.event.created_at);
  return Number.isFinite(elapsed) && elapsed >= 0 ? elapsed : null;
}

/** Pair before filtering/paging so a result beyond a page boundary stays attached. */
export function pairToolCalls(entries: TraceEntry[]): ToolSpan[] {
  const spans: ToolSpan[] = [];
  const pending = new Map<string, ToolSpan[]>();
  for (const entry of entries) {
    if (entry.event.kind !== 'tool_call' && entry.event.kind !== 'tool_result') continue;
    const queue = pending.get(entry.groupKey) ?? [];
    if (entry.event.kind === 'tool_result') {
      const index = queue.findIndex((span) => span.call && invocationMatches(span.call, entry));
      if (index !== -1) {
        const span = queue[index];
        span.result = entry;
        span.durationMs = duration(span.call, entry);
        if (!span.name) span.name = scalar(entry.payload.tool);
        queue.splice(index, 1);
        continue;
      }
    }
    const correlation = first(entry.payload.span_id, entry.payload.call_id) || 'uncorrelated';
    const span: ToolSpan = {
      key: JSON.stringify([entry.groupKey, correlation, entry.event.id]),
      context: entry.context,
      name: scalar(entry.payload.tool),
      durationMs: entry.event.kind === 'tool_result' ? duration(undefined, entry) : null,
      ...(entry.event.kind === 'tool_call' ? { call: entry } : { result: entry }),
    };
    spans.push(span);
    if (span.call) {
      queue.push(span);
      pending.set(entry.groupKey, queue);
    }
  }
  return spans;
}

export function filterTrace(entries: TraceEntry[], filters: TraceFilters): TraceEntry[] {
  return entries.filter(({ event, context }) =>
    (filters.role === 'all' || context.role === filters.role)
    && (filters.worker === 'all' || context.worker === filters.worker)
    && (filters.task === 'all' || context.task === filters.task)
    && (filters.attempt === 'all' || context.attempt === filters.attempt)
    && (filters.kind === 'all' || event.kind === filters.kind));
}

export function latestTracePage(entries: TraceEntry[], limit = 50): TraceEntry[] {
  const count = Math.max(0, Math.floor(limit));
  return count ? entries.slice(-count) : [];
}

function groupFinished(entries: TraceEntry[]): boolean {
  return entries.some(({ event }) => /^(planner_round_committed|planner_round_failed|planner_agent_terminal|task_agent_terminal|agent_terminal|recon_terminal|recon_skipped|unit_completed|unit_incomplete|run_finished|run_failed|run_cancelled|run_interrupted)$/.test(event.kind)
    || /^(planner_task|task_work)_(completed|exhausted|blocked|cancelled|skipped|requeued|settled)$/.test(event.kind));
}

export function traceRunState(entries: TraceEntry[], status?: string): 'running' | 'paused' | 'terminal' {
  if (status === 'paused') return 'paused';
  if (status) return ['succeeded', 'completed', 'unreachable', 'inconclusive', 'failed', 'cancelled', 'interrupted'].includes(status) ? 'terminal' : 'running';
  let state: 'running' | 'paused' | 'terminal' = 'running';
  for (const { event } of entries) {
    if (event.kind === 'run_paused') state = 'paused';
    else if (event.kind === 'run_resumed') state = 'running';
    else if (/^(run_(finished|completed|failed|cancelled|interrupted)|goal_unreachable|goal_inconclusive)$/.test(event.kind)) state = 'terminal';
  }
  return state;
}

export function groupTrace(visible: TraceEntry[], allEntries: TraceEntry[] = visible): TraceGroup[] {
  const spans = pairToolCalls(allEntries);
  const spanByEvent = new Map<AuditEvent, ToolSpan>();
  for (const span of spans) {
    if (span.call) spanByEvent.set(span.call.event, span);
    if (span.result) spanByEvent.set(span.result.event, span);
  }
  const allByGroup = new Map<string, TraceEntry[]>();
  for (const entry of allEntries) {
    const groupEntries = allByGroup.get(entry.groupKey) ?? [];
    groupEntries.push(entry);
    allByGroup.set(entry.groupKey, groupEntries);
  }
  const groups = new Map<string, TraceGroup>();
  const addedSpans = new Set<string>();
  for (const entry of visible) {
    const fullEntries = allByGroup.get(entry.groupKey) ?? [entry];
    let group = groups.get(entry.groupKey);
    if (!group) {
      group = {
        key: entry.groupKey, context: entry.context, entries: fullEntries, phases: [],
        finished: groupFinished(fullEntries), lastId: fullEntries[fullEntries.length - 1].event.id,
      };
      groups.set(entry.groupKey, group);
    }
    const span = spanByEvent.get(entry.event);
    if (span && addedSpans.has(span.key)) continue;
    if (span) addedSpans.add(span.key);
    const phaseEntry = span?.call ?? entry;
    let phase = group.phases.find((item) => item.key === phaseEntry.phaseKey);
    if (!phase) {
      phase = { key: phaseEntry.phaseKey, name: phaseEntry.phase, rows: [] };
      group.phases.push(phase);
    }
    phase.rows.push(span ? { type: 'tool', key: span.key, span }
      : { type: 'event', key: `${entry.event.run_id}:${entry.event.id}`, entry });
  }
  return [...groups.values()];
}

/** Parallel workers can each have a current stage; earlier attempts stay collapsed. */
export function currentTraceGroups(groups: TraceGroup[], running: boolean): Set<string> {
  if (!running) return new Set();
  const latest = new Map<string, TraceGroup>();
  for (const group of groups) {
    // Preserve explicit roles on older/projected records without treating their
    // sessionless queue placeholder as a permanently active Planner execution.
    if (group.context.role === 'host'
      || group.entries.every(({ event }) => event.kind === 'planner_run_queued')) continue;
    const owner = JSON.stringify([group.context.run, group.context.role, group.context.session, group.context.task || group.context.worker]);
    const known = latest.get(owner);
    if (!known || known.lastId < group.lastId) latest.set(owner, group);
  }
  const active = [...latest.values()].filter((group) => running && !group.finished);
  if (active.length) return new Set(active.map((group) => group.key));
  const last = [...latest.values()].sort((a, b) => b.lastId - a.lastId)[0];
  return new Set(last ? [last.key] : []);
}

export function eventSummary(entry: TraceEntry): string {
  const { payload, event, context } = entry;
  if (event.kind === 'model_request') return '正在调用模型';
  if (event.kind === 'model_response') return '模型响应已记录';
  if (event.kind === 'agent_phase') return '进入新阶段';
  if (event.kind === 'recon_phase') return '侦察阶段更新';
  if (event.kind === 'agent_code') {
    const details = [`第 ${shortText(payload.step, 12) || '—'} 步代码动作`];
    if (typeof payload.code_bytes === 'number') details.push(`${payload.code_bytes} 字节`);
    if (payload.truncated === true) details.push('服务端已截断');
    if (payload.error) details.push('执行报错');
    else if (payload.is_final === true) details.push('本阶段已提交');
    else if (payload.logs) details.push('已保存 print 输出');
    return details.join(' · ');
  }
  if (event.kind === 'planner_coverage_prepared') {
    const coverage = payload.coverage;
    if (coverage && typeof coverage === 'object' && !Array.isArray(coverage)) {
      const data = coverage as Record<string, unknown>;
      return `已读 ${shortText(data.files_read, 16) || '—'} / ${shortText(data.files_total, 16) || '—'} 个文件 · 导航统计`;
    }
  }
  if (event.kind === 'planner_situational_prepared') return '已保存本轮任务前沿、已结算任务与既有结论概况';
  if (event.kind === 'planner_investigation_reused') return `复用已固定调查 · ${shortText(payload.topic, 72) || '已有主题'} · 未重跑`;
  if (event.kind === 'planner_investigation_pinned') return `调查已固定 · ${shortText(payload.topic, 80) || '已保存可复用结果'}`;
  if (event.kind === 'planner_investigation_superseded') return `固定调查已被更新 · ${shortText(payload.topic, 80) || '保留既有记录'}`;
  if (event.kind === 'recon_started') return shortText(payload.question) || '开始只读侦察';
  if (event.kind === 'recon_brief_prepared') return '侦察简报已保存 · 导航线索，需源码证据核验';
  const summary = first(payload.summary, payload.basis_summary, payload.reason,
    payload.terminal_reason, payload.next_action, payload.title, payload.objective,
    payload.status, payload.outcome, payload.state, payload.error);
  if (summary) return shortText(summary);
  if (event.kind.startsWith('planner_round_')) return context.round ? `第 ${context.round} 回合` : 'Planner 计划更新';
  if (typeof payload.new_lines === 'number') return `新增 ${payload.new_lines} 行源码证据`;
  return Object.keys(payload).length ? `${Object.keys(payload).length} 项已保存数据` : '状态已记录';
}
