import type { ActivityItem, ActivityMessage } from './activity';
import type { AuditEvent } from './types';
import { diagnosticIncidents } from './diagnostics.ts';

export interface ProcessGroup {
  type: 'process-group'; key: string; order: number; actor: string;
  items: ActivityItem[]; files: number; operations: number; recoveries: number; warnings: number;
  running: number;
}
export type ProcessItem = ActivityItem | ProcessGroup;
const ROUTINE = new Set(['agent_code', 'poc_queue_heartbeat', 'poc_queue_progress', 'poc_http_observed', 'poc_job_started', 'poc_target_reset', 'poc_preconditions_checked']);
function contextKey(item: ActivityItem): string {
  const c = item.context;
  const entry = item.type === 'tool' ? item.span.call ?? item.span.result : item.entry;
  const payload = entry?.payload ?? {};
  const args = payload.args && typeof payload.args === 'object' ? payload.args as Record<string, unknown> : {};
  // Missing metadata stays distinct from a known identity/revision; never infer it.
  return JSON.stringify([c.run, c.role, c.task, c.taskKey, c.worker, c.attempt, c.invocationId || c.invocation, c.session, c.plan, c.round,
    payload.finding_id ?? args.finding_id, payload.revision ?? payload.finding_revision ?? args.revision ?? args.finding_revision,
    payload.project_finding_id ?? args.project_finding_id, payload.project_finding_revision ?? args.project_finding_revision,
    payload.identity ?? args.identity, payload.context_id ?? args.context_id, payload.target_key ?? args.target_key]);
}
/** A second projection only: full events and the original tool projection are retained. */
export function summarizeActivity(items: ActivityItem[], events: AuditEvent[], protectedKeys: ReadonlySet<string> = new Set(), pinnedGroups: Record<string, string[]> = {}): ProcessItem[] {
  const recovered = new Map<number, string>();
  for (const incident of diagnosticIncidents(events)) if (incident.recovery) {
    for (const entry of incident.entries) recovered.set(entry.event.id, incident.key);
  }
  const result: ProcessItem[] = [];
  const pinned = new Map(Object.entries(pinnedGroups).flatMap(([key, children]) => children.map((child) => [child, key] as const)));
  let pending: ActivityItem[] = [];
  let scope = '';
  const countedRecoveries = new Set<string>();
  const incidentKey = (item: ActivityItem) => recovered.get(item.type === 'tool' ? item.span.result?.event.id ?? -1 : item.entry.event.id);
  const flush = () => {
    if (!pending.length) return;
    const first = pending[0], files = new Set<string>(), recoveries = new Set<string>();
    let operations = 0, warnings = 0, running = 0;
    for (const item of pending) {
      const incident = incidentKey(item);
      if (incident && !countedRecoveries.has(incident)) recoveries.add(incident);
      if (!incident && (item.type === 'tool' && ['error', 'warning'].includes(item.status) || item.type === 'message' && ['error', 'warning'].includes(item.tone))) warnings++;
      if (item.type === 'tool') {
        operations++;
        if (item.status === 'running') running++;
        const path = item.span.call?.payload.args;
        if (item.status === 'success' && item.span.name === 'read_source' && path && typeof path === 'object' && 'path' in path && typeof path.path === 'string') files.add(path.path);
      }
    }
    recoveries.forEach((key) => countedRecoveries.add(key));
    result.push({ type: 'process-group', key: `process:${first.key}`, order: first.order, actor: first.actor, items: pending, files: files.size, operations, recoveries: recoveries.size, warnings, running });
    pending = [];
  };
  for (const item of items) {
    const eligible = pinned.has(item.key) || !protectedKeys.has(item.key) && (Boolean(incidentKey(item)) || item.type === 'tool' && ['success', 'running'].includes(item.status)
      || item.type === 'message' && (ROUTINE.has(item.kind) && !['warning', 'error'].includes(item.tone) || item.kind === 'poc_job_finished' && item.tone === 'neutral'));
    if (!eligible) { flush(); result.push(item); continue; }
    const key = pinned.get(item.key) ?? contextKey(item);
    const gap = pending.length ? Date.parse(item.createdAt) - Date.parse(pending.at(-1)!.createdAt) : 0;
    if (pending.length && (scope !== key || gap > 120000 && !pinned.has(item.key))) flush();
    scope = key; pending.push(item);
  }
  flush();
  return result;
}
export function processLabel(item: ProcessGroup): string {
  return [item.files ? `已读取 ${item.files} 个文件` : '', item.operations ? `${item.operations} 次操作` : '', item.running ? `${item.running} 项进行中` : '', item.recoveries ? `已自动恢复 ${item.recoveries} 次` : '', item.warnings ? `${item.warnings} 项异常待查看` : ''].filter(Boolean).join(' · ') || '过程记录';
}
/** Public summary text; raw payload, technical metadata and full explanations stay in details. */
export function conciseMessage(item: ActivityMessage): string {
  if (item.kind === 'poc_queue_item_started') return '正在验证当前漏洞。';
  if (item.kind === 'poc_gateway_error' || item.kind === 'poc_runtime_error') return item.text.replace(/^HTTP \d+ · /, '');
  return item.text;
}
export function processPage(items: ProcessItem[], limit: number, keep: ReadonlySet<string>): ProcessItem[] {
  const start = Math.max(0, items.length - limit);
  return items.filter((item, index) => index >= start || keep.has(item.key) || item.type === 'waiting'
    || item.type === 'tool' && (item.current || item.status === 'error')
    || item.type === 'message' && (item.tone === 'warning' || item.tone === 'error'));
}
