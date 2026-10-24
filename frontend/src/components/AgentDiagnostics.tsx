import { useMemo } from 'react';
import type { AuditEvent } from '../types';
import { diagnosticGroups, diagnosticIncidents, ERROR_LABELS, PHASE_LABELS, ROLE_LABELS, toolOutcome } from '../diagnostics';
import { eventSummary, scalar } from '../trace';
import { Disclosure } from './Disclosure';
import { LongContent } from './LongContent';

export function ToolOutcome({ payload }: { payload: Record<string, unknown> | undefined }) {
  const outcome = toolOutcome(payload);
  if (!outcome) return null;
  return <div className="tool-outcomes">
    <p className={outcome.failed ? 'diagnostic-error' : 'trace-notice'}>工具调用：{outcome.callText}{outcome.cached ? ' · 复用已保存结果' : ''}</p>
    {outcome.executionText && <p className={outcome.executionFailed ? 'diagnostic-error' : 'trace-notice'}>作业执行：{outcome.executionText}</p>}
    {outcome.httpStatus !== null && <p className="trace-notice">目标响应：HTTP {outcome.httpStatus}</p>}
    {outcome.errorCode && <p className="trace-notice">错误分类：{ERROR_LABELS[outcome.errorCode] || outcome.errorCode}</p>}
    {outcome.error && <LongContent value={outcome.error} label="错误原因" previewLines={3} />}
    {outcome.hint && <LongContent value={outcome.hint} label="修正建议" previewLines={3} />}
    {outcome.retryable && <p className="trace-notice">允许按预算显式重试；此返回没有自动重跑操作。</p>}
  </div>;
}

export function AgentDiagnostics({ events, onInspect }: { events: AuditEvent[]; onInspect?: () => void }) {
  const incidents = useMemo(() => diagnosticIncidents(events), [events]);
  const groups = useMemo(() => diagnosticGroups(incidents), [incidents]);
  if (!incidents.length) return null;
  const recovered = incidents.filter((incident) => incident.recovery).length;
  return <div className="agent-diagnostics" onClickCapture={onInspect}>
    <Disclosure title={`错误与恢复 · ${incidents.length} 次异常请求 · ${recovered} 次已恢复`}>
      <p className="trace-notice">按完整事件中的角色、执行轮次与模型请求去重。同一请求的格式、工具及解释器错误合并计一次；后续同轮次的无错动作或成功提交记为恢复。</p>
      <div className="diagnostic-counts">{groups.map((group) => <div key={group.key}>
        <strong>{ROLE_LABELS[group.role] || group.role} · {PHASE_LABELS[group.phase] || group.phase}</strong>
        <span>{group.errors} 次异常请求 · {group.recovered} 次已恢复 · {group.errors - group.recovered} 次未观察到恢复</span>
      </div>)}</div>
      {incidents.map((incident) => <Disclosure key={incident.key} title={`${ROLE_LABELS[incident.role] || incident.role} · ${PHASE_LABELS[incident.phase] || incident.phase}${incident.requestIndex ? ` · 请求 ${incident.requestIndex}` : ''} · ${incident.recovery ? '已恢复' : '未观察到恢复'}`}>
        {incident.entries.map((entry) => <div className="diagnostic-entry" key={entry.event.id}>
          <p>{eventSummary(entry)} <span className="trace-meta">事件 #{entry.event.id}</span></p>
          {scalar(entry.payload.error) && <LongContent value={entry.payload.error} label="错误原因" previewLines={3} />}
          {scalar(entry.payload.hint) && <LongContent value={entry.payload.hint} label="修正建议" previewLines={3} />}
          <LongContent value={entry.payload} label="已保存的诊断字段" previewLines={2} />
        </div>)}
        <p className="trace-notice">{incident.recovery ? `恢复依据：事件 #${incident.recovery.event.id} · ${eventSummary(incident.recovery)}` : '此执行轮次尚无可确认的后续成功动作。'}</p>
      </Disclosure>)}
    </Disclosure>
  </div>;
}
