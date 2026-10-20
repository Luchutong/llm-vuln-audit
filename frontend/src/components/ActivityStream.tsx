import { useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Check, ChevronDown, CircleAlert, Clock3, FileCode2, LoaderCircle, Terminal, Wrench } from 'lucide-react';
import type { AuditEvent, RunDetail } from '../types';
import type { ActivityDisplayItem, ActivityMessage, ActivityTool, ActivityToolGroup } from '../activity';
import { activityPage, activitySubject, groupCompletedTools, projectActivity } from '../activity';
import { scalar } from '../trace';
import { LongContent } from './LongContent';
import { SourceViewer } from './SourceViewer';

type DetailTab = 'parameters' | 'preview' | 'source' | 'error';
interface SourceRange { path: string; start: number; end: number }

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
function sourceRanges(item: ActivityTool): SourceRange[] {
  const args = object(item.span.call?.payload.args);
  const ranges: SourceRange[] = [];
  const add = (value: unknown) => {
    const range = object(value);
    const path = scalar(range.path);
    const start = Number(range.start_line ?? range.start);
    const end = Number(range.end_line ?? range.end);
    if (!path || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 1 || end < start) return;
    // Source API reads are bounded. Larger saved ranges remain fully visible in debug.
    for (let line = start; line <= end && ranges.length < 100; line += 400) {
      const window = { path, start: line, end: Math.min(end, line + 399) };
      if (!ranges.some((known) => known.path === path && known.start === window.start && known.end === window.end)) ranges.push(window);
    }
  };
  if (item.span.name === 'read_source') add(args);
  const seen = item.span.result?.payload.seen;
  if (Array.isArray(seen)) for (const range of seen) add(range);
  return ranges;
}
function duration(item: ActivityTool): string {
  const milliseconds = item.span.durationMs;
  if (milliseconds === null) return '';
  return milliseconds < 1000 ? `${Math.round(milliseconds)} ms` : `${(milliseconds / 1000).toFixed(1)} s`;
}
const STATUS_TEXT = { running: '执行中', success: '成功', warning: '已返回，需留意', error: '失败', missing: '结果未记录' };

function ToolDetails({ item, snapshotId }: { item: ActivityTool; snapshotId: string }) {
  const [choice, setChoice] = useState<DetailTab>(() => item.status === 'error' ? 'error' : item.span.result ? 'preview' : 'parameters');
  const [sourceIndex, setSourceIndex] = useState(0);
  const id = useId();
  const call = item.span.call?.payload;
  const result = item.span.result?.payload;
  const error = result?.error ?? result?.error_type;
  const ranges = sourceRanges(item);
  const tabs: { id: DetailTab; label: string }[] = [];
  if (call) tabs.push({ id: 'parameters', label: '参数' });
  if (result) tabs.push({ id: 'preview', label: '返回预览' });
  if (ranges.length && snapshotId) tabs.push({ id: 'source', label: '源码' });
  if (item.status === 'error' || error !== undefined) tabs.push({ id: 'error', label: '异常' });
  const preferred = item.status === 'error' ? 'error' : result ? 'preview' : 'parameters';
  const selected = tabs.some((tab) => tab.id === choice) ? choice! : tabs.some((tab) => tab.id === preferred) ? preferred : tabs[0]?.id;
  const range = ranges[Math.min(sourceIndex, ranges.length - 1)];
  const context = item.context;
  return <div className="activity-tool-detail">
    <div className="activity-detail-tabs" role="tablist" aria-label="工具详情内容">
      {tabs.map((tab) => <button type="button" role="tab" id={`${id}-${tab.id}`} aria-controls={`${id}-panel`} aria-selected={selected === tab.id}
        className={selected === tab.id ? 'active' : ''} key={tab.id} onClick={() => setChoice(tab.id)}>{tab.label}</button>)}
    </div>
    <div className="activity-detail-content" id={`${id}-panel`} role="tabpanel" aria-labelledby={`${id}-${selected}`}>
      {selected === 'parameters' && <LongContent value={call?.args ?? {}} label="已保存的参数" />}
      {selected === 'preview' && <>
        <p className="activity-detail-note">服务端受限预览：最多保存 1200 字符；这里展示已保存片段。
          {typeof result?.chars === 'number' && ` 原始返回共 ${result.chars.toLocaleString()} 字符。`}</p>
        <LongContent value={result?.preview ?? '此结果未保存返回预览。'} label="返回预览" />
      </>}
      {selected === 'error' && <LongContent value={error ?? result?.status ?? '工具执行未成功，详情未记录。'} label="已保存的错误" />}
      {selected === 'source' && range && <>
        {ranges.length > 1 && <label className="field"><span className="field-label">源码范围</span><select aria-label="选择源码范围" value={sourceIndex} onChange={(event) => setSourceIndex(Number(event.target.value))}>
          {ranges.map((entry, index) => <option value={index} key={`${entry.path}:${entry.start}-${entry.end}`}>{entry.path}:{entry.start}–{entry.end}</option>)}
        </select></label>}
        <p className="activity-detail-note">{range.path}:{range.start}–{range.end} · 冻结快照中的原始源码</p>
        <SourceViewer key={`${range.path}:${range.start}-${range.end}`} snapshotId={snapshotId} path={range.path} start={range.start} end={range.end} height={300} />
      </>}
      {!item.span.call && <p className="activity-detail-note">此历史记录只保存了返回事件，没有可关联的调用参数。</p>}
      {!item.span.result && <p className="activity-detail-note">{item.status === 'running' ? '调用已保存，正在等待工具返回。' : '事件日志没有保存此调用的返回结果。'}</p>}
    </div>
    <details className="activity-debug"><summary>调试信息</summary>
      <LongContent label="持久化调用标识" value={{
        tool: item.span.name, run_id: context.run, role: context.role, session_id: context.session || undefined,
        plan_id: context.plan || undefined, task_id: context.task || undefined, worker_id: context.worker || undefined,
        attempt: context.attempt || undefined, agent_invocation_id: context.invocationId || undefined,
        request_index: context.requestIndex || undefined, span_id: call?.span_id ?? result?.span_id,
        call_id: call?.call_id ?? result?.call_id, call_event: item.span.call?.event.id,
        result_event: item.span.result?.event.id, duration_ms: item.span.durationMs,
        status: result?.status, seen: result?.seen,
      }} />
    </details>
  </div>;
}

function ToolRow({ item, snapshotId, expanded, onToggle }: {
  item: ActivityTool; snapshotId: string; expanded: boolean; onToggle: () => void;
}) {
  const id = useId();
  return <div className={`activity-tool activity-tool-${item.status}`} data-activity-key={item.key} data-tool={item.span.name} data-status={item.status}>
    <button type="button" className="activity-tool-toggle" aria-label={`工具详情：${item.label}${item.subject ? ` ${activitySubject(item.subject)}` : ''}`}
      aria-expanded={expanded} aria-controls={id} onClick={onToggle}>
      <span className="activity-tool-icon">{item.status === 'running' ? <LoaderCircle size={15} className="spin" /> : item.status === 'error' ? <CircleAlert size={15} /> : item.status === 'success' ? <Check size={15} /> : <Wrench size={15} />}</span>
      <span className="activity-tool-action"><span>{item.label}</span>{item.subject && <span className="activity-tool-subject">{activitySubject(item.subject)}</span>}</span>
      <span className="activity-tool-owner">{item.actor}{item.context.attempt && Number(item.context.attempt) > 1 ? ` · 第 ${item.context.attempt} 次尝试` : ''}</span>
      <span className="activity-tool-status">{STATUS_TEXT[item.status]}{duration(item) && ` · ${duration(item)}`}</span>
      <ChevronDown size={13} className={expanded ? 'rotated' : ''} />
    </button>
    {item.status === 'error' && !expanded && <p className="activity-tool-error">{activitySubject(scalar(item.span.result?.payload.error ?? item.span.result?.payload.error_type) || '工具执行失败，点击查看异常详情。', 240)}</p>}
    {expanded && <div id={id}><ToolDetails item={item} snapshotId={snapshotId} /></div>}
  </div>;
}

function Message({ item, onOpenLogs }: { item: ActivityMessage; onOpenLogs: () => void }) {
  return <article className={`activity-message activity-message-${item.tone}${item.kind === 'audit_progress' ? ' audit-progress' : ''}`}
    data-activity-key={item.key} data-event-kind={item.kind}>
    <div className="activity-message-byline"><span>{item.actor}</span>{item.title && <span>{item.title}</span>}
      {item.context.attempt && Number(item.context.attempt) > 1 && <span>第 {item.context.attempt} 次尝试</span>}</div>
    {item.text.length <= 1000 ? <p>{item.text}</p> : <LongContent value={item.text} previewLines={6} />}
    {item.secondary && <div className="activity-message-rationale">{item.secondary.length <= 1000 ? <p>{item.secondary}</p> : <LongContent value={item.secondary} previewLines={6} />}</div>}
    {item.kind === 'agent_code' && <button type="button" className="text-button activity-message-log" onClick={onOpenLogs}>查看执行日志</button>}
  </article>;
}

/** The chat is a view of durable public events; IDs and raw code stay in the log. */
export function ActivityStream({ events, detail, connected, reconnects = 0, onOpenLogs, onInspect }: {
  events: AuditEvent[]; detail: RunDetail; connected: boolean; reconnects?: number; onOpenLogs: () => void; onInspect?: () => void;
}) {
  const stream = useRef<HTMLDivElement>(null);
  const [limit, setLimit] = useState(50);
  const [choices, setChoices] = useState<Record<string, boolean>>({});
  const [protectedItems, setProtectedItems] = useState<Set<string>>(() => new Set());
  const [groupsOpen, setGroupsOpen] = useState<Record<string, boolean>>({});
  const restoreScroll = useRef<{ box: HTMLElement; height: number; top: number } | null>(null);
  const items = useMemo(() => projectActivity(events, detail), [events, detail]);
  const groups = useMemo(() => groupCompletedTools(items, protectedItems), [items, protectedItems]);
  const visible = useMemo(() => {
    const keep = new Set([...protectedItems, ...Object.keys(groupsOpen).filter((key) => groupsOpen[key])]);
    return activityPage(groups, limit, keep);
  }, [groups, limit, protectedItems, groupsOpen]);
  const activeTasks = detail.tasks?.filter((task) => task.state === 'running') ?? [];
  const live = detail.run.status === 'running' || detail.run.status === 'pending';
  useLayoutEffect(() => {
    const saved = restoreScroll.current;
    if (saved) { saved.box.scrollTop = saved.top + saved.box.scrollHeight - saved.height; restoreScroll.current = null; }
  }, [limit]);
  const toolExpanded = (item: ActivityTool) => choices[item.key] ?? false;
  const toggleTool = (item: ActivityTool, insideGroup: boolean) => {
    const next = !toolExpanded(item);
    if (next) onInspect?.();
    setChoices((previous) => ({ ...previous, [item.key]: next }));
    // A row manually opened while standalone must never disappear into an automatic group.
    if (!insideGroup) setProtectedItems((previous) => {
      const value = new Set(previous); value.add(item.key); return value;
    });
  };
  const preserveInteraction = (target: EventTarget | null) => {
    if (!(target instanceof Element) || !target.closest('button, a, summary, input, select, textarea, [tabindex]')) return;
    // Protect the existing parent group as a unit. Pulling a focused child out of
    // that group would itself unmount it and defeat the focus protection.
    const row = target.closest('.activity-tool-group[data-activity-key]') ?? target.closest('[data-activity-key]');
    const key = row?.getAttribute('data-activity-key');
    if (!key) return;
    onInspect?.();
    setProtectedItems((previous) => previous.has(key) ? previous : new Set([...previous, key]));
  };
  const loadEarlier = () => {
    onInspect?.();
    const box = stream.current?.closest<HTMLElement>('.chat-scroll');
    if (box) restoreScroll.current = { box, height: box.scrollHeight, top: box.scrollTop };
    setLimit((previous) => previous + 50);
  };
  const renderTool = (item: ActivityTool, insideGroup = false) => <ToolRow key={item.key} item={item} snapshotId={detail.run.snapshot_id}
    expanded={toolExpanded(item)} onToggle={() => toggleTool(item, insideGroup)} />;
  const renderGroup = (item: ActivityToolGroup) => <div className="activity-tool-group" key={item.key} data-activity-key={item.key}>
    <button type="button" className="activity-group-toggle" aria-expanded={groupsOpen[item.key] ?? false} onClick={() => {
      if (!groupsOpen[item.key]) onInspect?.();
      setGroupsOpen((previous) => ({ ...previous, [item.key]: !previous[item.key] }));
    }}>
      <Check size={14} /><span>已完成 {item.tools.length} 项操作</span><span className="activity-group-owner">{item.actor}</span><ChevronDown size={13} className={groupsOpen[item.key] ? 'rotated' : ''} />
    </button>
    {groupsOpen[item.key] && <div className="activity-group-rows">{item.tools.map((tool) => renderTool(tool, true))}</div>}
  </div>;
  const renderItem = (item: ActivityDisplayItem) => {
    if (item.type === 'tool-group') return renderGroup(item);
    if (item.type === 'tool') return renderTool(item);
    if (item.type === 'message') return <Message item={item} key={item.key} onOpenLogs={onOpenLogs} />;
    return <div className="activity-waiting" role="status" key={item.key} data-activity-key={item.key}><LoaderCircle size={14} className="spin" /><span>{item.actor} · {item.text}</span></div>;
  };
  return <div ref={stream} className="activity-stream" role="region" aria-label="实时审计过程">
    <div className="activity-stream-toolbar"><span className="activity-stream-connection">{live ? <><span className={`status-dot ${connected ? 'status-completed' : 'status-inconclusive'}`} />{connected ? '实时同步' : '正在恢复连接'}</> : detail.run.status === 'paused' ? <><Clock3 size={13} />已暂停，记录已保存</> : <><Check size={13} />执行记录已恢复</>}{reconnects > 0 && ` · 重连 ${reconnects} 次`}</span>
      <button type="button" className="text-button" onClick={onOpenLogs}><Terminal size={13} />完整执行日志</button></div>
    {activeTasks.length > 0 && <div className="activity-active-tasks"><FileCode2 size={13} /><span>正在排查：{activeTasks.map((task) => task.title).join('、')}</span></div>}
    {visible.length < groups.length && <div className="activity-history"><button type="button" className="text-button" onClick={loadEarlier}>加载更早的 50 项活动</button><span>当前显示 {visible.length} / {groups.length} 项</span></div>}
    <div className="activity-feed" onFocusCapture={(event) => preserveInteraction(event.target)} onClickCapture={(event) => preserveInteraction(event.target)}>{visible.length ? visible.map((item, index) => <div className="activity-slot" key={item.key}>
      {index > 0 && groups.indexOf(item) > groups.indexOf(visible[index - 1]) + 1 && <button type="button" className="activity-gap text-button" onClick={loadEarlier}>展开中间的历史活动</button>}
      {renderItem(item)}
    </div>) : <p className="activity-empty">{live ? '任务已排队，等待规划与执行事件。' : '此运行没有可展示的公开摘要或工具记录。完整持久化事件可在执行日志查看。'}</p>}</div>
  </div>;
}
