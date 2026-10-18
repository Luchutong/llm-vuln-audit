import { useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, ChevronLeft, ChevronUp, ChevronsUpDown } from 'lucide-react';
import type { AuditEvent, RunDetail } from '../types';

const LABELS: Record<string, string> = {
  run_started: '运行开始',
  run_finished: '运行结束',
  run_failed: '运行失败',
  run_cancelled: '运行取消',
  run_interrupted: '运行中断',
  unit_started: '单元开始',
  unit_completed: '单元完成',
  unit_incomplete: '单元未完成',
  finding_created: '候选发现',
  finding_rejected_by_validation: '证据不通过',
  verification_recorded: '人工结论',
  model_error: '模型错误',
  model_retry: '模型重试',
  settle_started: '预算收尾',
  settled: '收尾判定',
  run_completed: '队列结束',
  agent_phase: '阶段',
  tool_call: '工具调用',
  tool_result: '工具结果',
  model_request: '模型请求',
  model_response: '模型响应',
  exploration_stopped: '探索停止',
  category_completed: '类别完成',
  category_incomplete: '类别未完成',
  unit_checkpoint: '检查点',
  agent_terminal: '终止原因',
  task_coordinator_started: '协调开始',
  task_plan_created: '执行计划',
  task_planner_started: '协调开始',
  task_work_started: '工作项开始',
  task_work_requeued: '工作项重试',
  task_work_completed: '工作项完成',
  task_work_exhausted: '轮次耗尽',
  task_work_blocked: '工作项受阻',
  task_work_skipped: '工作项跳过',
  task_goal_met: '目标达成',
  goal_unreachable: '目标不可达',
  goal_inconclusive: '目标未决',
  task_agent_terminal: '工作项终止',
  task_assessment: '依据摘要',
  planner_run_queued: '已排队',
  planner_session_started: '会话开始',
  planner_round_started: '回合开始',
  planner_round_committed: '回合提交',
  planner_assessment: '调度依据',
  planner_overview_prepared: '结构概览',
  planner_exploration_stopped: '索引停止',
  planner_agent_terminal: '回合终止',
  planner_terminal_deferred: '终态暂缓',
  planner_context_prepared: '上下文准备',
  planner_dependency_handoff_prepared: '交接准备',
  planner_task_started: '任务开始',
  planner_task_requeued: '任务重试',
  planner_task_completed: '任务完成',
  planner_task_exhausted: '方向耗尽',
  planner_task_blocked: '任务受阻',
  planner_task_cancelled: '任务取消',
};

const PAYLOAD_LABELS: Record<string, string> = {
  file_path: '文件', symbol: '符号', start_line: '起始行', end_line: '结束行',
  priority: '优先级', conclusion: '结论', conclusions: '历史结论', summary: '摘要',
  rationale: '依据', reasoning: '依据', outcome: '结果', next_focus: '下一步',
  missing_context: '缺失上下文', candidates: '候选数', model_responses: '模型响应',
  tool_calls: '工具调用', seconds: '耗时', category: '类别', title: '标题',
  line: '行号', reason: '原因', error: '错误', note: '说明', units: '单元数',
  usage: '用量', status: '状态', findings: '发现', exploration_incomplete: '探索未完成',
  missing: '缺失', problems: '证据问题', evidence: '证据', finding_id: '发现ID',
  verdict: '结论', execution_status: '执行状态', prompt_id: 'Prompt', model: '模型',
  budgets: '预算', phase: '阶段', tool: '工具', args: '参数', new_lines: '新增行',
  remaining_seconds: '剩余时间', category_errors: '未完成类别', preview: '预览',
  agent_policy: '策略', goal_id: '目标ID', work_id: '工作项ID', worker_id: 'worker',
  attempt: '轮次', call_id: '调用ID', span_id: '跨度ID', duration_ms: '耗时ms',
  finding_kind: '发现类型', max_attempts: '最大轮次', max_iterations: '每项轮次',
  max_total_attempts: '总尝试上限', max_workers: 'worker上限', goal_status: '目标状态',
  stop_on_achieved: '达成后停止', terminal_reason: '终止原因', mode: '模式',
  role: '角色', plan_id: '计划ID', task_id: '任务ID', task_key: '任务标识',
  task_count: '任务数', queue: '队列', basis_summary: '调度依据', next_action: '下一步',
  goal_state: '目标状态', project_map: '项目图', project_map_stats: '项目图统计',
  overview: '结构概览', overview_bytes: '概览字节', context_spec: '上下文规格',
  dependencies: '依赖', paths: '上下文文件', excerpts: '上下文片段', handoff_count: '交接数',
  notice: '说明', limitations: '限制', acceptance_criteria: '验收条件', objective: '目标',
};

type EventGroup = 'all' | 'tools' | 'decisions' | 'workers' | 'system';

const GROUP_LABELS: Record<EventGroup, string> = {
  all: '全部轨迹',
  tools: '工具调用与结果',
  decisions: '审计依据与结论',
  workers: 'worker 与工作项',
  system: '运行与系统事件',
};

/** Event kinds that are noisy / high-volume and should be visually compressed */
const NOISY_KINDS = new Set(['model_request', 'model_response', 'agent_phase']);

const PAGE_SIZE = 50;

function label(key: string) { return PAYLOAD_LABELS[key] ?? key; }

function payloadOf(event: AuditEvent): Record<string, unknown> {
  const payload = event.payload;
  return payload && typeof payload === 'object' && !Array.isArray(payload)
    ? payload as Record<string, unknown>
    : {};
}

function groupFor(kind: string): Exclude<EventGroup, 'all'> {
  if (kind === 'tool_call' || kind === 'tool_result') return 'tools';
  if (kind === 'task_assessment' || kind === 'planner_assessment' || kind === 'task_goal_met' || kind === 'goal_unreachable' || kind === 'goal_inconclusive' || kind === 'finding_created' || kind === 'finding_rejected_by_validation' || kind === 'settled' || kind === 'unit_completed' || kind === 'unit_incomplete') return 'decisions';
  if (kind.startsWith('task_work_') || kind.startsWith('planner_task_') || kind.startsWith('planner_round_') || kind.startsWith('planner_session_') || kind === 'planner_context_prepared' || kind === 'planner_dependency_handoff_prepared' || kind === 'planner_terminal_deferred' || kind === 'planner_overview_prepared' || kind === 'planner_exploration_stopped' || kind === 'task_agent_terminal' || kind === 'planner_agent_terminal' || kind === 'task_coordinator_started' || kind === 'task_planner_started' || kind === 'task_plan_created') return 'workers';
  return 'system';
}

function Value({ name, value }: { name: string; value: unknown }) {
  if (value === null || value === undefined || value === '') return null;
  if (name === 'evidence' && Array.isArray(value)) {
    return (
      <div>
        <span className="faint">{label(name)}：</span>
        {value.map((item, index) => {
          const ref = item as { path?: string; start_line?: number; end_line?: number };
          return (
            <span key={index} className="mono small">
              {index > 0 ? '；' : ''}{ref.path}:{ref.start_line}-{ref.end_line}
            </span>
          );
        })}
      </div>
    );
  }
  if (name === 'evidence' && value && typeof value === 'object') {
    const evidence = value as { summary?: unknown; references?: unknown[]; reviewed_ranges?: unknown[]; findings?: { title?: unknown; kind?: unknown; references?: unknown[] }[] };
    const reference = sourceReference(evidence);
    return (
      <div>
        <span className="faint">{label(name)}：</span>
        <span className="small">{String(evidence.summary ?? '')}</span>
        {reference && <span className="mono faint small"> · {reference}</span>}
        {Array.isArray(evidence.findings) && evidence.findings.length > 0 && (
          <div className="small faint" style={{ marginTop: 3 }}>
            {evidence.findings.map((item, index) => `${index + 1}. ${String(item.title ?? '发现')}（${String(item.kind ?? 'src')}）`).join('；')}
          </div>
        )}
      </div>
    );
  }
  if (typeof value === 'object') {
    const text = JSON.stringify(value);
    return (
      <div>
        <span className="faint">{label(name)}：</span>
        <span className="mono small">{text.length > 500 ? `${text.slice(0, 500)}…` : text}</span>
      </div>
    );
  }
  const text = String(value);
  return (
    <div>
      <span className="faint">{label(name)}：</span>
      <span className={name === 'error' ? 'mono small' : undefined}>
        {text.length > 700 ? `${text.slice(0, 700)}…` : text}
      </span>
    </div>
  );
}

function EventPayload({ event }: { event: AuditEvent }) {
  const entries = Object.entries(payloadOf(event));
  if (!entries.length) return <div className="faint small">此事件没有附加数据。</div>;
  return <div className="tl-detail">{entries.map(([key, value]) => <Value key={key} name={key} value={value} />)}</div>;
}

function sourceReference(value: unknown): string | null {
  const references = Array.isArray(value)
    ? value
    : value && typeof value === 'object' && Array.isArray((value as { references?: unknown[] }).references)
      ? (value as { references: unknown[] }).references
      : [];
  if (!references.length) return null;
  const first = references[0] as { path?: string; start_line?: number; end_line?: number };
  return first.path ? `${first.path}:${first.start_line}-${first.end_line}` : null;
}

interface ToolSpan { key: string; call?: AuditEvent; result?: AuditEvent; }

function toolSpans(events: AuditEvent[]): ToolSpan[] {
  const spans = new Map<string, ToolSpan>();
  for (const event of events) {
    if (event.kind !== 'tool_call' && event.kind !== 'tool_result') continue;
    const payload = payloadOf(event);
    const callId = String(payload.call_id ?? `legacy-${event.id}`);
    const key = [payload.task_id ?? payload.work_id ?? event.unit_id ?? 'planner', payload.attempt ?? '', callId].join(':');
    const current = spans.get(key) ?? { key };
    if (event.kind === 'tool_call') current.call = event;
    else current.result = event;
    spans.set(key, current);
  }
  return [...spans.values()].sort((left, right) => {
    const leftId = left.call?.id ?? left.result?.id ?? 0;
    const rightId = right.call?.id ?? right.result?.id ?? 0;
    return leftId - rightId;
  });
}

/* ---- Compact summary panel (top) ---- */
function ExecutionTrace({ events, unitName }: { events: AuditEvent[]; unitName: Record<string, string> }) {
  const toolEvents = events.filter((event) => groupFor(event.kind) === 'tools');
  const spans = toolSpans(events);
  const assessments = events.filter((event) => event.kind === 'task_assessment' || event.kind === 'planner_assessment');
  const recentTools = spans.slice(-15).reverse();
  const recentAssessments = assessments.slice(-10).reverse();

  return (
    <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--line-soft)', background: 'var(--surface-sunken)' }}>
      <div className="between" style={{ alignItems: 'flex-start', flexWrap: 'wrap', marginBottom: 8 }}>
        <div>
          <div className="panel-title">概览摘要</div>
          <div className="faint small">最近工具调用与依据摘要；完整事件列表在下方。</div>
        </div>
        <span className="faint small">工具 {toolEvents.length} · 摘要 {assessments.length}</span>
      </div>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 10 }}>
        <details style={{ border: '1px solid var(--line)', borderRadius: 8, background: 'var(--surface)', padding: '8px 10px' }}>
          <summary style={{ cursor: 'pointer', fontWeight: 500, fontSize: 13 }}>
            工具调用（最近 {recentTools.length}/{spans.length}）
          </summary>
          <div style={{ marginTop: 8, maxHeight: 300, overflowY: 'auto' }}>
            {recentTools.length === 0 ? (
              <div className="faint small">暂未记录工具调用。</div>
            ) : recentTools.map((span) => {
              const event = span.call ?? span.result;
              if (!event) return null;
              const callPayload = span.call ? payloadOf(span.call) : {};
              const resultPayload = span.result ? payloadOf(span.result) : {};
              const payload = { ...callPayload, ...resultPayload };
              const tool = String(payload.tool ?? '工具');
              const unit = event.unit_id ? unitName[event.unit_id] ?? event.unit_id.slice(0, 8) : String(payload.role === 'planner' ? 'Planner' : '协调器');
              return (
                <details key={span.key} style={{ padding: '5px 0', borderBottom: '1px solid var(--line-soft)' }}>
                  <summary className="small" style={{ cursor: 'pointer', overflowWrap: 'anywhere' }}>
                    <span className="mono">{tool}</span> · {span.result ? `${String(resultPayload.status ?? '完成')} · +${String(resultPayload.new_lines ?? 0)} 行` : '…'}
                    <span className="faint"> · {unit}</span>
                  </summary>
                  {span.call && <div className="tl-detail"><Value name="args" value={callPayload.args} /></div>}
                  {span.result && <EventPayload event={span.result} />}
                </details>
              );
            })}
          </div>
        </details>

        <details open={recentAssessments.length > 0} style={{ border: '1px solid var(--line)', borderRadius: 8, background: 'var(--surface)', padding: '8px 10px' }}>
          <summary style={{ cursor: 'pointer', fontWeight: 500, fontSize: 13 }}>
            依据摘要（{assessments.length}）
          </summary>
          <div style={{ marginTop: 8, maxHeight: 300, overflowY: 'auto' }}>
            {recentAssessments.length === 0 ? (
              <div className="faint small">工作项完成后会在这里出现依据摘要。</div>
            ) : recentAssessments.map((event) => {
              const payload = payloadOf(event);
              const rationale = String(payload.rationale ?? payload.reasoning ?? payload.basis_summary ?? '未提供。');
              const evidence = sourceReference(payload.evidence);
              const unit = event.unit_id ? unitName[event.unit_id] ?? event.unit_id.slice(0, 8) : 'Planner';
              return (
                <details key={event.id} style={{ padding: '5px 0', borderBottom: '1px solid var(--line-soft)' }}>
                  <summary className="small" style={{ cursor: 'pointer', overflowWrap: 'anywhere' }}>
                    {String(payload.outcome ?? '评估')} · {String(payload.summary ?? '')}
                    <span className="faint"> · {unit}</span>
                  </summary>
                  <div className="small" style={{ margin: '6px 0 4px', overflowWrap: 'anywhere' }}>{rationale}</div>
                  {evidence && <div className="mono faint small">证据：{evidence}</div>}
                  <EventPayload event={event} />
                </details>
              );
            })}
          </div>
        </details>
      </div>
    </div>
  );
}

/* ---- Group events by planner round ---- */
interface RoundGroup {
  key: string;
  label: string;
  events: AuditEvent[];
}

function groupByRound(events: AuditEvent[]): RoundGroup[] {
  const groups = new Map<string, AuditEvent[]>();
  for (const event of events) {
    const round = event.planner_round;
    const key = round != null ? `round-${round}` : 'bootstrap';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(event);
  }
  const result: RoundGroup[] = [];
  for (const [key, evts] of groups) {
    const round = evts[0]?.planner_round;
    const label = round != null ? `Planner 回合 ${round}` : '启动阶段';
    result.push({ key, label, events: evts });
  }
  // Sort: bootstrap first, then rounds ascending
  result.sort((a, b) => {
    if (a.key === 'bootstrap') return -1;
    if (b.key === 'bootstrap') return 1;
    return Number(a.key.replace('round-', '')) - Number(b.key.replace('round-', ''));
  });
  return result;
}

export function Timeline({ events, detail }: { events: AuditEvent[]; detail: RunDetail | null }) {
  const [open, setOpen] = useState<Record<number, boolean>>({});
  const [group, setGroup] = useState<EventGroup>('all');
  const [filter, setFilter] = useState<string>('all');
  const [unitFilter, setUnitFilter] = useState<string>('all');
  const [workerFilter, setWorkerFilter] = useState<string>('all');
  const [attemptFilter, setAttemptFilter] = useState<string>('all');
  const [page, setPage] = useState(0);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());

  const units = detail?.units ?? [];
  const tasks = detail?.tasks ?? [];
  const unitName = useMemo(() => {
    const map: Record<string, string> = {};
    for (const unit of units) map[unit.id] = `${unit.file_path}:${unit.start_line}-${unit.end_line}`;
    for (const task of tasks) map[task.id] = `${task.task_key} · ${task.title}`;
    return map;
  }, [units, tasks]);

  const groupEvents = useMemo(
    () => group === 'all' ? events : events.filter((event) => groupFor(event.kind) === group),
    [events, group],
  );
  const kinds = useMemo(
    () => ['all', ...Array.from(new Set(groupEvents.map((event) => event.kind)))],
    [groupEvents],
  );
  const workers = useMemo(
    () => Array.from(new Set(events.map((event) => String(payloadOf(event).worker_id ?? '')).filter(Boolean))).sort(),
    [events],
  );
  const attempts = useMemo(
    () => Array.from(new Set(events.map((event) => String(payloadOf(event).attempt ?? '')).filter(Boolean))).sort((a, b) => Number(a) - Number(b)),
    [events],
  );
  const effectiveKind = filter !== 'all' && !kinds.includes(filter) ? 'all' : filter;

  const shown = groupEvents.filter(
    (event) => {
      const payload = payloadOf(event);
      return (effectiveKind === 'all' || event.kind === effectiveKind) &&
        (unitFilter === 'all' || event.unit_id === unitFilter) &&
        (workerFilter === 'all' || String(payload.worker_id ?? '') === workerFilter) &&
        (attemptFilter === 'all' || String(payload.attempt ?? '') === attemptFilter);
    },
  );

  // Pagination
  const totalPages = Math.max(1, Math.ceil(shown.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages - 1);
  const pageEvents = shown.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);

  // Group the paginated events by round
  const roundGroups = useMemo(() => groupByRound(pageEvents), [pageEvents]);

  if (!events.length) return <div className="empty">还没有事件。运行开始后这里会实时出现。</div>;

  const toggleGroup = (key: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  const toggleRow = (id: number) => setOpen((prev) => ({ ...prev, [id]: !prev[id] }));

  return (
    <div>
      <ExecutionTrace events={events} unitName={unitName} />

      {/* Filter toolbar */}
      <div className="tl-toolbar">
        <select value={group} onChange={(e) => { setGroup(e.target.value as EventGroup); setFilter('all'); setPage(0); }}>
          {(Object.keys(GROUP_LABELS) as EventGroup[]).map((key) => (
            <option key={key} value={key}>{GROUP_LABELS[key]}</option>
          ))}
        </select>
        <select value={effectiveKind} onChange={(e) => { setFilter(e.target.value); setPage(0); }}>
          {kinds.map((kind) => (
            <option key={kind} value={kind}>
              {kind === 'all' ? '全部类型' : `${LABELS[kind] ?? kind}`}
            </option>
          ))}
        </select>
        <select value={unitFilter} onChange={(e) => { setUnitFilter(e.target.value); setPage(0); }}>
          <option value="all">全部任务/单元</option>
          {units.map((unit) => (
            <option key={unit.id} value={unit.id}>{unit.file_path}:{unit.start_line}-{unit.end_line}</option>
          ))}
          {tasks.map((task) => (
            <option key={task.id} value={task.id}>{task.task_key} · {task.title}</option>
          ))}
        </select>
        {workers.length > 0 && (
          <select value={workerFilter} onChange={(e) => { setWorkerFilter(e.target.value); setPage(0); }}>
            <option value="all">全部 worker</option>
            {workers.map((w) => <option key={w} value={w}>{w}</option>)}
          </select>
        )}
        {attempts.length > 0 && (
          <select value={attemptFilter} onChange={(e) => { setAttemptFilter(e.target.value); setPage(0); }}>
            <option value="all">全部轮次</option>
            {attempts.map((a) => <option key={a} value={a}>第 {a} 轮</option>)}
          </select>
        )}
        <span className="faint small" style={{ marginLeft: 'auto' }}>
          {shown.length} 条事件
        </span>
      </div>

      {/* Event list with round grouping */}
      {roundGroups.map((rg) => {
        const collapsed = collapsedGroups.has(rg.key);
        return (
          <div key={rg.key}>
            <div className="tl-group-header" onClick={() => toggleGroup(rg.key)}>
              {collapsed ? <ChevronRight size={13} /> : <ChevronDown size={13} />}
              <span>{rg.label}</span>
              <span className="count-badge">{rg.events.length}</span>
            </div>
            {!collapsed && rg.events.map((event) => {
              const payload = payloadOf(event);
              const entries = Object.entries(payload);
              const expanded = open[event.id];
              const noisy = NOISY_KINDS.has(event.kind);
              return (
                <div key={event.id}>
                  <div
                    className={`tl-row${noisy ? ' tl-noisy' : ''}`}
                    onClick={() => entries.length > 0 && toggleRow(event.id)}
                  >
                    <span className="tl-kind">{LABELS[event.kind] ?? event.kind}</span>
                    <div className="tl-body">
                      {event.unit_id && (
                        <span className="mono faint" style={{ fontSize: 11 }}>
                          {unitName[event.unit_id] ?? event.unit_id.slice(0, 8)}
                        </span>
                      )}
                      <Inline event={event} payload={payload} />
                    </div>
                    <span className="tl-id">
                      #{event.id}
                      {entries.length > 0 && (
                        <span className="tl-expand-hint" style={{ marginLeft: 6 }}>
                          {expanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                        </span>
                      )}
                    </span>
                  </div>
                  {expanded && <EventPayload event={event} />}
                </div>
              );
            })}
          </div>
        );
      })}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="tl-pagination">
          <span className="faint small">
            第 {safePage + 1} / {totalPages} 页 · {(safePage * PAGE_SIZE) + 1}–{Math.min((safePage + 1) * PAGE_SIZE, shown.length)} 条
          </span>
          <div className="row" style={{ gap: 6 }}>
            <button className="btn btn-sm" onClick={() => setPage(0)} disabled={safePage === 0}>
              <ChevronsUpDown size={13} /> 首页
            </button>
            <button className="btn btn-sm" onClick={() => setPage(Math.max(0, safePage - 1))} disabled={safePage === 0}>
              <ChevronLeft size={13} /> 上一页
            </button>
            <button className="btn btn-sm" onClick={() => setPage(Math.min(totalPages - 1, safePage + 1))} disabled={safePage >= totalPages - 1}>
              下一页 <ChevronRight size={13} />
            </button>
            <button className="btn btn-sm" onClick={() => setPage(totalPages - 1)} disabled={safePage >= totalPages - 1}>
              末页
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Inline({ event, payload }: { event: AuditEvent; payload: Record<string, unknown> }) {
  const kind = event.kind;
  if (kind === 'tool_call' || kind === 'tool_result') {
    return (
      <span className="small mono">
        {String(payload.tool ?? '')} · {kind === 'tool_call'
          ? JSON.stringify(payload.args ?? {})
          : `${String(payload.status ?? '')} · +${String(payload.new_lines ?? 0)} 行`}
      </span>
    );
  }
  if (kind === 'task_assessment' || kind === 'planner_assessment') {
    return (
      <span className="small">
        {String(payload.outcome ?? payload.goal_state ?? '调度')} · {String(payload.summary ?? payload.basis_summary ?? '')}
        {Boolean(payload.rationale || payload.reasoning || payload.basis_summary) && <span className="faint"> · 已记录依据</span>}
      </span>
    );
  }
  if (kind === 'agent_phase' || kind === 'agent_terminal' || kind === 'task_agent_terminal' || kind === 'exploration_stopped' || kind === 'planner_exploration_stopped') {
    return (
      <span className="small">
        {String(payload.phase ?? '')} {String(payload.reason ?? '')}
        {payload.remaining_seconds != null ? ` · 剩余 ${String(payload.remaining_seconds)}s` : ''}
      </span>
    );
  }
  if (kind === 'unit_started') return <span className="mono small">{String(payload.file_path ?? '')}</span>;
  if (kind === 'task_work_started' || kind === 'task_work_requeued' || kind === 'task_work_completed' || kind === 'task_work_exhausted' || kind === 'task_work_blocked' || kind === 'task_work_skipped') {
    return (
      <span className="small">
        {String(payload.file_path ?? '')} · 第 {String(payload.attempt ?? '')}/{String(payload.max_attempts ?? '')} 轮
        {payload.summary ? ` · ${String(payload.summary)}` : ''}
        {payload.terminal_reason ? ` · ${String(payload.terminal_reason)}` : ''}
      </span>
    );
  }
  if (kind.startsWith('planner_task_')) {
    return (
      <span className="small">
        {String(payload.task_key ?? '')} · {String(payload.title ?? payload.state ?? '')}
        {payload.attempt ? ` · 第 ${String(payload.attempt)}/${String(payload.max_attempts ?? '')} 次` : ''}
        {payload.summary ? ` · ${String(payload.summary)}` : ''}
      </span>
    );
  }
  if (kind.startsWith('planner_round_') || kind === 'planner_session_started' || kind === 'planner_run_queued') {
    return (
      <span className="small">
        {payload.round != null ? `第 ${String(payload.round)} 回合` : ''} {String(payload.basis_summary ?? payload.objective ?? payload.next_action ?? '')}
      </span>
    );
  }
  if (kind === 'task_goal_met' || kind === 'goal_unreachable' || kind === 'goal_inconclusive') {
    return (
      <span className="small">
        {String(payload.goal_status ?? '')} {String(payload.reason ?? '')}
        {payload.attempts != null ? ` · 累计 ${String(payload.attempts)} 次` : ''}
      </span>
    );
  }
  if (kind === 'unit_completed' || kind === 'unit_incomplete') {
    const conclusions = payload.conclusions as Record<string, string> | undefined;
    return (
      <span className="row" style={{ flexWrap: 'wrap' }}>
        {conclusions
          ? Object.entries(conclusions).map(([name, value]) => <span key={name} className={`chip chip-${value}`}>{name}={value}</span>)
          : <span className="small">{String(payload.reason ?? '')} {String(payload.error ?? '').slice(0, 120)}</span>}
        {payload.model_responses ? <span className="faint small">响应{String(payload.model_responses)} · 工具{String(payload.tool_calls)} · {String(payload.seconds)}s</span> : null}
        {payload.exploration_incomplete ? <span className="chip chip-incomplete">探索未完成</span> : null}
      </span>
    );
  }
  if (kind === 'finding_created' || kind === 'finding_rejected_by_validation') {
    const first = (payload.evidence as { path?: string; start_line?: number; end_line?: number }[] | undefined)?.[0];
    const problems = payload.validation_errors as string[] | undefined;
    return (
      <span className="row" style={{ flexWrap: 'wrap' }}>
        <span className="chip">{String(payload.category)}</span>
        <span>{String(payload.title ?? '')}</span>
        {first && <span className="mono faint small">{first.path}:{first.start_line}-{first.end_line}</span>}
        {problems && problems.length > 0 && <span className="chip chip-invalid_evidence">{problems.length} 处证据问题</span>}
      </span>
    );
  }
  if (kind === 'settled') return <span className="small">{String(payload.category ?? payload.conclusion ?? '')}</span>;
  if (kind === 'run_started' || kind === 'run_finished') return <span className="small muted">{String(payload.status ?? `单元 ${payload.units ?? ''}`)}</span>;
  if (kind === 'model_request' || kind === 'model_response') {
    // Compact summary for noisy model events
    const usage = payload.usage as { requests?: number; input_tokens?: number; output_tokens?: number; tool_calls?: number } | undefined;
    if (usage) {
      return <span className="small faint">用量：入{usage.input_tokens ?? '?'} / 出{usage.output_tokens ?? '?'} tok · 工具调用 {usage.tool_calls ?? 0}</span>;
    }
    const phase = payload.phase as string | undefined;
    return <span className="small faint">{phase ?? ''} {kind === 'model_request' ? '发送请求' : '收到响应'}</span>;
  }
  const text = JSON.stringify(payload);
  return <span className="small muted">{text.length > 200 ? `${text.slice(0, 200)}…` : text}</span>;
}
