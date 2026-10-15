import { useMemo, useState } from 'react';
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
  finding_rejected_by_validation: '证据校验不通过',
  verification_recorded: '人工结论记录',
  model_error: '模型错误',
  model_retry: '模型重试',
  settle_started: '预算收尾',
  settled: '收尾判定',
  run_completed: '队列结束',
  agent_phase: '审计阶段',
  tool_call: '工具调用',
  tool_result: '工具结果',
  model_request: '模型请求',
  model_response: '模型响应',
  exploration_stopped: '探索停止',
  category_completed: '类别完成',
  category_incomplete: '类别未完成',
  unit_checkpoint: '结果检查点',
  agent_terminal: '单元终止原因',
  task_coordinator_started: '目标协调开始',
  task_plan_created: '目标执行计划',
  // Kept for records produced while target mode was introduced.
  task_planner_started: '目标协调开始',
  task_work_started: '目标工作项开始',
  task_work_requeued: '目标工作项重试',
  task_work_completed: '目标工作项完成',
  task_work_exhausted: '目标工作项轮次耗尽',
  task_work_blocked: '目标工作项受阻',
  task_work_skipped: '目标工作项跳过',
  task_goal_met: '目标达成',
  goal_unreachable: '目标不可达',
  goal_inconclusive: '目标未决',
  task_agent_terminal: '目标工作项终止原因',
  task_assessment: '审计依据摘要',
  planner_run_queued: 'Planner 审计已排队',
  planner_session_started: 'Planner 会话开始',
  planner_round_started: 'Planner 回合开始',
  planner_round_committed: 'Planner 回合已提交',
  planner_assessment: 'Planner 调度依据摘要',
  planner_overview_prepared: 'Planner 项目结构概览已准备',
  planner_exploration_stopped: 'Planner 索引探索停止',
  planner_agent_terminal: 'Planner 回合终止原因',
  planner_terminal_deferred: 'Planner 终态建议暂缓',
  planner_context_prepared: '多文件上下文已准备',
  planner_dependency_handoff_prepared: '依赖任务交接已准备',
  planner_task_started: '动态任务开始',
  planner_task_requeued: '动态任务重试',
  planner_task_completed: '动态任务完成',
  planner_task_exhausted: '动态任务方向耗尽',
  planner_task_blocked: '动态任务受阻',
  planner_task_cancelled: '动态任务取消',
};

const PAYLOAD_LABELS: Record<string, string> = {
  file_path: '文件',
  symbol: '符号',
  start_line: '起始行',
  end_line: '结束行',
  priority: '排序优先级',
  conclusion: '结论',
  conclusions: '历史分类结论',
  summary: '摘要',
  rationale: '模型生成的审计依据摘要',
  reasoning: '模型生成的审计依据摘要',
  outcome: '工作项结论',
  next_focus: '下一步关注点',
  missing_context: '缺失上下文',
  candidates: '候选数',
  model_responses: '模型响应',
  tool_calls: '工具调用',
  seconds: '耗时(秒)',
  category: '类别',
  title: '标题',
  line: '行号',
  reason: '原因',
  error: '错误',
  note: '说明',
  units: '单元总数',
  usage: '用量',
  status: '状态',
  findings: '发现',
  exploration_incomplete: '探索阶段未走完',
  missing: '缺失字段',
  problems: '证据问题',
  evidence: '源码证据',
  finding_id: '发现 ID',
  verdict: '人工结论',
  execution_status: '执行状态',
  prompt_id: '历史 Prompt',
  model: '模型',
  budgets: '预算',
  phase: '阶段',
  tool: '工具',
  args: '参数',
  new_lines: '新增代码行',
  remaining_seconds: '剩余时间',
  category_errors: '未完成类别',
  preview: '返回内容预览',
  agent_policy: '执行策略',
  goal_id: '目标 ID',
  work_id: '工作项 ID',
  worker_id: 'worker',
  attempt: '当前轮次',
  call_id: '工具调用 ID',
  span_id: '轨迹跨度 ID',
  duration_ms: '耗时(毫秒)',
  finding_kind: '发现类型',
  max_attempts: '最大轮次',
  max_iterations: '每项最大轮次',
  max_total_attempts: '任务总尝试上限',
  max_workers: 'worker 上限',
  goal_status: '目标状态',
  stop_on_achieved: '达成后停止',
  terminal_reason: '终止原因',
  mode: '运行模式',
  role: '角色',
  plan_id: '计划版本 ID',
  task_id: '动态任务 ID',
  task_key: '动态任务标识',
  task_count: '任务数',
  queue: '任务队列',
  basis_summary: '调度依据摘要',
  next_action: '下一步',
  goal_state: '目标建议状态',
  project_map: '项目图摘要',
  project_map_stats: '项目图统计',
  overview: 'Planner 结构概览',
  overview_bytes: '结构概览字节数',
  context_spec: '任务上下文规格',
  dependencies: '依赖任务',
  paths: '上下文文件',
  excerpts: '上下文片段',
  handoff_count: '交接摘要数',
  notice: '说明',
  limitations: '静态分析限制',
  acceptance_criteria: '任务验收条件',
  objective: '任务目标',
};

type EventGroup = 'all' | 'tools' | 'decisions' | 'workers' | 'system';

const GROUP_LABELS: Record<EventGroup, string> = {
  all: '全部轨迹',
  tools: '工具调用与结果',
  decisions: '审计依据与结论',
  workers: 'worker 与工作项',
  system: '运行与系统事件',
};

function label(key: string) {
  return PAYLOAD_LABELS[key] ?? key;
}

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
              {index > 0 ? '；' : ''}
              {ref.path}:{ref.start_line}-{ref.end_line}
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
            {evidence.findings.map((item, index) => `${index + 1}. ${String(item.title ?? '发现')}（${String(item.kind ?? 'source_observation')}）`).join('；')}
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
        <span className="mono small">{text.length > 700 ? `${text.slice(0, 700)}…` : text}</span>
      </div>
    );
  }
  const text = String(value);
  return (
    <div>
      <span className="faint">{label(name)}：</span>
      <span className={name === 'error' ? 'mono small' : undefined}>
        {text.length > 900 ? `${text.slice(0, 900)}…` : text}
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

interface ToolSpan {
  key: string;
  call?: AuditEvent;
  result?: AuditEvent;
}

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

/**
 * A compact, expandable view of the parts people most often need while reviewing a run.
 * Rationale is a deliberately short, model-produced, source-grounded summary. It is not
 * a rendering of hidden model reasoning; the durable tool calls and cited source ranges
 * below are what make the result reviewable.
 */
function ExecutionTrace({ events, unitName }: { events: AuditEvent[]; unitName: Record<string, string> }) {
  const toolEvents = events.filter((event) => groupFor(event.kind) === 'tools');
  const spans = toolSpans(events);
  const assessments = events.filter((event) => event.kind === 'task_assessment' || event.kind === 'planner_assessment');
  const recentTools = spans.slice(-20).reverse();
  const recentAssessments = assessments.slice(-16).reverse();

  return (
    <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--line-soft)', background: 'var(--surface-sunken)' }}>
      <div className="between" style={{ alignItems: 'flex-start', flexWrap: 'wrap', marginBottom: 8 }}>
        <div>
          <div className="panel-title">可展开执行轨迹</div>
          <div className="faint small">工具调用、返回摘要、worker 决策和证据范围均来自已持久化事件。</div>
        </div>
        <span className="faint small">工具 {toolEvents.length} · 依据摘要 {assessments.length}</span>
      </div>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 10 }}>
        <details style={{ border: '1px solid var(--line)', borderRadius: 7, background: 'var(--surface)', padding: '8px 10px' }}>
          <summary style={{ cursor: 'pointer', fontWeight: 500 }}>工具调用与结果（最近 {recentTools.length} / {spans.length}）</summary>
          <div style={{ marginTop: 8, maxHeight: 360, overflowY: 'auto' }}>
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
                <details key={span.key} style={{ padding: '6px 0', borderBottom: '1px solid var(--line-soft)' }}>
                  <summary className="small" style={{ cursor: 'pointer', overflowWrap: 'anywhere' }}>
                    <span className="mono">{tool}</span> · {span.result ? `${String(resultPayload.status ?? '完成')} · 新增 ${String(resultPayload.new_lines ?? 0)} 行` : '调用中或未记录结果'}
                    <span className="faint"> · {unit}{payload.worker_id ? ` · ${String(payload.worker_id)}` : ''}{payload.attempt ? ` · 第 ${String(payload.attempt)} 轮` : ''}</span>
                  </summary>
                  {span.call && <div className="tl-detail"><Value name="args" value={callPayload.args} /></div>}
                  {span.result && <EventPayload event={span.result} />}
                </details>
              );
            })}
          </div>
        </details>

        <details open={recentAssessments.length > 0} style={{ border: '1px solid var(--line)', borderRadius: 7, background: 'var(--surface)', padding: '8px 10px' }}>
          <summary style={{ cursor: 'pointer', fontWeight: 500 }}>模型生成的审计依据摘要（{assessments.length}）</summary>
          <div className="faint small" style={{ marginTop: 6 }}>
            只展示基于源码和工具观察的简短依据摘要，不展示模型内部思维链。
          </div>
          <div style={{ marginTop: 8, maxHeight: 360, overflowY: 'auto' }}>
            {recentAssessments.length === 0 ? (
              <div className="faint small">工作项完成后会在这里出现依据摘要。</div>
            ) : recentAssessments.map((event) => {
              const payload = payloadOf(event);
              const rationale = String(payload.rationale ?? payload.reasoning ?? payload.basis_summary ?? '未提供依据摘要。');
              const evidence = sourceReference(payload.evidence);
              const unit = event.unit_id ? unitName[event.unit_id] ?? event.unit_id.slice(0, 8) : String(payload.role === 'planner' ? 'Planner' : '协调器');
              return (
                <details key={event.id} style={{ padding: '6px 0', borderBottom: '1px solid var(--line-soft)' }}>
                  <summary className="small" style={{ cursor: 'pointer', overflowWrap: 'anywhere' }}>
                    {String(payload.outcome ?? '评估')} · {String(payload.summary ?? '')}
                    <span className="faint"> · {unit}</span>
                  </summary>
                  <div className="small" style={{ margin: '7px 0 4px', overflowWrap: 'anywhere' }}>{rationale}</div>
                  {evidence && <div className="mono faint small">源码证据：{evidence}</div>}
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

/**
 * The audit process, read back from the event log.
 *
 * Everything shown here is stored SQLite rows, not client state: the same list comes back
 * after a reload, which is what makes a run reviewable rather than a live-only console.
 */
export function Timeline({ events, detail }: { events: AuditEvent[]; detail: RunDetail | null }) {
  const [open, setOpen] = useState<Record<number, boolean>>({});
  const [group, setGroup] = useState<EventGroup>('all');
  const [filter, setFilter] = useState<string>('all');
  const [unitFilter, setUnitFilter] = useState<string>('all');
  const [workerFilter, setWorkerFilter] = useState<string>('all');
  const [attemptFilter, setAttemptFilter] = useState<string>('all');

  const units = detail?.units ?? [];
  const tasks = detail?.tasks ?? [];
  const unitName = useMemo(() => {
    const map: Record<string, string> = {};
    for (const unit of units) {
      map[unit.id] = `${unit.file_path}:${unit.start_line}-${unit.end_line}`;
    }
    for (const task of tasks) {
      map[task.id] = `${task.task_key} · ${task.title}`;
    }
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
    () => Array.from(new Set(events.map((event) => String(payloadOf(event).attempt ?? '')).filter(Boolean))).sort((left, right) => Number(left) - Number(right)),
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

  if (!events.length) return <div className="empty">还没有事件。运行开始后这里会实时出现。</div>;

  return (
    <div>
      <ExecutionTrace events={events} unitName={unitName} />
      <div className="row" style={{ padding: '10px 14px', borderBottom: '1px solid var(--line-soft)', flexWrap: 'wrap' }}>
        <select value={group} onChange={(event) => { setGroup(event.target.value as EventGroup); setFilter('all'); }} style={{ width: 180 }}>
          {(Object.keys(GROUP_LABELS) as EventGroup[]).map((key) => <option key={key} value={key}>{GROUP_LABELS[key]}</option>)}
        </select>
        <select value={effectiveKind} onChange={(event) => setFilter(event.target.value)} style={{ width: 190 }}>
          {kinds.map((kind) => (
            <option key={kind} value={kind}>
              {kind === 'all' ? '全部事件类型' : `${LABELS[kind] ?? kind}（${kind}）`}
            </option>
          ))}
        </select>
        <select value={unitFilter} onChange={(event) => setUnitFilter(event.target.value)} style={{ width: 300 }}>
          <option value="all">全部任务或源码单元</option>
          {units.map((unit) => (
            <option key={unit.id} value={unit.id}>
              {unit.file_path}:{unit.start_line}-{unit.end_line}
            </option>
          ))}
          {tasks.map((task) => (
            <option key={task.id} value={task.id}>{task.task_key} · {task.title}</option>
          ))}
        </select>
        {workers.length > 0 && (
          <select value={workerFilter} onChange={(event) => setWorkerFilter(event.target.value)} style={{ width: 220 }}>
            <option value="all">全部 worker</option>
            {workers.map((worker) => <option key={worker} value={worker}>{worker}</option>)}
          </select>
        )}
        {attempts.length > 0 && (
          <select value={attemptFilter} onChange={(event) => setAttemptFilter(event.target.value)} style={{ width: 140 }}>
            <option value="all">全部轮次</option>
            {attempts.map((attempt) => <option key={attempt} value={attempt}>第 {attempt} 轮</option>)}
          </select>
        )}
        <span className="faint small">显示 {shown.length} / {events.length} 条</span>
      </div>

      {shown.map((event) => {
        const payload = payloadOf(event);
        const entries = Object.entries(payload);
        const expanded = open[event.id];
        return (
          <div className="tl-row" key={event.id}>
            <span className="tl-kind">{LABELS[event.kind] ?? event.kind}</span>
            <div className="tl-body">
              <div className="between">
                <span>
                  {event.unit_id && (
                    <span className="mono small faint" style={{ marginRight: 8 }}>
                      {unitName[event.unit_id] ?? event.unit_id.slice(0, 8)}
                    </span>
                  )}
                  <Inline event={event} payload={payload} />
                </span>
                <span className="row">
                  <span className="faint small mono">#{event.id}</span>
                  {entries.length > 0 && (
                    <button className="btn" style={{ padding: '1px 7px', fontSize: 12 }} onClick={() => setOpen({ ...open, [event.id]: !expanded })}>
                      {expanded ? '收起' : '展开'}
                    </button>
                  )}
                </span>
              </div>
              {expanded && <EventPayload event={event} />}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Inline({ event, payload }: { event: AuditEvent; payload: Record<string, unknown> }) {
  const kind = event.kind;
  if (kind === 'tool_call' || kind === 'tool_result') {
    return <span className="small mono">{String(payload.tool ?? '')} · {kind === 'tool_call'
      ? JSON.stringify(payload.args ?? {}) : `${String(payload.status ?? '')} · 新增 ${String(payload.new_lines ?? 0)} 行`}</span>;
  }
  if (kind === 'task_assessment' || kind === 'planner_assessment') {
    return <span className="small">
      {String(payload.outcome ?? payload.goal_state ?? '调度')} · {String(payload.summary ?? payload.basis_summary ?? '')}
      {payload.rationale || payload.reasoning || payload.basis_summary ? <span className="faint"> · 已记录依据摘要</span> : null}
    </span>;
  }
  if (kind === 'agent_phase' || kind === 'agent_terminal' || kind === 'task_agent_terminal' || kind === 'exploration_stopped' || kind === 'planner_exploration_stopped') {
    return <span className="small">{String(payload.phase ?? '')} {String(payload.reason ?? '')}
      {payload.remaining_seconds != null ? ` · 剩余 ${String(payload.remaining_seconds)}s` : ''}</span>;
  }
  if (kind === 'unit_started') return <span className="mono small">{String(payload.file_path ?? '')}</span>;
  if (kind === 'task_work_started' || kind === 'task_work_requeued' || kind === 'task_work_completed' || kind === 'task_work_exhausted' || kind === 'task_work_blocked' || kind === 'task_work_skipped') {
    return <span className="small">
      {String(payload.file_path ?? '')} · 第 {String(payload.attempt ?? '')}/{String(payload.max_attempts ?? '')} 轮
      {payload.summary ? ` · ${String(payload.summary)}` : ''}
      {payload.terminal_reason ? ` · ${String(payload.terminal_reason)}` : ''}
    </span>;
  }
  if (kind.startsWith('planner_task_')) {
    return <span className="small">
      {String(payload.task_key ?? '')} · {String(payload.title ?? payload.state ?? '')}
      {payload.attempt ? ` · 第 ${String(payload.attempt)}/${String(payload.max_attempts ?? '')} 次` : ''}
      {payload.summary ? ` · ${String(payload.summary)}` : ''}
    </span>;
  }
  if (kind.startsWith('planner_round_') || kind === 'planner_session_started' || kind === 'planner_run_queued') {
    return <span className="small">
      {payload.round != null ? `第 ${String(payload.round)} 回合` : ''} {String(payload.basis_summary ?? payload.objective ?? payload.next_action ?? '')}
    </span>;
  }
  if (kind === 'task_goal_met' || kind === 'goal_unreachable' || kind === 'goal_inconclusive') {
    return <span className="small">
      {String(payload.goal_status ?? '')} {String(payload.reason ?? '')}
      {payload.attempts != null ? ` · 累计 ${String(payload.attempts)} 次` : ''}
    </span>;
  }
  if (kind === 'unit_completed' || kind === 'unit_incomplete') {
    const conclusions = payload.conclusions as Record<string, string> | undefined;
    return (
      <span className="row" style={{ flexWrap: 'wrap' }}>
        {conclusions
          ? Object.entries(conclusions).map(([name, value]) => <span key={name} className={`chip chip-${value}`}>{name}={value}</span>)
          : <span className="small">{String(payload.reason ?? '')} {String(payload.error ?? '').slice(0, 160)}</span>}
        {payload.model_responses ? <span className="faint small">响应 {String(payload.model_responses)} · 工具 {String(payload.tool_calls)} · {String(payload.seconds)}s</span> : null}
        {payload.exploration_incomplete ? <span className="chip chip-incomplete">探索未走完</span> : null}
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
        {first && <span className="mono small faint">{first.path}:{first.start_line}-{first.end_line}</span>}
        {problems && problems.length > 0 && <span className="chip chip-invalid_evidence">{problems.length} 处证据问题</span>}
      </span>
    );
  }
  if (kind === 'settled') return <span className="small">{String(payload.category ?? payload.conclusion ?? '')} {String(payload.conclusion ?? '')}</span>;
  if (kind === 'run_started' || kind === 'run_finished') return <span className="small muted">{String(payload.status ?? `单元 ${payload.units ?? ''}`)}</span>;
  const text = JSON.stringify(payload);
  return <span className="small muted">{text.length > 240 ? `${text.slice(0, 240)}…` : text}</span>;
}
