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
  verification_recorded: '人工验证',
  model_error: '模型错误',
  model_retry: '模型重试',
  settle_started: '预算收尾',
  settled: '收尾判定',
  run_completed: '队列结束',
  agent_phase: '审计阶段',
  tool_call: '补读源码',
  tool_result: '工具结果',
  model_request: '模型请求',
  model_response: '模型响应',
  exploration_stopped: '探索停止',
  category_completed: '类别完成',
  category_incomplete: '类别未完成',
  unit_checkpoint: '结果检查点',
  agent_terminal: '单元终止原因',
  task_coordinator_started: '目标协调开始',
  // Kept for any event records written while the target mode was introduced.
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
};

const PAYLOAD_LABELS: Record<string, string> = {
  file_path: '文件',
  symbol: '符号',
  start_line: '起始行',
  end_line: '结束行',
  priority: '排序优先级',
  conclusion: '结论',
  conclusions: '三类结论',
  summary: '摘要',
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
  evidence: '证据',
  finding_id: '发现 ID',
  verdict: '人工结论',
  execution_status: '执行状态',
  prompt_id: 'Prompt',
  model: '模型',
  budgets: '预算',
  phase: '阶段',
  tool: '工具',
  args: '参数',
  new_lines: '新增代码行',
  remaining_seconds: '剩余时间',
  category_errors: '未完成类别',
  preview: '已返回代码预览',
  agent_policy: '执行策略',
  goal_id: '目标 ID',
  work_id: '工作项 ID',
  worker_id: 'worker',
  attempt: '当前轮次',
  max_attempts: '最大轮次',
  max_iterations: '每项最大轮次',
  max_total_attempts: '任务总尝试上限',
  max_workers: 'worker 上限',
  goal_status: '目标状态',
  stop_on_achieved: '达成后停止',
  terminal_reason: '终止原因',
  mode: '运行模式',
};

function label(key: string) {
  return PAYLOAD_LABELS[key] ?? key;
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
  if (typeof value === 'object') {
    const text = JSON.stringify(value);
    return (
      <div>
        <span className="faint">{label(name)}：</span>
        <span className="mono small">{text.length > 400 ? `${text.slice(0, 400)}…` : text}</span>
      </div>
    );
  }
  const text = String(value);
  return (
    <div>
      <span className="faint">{label(name)}：</span>
      <span className={name === 'error' ? 'mono small' : undefined}>
        {text.length > 600 ? `${text.slice(0, 600)}…` : text}
      </span>
    </div>
  );
}

/**
 * The audit process, read back from the event log.
 *
 * Everything shown here is stored SQLite rows, not client state: the same list comes back
 * after a reload, which is what makes a run reviewable rather than a live-only console.
 * Tool-level detail arrives as its own event kinds and stays collapsed until asked for.
 */
export function Timeline({ events, detail }: { events: AuditEvent[]; detail: RunDetail | null }) {
  const [open, setOpen] = useState<Record<number, boolean>>({});
  const [filter, setFilter] = useState<string>('all');
  const [unitFilter, setUnitFilter] = useState<string>('all');

  const units = detail?.units ?? [];
  const unitName = useMemo(() => {
    const map: Record<string, string> = {};
    for (const unit of units) {
      map[unit.id] = `${unit.file_path}:${unit.start_line}-${unit.end_line}`;
    }
    return map;
  }, [units]);

  const kinds = useMemo(
    () => ['all', ...Array.from(new Set(events.map((event) => event.kind)))],
    [events],
  );

  const shown = events.filter(
    (event) =>
      (filter === 'all' || event.kind === filter) &&
      (unitFilter === 'all' || event.unit_id === unitFilter),
  );

  if (!events.length) return <div className="empty">还没有事件。运行开始后这里会实时出现。</div>;

  return (
    <div>
      <div className="row" style={{ padding: '10px 14px', borderBottom: '1px solid var(--line-soft)', flexWrap: 'wrap' }}>
        <select value={filter} onChange={(event) => setFilter(event.target.value)} style={{ width: 190 }}>
          {kinds.map((kind) => (
            <option key={kind} value={kind}>
              {kind === 'all' ? '全部事件类型' : `${LABELS[kind] ?? kind}（${kind}）`}
            </option>
          ))}
        </select>
        <select value={unitFilter} onChange={(event) => setUnitFilter(event.target.value)} style={{ width: 300 }}>
          <option value="all">全部单元</option>
          {units.map((unit) => (
            <option key={unit.id} value={unit.id}>
              {unit.file_path}:{unit.start_line}-{unit.end_line}
            </option>
          ))}
        </select>
        <span className="faint small">{shown.length} / {events.length} 条</span>
      </div>

      {shown.map((event) => {
        const payload = (event.payload ?? {}) as Record<string, unknown>;
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
                      {expanded ? '收起' : '详情'}
                    </button>
                  )}
                </span>
              </div>
              {expanded && (
                <div className="tl-detail">
                  {entries.map(([key, value]) => (
                    <Value key={key} name={key} value={value} />
                  ))}
                </div>
              )}
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
  if (kind === 'agent_phase' || kind === 'agent_terminal' || kind === 'task_agent_terminal' || kind === 'exploration_stopped') {
    return <span className="small">{String(payload.phase ?? '')} {String(payload.reason ?? '')}
      {payload.remaining_seconds != null ? ` · 剩余 ${String(payload.remaining_seconds)}s` : ''}</span>;
  }
  if (kind === 'unit_started') {
    return <span className="mono small">{String(payload.file_path ?? '')}</span>;
  }
  if (kind === 'task_work_started' || kind === 'task_work_requeued' || kind === 'task_work_completed' || kind === 'task_work_exhausted' || kind === 'task_work_blocked' || kind === 'task_work_skipped') {
    return <span className="small">
      {String(payload.file_path ?? '')} · 第 {String(payload.attempt ?? '')}/{String(payload.max_attempts ?? '')} 轮
      {payload.summary ? ` · ${String(payload.summary)}` : ''}
      {payload.terminal_reason ? ` · ${String(payload.terminal_reason)}` : ''}
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
          ? Object.entries(conclusions).map(([name, value]) => (
              <span key={name} className={`chip chip-${value}`}>
                {name}={value}
              </span>
            ))
          : <span className="small">{String(payload.reason ?? '')} {String(payload.error ?? '').slice(0, 160)}</span>}
        {payload.model_responses ? (
          <span className="faint small">响应 {String(payload.model_responses)} · 工具 {String(payload.tool_calls)} · {String(payload.seconds)}s</span>
        ) : null}
        {payload.exploration_incomplete ? <span className="chip chip-incomplete">探索未走完</span> : null}
      </span>
    );
  }
  if (kind === 'finding_created' || kind === 'finding_rejected_by_validation') {
    // The event carries the cited ranges rather than a location: show the first one, so
    // the line the auditor should open is on screen without expanding anything.
    const first = (payload.evidence as { path?: string; start_line?: number; end_line?: number }[] | undefined)?.[0];
    const problems = payload.validation_errors as string[] | undefined;
    return (
      <span className="row" style={{ flexWrap: 'wrap' }}>
        <span className="chip">{String(payload.category)}</span>
        <span>{String(payload.title ?? '')}</span>
        {first && (
          <span className="mono small faint">
            {first.path}:{first.start_line}-{first.end_line}
          </span>
        )}
        {problems && problems.length > 0 && (
          <span className="chip chip-invalid_evidence">{problems.length} 处证据问题</span>
        )}
      </span>
    );
  }
  if (kind === 'settled') {
    return <span className="small">{String(payload.category ?? payload.conclusion ?? '')} {String(payload.conclusion ?? '')}</span>;
  }
  if (kind === 'run_started' || kind === 'run_finished') {
    return <span className="small muted">{String(payload.status ?? `单元 ${payload.units ?? ''}`)}</span>;
  }
  const text = JSON.stringify(payload);
  return <span className="small muted">{text.length > 240 ? `${text.slice(0, 240)}…` : text}</span>;
}
