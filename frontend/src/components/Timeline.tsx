import { useMemo, useState } from 'react';
import { Bot, CircleAlert, CircleCheck, CircleDot, Clock3, Code2, FlaskConical, ScanSearch, Server, Wrench, Workflow } from 'lucide-react';
import type { AuditEvent, RunDetail } from '../types';
import {
  currentTraceGroups, EMPTY_TRACE_FILTERS, eventSummary, filterTrace, groupTrace,
  latestTracePage, normalizeTrace, pairToolCalls, scalar, shortText, traceRunState,
} from '../trace';
import type { ToolSpan, TraceContext, TraceEntry, TraceFilters, TraceGroup } from '../trace';
import { Disclosure } from './Disclosure';
import { LongContent } from './LongContent';
import { toolOutcome } from '../diagnostics';
import { AgentDiagnostics, ToolOutcome } from './AgentDiagnostics';

const LABELS: Record<string, string> = {
  run_started: '运行开始', run_finished: '运行结束', run_failed: '运行失败',
  run_cancelled: '运行取消', run_interrupted: '运行中断', run_completed: '队列结束',
  unit_started: '单元开始', unit_completed: '单元完成', unit_incomplete: '单元未完成',
  finding_created: '候选发现', finding_rejected_by_validation: '证据校验不通过',
  verification_recorded: '自动验证记录', model_error: '模型错误', model_retry: '模型重试',
  settle_started: '预算收尾', settled: '收尾判定', agent_phase: '阶段更新',
  tool_call: '工具调用', tool_result: '工具结果', model_request: '模型请求', model_response: '模型响应',
  audit_progress: '审计进展摘要',
  exploration_stopped: '探索停止', category_completed: '类别完成', category_incomplete: '类别未完成',
  unit_checkpoint: '结果检查点', agent_terminal: '单元终止原因',
  task_coordinator_started: '目标协调开始', task_plan_created: '目标执行计划',
  task_planner_started: '目标协调开始', task_work_started: '工作项开始', task_work_requeued: '工作项重试',
  task_work_completed: '工作项完成', task_work_exhausted: '工作项轮次耗尽',
  task_work_blocked: '工作项受阻', task_work_skipped: '工作项跳过',
  task_goal_met: '目标达成', goal_unreachable: '目标不可达', goal_inconclusive: '目标未决',
  task_agent_terminal: '工作项终止原因', task_assessment: '审计依据摘要',
  planner_run_queued: '审计已排队', planner_session_started: 'Planner 会话开始',
  planner_round_started: 'Planner 回合开始', planner_round_committed: 'Planner 回合已提交',
  planner_assessment: '调度依据摘要', planner_overview_prepared: '项目结构概览已准备',
  planner_exploration_stopped: '索引探索停止', planner_agent_terminal: 'Planner 回合终止原因',
  planner_terminal_deferred: '终态建议暂缓', planner_context_prepared: '多文件上下文已准备',
  planner_dependency_handoff_prepared: '依赖任务交接已准备',
  planner_task_started: '动态任务开始', planner_task_requeued: '动态任务重试',
  planner_task_completed: '动态任务完成', planner_task_exhausted: '动态任务方向耗尽',
  planner_task_blocked: '动态任务受阻', planner_task_cancelled: '动态任务取消',
  run_pause_requested: '暂停请求', run_paused: '运行已暂停', run_resumed: '运行已继续',
  agent_code: '模型代码动作', agent_parse_error: '动作解析错误', agent_execution_error: '动作执行错误', agent_error_summary: '纠错统计',
  planner_round_failed: '规划回合未产出可用决策',
  planner_coverage_prepared: '读取覆盖统计已准备', planner_situational_prepared: '本轮任务态势已准备',
  planner_decision_sanitized: '规划决策字段已清洗', planner_tools_withdrawn: '确认预算耗尽，工具已收回',
  planner_investigation_pinned: '调查结果已固定', planner_investigation_reused: '复用已固定调查',
  planner_investigation_superseded: '固定调查已被更新',
  recon_started: '侦察子 Agent 开始', recon_phase: '侦察阶段', recon_brief_prepared: '侦察简报已准备',
  recon_terminal: '侦察结束', recon_skipped: '侦察已跳过',
  context_summarized: '早期历史已压缩', context_summary_failed: '上下文摘要失败',
  context_limit: '上下文达到上限', planner_pinned_expanded: 'Planner 态势上限已放宽',
  planner_task_reopened: '动态任务重新打开', planner_task_settled: '动态任务结算',
  finding_superseded: '结论被后续结论取代', finding_retracted: '结论被撤回',
  finding_duplicate: '结论被标记为重复', finding_contested: '结论存在争议', finding_disposition_changed: '结论处置变更',
  poc_agent_phase: 'POC 验证阶段', poc_verification_started: 'POC 自动验证开始',
  poc_job_started: '靶场作业开始', poc_job_finished: '靶场作业结束',
  poc_http_observed: '靶场 HTTP 观测',
  poc_verification_recorded: '自动验证结论记录', poc_verification_skipped: '自动验证跳过',
  poc_verification_unavailable: '自动验证环境不可用',
  poc_execution_finished: 'POC 执行阶段结束', poc_conclusion_failed: 'POC 结论生成失败',
  poc_preconditions_checked: '实验前提检查', poc_precondition_failed: '实验前提不符', poc_context_blocked: '验证上下文受阻',
  poc_context_acquired: '取得靶场验证租约', poc_context_released: '释放靶场验证租约',
  poc_target_reset: '靶场已复位', poc_target_reset_failed: '靶场复位失败',
  poc_authentication_failed: '靶场身份认证失败',
  project_findings_baseline_frozen: '项目台账基线已冻结',
  project_finding_created: '写入项目台账', project_finding_rediscovered: '项目台账再次命中',
  project_finding_corrected: '项目台账结论更正', project_finding_retracted: '台账结论撤回',
  project_finding_duplicate: '台账结论判重', project_finding_reopened: '台账结论重新打开',
  project_finding_disposition_changed: '台账结论处置变更', project_finding_update_rejected: '台账更新被拒绝',
  carried_findings_recorded: '沿用项目既有结论', report_narrative_committed: 'Planner 结论摘要已提交',
  planner_kept_rejected_finding: '自动验证未通过的结论仍被保留',
};

const PHASES: Record<string, string> = {
  lifecycle: '运行状态', prepare: '准备上下文', explore: '源码探索', verdict: '证据判定',
  poc: '生成验证用例', task_prepare: '准备审计任务', task_execute: '执行审计',
  planner_prepare: '准备规划', planner_explore: '探索项目结构', planner_decision: '生成与调整计划',
  planner_publish: '提交规划结果', recon_explore: '只读侦察',
  poc_prepare: '准备隔离靶场', poc_execute: '执行 POC', poc_conclude: '汇总结论',
};

const ROLES: Record<string, string> = { planner: 'Planner', worker: 'Worker', recon: '侦察子 Agent', poc: 'POC Agent', host: '运行服务' };
const STATUS_LABELS: Record<string, string> = {
  ok: '成功', success: '成功', completed: '完成', error: '失败', failed: '失败', timeout: '超时',
  context_missing: '缺少上下文', repeated: '重复调用', no_progress: '无新增进展',
  duplicate: '重复调用', cancelled: '已取消',
  invalid_arguments: '参数无效', context_limit: '达到上下文上限',
};

function contextLabel(context: TraceContext, names: Map<string, string>): string {
  if (context.role === 'planner') return context.round ? `第 ${context.round} 回合` : '任务规划';
  if (context.role === 'recon') return `${context.round ? `第 ${context.round} 回合 · ` : ''}项目侦察`;
  if (context.role === 'poc') return 'POC 自动验证';
  if (context.task) return names.get(context.task) || context.taskKey || context.task.slice(0, 12);
  return context.role === 'host' ? '任务调度与状态' : '审计执行';
}

function durationLabel(value: number | null): string {
  if (value === null) return '耗时未记录';
  return value < 1000 ? `${Math.round(value)} ms` : `${(value / 1000).toFixed(1)} s`;
}

function timeLabel(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleTimeString('zh-CN', { hour12: false });
}

function toolStatus(span: ToolSpan, active: boolean): { text: string; tone: string } {
  if (!span.result) return { text: active ? '等待结果' : '结果未记录', tone: active ? 'active' : 'warning' };
  const status = scalar(span.result.payload.status);
  const outcome = toolOutcome(span.result.payload)!;
  if (status === 'cancelled') return { text: '已取消', tone: 'warning' };
  if (outcome.failed) return { text: outcome.callText, tone: 'error' };
  if (outcome.executionFailed) return { text: '调用完成 · 作业需检查', tone: 'warning' };
  return { text: outcome.cached ? '已返回 · 复用结果' : ['ok', 'success', 'completed'].includes(status) ? '调用完成' : STATUS_LABELS[status] ?? shortText(status || '已返回', 24),
    tone: ['ok', 'success', 'completed'].includes(status) ? 'success' : 'warning' };
}

function RoleIcon({ role }: { role: string }) {
  return role === 'planner' ? <Workflow size={16} /> : role === 'worker' ? <Bot size={16} />
    : role === 'recon' ? <ScanSearch size={16} /> : role === 'poc' ? <FlaskConical size={16} /> : <Server size={16} />;
}

function ToolCard({ span, active, names }: { span: ToolSpan; active: boolean; names: Map<string, string> }) {
  const status = toolStatus(span, active);
  const call = span.call?.payload;
  const result = span.result?.payload;
  const preview = result?.preview;
  const error = result?.error ?? result?.error_type;
  const seen = result?.seen;
  const context = span.context;
  const metadata = [context.worker, contextLabel(context, names), context.attempt ? `第 ${context.attempt} 次尝试` : '', durationLabel(span.durationMs)].filter(Boolean);
  const StatusIcon = status.tone === 'error' ? CircleAlert : status.tone === 'success' ? CircleCheck : CircleDot;
  return (
    <Disclosure className={`trace-item trace-tool trace-${status.tone}`} title={
      <span className="trace-item-title">
        <span className="trace-item-primary"><Wrench size={15} /><span>{shortText(span.name || '未知工具', 80)}</span>
          <span className={`trace-status trace-status-${status.tone}`}><StatusIcon size={12} />{status.text}</span>
        </span>
        <span className="trace-item-secondary">{metadata.map((item) => shortText(item, 70)).join(' · ')}</span>
      </span>
    }>
      <div className="trace-tool-content">
        <ToolOutcome payload={result} />
        {!span.call && <p className="trace-notice">此历史记录仅保留了返回事件，未找到对应调用。</p>}
        {!span.result && <p className="trace-notice">{active ? '调用已记录，等待服务端返回。' : '事件日志中没有保存此调用的结果。'}</p>}
        {Boolean(call || result?.args) && <Disclosure title="调用参数"><LongContent value={call?.args ?? result?.args ?? {}} label="已保存的参数" /></Disclosure>}
        {result && <Disclosure title="已保存的返回预览">
          <p className="trace-notice">服务端受限预览：最多保存 1200 字符；这里展示已保存片段。</p>
          {typeof result.chars === 'number' && <p className="trace-notice">原始返回共 {result.chars.toLocaleString()} 字符{typeof result.new_lines === 'number' ? ` · 新增 ${result.new_lines} 行源码证据` : ''}。</p>}
          <LongContent value={preview ?? '此结果未保存返回内容预览。'} label="返回预览" previewLines={3} />
        </Disclosure>}
        {error !== undefined && <Disclosure title="错误信息"><LongContent value={error} label="已保存的错误" /></Disclosure>}
        {seen !== undefined && <Disclosure title="已读源码范围"><LongContent value={seen} label="已保存的 seen 范围" /></Disclosure>}
        <Disclosure title="事件标识与元数据"><LongContent value={{
          run_id: context.run, role: context.role, session_id: context.session || undefined,
          plan_id: context.plan || undefined, task_id: context.task || undefined,
          attempt: context.attempt || undefined, worker_id: context.worker || undefined,
          recon_invocation: context.invocation || undefined,
          span_id: call?.span_id ?? result?.span_id, call_id: call?.call_id ?? result?.call_id,
          call_event: span.call?.event.id, result_event: span.result?.event.id,
          status: result?.status, duration_ms: span.durationMs, phase: result?.phase ?? call?.phase,
          error_code: result?.error_code, retryable: result?.retryable, cached: result?.cached ?? result?.cache_hit,
        }} label="持久化轨迹标识" /></Disclosure>
      </div>
    </Disclosure>
  );
}

function CodeActionCard({ entry }: { entry: TraceEntry }) {
  const { payload, event } = entry;
  const metadata = Object.fromEntries(Object.entries(payload).filter(([key]) => !['code', 'logs', 'error'].includes(key)));
  const tone = payload.error ? 'error' : 'success';
  return <Disclosure className={`trace-item trace-code trace-${tone}`} title={
    <span className="trace-item-title">
      <span className="trace-item-primary"><Code2 size={15} /><span>模型代码动作</span><span className="trace-meta">{timeLabel(event.created_at)}</span></span>
      <span className="trace-item-secondary">{eventSummary(entry)}</span>
    </span>
  }>
    <div className="trace-tool-content">
      <p className="trace-notice">已执行的 Python 代码与其 print 输出，按服务端实际保存的内容回放。</p>
      {payload.truncated === true && <p className="trace-notice">服务端已截断脚本{typeof payload.code_bytes === 'number' ? `；原始动作 ${payload.code_bytes.toLocaleString()} 字节` : ''}。下方可展开查看全部已保存内容。</p>}
      {payload.is_final === true && <p className="trace-notice">此动作提交了当前阶段的结果；运行结论以审计任务状态为准。</p>}
      <Disclosure title="已执行的代码"><LongContent value={payload.code ?? '此事件没有保存代码。'} label="已保存的 Python 代码" previewLines={3} /></Disclosure>
      {payload.logs !== undefined && payload.logs !== null && <Disclosure title="Print 与执行日志"><LongContent value={payload.logs} label="已保存的 print / log 输出" previewLines={3} /><p className="trace-notice">输出已受解释器预算限制，保留服务端保存的截断标记。</p></Disclosure>}
      {payload.error !== undefined && payload.error !== null && <Disclosure title="代码执行错误"><LongContent value={payload.error} label="已保存的执行错误" /></Disclosure>}
      <Disclosure title="代码动作元数据"><LongContent value={metadata} label="阶段、步骤与预算用量" /></Disclosure>
    </div>
  </Disclosure>;
}

function EventCard({ entry }: { entry: TraceEntry }) {
  const { event, payload } = entry;
  if (event.kind === 'agent_code') return <CodeActionCard entry={entry} />;
  const assessment = event.kind === 'planner_assessment' || event.kind === 'task_assessment';
  return <Disclosure className="trace-item trace-event" title={
    <span className="trace-item-title">
      <span className="trace-item-primary"><CircleDot size={14} /><span>{LABELS[event.kind] ?? shortText(event.kind, 50)}</span><span className="trace-meta">{timeLabel(event.created_at)}</span></span>
      <span className="trace-item-secondary">{eventSummary(entry)}</span>
    </span>
  }>
    <div className="trace-event-content">
      {['agent_parse_error', 'agent_execution_error'].includes(event.kind) && <>
        {scalar(payload.error) && <LongContent value={payload.error} label="错误原因" />}
        {scalar(payload.hint) && <LongContent value={payload.hint} label="修正建议" />}
        {payload.diagnostics !== undefined && <LongContent value={payload.diagnostics} label="动作解析诊断" />}
      </>}
      {event.kind === 'planner_coverage_prepared' && <p className="trace-notice">读取覆盖率是宿主计算的导航统计，需要结合源码引用复核结论。</p>}
      {event.kind === 'recon_brief_prepared' && <p className="trace-notice">侦察简报提供项目导航线索，结论仍需 Worker 读取原始源码后形成证据。</p>}
      {event.kind === 'planner_investigation_reused' && <p className="trace-notice">此事件复用了已有固定调查，没有再次执行该主题的侦察或查询。</p>}
      {assessment && <>
        <p className="trace-notice">基于源码与工具观察的审计依据摘要。</p>
        <LongContent value={payload.summary ?? payload.basis_summary ?? payload.outcome} label="审计摘要" />
        {(payload.rationale ?? payload.reasoning) !== undefined && <LongContent value={payload.rationale ?? payload.reasoning} label="审计依据" />}
        {payload.evidence !== undefined && <Disclosure title="源码证据"><LongContent value={payload.evidence} label="已保存的证据" /></Disclosure>}
      </>}
      <LongContent value={event.payload} label={assessment ? '已保存事件字段' : '已保存事件详情'} />
      <span className="trace-meta">事件 #{event.id} · {event.created_at}</span>
    </div>
  </Disclosure>;
}

function TraceGroupCard({ group, current, names, running }: {
  group: TraceGroup; current: boolean; names: Map<string, string>; running: boolean;
}) {
  const toolCount = group.entries.filter((entry) => entry.event.kind === 'tool_call').length;
  const codeCount = group.entries.filter((entry) => entry.event.kind === 'agent_code').length;
  const lastPhase = group.entries[group.entries.length - 1]?.phaseKey;
  const role = ROLES[group.context.role] ?? shortText(group.context.role, 30);
  return <Disclosure className={`trace-group${current ? ' trace-group-current' : ''}`} defaultOpen={current} title={
    <span className="trace-group-title">
      <span className="trace-item-primary"><RoleIcon role={group.context.role} /><span className="trace-role">{role}</span><span>{shortText(contextLabel(group.context, names), 80)}</span>
        {group.context.attempt && <span className="trace-meta">第 {shortText(group.context.attempt, 12)} 次尝试</span>}
      </span>
      <span className="trace-item-secondary">{[shortText(group.context.worker, 70), `${toolCount} 次工具调用`, codeCount ? `${codeCount} 个代码动作` : '', `${group.entries.length} 条事件`, current && running && !group.finished ? '正在执行' : group.finished ? '已结束' : '已记录'].filter(Boolean).join(' · ')}</span>
    </span>
  }>
    <div className="trace-phases">{group.phases.map((phase) => {
      const phaseCurrent = current && phase.key === lastPhase;
      return <Disclosure key={phase.key} className="trace-phase" defaultOpen={phaseCurrent} title={
        <span className="trace-phase-title"><span>{PHASES[phase.name] ?? shortText(phase.name, 60)}</span>
          <span className="trace-meta">{phase.rows.length} 项活动{phaseCurrent ? ' · 当前阶段' : ''}</span>
        </span>
      }>
        <div className="trace-rows">{phase.rows.map((row) => row.type === 'tool'
          ? <ToolCard key={row.key} span={row.span} active={phaseCurrent && running && !group.finished} names={names} />
          : <EventCard key={row.key} entry={row.entry} />)}</div>
      </Disclosure>;
    })}</div>
  </Disclosure>;
}

/** Public activity only: replayed durable events, tool arguments and bounded outputs. */
export function Timeline({ events, detail, compact = false }: { events: AuditEvent[]; detail: RunDetail | null; compact?: boolean }) {
  const [filters, setFilters] = useState<TraceFilters>(EMPTY_TRACE_FILTERS);
  const [page, setPage] = useState({ signature: '', limit: 50 });
  const entries = useMemo(() => normalizeTrace(events), [events]);
  const allGroups = useMemo(() => groupTrace(entries), [entries]);
  const state = traceRunState(entries, detail?.run.status);
  const running = state === 'running';
  const currentGroups = useMemo(() => currentTraceGroups(allGroups, running), [allGroups, running]);
  const names = useMemo(() => {
    const map = new Map<string, string>();
    for (const task of detail?.tasks ?? []) map.set(task.id, `${task.task_key} · ${task.title}`);
    for (const unit of detail?.units ?? []) map.set(unit.id, `${unit.file_path}:${unit.start_line}-${unit.end_line}`);
    for (const work of detail?.work_items ?? []) map.set(work.id, work.summary || work.focus || work.id);
    return map;
  }, [detail]);
  const matching = useMemo(() => filterTrace(entries, filters), [entries, filters]);
  const signature = JSON.stringify([detail?.run.id ?? events[0]?.run_id, filters]);
  const limit = page.signature === signature ? page.limit : 50;
  const visible = useMemo(() => latestTracePage(matching, limit), [matching, limit]);
  const groups = useMemo(() => groupTrace(visible, entries), [visible, entries]);
  const tools = useMemo(() => pairToolCalls(entries), [entries]);
  const codeCount = entries.filter((entry) => entry.event.kind === 'agent_code').length;
  const roles = [...new Set(entries.map((entry) => entry.context.role))];
  const workers = [...new Set(entries.map((entry) => entry.context.worker).filter(Boolean))].sort();
  const tasks = [...new Set(entries.map((entry) => entry.context.task).filter(Boolean))];
  const attempts = [...new Set(entries.map((entry) => entry.context.attempt).filter(Boolean))].sort((a, b) => Number(a) - Number(b));
  const kinds = [...new Set(events.map((event) => event.kind))].sort();
  function update(field: keyof TraceFilters, value: string) { setFilters((previous) => ({ ...previous, [field]: value })); }
  const controls = <div className="trace-filters">
    <label><span className="field-label">角色</span><select aria-label="按角色筛选轨迹" value={filters.role} onChange={(event) => update('role', event.target.value)}><option value="all">全部角色</option>{roles.map((role) => <option value={role} key={role}>{ROLES[role] ?? shortText(role, 40)}</option>)}</select></label>
    <label><span className="field-label">Worker</span><select aria-label="按 Worker 筛选轨迹" value={filters.worker} onChange={(event) => update('worker', event.target.value)}><option value="all">全部 Worker</option>{workers.map((worker) => <option value={worker} key={worker}>{shortText(worker, 80)}</option>)}</select></label>
    <label><span className="field-label">任务</span><select aria-label="按任务筛选轨迹" value={filters.task} onChange={(event) => update('task', event.target.value)}><option value="all">全部任务</option>{tasks.map((task) => <option value={task} key={task}>{shortText(names.get(task) || task, 90)}</option>)}</select></label>
    <label><span className="field-label">尝试</span><select aria-label="按尝试筛选轨迹" value={filters.attempt} onChange={(event) => update('attempt', event.target.value)}><option value="all">全部尝试</option>{attempts.map((attempt) => <option value={attempt} key={attempt}>第 {shortText(attempt, 20)} 次</option>)}</select></label>
    <label><span className="field-label">事件类型</span><select aria-label="按事件类型筛选轨迹" value={filters.kind} onChange={(event) => update('kind', event.target.value)}><option value="all">全部事件</option>{kinds.map((kind) => <option value={kind} key={kind}>{LABELS[kind] ?? shortText(kind, 60)}</option>)}</select></label>
    {Object.values(filters).some((value) => value !== 'all') && <button type="button" className="text-button" onClick={() => setFilters(EMPTY_TRACE_FILTERS)}>清除筛选</button>}
  </div>;

  if (!events.length) return <div className="trace-empty"><Clock3 size={18} /><span>等待执行事件。审计开始后会在这里显示工具链过程。</span></div>;
  return <div className={`trace${compact ? ' trace-compact' : ''}`}>
    <div className="trace-overview">
      <span className="trace-overview-title"><Workflow size={17} />执行活动</span>
      <span className="trace-counts">{tools.length} 次工具活动 · {codeCount} 个代码动作 · {allGroups.filter((group) => group.context.role === 'worker').length} 个工作轮次 · {events.length} 条事件{state === 'paused' ? ' · 已暂停，可继续' : ''}</span>
    </div>
    <AgentDiagnostics events={events} />
    <Disclosure className="trace-filter-panel" title={`筛选轨迹 · ${matching.length} 条匹配`} defaultOpen={!compact}>{controls}</Disclosure>
    <div className="trace-groups">{groups.length ? groups.map((group) => <TraceGroupCard key={group.key} group={group} current={currentGroups.has(group.key)} names={names} running={running} />)
      : <div className="trace-empty">没有符合筛选条件的事件。</div>}</div>
    <div className="trace-footer">
      <span className="trace-meta">显示最近 {visible.length} / {matching.length} 条事件 · 配对的调用与结果共同展示</span>
      {visible.length < matching.length && <button type="button" className="btn" onClick={() => setPage({ signature, limit: limit + 50 })}>加载更早的 50 条</button>}
    </div>
  </div>;
}
