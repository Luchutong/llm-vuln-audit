import { scopeFileCount, scopeLabel } from '../types';
import type { AuditEvent, PlannerTask, RunDetail } from '../types';
import { Disclosure } from '../components/Disclosure';
import { LongContent } from '../components/LongContent';

const GOAL_LABELS: Record<string, string> = {
  open: '探索中', met: '已达成', unreachable: '不可达', inconclusive: '未决',
};

const TASK_LABELS: Record<string, string> = {
  pending: '等待依赖', ready: '待领取', running: '执行中', deferred: '已暂缓', completed: '已完成',
  exhausted: '方向耗尽', blocked: '受阻', cancelled: '已取消', skipped: '已跳过',
};

function references(task: PlannerTask) {
  return {
    refs: (task.context_spec?.source_refs ?? []).map((item) => `${item.path}:${item.start_line}-${item.end_line}`),
    scopePaths: task.context_spec?.scope_paths ?? [],
    symbols: task.context_spec?.target_symbols ?? [],
  };
}

function Stat({ value, label, note }: { value: string | number; label: string; note: string }) {
  return (
    <div className="stat">
      <strong className="stat-value">{value}</strong>
      <span className="stat-label">{label}</span>
      <small className="stat-note">{note}</small>
    </div>
  );
}

/** Project-level status: source slices are not displayed as a work queue. */
export function Overview({ detail, events }: { detail: RunDetail; events: AuditEvent[] }) {
  const { run, metrics } = detail;
  const planner = detail.planner;
  const goal = detail.goal ?? detail.goals?.[0];
  const projectMap = detail.project_map;
  const plans = detail.plans ?? [];
  const tasks = detail.tasks ?? [];
  const findings = detail.findings ?? [];
  const withdrawn = findings.filter((finding) => ['superseded', 'retracted', 'duplicate'].includes(finding.disposition));
  const candidateCount = metrics.candidate_findings ?? findings.filter((finding) => finding.validation_state === 'candidate' && !['superseded', 'retracted', 'duplicate'].includes(finding.disposition)).length;
  const withdrawnCount = metrics.withdrawn_findings ?? withdrawn.length;
  const counts = tasks.reduce<Record<string, number>>((result, task) => {
    result[task.state] = (result[task.state] ?? 0) + 1;
    return result;
  }, {});
  const toolCalls = events.filter((event) => event.kind === 'tool_call').length;
  const plannerEvents = events.filter((event) => event.kind.startsWith('planner_')).length;
  const mapStats = projectMap?.stats ?? {};

  return (
    <div className="grid">
      <div className="grid stats-grid">
        <Stat value={`${planner?.current_round ?? 0}/${planner?.max_rounds ?? run.task_spec?.max_planner_rounds ?? '—'}`} label="Planner 回合" note={`版本 ${planner?.current_revision ?? 0}`} />
        <Stat value={`${metrics.terminal_tasks ?? 0}/${metrics.total_tasks ?? tasks.length}`} label="已结算动态任务" note={`执行中 ${metrics.active_tasks ?? counts.running ?? 0}`} />
        <Stat value={candidateCount} label="有效证据化发现" note={`待复核 ${metrics.awaiting_verification} · 已撤回/取代/判重 ${withdrawnCount}`} />
        <Stat value={toolCalls || run.usage.tool_calls} label="只读工具调用" note={`模型响应 ${run.usage.requests}`} />
        <Stat value={mapStats.files ?? scopeFileCount(run, projectMap)} label="项目图文件" note={`${mapStats.symbols ?? 0} 个符号`} />
        <Stat value={plannerEvents} label="Planner 轨迹事件" note="可在执行轨迹展开" />
      </div>

      <section className="panel" aria-label="目标收束">
        <div className="panel-head">
          <div className="panel-title">目标收束</div>
          <span className={`chip chip-${goal?.status ?? run.status}`}>{GOAL_LABELS[goal?.status ?? ''] ?? run.status}</span>
        </div>
        <div className="grid detail-fields panel-body">
          <div className="field"><LongContent value={run.task_spec?.objective ?? '—'} label="审计目标" /></div>
          <div className="field"><LongContent value={run.task_spec?.success_criteria ?? '—'} label="验收条件" /></div>
          <div className="field"><LongContent value={goal?.terminal_reason ?? planner?.terminal_reason ?? '尚在收集项目图或 worker 反馈。'} label="当前状态" /></div>
          <div className="field"><span className="field-label">边界</span><span className="small">{scopeLabel(run, projectMap)}</span></div>
        </div>
      </section>

      <PlannerNavigation detail={detail} />

      <div className="grid overview-columns">
        <section className="panel" aria-label="冻结项目图">
          <div className="panel-head"><span className="panel-title">冻结项目图</span><span className="faint small">规划索引</span></div>
          <div className="panel-body grid">
            <div className="small">文件 {mapStats.files ?? 0} · 符号 {mapStats.symbols ?? 0} · 静态 include {mapStats.includes ?? 0} · 调用点 {mapStats.calls ?? 0}</div>
            <div className="faint small">高置信入口 {mapStats.entrypoints ?? 0} · 未解析 include {mapStats.unresolved_includes ?? 0}</div>
            <Disclosure title={`入口候选（${projectMap?.entrypoints?.length ?? 0}）`}>
              <LongContent value={projectMap?.entrypoints ?? []} label="入口候选" />
              <p className="faint small">低置信静态根 {mapStats.low_confidence_roots ?? 0}</p>
            </Disclosure>
            <LongContent value={projectMap?.limitations?.length ? projectMap.limitations : '静态图不能代替运行时调用图。'} label="静态分析限制" />
          </div>
        </section>

        <section className="panel" aria-label="Planner 回合">
          <div className="panel-head"><span className="panel-title">Planner 回合</span><span className="faint small">{plans.length} 个版本</span></div>
          {plans.length === 0 ? <div className="empty">等待主 Planner 建立第一版任务图。</div> : (
            <div className="panel-body">
              <Disclosure title={`查看 Planner 版本（${plans.length}）`}>
                {plans.map((plan) => (
                  <Disclosure key={plan.id} title={<span className="disclosure-heading"><span className={`chip chip-${plan.status}`}>第 {plan.round_no} 回合</span><span className="disclosure-preview">{plan.basis_summary || '等待 Planner 返回依据摘要。'}</span></span>}>
                    <div className="grid">
                      <LongContent value={plan.basis_summary || '尚无依据摘要'} label="调度依据" />
                      <div className="small">目标建议：{plan.goal_state ?? 'continue'}</div>
                      <LongContent value={plan.next_action || '—'} label="下一步" />
                      {plan.error && <LongContent value={plan.error} label="错误" />}
                      <LongContent value={plan.task_snapshot} label="本轮任务" />
                    </div>
                  </Disclosure>
                ))}
              </Disclosure>
            </div>
          )}
        </section>
      </div>

      <section className="panel" aria-label="动态任务图">
        <div className="panel-head">
          <span className="panel-title">动态任务图</span>
          <span className="faint small">{tasks.length} 个任务</span>
        </div>
        <div className="panel-body">
          <p className="small muted">{Object.entries(counts).map(([state, count]) => `${TASK_LABELS[state] ?? state} ${count}`).join(' · ') || '首轮 Planner 尚未提交任务。'}</p>
          {tasks.length > 0 && <Disclosure title={`查看任务与尝试（${tasks.length}）`}>
            {tasks.map((item) => {
              const source = references(item);
              return (
                <Disclosure key={item.id} title={<span className="disclosure-heading"><span className={`chip chip-${item.state}`}>{TASK_LABELS[item.state] ?? item.state}</span><span className="disclosure-preview">{item.title}</span><span className="faint small">{item.attempts}/{item.max_attempts} 次</span></span>}>
                  <div className="grid">
                    <LongContent value={item.objective} label="任务目标" />
                    <LongContent value={item.result?.summary || item.error || '尚无 worker 结果'} label="任务结果" />
                    <LongContent value={{ 源码引用: source.refs, 范围: source.scopePaths, 符号: source.symbols, 依赖: item.dependencies }} label="初始上下文与依赖" />
                    {item.error && <LongContent value={item.error} label="错误" />}
                    {(item.attempt_history ?? []).length > 0 && <Disclosure title={`尝试历史（${item.attempt_history?.length}）`}><LongContent value={item.attempt_history} label="尝试历史" /></Disclosure>}
                  </div>
                </Disclosure>
              );
            })}
          </Disclosure>}
        </div>
      </section>
    </div>
  );
}

/** Round-level navigation history remains separate from validated source evidence. */
export function PlannerNavigation({ detail }: { detail: RunDetail }) {
  const observations = detail.observations ?? [];
  const investigations = detail.investigations;
  if (!observations.length && !investigations?.total) return null;
  const coverage = [...observations].reverse().find((item) => item.payload.coverage)?.payload.coverage;
  const observationLabels: Record<string, string> = { planner_coverage_prepared: '阅读覆盖', recon_brief_prepared: '侦察简报', recon_terminal: '侦察终态', recon_skipped: '侦察已跳过' };
  const dispositionLabels: Record<string, string> = { active: '当前有效', superseded: '已取代', retracted: '已撤回' };
  return <section className="panel" aria-label="覆盖、侦察与固定调查">
    <div className="panel-head"><span className="panel-title">规划上下文</span><span className="faint small">导航记录</span></div>
    <div className="panel-body grid">
      <p className="small muted">阅读覆盖、侦察简报和固定调查用于指导后续审计；结论仍需原始源码引用。</p>
      {coverage && <div className="small">已读 {coverage.files_read} / {coverage.files_total} 个文件 · 依赖目录已读 {coverage.dependency_tree_read} / {coverage.dependency_tree_total} 个文件</div>}
      {observations.length > 0 && <Disclosure title={`覆盖与侦察记录（${observations.length}）`}>
        {observations.map((observation, index) => <Disclosure key={`${observation.kind}-${observation.round ?? index}-${index}`} title={`${observationLabels[observation.kind] ?? observation.kind}${observation.round != null ? ` · 第 ${observation.round} 回合` : ''}`}>
          {observation.payload.coverage && <LongContent value={observation.payload.coverage} label="已保存的阅读覆盖" />}
          {observation.payload.question && <LongContent value={observation.payload.question} label="侦察问题" />}
          {observation.payload.brief && <LongContent value={observation.payload.brief} label="已保存的侦察简报" />}
          {observation.payload.reason && <LongContent value={observation.payload.reason} label="记录原因" />}
          {observation.payload.error && <LongContent value={observation.payload.error} label="侦察错误" />}
          {observation.payload.files_examined && <LongContent value={observation.payload.files_examined} label="已查看文件" />}
        </Disclosure>)}
      </Disclosure>}
      {investigations && investigations.total > 0 && <Disclosure title={`固定调查（${investigations.total}）`}>
        <p className="small muted">{investigations.notice}</p>
        <div className="small">{Object.entries(investigations.by_status).map(([status, count]) => `${dispositionLabels[status] ?? status} ${count}`).join(' · ')}</div>
        {investigations.recent.map((record) => <Disclosure key={record.id} title={<span className="disclosure-heading"><span className="chip">{dispositionLabels[record.status] ?? record.status}</span><span className="disclosure-preview">{record.topic}</span><span className="faint small">第 {record.round_no} 回合 · 第 {record.revision} 版</span></span>}>
          <LongContent value={record} label="已保存的调查记录" />
        </Disclosure>)}
      </Disclosure>}
    </div>
  </section>;
}
