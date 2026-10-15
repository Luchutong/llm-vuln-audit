import { useEffect, useState } from 'react';
import { api, downloadUrl, errorText, post } from '../api';
import type { AuditEvent, Goal, Run, RunDetail, TaskSpec, TaskWorkItem } from '../types';
import { useEvents } from '../useEvents';
import { Timeline } from '../components/Timeline';
import { FindingsView } from './FindingsView';
import { Overview } from './Overview';
import { ReportView } from './ReportView';

const TABS = [
  { key: 'overview', label: '结果概览' },
  { key: 'process', label: '执行轨迹' },
  { key: 'findings', label: '发现与复核' },
  { key: 'report', label: '结果报告' },
] as const;

type TabKey = (typeof TABS)[number]['key'];

const TERMINAL = new Set(['succeeded', 'completed', 'unreachable', 'inconclusive', 'failed', 'cancelled', 'interrupted']);

const GOAL_STATUS_LABELS: Record<string, string> = {
  open: '待达成',
  met: '已达成',
  unreachable: '不可达',
  inconclusive: '未决',
};

const WORK_ITEM_STATE_LABELS: Record<string, string> = {
  open: '排队中',
  running: '执行中',
  done: '已完成',
  exhausted: '轮次耗尽',
  blocked: '受阻',
  skipped: '已跳过',
};

const TASK_TERMINAL: Record<string, { label: string; explanation: string }> = {
  completed: { label: '目标已达成', explanation: '协调器已收到满足验收条件的、可回溯到源码证据的结果。' },
  unreachable: { label: '目标不可达', explanation: '所有可执行工作项均已完成、正常耗尽轮次或耗尽任务总尝试上限，尚无结果能满足验收条件。' },
  inconclusive: { label: '目标未决', explanation: '运行已结束，但现有证据不足以判定任务已达成或不可达。' },
  failed: { label: '运行失败', explanation: '任务在完成目标判断前发生错误。请结合工作项和事件记录定位原因。' },
  cancelled: { label: '已取消', explanation: '运行被取消，尚未完成的工作项不会被视为不可达。' },
  interrupted: { label: '已中断', explanation: '服务或运行过程被中断，尚未完成的工作项保留当前状态。' },
};

function taskFindings(item: TaskWorkItem) {
  const findings = item.result?.findings ?? [];
  return findings.length > 0
    ? findings
    : item.result?.finding ? [item.result.finding] : [];
}

/**
 * One run, four tabs.
 *
 * The run detail is re-fetched whenever an event arrives rather than being patched from
 * the event payload: the event log is the nudge, the database is the truth, and a page
 * reload in the middle of a run reproduces exactly what was on screen before.
 */
export function RunView({ runId, onBack }: { runId: string; onBack: () => void }) {
  const [tab, setTab] = useState<TabKey>('overview');
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = () => {
    api<RunDetail>(`/runs/${runId}`)
      .then((data) => {
        setDetail(data);
        setError(null);
      })
      .catch((exc) => setError(errorText(exc)));
  };

  const { events, connected, reconnects } = useEvents(runId, refresh);

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId]);

  const cancel = async () => {
    setBusy(true);
    try {
      await post(`/runs/${runId}/cancel`, {});
      refresh();
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(false);
    }
  };

  if (!detail) {
    return <div className="empty">{error ?? '载入运行…'}</div>;
  }

  const { run } = detail;
  const live = !TERMINAL.has(run.status);

  return (
    <div className="grid">
      <div className="page-head">
        <div className="between">
          <div>
            <h1 className="row" style={{ flexWrap: 'wrap' }}>
              <button className="btn" onClick={onBack} style={{ marginRight: 4 }}>← 任务列表</button>
              <span className="mono" style={{ fontSize: 15 }}>{run.id.slice(0, 10)}</span>
              <span className={`chip chip-${run.status}`}>{run.status}</span>
              {live && (
                <span className={`chip ${connected ? 'chip-running' : 'chip-pending'}`}>
                  {connected ? '事件流已连接' : '事件流断开，重连中'}
                </span>
              )}
            </h1>
            <p>
              {run.snapshot_name} · {run.task_spec ? '目标驱动多 worker 审计' : '历史审计记录'} · 模型 {run.model}
              {' · '}预算 响应 {run.budgets.responses} / 工具 {run.budgets.tools} / {run.budgets.seconds}s
              {reconnects > 0 && ` · 已重连 ${reconnects} 次`}
            </p>
          </div>
          <div className="row">
            {live && <button className="btn btn-danger" onClick={cancel} disabled={busy}>取消运行</button>}
            <a className="btn" href={downloadUrl(`/runs/${runId}/report?format=markdown`)}>下载 Markdown</a>
            <a className="btn" href={downloadUrl(`/runs/${runId}/report?format=json`)}>JSON</a>
            <a className="btn" href={downloadUrl(`/runs/${runId}/report?format=zip`)}>证据包</a>
          </div>
        </div>
      </div>

      {error && <div className="error-box">{error}</div>}
      {run.error && <div className="error-box">运行错误：{run.error}</div>}
      {run.task_spec && <GoalTaskSummary run={run} task={run.task_spec} goals={detail.goals ?? []} workItems={detail.work_items ?? []} />}

      <div className="tabs">
        {TABS.map((item) => (
          <button key={item.key} className={`tab${tab === item.key ? ' active' : ''}`} onClick={() => setTab(item.key)}>
            {item.label}
          </button>
        ))}
      </div>

      {tab === 'overview' && <Overview detail={detail} events={events} />}
      {tab === 'process' && (
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">执行轨迹</span>
            <span className="faint small">
              SQLite 事件为准，SSE 只做推送；可展开查看工具调用、worker 状态和证据化依据摘要
            </span>
          </div>
          <Timeline events={events} detail={detail} />
        </div>
      )}
      {tab === 'findings' && (
        <FindingsView detail={detail} snapshotId={run.snapshot_id} onChanged={refresh} />
      )}
      {tab === 'report' && <ReportView runId={runId} detail={detail} onChanged={refresh} />}
    </div>
  );
}

function GoalTaskSummary({
  run,
  task,
  goals,
  workItems,
}: {
  run: Run;
  task: TaskSpec;
  goals: Goal[];
  workItems: TaskWorkItem[];
}) {
  const stateCounts = workItems.reduce<Record<string, number>>((counts, item) => {
    counts[item.state] = (counts[item.state] ?? 0) + 1;
    return counts;
  }, {});
  const activeWorkers = new Set(
    workItems.filter((item) => item.state === 'running' && item.claimed_by).map((item) => item.claimed_by),
  ).size;
  const terminal = TASK_TERMINAL[run.status];
  const terminalReason = goals.map((goal) => goal.terminal_reason).find(Boolean);

  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <div className="panel-title">目标审计</div>
          <div className="faint small">目标、工作项和每次尝试均随本次运行冻结</div>
        </div>
        {terminal
          ? <span className={`chip chip-${run.status}`}>{terminal.label}</span>
          : <span className="chip chip-running">探索中</span>}
      </div>
      <div style={{ padding: '12px 16px' }} className="grid">
        <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))' }}>
          <TaskFact label="目标" value={task.objective} />
          <TaskFact label="验收条件" value={task.success_criteria} />
          <TaskFact label="每项最大轮次" value={`${task.max_iterations} 次`} />
          <TaskFact label="任务总尝试上限" value={`${task.max_total_attempts} 次`} />
          <TaskFact label="worker 上限" value={`${task.max_workers} 个（当前 ${activeWorkers} 个执行中）`} />
          <TaskFact label="达成后停止" value={task.stop_on_achieved ? '是，跳过尚未开始的工作项' : '否，继续处理全部工作项'} />
          <TaskFact label="POC 要求" value={task.require_poc ? '达成时必须附带 POC' : '仅源码事实任务可省略 POC'} />
        </div>

        {terminal && (
          <div className={run.status === 'completed' ? 'small' : 'error-box'}>
            <strong>{terminal.label}：</strong>{terminal.explanation}
            {terminalReason && <span> 原因：{terminalReason}</span>}
          </div>
        )}

        <div className="grid" style={{ gridTemplateColumns: 'minmax(260px, 1fr) minmax(360px, 2fr)', alignItems: 'start' }}>
          <div>
            <div className="field-label" style={{ marginBottom: 7 }}>目标状态</div>
            {goals.length === 0 ? (
              <div className="small faint">目标拆解尚未写入；刷新后会显示协调器保存的目标。</div>
            ) : goals.map((goal) => (
              <div key={goal.id} style={{ padding: '8px 0', borderTop: '1px solid var(--line-soft)' }}>
                <div className="row" style={{ flexWrap: 'wrap' }}>
                  <span className={`chip chip-${goal.status}`}>{GOAL_STATUS_LABELS[goal.status] ?? goal.status}</span>
                  <span className="small">累计尝试 {goal.attempts}/{goal.max_total_attempts} 次（每项最多 {goal.max_iterations} 轮）</span>
                </div>
                <div className="small" style={{ marginTop: 4 }}>{goal.objective}</div>
                {goal.terminal_reason && <div className="faint small" style={{ marginTop: 3 }}>{goal.terminal_reason}</div>}
              </div>
            ))}
          </div>

          <div>
            <div className="between" style={{ marginBottom: 7 }}>
              <span className="field-label">工作项队列</span>
              <span className="faint small">
                {Object.entries(stateCounts).map(([state, count]) => `${WORK_ITEM_STATE_LABELS[state] ?? state} ${count}`).join(' · ') || '尚未建立'}
              </span>
            </div>
            {workItems.length === 0 ? (
              <div className="small faint">尚无工作项。</div>
            ) : (
              <div style={{ maxHeight: 280, overflowY: 'auto', border: '1px solid var(--line-soft)', borderRadius: 7 }}>
                {workItems.map((item) => (
                  <div key={item.id} style={{ padding: '9px 10px', borderBottom: '1px solid var(--line-soft)' }}>
                    <div className="row" style={{ flexWrap: 'wrap' }}>
                      <span className={`chip chip-${item.state}`}>{WORK_ITEM_STATE_LABELS[item.state] ?? item.state}</span>
                      <span className="small">轮次 {item.attempt}/{item.max_attempts}</span>
                      {item.attempt_history && <span className="faint small">历史 {item.attempt_history.length} 条</span>}
                      {item.claimed_by && <span className="faint small">{item.claimed_by}</span>}
                    </div>
                    <div className="small" style={{ marginTop: 4 }}>{item.summary || item.focus}</div>
                    {item.focus && item.focus !== item.summary && <div className="faint small" style={{ marginTop: 2 }}>关注点：{item.focus}</div>}
                    {item.result?.summary && <div className="faint small" style={{ marginTop: 2 }}>{item.result.summary}</div>}
                    {taskFindings(item).map((finding, index) => (
                      <div className="small" style={{ marginTop: 3 }} key={`${finding.title}-${index}`}>
                        达成证据{index > 0 ? ` ${index + 1}` : ''}：{finding.title} · {finding.evidence}
                      </div>
                    ))}
                    {item.error && <div className="small" style={{ marginTop: 2, color: 'var(--danger)' }}>{item.error}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function TaskFact({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ minWidth: 0 }}>
      <div className="field-label">{label}</div>
      <div className="small" style={{ overflowWrap: 'anywhere' }}>{value}</div>
    </div>
  );
}
