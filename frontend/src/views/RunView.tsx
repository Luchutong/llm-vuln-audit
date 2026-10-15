import { useEffect, useState } from 'react';
import { api, downloadUrl, errorText, post } from '../api';
import type { AuditEvent, RunDetail } from '../types';
import { useEvents } from '../useEvents';
import { Timeline } from '../components/Timeline';
import { FindingsView } from './FindingsView';
import { Overview } from './Overview';
import { ReportView } from './ReportView';

const TABS = [
  { key: 'overview', label: '项目与任务图' },
  { key: 'process', label: '执行轨迹' },
  { key: 'findings', label: '发现与复核' },
  { key: 'report', label: '结果报告' },
] as const;

type TabKey = (typeof TABS)[number]['key'];
const TERMINAL = new Set(['succeeded', 'completed', 'unreachable', 'inconclusive', 'failed', 'cancelled', 'interrupted']);

const RUN_LABELS: Record<string, string> = {
  completed: '目标已达成', unreachable: '目标不可达', inconclusive: '结果未决',
  failed: '运行失败', cancelled: '已取消', interrupted: '已中断',
};

/** Re-fetch durable data after each SSE event; the database is the review record. */
export function RunView({ runId, onBack }: { runId: string; onBack: () => void }) {
  const [tab, setTab] = useState<TabKey>('overview');
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = () => {
    api<RunDetail>(`/runs/${runId}`)
      .then((data) => { setDetail(data); setError(null); })
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

  if (!detail) return <div className="empty">{error ?? '载入运行…'}</div>;
  const { run } = detail;
  const live = !TERMINAL.has(run.status);

  return (
    <div className="grid">
      <div className="page-head">
        <div className="between">
          <div>
            <h1 className="row" style={{ flexWrap: 'wrap' }}>
              <button className="btn" onClick={onBack} style={{ marginRight: 4 }}>← 审计列表</button>
              <span className="mono" style={{ fontSize: 15 }}>{run.id.slice(0, 10)}</span>
              <span className={`chip chip-${run.status}`}>{RUN_LABELS[run.status] ?? run.status}</span>
              {live && <span className={`chip ${connected ? 'chip-running' : 'chip-pending'}`}>{connected ? '事件流已连接' : '事件流重连中'}</span>}
            </h1>
            <p>
              {run.snapshot_name} · 项目级 Planner 审计 · 模型 {run.model}
              {' · '}每个回合 响应 {run.budgets.responses} / 工具 {run.budgets.tools} / {run.budgets.seconds}s
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
      <PlannerSummary detail={detail} />

      <div className="tabs">
        {TABS.map((item) => <button key={item.key} className={`tab${tab === item.key ? ' active' : ''}`} onClick={() => setTab(item.key)}>{item.label}</button>)}
      </div>
      {tab === 'overview' && <Overview detail={detail} events={events} />}
      {tab === 'process' && (
        <div className="panel">
          <div className="panel-head"><span className="panel-title">执行轨迹</span><span className="faint small">展开查看 Planner、worker、工具调用和源码依据摘要；不展示模型内部思维链。</span></div>
          <Timeline events={events} detail={detail} />
        </div>
      )}
      {tab === 'findings' && <FindingsView detail={detail} snapshotId={run.snapshot_id} onChanged={refresh} />}
      {tab === 'report' && <ReportView runId={runId} detail={detail} onChanged={refresh} />}
    </div>
  );
}

function PlannerSummary({ detail }: { detail: RunDetail }) {
  const { run } = detail;
  const goal = detail.goal ?? detail.goals?.[0];
  const planner = detail.planner;
  const tasks = detail.tasks ?? [];
  const activeWorkers = new Set(tasks.filter((item) => item.state === 'running').map((item) => item.claimed_by).filter(Boolean)).size;
  const counts = tasks.reduce<Record<string, number>>((result, item) => {
    result[item.state] = (result[item.state] ?? 0) + 1;
    return result;
  }, {});
  return (
    <div className="panel">
      <div className="panel-head">
        <div><div className="panel-title">Planner → Worker 闭环</div><div className="faint small">项目图先冻结，Planner 再动态创建跨文件任务；源码片段不会直接成为派工单位。</div></div>
        <span className={`chip chip-${planner?.status ?? 'pending'}`}>{planner?.status ?? '等待初始化'}</span>
      </div>
      <div className="grid" style={{ padding: '12px 16px', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
        <Fact label="审计目标" value={run.task_spec?.objective ?? '—'} />
        <Fact label="Planner 回合" value={`${planner?.current_round ?? 0}/${planner?.max_rounds ?? run.task_spec?.max_planner_rounds ?? '—'}`} />
        <Fact label="worker 尝试" value={`${goal?.attempts ?? 0}/${goal?.max_total_attempts ?? run.task_spec?.max_total_attempts ?? '—'}`} />
        <Fact label="动态任务" value={`${tasks.length} 项 · 执行中 ${activeWorkers} worker`} />
        <Fact label="任务状态" value={Object.entries(counts).map(([state, count]) => `${state} ${count}`).join(' · ') || '等待首轮规划'} />
        <Fact label="终止依据" value={goal?.terminal_reason ?? planner?.terminal_reason ?? '—'} />
      </div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div><div className="field-label">{label}</div><div className="small" style={{ overflowWrap: 'anywhere' }}>{value}</div></div>;
}
