import { useEffect, useState } from 'react';
import { api, downloadUrl, errorText, post } from '../api';
import type { AuditEvent, RunDetail } from '../types';
import { useEvents } from '../useEvents';
import { Timeline } from '../components/Timeline';
import { FindingsView } from './FindingsView';
import { Overview } from './Overview';
import { ReportView } from './ReportView';

const TABS = [
  { key: 'overview', label: '概览' },
  { key: 'process', label: '审计过程' },
  { key: 'findings', label: '发现与验证' },
  { key: 'report', label: '实验报告' },
] as const;

type TabKey = (typeof TABS)[number]['key'];

const TERMINAL = new Set(['succeeded', 'failed', 'cancelled', 'interrupted']);

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
              {run.snapshot_name} · Prompt {run.prompt_id}（{run.prompt_label}）· 模型 {run.model}
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
            <span className="panel-title">事件时间线</span>
            <span className="faint small">
              SQLite 为准，SSE 只做推送；工具调用记录按事件保留
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
