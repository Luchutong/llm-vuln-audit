import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowDown, ArrowUpRight, FileArchive, LoaderCircle, MoreHorizontal, PanelRightOpen, Plus, Pause, Play, ShieldCheck, Square } from 'lucide-react';
import { api, errorText, post } from '../api';
import type { Run, RunDetail } from '../types';
import { useEvents } from '../useEvents';
import { Timeline } from '../components/Timeline';
import { ActivityStream } from '../components/ActivityStream';
import { LongContent } from '../components/LongContent';
import { Overlay } from '../components/Overlay';
import { DeleteRunButton } from '../components/RecordActions';
import { BrandWordmark } from '../components/BrandWordmark';
import { scopeFileCount, scopeLabel } from '../types';
import { FindingsView } from './FindingsView';
import { Overview } from './Overview';
import { ReportView } from './ReportView';
import { ReportDownloads } from '../components/ReportDownloads';
import { localDate, TERMINAL } from '../status';
import { sourceHref } from '../routes';
import { ExecutionStatus, HostSummary } from '../components/ExecutionStatus';
import { DefencePanel } from '../components/DefencePanel';
import { executionSummary } from '../execution';
import { CompactText } from '../components/CompactText';
import { Disclosure } from '../components/Disclosure';
import { RunResult } from '../components/RunResult';
import { RunSnapshot } from '../components/RunSnapshot';
import '../runPage.css';
import { useFinalReview } from '../useFinalReview';
import { resultStatus } from '../runPresentation';
import { frozenTaskPolicy } from '../taskDraft';


export function RunView({ runId, onNewTask, onChanged }: { runId: string; onNewTask: (seed?: Run) => void; onChanged: () => void }) {
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const [tab, setTab] = useState<'overview' | 'findings' | 'defence' | 'report' | 'logs'>('overview');
  const [newActivity, setNewActivity] = useState(false);
  const scrollbox = useRef<HTMLDivElement>(null);
  const follow = useRef(true);
  const timer = useRef<number | undefined>(undefined);
  const active = useRef(true);
  const inFlight = useRef(false);
  const dirty = useRef(false);
  const lastFetch = useRef(0);
  const request = useRef<AbortController | null>(null);
  const refreshRef = useRef<() => void>(() => {});
  const scheduleRefresh = useCallback(() => {
    dirty.current = true;
    if (!active.current || inFlight.current || timer.current !== undefined) return;
    timer.current = window.setTimeout(() => {
      timer.current = undefined;
      if (!active.current) return;
      inFlight.current = true; dirty.current = false; lastFetch.current = Date.now();
      const abort = new AbortController(); request.current = abort;
      api<RunDetail>(`/runs/${runId}`, { signal: abort.signal }).then((data) => {
        if (!abort.signal.aborted && active.current) { setDetail(data); setError(null); }
      }).catch((exc) => { if (!abort.signal.aborted && active.current) setError(errorText(exc)); }).finally(() => {
        inFlight.current = false;
        if (dirty.current && active.current) refreshRef.current();
      });
    }, Math.max(0, 1000 - (Date.now() - lastFetch.current)));
  }, [runId]);
  refreshRef.current = scheduleRefresh;
  const live = detail ? !TERMINAL.has(detail.run.status) : null;
  const { facts: finalFacts } = useFinalReview(runId, detail?.run.status ?? '', live === false);
  const { events, connected, reconnects, error: streamError, retry } = useEvents(runId, scheduleRefresh, live);
  useEffect(() => {
    active.current = true; scheduleRefresh();
    return () => { active.current = false; window.clearTimeout(timer.current); timer.current = undefined; request.current?.abort(); };
  }, [scheduleRefresh]);
  useEffect(() => {
    if (!live) return;
    const poll = window.setInterval(scheduleRefresh, 4000);
    return () => window.clearInterval(poll);
  }, [live, connected, scheduleRefresh]);
  useEffect(() => {
    if (!scrollbox.current) return;
    if (follow.current) { scrollbox.current.scrollTop = scrollbox.current.scrollHeight; setNewActivity(false); }
    else if (events.length) setNewActivity(true);
  }, [events.length, detail?.run.status]);
  const changed = () => { scheduleRefresh(); onChanged(); if (live === false) retry(); };
  const openDetails = (next: typeof tab) => { setTab(next); setDrawer(true); };
  const control = async (action: 'pause' | 'resume') => {
    if (busy) return;
    setBusy(true);
    try { await post(`/runs/${runId}/${action}`, {}); changed(); }
    catch (exc) { setError(`${action === 'pause' ? '暂停' : '继续'}失败：${errorText(exc)}`); scheduleRefresh(); }
    finally { setBusy(false); }
  };
  const cancel = async () => {
    if (busy) return;
    setBusy(true);
    try { await post(`/runs/${runId}/cancel`, {}); changed(); }
    catch (exc) { setError(`取消失败：${errorText(exc)}`); scheduleRefresh(); }
    finally { setBusy(false); }
  };
  if (!detail) return <div className="run-loading">{error ? <><p role="alert">任务读取失败：{error}</p><button className="btn" onClick={scheduleRefresh}>重新加载</button></> : <><LoaderCircle size={24} className="spin" /><p>正在恢复审计会话…</p></>}</div>;
  const { run } = detail;
  const paused = run.status === 'paused';
  const summary = executionSummary(detail);
  const pauseSettling = paused && summary !== null && summary.phase !== 'paused';
  const executing = run.status === 'running' || run.status === 'pending';
  const statusLabel = resultStatus(detail, finalFacts);
  const statusTone = statusLabel === '审计未完成' || statusLabel === '执行已结束' ? 'inconclusive' : run.status;
  const frozenPolicy = frozenTaskPolicy(run.task_spec);
  return <section className="run-workspace" data-run-id={run.id}>
    <header className="conversation-header"><div className="conversation-heading"><h1 title={run.task_spec?.objective}>{run.task_spec?.objective ?? run.snapshot_name}</h1><div className="conversation-meta"><span className={`chip chip-${statusTone}`}><span className={`status-dot status-${statusTone}`} />{pauseSettling ? '正在暂停' : statusLabel}</span>{run.project_id ? <a href={sourceHref(run.project_id)}>{detail.project?.name ?? run.project_name ?? run.snapshot_name}</a> : <span>{run.snapshot_name}</span>}</div></div><div className="conversation-actions">
      {executing && <button className="btn" disabled={busy} onClick={() => void control('pause')}><Pause size={13} />暂停运行</button>}
      {paused && <button className="btn btn-primary" disabled={busy || pauseSettling} onClick={() => void control('resume')}><Play size={13} />继续运行</button>}
      {TERMINAL.has(run.status) && <button className="btn" onClick={() => openDetails('report')}>查看报告</button>}
      <button className="btn" onClick={() => openDetails('overview')}><PanelRightOpen size={16} /><span>审计详情</span></button>
      <details className="run-more" onKeyDown={(event) => { if (event.key === 'Escape') { event.currentTarget.open = false; event.currentTarget.querySelector('summary')?.focus(); } }}><summary className="btn"><MoreHorizontal size={16} />更多</summary><div className="run-more-menu">
        <button className="btn" onClick={() => onNewTask(run)}><Plus size={14} />基于此任务新建</button>
        {live && <button className="btn btn-danger" disabled={busy} onClick={() => void cancel()}><Square size={13} />{busy ? '取消中…' : '停止审计'}</button>}
        <DeleteRunButton run={run} />
      </div></details>
    </div></header>
    <div className="chat-scroll" ref={scrollbox} onFocusCapture={() => { follow.current = false; }} onClickCapture={(event) => { if ((event.target as Element).closest('button, a, summary')) follow.current = false; }} onScroll={() => { const box = scrollbox.current; if (box) { follow.current = box.scrollHeight - box.scrollTop - box.clientHeight < 100; if (follow.current) setNewActivity(false); } }}>
      <div className="chat-content">
        <div className="session-date">{localDate(run.created_at)}</div>
        <article className="user-message"><div className="message-label">你 <span>审计任务</span></div><div className="user-bubble">
          <button className="message-attachment" onClick={() => openDetails('overview')}><FileArchive size={24} /><span><strong>{run.snapshot_name}</strong><small>{scopeFileCount(run, detail.project_map)} 个可读文件 · 冻结项目快照</small></span><ArrowUpRight size={16} /></button>
          <CompactText text={run.task_spec?.objective ?? run.prompt_text ?? '历史审计任务'} lines={3} label="任务目标" />
          <Disclosure title="任务要求与策略">
          {run.task_spec && <><div className="result-actions" aria-label="已冻结的审计策略"><span className="chip">{frozenPolicy.mode}</span><span className="chip">{frozenPolicy.baseline}</span><span className="chip">{frozenPolicy.workflow}</span>{run.task_spec.exploration_policy === 'exhaustive-v1' && <span className="chip">{frozenPolicy.exploration}</span>}</div><p className="field-hint">{frozenPolicy.baselineDescription}</p></>}
          {run.task_spec?.success_criteria && <LongContent value={run.task_spec.success_criteria} label="验收目标" />}
          {run.task_spec?.continuation && <p className="small muted">本次继承已有证据并独立使用新增预算，<a href={`#run/${run.task_spec.continuation.parent_run_id}`}>查看原审计</a>。</p>}
          </Disclosure>
        </div></article>
        <article className="assistant-message"><div className="assistant-avatar"><ShieldCheck size={20} /></div><div className="assistant-body"><div className="message-label"><BrandWordmark compact /> <span>源码审计助手</span></div>
          <ExecutionStatus detail={detail} compact />
          <ActivityStream events={events} detail={detail} connected={connected} reconnects={reconnects} onOpenLogs={() => openDetails('logs')} onInspect={() => { follow.current = false; }} />
          {streamError && <div className="error-box" role="alert">轨迹读取失败：{streamError} <button className="text-button" onClick={retry}>重新读取</button></div>}
          {error && <div className="error-box" role="alert">{error}</div>}
          {run.error && !error && !events.some((event) => event.kind === 'run_failed') && <div className="error-box" role="alert"><CompactText text="审计执行遇到异常，已保存当前记录。" /><button className="text-button" onClick={() => openDetails('overview')}>查看错误详情</button></div>}
          {TERMINAL.has(run.status) && <RunResult detail={detail} onChanged={changed} onDetails={openDetails} />}
        </div></article>
      </div>
    </div>
    {newActivity && <button className="new-activity-button" onClick={() => { follow.current = true; scrollbox.current?.scrollTo({ top: scrollbox.current.scrollHeight, behavior: 'smooth' }); setNewActivity(false); }}><ArrowDown size={15} />有新活动</button>}
    {drawer && <Overlay title="审计详情" onClose={() => setDrawer(false)} drawer className="run-details"><div className="drawer-context"><strong>{run.snapshot_name}</strong><span className={`chip chip-${statusTone}`}>{statusLabel}</span></div><div className="tabs" role="tablist" aria-label="审计详情视图">{([{ key: 'overview', label: '项目与任务图' }, { key: 'findings', label: '发现与验证' }, { key: 'defence', label: '防御评分' }, { key: 'report', label: '结果报告' }, { key: 'logs', label: '执行日志' }] as const).map((item) => <button key={item.key} role="tab" id={`tab-${item.key}`} aria-selected={tab === item.key} aria-controls={`panel-${item.key}`} className={`tab${tab === item.key ? ' active' : ''}`} onClick={() => setTab(item.key)}>{item.label}</button>)}</div><div className="drawer-body" role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>{tab === 'overview' ? <>{run.error && <LongContent label="运行错误" value={run.error} />}<ExecutionStatus detail={detail} /><HostSummary detail={detail} /><div className="panel panel-body grid"><LongContent label="运行与来源" value={{ run_id: run.id, snapshot_id: run.snapshot_id, snapshot_name: run.snapshot_name, project_id: run.project_id }} />{run.project_id && <div className="result-actions"><a href={sourceHref(run.project_id, 'findings')}>项目漏洞台账</a><a href={`${sourceHref(run.project_id, 'archives')}&snapshot=${encodeURIComponent(run.snapshot_id)}`}>ZIP 与源码</a></div>}<RunSnapshot snapshotId={run.snapshot_id} /><LongContent label="冻结审计范围" value={scopeLabel(run, detail.project_map)} /><LongContent label="完整冻结策略" value={run.task_spec ?? run.poc_policy} /><LongContent label="模型与连接档案" value={run.model_profile ?? { model: run.model }} /></div><Overview detail={detail} events={events} /></> : tab === 'findings' ? <FindingsView detail={detail} snapshotId={run.snapshot_id} /> : tab === 'defence' ? <DefencePanel defence={detail.defence} /> : tab === 'logs' ? <Timeline events={events} detail={detail} compact /> : <ReportView runId={runId} detail={detail} onChanged={changed} />}</div><div className="drawer-downloads"><ReportDownloads runId={runId} status={run.status} /></div></Overlay>}
  </section>;
}
