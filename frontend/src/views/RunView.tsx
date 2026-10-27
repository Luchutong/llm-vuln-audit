import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowDown, ArrowUpRight, CircleHelp, Download, FileArchive, GitBranch, LoaderCircle, PanelRightOpen, Plus, Pause, Play, ShieldCheck, Square, Wrench } from 'lucide-react';
import { api, downloadUrl, errorText, post } from '../api';
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
import { localDate, runLabel, TERMINAL } from '../status';
import { sourceHref } from '../routes';
import { activeVulnerabilityFindings, sourceObservations, vulnerabilityFindings } from '../results';
import { ExecutionStatus, HostSummary } from '../components/ExecutionStatus';
import { DefencePanel } from '../components/DefencePanel';
import { executionSummary } from '../execution';
import { SeverityBadge } from '../components/CvssPanel';
import { frozenTaskPolicy } from '../taskDraft';

const SCENARIO_LABELS: Record<string, string> = { sqli: 'SQL 注入', xss_r: '反射型 XSS', command_injection: '命令注入' };

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
  const tasks = detail.tasks ?? [];
  const goal = detail.goal ?? detail.goals?.[0];
  const activeWorkers = new Set(tasks.filter((item) => item.state === 'running').map((item) => item.claimed_by).filter(Boolean)).size;
  const completed = tasks.filter((item) => ['completed', 'cancelled', 'blocked'].includes(item.state)).length;
  const findings = vulnerabilityFindings(detail);
  const evidenceFindings = activeVulnerabilityFindings(detail);
  const observations = sourceObservations(detail);
  const reason = goal?.terminal_reason ?? detail.planner?.terminal_reason;
  const paused = run.status === 'paused';
  const summary = executionSummary(detail);
  const pauseSettling = paused && summary !== null && summary.phase !== 'paused';
  const executing = run.status === 'running' || run.status === 'pending';
  const achieved = goal?.status === 'met';
  const reviews = detail.verification_reviews ?? [];
  const contested = reviews.filter((item) => item.decision !== 'confirmed').length;
  const statusLabel = runLabel(run.status, goal?.status);
  const frozenPolicy = frozenTaskPolicy(run.task_spec);
  return <section className="run-workspace">
    <header className="conversation-header"><div className="conversation-heading"><span className="eyebrow">AUDIT SESSION</span><h1 title={run.task_spec?.objective}>{run.task_spec?.objective ?? run.snapshot_name}</h1><div className="conversation-meta"><span className={`chip chip-${run.status}`}><span className={`status-dot status-${run.status}`} />{statusLabel}</span>{run.task_spec?.scenario && <span className="chip" title="分场景专属运行：宿主要求穷尽该类别全部方向后才允许收束">{SCENARIO_LABELS[run.task_spec.scenario] ?? run.task_spec.scenario} · 分场景穷尽</span>}<span>{run.snapshot_name}</span><span className="mono" title="实际 ZIP 快照">ZIP {run.snapshot_id.slice(0, 8)}</span><span className="mono">{run.id.slice(0, 8)}</span>{run.project_id && <><a href={sourceHref(run.project_id)}>{detail.project?.name ?? run.project_name ?? '所属源码包'}</a><a href={sourceHref(run.project_id, 'findings')}>项目漏洞台账</a><a href={`${sourceHref(run.project_id, 'archives')}&snapshot=${encodeURIComponent(run.snapshot_id)}`}>ZIP 与源码</a></>}</div></div><div className="conversation-actions"><DeleteRunButton run={run} />{executing && <button className="btn" disabled={busy} onClick={() => void control('pause')}><Pause size={13} />暂停运行</button>}{paused && <button className="btn btn-primary" disabled={busy || pauseSettling} onClick={() => void control('resume')}><Play size={13} />继续运行</button>}{live && <button className="btn btn-danger" disabled={busy} onClick={() => void cancel()}><Square size={13} />{busy ? '取消中…' : '停止审计'}</button>}<button className="btn" onClick={() => openDetails('overview')}><PanelRightOpen size={16} /><span>审计详情</span></button></div></header>
    <div className="chat-scroll" ref={scrollbox} onScroll={() => { const box = scrollbox.current; if (box) { follow.current = box.scrollHeight - box.scrollTop - box.clientHeight < 100; if (follow.current) setNewActivity(false); } }}>
      <div className="chat-content">
        <div className="session-date">{localDate(run.created_at)}</div>
        <article className="user-message"><div className="message-label">你 <span>审计任务</span></div><div className="user-bubble">
          <button className="message-attachment" onClick={() => openDetails('overview')}><FileArchive size={24} /><span><strong>{run.snapshot_name}</strong><small>{scopeFileCount(run, detail.project_map)} 个可读文件 · 冻结项目快照</small></span><ArrowUpRight size={16} /></button>
          <LongContent value={run.task_spec?.objective ?? run.prompt_text ?? '历史审计任务'} label="审计任务" />
          {run.task_spec && <><div className="result-actions" aria-label="已冻结的审计策略"><span className="chip">{frozenPolicy.mode}</span><span className="chip">{frozenPolicy.baseline}</span></div><p className="field-hint">{frozenPolicy.baselineDescription}</p></>}
          {run.task_spec?.success_criteria && <LongContent value={run.task_spec.success_criteria} label="验收目标" />}
        </div></article>
        <article className="assistant-message"><div className="assistant-avatar"><ShieldCheck size={20} /></div><div className="assistant-body"><div className="message-label"><BrandWordmark compact /> <span>源码审计助手</span></div>
          <p className="assistant-intro">{paused ? pauseSettling ? '正在等待在途执行静止，静止后可继续审计。' : '审计已暂停，任务前沿和回合号均已保存，可随时继续。' : run.status === 'pending' ? '审计任务已加入队列，等待 Planner 建立项目级任务图。' : live ? '正在围绕你的目标审计源码。下方展示已保存的规划、工具调用与证据过程。' : '审计执行记录已恢复。你可以展开工具调用，或打开详情复核源码证据。'}</p>
          <div className="run-progress"><span><GitBranch size={15} />Planner {detail.planner?.current_round ?? 0} / {detail.planner?.max_rounds ?? run.task_spec?.max_planner_rounds ?? '—'} 回合</span><span><Wrench size={15} />{run.usage.tool_calls} 次工具调用</span><span>{paused ? '已暂停 · 可原样继续' : live ? `${activeWorkers} 个 worker 活跃` : `${completed} / ${tasks.length} 个任务已结算`}</span></div>
          <ExecutionStatus detail={detail} />
          <ActivityStream events={events} detail={detail} connected={connected} reconnects={reconnects} onOpenLogs={() => openDetails('logs')} onInspect={() => { follow.current = false; }} />
          {streamError && <div className="error-box" role="alert">轨迹读取失败：{streamError} <button className="text-button" onClick={retry}>重新读取</button></div>}
          {error && <div className="error-box" role="alert">{error}</div>}
          {run.error && <div className="error-box" role="alert"><LongContent label="运行错误" value={run.error} /></div>}
          {!live && <div className={`result-card${achieved ? ' result-achieved' : ''}`}>
            <div className="result-heading">{achieved ? <ShieldCheck size={22} /> : <CircleHelp size={22} />}<div><span className="eyebrow">AUDIT RESULT</span><h2>{statusLabel}</h2></div></div>
            {reason && <LongContent label="结论依据" value={reason} />}
            <HostSummary detail={detail} />
            <p className="muted small">共保存 {findings.length} 项漏洞候选，其中 {evidenceFindings.length} 项仍被本次运行主张且通过源码证据校验。另有 {observations.length} 条排查记录，不计为漏洞。处置、历史版本及自动验证记录见详情。</p>
            {reviews.length > 0 && <p className="small muted">Planner 比对核实了 {reviews.length} 条自动验证结论，其中 {contested} 条被判为观测不支持。未复核的已验证结论不会被当作收束依据。</p>}
            {detail.defence?.score !== null && detail.defence?.score !== undefined && <div className="panel panel-body grid">
              <DefencePanel defence={detail.defence} compact />
              <button className="text-button" onClick={() => openDetails('defence')}>查看防御评分明细</button>
            </div>}
            {achieved && !evidenceFindings.length && <p className="small muted">历史任务状态沿用原判定；排查记录不表示发现漏洞，也不保证项目安全。</p>}
            {evidenceFindings.slice(0, 3).map((finding) => <button key={finding.id} className="result-finding" onClick={() => openDetails('findings')}><SeverityBadge finding={finding} /><span>{finding.title}</span><ArrowUpRight size={15} /></button>)}
            <div className="result-actions"><button className="btn" onClick={() => openDetails('findings')}>发现与验证<ArrowUpRight size={14} /></button>{observations.length > 0 && <button className="btn" onClick={() => openDetails('findings')}>排查记录 · {observations.length}</button>}<button className="btn" onClick={() => openDetails('report')}>查看报告</button><a className="btn" href={downloadUrl(`/runs/${runId}/report?format=markdown`)}><Download size={14} />Markdown</a></div>
          </div>}
        </div></article>
      </div>
    </div>
    {newActivity && <button className="new-activity-button" onClick={() => { follow.current = true; scrollbox.current?.scrollTo({ top: scrollbox.current.scrollHeight, behavior: 'smooth' }); setNewActivity(false); }}><ArrowDown size={15} />有新活动</button>}
    <footer className="session-footer"><span><ShieldCheck size={14} />任务目标与项目快照已冻结</span><button className="btn" onClick={() => onNewTask(run)}><Plus size={16} />基于此任务新建</button></footer>
    {drawer && <Overlay title="审计详情" onClose={() => setDrawer(false)} drawer className="run-details"><div className="drawer-context"><strong>{run.snapshot_name}</strong><span className={`chip chip-${run.status}`}>{statusLabel}</span></div><div className="tabs" role="tablist" aria-label="审计详情视图">{([{ key: 'overview', label: '项目与任务图' }, { key: 'findings', label: '发现与验证' }, { key: 'defence', label: '防御评分' }, { key: 'report', label: '结果报告' }, { key: 'logs', label: '执行日志' }] as const).map((item) => <button key={item.key} role="tab" id={`tab-${item.key}`} aria-selected={tab === item.key} aria-controls={`panel-${item.key}`} className={`tab${tab === item.key ? ' active' : ''}`} onClick={() => setTab(item.key)}>{item.label}</button>)}</div><div className="drawer-body" role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>{tab === 'overview' ? <><div className="panel panel-body grid"><LongContent label="冻结审计范围" value={scopeLabel(run, detail.project_map)} /><LongContent label="模型与连接档案" value={run.model_profile ?? { model: run.model }} /></div><Overview detail={detail} events={events} /></> : tab === 'findings' ? <FindingsView detail={detail} snapshotId={run.snapshot_id} /> : tab === 'defence' ? <DefencePanel defence={detail.defence} /> : tab === 'logs' ? <Timeline events={events} detail={detail} compact /> : <ReportView runId={runId} detail={detail} onChanged={changed} />}</div><div className="drawer-downloads"><span className="faint small">下载审计工件</span><a className="btn" href={downloadUrl(`/runs/${runId}/report?format=markdown`)}>Markdown</a><a className="btn" href={downloadUrl(`/runs/${runId}/report?format=json`)}>JSON</a><a className="btn" href={downloadUrl(`/runs/${runId}/report?format=zip`)}>证据包</a></div></Overlay>}
  </section>;
}
