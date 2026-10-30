import { useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { api, errorText, post } from '../api';
import type { ModelProfile, Run } from '../types';
import { runLabel, localDate } from '../status';
import { Overlay } from './Overlay';

type Mode = 'poc_review' | 'review' | 'audit';
const STATUS_LABELS: Record<string, string> = { inconclusive: '未决', unverified: '未验证', stale: '结论已更新', environment_unavailable: '环境不可用', rejected: '验证未通过', not_applicable: '不适用' };
interface Options {
  available: boolean; reason: string; active_run_ids: string[];
  retestable_count: number; pending_review_count: number;
  model_profiles?: ModelProfile[]; selected_profile_id?: string | null;
  continuations?: { id: string; status: Run['status']; created_at: string }[];
  items: { finding_id: string; title: string; verification_status: string; can_retest: boolean }[];
}

export function ContinueAuditButton({ run, onChanged }: { run: Run; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  if (run.task_spec?.orchestration_policy !== 'host-queue-v1') return null;
  return <><button className="btn btn-primary" onClick={() => setOpen(true)}><RefreshCw size={14} />复测与继续审计</button>
    {open && <ContinueAudit run={run} onClose={() => setOpen(false)} onChanged={onChanged} />}</>;
}

function ContinueAudit({ run, onClose, onChanged }: { run: Run; onClose: () => void; onChanged: () => void }) {
  const originalModelUnavailable = run.model.trim().toLowerCase() === 'ark-code-latest';
  const [options, setOptions] = useState<Options | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<Mode>('poc_review');
  const [profileId, setProfileId] = useState('current');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [requestId] = useState(() => typeof crypto.randomUUID === 'function' ? crypto.randomUUID()
    : `continue-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`);
  const [responses, setResponses] = useState(256);
  const [tools, setTools] = useState(2048);
  const [seconds, setSeconds] = useState(1800);
  const [pocSeconds, setPocSeconds] = useState(600);
  const [jobs, setJobs] = useState(12);
  const [execute, setExecute] = useState(60);
  const [conclude, setConclude] = useState(3);
  const [sessionPolicy, setSessionPolicy] = useState('session-queue-v1');
  const sdk = run.poc_policy?.runtime === 'claude_sdk';
  const queued = sdk && sessionPolicy === 'session-queue-v1';
  useEffect(() => {
    let active = true;
    let timedOut = false;
    const abort = new AbortController();
    const timer = window.setTimeout(() => { timedOut = true; abort.abort(); }, 10000);
    setOptions(null); setError('');
    api<Options>(`/runs/${run.id}/continuation`, { signal: abort.signal }).then(value => {
      if (!active || abort.signal.aborted) return;
      setError('');
      setOptions(value); setSelected(new Set(value.items.filter(i => i.can_retest).map(i => i.finding_id)));
      setProfileId(value.selected_profile_id || 'current');
      if (!value.retestable_count) setMode('review');
    }).catch(exc => {
      if (!active) return;
      setError(timedOut ? '复测配置读取超时，请关闭后重试。' : errorText(exc));
    })
      .finally(() => window.clearTimeout(timer));
    // Cleanup (including StrictMode's extra mount) is cancellation, not a timeout.
    return () => { active = false; window.clearTimeout(timer); abort.abort(); };
  }, [run.id]);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true); setError('');
    try {
      const next = await post<Run>(`/runs/${run.id}/continuation`, {
        request_id: requestId, mode, model_profile_id: profileId, finding_ids: mode === 'review' ? [] : [...selected],
        run_limits: { responses, tools, seconds },
        ...(mode !== 'review' ? { poc: { session_policy: sessionPolicy, max_seconds: pocSeconds, max_jobs: jobs, execute_requests: execute, conclude_requests: conclude } } : {}),
      });
      onChanged(); onClose(); window.location.hash = `#run/${next.id}`;
    } catch (exc) { setError(errorText(exc)); setBusy(false); }
  };
  return <Overlay title="复测与继续审计" onClose={() => { if (!busy) onClose(); }}>
    <form className="overlay-body grid" onSubmit={event => void submit(event)}>
      <p className="small muted">基于原 ZIP 和已保存证据创建关联任务，新增预算单独计时。原审计、用量及冻结报告保留；已完成验证默认复用。</p>
      {options ? <>
        {!!options.continuations?.length && <div className="grid"><strong className="small">关联继续任务</strong>{options.continuations.map(item => <a key={item.id} href={`#run/${item.id}`} onClick={onClose} className="small">{item.id.slice(0, 8)} · {runLabel(item.status)} · {localDate(item.created_at)}</a>)}</div>}
        {!options.available && <div role="alert" className="error-box">{options.reason}{options.active_run_ids.map(id => <a key={id} href={`#run/${id}`} onClick={onClose}>查看继续任务 {id.slice(0, 8)}</a>)}</div>}
        <label className="field">审计与终审模型档案<select value={profileId} onChange={e => setProfileId(e.target.value)} disabled={busy}>
          {!options.selected_profile_id && <option value="current">使用配置页当前档案</option>}
          {options.model_profiles?.map(profile => <option key={profile.id} value={profile.id} disabled={!!profile.unavailable_reason || profile.model.trim().toLowerCase() === 'ark-code-latest'}>{profile.label} · {profile.model}{profile.unavailable_reason || profile.model.trim().toLowerCase() === 'ark-code-latest' ? '（已停用）' : profile.id === options.selected_profile_id ? '（当前）' : ''}</option>)}
          <option value="original" disabled={originalModelUnavailable}>沿用原任务冻结档案 · {run.model}{originalModelUnavailable ? '（已停用）' : ''}</option>
        </select></label>
        <p className="small muted">新任务默认采用配置页当前档案，创建后冻结。POC SDK 使用其独立配置的模型与网关，不随此选项切换。</p>
        <label className="field">继续范围<select value={mode} onChange={e => setMode(e.target.value as Mode)} disabled={busy}>
          <option value="poc_review">复测未决 POC，再完成终审</option><option value="review">仅补终审，不执行新 POC</option><option value="audit">继续源码审计、验证与终审</option>
        </select></label>
        <p className="small muted">可复测 {options.retestable_count} 项 · 原运行待审或需重新处置 {options.pending_review_count} 项。所选复测项及关联结论将在新任务中重新终审；追加预算不保证漏洞成立或全部完成。</p>
        {mode !== 'review' && <fieldset className="grid" disabled={busy}><legend>选择复测项目</legend>
          <div className="result-actions"><button className="text-button" type="button" onClick={() => setSelected(new Set(options.items.filter(i => i.can_retest).map(i => i.finding_id)))}>全选未决项</button><button className="text-button" type="button" onClick={() => setSelected(new Set())}>清空选择</button></div>
          <div style={{ maxHeight: 230, overflowY: 'auto' }} className="grid">{options.items.filter(i => i.can_retest).map(item => <label key={item.finding_id} style={{ display: 'flex', gap: 8, alignItems: 'start' }}>
            <input type="checkbox" checked={selected.has(item.finding_id)} onChange={e => setSelected(previous => { const next = new Set(previous); if (e.target.checked) next.add(item.finding_id); else next.delete(item.finding_id); return next; })} />
            <span className="small">{item.title}<span className="muted"> · {STATUS_LABELS[item.verification_status] || item.verification_status}</span></span>
          </label>)}</div>
        </fieldset>}
        <fieldset className="grid" disabled={busy}><legend>新增整次预算</legend>
          <label className="field">模型请求上限<input type="number" min={mode === 'review' ? 3 : 8} max={4096} required value={responses} onChange={e => setResponses(e.target.valueAsNumber)} /></label>
          <label className="field">工具调用上限<input type="number" min={0} max={32768} required value={tools} onChange={e => setTools(e.target.valueAsNumber)} /></label>
          <label className="field">总时长（秒）<input type="number" min={30} max={14400} required value={seconds} onChange={e => setSeconds(e.target.valueAsNumber)} /></label>
        </fieldset>
        {mode !== 'review' && <fieldset className="grid" disabled={busy}><legend>POC 执行设置</legend>
          {sdk && <label className="field">验证方式<select value={sessionPolicy} onChange={e => setSessionPolicy(e.target.value)}>
            <option value="session-queue-v1">持续会话队列 · 逐项发布</option><option value="staged-v1">旧版逐项执行／结论</option>
          </select></label>}
          {queued && <p className="small muted">同一 SDK 会话顺序处理所选任务，每项结论立即保存。单项耗时只提醒；请求与时间使用整次及 POC 阶段预算，不再按漏洞切分 75% 时间。各项 Cookie 和证据独立。</p>}
          <label className="field">{queued ? '单项耗时提醒（秒）' : '单项验证时长（秒）'}<input type="number" min={30} max={3600} required value={pocSeconds} onChange={e => setPocSeconds(e.target.valueAsNumber)} /></label>
          <label className="field">单项作业上限<input type="number" min={1} max={32} required value={jobs} onChange={e => setJobs(e.target.valueAsNumber)} /></label>
          {!queued && <><label className="field">SDK 实验请求上限<input type="number" min={1} max={512} required value={execute} onChange={e => setExecute(e.target.valueAsNumber)} /></label>
          <label className="field">SDK 结论请求上限<input type="number" min={3} max={16} required value={conclude} onChange={e => setConclude(e.target.valueAsNumber)} /></label>
          </>}
        </fieldset>}
        <p className="small muted">启动后会使用模型预算。复测沿用原靶场重置政策并可能修改靶场数据；每项使用新的验证上下文，未确认结束的旧作业仍受 runner 占用保护。</p>
        <button className="btn btn-primary" type="submit" disabled={busy || !options.available || (mode === 'poc_review' && selected.size === 0)}>{busy ? '正在创建…' : '创建并启动继续任务'}</button>
      </> : !error && <p role="status">正在读取未决项目…</p>}
      {error && <div className="error-box" role="alert">{error}</div>}
    </form>
  </Overlay>;
}
