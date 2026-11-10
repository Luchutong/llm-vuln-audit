import { useState } from 'react';
import { post, errorText } from '../api';
import type { Run } from '../types';
import { Overlay } from './Overlay';

const PRESETS = [
  { id: 'small', label: '小幅补充', responses: 64, tools: 512, minutes: 30 },
  { id: 'standard', label: '继续一轮', responses: 128, tools: 1024, minutes: 60 },
  { id: 'deep', label: '深入补查', responses: 256, tools: 2048, minutes: 90 },
] as const;

export function BudgetGrantButton({ run, onChanged, disabled }: { run: Run; onChanged: () => void; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  return <><button className="btn" disabled={disabled} onClick={() => setOpen(true)}>追加预算并继续</button>
    {open && <BudgetGrant run={run} onClose={() => setOpen(false)} onChanged={onChanged} />}</>;
}

function BudgetGrant({ run, onClose, onChanged }: { run: Run; onClose: () => void; onChanged: () => void }) {
  const [preset, setPreset] = useState<string>('standard');
  const [responses, setResponses] = useState<number>(128);
  const [tools, setTools] = useState<number>(1024);
  const [minutes, setMinutes] = useState<number>(60);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [requestId] = useState(() => typeof crypto.randomUUID === 'function' ? crypto.randomUUID()
    : `budget-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true); setError('');
    try {
      await post(`/runs/${run.id}/budget`, { request_id: requestId, responses, tools,
        seconds: minutes * 60, resume: true });
      onChanged(); onClose();
    } catch (exc) { setError(errorText(exc)); setBusy(false); }
  };
  return <Overlay title="追加预算并继续当前记录" onClose={() => { if (!busy) onClose(); }}>
    <form className="overlay-body grid" onSubmit={event => void submit(event)}>
      <p className="small muted">选择新增额度，接着完成剩余任务。已有成果和剩余额度继续保留，系统自动安排后续流程。</p>
      <div className="budget-presets" role="group" aria-label="追加额度预设">
        {PRESETS.map(option => <button key={option.id} type="button" className="budget-preset" aria-pressed={preset === option.id} disabled={busy} onClick={() => {
          setPreset(option.id); setResponses(option.responses); setTools(option.tools); setMinutes(option.minutes); setError('');
        }}><strong>{option.label}{option.id === 'standard' && <span className="small muted"> · 推荐</span>}</strong>
          <span>{option.responses} 次请求</span><span>{option.tools} 次工具 · {option.minutes} 分钟</span>
        </button>)}
      </div>
      <details className="budget-tuning"><summary>微调额度{preset === 'custom' ? ' · 已自定义' : ''}</summary>
        <fieldset className="grid" disabled={busy}><legend className="sr-only">自定义新增额度</legend>
          <label className="field">新增模型请求<input type="number" required min={0} max={4096} value={responses} onChange={e => { setPreset('custom'); setResponses(e.target.valueAsNumber); }} /></label>
          <label className="field">新增工具调用<input type="number" required min={0} max={32768} value={tools} onChange={e => { setPreset('custom'); setTools(e.target.valueAsNumber); }} /></label>
          <label className="field">新增时长（分钟）<input type="number" required min={0} max={240} step={1} value={minutes} onChange={e => { setPreset('custom'); setMinutes(e.target.valueAsNumber); }} /></label>
          <p className="small muted">0 表示该项不增加。</p>
        </fieldset>
      </details>
      <p className="small">本次新增：<strong>{responses} 次请求 · {tools} 次工具 · {minutes} 分钟</strong></p>
      {run.execution_summary?.run_remaining && <p className="small muted">当前已有剩余 {run.execution_summary.run_remaining.responses} 次请求，继续合并使用。额度是上限，完成任务即可提前结束。</p>}
      {error && <p className="error-box" role="alert">{error}</p>}
      <button className="btn btn-primary" disabled={busy || ![responses, tools, minutes].every(n => Number.isFinite(n) && n >= 0) || !(responses || tools || minutes)} type="submit">{busy ? '正在保存…' : '追加并继续'}</button>
    </form>
  </Overlay>;
}
