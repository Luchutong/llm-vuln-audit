import { createContext, useContext, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { LoaderCircle, Trash2 } from 'lucide-react';
import { ApiError, errorText, post, remove } from '../api';
import type { Prompt, Run, SnapshotSummary } from '../types';
import { cleanupCandidates, promptDeletionBlock, runDeletionBlock, snapshotDeletionBlock } from '../records';
import type { RecordsChange, RunCleanup, RunDeletion } from '../records';
import { Overlay } from './Overlay';
import '../records.css';

type Target = { kind: 'run'; run: Run } | { kind: 'cleanup'; projectId?: string; name?: string }
  | { kind: 'snapshot'; snapshot: SnapshotSummary } | { kind: 'prompt'; prompt: Prompt };
const Context = createContext<{ runs: Run[]; open: (target: Target) => void }>({ runs: [], open: () => {} });

function failureMessage(error: unknown, target: Target): string {
  if (error instanceof ApiError && error.status === 409) {
    if (target.kind === 'run') return '审计状态已变化。请先停止排队或运行中的任务，再重试删除。';
    if (target.kind === 'snapshot') return '此 ZIP 仍被审计引用。请先删除所有相关审计记录，再重试。';
    if (target.kind === 'prompt') return '内置或已被审计引用的提示词不能删除。请刷新记录后重试。';
  }
  return `操作失败：${errorText(error)}`;
}

export function RecordsProvider({ runs, onChanged, children }: { runs: Run[]; onChanged: (change: RecordsChange) => void; children: ReactNode }) {
  const [target, setTarget] = useState<Target | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lock = useRef(false);
  const active = useRef(true);
  const pending = useRef<Target | null>(null);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  useEffect(() => {
    const changed = () => { if (!lock.current) { setTarget(null); pending.current = null; setError(null); } };
    window.addEventListener('hashchange', changed);
    return () => window.removeEventListener('hashchange', changed);
  }, []);
  const open = (next: Target) => { if (!lock.current) { pending.current = next; setTarget(next); setError(null); } };
  const candidates = target?.kind === 'cleanup' ? cleanupCandidates(runs, target.projectId) : [];
  const paused = candidates.filter((run) => run.status === 'paused').length;
  const block = !target ? null : target.kind === 'run' ? runDeletionBlock(runs.find((run) => run.id === target.run.id) ?? target.run)
    : target.kind === 'snapshot' ? snapshotDeletionBlock(target.snapshot, runs)
    : target.kind === 'prompt' ? promptDeletionBlock(target.prompt, runs) : candidates.length ? null : '没有可清理的审计记录。';
  const close = () => { if (!lock.current) { setTarget(null); pending.current = null; setError(null); } };
  const submit = async () => {
    const selected = pending.current;
    if (!selected || lock.current || block) return;
    lock.current = true; setBusy(true); setError(null);
    let change: RecordsChange;
    try {
      if (selected.kind === 'run') {
        const result = await remove<RunDeletion>(`/runs/${encodeURIComponent(selected.run.id)}`);
        const count = Object.values(result.deleted).reduce((sum, value) => sum + value, 0);
        change = { runIds: [result.run_id], projectId: selected.run.project_id, notice: `已删除审计记录及 ${count} 条关联数据，项目漏洞台账保留。` };
      } else if (selected.kind === 'cleanup') {
        const result = await post<RunCleanup>('/runs/cleanup', selected.projectId ? { project_id: selected.projectId } : {});
        change = { runIds: result.runs.map((run) => run.run_id), projectId: selected.projectId, notice: `已清理 ${result.deleted_runs} 次审计记录，排队和运行中的任务已跳过；项目漏洞台账保留。` };
      } else if (selected.kind === 'snapshot') {
        await remove(`/snapshots/${encodeURIComponent(selected.snapshot.id)}`);
        change = { snapshotId: selected.snapshot.id, projectId: selected.snapshot.project_id, notice: `已删除 ZIP 记录「${selected.snapshot.name}」。` };
      } else {
        await remove(`/prompts/${encodeURIComponent(selected.prompt.id)}`);
        change = { promptId: selected.prompt.id, notice: `已删除提示词草稿「${selected.prompt.label}」。` };
      }
      if (active.current) { pending.current = null; setTarget(null); onChanged(change); }
    } catch (exc) {
      if (!active.current) return;
      if (exc instanceof ApiError && exc.status === 404 && selected.kind !== 'cleanup') {
        pending.current = null; setTarget(null);
        onChanged({ notice: '记录已不存在，已刷新列表。', ...(selected.kind === 'run' ? { runIds: [selected.run.id], projectId: selected.run.project_id } : selected.kind === 'snapshot' ? { snapshotId: selected.snapshot.id, projectId: selected.snapshot.project_id } : { promptId: selected.prompt.id }) });
      } else setError(failureMessage(exc, selected));
    } finally { lock.current = false; if (active.current) setBusy(false); }
  };
  const title = target?.kind === 'cleanup' ? '清理审计记录' : target?.kind === 'snapshot' ? '删除 ZIP 记录' : target?.kind === 'prompt' ? '删除提示词草稿' : '删除审计记录';
  return <Context.Provider value={{ runs, open }}>{children}{target && <Overlay title={title} onClose={close} className="records-dialog">
    <div className="overlay-body records-confirm">
      {target.kind === 'run' && <><p>确认删除审计「<strong>{target.run.task_spec?.objective ?? target.run.id}</strong>」？</p><p>将删除本次审计的发现、验证、执行日志及报告记录，无法恢复。所属项目的累计漏洞台账继续保留。</p>{target.run.status === 'paused' && <p className="records-warning">此任务已暂停；删除后无法继续。</p>}</>}
      {target.kind === 'cleanup' && <><p>清理范围：<strong>{target.name ?? '全部源码项目'}</strong></p><p>当前有 {candidates.length} 次可清理审计，其中 {paused} 次已暂停。将删除这些审计的发现、验证及执行记录，无法恢复；排队和运行中的任务会跳过，源码 ZIP 与项目台账保留。</p>{paused > 0 && <p className="records-warning">包含已暂停的任务，清理后将无法继续。</p>}</>}
      {target.kind === 'snapshot' && <><p>确认删除 ZIP 记录「<strong>{target.snapshot.name}</strong>」？</p><p>此 ZIP 将从可选源码列表移除。所属源码项目与累计漏洞台账保留。</p><p className="mono">SHA-256：{target.snapshot.archive_sha256}</p></>}
      {target.kind === 'prompt' && <><p>确认删除提示词草稿「<strong>{target.prompt.label}</strong>」？</p><p>删除后无法恢复。</p></>}
      {block && <p className="records-warning" role="status">{block}</p>}{error && <div className="error-box" role="alert">{error}</div>}
    </div><div className="overlay-footer records-dialog-actions"><button className="btn" disabled={busy} onClick={close}>取消</button><button className="btn btn-danger" aria-label={target.kind === 'cleanup' ? '确认清理' : '确认删除'} aria-busy={busy} disabled={busy || Boolean(block)} onClick={() => void submit()}>{busy ? <LoaderCircle size={15} className="spin" /> : <Trash2 size={15} />}{busy ? '处理中…' : target.kind === 'cleanup' ? '确认清理' : '确认删除'}</button></div>
  </Overlay>}</Context.Provider>;
}

function ActionButton({ label, block, onClick, compact }: { label: string; block: string | null; onClick: () => void; compact?: boolean }) {
  return <span className="record-action" title={block ?? label}><button type="button" className={compact ? 'icon-button record-delete-icon' : 'btn btn-danger'} aria-label={label} disabled={Boolean(block)} onClick={onClick}><Trash2 size={compact ? 14 : 15} />{!compact && label}</button></span>;
}
export function DeleteRunButton({ run, compact = false }: { run: Run; compact?: boolean }) { const { open } = useContext(Context); return <ActionButton label={compact ? `删除审计 ${run.task_spec?.objective ?? run.id}` : '删除审计记录'} block={runDeletionBlock(run)} compact={compact} onClick={() => open({ kind: 'run', run })} />; }
export function CleanupRunsButton({ projectId, name }: { projectId?: string; name?: string }) { const { runs, open } = useContext(Context); return <ActionButton label="清理审计记录" block={cleanupCandidates(runs, projectId).length ? null : '没有可清理的审计记录。'} onClick={() => open({ kind: 'cleanup', projectId, name })} />; }
export function DeleteSnapshotButton({ snapshot }: { snapshot: SnapshotSummary }) { const { runs, open } = useContext(Context); const block = snapshotDeletionBlock(snapshot, runs); return <div className="records-snapshot-delete"><ActionButton label="删除 ZIP 记录" block={block} onClick={() => open({ kind: 'snapshot', snapshot })} />{block && <span className="faint small">{block}</span>}</div>; }
export function DeletePromptButton({ prompt }: { prompt: Prompt }) { const { runs, open } = useContext(Context); const block = promptDeletionBlock(prompt, runs); return <div className="records-prompt-delete"><ActionButton label="删除提示词草稿" block={block} onClick={() => open({ kind: 'prompt', prompt })} />{block && <span className="faint small">{block}</span>}</div>; }
