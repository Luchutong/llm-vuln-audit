import { useEffect, useRef, useState } from 'react';
import { Download } from 'lucide-react';
import { api, downloadUrl, errorText } from '../api';
import { useFinalReview } from '../useFinalReview';

type ReportView = 'audit' | 'vulnerabilities' | 'accepted' | 'archive';
type Source = { run_id: string; canonical_id: string; path: string; current: boolean; project_revision: number; assessment_revision: number; snapshot_name?: string };

export function ReportDownloads({ runId, status, compact = false, hasAccepted = false }: { runId: string; status: string; compact?: boolean; hasAccepted?: boolean }) {
  const [view, setView] = useState<ReportView>('audit');
  const selected = compact && hasAccepted ? 'accepted' : view;
  const terminal = ['completed', 'inconclusive', 'unreachable', 'cancelled', 'failed', 'interrupted'].includes(status);
  return <div className="grid" aria-label="审计报告下载">
    {!compact && <label className="field"><span className="field-label">报告内容</span><select aria-label="报告内容" value={view} onChange={e => setView(e.target.value as ReportView)}><option value="audit">审计执行报告</option><option value="accepted">已确认漏洞报告</option><option value="vulnerabilities">漏洞审计报告汇编（含待审）</option><option value="archive">历史归档原件</option></select></label>}
    {terminal ? <DownloadButtons path={`/runs/${encodeURIComponent(runId)}/report?view=${selected}`} label={selected === 'accepted' ? '已确认漏洞报告' : selected === 'vulnerabilities' ? '漏洞汇编' : selected === 'archive' ? '归档原件' : '审计报告'} compact={compact} /> : <p className="muted small">运行结束后可下载冻结报告。</p>}
  </div>;
}

function DownloadButtons({ path, label, compact = false }: { path: string; label: string; compact?: boolean }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [retryFormat, setRetryFormat] = useState('markdown');
  const controller = useRef<AbortController | null>(null);
  useEffect(() => { setError(null); setBusy(false); return () => controller.current?.abort(); }, [path]);
  const download = async (format: string) => {
    controller.current?.abort();
    const request = new AbortController(); controller.current = request;
    setBusy(true); setError(null); setRetryFormat(format);
    try {
      const response = await fetch(downloadUrl(`${path}${path.includes('?') ? '&' : '?'}format=${format}`), { signal: request.signal });
      if (!response.ok) {
        const data = await response.json().catch(() => null);
        throw new Error(data?.detail?.message ?? (typeof data?.detail === 'string' ? data.detail : `下载失败（${response.status}）`));
      }
      const blob = await response.blob();
      if (request.signal.aborted) return;
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement('a'); link.href = objectUrl;
      link.download = /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') ?? '')?.[1] ?? `audit-report.${format === 'markdown' ? 'md' : format}`;
      document.body.appendChild(link); link.click(); link.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    } catch (exc) { if (!request.signal.aborted) setError(errorText(exc)); }
    finally { if (!request.signal.aborted) setBusy(false); }
  };
  return <div><div className="result-actions">{(compact ? ['markdown'] : ['markdown', 'json', 'zip']).map(format => <button type="button" key={format} className="btn" disabled={busy} onClick={() => void download(format)} aria-label={`下载${label} ${format}`}><Download size={14} />{compact ? label : format === 'markdown' ? 'Markdown' : format === 'zip' ? '证据包' : 'JSON'}</button>)}</div>{error && <p className="error-box small" role="alert">{error} <button type="button" className="text-button" disabled={busy} onClick={() => void download(retryFormat)}>重试下载</button></p>}</div>;
}

export function FindingReportDownloads({ runId, status, findingId, revision, assessmentRevision }: { runId: string; status: string; findingId: string; revision: number; assessmentRevision?: number }) {
  const [historical, setHistorical] = useState(false);
  const { facts, state, retry } = useFinalReview(runId, status, !['pending', 'running', 'paused'].includes(status));
  const entry = facts?.canonical_findings.find(item => item.current_claim_ref?.finding_id === findingId || item.source_record_refs?.some(ref => ref.finding_id === findingId));
  if (state === 'error') return <p className="small">漏洞报告来源读取失败。<button className="text-button" onClick={retry}>重试</button></p>;
  if (!entry) return <p className="muted small">{state === 'loading' ? '正在解析冻结报告来源…' : '当前发现暂无冻结漏洞报告。'}</p>;
  const current = entry.current_claim_ref?.finding_id === findingId && entry.current_claim_ref.revision === revision && assessmentRevision !== undefined && entry.assessment_revision === assessmentRevision;
  if (!current && !historical) return <p className="muted small">当前版本暂无匹配的冻结报告。<button className="text-button" onClick={() => setHistorical(true)}>选择该任务历史冻结版本</button></p>;
  return <div className="grid"><span className="muted small">{current ? '冻结报告' : '历史冻结报告'} · 结论第 {entry.current_claim_ref?.revision ?? '未知'} 版 · 评分第 {entry.assessment_revision ?? '未知'} 版</span><DownloadButtons path={`/runs/${encodeURIComponent(runId)}/canonical-findings/${encodeURIComponent(entry.canonical_id)}/report`} label="单漏洞报告" /></div>;
}

export function LedgerReportDownloads({ findingId }: { findingId: string }) {
  const [data, setData] = useState<{ items: Source[]; current_available: boolean } | null>(null);
  const [selected, setSelected] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [attempt, retry] = useState(0);
  useEffect(() => {
    const controller = new AbortController(); setData(null); setSelected(''); setError(null);
    api<{ items: Source[]; current_available: boolean }>(`/project-findings/${encodeURIComponent(findingId)}/reports`, { signal: controller.signal }).then(value => {
      if (controller.signal.aborted) return;
      setData(value); setSelected(value.items.find(item => item.current)?.path ?? '');
    }).catch(exc => { if (!controller.signal.aborted) setError(errorText(exc)); });
    return () => controller.abort();
  }, [findingId, attempt]);
  return <section className="panel panel-body grid" aria-label="单漏洞报告下载"><strong>单漏洞审计报告</strong>{error ? <p role="alert">{error} <button className="text-button" onClick={() => retry(value => value + 1)}>重新加载</button></p> : !data ? <p className="muted small">正在读取冻结报告来源…</p> : <>{!data.current_available && <p className="muted small">当前版本暂无冻结报告。可选择历史任务，下载其当时的结论与评分。</p>}{data.items.length > 0 && <label className="field"><span className="field-label">报告来源版本</span><select aria-label="报告来源版本" value={selected} onChange={event => setSelected(event.target.value)}><option value="">选择冻结来源</option>{data.items.map(item => <option key={item.path} value={item.path}>{item.current ? '当前版本' : '历史版本'} · 结论 {item.project_revision} / 评分 {item.assessment_revision} · {item.snapshot_name ?? '源码包'} · {item.run_id.slice(0, 8)}</option>)}</select></label>}{selected && <DownloadButtons path={selected} label="单漏洞报告" />}</>}</section>;
}
