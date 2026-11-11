import { useEffect, useRef, useState } from 'react';
import { Download } from 'lucide-react';
import { downloadUrl, errorText } from '../api';

export function ReportDownloads({ runId, status }: { runId: string; status: string; compact?: boolean; hasAccepted?: boolean }) {
  const terminal = ['completed', 'inconclusive', 'unreachable', 'cancelled', 'failed', 'interrupted'].includes(status);
  return <div className="grid" aria-label="审计报告下载">
    {terminal ? <DownloadButtons path={`/runs/${encodeURIComponent(runId)}/report?view=report`} label="审计报告" /> : <p className="muted small">运行结束后可下载审计报告及证据包。</p>}
  </div>;
}

function DownloadButtons({ path, label }: { path: string; label: string }) {
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
  return <div><div className="result-actions">{['markdown', 'zip'].map(format => <button type="button" key={format} className="btn" disabled={busy} onClick={() => void download(format)} aria-label={`下载${label} ${format}`}><Download size={14} />{format === 'markdown' ? '审计报告' : '证据包'}</button>)}</div>{error && <p className="error-box small" role="alert">{error} <button type="button" className="text-button" disabled={busy} onClick={() => void download(retryFormat)}>重试下载</button></p>}</div>;
}
