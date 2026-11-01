import { useEffect, useState } from 'react';
import { api, errorText } from '../api';
import type { Snapshot } from '../types';
import { LongContent } from './LongContent';

/** Mounted only in audit details; never fetch source files to display ZIP identity. */
export function RunSnapshot({ snapshotId }: { snapshotId: string }) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const abort = new AbortController(); setSnapshot(null); setError('');
    api<Snapshot>(`/snapshots/${encodeURIComponent(snapshotId)}`, { signal: abort.signal, timeoutMs: 10000 })
      .then((value) => { if (!abort.signal.aborted) setSnapshot(value); })
      .catch((cause) => { if (!abort.signal.aborted) setError(errorText(cause)); });
    return () => abort.abort();
  }, [snapshotId, revision]);
  if (error) return <p className="small" role="status">ZIP 信息读取失败：{error} <button className="text-button" onClick={() => setRevision((value) => value + 1)}>重试 ZIP 信息</button></p>;
  return <LongContent label="ZIP SHA-256" value={snapshot ? snapshot.archive_sha256 || '暂无数据' : '正在读取…'} />;
}
