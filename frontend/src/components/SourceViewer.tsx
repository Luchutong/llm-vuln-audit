import { useEffect, useMemo, useRef, useState } from 'react';
import { api, errorText } from '../api';
import type { Source } from '../types';

interface Range {
  start_line: number;
  end_line: number;
}

/**
 * Original-file source with real line numbers.
 *
 * Line numbers are the currency of this whole tool: a finding is only meaningful if the
 * line it cites is the line the auditor can open. So they come from the server, never
 * from an index we compute here, and the cited ranges are highlighted in place.
 */
export function SourceViewer({
  snapshotId,
  path,
  start = 1,
  end = 200,
  highlight = [],
  height = 340,
}: {
  snapshotId: string;
  path: string;
  start?: number;
  end?: number;
  highlight?: Range[];
  height?: number;
}) {
  const [source, setSource] = useState<Source | null>(null);
  const [error, setError] = useState<string | null>(null);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const abort = new AbortController();
    setSource(null);
    setError(null);
    api<Source>(`/snapshots/${snapshotId}/source?path=${encodeURIComponent(path)}&start=${start}&end=${end}`, { signal: abort.signal })
      .then((data) => !abort.signal.aborted && setSource(data))
      .catch((exc) => !abort.signal.aborted && setError(errorText(exc)));
    return () => {
      abort.abort();
    };
  }, [snapshotId, path, start, end]);

  const hit = useMemo(() => {
    const set = new Set<number>();
    for (const range of highlight) {
      for (let line = range.start_line; line <= range.end_line; line += 1) set.add(line);
    }
    return set;
  }, [highlight]);

  useEffect(() => {
    const first = source?.lines.find((line) => hit.has(line.number));
    if (first && box.current) {
      const row = box.current.querySelector<HTMLDivElement>(`[data-line="${first.number}"]`);
      if (row) {
        const container = box.current;
        const top = row.getBoundingClientRect().top - container.getBoundingClientRect().top + container.scrollTop;
        container.scrollTop = Math.max(0, top - container.clientHeight / 2 + row.clientHeight / 2);
      }
    }
  }, [source, hit]);

  if (error) return <div role="alert" className="error-box">{error}</div>;
  if (!source) return <div role="status" className="empty">读取源码…</div>;

  return (
    <div className="source" role="region" aria-label={`${path} 第 ${start} 至 ${end} 行源码`} tabIndex={0} style={{ maxHeight: height }} ref={box}>
      {source.lines.map((line) => (
        <div
          key={line.number}
          data-line={line.number}
          className={`source-row${hit.has(line.number) ? ' hit' : ''}`}
        >
          <span className="source-no">{line.number}</span>
          <span className="source-text">{line.text || ' '}</span>
        </div>
      ))}
    </div>
  );
}
