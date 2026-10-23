import { useEffect, useRef, useState } from 'react';
import { api, errorText } from './api';
import type { AuditEvent } from './types';

/** SQLite is authoritative. A terminal run is drained through the paged event log. */
export function useEvents(runId: string | null, onEvent?: (event: AuditEvent) => void, live: boolean | null = true) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [reconnects, setReconnects] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [retryVersion, setRetryVersion] = useState(0);
  const cursor = useRef(0);
  const handler = useRef(onEvent);
  handler.current = onEvent;

  useEffect(() => {
    cursor.current = 0;
    setEvents([]);
    setReconnects(0);
    setError(null);
  }, [runId]);

  useEffect(() => {
    if (!runId || live === null) return;
    let disposed = false;
    let source: EventSource | null = null;
    let retry: number | undefined;
    let flush: number | undefined;
    let pending: AuditEvent[] = [];
    const abort = new AbortController();
    const publish = () => {
      flush = undefined;
      if (disposed || !pending.length) return;
      const batch = pending;
      pending = [];
      setEvents((current) => [...current, ...batch]);
      handler.current?.(batch[batch.length - 1]);
    };
    const accept = (items: AuditEvent[]) => {
      for (const event of items) {
        if (event.run_id !== runId || !Number.isSafeInteger(event.id) || event.id <= cursor.current) continue;
        cursor.current = event.id;
        pending.push(event);
      }
      if (pending.length && flush === undefined) flush = window.setTimeout(publish, 60);
    };
    const drain = async () => {
      try {
        while (!disposed) {
          const page = await api<{ events: AuditEvent[]; remaining?: number }>(`/runs/${runId}/event-log?after=${cursor.current}`, { signal: abort.signal });
          if (disposed) return;
          const previous = cursor.current;
          accept(page.events);
          publish();
          if (cursor.current === previous || (page.remaining === undefined ? page.events.length < 2000 : page.remaining <= page.events.length)) break;
        }
        if (!disposed) setError(null);
      } catch (exc) { if (!disposed) setError(errorText(exc)); }
    };
    const open = () => {
      if (disposed) return;
      source = new EventSource(`/api/runs/${runId}/events?after=${cursor.current}`);
      source.onopen = () => { if (!disposed) { setConnected(true); setError(null); } };
      source.onmessage = (message) => {
        if (disposed) return;
        try { accept([JSON.parse(message.data) as AuditEvent]); } catch { /* Ignore malformed frames. */ }
      };
      source.onerror = () => {
        if (disposed) return;
        publish();
        setConnected(false);
        source?.close();
        setReconnects((count) => count + 1);
        retry = window.setTimeout(open, 2000);
      };
    };
    setConnected(false);
    if (live) open(); else void drain();
    return () => {
      // Flush accepted frames before a live -> terminal transition, without replay duplicates.
      publish();
      disposed = true;
      abort.abort();
      window.clearTimeout(retry);
      window.clearTimeout(flush);
      source?.close();
    };
  }, [runId, live, retryVersion]);

  return { events, connected, reconnects, cursor: cursor.current, error, retry: () => setRetryVersion((value) => value + 1) };
}
