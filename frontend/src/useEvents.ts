import { useCallback, useEffect, useRef, useState } from 'react';
import type { AuditEvent } from './types';

/**
 * Follow one run's event stream.
 *
 * The server writes every event to SQLite before pushing it, so the stream is only a
 * nudge: on reconnect we ask for everything after the last id we stored. EventSource
 * does that for us through `Last-Event-ID` when the browser reconnects on its own, but
 * a reconnect we trigger (run switched, stream errored) starts from scratch — hence
 * the id we pass explicitly as `after`.
 */
export function useEvents(runId: string | null, onEvent?: (event: AuditEvent) => void) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [reconnects, setReconnects] = useState(0);
  const cursor = useRef(0);
  const handler = useRef(onEvent);
  handler.current = onEvent;

  const reset = useCallback(() => {
    cursor.current = 0;
    setEvents([]);
  }, []);

  useEffect(() => {
    if (!runId) return;
    reset();

    let source: EventSource | null = null;
    let retry: number | undefined;
    let closed = false;

    const open = () => {
      if (closed) return;
      source = new EventSource(`/api/runs/${runId}/events?after=${cursor.current}`);
      source.onopen = () => setConnected(true);
      source.onmessage = (message) => {
        let event: AuditEvent;
        try {
          event = JSON.parse(message.data) as AuditEvent;
        } catch {
          return;
        }
        // The server replays from the cursor, so a duplicate is possible after a
        // reconnect; ignoring old ids keeps the timeline monotonic.
        if (event.id <= cursor.current) return;
        cursor.current = event.id;
        setEvents((current) => [...current, event]);
        handler.current?.(event);
      };
      source.onerror = () => {
        setConnected(false);
        source?.close();
        if (closed) return;
        setReconnects((count) => count + 1);
        retry = window.setTimeout(open, 2000);
      };
    };

    open();
    return () => {
      closed = true;
      window.clearTimeout(retry);
      source?.close();
      setConnected(false);
    };
  }, [runId, reset]);

  return { events, connected, reconnects, cursor: cursor.current, reset };
}
