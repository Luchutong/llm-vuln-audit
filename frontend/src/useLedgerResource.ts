import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, api, errorText } from './api';
import { RECORDS_CHANGED } from './records';

/** Keep a visible ledger current without remounting its evidence or form controls. */
export function useLedgerResource<T>(path: string) {
  const [state, setState] = useState<{ path: string; data: T | null; error: string | null; refreshing: boolean }>({ path, data: null, error: null, refreshing: true });
  const refreshRef = useRef<() => void>(() => {});
  const refresh = useCallback(() => refreshRef.current(), []);
  useEffect(() => {
    let active = true;
    let inFlight = false;
    let request: AbortController | null = null;
    let queued = false;
    let version = 0;
    const read = () => {
      if (!active || inFlight) return;
      inFlight = true;
      request = new AbortController();
      const startedVersion = version;
      setState((current) => ({ path, data: current.path === path ? current.data : null, error: null, refreshing: true }));
      api<T>(path, { signal: request.signal }).then((data) => {
        if (active && startedVersion === version) setState({ path, data, error: null, refreshing: false });
      }).catch((error) => {
        if (active && startedVersion === version) setState((current) => ({ path,
          data: error instanceof ApiError && error.status === 404 ? null : current.path === path ? current.data : null,
          error: errorText(error), refreshing: false }));
      }).finally(() => { inFlight = false; if (queued && active) { queued = false; read(); } });
    };
    refreshRef.current = read;
    read();
    const timer = window.setInterval(() => { if (!document.hidden) read(); }, 5000);
    const changed = () => { version += 1; if (inFlight) queued = true; else read(); };
    window.addEventListener(RECORDS_CHANGED, changed);
    return () => { active = false; window.clearInterval(timer); window.removeEventListener(RECORDS_CHANGED, changed); request?.abort(); refreshRef.current = () => {}; };
  }, [path]);
  return state.path === path ? { ...state, refresh } : { path, data: null, error: null, refreshing: true, refresh };
}
