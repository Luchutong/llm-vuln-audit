import { useCallback, useEffect, useRef, useState } from 'react';
import { api, errorText } from './api';

/** Keep a visible ledger current without remounting its evidence or form controls. */
export function useLedgerResource<T>(path: string) {
  const [state, setState] = useState<{ path: string; data: T | null; error: string | null; refreshing: boolean }>({ path, data: null, error: null, refreshing: true });
  const refreshRef = useRef<() => void>(() => {});
  const refresh = useCallback(() => refreshRef.current(), []);
  useEffect(() => {
    let active = true;
    let inFlight = false;
    let request: AbortController | null = null;
    const read = () => {
      if (!active || inFlight) return;
      inFlight = true;
      request = new AbortController();
      setState((current) => ({ path, data: current.path === path ? current.data : null, error: null, refreshing: true }));
      api<T>(path, { signal: request.signal }).then((data) => {
        if (active) setState({ path, data, error: null, refreshing: false });
      }).catch((error) => {
        if (active) setState((current) => ({ path, data: current.path === path ? current.data : null, error: errorText(error), refreshing: false }));
      }).finally(() => { inFlight = false; });
    };
    refreshRef.current = read;
    read();
    const timer = window.setInterval(() => { if (!document.hidden) read(); }, 5000);
    return () => { active = false; window.clearInterval(timer); request?.abort(); refreshRef.current = () => {}; };
  }, [path]);
  return state.path === path ? { ...state, refresh } : { path, data: null, error: null, refreshing: true, refresh };
}
