import { api, ApiError, errorText } from './api.ts';
import type { FinalReviewFacts } from './finalReview';

export interface ReviewSnapshot {
  state: 'idle' | 'loading' | 'ready' | 'missing' | 'error';
  facts: FinalReviewFacts | null;
  error?: string;
}
type Loader = (runId: string, signal: AbortSignal) => Promise<FinalReviewFacts>;
/** Shared by the conversation and report. Pending reads have subscriber ownership. */
export function createFinalReviewCache(load: Loader) {
  const entries = new Map<string, { snapshot: ReviewSnapshot; listeners: Set<() => void>; abort?: AbortController; at: number }>();
  const entry = (key: string) => {
    if (!entries.has(key)) entries.set(key, { snapshot: { state: 'idle', facts: null }, listeners: new Set(), at: 0 });
    return entries.get(key)!;
  };
  const read = (key: string) => entry(key).snapshot;
  const start = (key: string, runId: string, force = false) => {
    const item = entry(key);
    if (item.abort) return;
    if (!force && (item.snapshot.state === 'ready' || item.snapshot.state === 'missing')
        && (item.snapshot.facts?.provenance?.immutable || Date.now() - item.at < 15000)) return;
    const abort = new AbortController(); item.abort = abort;
    const publish = (snapshot: ReviewSnapshot) => { item.snapshot = snapshot; item.listeners.forEach((listener) => listener()); };
    publish({ state: 'loading', facts: null });
    load(runId, abort.signal).then((facts) => {
      if (!abort.signal.aborted) { item.at = Date.now(); publish({ state: 'ready', facts }); }
    }).catch((error) => {
      if (!abort.signal.aborted) {
        item.at = Date.now();
        const legacy = error instanceof ApiError && (error.status === 404 || error.status === 409 && error.detail === 'This run predates Planner v2; it keeps its historical report layout');
        publish(legacy ? { state: 'missing', facts: null } : { state: 'error', facts: null, error: errorText(error) });
      }
    }).finally(() => { if (item.abort === abort) item.abort = undefined; });
  };
  return {
    read,
    retry: (key: string, runId: string) => start(key, runId, true),
    subscribe: (key: string, runId: string, listener: () => void) => {
      const item = entry(key); item.listeners.add(listener); start(key, runId);
      return () => {
        item.listeners.delete(listener);
        // StrictMode can immediately subscribe again. An open report also owns its read.
        queueMicrotask(() => {
          if (!item.listeners.size && item.abort) {
            item.abort.abort(); item.abort = undefined;
            item.snapshot = { state: 'idle', facts: null };
          }
        });
      };
    },
  };
}
export const finalReviewCache = createFinalReviewCache((id, signal) => api(`/runs/${id}/final-review`, { signal, timeoutMs: 10000 }));
