import { useCallback, useSyncExternalStore } from 'react';
import { finalReviewCache } from './finalReviewCache';
import type { ReviewSnapshot } from './finalReviewCache';
const disabled: ReviewSnapshot = { state: 'idle', facts: null };

export function useFinalReview(runId: string, status: string, enabled = true) {
  const key = `${runId}:${status}`;
  const subscribe = useCallback((listener: () => void) => enabled ? finalReviewCache.subscribe(key, runId, listener) : () => {}, [key, runId, enabled]);
  const read = useCallback(() => enabled ? finalReviewCache.read(key) : disabled, [key, enabled]);
  const snapshot = useSyncExternalStore(subscribe, read);
  return { ...snapshot, retry: () => finalReviewCache.retry(key, runId) };
}
