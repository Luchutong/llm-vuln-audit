import test from 'node:test';
import assert from 'node:assert/strict';
import { compatibleStrategies, defaultStrategies, lineDiff, metricLabel, percent, points } from '../src/promptComparison.ts';
import { parseRoute } from '../src/routes.ts';
import { promptDeletionBlock } from '../src/records.ts';

test('comparison distinguishes a missing precision from a real zero and uses percentage points for deltas', () => {
  assert.equal(percent(null), '—');
  assert.equal(percent(0), '0.0%');
  assert.equal(points(-0.1), '-10.0 个百分点');
  assert.equal(points(0.1), '+10.0 个百分点');
  assert.equal(points(0), '0.0 个百分点');
  assert.equal(metricLabel({ mean: null, sample_std: null, n: 0 }, true), '—');
  assert.equal(metricLabel({ mean: 0, sample_std: null, n: 1 }, true), '0.0% (n=1)');
  assert.equal(metricLabel({ mean: 0.5, sample_std: 0.1, n: 3 }, true), '50.0% ± 10.0% (n=3)');
});

test('only versioned worker strategies participate; builtin W0 W1 W2 have stable default order', () => {
  const prompts = [
    { id: 'custom-z', kind: 'worker_strategy', contract_version: 'worker-strategy-v1' },
    { id: 'P0-basic', kind: 'legacy' },
    { id: 'worker-w2-v1', kind: 'worker_strategy', contract_version: 'worker-strategy-v1' },
    { id: 'worker-w0-v1', kind: 'worker_strategy', contract_version: 'worker-strategy-v1' },
    { id: 'worker-w1-v1', kind: 'worker_strategy', contract_version: 'worker-strategy-v1' },
    { id: 'future', kind: 'worker_strategy', contract_version: 'worker-strategy-v99' },
  ];
  assert.equal(compatibleStrategies(prompts).length, 4);
  assert.deepEqual(defaultStrategies(prompts), ['worker-w0-v1', 'worker-w1-v1', 'worker-w2-v1']);
});

test('frozen prompt changes retain unchanged lines and do not mutate either version', () => {
  assert.deepEqual(lineDiff('共同契约\n基础策略\n证据', '共同契约\n增强策略\n证据'), [
    { kind: 'same', text: '共同契约' },
    { kind: 'removed', text: '基础策略' },
    { kind: 'added', text: '增强策略' },
    { kind: 'same', text: '证据' },
  ]);
  assert.deepEqual(lineDiff('same', 'same'), [{ kind: 'same', text: 'same' }]);
});

test('current comparison prefers the unchanged W0 baseline with both v2 strategies', () => {
  const ids = ['worker-w0-v1', 'worker-w1-v1', 'worker-w1-v2', 'worker-w2-v1', 'worker-w2-v2'];
  assert.deepEqual(defaultStrategies(ids.map((id) => ({ id, kind: 'worker_strategy', contract_version: 'worker-strategy-v1' }))),
    ['worker-w0-v1', 'worker-w1-v2', 'worker-w2-v2']);
});

test('isolated experiments have a refreshable route and reject paths with unexpected trailing segments', () => {
  assert.deepEqual(parseRoute('#experiments/frozen%20one?tab=findings&round=2&class=sqli'), {
    page: 'experiments',
    experimentId: 'frozen one',
  });
  assert.deepEqual(parseRoute('#experiments/x/trial'), { page: 'missing' });
});

test('experiment references protect a strategy even when isolated runs are absent from the main run list', () => {
  assert.match(promptDeletionBlock({ id: 'used', used_by_experiments: 2 }, []), /2 次实验/);
  assert.match(promptDeletionBlock({ id: 'used', used_by_runs: 1 }, []), /1 次审计/);
});

test('the initial timed batch fits exactly two hours and rejects larger schedules', async () => {
  const { experimentBudgetCheck, formatDuration } = await import('../src/promptComparison.ts');
  assert.deepEqual(experimentBudgetCheck(3, 3, 720), { trials: 9, requiredSeconds: 7200, valid: true });
  assert.equal(experimentBudgetCheck(3, 3, 721).valid, false);
  assert.equal(experimentBudgetCheck(3, 4, 720).valid, false);
  assert.equal(experimentBudgetCheck(3, 4, 525).valid, true);
  assert.equal(formatDuration(0), '0分00秒');
  assert.equal(formatDuration(7200), '120分00秒');
  assert.equal(formatDuration(null), '—');
});

test('an experiment read timeout is distinct from navigation cancellation and never poisons a later request', async () => {
  const { api, ApiError } = await import('../src/api.ts');
  const previous = globalThis.fetch;
  try {
    globalThis.fetch = async (_url, options) =>
      new Promise((_resolve, reject) => {
        options.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
      });
    await assert.rejects(
      api('/prompt-experiments/slow', { timeoutMs: 10 }),
      (error) => error instanceof ApiError && error.status === 408 && /保留/.test(error.message),
    );
    const abort = new AbortController();
    const pending = api('/prompt-experiments/old', { timeoutMs: 1000, signal: abort.signal });
    abort.abort();
    await assert.rejects(pending, (error) => error.name === 'AbortError');
    globalThis.fetch = async () => new Response(JSON.stringify({ status: 'running' }));
    assert.deepEqual(await api('/prompt-experiments/current', { timeoutMs: 10 }), { status: 'running' });
  } finally {
    globalThis.fetch = previous;
  }
});
