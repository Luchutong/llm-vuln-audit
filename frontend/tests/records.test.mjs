import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanupCandidates, findingDeletionBlock, findingDeletionPath, promptDeletionBlock, runDeletionBlock, snapshotDeletionBlock } from '../src/records.ts';
import { ApiError, remove } from '../src/api.ts';

test('cleanup respects project boundaries and explicitly includes paused audits', () => {
  const runs = ['pending', 'running', 'paused', 'completed', 'failed', 'cancelled', 'unreachable'].map((status) => ({ id: status, status, project_id: 'one', snapshot_id: 'source', prompt_id: 'draft' }));
  const other = { id: 'other', status: 'completed', project_id: 'two', snapshot_id: 'other-source' };
  assert.deepEqual(cleanupCandidates([...runs, other], 'one').map((run) => run.id), ['paused', 'completed', 'failed', 'cancelled', 'unreachable']);
  assert.equal(cleanupCandidates([...runs, other]).length, 6);
  assert.ok(runDeletionBlock(runs[0]));
  assert.ok(runDeletionBlock(runs[1]));
  assert.equal(runDeletionBlock(runs[2]), null);
});

test('all audit references protect ZIPs and prompts, including completed audits', () => {
  const runs = [{ status: 'completed', snapshot_id: 'source', prompt_id: 'draft' }];
  assert.match(snapshotDeletionBlock({ id: 'source' }, runs), /1 次审计/);
  assert.equal(snapshotDeletionBlock({ id: 'other' }, runs), null);
  assert.match(promptDeletionBlock({ id: 'builtin', builtin: true }, []), /内置/);
  assert.match(promptDeletionBlock({ id: 'draft', builtin: false }, runs), /1 次审计/);
  assert.equal(promptDeletionBlock({ id: 'unused', builtin: false }, runs), null);
});

test('delete requests accept empty 204 responses and retain conflict status and details', async () => {
  const previous = globalThis.fetch;
  try {
    globalThis.fetch = async (url, options) => { assert.equal(url, '/api/snapshots/zip'); assert.equal(options.method, 'DELETE'); return new Response(null, { status: 204 }); };
    assert.equal(await remove('/snapshots/zip'), undefined);
    globalThis.fetch = async () => new Response(JSON.stringify({ detail: 'Snapshot is referenced by 2 run(s)' }), { status: 409 });
    await assert.rejects(remove('/snapshots/zip'), (error) => error instanceof ApiError && error.status === 409 && error.message.includes('2 run(s)'));
  } finally { globalThis.fetch = previous; }
});

test('finding deletion blocks paused audits and scopes active-run guards to the selected project', () => {
  for (const status of ['pending', 'running', 'paused']) {
    const runs = [{ status, project_id: 'one' }];
    assert.match(findingDeletionBlock(runs, 'one'), /取消或完成/);
    assert.match(findingDeletionBlock(runs), /已暂停/);
    assert.equal(findingDeletionBlock(runs, 'two'), null);
  }
  assert.equal(findingDeletionBlock(['completed', 'failed', 'cancelled', 'unreachable'].map((status) => ({ status, project_id: 'one' })), 'one'), null);
  assert.equal(findingDeletionBlock([], 'one'), null);
});

test('finding cleanup paths use only the selected project and encode source identifiers', () => {
  assert.equal(findingDeletionPath(), '/project-findings');
  assert.equal(findingDeletionPath('source/a & b'), '/project-findings?project_id=source%2Fa+%26+b');
  assert.equal(findingDeletionPath('source/a', 'ledger/a?b'), '/project-findings/ledger%2Fa%3Fb');
});

test('finding cleanup keeps server conflict and failure responses available for retry', async () => {
  const previous = globalThis.fetch;
  try {
    globalThis.fetch = async (url, options) => {
      assert.equal(url, '/api/project-findings?project_id=source');
      assert.equal(options.method, 'DELETE');
      return new Response(JSON.stringify({ detail: 'Run execution is not quiescent' }), { status: 409 });
    };
    await assert.rejects(remove(findingDeletionPath('source')), (error) => error instanceof ApiError && error.status === 409 && error.message.includes('not quiescent'));
    const result = { deleted_project_findings: 2, deleted_run_findings: 5, deleted: { verifications: 3 }, affected_project_ids: ['source'] };
    globalThis.fetch = async () => new Response(JSON.stringify(result), { status: 200 });
    assert.deepEqual(await remove(findingDeletionPath('source')), result);
  } finally { globalThis.fetch = previous; }
});
