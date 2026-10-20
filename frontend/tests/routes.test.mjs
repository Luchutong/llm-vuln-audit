import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRoute, newAuditHref } from '../src/routes.ts';

test('source library is default and legacy audit/settings links keep working', () => {
  assert.deepEqual(parseRoute(''), { page: 'sources' });
  assert.deepEqual(parseRoute('#sources?q=app'), { page: 'sources' });
  assert.deepEqual(parseRoute('#run/task-1'), { page: 'run', runId: 'task-1' });
  assert.deepEqual(parseRoute('#settings'), { page: 'settings' });
});

test('source tasks keep an explicit ZIP identifier and decode identifiers safely', () => {
  assert.deepEqual(parseRoute(newAuditHref('项目 1', 'zip-2')), { page: 'new', projectId: '项目 1', snapshotId: 'zip-2' });
  assert.deepEqual(parseRoute('#sources/p?tab=findings'), { page: 'project', projectId: 'p', tab: 'findings' });
  assert.equal(parseRoute('#sources/p?tab=unknown').tab, 'tasks');
  assert.deepEqual(parseRoute('#findings/ledger-1'), { page: 'finding', findingId: 'ledger-1' });
  assert.deepEqual(parseRoute('#sources/p?tab=archives&snapshot=zip-1'), { page: 'project', projectId: 'p', tab: 'archives', snapshotId: 'zip-1' });
});

test('malformed or unsupported links show a missing page instead of silently creating a draft', () => {
  for (const hash of ['#sources/%E0%A4%A', '#sources/p/other', '#findings/a/extra', '#unknown']) {
    assert.deepEqual(parseRoute(hash), { page: 'missing' });
  }
});
