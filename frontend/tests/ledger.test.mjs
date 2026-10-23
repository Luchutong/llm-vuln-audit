import test from 'node:test';
import assert from 'node:assert/strict';
import { groupLedgerEvidence, ledgerFilters, ledgerFindingForDisplay, ledgerHash, ledgerQuery, ledgerReturnHash } from '../src/ledger.ts';

test('ledger URLs retain committed filters, pagination and the source workspace tab', () => {
  const filters = ledgerFilters('#sources/source-a?tab=findings&q=文件上传&severity=high&verification=verified&disposition=all&page=3', 'source-a');
  assert.deepEqual(filters, { q: '文件上传', projectId: 'source-a', severity: 'high', verification: 'verified', disposition: 'all', page: 3 });
  const query = new URLSearchParams(ledgerQuery(filters));
  assert.equal(query.get('project_id'), 'source-a');
  assert.equal(query.get('offset'), '50');
  assert.equal(query.get('limit'), '25');
  assert.equal(query.get('verification_status'), 'verified');
  const hash = ledgerHash('#sources/source-a?tab=findings', filters, true);
  assert.equal(new URLSearchParams(hash.split('?')[1]).get('tab'), 'findings');
  assert.equal(new URLSearchParams(hash.split('?')[1]).has('project'), false);
  assert.deepEqual(ledgerFilters(hash, 'source-a'), filters);
});

test('default filtering delegates active dispositions to the API and validates URL inputs', () => {
  const filters = ledgerFilters('#findings?severity=invalid&verification=other&disposition=drop&page=-2');
  assert.deepEqual(filters, { q: '', projectId: '', severity: '', verification: '', disposition: '', page: 1 });
  assert.equal(new URLSearchParams(ledgerQuery(filters)).has('disposition'), false);
  assert.equal(ledgerFilters('#findings?page=1.2').page, 1);
  assert.equal(ledgerFilters('#findings?page=9007199254740992').page, 1);
  const global = ledgerFilters('#findings?project=source-b&disposition=all&page=2');
  assert.equal(ledgerHash('#findings', global), '#findings?project=source-b&disposition=all&page=2');
});

test('evidence from equal paths in different ZIP snapshots never shares a source window', () => {
  const references = [
    { snapshot_id: 'zip-a', path: 'index.php', start_line: 1, end_line: 3 },
    { snapshot_id: 'zip-b', path: 'index.php', start_line: 4, end_line: 5 },
    { path: 'legacy.php', start_line: 2, end_line: 2 },
  ];
  const groups = groupLedgerEvidence(references, 'source-run-zip');
  assert.deepEqual(groups.map(({ snapshotId, path }) => [snapshotId, path]), [['zip-a', 'index.php'], ['zip-b', 'index.php'], ['source-run-zip', 'legacy.php']]);
  assert.equal(groups[0].references.length, 1);
});

test('finding return links restore valid list filters and reject unrelated destinations', () => {
  const from = '#findings?project=source-a&severity=high&page=3';
  assert.equal(ledgerReturnHash(`#findings/item?from=${encodeURIComponent(from)}`, 'source-a'), from);
  const scoped = '#sources/source-a?tab=findings&verification=verified&page=2';
  assert.equal(ledgerReturnHash(`#findings/item?from=${encodeURIComponent(scoped)}`, 'source-a'), scoped);
  for (const bad of ['https://example.test', '#settings', '#findings/other', '#sources/source-b?tab=findings']) {
    assert.equal(ledgerReturnHash(`#findings/item?from=${encodeURIComponent(bad)}`, 'source-a'), '#sources/source-a?tab=findings');
  }
});

test('canonical detail keeps ledger wording and status without promoting historical verification', () => {
  const current = { id: 'verification-current', status: 'verified', run_id: 'older-run' };
  const row = { id: 'ledger-id', title: '当前台账标题', summary: '当前台账正文', evidence: [{ path: 'a.php', start_line: 8, end_line: 9 }], file_path: 'a.php', last_run_id: 'latest-run', origin_run_id: 'first-run', last_finding_id: 'run-finding', revision: 3, verification_status: 'verified', disposition: 'open', superseded_summary: [] };
  const detail = { finding: row, last_run: { id: 'latest-run', snapshot_id: 'zip-latest' }, verifications: [{ id: 'historical', status: 'rejected' }, current], current_verification: current };
  const display = ledgerFindingForDisplay(detail);
  assert.equal(display.id, 'ledger-id');
  assert.equal(display.title, '当前台账标题');
  assert.equal(display.run_id, 'latest-run');
  assert.equal(display.unit_start_line, 8);
  assert.equal(display.verification_status, 'verified');
  assert.deepEqual(display.verifications, [current]);
  assert.deepEqual(ledgerFindingForDisplay({ ...detail, current_verification: null, finding: { ...row, verification_status: 'stale' } }).verifications, []);
});

test('CVSS status and zero-score severity survive filters, history and reset', () => {
  const filters=ledgerFilters('#findings?severity=none&cvss_status=scored&page=2');
  assert.equal(filters.cvssStatus,'scored');
  assert.equal(filters.severity,'none');
  assert.equal(new URLSearchParams(ledgerQuery(filters)).get('cvss_status'),'scored');
  assert.deepEqual(ledgerFilters(ledgerHash('#findings',filters)),filters);
  assert.equal(new URLSearchParams(ledgerHash('#findings', {...filters,cvssStatus:''}).split('?')[1]).has('cvss_status'),false);
  assert.equal(ledgerFilters('#findings?cvss_status=other').cvssStatus,undefined);
});
