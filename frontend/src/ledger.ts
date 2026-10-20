import type { Evidence, Finding, LedgerFindingDetail } from './types';

export const LEDGER_PAGE_SIZE = 25;
export const LEDGER_SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
export const LEDGER_VERIFICATIONS = ['verified', 'unverified', 'inconclusive', 'environment_unavailable', 'not_applicable', 'rejected', 'stale'] as const;
export const LEDGER_DISPOSITIONS = ['open', 'contested', 'retracted', 'duplicate', 'superseded', 'all'] as const;
export const SEVERITY_LABELS: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', unknown: '未标注' };
export const LEDGER_DISPOSITION_LABELS: Record<string, string> = { open: '当前主张', contested: '存在争议', retracted: '已撤回', duplicate: '重复', superseded: '已取代' };
export const RELATION_LABELS: Record<string, string> = { created: '首次发现', rediscovered: '再次发现', corrected: '更正结论', retracted: '撤回', withdrawn: '撤回', restored: '恢复', carried: '沿用', duplicate: '判为重复', superseded: '被后续结论取代', contested: '标记争议', open: '恢复有效', reopened: '恢复' };

export interface LedgerFilters {
  q: string;
  projectId: string;
  severity: string;
  verification: string;
  disposition: string;
  page: number;
}

function choice(value: string | null, values: readonly string[]): string { return value && values.includes(value) ? value : ''; }

export function ledgerFilters(hash: string, projectId?: string): LedgerFilters {
  const params = new URLSearchParams(hash.split('?')[1] ?? '');
  const page = Number(params.get('page') ?? 1);
  return {
    q: params.get('q') ?? '',
    projectId: projectId ?? params.get('project') ?? '',
    severity: choice(params.get('severity'), LEDGER_SEVERITIES),
    verification: choice(params.get('verification'), LEDGER_VERIFICATIONS),
    disposition: choice(params.get('disposition'), LEDGER_DISPOSITIONS),
    page: Number.isSafeInteger(page) && page > 0 ? page : 1,
  };
}

/** Retain the workspace tab while changing the committed, shareable filters. */
export function ledgerHash(hash: string, filters: LedgerFilters, scoped = false): string {
  const [base, query = ''] = hash.split('?');
  const params = new URLSearchParams(query);
  for (const key of ['q', 'project', 'severity', 'verification', 'disposition', 'page']) params.delete(key);
  if (filters.q.trim()) params.set('q', filters.q.trim());
  if (!scoped && filters.projectId) params.set('project', filters.projectId);
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.verification) params.set('verification', filters.verification);
  if (filters.disposition) params.set('disposition', filters.disposition);
  if (filters.page > 1) params.set('page', String(filters.page));
  const suffix = params.toString();
  return `${base || '#findings'}${suffix ? `?${suffix}` : ''}`;
}

export function ledgerQuery(filters: LedgerFilters): string {
  const params = new URLSearchParams({ offset: String((filters.page - 1) * LEDGER_PAGE_SIZE), limit: String(LEDGER_PAGE_SIZE) });
  if (filters.projectId) params.set('project_id', filters.projectId);
  if (filters.q.trim()) params.set('q', filters.q.trim());
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.verification) params.set('verification_status', filters.verification);
  if (filters.disposition) params.set('disposition', filters.disposition);
  return params.toString();
}

export function ledgerReturnHash(hash: string, projectId: string): string {
  const candidate = new URLSearchParams(hash.split('?')[1] ?? '').get('from') ?? '';
  const base = candidate.split('?')[0];
  if (base === '#findings' || base === `#sources/${encodeURIComponent(projectId)}`) return candidate;
  return `#sources/${encodeURIComponent(projectId)}?tab=findings`;
}

/** A path can exist in several uploads; its snapshot is part of the evidence key. */
export function groupLedgerEvidence(references: Evidence[], fallbackSnapshotId: string) {
  const groups = new Map<string, { snapshotId: string; path: string; references: Evidence[] }>();
  for (const reference of references) {
    const snapshotId = reference.snapshot_id || fallbackSnapshotId;
    const key = JSON.stringify([snapshotId, reference.path]);
    const group = groups.get(key) ?? { snapshotId, path: reference.path, references: [] };
    group.references.push(reference);
    groups.set(key, group);
  }
  return [...groups.values()];
}

/** Adapt canonical content for the shared renderer, never a historical run's prose. */
export function ledgerFindingForDisplay(detail: LedgerFindingDetail): Finding {
  const row = detail.finding;
  const primary = row.evidence.find((reference) => reference.path === row.file_path) ?? row.evidence[0];
  return {
    ...row,
    id: row.id,
    run_id: detail.last_run?.id ?? row.last_run_id,
    line: primary?.start_line ?? 0,
    unit_start_line: primary?.start_line ?? 0,
    unit_end_line: primary?.end_line ?? 0,
    validation_errors: [],
    verifications: detail.current_verification ? [detail.current_verification] : [],
    project_finding_id: row.id,
    superseded_summary: row.superseded_summary ?? [],
  };
}
