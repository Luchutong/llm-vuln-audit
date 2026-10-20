import type { Finding, RunDetail } from './types';

const VULNERABILITY_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const LEGACY_VULNERABILITY_CATEGORIES = new Set(['sqli', 'xss_r', 'command_injection']);

/** Match the API's result boundary, including older responses that mixed both lists. */
export function isVulnerabilityFinding(finding: Pick<Finding, 'finding_kind' | 'category' | 'severity'>): boolean {
  const kind = (finding.finding_kind ?? '').trim().toLowerCase();
  if (kind) return kind === 'vulnerability' && VULNERABILITY_SEVERITIES.has(finding.severity);
  return LEGACY_VULNERABILITY_CATEGORIES.has(finding.category);
}

export function vulnerabilityFindings(detail: Pick<RunDetail, 'findings'>): Finding[] {
  return detail.findings.filter(isVulnerabilityFinding);
}

export function sourceObservations(detail: Pick<RunDetail, 'findings' | 'source_observations'>): Finding[] {
  // Explicit observations remain observations even when a historical raw row still
  // resembles a finding. Prefer that projection and never duplicate its original ID.
  const observations = new Map((detail.source_observations ?? []).map((item) => [item.id, item]));
  for (const item of detail.findings) {
    if (!isVulnerabilityFinding(item) && !observations.has(item.id)) observations.set(item.id, item);
  }
  return [...observations.values()];
}

export function activeVulnerabilityFindings(detail: Pick<RunDetail, 'findings'>): Finding[] {
  return vulnerabilityFindings(detail).filter((finding) => finding.validation_state === 'candidate'
    && !['superseded', 'retracted', 'duplicate'].includes(finding.disposition));
}
