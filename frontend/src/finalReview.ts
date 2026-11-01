import type { ExecutionSummary } from './types';

export const FINAL_REVIEW_PUBLISH_LABELS: Record<string, string> = {
  releasable_final: '可发布完整报告',
  releasable_partial: '可发布阶段报告',
  review_required: '需修复交付错误',
};
export const FINAL_REVIEW_COUNT_LABELS = { raw_records: '原始记录', valid_records: '有效记录', canonical: '规范结论', accepted: '终审接受', pending: '待终审', contested: '存疑或排除' } as const;

export interface FinalReviewFacts {
  schema_version: string;
  provenance?: { immutable?: boolean; input_hash?: string };
  review_batch?: { item_refs: unknown[]; decisions: unknown[]; unresolved_items: string[] };
  review_batches?: { batches: Array<{ id: string; phase: string; status: string; items: unknown[]; decisions: unknown[] }> };
  counts: {
    raw_records: number; valid_records: number; canonical: number;
    withdrawn: number; accepted: number; pending: number; contested: number;
  };
  run_outcome: { status: string; audit_complete: boolean; stop_reason?: ExecutionSummary['stop_reason']; dimensions?: {
    focus_complete: boolean; source_review_complete: boolean; risk_obligations_complete: boolean;
    dynamic_verification: { mode: 'off' | 'auto' | 'required'; requirement_met: boolean; verified?: number; pending?: number };
    final_review_complete: boolean; delivery_readiness: { complete: boolean; gaps: Array<{ canonical_id: string; items: string[] }> };
  } };
  quality_result: {
    report_kind: string; publishability: string; failed_checks: string[];
  };
  coverage: {
    files: { total: number; read: number; reviewed: number; skipped: number; pending: number | null; complete: boolean | null };
    directions: { total: number; required?: number; advisory?: number; resolved: number; skipped: number; unsettled: number; complete: boolean | null };
    verification: { total: number; verified: number; rejected: number; uncertain: number; pending: number };
  };
  canonical_findings: Array<{
    canonical_id: string;
    current_claim_ref?: { finding_id: string; revision: number; project_revision?: number };
    assessment_revision?: number;
    source_record_refs?: Array<{ finding_id: string; revision: number }>;
    final_disposition: string;
    final_batch_review?: { rationale?: string; focus?: { relation: string; rationale: string } };
    frozen_claim: {
      title: string; category: string; file_path: string;
      primary_location?: { path?: string; line?: number };
      cvss?: { base_score?: number } | null;
    };
    conflicts?: Array<{ kind: string; detail: string }>;
  }>;
  advisory_directions?: Array<{ id: string; text: string }>;
  action_items: Array<{ kind: string; object?: string; detail?: string; action?: string; title?: string }>;
}
