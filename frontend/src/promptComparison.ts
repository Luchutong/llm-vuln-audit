import type { AuditEvent, Budget, Finding, Prompt, PromptExperiment, Run } from './types';

export const PROMPT_PROTOCOL = 'lab30-full-v2';
export const CLASS_LABELS: Record<string, string> = {
  auth_bypass: '认证绕过',
  code_execution: '代码执行',
  command_injection: '命令注入',
  csrf: 'CSRF',
  idor: '对象越权',
  info_disclosure: '信息泄露',
  insecure_deserialization: '不安全反序列化',
  lfi: '本地文件包含',
  mass_assignment: '批量赋值',
  open_redirect: '开放重定向',
  path_traversal: '路径穿越',
  price_manipulation: '价格篡改',
  race_condition: '竞争条件',
  rfi: '远程文件包含',
  session_fixation: '会话固定',
  sqli: 'SQL 注入',
  ssrf: 'SSRF',
  weak_crypto: '弱密码学',
  weak_type_comparison: '弱类型比较',
  xss_r: '反射型 XSS',
  xss_s: '存储型 XSS',
  xxe: 'XXE',
};
export const EXPERIMENT_STATUS: Record<string, string> = {
  pending: '待执行',
  queued: '排队中',
  running: '运行中',
  completed: '已完成',
  finished: '执行结束',
  preparing: '准备中',
  cancelling: '取消中',
  failed: '失败',
  cancelled: '已取消',
  interrupted: '已中断',
  valid: '有效成绩',
  invalid: '无效试次',
  budget_exhausted: '预算耗尽',
  partial: '部分完成',
  not_started: '未开始',
};
export interface PairedValue {
  round_index: number;
  trial_id: string;
  baseline_trial_id: string;
  value: number;
  gained_truth_ids?: string[];
  lost_truth_ids?: string[];
}
export interface AggregateMetric {
  mean: number | null;
  sample_std: number | null;
  n: number;
  values?: (number | PairedValue)[];
}
export interface FrozenVariant {
  id: string;
  label: string;
  text: string;
  hash?: string;
  sha256?: string;
  reason?: string;
  parent_id?: string | null;
}
export interface ExperimentManifest {
  variants: FrozenVariant[];
  baseline_prompt_id: string;
  repeats: number;
  model?: string | { model?: string; base_url?: string; thinking?: string; [key: string]: unknown };
  experiment_wall_seconds?: number;
  budgets?: Budget;
  run_limits?: Budget;
  hashes?: Record<string, string>;
  order?: string[][];
  [key: string]: unknown;
}
export interface TrialScore {
  TP: number;
  D: number;
  U: number;
  FN: number;
  FP?: number;
  precision: number | null;
  recall: number;
  f1: number;
  matches?: FindingMatch[];
  duplicates?: FindingMatch[];
  unmatched?: FindingMatch[];
  diagnostics?: Record<string, unknown>[];
  missed_diagnostics?: { truth_id: string; reason: string; related_candidates: { finding_id?: string; reason?: string }[]; affects_score: false }[];
  duplicate_statistics?: { still_asserted: number; resolved: number };
  truth_results?: Record<string, unknown>[];
  cvss?: Record<string, unknown>;
}
export interface FindingMatch {
  finding_id?: string;
  truth_id?: string;
  reason?: string;
  [key: string]: unknown;
}
export interface TrialUsage {
  requests?: number | null;
  responses?: number | null;
  tool_calls?: number | null;
  input_tokens?: number | null;
  output_tokens?: number | null;
  total_tokens?: number | null;
  tokens?: number | null;
}
export interface StopReason {
  code?: string;
  message?: string | null;
  dimension?: string | null;
}
export interface ReadCoverage {
  read_files: number;
  total_files: number;
  read_lines: number;
  total_lines: number;
  file_ratio: number | null;
  line_ratio: number | null;
}
export interface TrialAttempt {
  id?: string;
  attempt_id?: string;
  status?: string;
  evaluation_status?: string;
  termination_reason?: string;
  stop_reason?: string | StopReason;
  attempt_no?: number;
  error?: string | null;
  score?: TrialScore | null;
  usage?: TrialUsage;
  created_at?: string;
  duration_seconds?: number | null;
  audit_elapsed_seconds?: number | null;
  wall_elapsed_seconds?: number | null;
  coverage_review?: Record<string, unknown> | null;
  coverage_gaps?: unknown;
}
export interface Trial {
  id: string;
  round_index: number;
  prompt_id: string;
  status: string;
  evaluation_status?: string;
  termination_reason?: string;
  stop_reason?: string | StopReason;
  error?: string | null;
  score?: TrialScore | null;
  usage?: TrialUsage;
  duration_seconds?: number | null;
  audit_elapsed_seconds?: number | null;
  wall_elapsed_seconds?: number | null;
  attempts?: TrialAttempt[];
  read_coverage?: ReadCoverage;
  retry_reason?: string | null;
  can_retry?: boolean;
  run_id?: string;
}
export interface TruthRound {
  round_index: number;
  trial_id: string;
  detected: boolean;
  finding_id?: string | null;
}
export interface TruthResult {
  id: string;
  title: string;
  class: string;
  variants: Record<string, { hits: number; total: number; rounds: TruthRound[] }>;
}
export interface VariantSummary {
  id: string;
  label: string;
  metrics: Record<string, AggregateMetric>;
  paired_deltas?: Record<string, AggregateMetric>;
  trial_ids?: string[];
  valid_trials?: number;
}
export interface ExperimentSummary {
  complete_rounds: number[];
  complete_round_count: number;
  repeats: number;
  preliminary: boolean;
  baseline_prompt_id: string;
  variants: VariantSummary[];
  truth_matrix: TruthResult[];
  class_coverage?: {
    class: string;
    total: number;
    variants: Record<string, { detected: number; total: number; recall: number | null }>;
  }[];
  cvss_common_rounds?: {
    round_index: number;
    truth_ids: string[];
    total: number;
    variants: Record<string, { score_mae: number | null; severity_accuracy: number | null }>;
    paired_deltas?: Record<string, { score_mae: number | null; severity_accuracy: number | null }>;
  }[];
  cvss_paired_deltas?: Record<string, { score_mae: AggregateMetric; severity_accuracy: AggregateMetric }>;
  execution_diagnostics?: { trial_id: string; prompt_id: string; stop_reason?: string; audit_elapsed_seconds?: number | null;
    wall_elapsed_seconds?: number | null; audit_budget_utilization?: number | null; coverage_review?: Record<string, unknown> | null;
    coverage_gaps?: unknown; duplicate_statistics?: { still_asserted: number; resolved: number } | null;
    missed_diagnostics?: TrialScore['missed_diagnostics'] | null }[];
  actual_total_usage?: Record<
    string,
    { known_total: number; known_trials?: number; trials?: number; known_attempts?: number; attempts?: number }
  >;
  [key: string]: unknown;
}
export interface ExperimentBatch {
  id: string;
  kind?: string;
  started_at?: string | null;
  deadline_at?: string | null;
  finished_at?: string | null;
  remaining_seconds?: number | null;
}
export interface ExperimentLive {
  run_id?: string | null;
  phase?: string;
  usage?: TrialUsage;
  finding_count?: number;
  read_coverage?: ReadCoverage;
  audit_started_at?: string | null;
  audit_elapsed_seconds?: number;
  audit_remaining_seconds?: number | null;
  last_event_id?: number;
  last_event_at?: string | null;
  heartbeat_at?: string | null;
}
export interface ExperimentProgress {
  tail?: string[];
  current?: string | null;
  phase?: string;
  trial_id?: string;
  round_index?: number;
  timing?: { initial_batch?: ExperimentBatch; active_batch_id?: string; batches?: ExperimentBatch[] };
  live?: ExperimentLive;
}
export interface FullExperiment {
  id: string;
  protocol: string;
  status: string;
  created_at: string;
  finished_at?: string | null;
  manifest: ExperimentManifest;
  trials: Trial[];
  summary?: ExperimentSummary | null;
  error?: string | null;
  progress?: ExperimentProgress;
  [key: string]: unknown;
}
export type ExperimentRecord = FullExperiment | (PromptExperiment & { protocol?: string });
export interface TrialDetail {
  trial?: Trial;
  attempt?: TrialAttempt;
  run?: Run | null;
  findings?: Finding[];
  events?: AuditEvent[];
  event_cursor?: number;
  has_earlier?: boolean;
  attempts?: TrialAttempt[];
  score?: TrialScore | null;
  report?: string;
  error?: string | null;
  read_coverage?: ReadCoverage;
  [key: string]: unknown;
}
export interface ExperimentSource {
  path: string;
  start_line?: number;
  end_line?: number;
  line_count?: number;
  lines: { number: number; text: string }[];
}
export const isFullExperiment = (item: ExperimentRecord): item is FullExperiment => item.protocol === PROMPT_PROTOCOL;
export const percent = (value: number | null | undefined) =>
  value == null || !Number.isFinite(value) ? '—' : `${(100 * value).toFixed(1)}%`;
export const points = (value: number | null | undefined) =>
  value == null || !Number.isFinite(value) ? '—' : `${value > 0 ? '+' : ''}${(100 * value).toFixed(1)} 个百分点`;
export const numeric = (value: number | null | undefined, digits = 1) =>
  value == null || !Number.isFinite(value) ? '—' : value.toLocaleString('zh-CN', { maximumFractionDigits: digits });
export const metricLabel = (metric?: AggregateMetric, asPercent = false) =>
  !metric || metric.mean == null
    ? '—'
    : `${asPercent ? percent(metric.mean) : numeric(metric.mean)}${metric.sample_std == null ? '' : ` ± ${asPercent ? `${(metric.sample_std * 100).toFixed(1)}%` : numeric(metric.sample_std)}`} (n=${metric.n})`;
export function compatibleStrategies(prompts: Prompt[]): Prompt[] {
  return prompts.filter((prompt) => prompt.kind === 'worker_strategy' && prompt.contract_version === 'worker-strategy-v1');
}
export function defaultStrategies(prompts: Prompt[]): string[] {
  const sorted = [...compatibleStrategies(prompts)].sort((a, b) => a.id.localeCompare(b.id));
  const current = ['worker-w0-v1', 'worker-w1-v2', 'worker-w2-v2'];
  if (current.every((id) => sorted.some((item) => item.id === id))) return current;
  const defaults = sorted.filter((item) => /(?:^|[-_])w[012](?:[-_]|$)/i.test(item.id));
  return (defaults.length >= 3 ? defaults : sorted).slice(0, 3).map((item) => item.id);
}
/** This comparison never recomputes backend scores or silently substitutes current prompt text. */
export function lineDiff(before: string, after: string): { kind: 'same' | 'removed' | 'added'; text: string }[] {
  const left = before.split('\n'),
    right = after.split('\n');
  // Bound the quadratic comparison for unusually long custom strategy documents.
  if (left.length * right.length > 250000)
    return [
      ...left.map((text) => ({ kind: 'removed' as const, text })),
      ...right.map((text) => ({ kind: 'added' as const, text })),
    ];
  const table = Array.from({ length: left.length + 1 }, () => new Uint16Array(right.length + 1));
  for (let i = left.length - 1; i >= 0; i--)
    for (let j = right.length - 1; j >= 0; j--)
      table[i][j] = left[i] === right[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]);
  const rows: ReturnType<typeof lineDiff> = [];
  let i = 0,
    j = 0;
  while (i < left.length || j < right.length) {
    if (i < left.length && j < right.length && left[i] === right[j]) {
      rows.push({ kind: 'same', text: left[i++] });
      j++;
    } else if (j < right.length && (i === left.length || table[i][j + 1] > table[i + 1][j]))
      rows.push({ kind: 'added', text: right[j++] });
    else rows.push({ kind: 'removed', text: left[i++] });
  }
  return rows;
}

export function experimentBudgetCheck(variants: number, repeats: number, seconds: number) {
  const trials = variants * repeats;
  const requiredSeconds = trials * (seconds + 60) + 180;
  return {
    trials,
    requiredSeconds,
    valid: Number.isInteger(seconds) && seconds >= 1 && seconds <= 720 && requiredSeconds <= 7200,
  };
}
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds)) return '—';
  const rounded = Math.max(0, Math.floor(seconds));
  return `${Math.floor(rounded / 60)}分${String(rounded % 60).padStart(2, '0')}秒`;
}
