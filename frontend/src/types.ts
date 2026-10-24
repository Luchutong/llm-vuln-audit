export type Category = 'sqli' | 'xss_r' | 'command_injection';
export type RunStatus =
  | 'pending' | 'running' | 'paused'
  | 'completed' | 'unreachable' | 'inconclusive' | 'failed' | 'cancelled' | 'interrupted';
export interface TaskSpec {
  objective: string;
  success_criteria: string;
  max_iterations: number;
  max_total_attempts: number;
  max_planner_rounds: number;
  max_workers: number;
  stop_on_achieved: boolean;
  require_poc: boolean;
  /** Single vulnerability class the run must exhaustively cover (backend hard constraint). */
  scenario?: Category | null;
}
export type GoalStatus = 'open' | 'met' | 'unreachable' | 'inconclusive';
export type TaskWorkItemState = 'open' | 'running' | 'done' | 'exhausted' | 'blocked' | 'skipped';
export type TaskOutcome = 'achieved' | 'continue' | 'no_evidence' | 'blocked';
export interface GoalFinding {
  title: string;
  kind?: string;
  severity?: string | null;
  summary: string;
  evidence: string;
  input_source: string;
  propagation: string;
  dangerous_operation: string;
  protection: string;
  preconditions: string;
  poc?: POC | null;
  remediation: string;
}
export interface GoalAssessment {
  outcome: TaskOutcome;
  summary: string;
  reasoning: string;
  next_focus?: string;
  missing_context?: string[];
  finding?: GoalFinding | null;
  findings?: GoalFinding[];
  observations?: { title: string; kind?: string; summary: string; evidence: string }[];
  attempt?: number;
  terminal_reason?: string;
  retry_exhausted?: boolean;
  error?: string | null;
}
export interface Goal {
  id: string;
  run_id: string;
  objective: string;
  success_criteria: string;
  status: GoalStatus;
  max_iterations: number;
  max_total_attempts: number;
  terminal_reason?: string | null;
  attempts: number;
  created_at: string;
  updated_at: string;
}
export type PlannerStatus = 'pending' | 'planning' | 'dispatching' | 'reviewing' | 'completed' | 'failed' | 'cancelled';
export type PlannerTerminalState = 'met' | 'unreachable' | 'inconclusive' | null;
export interface PlannerState {
  run_id: string;
  goal_id: string;
  session_id: string;
  status: PlannerStatus | string;
  current_round: number;
  max_rounds: number;
  current_plan_id?: string | null;
  current_revision: number;
  terminal_state?: PlannerTerminalState;
  terminal_reason?: string | null;
  created_at: string;
  updated_at: string;
}
export interface ProjectMap {
  snapshot_id: string;
  scope: string[];
  /**
   * The full map is served by `GET /api/runs/{id}/project-map`. `GET /api/runs/{id}`
   * carries a bounded projection instead, so a whole-snapshot audit does not turn every
   * poll into megabytes of JSON — which is why the arrays below may be absent.
   */
  files?: unknown[];
  directories?: unknown[];
  symbols?: unknown[];
  includes?: unknown[];
  calls?: unknown[];
  entrypoints?: unknown[];
  unresolved_root_candidates?: unknown[];
  binary_files?: { path: string; size: number; readable: false }[];
  architecture?: {
    role_counts?: Record<string, number>;
    include_graph?: Record<string, number>;
    /**
     * Module rows name the *directory* they cover, not a file. The key is `directory`
     * rather than `path` precisely because a `path` elsewhere in this type is always a
     * file — one plan cited a module row as a source ref and sent a worker to read a
     * directory.
     */
    modules?: { directory: string; role?: string; files?: number }[];
    bootstrap_files?: unknown[];
  };
  parse_errors?: unknown[];
  stats: Record<string, number>;
  limitations: string[];
  scope_mode?: string;
  scope_files?: number;
}
export interface PlanVersion {
  id: string;
  run_id: string;
  goal_id: string;
  session_id: string;
  round_no: number;
  revision: number;
  status: string;
  goal_state?: string | null;
  basis_summary: string;
  next_action?: string;
  task_snapshot: unknown[];
  usage?: Usage | null;
  error?: string | null;
  created_at: string;
  finished_at?: string | null;
}
export type PlannerTaskState = 'pending' | 'ready' | 'running' | 'deferred' | 'completed' | 'blocked' | 'cancelled';
export interface PlannerTaskContext {
  source_refs?: { path: string; start_line: number; end_line: number; reason?: string }[];
  scope_paths?: string[];
  target_symbols?: string[];
  expected_evidence?: string[];
  focus?: string;
  query_hints?: string[];
  [key: string]: unknown;
}
export interface PlannerTaskAttempt {
  id?: number | string;
  attempt: number;
  worker_id?: string | null;
  session_id?: string | null;
  state?: string;
  outcome?: TaskOutcome;
  result?: GoalAssessment | null;
  usage?: Usage | null;
  seen?: { path: string; start_line: number; end_line: number }[];
  error?: string | null;
  created_at?: string;
}
export interface PlannerTask {
  id: string;
  task_key: string;
  title: string;
  objective: string;
  context_spec: PlannerTaskContext;
  session_id: string;
  plan_id?: string | null;
  priority: number;
  state: PlannerTaskState | string;
  max_attempts: number;
  attempts: number;
  dependencies: string[];
  result?: GoalAssessment | null;
  error?: string | null;
  claimed_by?: string | null;
  claimed_at?: string | null;
  created_at: string;
  updated_at: string;
  finished_at?: string | null;
  attempt_history?: PlannerTaskAttempt[];
}
export interface TaskWorkAttempt {
  id: number;
  work_id: string;
  run_id: string;
  goal_id: string;
  attempt: number;
  worker_id?: string | null;
  outcome: TaskOutcome;
  state: TaskWorkItemState;
  result: GoalAssessment;
  usage?: Usage | null;
  seen?: { path: string; start_line: number; end_line: number }[];
  error?: string | null;
  created_at: string;
}
export interface TaskWorkItem {
  id: string;
  run_id: string;
  goal_id: string;
  unit_id: string;
  summary: string;
  focus: string;
  priority: number;
  state: TaskWorkItemState;
  attempt: number;
  max_attempts: number;
  result?: GoalAssessment | null;
  attempt_history?: TaskWorkAttempt[];
  error?: string | null;
  claimed_by?: string | null;
  created_at: string;
  finished_at?: string | null;
}
export interface Budget { responses: number; tools: number; seconds: number }
export type PocMode = 'off' | 'auto' | 'required';
export interface PocReadiness {
  available: boolean;
  reason: string;
  message: string;
  checked_at: string;
  capabilities: { supported_targets: string[]; browser: boolean };
}
export interface ExecutionSummary {
  policy_version?: string;
  phase: string;
  run_limits: Budget | null;
  run_usage: Budget;
  run_remaining: Budget | null;
  active_executions: { [key: string]: unknown }[] | number;
  stop_reason?: { code: string; dimension?: string | null; message?: string | null } | null;
  blocked_task_ids: string[];
  poc: { mode?: PocMode; available?: boolean | null; reason?: string | null; message?: string | null };
  final_summary_available: boolean;
}
export interface HostFinalSummary {
  source: 'host';
  status: RunStatus;
  complete: boolean;
  stop_reason: { code: string; dimension?: string | null; message?: string | null } | null;
  raw_finding_count: number;
  valid_finding_count: number;
  ledger_group_count: number;
  finding_groups: { id: string; project_finding_id?: string | null; finding_ids: string[]; findings?: (CvssFields & { id: string; revision: number; project_revision?: number | null; title: string; severity: string; category: string; evidence: Evidence[]; verification_status?: VerificationStatus; disposition: FindingDisposition })[] }[];
  tasks: { id: string; title: string; state: string; error?: string | null; result?: unknown; depends_on?: string[] }[];
  coverage: Record<string, unknown>;
  execution?: Record<string, unknown>;
  limitations: string[];
}
export interface Usage { requests: number; tool_calls: number; input_tokens: number; output_tokens: number }
export interface FileRecord {
  path: string;
  sha256: string;
  size: number;
  line_count: number;
  /** `text` files can be read and cited; `binary` files are registered but unreadable. */
  kind?: 'text' | 'binary';
  language?: string;
  /** Dependency or generated directory. Navigation metadata only — not an exclusion. */
  dependency_tree?: boolean;
  is_php?: boolean;
  excluded: boolean;
  exclude_reason?: string;
  parse_errors?: unknown[];
}
export interface Evidence { snapshot_id: string; path: string; start_line: number; end_line: number }
export interface UnitUsage { requests: number; tool_calls: number; input_tokens: number; output_tokens: number }
export interface UnitResult {
  summary?: string;
  conclusions?: Record<Category, Conclusion>;
  // Verdicts are preserved even when a later POC call times out, so the UI/report can
  // distinguish an unfinished proof from a missing source-level judgement.
  verdicts?: Partial<Record<Category, {
    conclusion: Conclusion;
    reasoning: string;
    evidence: string;
    input_source: string;
    propagation: string;
    dangerous_operation: string;
    protection: string;
    preconditions: string;
    missing_context: string;
    severity: string;
  }>>;
  poc_status?: Partial<Record<Category, 'not_required' | 'pending' | 'completed' | 'incomplete'>>;
  exploration_incomplete?: string | null;
  terminal_reason?: string;
  phase?: string;
  category_errors?: Record<string, string>;
}
export interface AuditUnit { id: string; run_id?: string; file_path: string; start_line: number; end_line: number; symbol: string; kind: string; priority: number; slice_index: number; slice_count: number; cleaned_lines?: unknown[]; omissions?: unknown; slice_rule?: string; status?: string; result?: UnitResult | null; error?: string; usage?: Usage; seen?: {path: string; start_line: number; end_line: number}[]; checklist?: string[] }
/**
 * `GET /api/snapshots` returns summaries (counts), while `GET /api/snapshots/{id}` returns
 * the full record with the file list and the frozen unit queue. Keeping them as separate
 * types is what stops the list view from reading `.files` off a summary row.
 */
export interface SnapshotSummary {
  id: string;
  name: string;
  created_at: string;
  archive_sha256: string;
  source: string;
  file_count: number;
  unit_count: number;
  warning_count: number;
  project_id?: string | null;
}
/**
 * A project is the audit identity of a source tree: every upload whose readable text
 * files are identical lands on the same project, so runs under it share one ledger.
 */
export interface Project {
  id: string;
  name: string;
  content_key: string;
  target_profile: 'lab30' | 'unknown' | string;
  created_at: string;
  updated_at: string;
  latest_snapshot_id?: string | null;
  latest_run_id?: string | null;
  snapshot_count: number;
  run_count: number;
  finding_counts?: ProjectFindingCounts;
  findings?: ProjectFinding[];
  runs?: Run[];
  snapshots?: SnapshotSummary[];
}
export interface ProjectFinding extends CvssFields {
  id: string;
  project_id: string;
  revision: number;
  fingerprint: string;
  title: string;
  file_path: string;
  symbol: string;
  category: string;
  finding_kind?: string;
  severity: string;
  summary: string;
  disposition: FindingDisposition;
  disposition_reason?: string | null;
  verification_status: VerificationStatus;
  verification_verdict?: Verdict | null;
  origin_run_id: string;
  last_run_id: string;
  discovered_at: string;
  updated_at: string;
  /** Present on rows returned with a run bundle: how this run related to the ledger row. */
  run_relation?: string;
  run_relation_revision?: number;
  already_known?: boolean;
}
/** The lightweight run identity returned by ledger reads; no execution payload. */
export interface LedgerRunReference {
  id: string;
  snapshot_id: string;
  snapshot_name: string;
  status: RunStatus;
  created_at: string;
}
export interface ProjectFindingListItem extends ProjectFinding {
  project_name: string;
  validation_state: Finding['validation_state'];
  origin_finding_id: string;
  last_finding_id: string;
  origin_run: LedgerRunReference | null;
  last_run: LedgerRunReference | null;
}
export interface ProjectFindingPage {
  items: ProjectFindingListItem[];
  total: number;
  offset: number;
  limit: number;
}
/** Canonical content belongs to the ledger, even if its source run has changed. */
export interface LedgerFinding extends ProjectFinding {
  evidence: Evidence[];
  input_source: string;
  propagation: string;
  dangerous_operation: string;
  protection: string;
  preconditions: string[];
  missing_context: string[];
  poc: POC | null;
  remediation: string;
  validation_state: Finding['validation_state'];
  origin_finding_id: string;
  last_finding_id: string;
  disposition_by?: string | null;
  disposition_at?: string | null;
  superseded_summary: ArchivedRevision[];
  latest_verification_id?: string | null;
}
export interface LedgerFindingRelation {
  run_id: string;
  run_finding_id: string | null;
  relation: string;
  revision: number;
  created_at: string;
  snapshot_id: string | null;
  snapshot_name: string | null;
  run_status: RunStatus | null;
}
export interface LedgerFindingDetail {
  finding: LedgerFinding;
  project: Project;
  origin_run: LedgerRunReference | null;
  last_run: LedgerRunReference | null;
  history: LedgerFindingRelation[];
  verifications: LedgerVerification[];
  current_verification: LedgerVerification | null;
  poc_finding_id: string | null;
  /** A server-provided /api/findings/{actualRunFindingId}/poc path. */
  poc_download_path: string | null;
}
export interface LedgerVerification extends Verification {
  finding_id?: string;
  run_id?: string | null;
  project_finding_id?: string | null;
  finding_revision?: number | null;
}
export interface ProjectFindingCounts {
  total: number;
  open: number;
  verified: number;
  rejected: number;
  withdrawn: number;
  unverified: number;
  /** The remaining verification states are counted separately so an unavailable
   * environment does not make the ledger look empty. */
  inconclusive?: number;
  not_applicable?: number;
  environment_unavailable?: number;
  stale?: number;
}
/**
 * Import-time counters. Unlike `ProjectMap.stats` these are not all numeric: `languages`
 * is a distribution, so a bare `Record<string, number>` would be a lie.
 */
export interface SnapshotStats {
  files?: number;
  text_files?: number;
  binary_files?: number;
  php_files?: number;
  dependency_tree_files?: number;
  /** Language name → file count, most common first. */
  languages?: Record<string, number>;
  skipped_count?: number;
  excluded_count?: number;
}

export interface Snapshot {
  id: string; name: string; created_at: string; archive_sha256: string; source: string;
  schema_version?: number;
  files: FileRecord[];
  units?: AuditUnit[];
  warnings: string[];
  /** First 200 entries only; the count lives in `stats.skipped_count`. */
  skipped_files?: { path: string; reason: string }[];
  /** First 200 entries only; the count lives in `stats.excluded_count`. */
  excluded_files?: string[];
  stats?: SnapshotStats;
  immutable: boolean;
  /** Set by every upload: the project this snapshot was bound to, by content key. */
  project_id?: string | null;
  project?: Project;
  /** True when an identical archive was already imported. */
  snapshot_reused?: boolean;
  /** True when this source tree already had a project; the upload joined it. */
  project_reused?: boolean;
}
export interface Prompt { id: string; label: string; phase: string; text: string; reason: string; issues: string[]; parent_id?: string | null; created_at: string; builtin?: boolean; used_by_runs?: number }

/** One worker-instruction variant in the Lab30 comparison, with the text it sends. */
export interface PromptVariant { id: string; label: string; phase: string; focus: string; prompt: string }

/** One variant's row as the comparison script scored it, kept verbatim. */
export interface PromptExperimentRow {
  variant: string;
  score: { TP: number; FP: number; FN: number; precision: number | null; recall: number | null; f1: number | null; [key: string]: unknown };
  discipline: { reported: number; with_chain: number; with_protection: number; with_preconditions: number; chain_rate: number | null };
  injection: { canaries: number; reported: number; resisted: number; obeyed: number; resistance_rate: number | null; reported_paths: string[] };
  stats: { units: number; achieved: number; no_evidence: number; blocked: number; failed: number; requests: number; tool_calls: number; tokens: number };
  findings: unknown[];
}

export interface PromptExperiment {
  id: string;
  created_at: string;
  finished_at: string | null;
  status: 'running' | 'completed' | 'failed' | 'cancelled' | string;
  variants: string[];
  units_limit: number;
  scenario: string | null;
  model: string;
  budgets: Record<string, number>;
  report_path: string;
  rows: PromptExperimentRow[];
  progress: { current?: string | null; done?: { variant: string; TP: number; FP: number; FN: number }[]; tail?: string[] };
  error: string;
}
/** Public provider identity frozen with a run. It deliberately has no credential. */
export interface ModelProfileSnapshot { profile_id: string; model: string; base_url: string }
export interface Run { id: string; snapshot_id: string; snapshot_name: string; scope?: string[]; scope_mode?: 'snapshot' | 'explicit'; prompt_id?: string; prompt_label?: string; prompt_text?: string; model: string; model_profile?: ModelProfileSnapshot; budgets: Budget; run_limits?: Budget | null; poc_mode?: PocMode; execution_summary?: ExecutionSummary | null; final_summary?: HostFinalSummary | null; agent_policy?: {version: string}; task_spec?: TaskSpec | null; status: RunStatus; created_at: string; started_at?: string; finished_at?: string; error?: string; usage: Usage; total_units?: number; completed_units?: number; total_tasks?: number; completed_tasks?: number; project_id?: string | null; project_name?: string | null; project_mode?: 'project' | 'legacy'; poc_policy?: Record<string, unknown> }
/** One execution the isolated runner performed for a verification record. */
export interface VerificationJob {
  id?: number | string;
  verification_id: string;
  finding_id: string;
  job_id: string;
  kind: 'script' | 'http' | 'browser' | string;
  exit_code?: number | null;
  duration_ms?: number | null;
  created_at?: string;
  request?: Record<string, unknown>;
  result?: Record<string, unknown>;
}
export interface POC { filename: string; language: string; script: string; instructions: string; normal_input: string; attack_input: string; expected_result: string }
export type Verdict = 'confirmed' | 'rejected' | 'uncertain';
export type Conclusion = 'candidate' | 'no_candidate' | 'insufficient_context';
export type ExecutionStatus = 'success' | 'syntax_error' | 'connection_failed' | 'environment_mismatch' | 'not_triggered' | 'not_run' | 'other_error';
export type VerificationStatus = 'verified' | 'rejected' | 'inconclusive' | 'not_applicable' | 'environment_unavailable' | 'unverified' | 'stale';
/** Where a verification row came from: the isolated POC agent, or a pre-migration human record. */
export type VerificationSource = 'poc_agent' | 'legacy_human';
/** A Planner cross-check of one automatic verdict, at the revision it reviewed. */
export interface VerificationReview {
  id?: string;
  finding_id: string;
  revision: number;
  decision: 'confirmed' | 'contested' | string;
  rationale: string;
  observed_normal?: string;
  observed_attack?: string;
  created_at?: string;
}
export interface VerificationArtifact { name?: string; path?: string; sha256?: string; size?: number }
export interface VerificationTarget { name?: string; base_url?: string; security?: string; version?: string; prepared_at?: string }
export interface VerificationAgent { jobs?: string[]; summary?: string; reason?: string; usage?: Record<string, unknown>; policy?: Record<string, unknown> }
export interface Verification { id?: string; created_at?: string; source?: VerificationSource; status?: VerificationStatus; execution_status?: ExecutionStatus; verdict?: Verdict; original_script?: string; modified_script: string; modification_notes: string; target_version: string; command: string; expected_result: string; normal_observation: string; attack_observation: string; browser_execution: boolean; notes: string; files?: (string | {name?: string; filename?: string; path?: string; url?: string; stored?: string})[]; target?: VerificationTarget; agent?: VerificationAgent; artifacts?: VerificationArtifact[] }
export interface Finding extends CvssFields {
  file_path: string;
  symbol: string;
  line: number;
  unit_start_line: number;
  unit_end_line: number;
  validation_state: 'candidate' | 'invalid_evidence' | 'invalid_finding' | 'observation';
  validation_errors: string[]; id: string; run_id: string; unit_id?: string; task_id?: string; task_key?: string; fingerprint: string; category: string; finding_kind?: string; title: string; severity: string; summary: string; evidence: Evidence[]; input_source: string; propagation: string; dangerous_operation: string; protection: string; preconditions: string[]; missing_context: string[]; poc: POC | null; remediation: string; verdict?: Verdict; verifications: Verification[];
  /**
   * The Planner's own reading of those verifications, one row per reviewed revision.
   * Present so the page can show that the verdict was cross-checked, not just recorded.
   */
  verification_reviews?: VerificationReview[];
  /** The POC agent's latest verdict, denormalised onto the finding for cheap listing. */
  verification_status?: VerificationStatus;
  verification_verdict?: Verdict | null;
  /** Which project-ledger row this run finding was merged into, when it belongs to one. */
  project_finding_id?: string | null;
  /** `known` when the run rediscovered a ledger row instead of creating one. */
  known_state?: 'new' | 'known' | string;
  /**
   * Disposition is a third axis, independent of the evidence check and automatic
   * verification: whether the run still claims this conclusion. A withdrawn conclusion
   * stays in the response and in the report — the row, its evidence and its verifications
   * are never deleted, because "this run changed its mind" is itself part of the record.
   */
  disposition: FindingDisposition;
  disposition_reason?: string | null;
  disposition_by?: 'planner' | 'human' | string | null;
  disposition_at?: string | null;
  /** How many conclusions this slot has held. Above 1, earlier text is in `superseded_summary`. */
  revision: number;
  /** What the earlier revisions of this same slot claimed. Oldest first; capped by the server. */
  superseded_summary: ArchivedRevision[];
  /** The finding this one grew out of, when a correction was recorded as a derivation. */
  derived_from_finding_id?: string | null;
  /** Worker attempt that produced a source observation, when available. */
  attempt?: number;
}

export type FindingDisposition = 'open' | 'superseded' | 'retracted' | 'duplicate' | 'contested';

/** One earlier occupant of a finding slot, archived when a re-run reused it. */
export interface ArchivedRevision extends CvssFields {
  revision: number;
  title: string;
  severity: string;
  summary: string;
  evidence: Evidence[];
  validation_state: string;
  validation_errors: string[];
  disposition?: FindingDisposition | null;
  disposition_reason?: string | null;
  disposition_by?: string | null;
  replaced_at?: string | null;
}
export interface UnresolvedSample {
  file_path: string;
  category: Category;
  vulnerable: boolean;
  // Why this sample could not be counted either way — a file with an unfinished unit has
  // no verdict, so it is excluded from the matrix rather than folded into a negative.
  reason: string;
  units?: { unit_id: string; symbol: string; status: string; error?: string | null }[];
}
export interface Evaluation { TP: number; FP: number; FN: number; TN: number; precision: number | null; recall: number | null; f1: number | null; unresolved: UnresolvedSample[]; eligible: number; total_samples: number; excluded_samples: { file_path: string; category: Category }[] }
export interface Metrics {
  candidates: number;
  candidate_findings: number;
  withdrawn_findings?: number;
  source_observations?: number;
  discarded_candidates: number;
  confirmed: number;
  rejected: number;
  uncertain: number;
  awaiting_verification: number;
  audit_coverage: number;
  verification_coverage: number;
  total_units: number;
  completed_units: number;
  incomplete_units: number;
  pending_units: number;
  total_tasks?: number;
  completed_tasks?: number;
  terminal_tasks?: number;
  active_tasks?: number;
  blocked_tasks?: number;
  task_coverage?: number;
  task_states?: Record<string, number>;
  truth_status: string;
  evaluation: Evaluation | null;
}
export interface Attribution { id?: string; file_path: string; category: string; kind: string; cause: string; check_item: string; finding_id?: string; created_at?: string }
export interface RunDetail {
  execution_summary?: ExecutionSummary | null;
  run: Run;
  goal?: Goal | null;
  /** The shared project ledger this run reasoned over; live, unlike the frozen baseline. */
  project?: Project | null;
  project_findings?: ProjectFinding[];
  carried_findings?: ProjectFinding[];
  report_narrative?: { summary?: string; conclusion?: string; limitations?: string[] } | null;
  verification_summary?: Partial<Record<VerificationStatus, number>>;
  verification_jobs?: VerificationJob[];
  /** Every Planner cross-check in this run, newest last. */
  verification_reviews?: VerificationReview[];
  planner?: PlannerState | null;
  project_map?: ProjectMap | null;
  plans?: PlanVersion[];
  tasks?: PlannerTask[];
  /** Per-round navigation aids (reading coverage, reconnaissance briefs). Not evidence. */
  observations?: PlannerObservation[];
  /**
   * What this run has already had answered, and what it declined to re-ask. Payload-free:
   * the answer itself is fetched one topic at a time, so a run response cannot grow with
   * research the caller did not ask for.
   */
  investigations?: InvestigationOverview;
  findings: Finding[];
  /** Source-backed investigation records, kept separate from vulnerability candidates. */
  source_observations?: Finding[];
  metrics: Metrics;
  attributions: Attribution[];
  // Kept optional so historical records can still be decoded; Planner views never use
  // these queues as their source of progress.
  units?: AuditUnit[];
  goals?: Goal[];
  work_items?: TaskWorkItem[];
}

/**
 * Host-computed, per-round navigation aids. Coverage says how much of the snapshot has
 * been read; a reconnaissance brief says where a Planner looked first. Neither is a
 * finding, and neither can be cited as evidence.
 */
export interface PlannerCoverage {
  files_total: number;
  files_read: number;
  files_with_findings: number;
  coverage_ratio: number;
  read_paths: string[];
  unread_hot_modules: { module: string; unread: number; total: number }[];
  dependency_tree_total: number;
  dependency_tree_read: number;
  notice: string;
}

export interface ReconRef { path: string; start_line: number; end_line: number; why?: string }
export interface ReconBrief {
  summary: string;
  layout: { path: string; role?: string; notes?: string }[];
  entry_candidates: ReconRef[];
  data_stores: ReconRef[];
  security_boundaries: ReconRef[];
  reading_plan: ReconRef[];
  uncertainties: string[];
  files_examined?: string[];
  notice?: string;
}

export interface PlannerObservation {
  kind: 'planner_coverage_prepared' | 'recon_brief_prepared' | 'recon_terminal' | 'recon_skipped' | string;
  round?: number | null;
  payload: {
    round?: number;
    coverage?: PlannerCoverage;
    question?: string;
    brief?: ReconBrief;
    reason?: string;
    error?: string | null;
    files_examined?: string[];
  };
}
/**
 * A pinned investigation: an answer the host wrote down once so a later round can reuse
 * it instead of paying for the same research again.
 *
 * Only the disposition columns ever change. The topic, the arguments and the payload are
 * written once and never rewritten, which is what makes "this was investigated in round 2
 * and superseded in round 4" a readable fact rather than a silent overwrite.
 */
export interface Investigation {
  id: string;
  run_id: string;
  goal_id?: string | null;
  plan_id?: string | null;
  round_no: number;
  revision: number;
  kind: 'recon' | 'navigation' | 'search' | 'read' | string;
  tool: string;
  topic: string;
  topic_key: string;
  args: Record<string, unknown>;
  /** Absent from list projections by design; fetch it per topic. */
  payload?: unknown;
  payload_bytes: number;
  files_read: string[];
  usage?: Usage | null;
  status: 'active' | 'superseded' | 'retracted' | string;
  reason?: string | null;
  superseded_by?: string | null;
  created_at: string;
}

export interface InvestigationOverview {
  total: number;
  by_status: Record<string, number>;
  /** Most recent first, capped by the server; the rest live behind the per-topic fetch. */
  recent: Investigation[];
  notice: string;
}

/**
 * One code action from a phase's loop: the model writes Python, the host runs it in a
 * restricted interpreter, and the code inside may call the read-only tools. The code is
 * an action rather than hidden reasoning, so it is persisted and shown the way a tool
 * call is; what the model wrote outside the code fences is never sent.
 */
export interface AgentCode {
  phase: string;
  step: number;
  /** The executed code, cut to the server's per-action byte budget when `truncated`. */
  code: string;
  /** Size before the cut, so a shortened block is never mistaken for the whole script. */
  code_bytes: number;
  truncated: boolean;
  /** What the step printed, already cut to the interpreter's output budget. */
  logs?: string | null;
  /** True when this step ended the phase by handing over its terminal answer. */
  is_final?: boolean;
  /** The interpreter's own error text when the step failed. */
  error?: string | null;
}

export interface AuditEvent {
  id: number;
  run_id: string;
  kind: string;
  payload: unknown;
  created_at: string;
  actor_role?: 'planner' | 'worker' | 'host' | string;
  session_id?: string;
  plan_id?: string;
  planner_round?: number;
  task_id?: string;
  attempt?: number;
  unit_id?: string;
}
export interface Source { snapshot_id: string; path: string; sha256: string; lines: {number: number; text: string}[] }
export interface ModelHealthSnapshot {
  status: string;
  fails: number;
  trips: number;
  cooldown_seconds: number;
  last_error?: string | null;
  last_at?: number | null;
}

/**
 * A complete provider connection, rather than merely a model identifier.
 *
 * The API key is deliberately absent: the server only returns whether a key is
 * configured, and encrypts a browser-submitted key before it reaches SQLite.
 */
export interface ModelProfile {
  id: string;
  label: string;
  model: string;
  base_url: string;
  credential_source: 'stored' | 'environment' | string;
  api_key_configured: boolean;
  ordinal?: number;
  created_at?: string;
  updated_at?: string;
  selected?: boolean;
}

export interface Config {
  model: string;
  base_url?: string;
  configured: boolean;
  thinking?: string;
  missing?: string[];
  selected_profile_id: string | null;
  model_profiles: ModelProfile[];
  budgets: Budget;
  /** The defaults the server applies when a caller names none; the ceiling is not sent. */
  budget_limits?: { defaults: Budget };
  run_budget_limits?: { defaults: Budget; min: Budget; max: Budget };
  worker: Record<string, unknown>;
  model_health?: ModelHealthSnapshot;
  version: string;
}
export interface Experiment { comparable: boolean; reasons: string[]; notes?: string[]; runs: {run: Run; metrics: Metrics}[]; prompt_diffs: unknown[] }
export interface Truth { file_path: string; category: Category; vulnerable: boolean; independently_verified: boolean; verification_basis: string; evidence: unknown[] }

/**
 * How a run's scope is described in the UI.
 *
 * A Planner run freezes the whole uploaded snapshot and stores no path list at all, so
 * anything that reads `run.scope` directly reports zero files for exactly the runs that
 * cover the most. Both views go through here instead.
 */
export function scopeFileCount(run: Run, projectMap?: ProjectMap | null): number {
  const frozen = projectMap?.stats?.files;
  if (typeof frozen === 'number') return frozen;
  if (typeof projectMap?.scope_files === 'number') return projectMap.scope_files;
  return run.scope?.length ?? 0;
}

export function scopeLabel(run: Run, projectMap?: ProjectMap | null): string {
  if ((run.scope_mode ?? 'explicit') === 'snapshot') {
    return `上传项目整包快照，共 ${scopeFileCount(run, projectMap)} 个可读文件（含依赖目录与其它语言的文本文件）`;
  }
  return `${scopeFileCount(run, projectMap)} 个已冻结源码文件`;
}


export type CvssEvidence = Omit<Evidence, 'snapshot_id'> & { snapshot_id?: string };
export interface CvssMetricDetail { value: string | null; rationale: string; evidence: CvssEvidence[]; assumption?: boolean; issues?: string[] }
export interface CvssScore { version: '3.1'; score_basis: 'Base'; base_score: number; base_vector: string; metrics: Record<string,string>; severity: string }
export interface CvssAssessment {
  status: 'scored' | 'needs_information' | 'legacy_unrated' | 'stale'; source: 'auto' | 'manual' | 'legacy';
  assessment_revision: number; conclusion_revision: number; engine_version?: string; metric_details: Record<string,CvssMetricDetail>;
  issues?: string[]; reason?: string; created_at?: string; snapshot_id?: string | null; run_id?: string | null;
}
export interface CvssFields { cvss?: CvssScore | null; cvss_assessment?: CvssAssessment | null; legacy_severity?: string | null }
export interface CvssHistoryPage { items: (CvssFields & {id:number; applicable:boolean; source_run_available:boolean})[]; total:number; offset:number; limit:number }
