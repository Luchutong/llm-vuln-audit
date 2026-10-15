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
}
export interface Prompt { id: string; label: string; phase: string; text: string; reason: string; issues: string[]; parent_id?: string | null; created_at: string }
/** Public provider identity frozen with a run. It deliberately has no credential. */
export interface ModelProfileSnapshot { profile_id: string; model: string; base_url: string }
export interface Run { id: string; snapshot_id: string; snapshot_name: string; scope?: string[]; scope_mode?: 'snapshot' | 'explicit'; prompt_id?: string; prompt_label?: string; prompt_text?: string; model: string; model_profile?: ModelProfileSnapshot; budgets: Budget; agent_policy?: {version: string}; task_spec?: TaskSpec | null; status: RunStatus; created_at: string; started_at?: string; finished_at?: string; error?: string; usage: Usage; total_units?: number; completed_units?: number; total_tasks?: number; completed_tasks?: number }
export interface POC { filename: string; language: string; script: string; instructions: string; normal_input: string; attack_input: string; expected_result: string }
export type Verdict = 'confirmed' | 'rejected' | 'uncertain';
export type Conclusion = 'candidate' | 'no_candidate' | 'insufficient_context';
export type ExecutionStatus = 'success' | 'syntax_error' | 'connection_failed' | 'environment_mismatch' | 'not_triggered' | 'not_run' | 'other_error';
export interface Verification { id?: string; created_at?: string; execution_status: ExecutionStatus; verdict: Verdict; original_script?: string; modified_script: string; modification_notes: string; target_version: string; command: string; expected_result: string; normal_observation: string; attack_observation: string; browser_execution: boolean; notes: string; files?: (string | {name?: string; filename?: string; path?: string; url?: string; stored?: string})[] }
export interface Finding {
  file_path: string;
  symbol: string;
  line: number;
  unit_start_line: number;
  unit_end_line: number;
  validation_state: 'candidate' | 'invalid_evidence';
  validation_errors: string[]; id: string; run_id: string; unit_id?: string; task_id?: string; task_key?: string; fingerprint: string; category: string; finding_kind?: string; title: string; severity: string; summary: string; evidence: Evidence[]; input_source: string; propagation: string; dangerous_operation: string; protection: string; preconditions: string[]; missing_context: string[]; poc: POC | null; remediation: string; verdict?: Verdict; verifications: Verification[];
  /**
   * Disposition is a third axis, independent of the evidence check and the human verdict:
   * whether the run still claims this conclusion. A withdrawn conclusion stays in the
   * response and in the report — the row, its evidence and its verifications are never
   * deleted, because "this run changed its mind" is itself part of the record.
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
}

export type FindingDisposition = 'open' | 'superseded' | 'retracted' | 'duplicate' | 'contested';

/** One earlier occupant of a finding slot, archived when a re-run reused it. */
export interface ArchivedRevision {
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
  run: Run;
  goal?: Goal | null;
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
