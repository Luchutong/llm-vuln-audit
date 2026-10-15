export type Category = 'sqli' | 'xss_r' | 'command_injection';
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
  files: unknown[];
  directories: unknown[];
  symbols: unknown[];
  includes: unknown[];
  calls: unknown[];
  entrypoints: unknown[];
  parse_errors: unknown[];
  stats: Record<string, number>;
  limitations: string[];
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
export interface FileRecord { path: string; sha256: string; size: number; line_count: number; is_php?: boolean; excluded: boolean; exclude_reason?: string; parse_errors?: unknown[] }
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
export interface Snapshot { id: string; name: string; created_at: string; archive_sha256: string; source: string; files: FileRecord[]; units?: AuditUnit[]; warnings: string[]; immutable: boolean }
export interface Prompt { id: string; label: string; phase: string; text: string; reason: string; issues: string[]; parent_id?: string | null; created_at: string }
export interface Run { id: string; snapshot_id: string; snapshot_name: string; scope: string[]; prompt_id?: string; prompt_label?: string; prompt_text?: string; model: string; budgets: Budget; agent_policy?: {version: string}; task_spec?: TaskSpec | null; status: string; created_at: string; started_at?: string; finished_at?: string; error?: string; usage: Usage; total_units?: number; completed_units?: number; total_tasks?: number; completed_tasks?: number }
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
  validation_errors: string[]; id: string; run_id: string; unit_id?: string; task_id?: string; task_key?: string; fingerprint: string; category: string; finding_kind?: string; title: string; severity: string; summary: string; evidence: Evidence[]; input_source: string; propagation: string; dangerous_operation: string; protection: string; preconditions: string[]; missing_context: string[]; poc: POC | null; remediation: string; verdict?: Verdict; verifications: Verification[] }
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
  findings: Finding[];
  metrics: Metrics;
  attributions: Attribution[];
  // Kept optional so historical records can still be decoded; Planner views never use
  // these queues as their source of progress.
  units?: AuditUnit[];
  goals?: Goal[];
  work_items?: TaskWorkItem[];
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
export interface Config { model: string; base_url?: string; configured: boolean; budgets: Budget; worker: string; version: string }
export interface Experiment { comparable: boolean; reasons: string[]; notes?: string[]; runs: {run: Run; metrics: Metrics}[]; prompt_diffs: unknown[] }
export interface Truth { file_path: string; category: Category; vulnerable: boolean; independently_verified: boolean; verification_basis: string; evidence: unknown[] }
