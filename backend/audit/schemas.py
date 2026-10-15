"""Structured model output and HTTP request bodies."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CATEGORIES = ("sqli", "xss_r", "command_injection")
CATEGORY_LABELS = {
    "sqli": "SQL 注入",
    "xss_r": "反射型 XSS",
    "command_injection": "命令注入",
}

Conclusion = Literal["candidate", "no_candidate", "insufficient_context"]
Severity = Literal["low", "medium", "high", "critical"]
Verdict = Literal["confirmed", "rejected", "uncertain"]
TaskOutcome = Literal["achieved", "continue", "no_evidence", "blocked"]
ExecutionStatus = Literal[
    "success",
    "syntax_error",
    "connection_failed",
    "environment_mismatch",
    "not_triggered",
    "not_run",
    "other_error",
]

_PLACEHOLDER_TEXT = {"", "无", "不适用", "n/a", "na", "none", "null", "todo", "待补充", "...", "…", "-", "—"}


def _meaningful_text(value: str, field_name: str) -> str:
    """Reject empty template fields before a candidate can become an artifact."""
    if not value.strip() or value.strip().strip("。.").casefold() in _PLACEHOLDER_TEXT:
        raise ValueError(f"{field_name} must contain a concrete value, not a placeholder")
    return value


class EvidenceRef(BaseModel):
    """A one-based, inclusive original-file line range."""

    path: str = Field(description="Snapshot-relative source path, exactly as shown in the unit header")
    start_line: int = Field(ge=1, description="First original file line of the cited code")
    end_line: int = Field(ge=1, description="Last original file line of the cited code")


class PocSpec(BaseModel):
    filename: str = Field(description="Suggested file name, for example sqli_low_poc.php")
    language: str = Field(default="php", description="Script language")
    script: str = Field(description="Complete, runnable proof-of-concept script")
    instructions: str = Field(description="How to adapt and run it, including the target entry URL")
    normal_input: str = Field(description="Benign input used as the control")
    attack_input: str = Field(description="Payload that should trigger the vulnerability")
    expected_result: str = Field(description="Observable difference between the control and the attack run")

    @field_validator("filename", "language", "script", "instructions", "normal_input", "attack_input", "expected_result")
    @classmethod
    def _required_poc_content(cls, value: str, info) -> str:
        return _meaningful_text(value, info.field_name)


class Check(BaseModel):
    """One vulnerability category examined for the current audit unit."""

    conclusion: Conclusion = Field(
        description="candidate: the evidence supports a reachable vulnerability; "
        "no_candidate: the examined code was sufficient and shows no vulnerability; "
        "insufficient_context: the examined code was not enough to decide"
    )
    reasoning: str = Field(description="Short justification organised as syntax -> vulnerability semantics -> real risk")
    evidence: list[EvidenceRef] = Field(default_factory=list, description="Original file line ranges that carry the claim")
    input_source: str = Field(default="", description="Where attacker-controlled data enters, or empty when not a candidate")
    propagation: str = Field(default="", description="How the data reaches the dangerous operation")
    dangerous_operation: str = Field(default="", description="The sink, with its file and line")
    protection: str = Field(default="", description="Protections present and why they are ineffective, or the reason none apply")
    preconditions: list[str] = Field(default_factory=list, description="Runtime requirements: route, session, configuration, database branch")
    missing_context: list[str] = Field(default_factory=list, description="Context that was unavailable and would change the verdict")
    severity: Severity | None = Field(default=None, description="Impact level; required for a candidate")
    poc: PocSpec | None = Field(default=None, description="Runnable proof of concept; required for a candidate")
    remediation: str = Field(default="", description="Concrete fix")

    @model_validator(mode="after")
    def _candidate_is_complete(self) -> "Check":
        if self.conclusion != "candidate":
            return self
        missing = [
            name
            for name, value in (
                ("evidence", self.evidence),
                ("input_source", self.input_source.strip()),
                ("propagation", self.propagation.strip()),
                ("dangerous_operation", self.dangerous_operation.strip()),
                ("preconditions", self.preconditions),
                ("severity", self.severity),
                ("poc", self.poc),
                ("remediation", self.remediation.strip()),
            )
            if not value
        ]
        if missing:
            raise ValueError(f"a candidate must fill: {', '.join(missing)}")
        return self


class UnitAnalysis(BaseModel):
    """The complete result for one audit unit.

    The three categories are separate fields, so a unit can never be reported with
    a missing category: the shape of this object is the checklist.
    """

    sqli: Check = Field(description="SQL injection findings")
    xss_r: Check = Field(description="Reflected XSS findings")
    command_injection: Check = Field(description="Command injection findings")
    summary: str = Field(description="One or two sentences on what this unit does and how it is reached")

    def by_category(self) -> dict[str, Check]:
        return {
            "sqli": self.sqli,
            "xss_r": self.xss_r,
            "command_injection": self.command_injection,
        }


# --- settlement: the forced final answer ------------------------------------
#
# Answering a whole unit in one response — three categories, each carrying a full
# multi-line POC script — is more than a small model can emit in a single structured
# reply: it truncates or malforms the JSON and burns both of its retries. The
# settlement phase therefore asks for the same content in payloads small enough to
# validate, with the tools hidden so it cannot start exploring again:
#
#   call 1  UnitVerdicts  the three conclusions, no scripts
#   call 2  PocBundle     the scripts, only for the categories judged candidates


class CategoryVerdict(BaseModel):
    """One category, judged from code that has already been gathered. No script here.

    Deliberately flat, and every field is required. An earlier shape used nested objects
    plus a "a candidate must also fill X" validator; the model answered with just
    `conclusion`/`reasoning`/`severity`, failed validation, and burned all of its retries
    on the same omission. With no conditional fields there is no state it cannot satisfy,
    and the shape below is one it fills in full. Whether a candidate is actually
    complete is judged in Python, where a failure can be reported as `incomplete`
    instead of being mistaken for a verdict.
    """

    conclusion: Conclusion = Field(
        description="candidate: the evidence supports a reachable vulnerability; "
        "no_candidate: the examined code was sufficient and shows no vulnerability; "
        "insufficient_context: the examined code was not enough to decide"
    )
    reasoning: str = Field(
        min_length=1,
        description="Justification organised as syntax -> vulnerability semantics -> real risk",
    )
    evidence: str = Field(
        min_length=1,
        description="Original file line ranges carrying the claim, as `path:start-end`, "
        "several separated by `;`. Write 不适用 when this category is not a candidate.",
    )
    input_source: str = Field(min_length=1, description="Where attacker-controlled data enters; 不适用 if not a candidate")
    propagation: str = Field(min_length=1, description="How the data reaches the dangerous operation; 不适用 if not a candidate")
    dangerous_operation: str = Field(min_length=1, description="The sink with its file and line; 不适用 if not a candidate")
    protection: str = Field(min_length=1, description="Protections present and why they do not cover this path, or 无")
    preconditions: str = Field(
        min_length=1,
        description="Runtime requirements to trigger it, for example needing a session, a "
        "parameter name, a security level or a database branch; 不适用 if not a candidate",
    )
    missing_context: str = Field(min_length=1, description="Context that was unavailable and would change the verdict, or 无")
    severity: Severity = Field(
        description="Impact level when this category is a candidate; pick low when it is not"
    )


class UnitVerdicts(BaseModel):
    """Settlement call 1: all three conclusions for one unit, no proof-of-concept scripts."""

    sqli: CategoryVerdict = Field(description="SQL injection")
    xss_r: CategoryVerdict = Field(description="Reflected XSS")
    command_injection: CategoryVerdict = Field(description="Command injection")
    summary: str = Field(default="", description="One or two sentences on what this unit does and how it is reached")

    def by_category(self) -> dict[str, CategoryVerdict]:
        return {
            "sqli": self.sqli,
            "xss_r": self.xss_r,
            "command_injection": self.command_injection,
        }


class CategoryPoc(BaseModel):
    """A proof of concept plus the fix, for one category judged a candidate."""

    category: Literal["sqli", "xss_r", "command_injection"] = Field(description="Which category this script proves")
    poc: PocSpec
    remediation: str = Field(description="Concrete fix for this category")

    @field_validator("remediation")
    @classmethod
    def _required_remediation(cls, value: str) -> str:
        return _meaningful_text(value, "remediation")


class PocBundle(BaseModel):
    """Settlement call 2: one script per candidate category."""

    proofs: list[CategoryPoc] = Field(default_factory=list, description="One entry per category judged a candidate")


# --- goal-driven source tasks ----------------------------------------------


class TaskSpec(BaseModel):
    """A user-defined source-analysis target, frozen with the run that executes it."""

    objective: str = Field(min_length=8, max_length=2000, description="What the agents should establish from the selected source")
    success_criteria: str = Field(
        default="在所选源码中找到至少一处能由原始行号证据支撑的目标相关发现。",
        min_length=8,
        max_length=2000,
        description="Observable condition that lets the coordinator mark the goal reached",
    )
    max_iterations: int = Field(default=3, ge=1, le=8, description="Maximum agent passes over one work item")
    max_total_attempts: int = Field(
        default=24,
        ge=1,
        le=128,
        description="Maximum settled worker attempts across the entire task frontier",
    )
    max_planner_rounds: int = Field(
        default=8,
        ge=1,
        le=32,
        description="Maximum autonomous Planner rounds for this run",
    )
    max_workers: int = Field(default=2, ge=1, le=4, description="Concurrent source-analysis workers for this run")
    stop_on_achieved: bool = Field(default=True, description="Stop queued work once an evidence-backed result reaches the goal")
    require_poc: bool = Field(
        default=False,
        description="Require achieved results to include manually reviewable POCs; normally off for source facts and non-exploit tasks",
    )

    @field_validator("objective", "success_criteria")
    @classmethod
    def _concrete_task_text(cls, value: str, info) -> str:
        return _meaningful_text(value, info.field_name)


class TaskFinding(BaseModel):
    """A source-backed result for a user-defined task.

    Unlike the fixed vulnerability checklist, a task may establish an architectural
    fact, map a data flow, identify a security boundary, or report a vulnerability.
    The common contract is therefore deliberately small: a concrete conclusion and
    source citations.  Vulnerability-oriented fields remain available when they add
    meaning, but they are never required for a general source-analysis task.
    """

    title: str = Field(min_length=3, max_length=240, description="Short, concrete result title")
    kind: str = Field(
        default="source_observation",
        min_length=3,
        max_length=120,
        description="Result type such as source_observation, data_flow, security_boundary, or vulnerability",
    )
    severity: Severity | None = Field(
        default=None,
        description="Impact level when the result is a vulnerability or risk; omit for neutral source facts",
    )
    summary: str = Field(
        min_length=8,
        max_length=4000,
        description="Evidence-bound explanation of what the cited source establishes",
    )
    evidence: str = Field(
        min_length=3,
        max_length=2000,
        description="Snapshot citations as path:start-end, separated by semicolons",
    )
    input_source: str = Field(default="", max_length=1200, description="Optional attacker or data input source")
    propagation: str = Field(default="", max_length=1800, description="Optional relevant data or control-flow path")
    dangerous_operation: str = Field(default="", max_length=1200, description="Optional risk sink or sensitive operation")
    protection: str = Field(default="", max_length=1200, description="Optional relevant protection or boundary")
    preconditions: str = Field(default="", max_length=1600, description="Optional runtime assumptions or entry conditions")
    poc: PocSpec | None = Field(default=None, description="Optional manually reviewable POC for a vulnerability result")
    remediation: str = Field(default="", max_length=2400, description="Optional remediation when an actionable issue exists")

    @field_validator("title", "kind", "summary", "evidence")
    @classmethod
    def _concrete_finding_text(cls, value: str, info) -> str:
        return _meaningful_text(value, info.field_name)


class GoalFinding(TaskFinding):
    """Compatibility name for the original single goal-task finding payload.

    New integrations should use :class:`TaskFinding`.  Keeping this subclass lets
    callers importing the older name continue to construct and validate results while
    the task executor adopts a plural ``findings`` payload.
    """


class GoalAssessment(BaseModel):
    """One bounded executor pass over a source work item.

    A worker may ask for another, distinct pass but cannot unilaterally call the whole
    task unreachable. The coordinator only makes that judgement after the durable queue
    drains and all worker outcomes are available.
    """

    outcome: TaskOutcome
    summary: str = Field(min_length=3, max_length=4000)
    reasoning: str = Field(
        min_length=3,
        max_length=4000,
        description="Concise auditable rationale tied to displayed source evidence; do not provide private chain-of-thought",
    )
    next_focus: str = Field(default="", max_length=1600)
    missing_context: list[str] = Field(default_factory=list)
    # ``finding`` was the original single-result field.  Keep it for existing
    # clients and normalise it into ``findings`` below.  One work item can now
    # surface several independently cited results, which matters for broad source
    # goals such as mapping all authentication boundaries in a function.
    finding: TaskFinding | None = None
    findings: list[TaskFinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def _outcome_has_the_required_payload(self) -> "GoalAssessment":
        normalised = list(self.findings)
        if self.finding is not None and not any(
            item.model_dump() == self.finding.model_dump() for item in normalised
        ):
            normalised.insert(0, self.finding)
        self.findings = normalised
        # Older worker/agent integrations still read ``finding``.  Expose the first
        # result there while making the full collection authoritative for new code.
        self.finding = normalised[0] if normalised else None

        if self.outcome == "achieved" and not normalised:
            raise ValueError("achieved requires an evidence-backed finding")
        if self.outcome != "achieved" and normalised:
            raise ValueError("only achieved may attach a finding")
        if self.outcome == "continue":
            _meaningful_text(self.next_focus, "next_focus")
        return self


# --- planner/frontier contract ---------------------------------------------


PlannerGoalState = Literal["continue", "met", "unreachable", "inconclusive"]


class PlannerSourceRef(BaseModel):
    """A source window selected by the Planner for a worker context bundle.

    The host validates every path and line range against the immutable snapshot before
    persisting a task.  It is deliberately separate from a finding ``EvidenceRef``:
    this is a *reading instruction*, not a claim that the source proves anything.
    """

    path: str = Field(min_length=1, max_length=1024)
    start_line: int = Field(default=1, ge=1)
    end_line: int = Field(default=160, ge=1, le=400)
    reason: str = Field(default="planner_selected", max_length=240)

    @model_validator(mode="after")
    def _ordered_lines(self) -> "PlannerSourceRef":
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        if self.end_line - self.start_line + 1 > 400:
            raise ValueError("a planner source window may not exceed 400 lines")
        return self


class PlannerTaskProposal(BaseModel):
    """One dependency-aware, multi-file direction emitted by the main Planner."""

    task_key: str = Field(
        min_length=3,
        max_length=96,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]*$",
        description="Stable, run-local identifier used by dependency edges",
    )
    title: str = Field(min_length=3, max_length=240)
    objective: str = Field(min_length=8, max_length=2000)
    acceptance_criteria: str = Field(min_length=8, max_length=1600)
    rationale_summary: str = Field(
        min_length=3,
        max_length=1600,
        description="Short project-map-grounded reason to schedule this task; never private reasoning",
    )
    source_refs: list[PlannerSourceRef] = Field(default_factory=list, max_length=16)
    target_symbols: list[str] = Field(default_factory=list, max_length=24)
    dependencies: list[str] = Field(default_factory=list, max_length=12)
    query_hints: list[str] = Field(default_factory=list, max_length=12)
    priority: int = Field(default=50, ge=1, le=100)

    @field_validator("target_symbols", "dependencies", "query_hints")
    @classmethod
    def _dedupe_short_strings(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            value = str(value).strip()
            if value and value not in result:
                result.append(value[:240])
        return result

    @model_validator(mode="after")
    def _no_self_dependency(self) -> "PlannerTaskProposal":
        if self.task_key in self.dependencies:
            raise ValueError("a planner task cannot depend on itself")
        return self


class PlannerTaskUpdate(BaseModel):
    """A constrained update to an existing task in the durable frontier."""

    task_key: str = Field(min_length=3, max_length=96, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]*$")
    action: Literal["cancel", "defer", "reprioritize"]
    rationale_summary: str = Field(min_length=3, max_length=1200)
    priority: int | None = Field(default=None, ge=1, le=100)


class PlannerDecision(BaseModel):
    """Structured output of the sole intent-generating agent.

    Workers cannot use this shape.  The host owns all state transitions and accepts
    only validated source references and dependencies from it.
    """

    goal_state: PlannerGoalState = "continue"
    basis_summary: str = Field(
        min_length=3,
        max_length=4000,
        description="Concise auditable planning basis derived from the project map and worker results",
    )
    next_action: str = Field(default="", max_length=1200)
    missing_context: list[str] = Field(default_factory=list, max_length=24)
    tasks: list[PlannerTaskProposal] = Field(default_factory=list, max_length=8)
    updates: list[PlannerTaskUpdate] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def _distinct_task_keys(self) -> "PlannerDecision":
        keys = [item.task_key for item in self.tasks]
        if len(keys) != len(set(keys)):
            raise ValueError("a planning round cannot contain duplicate task_key values")
        return self


# --- request bodies ---------------------------------------------------------


class CreateRunRequest(BaseModel):
    # The public entrypoint has one execution model: a user-defined Planner task.
    # Reject stale prompt-era fields instead of silently accepting and ignoring them.
    model_config = ConfigDict(extra="forbid")

    snapshot_id: str
    scope: list[str] = Field(
        default_factory=list,
        description="Exact file paths frozen into this run; omit only for a goal task to select all indexable PHP files",
    )
    budgets: dict | None = None
    task: TaskSpec = Field(description="Goal-driven white-box audit task")


class PromptCreateRequest(BaseModel):
    label: str = Field(min_length=1, max_length=120)
    text: str = Field(min_length=1)
    reason: str = ""
    issues: list[str] = Field(default_factory=list)
    parent_id: str | None = None


class TruthSample(BaseModel):
    file_path: str
    category: Literal["sqli", "xss_r", "command_injection"]
    vulnerable: bool
    independently_verified: bool = False
    verification_basis: str = ""
    evidence: list[dict] = Field(default_factory=list)


class TruthRequest(BaseModel):
    samples: list[TruthSample] = Field(min_length=1)


class AttributionRequest(BaseModel):
    file_path: str
    category: Literal["sqli", "xss_r", "command_injection"]
    kind: Literal["false_positive", "false_negative", "unresolved"]
    cause: str = ""
    check_item: str = ""
    finding_id: str | None = None


class VerificationRecord(BaseModel):
    """The JSON portion of a multipart human-verification submission."""

    execution_status: ExecutionStatus
    verdict: Verdict
    modified_script: str = ""
    modification_notes: str = ""
    target_version: str = ""
    command: str = ""
    expected_result: str = ""
    normal_observation: str = ""
    attack_observation: str = ""
    browser_execution: bool = False
    notes: str = ""
