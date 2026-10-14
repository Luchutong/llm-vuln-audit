"""Structured model output and HTTP request bodies."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

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
        description="Maximum settled attempts across the entire task queue",
    )
    max_workers: int = Field(default=2, ge=1, le=4, description="Concurrent source-analysis workers for this run")
    stop_on_achieved: bool = Field(default=True, description="Stop queued work once an evidence-backed result reaches the goal")
    require_poc: bool = Field(
        default=True,
        description="Require an achieved finding to include a manually reviewable proof of concept",
    )

    @field_validator("objective", "success_criteria")
    @classmethod
    def _concrete_task_text(cls, value: str, info) -> str:
        return _meaningful_text(value, info.field_name)


class GoalFinding(BaseModel):
    """Evidence-backed finding emitted only when a goal executor reaches its target.

    A goal can also ask for non-exploit source facts, so the TaskSpec decides whether a
    POC is required. When it is required, the same immutable artifact flows into the
    existing manual-verification path.
    """

    title: str = Field(min_length=3, max_length=240)
    severity: Severity
    summary: str = Field(min_length=8, max_length=4000)
    evidence: str = Field(min_length=3, max_length=2000, description="Snapshot citations as path:start-end")
    input_source: str = Field(min_length=1, max_length=1200)
    propagation: str = Field(min_length=1, max_length=1800)
    dangerous_operation: str = Field(min_length=1, max_length=1200)
    protection: str = Field(min_length=1, max_length=1200)
    preconditions: str = Field(min_length=1, max_length=1600)
    poc: PocSpec | None = Field(default=None, description="Runnable POC when the target is a vulnerability")
    remediation: str = Field(min_length=3, max_length=2400)

    @field_validator(
        "title", "summary", "evidence", "input_source", "propagation", "dangerous_operation",
        "protection", "preconditions", "remediation",
    )
    @classmethod
    def _concrete_finding_text(cls, value: str, info) -> str:
        return _meaningful_text(value, info.field_name)


class GoalAssessment(BaseModel):
    """One bounded executor pass over a source work item.

    A worker may ask for another, distinct pass but cannot unilaterally call the whole
    task unreachable. The coordinator only makes that judgement after the durable queue
    drains and all worker outcomes are available.
    """

    outcome: TaskOutcome
    summary: str = Field(min_length=3, max_length=4000)
    reasoning: str = Field(min_length=3, max_length=4000)
    next_focus: str = Field(default="", max_length=1600)
    missing_context: list[str] = Field(default_factory=list)
    finding: GoalFinding | None = None

    @model_validator(mode="after")
    def _outcome_has_the_required_payload(self) -> "GoalAssessment":
        if self.outcome == "achieved" and self.finding is None:
            raise ValueError("achieved requires an evidence-backed finding")
        if self.outcome != "achieved" and self.finding is not None:
            raise ValueError("only achieved may attach a finding")
        if self.outcome == "continue":
            _meaningful_text(self.next_focus, "next_focus")
        return self


# --- request bodies ---------------------------------------------------------


class CreateRunRequest(BaseModel):
    snapshot_id: str
    scope: list[str] = Field(min_length=1, description="Exact file paths frozen into this run")
    prompt_id: str | None = Field(
        default=None,
        description="Fixed-audit prompt version; omitted for a goal-driven task",
    )
    budgets: dict | None = None
    task: TaskSpec | None = Field(default=None, description="Optional goal-driven task; omit for the fixed three-category audit")

    @field_validator("prompt_id")
    @classmethod
    def _normalise_prompt_id(cls, value: str | None) -> str | None:
        return value.strip() if value and value.strip() else None

    @model_validator(mode="after")
    def _require_a_fixed_prompt_only_for_the_fixed_audit(self) -> "CreateRunRequest":
        if self.task is None and self.prompt_id is None:
            raise ValueError("prompt_id is required when task is omitted")
        if self.task is not None and self.prompt_id is not None:
            raise ValueError("prompt_id must be omitted when task is provided")
        return self


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
