"""Per-state publication contract for a finding.

Adapted from AutoCVE's finalized-finding contract, but deliberately narrower: the host
still owns verification, CVSS scoring and evidence checks.  A model cannot set a
verified state, cannot submit without a root cause and citation for a candidate, and is
not forced to invent a POC or runtime impact for a static-only conclusion.  Rejections
name the field so the worker can correct the same conclusion instead of re-reporting it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from ...worker_strategies import ROOT_CAUSE_TYPES, canonical_vulnerability_type

STATES = ("static_candidate", "static_supported", "needs_evidence", "no_evidence")
# Fields only the host may set.  They are stripped with a diagnostic, never echoed into
# the record: a model saying "confirmed" is not dynamic evidence.
HOST_OWNED = frozenset({
    "confirmed", "is_verified", "verified", "verification_status", "verification_verdict",
    "latest_verification_id", "validation_state", "verdict", "status",
})
# New optional TaskFinding fields this contract encourages.  They are additive: an
# older payload without them is judged only on the requirements it can satisfy.
BASIS_FIELDS = ("input_source", "propagation", "dangerous_operation", "attack_identity",
                "object_ownership", "impact", "preconditions")


@dataclass(frozen=True)
class Rejection:
    field: str
    code: str
    message: str

    def as_dict(self) -> dict:
        return {"field": self.field, "code": self.code, "message": self.message}


@dataclass(frozen=True)
class ContractResult:
    ok: bool
    state: str
    rejections: tuple[Rejection, ...] = ()
    ignored: tuple[dict, ...] = ()
    normalized: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "state": self.state,
            "rejections": [item.as_dict() for item in self.rejections],
            "ignored": [dict(item) for item in self.ignored],
        }


def _text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) else ""


def _location(payload: dict) -> tuple[bool, str]:
    location = payload.get("primary_location")
    if not isinstance(location, dict):
        return False, "primary_location must be an object with path and line"
    path = _text(location.get("path"))
    line = location.get("line")
    if not path:
        return False, "primary_location.path is required"
    if path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
        return False, "primary_location.path must be snapshot-relative"
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        return False, "primary_location.line must be a positive integer"
    return True, ""


def _root_cause(payload: dict) -> tuple[bool, str]:
    raw = _text(payload.get("vulnerability_type"))
    if not raw:
        return False, "vulnerability_type is required (use unknown with classification_reason when unsure)"
    cause = canonical_vulnerability_type(raw)
    if cause and cause != "unknown":
        return True, ""
    if cause == "unknown" and not _text(payload.get("classification_reason")):
        return False, "unknown vulnerability_type requires classification_reason"
    return True, ""


def _basis(payload: dict) -> list[str]:
    return [name for name in BASIS_FIELDS if _text(payload.get(name))]


def derive_state(payload: dict, missing_context: Iterable[str] = ()) -> str:
    """Classify a payload without deciding whether it is true.

    ``needs_evidence`` is only for a payload that explicitly says a decisive fact is
    missing.  A completed POC description does not make a claim dynamically verified.
    """
    if str(payload.get("kind") or "").strip().casefold() != "vulnerability":
        return "no_evidence"
    declared_missing = payload.get("missing_context")
    declared_missing = declared_missing if isinstance(declared_missing, list) else ()
    if list(missing_context) or declared_missing:
        return "needs_evidence"
    # ``static_supported`` is claimed only when the payload states a path *and* an
    # impact, which is exactly what its stricter checks require.  A live publication
    # rarely carries an explicit impact field, so it stays a candidate rather than
    # being rejected for a field the host never asked it for.
    if (_text(payload.get("dangerous_operation"))
            and (_text(payload.get("propagation")) or _text(payload.get("attack_identity"))
                 or _text(payload.get("object_ownership")))
            and _text(payload.get("impact"))
            and not payload.get("unproven_impact")):
        return "static_supported"
    return "static_candidate"


def validate_finding(
    payload: Any,
    *,
    state: str | None = None,
    missing_context: Iterable[str] = (),
) -> ContractResult:
    """Validate one finding payload at the requested conclusion state."""
    if not isinstance(payload, dict):
        return ContractResult(ok=False, state=state or "static_candidate",
                              rejections=(Rejection("finding", "not_object",
                                                    "finding must be a JSON object"),))
    chosen = state or derive_state(payload, missing_context)
    if chosen not in STATES:
        chosen = "static_candidate"
    ignored = tuple({"field": key, "message": "host-owned field ignored"}
                    for key in sorted(HOST_OWNED & set(payload)))
    rejections: list[Rejection] = []

    def require(field_name: str, ok: bool, code: str, message: str) -> None:
        if not ok:
            rejections.append(Rejection(field_name, code, message))

    kind = str(payload.get("kind") or "").strip().casefold()
    if chosen == "no_evidence":
        if kind == "vulnerability":
            rejections.append(Rejection("kind", "vulnerability_without_evidence",
                                        "a vulnerability claim needs a supported state, not no_evidence"))
        return ContractResult(ok=not rejections, state=chosen, rejections=tuple(rejections),
                              ignored=ignored)

    require("kind", kind == "vulnerability", "kind",
            'kind must be "vulnerability" for a finding')
    require("title", len(_text(payload.get("title"))) >= 3, "title_missing",
            "title must be at least 3 characters")
    require("summary", len(_text(payload.get("summary"))) >= 8, "summary_missing",
            "summary must explain the cited source")
    require("evidence", bool(_text(payload.get("evidence"))), "evidence_missing",
            "evidence must cite at least one displayed path:start-end")

    if chosen == "needs_evidence":
        missing = [str(item) for item in missing_context if str(item).strip()]
        require("missing_context", bool(missing), "missing_context_missing",
                "a needs_evidence finding must name the decisive missing fact")
        # A location is optional here, but a provided one must still be well formed.
        if payload.get("primary_location") is not None:
            ok, message = _location(payload)
            require("primary_location", ok, "primary_location_invalid", message)
        return ContractResult(ok=not rejections, state=chosen, rejections=tuple(rejections),
                              ignored=ignored)

    ok, message = _root_cause(payload)
    require("vulnerability_type", ok, "root_cause_missing", message)
    ok, message = _location(payload)
    require("primary_location", ok, "primary_location_invalid", message)
    # A cited candidate does not have to spell out every basis field: the host asks for
    # them, but a title+summary+evidence+location claim is already reviewable and must not
    # be demoted for a field the model left empty.  The stricter state does require them.
    if chosen == "static_supported":
        basis = _basis(payload)
        require("basis", bool(basis), "basis_missing",
                "at least one of " + ", ".join(BASIS_FIELDS) + " must describe the concrete basis")
        require("dangerous_operation", bool(_text(payload.get("dangerous_operation"))),
                "sink_missing", "a static-supported conclusion needs a sink or state change")
        require("impact", bool(_text(payload.get("impact"))),
                "impact_missing", "a static-supported conclusion needs an actual impact")
        # An input source alone names where data enters, not how it reaches the sink; a
        # static-supported claim must also describe that path or the authorization basis.
        require("propagation_or_identity",
                bool(_text(payload.get("propagation")) or _text(payload.get("attack_identity"))
                     or _text(payload.get("object_ownership"))),
                "path_missing",
                "a static-supported conclusion needs a data/control path or an authorization basis")
    normalized = dict(payload)
    if _text(normalized.get("vulnerability_type")):
        normalized["vulnerability_type"] = (
            canonical_vulnerability_type(normalized["vulnerability_type"])
            if canonical_vulnerability_type(normalized["vulnerability_type"]) in ROOT_CAUSE_TYPES
            else _text(normalized["vulnerability_type"]).casefold()
        )
    return ContractResult(ok=not rejections, state=chosen, rejections=tuple(rejections),
                          ignored=ignored, normalized=normalized)


def rejections_text(result: ContractResult) -> str:
    return "; ".join(f"{item.field}: {item.message}" for item in result.rejections)
