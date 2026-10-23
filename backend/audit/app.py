"""FastAPI application: HTTP surface, SSE stream and the worker lifespan."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Body, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .config import CredentialVault, DEFAULT_BUDGETS, VERSION, Settings, clamp_budgets, find_env_file, load_env_file
from .db import Store, now
from .events import EventBus
from .health import ModelHealth
from .finding_policy import partition_findings, source_observations
from .metrics import comparable_runs, prompt_diffs, summarise
from .project_findings import backfill_project_ledger
from .projects import ensure_project, ensure_projects
from .prompts import DEFAULT_PROMPT_ID, builtin_prompt_records
from .report import collect_evidence, render_json, render_markdown, render_zip
from .schemas import (
    AttributionRequest,
    CreateRunRequest,
    ModelProfileCreateRequest,
    ModelProfileUpdateRequest,
    PromptCreateRequest,
    TruthRequest,
)
from .source import MAX_LISTED_PATHS, SourceRepository
from .worker import AuditWorker
from .runtime import AgentPolicy
from .cvss_assessment import propose
from .cvss31 import BASE
from .cvss_store import CvssConflict
from .schemas import CvssEditRequest
from .evidence import validate_evidence
from .execution_state import DEFAULT_RUN_LIMITS, MIN_RUN_LIMITS, MAX_RUN_LIMITS
from .poc_readiness import PocReadinessService
from .poc_store import poc_target_key

BACKEND_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIST = BACKEND_DIR.parent / "frontend" / "dist"


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_name(value: str) -> str:
    cleaned = Path(value.replace("\\", "/")).name.strip()[:120]
    return "".join(ch for ch in cleaned if ch.isprintable() and ch not in '/\\:*?"<>|') or "upload.bin"


class Services:
    """Process-wide singletons, created once in the lifespan hook."""

    def __init__(self, settings: Settings):
        self.settings = settings
        # Keep the environment connection separate from the currently selected
        # profile.  It remains available as a non-secret fallback profile and
        # provides the common thinking policy for browser-saved profiles.
        self.environment_model = settings.model
        self.store = Store(settings.db_path)
        self.vault = CredentialVault(settings.data_dir)
        selected_profile = self.store.ensure_environment_model_profile(
            self.environment_model.model,
            self.environment_model.base_url,
        )
        if selected_profile is not None:
            self.settings.model = self.model_config_for_profile(selected_profile)
        self.repository = SourceRepository(settings.data_dir)
        # Backfill is guarded by schema_meta and idempotent: an old data directory gains
        # projects and a ledger exactly once, while a fresh one does nothing here.
        if self.store.schema_meta("project_backfill_v1") != "done":
            ensure_projects(self.store, self.repository)
            backfill_project_ledger(self.store)
            self.store.set_schema_meta("project_backfill_v1", "done")
        self.bus = EventBus(self.store)
        self.poc_readiness = PocReadinessService(settings)
        self.health = ModelHealth()
        saved_health = self.store.load_health()
        if saved_health is not None and saved_health.get("model") == self.health_key:
            self.health.restore(saved_health)
        self.health.on_change = lambda state: self.store.save_health(self.health_key, state)
        self.worker = AuditWorker(
            settings=settings,
            store=self.store,
            repository=self.repository,
            bus=self.bus,
            health=self.health,
            resolve_model_profile=self.model_config_for_run_profile,
        )
        for prompt in builtin_prompt_records():
            self.store.upsert_builtin_prompt(prompt)

    def model_config_for_profile(self, profile: dict):
        """Build the only runtime config used for a saved provider profile."""
        if profile.get("credential_source") == "environment":
            # The persisted environment profile is deliberately display-safe: it
            # never carries URL user-info or query parameters.  Keep the original
            # process configuration only in memory for the actual model client.
            return self.environment_model
        try:
            api_key = self.vault.decrypt(str(profile.get("api_key_secret") or ""))
        except RuntimeError:
            # A lost local key must make the profile visibly unconfigured, not
            # stop the server before the user can replace its credential.
            api_key = ""
        return replace(
            self.environment_model,
            model=str(profile.get("model") or ""),
            base_url=str(profile.get("base_url") or "").rstrip("/"),
            api_key=api_key,
        )

    def model_config_for_run_profile(self, snapshot: dict):
        """Resolve a frozen run's credential without changing its public identity.

        A run stores only the profile id, model id, and public endpoint.  The
        selected profile may be different after a restart, so lookup is always by
        the frozen id.  The public endpoint is used to verify identity; the actual
        endpoint remains in the profile so compatibility query parameters or other
        credentials are never written into a run record.
        """
        profile_id = str(snapshot.get("profile_id") or "").strip()
        model = str(snapshot.get("model") or "").strip()
        base_url = str(snapshot.get("base_url") or "").strip().rstrip("/")
        if not (profile_id and model and base_url):
            return None
        profile = self.store.get_model_profile(profile_id, include_secret=True)
        if profile is None:
            return None
        config = self.model_config_for_profile(profile)
        if config.public_base_url() != base_url:
            return None
        return replace(config, model=model)

    @property
    def health_key(self) -> str:
        """Tie persisted breaker state to a profile, not merely a model name."""
        profile = self.store.selected_model_profile()
        if profile is not None:
            return f"profile:{profile['id']}"
        return f"legacy:{self.settings.model.model}:{self.settings.model.base_url}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    env_file = find_env_file(BACKEND_DIR)
    if env_file is not None:
        load_env_file(env_file)
    settings = Settings.load()
    services = Services(settings)
    app.state.services = services
    await services.worker.start()
    try:
        yield
    finally:
        await services.worker.stop()
        services.store.close()


app = FastAPI(title="PHP White-box Audit Workbench", version=VERSION, lifespan=lifespan)


def _client_in_networks(client: str, entries) -> bool:
    """True when a peer address matches one of the configured runner networks.

    Invalid entries are ignored rather than raising: a typo in an optional hardening
    list must not prevent the server from starting.
    """
    import ipaddress

    try:
        address = ipaddress.ip_address(client or "")
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    for entry in entries or ():
        text = str(entry or "").strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        if address in network:
            return True
    return False


@app.middleware("http")
async def reject_runner_clients(request: Request, call_next):
    """Keep the POC runner away from the audit API.

    Network isolation already places the runner on a private control network; this is
    defence in depth for the one reachable service.  Requests from configured runner
    addresses may only use the reserved ``/internal/poc`` prefix (none today) and are
    refused on ``/api/*``.  The list is empty by default, so an ordinary local browser
    keeps working even when the setting is not provided.
    """
    path = request.url.path
    if path.startswith("/api/") and not path.startswith("/internal/poc/"):
        state = getattr(request.app.state, "services", None)
        poc = getattr(getattr(state, "settings", None), "poc", None)
        entries = getattr(poc, "runner_addrs", ()) if poc is not None else ()
        peer = request.client.host if request.client else ""
        if entries and _client_in_networks(peer, entries):
            return JSONResponse(
                status_code=403,
                content={"detail": "POC runner clients may not call the audit API"},
            )
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def redact_model_key_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    """Keep an invalid browser-submitted API key out of FastAPI's 422 payload.

    Pydantic v2 includes the rejected input in validation details by default. That
    is helpful for ordinary form fields, but returning a malformed or too-long
    provider key defeats the profile endpoint's no-key-readback guarantee.
    """
    details = []
    for error in exc.errors():
        cleaned = dict(error)
        if "api_key" in cleaned.get("loc", ()):
            cleaned["input"] = "[redacted]"
        details.append(cleaned)
    return JSONResponse(status_code=422, content=jsonable_encoder({"detail": details}))


def services(request: Request) -> Services:
    return request.app.state.services


def _module_row(module: dict) -> dict:
    """One architecture grouping, under a key that says it is a directory.

    The stored map calls this key ``path``.  Every other ``path`` in this projection is a
    file, so leaving the original key in place lets a reader -- or a plan -- cite a module
    as a source ref and send a worker to read a directory.  The Planner's own views rename
    it the same way (`agent.py`); the stored map keeps its own key.
    """
    row = {key: value for key, value in module.items() if key != "path"}
    row["directory"] = module.get("path")
    return row


def _project_map_projection(run_id: str, project_map: dict | None) -> dict | None:
    """Bound the frozen project map before it is sent to a browser.

    ``GET /runs/{id}`` used to inline the whole map, which was acceptable for a few
    hundred PHP files and is megabytes of JSON for a whole uploaded project.  The
    projection keeps every field the views and the report actually read, under the same
    ``project_map`` key, and points at the full map for export and deep inspection.
    """
    if not isinstance(project_map, dict):
        return None
    architecture = project_map.get("architecture") or {}
    return {
        "run_id": run_id,
        "snapshot_id": project_map.get("snapshot_id"),
        "scope_files": len(project_map.get("scope") or []),
        "stats": project_map.get("stats") or {},
        "entrypoints": list(project_map.get("entrypoints") or [])[:16],
        "binary_files": list(project_map.get("binary_files") or [])[:50],
        "unresolved_root_candidates": list(project_map.get("unresolved_root_candidates") or [])[:16],
        "directories": list(project_map.get("directories") or [])[:MAX_LISTED_PATHS],
        "architecture": {
            "role_counts": architecture.get("role_counts") or {},
            "modules": [_module_row(module) for module in list(architecture.get("modules") or [])[:12]],
            "bootstrap_files": list(architecture.get("bootstrap_files") or [])[:8],
            "include_graph": architecture.get("include_graph") or {},
        },
        "parse_errors": list(project_map.get("parse_errors") or [])[:20],
        "limitations": list(project_map.get("limitations") or [])[:3],
        # The arrays omitted above are large; the UI must be able to say so honestly.
        "omitted": ["files", "symbols", "includes", "calls"],
        "full_map_path": f"/api/runs/{run_id}/project-map",
    }


_VERIFICATION_STATUSES = (
    "verified", "rejected", "inconclusive", "not_applicable",
    "environment_unavailable", "unverified", "stale",
)


def _verification_summary(findings: list[dict]) -> dict:
    summary = {status: 0 for status in _VERIFICATION_STATUSES}
    for finding in findings:
        status = str(finding.get("verification_status") or "unverified")
        summary[status] = summary.get(status, 0) + 1
    return summary


def _verification_records(store, findings: list[dict]) -> list[dict]:
    """The per-finding POC verification detail the Planner acts on.

    The summary only counts statuses; this is the feedback loop the audit agent
    actually needs: for every finding the run has already verified or judged, the
    latest record's observation, verdict and evidence notes, bounded to keep the
    prompt readable.  A rejected verdict with a contradictory observation means
    the finding itself is wrong (retract), while an inconclusive record with a
    healthy-looking observation points at insufficient evidence (re-verify), and
    the Planner can only tell the two apart with these details in front of it.
    """
    records: list[dict] = []
    for finding in findings:
        status = str(finding.get("verification_status") or "unverified")
        if status == "unverified":
            continue
        rows = store.list_verifications(finding["id"]) if finding.get("id") else []
        if not rows:
            continue
        row = rows[-1]
        agent = row.get("agent") or {}
        title = str(finding.get("title") or "")[:160]
        records.append({
            "finding_id": finding.get("id"),
            "finding_title": title,
            "status": str(row.get("status") or status),
            "verdict": row.get("verdict"),
            "execution_status": str(row.get("execution_status") or ""),
            "summary": str(agent.get("summary") or "")[:400],
            "normal_observation": str(row.get("normal_observation") or "")[:600],
            "attack_observation": str(row.get("attack_observation") or "")[:1200],
            "evidence_notes": str(row.get("notes") or "")[:600],
            "browser_execution": bool(row.get("browser_execution")),
            "jobs": list(agent.get("jobs") or [])[:8],
            "verification_id": row.get("id"),
        })
    return records


def _project_projection(
    state: Services, run: dict, findings: list[dict], relations: list[dict] | None = None
) -> dict:
    """The project half of a run bundle: ledger context, carried findings, verification.

    Kept out of the run row itself because it is live: the ledger is shared, so a sibling
    run may add to it while this run is still going.  ``project_baseline`` on the run is
    the frozen view this run actually reasoned over.
    """
    project_id = str(run.get("project_id") or "")
    project = state.store.get_project(project_id) if project_id else None
    if project is None:
        return {
            "project": None,
            "project_findings": [],
            "carried_findings": [],
            "verification_jobs": [],
            "verification_summary": _verification_summary(findings),
            "verification_records": _verification_records(state.store, findings),
            # Narratives only exist for project-mode runs; a legacy run's report must not
            # gain a section it never produced.
            "report_narrative": {},
        }
    relations = relations if relations is not None else state.store.list_run_project_findings(run["id"])
    return {
        "project": project,
        "project_findings": state.store.list_project_findings(
            project_id, include_withdrawn=False, limit=200
        ),
        "carried_findings": [
            row for row in relations if str(row.get("run_relation")) == "carried"
        ],
        "verification_jobs": state.store.list_run_verification_jobs(run["id"]),
        "verification_summary": _verification_summary(findings),
        "verification_records": _verification_records(state.store, findings),
        "report_narrative": state.store.latest_plan_narrative(run["id"]),
    }


def _run_bundle(state: Services, run_id: str) -> dict:
    run = state.store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    all_findings = state.store.list_findings(run_id)
    findings, _ = partition_findings(all_findings)
    truths = state.store.list_truths(run["snapshot_id"])
    # One query serves both the metrics delta and the "carried" section; the ledger rows
    # are the only record of which conclusions this run reused rather than reached.
    relations = state.store.list_run_project_findings(run_id) if run.get("project_id") else []
    planner = state.store.get_planner_session(run_id)
    if planner is not None:
        tasks = state.store.list_tasks(run_id)
        goal = state.store.get_task_goal(run_id)
        audit_observations = source_observations(all_findings, tasks)
        return {
            "run": run,
            "goal": goal,
            "goals": [goal] if goal else [],
            "planner": planner,
            "project_map": _project_map_projection(run_id, state.store.get_project_map(run_id)),
            "plans": state.store.list_plans(run_id),
            "tasks": tasks,
            # What the Planner was told about coverage and reconnaissance, read back
            # from the event log so the report can explain the rounds it summarises.
            "observations": state.store.list_planner_observations(run_id),
            # What this run has already had answered, and what it declined to re-ask.
            # Payload-free: the answer itself is fetched one topic at a time, so a run
            # API response cannot grow with research the caller did not ask for.
            "investigations": state.store.investigation_overview(run_id),
            # Compatibility fields remain empty for older API consumers; Planner v2
            # does not create per-file run units or the former static work queue.
            "units": [],
            "work_items": [],
            "findings": findings,
            "source_observations": audit_observations,
            "attributions": [],
            "metrics": {**summarise(run, [], all_findings, truths, tasks=tasks,
                                     project_relations=relations),
                        "source_observations": len(audit_observations)},
            **_project_projection(state, run, all_findings, relations),
        }
    units = state.store.list_run_units(run_id)
    work_items = state.store.list_task_work_items(run_id)
    audit_observations = source_observations(all_findings, work_items)
    return {
        "run": run,
        "units": units,
        "goals": state.store.list_task_goals(run_id),
        "work_items": work_items,
        "findings": findings,
        "source_observations": audit_observations,
        "attributions": state.store.list_attributions(run_id),
        "metrics": {**summarise(run, units, all_findings, truths, project_relations=relations),
                    "source_observations": len(audit_observations)},
        **_project_projection(state, run, all_findings, relations),
    }


# --- configuration ----------------------------------------------------------


def _config_payload(state: Services) -> dict:
    selected_profile = state.store.selected_model_profile()
    selected_id = selected_profile["id"] if selected_profile is not None else None
    profiles = state.store.list_model_profiles()
    for profile in profiles:
        profile["selected"] = profile["id"] == selected_id
        if profile.get("credential_source") == "environment":
            profile["api_key_configured"] = bool(state.environment_model.api_key)
    return {
        **state.settings.model.public(),
        "selected_profile_id": selected_id,
        "model_profiles": profiles,
        "budgets": state.settings.budgets,
        "budget_limits": {"defaults": DEFAULT_BUDGETS},
        "run_budget_limits": {"defaults": DEFAULT_RUN_LIMITS, "min": MIN_RUN_LIMITS, "max": MAX_RUN_LIMITS},
        "agent_policy": AgentPolicy().snapshot(),
        "poc": {**state.settings.poc.public(), "supported_targets": ["dvwa"]},
        "worker": state.worker.status,
        "model_health": state.health.snapshot(),
        "version": VERSION,
    }


@app.get("/api/config")
async def get_config(request: Request) -> dict:
    return _config_payload(services(request))


@app.get("/api/poc/readiness")
async def poc_readiness(request: Request, snapshot_id: str) -> dict:
    state = services(request)
    snapshot = state.store.get_snapshot(snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Snapshot does not exist")
    if not hasattr(state, "poc_readiness"):
        state.poc_readiness = PocReadinessService(state.settings)
    return await state.poc_readiness.check(snapshot.get("target_profile", "unknown"))


def _require_no_active_run(state: Services) -> None:
    """Keep a profile edit from changing the connection mid-audit."""
    active_runs = state.store.active_run_count()
    if active_runs:
        raise HTTPException(
            status_code=409,
            detail=f"当前有 {active_runs} 个排队、执行或暂停中的审计；结束或取消后再切换模型配置。",
        )


def _activate_profile(state: Services, profile: dict) -> None:
    state.store.select_model_profile(profile["id"])
    state.settings.model = state.model_config_for_profile(profile)
    # A breaker state belongs to a concrete model/endpoint/credential history.
    # Never carry its failures into a newly selected or edited profile.
    state.health.reset()


@app.post("/api/config/profiles", status_code=201)
async def create_model_profile(request: Request, payload: ModelProfileCreateRequest) -> dict:
    state = services(request)
    _require_no_active_run(state)
    profile = state.store.create_model_profile(
        label=payload.label,
        model=payload.model,
        base_url=payload.base_url,
        api_key_secret=state.vault.encrypt(payload.api_key),
        credential_source="stored",
    )
    if state.store.selected_model_profile() is None:
        _activate_profile(state, profile)
    return _config_payload(state)


@app.put("/api/config/profiles/{profile_id}")
async def update_model_profile(request: Request, profile_id: str, payload: ModelProfileUpdateRequest) -> dict:
    state = services(request)
    _require_no_active_run(state)
    current = state.store.get_model_profile(profile_id, include_secret=True)
    if current is None:
        raise HTTPException(status_code=404, detail="模型配置档案不存在")
    if current.get("credential_source") == "environment":
        raise HTTPException(status_code=409, detail="环境变量档案由 .env 管理；请新建档案并录入独立 API Key。")
    secret = state.vault.encrypt(payload.api_key) if payload.api_key is not None else None
    source = "stored" if payload.api_key is not None else None
    try:
        profile = state.store.update_model_profile(
            profile_id,
            label=payload.label,
            model=payload.model,
            base_url=payload.base_url,
            api_key_secret=secret,
            credential_source=source,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if state.store.selected_model_profile() and state.store.selected_model_profile()["id"] == profile_id:
        _activate_profile(state, profile)
    return _config_payload(state)


@app.post("/api/config/profiles/{profile_id}/select")
async def select_model_profile(request: Request, profile_id: str) -> dict:
    state = services(request)
    _require_no_active_run(state)
    profile = state.store.get_model_profile(profile_id, include_secret=True)
    if profile is None:
        raise HTTPException(status_code=404, detail="模型配置档案不存在")
    _activate_profile(state, profile)
    return _config_payload(state)


@app.delete("/api/config/profiles/{profile_id}")
async def delete_model_profile(request: Request, profile_id: str) -> Response:
    state = services(request)
    _require_no_active_run(state)
    selected = state.store.selected_model_profile()
    if selected is not None and selected["id"] == profile_id:
        raise HTTPException(status_code=409, detail="不能删除当前模型档案；请先选择另一个档案。")
    profile = state.store.get_model_profile(profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="模型配置档案不存在")
    if profile.get("credential_source") == "environment":
        raise HTTPException(status_code=409, detail="环境变量档案不能删除。")
    state.store.delete_model_profile(profile_id)
    return Response(status_code=204)


@app.post("/api/config/check")
async def check_config(request: Request) -> dict:
    """Send one real minimal request. A silent-but-connected model still fails."""
    state = services(request)
    config = state.settings.model
    if not config.configured:
        return {"ok": False, "error": f"缺少配置：{', '.join(config.missing())}"}

    # The check goes through the same client, the same gate and the same request
    # parameters as a real phase, so "connected" here means the endpoint answers what
    # this run actually sends -- not a second, differently-configured code path that can
    # pass while every real request fails.
    from smolagents.models import ChatMessage

    from .codemodel import AuditCodeModel, PhaseGate
    from .runtime import AgentPolicy, Execution

    started = time.monotonic()
    # The request ceiling is the check's own wall clock, so the HTTP timeout and the
    # deadline below are the same number rather than two independently chosen ones.
    execution = Execution({"responses": 1, "tools": 0, "seconds": 45},
                          AgentPolicy(request_seconds=45), lambda event: None)
    execution.enter("config_check")
    model = None

    async def unreachable(name: str, args: dict) -> str:  # pragma: no cover - no tools offered
        raise RuntimeError(f"配置检查没有工具：{name}")

    try:
        gate = PhaseGate(
            execution=execution,
            loop=asyncio.get_running_loop(),
            dispatch=unreachable,
            deadline=execution.deadline,
            limit=1,
        )
        model = AuditCodeModel(config, gate=gate, max_tokens=32)
        # The client is synchronous, like every other request this run makes; the thread
        # hop is what keeps the gate's callbacks on this loop.
        message = await asyncio.wait_for(
            asyncio.to_thread(
                model.generate,
                [ChatMessage(role="user", content="Reply with exactly two characters: OK")],
            ),
            timeout=45,
        )
        reply = (message.content or "").strip() if isinstance(message.content, str) else ""
        elapsed = int((time.monotonic() - started) * 1000)
        if not reply:
            state.health.trip("endpoint returned an empty reply")
            return {"ok": False, "error": "端点连通但模型未返回任何内容", "latency_ms": elapsed}
        state.health.pass_()
        return {"ok": True, "model": config.label, "latency_ms": elapsed, "reply": config.redact(reply)[:200]}
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        error = config.redact(f"{type(exc).__name__}: {exc}")
        state.health.trip(error, status=status)
        return {
            "ok": False,
            "error": error[:300],
            "latency_ms": int((time.monotonic() - started) * 1000),
        }
    finally:
        close = getattr(getattr(model, "client", None), "close", None)
        if close is not None:
            close()


# --- snapshots --------------------------------------------------------------


@app.post("/api/snapshots")
async def create_snapshot(request: Request, file: UploadFile = File(...)) -> dict:
    """Import an uploaded project and bind it to its content-key project.

    A byte-identical archive reuses the existing snapshot outright; a re-zipped archive
    of the same tree becomes a new snapshot of the *same* project, because the project
    identity is the indexed text content rather than the archive bytes.
    """
    state = services(request)
    data = await file.read()
    digest = hashlib.sha256(data).hexdigest()
    existing = state.store.get_snapshot_by_archive_sha256(digest)
    if existing is not None:
        try:
            snapshot = await asyncio.to_thread(state.repository.get_snapshot, existing["id"])
        except (FileNotFoundError, ValueError):
            snapshot = dict(existing)
        project = state.store.get_project(existing["project_id"]) if existing.get("project_id") else None
        if project is None:
            # A snapshot from before projects existed, or one whose binding was lost:
            # rebind it rather than leaving the upload path inconsistent.
            snapshot, _ = ensure_project(state.store, snapshot)
            project = state.store.get_project(snapshot["project_id"])
        snapshot.setdefault("content_key", existing.get("content_key"))
        snapshot.setdefault("target_profile", existing.get("target_profile") or "unknown")
        return {
            **snapshot,
            "project_id": project["id"] if project else None,
            "project": project,
            "project_reused": True,
            "snapshot_reused": True,
        }
    try:
        snapshot = await asyncio.to_thread(state.repository.import_zip, data, file.filename or "upload.zip")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    state.store.add_snapshot(snapshot)
    project, created = ensure_project(state.store, snapshot)
    return {
        **snapshot,
        "project_id": project["id"],
        "project": project,
        "project_reused": not created,
        "snapshot_reused": False,
    }


@app.get("/api/snapshots")
async def list_snapshots(request: Request) -> list[dict]:
    return services(request).store.list_snapshots()


@app.get("/api/snapshots/{snapshot_id}")
async def get_snapshot(request: Request, snapshot_id: str) -> dict:
    state = services(request)
    try:
        # The immutable index is published before content-key project binding. Keep
        # provenance in SQLite and enrich a response copy, never the cached/disk index.
        snapshot = dict(state.repository.get_snapshot(snapshot_id))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot does not exist") from exc
    stored = state.store.get_snapshot(snapshot_id)
    if stored is not None:
        for key in ("project_id", "content_key", "target_profile"):
            if stored.get(key) is not None:
                snapshot[key] = stored[key]
    return snapshot


@app.get("/api/snapshots/{snapshot_id}/source")
async def get_source(
    request: Request,
    snapshot_id: str,
    path: str = Query(...),
    start: int = Query(1, ge=1),
    end: int = Query(200, ge=1),
) -> dict:
    try:
        return services(request).repository.read_source(snapshot_id, path, start, end)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/snapshots/{snapshot_id}")
async def delete_snapshot(request: Request, snapshot_id: str) -> Response:
    """Drop an uploaded source archive and its truth table.

    Refused with 409 while any run still freezes this snapshot as its source:
    deleting it would make those runs' reports unreproducible.  Delete the runs
    first.
    """
    state = services(request)
    if state.store.get_snapshot(snapshot_id) is None:
        raise HTTPException(status_code=404, detail="Snapshot does not exist")
    try:
        await asyncio.to_thread(state.store.delete_snapshot, snapshot_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=204)


# --- projects ---------------------------------------------------------------


def _project_detail(state: Services, project_id: str, *, include_findings: bool) -> dict:
    project = state.store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project does not exist")
    detail = dict(project)
    detail["runs"] = [run for run in state.store.list_runs() if run.get("project_id") == project_id]
    detail["snapshots"] = [
        row for row in state.store.list_snapshots() if row.get("project_id") == project_id
    ]
    if include_findings:
        detail["findings"] = state.store.list_project_findings(project_id, include_withdrawn=True)
    return detail


@app.get("/api/projects")
async def list_projects(request: Request) -> list[dict]:
    return services(request).store.list_projects()


@app.get("/api/projects/{project_id}")
async def get_project(request: Request, project_id: str, include_findings: bool = Query(True)) -> dict:
    return _project_detail(services(request), project_id, include_findings=include_findings)


@app.get("/api/projects/{project_id}/findings")
async def list_project_findings(
    request: Request,
    project_id: str,
    include_withdrawn: bool = Query(True),
    limit: int = Query(200, ge=1, le=1000),
) -> list[dict]:
    state = services(request)
    if state.store.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project does not exist")
    return state.store.list_project_findings(
        project_id, include_withdrawn=include_withdrawn, limit=limit
    )


@app.get("/api/projects/{project_id}/runs")
async def list_project_runs(request: Request, project_id: str) -> list[dict]:
    state = services(request)
    if state.store.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project does not exist")
    return [run for run in state.store.list_runs() if run.get("project_id") == project_id]


@app.get("/api/project-findings")
async def search_project_findings(
    request: Request,
    project_id: str | None = Query(None),
    q: str | None = Query(None, max_length=200),
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|none|unknown)$"),
    verification_status: str | None = Query(
        None, pattern="^(verified|rejected|inconclusive|not_applicable|environment_unavailable|unverified|stale)$"
    ),
    cvss_status: str | None = Query(None, pattern="^(scored|needs_information|legacy_unrated|stale)$"),
    disposition: str | None = Query(None, pattern="^(all|open|retracted|duplicate|superseded|contested)$"),
    offset: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=100),
) -> dict:
    state = services(request)
    if project_id and state.store.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project does not exist")
    return state.store.search_project_findings(
        project_id=project_id, q=q, severity=severity, verification_status=verification_status,
        cvss_status=cvss_status, disposition=disposition, offset=offset, limit=limit,
    )



def _cvss_edit(state, ident, payload):
    finding = state.store.get_project_finding(ident)
    if finding is None:
        raise HTTPException(404, "Project finding does not exist")
    info = finding.get("cvss_assessment") or {}
    if finding["revision"] != payload.expected_revision or int(info.get("assessment_revision") or 0) != payload.expected_assessment_revision:
        raise HTTPException(409, "结论或评分已更新，请刷新后比较并重新提交。")
    if set(payload.metrics) != set(BASE):
        raise HTTPException(422, "必须且只能提供 AV/AC/PR/UI/S/C/I/A 八项指标")
    run = state.store.get_run(finding.get("last_run_id") or "")
    snapshot_id = (run or {}).get("snapshot_id")
    def references(refs):
        if not snapshot_id or not getattr(state, "repository", None):
            return [], ["评分依据的源码快照不可用；可使用明确说明的人工假设"]
        try:
            snapshot = state.repository.get_snapshot(snapshot_id)
        except (KeyError, FileNotFoundError):
            return [], ["评分依据的源码快照不可用"]
        files = {item["path"]: item["line_count"] for item in snapshot["files"] if item.get("kind") != "binary"}
        return validate_evidence(refs, files, [(path, 1, end) for path, end in files.items()])
    try:
        return propose(payload.metrics, source="manual", strict=True, validate_refs=references,
                       snapshot_id=snapshot_id, run_id=(run or {}).get("id"))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/api/project-findings/{finding_id}/cvss/preview")
async def preview_project_cvss(request: Request, finding_id: str, payload: CvssEditRequest) -> dict:
    return _cvss_edit(services(request), finding_id, payload)


@app.put("/api/project-findings/{finding_id}/cvss")
async def update_project_cvss(request: Request, finding_id: str, payload: CvssEditRequest) -> dict:
    state = services(request)
    rating = _cvss_edit(state, finding_id, payload)
    try:
        return state.store.update_project_cvss(finding_id, rating, expected_revision=payload.expected_revision,
            expected_assessment_revision=payload.expected_assessment_revision, reason=payload.reason.strip())
    except KeyError as exc:
        raise HTTPException(404, "Project finding does not exist") from exc
    except CvssConflict as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/project-findings/{finding_id}/cvss-history")
async def project_cvss_history(request: Request, finding_id: str,
        offset: int = Query(0, ge=0), limit: int = Query(25, ge=1, le=100)) -> dict:
    try:
        return services(request).store.project_cvss_history(finding_id, offset=offset, limit=limit)
    except KeyError as exc:
        raise HTTPException(404, "Project finding does not exist") from exc


def _finding_run_source(run: dict | None) -> dict | None:
    if run is None:
        return None
    return {key: run.get(key) for key in ("id", "snapshot_id", "snapshot_name", "status", "created_at")}


@app.get("/api/project-findings/{project_finding_id}")
async def get_project_finding(request: Request, project_finding_id: str) -> dict:
    state = services(request)
    finding = state.store.get_project_finding(project_finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Project finding does not exist")
    verifications = state.store.project_finding_verifications(project_finding_id)
    # Rediscovery can keep a valid verification from an earlier run. A correction keeps
    # that record as history, but it must not support the current canonical conclusion.
    current_verification = next((
        record for record in verifications
        if record["id"] == finding.get("latest_verification_id")
        and finding.get("verification_status") != "stale"
        and (record.get("finding_revision") is None or record["finding_revision"] == finding["revision"])
    ), None)
    last_finding = state.store.get_finding(finding["last_finding_id"])
    poc_finding_id = None
    if (finding.get("poc") or {}).get("script") and last_finding is not None:
        if last_finding.get("poc") == finding["poc"]:
            poc_finding_id = last_finding["id"]
    return {
        "finding": finding,
        "project": state.store.get_project(finding["project_id"]),
        "origin_run": _finding_run_source(state.store.get_run(finding["origin_run_id"])),
        "last_run": _finding_run_source(state.store.get_run(finding["last_run_id"])),
        "history": state.store.project_finding_history(project_finding_id),
        "verifications": verifications,
        "current_verification": current_verification,
        "poc_finding_id": poc_finding_id,
        "poc_download_path": f"/api/findings/{poc_finding_id}/poc" if poc_finding_id else None,
    }


# --- runs -------------------------------------------------------------------


def _resolve_run_scope(state: Services, payload: CreateRunRequest) -> tuple[dict, dict]:
    """Resolve the one snapshot a run audits and the project that snapshot belongs to.

    A project run uses the project's latest snapshot: the audit target is the project's
    content, and the latest upload is the most recent reading of it.  A snapshot run still
    works for embedding callers, and is bound to the snapshot's project (creating it if an
    older database predates projects) so its findings join the same ledger.
    """
    if payload.project_id:
        project = state.store.get_project(payload.project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project does not exist")
        if not project.get("latest_snapshot_id"):
            raise HTTPException(status_code=409, detail="该项目还没有可审计的快照，请先上传源码。")
        try:
            snapshot = state.repository.get_snapshot(project["latest_snapshot_id"])
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Project snapshot does not exist") from exc
        bound = snapshot.get("project_id")
        if bound and bound != project["id"]:
            raise HTTPException(
                status_code=409, detail="快照所属项目与请求的项目不一致，请重新上传源码。"
            )
        if not bound:
            ensure_project(state.store, snapshot)
        return snapshot, state.store.get_project(project["id"]) or project

    assert payload.snapshot_id is not None  # enforced by CreateRunRequest
    try:
        snapshot = state.repository.get_snapshot(payload.snapshot_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot does not exist") from exc
    project = state.store.get_project(snapshot["project_id"]) if snapshot.get("project_id") else None
    if project is None:
        project, _ = ensure_project(state.store, snapshot)
    return snapshot, project


@app.post("/api/runs")
async def create_run(request: Request, payload: CreateRunRequest) -> dict:
    """Create a Planner-led audit over a whole immutable project snapshot.

    The uploaded project *is* the scope: every readable text file is available to the
    Planner and its workers, and cost is controlled by the run's budgets rather than by
    asking a user to choose files.  No source unit queue is frozen here; the project map
    is frozen instead, then the run's main Planner creates and revises cross-file worker
    tasks as evidence arrives.
    """
    state = services(request)
    snapshot, project = _resolve_run_scope(state, payload)

    readiness_service = getattr(state, "poc_readiness", None)
    if readiness_service is None:
        readiness_service = state.poc_readiness = PocReadinessService(state.settings)
    readiness = None
    if payload.poc_mode != "off":
        readiness = await readiness_service.check(snapshot.get("target_profile", "unknown"), mode=payload.poc_mode, fresh=payload.poc_mode == "required")
        if payload.poc_mode == "required" and not readiness["available"]:
            raise HTTPException(status_code=409, detail={"code": "poc_not_ready", **{k: readiness[k] for k in ("reason", "message", "checked_at")}})

    budgets = clamp_budgets(payload.budgets)
    run_id = uuid.uuid4().hex
    try:
        project_map = await asyncio.to_thread(
            state.repository.build_project_map, snapshot["id"], None
        )
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=f"Unable to build the frozen project map: {exc}") from exc
    if not project_map.get("files"):
        raise HTTPException(status_code=400, detail="The snapshot contains no readable text files")
    selected_profile = state.store.selected_model_profile()
    active_model = state.settings.model
    frozen_model = str(getattr(active_model, "model", "") or "").strip()
    if not frozen_model:
        # Compatibility for embedding callers from before ModelConfig gained
        # provider profiles; their minimal test/runtime object exposes `label`.
        frozen_model = str(getattr(active_model, "label", "") or "").strip()
    public_base_url = getattr(active_model, "public_base_url", None)
    model_profile = {
        "profile_id": selected_profile["id"] if selected_profile is not None else "",
        "model": frozen_model,
        "base_url": public_base_url() if callable(public_base_url) else str(getattr(active_model, "base_url", "") or ""),
    }
    # The ledger is frozen at run start: a sibling run that discovers something later must
    # not change what this run is trying to prove.  Withdrawn rows are excluded -- they are
    # history, not standing conclusions.
    baseline = state.store.list_project_findings(project["id"], include_withdrawn=False)
    poc_policy = state.settings.poc.snapshot()
    poc_policy["mode"] = payload.poc_mode
    poc_policy["required"] = payload.poc_mode == "required"
    task_spec = payload.task.model_dump()
    if task_spec.get("scenario"):
        # A scenario run must exhaust the whole class, not stop at the first finding.
        # ``stop_on_achieved`` is forced off and the frozen acceptance criterion states the
        # exhaustion requirement outright, so the goal text the Planner reads matches the
        # host-side gate in ``Store.finalize_goal`` instead of the "find at least one" default.
        task_spec["stop_on_achieved"] = False
        task_spec["success_criteria"] = (
            "穷尽所选分场景下全部可被外部输入触发的漏洞实例，并在收束报告中逐条列出已确认结论、"
            "已排查无证据的方向与仍可能遗漏的位置，而不是找到第一处就停止。"
        )
    run = {
        "id": run_id,
        "snapshot_id": snapshot["id"],
        "snapshot_name": snapshot["name"],
        "project_id": project["id"],
        "project_mode": "project",
        "project_baseline": baseline,
        "poc_policy": poc_policy,
        # The whole snapshot is the scope, so no explicit file list is stored. Downstream
        # code must branch on ``scope_mode`` (see ``runtime.allowed_paths_for_run``)
        # instead of reading this list directly.
        "scope": [],
        "scope_mode": "snapshot",
        # Historical columns stay populated for database compatibility. They are not
        # a selectable prompt path in the Planner-led API or UI.
        "prompt_id": "planner-v2",
        "prompt_label": "项目级 Planner",
        "prompt_text": "",
        "model": state.settings.model.label,
        "model_profile": model_profile,
        "budgets": budgets,
        "run_limits": payload.run_limits.model_dump(),
        "agent_policy": AgentPolicy().snapshot(),
        "task_spec": task_spec,
        "created_at": _iso(),
    }
    poc_policy["target_key"] = poc_target_key({**run, "target_profile": project.get("target_profile", "unknown")}, state.settings.poc, state.settings)
    run["poc_state"] = readiness or {
        "mode": "off", "available": False, "reason": "disabled",
        "message": "本次审计未启用自动执行 POC。", "checked_at": _iso(),
    }
    state.store.create_run(run)
    state.store.touch_project_run(project["id"], run_id)
    state.store.create_planner_session(
        run_id,
        f"planner:{run_id[:12]}",
        payload.task.max_planner_rounds,
        project_map,
    )
    persisted = state.store.get_run(run_id)
    if persisted is None:  # pragma: no cover - the preceding transaction created it
        raise RuntimeError("Run disappeared after it was persisted")
    state.bus.emit(run_id, None, "planner_run_queued", {
        "objective": payload.task.objective,
        "scope_mode": run["scope_mode"],
        "scope_files": len(project_map.get("scope") or []),
        "project_map_stats": project_map.get("stats") or {},
        "max_planner_rounds": payload.task.max_planner_rounds,
        "model_profile": persisted["model_profile"],
    })
    state.bus.emit(run_id, None, "project_findings_baseline_frozen", {
        "project_id": project["id"],
        "project_name": project["name"],
        "count": len(baseline),
        "ids": [item["id"] for item in baseline][:64],
        "verified": sum(1 for item in baseline if item.get("verification_status") == "verified"),
    })
    state.worker.notify()
    return persisted


@app.get("/api/runs")
async def list_runs(request: Request) -> list[dict]:
    return services(request).store.list_runs()


@app.get("/api/runs/{run_id}")
async def get_run(request: Request, run_id: str) -> dict:
    return _run_bundle(services(request), run_id)


@app.get("/api/runs/{run_id}/project-map")
async def get_run_project_map(request: Request, run_id: str) -> dict:
    """Return the full frozen project map.

    ``GET /runs/{id}`` carries a bounded projection so a whole-project snapshot does not
    turn every poll into megabytes of JSON; this endpoint is the export/deep-inspection
    path for callers that really want the whole index.
    """
    state = services(request)
    if state.store.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    project_map = state.store.get_project_map(run_id)
    if project_map is None:
        raise HTTPException(status_code=404, detail="Run has no frozen project map")
    return project_map


@app.get("/api/runs/{run_id}/project-overview")
async def get_run_project_overview(request: Request, run_id: str) -> dict:
    """Return a bounded, source-free project navigation view for the interface."""
    state = services(request)
    if state.store.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    project_map = state.store.get_project_map(run_id)
    if project_map is None:
        raise HTTPException(status_code=404, detail="Run has no frozen project map")
    files = project_map.get("files") or []
    listed = sorted(files, key=lambda item: str(item.get("path") or ""))
    return {
        **_project_map_projection(run_id, project_map),
        "listing": [
            {
                "path": item.get("path"),
                "language": item.get("language"),
                "line_count": item.get("line_count"),
                "size": item.get("size"),
                "roles": item.get("roles") or [],
                "module": item.get("module"),
                "dependency_tree": bool(item.get("dependency_tree")),
            }
            for item in listed[:MAX_LISTED_PATHS]
        ],
        "listing_truncated": len(listed) > MAX_LISTED_PATHS,
    }


@app.post("/api/runs/{run_id}/cancel")
async def cancel_run(request: Request, run_id: str) -> dict:
    state = services(request)
    run = state.store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    if run["status"] not in ("pending", "running", "paused"):
        raise HTTPException(status_code=409, detail=f"Run is already {run['status']}")
    state.store.request_cancel(run_id)
    state.worker.cancel(run_id, reason="user_cancelled")
    # A pending unit may be mid-flight; the worker observes the status between units.
    if state.worker._run_id != run_id:
        current = state.store.get_run(run_id)
        if current and current["status"] == "cancelled":
            state.bus.emit(run_id, None, "run_cancelled", {"reason": "cancel requested"})
    state.worker.notify()
    return state.store.get_run(run_id)


@app.post("/api/runs/{run_id}/pause")
async def pause_run(request: Request, run_id: str) -> dict:
    """Park a run at its next boundary, keeping everything it would need to continue.

    Unlike cancel, nothing is abandoned: the frontier, the Planner session and its round
    number are untouched, and an attempt already in flight is allowed to finish and
    commit. The two are deliberately different buttons -- only one of them is reversible.
    """
    state = services(request)
    run = state.store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    if run["status"] not in ("pending", "running"):
        raise HTTPException(status_code=409, detail=f"Run is already {run['status']}")
    state.store.request_pause(run_id)
    # The worker owns the run's cooperative flag. A pending run has none: it never
    # started, and `paused` is enough to keep it out of `claim_next_run`.
    state.worker.pause(run_id)
    state.bus.emit(run_id, None, "run_pause_requested", {"reason": "user_paused"})
    return state.store.get_run(run_id)


@app.post("/api/runs/{run_id}/resume")
async def resume_run(request: Request, run_id: str) -> dict:
    state = services(request)
    run = state.store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    if run["status"] != "paused":
        raise HTTPException(status_code=409, detail=f"Run is {run['status']}, not paused")
    if not state.store.resume_run(run_id):
        raise HTTPException(
            status_code=409, detail="Run can no longer be resumed: its goal or session has already settled"
        )
    # Back in the queue the worker claims from; the durable frontier continues from where
    # the pause left it rather than from a fresh plan.
    state.worker.notify()
    state.bus.emit(run_id, None, "run_resumed", {"reason": "user_resumed"})
    return state.store.get_run(run_id)


@app.delete("/api/runs/{run_id}")
async def delete_run(request: Request, run_id: str) -> dict:
    """Permanently remove one finished audit and every row it owns.

    This is the housekeeping half of the run lifecycle that was missing: the UI
    could list 200 historical runs but could never discard one.  Runs still
    ``pending`` or ``running`` are refused with 409 -- the worker may be mid-write
    -- while ``paused``/``completed``/``failed``/``cancelled`` records go.  The
    response echoes the per-table row counts so the interface can confirm what
    was actually cleaned up rather than just returning 204.
    """
    state = services(request)
    run = state.store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    if run["status"] in ("pending", "running"):
        raise HTTPException(
            status_code=409,
            detail=f"Run is {run['status']}; cancel it before deleting",
        )
    summary = await asyncio.to_thread(state.store.delete_run, run_id)
    state.bus.emit(run_id, None, "run_deleted", {"reason": "user_deleted"})
    return summary


@app.post("/api/runs/cleanup")
async def cleanup_terminal_runs(
    request: Request,
    project_id: str | None = Body(default=None, embed=True),
) -> dict:
    """Bulk housekeeping: delete every finished run in one call.

    The per-row ``DELETE /runs/{id}`` is precise; this is the sweep after a week
    of re-running the same snapshot.  Active runs are skipped, not errored.
    ``project_id`` optionally scopes the sweep to one project's history.
    """
    state = services(request)
    return await asyncio.to_thread(state.store.delete_terminal_runs, project_id)


def _sse(event: dict) -> str:
    return f"id: {event['id']}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"


SSE_HEARTBEAT_SECONDS = 20


@app.get("/api/runs/{run_id}/events")
async def stream_events(request: Request, run_id: str, after: int = Query(0, ge=0)):
    state = services(request)
    if state.store.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    header = request.headers.get("last-event-id")
    resume_from = int(header) if header and header.isdigit() else after

    async def generate():
        # Subscribe before replaying so nothing can fall between the two.
        queue = state.bus.subscribe(run_id)
        # This must not be named `resume_from`: assigning to that name anywhere in here
        # would make the whole closure treat it as a local, and the first read below would
        # raise UnboundLocalError before a single frame was sent. The stream then died at
        # the first byte, which the client saw as a connection closed mid-body.
        position = resume_from
        try:
            while True:
                if await request.is_disconnected():
                    return
                # Notifications only wake the reader. Drain old wakeups before replaying
                # so an emission during a database read leaves a fresh wakeup behind.
                # A full queue may drop notifications, but the durable log retains every
                # event, including those emitted while a slow client is consuming a batch.
                while not queue.empty():
                    queue.get_nowait()
                while True:
                    batch = await asyncio.to_thread(state.store.list_events, run_id, position, 500)
                    if not batch:
                        break
                    for event in batch:
                        position = event["id"]
                        yield _sse(event)
                    if await request.is_disconnected():
                        return
                try:
                    await asyncio.wait_for(queue.get(), timeout=SSE_HEARTBEAT_SECONDS)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                # Both notifications and heartbeats replay after the last delivered ID.
                # IDs are global across runs, so gaps do not imply missing run events.
        finally:
            state.bus.unsubscribe(run_id, queue)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.get("/api/runs/{run_id}/event-log")
async def event_log(request: Request, run_id: str, after: int = Query(0, ge=0)) -> dict:
    state = services(request)
    if state.store.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    return {
        "events": state.store.list_events(run_id, after, limit=2000),
        "remaining": state.store.count_events(run_id, after),
    }


# --- findings and verification ---------------------------------------------


@app.get("/api/findings/{finding_id}")
async def get_finding(request: Request, finding_id: str) -> dict:
    finding = services(request).store.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding does not exist")
    return finding


@app.get("/api/findings/{finding_id}/poc")
async def download_poc(request: Request, finding_id: str) -> Response:
    finding = services(request).store.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding does not exist")
    poc = finding.get("poc") or {}
    if not poc.get("script"):
        raise HTTPException(status_code=404, detail="This finding has no proof-of-concept script")
    filename = _safe_name(poc.get("filename") or f"poc_{finding_id[:8]}.php")
    return Response(
        # The exported report stores the model artifact verbatim. Downloads must do
        # the same: a PHP comment header corrupts Python/shell POCs and makes the two
        # supposedly identical copies impossible to reproduce.
        content=poc["script"],
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/evidence/{name}")
async def get_evidence(request: Request, name: str) -> FileResponse:
    path = services(request).settings.evidence_dir / _safe_name(name)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file does not exist")
    return FileResponse(path)


# --- prompts ----------------------------------------------------------------


@app.get("/api/prompts")
async def list_prompts(request: Request) -> list[dict]:
    return services(request).store.list_prompts()


@app.post("/api/prompts")
async def create_prompt(request: Request, payload: PromptCreateRequest) -> dict:
    state = services(request)
    prompt = {
        "id": uuid.uuid4().hex,
        "label": payload.label,
        "phase": "custom",
        "text": payload.text,
        "reason": payload.reason,
        "issues": payload.issues,
        "parent_id": payload.parent_id,
        "created_at": _iso(),
    }
    state.store.add_prompt(prompt)
    return state.store.get_prompt(prompt["id"])


@app.delete("/api/prompts/{prompt_id}")
async def delete_prompt(request: Request, prompt_id: str) -> Response:
    """Remove a user-defined prompt draft.

    Built-in prompts and prompts frozen into an existing run are refused with
    409 -- deleting text a report quotes would break reproducibility.
    """
    state = services(request)
    if state.store.get_prompt(prompt_id) is None:
        raise HTTPException(status_code=404, detail="Prompt does not exist")
    try:
        await asyncio.to_thread(state.store.delete_prompt, prompt_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=204)


# --- truths and attributions ------------------------------------------------


@app.get("/api/snapshots/{snapshot_id}/truths")
async def list_truths(request: Request, snapshot_id: str) -> list[dict]:
    return services(request).store.list_truths(snapshot_id)


@app.post("/api/snapshots/{snapshot_id}/truths")
async def set_truths(request: Request, snapshot_id: str, payload: TruthRequest) -> list[dict]:
    state = services(request)
    try:
        snapshot = state.repository.get_snapshot(snapshot_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot does not exist") from exc
    available = {item["path"] for item in snapshot["files"]}
    unknown = [sample.file_path for sample in payload.samples if sample.file_path not in available]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Truth samples reference unknown files: {unknown[:5]}")
    samples = [
        {
            "id": uuid.uuid4().hex,
            "file_path": sample.file_path,
            "category": sample.category,
            "vulnerable": sample.vulnerable,
            "independently_verified": sample.independently_verified,
            "verification_basis": sample.verification_basis,
            "evidence": sample.evidence,
        }
        for sample in payload.samples
    ]
    state.store.replace_truths(snapshot_id, samples)
    return state.store.list_truths(snapshot_id)


@app.post("/api/runs/{run_id}/attributions")
async def add_attribution(request: Request, run_id: str, payload: AttributionRequest) -> dict:
    state = services(request)
    run = state.store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    if run.get("task_spec"):
        raise HTTPException(
            status_code=409,
            detail="Goal-driven tasks do not use the fixed three-category attribution table",
        )
    record = {
        "id": uuid.uuid4().hex,
        "run_id": run_id,
        "file_path": payload.file_path,
        "category": payload.category,
        "kind": payload.kind,
        "cause": payload.cause,
        "check_item": payload.check_item,
        "finding_id": payload.finding_id,
        "created_at": _iso(),
    }
    state.store.add_attribution(record)
    return record


def _round_comparison(state: Services, run: dict) -> dict:
    """The prompt rounds that share this run's snapshot, one row per version.

    The optimisation story is P0 → P1 → P2 over one frozen snapshot, so that is what the
    exported report has to carry — showing only the version this run happened to use leaves
    the reader unable to see what changed or whether anything moved. Repeated runs of the
    same version are collapsed to the newest, otherwise a re-run would appear as a fourth
    round and the comparison would silently become "latest attempt vs the others".

    Ad-hoc versions created in the UI (`phase == "custom"`) are left out. They are not
    rounds of the experiment: a copy of P2 made to try one thing would otherwise be counted
    as a fourth round, and an interrupted scratch run would be dragged into the comparison
    as if it were a data point.
    """
    # Goal-task runs are coordinated by their frozen TaskSpec, not by P0/P1/P2.  A
    # target run must never appear as another prompt round or inherit that experiment's
    # SQLi/XSS/command-injection matrix.
    if run.get("task_spec"):
        return {
            "comparable": False,
            "reasons": ["自定义目标任务不参与固定提示词轮次对比"],
            "notes": [],
            "runs": [],
        }

    prompts = {item["id"]: item for item in state.store.list_prompts()}
    newest: dict[str, dict] = {}
    for candidate in state.store.list_runs():
        if candidate["snapshot_id"] != run["snapshot_id"]:
            continue
        if candidate.get("task_spec"):
            continue
        prompt = prompts.get(candidate["prompt_id"])
        if prompt is not None and prompt.get("phase") == "custom":
            continue
        known = newest.get(candidate["prompt_id"])
        if known is None or candidate["created_at"] > known["created_at"]:
            newest[candidate["prompt_id"]] = candidate

    ordered = sorted(newest.values(), key=lambda item: item["created_at"])
    entries = []
    for item in ordered:
        units = state.store.list_run_units(item["id"])
        findings = state.store.list_findings(item["id"])
        truths = state.store.list_truths(item["snapshot_id"])
        entries.append({"run": item, "metrics": summarise(item, units, findings, truths)})
    return {**comparable_runs(ordered), "runs": entries}


# --- experiments and reports ------------------------------------------------


@app.get("/api/experiments")
async def experiments(request: Request, run_ids: str = Query(...)) -> dict:
    state = services(request)
    wanted = [item for item in run_ids.split(",") if item]
    runs = [state.store.get_run(run_id) for run_id in wanted]
    if any(run is None for run in runs):
        raise HTTPException(status_code=404, detail="One or more runs do not exist")
    if any(run.get("task_spec") for run in runs):
        raise HTTPException(
            status_code=400,
            detail="Goal-driven tasks cannot be compared as fixed prompt experiment rounds",
        )
    ordered = sorted(runs, key=lambda run: run["created_at"])
    entries = []
    for run in ordered:
        units = state.store.list_run_units(run["id"])
        findings = state.store.list_findings(run["id"])
        truths = state.store.list_truths(run["snapshot_id"])
        entries.append({"run": run, "metrics": summarise(run, units, findings, truths)})
    return {**comparable_runs(ordered), "runs": entries, "prompt_diffs": prompt_diffs(ordered)}


@app.get("/api/runs/{run_id}/report")
async def report(request: Request, run_id: str, format: str = Query("markdown")):
    state = services(request)
    if state.store.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    bundle = _run_bundle(state, run_id)
    bundle["snapshot"] = state.store.get_snapshot(bundle["run"]["snapshot_id"])
    bundle["snapshot_detail"] = state.repository.get_snapshot(bundle["run"]["snapshot_id"])
    bundle["truths"] = state.store.list_truths(bundle["run"]["snapshot_id"])
    bundle["prompts"] = state.store.list_prompts()
    bundle["rounds"] = _round_comparison(state, bundle["run"])
    bundle["generated_at"] = _iso()
    bundle["version"] = VERSION

    if format == "json":
        return Response(
            content=render_json(bundle),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="result-{run_id[:8]}.json"'},
        )
    if format == "zip":
        # The bundle is meant to be handed to someone else and stand on its own. Which
        # evidence that takes is `collect_evidence`'s job — it is the half of the archive a
        # reader checks the report against, so it lives next to the report and is tested
        # with it rather than being an untested loop in a route.
        payload = render_zip(bundle, collect_evidence(bundle, state.settings.evidence_dir))
        return Response(
            content=payload,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="audit-{run_id[:8]}.zip"'},
        )
    return Response(
        content=render_markdown(bundle),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report-{run_id[:8]}.md"'},
    )


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "version": VERSION, "time": _iso()}


if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")
