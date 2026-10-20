"""FastAPI application: HTTP surface, SSE stream and the worker lifespan."""
from __future__ import annotations

import asyncio
import contextlib
import json
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Body, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .config import CredentialVault, DEFAULT_BUDGETS, VERSION, Settings, clamp_budgets, find_env_file, load_env_file
from .db import Store, now
from .events import EventBus
from .health import ModelHealth
from .finding_policy import partition_findings, source_observations
from .metrics import comparable_runs, prompt_diffs, summarise
from .prompts import DEFAULT_PROMPT_ID, builtin_prompt_records
from .report import collect_evidence, render_json, render_markdown, render_zip
from .schemas import (
    AttributionRequest,
    CreateRunRequest,
    ModelProfileCreateRequest,
    ModelProfileUpdateRequest,
    PromptCreateRequest,
    TruthRequest,
    VerificationRecord,
)
from .source import MAX_LISTED_PATHS, SourceRepository
from .worker import AuditWorker
from .runtime import AgentPolicy

BACKEND_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIST = BACKEND_DIR.parent / "frontend" / "dist"


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_name(value: str) -> str:
    cleaned = Path(value.replace("\\", "/")).name.strip()[:120]
    return "".join(ch for ch in cleaned if ch.isprintable() and ch not in '/\\:*?"<>|') or "upload.bin"


def _required_verification_fields(record: VerificationRecord) -> list[str]:
    labels = {
        "target_version": "目标版本",
        "command": "执行命令",
        "normal_observation": "正常输入的实际观测",
        "attack_observation": "攻击输入的实际观测",
    }
    return [label for field, label in labels.items() if not getattr(record, field).strip()]


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
        self.bus = EventBus(self.store)
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


def _run_bundle(state: Services, run_id: str) -> dict:
    run = state.store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    all_findings = state.store.list_findings(run_id)
    findings, _ = partition_findings(all_findings)
    truths = state.store.list_truths(run["snapshot_id"])
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
            "metrics": {**summarise(run, [], all_findings, truths, tasks=tasks),
                        "source_observations": len(audit_observations)},
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
        "metrics": {**summarise(run, units, all_findings, truths),
                    "source_observations": len(audit_observations)},
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
        "agent_policy": AgentPolicy().snapshot(),
        "worker": state.worker.status,
        "model_health": state.health.snapshot(),
        "version": VERSION,
    }


@app.get("/api/config")
async def get_config(request: Request) -> dict:
    return _config_payload(services(request))


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
    state = services(request)
    data = await file.read()
    try:
        snapshot = await asyncio.to_thread(state.repository.import_zip, data, file.filename or "upload.zip")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    state.store.add_snapshot(snapshot)
    return snapshot


@app.get("/api/snapshots")
async def list_snapshots(request: Request) -> list[dict]:
    return services(request).store.list_snapshots()


@app.get("/api/snapshots/{snapshot_id}")
async def get_snapshot(request: Request, snapshot_id: str) -> dict:
    try:
        return services(request).repository.get_snapshot(snapshot_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot does not exist") from exc


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


# --- runs -------------------------------------------------------------------


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
    try:
        snapshot = state.repository.get_snapshot(payload.snapshot_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot does not exist") from exc

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
    run = {
        "id": run_id,
        "snapshot_id": snapshot["id"],
        "snapshot_name": snapshot["name"],
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
        "agent_policy": AgentPolicy().snapshot(),
        "task_spec": payload.task.model_dump(),
        "created_at": _iso(),
    }
    state.store.create_run(run)
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
            state.store.abandon_pending_units(run_id, "Run cancelled")
            if state.store.get_planner_session(run_id) is not None:
                state.store.abandon_planner_tasks(run_id, "Run cancelled")
            else:
                state.store.abandon_task_work(run_id, "Run cancelled")
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


@app.post("/api/findings/{finding_id}/verifications")
async def add_verification(
    request: Request,
    finding_id: str,
    record: str = Form(...),
    files: list[UploadFile] = File(default=[]),
) -> dict:
    state = services(request)
    finding = state.store.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding does not exist")
    try:
        payload = json.loads(record)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="record must be a JSON object") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="record must be a JSON object")
    try:
        verification = VerificationRecord.model_validate(payload)
    except ValidationError as exc:
        first = exc.errors(include_url=False)[0]
        raise HTTPException(status_code=400, detail=f"record is invalid: {first['msg']}") from exc

    verdict = verification.verdict
    execution_status = verification.execution_status
    has_upload = any(upload is not None and bool((upload.filename or "").strip()) for upload in files)
    # A target task may return a neutral source fact (for example, an authentication
    # boundary or configuration origin) with no POC. Requiring a fake attack command
    # and control experiment to accept that review would reintroduce the legacy
    # vulnerability template into a generic result. POC-bearing findings keep the
    # stronger reproducibility gate below.
    generic_source_review = (
        (str(finding.get("category") or "").startswith("task_goal") or bool(finding.get("finding_kind")))
        and not bool((finding.get("poc") or {}).get("script"))
    )

    # A confirmation claims that the vulnerability was reproduced, so it needs a
    # successful run, both sides of the control experiment, enough environment detail
    # to reproduce it, and an attachment. An exclusion also needs a successful run and
    # observations; a failed POC is an uncertain result, never an automatic false positive.
    if generic_source_review and verdict == "confirmed" and finding.get("validation_state") != "candidate":
        raise HTTPException(
            status_code=400,
            detail="证据校验未通过的通用源码结论不能确认；请先补充可核验的源码引用或记录为驳回/待定",
        )
    if generic_source_review and verdict in ("confirmed", "rejected"):
        if not verification.notes.strip():
            raise HTTPException(
                status_code=400,
                detail="通用源码结论的确认或排除需要填写人工复核说明",
            )
    elif verdict in ("confirmed", "rejected"):
        if execution_status != "success":
            label = "确认" if verdict == "confirmed" else "排除"
            raise HTTPException(status_code=400, detail=f"执行未成功时不能{label}；请改用 uncertain 或补充决定性观测")
        missing = _required_verification_fields(verification)
        if missing:
            raise HTTPException(status_code=400, detail=f"{verdict} 需要填写：{'、'.join(missing)}")
    if verdict == "confirmed" and not generic_source_review and not has_upload:
        raise HTTPException(status_code=400, detail="确认为漏洞时必须上传日志、截图或其他可复核证据")
    if finding["category"] == "xss_r" and verdict == "confirmed" and not verification.browser_execution:
        raise HTTPException(status_code=400, detail="反射型 XSS 确认需要浏览器执行证据")

    verification_id = uuid.uuid4().hex
    saved: list[dict] = []
    written: list[Path] = []
    try:
        for index, upload in enumerate(files, 1):
            if upload is None or not (upload.filename or "").strip():
                continue
            name = f"{verification_id[:8]}-{index:02d}-{_safe_name(upload.filename)}"
            target = state.settings.evidence_dir / name
            content = await upload.read()
            if not content:
                continue
            await asyncio.to_thread(target.write_bytes, content)
            written.append(target)
            saved.append({"name": upload.filename, "stored": name, "url": f"/api/evidence/{name}"})
    except Exception:
        for path in written:
            path.unlink(missing_ok=True)
        raise
    if verdict == "confirmed" and not generic_source_review and not saved:
        raise HTTPException(status_code=400, detail="确认证据附件不能为空")

    entry = {
        "id": verification_id,
        "finding_id": finding_id,
        "created_at": _iso(),
        "execution_status": execution_status,
        "verdict": verdict,
        "original_script": ((finding.get("poc") or {}).get("script") or ""),
        "modified_script": verification.modified_script,
        "modification_notes": verification.modification_notes,
        "target_version": verification.target_version,
        "command": verification.command,
        "expected_result": verification.expected_result,
        "normal_observation": verification.normal_observation,
        "attack_observation": verification.attack_observation,
        "browser_execution": verification.browser_execution,
        "notes": verification.notes,
        "files": saved,
    }
    try:
        state.store.record_verification(entry)
    except Exception:
        for path in written:
            path.unlink(missing_ok=True)
        raise
    state.bus.emit(
        finding["run_id"],
        finding["unit_id"],
        "verification_recorded",
        {"finding_id": finding_id, "verdict": verdict, "execution_status": execution_status},
    )
    return state.store.get_finding(finding_id)


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
