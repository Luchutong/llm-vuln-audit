"""FastAPI application: HTTP surface, SSE stream and the worker lifespan."""
from __future__ import annotations

import asyncio
import contextlib
import json
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Body, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from pydantic import ValidationError
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .config import DEFAULT_BUDGETS, VERSION, Settings, clamp_budgets, find_env_file, load_env_file
from .db import Store, now
from .events import EventBus
from .health import ModelHealth
from .metrics import comparable_runs, prompt_diffs, summarise
from .prompts import DEFAULT_PROMPT_ID, builtin_prompt_records
from .report import collect_evidence, render_json, render_markdown, render_zip
from .schemas import (
    AttributionRequest,
    CreateRunRequest,
    PromptCreateRequest,
    TruthRequest,
    VerificationRecord,
)
from .source import SourceRepository
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
        self.store = Store(settings.db_path)
        self.repository = SourceRepository(settings.data_dir)
        self.bus = EventBus(self.store)
        self.health = ModelHealth()
        self.health.restore(self.store.load_health())
        self.health.on_change = lambda state: self.store.save_health(settings.model.label, state)
        self.worker = AuditWorker(
            settings=settings,
            store=self.store,
            repository=self.repository,
            bus=self.bus,
            health=self.health,
        )
        for prompt in builtin_prompt_records():
            self.store.upsert_builtin_prompt(prompt)


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


def services(request: Request) -> Services:
    return request.app.state.services


def _run_bundle(state: Services, run_id: str) -> dict:
    run = state.store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    units = state.store.list_run_units(run_id)
    findings = state.store.list_findings(run_id)
    truths = state.store.list_truths(run["snapshot_id"])
    return {
        "run": run,
        "units": units,
        "findings": findings,
        "attributions": state.store.list_attributions(run_id),
        "metrics": summarise(run, units, findings, truths),
    }


# --- configuration ----------------------------------------------------------


@app.get("/api/config")
async def get_config(request: Request) -> dict:
    state = services(request)
    return {
        **state.settings.model.public(),
        "budgets": state.settings.budgets,
        "budget_limits": {"defaults": DEFAULT_BUDGETS},
        "agent_policy": AgentPolicy().snapshot(),
        "worker": state.worker.status,
        "model_health": state.health.snapshot(),
        "version": VERSION,
    }


@app.post("/api/config/check")
async def check_config(request: Request) -> dict:
    """Send one real minimal request. A silent-but-connected model still fails."""
    state = services(request)
    config = state.settings.model
    if not config.configured:
        return {"ok": False, "error": f"缺少配置：{', '.join(config.missing())}"}

    from pydantic_ai import Agent
    from pydantic_ai.settings import ModelSettings

    from .agent import build_model

    started = time.monotonic()
    try:
        agent = Agent(
            build_model(config),
            output_type=str,
            instructions="Reply with exactly two characters: OK",
            model_settings=ModelSettings(extra_body=config.extra_body(), max_tokens=32),
        )
        result = await asyncio.wait_for(agent.run("ping"), timeout=45)
        reply = (result.output or "").strip()
        elapsed = int((time.monotonic() - started) * 1000)
        if not reply:
            state.health.trip("endpoint returned an empty reply")
            return {"ok": False, "error": "端点连通但模型未返回任何内容", "latency_ms": elapsed}
        state.health.pass_()
        return {"ok": True, "model": config.label, "latency_ms": elapsed, "reply": reply[:200]}
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        state.health.trip(f"{type(exc).__name__}: {exc}", status=status)
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
            "latency_ms": int((time.monotonic() - started) * 1000),
        }


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
    state = services(request)
    try:
        snapshot = state.repository.get_snapshot(payload.snapshot_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot does not exist") from exc

    prompt = state.store.get_prompt(payload.prompt_id)
    if prompt is None:
        raise HTTPException(status_code=400, detail="Prompt version does not exist")

    available = {item["path"] for item in snapshot["files"] if not item["excluded"]}
    requested = list(dict.fromkeys(payload.scope))
    unknown = [path for path in requested if path not in available]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Scope contains files outside the snapshot: {unknown[:5]}")

    scope = set(requested)
    units = [unit for unit in snapshot["units"] if unit["file_path"] in scope]
    if not units:
        raise HTTPException(status_code=400, detail="The selected scope contains no audit units")
    # Freeze order: priority only ranks, it never filters.
    units.sort(key=lambda unit: (-unit["priority"], unit["file_path"], unit["start_byte"]))

    budgets = clamp_budgets(payload.budgets)
    run_id = uuid.uuid4().hex
    run = {
        "id": run_id,
        "snapshot_id": snapshot["id"],
        "snapshot_name": snapshot["name"],
        "scope": requested,
        "prompt_id": prompt["id"],
        "prompt_label": prompt["label"],
        "prompt_text": prompt["text"],
        "model": state.settings.model.label,
        "budgets": budgets,
        "agent_policy": AgentPolicy().snapshot(),
        "created_at": _iso(),
    }
    state.store.create_run(run, units)
    state.worker.notify()
    return state.store.get_run(run_id)


@app.get("/api/runs")
async def list_runs(request: Request) -> list[dict]:
    return services(request).store.list_runs()


@app.get("/api/runs/{run_id}")
async def get_run(request: Request, run_id: str) -> dict:
    return _run_bundle(services(request), run_id)


@app.post("/api/runs/{run_id}/cancel")
async def cancel_run(request: Request, run_id: str) -> dict:
    state = services(request)
    run = state.store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
    if run["status"] not in ("pending", "running"):
        raise HTTPException(status_code=409, detail=f"Run is already {run['status']}")
    state.store.request_cancel(run_id)
    state.worker.cancel(run_id, reason="user_cancelled")
    # A pending unit may be mid-flight; the worker observes the status between units.
    if state.worker._run_id != run_id:
        current = state.store.get_run(run_id)
        if current and current["status"] == "cancelled":
            state.store.abandon_pending_units(run_id, "Run cancelled")
            state.bus.emit(run_id, None, "run_cancelled", {"reason": "cancel requested"})
    state.worker.notify()
    return state.store.get_run(run_id)


def _sse(event: dict) -> str:
    return f"id: {event['id']}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"


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
                batch = await asyncio.to_thread(state.store.list_events, run_id, position, 500)
                if not batch:
                    break
                for event in batch:
                    position = event["id"]
                    yield _sse(event)
            while True:
                if await request.is_disconnected():
                    return
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                # Events queued between the subscribe and the end of the replay are already
                # in the log, so skip them rather than showing them twice.
                if event["id"] <= position:
                    continue
                position = event["id"]
                yield _sse(event)
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

    # A confirmation claims that the vulnerability was reproduced, so it needs a
    # successful run, both sides of the control experiment, enough environment detail
    # to reproduce it, and an attachment. An exclusion also needs a successful run and
    # observations; a failed POC is an uncertain result, never an automatic false positive.
    if verdict in ("confirmed", "rejected"):
        if execution_status != "success":
            label = "确认" if verdict == "confirmed" else "排除"
            raise HTTPException(status_code=400, detail=f"执行未成功时不能{label}；请改用 uncertain 或补充决定性观测")
        missing = _required_verification_fields(verification)
        if missing:
            raise HTTPException(status_code=400, detail=f"{verdict} 需要填写：{'、'.join(missing)}")
    if verdict == "confirmed" and not has_upload:
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
    if verdict == "confirmed" and not saved:
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
    if state.store.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="Run does not exist")
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
    prompts = {item["id"]: item for item in state.store.list_prompts()}
    newest: dict[str, dict] = {}
    for candidate in state.store.list_runs():
        if candidate["snapshot_id"] != run["snapshot_id"]:
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
