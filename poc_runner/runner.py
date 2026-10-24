"""Isolated POC execution service.

This process is deliberately small and boring.  It listens only on the Compose
``poc-control`` network, executes one whitelisted script at a time inside a fresh
``/tmp`` directory, and talks to the local Lab30 shop on ``poc-target``.  It never
touches uploaded archives, the audit database, the model endpoint or the Docker socket.

The container is built read-only, runs as an unprivileged uid, drops all capabilities
and has no published port.  Those are mitigations, not a proof: a script that escapes
the container runtime is still a script that escaped.  See README.md for the threat
model this service does and does not claim.
"""
from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import os
import re
import resource
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager
from http.cookiejar import Cookie, eff_request_host
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request as UrlRequest

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, Field

VERSION = "3.0.0"
TOKEN = (os.environ.get("POC_RUNNER_TOKEN") or "").strip()
# Lab30 shop (拾光商城): PHP/Apache + MariaDB, member accounts required.
LAB30_URL = (os.environ.get("LAB30_URL") or "http://lab30").rstrip("/")
LAB30_USER = os.environ.get("LAB30_USER") or "alice"
LAB30_PASSWORD = os.environ.get("LAB30_PASSWORD") or "Alice123!"
WORKDIR = Path(os.environ.get("POC_RUNNER_WORKDIR") or "/tmp/poc-runner")
MAX_CONCURRENCY = max(1, min(8, int(os.environ.get("POC_RUNNER_CONCURRENCY") or 2)))
JOB_TTL_SECONDS = 900
MAX_SCRIPT_BYTES = 32 * 1024
MAX_STDOUT = 64 * 1024
MAX_STDERR = 32 * 1024
MAX_ARTIFACT_BYTES = 1 * 1024 * 1024
MAX_ARTIFACTS_TOTAL = 5 * 1024 * 1024
MAX_ARTIFACT_COUNT = 8
BODY_PREVIEW = 32 * 1024
JOB_MEMORY = 512 * 1024 * 1024
JOB_FILESIZE = 16 * 1024 * 1024

ALLOWED_LANGUAGES = {"php": "poc.php", "python": "poc.py"}
ALLOWED_PATHS = (
    "/auth/", "/catalog/", "/orders/index.php", "/wallet/", "/account/", "/ops/",
    "/partner/", "/support/", "/content/", "/assets/",
)
ALLOWED_PAGES = {"/", "/index.php", "/health.php"}
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SAFE_TARGET = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")

@asynccontextmanager
async def lifespan(_app: FastAPI):
    WORKDIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WORKDIR, 0o700)
    (WORKDIR / "jobs").mkdir(exist_ok=True)
    _restore_leases()
    if not TOKEN:
        # Keep answering /healthz so the audit app can report the misconfiguration.
        print(json.dumps({"level": "error", "message": "POC_RUNNER_TOKEN is not set"}), flush=True)
    yield


app = FastAPI(
    title="poc-runner",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
_semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
SUPPORTED_TARGETS = frozenset({"lab30"})
IDENTITIES = {
    "guest": ("", "", "guest"),
    "alice": (LAB30_USER, LAB30_PASSWORD, "customer"),
    "bob": (os.environ.get("LAB30_BOB_USER") or "bob", os.environ.get("LAB30_BOB_PASSWORD") or "Bob123!", "customer"),
    "operator": (os.environ.get("LAB30_OPERATOR_USER") or "operator", os.environ.get("LAB30_OPERATOR_PASSWORD") or "Ops123!", "operator"),
    "admin": (os.environ.get("LAB30_ADMIN_USER") or "admin", os.environ.get("LAB30_ADMIN_PASSWORD") or "Admin123!", "admin"),
}
_contexts: dict[str, dict] = {}
_leases: dict[str, str] = {}
_contexts_lock = threading.RLock()
_account_baselines: dict[str, dict] = {}
_cancelled_contexts: dict[str, float] = {}
CONTEXT_TOMBSTONE_SECONDS = 24 * 60 * 60


def _persist_leases() -> None:
    """Only metadata is persisted; credentials, cookies and response bodies never are."""
    WORKDIR.mkdir(parents=True, exist_ok=True)
    path = WORKDIR / "verification-contexts.json"
    pending = [{"context_id": ident, "target": ctx["target"], "run_id": ctx["run_id"],
                "finding_id": ctx["finding_id"]} for ident, ctx in _contexts.items()
               if ctx["state"] != "closed"]
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"leases": pending, "cancelled_contexts": _cancelled_contexts}), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _restore_leases() -> None:
    path = WORKDIR / "verification-contexts.json"
    if not path.exists():
        return
    try:
        journal = json.loads(path.read_text(encoding="utf-8"))
        pending = journal.get("leases", []) if isinstance(journal, dict) else journal
        if isinstance(journal, dict):
            cancelled = journal.get("cancelled_contexts", {})
            if not isinstance(cancelled, dict) or any(not SAFE_NAME.fullmatch(ident) or not isinstance(stamp, (int, float)) for ident, stamp in cancelled.items()):
                raise ValueError("invalid cancellation journal")
            _cancelled_contexts.update(cancelled)
        if not isinstance(pending, list):
            raise ValueError("invalid lease journal")
        for entry in pending:
            if not isinstance(entry, dict) or entry.get("target") not in SUPPORTED_TARGETS:
                raise ValueError("invalid lease journal")
            ident = entry["context_id"]
            _contexts[ident] = {**entry, "state": "unresolved", "active": 0, "sessions": {},
                                "operation_lock": threading.Lock(), "state_changes": []}
            _leases[entry["target"]] = ident
    except (OSError, ValueError, KeyError, TypeError):
        # Losing the journal must never turn an uncertain in-flight operation into
        # permission to launch another experiment against the same database.
        for target in SUPPORTED_TARGETS:
            _leases[target] = "unresolved-journal"


def _context_public(ctx: dict) -> dict:
    return {key: ctx[key] for key in ("context_id", "target", "run_id", "finding_id", "state", "active", "state_changes")}


def _context(context_id: str, target: str, *, allow_closing: bool = False) -> dict:
    with _contexts_lock:
        ctx = _contexts.get(context_id)
        if ctx is None or ctx["target"] != target:
            raise HTTPException(status_code=409, detail="unknown verification context; do not resubmit lost jobs")
        if ctx["state"] != "open" and not (allow_closing and ctx["state"] == "closing"):
            raise HTTPException(status_code=409, detail=f"verification context is {ctx['state']}")
        return ctx


def _release_context(ctx: dict) -> None:
    if ctx["active"] or ctx["state"] != "closing" or ctx.get("unresolved_jobs"):
        return
    for session in ctx["sessions"].values():
        session["client"].close()
    ctx["sessions"].clear()
    ctx["state"] = "closed"
    ctx["closed_ts"] = time.time()
    _cancelled_contexts[ctx["context_id"]] = time.time()
    if _leases.get(ctx["target"]) == ctx["context_id"]:
        _leases.pop(ctx["target"], None)
    _persist_leases()


def _context_operation(context_id: str, target: str, operation):
    with _contexts_lock:
        ctx = _context(context_id, target)
        ctx["active"] += 1
    try:
        with ctx["operation_lock"]:
            _context(context_id, target)
            return operation(ctx)
    finally:
        with _contexts_lock:
            ctx["active"] -= 1
            _release_context(ctx)


class ContextRequest(BaseModel):
    target: str = "lab30"
    run_id: str = Field(min_length=1, max_length=128)
    finding_id: str = Field(min_length=1, max_length=128)
    context_id: str = ""


# --------------------------------------------------------------------------- auth


def require_token(authorization: str | None = Header(default=None)) -> None:
    if not TOKEN:
        # Refuse to run without a token rather than exposing an unauthenticated executor.
        raise HTTPException(status_code=503, detail="runner token is not configured")
    expected = f"Bearer {TOKEN}"
    if not authorization or not secrets.compare_digest(authorization, expected):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )


protected = [Depends(require_token)]


# --------------------------------------------------------------------------- models


class PrepareRequest(BaseModel):
    reset: bool = False
    context_id: str = ""
    identity: str = "alice"
    expected_role: str | None = None
    expected_state: dict | None = None


class JobRequest(BaseModel):
    target: str = Field(default="lab30", max_length=32)
    language: str = Field(max_length=16)
    script: str
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    artifacts: list[str] = Field(default_factory=list, max_length=MAX_ARTIFACT_COUNT)
    context_id: str = ""
    identity: str = "alice"
    job_id: str = ""


class HttpRequest(BaseModel):
    target: str = Field(default="lab30", max_length=32)
    method: str = Field(default="GET", max_length=8)
    path: str = Field(max_length=2048)
    body: str = Field(default="", max_length=256 * 1024)
    headers: dict[str, str] = Field(default_factory=dict)
    context_id: str = ""
    identity: str = "alice"


class BrowserRequest(BaseModel):
    target: str = Field(default="lab30", max_length=32)
    path: str = Field(max_length=2048)
    script: str = Field(default="", max_length=8 * 1024)
    wait_ms: int = Field(default=1000, ge=0, le=10000)
    context_id: str = ""
    identity: str = "alice"


# --------------------------------------------------------------------------- helpers


def _check_target(target: str) -> None:
    if not SAFE_TARGET.fullmatch(target or ""):
        raise HTTPException(status_code=400, detail="invalid target")
    if target not in SUPPORTED_TARGETS:
        raise HTTPException(status_code=404, detail="unknown target")


def _check_path(path: str) -> str:
    candidate = (path or "").strip()
    if not candidate.startswith("/") or candidate.startswith("//"):
        raise HTTPException(status_code=400, detail="path must be absolute and local")
    bare, _, query = candidate.partition("?")
    if any(token in bare for token in ("..", "\\", "\x00", "://")):
        raise HTTPException(status_code=400, detail="invalid path")
    if bare not in ALLOWED_PAGES and not any(bare.startswith(prefix) for prefix in ALLOWED_PATHS):
        raise HTTPException(status_code=403, detail="path is not in the Lab30 allowlist")
    return candidate


def _safe_artifact_names(names: list[str]) -> list[str]:
    clean: list[str] = []
    for name in names:
        if not SAFE_NAME.fullmatch(name or "") or name in {".", ".."}:
            raise HTTPException(status_code=400, detail=f"invalid artifact name: {name!r}")
        if name not in clean:
            clean.append(name)
    return clean


def _job_dir(job_id: str) -> Path:
    return WORKDIR / "jobs" / job_id


def _cleanup() -> None:
    cutoff = time.time() - JOB_TTL_SECONDS
    jobs_root = WORKDIR / "jobs"
    try:
        entries = list(jobs_root.iterdir())
    except OSError:
        return
    with _jobs_lock:
        active_jobs = {ident for ident, job in _jobs.items() if job.get("status") == "running"}
    for entry in entries:
        try:
            if entry.is_dir() and entry.name not in active_jobs and entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)
        except OSError:
            continue
    with _jobs_lock:
        for job_id, job in list(_jobs.items()):
            if job.get("status") != "running" and job.get("created_ts", 0) < cutoff:
                _jobs.pop(job_id, None)
    with _contexts_lock:
        for ident, ctx in list(_contexts.items()):
            if ctx["state"] == "closed" and ctx.get("closed_ts", time.time()) < cutoff:
                _contexts.pop(ident, None)
        expired = [ident for ident, stamp in _cancelled_contexts.items() if stamp < time.time() - CONTEXT_TOMBSTONE_SECONDS]
        for ident in expired:
            _cancelled_contexts.pop(ident, None)
        if expired:
            _persist_leases()


def _job_public(job: dict) -> dict:
    return {
        key: job[key]
        for key in (
            "job_id",
            "kind",
            "status",
            "exit_code",
            "duration_ms",
            "stdout",
            "stderr",
            "truncated",
            "artifacts",
            "timed_out",
            "context_id", "identity", "precondition", "postcondition", "state_changes", "execution_status",
            "process_confirmed_stopped",
        )
        if key in job
    }


def _drain(stream, limit: int) -> tuple[bytes, bool]:
    kept = bytearray()
    truncated = False
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        if len(kept) < limit:
            kept.extend(chunk[: limit - len(kept)])
        if len(kept) >= limit and len(chunk) + len(kept) > limit:
            truncated = True
    return bytes(kept), truncated


def _child_limits(identity: str = "alice") -> None:
    os.umask(0o077)
    for name, value in (
        (resource.RLIMIT_CPU, (30, 31)),
        (resource.RLIMIT_AS, (JOB_MEMORY, JOB_MEMORY)),
        (resource.RLIMIT_FSIZE, (JOB_FILESIZE, JOB_FILESIZE)),
        (resource.RLIMIT_NOFILE, (64, 64)),
    ):
        try:
            resource.setrlimit(name, value)
        except (ValueError, OSError):
            pass
    try:
        # Best effort: limits runaway forks.  Not available for every kernel/uid pair.
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    except (ValueError, OSError, AttributeError):
        pass
    os.environ.clear()
    os.environ.update(
        {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": os.getcwd(),
            "TMPDIR": os.getcwd(),
            "LANG": "C.UTF-8",
            "LAB30_URL": LAB30_URL,
            "LAB30_USER": IDENTITIES[identity][0],
            "LAB30_PASSWORD": IDENTITIES[identity][1],
            "LAB30_IDENTITY": identity,
            # An inherited proxy would turn a target-local script into an egress
            # attempt; explicitly neutralize the common names.
            "NO_PROXY": "*",
            "no_proxy": "*",
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "http_proxy": "",
            "https_proxy": "",
        }
    )


def _collect_artifacts(directory: Path, names: list[str]) -> list[dict]:
    collected: list[dict] = []
    total = 0
    root = directory.resolve()
    for name in names:
        path = (directory / name).resolve()
        if path.parent != root or not path.is_file():
            continue
        size = path.stat().st_size
        if size > MAX_ARTIFACT_BYTES or total + size > MAX_ARTIFACTS_TOTAL:
            continue
        payload = path.read_bytes()
        collected.append(
            {"name": name, "sha256": hashlib.sha256(payload).hexdigest(), "size": size}
        )
        total += size
    return collected


def _process_group_active(group_id: int) -> bool | None:
    """Confirm no live member remains, ignoring reparented zombie entries.

    killpg(0) alone also sees zombies, which may await the container init's reaper.
    An unreadable proc table is uncertainty rather than proof of termination.
    """
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group_id and fields[0] not in {"Z", "X"}:
                return True
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError, IndexError):
            return None
    return False


def _terminate_process_group(process: subprocess.Popen) -> bool:
    """A completed script may leave children: kill its whole job group as well."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        return False
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        return False
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        active = _process_group_active(process.pid)
        if active is False:
            return True
        if active is None:
            return False
        time.sleep(.01)
    return False


def _execute(request: JobRequest) -> dict:
    job_id = request.job_id or secrets.token_hex(16)
    directory = _job_dir(job_id)
    directory.mkdir(parents=True, exist_ok=False)
    os.chmod(directory, 0o700)
    script_name = ALLOWED_LANGUAGES[request.language]
    script_path = directory / script_name
    script_path.write_text(request.script, encoding="utf-8")
    os.chmod(script_path, 0o600)

    command = (
        ["php", "-d", "display_errors=1", "-d", "log_errors=0", script_name]
        if request.language == "php"
        else [sys.executable, "-I", script_name]
    )
    started = time.monotonic()
    timed_out = False
    process = subprocess.Popen(
        command,
        cwd=str(directory),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=functools.partial(_child_limits, request.identity),
        start_new_session=True,
        close_fds=True,
    )
    stdout_box: list[tuple[bytes, bool]] = []
    stderr_box: list[tuple[bytes, bool]] = []

    def read(stream, limit, box):
        box.append(_drain(stream, limit))

    threads = [
        threading.Thread(target=read, args=(process.stdout, MAX_STDOUT, stdout_box), daemon=True),
        threading.Thread(target=read, args=(process.stderr, MAX_STDERR, stderr_box), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        exit_code = process.wait(timeout=request.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        exit_code = None
    # This also kills background children when the script's leader exited normally.
    confirmed_stopped = _terminate_process_group(process)
    exit_code = process.returncode if confirmed_stopped else None
    for thread in threads:
        thread.join(timeout=5)
    confirmed_stopped = confirmed_stopped and not any(thread.is_alive() for thread in threads)
    if not confirmed_stopped:
        exit_code = None
    duration_ms = int((time.monotonic() - started) * 1000)
    stdout, stdout_truncated = stdout_box[0] if stdout_box else (b"", False)
    stderr, stderr_truncated = stderr_box[0] if stderr_box else (b"", False)
    artifacts = _collect_artifacts(directory, request.artifacts)
    job = {
        "job_id": job_id,
        "kind": "script",
        "status": "unresolved" if not confirmed_stopped else "timeout" if timed_out else "finished",
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout": stdout.decode("utf-8", "replace"),
        "stderr": stderr.decode("utf-8", "replace"),
        "truncated": bool(stdout_truncated or stderr_truncated),
        "timed_out": timed_out,
        "artifacts": artifacts,
        "created_ts": time.time(),
        "process_confirmed_stopped": confirmed_stopped,
    }
    return job


# --------------------------------------------------------------------------- endpoints


@app.get("/healthz")
def healthz() -> dict:
    return {
        "ok": TOKEN != "",
        "version": VERSION,
        "target": "lab30",
        "supported_targets": ["lab30"],
        "capabilities": {
            "php": shutil.which("php") is not None,
            "python": True,
            "curl": shutil.which("curl") is not None,
            "browser": _browser_available(),
            "verification_contexts": True,
            "identity_preconditions": True,
            "idempotent_jobs": True,
        },
    }


def _browser_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except Exception:
        return False
    return True


def _lab30_client() -> httpx.Client:
    return httpx.Client(
        base_url=LAB30_URL,
        timeout=httpx.Timeout(15.0, connect=5.0),
        follow_redirects=False,
        trust_env=False,
    )


def _session(session: httpx.Client, method: str, path: str, **kwargs) -> httpx.Response:
    return session.request(method, path, **kwargs)


TOKEN_FIELD = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]")


def _identity(identity: str) -> tuple[str, str, str]:
    if identity not in IDENTITIES:
        raise HTTPException(status_code=400, detail="unknown Lab30 identity")
    return IDENTITIES[identity]


def _account_snapshot(session: httpx.Client, identity: str) -> dict:
    username, _, role = _identity(identity)
    try:
        response = _session(session, "GET", "/account/me.php", headers={"Accept": "application/json"})
        if identity == "guest":
            actual = {"username": "", "role": "guest"} if response.status_code == 401 else {}
            return {"ok": response.status_code == 401, "identity": identity, "expected_role": role,
                    "actual": actual, "reason": "" if response.status_code == 401 else "guest_session_authenticated"}
        payload = response.json() if response.status_code == 200 else {}
        if not isinstance(payload, dict):
            payload = {}
        actual = {key: payload[key] for key in ("id", "username", "role", "balance", "tier", "nickname", "homepage") if key in payload}
        valid = actual.get("username") == username and actual.get("role") == role
        return {"ok": valid, "identity": identity, "expected_role": role, "actual": actual,
                "reason": "" if valid else "identity_or_role_mismatch"}
    except (httpx.HTTPError, ValueError):
        return {"ok": False, "identity": identity, "expected_role": role,
                "actual": {}, "reason": "identity_check_unavailable"}


def _identity_state(ctx: dict, identity: str) -> dict:
    username, password, _ = _identity(identity)
    existing = ctx["sessions"].get(identity)
    if existing is not None:
        return existing
    session = _lab30_client()
    try:
        health = _session(session, "GET", "/health.php")
        payload = health.json()
        if health.status_code != 200 or not isinstance(payload, dict) or payload.get("ok") is not True:
            raise HTTPException(status_code=503, detail="Lab30 health check failed")
        if identity != "guest":
            response = _session(session, "POST", "/auth/login.php", data={"username": username, "password": password})
            if response.status_code not in {302, 303}:
                raise HTTPException(status_code=502, detail="Lab30 login rejected")
        entry = {"client": session, "identity": identity}
        ctx["sessions"][identity] = entry
        return entry
    except Exception:
        session.close()
        raise


def _precondition(ctx: dict, identity: str) -> dict:
    try:
        entry = _identity_state(ctx, identity)
        check = _account_snapshot(entry["client"], identity)
    except (HTTPException, httpx.HTTPError, ValueError):
        return {"ok": False, "identity": identity, "expected_role": _identity(identity)[2],
                "actual": {}, "reason": "identity_preparation_failed"}
    actual = check["actual"]
    _assert_account_state(ctx, identity, check)
    if check["ok"]:
        initial = _account_baselines.setdefault(identity, dict(actual))
        changes = [{"field": key, "before": initial.get(key), "after": actual.get(key)}
                   for key in sorted(initial.keys() | actual.keys()) if initial.get(key) != actual.get(key)]
        if changes:
            check.update(ok=False, reason="target_state_changed_manual_reset_required", state_changes=changes)
    if identity not in ctx.setdefault("initial_accounts", {}):
        ctx["initial_accounts"][identity] = dict(actual)
    entry["precondition"] = check
    return check


def _assert_account_state(ctx: dict, identity: str, check: dict) -> None:
    expected = ctx.get("assertions", {}).get(identity, {})
    check["expected_state"] = dict(expected)
    if check["ok"] and any(type(check["actual"].get(key)) is not type(value) or check["actual"].get(key) != value
                           for key, value in expected.items()):
        check.update(ok=False, reason="required_account_state_mismatch")


def _postcondition(ctx: dict, identity: str, before: dict) -> dict:
    entry = _identity_state(ctx, identity)
    after = _account_snapshot(entry["client"], identity)
    _assert_account_state(ctx, identity, after)
    previous, actual = before.get("actual", {}), after.get("actual", {})
    changes = [{"identity": identity, "field": key, "before": previous.get(key), "after": actual.get(key)}
               for key in sorted(previous.keys() | actual.keys()) if previous.get(key) != actual.get(key)]
    ctx["state_changes"].extend(changes)
    return {"context_id": ctx["context_id"], "identity": identity, "precondition": before,
            "postcondition": after, "state_changes": changes}


def _observed_action(ctx: dict, identity: str, action) -> dict:
    before = _precondition(ctx, identity)
    if not before["ok"]:
        return {"status": "precondition_failed", "execution_status": "precondition_failed", "error": "precondition_failed",
                "exit_code": None, "stdout": "", "stderr": before["reason"],
                "context_id": ctx["context_id"], "identity": identity, "precondition": before,
                "postcondition": before, "state_changes": []}
    try:
        result = action()
    except Exception as exc:
        result = {"status": "error", "execution_status": "error", "error": type(exc).__name__,
                  "exit_code": None, "stdout": "", "stderr": type(exc).__name__, "timed_out": False}
    result.update(_postcondition(ctx, identity, before))
    if result.get("process_confirmed_stopped") is False:
        with _contexts_lock:
            ctx["state"] = "unresolved"
            ctx.setdefault("unresolved_jobs", []).append(result.get("job_id", "unknown"))
            _persist_leases()
    result.setdefault("execution_status", result.get("status", "finished"))
    return result


def _prepare_sync(reset: bool = False, context_id: str = "", identity: str = "alice", expected_role: str | None = None, expected_state: dict | None = None) -> dict:
    if reset:
        raise HTTPException(status_code=400, detail="Reset Lab30 explicitly with its CLI between audits")
    role = _identity(identity)[2]
    if expected_role is not None and expected_role != role:
        raise HTTPException(status_code=400, detail="expected role must match the configured identity")
    if expected_state is not None and (not isinstance(expected_state, dict) or
            any(key not in {"balance", "tier", "nickname", "homepage", "id"} or type(value) not in {str, int, float, bool, type(None)}
                for key, value in expected_state.items())):
        raise HTTPException(status_code=400, detail="expected_state must use account/me fields balance, tier, nickname, homepage or id with scalar values")
    def prepare(ctx):
        assertions = ctx.setdefault("assertions", {}).setdefault(identity, {})
        for key, value in (expected_state or {}).items():
            if key in assertions and (type(value) is not type(assertions[key]) or value != assertions[key]):
                raise HTTPException(status_code=409, detail="verification prerequisites cannot be changed within a context")
        assertions.update(expected_state or {})
        check = _precondition(ctx, identity)
        return {"ok": check["ok"], "context_id": context_id, "identity": identity,
                "base_url": LAB30_URL, "version": "lab30-shop-1.0.0", "user": _identity(identity)[0],
                "authenticated": check["ok"] and identity != "guest", "precondition": check,
                "state_changes": list(ctx["state_changes"]),
                "prepared_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    return _context_operation(context_id, "lab30", prepare)


@app.post("/v1/verification-contexts", dependencies=protected)
def create_context(request: ContextRequest) -> dict:
    _check_target(request.target)
    _cleanup()
    with _contexts_lock:
        if request.context_id in _cancelled_contexts:
            raise HTTPException(status_code=409, detail="verification context was cancelled before creation")
        if request.context_id and request.context_id in _contexts:
            existing = _contexts[request.context_id]
            if all(existing[key] == getattr(request, key) for key in ("run_id", "finding_id", "target")) and existing["state"] == "open":
                return _context_public(existing)
            raise HTTPException(status_code=409, detail="context id already bound or closed")
        if request.target in _leases:
            raise HTTPException(status_code=409, detail="target busy or unresolved; wait for its verification context to close")
        ident = request.context_id or secrets.token_hex(16)
        if not SAFE_NAME.fullmatch(ident):
            raise HTTPException(status_code=400, detail="invalid context id")
        ctx = {"context_id": ident, "target": request.target, "run_id": request.run_id,
               "finding_id": request.finding_id, "state": "open", "active": 0, "sessions": {},
               "state_changes": [], "operation_lock": threading.Lock(), "initial_accounts": {}}
        _contexts[ident] = ctx
        _leases[request.target] = ident
        _persist_leases()
        return _context_public(ctx)


@app.delete("/v1/verification-contexts/{context_id}", dependencies=protected)
def close_context(context_id: str) -> dict:
    if not SAFE_NAME.fullmatch(context_id):
        raise HTTPException(status_code=400, detail="invalid context id")
    with _contexts_lock:
        ctx = _contexts.get(context_id)
        if ctx is None:
            # Closing a timed-out creation must prevent a delayed server worker
            # from opening its lease after this cleanup request has completed.
            _cancelled_contexts[context_id] = time.time()
            _persist_leases()
            return {"context_id": context_id, "state": "closed", "active": 0, "was_unknown": True}
        if ctx["state"] == "unresolved":
            raise HTTPException(status_code=409, detail="unresolved verification context; confirm jobs and descendants stopped and manually recreate the runner before reuse")
        if ctx["state"] == "open":
            ctx["state"] = "closing"
        _release_context(ctx)
        return _context_public(ctx)


@app.post("/v1/targets/{target}/prepare", dependencies=protected)
async def prepare_target(target: str, request: PrepareRequest) -> dict:
    _check_target(target)
    _cleanup()
    return await asyncio.to_thread(_prepare_sync, request.reset, request.context_id, request.identity, request.expected_role, request.expected_state)


@app.get("/v1/targets/{target}/status", dependencies=protected)
async def target_status(target: str, context_id: str = "", identity: str = "alice") -> dict:
    _check_target(target)
    return await asyncio.to_thread(_prepare_sync, False, context_id, identity)


@app.post("/v1/jobs", dependencies=protected)
async def create_job(request: JobRequest) -> dict:
    _check_target(request.target)
    language = (request.language or "").casefold()
    if language not in ALLOWED_LANGUAGES:
        raise HTTPException(status_code=400, detail="language must be php or python")
    encoded = request.script.encode("utf-8")
    if not request.script.strip() or len(encoded) > MAX_SCRIPT_BYTES:
        raise HTTPException(status_code=413, detail="script is empty or too large")
    request.artifacts = _safe_artifact_names(request.artifacts)
    _identity(request.identity)
    request.language = language
    _context(request.context_id, request.target)
    job_id = request.job_id or secrets.token_hex(16)
    if not SAFE_NAME.fullmatch(job_id):
        raise HTTPException(status_code=400, detail="invalid job id")
    request.job_id = job_id
    fingerprint = hashlib.sha256(request.model_dump_json().encode()).hexdigest()
    with _jobs_lock:
        existing = _jobs.get(job_id)
        if existing is not None:
            if existing.get("fingerprint") != fingerprint:
                raise HTTPException(status_code=409, detail="job id already bound to a different request")
            return _job_public(existing)
        _jobs[job_id] = {"job_id": job_id, "kind": "script", "status": "running", "context_id": request.context_id,
                         "identity": request.identity, "fingerprint": fingerprint, "created_ts": time.time()}
    _cleanup()
    async def complete():
        try:
            async with _semaphore:
                job = await asyncio.to_thread(_context_operation, request.context_id, request.target,
                                             lambda ctx: _observed_action(ctx, request.identity, lambda: _execute(request)))
        except Exception as exc:
            job = {"job_id": job_id, "kind": "script", "status": "error", "exit_code": None,
                   "stdout": "", "stderr": type(exc).__name__, "timed_out": False}
        job.update(job_id=job_id, context_id=request.context_id, identity=request.identity,
                   fingerprint=fingerprint, created_ts=time.time())
        with _jobs_lock:
            _jobs[job_id] = job
        return _job_public(job)
    task = asyncio.create_task(complete())
    return await asyncio.shield(task)


@app.get("/v1/jobs/{job_id}", dependencies=protected)
async def get_job(job_id: str) -> dict:
    if not SAFE_NAME.fullmatch(job_id):
        raise HTTPException(status_code=400, detail="invalid job id")
    _cleanup()
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return _job_public(job)


@app.get("/v1/jobs/{job_id}/artifacts/{name}", dependencies=protected)
def get_artifact(job_id: str, name: str) -> Response:
    if not SAFE_NAME.fullmatch(job_id) or not SAFE_NAME.fullmatch(name):
        raise HTTPException(status_code=400, detail="invalid artifact reference")
    path = _job_dir(job_id) / name
    try:
        resolved = path.resolve()
        if resolved.parent != _job_dir(job_id).resolve() or not resolved.is_file():
            raise OSError
        if resolved.stat().st_size > MAX_ARTIFACT_BYTES:
            raise HTTPException(status_code=413, detail="artifact too large")
        payload = resolved.read_bytes()
    except OSError:
        raise HTTPException(status_code=404, detail="artifact not found")
    return Response(content=payload, media_type="application/octet-stream")


def _observe_sync(request: HttpRequest) -> dict:
    """Send exactly one request and report the response the server actually produced.

    Redirects are deliberately not followed.  For an open-redirect finding the first 3xx
    and its ``Location`` *are* the evidence; following it replaces that evidence with
    whatever the target happens to answer -- or fails outright when the target is external
    and the runner network is isolated.  Resolving a relative ``Location`` is also not this
    service's job: the observed value is what the vulnerable code emitted, and the caller
    can judge it against the request path.
    """
    path = _check_path(request.path)
    method = (request.method or "GET").upper()
    if method not in {"GET", "POST"}:
        raise HTTPException(status_code=400, detail="method must be GET or POST")
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() in {"content-type", "accept", "cookie", "x-requested-with"}
        and len(value) <= 2048
    }
    ctx = _context(request.context_id, request.target, allow_closing=True)
    session = _identity_state(ctx, request.identity)["client"]
    payload = (request.body or None) if method == "POST" else None
    try:
        response = session.request(method, path, content=payload, headers=headers)
        location = response.headers.get("location", "")
        content = response.content[:BODY_PREVIEW]
        truncated = len(response.content) > BODY_PREVIEW
        body = content.decode("utf-8", "replace")
        if truncated and body.endswith("�"):
            # The preview cut a multi-byte character in half.  Dropping the orphan keeps
            # the preview inside the byte limit instead of reporting 32769 bytes for a
            # 32768-byte slice (the replacement character is three bytes).
            body = body[:-1]
        return {
            "status": response.status_code,
            "url": str(response.url),
            "headers": {
                key: value
                for key, value in response.headers.items()
                if key.lower() in {"content-type", "content-length", "location"}
            },
            # No redirect was followed; this is the single Location the server sent, kept
            # in the field's original shape so existing readers do not have to change.
            "redirects": [location] if location and response.status_code in {301, 302, 303, 307, 308} else [],
            "body": body,
            "truncated": truncated,
        }
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"target request failed ({type(exc).__name__})")


@app.post("/v1/http", dependencies=protected)
async def http_observe(request: HttpRequest) -> dict:
    _check_target(request.target)
    _identity(request.identity)
    result = await asyncio.to_thread(_context_operation, request.context_id, request.target,
                                    lambda ctx: _observed_action(ctx, request.identity, lambda: _observe_sync(request)))
    return _register_observation(result, "http")


def _prepared_cookies(context_id: str, identity: str = "alice") -> list[dict]:
    """Inject the prepared member session into Chromium at the runner's target URL."""
    ctx = _context(context_id, "lab30", allow_closing=True)
    entry = _identity_state(ctx, identity)
    return [
        {"name": cookie.name, "value": cookie.value, "url": f"{LAB30_URL}/"}
        for cookie in entry["client"].cookies.jar
    ]


def _store_browser_cookies(context_id: str, identity: str, cookies: list[dict]) -> None:
    """Translate Chromium host cookies using Python's effective-host convention.

    http.cookiejar uses ``lab30.local`` for host-only cookies received from a
    single-label host. Assigning Chromium's bare ``lab30`` makes those cookies
    disappear from subsequent requests. Keep them host-only and let cookiejar
    calculate the correct effective host, rather than widening the domain.
    """
    session = _identity_state(_context(context_id, "lab30", allow_closing=True), identity)["client"]
    hostname = (urlsplit(LAB30_URL).hostname or "").lower()
    _, effective_host = eff_request_host(UrlRequest(f"{LAB30_URL}/"))
    session.cookies.clear()
    for item in cookies:
        if str(item.get("domain", hostname)).lstrip(".").lower() != hostname:
            continue
        expires = item.get("expires", -1)
        session.cookies.jar.set_cookie(Cookie(
            version=0, name=item["name"], value=item["value"], port=None, port_specified=False,
            domain=effective_host, domain_specified=False, domain_initial_dot=False,
            path=item.get("path") or "/", path_specified=True, secure=bool(item.get("secure")),
            expires=int(expires) if expires is not None and expires > 0 else None,
            discard=expires is None or expires <= 0, comment=None, comment_url=None,
            rest={"HttpOnly": None} if item.get("httpOnly") else {}, rfc2109=False,
        ))


def _register_observation(result: dict, kind: str) -> dict:
    ident = result.get("job_id") or secrets.token_hex(16)
    successful = not result.get("error") and result.get("available", True)
    execution_status = "finished" if successful else result.get("execution_status", "error")
    if not isinstance(execution_status, str):
        execution_status = "finished" if successful else "error"
    result.update(job_id=ident, exit_code=0 if successful else None, execution_status=execution_status)
    stdout = str(result.get("body", "")) if kind == "http" else json.dumps(
        {key: result.get(key) for key in ("title", "url", "dialogs", "console_errors", "body_text", "evaluated")}, ensure_ascii=False)
    job = {"job_id": ident, "kind": kind, "status": execution_status, "exit_code": result["exit_code"],
           "stdout": stdout, "stderr": str(result.get("error", "")), "timed_out": False,
           "created_ts": time.time(), "artifacts": result.get("artifacts", []),
           **{key: result[key] for key in ("context_id", "identity", "precondition", "postcondition", "state_changes") if key in result}}
    if kind == "http":
        job["http_status"] = result.get("status")
    with _jobs_lock:
        _jobs[ident] = job
    result.setdefault("stdout", stdout)
    return result


def _browser_sync(request: BrowserRequest) -> dict:
    path = _check_path(request.path)
    job_id = secrets.token_hex(16)
    directory = _job_dir(job_id)
    directory.mkdir(parents=True, exist_ok=False)
    os.chmod(directory, 0o700)
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return {"available": False, "reason": "browser_unavailable", "job_id": ""}
    dialogs: list[str] = []
    console_errors: list[str] = []
    title = ""
    url = ""
    body_text = ""
    evaluated = ""
    screenshot = ""
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context()
            cookies = _prepared_cookies(request.context_id, request.identity)
            if cookies:
                context.add_cookies(cookies)
            page = context.new_page()
            page.on("dialog", lambda dialog: (dialogs.append(str(dialog.message)[:500]), dialog.dismiss()))
            page.on("console", lambda message: console_errors.append(str(message.text)[:500]) if message.type == "error" else None)
            page.goto(f"{LAB30_URL}{path}", wait_until="domcontentloaded", timeout=20000)
            page.wait_for_timeout(request.wait_ms)
            title = page.title()[:500]
            url = page.url
            body_text = (page.inner_text("body") or "")[:4000]
            if request.script:
                result = page.evaluate(request.script)
                evaluated = str(result)[:2000]
            screenshot_path = directory / "screenshot.png"
            page.screenshot(path=str(screenshot_path), full_page=True)
            # Keep changes inside this context/identity only. A new browser
            # process must not silently discard login/logout or attack cookies.
            _store_browser_cookies(request.context_id, request.identity, context.cookies())
            browser.close()
            if screenshot_path.is_file() and screenshot_path.stat().st_size <= MAX_ARTIFACT_BYTES:
                screenshot = "screenshot.png"
    except Exception as exc:  # Playwright raises its own error hierarchy.
        return {
            "available": True,
            "error": type(exc).__name__,
            "job_id": "",
            "title": title,
            "url": url,
            "dialogs": dialogs[:20],
            "console_errors": console_errors[:20],
            "body_text": body_text,
            "evaluated": evaluated,
            "artifacts": [],
        }
    job = {
        "job_id": job_id,
        "kind": "browser",
        "status": "finished",
        "exit_code": 0,
        "duration_ms": 0,
        "stdout": "",
        "stderr": "",
        "truncated": False,
        "timed_out": False,
        "artifacts": _collect_artifacts(directory, [screenshot] if screenshot else []),
        "created_ts": time.time(),
    }
    with _jobs_lock:
        _jobs[job_id] = job
    return {
        "available": True,
        "job_id": job_id,
        "title": title,
        "url": url,
        "dialogs": dialogs[:20],
        "console_errors": console_errors[:20],
        "body_text": body_text,
        "evaluated": evaluated,
        "artifacts": job["artifacts"],
    }


@app.post("/v1/browser/check", dependencies=protected)
async def browser_check(request: BrowserRequest) -> dict:
    _check_target(request.target)
    _identity(request.identity)
    _cleanup()
    async with _semaphore:
        result = await asyncio.to_thread(_context_operation, request.context_id, request.target,
                                        lambda ctx: _observed_action(ctx, request.identity, lambda: _browser_sync(request)))
    return _register_observation(result, "browser")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("POC_RUNNER_PORT") or 8080), log_level="info")
