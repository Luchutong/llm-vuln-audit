"""Isolated POC execution service.

This process is deliberately small and boring.  It listens only on the Compose
``poc-control`` network, executes one whitelisted script at a time inside a fresh
``/tmp`` directory, and talks to the local DVWA instance on ``poc-target``.  It never
touches uploaded archives, the audit database, the model endpoint or the Docker socket.

The container is built read-only, runs as an unprivileged uid, drops all capabilities
and has no published port.  Those are mitigations, not a proof: a script that escapes
the container runtime is still a script that escaped.  See README.md for the threat
model this service does and does not claim.
"""
from __future__ import annotations

import asyncio
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
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, Field

VERSION = "1.0.0"
TOKEN = (os.environ.get("POC_RUNNER_TOKEN") or "").strip()
DVWA_URL = (os.environ.get("DVWA_URL") or "http://dvwa").rstrip("/")
DVWA_USER = os.environ.get("DVWA_USER") or "admin"
DVWA_PASSWORD = os.environ.get("DVWA_PASSWORD") or "password"
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
    "/login.php",
    "/setup.php",
    "/security.php",
    "/index.php",
    "/about.php",
    "/instructions.php",
    "/logout.php",
    "/vulnerabilities/",
    "/hackable/",
    "/docs/",
)
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SAFE_TARGET = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")

@asynccontextmanager
async def lifespan(_app: FastAPI):
    WORKDIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WORKDIR, 0o700)
    (WORKDIR / "jobs").mkdir(exist_ok=True)
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
_targets: dict[str, dict] = {}
_target_locks = {name: threading.Lock() for name in ("dvwa",)}


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
    reset: bool = True
    security: str = Field(default="low", max_length=16)


class JobRequest(BaseModel):
    target: str = Field(default="dvwa", max_length=32)
    language: str = Field(max_length=16)
    script: str
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    artifacts: list[str] = Field(default_factory=list, max_length=MAX_ARTIFACT_COUNT)


class HttpRequest(BaseModel):
    target: str = Field(default="dvwa", max_length=32)
    method: str = Field(default="GET", max_length=8)
    path: str = Field(max_length=2048)
    body: str = Field(default="", max_length=256 * 1024)
    headers: dict[str, str] = Field(default_factory=dict)


class BrowserRequest(BaseModel):
    target: str = Field(default="dvwa", max_length=32)
    path: str = Field(max_length=2048)
    script: str = Field(default="", max_length=8 * 1024)
    wait_ms: int = Field(default=1000, ge=0, le=10000)


# --------------------------------------------------------------------------- helpers


def _check_target(target: str) -> None:
    if not SAFE_TARGET.fullmatch(target or ""):
        raise HTTPException(status_code=400, detail="invalid target")
    if target != "dvwa":
        raise HTTPException(status_code=404, detail="unknown target")


def _check_path(path: str) -> str:
    candidate = (path or "").strip()
    if not candidate.startswith("/") or candidate.startswith("//"):
        raise HTTPException(status_code=400, detail="path must be absolute and local")
    bare, _, query = candidate.partition("?")
    if any(token in bare for token in ("..", "\\", "\x00", "://")):
        raise HTTPException(status_code=400, detail="invalid path")
    if not any(bare == prefix or bare.startswith(prefix) for prefix in ALLOWED_PATHS):
        raise HTTPException(status_code=403, detail="path is not in the DVWA allowlist")
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
    for entry in entries:
        try:
            if entry.is_dir() and entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)
        except OSError:
            continue
    with _jobs_lock:
        for job_id, job in list(_jobs.items()):
            if job.get("created_ts", 0) < cutoff:
                _jobs.pop(job_id, None)


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


def _child_limits() -> None:
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
            "DVWA_URL": DVWA_URL,
            "DVWA_USER": DVWA_USER,
            "DVWA_PASSWORD": DVWA_PASSWORD,
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


def _execute(request: JobRequest) -> dict:
    job_id = secrets.token_hex(16)
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
        preexec_fn=_child_limits,
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
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        try:
            exit_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            exit_code = -9
    for thread in threads:
        thread.join(timeout=5)
    duration_ms = int((time.monotonic() - started) * 1000)
    stdout, stdout_truncated = stdout_box[0] if stdout_box else (b"", False)
    stderr, stderr_truncated = stderr_box[0] if stderr_box else (b"", False)
    artifacts = _collect_artifacts(directory, request.artifacts)
    job = {
        "job_id": job_id,
        "kind": "script",
        "status": "timeout" if timed_out else "finished",
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout": stdout.decode("utf-8", "replace"),
        "stderr": stderr.decode("utf-8", "replace"),
        "truncated": bool(stdout_truncated or stderr_truncated),
        "timed_out": timed_out,
        "artifacts": artifacts,
        "created_ts": time.time(),
    }
    with _jobs_lock:
        _jobs[job_id] = job
    return job


# --------------------------------------------------------------------------- endpoints


@app.get("/healthz")
def healthz() -> dict:
    return {
        "ok": TOKEN != "",
        "version": VERSION,
        "target": "dvwa",
        "capabilities": {
            "php": shutil.which("php") is not None,
            "python": True,
            "curl": shutil.which("curl") is not None,
            "browser": _browser_available(),
        },
    }


def _browser_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except Exception:
        return False
    return True


def _dvwa_client() -> httpx.Client:
    return httpx.Client(
        base_url=DVWA_URL,
        timeout=httpx.Timeout(15.0, connect=5.0),
        follow_redirects=False,
        trust_env=False,
    )


def _session(session: httpx.Client, method: str, path: str, **kwargs) -> httpx.Response:
    return session.request(method, path, **kwargs)


TOKEN_FIELD = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]")


def _form_token(session: httpx.Client, path: str) -> str:
    """Fetch a page and read its anti-CSRF token.

    DVWA regenerates the token every time it renders one of these pages, so the token
    must come from the exact page that is about to be submitted and no other page may
    be fetched in between.
    """
    page = _session(session, "GET", path)
    if page.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"{path} unavailable")
    match = TOKEN_FIELD.search(page.text)
    return match.group(1) if match else ""


def _prepare_sync(security: str, reset: bool) -> dict:
    if security not in {"low", "medium", "high", "impossible"}:
        raise HTTPException(status_code=400, detail="security must be low, medium, high or impossible")
    deadline = time.time() + 30
    last_error = ""
    session = _dvwa_client()
    try:
        while time.time() < deadline:
            try:
                response = _session(session, "GET", "/login.php")
                if response.status_code < 500 and "DVWA" in response.text:
                    break
            except httpx.HTTPError as exc:
                last_error = type(exc).__name__
            time.sleep(1)
        else:
            raise HTTPException(status_code=503, detail=f"target unreachable: {last_error or 'timeout'}")

        def login() -> bool:
            token = _form_token(session, "/login.php")
            if not token:
                return False
            response = _session(
                session,
                "POST",
                "/login.php",
                data={
                    "username": DVWA_USER,
                    "password": DVWA_PASSWORD,
                    "Login": "Login",
                    "user_token": token,
                },
            )
            if response.status_code >= 400:
                return False
            body = session.get("/index.php")
            return "Logout" in body.text

        if reset:
            # A first-time DVWA has no `users` table, so setup must run before login.
            token = _form_token(session, "/setup.php")
            setup = _session(
                session,
                "POST",
                "/setup.php",
                data={"create_db": "Create / Reset Database", "user_token": token},
            )
            if setup.status_code >= 500:
                raise HTTPException(status_code=502, detail="database reset failed")
        if not login():
            raise HTTPException(status_code=502, detail="target login failed")
        if reset:
            # Recreated tables drop the session's authenticated flag in some releases.
            session.cookies.clear()
            if not login():
                raise HTTPException(status_code=502, detail="login after reset failed")
        token = _form_token(session, "/security.php")
        _session(
            session,
            "POST",
            "/security.php",
            data={"security": security, "seclev_submit": "Submit", "user_token": token},
        )
        level = session.cookies.get("security") or security
        index = session.get("/index.php")
        authenticated = "Logout" in index.text
        version = ""
        match = re.search(r"Version\s+([0-9][0-9A-Za-z.\-]*)", index.text)
        if match:
            version = match.group(1)
        snapshot = {
            "base_url": DVWA_URL,
            "version": version,
            "security": level,
            "authenticated": authenticated,
            "prepared_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        # The prepared client keeps the PHP session cookie in memory.  It is never
        # returned to the model; scripts log in themselves using the DVWA_* env vars.
        previous = _targets.get("dvwa")
        if previous is not None:
            try:
                previous["client"].close()
            except Exception:
                pass
        _targets["dvwa"] = {"client": session, "status": snapshot}
        return {"ok": authenticated, **snapshot}
    except Exception:
        session.close()
        raise


@app.post("/v1/targets/{target}/prepare", dependencies=protected)
async def prepare_target(target: str, request: PrepareRequest) -> dict:
    _check_target(target)
    _cleanup()
    lock = _target_locks.setdefault(target, threading.Lock())
    await asyncio.to_thread(lock.acquire)
    try:
        return await asyncio.to_thread(_prepare_sync, request.security, request.reset)
    finally:
        lock.release()


@app.get("/v1/targets/{target}/status", dependencies=protected)
async def target_status(target: str) -> dict:
    _check_target(target)

    def probe() -> dict:
        state = _targets.get(target)
        if state is None:
            return {
                "ok": False,
                "base_url": DVWA_URL,
                "authenticated": False,
                "security": "",
                "version": "",
                "prepared_at": "",
            }
        session: httpx.Client = state["client"]
        status = dict(state["status"])
        try:
            index = session.get("/index.php")
            status["ok"] = index.status_code < 400
            status["authenticated"] = "Logout" in index.text
            status["security"] = session.cookies.get("security") or status.get("security", "")
        except httpx.HTTPError:
            status["ok"] = False
        return status

    return await asyncio.to_thread(probe)


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
    _cleanup()
    async with _semaphore:
        job = await asyncio.to_thread(_execute, request)
    return _job_public(job)


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
    state = _targets.get(request.target)
    session = state["client"] if state else None
    owned = session is None
    if session is None:
        session = _dvwa_client()
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
    finally:
        if owned:
            session.close()


@app.post("/v1/http", dependencies=protected)
async def http_observe(request: HttpRequest) -> dict:
    _check_target(request.target)
    return await asyncio.to_thread(_observe_sync, request)


def _prepared_cookies() -> list[dict]:
    """The prepared DVWA session in the shape Playwright accepts.

    DVWA serves its vulnerability pages only to an authenticated session.  A browser
    launched without these cookies lands on ``login.php`` and can never observe the
    injected script, which would make every XSS conclusion unverifiable.

    The cookies are scoped by ``url`` rather than by their original ``domain``: DVWA
    issues them for ``dvwa.local`` while the runner reaches it as ``dvwa``.  httpx
    tolerates that mismatch, Chromium does not, and would silently drop the session.
    """
    entry = _targets.get("dvwa")
    if not entry:
        return []
    return [
        {"name": cookie.name, "value": cookie.value, "url": f"{DVWA_URL}/"}
        for cookie in entry["client"].cookies.jar
    ]


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
            cookies = _prepared_cookies()
            if cookies:
                context.add_cookies(cookies)
            page = context.new_page()
            page.on("dialog", lambda dialog: (dialogs.append(str(dialog.message)[:500]), dialog.dismiss()))
            page.on("console", lambda message: console_errors.append(str(message.text)[:500]) if message.type == "error" else None)
            page.goto(f"{DVWA_URL}{path}", wait_until="domcontentloaded", timeout=20000)
            page.wait_for_timeout(request.wait_ms)
            title = page.title()[:500]
            url = page.url
            body_text = (page.inner_text("body") or "")[:4000]
            if request.script:
                result = page.evaluate(request.script)
                evaluated = str(result)[:2000]
            screenshot_path = directory / "screenshot.png"
            page.screenshot(path=str(screenshot_path), full_page=True)
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
    _cleanup()
    async with _semaphore:
        return await asyncio.to_thread(_browser_sync, request)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("POC_RUNNER_PORT") or 8080), log_level="info")
