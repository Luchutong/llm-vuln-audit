"""Server-side model configuration, saved credentials and run budgets.

The initial profile is read from ``LLM_*`` environment variables.  Additional
provider profiles may be entered locally; their API keys are encrypted before
SQLite persistence and are never returned by an endpoint. ``LLM_*`` names are
shared with the sibling harness-generation project so one local ``.env`` can
still drive the default profile.
"""
from __future__ import annotations

import os
import re
import shlex
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from cryptography.fernet import Fernet, InvalidToken

VERSION = "0.1.0"
WORKER_NAME = "audit-worker-1"

# The allowance a run gets when the caller names none.  Deliberately loose: a Planner
# round that runs out of responses before it reaches a structured decision produces no
# task at all, which costs a whole run rather than a few calls, and the way to stop a
# run early is ``pause``/``cancel`` rather than a budget that expires mid-decision.
# ``MAX_BUDGETS`` is the ceiling a caller may ask for, not a recommendation.
DEFAULT_BUDGETS = {"responses": 24, "tools": 96, "seconds": 1800}
MIN_BUDGETS = {"responses": 1, "tools": 0, "seconds": 30}
MAX_BUDGETS = {"responses": 256, "tools": 2048, "seconds": 14400}

_MODEL_KEYS = ("LLM_MODEL", "AUDIT_MODEL")
_BASE_KEYS = ("LLM_BASE_URL", "AUDIT_BASE_URL")
_KEY_KEYS = ("LLM_API_KEY", "AUDIT_API_KEY", "OPENAI_API_KEY")
_THINKING_KEYS = ("LLM_THINKING", "AUDIT_THINKING")

_TRUTHY = {"1", "true", "yes", "on"}


def model_unavailable_reason(model: str) -> str:
    if str(model).strip().casefold() == 'ark-code-latest':
        return 'ark-code-latest 已停用，请选择当前有效的模型档案后创建新的继续任务。'
    return ''

# POC model-loop implementations.  ``legacy`` is the built-in code-action loop and the
# only one enabled by default: the SDK adapter must be verified on this host first.
POC_RUNTIMES = ("legacy", "claude_sdk")
# The frozen SDK generation policy block.  The version string lives here because both
# the server settings and the runtime adapter freeze the same document.
SDK_GENERATION_VERSION = "sdk-generation-v1"
SDK_OUTPUT_POLICIES = ("bounded-v1", "provider_default")
SDK_THINKING_POLICIES = ("disabled", "provider_default")

_URL_USERINFO = re.compile(r"(?i)(https?://)[^/\s@]*@")
_URL_QUERY_FRAGMENT = re.compile(r"(?i)(https?://[^\s?#]+)(?:\?[^\s#]*)?(?:#[^\s]*)?")


def _first(environ: dict[str, str], names: tuple[str, ...], default: str = "") -> str:
    for name in names:
        value = (environ.get(name) or "").strip()
        if value:
            return value
    return default


def load_env_file(path: Path) -> None:
    """Populate os.environ from a KEY=VALUE file without overriding real env."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip().removeprefix("export ").strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, raw = line.partition("=")
        name = name.strip()
        if not name or name in os.environ:
            continue
        value = raw.strip()
        if value[:1] in {"'", '"'}:
            try:
                parts = shlex.split(value, comments=False)
            except ValueError:
                continue
            if len(parts) != 1:
                continue
            value = parts[0]
        os.environ[name] = value


def sync_model_env(path: Path, model: "ModelConfig") -> None:
    """Explicitly export one selected connection, preserving unrelated configuration."""
    if reason := model_unavailable_reason(model.model):
        raise ValueError(reason)
    values = dict(LLM_MODEL=model.model, LLM_BASE_URL=model.base_url,
                  LLM_API_KEY=model.api_key, LLM_THINKING='true' if model.thinking == 'enabled' else 'false')
    if not model.configured or any(any(ch in value for ch in '\r\n\x00') for value in values.values()):
        raise ValueError('档案未完整配置，或包含不支持的换行字符')
    original = path.read_text(encoding='utf-8') if path.exists() else ''
    lines, written = [], set()
    for line in original.splitlines(keepends=True):
        match = re.match(r'^\s*(?:export\s+)?(LLM_MODEL|LLM_BASE_URL|LLM_API_KEY|LLM_THINKING)\s*=', line)
        if not match:
            lines.append(line)
        elif match[1] not in written:
            lines.append(f'{match[1]}={shlex.quote(values[match[1]])}\n')
            written.add(match[1])
    if lines and not lines[-1].endswith(('\n', '\r')):
        lines[-1] += '\n'
    lines.extend(f'{key}={shlex.quote(value)}\n' for key, value in values.items() if key not in written)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(''.join(lines))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def find_env_file(start: Path) -> Path | None:
    for candidate in (start / ".env", start.parent / ".env", start.parent.parent / ".env"):
        if candidate.is_file():
            return candidate
    return None


@dataclass(frozen=True)
class ModelConfig:
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    thinking: str = "disabled"

    @classmethod
    def from_environ(cls, environ: dict[str, str] | None = None) -> "ModelConfig":
        env = dict(os.environ if environ is None else environ)
        thinking = _first(env, _THINKING_KEYS, "disabled").casefold()
        return cls(
            model=_first(env, _MODEL_KEYS),
            base_url=_first(env, _BASE_KEYS).rstrip("/"),
            api_key=_first(env, _KEY_KEYS),
            thinking="enabled" if thinking in _TRUTHY else "disabled",
        )

    @property
    def configured(self) -> bool:
        return bool(self.model and self.base_url and self.api_key)

    @property
    def label(self) -> str:
        return self.model or "unconfigured"

    def public_base_url(self) -> str:
        """Render an endpoint without accidental URL user-info or query secrets."""
        try:
            parsed = urlsplit(self.base_url)
        except ValueError:
            return ""
        netloc = parsed.netloc.rsplit("@", 1)[-1]
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))

    def redact(self, value: object) -> str:
        """Remove configured credentials before errors enter durable state or a response."""
        text = str(value)
        if self.api_key:
            text = text.replace(self.api_key, "[redacted]")
        # Environment variables predate the profile URL validator and might still
        # contain user-info.  Libraries frequently echo their endpoint in network
        # exceptions, so remove user-info from any http(s) URL before persisting it
        # as a health error or returning it to the browser.
        if self.base_url:
            text = text.replace(self.base_url, self.public_base_url())
        text = _URL_USERINFO.sub(r"\1", text)
        return _URL_QUERY_FRAGMENT.sub(r"\1", text)

    def extra_body(self) -> dict:
        # The Ark plan endpoint and DeepSeek both accept this toggle; sending it
        # explicitly keeps reasoning output from consuming the response budget.
        return {"thinking": {"type": self.thinking}}

    def missing(self) -> list[str]:
        absent = []
        if not self.model:
            absent.append("LLM_MODEL")
        if not self.base_url:
            absent.append("LLM_BASE_URL")
        if not self.api_key:
            absent.append("LLM_API_KEY")
        return absent

    def public(self) -> dict:
        return {
            # ``label`` is useful for human-facing run records, but API consumers
            # need the actual selected identifier so they can edit a saved model
            # catalogue without treating "unconfigured" as a real model name.
            "model": self.model,
            "base_url": self.public_base_url(),
            "configured": self.configured,
            "thinking": self.thinking,
            "missing": self.missing(),
        }


class CredentialVault:
    """Encrypt UI-saved provider keys with a machine-local Fernet key.

    The key lives alongside the local SQLite data with owner-only permissions, not
    in the database or a browser response.  This protects against accidentally
    sharing ``audit.db`` while keeping a single-user local workbench usable without
    adding another mandatory environment variable.  Operators can still use the
    original environment-backed profile when they do not want a key persisted.
    """

    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / ".model-config.key"
        self._cipher = Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        try:
            key = self.path.read_bytes().strip()
        except FileNotFoundError:
            key = Fernet.generate_key()
            try:
                descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                key = self.path.read_bytes().strip()
            else:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(key)
        try:
            # A pre-existing key can come from an older umask. Tighten it when
            # the platform supports POSIX permissions; this is harmless on the
            # local Docker and Linux workflows the project documents.
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        try:
            # Constructing a Fernet instance validates the key before a saved
            # credential can be accepted or decrypted.
            Fernet(key)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("本地模型凭据密钥无效；请恢复 data/.model-config.key 的备份") from exc
        return key

    def encrypt(self, value: str) -> str:
        return self._cipher.encrypt(value.encode("utf-8")).decode("ascii") if value else ""

    def decrypt(self, value: str) -> str:
        if not value:
            return ""
        try:
            return self._cipher.decrypt(value.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError) as exc:
            raise RuntimeError("无法解密已保存的模型凭据；请重新录入该模型的 API Key") from exc


def clamp_budgets(raw: object) -> dict:
    """Merge a requested budget with defaults and clamp it to the allowed range."""
    result = dict(DEFAULT_BUDGETS)
    if isinstance(raw, dict):
        for name in DEFAULT_BUDGETS:
            value = raw.get(name)
            if isinstance(value, bool) or not isinstance(value, int):
                continue
            result[name] = max(MIN_BUDGETS[name], min(MAX_BUDGETS[name], value))
    return result


@dataclass(frozen=True)
class PocSettings:
    """Where and how automatically verified POCs are executed.

    The only executor is the isolated ``poc-runner`` service: this process never runs a
    POC script itself.  ``snapshot()`` is what a run freezes and what ``/api/config``
    exposes, so it deliberately omits the bearer token and the runner's network
    addresses -- neither is needed by the browser or by a report.
    """

    enabled: bool = True
    required: bool = False
    runner_url: str = ""
    runner_token: str = ""
    target: str = "lab30"
    job_seconds: int = 30
    max_steps: int = 8
    max_jobs: int = 8
    max_seconds: int = 300
    concurrency: int = 2
    max_script_bytes: int = 32768
    browser: bool = True
    runner_addrs: tuple[str, ...] = ()
    reset_between_findings: bool = False
    reset_command: str = ""
    reset_timeout: int = 30
    # Which model loop drives one POC attempt.  ``legacy`` is the hand-written code
    # action loop; ``claude_sdk`` is the Claude Agent SDK adapter.  The server decides
    # the default; a run request can only downgrade to ``legacy``.
    runtime: str = "legacy"
    sdk_requests: dict | None = None
    # Frozen generation policy for the SDK subprocess, mirroring ``PocPolicy``.  None
    # means the run predates it (or the runtime is legacy) and keeps provider defaults.
    sdk_generation: dict | None = None

    @classmethod
    def from_environ(cls, environ: dict[str, str] | None = None) -> "PocSettings":
        env = dict(os.environ if environ is None else environ)

        def flag(name: str, default: bool) -> bool:
            raw = (env.get(name) or "").strip().casefold()
            if not raw:
                return default
            return raw in _TRUTHY

        def number(name: str, default: int, low: int, high: int) -> int:
            try:
                value = int((env.get(name) or "").strip() or default)
            except ValueError:
                return default
            return max(low, min(high, value))

        def strict_number(name: str, default: int, low: int, high: int) -> int:
            # Generation limits are enforced by the gateway on every request, so a
            # malformed deployment value fails at startup instead of being clamped
            # into a limit the operator never asked for.
            raw = (env.get(name) or "").strip()
            if not raw:
                return default
            try:
                value = int(raw)
            except ValueError as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if not low <= value <= high:
                raise ValueError(f"{name} must be between {low} and {high}")
            return value

        def choice(name: str, default: str, allowed: tuple[str, ...]) -> str:
            value = (env.get(name) or "").strip().casefold() or default
            if value not in allowed:
                raise ValueError(f"{name} must be one of {', '.join(allowed)}")
            return value

        addrs = tuple(
            value.strip()
            for value in (env.get("POC_RUNNER_ADDRS") or "").split(",")
            if value.strip()
        )
        runtime = (env.get("POC_RUNTIME") or "").strip().casefold() or "legacy"
        if runtime not in POC_RUNTIMES:
            raise ValueError(f"POC_RUNTIME must be one of {', '.join(POC_RUNTIMES)}")
        sdk_requests = None
        sdk_generation = None
        if runtime == "claude_sdk":
            # Keep the static application available on malformed SDK deployment
            # settings. Runtime readiness still diagnoses those strictly before POC.
            sdk_requests = {"version": "sdk-requests-v1",
                            "execute": number("POC_CLAUDE_EXECUTE_REQUESTS", 40, 1, 512),
                            "conclude": number("POC_CLAUDE_CONCLUDE_REQUESTS", 3, 3, 16)}
            sdk_generation = {
                "version": SDK_GENERATION_VERSION,
                "output_policy": choice("POC_SDK_OUTPUT_POLICY", "bounded-v1", SDK_OUTPUT_POLICIES),
                "execute_output_tokens": strict_number("POC_SDK_EXECUTE_OUTPUT_TOKENS", 4096, 256, 65536),
                "publish_output_tokens": strict_number("POC_SDK_PUBLISH_OUTPUT_TOKENS", 1024, 128, 65536),
                "thinking": choice("POC_SDK_THINKING", "disabled", SDK_THINKING_POLICIES),
            }
        return cls(
            enabled=flag("POC_ENABLED", True),
            required=flag("POC_REQUIRED", False),
            runner_url=(env.get("POC_RUNNER_URL") or "").strip().rstrip("/"),
            runner_token=(env.get("POC_RUNNER_TOKEN") or "").strip(),
            target="lab30",
            job_seconds=number("POC_JOB_SECONDS", 30, 1, 120),
            max_steps=number("POC_MAX_STEPS", 8, 1, 32),
            max_jobs=number("POC_MAX_JOBS", 8, 1, 32),
            max_seconds=number("POC_MAX_SECONDS", 300, 10, 3600),
            concurrency=number("POC_CONCURRENCY", 2, 1, 8),
            max_script_bytes=number("POC_MAX_SCRIPT_BYTES", 32768, 1024, 131072),
            browser=flag("POC_BROWSER", True),
            runner_addrs=addrs,
            # Resetting between findings keeps every automatic proof on seed accounts.
            # The command comes only from the server environment: a run request may pin
            # the switch but can never supply or override the command itself.
            reset_between_findings=flag("POC_RESET_BETWEEN_FINDINGS", False),
            reset_command=(env.get("POC_LAB30_RESET_COMMAND") or "").strip(),
            reset_timeout=number("POC_RESET_TIMEOUT", 30, 5, 300),
            runtime=runtime,
            sdk_requests=sdk_requests,
            sdk_generation=sdk_generation,
        )

    @property
    def configured(self) -> bool:
        return bool(self.enabled and self.runner_url)

    def snapshot(self) -> dict:
        """The run-frozen policy: no credentials, no internal addresses."""
        return {
            "enabled": self.enabled,
            "required": self.required,
            "target": self.target,
            "runner_configured": bool(self.runner_url),
            "job_seconds": self.job_seconds,
            "max_steps": self.max_steps,
            "max_jobs": self.max_jobs,
            "max_seconds": self.max_seconds,
            "browser": self.browser,
            "max_script_bytes": self.max_script_bytes,
            "reset_between_findings": self.reset_between_findings,
            "reset_timeout": self.reset_timeout,
            "runtime": self.runtime,
            **({"sdk_requests": dict(self.sdk_requests or {"version": "sdk-requests-v1", "execute": 40, "conclude": 3})}
               if self.runtime == "claude_sdk" else {}),
            **({"sdk_generation": dict(self.sdk_generation or {
                "version": SDK_GENERATION_VERSION, "output_policy": "provider_default",
                "execute_output_tokens": 4096, "publish_output_tokens": 1024,
                "thinking": "provider_default"})}
               if self.runtime == "claude_sdk" else {}),
        }

    def public(self) -> dict:
        return {
            "enabled": self.enabled,
            "required": self.required,
            "target": self.target,
            "runner_configured": bool(self.runner_url),
            "browser": self.browser,
            "max_script_bytes": self.max_script_bytes,
            "reset_between_findings": self.reset_between_findings,
            "reset_command_configured": bool(self.reset_command),
            "runtime": self.runtime,
            # What the gateway will verify on every SDK request. Provider defaults are
            # reported as such rather than as an enforced numeric cap.
            **({"sdk_generation": dict(self.sdk_generation)} if self.sdk_generation else {}),
        }


@dataclass
class Settings:
    data_dir: Path
    model: ModelConfig
    budgets: dict = field(default_factory=lambda: dict(DEFAULT_BUDGETS))
    version: str = VERSION
    worker: str = WORKER_NAME
    poc: PocSettings = field(default_factory=PocSettings)

    @classmethod
    def load(cls, environ: dict[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ
        data_dir = Path(env.get("AUDIT_DATA_DIR") or (Path(__file__).resolve().parent.parent / "data"))
        data_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            data_dir=data_dir,
            model=ModelConfig.from_environ(env),
            poc=PocSettings.from_environ(env),
        )

    @property
    def db_path(self) -> Path:
        return self.data_dir / "audit.db"

    @property
    def evidence_dir(self) -> Path:
        path = self.data_dir / "evidence"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def snapshot_dir(self) -> Path:
        path = self.data_dir / "snapshots"
        path.mkdir(parents=True, exist_ok=True)
        return path
