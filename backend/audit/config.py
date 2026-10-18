"""Server-side model configuration and run budgets.

Credentials come from the environment only; they are never stored in the database
and never returned by an endpoint. ``LLM_*`` names are shared with the sibling
harness-generation project so one local ``.env`` can drive both.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "0.1.0"
WORKER_NAME = "audit-worker-1"

DEFAULT_BUDGETS = {"responses": 8, "tools": 16, "seconds": 300}
MIN_BUDGETS = {"responses": 1, "tools": 0, "seconds": 30}
MAX_BUDGETS = {"responses": 64, "tools": 256, "seconds": 3600}

_MODEL_KEYS = ("LLM_MODEL", "AUDIT_MODEL")
_BASE_KEYS = ("LLM_BASE_URL", "AUDIT_BASE_URL")
_KEY_KEYS = ("LLM_API_KEY", "AUDIT_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY")
_THINKING_KEYS = ("LLM_THINKING", "AUDIT_THINKING")
_DEEPSEEK_BASE_URL = "https://api.deepseek.com"
_DEEPSEEK_MODEL = "deepseek-flash"

_TRUTHY = {"1", "true", "yes", "on"}


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
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ[name] = value


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
        deepseek_configured = bool((env.get("DEEPSEEK_API_KEY") or "").strip())
        return cls(
            model=_first(env, _MODEL_KEYS, _DEEPSEEK_MODEL if deepseek_configured else ""),
            base_url=_first(
                env, _BASE_KEYS, _DEEPSEEK_BASE_URL if deepseek_configured else ""
            ).rstrip("/"),
            api_key=_first(env, _KEY_KEYS),
            thinking="enabled" if thinking in _TRUTHY else "disabled",
        )

    @property
    def configured(self) -> bool:
        return bool(self.model and self.base_url and self.api_key)

    @property
    def label(self) -> str:
        return self.model or "unconfigured"

    def masked_key(self) -> str:
        if not self.api_key:
            return ""
        return f"{self.api_key[:6]}****" if len(self.api_key) > 6 else "****"

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
            "model": self.label,
            "base_url": self.base_url,
            "configured": self.configured,
            "thinking": self.thinking,
            "api_key_hint": self.masked_key(),
            "missing": self.missing(),
        }


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


@dataclass
class Settings:
    data_dir: Path
    model: ModelConfig
    budgets: dict = field(default_factory=lambda: dict(DEFAULT_BUDGETS))
    version: str = VERSION
    worker: str = WORKER_NAME

    @classmethod
    def load(cls, environ: dict[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ
        data_dir = Path(env.get("AUDIT_DATA_DIR") or (Path(__file__).resolve().parent.parent / "data"))
        data_dir.mkdir(parents=True, exist_ok=True)
        return cls(data_dir=data_dir, model=ModelConfig.from_environ(env))

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
