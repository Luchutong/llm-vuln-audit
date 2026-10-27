"""Environment-backed defaults for the context window and output budgets.

Every limit in :class:`AgentPolicy` used to be a literal.  That made the one hard
gate -- the serialized size of a request -- impossible to tune for a model with a
larger or smaller window, and impossible to reproduce against a live provider.

Reading the environment here, at ``runtime`` import time, rather than in ``app.py``
is deliberate: ``AgentPolicy()`` is also constructed as a fallback inside the planner,
the worker, the POC agent and the comparison runner.  A value set only on the application
object would be silently ignored on every one of those paths.

An invalid value is a startup failure.  A limit that quietly falls back to its default
would make ``/api/config`` disagree with what the process actually enforces, which is
exactly the kind of drift these knobs exist to remove.
"""
from __future__ import annotations

import os

_TRUTHY = {"1", "true", "yes", "on"}
_FALSEY = {"0", "false", "no", "off"}


def _raw(name: str, environ: dict[str, str] | None) -> str:
    source = os.environ if environ is None else environ
    return str(source.get(name) or "").strip()


def env_int(
    name: str,
    default: int,
    minimum: int,
    maximum: int,
    *,
    environ: dict[str, str] | None = None,
) -> int:
    """One bounded integer setting; unset means ``default``."""
    raw = _raw(name, environ)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"{name} 必须是整数，当前为 {raw!r}") from None
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} 必须在 {minimum}..{maximum} 之间，当前为 {value}")
    return value


def env_float(
    name: str,
    default: float,
    minimum: float,
    maximum: float,
    *,
    environ: dict[str, str] | None = None,
) -> float:
    """One bounded numeric setting that accepts a decimal point."""
    raw = _raw(name, environ)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise RuntimeError(f"{name} 必须是数字，当前为 {raw!r}") from None
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} 必须在 {minimum}..{maximum} 之间，当前为 {value}")
    return value


def env_flag(name: str, default: bool, *, environ: dict[str, str] | None = None) -> bool:
    """One boolean setting; an unknown spelling is a startup failure, not silence."""
    raw = _raw(name, environ).casefold()
    if not raw:
        return default
    if raw in _TRUTHY:
        return True
    if raw in _FALSEY:
        return False
    raise RuntimeError(f"{name} 必须是布尔值（1/0、true/false、yes/no、on/off），当前为 {raw!r}")
