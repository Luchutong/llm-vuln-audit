"""Read-only, bounded POC runner preflight checks.

Checking readiness never prepares/resets a target and never submits a job.  The
cache is process-local; an execution still checks readiness before preparing its
target, and required-mode creation can explicitly bypass a cached answer.
"""
from __future__ import annotations

import asyncio
import copy
import time
from datetime import datetime, timezone

from .poc_runner import PocRunnerClient, PocRunnerError, PocRunnerUnavailable


POC_MODES = frozenset({"off", "auto", "required"})
# Profiles (source-package identity) and runner target names that the automatic
# verifier may prepare.  Lab30 shop (拾光商城) joins DVWA as a supported range.
SUPPORTED_PROFILES = frozenset({"dvwa", "lab30"})
SUPPORTED_TARGETS = frozenset({"dvwa", "lab30"})
READINESS_MESSAGES = {
    "disabled": "服务端未开放自动执行 POC。",
    "unsupported_target": "当前自动验证环境仅支持 DVWA 与 Lab30 商城靶场，该源码包不适用。",
    "runner_unconfigured": "尚未配置隔离 POC runner。",
    "runner_unhealthy": "隔离 POC runner 当前不可用。",
    "ready": "隔离 POC runner 已就绪。",
}


def normalize_poc_mode(run: dict) -> tuple[str, bool]:
    """Preserve old runs' *actual* gate, independently of new-request defaults.

    New POST requests must freeze an explicit mode (default off) in poc_policy.
    An old require_poc=True run required dynamic verification even when its
    frozen enabled flag was false; treating that run as off would change its goal.
    """
    policy = run.get("poc_policy") or {}
    explicit = policy.get("mode", run.get("poc_mode"))
    if explicit in POC_MODES:
        return str(explicit), bool(policy.get("legacy", False))
    task = run.get("task_spec") or {}
    if task.get("require_poc"):
        return "required", True
    return ("auto" if policy.get("enabled", False) else "off"), True


class PocReadinessService:
    def __init__(self, settings, *, client_factory=None, clock=time.monotonic, timeout=5.0):
        self.settings = settings
        self.client_factory = client_factory
        self.clock = clock
        self.timeout = min(5.0, max(0.01, float(timeout)))
        self._cache: dict[tuple, tuple[float, dict]] = {}
        self._pending: dict[tuple, asyncio.Task] = {}

    def _result(self, reason: str, *, mode: str, profile: str, target: str, capabilities=None) -> dict:
        return {
            "available": reason == "ready",
            "reason": reason,
            "message": READINESS_MESSAGES[reason],
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "target_profile": profile,
            "target": target,
            # Only booleans for known public capabilities cross the boundary.
            "capabilities": {"supported_targets": sorted(SUPPORTED_TARGETS), **{
                name: bool((capabilities or {}).get(name, False)) and (name != "browser" or self.settings.poc.browser)
                for name in ("php", "python", "browser")
            }},
        }

    async def check(self, target_profile: str, *, mode="auto", target=None, fresh=False) -> dict:
        if mode not in POC_MODES:
            raise ValueError("Invalid POC mode")
        poc = self.settings.poc
        profile = str(target_profile or "unknown")
        target = str(target or poc.target or "dvwa")
        reason = (
            "disabled" if mode == "off" else
            "disabled" if not poc.enabled else
            "unsupported_target" if profile not in SUPPORTED_PROFILES or target not in SUPPORTED_TARGETS else
            "runner_unconfigured" if not poc.runner_url else None
        )
        if reason:
            result = self._result(reason, mode=mode, profile=profile, target=target)
            if mode == "off":
                result["message"] = "本次审计未启用自动执行 POC，源码审计与验证脚本生成不受影响。"
            return result

        # Credentials/configuration participate in invalidation but never leave this
        # object.  Mode changes do not create redundant concurrent health requests.
        key = (poc.runner_url, poc.runner_token, target)
        cached = self._cache.get(key)
        if not fresh and cached and cached[0] > self.clock():
            return {**copy.deepcopy(cached[1]), "mode": mode, "target_profile": profile}
        pending = self._pending.get(key)
        if pending is None:
            pending = asyncio.create_task(self._check_health(profile, target, mode))
            self._pending[key] = pending
            pending.add_done_callback(lambda task: self._pending.pop(key, None))
        # One caller cancelling navigation must not cancel other callers' preflight.
        result = await asyncio.shield(pending)
        ttl = 15.0 if result["available"] else 5.0
        self._cache[key] = (self.clock() + ttl, copy.deepcopy(result))
        return {**copy.deepcopy(result), "mode": mode, "target_profile": profile}

    async def _check_health(self, profile: str, target: str, mode: str) -> dict:
        client = None
        try:
            poc = self.settings.poc
            client = self.client_factory() if self.client_factory else PocRunnerClient(poc.runner_url, poc.runner_token)
            health = await asyncio.wait_for(client.health(), timeout=self.timeout)
            if not isinstance(health, dict) or not health.get("ok"):
                raise PocRunnerUnavailable("runner not healthy")
            capabilities = health.get("capabilities")
            if not isinstance(capabilities, dict):
                capabilities = {}
            return self._result("ready", mode=mode, profile=profile, target=target, capabilities=capabilities)
        except (PocRunnerError, PocRunnerUnavailable, asyncio.TimeoutError, OSError, ValueError):
            return self._result("runner_unhealthy", mode=mode, profile=profile, target=target)
        finally:
            if client is not None:
                close = getattr(client, "aclose", None)
                if close:
                    try:
                        await asyncio.wait_for(close(), timeout=0.1)
                    except (Exception, asyncio.CancelledError):
                        pass
