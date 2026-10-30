"""Automatic POC verification orchestration.

``PocVerifier`` is the host half: it decides *when* verification happens, prepares the
target once, runs the POC agent per standing conclusion, persists the verdict and its
runner jobs, and keeps the run's closure rules honest.  The model half lives in
``poc_agent``.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import shlex
import time
import uuid
from dataclasses import dataclass, replace

from .config import ModelConfig, Settings
from .db import Store, now
from .events import EventBus
from .poc_agent import PocDeps, run_poc_agent
from .poc_runner import PocRunnerClient, PocRunnerError, PocRunnerUnavailable, PocRunnerBusy
from .poc_readiness import PocReadinessService, normalize_poc_mode
from .poc_source import PROGRESS_POLICY, PocSourceProvider, SourceLimits
from .poc_store import poc_target_key
from .runtime import AgentPolicy, StopAudit
from .schemas import PocVerificationResult


def _int(raw: object, default: int, low: int, high: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def _pin_sdk_requests(limits, frozen):
    if frozen is None:
        return limits
    if (not isinstance(frozen, dict) or frozen.get("version") != "sdk-requests-v1"
            or type(frozen.get("execute")) is not int or not 1 <= frozen["execute"] <= 512
            or type(frozen.get("conclude")) is not int or not 3 <= frozen["conclude"] <= 16):
        raise ValueError("冻结的 SDK 请求额度无效")
    seconds = frozen.get("max_seconds", limits.max_seconds)
    if "max_seconds" in frozen and (type(seconds) is not int or not 30 <= seconds <= 3600):
        raise ValueError("冻结的 SDK 时间额度无效")
    return replace(limits, execute_requests=frozen["execute"], conclude_requests=frozen["conclude"], max_seconds=seconds)


def _generation_limits(limits, frozen):
    """Apply one frozen generation policy to deployment limits.

    ``None`` keeps ``provider_default`` (a historical run), and an invalid block raises
    so the attempt ends as ``runtime_misconfigured`` instead of quietly running with a
    different generation policy than the one recorded for the run.
    """
    from .runtimes.claude_poc import SdkGeneration
    generation = SdkGeneration.from_frozen(frozen)
    return replace(limits, output_policy=generation.output_policy,
                   execute_output_tokens=generation.execute_output_tokens,
                   publish_output_tokens=generation.publish_output_tokens,
                   thinking=generation.thinking)


def _attempt_responses(policy, allowance=None):
    # New SDK runs use their frozen SDK quota. Historical runs retain max_steps;
    # resuming an old run cannot silently adopt a larger current default.
    if policy.runtime == "claude_sdk" and policy.sdk_requests is not None:
        from .runtimes.claude_poc import ClaudePocLimits
        limits = _pin_sdk_requests(ClaudePocLimits(), policy.sdk_requests)
        capacity = limits.execute_requests + limits.conclude_requests
    else:
        capacity = max(2, policy.max_steps) + 3
    available = allowance if type(allowance) is int else policy.max_responses
    return min(capacity, available) if type(available) is int else capacity


@dataclass(frozen=True)
class PocPolicy:
    mode: str = "off"
    legacy: bool = False
    enabled: bool = False
    required: bool = False
    target: str = "lab30"
    job_seconds: int = 30
    max_steps: int = 8
    max_jobs: int = 8
    max_seconds: int = 300
    browser: bool = True
    max_script_bytes: int = 32768
    max_tokens: int = 4096
    # Host-derived allowance for this invocation, never read from user policy.
    max_responses: int | None = None
    reset_between_findings: bool = False
    reset_command: str = ""
    reset_timeout: int = 30
    # Which model loop runs this attempt.  Frozen with the run so a verification record
    # can be read without guessing; a run may only downgrade to ``legacy``.
    runtime: str = "legacy"
    sdk_requests: dict | None = None
    # Frozen SDK generation policy (output caps + thinking).  None on historical runs:
    # they keep the installed SDK/CLI defaults and the gateway verifies nothing.
    sdk_generation: dict | None = None
    # Missing on historical runs: never change a paused run's runtime contract.
    session_policy: str = ""
    item_warning_seconds: int | None = None
    # Which verification loop the host drives.  Historical runs have no value and keep
    # their original behaviour; only the exact frozen name enables the bounded-evidence
    # source window, so an unknown future value can never silently change a live run.
    progress_policy: str = ""
    progress_params: dict | None = None

    @classmethod
    def from_run(cls, run: dict, settings: Settings) -> "PocPolicy":
        raw = run.get("poc_policy") if isinstance(run.get("poc_policy"), dict) else {}
        poc = getattr(settings, "poc", None)
        default_enabled = bool(getattr(poc, "enabled", False))
        mode, legacy = normalize_poc_mode(run)
        server_runtime = str(getattr(poc, "runtime", "legacy") or "legacy")
        requested_runtime = str(raw.get("runtime") or server_runtime)
        return cls(
            mode=mode,
            legacy=legacy,
            enabled=bool(raw.get("enabled", default_enabled)),
            required=mode == "required",
            target=str(raw.get("target") or getattr(poc, "target", "lab30")),
            job_seconds=_int(raw.get("job_seconds", getattr(poc, "job_seconds", 30)), 30, 1, 120),
            max_steps=_int(raw.get("max_steps", getattr(poc, "max_steps", 8)), 8, 1, 32),
            max_jobs=_int(raw.get("max_jobs", getattr(poc, "max_jobs", 8)), 8, 1, 32),
            max_seconds=_int(raw.get("max_seconds", getattr(poc, "max_seconds", 300)), 300, 10, 3600),
            browser=bool(raw.get("browser", getattr(poc, "browser", True))),
            max_script_bytes=_int(
                raw.get("max_script_bytes", getattr(poc, "max_script_bytes", 32768)),
                32768, 1024, 131072,
            ),
            # The run may pin its own output budget; the server-side default is the one
            # ``AUDIT_POC_MAX_TOKENS`` configures, so both paths agree.
            max_tokens=_int(
                raw.get("max_tokens", getattr(poc, "max_tokens", AgentPolicy().poc_max_tokens)),
                AgentPolicy().poc_max_tokens, 512, 16384,
            ),
            # The switch may be frozen by the run, but the command is host configuration:
            # nothing that arrives over HTTP can point the reset at another program.
            reset_between_findings=bool(
                raw.get("reset_between_findings", getattr(poc, "reset_between_findings", False))
            ),
            reset_command=str(getattr(poc, "reset_command", "") or ""),
            reset_timeout=_int(
                raw.get("reset_timeout", getattr(poc, "reset_timeout", 30)), 30, 5, 300
            ),
            # A run may ask for the legacy loop, but it cannot promote itself to the SDK
            # adapter when the server has not enabled it.
            runtime=("legacy" if requested_runtime == "legacy" else server_runtime),
            # Missing on historical runs: retain their legacy max_steps contract.
            sdk_requests=dict(raw["sdk_requests"]) if isinstance(raw.get("sdk_requests"), dict) else None,
            # Missing on historical runs: provider defaults, exactly as before.  The
            # current server default must never be injected into an existing run.
            sdk_generation=dict(raw["sdk_generation"]) if isinstance(raw.get("sdk_generation"), dict) else None,
            session_policy=str(raw.get("session_policy") or ""),
            item_warning_seconds=_int(raw.get("item_warning_seconds", raw.get("max_seconds", 300)), 300, 10, 3600),
            progress_policy=str(raw.get("progress_policy") or ""),
            progress_params=dict(raw["progress_params"]) if isinstance(raw.get("progress_params"), dict) else None,
        )

    def snapshot(self) -> dict:
        return {
            "mode": self.mode,
            "legacy": self.legacy,
            "enabled": self.enabled,
            "required": self.required,
            "target": self.target,
            "job_seconds": self.job_seconds,
            "max_steps": self.max_steps,
            "max_jobs": self.max_jobs,
            "max_seconds": self.max_seconds,
            "browser": self.browser,
            "max_script_bytes": self.max_script_bytes,
            "max_tokens": self.max_tokens,
            **({"max_responses": self.max_responses} if self.max_responses is not None else {}),
            "reset_between_findings": self.reset_between_findings,
            "reset_timeout": self.reset_timeout,
            "runtime": self.runtime,
            **({"sdk_requests": dict(self.sdk_requests)} if self.sdk_requests is not None else {}),
            **({"sdk_generation": dict(self.sdk_generation)} if self.sdk_generation is not None else {}),
            **({"session_policy": self.session_policy, "item_warning_seconds": self.item_warning_seconds}
               if self.session_policy else {}),
            **({"progress_policy": self.progress_policy,
                "progress_params": dict(self.progress_params or {})}
               if self.progress_policy else {}),
        }

    @property
    def queued(self) -> bool:
        return self.runtime == "claude_sdk" and self.session_policy == "session-queue-v1"

    @property
    def source_context(self) -> bool:
        """Only the frozen policy name enables the preloaded source window."""
        return self.progress_policy == PROGRESS_POLICY


def _finding_key(finding: dict) -> str:
    return str(finding.get("project_finding_id") or finding.get("id") or "")


def _revision(finding: dict) -> int:
    return _int(finding.get("project_revision") or finding.get("revision") or 1, 1, 1, 10**6)


# Ordinary-member accounts, tried in order.  Privileged identities are never chosen
# automatically: a POC for an operator-only endpoint would otherwise pass by accident
# and claim a member-level authorization bug.
MEMBER_IDENTITIES = ("alice", "bob")
AUTHENTICATION_REASONS = frozenset({"identity_or_role_mismatch", "identity_preparation_failed"})


class PocVerifier:
    def __init__(
        self,
        *,
        store: Store,
        bus: EventBus,
        settings: Settings,
        client_factory=None,
        readiness=None,
        repository=None,
    ) -> None:
        self.store = store
        self.bus = bus
        self.settings = settings
        self.client_factory = client_factory
        # Read-only access to published source snapshots.  Optional so embedding
        # callers that never verify keep working; without it the bounded-evidence
        # policy reports ``source_unavailable`` instead of guessing a path.
        self.repository = repository
        self.readiness = readiness or PocReadinessService(settings, client_factory=client_factory)
        self._notices: set[tuple[str, str]] = set()
        # The most recent verification context per target.  A reset is only safe once
        # that context reports closed; the runner keeps the target lease until then.
        self._last_context: dict[str, str] = {}

    def _allowed(self, run_id: str, epoch=None) -> bool:
        check = getattr(self.store, "execution_write_allowed", None)
        return check(run_id, epoch) if check else True

    def _notice(self, run: dict, reason: str, payload: dict) -> None:
        run_id = str(run["id"])
        epoch = run.get("execution_epoch")
        claim = getattr(self.store, "claim_poc_notice", None)
        key = (run_id, reason)
        first = claim(run_id, reason, epoch) if claim else key not in self._notices
        if first and self._allowed(run_id, epoch):
            self._notices.add(key)
            self.bus.emit(run_id, None, "poc_verification_unavailable" if reason == "runner_unhealthy" else "poc_verification_skipped", payload)

    # --- client -----------------------------------------------------------------

    def _make_client(self, policy: PocPolicy) -> PocRunnerClient:
        if self.client_factory is not None:
            return self.client_factory()
        poc = getattr(self.settings, "poc", None)
        url = getattr(poc, "runner_url", "") if poc is not None else ""
        token = getattr(poc, "runner_token", "") if poc is not None else ""
        if not url:
            raise PocRunnerUnavailable("POC runner URL is not configured")
        return PocRunnerClient(url, token)

    async def _close(self, client: PocRunnerClient) -> None:
        close = getattr(client, "aclose", None)
        if close is None:
            return
        try:
            await close()
        except Exception:
            return

    # --- target reset and identity ------------------------------------------------

    async def _wait_context_closed(self, client: PocRunnerClient, context_id: str, *, timeout: float = 15.0) -> bool:
        """Wait until the previous context has no active or pending job.

        Resetting the database while a runner job is still executing would corrupt the
        observation the job is about to report, so a context that will not close blocks
        the reset instead of being ignored.
        """
        deadline = time.monotonic() + timeout
        while True:
            try:
                status = await asyncio.wait_for(client.context_status(context_id), timeout=5)
            except (PocRunnerError, PocRunnerUnavailable, asyncio.TimeoutError):
                return False
            closed = (str(status.get("state") or "") == "closed"
                      and not status.get("active") and not status.get("pending_jobs"))
            if closed:
                return True
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(0.25)

    def _reset_event(self, run: dict, finding: dict, policy: PocPolicy, kind: str, payload: dict) -> None:
        run_id = str(run.get("id") or "")
        if not self._allowed(run_id, run.get("execution_epoch")):
            return
        self.bus.emit(run_id, str(finding.get("id") or ""), kind, {
            "target": policy.target,
            "finding_id": str(finding.get("id") or ""),
            **payload,
        })

    async def _reset_target(self, run: dict, finding: dict, policy: PocPolicy) -> tuple[bool, dict]:
        """Run the server-configured reset command; never a shell, never a user string."""
        started = time.monotonic()
        try:
            argv = shlex.split(policy.reset_command)
        except ValueError as exc:
            argv, problem = [], f"复位命令无法解析：{type(exc).__name__}"
        else:
            problem = "" if argv else "服务端未配置复位命令（POC_LAB30_RESET_COMMAND）"
        if problem:
            self._reset_event(run, finding, policy, "poc_target_reset_failed",
                              {"reason": "target_reset_failed", "message": problem})
            return False, {"reason": "target_reset_failed", "message": problem}

        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            message = f"复位命令无法启动：{type(exc).__name__}"
            self._reset_event(run, finding, policy, "poc_target_reset_failed",
                              {"reason": "target_reset_failed", "message": message})
            return False, {"reason": "target_reset_failed", "message": message}

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=policy.reset_timeout)
        except asyncio.TimeoutError:
            process.kill()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except (asyncio.TimeoutError, ProcessLookupError):
                pass
            message = f"复位命令在 {policy.reset_timeout}s 内未完成，已终止"
            self._reset_event(run, finding, policy, "poc_target_reset_failed", {
                "reason": "target_reset_failed", "message": message,
                "duration_ms": round((time.monotonic() - started) * 1000),
            })
            return False, {"reason": "target_reset_failed", "message": message}

        # The reset script prints one JSON line with the seed accounts and a drift list;
        # a custom command may print nothing, in which case only the exit code counts.
        seed: dict = {}
        for line in reversed(stdout.decode("utf-8", "replace").strip().splitlines()):
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                seed = parsed
                break
        duration_ms = round((time.monotonic() - started) * 1000)
        drift = seed.get("drift") if isinstance(seed.get("drift"), list) else []
        accounts = seed.get("accounts") if isinstance(seed.get("accounts"), list) else []
        if process.returncode != 0 or seed.get("ok") is False:
            detail = " ".join(stderr.decode("utf-8", "replace").split())[:400]
            message = f"复位命令返回 {process.returncode}" + (f"：{detail}" if detail else "")
            self._reset_event(run, finding, policy, "poc_target_reset_failed", {
                "reason": str(seed.get("error") or "target_reset_failed"),
                "message": message,
                "returncode": process.returncode,
                "drift": drift[:8],
                "duration_ms": duration_ms,
            })
            return False, {"reason": "target_reset_failed", "message": message,
                           "returncode": process.returncode, "drift": drift[:8]}
        self._reset_event(run, finding, policy, "poc_target_reset", {
            "returncode": process.returncode,
            "duration_ms": duration_ms,
            "accounts": accounts[:8],
        })
        return True, {"returncode": process.returncode, "duration_ms": duration_ms,
                      "accounts": accounts[:8]}

    def _reset_failure(
        self, run: dict, finding: dict, policy: PocPolicy, reason: str, message: str,
        *, attempt_key: str | None, target_key: str,
    ) -> tuple[PocVerificationResult, str, dict, dict, list]:
        result = PocVerificationResult(
            status="inconclusive", verdict="uncertain", summary=message, evidence_notes=message,
        )
        record = self._record(
            run, finding, policy, result,
            prepared={"context_id": "", "reset": {"reason": reason, "message": message}},
            jobs=[], artifacts={}, usage={}, reason=reason,
            attempt_key=attempt_key, target_key=target_key,
        )
        return result, reason, record, {}, []

    async def _reset_before_finding(
        self, run: dict, finding: dict, policy: PocPolicy, client: PocRunnerClient,
        *, attempt_key: str | None, target_key: str,
    ) -> tuple[PocVerificationResult, str, dict, dict, list] | None:
        """Reset the target between findings; ``None`` means the context may be created."""
        previous = self._last_context.get(policy.target)
        if previous and not await self._wait_context_closed(client, previous):
            message = "上一条验证上下文仍未关闭，未复位靶场。"
            self._reset_event(run, finding, policy, "poc_target_reset_failed", {
                "reason": "target_reset_blocked", "message": message,
                "context_id": previous,
            })
            return self._reset_failure(run, finding, policy, "target_reset_blocked", message,
                                       attempt_key=attempt_key, target_key=target_key)
        ok, detail = await self._reset_target(run, finding, policy)
        if not ok:
            return self._reset_failure(run, finding, policy, "target_reset_failed",
                                       str(detail.get("message") or "靶场复位失败"),
                                       attempt_key=attempt_key, target_key=target_key)
        return None

    async def _prepare_identity(
        self, client: PocRunnerClient, policy: PocPolicy, context_id: str, deadline: float,
    ) -> dict:
        """Prepare the first ordinary-member identity that matches its configured role.

        alice is the documented default, but a previously exploited target (or a manual
        experiment) can leave alice with another role while bob is still a customer.
        Trying both keeps the isolation honest: privileged accounts are never chosen
        automatically, and both failing is reported as an authentication problem.
        """
        attempts: list[dict] = []
        chosen: dict | None = None
        fallback: dict | None = None
        for identity in MEMBER_IDENTITIES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("等待独占验证环境的预算已用尽")
            prepared = await asyncio.wait_for(client.prepare_target(
                policy.target, reset=False, context_id=context_id, identity=identity,
            ), timeout=max(.01, min(10, remaining)))
            check = prepared.get("precondition") if isinstance(prepared.get("precondition"), dict) else {}
            attempts.append({
                "identity": identity,
                "ok": bool(prepared.get("ok")),
                "reason": str(check.get("reason") or ""),
                "status": check.get("status"),
                "actual": check.get("actual") or {},
            })
            if prepared.get("ok"):
                chosen = prepared
                break
            fallback = prepared
        selected = dict(chosen or fallback or {})
        selected["identity_attempts"] = attempts
        if chosen is None:
            selected["authentication_failed"] = True
        return selected

    # --- public entry -----------------------------------------------------------

    async def verify_standing(
        self,
        run_id: str,
        findings: list[dict],
        verified_for: dict[str, int],
        *,
        model_config: ModelConfig,
        should_stop=None,
        max_findings: int | None = None,
    ) -> dict:
        """Verify each standing conclusion this run has not verified yet.

        ``verified_for`` is a fast local index. Durable poc_attempts remains the
        authority across pause/resume and process interruption.
        """
        run = self.store.get_run(run_id) or {}
        policy = PocPolicy.from_run(run, self.settings)
        current: dict[str, tuple[dict, str, int]] = {}
        for finding in findings:
            if finding.get("run_id") not in {None, run_id}:
                continue
            if finding.get("disposition", "open") in {"duplicate", "retracted", "superseded"}:
                continue
            if finding.get("validation_state", "candidate") != "candidate":
                continue
            key = _finding_key(finding)
            revision = _revision(finding)
            if not key:
                continue
            previous = current.get(key)
            if previous is None or (revision, int(finding.get("revision") or 1), str(finding.get("id") or "")) > (
                previous[2], int(previous[0].get("revision") or 1), str(previous[0].get("id") or ""),
            ):
                current[key] = (finding, key, revision)
        eligible = [entry for key, entry in current.items() if int(verified_for.get(key, 0)) < entry[2]]
        if max_findings is not None and (type(max_findings) is not int or max_findings < 1):
            raise ValueError("max_findings must be a positive integer or None")
        # The cap counts newly executed experiments, not already durable claims
        # encountered while rebuilding the local index after pause/restart.
        selected = eligible
        summary = {
            "attempted": 0, "verified": 0, "rejected": 0,
            "inconclusive": 0, "environment_unavailable": 0, "not_applicable": 0,
            "authentication_failed": 0, "state_mismatch": 0,
            "processed": 0, "remaining": len(eligible) - len(selected), "processed_findings": [],
            "deferred": 0, "stop_reason": "",
        }
        def finished_summary():
            summary["remaining"] = sum(int(verified_for.get(key, 0)) < revision for _, key, revision in eligible)
            return summary

        if not selected:
            return finished_summary()

        epoch = run.get("execution_epoch")
        if not self._allowed(run_id, epoch) or (should_stop is not None and should_stop()):
            return finished_summary()
        if policy.runtime == "claude_sdk":
            sdk_readiness = self._sdk_readiness(policy)
            if not sdk_readiness.get("ready"):
                self.bus.emit(run_id, None, "poc_runtime_unavailable", sdk_readiness)
                # SDK configuration is checked before acquiring a target lease or
                # preparing an identity. Unavailable runtimes cause no experiments.
                summary["environment_unavailable"] = len(selected)
                for _, key, revision in selected:
                    verified_for[key] = revision
                if policy.required:
                    raise StopAudit("environment_unavailable", sdk_readiness.get("message", "SDK runtime unavailable"))
                return finished_summary()
        profile = str(run.get("target_profile") or "unknown")
        readiness = await self.readiness.check(profile, mode=policy.mode, target=policy.target)
        if not policy.enabled and policy.mode != "off":
            readiness = {**readiness, "available": False, "reason": "disabled",
                         "message": "该运行冻结策略未开放自动执行 POC。"}
        save_state = getattr(self.store, "set_poc_state", None)
        if save_state:
            save_state(run_id, {**readiness, "legacy": policy.legacy}, epoch)
        if not readiness["available"]:
            reason = readiness["reason"]
            self._notice(run, reason, {**readiness, "count": len(selected)})
            for _, key, revision in selected:
                verified_for[key] = revision
            if reason == "unsupported_target":
                summary["not_applicable"] = len(selected)
            elif policy.mode != "off":
                summary["environment_unavailable"] = len(selected)
            if policy.required:
                raise StopAudit("environment_unavailable", readiness["message"])
            return finished_summary()

        target_key = poc_target_key(run, policy, self.settings)
        claim_method = getattr(self.store, "claim_poc_attempt", None)
        from .execution_state import CURRENT_EXECUTION
        owner = CURRENT_EXECUTION.get()
        client = None
        try:
            client = self._make_client(policy)
            if not readiness.get("capabilities", {}).get("browser", True):
                policy = replace(policy, browser=False)
            prepared = {}  # Every finding acquires and prepares its own verification context.
        except (PocRunnerUnavailable, PocRunnerError):
            if save_state:
                save_state(run_id, {**readiness, "available": False, "reason": "runner_unhealthy",
                                   "message": "隔离靶场准备失败。", "legacy": policy.legacy}, epoch)
            self._notice(run, "runner_unhealthy", {
                "reason": "runner_unhealthy", "message": "隔离靶场准备失败，本次保留静态审计结果。",
                "count": len(selected),
            })
            for _, key, revision in selected:
                verified_for[key] = revision
            summary["environment_unavailable"] = len(selected)
            if client is not None:
                await self._close(client)
            if policy.required:
                raise StopAudit("environment_unavailable", "隔离靶场准备失败，无法满足必须动态验证的要求。")
            return finished_summary()

        if not self._allowed(run_id, epoch) or (should_stop is not None and should_stop()):
            await self._close(client)
            return finished_summary()
        self.bus.emit(run_id, None, "poc_agent_phase", {
            "phase": "poc_prepare", "target": policy.target,
            "count": len(selected), "policy": policy.snapshot(),
        })
        queue_runtime = None
        try:
            if policy.queued:
                queue_runtime = self._make_queue_runtime(run, selected, policy)
            for finding, key, revision in selected:
                if max_findings is not None and summary["processed"] >= max_findings:
                    break
                if not self._allowed(run_id, epoch) or (should_stop is not None and should_stop()):
                    break
                # Do not claim a side-effectful experiment that cannot afford even
                # one execution response and the three bounded conclusion responses.
                # Re-read after every finding: the previous one may have spent the
                # final allowance in this batch. Legacy runs have no workflow policy.
                state_method = getattr(self.store, "workflow_state", None)
                if (run.get("task_spec") or {}).get("orchestration_policy") == "host-queue-v1":
                    reserve = self.store.refresh_review_reserve(run_id)
                    if not reserve.get("review_reserve", {}).get("upstream_allowed", True):
                        summary["deferred"] += 1
                        summary["stop_reason"] = "final_review_reserved"
                        self.bus.emit(run_id, finding.get("id"), "poc_verification_deferred", {
                            "reason": "final_review_reserved", "message": "已为当前事实保留统一终审额度，本条未认领或重置靶场。"})
                        break
                workflow = state_method(run_id) if state_method else {}
                allowance = None
                if workflow:
                    allowance = int((workflow.get("remaining") or {}).get("poc", 0))
                    if (workflow.get("stage") != "poc" or allowance < (2 if policy.queued else 4)
                            or workflow.get("stage_remaining_seconds", 1) <= 0):
                        self.bus.emit(run_id, finding.get("id"), "poc_verification_deferred", {
                            "reason": "stage_budget_reserved", "responses_remaining": allowance,
                            "required_responses": 2 if policy.queued else 4,
                            "message": "剩余额度不足以执行并发布结论，保留未验证状态及最终复核额度。",
                        })
                        break
                if owner is not None:
                    owner.admit("work")
                if policy.runtime == "claude_sdk" and not policy.queued and not self._sdk_quota_available(run, finding, policy, allowance):
                    summary["deferred"] += 1
                    summary["stop_reason"] = "sdk_quota_deferred"
                    self.bus.emit(run_id, finding.get("id"), "poc_verification_deferred", {
                        "reason": "sdk_quota_insufficient", "message": "SDK 额度不足，未认领、未重置靶场，留待用户另行验证。"})
                    break
                claim = claim_method(run_id, finding, target_key, epoch) if claim_method else {"claimed": True}
                if not claim.get("claimed"):
                    if queue_runtime is not None:
                        queue_runtime.mark_task(finding['id'], claim.get('state') or 'unavailable')
                    verified_for[key] = revision
                    if claim.get("state") in {"interrupted", "unavailable"}:
                        summary["inconclusive"] += 1
                        if claim.get("runner_job_id"):
                            # Query only the original job; never replay its effects
                            # or invent a verdict from an interrupted attempt.
                            try:
                                prior_job = await asyncio.wait_for(client.get_job(claim["runner_job_id"]), timeout=5)
                                state = "recovered" if isinstance(prior_job, dict) else "unknown"
                            except (PocRunnerError, PocRunnerUnavailable, asyncio.TimeoutError):
                                state = "unknown"
                            self.bus.emit(run_id, claim.get("finding_id"), "poc_job_recovered", {
                                "job_id": claim["runner_job_id"], "state": state,
                                "message": "已查询原作业；验证结论未完整提交，保留未完成状态，不自动重新执行。",
                            })
                    continue
                attempt_key = claim.get("key")
                start_attempt = getattr(self.store, "start_poc_attempt", None)
                if start_attempt and not start_attempt(attempt_key, epoch):
                    continue
                summary["attempted"] += 1
                summary["processed"] += 1
                finding_policy = policy if allowance is None else replace(
                    policy, max_responses=_attempt_responses(policy, allowance),
                    max_seconds=min(policy.max_seconds, max(1, int(workflow.get("stage_remaining_seconds", policy.max_seconds)))),
                    job_seconds=min(policy.job_seconds, max(1, int(workflow.get("stage_remaining_seconds", policy.max_seconds)))),
                )
                if policy.queued:
                    # Each item can use the remaining POC/run window. max_seconds
                    # from its original policy is only an elapsed-time reminder.
                    remaining = (self.store.execution_summary(run_id).get("run_remaining") or {}).get("seconds", 0)
                    if workflow:
                        remaining = min(remaining, workflow.get("stage_remaining_seconds", remaining))
                    if remaining <= 0:
                        finish = getattr(self.store, "finish_poc_attempt_without_result", None)
                        if finish and attempt_key:
                            finish(attempt_key, "interrupted", epoch)
                        summary["stop_reason"] = "stage_budget_exhausted"
                        break
                    finding_policy = replace(policy, max_seconds=max(1, int(remaining)), max_responses=allowance)
                try:
                    result, reason, record, artifacts, jobs = await self.verify_finding(
                        run, finding, finding_policy, prepared, client, model_config=model_config,
                        attempt_key=attempt_key, target_key=target_key,
                        **({"queue_runtime": queue_runtime} if queue_runtime is not None else {}),
                    )
                    if reason == "quota_deferred":
                        summary["processed"] -= 1
                        summary["attempted"] -= 1
                        summary["deferred"] += 1
                        summary["stop_reason"] = "sdk_quota_deferred"
                        finish = getattr(self.store, "finish_poc_attempt_without_result", None)
                        if finish and attempt_key:
                            finish(attempt_key, "unavailable", epoch)
                        break
                except StopAudit as exc:
                    if exc.reason == "stage_budget_exhausted" and attempt_key:
                        finish = getattr(self.store, "finish_poc_attempt_without_result", None)
                        if finish is not None:
                            finish(attempt_key, "interrupted", epoch)
                    raise
                verified_for[key] = revision
                summary["processed_findings"].append({"finding_id": finding["id"], "ledger_id": key,
                    "revision": revision, "status": result.status})
                summary[result.status if result.status in summary else "inconclusive"] += 1
                outcome_status = record.get("execution_status") if isinstance(record, dict) else ""
                if outcome_status in {"authentication_failed", "state_mismatch"}:
                    summary[outcome_status] += 1
                if queue_runtime is not None and queue_runtime._query_failed:
                    summary["stop_reason"] = "sdk_session_stopped"
                    break
                if reason in {"environment_unavailable", "target_reset_failed", "target_reset_blocked"}:
                    reset_reason = reason if reason != "environment_unavailable" else "runner_unhealthy"
                    reset_message = ("靶场复位失败，已停止自动验证。" if reason == "target_reset_failed"
                                     else "上一条验证上下文未关闭，已停止自动验证。" if reason == "target_reset_blocked"
                                     else "POC 执行期间隔离环境不可用。")
                    if save_state:
                        save_state(run_id, {**readiness, "available": False, "reason": reset_reason,
                                           "message": reset_message, "legacy": policy.legacy}, epoch)
                    if reason == "environment_unavailable":
                        self._notice(run, "runner_unhealthy", {"reason": reset_reason, "message": reset_message})
                    if policy.required:
                        raise StopAudit("environment_unavailable", reset_message)
                    break
        finally:
            try:
                if queue_runtime is not None:
                    await queue_runtime.aclose()
            finally:
                await self._close(client)
        return finished_summary()

    async def verify_finding(
        self, run: dict, finding: dict, policy: PocPolicy, prepared: dict,
        client: PocRunnerClient, *, model_config: ModelConfig,
        attempt_key: str | None = None, target_key: str = "",
        queue_runtime=None,
    ) -> tuple[PocVerificationResult, str, dict, dict[str, bytes], list[dict]]:
        if policy.queued and queue_runtime is None:
            runtime = self._make_queue_runtime(run, [(finding, _finding_key(finding), _revision(finding))], policy)
            remaining = max(1, int(runtime.limits.max_seconds))
            try:
                return await self.verify_finding(run, finding, replace(policy, max_seconds=remaining),
                    prepared, client, model_config=model_config, attempt_key=attempt_key,
                    target_key=target_key, queue_runtime=runtime)
            finally:
                await runtime.aclose()
        if policy.runtime == "claude_sdk":
            sdk_readiness = self._sdk_readiness(policy)
            if not sdk_readiness.get("ready"):
                self.bus.emit(str(run.get("id") or ""), finding.get("id"),
                              "poc_runtime_unavailable", sdk_readiness)
                result = PocVerificationResult(status="inconclusive", summary="POC SDK 运行环境尚未就绪，未执行实验。")
                record = self._record(
                    run, finding, policy, result, prepared={}, jobs=[], artifacts={},
                    usage={"readiness": sdk_readiness}, reason="runtime_unavailable",
                    attempt_key=attempt_key, target_key=target_key,
                )
                return result, "runtime_unavailable", record, {}, []
            if not policy.queued and not self._sdk_quota_available(run, finding, policy, policy.max_responses):
                return PocVerificationResult(status="inconclusive", summary="SDK 额度不足，未执行实验。"), "quota_deferred", {}, {}, []
        context_id = uuid.uuid4().hex
        deadline = time.monotonic() + policy.max_seconds
        run_id = str(run.get("id") or "")
        try:
            # Between findings the target goes back to its seed.  This runs before the
            # new context is created, so the reset can never race a job of this finding.
            if policy.reset_between_findings and policy.target == "lab30":
                outcome = await self._reset_before_finding(
                    run, finding, policy, client,
                    attempt_key=attempt_key, target_key=target_key,
                )
                if outcome is not None:
                    return outcome
            while True:
                if not self._allowed(run_id, run.get("execution_epoch")):
                    raise StopAudit("interrupted", "排队中的验证已停止")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("等待独占验证环境的预算已用尽")
                try:
                    await asyncio.wait_for(client.create_context(
                        target=policy.target, run_id=run_id, finding_id=str(finding.get("id") or ""),
                        context_id=context_id,
                    ), timeout=min(remaining, 10))
                    break
                except PocRunnerBusy:
                    await asyncio.sleep(min(.5, max(.01, remaining)))
            self._last_context[policy.target] = context_id
            prepared = await self._prepare_identity(client, policy, context_id, deadline)
            remaining_policy = replace(policy, max_seconds=max(1, int(deadline - time.monotonic())))
            return await self._verify_with_context(
                run, finding, remaining_policy, prepared, client, model_config=model_config,
                attempt_key=attempt_key, target_key=target_key, context_id=context_id,
                queue_runtime=queue_runtime,
            )
        except (PocRunnerUnavailable, PocRunnerError, TimeoutError) as exc:
            result = PocVerificationResult(
                status="inconclusive", summary="验证环境未能准备完成，未执行新实验。",
                evidence_notes=("目标正在被其他验证占用或实验前提无法核实：" + type(exc).__name__),
            )
            record = self._record(run, finding, policy, result, prepared={"context_id": context_id},
                                  jobs=[], artifacts={}, usage={}, reason="environment_unavailable",
                                  attempt_key=attempt_key, target_key=target_key)
            return result, "environment_unavailable", record, {}, []
        finally:
            # A closing context retains its lease until every accepted runner job ends.
            # Shield cleanup against cancellation; it never authorizes another action.
            try:
                await asyncio.wait_for(asyncio.shield(client.close_context(context_id)), timeout=5)
            except (Exception, asyncio.CancelledError):
                pass

    @staticmethod
    def _source_record(deps) -> dict:
        """What this finding received and read from its frozen snapshot.

        Host facts only: the initial window size, the exact read ranges and the remaining
        call budget.  It never contains source text, so a verification record stays a
        record of what was shown rather than a second copy of the archive.
        """
        source = getattr(deps, "source", None)
        snapshot = getattr(source, "snapshot", None)
        return snapshot() if callable(snapshot) else {}

    def _source_provider(self, run: dict, finding: dict, policy: PocPolicy, prepared: dict) -> PocSourceProvider | None:
        """Bind this finding to its own frozen snapshot, or report the gap.

        A historical policy (no ``progress_policy``) gets no provider at all, which is
        exactly its old prompt.  A new policy with no snapshot still gets a provider so
        the tool can answer ``source_unavailable`` honestly instead of the model
        inventing that it read the code.
        """
        if not policy.source_context or self.repository is None:
            return None
        return PocSourceProvider(
            self.repository,
            str(run.get("snapshot_id") or ""),
            finding=finding,
            target_version=str(prepared.get("version") or ""),
            limits=SourceLimits.from_params(policy.progress_params),
        )

    async def _verify_with_context(
        self,
        run: dict,
        finding: dict,
        policy: PocPolicy,
        prepared: dict,
        client: PocRunnerClient,
        *,
        model_config: ModelConfig,
        attempt_key: str | None = None,
        target_key: str = "",
        context_id: str = "",
        queue_runtime=None,
    ) -> tuple[PocVerificationResult, str, dict, dict[str, bytes], list[dict]]:
        run_id = str(run.get("id") or "")
        finding_id = str(finding.get("id") or "")
        self.bus.emit(run_id, finding_id, "poc_verification_started", {
            "finding_id": finding_id,
            "project_finding_id": finding.get("project_finding_id"),
            "title": str(finding.get("title") or "")[:300],
            "target": policy.target,
            "policy": policy.snapshot(),
        })

        def emit(event: dict) -> None:
            kind = event.get("kind", "poc_agent_event")
            payload = {key: value for key, value in event.items() if key != "kind"}
            payload.update({
                "role": "poc",
                "finding_id": finding_id,
                "project_finding_id": finding.get("project_finding_id"),
            })
            if self._allowed(run_id, run.get("execution_epoch")):
                self.bus.emit(run_id, finding_id, kind, payload)

        source = self._source_provider(run, finding, policy, prepared)
        deps = PocDeps(
            client=client,
            policy=policy.snapshot(),
            target=policy.target,
            finding=finding,
            prepared=prepared,
            job_seconds=policy.job_seconds,
            max_jobs=policy.max_jobs,
            max_script_bytes=policy.max_script_bytes,
            should_stop=lambda: not self._allowed(run_id, run.get("execution_epoch")),
            context_id=context_id,
            source=source,
            default_identity=str(prepared.get("identity") or MEMBER_IDENTITIES[0]),
            on_job=lambda job_id: self.store.note_poc_job(attempt_key, job_id, run.get("execution_epoch"))
                if attempt_key and hasattr(self.store, "note_poc_job") else None,
            on_job_fact=lambda job: self.store.persist_poc_job_fact(attempt_key, job, run.get("execution_epoch"))
                if attempt_key and hasattr(self.store, "persist_poc_job_fact") else None,
        )
        deps._remember_state(prepared)
        deps.quota_scope = self._sdk_scope(run, finding)
        published_record = {}
        if queue_runtime is not None:
            def publish(result, usage):
                nonlocal published_record
                published_record = self._record(run, finding, policy, result,
                    prepared={**prepared, "context_id": context_id,
                              "preconditions": deps.preconditions, "state_changes": deps.state_changes,
                              "source": self._source_record(deps)},
                    jobs=deps.jobs, artifacts=deps.artifacts, usage=usage,
                    reason="completed", attempt_key=attempt_key, target_key=target_key)
                return published_record
            outcome = await queue_runtime.verify(service=deps, emit=emit, run_id=run_id,
                epoch=int(run.get("execution_epoch") or 0), publisher=publish)
            result, reason, usage = outcome.result, outcome.reason, outcome.usage
            if published_record:
                finalize = getattr(self.store, "finalize_poc_verification_usage", None)
                if finalize is not None:
                    finalize(run_id, published_record["id"], usage, run.get("execution_epoch"))
                published_record["agent"]["usage"] = usage
                return result, "completed", published_record, deps.artifacts, deps.jobs
        elif policy.runtime == "claude_sdk":
            result, reason, usage = await self._verify_with_sdk(run, deps, emit, run_id)
        else:
            result, reason = await run_poc_agent(
                finding=finding,
                deps=deps,
                config=model_config,
                on_event=emit,
            )
            usage = deps.execution.snapshot() if deps.execution is not None else {}
        if result is None:
            result = PocVerificationResult(
                status="inconclusive",
                verdict="uncertain",
                summary=f"POC agent 未能给出结论（{reason}）。",
                evidence_notes=deps.runner_error[:2000],
                jobs=[str(job.get("job_id") or "") for job in deps.jobs if job.get("job_id")],
                artifacts=[
                    {"name": name, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
                    for name, payload in deps.artifacts.items()
                ],
            )
        record = self._record(
            run, finding, policy, result,
            prepared={**prepared, "context_id": context_id, "preconditions": deps.preconditions,
                      "state_changes": deps.state_changes, "source": self._source_record(deps)},
            jobs=deps.jobs, artifacts=deps.artifacts,
            usage=usage, reason=reason, attempt_key=attempt_key, target_key=target_key,
        )
        return result, reason, record, deps.artifacts, deps.jobs

    def _make_queue_runtime(self, run, selected, policy=None):
        from .runtimes.claude_poc import ClaudePocLimits, StorePocRequestGateway
        from .runtimes.claude_queue import ClaudeQueuePocRuntime
        state = self.store.execution_summary(run["id"]) or {}
        remaining = (state.get("run_remaining") or {}).get("seconds", 0)
        workflow = self.store.workflow_state(run["id"]) or {}
        if workflow:
            remaining = min(remaining, workflow.get("stage_remaining_seconds", remaining))
        # This row is a shared gateway admission scope. Global/stage counters, not
        # the former 40-request single-finding default, limit all actual requests.
        capacity = int((state.get("run_limits") or run.get("run_limits") or {}).get("responses") or 512)
        limits = replace(ClaudePocLimits.from_environ(), max_seconds=max(1, remaining),
                         execute_requests=capacity)
        # The queue session is one long-lived CLI process, so its generation policy
        # comes from the run's frozen block, never the current server defaults.
        limits = _generation_limits(limits, policy.sdk_generation if policy is not None else None)
        scope = hashlib.sha256(f"{run['id']}:session-queue-v1".encode()).hexdigest()
        return ClaudeQueuePocRuntime(limits=limits, gateway=StorePocRequestGateway(self.store, scope=scope),
            tasks=[dict(finding_id=f["id"], revision=revision, title=str(f.get("title") or "")[:160],
                        state="pending") for f, _, revision in selected])

    def _sdk_readiness(self, policy=None) -> dict:
        from .runtimes.claude_poc import ClaudeCodePocRuntime, ClaudePocLimits, StorePocRequestGateway
        frozen = (policy.sdk_generation if policy is not None
                  else getattr(getattr(self.settings, "poc", None), "sdk_generation", None))
        try:
            limits = _generation_limits(ClaudePocLimits.from_environ(), frozen)
        except ValueError:
            return {"ready": False, "reason": "runtime_misconfigured",
                    "message": "POC SDK 配置格式无效。"}
        return ClaudeCodePocRuntime(
            limits=limits, gateway=StorePocRequestGateway(self.store),
        ).readiness().snapshot()

    @staticmethod
    def _sdk_scope(run, finding):
        if (run.get("task_spec") or {}).get("review_policy") != "batch-v1":
            return ""
        return hashlib.sha256(json.dumps([
            run["id"], finding.get("project_finding_id") or finding["id"],
            finding.get("project_revision") or finding.get("revision") or 1,
        ]).encode()).hexdigest()

    def _sdk_quota_available(self, run, finding, policy, allowance=None):
        from .runtimes.claude_poc import ClaudePocLimits, StorePocRequestGateway
        limits = _pin_sdk_requests(ClaudePocLimits.from_environ(), policy.sdk_requests)
        count = _attempt_responses(policy, allowance)
        state = self.store.execution_summary(run["id"]) or {}
        if (state.get("run_remaining") or {}).get("responses", 4) < 4:
            return False
        if count < 4:
            return False
        conclude = min(limits.conclude_requests, count - 1)
        gateway = StorePocRequestGateway(self.store, scope=self._sdk_scope(run, finding))
        epoch = int(run.get("execution_epoch") or 0)
        for stage, limit in (("conclude", conclude), ("execute", min(limits.execute_requests, count - conclude))):
            if not gateway.open_stage(run_id=run["id"], epoch=epoch, stage=stage, limit=limit).get("ok"):
                return False
        stages = gateway.snapshot(run_id=run["id"], epoch=epoch)
        return all(stages[stage]["remaining"] > 0 and not stages[stage].get("refused") for stage in ("execute", "conclude"))

    async def _verify_with_sdk(
        self,
        run: dict,
        deps: PocDeps,
        emit,
        run_id: str,
    ) -> tuple[PocVerificationResult | None, str, dict]:
        """Run one attempt with the Claude Agent SDK adapter.

        There is deliberately no ``except`` that falls back to ``run_poc_agent``: an
        attempt belongs to one runtime, and a caller that wants the legacy loop starts a
        new attempt.  A missing SDK, gateway or shared evidence id therefore ends this
        attempt as ``unavailable`` instead of silently changing the model loop.
        """
        from .runtimes.claude_poc import (
            ClaudeCodePocRuntime,
            ClaudePocLimits,
            StorePocRequestGateway,
        )

        try:
            limits = _pin_sdk_requests(ClaudePocLimits.from_environ(), deps.policy.get("sdk_requests"))
            limits = _generation_limits(limits, deps.policy.get("sdk_generation"))
        except ValueError as exc:
            # A malformed deployment setting is reported, not "repaired" with defaults.
            self.bus.emit(run_id, deps.finding.get("id"), "poc_runtime_misconfigured", {
                "error": str(exc)[:300],
            })
            return None, "runtime_misconfigured", {}
        seconds = deps.policy.get("max_seconds")
        if type(seconds) is int:
            limits = replace(limits, max_seconds=min(limits.max_seconds, max(1, seconds)))
        allowance = deps.policy.get("max_responses")
        if type(allowance) is not int:
            allowance = (limits.execute_requests + limits.conclude_requests if deps.policy.get("sdk_requests")
                         else max(2, int(deps.policy.get("max_steps") or 8)) + 3)
        if allowance < 4:
            return None, "quota_deferred", {"runtime": limits.snapshot()}
        conclude = min(limits.conclude_requests, allowance - 1)
        limits = replace(limits, conclude_requests=conclude,
                         execute_requests=min(limits.execute_requests, allowance - conclude))
        runtime = ClaudeCodePocRuntime(
            limits=limits, gateway=StorePocRequestGateway(self.store, scope=getattr(deps, "quota_scope", "")),
        )
        outcome = await runtime.verify(
            service=deps, emit=emit, run_id=run_id,
            epoch=int(run.get("execution_epoch") or 0),
        )
        return outcome.result, outcome.reason, outcome.usage

    # --- persistence -------------------------------------------------------------

    def _record(
        self,
        run: dict,
        finding: dict,
        policy: PocPolicy,
        result: PocVerificationResult,
        *,
        prepared: dict,
        jobs: list[dict],
        artifacts: dict[str, bytes],
        usage: dict,
        reason: str,
        attempt_key: str | None = None,
        target_key: str = "",
    ) -> dict:
        run_id = str(run.get("id") or "")
        verification_id = uuid.uuid4().hex
        finding_id = str(finding.get("id") or "")
        project_finding_id = finding.get("project_finding_id")
        if not self._allowed(run_id, run.get("execution_epoch")):
            return {}
        stored_artifacts = self._store_artifacts(verification_id, artifacts)
        if not stored_artifacts:
            stored_artifacts = [
                item.model_dump() for item in result.artifacts
            ]
        from .poc_agent import successful_job
        succeeded = any(successful_job(job) for job in jobs)
        preconditions = [item for item in prepared.get("preconditions") or [] if isinstance(item, dict)]
        attempts = [item for item in prepared.get("identity_attempts") or [] if isinstance(item, dict)]
        used_identity = str(prepared.get("identity") or "")
        # Judge the identity that was actually handed to the agent.  A failed alice
        # preparation followed by a successful bob one is not an authentication failure.
        relevant = [
            item for item in preconditions + attempts
            if item.get("ok") is False and (not used_identity or str(item.get("identity") or "") in {"", used_identity})
        ]
        reasons = {str(item.get("reason") or "") for item in relevant}
        authentication_failed = bool(
            not succeeded and (prepared.get("authentication_failed") or (reasons & AUTHENTICATION_REASONS))
        )
        state_mismatch = bool(not succeeded and not authentication_failed
                              and "required_account_state_mismatch" in reasons)
        # A successful job is an execution fact, not a completed negative experiment.
        # SDK/transport/contract failure must not be presented as 'not triggered'.
        conclusion_failed = reason not in {"completed", "", None} and result.status == "inconclusive"
        execute_reason = str(usage.get('execute_reason') or '')
        execution_failed = result.status == 'inconclusive' and execute_reason.startswith(('sdk_', 'runtime_'))
        execution_status = (
            "success" if result.status in {"verified", "rejected"} else
            "authentication_failed" if authentication_failed else
            "state_mismatch" if state_mismatch else
            "environment_mismatch" if any(item.get("ok") is False for item in preconditions) and not succeeded else
            "execution_error" if execution_failed else
            "conclusion_error" if conclusion_failed and succeeded else
            "other_error" if jobs and not succeeded else
            "not_triggered" if succeeded else "not_run"
        )
        record = {
            "id": verification_id,
            "finding_id": finding_id,
            "created_at": now(),
            "execution_status": execution_status,
            "verdict": result.verdict,
            "original_script": str(finding.get("poc") or "")[:131072],
            "modified_script": (result.adapted_script or "")[:131072],
            "modification_notes": result.modification_notes[:4000],
            "target_version": str(prepared.get("version") or "")[:200],
            "command": result.command[:1000],
            "expected_result": "",
            "normal_observation": result.normal_observation[:4000],
            "attack_observation": result.attack_observation[:8000],
            "browser_execution": bool(result.browser_execution),
            "notes": result.evidence_notes[:4000],
            "files": [],
            "source": "poc_agent",
            "status": result.status,
            "agent": {
                "context_id": prepared.get("context_id") or "",
                "identity": used_identity,
                "identity_attempts": attempts[:4],
                "reset": prepared.get("reset") or {},
                "preconditions": prepared.get("preconditions") or [],
                "state_changes": prepared.get("state_changes") or [],
                "normal_evidence": [ref.model_dump() for ref in result.normal_evidence],
                "attack_evidence": [ref.model_dump() for ref in result.attack_evidence],
                "job_results": jobs,
                "summary": result.summary[:4000],
                "reason": reason,
                "usage": usage,
                "jobs": list(result.jobs)[:16],
                "policy": policy.snapshot(),
                "source": prepared.get("source") or {},
                "target_key": target_key,
                "source_content_key": run.get("project_content_key") or run.get("content_key") or "",
                "run_finding_revision": int(finding.get("revision") or 1),
            },
            "target": {
                "name": policy.target,
                "base_url": str(prepared.get("base_url") or ""),
                "user": str(prepared.get("user") or ""),
                "security": str(prepared.get("security") or ""),
                "version": str(prepared.get("version") or ""),
                "prepared_at": str(prepared.get("prepared_at") or ""),
            },
            "artifacts": stored_artifacts,
            "project_finding_id": project_finding_id,
            "finding_revision": _revision(finding),
        }
        guarded = getattr(self.store, "record_automatic_verification_guarded", None)
        if guarded is not None and attempt_key:
            if not guarded(record, attempt_key=attempt_key, epoch=run.get("execution_epoch"), jobs=jobs):
                return {}
            jobs_to_save = []  # The guarded method commits jobs with the verdict.
        else:
            self.store.record_automatic_verification(record)
            jobs_to_save = jobs
        for job in jobs_to_save:
            job_id = str(job.get("job_id") or "")
            if not job_id:
                continue
            self.store.add_poc_verification_job({
                "id": uuid.uuid4().hex,
                "verification_id": verification_id,
                "finding_id": finding_id,
                "project_finding_id": project_finding_id,
                "run_id": run_id,
                "job_id": job_id,
                "kind": str(job.get("kind") or "script"),
                "request": job.get("request") or {},
                "result": job.get("result") or {},
                "exit_code": job.get("exit_code"),
                "duration_ms": job.get("duration_ms"),
                "created_at": now(),
            })
        if execution_status == "authentication_failed":
            self.bus.emit(run_id, finding_id, "poc_authentication_failed", {
                "finding_id": finding_id,
                "project_finding_id": project_finding_id,
                "identity": used_identity,
                "reasons": sorted(reasons & AUTHENTICATION_REASONS),
                "identities": [str(item.get("identity") or "") for item in attempts][:4],
                "succeeded": succeeded,
                "target": policy.target,
            })
        self.bus.emit(run_id, finding_id, "poc_verification_recorded", {
            "verification_id": verification_id,
            "finding_id": finding_id,
            "project_finding_id": project_finding_id,
            "status": result.status,
            "verdict": result.verdict,
            "execution_status": execution_status,
            "identity": used_identity,
            "summary": result.summary[:300],
            "jobs": [str(job.get("job_id") or "") for job in jobs if job.get("job_id")],
            "artifacts": [item.get("name") for item in stored_artifacts],
        })
        return record

    def _store_artifacts(self, verification_id: str, artifacts: dict[str, bytes]) -> list[dict]:
        stored: list[dict] = []
        total = 0
        for name, payload in artifacts.items():
            if len(payload) > 1024 * 1024 or total + len(payload) > 5 * 1024 * 1024:
                continue
            safe = "".join(ch for ch in name if ch.isalnum() or ch in "._-")[:64]
            if not safe:
                continue
            filename = f"{verification_id}-{safe}"
            try:
                (self.settings.evidence_dir / filename).write_bytes(payload)
            except OSError:
                continue
            stored.append({
                "name": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "path": filename,
            })
            total += len(payload)
        return stored
