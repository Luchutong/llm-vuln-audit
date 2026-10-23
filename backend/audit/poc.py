"""Automatic POC verification orchestration.

``PocVerifier`` is the host half: it decides *when* verification happens, prepares the
target once, runs the POC agent per standing conclusion, persists the verdict and its
runner jobs, and keeps the run's closure rules honest.  The model half lives in
``poc_agent``.
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid
from dataclasses import dataclass, replace

from .config import ModelConfig, Settings
from .db import Store, now
from .events import EventBus
from .poc_agent import PocDeps, run_poc_agent
from .poc_runner import PocRunnerClient, PocRunnerError, PocRunnerUnavailable
from .poc_readiness import PocReadinessService, normalize_poc_mode
from .poc_store import poc_target_key
from .runtime import StopAudit
from .schemas import PocVerificationResult


def _int(raw: object, default: int, low: int, high: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


@dataclass(frozen=True)
class PocPolicy:
    mode: str = "off"
    legacy: bool = False
    enabled: bool = False
    required: bool = False
    target: str = "dvwa"
    job_seconds: int = 30
    max_steps: int = 8
    max_jobs: int = 8
    max_seconds: int = 300
    browser: bool = True
    max_script_bytes: int = 32768

    @classmethod
    def from_run(cls, run: dict, settings: Settings) -> "PocPolicy":
        raw = run.get("poc_policy") if isinstance(run.get("poc_policy"), dict) else {}
        poc = getattr(settings, "poc", None)
        default_enabled = bool(getattr(poc, "enabled", False))
        mode, legacy = normalize_poc_mode(run)
        return cls(
            mode=mode,
            legacy=legacy,
            enabled=bool(raw.get("enabled", default_enabled)),
            required=mode == "required",
            target=str(raw.get("target") or getattr(poc, "target", "dvwa")),
            job_seconds=_int(raw.get("job_seconds", getattr(poc, "job_seconds", 30)), 30, 1, 120),
            max_steps=_int(raw.get("max_steps", getattr(poc, "max_steps", 8)), 8, 1, 32),
            max_jobs=_int(raw.get("max_jobs", getattr(poc, "max_jobs", 8)), 8, 1, 32),
            max_seconds=_int(raw.get("max_seconds", getattr(poc, "max_seconds", 300)), 300, 10, 3600),
            browser=bool(raw.get("browser", getattr(poc, "browser", True))),
            max_script_bytes=_int(
                raw.get("max_script_bytes", getattr(poc, "max_script_bytes", 32768)),
                32768, 1024, 131072,
            ),
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
        }


def _finding_key(finding: dict) -> str:
    return str(finding.get("project_finding_id") or finding.get("id") or "")


def _revision(finding: dict) -> int:
    return _int(finding.get("project_revision") or finding.get("revision") or 1, 1, 1, 10**6)


class PocVerifier:
    def __init__(
        self,
        *,
        store: Store,
        bus: EventBus,
        settings: Settings,
        client_factory=None,
        readiness=None,
    ) -> None:
        self.store = store
        self.bus = bus
        self.settings = settings
        self.client_factory = client_factory
        self.readiness = readiness or PocReadinessService(settings, client_factory=client_factory)
        self._notices: set[tuple[str, str]] = set()

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

    # --- public entry -----------------------------------------------------------

    async def verify_standing(
        self,
        run_id: str,
        findings: list[dict],
        verified_for: dict[str, int],
        *,
        model_config: ModelConfig,
        should_stop=None,
    ) -> dict:
        """Verify each standing conclusion this run has not verified yet.

        ``verified_for`` is a fast local index. Durable poc_attempts remains the
        authority across pause/resume and process interruption.
        """
        run = self.store.get_run(run_id) or {}
        policy = PocPolicy.from_run(run, self.settings)
        selected: list[tuple[dict, str, int]] = []
        for finding in findings:
            key = _finding_key(finding)
            revision = _revision(finding)
            if not key:
                continue
            if int(verified_for.get(key, 0)) >= revision:
                continue
            selected.append((finding, key, revision))
        summary = {
            "attempted": 0, "verified": 0, "rejected": 0,
            "inconclusive": 0, "environment_unavailable": 0, "not_applicable": 0,
        }
        if not selected:
            return summary

        epoch = run.get("execution_epoch")
        if not self._allowed(run_id, epoch) or (should_stop is not None and should_stop()):
            return summary
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
            return summary

        target_key = poc_target_key(run, policy, self.settings)
        claims = []
        recoveries = []
        claim_method = getattr(self.store, "claim_poc_attempt", None)
        for finding, key, revision in selected:
            claim = claim_method(run_id, finding, target_key, epoch) if claim_method else {"claimed": True}
            if claim.get("claimed"):
                claims.append((finding, key, revision, claim.get("key")))
            else:
                verified_for[key] = revision
                if claim.get("state") in {"interrupted", "unavailable"}:
                    summary["inconclusive"] += 1
                    if claim.get("runner_job_id"):
                        recoveries.append(claim)
        # The runner has no idempotent submission protocol. A known prior job can
        # be inspected, never resubmitted or converted into verified by inference.
        if recoveries and self._allowed(run_id, epoch):
            recovery_client = self._make_client(policy)
            try:
                for attempt in recoveries:
                    try:
                        prior_job = await asyncio.wait_for(recovery_client.get_job(attempt["runner_job_id"]), timeout=5)
                        state = "recovered" if isinstance(prior_job, dict) else "unknown"
                    except (PocRunnerError, PocRunnerUnavailable, asyncio.TimeoutError):
                        state = "unknown"
                    self.bus.emit(run_id, attempt.get("finding_id"), "poc_job_recovered", {
                        "job_id": attempt["runner_job_id"], "state": state,
                        "message": "已查询原作业；验证结论未完整提交，保留未完成状态，不自动重新执行。",
                    })
            finally:
                await self._close(recovery_client)
        if not claims or not self._allowed(run_id, epoch):
            return summary
        from .execution_state import CURRENT_EXECUTION
        owner = CURRENT_EXECUTION.get()
        if owner is not None:
            owner.admit("work")
        client = None
        try:
            client = self._make_client(policy)
            if not readiness.get("capabilities", {}).get("browser", True):
                policy = replace(policy, browser=False)
            prepared = await client.prepare_target(policy.target, reset=True)
            if not prepared.get("ok", False):
                raise PocRunnerUnavailable("target is not ready for verification")
        except (PocRunnerUnavailable, PocRunnerError):
            if save_state:
                save_state(run_id, {**readiness, "available": False, "reason": "runner_unhealthy",
                                   "message": "隔离靶场准备失败。", "legacy": policy.legacy}, epoch)
            self._notice(run, "runner_unhealthy", {
                "reason": "runner_unhealthy", "message": "隔离靶场准备失败，本次保留静态审计结果。",
                "count": len(claims),
            })
            abandon = getattr(self.store, "finish_poc_attempt_without_result", None)
            for _, key, revision, attempt_key in claims:
                if abandon:
                    abandon(attempt_key, "unavailable", epoch)
                verified_for[key] = revision
            summary["environment_unavailable"] = len(claims)
            if client is not None:
                await self._close(client)
            if policy.required:
                raise StopAudit("environment_unavailable", "隔离靶场准备失败，无法满足必须动态验证的要求。")
            return summary

        if not self._allowed(run_id, epoch) or (should_stop is not None and should_stop()):
            await self._close(client)
            return summary
        self.bus.emit(run_id, None, "poc_agent_phase", {
            "phase": "poc_prepare", "target": policy.target,
            "count": len(claims), "policy": policy.snapshot(),
        })
        try:
            for finding, key, revision, attempt_key in claims:
                if not self._allowed(run_id, epoch) or (should_stop is not None and should_stop()):
                    break
                start_attempt = getattr(self.store, "start_poc_attempt", None)
                if start_attempt and not start_attempt(attempt_key, epoch):
                    continue
                summary["attempted"] += 1
                result, reason, usage, artifacts, jobs = await self.verify_finding(
                    run, finding, policy, prepared, client, model_config=model_config,
                    attempt_key=attempt_key, target_key=target_key,
                )
                verified_for[key] = revision
                summary[result.status if result.status in summary else "inconclusive"] += 1
                if reason == "environment_unavailable":
                    if save_state:
                        save_state(run_id, {**readiness, "available": False, "reason": "runner_unhealthy",
                                           "message": "POC 执行期间隔离环境不可用。", "legacy": policy.legacy}, epoch)
                    self._notice(run, "runner_unhealthy", {"reason": "runner_unhealthy", "message": "POC 执行期间隔离环境不可用，已停止自动验证。"})
                    if policy.required:
                        raise StopAudit("environment_unavailable", "POC 执行期间隔离环境不可用。")
                    break
        finally:
            await self._close(client)
        return summary

    async def verify_finding(
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
            on_job=lambda job_id: self.store.note_poc_job(attempt_key, job_id, run.get("execution_epoch"))
                if attempt_key and hasattr(self.store, "note_poc_job") else None,
        )
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
            prepared=prepared, jobs=deps.jobs, artifacts=deps.artifacts,
            usage=usage, reason=reason, attempt_key=attempt_key, target_key=target_key,
        )
        return result, reason, record, deps.artifacts, deps.jobs

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
        execution_status = (
            "success" if result.status in {"verified", "rejected"}
            else ("not_triggered" if jobs else ("not_run" if result.status in {"not_applicable", "environment_unavailable"} else "other_error"))
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
                "summary": result.summary[:4000],
                "reason": reason,
                "usage": usage,
                "jobs": list(result.jobs)[:16],
                "policy": policy.snapshot(),
                "target_key": target_key,
                "source_content_key": run.get("project_content_key") or run.get("content_key") or "",
                "run_finding_revision": int(finding.get("revision") or 1),
            },
            "target": {
                "name": policy.target,
                "base_url": str(prepared.get("base_url") or ""),
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
        self.bus.emit(run_id, finding_id, "poc_verification_recorded", {
            "verification_id": verification_id,
            "finding_id": finding_id,
            "project_finding_id": project_finding_id,
            "status": result.status,
            "verdict": result.verdict,
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
