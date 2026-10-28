"""POC agent orchestration and the host's fact-checking of its conclusions."""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import time
from types import SimpleNamespace

import pytest

from audit import poc, poc_agent
from audit.config import PocSettings
from audit.poc import PocPolicy, PocVerifier
from audit.poc_runner import PocRunnerError, PocRunnerUnavailable
from audit.poc_agent import PocDeps, host_check
from audit.runtime import AgentPolicy, Execution
from audit.schemas import PocVerificationResult
from tests.code_model import CONFIG, Always, ModelFactory, call, final_answer

FINDING = {
    "id": "finding-1",
    "project_finding_id": "project-finding-1",
    "project_revision": 1,
    "title": "SQL injection in id parameter",
    "category": "sqli",
    "severity": "high",
    "file_path": "vulnerabilities/sqli/index.php",
    "symbol": "index",
    "summary": "id reaches the query unparameterised",
    "evidence": [{"path": "vulnerabilities/sqli/index.php", "lines": [10, 20], "note": "query built by concatenation"}],
    "dangerous_operation": "\"SELECT first_name, last_name FROM users WHERE user_id = '$id';\"",
    "poc": "id=1' OR '1'='1",
}

SCRIPT = "print('normal')\n"


class FakeClient:
    def __init__(self, *, health_ok: bool = True, job: dict | None = None, browser: bool = True):
        self.health_ok = health_ok
        self.browser = browser
        self.job = job or {
            "job_id": "job-1",
            "status": "finished",
            "exit_code": 0,
            "duration_ms": 12,
            "stdout": "normal id returned one user\nFirst name: admin\nSurname: admin\n",
            "stderr": "",
            "truncated": False,
            "timed_out": False,
            "artifacts": [{"name": "out.txt", "sha256": "a" * 64, "size": 4}],
        }
        self.jobs: list[dict] = []
        self.prepared: list[dict] = []
        self.created: list[str] = []
        self.closed = False

    async def health(self):
        if not self.health_ok:
            raise PocRunnerUnavailable("runner down")
        return {"ok": True, "capabilities": {"php": True, "python": True, "browser": self.browser, "verification_contexts": True, "identity_preconditions": True, "idempotent_jobs": True, "idempotent_http_jobs": True, "idempotent_browser_jobs": True}}

    async def create_context(self, *, target="lab30", run_id, finding_id, context_id=None):
        self.created.append(context_id or "")
        self.context_id = context_id or "test-context"
        return {"ok": True, "context_id": self.context_id}

    async def close_context(self, context_id):
        return {"ok": True, "context_id": context_id, "status": "closed"}

    async def context_status(self, context_id):
        return {"context_id": context_id, "state": getattr(self, "context_state", "closed"),
                "active": 0, "pending_jobs": 0}

    async def prepare_target(self, target="lab30", *, reset=False, security="low", context_id="test-context", identity="alice", expected_role=None, expected_state=None):
        self.prepared.append({"target": target, "reset": reset, "security": security})
        return {"ok": True, "base_url": "http://lab30", "security": security, "version": "2.5", "authenticated": True, "context_id": context_id, "identity": identity, "precondition": {"ok": True}}

    async def target_status(self, target="lab30", *, identity="alice", **kwargs):
        self.last_identity = identity
        return {"ok": True, "authenticated": True, "security": "low"}

    async def run_job(self, *, target, language, script, timeout_seconds=30, artifacts=None, context_id="test-context", identity="alice", job_id=None):
        self.jobs.append({"target": target, "language": language, "script": script})
        return {**self.job, "context_id": context_id, "identity": identity, "precondition": {"ok": True}}

    async def fetch_artifact(self, job_id, name):
        return b"data"

    async def http_observe(self, *, target, method, path, body=None, headers=None, **kwargs):
        return {"ok": True, "status": 200, "path": path, "body": "First name: admin"}

    async def browser_check(self, *, target, path, script=None, wait_ms=1000, **kwargs):
        return {"ok": True, "available": True, "title": "Lab30", "dialogs": ["XSS"], "body_text": "XSS"}

    async def aclose(self):
        self.closed = True


class FakeStore:
    def __init__(self, run: dict | None = None):
        self.run = run or {
            "id": "run-1",
            "project_id": "project-1",
            "project_mode": "project",
            "target_profile": "lab30",
            "poc_policy": {"mode": "auto", "enabled": True},
        }
        self.records: list[dict] = []
        self.jobs: list[dict] = []

    def get_run(self, run_id):
        return self.run if run_id == "run-1" else None

    def record_automatic_verification(self, record):
        self.records.append(record)

    def add_poc_verification_job(self, job):
        self.jobs.append(job)


class FakeBus:
    def __init__(self):
        self.events: list[tuple] = []

    def emit(self, run_id, task_id, kind, payload):
        self.events.append((run_id, kind, payload))

    def kinds(self):
        return [kind for _, kind, _ in self.events]


def settings(tmp_path, **overrides):
    poc = PocSettings(enabled=True, runner_url="http://runner:8080", runner_token="secret", **overrides)
    return SimpleNamespace(poc=poc, evidence_dir=tmp_path)


def deps(client, **overrides) -> PocDeps:
    values = dict(client=client, policy=PocPolicy().snapshot(), target="lab30", finding=FINDING, context_id="test-context")
    values.update(overrides)
    return PocDeps(**values)


def make_verifier(tmp_path, store, bus, client):
    return PocVerifier(
        store=store, bus=bus, settings=settings(tmp_path), client_factory=lambda: client,
    )


def test_policy_from_run_uses_defaults_and_clamps():
    policy = PocPolicy.from_run(
        {"poc_policy": {"enabled": True, "job_seconds": 9999, "max_jobs": 0}},
        SimpleNamespace(poc=PocSettings(enabled=True)),
    )
    assert policy.enabled is True
    assert policy.job_seconds == 120
    assert policy.max_jobs == 1
    assert "runner_token" not in policy.snapshot()


def test_non_lab30_project_is_not_applicable(tmp_path):
    store = FakeStore(run={
        "id": "run-1", "project_id": "p1", "project_mode": "project",
        "target_profile": "unknown", "poc_policy": {"mode": "auto", "enabled": True},
    })
    bus = FakeBus()
    verifier = make_verifier(tmp_path, store, bus, FakeClient())
    summary = asyncio.run(verifier.verify_standing(
        "run-1", [FINDING], {}, model_config=CONFIG,
    ))
    assert summary["not_applicable"] == 1
    assert store.records == []
    assert bus.kinds() == ["poc_verification_skipped"]


def test_runner_unavailable_keeps_one_run_notice_without_finding_records(tmp_path):
    store = FakeStore()
    bus = FakeBus()
    client = FakeClient(health_ok=False)
    verifier = make_verifier(tmp_path, store, bus, client)
    summary = asyncio.run(verifier.verify_standing(
        "run-1", [FINDING], {}, model_config=CONFIG,
    ))
    assert summary["environment_unavailable"] == 1
    assert store.records == []
    assert "poc_verification_unavailable" in bus.kinds()
    assert client.closed is True


def test_repeated_revision_is_not_verified_twice(tmp_path):
    store = FakeStore()
    verifier = make_verifier(tmp_path, store, FakeBus(), FakeClient())
    verified = {"project-finding-1": 1}
    summary = asyncio.run(verifier.verify_standing(
        "run-1", [FINDING], verified, model_config=CONFIG,
    ))
    assert summary["attempted"] == 0
    assert store.records == []


def test_a_runner_without_a_browser_says_so_in_the_agent_policy(tmp_path, monkeypatch):
    store, bus = FakeStore(), FakeBus()
    seen: dict = {}

    async def fake_agent(*, finding, deps, config, on_event=None):
        seen["browser"] = deps.policy.get("browser")
        return PocVerificationResult(status="inconclusive", summary="no browser"), "completed"

    monkeypatch.setattr(poc, "run_poc_agent", fake_agent)
    verifier = make_verifier(tmp_path, store, bus, FakeClient(browser=False))

    asyncio.run(verifier.verify_standing("run-1", [FINDING], {}, model_config=CONFIG))

    assert seen["browser"] is False
    assert store.records[0]["agent"]["policy"]["browser"] is False


def run_agent(monkeypatch, script, client, **overrides):
    factory = ModelFactory(script)
    monkeypatch.setattr(poc_agent, "build_code_model", factory)
    deps_ = deps(client, **overrides)
    result, reason = asyncio.run(poc_agent.run_poc_agent(
        finding=FINDING, deps=deps_, config=CONFIG,
    ))
    return result, reason, deps_, factory


def run_agent_events(monkeypatch, script, client, **overrides):
    """``run_agent`` with the durable event stream kept for assertions."""
    factory = ModelFactory(script)
    monkeypatch.setattr(poc_agent, "build_code_model", factory)
    deps_ = deps(client, **overrides)
    events: list[dict] = []
    result, reason = asyncio.run(poc_agent.run_poc_agent(
        finding=FINDING, deps=deps_, config=CONFIG, on_event=events.append,
    ))
    return result, reason, deps_, factory, events


def conclude_with(payload: dict) -> str:
    return final_answer(payload)


INCONCLUSIVE = {"status": "inconclusive", "verdict": "uncertain", "summary": "作业证据不足，无法判定影响"}


@pytest.mark.parametrize("reply", [
    "攻击请求和正常请求的结果相同，无法确认漏洞。",
    'final_answer({"status": "inconclusive", "summary": "证据不足"})',
    '{"status": "inconclusive", "summary":',
], ids=["prose", "bare-call", "truncated-json"])
def test_an_unparsable_conclusion_is_recorded_and_corrected(monkeypatch, reply):
    """Prose, a bare call and pure JSON all arrive with no ``<code>`` block of their own.

    The loop appends the closing tag to each of them, so the library's parser refuses all
    three.  Each refusal is a bounded correction rather than a silent step, and the
    correction is what makes the next reply a submission.
    """
    client = FakeClient()
    script = {
        "poc_execute": [final_answer("探索结束")],
        "poc_conclude": [reply, conclude_with(INCONCLUSIVE)],
    }
    result, reason, _, factory, events = run_agent_events(monkeypatch, script, client)

    assert result is not None and result.status == "inconclusive", reason
    assert reason == "completed"
    parse_events = [event for event in events if event.get("kind") == "agent_parse_error"]
    assert len(parse_events) == 1
    event = parse_events[0]
    assert event["phase"] == "poc_conclude"
    assert event["step"] == 1
    # The request that produced the unparsable reply: one execute request came before it.
    assert event["request_index"] == 2
    assert event["category"] == "invalid_json"
    assert event["hint"]
    retries = [item for item in events if item.get("kind") == "model_retry"]
    assert len(retries) == 1 and retries[0]["phase"] == "poc_conclude"
    assert retries[0]["corrections"] == 1
    assert factory.phases.count("poc_conclude") == 2
    # It was a format problem, not a failed execution: no code action is claimed for it.
    conclude_codes = [
        item for item in events
        if item.get("kind") == "agent_code" and item.get("phase") == "poc_conclude"
    ]
    assert conclude_codes == []


def test_three_format_failures_end_as_invalid_output_without_an_extra_request(monkeypatch):
    client = FakeClient()
    script = {
        "poc_execute": [final_answer("探索结束")],
        "poc_conclude": ["散文一。", "散文二。", "散文三。"],
    }
    result, reason, _, factory, events = run_agent_events(monkeypatch, script, client)

    assert result is None
    assert reason == "invalid_output"
    assert factory.built().asked["poc_conclude"] == 3
    assert len([item for item in events if item.get("kind") == "agent_parse_error"]) == 3
    retries = [item for item in events if item.get("kind") == "model_retry"]
    assert len(retries) == 2
    failed = [item for item in events if item.get("kind") == "poc_conclusion_failed"]
    assert failed and failed[-1]["reason"] == "invalid_output"


def test_an_invalid_submission_is_a_contract_correction_not_a_parse_error(monkeypatch):
    client = FakeClient()
    script = {
        "poc_execute": [final_answer("探索结束")],
        "poc_conclude": [
            final_answer({"status": "definitely", "summary": "x"}),
            conclude_with(INCONCLUSIVE),
        ],
    }
    result, reason, _, _, events = run_agent_events(monkeypatch, script, client)

    assert result is not None and result.status == "inconclusive"
    assert reason == "completed"
    assert not [item for item in events if item.get("kind") == "agent_parse_error"]
    retries = [item for item in events if item.get("kind") == "model_retry"]
    assert len(retries) == 1 and "status" in (retries[0]["reason"] or "")


def test_python_conclusion_is_rejected_then_corrected_as_json(monkeypatch):
    client = FakeClient()
    payload = json.dumps(INCONCLUSIVE, ensure_ascii=False)
    script = {
        "poc_execute": [final_answer("探索结束")],
        "poc_conclude": [f"<code>\nfinal_answer({payload})", payload],
    }
    result, reason, _, _, events = run_agent_events(monkeypatch, script, client)

    assert result is not None and result.status == "inconclusive", reason
    assert reason == "completed"
    assert len([item for item in events if item.get("kind") == "agent_parse_error"]) == 1


def test_a_bad_reply_s_prose_never_reaches_the_durable_events(monkeypatch):
    marker = "PRIVATE_MODEL_PROSE_MARKER"
    client = FakeClient()
    script = {
        "poc_execute": [final_answer("探索结束")],
        "poc_conclude": [f"完整报告：{marker}", conclude_with(INCONCLUSIVE)],
    }
    _, _, _, _, events = run_agent_events(monkeypatch, script, client)

    persisted = json.dumps(events, ensure_ascii=False)
    assert marker not in persisted
    parse_events = [item for item in events if item.get("kind") == "agent_parse_error"]
    assert parse_events and all(marker not in (item.get("hint") or "") for item in parse_events)


def test_successful_job_supports_verified(monkeypatch):
    client = FakeClient()
    script = {
        "poc_execute": [
            call("run_poc", language="python", script=SCRIPT),
            final_answer("探索结束"),
        ],
        "poc_conclude": [
            final_answer({
                "status": "verified",
                "verdict": "confirmed",
                "summary": "union result returned admin rows",
                "normal_observation": "normal id returned one user",
                "attack_observation": "First name: admin",
                "jobs": ["job-1"],
                "normal_evidence": [{"job_id": "job-1", "channel": "stdout", "excerpt": "normal id returned one user"}],
                "attack_evidence": [{"job_id": "job-1", "channel": "stdout", "excerpt": "First name: admin"}],
                "adapted_script": SCRIPT,
            }),
        ],
    }
    result, reason, deps_, factory = run_agent(monkeypatch, script, client)
    assert result is not None and result.status == "verified", reason
    assert result.adapted_script == SCRIPT
    assert deps_.jobs and deps_.jobs[0]["job_id"] == "job-1"
    assert len(client.jobs) == 1


def test_exhausting_the_exploration_budget_still_leaves_a_conclusion(monkeypatch):
    """An agent that keeps probing must not spend the response reserved for its verdict."""
    client = FakeClient()
    script = {
        "poc_execute": Always([call("run_poc", language="python", script=SCRIPT)]),
        "poc_conclude": [
            final_answer({
                "status": "verified",
                "verdict": "confirmed",
                "summary": "union result returned admin rows",
                "normal_observation": "normal id returned one user",
                "attack_observation": "First name: admin",
                "jobs": ["job-1"],
                "normal_evidence": [{"job_id": "job-1", "channel": "stdout", "excerpt": "normal id returned one user"}],
                "attack_evidence": [{"job_id": "job-1", "channel": "stdout", "excerpt": "First name: admin"}],
            }),
        ],
    }
    result, reason, _, factory, events = run_agent_events(monkeypatch, script, client)
    assert result is not None, reason
    assert result.status == "verified"
    assert factory.phases.count("poc_conclude") == 1
    # A published conclusion is the outcome; the exploration phase's own stop label stays
    # in its event rather than becoming the whole agent's reason.
    assert reason == "completed"
    finished = [event for event in events if event.get("kind") == "poc_execution_finished"]
    assert len(finished) == 1 and finished[0]["reason"] == "job_limit"
    assert not [event for event in events if event.get("kind") == "poc_conclusion_failed"]


def test_verified_without_job_is_downgraded(monkeypatch):
    client = FakeClient()
    script = {
        "poc_execute": [final_answer("探索结束")],
        "poc_conclude": [
            final_answer({
                "status": "verified",
                "verdict": "confirmed",
                "summary": "looked exploitable",
                "attack_observation": "First name: admin",
            }),
        ],
    }
    result, _, _, _ = run_agent(monkeypatch, script, client)
    assert result is not None
    assert result.status == "inconclusive"
    assert "缺少成功作业支撑" in result.evidence_notes


def test_observation_without_runner_token_is_downgraded(monkeypatch):
    client = FakeClient()
    script = {
        "poc_execute": [
            call("run_poc", language="python", script=SCRIPT),
            final_answer("探索结束"),
        ],
        "poc_conclude": [
            final_answer({
                "status": "verified",
                "verdict": "confirmed",
                "summary": "claimed",
                "attack_observation": "totally unrelated payload executed",
                "jobs": ["job-1"],
            }),
        ],
    }
    result, _, _, _ = run_agent(monkeypatch, script, client)
    assert result is not None and result.status == "inconclusive"
    assert "原文证据引用" in result.evidence_notes


def test_a_single_shared_token_does_not_support_verified(monkeypatch):
    """Coincidental words cannot replace the host's exact paired evidence check."""
    client = FakeClient(job={
        "job_id": "job-1", "status": "finished", "exit_code": 0, "duration_ms": 12,
        "stdout": "normal request denied\ncommand executed\n", "stderr": "",
        "truncated": False, "timed_out": False, "artifacts": [],
    })
    script = {
        "poc_execute": [
            call("run_poc", language="python", script=SCRIPT),
            final_answer("探索结束"),
        ],
        "poc_conclude": [
            final_answer({
                "status": "verified",
                "verdict": "confirmed",
                "summary": "claimed",
                "normal_observation": "normal request denied",
                "attack_observation": "sqlmap executed",
                "jobs": ["job-1"],
                "normal_evidence": [{"job_id": "job-1", "channel": "stdout", "excerpt": "normal request denied"}],
                "attack_evidence": [{"job_id": "job-1", "channel": "stdout", "excerpt": "sqlmap executed"}],
            }),
        ],
    }
    result, _, _, _ = run_agent(monkeypatch, script, client)
    assert result is not None and result.status == "inconclusive"
    assert "攻击侧原文片段不在作业" in result.evidence_notes
    assert result.adapted_script == ""


def test_xss_requires_browser_execution(monkeypatch):
    finding = dict(FINDING, category="xss", title="reflected XSS", file_path="vulnerabilities/xss_r/index.php")
    client = FakeClient()
    script = {
        "poc_execute": [
            call("run_poc", language="python", script=SCRIPT),
            final_answer("探索结束"),
        ],
        "poc_conclude": [
            final_answer({
                "status": "verified",
                "verdict": "confirmed",
                "summary": "script reflected",
                "attack_observation": "First name: admin",
                "jobs": ["job-1"],
            }),
        ],
    }
    factory = ModelFactory(script)
    monkeypatch.setattr(poc_agent, "build_code_model", factory)
    deps_ = deps(client, finding=finding)
    result, _ = asyncio.run(poc_agent.run_poc_agent(finding=finding, deps=deps_, config=CONFIG))
    assert result is not None and result.status == "inconclusive"
    assert "浏览器" in result.evidence_notes


def test_is_xss_matches_full_category_name():
    # 审计侧可能给出完整分类名 "Cross-Site Scripting"（不含子串 "xss"），
    # _is_xss 必须识别，否则 XSS 结论不会被强制要求浏览器弹窗证据。
    assert poc_agent._is_xss(dict(FINDING, category="Cross-Site Scripting", title="reflected"))
    assert poc_agent._is_xss(dict(FINDING, category="xss", title="reflected XSS"))
    assert not poc_agent._is_xss(dict(FINDING, category="sqli", title="SQL injection"))
    assert not poc_agent._is_xss(dict(FINDING, category="command injection", title="exec"))


def test_xss_requires_browser_execution_with_full_category_name(monkeypatch):
    finding = dict(
        FINDING,
        category="Cross-Site Scripting",
        title="reflected cross-site scripting in name parameter",
        file_path="vulnerabilities/xss_r/index.php",
    )
    client = FakeClient()
    script = {
        "poc_execute": [
            call("run_poc", language="python", script=SCRIPT),
            final_answer("探索结束"),
        ],
        "poc_conclude": [
            final_answer({
                "status": "verified",
                "verdict": "confirmed",
                "summary": "script reflected",
                "attack_observation": "First name: admin",
                "jobs": ["job-1"],
            }),
        ],
    }
    factory = ModelFactory(script)
    monkeypatch.setattr(poc_agent, "build_code_model", factory)
    deps_ = deps(client, finding=finding)
    result, _ = asyncio.run(poc_agent.run_poc_agent(finding=finding, deps=deps_, config=CONFIG))
    assert result is not None and result.status == "inconclusive"
    assert "浏览器" in result.evidence_notes


def test_model_reported_environment_state_is_overridden(monkeypatch):
    client = FakeClient()
    script = {
        "poc_execute": [final_answer("探索结束")],
        "poc_conclude": [
            final_answer({
                "status": "environment_unavailable",
                "summary": "gave up",
            }),
        ],
    }
    result, _, _, _ = run_agent(monkeypatch, script, client)
    assert result is not None and result.status == "inconclusive"


def test_host_check_does_not_publish_an_unreferenced_script():
    deps_ = deps(FakeClient(), scripts=[SCRIPT, "print('second')\n"])
    result = PocVerificationResult(status="verified", summary="ok", adapted_script="print('invented')\n")
    checked = host_check(result, deps_)
    assert checked.status == "inconclusive"
    assert checked.adapted_script == ""


def test_verifier_persists_jobs_and_artifacts(tmp_path, monkeypatch):
    client = FakeClient()
    store = FakeStore()
    bus = FakeBus()
    verifier = make_verifier(tmp_path, store, bus, client)
    script = {
        "poc_execute": [
            call("run_poc", language="python", script=SCRIPT),
            final_answer("探索结束"),
        ],
        "poc_conclude": [
            final_answer({
                "status": "verified",
                "verdict": "confirmed",
                "summary": "union result returned admin rows",
                "normal_observation": "normal id returned one user",
                "attack_observation": "First name: admin",
                "jobs": ["job-1"],
                "normal_evidence": [{"job_id": "job-1", "channel": "stdout", "excerpt": "normal id returned one user"}],
                "attack_evidence": [{"job_id": "job-1", "channel": "stdout", "excerpt": "First name: admin"}],
            }),
        ],
    }
    monkeypatch.setattr(poc_agent, "build_code_model", ModelFactory(script))
    summary = asyncio.run(verifier.verify_standing("run-1", [FINDING], {}, model_config=CONFIG))
    assert summary["verified"] == 1
    record = store.records[0]
    assert record["source"] == "poc_agent"
    assert record["status"] == "verified"
    assert record["project_finding_id"] == "project-finding-1"
    assert record["finding_revision"] == 1
    assert record["artifacts"] and (tmp_path / record["artifacts"][0]["path"]).exists()
    assert store.jobs and store.jobs[0]["job_id"] == "job-1"
    assert "poc_agent_phase" in bus.kinds()
    assert "poc_verification_started" in bus.kinds()
    assert bus.kinds()[-1] == "poc_verification_recorded"


# --- tool contract, phase assembly and durable pairing -----------------------------


def test_each_poc_phase_carries_its_own_rules_and_tool_table(monkeypatch):
    """The conclusion must not still be told to execute scripts.

    Live run 538f47d9 switched phases without switching instructions: every tool was
    withdrawn, the model was still told to run POCs, and it spent its conclusion steps on
    ``import urllib.request`` errors before handing in an answer.
    """
    client = FakeClient()
    script = {
        "poc_execute": [final_answer("探索结束")],
        "poc_conclude": [final_answer({
            "status": "inconclusive",
            "summary": "no job was executed",
        })],
    }
    _, _, _, factory = run_agent(monkeypatch, script, client)
    phases = factory.phases
    prompts = factory.prompts

    explore = prompts[phases.index("poc_execute")]
    conclude = next(p for p, phase in zip(prompts, phases) if phase == "poc_conclude")

    # The POC role, not the frozen-snapshot audit role, and the JSON tutorial it needs.
    assert "POC 自动验证 Agent" in explore
    assert "json.loads" in explore
    assert "冻结的快照" not in explore
    assert "def run_poc(" in explore
    assert "def http_observe(" in explore
    # The exploration rules are gone from the conclusion request, and so are the tools.
    assert "所有工具都已收回" in conclude
    assert "探索阶段结束时调用 final_answer" not in conclude
    assert "def run_poc(" not in conclude
    assert "def http_observe(" not in conclude
    assert "def browser_check(" not in conclude
    assert "json.loads" not in conclude
    # Publication is JSON, with neither interpreter nor tool signatures.
    assert "def final_answer(" not in conclude
    assert "只输出JSON" in conclude
    assert '"status":"inconclusive"' in conclude
    # Named only to forbid constructing it inside the interpreter.
    assert "PocVerificationResult(" not in conclude
    # The host supplies the last executed script, so the model is not asked to repeat it.
    assert "宿主仅从支撑结论的成功作业补齐" in conclude


def test_a_large_reply_is_clipped_but_stays_valid_json():
    """Truncating serialized text produced a half-written object; clipping fields does not."""
    deps_ = deps(FakeClient())
    raw = deps_._reply({
        "job_id": "job-1",
        "status": "finished",
        "exit_code": 0,
        "stdout": "中文观测结果。" * 4000,
    })
    parsed = json.loads(raw)

    assert parsed["job_id"] == "job-1"
    assert parsed["status"] == "finished"
    assert parsed["exit_code"] == 0
    assert parsed["host_truncated"] is True
    assert len(raw.encode("utf-8")) <= poc_agent.MAX_TOOL_REPLY


def test_a_small_reply_is_not_marked_truncated():
    deps_ = deps(FakeClient())
    parsed = json.loads(deps_._reply({"status": "ok", "job_id": "job-1"}))

    assert parsed == {"ok": True, "status": "ok", "job_id": "job-1"}


def recorded_deps(client, **overrides):
    events: list[dict] = []
    deps_ = deps(client, **overrides)
    deps_.execution = Execution(
        {"responses": 8, "tools": 32, "seconds": 30}, AgentPolicy(), events.append
    )
    # The driver enters the phase before any tool can be called; ``before_tool`` books the
    # call against the current phase, and an unentered one is a KeyError, not a budget pass.
    deps_.execution.phase = "poc_execute"
    deps_.execution.phases["poc_execute"] = {"model_attempts": 0, "tool_calls": 0}
    return deps_, events


def test_a_successful_tool_call_is_paired_with_its_result():
    deps_, events = recorded_deps(FakeClient())

    text = asyncio.run(deps_.call("target_status", {}))

    assert json.loads(text)["ok"] is True
    assert [event["kind"] for event in events] == ["tool_call", "tool_result"]
    call_event, result_event = events
    assert call_event["call_id"] == result_event["call_id"]
    assert call_event["span_id"] == result_event["span_id"]
    assert result_event["status"] == "ok"
    assert result_event["duration_ms"] >= 0


class UnavailableClient(FakeClient):
    async def target_status(self, target="lab30", **kwargs):
        raise PocRunnerUnavailable("runner down")


class RejectingClient(FakeClient):
    async def target_status(self, target="lab30", **kwargs):
        raise PocRunnerError("runner rejected the request (403): path is not in the Lab30 allowlist")


class BrokenClient(FakeClient):
    async def target_status(self, target="lab30", **kwargs):
        raise ValueError("unexpected")


class CancelledClient(FakeClient):
    async def target_status(self, target="lab30", **kwargs):
        raise asyncio.CancelledError()


def test_runner_unavailable_is_still_a_paired_result():
    deps_, events = recorded_deps(UnavailableClient())

    from audit.runtime import StopAudit
    with pytest.raises(StopAudit, match="runner 不可用"):
        asyncio.run(deps_.call("target_status", {}))
    assert json.loads(events[-1]["preview"])["error"] == "runner_unavailable"
    assert [event["kind"] for event in events] == [
        "tool_call", "poc_runner_unavailable", "tool_result",
    ]
    assert events[-1]["status"] == "runner_unavailable"
    assert events[-1]["error_type"] == "PocRunnerUnavailable"
    assert events[-1]["call_id"] == events[0]["call_id"]


def test_runner_rejection_is_still_a_paired_result():
    deps_, events = recorded_deps(RejectingClient())

    parsed = json.loads(asyncio.run(deps_.call("target_status", {})))

    assert parsed["error"] == "runner_rejected"
    assert [event["kind"] for event in events] == [
        "tool_call", "poc_runner_rejected", "tool_result",
    ]
    assert events[-1]["status"] == "runner_rejected"


def test_an_unexpected_tool_failure_is_still_paired():
    deps_, events = recorded_deps(BrokenClient())

    with pytest.raises(ValueError):
        asyncio.run(deps_.call("target_status", {}))

    assert [event["kind"] for event in events] == ["tool_call", "tool_result"]
    assert events[-1]["status"] == "error"
    assert events[-1]["error_type"] == "ValueError"


def test_a_cancelled_tool_call_is_still_paired():
    deps_, events = recorded_deps(CancelledClient())

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(deps_.call("target_status", {}))

    assert [event["kind"] for event in events] == ["tool_call", "tool_result"]
    assert events[-1]["status"] == "cancelled"


def test_http_only_observation_cannot_support_verified(monkeypatch):
    """The choice was explicit: a verdict needs a successful job, not a favourable GET."""
    client = FakeClient(job={
        "job_id": "job-1",
        "status": "finished",
        "exit_code": 1,
        "duration_ms": 12,
        "stdout": "",
        "stderr": "DNS failure for //evil.com",
        "truncated": False,
        "timed_out": False,
        "artifacts": [],
    })
    script = {
        "poc_execute": [
            call("run_poc", language="python", script=SCRIPT),
            call("http_observe", path="/auth/continue.php?redirect=//evil.com"),
            final_answer("探索结束"),
        ],
        "poc_conclude": [final_answer({
            "status": "verified",
            "verdict": "confirmed",
            "summary": "the GET returned a redirect",
            "normal_observation": "control returned 200",
            "attack_observation": "First name: admin",
            "jobs": ["job-1"],
        })],
    }
    result, _, deps_, _ = run_agent(monkeypatch, script, client)

    assert result is not None
    assert result.status == "inconclusive"
    assert "缺少成功作业支撑" in result.evidence_notes
    # The single-request observation is kept as diagnostic evidence, never as proof.
    assert deps_.observations and deps_.observations[0]["followed_redirects"] is False


def test_outdated_runner_disables_auto_poc_without_rewriting_static_findings(tmp_path, monkeypatch):
    class OldRunner(FakeClient):
        async def health(self):
            health = await super().health()
            health['capabilities'].pop('idempotent_http_jobs')
            return health

    async def forbidden(**kwargs):
        raise AssertionError('an outdated runner must never receive a new experiment')

    monkeypatch.setattr(poc, 'run_poc_agent', forbidden)
    store, bus = FakeStore(), FakeBus()
    original = dict(FINDING)
    result = asyncio.run(make_verifier(tmp_path, store, bus, OldRunner()).verify_standing(
        'run-1', [FINDING], {}, model_config=CONFIG))
    assert result['environment_unavailable'] == 1
    assert store.records == [] and store.jobs == [] and FINDING == original
    assert 'poc_verification_skipped' in bus.kinds()
    assert any(payload.get('reason') == 'runner_upgrade_required' for _, _, payload in bus.events)


def test_identical_preconditions_are_remembered_once():
    """A status check repeated with the same account facts is the same precondition."""
    deps_ = deps(FakeClient())
    snapshot = {
        "identity": "alice",
        "precondition": {"ok": True, "identity": "alice", "reason": "",
                         "actual": {"role": "customer", "balance": "100.00", "tier": "standard",
                                    "nickname": "Alice", "homepage": "https://example.invalid"}},
    }

    for _ in range(5):
        deps_._remember_state(dict(snapshot))
    # A different account state is a new fact and is kept.
    deps_._remember_state({**snapshot, "precondition": {
        **snapshot["precondition"],
        "actual": {**snapshot["precondition"]["actual"], "tier": "gold"},
    }})

    assert len(deps_.preconditions) == 2
    assert deps_.preconditions[0]["identity"] == "alice"


def test_preconditions_are_capped_and_the_omission_is_counted():
    deps_ = deps(FakeClient())
    for index in range(20):
        deps_._remember_state({
            "identity": "alice",
            "precondition": {"ok": True, "actual": {"role": "customer", "balance": str(index)}},
        })

    assert len(deps_.preconditions) == deps_.max_preconditions
    assert deps_.preconditions_omitted == 20 - deps_.max_preconditions
    # The newest fact survives; the oldest are what was dropped.
    assert deps_.preconditions[-1]["actual"]["balance"] == "19"


def test_artifacts_share_one_phase_budget():
    deps_ = deps(FakeClient())
    deps_.max_artifact_bytes = 10

    assert deps_.store_artifact("a.txt", b"12345") is True
    assert deps_.store_artifact("b.txt", b"123456") is False
    assert deps_.artifacts == {"a.txt": b"12345"}
    assert deps_.artifacts_omitted == 1


def test_save_artifact_refuses_past_the_phase_budget():
    deps_ = deps(FakeClient())
    deps_.max_artifact_bytes = 4

    reply = json.loads(asyncio.run(deps_._save_artifact({"filename": "a.txt", "content": "12345"})))

    assert reply["error"] == "artifact_budget_exceeded"
    assert deps_.artifacts == {}


def test_observations_are_capped_without_losing_the_newest():
    deps_, _events = recorded_deps(FakeClient())
    deps_.max_observations = 5

    for index in range(8):
        asyncio.run(deps_._http_observe({"path": f"/p{index}.php"}))

    assert len(deps_.observations) == deps_.max_observations
    assert deps_.observations[-1]["path"] == "/p7.php"
    assert deps_.observations[0]["path"] == "/p3.php"


# --- target reset and member identity ----------------------------------------------


class IdentityClient(FakeClient):
    """A runner that can answer differently per identity and to context reads."""

    def __init__(self, by_identity, **kwargs):
        super().__init__(**kwargs)
        self.by_identity = by_identity
        self.prepared_identities: list[str] = []

    async def prepare_target(self, target="lab30", *, reset=False, security="low",
                             context_id="test-context", identity="alice",
                             expected_role=None, expected_state=None):
        self.prepared_identities.append(identity)
        return self.by_identity(identity)


FINDING_TWO = {**FINDING, "id": "finding-2", "project_finding_id": "project-finding-2"}


def member_precondition(identity: str, *, ok: bool, role: str = "customer", status: int = 200) -> dict:
    return {
        "ok": ok, "identity": identity, "status": status,
        "reason": "" if ok else "identity_or_role_mismatch",
        "expected_role": "customer",
        "actual": {"id": 1, "username": identity, "role": role, "balance": "100.00", "tier": "standard"},
    }


def prepared_for(identity: str, *, ok: bool, role: str = "customer") -> dict:
    return {
        "ok": ok, "identity": identity, "user": identity, "base_url": "http://lab30",
        "version": "lab30-shop-1.0.0", "authenticated": ok,
        "precondition": member_precondition(identity, ok=ok, role=role),
    }


def reset_settings(tmp_path, command: str, **overrides):
    return settings(tmp_path, reset_between_findings=True, reset_command=command, reset_timeout=10, **overrides)


def make_reset_verifier(tmp_path, store, bus, client, command, **overrides):
    return PocVerifier(
        store=store, bus=bus, settings=reset_settings(tmp_path, command, **overrides),
        client_factory=lambda: client,
    )


def test_the_first_member_identity_that_matches_its_role_is_used(tmp_path, monkeypatch):
    seen = {}

    async def fake_agent(*, finding, deps, config, on_event=None):
        seen["identity"] = deps.default_identity
        return PocVerificationResult(status="inconclusive", summary="没有可执行结论"), "completed"

    monkeypatch.setattr(poc, "run_poc_agent", fake_agent)
    client = IdentityClient(lambda identity: prepared_for(
        identity, ok=identity == "bob", role="admin" if identity == "alice" else "customer"))
    store, bus = FakeStore(), FakeBus()
    summary = asyncio.run(make_verifier(tmp_path, store, bus, client).verify_standing(
        "run-1", [FINDING], {}, model_config=CONFIG))

    assert client.prepared_identities == ["alice", "bob"]
    assert seen["identity"] == "bob"
    assert summary["authentication_failed"] == 0
    assert "poc_authentication_failed" not in bus.kinds()
    record = store.records[0]
    assert record["agent"]["identity"] == "bob"
    assert [item["identity"] for item in record["agent"]["identity_attempts"]] == ["alice", "bob"]
    assert record["execution_status"] != "authentication_failed"


def test_two_failed_member_identities_are_reported_as_authentication_failure(tmp_path, monkeypatch):
    async def fake_agent(*, finding, deps, config, on_event=None):
        return PocVerificationResult(status="inconclusive", summary="无法登录普通会员"), "completed"

    monkeypatch.setattr(poc, "run_poc_agent", fake_agent)
    client = IdentityClient(lambda identity: prepared_for(identity, ok=False, role="admin"))
    store, bus = FakeStore(), FakeBus()
    summary = asyncio.run(make_verifier(tmp_path, store, bus, client).verify_standing(
        "run-1", [FINDING], {}, model_config=CONFIG))

    assert client.prepared_identities == ["alice", "bob"]
    assert summary["authentication_failed"] == 1
    assert "poc_authentication_failed" in bus.kinds()
    record = store.records[0]
    assert record["execution_status"] == "authentication_failed"
    event = next(payload for _, kind, payload in bus.events if kind == "poc_authentication_failed")
    assert event["identities"] == ["alice", "bob"]
    assert "password" not in json.dumps(event).casefold()


def test_a_failed_reset_is_recorded_and_stops_the_batch(tmp_path, monkeypatch):
    ran = []

    async def fake_agent(*, finding, deps, config, on_event=None):
        ran.append(finding["id"])
        return PocVerificationResult(status="inconclusive", summary="x"), "completed"

    monkeypatch.setattr(poc, "run_poc_agent", fake_agent)
    client = FakeClient()
    store, bus = FakeStore(), FakeBus()
    verifier = make_reset_verifier(tmp_path, store, bus, client, f"{sys.executable} -c \"import sys; sys.exit(3)\"")
    summary = asyncio.run(verifier.verify_standing(
        "run-1", [FINDING, FINDING_TWO], {}, model_config=CONFIG))

    assert ran == []
    assert client.created == []
    assert summary["inconclusive"] == 1
    assert bus.kinds().count("poc_target_reset_failed") == 1
    record = store.records[0]
    assert record["agent"]["reason"] == "target_reset_failed"
    assert record["agent"]["reset"]["reason"] == "target_reset_failed"


def test_a_successful_reset_happens_before_the_context_is_created(tmp_path, monkeypatch):
    async def fake_agent(*, finding, deps, config, on_event=None):
        return PocVerificationResult(status="inconclusive", summary="x"), "completed"

    monkeypatch.setattr(poc, "run_poc_agent", fake_agent)
    client = FakeClient()
    store, bus = FakeStore(), FakeBus()
    script = tmp_path / "reset_seed.py"
    script.write_text(
        "import json\n"
        "print(json.dumps({'ok': True, 'accounts': [{'username': 'alice'}]}))\n",
        encoding="utf-8",
    )
    verifier = make_reset_verifier(tmp_path, store, bus, client, f"{sys.executable} {script}")
    asyncio.run(verifier.verify_standing("run-1", [FINDING, FINDING_TWO], {}, model_config=CONFIG))

    kinds = bus.kinds()
    assert kinds.count("poc_target_reset") == 2
    assert kinds.index("poc_target_reset") < kinds.index("poc_verification_started")
    assert len(client.created) == 2
    event = next(payload for _, kind, payload in bus.events if kind == "poc_target_reset")
    assert event["accounts"] == [{"username": "alice"}]


def test_a_context_that_will_not_close_blocks_the_reset(tmp_path, monkeypatch):
    async def still_open(self, client, context_id, *, timeout=15.0):
        return False

    monkeypatch.setattr(PocVerifier, "_wait_context_closed", still_open)
    store, bus = FakeStore(), FakeBus()
    client = FakeClient()
    verifier = make_reset_verifier(tmp_path, store, bus, client, f"{sys.executable} -c \"raise SystemExit(0)\"")
    verifier._last_context["lab30"] = "previous-context"
    asyncio.run(verifier.verify_standing("run-1", [FINDING], {}, model_config=CONFIG))

    assert client.created == []
    assert store.records[0]["agent"]["reason"] == "target_reset_blocked"
    event = next(payload for _, kind, payload in bus.events if kind == "poc_target_reset_failed")
    assert event["reason"] == "target_reset_blocked"
    assert event["context_id"] == "previous-context"


def test_wait_context_closed_polls_until_the_runner_reports_closed(tmp_path):
    class Client:
        def __init__(self):
            self.reads = 0

        async def context_status(self, context_id):
            self.reads += 1
            state = "closing" if self.reads < 3 else "closed"
            return {"context_id": context_id, "state": state, "active": 0, "pending_jobs": 0}

    verifier = make_verifier(tmp_path, FakeStore(), FakeBus(), FakeClient())
    client = Client()
    assert asyncio.run(verifier._wait_context_closed(client, "ctx", timeout=2)) is True
    assert client.reads == 3


def test_a_reset_that_times_out_is_killed_and_reported(tmp_path):
    store, bus = FakeStore(), FakeBus()
    verifier = PocVerifier(store=store, bus=bus, settings=settings(tmp_path),
                           client_factory=lambda: FakeClient())
    policy = PocPolicy(mode="auto", enabled=True, reset_between_findings=True,
                       reset_command=f"{sys.executable} -c \"import time; time.sleep(10)\"",
                       reset_timeout=1)
    started = time.monotonic()
    ok, detail = asyncio.run(verifier._reset_target(store.run, FINDING, policy))
    assert ok is False and "未完成" in detail["message"]
    assert time.monotonic() - started < 5
    assert "poc_target_reset_failed" in bus.kinds()


def test_a_tool_without_an_identity_uses_the_prepared_one():
    data, _events = recorded_deps(FakeClient(), default_identity="bob")
    reply = json.loads(asyncio.run(data.call("target_status", {})))
    assert reply["ok"] is True
    assert data.client.last_identity == "bob"

    reply = json.loads(asyncio.run(data.call("target_status", {"identity": "alice"})))
    assert reply["ok"] is True
    assert data.client.last_identity == "alice"


def test_prepare_state_drift_is_handed_to_the_model():
    prepared = prepared_for("alice", ok=True)
    prepared["precondition"]["state_drift"] = [
        {"field": "balance", "before": "100.00", "after": "1.00"},
    ]
    data, _events = recorded_deps(IdentityClient(lambda identity: prepared))
    reply = json.loads(asyncio.run(data._target_prepare({"identity": "alice"})))
    assert reply["ok"] is True
    assert data.preconditions[-1]["state_drift"] == prepared["precondition"]["state_drift"]
