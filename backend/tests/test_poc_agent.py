"""POC agent orchestration and the host's fact-checking of its conclusions."""
from __future__ import annotations

import asyncio
import hashlib
import json
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
            "stdout": "First name: admin\nSurname: admin\n",
            "stderr": "",
            "truncated": False,
            "timed_out": False,
            "artifacts": [{"name": "out.txt", "sha256": "a" * 64, "size": 4}],
        }
        self.jobs: list[dict] = []
        self.prepared: list[dict] = []
        self.closed = False

    async def health(self):
        if not self.health_ok:
            raise PocRunnerUnavailable("runner down")
        return {"ok": True, "capabilities": {"php": True, "python": True, "browser": self.browser}}

    async def prepare_target(self, target="lab30", *, reset=True, security="low"):
        self.prepared.append({"target": target, "reset": reset, "security": security})
        return {"ok": True, "base_url": "http://lab30", "security": security, "version": "2.5", "authenticated": True}

    async def target_status(self, target="lab30"):
        return {"ok": True, "authenticated": True, "security": "low"}

    async def run_job(self, *, target, language, script, timeout_seconds=30, artifacts=None):
        self.jobs.append({"target": target, "language": language, "script": script})
        return dict(self.job)

    async def fetch_artifact(self, job_id, name):
        return b"data"

    async def http_observe(self, *, target, method, path, body=None, headers=None):
        return {"ok": True, "status": 200, "path": path, "body": "First name: admin"}

    async def browser_check(self, *, target, path, script=None, wait_ms=1000):
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
    values = dict(client=client, policy=PocPolicy().snapshot(), target="lab30", finding=FINDING)
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
    '{"status": "inconclusive", "summary": "证据不足"}',
], ids=["prose", "bare-call", "pure-json"])
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
    assert event["category"] == "no_code_block"
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
    assert len(conclude_codes) == 1


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


def test_a_conclusion_without_its_closing_tag_still_parses(monkeypatch):
    """The loop appends the closing tag itself; that must not be mistaken for a bad reply."""
    client = FakeClient()
    payload = json.dumps(INCONCLUSIVE, ensure_ascii=False)
    script = {
        "poc_execute": [final_answer("探索结束")],
        "poc_conclude": [f"<code>\nfinal_answer({payload})"],
    }
    result, reason, _, _, events = run_agent_events(monkeypatch, script, client)

    assert result is not None and result.status == "inconclusive", reason
    assert reason == "completed"
    assert not [item for item in events if item.get("kind") == "agent_parse_error"]


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
                "attack_observation": "First name: admin",
                "jobs": ["job-1"],
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
    assert len(finished) == 1 and finished[0]["reason"] == "budget"
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
    assert "token" in result.evidence_notes


def test_a_single_shared_token_does_not_support_verified(monkeypatch):
    """One coincidental word is no longer enough to corroborate an attack observation."""
    client = FakeClient(job={
        "job_id": "job-1", "status": "finished", "exit_code": 0, "duration_ms": 12,
        "stdout": "command executed\n", "stderr": "",
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
                "attack_observation": "sqlmap executed",
                "jobs": ["job-1"],
            }),
        ],
    }
    result, _, _, _ = run_agent(monkeypatch, script, client)
    assert result is not None and result.status == "inconclusive"
    assert "共同关键 token" in result.evidence_notes


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


def test_host_check_forces_last_executed_script():
    deps_ = deps(FakeClient(), scripts=[SCRIPT, "print('second')\n"])
    result = PocVerificationResult(status="verified", summary="ok")
    result.adapted_script = "print('invented')\n"
    checked = host_check(result, deps_)
    assert checked.adapted_script == "print('second')\n"


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
                "attack_observation": "First name: admin",
                "jobs": ["job-1"],
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
    # What replaces them: the one remaining tool and an exact submission example.  A bare
    # "submit the result" is what a model answered with prose; the code block is the
    # format the parser actually accepts.
    assert "def final_answer(" in conclude
    assert "final_answer({" in conclude
    assert '"status": "inconclusive"' in conclude
    assert "普通 dict" in conclude
    # Named only to forbid constructing it inside the interpreter.
    assert "PocVerificationResult(" not in conclude
    # The host supplies the last executed script, so the model is not asked to repeat it.
    assert "宿主会按实际执行的最后一份脚本补齐" in conclude


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

    assert parsed == {"status": "ok", "job_id": "job-1"}


def recorded_deps(client):
    events: list[dict] = []
    deps_ = deps(client)
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
    async def target_status(self, target="lab30"):
        raise PocRunnerUnavailable("runner down")


class RejectingClient(FakeClient):
    async def target_status(self, target="lab30"):
        raise PocRunnerError("runner rejected the request (403): path is not in the Lab30 allowlist")


class BrokenClient(FakeClient):
    async def target_status(self, target="lab30"):
        raise ValueError("unexpected")


class CancelledClient(FakeClient):
    async def target_status(self, target="lab30"):
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
