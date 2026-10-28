"""Offline regressions for the conclusion prompt's bounded, attributable evidence."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from audit.poc_agent import (
    CONCLUDE_INSTRUCTIONS,
    PocDeps,
    _conclusion_jobs,
    _context_json,
    _finding_block,
    conclude_prompt,
    execute_prompt,
)


CONTEXT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
JOBS_LIMIT = 24 * 1024


def make_job(index: int, kind: str, text: str = "normal\nattack") -> dict:
    result = {"status": "finished", "timed_out": False, "truncated": False}
    if kind == "script":
        result.update(stdout=text, stderr="stderr: diagnostic only\n诊断原文")
        request = {"language": "python", "script_sha256": "a" * 64}
    elif kind == "http":
        result.update(
            execution_status="finished", http_status=403, body=text,
            headers={"X-Observation": "denied", "Content-Type": "text/html; charset=UTF-8"},
        )
        request = {"method": "GET", "path": "/support/reply.php"}
    elif kind == "browser":
        result.update(
            available=True, body_text=text,
            dialogs=[f"browser-executed-{index}", "弹窗原文\n第二行"],
            evaluated=f"evaluated-original-{index}",
        )
        request = {"path": "/support/reply.php", "wait_ms": 1000}
    else:
        raise AssertionError(kind)
    return {
        "job_id": f"00000000-0000-4000-8000-{index:012d}",
        "kind": kind, "context_id": CONTEXT_ID, "identity": "alice", "exit_code": 0,
        "precondition": {"ok": True, "actual": {"role": "customer"}},
        "request": request,
        "result": result,
    }


def make_deps(jobs: list[dict]) -> PocDeps:
    return PocDeps(
        client=None, policy={"max_jobs": 32}, target="lab30",
        finding={"id": "finding-context", "category": "other", "vulnerability_type": "xss_r"},
        context_id=CONTEXT_ID, jobs=jobs,
    )


def raw_channels(job: dict) -> dict[str, str]:
    """Build expectations from raw fixtures, independently of production helpers."""
    result = job["result"]
    if job["kind"] == "script":
        return {"stdout": result["stdout"], "stderr": result["stderr"]}
    if job["kind"] == "http":
        return {
            "body": result["body"],
            "headers": "Content-Type: text/html; charset=UTF-8\nX-Observation: denied",
        }
    return {
        "body_text": result["body_text"], "dialogs": "\n".join(result["dialogs"]),
        "evaluated": result["evaluated"],
    }


def assert_exact_windows(channel: dict, raw: str) -> None:
    assert channel["total_characters"] == len(raw)
    shown = 0
    previous_end = 0
    for segment in channel["segments"]:
        start, text = segment["offset"], segment["text"]
        assert type(start) is int and previous_end <= start <= len(raw)
        assert text == raw[start:start + len(text)]
        previous_end = start + len(text)
        shown += len(text)
    assert channel["omitted_characters"] == len(raw) - shown
    assert channel["omitted_characters"] >= 0
    if not channel["omitted_characters"]:
        assert "".join(part["text"] for part in channel["segments"]) == raw
    elif channel["segments"]:
        assert channel["segments"][0]["offset"] == 0
        last = channel["segments"][-1]
        assert last["offset"] + len(last["text"]) == len(raw)


def test_empty_jobs_are_valid_untruncated_json():
    deps = make_deps([])
    assert json.loads(_conclusion_jobs(deps)) == {
        "items": [], "total": 0, "omitted_jobs": 0, "output_truncated": False,
    }


@pytest.mark.parametrize("count", [8, 32])
@pytest.mark.parametrize("body", [
    'English output: "quoted" <html>\\path\n' * 5000,
    '中文输出："原始字符"\n多字节边界🧪与反斜线\\\t' * 5000,
], ids=["english", "unicode"])
def test_long_mixed_job_outputs_keep_every_id_and_exact_windows(count, body):
    jobs = [make_job(i, ("script", "http", "browser")[i % 3], body) for i in range(count)]
    # A browser experiment at the end must survive the same budget as early stdout.
    jobs[-1] = make_job(count - 1, "browser", body)
    deps = make_deps(jobs)
    before = deepcopy(vars(deps))

    encoded = _conclusion_jobs(deps)
    payload = json.loads(encoded)

    assert len(encoded.encode("utf-8")) <= JOBS_LIMIT
    assert payload["total"] == count and payload["omitted_jobs"] == 0
    assert payload["output_truncated"] is True
    assert [item["job_id"] for item in payload["items"]] == [job["job_id"] for job in jobs]
    for original, summary in zip(jobs, payload["items"], strict=True):
        for key in ("job_id", "kind", "context_id", "identity", "exit_code"):
            assert summary[key] == original[key]
        assert summary["evidence_usable"] is True
        expected = raw_channels(original)
        assert set(summary["evidence_channels"]) == set(expected)
        for name, raw in expected.items():
            assert_exact_windows(summary["evidence_channels"][name], raw)
    browser = payload["items"][-1]["evidence_channels"]
    assert browser["dialogs"]["segments"] == [{"offset": 0, "text": "\n".join(jobs[-1]["result"]["dialogs"])}]
    assert browser["evaluated"]["segments"] == [{"offset": 0, "text": jobs[-1]["result"]["evaluated"]}]
    assert vars(deps) == before


def test_short_raw_channels_are_preserved_in_full_without_injected_markers():
    text = 'normal\nattack: <b title="原文">\\path\t🧪</b>\r\n'
    jobs = [make_job(i, kind, text) for i, kind in enumerate(("script", "http", "browser"))]
    payload = json.loads(_conclusion_jobs(make_deps(jobs)))
    assert payload["output_truncated"] is False
    for original, summary in zip(jobs, payload["items"], strict=True):
        for name, raw in raw_channels(original).items():
            channel = summary["evidence_channels"][name]
            assert_exact_windows(channel, raw)
            assert channel["segments"] == ([{"offset": 0, "text": raw}] if raw else [])
            assert channel["omitted_characters"] == 0


def test_maximum_browser_jobs_keep_short_execution_proof_visible_at_the_end():
    jobs = [make_job(i, "browser", "长页面 body text\n" * 5000) for i in range(32)]
    encoded = _conclusion_jobs(make_deps(jobs))
    payload = json.loads(encoded)
    assert len(encoded.encode("utf-8")) <= JOBS_LIMIT
    assert payload["total"] == 32 and payload["omitted_jobs"] == 0
    assert [item["job_id"] for item in payload["items"]] == [job["job_id"] for job in jobs]
    last = payload["items"][-1]
    assert last["evidence_usable"] is True
    for channel in ("dialogs", "evaluated"):
        raw = raw_channels(jobs[-1])[channel]
        assert last["evidence_channels"][channel]["segments"] == [{"offset": 0, "text": raw}]
        assert_exact_windows(last["evidence_channels"][channel], raw)


@pytest.mark.parametrize("kind", ["script", "http", "browser"])
@pytest.mark.parametrize("change", [
    {"exit_code": 1}, {"exit_code": None}, {"exit_code": False},
    {"context_id": "another-experiment"}, {"precondition": {"ok": False}},
    {"precondition": {}}, {"precondition": {"ok": "true"}},
    {"result": {"status": "failed", "execution_status": "failed"}},
    {"result": {"timed_out": True}}, {"result": {"error": "synthetic runner failure"}},
])
def test_invalid_job_cannot_be_marked_as_usable_evidence(kind, change):
    job = make_job(0, kind)
    if "result" in change:
        job["result"].update(change["result"])
    else:
        job.update(deepcopy(change))
    deps = make_deps([job])
    before = deepcopy(vars(deps))
    summary = json.loads(_conclusion_jobs(deps))["items"][0]
    assert summary["evidence_usable"] is False
    assert summary["job_id"] == job["job_id"]
    assert summary["context_id"] == job["context_id"]
    assert summary["exit_code"] == job["exit_code"]
    assert vars(deps) == before


def test_missing_verification_context_never_marks_success_as_usable():
    deps = make_deps([make_job(0, "script")])
    deps.context_id = ""
    assert json.loads(_conclusion_jobs(deps))["items"][0]["evidence_usable"] is False


@pytest.mark.parametrize("limit", [4 * 1024, 12 * 1024])
def test_long_metadata_is_structurally_bounded_valid_json_without_mutation(limit):
    metadata = {
        "summary": '中文与英文 mixed "\\\n🧪' * 10000,
        "observations": [{"state": ["原始元数据" * 2000] * 25}] * 25,
    }
    before = deepcopy(metadata)
    encoded = _context_json(metadata, limit)
    assert len(encoded.encode("utf-8")) <= limit
    assert json.loads(encoded)["host_truncated"] is True
    assert metadata == before
    assert json.loads(_context_json({"role": "普通会员", "ok": True}, limit)) == {"role": "普通会员", "ok": True}


def test_canonical_vulnerability_type_is_present_in_both_phase_prompts():
    deps = make_deps([])
    before = deepcopy(deps.finding)
    assert json.loads(_finding_block(deps.finding))["vulnerability_type"] == "xss_r"
    for prompt in (execute_prompt(deps.finding, deps, deps.policy), conclude_prompt(deps.finding, deps)):
        finding_block = prompt.split("\n", 1)[1].split("\n#", 1)[0]
        assert json.loads(finding_block)["vulnerability_type"] == "xss_r"
    assert deps.finding == before


def test_state_metadata_stays_separate_from_raw_output_and_http_is_not_duplicated():
    body = "UNIQUE_HTTP_RAW_OBSERVATION\n响应正常"
    deps = make_deps([make_job(0, "http", body)])
    deps.observations = [{"body": body, "headers": {"X-Observation": "denied"}}]
    deps.preconditions = [{"ok": True, "actual": {"role": "customer"}}]
    deps.state_changes = [{"field": "role", "before": "customer", "after": "STATE_METADATA_ONLY"}]
    before = deepcopy(vars(deps))

    prompt = conclude_prompt(deps.finding, deps)
    jobs_block = prompt.split("# 执行阶段实际发生的作业（宿主记录）\n", 1)[1]
    payload, _ = json.JSONDecoder().raw_decode(jobs_block)
    assert "STATE_METADATA_ONLY" not in json.dumps(payload, ensure_ascii=False)
    assert payload["items"][0]["evidence_channels"]["body"]["segments"] == [{"offset": 0, "text": body}]
    assert "body_text" not in payload["items"][0]["evidence_channels"]
    metadata_block = prompt.split("# 实验前提与状态变化\n", 1)[1].split("\n#", 1)[0]
    assert json.loads(metadata_block)["state_changes"] == deps.state_changes
    assert prompt.count("UNIQUE_HTTP_RAW_OBSERVATION") == 1
    assert "state_changes/precondition/postcondition" in CONCLUDE_INSTRUCTIONS
    assert "不要把分开的 segments 拼成一个 excerpt" in prompt
    assert vars(deps) == before
