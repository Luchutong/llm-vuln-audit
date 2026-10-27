"""Offline regressions for bounded Planner verification memory and honest review reads."""
from __future__ import annotations

import asyncio
import copy
from contextlib import closing
import json

import pytest
from pydantic_ai import ModelRetry

from audit import agent
from audit.runtime import AgentPolicy, Execution
from audit.schemas import PlannerDecision
from audit.verification_context import list_page, read_chunk
from tests.test_planner_situation import CONFIG, TASK


def context(count: int) -> dict:
    records = [{
        "finding_id": f"finding-{index:04d}", "verification_id": f"verification-{index:04d}",
        "revision": 2, "status": "verified", "verification_status": "verified", "verdict": "confirmed",
        "finding_title": "中文漏洞标题" * 100,
        "summary": "可公开验证摘要" * 100,
        "normal_observation": "正常侧原始观测\n" * 2000,
        "attack_observation": "攻击侧原始观测\n" * 2000,
        "evidence_notes": "原始验证记录" * 2000,
        "normal_evidence": [{"job_id": f"job-{index}", "excerpt": "正常响应" * 1000}],
    } for index in range(count)]
    return {
        "goal": {"id": "goal", "status": "open"}, "tasks": [],
        "findings": [], "verification_summary": {"verified": count},
        "verification_records": records, "verification_details": records,
        "verification_reviews_required": copy.deepcopy(records),
        "verification_reviews": [{
            "id": f"review-{index}", "finding_id": row["finding_id"], "verification_id": row["verification_id"],
            "revision": 1, "decision": "confirmed", "rationale": "历史判读" * 1000,
        } for index, row in enumerate(records)],
    }


def deps(value: dict, *, reader=None) -> agent.PlannerDeps:
    execution = Execution({"responses": 20, "tools": 300, "seconds": 60},
                          AgentPolicy(no_progress_calls=500), lambda _: None)
    execution.enter("planner_decision")
    return agent.PlannerDeps({}, value, execution, context_reader=reader)


@pytest.mark.parametrize("count", [0, 5, 10, 26, 200])
def test_long_verification_lists_fit_the_existing_16k_ceiling(count):
    value = context(count)
    before = copy.deepcopy(value)
    situation = agent._planner_situation(value)
    bounded = agent._bound_situation(situation)
    encoded = agent._planner_json(bounded, limit=16 * 1024)
    parsed = json.loads(encoded)
    assert len(encoded.encode("utf-8")) <= 16 * 1024
    assert parsed["counts"]["verification_records"] == count
    assert parsed["counts"]["verification_reviews_required"] == count
    assert parsed["closure_checks"]["unreviewed_verifications"] == count
    assert parsed["verification_access"]["totals"] == {"records": count, "pending": count, "reviews": count}
    assert len(parsed["verification_reviews_required"]) <= 4
    for row in parsed["verification_reviews_required"]:
        assert row["verification_id"].startswith("verification-")
        assert row["revision"] == 2
        assert row["observations_preloaded"] is False
        assert "normal_observation" not in row and "attack_observation" not in row
    assert "正常侧原始观测" not in encoded
    assert "历史判读" in encoded if count else "历史判读" not in encoded
    assert value == before


def test_pages_enumerate_all_200_exact_identities_without_truncated_strings():
    value = context(200)
    cursor = ""
    seen = []
    while True:
        page = list_page(value, kind="pending", cursor=cursor, limit=16)
        assert len(json.dumps(page, ensure_ascii=False, separators=(",", ":")).encode()) <= 8 * 1024
        seen.extend((item["finding_id"], item["verification_id"], item["revision"]) for item in page["items"])
        if page["next_cursor"] is None:
            break
        cursor = page["next_cursor"]
    assert seen == [(item["finding_id"], item["verification_id"], 2)
                    for item in value["verification_reviews_required"]]


def test_cursor_rejects_a_new_revision_instead_of_skipping_an_updated_conclusion():
    value = context(5)
    cursor = list_page(value)["next_cursor"]
    value["verification_reviews_required"][0]["revision"] = 3
    with pytest.raises(ValueError, match="已更新"):
        list_page(value, cursor=cursor)


@pytest.mark.parametrize("field", ["normal_observation", "attack_observation", "evidence_notes", "normal_evidence", "reviews"])
def test_full_field_chunks_round_trip_unicode_and_nested_json(field):
    value = context(1)
    offset = 0
    texts = []
    while True:
        chunk, _ = read_chunk(value, verification_id="verification-0000", field=field, offset=offset, limit=257)
        # A wire round-trip does not corrupt multibyte text or JSON excerpts.
        chunk = json.loads(json.dumps(chunk, ensure_ascii=False))
        assert chunk["verification_id"] == "verification-0000" and chunk["revision"] == 2
        texts.append(chunk["text"])
        if chunk["next_offset"] is None:
            break
        offset = chunk["next_offset"]
    text = "".join(texts)
    expected = value["verification_details"][0].get(field, value["verification_reviews"])
    assert (json.loads(text) if chunk["encoding"] == "json" else text) == expected


def test_reads_prefer_full_details_over_the_legacy_600_character_preview():
    value = context(1)
    value["verification_records"] = [{**value["verification_records"][0], "normal_observation": "preview"}]
    chunk, _ = read_chunk(value, verification_id="verification-0000", field="normal_observation")
    assert chunk["total_characters"] == len(value["verification_details"][0]["normal_observation"])
    assert chunk["text"] != "preview"


def test_incomplete_reads_or_old_revisions_cannot_attest_and_complete_reads_can():
    async def scenario():
        value = context(1)
        value["verification_details"][0]["normal_observation"] = "正常" * 900
        value["verification_details"][0]["attack_observation"] = "攻击" * 900
        host = deps(value)
        review = {"finding_id": "finding-0000", "verification_id": "verification-0000", "revision": 2}
        with pytest.raises(ValueError, match="尚未完整读取"):
            host.validate_verification_reads([review], value)
        for name in ("normal_observation", "attack_observation"):
            offset = 0
            while True:
                result = json.loads(await host.call("read_verification", {
                    "verification_id": "verification-0000", "field": name, "offset": offset,
                }))
                if result["next_offset"] is None:
                    break
                offset = result["next_offset"]
        host.validate_verification_reads([review], value)
        with pytest.raises(ValueError, match="revision"):
            host.validate_verification_reads([{**review, "revision": 1}], value)
        # Even the same verification id cannot reuse an attestation across a conclusion revision.
        value["verification_reviews_required"][0]["revision"] = 3
        with pytest.raises(ValueError, match="尚未完整读取"):
            host.validate_verification_reads([{**review, "revision": 3}], value)
    asyncio.run(scenario())


def test_unknown_verification_is_refused_without_a_global_store_lookup():
    async def scenario():
        host = deps(context(1))
        value = json.loads(await host.call("read_verification", {"verification_id": "other-run-verification"}))
        assert value["ok"] is False
        assert "其他运行" in value["error"]
        assert host.verification_reads == {}
    asyncio.run(scenario())


def test_verification_tools_refresh_context_instead_of_caching_old_versions():
    async def scenario():
        first = context(1)
        second = context(2)
        values = iter([first, second])
        host = deps({}, reader=lambda: next(values))
        assert json.loads(await host.call("list_verifications", {}))["total"] == 1
        assert json.loads(await host.call("list_verifications", {}))["total"] == 2
        assert host.repeats == 0
    asyncio.run(scenario())


def test_context_preparation_failure_is_a_structured_host_terminal(monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError("synthetic capacity regression")
    monkeypatch.setattr(agent, "_bound_situation", fail)
    monkeypatch.setattr(agent, "build_code_model", lambda *args, **kwargs: pytest.fail("must not call a model"))
    events = []
    value = context(5)
    result = asyncio.run(agent.plan_audit_frontier(
        project_map={}, run_context=value, task=TASK, round_no=3, config=CONFIG,
        budgets={"responses": 4, "tools": 4, "seconds": 8}, on_event=events.append,
    ))
    assert result["terminal_reason"] == "planner_context_error"
    assert result["decision"] is None
    event = next(item for item in events if item["kind"] == "planner_context_error")
    assert event["stage"] == "situation_budget"
    assert event["field_bytes"]["verification_records"] > 16 * 1024
    assert event["ceiling_bytes"] == 16 * 1024
    assert "正常侧原始观测" not in json.dumps(event, ensure_ascii=False)
    assert result["usage"]["requests"] == 0


def test_coverage_policy_never_gets_the_legacy_silent_closure_notice():
    value = context(1)
    value["completion_policy"] = "coverage_review"
    value["coverage_review"] = {"total": 80, "pending_total": 80, "pending_paths": [f"src/{i}.php" for i in range(80)], "complete": False}
    situation = agent._planner_situation(value)
    assert situation["completion_policy"] == "coverage_review"
    assert "本轮没有更改不等于目标完成" in situation["notice"]
    assert "什么都不改，宿主就以已成立" not in situation["notice"]
    assert len(situation["coverage_review"]["pending_paths"]) == 4


def test_coverage_gap_pagination_is_complete_and_does_not_mutate_host_context():
    async def scenario():
        value = context(0)
        paths = [f"源码模块/{index:04d}/入口.php" for index in range(200)]
        value["coverage_review"] = {"version": "coverage-v1", "total": 200, "pending_total": 200,
                                    "pending_paths": paths, "complete": False}
        original = copy.deepcopy(value)
        host = deps(value)
        cursor = 0
        seen = []
        while True:
            page = json.loads(await host.call("get_coverage", {"cursor": cursor, "limit": 40}))["coverage_review"]
            seen.extend(page["pending_paths"])
            if page["next_cursor"] is None:
                break
            cursor = page["next_cursor"]
        assert seen == paths
        assert value == original
    asyncio.run(scenario())


def test_only_coverage_paths_in_the_frozen_snapshot_can_be_skipped():
    decision = PlannerDecision.model_validate({
        "goal_state": "continue", "basis_summary": "小批覆盖复核", "next_action": "继续未覆盖区域", "tasks": [],
        "coverage_review": [{"path": "not-uploaded.php", "action": "skip", "reason": "该文件不在上传源码内"}],
    })
    with pytest.raises(ModelRetry, match="范围外"):
        agent._validate_planner_decision(decision, {"files": [{"path": "public/index.php", "line_count": 3}]}, [])


def test_more_than_32_pending_reviews_are_processed_across_rounds_without_weakening_store_gate(tmp_path):
    from audit.db import Store
    from audit.source import SourceRepository
    from tests.test_finding_disposition import create_planner_run, dispatch_one, settle, conclusion
    from tests.test_poc_store import record as proof_record

    async def scenario():
        with closing(Store(tmp_path / "audit.db")) as store:
            repository = SourceRepository(tmp_path / "source")
            run, _ = create_planner_run(store, repository)
            task = dispatch_one(store, run)
            settle(store, run)
            for index in range(37):
                finding = conclusion(run, task["id"], id=f"finding-{index}", fingerprint=f"different-proof-{index}", category=f"task_goal_vulnerability_{index}")
                store.add_finding(finding)
                store.set_finding_verification_state(finding["id"], "verified", "confirmed")
                proof = proof_record({**finding, "project_finding_id": None, "project_revision": 1}, record_id=f"proof-{index}")
                proof["normal_observation"] = f"normal denied {index}"
                proof["attack_observation"] = f"attack reproduced {index}"
                store.add_verification(proof)
            rounds = 0
            while store.unreviewed_verified_findings(run["id"]):
                with pytest.raises(ValueError, match="未经 Planner 比对核实"):
                    store.finalize_goal(run["id"], "met", "尚有未展示的验证待复核。", require_reviewed=True)
                value = store.list_planner_context(run["id"])
                bounded = agent._bound_situation(agent._planner_situation(value))
                assert len(json.dumps(bounded, ensure_ascii=False, separators=(",", ":")).encode()) <= 16 * 1024
                batch = bounded["verification_reviews_required"]
                assert 0 < len(batch) <= 4
                host = deps(value)
                reviews = []
                for item in batch:
                    for name in ("normal_observation", "attack_observation"):
                        await host.call("read_verification", {"verification_id": item["verification_id"], "field": name})
                    reviews.append({"finding_id": item["finding_id"], "revision": item["revision"],
                                    "verification_id": item["verification_id"], "decision": "confirmed",
                                    "rationale_summary": "正常侧拒绝而攻击侧复现，观测与结论一致。"})
                host.validate_verification_reads(reviews, value)
                assert len(store.record_verification_reviews(run["id"], reviews)) == len(batch)
                rounds += 1
            assert rounds == 10
            assert len(store.list_verification_reviews(run["id"])) == 37
            assert store.finalize_goal(run["id"], "met", "全部验证已跨轮比对核实。", require_reviewed=True)["status"] == "met"
    asyncio.run(scenario())


def test_skip_rejects_a_directory_even_when_it_is_in_the_frozen_scope():
    decision = PlannerDecision.model_validate({
        "goal_state": "continue", "basis_summary": "逐文件覆盖复核", "tasks": [],
        "coverage_review": [{"path": "public", "action": "skip", "reason": "不能把目录整体视作已覆盖"}],
    })
    with pytest.raises(ModelRetry, match="逐文件"):
        agent._validate_planner_decision(decision, {"files": [{"path": "public/index.php", "line_count": 3}]}, [])


def test_real_planner_loop_corrects_an_unread_review_then_accepts_explicit_observation_reads(monkeypatch):
    from tests.code_model import ModelFactory, code, final_answer
    value = context(1)
    for collection in ("verification_details", "verification_reviews_required"):
        value[collection][0]["normal_observation"] = "normal denied"
        value[collection][0]["attack_observation"] = "attack reproduced"
    decision = {
        "goal_state": "continue", "basis_summary": "当前小批验证已独立比对", "tasks": [],
        "verification_reviews": [{"finding_id": "finding-0000", "verification_id": "verification-0000",
                                  "revision": 2, "decision": "confirmed",
                                  "rationale_summary": "正常侧拒绝、攻击侧复现，支持当前结论。"}],
    }
    factory = ModelFactory({"planner_decision": [
        final_answer(decision),
        code("print(read_verification('verification-0000', 'normal_observation'))\n"
             "print(read_verification('verification-0000', 'attack_observation'))"),
        final_answer(decision),
    ]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []
    result = asyncio.run(agent.plan_audit_frontier(
        project_map={}, run_context=value, task=TASK, round_no=1, config=CONFIG,
        budgets={"responses": 5, "tools": 8, "seconds": 8},
        policy=AgentPolicy(decision_confirmations=3, output_corrections=1), on_event=events.append,
    ))
    assert result["terminal_reason"] == "completed"
    assert result["decision"]["verification_reviews"][0]["verification_id"] == "verification-0000"
    assert len([item for item in events if item["kind"] == "tool_result" and item["tool"] == "read_verification"]) == 2
    assert any("尚未完整读取" in prompt for prompt in factory.prompts[1:])
    assert result["usage"]["corrections"] == 1


def test_sqlite_context_and_tools_recover_full_chinese_observations_and_evidence(tmp_path):
    from audit.db import Store
    from audit.source import SourceRepository
    from tests.test_finding_disposition import create_planner_run, dispatch_one, settle, conclusion
    from tests.test_poc_store import record as proof_record

    async def scenario():
        with closing(Store(tmp_path / "audit.db")) as store:
            repository = SourceRepository(tmp_path / "source")
            run, _ = create_planner_run(store, repository)
            task = dispatch_one(store, run)
            settle(store, run)
            finding = conclusion(run, task["id"])
            store.add_finding(finding)
            store.set_finding_verification_state(finding["id"], "verified", "confirmed")
            proof = proof_record({**finding, "project_finding_id": None, "project_revision": 1}, record_id="full-proof")
            proof["normal_observation"] = "中文正常响应：拒绝访问\n" * 400
            proof["attack_observation"] = "中文攻击响应：已越权访问\n" * 600
            proof["notes"] = "完整证据备注" * 300
            proof["agent"]["normal_evidence"] = [{"job_id": "normal-job", "channel": "stdout", "excerpt": "完整正常侧输出" * 200}]
            proof["agent"]["attack_evidence"] = [{"job_id": "attack-job", "channel": "stdout", "excerpt": "完整攻击侧输出" * 200}]
            store.add_verification(proof)
            value = store.list_planner_context(run["id"])
            # Existing public summary remains compatible and bounded; the new read-only
            # detail source retains all bytes without rewriting the archived record.
            assert len(value["verification_records"][0]["normal_observation"]) == 600
            assert len(value["verification_records"][0]["attack_observation"]) == 1200
            expected = {name: proof[name] for name in ("normal_observation", "attack_observation")}
            expected["evidence_notes"] = proof["notes"]
            expected.update({name: proof["agent"][name] for name in ("normal_evidence", "attack_evidence")})
            host = deps(value, reader=lambda: store.list_planner_context(run["id"]))
            for name, original in expected.items():
                offset = 0
                pieces = []
                while True:
                    result = json.loads(await host.call("read_verification", {
                        "verification_id": "full-proof", "field": name, "offset": offset,
                    }))
                    pieces.append(result["text"])
                    if result["next_offset"] is None:
                        break
                    offset = result["next_offset"]
                text = "".join(pieces)
                assert (json.loads(text) if result["encoding"] == "json" else text) == original
            assert store.list_verifications(finding["id"])[0]["normal_observation"] == proof["normal_observation"]
    asyncio.run(scenario())
