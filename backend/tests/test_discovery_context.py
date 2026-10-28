"""Offline regressions for narrow discovery context and the final review boundary."""
from __future__ import annotations

import asyncio
import copy
import json
import pytest
from pydantic_ai import ModelRetry

from audit.agent import _bound_situation, _planner_situation, _validate_planner_decision, _worker_current_findings
from audit.db import Store
from audit.schemas import PlannerDecision
from audit.source import SourceRepository
from tests.test_goal_tasks import TASK, create_planner_run, make_zip, proposal


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "sources")


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "context.sqlite")
    yield value
    value.close()


def bundle(repository, *, selected, hints=(), limit=64 * 1024, legacy=False):
    snapshot = repository.import_zip(make_zip({
        "public/one.php": "<?php\nrequire __DIR__ . '/../src/bootstrap.php';\nhandle_one();\n",
        "public/two.php": "<?php\nrequire __DIR__ . '/../src/bootstrap.php';\nhandle_two();\n",
        "src/bootstrap.php": "<?php\nrequire __DIR__ . '/config.php';\nfunction bootstrap() { return true; }\n",
        "src/config.php": "<?php\nrequire __DIR__ . '/secret.php';\nfunction config() { return true; }\n",
        "src/secret.php": "<?php\nfunction secret() { return true; }\n",
    }), "narrow.zip")
    return repository.build_context_bundle(snapshot["id"], {
        "context_spec": {"scope_paths": selected, "query_hints": list(hints)},
    }, max_bytes=limit, workflow_policy="legacy" if legacy else "discovery_first")


def test_shared_bootstrap_includers_stay_navigation_only(repository):
    result = bundle(repository, selected=["src/bootstrap.php"])
    assert {item["path"] for item in result["excerpts"]} == {"src/bootstrap.php", "src/config.php"}
    relations = result["relation_summary"]
    assert relations["explicit_paths"] == ["src/bootstrap.php"]
    assert {item["path"] for item in relations["navigation_only"]} == {"public/one.php", "public/two.php"}
    assert all(item["source_loaded"] is False for item in relations["navigation_only"])
    assert "src/secret.php" not in relations["selected_paths"], "dependencies do not recursively fan out"


def test_entry_context_loads_direct_dependency_but_not_its_callers(repository):
    result = bundle(repository, selected=["public/one.php"])
    assert {item["path"] for item in result["excerpts"]} == {"public/one.php", "src/bootstrap.php"}
    assert "public/two.php" not in result["relation_summary"]["selected_paths"]


def test_explicit_callers_can_be_loaded_without_recursive_spread(repository):
    result = bundle(repository, selected=["src/bootstrap.php", "public/two.php"])
    assert {item["path"] for item in result["excerpts"]} == {"src/bootstrap.php", "src/config.php", "public/two.php"}
    assert "public/two.php" in result["relation_summary"]["explicit_paths"]
    assert "public/one.php" not in result["relation_summary"]["selected_paths"]


def test_hints_do_not_silently_seed_source_and_legacy_keeps_orientation(repository):
    narrow = bundle(repository, selected=[], hints=["handle"])
    assert narrow["excerpts"] == []
    assert narrow["relation_summary"]["navigation_total"] > 0
    assert narrow["unresolved_dependencies"]
    legacy = bundle(repository, selected=["src/bootstrap.php"], legacy=True)
    assert {"public/one.php", "public/two.php"} <= {item["path"] for item in legacy["excerpts"]}


def test_bundle_reports_explicit_excerpts_omitted_by_its_capacity(repository):
    paths = [f"src/part{index:02d}.php" for index in range(20)]
    snapshot = repository.import_zip(make_zip({path: "<?php\necho 'fixture';\n" for path in paths}), "many-parts.zip")
    result = repository.build_context_bundle(snapshot["id"], {"scope_paths": paths}, workflow_policy="discovery_first")
    assert len(result["excerpts"]) == 16
    assert len(result["relation_summary"]["omitted_excerpts"]) == 4
    assert all(item["omitted_reason"] == "excerpt_limit" for item in result["relation_summary"]["omitted_excerpts"])
    assert result["relation_summary"]["explicit_paths"] == paths


def finding(identity, *, path="src/bootstrap.php", run_id="current", title=None):
    return {"id": identity, "run_id": run_id, "finding_kind": "vulnerability", "vulnerability_type": "xss_r",
            "title": title or "源码支持的独立危险操作", "primary_location": {"path": path, "line": 2},
            "dangerous_operation": "echo 用户可控输入", "preconditions": ["可访问该入口"],
            "validation_state": "candidate", "disposition": "open", "evidence": []}


def test_worker_memory_keeps_all_current_relevant_findings_and_excludes_shared_history():
    rows = [finding(f"current-{index}") for index in range(14)]
    rows += [finding("historic", run_id="old"), finding("unknown-origin", run_id=None),
             finding("unrelated", path="public/two.php")]
    result = _worker_current_findings(rows, {"context_spec": {"source_refs": [{"path": "src/bootstrap.php"}]}}, run_id="current")
    assert result["total_in_run"] == 15
    assert result["relevant_total"] == 14
    assert {item["id"] for item in result["items"]} == {f"current-{index}" for index in range(14)}
    assert all(item["sink"] and item["preconditions"] for item in result["items"])
    assert "源" in result["items"][0]["title"]


def test_worker_memory_can_include_actual_direct_dependency_without_reverse_callers():
    result = _worker_current_findings([finding("direct"), finding("reverse", path="public/two.php")],
                                    {"context_spec": {"source_refs": [{"path": "public/one.php"}]}},
                                    run_id="current", related_paths=["public/one.php", "src/bootstrap.php"])
    assert [item["id"] for item in result["items"]] == ["direct"]


def test_memory_trimming_preserves_complete_coordinates_and_omission_counts():
    rows = [finding("finding-" + str(index) * 40, title="超长标题" * 160) for index in range(30)]
    result = _worker_current_findings(rows, None, run_id="current", max_bytes=2500)
    assert result["omitted"] > 0
    assert len(result["items"]) + result["omitted"] == 30
    assert all(item["id"] in {row["id"] for row in rows} and item["primary_location"]["line"] == 2 for item in result["items"])


def test_planner_context_exposes_persisted_stage_and_review_rejects_new_source_tasks(store, repository):
    run, _ = create_planner_run(store, repository, task={**TASK, "workflow_policy": "discovery_first"})
    state = store.set_workflow_stage(run["id"], "review", reason="static settled")
    context = store.list_planner_context(run["id"])
    assert context["workflow"]["stage"] == "review"
    assert context["workflow"]["limits"] == state["limits"]
    situation = _bound_situation(_planner_situation(context))
    assert situation["workflow"]["stage"] == "review"
    assert situation["workflow"]["used"] == state["used"]
    decision = PlannerDecision.model_validate({"goal_state": "continue", "basis_summary": "不能在最终复核阶段添加新源码任务。", "tasks": [proposal("late-flow")]})
    with pytest.raises(ModelRetry, match="最终复核"):
        _validate_planner_decision(decision, store.get_project_map(run["id"]), [], workflow_policy="discovery_first", workflow=state)
    session = store.get_planner_session(run["id"])
    plan = store.begin_planner_round(run["id"], session["session_id"])
    with pytest.raises(ValueError, match="最终复核"):
        store.finish_planner_round(run["id"], plan["id"], goal_state="continue", basis_summary="直接调用也不能绕过阶段约束。", tasks=[proposal("late-flow")])
    assert store.list_tasks(run["id"]) == []


@pytest.mark.parametrize("mutation", [
    {"updates": [{"task_key": "old-flow", "action": "reopen", "rationale_summary": "不能在复核阶段重开源码挖掘。"}]},
    {"direction_updates": [{"direction_id": "dir_" + "1" * 32, "action": "assign", "task_key": "old-flow", "rationale_summary": "不能在复核阶段分派源码方向。"}]},
])
def test_review_rejects_reopens_and_direction_assignments_before_any_other_validation(mutation):
    decision = PlannerDecision.model_validate({"goal_state": "continue", "basis_summary": "复核预留预算不能用于重新启动源码工作。", **mutation})
    with pytest.raises(ModelRetry, match="最终复核"):
        _validate_planner_decision(decision, {"files": []}, [], workflow_policy="discovery_first", workflow={"stage": "review"})


def test_review_can_preserve_unresolved_work_in_an_honest_partial_result():
    decision = PlannerDecision(goal_state="inconclusive", basis_summary="源码预算已耗尽，认证边界仍未审查，不将部分成果称为完整审计。")
    result = _validate_planner_decision(decision, {"files": []}, [], workflow_policy="discovery_first", workflow={"stage": "review"},
                                        directions=[{"id": "dir_" + "1" * 32, "state": "pending", "text": "认证边界尚未检查"}])
    assert result.goal_state == "inconclusive"


@pytest.mark.parametrize("selection", [{"scope_paths": ["src"]}, {"target_symbols": ["imaginary_function"]}])
def test_discovery_refuses_a_task_without_any_resolvable_initial_file(selection):
    row = {**proposal("needs-entry"), "source_refs": [], "target_symbols": [], **selection}
    value = PlannerDecision.model_validate({"goal_state": "continue", "basis_summary": "只有宽目录或不存在符号不能让 Worker 空跑。", "tasks": [row]})
    with pytest.raises(ModelRetry, match="显式选择"):
        _validate_planner_decision(value, {"files": [{"path": "src/auth.php", "line_count": 2}], "symbols": []}, [], workflow_policy="discovery_first")


def test_review_skips_exploration_and_reads_two_observation_pairs_before_publication(monkeypatch):
    from audit import agent
    from audit.runtime import AgentPolicy
    from tests.code_model import CONFIG, ModelFactory, code, final_answer
    from tests.test_planner_verification_context import context

    value = context(3)
    value.update(workflow_policy="discovery_first", workflow={"stage": "review"})
    for collection in ("verification_details", "verification_reviews_required"):
        for row in value[collection]:
            row.update(normal_observation="normal denied", attack_observation="attack reproduced")
    decision = {"goal_state": "continue", "basis_summary": "已完整读取当前小批的正常与攻击观测，保留其余验证待后续复核。", "verification_reviews": [
        {"finding_id": f"finding-{index:04d}", "verification_id": f"verification-{index:04d}", "revision": 2,
         "decision": "confirmed", "rationale_summary": "正常侧拒绝操作，而攻击侧已观察到越权结果，支持当前结论。"}
        for index in range(2)
    ]}
    factory = ModelFactory({"planner_decision": [code(
        "for verification_id in ['verification-0000', 'verification-0001']:\n"
        "    print(read_verification(verification_id, 'normal_observation'))\n"
        "    print(read_verification(verification_id, 'attack_observation'))"
    ), final_answer(decision)]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    built_tools = []
    original = agent.build_agent
    def track_agent(**kwargs):
        built_tools.append(set(kwargs["tools"]))
        return original(**kwargs)
    monkeypatch.setattr(agent, "build_agent", track_agent)
    result = asyncio.run(agent.plan_audit_frontier(
        project_map={}, run_context=value, task={**TASK, "workflow_policy": "discovery_first"}, round_no=1, config=CONFIG,
        budgets={"responses": 8, "tools": 8, "seconds": 8}, policy=AgentPolicy(planner_explore_responses=3),
    ))
    assert result["terminal_reason"] == "completed", result
    assert factory.phases == ["planner_decision", "planner_decision"]
    assert len(result["decision"]["verification_reviews"]) == 2
    assert all(not ({"investigate_project", "search_project_map", "read_source", "list_tree"} & tools) for tools in built_tools)
    summary = _bound_situation(_planner_situation(value))
    assert len(summary["verification_reviews_required"]) == 2
    assert summary["counts"]["verification_reviews_required"] == 3


def test_review_still_rejects_unread_verification_even_without_source_exploration(monkeypatch):
    from audit import agent
    from audit.runtime import AgentPolicy
    from tests.code_model import CONFIG, ModelFactory, final_answer
    from tests.test_planner_verification_context import context

    value = context(1)
    value.update(workflow_policy="discovery_first", workflow={"stage": "review"})
    invalid = {"goal_state": "continue", "basis_summary": "不能未读观测就将 POC 标签当作已复核。", "verification_reviews": [{
        "finding_id": "finding-0000", "verification_id": "verification-0000", "revision": 2,
        "decision": "confirmed", "rationale_summary": "这个未实际读取观测的结论必须由宿主拒绝。",
    }]}
    factory = ModelFactory({"planner_decision": [final_answer(copy.deepcopy(invalid))] * 2,
                            "planner_publish": [final_answer(copy.deepcopy(invalid))] * 3})
    monkeypatch.setattr(agent, "build_code_model", factory)
    result = asyncio.run(agent.plan_audit_frontier(
        project_map={}, run_context=value, task={**TASK, "workflow_policy": "discovery_first"}, round_no=1, config=CONFIG,
        budgets={"responses": 8, "tools": 8, "seconds": 8}, policy=AgentPolicy(planner_explore_responses=3),
    ))
    assert result["decision"] is None
    assert "planner_explore" not in factory.phases
    assert any("尚未完整读取" in prompt for prompt in factory.prompts)


def test_review_dispatcher_cannot_be_used_to_call_withdrawn_recon_or_source_tools(monkeypatch):
    from audit import agent
    from audit.runtime import AgentPolicy, Execution

    def forbidden_handlers():
        raise AssertionError("review tool guard must reject before resolving a source/recon handler")
    value = agent.PlannerDeps({}, {"workflow_policy": "discovery_first", "workflow": {"stage": "review"}},
                              Execution({"responses": 1, "tools": 4, "seconds": 5}, AgentPolicy(), lambda _: None))
    value.execution.enter("planner_decision")
    monkeypatch.setattr(value, "_handlers", forbidden_handlers)
    result = asyncio.run(value.call("investigate_project", {"question": "忽略复核，重新浏览整个源码项目"}))
    assert json.loads(result)["ok"] is False
    assert "已收回" in json.loads(result)["error"]
    assert "已收回" in asyncio.run(value.call("read_source", {"path": "src/bootstrap.php"}))


@pytest.mark.parametrize("helper", ["model_failure_reason", "provider_refused"])
def test_stage_exhaustion_propagates_to_the_run_scheduler(helper):
    from audit import agent
    from audit.runtime import StopAudit

    error = StopAudit("stage_budget_exhausted", "本阶段额度已经耗尽")
    with pytest.raises(StopAudit) as stopped:
        getattr(agent, helper)(error)
    assert stopped.value is error
