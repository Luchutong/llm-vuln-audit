"""What the Planner is told about how much of the project has actually been read.

Every Planner round now carries a host-computed coverage block, because the decision
between "dispatch another evidence direction" and "converge" needs one fact the durable
task summaries do not carry: which areas nobody has read yet.  Three properties keep it
safe, and each is pinned here: it counts only reads the host itself recorded, it stays a
bounded summary instead of a second copy of the project map, and the Planner always
receives it -- labelled -- even when there is nothing yet to report.
"""
from __future__ import annotations

import asyncio

import pytest

from audit import agent
from audit.config import ModelConfig
from audit.db import Store, now
from audit.runtime import AgentPolicy
from audit.source import SourceRepository
from tests.code_model import ModelFactory, final_answer
from tests.test_source import make_zip

CONFIG = ModelConfig(model="test", base_url="https://example.invalid", api_key="private-test-key")

TASK = {
    "objective": "追踪请求入口经过认证边界到文件读取的跨文件路径。",
    "success_criteria": "结论必须引用原始源码行号，或说明所有方向为何不可达。",
    "max_iterations": 2,
    "max_total_attempts": 12,
    "max_planner_rounds": 3,
    "max_workers": 2,
    "stop_on_achieved": True,
    "require_poc": False,
}

FILES = {
    "public/index.php": "<?php\nrequire '../src/auth.php';\nhandle($_GET['path'] ?? 'readme.txt');\n",
    "src/auth.php": "<?php\nfunction require_admin() { return isset($_SESSION['admin']); }\n",
    "src/files.php": "<?php\nfunction handle($path) {\n  readfile('/srv/uploads/' . $path);\n}\n",
    "vendor/lib/util.php": "<?php\nfunction vendor_util() { return true; }\n",
    "docs/readme.md": "# 项目说明\n",
}

# The exact shape of the block, so a later change cannot quietly grow it back into a
# whole-project structure.
COVERAGE_KEYS = {
    "files_total",
    "files_read",
    "files_with_findings",
    "coverage_ratio",
    "read_paths",
    "unread_hot_modules",
    "dependency_tree_total",
    "dependency_tree_read",
    "notice",
}


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path / "source-data")


def planner_run(store: Store, repository: SourceRepository, files: dict | None = None) -> tuple[dict, dict]:
    snapshot = repository.import_zip(make_zip(list((files or FILES).items())), "coverage.zip")
    store.add_snapshot(snapshot)
    store.create_run({
        "id": "coverage-run",
        "snapshot_id": snapshot["id"],
        "snapshot_name": snapshot["name"],
        "scope": [],
        "scope_mode": "snapshot",
        "prompt_id": "planner-v2",
        "prompt_label": "项目级 Planner",
        "prompt_text": "",
        "model": "test-model",
        "budgets": {"responses": 8, "tools": 16, "seconds": 30},
        "agent_policy": AgentPolicy().snapshot(),
        "task_spec": TASK,
        "created_at": now(),
    })
    project_map = repository.build_project_map(snapshot["id"], None)
    store.create_planner_session("coverage-run", "planner:coverage-run", TASK["max_planner_rounds"], project_map)
    run = store.claim_next_run()
    assert run is not None
    return run, project_map


def proposal(key: str, path: str, end: int) -> dict:
    return {
        "task_key": key,
        "title": f"{key} 跨文件审计方向",
        "objective": "从入口、认证检查与文件读取之间确认目标相关的可达路径。",
        "acceptance_criteria": "结论必须引用已读取的原始源码行号。",
        "rationale_summary": "冻结项目图显示入口 include 认证模块与文件处理模块。",
        "source_refs": [{"path": path, "start_line": 1, "end_line": end, "reason": "project_entry"}],
        "target_symbols": [],
        "dependencies": [],
        "query_hints": [],
        "priority": 80,
    }


def drain(store: Store, run: dict, payloads: dict[str, dict]) -> None:
    """Resolve every ready task with the outcome recorded for its ``task_key``.

    Two tasks at the same priority are claimed in whatever order the queue returns
    them, so the test resolves by key instead of assuming a dispatch order.
    """
    while True:
        claimed = store.claim_ready_task(run["id"], "worker-1")
        if claimed is None:
            return
        payload = payloads[claimed["task_key"]]
        store.resolve_task_attempt(
            claimed["id"], "worker-1", outcome=payload["outcome"], result=payload["result"],
            usage={"requests": 1, "tool_calls": 1, "input_tokens": 4, "output_tokens": 2},
            seen=payload["seen"],
        )


def test_coverage_counts_only_the_reads_the_host_recorded(store, repository):
    """Model prose cannot inflate coverage; the persisted ledger decides."""
    run, project_map = planner_run(store, repository)
    plan = store.begin_planner_round(run["id"], "planner:coverage-run")
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue", basis_summary="先读入口与文件读取方向。",
        next_action="读取入口与文件读取方向。",
        tasks=[proposal("entry", "public/index.php", 3), proposal("read", "src/files.php", 4)],
    )
    drain(store, run, {
        "entry": {
            "outcome": "no_evidence",
            "result": {"summary": "入口未直接形成结论。", "reasoning": "已检查入口源码。"},
            "seen": [
                {"path": "public/index.php", "start_line": 1, "end_line": 2},
                # Adjacent reads of the same file are one covered interval, and a path
                # the snapshot does not contain never counts toward the ratio.
                {"path": "public/index.php", "start_line": 3, "end_line": 3},
                {"path": "ghost/never-imported.php", "start_line": 1, "end_line": 4},
            ],
        },
        "read": {
            "outcome": "achieved",
            "result": {
                "summary": "文件读取未校验路径。", "reasoning": "handle 直接把请求参数拼进路径。",
                "findings": [{
                    "title": "路径未做校验即进入 readfile", "kind": "vulnerability",
                    "summary": "handle($path) 直接拼接用户输入后调用 readfile。",
                    "evidence": "src/files.php:2-4；另见 `src/auth.php:2`（认证边界）",
                }],
            },
            "seen": [{"path": "src/files.php", "start_line": 1, "end_line": 5}],
        },
    })

    coverage = store.planner_coverage(run["id"])
    assert set(coverage) == COVERAGE_KEYS
    assert coverage["files_total"] == len(project_map["files"])
    assert coverage["files_read"] == 2
    assert coverage["coverage_ratio"] == round(2 / len(project_map["files"]), 4)
    assert coverage["read_paths"] == ["public/index.php", "src/files.php"]
    # Both cited paths are real snapshot files, so both count; the citation is a flat
    # string, so this is what proves the citations are parsed rather than assumed.
    assert coverage["files_with_findings"] == 2
    assert coverage["dependency_tree_total"] == 1
    assert coverage["dependency_tree_read"] == 0
    assert "不是安全结论" in coverage["notice"]


def test_coverage_points_at_unread_first_party_modules_only(store, repository):
    """``vendor`` would otherwise dominate "unread" and say nothing about the project."""
    run, _project_map = planner_run(store, repository)
    plan = store.begin_planner_round(run["id"], "planner:coverage-run")
    store.finish_planner_round(
        run["id"], plan["id"], goal_state="continue", basis_summary="先读入口方向。",
        next_action="读取入口方向。",
        tasks=[proposal("entry", "public/index.php", 3)],
    )
    drain(store, run, {
        "entry": {
            "outcome": "no_evidence",
            "result": {"summary": "入口未直接形成结论。", "reasoning": "已检查入口源码。"},
            "seen": [{"path": "public/index.php", "start_line": 1, "end_line": 3}],
        },
    })

    coverage = store.planner_coverage(run["id"])
    modules = {item["module"]: item for item in coverage["unread_hot_modules"]}
    assert "public" not in modules  # read
    assert modules["src"] == {"module": "src", "unread": 2, "total": 2}
    assert modules["docs"] == {"module": "docs", "unread": 1, "total": 1}
    assert "vendor" not in modules
    # Largest unread module first, so the Planner's attention lands on the big gap.
    assert coverage["unread_hot_modules"][0]["module"] == "src"


def test_coverage_stays_bounded_on_a_large_project(store, repository):
    """The block rides in every round's prompt, so it can never echo the whole map."""
    files = {f"pkg{index:02d}/module{index:02d}.php": f"<?php function f{index}() {{ return {index}; }}\n"
             for index in range(60)}
    run, _project_map = planner_run(store, repository, files=files)
    coverage = store.planner_coverage(run["id"])

    assert coverage["files_total"] == 60
    assert coverage["files_read"] == 0
    assert coverage["read_paths"] == []
    assert coverage["coverage_ratio"] == 0.0
    assert len(coverage["unread_hot_modules"]) == 12
    assert all(item["unread"] == 1 for item in coverage["unread_hot_modules"])
    # Every module is unread and equally large, so the order has to be deterministic
    # rather than whatever the map happened to iterate first.
    assert [item["module"] for item in coverage["unread_hot_modules"]] == sorted(
        f"pkg{index:02d}" for index in range(12)
    )
    assert str(40) in coverage["notice"]


def test_list_planner_context_carries_coverage_outside_the_project_map(store, repository):
    run, project_map = planner_run(store, repository)
    context = store.list_planner_context(run["id"])

    assert context["coverage"]["files_total"] == len(project_map["files"])
    # The whole map is passed to the Planner as a separate argument; duplicating it in
    # the durable context is exactly what the coverage block exists to avoid.
    assert "project_map" not in context


def decision_payload(tasks=None) -> dict:
    return {
        "goal_state": "continue",
        "basis_summary": "覆盖统计显示 src 模块无人读过。",
        "next_action": "派发覆盖 src 的证据方向。",
        "missing_context": [],
        "tasks": tasks or [{
            "task_key": "src-read",
            "title": "src 目录的读取路径",
            "objective": "读取 src 下的文件，确认请求数据如何到达 readfile。",
            "acceptance_criteria": "worker 引用原始行号。",
            "rationale_summary": "覆盖统计显示 src 未被读过。",
            "source_refs": [{"path": "src/files.php", "start_line": 1, "end_line": 4, "reason": "sink"}],
            "scope_paths": [],
            "target_symbols": ["handle"],
            "dependencies": [],
            "query_hints": ["readfile"],
            "priority": 80,
        }],
        "updates": [],
    }


def run_round(monkeypatch, project_map, run_context, prompts, budgets=None):
    """One round whose model has nothing to look up: it hands the decision straight back.

    The script is written for the decision phase only.  With a budget this small the
    round has no exploration allowance to spend, which is the other half of what these
    tests are about -- the coverage block has to reach the phase that actually runs.
    """
    factory = ModelFactory({"planner_decision": [final_answer(decision_payload())]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=project_map,
        run_context=run_context,
        task={"objective": TASK["objective"], "success_criteria": TASK["success_criteria"]},
        round_no=2,
        config=CONFIG,
        budgets=budgets or {"responses": 4, "tools": 4, "seconds": 8},
        policy=AgentPolicy(request_seconds=0.5),
        on_event=events.append,
    ))
    prompts.extend(factory.prompts)
    return result, events


def test_planner_round_is_handed_the_coverage_block_and_reports_it(monkeypatch, store, repository):
    run, project_map = planner_run(store, repository)
    prompts: list[str] = []
    result, events = run_round(monkeypatch, project_map, store.list_planner_context(run["id"]), prompts)

    assert result["decision"] is not None, result
    assert prompts and all("# 覆盖统计（宿主计算，不是证据）" in text for text in prompts)
    assert '"unread_hot_modules"' in prompts[0]

    prepared = [event for event in events if event["kind"] == "planner_coverage_prepared"]
    assert [event["round"] for event in prepared] == [2]
    # The event is what lets a reviewer tell "the Planner ignored the coverage" apart
    # from "the host never had any" -- so it must carry the numbers, not a flag.
    assert prepared[0]["coverage"]["files_total"] == len(project_map["files"])
    assert prepared[0]["coverage"]["files_read"] == 0


def test_a_one_response_round_spends_it_on_the_decision_and_still_sees_coverage(monkeypatch, store, repository):
    """With one response to spend, the host spends it on the decision, not on exploring.

    The whole round is a single request, so the coverage block has to be in it: a block
    that only reached the exploration phase would be invisible to exactly the rounds
    that have no room to look anything up.
    """
    run, project_map = planner_run(store, repository)
    prompts: list[str] = []
    result, events = run_round(
        monkeypatch, project_map, store.list_planner_context(run["id"]), prompts,
        budgets={"responses": 1, "tools": 4, "seconds": 8},
    )

    assert result["decision"] is not None, result
    assert len(prompts) == 1
    assert "# 覆盖统计（宿主计算，不是证据）" in prompts[0]
    # The reserved request is the decision one: the tool phase never opened.
    phases = [event["phase"] for event in events if event["kind"] == "agent_phase"]
    assert phases == ["planner_prepare", "planner_decision"]
    assert "本轮探索阶段已经结束" in prompts[0]


def test_a_run_without_coverage_says_so_instead_of_dropping_the_block(monkeypatch, store, repository):
    run, project_map = planner_run(store, repository)
    prompts: list[str] = []
    result, events = run_round(monkeypatch, project_map, {"goal": {}, "tasks": [], "plans": []}, prompts)

    assert result["decision"] is not None, result
    assert "# 覆盖统计（宿主计算，不是证据）" in prompts[0]
    # The instruction text refers to the block by name, so an empty block must say it is
    # empty rather than let the Planner read a rule about a section it cannot see.
    assert "没有可用的覆盖统计" in prompts[0]
    prepared = [event for event in events if event["kind"] == "planner_coverage_prepared"]
    assert prepared and prepared[0]["coverage"]["files_read"] == 0

