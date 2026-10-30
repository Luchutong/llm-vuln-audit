"""One POC accounting object feeds the page, the JSON export and the Markdown report.

The five kinds of fact — host liveness, model requests, model generation, experiment
outcomes and the formal conclusion — are not substitutes for one another. A report that
printed only "heartbeat is recent" would look identical whether the model was generating
or had stalled, and a report that folded carried-over results into this round's output
would claim work the run did not do.
"""
import json

from audit.metrics import summarise
from audit.report import _poc_statistics_section, render_json, render_markdown

RUN = {
    "id": "p" * 32,
    "snapshot_id": "s" * 32,
    "snapshot_name": "lab30.zip",
    "scope": ["index.php"],
    "prompt_id": "P0",
    "prompt_label": "P0 初始版",
    "prompt_text": "# 一、审计角色\n\n四段式提示词全文。",
    "model": "test-model",
    "budgets": {"responses": 8, "tools": 16, "seconds": 300},
    "status": "completed",
    "created_at": "2026-01-01T00:00:00+00:00",
    "started_at": "2026-01-01T00:00:00+00:00",
    "finished_at": "2026-01-01T00:10:00+00:00",
    "error": None,
    "usage": {"requests": 12, "tool_calls": 9, "input_tokens": 1000, "output_tokens": 200},
    "project_id": "proj-1",
    "project_mode": "project",
    "poc_policy": {"target": "lab30", "job_seconds": 30, "max_jobs": 8, "mode": "required"},
    "task_spec": {
        "objective": "审计 lab30 的越权面。",
        "success_criteria": "保存一条带原始行号的结论。",
        "max_iterations": 2,
        "max_total_attempts": 8,
        "max_workers": 2,
        "max_planner_rounds": 3,
        "stop_on_achieved": True,
        "require_poc": True,
    },
}

STATS = {
    "version": "poc-statistics-v1",
    "run_status": "completed",
    "host": {
        "last_heartbeat_at": "2026-01-01T00:09:00+00:00",
        "heartbeat_age_seconds": 12.0,
        "current_item_seconds": 12.0,
        "soft_limit_exceeded": False,
        "note": "心跳只说明宿主仍在运行，不代表模型有新进展。",
    },
    "model": {
        "streams": 4, "aborted": 1, "last_abort_code": "stream_timeout",
        "event_types": {"content_block_delta": 40, "ping": 6},
        "content_events": 40, "received_bytes": 8192,
        "last_elapsed_seconds": 31.0, "first_event_seconds": 1.2,
        "usage": {"output_tokens": 512},
        "waiting_seconds": 3.5,
        "note": "HTTP 200 只表示响应头已到；ping/keepalive 不计入进展。",
    },
    "generation": {"text_chars": 900, "thinking_chars": 0, "tool_arg_chars": 120,
                   "note": "仅计数，不保存生成内容。"},
    "experiments": {
        "jobs": 3, "duration_ms": 90000, "observations": 5,
        "last_at": "2026-01-01T00:08:00+00:00", "since_last_seconds": 60.0,
        "checkpoints": 2, "duplicates": 1, "supplements": 1,
    },
    "conclusion": {
        "published": 2, "verdicts": {"confirmed": 1, "rejected": 1},
        "unpublished_reason": "已完成 3 个实验，尚未调用 publish_verification。",
    },
    "recovery": {"started": 1, "published": 1, "failed": 0, "skipped": 0, "requests": 2},
    "continuation": {
        "inherited": 3, "retested": 1,
        "inherited_status": {"verified": 3},
        "current_status": {"verified": 2},
        "parent_run_id": "a" * 32, "root_run_id": "a" * 32,
        "note": "沿用项不构成本轮成果。",
    },
    "unfinished": [{"finding_id": "f9", "title": "订单越权", "state": "deferred",
                    "reason": "未执行，等待追加预算"}],
    "unfinished_total": 1,
}


def bundle(stats=None):
    run = dict(RUN)
    run["execution_summary"] = {"poc_statistics": STATS if stats is None else stats}
    return {
        "run": run,
        "units": [],
        "findings": [],
        "attributions": [],
        "metrics": summarise(RUN, [], [], []),
        "snapshot": {"id": RUN["snapshot_id"], "name": "lab30.zip", "files": [], "warnings": []},
        "truths": [],
        "prompts": [],
        "rounds": {},
        "generated_at": "2026-01-01T00:10:00+00:00",
        "version": "test",
        "planner": {"max_rounds": 3},
        "plans": [],
        "tasks": [],
        "project_map": {"stats": {}},
        "report_narrative": {},
        "carried_findings": [],
        "verification_jobs": [],
    }


def test_a_run_without_poc_statistics_gets_no_section():
    # POC off or a legacy run never measured these facts; an empty table would read as
    # "measured and zero", which is a different claim.
    assert _poc_statistics_section({}) == []
    assert _poc_statistics_section({"execution_summary": {"poc_statistics": None}}) == []


def test_the_five_kinds_of_fact_stay_in_separate_rows():
    text = "\n".join(_poc_statistics_section(bundle()["run"]))
    assert "### POC 统计" in text
    for row in ("| 模型请求 |", "| 实验作业 |", "| 发布 |", "| 宿主心跳 |"):
        assert row in text
    # Host liveness is stated as liveness only, never as evidence of generation.
    assert "心跳不代表模型有进展" in text
    assert "4 次结束，其中中断 1 次" in text
    assert "3 次，累计 90 秒" in text
    # Generation counters are not a substitute for the conclusion.
    assert "已发布 2 项；结论 confirmed 1、rejected 1" in text


def test_carried_results_are_not_reported_as_this_rounds_output():
    text = "\n".join(_poc_statistics_section(bundle()["run"]))
    assert "沿用 3 项（不构成本轮成果）" in text
    assert "本轮新增 2 项，其中复测 1 项" in text


def test_unpublished_reason_and_unfinished_items_are_printed():
    text = "\n".join(_poc_statistics_section(bundle()["run"]))
    assert "尚未调用 publish_verification" in text
    assert "未完成 1 项" in text and "订单越权" in text and "等待追加预算" in text


def test_page_json_and_markdown_read_the_same_object():
    made = bundle()
    markdown = render_markdown(made)
    assert "### POC 统计" in markdown
    exported = json.loads(render_json(made))
    # The JSON export must carry the very object the page reads, not a re-derivation.
    assert exported["run"]["execution_summary"]["poc_statistics"] == STATS
