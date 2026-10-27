"""The report has to say which phase approached the request ceiling, not just that one did.

The ceiling is imposed by the host (serialized request bytes), not by the provider, so a
run that stopped near it needs a readable record: per-phase peak, how many summaries it
cost to stay under, and where — if anywhere — the limit was actually hit.
"""
from audit.report import _context_section


def run(context):
    return {"execution_summary": {"context": context}}


def test_no_recorded_context_means_no_section():
    # Legacy runs never wrote these stats; inventing an empty table would imply they were
    # measured and stayed at zero.
    assert _context_section({}) == []
    assert _context_section({"execution_summary": {"context": {}}}) == []


def test_each_phase_reports_its_own_peak_and_summary_cost():
    text = "\n".join(_context_section(run({
        "history_bytes": 393216, "peak_request_bytes": 300000, "summary_requests": 2,
        "compactions": 1, "dropped_groups": 3, "limit_hits": 0, "sources": {},
        "phases": {
            "task_execute": {"peak_request_bytes": 300000, "requests": 12,
                             "summary_requests": 2, "limit_hits": 0},
        },
    })))
    assert "### 上下文控制" in text
    assert "字节不等于 token" in text
    assert "| 源码审计 | 293.0 KiB | 76% | 12 | 2 | 0 |" in text
    assert "摘要请求 2 次、压缩 1 次、丢弃最旧步骤组 3 组" in text


def test_a_limit_hit_names_the_source_and_prints_the_aggregate_row():
    text = "\n".join(_context_section(run({
        "history_bytes": 65536, "peak_request_bytes": 70000, "summary_requests": 0,
        "limit_hits": 1, "sources": {"source_ledger": 1},
    })))
    assert "| 全部阶段 | 68.4 KiB | — | — | 0 | 1 |" in text
    assert "已读源码账本超过上限 1 次" in text
