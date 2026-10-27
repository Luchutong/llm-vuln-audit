"""The context and output budgets are configuration, and bad configuration is fatal.

Every limit used to be a literal in a frozen dataclass.  These tests pin the replacement:
environment parsing with a bounded range, a startup failure instead of a silent fallback,
and a snapshot that both the run record and ``/api/config`` can carry so a live process
never enforces a number it did not publish.
"""
import pytest

from audit.context_config import env_flag, env_int
from audit.runtime import AgentPolicy, policy_from_snapshot


def test_an_unset_variable_keeps_the_default():
    assert env_int("AUDIT_TEST_UNSET", 7, 1, 9, environ={}) == 7
    assert env_flag("AUDIT_TEST_UNSET", True, environ={}) is True
    assert env_flag("AUDIT_TEST_UNSET", False, environ={}) is False


def test_a_valid_value_is_parsed_and_whitespace_is_ignored():
    assert env_int("AUDIT_HISTORY_BYTES", 1, 1, 10, environ={"AUDIT_HISTORY_BYTES": " 8 "}) == 8
    assert env_flag("AUDIT_HISTORY_SUMMARY", False, environ={"AUDIT_HISTORY_SUMMARY": "ON"}) is True
    assert env_flag("AUDIT_HISTORY_SUMMARY", True, environ={"AUDIT_HISTORY_SUMMARY": "0"}) is False


@pytest.mark.parametrize("raw", ["0", "11", "-1", "1e3"])
def test_an_out_of_range_integer_is_a_startup_failure(raw: str):
    with pytest.raises(RuntimeError):
        env_int("AUDIT_HISTORY_BYTES", 1, 1, 10, environ={"AUDIT_HISTORY_BYTES": raw})


def test_a_non_integer_is_a_startup_failure_not_a_fallback():
    with pytest.raises(RuntimeError) as failure:
        env_int("AUDIT_HISTORY_BYTES", 4096, 1024, 8192, environ={"AUDIT_HISTORY_BYTES": "lots"})
    assert "AUDIT_HISTORY_BYTES" in str(failure.value)


def test_an_unrecognised_boolean_is_a_startup_failure():
    with pytest.raises(RuntimeError):
        env_flag("AUDIT_HISTORY_SUMMARY", True, environ={"AUDIT_HISTORY_SUMMARY": "maybe"})


def test_the_defaults_are_the_documented_context_budget():
    policy = AgentPolicy()

    assert policy.history_bytes == 384 * 1024
    assert policy.history_summary is True
    assert policy.history_trigger_ratio < 1.0
    assert policy.history_target_ratio < policy.history_trigger_ratio
    assert policy.history_summary_bytes < policy.history_bytes
    assert policy.planner_pinned_bytes < policy.planner_pinned_hard_bytes
    assert policy.worker_max_tokens > 0 and policy.poc_max_tokens > 0


def test_the_snapshot_round_trips_through_a_stored_run_policy():
    stored = AgentPolicy(history_bytes=65536, history_summary=False).snapshot()
    rebuilt = policy_from_snapshot(stored)

    assert rebuilt.history_bytes == 65536 and rebuilt.history_summary is False
    # A run written by an older build may carry fields this build does not know.
    assert policy_from_snapshot({**stored, "retired_field": 1}).history_bytes == 65536


def test_the_execution_context_stats_start_from_the_policy():
    from audit.runtime import Execution

    events = []
    execution = Execution({"responses": 1, "tools": 1, "seconds": 60},
                          AgentPolicy(history_bytes=8192), events.append)
    context = execution.snapshot()["context"]

    assert context["history_bytes"] == 8192
    assert context["summary_requests"] == 0
    assert context["limit_hits"] == 0 and context["sources"] == {}
