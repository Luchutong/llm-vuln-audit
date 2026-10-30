"""The recorded POC is executed once by the host before the model plans anything.

The audit already produces an executable check; making the verifying agent re-derive it
from the source every time spent most of an item's wall clock on that rewrite.  These
tests pin down which recorded scripts the runner can execute unchanged and that the
pre-run stays inside the ordinary tool/identity/job gates.
"""
import asyncio
import json

import pytest

from audit.poc_agent import run_stored_poc, stored_poc_preflight, stored_poc_script
from tests.test_poc_agent import FINDING, FakeClient, deps


RUNNABLE = {
    "filename": "check.py",
    "language": "python",
    "script": "import os, urllib.request\nBASE = os.environ['LAB30_URL'].rstrip('/')\n"
              "print(BASE)\nprint(os.environ['LAB30_USER'])\n",
}


def finding_with(poc):
    return {**FINDING, "poc": poc}


@pytest.mark.parametrize("poc,reason", [
    (RUNNABLE, ""),
    ({"filename": "x.php", "language": "php", "script": "<?php echo getenv('LAB30_URL');"}, ""),
    ({"filename": "x.sh", "language": "bash", "script": "curl -s http://TARGET/"}, "unsupported_language"),
    ({"filename": "x.py", "language": "python", "script": "print(os.environ['LAB30_PASSWORD'])"}, ""),
    ({"filename": "x.py", "language": "python"}, "no_script"),
    ({"filename": "x.py", "language": "python", "script": "import requests\nprint(1)"}, "third_party_import"),
    ({"filename": "x.py", "language": "python", "script": "B='http://TARGET'\nprint(B)"}, "unresolved_placeholder"),
    ({"filename": "x.py", "language": "python", "script": "print('<sid>')"}, "unresolved_placeholder"),
    ({"filename": "x.py", "language": "python", "script": "s.post(u, data={'username':'USER'})"}, "unresolved_placeholder"),
    ({"filename": "x.php", "language": "php", "script": "echo 1;"}, "invalid_php"),
])
def test_only_runner_executable_scripts_are_selected(poc, reason):
    selected, skip_reason = stored_poc_script(finding_with(poc))
    assert skip_reason == reason
    assert (selected is None) == bool(reason)
    if selected:
        assert selected["language"] == poc["language"] and selected["script"] == poc["script"]


def test_free_text_poc_and_missing_poc_are_not_scripts():
    assert stored_poc_script({**FINDING, "poc": "id=1' OR '1'='1"}) == (None, "no_script")
    assert stored_poc_script({**FINDING, "poc": None}) == (None, "no_script")


@pytest.mark.parametrize("policy,expected", [
    ({"runtime": "claude_sdk", "session_policy": "session-queue-v1"}, True),
    ({"runtime": "claude_sdk"}, False),
    ({"runtime": "legacy", "session_policy": "session-queue-v1"}, False),
    ({}, False),
])
def test_preflight_is_limited_to_the_new_queue_runtime(policy, expected):
    assert stored_poc_preflight(policy) is expected


def test_recorded_poc_runs_once_through_the_normal_job_gates():
    client = FakeClient()
    service = deps(client)
    events = []
    reply = asyncio.run(run_stored_poc(finding_with(RUNNABLE), service, events.append))
    assert len(client.jobs) == 1
    assert client.jobs[0]["language"] == "python" and client.jobs[0]["script"] == RUNNABLE["script"]
    assert json.loads(reply)["job_id"] == "job-1"
    assert [event["kind"] for event in events] == ["poc_stored_poc_executed"]
    assert len(service.jobs) == 1 and service.scripts == [RUNNABLE["script"]]


def test_unrunnable_recorded_poc_submits_nothing_and_says_why():
    client = FakeClient()
    service = deps(client)
    events = []
    reply = asyncio.run(run_stored_poc(
        finding_with({"filename": "sqli_catalog.sh", "language": "bash",
                      "script": "curl -s 'http://TARGET/catalog/index.php?q=1'"}), service, events.append))
    assert reply == "" and client.jobs == []
    assert events == [{"kind": "poc_stored_poc_skipped", "finding_id": FINDING["id"],
                       "filename": "sqli_catalog.sh", "reason": "unsupported_language"}]
