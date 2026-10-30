"""Bounded white-box source context: initial window, read tool and its limits."""
import asyncio
import io
import json
import zipfile
from types import SimpleNamespace

import pytest

from audit.config import PocSettings
from audit.poc import PocPolicy, PocVerifier
from audit.poc_agent import PocDeps, execute_instructions, execute_prompt, source_block
from audit.poc_source import PROGRESS_POLICY, PocSourceProvider, SourceLimits, progress_policy_snapshot
from audit.source import SourceRepository


def make_zip(files):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, content in files:
            archive.writestr(path, content)
    return target.getvalue()


def php_file(name, lines=40):
    body = [f"<?php // {name} line {number}" for number in range(1, lines + 1)]
    body[1] = "<?php require __DIR__ . '/../../src/bootstrap.php';"
    return "\n".join(body) + "\n"


FINDING = {
    "id": "finding-1",
    "file_path": "app/public/account/update.php",
    "primary_location": {"path": "app/public/account/update.php", "line": 4},
    "evidence": [
        {"path": "app/public/account/update.php", "start_line": 2, "end_line": 6},
        {"path": "app/src/bootstrap.php", "start_line": 33, "end_line": 36},
    ],
}


@pytest.fixture
def repository(tmp_path):
    repo = SourceRepository(tmp_path)
    snapshot = repo.import_zip(make_zip([
        ("app/public/account/update.php", php_file("update")),
        ("app/src/bootstrap.php", php_file("bootstrap")),
    ]), "lab30-shop-1.0.0-source.zip")
    return repo, snapshot["id"]


def provider(repository, *, finding=FINDING, target="lab30-shop-1.0.0", limits=None, snapshot_id=None):
    repo, snapshot_id = repository if snapshot_id is None else (repository[0], snapshot_id)
    return PocSourceProvider(repo, snapshot_id, finding=finding, target_version=target, limits=limits)


def test_initial_window_keeps_original_line_numbers_and_evidence_files(repository):
    context = provider(repository).initial_context()
    assert context["available"] is True
    assert context["applicability"] == "match"
    assert context["archive_version"] == "1.0.0"
    assert [item["path"] for item in context["files"]] == [
        "app/public/account/update.php", "app/src/bootstrap.php",
    ]
    update = context["files"][0]
    numbers = [line["number"] for line in update["lines"]]
    # The primary sink line 4 and the evidence range 2-6 plus context are present, and
    # every number is the original one (no renumbering of the excerpt).
    assert numbers == list(range(1, 27))
    assert any(line["text"].startswith("<?php require") for line in update["lines"] if line["number"] == 2)
    bootstrap = context["files"][1]
    assert [line["number"] for line in bootstrap["lines"]] == list(range(13, 41))
    assert context["bytes"] <= SourceLimits().initial_bytes


def test_initial_window_is_byte_bounded_and_says_what_it_omitted(repository):
    context = provider(repository, limits=SourceLimits(initial_bytes=600)).initial_context()
    assert context["bytes"] <= 600
    assert context["truncated"] is True
    assert context["omitted_ranges"] >= 1 or any(
        item["ranges"] and item["ranges"][-1]["truncated"] for item in context["files"]
    )


def test_initial_window_limits_file_count(repository):
    finding = {
        "id": "many",
        "evidence": [
            {"path": "app/public/account/update.php", "start_line": number, "end_line": number}
            for number in range(1, 7)
        ] + [
            {"path": "app/src/bootstrap.php", "start_line": 1, "end_line": 2},
        ],
    }
    context = provider(repository, finding=finding, limits=SourceLimits(initial_files=1)).initial_context()
    assert len(context["files"]) == 1
    assert context["omitted_files"] >= 1


def test_missing_snapshot_reports_source_unavailable_instead_of_guessing(repository):
    source = provider(repository, snapshot_id="")
    assert source.available is False
    context = source.initial_context()
    assert context["available"] is False and context["reason"] == "missing_snapshot"
    reply = source.read("app/public/account/update.php", 1, 5)
    assert reply["error"] == "source_unavailable"


def test_a_different_zip_is_not_read_for_the_same_project(tmp_path):
    repo = SourceRepository(tmp_path)
    first = repo.import_zip(make_zip([("app/a.php", php_file("a", 10))]), "shop-1.0.0.zip")
    second = repo.import_zip(make_zip([("app/b.php", php_file("b", 10))]), "shop-1.0.1.zip")
    source = PocSourceProvider(repo, first["id"], finding={"evidence": [{"path": "app/a.php", "start_line": 1, "end_line": 2}]},
                               target_version="shop-1.0.0")
    assert source.read("app/b.php", 1, 5)["reason"] == "file_not_in_snapshot"
    other = PocSourceProvider(repo, second["id"], finding={"evidence": [{"path": "app/b.php", "start_line": 1, "end_line": 2}]},
                              target_version="shop-1.0.0")
    assert other.initial_context()["applicability"] == "mismatch"


def test_version_applicability_is_unknown_without_a_target_version(repository):
    context = provider(repository, target="").initial_context()
    assert context["applicability"] == "unknown"


def test_read_returns_original_lines_and_records_the_range(repository):
    source = provider(repository)
    reply = source.read("app/public/account/update.php", 3, 8)
    assert reply["ok"] is True
    assert [line["number"] for line in reply["lines"]] == [3, 4, 5, 6, 7, 8]
    assert reply["end_line"] == 8
    assert reply["reads_remaining"] == source.limits.read_calls - 1
    record = source.snapshot()
    assert record["read_calls"] == 1
    assert record["reads"] == [{"path": "app/public/account/update.php", "start_line": 3, "end_line": 8,
                                "bytes": record["reads"][0]["bytes"]}]
    assert "line 3" not in json.dumps(record)  # the record names ranges, not source text


@pytest.mark.parametrize("start,end", [(0, 5), (5, 4), (1, 201), (True, 5), (1, False)])
def test_read_rejects_invalid_ranges_before_reading(repository, start, end):
    source = provider(repository)
    reply = source.read("app/public/account/update.php", start, end)
    assert reply["ok"] is False and reply["error"] == "invalid_range"
    assert source.calls == 0


def test_read_rejects_non_positive_and_host_paths(repository):
    source = provider(repository)
    for path in ("../etc/passwd", "/etc/passwd", "app/../../secret", "", None):
        reply = source.read(path, 1, 5)
        assert reply["ok"] is False
        assert reply["error"] in {"invalid_path", "source_unavailable"}
    assert source.calls == 0


def test_read_budget_is_enforced_and_reported(repository):
    source = provider(repository, limits=SourceLimits(read_calls=1))
    assert source.read("app/public/account/update.php", 1, 5)["ok"] is True
    reply = source.read("app/public/account/update.php", 6, 10)
    assert reply["error"] == "source_read_budget_exhausted"
    assert reply["reads_remaining"] == 0


def test_read_is_bounded_to_the_tool_byte_cap(tmp_path):
    long_lines = "\n".join("<?php // " + "x" * 400 + f" {number}" for number in range(1, 80))
    repo = SourceRepository(tmp_path)
    snapshot = repo.import_zip(make_zip([("long.php", long_lines)]), "long-1.0.0.zip")
    source = PocSourceProvider(repo, snapshot["id"],
                               finding={"evidence": [{"path": "long.php", "start_line": 1, "end_line": 1}]},
                               limits=SourceLimits(read_bytes=4096))
    reply = source.read("long.php", 1, 80)
    assert reply["ok"] is True and reply["truncated"] is True
    assert reply["next_start"] == reply["end_line"] + 1


def _deps(source):
    return PocDeps(client=SimpleNamespace(), policy=PocPolicy().snapshot(), target="lab30",
                   finding=FINDING, source=source)


def test_tool_reads_through_the_host_bound_snapshot(repository):
    deps = _deps(provider(repository))
    text = asyncio.run(deps._read_verification_source({"path": "app/public/account/update.php",
                                                      "start_line": 1, "end_line": 4}))
    reply = json.loads(text)
    assert reply["ok"] is True
    assert reply["snapshot_id"] == repository[1]
    assert [line["number"] for line in reply["lines"]] == [1, 2, 3, 4]


def test_tool_reports_policy_disabled_without_a_provider():
    reply = json.loads(asyncio.run(_deps(None)._read_verification_source({"path": "app/a.php"})))
    assert reply["error"] == "source_unavailable"
    assert reply["reason"] == "policy_disabled"


def test_prompts_carry_the_source_window_only_for_the_new_policy(repository):
    deps = _deps(provider(repository))
    assert "# 源码窗口" in execute_prompt(FINDING, deps, PocPolicy().snapshot())
    assert "app/public/account/update.php" in source_block(deps)
    assert "read_verification_source" in execute_instructions(deps)
    legacy = _deps(None)
    assert source_block(legacy) == ""
    assert "# 源码窗口" not in execute_prompt(FINDING, legacy, PocPolicy().snapshot())


def test_policy_freezes_and_round_trips_the_progress_contract():
    run = {"poc_policy": {"enabled": True, "progress_policy": PROGRESS_POLICY,
                          "progress_params": progress_policy_snapshot()}}
    policy = PocPolicy.from_run(run, SimpleNamespace(poc=PocSettings(enabled=True)))
    assert policy.source_context is True
    assert policy.progress_params["initial_bytes"] == 24 * 1024
    snapshot = policy.snapshot()
    assert snapshot["progress_policy"] == PROGRESS_POLICY
    assert snapshot["progress_params"]["read_calls"] == 12
    historical = PocPolicy.from_run({"poc_policy": {"enabled": True}}, SimpleNamespace(poc=PocSettings(enabled=True)))
    assert historical.source_context is False
    assert "progress_policy" not in historical.snapshot()


def test_unknown_progress_policy_never_enables_the_window():
    policy = PocPolicy.from_run({"poc_policy": {"progress_policy": "future-v9"}},
                                SimpleNamespace(poc=PocSettings()))
    assert policy.source_context is False


def test_verifier_requires_a_repository_before_offering_source(repository, tmp_path):
    settings = SimpleNamespace(poc=PocSettings(enabled=True), evidence_dir=tmp_path)
    policy = PocPolicy(enabled=True, progress_policy=PROGRESS_POLICY, progress_params=progress_policy_snapshot())
    without = PocVerifier(store=SimpleNamespace(), bus=SimpleNamespace(), settings=settings)
    assert without._source_provider({"snapshot_id": repository[1]}, FINDING, policy, {}) is None
    with_repo = PocVerifier(store=SimpleNamespace(), bus=SimpleNamespace(), settings=settings,
                            repository=repository[0])
    source = with_repo._source_provider({"snapshot_id": repository[1]}, FINDING, policy,
                                        {"version": "lab30-shop-1.0.0"})
    assert source is not None and source.applicability == "match"
    legacy = with_repo._source_provider({"snapshot_id": repository[1]}, FINDING, PocPolicy(), {})
    assert legacy is None
