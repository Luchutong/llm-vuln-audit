"""The LFI replay keeps a recorded response difference a difference.

The investigated run saw 1381 characters normally, 1242 for a traversal to a missing
path, and 1052 (no footer) for a traversal to an existing out-of-directory PHP file.
Those facts support "the responses differ"; they do not establish arbitrary file read or
RCE.  The tool also has to be safe to keep: no bodies, cookies, hosts or user data.
"""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "scripts/replay_lfi_evidence.py"
spec = importlib.util.spec_from_file_location("replay_lfi", PATH)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)

FIXTURE = ROOT / "backend/tests/fixtures/lfi-replay-lab30.json"


def observations():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["observations"]


def observed(path, chars, *, footer=True, diagnostics=None, status=200):
    return {
        "kind": "http", "path": path, "status": status, "body_chars": chars,
        "has_footer": footer, "title": "内容中心 · 拾光商城", "error_recorded": False,
        "diagnostics": diagnostics or {"status": "not_recorded"},
    }


def test_the_recorded_run_replays_as_a_difference_with_named_gaps():
    result = script.replay(observations())
    assert result["baseline"] == {"path": "/content/page.php?page=home", "status": 200,
                                  "body_chars": 1381, "has_footer": True, "sizes": [1381]}
    by_size = {item["body_chars"]: item for item in result["variants"]}
    # 1242: the body is shorter but still complete (footer present).
    assert by_size[1242]["delta_chars"] == -139
    assert by_size[1242]["classification"] == ["shorter_body"]
    # 1052/1070: the response stops before the footer, so it is visibly incomplete.
    assert by_size[1052]["classification"] == ["shorter_body", "footer_missing"]
    assert by_size[1070]["classification"] == ["shorter_body", "footer_missing"]
    assert result["server_evidence"]["state"] == "diagnostics_not_recorded"
    assert "diagnostics_not_recorded" in result["gaps"]
    assert "sanitized_replay_has_no_body_content" in result["gaps"]


def test_a_difference_only_replay_never_claims_file_read_or_code_execution():
    result = script.replay(observations())
    assert result["impact"]["level"] == "response_difference"
    assert result["impact"]["arbitrary_file_read"] is False
    assert result["impact"]["remote_code_execution"] is False
    assert result["conclusion"] == {"status": "inconclusive", "verdict": "uncertain",
                                    "basis": "difference_only"}
    assert script.check(result, observations()) == []


def test_a_correlated_diagnostic_explains_the_interruption_but_not_the_impact():
    diagnostics = {"status": "available", "items": [{
        "kind": "warning", "source_file": "page.php", "line": 12, "include_related": True}]}
    result = script.replay([
        observed("/content/page.php?page=home", 1381),
        observed("/content/page.php?page=../missing", 1242, footer=False, diagnostics=diagnostics),
    ])
    assert result["interruption"] == {"explained": True, "reason": "correlated_server_diagnostic"}
    assert result["server_evidence"]["correlated_errors"][0]["source_file"] == "page.php"
    assert result["impact"]["level"] == "response_difference"
    assert result["conclusion"]["status"] == "inconclusive"


def test_unavailable_diagnostics_are_a_gap_not_proof_that_nothing_went_wrong():
    result = script.replay([
        observed("/content/page.php?page=home", 1381),
        observed("/content/page.php?page=../missing", 1242,
                 diagnostics={"status": "unavailable", "reason": "capability_unavailable"}),
    ])
    assert result["server_evidence"]["state"] == "diagnostics_unavailable"
    assert result["server_evidence"]["reasons"] == ["capability_unavailable"]
    assert "diagnostics_unavailable" in result["gaps"]
    assert result["interruption"]["explained"] is False


def test_loading_a_job_keeps_structure_and_drops_content_and_credentials():
    body = ('<html><title>内容中心 · 拾光商城</title><body>林晓 alice@shop.local '
            'SHOPSESSID=abc123 http://127.0.0.1:18882/content/page.php</body>'
            '</footer></html>')
    item = script.observation({"kind": "http", "request": json.dumps(
        {"path": "/content/page.php?page=home"}),
        "result": json.dumps({"status": 200, "body": body, "error": ""})})
    assert item["body_chars"] == len(body)
    assert item["has_footer"] is True
    assert "body" not in item
    assert "SHOPSESSID" not in json.dumps(item, ensure_ascii=False)
    assert "alice@shop.local" not in json.dumps(item, ensure_ascii=False)
    script.assert_sanitized([item])


def test_a_tampered_fixture_is_refused_instead_of_replayed():
    with pytest.raises(ValueError):
        script.assert_sanitized([observed("/content/page.php?cookie=SHOPSESSID=1", 100)])
    with pytest.raises(ValueError):
        script.assert_sanitized([{**observed("/content/page.php", 100), "body": "secret"}])
    with pytest.raises(ValueError):
        script.assert_sanitized([observed("http://127.0.0.1/content/page.php", 100)])


def test_the_replay_command_succeeds_on_the_checked_in_fixture(tmp_path):
    markdown = tmp_path / "replay.md"
    code = script.main(["--fixture", str(FIXTURE), "--markdown-out", str(markdown), "--check"])
    assert code == 0
    text = markdown.read_text(encoding="utf-8")
    assert "### LFI 脱敏回放" in text
    assert "影响判定：response_difference" in text
    assert "诊断" in text and "证据缺口" in text
