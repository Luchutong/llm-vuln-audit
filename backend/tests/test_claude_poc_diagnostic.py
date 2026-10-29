"""Configuration diagnostics must stay offline and keep credentials out of JSON."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_claude_poc.py"
SPEC = importlib.util.spec_from_file_location("check_claude_poc", SCRIPT)
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)


@pytest.fixture
def installed_sdk(monkeypatch):
    monkeypatch.setattr(diagnostic, "sdk_installation", lambda: ("0.2.174", Path("/offline/claude")))
    monkeypatch.setattr(diagnostic, "cli_version", lambda _: "2.1.310")


def configured_environment(tmp_path):
    return {
        "POC_RUNTIME": "claude_sdk", "POC_ENABLED": "1",
        "POC_CLAUDE_WORKSPACE": str(tmp_path),
        "POC_CLAUDE_GATEWAY_ENABLED": "1",
        "POC_CLAUDE_GATEWAY_URL": "http://127.0.0.1:8899/api/internal/poc-gateway",
        "POC_CLAUDE_UPSTREAM_URL": "https://upstream.example.invalid",
        "POC_CLAUDE_UPSTREAM_API_KEY": "test-only-private-key",
        "POC_CLAUDE_MODEL": "test-only-private-model",
    }


def test_fully_configured_diagnostic_reports_no_live_requests(tmp_path, installed_sdk):
    env = configured_environment(tmp_path)
    result = diagnostic.inspect_configuration(env)
    assert result["ready_for_live"]
    assert result["model_requests"] == 0
    assert not result["live_connectivity_checked"]
    rendered = json.dumps(result)
    for name in ("POC_CLAUDE_UPSTREAM_API_KEY", "POC_CLAUDE_UPSTREAM_URL", "POC_CLAUDE_MODEL",
                 "POC_CLAUDE_GATEWAY_URL", "POC_CLAUDE_WORKSPACE"):
        assert env[name] not in rendered


def test_legacy_default_and_disabled_gateway_are_not_ready(installed_sdk):
    result = diagnostic.inspect_configuration({})
    assert not result["runtime_claude_sdk"]
    assert not result["gateway_enabled"]
    assert not result["ready_for_live"]
    assert result["model_requests"] == 0


@pytest.mark.parametrize("field,value,check", [
    ("POC_CLAUDE_SDK_VERSION", "0.0.0", "sdk_version_matches"),
    ("POC_CLAUDE_CLI_VERSION", "0.0.0", "cli_version_matches"),
    ("POC_CLAUDE_UPSTREAM_URL", "https://user:password@example.invalid", "upstream_configuration_valid"),
    ("POC_CLAUDE_UPSTREAM_API_KEY", "secret\r\nheader", "upstream_configuration_valid"),
    ("POC_CLAUDE_GATEWAY_URL", "https://example.invalid?token=secret", "gateway_url_valid"),
    ("POC_CLAUDE_WORKSPACE", str(ROOT), "workspace_available"),
])
def test_invalid_local_configuration_cannot_pass_readiness(tmp_path, installed_sdk, field, value, check):
    env = {**configured_environment(tmp_path), field: value}
    result = diagnostic.inspect_configuration(env)
    assert not result[check]
    assert not result["ready_for_live"]


def test_cli_version_probe_has_no_credentials_or_provider_routes(monkeypatch):
    captured = {}

    def version_only(command, **kwargs):
        captured.update(command=command, **kwargs)
        return SimpleNamespace(returncode=0, stdout="2.1.310 (Claude Code)\nprivate-banner-text", stderr="private-error")

    monkeypatch.setattr(diagnostic.subprocess, "run", version_only)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "never-forward")
    monkeypatch.setenv("ANTHROPIC_CUSTOM_HEADERS", "never-forward")
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("HTTPS_PROXY", "http://never-forward.invalid")
    assert diagnostic.cli_version(Path("/offline/claude")) == "2.1.310"
    assert captured["command"] == ["/offline/claude", "--version"]
    assert not any(name in captured["env"] for name in (
        "ANTHROPIC_API_KEY", "ANTHROPIC_CUSTOM_HEADERS", "CLAUDE_CODE_USE_BEDROCK", "HTTPS_PROXY", "HOME",
    ))


def test_command_does_not_load_dotenv_or_open_an_audit_database(tmp_path):
    # A real command invocation checks argparse and package discovery. No provider
    # configuration is inherited, and --version is the only possible CLI command.
    (tmp_path / ".env").write_text("POC_CLAUDE_MODEL=dotenv-must-not-be-loaded\nPOC_RUNTIME=claude_sdk\n")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--require-ready"], cwd=tmp_path,
        env={"PATH": os.defpath, "LANG": "C.UTF-8"},
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["model_configured"] is False
    assert report["runtime_claude_sdk"] is False
    assert report["model_requests"] == 0
    assert report["ready_for_live"] is False
    assert "dotenv-must-not-be-loaded" not in result.stdout + result.stderr
    assert sorted(path.name for path in tmp_path.iterdir()) == [".env"]
