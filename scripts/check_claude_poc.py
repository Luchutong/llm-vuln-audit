#!/usr/bin/env python3
"""Inspect local Claude POC configuration without a database or model request.

Run with backend/.venv/bin/python scripts/check_claude_poc.py. Only the current
process environment is inspected; .env files are never loaded. The sole child
command is the installed SDK's bundled CLI with --version and a clean environment.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Mapping
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
PINNED_SDK_VERSION = "0.2.174"
PINNED_CLI_VERSION = "2.1.310"


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes"}


def _valid_url(value: str) -> bool:
    try:
        url = urlsplit(value)
        _ = url.port
        return bool(
            url.scheme in {"http", "https"} and url.hostname
            and not url.username and not url.password and not url.query and not url.fragment
            and not any(ch.isspace() or ord(ch) < 32 for ch in value)
        )
    except ValueError:
        return False


def sdk_installation() -> tuple[str, Path | None]:
    """Read package metadata and location without importing application modules."""
    try:
        version = importlib.metadata.version("claude-agent-sdk")
        spec = importlib.util.find_spec("claude_agent_sdk")
    except (importlib.metadata.PackageNotFoundError, ImportError, ValueError):
        return "", None
    if spec is None or not spec.origin:
        return version, None
    name = "claude.exe" if os.name == "nt" else "claude"
    binary = Path(spec.origin).resolve().parent / "_bundled" / name
    return version, binary if binary.is_file() and os.access(binary, os.X_OK) else None


def cli_version(binary: Path | None) -> str:
    if binary is None:
        return ""
    try:
        result = subprocess.run(
            [str(binary), "--version"], capture_output=True, text=True, timeout=10,
            # Do not pass provider credentials, proxy routes, custom headers or
            # the invoking user's Claude configuration into the version probe.
            env={
                "PATH": os.defpath, "LANG": "C.UTF-8",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "DISABLE_AUTOUPDATER": "1", "CLAUDE_CODE_SKIP_PROMPT_HISTORY": "1",
            },
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    # Only the numeric version is public, even if a failed wrapper prints a
    # credential or a URL in its banner or stderr.
    match = re.search(r"(?<![\w.])\d+\.\d+\.\d+(?:[-+][\w.-]+)?", result.stdout)
    return match.group(0) if match else ""


def workspace_available(value: str) -> bool:
    if not value:
        return False
    try:
        workspace = Path(value).expanduser().resolve()
        return bool(
            workspace.is_dir() and os.access(workspace, os.W_OK | os.X_OK)
            and not (workspace / ".git").exists()
            and workspace not in {ROOT, ROOT / "backend", Path.cwd().resolve()}
        )
    except (OSError, RuntimeError, ValueError):
        return False


def inspect_configuration(environ: Mapping[str, str] | None = None) -> dict:
    env = os.environ if environ is None else environ
    sdk_version, binary = sdk_installation()
    bundled_version = cli_version(binary)
    expected_sdk = env.get("POC_CLAUDE_SDK_VERSION", "").strip() or PINNED_SDK_VERSION
    expected_cli = env.get("POC_CLAUDE_CLI_VERSION", "").strip() or PINNED_CLI_VERSION
    workspace = env.get("POC_CLAUDE_WORKSPACE", "").strip()
    gateway_url = env.get("POC_CLAUDE_GATEWAY_URL", "").strip()
    upstream_url = env.get("POC_CLAUDE_UPSTREAM_URL", "").strip()
    upstream_key = env.get("POC_CLAUDE_UPSTREAM_API_KEY", "").strip()
    checks = {
        "sdk_installed": bool(sdk_version),
        "sdk_version_matches": bool(sdk_version and sdk_version == expected_sdk),
        "bundled_cli_available": binary is not None and bool(bundled_version),
        "cli_version_matches": bool(bundled_version and bundled_version == expected_cli),
        "runtime_claude_sdk": env.get("POC_RUNTIME", "legacy").strip() == "claude_sdk",
        "poc_enabled": _enabled(env.get("POC_ENABLED", "0")),
        "workspace_configured": bool(workspace),
        "workspace_available": workspace_available(workspace),
        "gateway_enabled": _enabled(env.get("POC_CLAUDE_GATEWAY_ENABLED", "0")),
        "gateway_url_configured": bool(gateway_url),
        "gateway_url_valid": _valid_url(gateway_url),
        "upstream_url_configured": bool(upstream_url),
        "upstream_key_configured": bool(upstream_key),
        "upstream_configuration_valid": bool(
            _valid_url(upstream_url) and upstream_key and len(upstream_key) <= 4096
            and all(32 <= ord(ch) <= 126 for ch in upstream_key)
        ),
        "model_configured": bool(env.get("POC_CLAUDE_MODEL", "").strip()),
    }
    return {
        "scope": "offline_configuration", "sdk_version": sdk_version,
        "bundled_cli_version": bundled_version, **checks,
        "ready_for_live": all(checks.values()),
        "live_connectivity_checked": False, "model_requests": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-ready", action="store_true",
                        help="Exit with status 1 unless all local configuration checks pass.")
    args = parser.parse_args(argv)
    result = inspect_configuration()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(args.require_ready and not result["ready_for_live"])


if __name__ == "__main__":
    raise SystemExit(main())
