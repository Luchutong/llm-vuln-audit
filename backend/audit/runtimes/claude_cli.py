#!/usr/bin/env python3
"""Exec the pinned CLI with a minimal environment, without touching parent state.

The official SDK merges options.env into os.environ. This small process boundary
removes inherited provider credentials, custom headers and alternate cloud routes.
It performs no model calls of its own and never prints environment values.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys


ALLOWED_ENV = frozenset({
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT",
    "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_DISABLE_AUTO_MEMORY", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "DISABLE_AUTOUPDATER", "CLAUDE_CODE_SKIP_PROMPT_HISTORY", "ENABLE_CLAUDEAI_MCP_SERVERS",
    "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_AGENT_SDK_VERSION", "CLAUDE_AGENT_SDK_CLIENT_APP",
    "CLAUDE_CODE_MAX_OUTPUT_TOKENS", "CLAUDE_CODE_SDK_READS_SESSION_STATE",
})


def clean_environment(environ: dict[str, str]) -> dict[str, str]:
    result = {name: value for name, value in environ.items() if name in ALLOWED_ENV}
    result.update({
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1", "CLAUDE_CODE_SKIP_PROMPT_HISTORY": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false", "NO_PROXY": "localhost,127.0.0.1,::1",
        "CLAUDE_CODE_SDK_READS_SESSION_STATE": "1",
    })
    return result


def main() -> None:
    binary = os.environ.get("AUDIT_POC_CLAUDE_REAL_CLI", "")
    if not binary or not Path(binary).is_absolute() or not os.access(binary, os.X_OK):
        print("Pinned Claude CLI is unavailable.", file=sys.stderr)
        raise SystemExit(2)
    os.execve(binary, [binary, *sys.argv[1:]], clean_environment(dict(os.environ)))


if __name__ == "__main__":
    main()
