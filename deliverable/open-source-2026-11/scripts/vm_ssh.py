#!/usr/bin/env python3
"""Minimal SSH helper for driving the project VM during evidence collection.

Usage:
    python scripts/vm_ssh.py probe
    python scripts/vm_ssh.py run "<shell command>"
    python scripts/vm_ssh.py push <local> <remote>
    python scripts/vm_ssh.py pull <remote> <local>

Connection settings come from env vars (defaults match the lab VM):
    VM_HOST (192.168.239.128)  VM_USER (zsh)  VM_PASS（环境变量注入）  VM_PORT (22)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import paramiko

HOST = os.environ.get("VM_HOST", "192.168.239.128")
USER = os.environ.get("VM_USER", "zsh")
PASS = os.environ.get("VM_PASS", "")  # 归档副本已脱敏
PORT = int(os.environ.get("VM_PORT", "22"))
REMOTE_ROOT = os.environ.get("VM_ROOT", "/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main")


def connect() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=USER, password=PASS, timeout=15,
                   allow_agent=False, look_for_keys=False)
    return client


def run(client: paramiko.SSHClient, command: str, timeout: int = 900) -> int:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=False)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    if out:
        print(out.rstrip())
    if err.strip():
        print("--- stderr ---\n" + err.rstrip(), file=sys.stderr)
    return code


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    action = argv[1]
    client = connect()
    try:
        if action == "probe":
            script = f"""
set +e
echo "== whoami =="; whoami; hostname; uname -srm; cat /etc/os-release | grep PRETTY
echo "== tools =="
for c in python3 python3.12 node npm docker uv git zip cloc curl; do printf '%-10s ' "$c"; command -v $c >/dev/null && $c --version 2>&1 | head -1 || echo MISSING; done
echo "== repo =="
ls -d "{REMOTE_ROOT}" 2>/dev/null || echo "REPO_NOT_FOUND"
ls "{REMOTE_ROOT}" 2>/dev/null | head -15
echo "== disk/mem =="; df -h / | tail -1; free -m | head -2
"""
            return run(client, script)
        if action == "run":
            return run(client, argv[2])
        if action in {"push", "write"}:
            # SFTP is not always available on the lab VM; base64 over exec_command is.
            payload = Path(argv[2]).read_bytes()
            import base64
            encoded = base64.b64encode(payload).decode()
            remote = argv[3]
            code = run(client, f"mkdir -p \"$(dirname '{remote}')\" && printf '%s' '{encoded}' | base64 -d > '{remote}' && wc -c '{remote}'")
            if code == 0:
                print(f"pushed {argv[2]} -> {remote}")
            return code
        if action == "pull":
            sftp = client.open_sftp()
            Path(argv[3]).parent.mkdir(parents=True, exist_ok=True)
            sftp.get(argv[2], argv[3])
            sftp.close()
            print(f"pulled {argv[2]} -> {argv[3]}")
            return 0
    finally:
        client.close()
    print(f"unknown action: {action}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
