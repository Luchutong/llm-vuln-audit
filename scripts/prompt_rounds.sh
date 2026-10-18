#!/usr/bin/env bash
# Coursework compatibility example; not part of the default Planner workflow.
# Portable orchestration is implemented in Python; this shell wrapper preserves the
# existing command name for Unix/Git Bash users.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
  if [ -x "$ROOT/backend/.venv/bin/python" ]; then
    PYTHON="$ROOT/backend/.venv/bin/python"
  else
    PYTHON="python3"
  fi
fi
exec "$PYTHON" "$ROOT/scripts/prompt_rounds.py" "$@"
