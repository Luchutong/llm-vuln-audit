#!/usr/bin/env bash
# Collect D-B03 evidence: backend pytest (dev + poc extras) and frontend node:test.
set -uo pipefail
REPO="/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main"
BACKEND="$REPO/backend"
export PATH="/home/zsh/.local/bin:/home/zsh/opt/node/bin:$PATH"
mkdir -p "$REPO/.run"
rm -f "$REPO/.run/db03.done"

cd "$BACKEND" || exit 1
uv run --project "$BACKEND" --frozen --extra dev --extra poc-claude python -m pytest tests --collect-only -q \
  > "$REPO/.run/pytest-collect.log" 2>&1
uv run --project "$BACKEND" --frozen --extra dev --extra poc-claude python -m pytest tests -q -p no:cacheprovider \
  > "$REPO/.run/pytest.log" 2>&1
echo "PYTEST_EXIT=$?" >> "$REPO/.run/pytest.log"

cd "$REPO/frontend" || exit 1
npm test > "$REPO/.run/npmtest.log" 2>&1
echo "NPM_EXIT=$?" >> "$REPO/.run/npmtest.log"

echo "DONE" > "$REPO/.run/db03.done"
