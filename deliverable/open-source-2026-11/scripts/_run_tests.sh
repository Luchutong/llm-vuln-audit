#!/bin/bash
export PATH="$HOME/opt/node/bin:$HOME/.local/bin:$PATH"
ROOT="/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main"
cd "$ROOT" || exit 1
mkdir -p .run
cd backend || exit 1
.venv/bin/python -m pytest tests -q -p no:cacheprovider > ../.run/pytest_20261108.log 2>&1
echo "PYTEST_EXIT=$?" >> ../.run/pytest_20261108.log
cd ../frontend || exit 1
npm test > ../.run/npmtest_20261108.log 2>&1
echo "NPM_EXIT=$?" >> ../.run/npmtest_20261108.log
echo "=== PYTEST TAIL ==="
tail -6 ../.run/pytest_20261108.log
echo "=== NPM TAIL ==="
tail -8 ../.run/npmtest_20261108.log
