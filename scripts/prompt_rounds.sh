#!/usr/bin/env bash
# Run the three prompt versions back to back over one snapshot.
#
# The comparison only means anything if the three runs differ in nothing but the prompt,
# so the snapshot, scope, model and budgets are fixed here and only the version changes.
# Runs are sequential because the worker takes one run at a time; a second run would just
# sit pending until the first finished.
#
# Usage: prompt_rounds.sh <base-url> <snapshot-id> [P0 P1 P2]
set -u

BASE="${1:?base url required}"
SNAPSHOT="${2:?snapshot id required}"
shift 2 || true
VERSIONS=("$@")
if [ ${#VERSIONS[@]} -eq 0 ]; then
  VERSIONS=(P0 P1 P2)
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/backend/.venv/bin/python"
LOG_DIR="${LOG_DIR:-/tmp}"

for version in "${VERSIONS[@]}"; do
  log="$LOG_DIR/run_${version}.log"
  echo "=== ${version} -> ${log}"
  if ! timeout 5400 "$PY" -I -u "$ROOT/scripts/demo_run.py" "$BASE" "$SNAPSHOT" "$version" >"$log" 2>&1; then
    echo "    ${version} exited $? — see $log"
  fi
  # The run id is the line demo_run prints; keep it so the comparison can be assembled
  # without guessing from timestamps.
  grep -m1 -E "^run id" "$log" || true
done

echo "=== rounds finished"
# Single-quoted so the shell leaves the program alone: writing \" in here reaches Python as
# a literal backslash and the summary dies with a SyntaxError after all three runs are done.
curl -s "$BASE/api/runs" | "$PY" -c '
import json, sys
for run in json.load(sys.stdin):
    label = run.get("prompt_label") or "?"
    units = "{}/{}".format(run.get("completed_units"), run.get("total_units"))
    print("  {:8}  {:<22} {:<12} {}".format(
        str(run.get("id", ""))[:8], label, run.get("status", ""), units))
'
