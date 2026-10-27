#!/usr/bin/env bash
# Reset the local Lab30 target and assert its seed accounts.
#
# The audit host runs this between findings so every automatic proof starts from the
# same account state: a POC that legitimately exploits mass assignment must not leak
# into the next finding, and the runner must not have to remember a global baseline.
#
# Prints exactly one JSON line (accounts, drift, ok).  Exits 1 when the seed does not
# match, so a caller can refuse to start an audit against a polluted target.
#
# Run as www-data: reset_shop() recreates files under /var/lib/shop, which is owned by
# www-data, and the Lab30 CLI resets the same way.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SERVICE="${LAB30_SERVICE:-lab30}"
LIMIT="${POC_RESET_TIMEOUT:-${RESET_TIMEOUT:-60}}"

json_escape() {
  printf '%s' "$1" | tr '\n\r\t' '   ' | cut -c1-400 | sed 's/\\/\\\\/g; s/"/\\"/g'
}

fail() {
  printf '{"ok":false,"error":"%s","detail":"%s"}\n' "$1" "$(json_escape "$2")"
  exit 1
}

compose_exec() {
  timeout --kill-after=5 "$LIMIT" docker compose --profile poc exec -T --user www-data "$SERVICE" "$@"
}

# 1) Restore the seed.  Output is dropped: it contains no secrets, but callers only
#    parse the JSON line below.
reset_output="$(compose_exec php /var/www/shop/bin/reset.php 2>&1)" \
  || fail "reset_failed" "$reset_output"

# 2) Read back what the seed wrote.  Only account fields: no password hash, no session.
check_code='
require "/var/www/shop/src/bootstrap.php";
$rows = array();
foreach (db()->query("SELECT id,username,role,balance,tier FROM users ORDER BY id") as $u) {
    $rows[] = array("id"=>(int)$u["id"], "username"=>$u["username"], "role"=>$u["role"],
                    "balance"=>$u["balance"], "tier"=>$u["tier"]);
}
echo json_encode(array("accounts"=>$rows), JSON_UNESCAPED_SLASHES), "\n";
'
check_output="$(compose_exec php -r "$check_code" 2>&1)" \
  || fail "seed_query_failed" "$check_output"

# 3) Compare against the seed.  The last line is the JSON payload; anything before it
#    is container noise the PHP CLI may print.
printf '%s\n' "$check_output" | python3 -c '
import json, sys

EXPECTED = {"alice": "customer", "bob": "customer", "operator": "operator", "admin": "admin"}

lines = [line for line in sys.stdin.read().splitlines() if line.strip()]
try:
    payload = json.loads(lines[-1])
    accounts = payload.get("accounts")
    if not isinstance(accounts, list):
        raise ValueError("accounts missing")
except (IndexError, ValueError) as exc:
    print(json.dumps({"ok": False, "error": "seed_query_unparsable", "detail": str(exc)}))
    raise SystemExit(1)

summary, drift, seen = [], [], set()
for row in accounts[:8]:
    if not isinstance(row, dict):
        continue
    seen.add(row.get("username"))
    summary.append({key: row.get(key) for key in ("username", "role", "balance", "tier")})
    expected_role = EXPECTED.get(row.get("username"))
    if expected_role is None:
        continue
    for field, wanted in (("role", expected_role), ("balance", "100.00"), ("tier", "standard")):
        if row.get(field) != wanted and len(drift) < 8:
            drift.append({"username": row.get("username"), "field": field,
                          "expected": wanted, "actual": row.get(field)})
for username in sorted(EXPECTED):
    if username not in seen and len(drift) < 8:
        drift.append({"username": username, "field": "presence", "expected": "present", "actual": "missing"})

print(json.dumps({"ok": not drift, "accounts": summary, "drift": drift}, ensure_ascii=False, sort_keys=True))
raise SystemExit(0 if not drift else 1)
'
