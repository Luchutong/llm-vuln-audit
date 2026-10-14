#!/usr/bin/env bash
# Start this repository's local development stack (FastAPI + Vite) as one process.
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
RUN_DIR="$ROOT_DIR/.run"

AUDIT_PORT="${AUDIT_PORT:-8899}"
WEB_PORT="${WEB_PORT:-5173}"
SKIP_INSTALL=false
BACKEND_PID=""
FRONTEND_PID=""
BACKEND_LOG="$RUN_DIR/backend.log"
FRONTEND_LOG="$RUN_DIR/frontend.log"

usage() {
  cat <<'EOF'
Usage: ./scripts/start.sh [--skip-install]

Starts the vuln-audit backend on 127.0.0.1:8899 and the Vite frontend on
127.0.0.1:5173. Ctrl+C stops both processes.

Environment:
  AUDIT_PORT  Backend port (default: 8899)
  WEB_PORT    Frontend port (default: 5173)

Options:
  --skip-install  Do not run `uv sync` or `npm install` before starting.
  -h, --help      Show this help text.
EOF
}

fail() {
  printf '启动失败：%s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "未找到 $1，请先安装后重试。"
}

validate_port() {
  local value="$1"
  [[ "$value" =~ ^[1-9][0-9]{0,4}$ ]] && (( value <= 65535 )) \
    || fail "端口必须是 1 到 65535 的整数：$value"
}

port_is_available() {
  python3 - "$1" <<'PY'
import socket
import sys

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    # A just-closed development server can leave TIME_WAIT entries. Reuse is safe
    # for this probe and still fails when another process is actively listening.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", int(sys.argv[1])))
    except OSError:
        raise SystemExit(1)
PY
}

show_log_tail() {
  local name="$1" log_file="$2"
  printf '\n--- %s 最近日志 ---\n' "$name" >&2
  tail -n 60 "$log_file" >&2 || true
}

stop_process_group() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  # `setsid` below makes every service its own process group. Terminating the group
  # also stops npm/uv helper children instead of leaving Vite or Uvicorn behind.
  kill -TERM -- "-$pid" 2>/dev/null || true
  local attempt
  for ((attempt = 1; attempt <= 20; attempt += 1)); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL -- "-$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  stop_process_group "$FRONTEND_PID"
  stop_process_group "$BACKEND_PID"
  exit "$status"
}

probe_url() {
  python3 - "$1" <<'PY'
import sys
from urllib.request import urlopen

try:
    with urlopen(sys.argv[1], timeout=1) as response:
        raise SystemExit(0 if 200 <= response.status < 400 else 1)
except Exception:
    raise SystemExit(1)
PY
}

wait_for_url() {
  local name="$1" url="$2" pid="$3" log_file="$4"
  local attempt
  for ((attempt = 1; attempt <= 80; attempt += 1)); do
    if probe_url "$url"; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      show_log_tail "$name" "$log_file"
      fail "$name 意外退出。"
    fi
    sleep 0.25
  done
  show_log_tail "$name" "$log_file"
  fail "等待 $name 在 $url 就绪超时。"
}

while (($#)); do
  case "$1" in
    --skip-install) SKIP_INSTALL=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "未知参数：$1" ;;
  esac
  shift
done

validate_port "$AUDIT_PORT"
validate_port "$WEB_PORT"
[[ "$AUDIT_PORT" != "$WEB_PORT" ]] || fail "后端与前端不能使用同一个端口。"
require_command python3
require_command setsid

port_is_available "$AUDIT_PORT" || fail "后端端口 $AUDIT_PORT 已被占用。"
port_is_available "$WEB_PORT" || fail "前端端口 $WEB_PORT 已被占用。"

if [[ "$SKIP_INSTALL" == false ]]; then
  require_command uv
  require_command npm
  printf '同步后端依赖…\n'
  (cd "$BACKEND_DIR" && uv sync --locked)
  printf '同步前端依赖…\n'
  (cd "$FRONTEND_DIR" && npm install --no-audit --no-fund)
else
  [[ -x "$BACKEND_DIR/.venv/bin/uvicorn" ]] || fail "后端虚拟环境不存在；请去掉 --skip-install。"
  [[ -d "$FRONTEND_DIR/node_modules" ]] || fail "前端依赖不存在；请去掉 --skip-install。"
fi

if [[ ! -f "$ROOT_DIR/.env" && ! -f "$BACKEND_DIR/.env" ]]; then
  printf '提示：未发现 .env；应用可以启动，但 LLM 审计前需要配置模型环境变量。\n'
fi

mkdir -p "$RUN_DIR"
: > "$BACKEND_LOG"
: > "$FRONTEND_LOG"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

(
  exec setsid "$BACKEND_DIR/.venv/bin/uvicorn" audit.app:app \
    --host 127.0.0.1 --port "$AUDIT_PORT"
) >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
wait_for_url "后端" "http://127.0.0.1:$AUDIT_PORT/api/config" "$BACKEND_PID" "$BACKEND_LOG"

(
  cd "$FRONTEND_DIR"
  exec setsid env VITE_API_TARGET="http://127.0.0.1:$AUDIT_PORT" \
    npm run dev -- --port "$WEB_PORT" --strictPort
) >"$FRONTEND_LOG" 2>&1 &
FRONTEND_PID=$!
wait_for_url "前端" "http://127.0.0.1:$WEB_PORT" "$FRONTEND_PID" "$FRONTEND_LOG"

printf '\nvuln-audit 已启动：\n'
printf '  前端：http://127.0.0.1:%s\n' "$WEB_PORT"
printf '  后端：http://127.0.0.1:%s/api/config\n' "$AUDIT_PORT"
printf '  日志：%s 与 %s\n' "$BACKEND_LOG" "$FRONTEND_LOG"
printf '按 Ctrl+C 同时停止前后端。\n\n'

while true; do
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    show_log_tail "后端" "$BACKEND_LOG"
    fail "后端已退出。"
  fi
  if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
    show_log_tail "前端" "$FRONTEND_LOG"
    fail "前端已退出。"
  fi
  sleep 1
done
