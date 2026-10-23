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
POC=false
BACKEND_PID=""
FRONTEND_PID=""
BACKEND_LOG="$RUN_DIR/backend.log"
FRONTEND_LOG="$RUN_DIR/frontend.log"

usage() {
  cat <<'EOF'
Usage: ./scripts/start.sh [--skip-install] [--poc]

Starts the vuln-audit backend on 127.0.0.1:8899 and the Vite frontend on
127.0.0.1:5173. Ctrl+C stops both processes.

--poc starts the local Lab30 target and the isolated poc-runner with
`docker compose --profile poc`, then points the backend at the runner's
private Compose address. The containers are left running after Ctrl+C; stop
them with `docker compose --profile poc down`.

Environment:
  AUDIT_PORT  Backend port (default: 8899)
  WEB_PORT    Frontend port (default: 5173)

Options:
  --poc           Enable automatic POC verification against local Lab30.
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
    # for this probe and still fails when another process is actively listening
    # (SO_REUSEADDR cannot displace a LISTEN socket; only SO_REUSEPORT could).
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", int(sys.argv[1])))
    except OSError:
        raise SystemExit(1)
PY
}

port_holder() {
  # Best effort, so the "already in use" error names the existing stack instead of
  # leaving the user to guess. `ss -p` can only read processes this user owns.
  local port="$1"
  command -v ss >/dev/null 2>&1 || return 0
  local line
  line="$(ss -Hltnp "sport = :$port" 2>/dev/null | head -n 1 || true)"
  [[ -n "$line" ]] || return 0
  printf '；当前监听：%s' "$line"
}

# --- replacing this checkout's own stack --------------------------------------------
# Re-running start.sh while a previous invocation is still up used to abort with the same
# message as a foreign process holding the port.  A previous stack is ours to replace: the
# same checkout's uvicorn and Vite are stopped and started again.  Anything else keeps the
# old behaviour and is never signalled.

listener_pids() {
  # Every PID listening on the port, one per line. `ss -p` only names this user's processes.
  command -v ss >/dev/null 2>&1 || return 0
  ss -Hltnp "sport = :$1" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u
}

proc_arg() {
  # One /proc field, defaulting to empty when the process is gone or not readable.
  case "$1" in
    cmdline) tr '\0' ' ' < "/proc/$2/cmdline" 2>/dev/null || true ;;
    cwd) readlink "/proc/$2/cwd" 2>/dev/null || true ;;
    stat) cat "/proc/$2/stat" 2>/dev/null || true ;;
  esac
}

proc_field() {
  # A /proc/<pid>/stat field after the command name (2 = parent, 3 = process group).
  # ``comm`` may contain spaces and parentheses, so strip through the last ``) ``.
  local stat
  stat="$(proc_arg stat "$1")"
  [[ -n "$stat" ]] || return 1
  printf '%s' "${stat##*) }" | awk -v field="$2" '{print $field}'
}

pid_is_own_stack() {
  # True only for this checkout's backend/frontend, which is what makes stopping safe.
  local pid="$1" kind="$2" cmd cwd
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  cmd="$(proc_arg cmdline "$pid")"
  cwd="$(proc_arg cwd "$pid")"
  case "$kind" in
    backend)
      [[ "$cmd" == *"$BACKEND_DIR/.venv/bin/"* && "$cmd" == *"audit.app:app"* ]] \
        || [[ "$cmd" == *"audit.app:app"* && "$cwd" == "$BACKEND_DIR" ]]
      ;;
    frontend)
      [[ "$cmd" == *"vite"* && ( "$cmd" == *"$FRONTEND_DIR"* || "$cwd" == "$FRONTEND_DIR" ) ]]
      ;;
    *) return 1 ;;
  esac
}

own_stack_leader() {
  # The start.sh that launched this listener, if it is still around. Signalling that
  # script runs its own cleanup, so the other terminal shows a clean stop and both of its
  # services go down together.
  local pid="$1" depth cmd cwd ppid
  for ((depth = 0; depth < 6; depth += 1)); do
    cmd="$(proc_arg cmdline "$pid")"
    cwd="$(proc_arg cwd "$pid")"
    if [[ "$cmd" == *"scripts/start.sh"* && ( "$cmd" == *"$ROOT_DIR"* || "$cwd" == "$ROOT_DIR" ) ]]; then
      printf '%s\n' "$pid"
      return 0
    fi
    ppid="$(proc_field "$pid" 2)" || return 1
    [[ "$ppid" =~ ^[0-9]+$ ]] && (( ppid > 1 )) || return 1
    pid="$ppid"
  done
  return 1
}

signal_process() {
  # Signal the whole group only when the PID owns it: the services are started with
  # setsid, but an inherited process group must never be signalled by mistake.
  local signal="$1" pid="$2"
  if [[ "$(proc_field "$pid" 3)" == "$pid" ]]; then
    kill "-$signal" -- "-$pid" 2>/dev/null && return 0
  fi
  kill "-$signal" "$pid" 2>/dev/null || true
}

reclaim_port() {
  # Stop this checkout's own listener on the port. Returns 1 without touching anything if
  # any listener belongs to another process, so the caller can keep the port-conflict error.
  local port="$1" kind="$2" label="$3"
  local pids pid foreign=() own=()
  pids="$(listener_pids "$port")"
  [[ -n "$pids" ]] || return 0
  while read -r pid; do
    [[ -n "$pid" ]] || continue
    if pid_is_own_stack "$pid" "$kind"; then own+=("$pid"); else foreign+=("$pid"); fi
  done <<< "$pids"
  ((${#foreign[@]} == 0)) || return 1

  printf '检测到本项目已有的%s（pid %s），停止后重新启动…\n' "$label" "${own[*]}" >&2
  local leaders=() targets=() leader target attempt
  for pid in "${own[@]}"; do
    if leader="$(own_stack_leader "$pid")"; then
      leaders+=("$leader")
    else
      targets+=("$pid")
    fi
  done
  # Leaders first: a live start.sh tears both services down through its own trap.
  for target in "${leaders[@]}" "${targets[@]}"; do
    signal_process TERM "$target"
  done
  for ((attempt = 1; attempt <= 40; attempt += 1)); do
    port_is_available "$port" && return 0
    sleep 0.25
  done
  for target in "${leaders[@]}" "${targets[@]}"; do
    signal_process KILL "$target"
  done
  for ((attempt = 1; attempt <= 20; attempt += 1)); do
    port_is_available "$port" && return 0
    sleep 0.25
  done
  return 1
}

ensure_port_free() {
  # A free port, a replaced own instance, or a hard error naming a foreign listener.
  local port="$1" kind="$2" label="$3"
  port_is_available "$port" && return 0
  reclaim_port "$port" "$kind" "$label" && return 0
  fail "${label}端口 $port 已被占用$(port_holder "$port")。请先停止已有实例。"
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
import urllib.request

# Local/private Compose addresses must never be sent through a developer proxy;
# the same reason the backend's runner client disables trust_env.
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with opener.open(sys.argv[1], timeout=1) as response:
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
    --poc) POC=true ;;
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

# Check the ports before touching Compose: otherwise a second invocation brings the
# Lab30/runner stack up and waits for the runner's health endpoint only to fail here.
# A listener that belongs to this checkout is replaced; a foreign one aborts.
ensure_port_free "$AUDIT_PORT" backend "后端"
ensure_port_free "$WEB_PORT" frontend "前端"

if [[ "$POC" == true ]]; then
  require_command docker
  [[ -f "$ROOT_DIR/.env" ]] || fail "--poc 需要 $ROOT_DIR/.env：请从 .env.example 复制并填写 POC_RUNNER_TOKEN 及可选的 LAB30_DB_* 配置。"
  grep -Eq '^[[:space:]]*(export[[:space:]]+)?POC_RUNNER_TOKEN=[^[:space:]]+' "$ROOT_DIR/.env" \
    || fail ".env 缺少 POC_RUNNER_TOKEN。"
  printf '启动本地 Lab30 靶场与隔离 POC runner…\n'
  (cd "$ROOT_DIR" && docker compose --profile poc up --build -d --remove-orphans lab30-db lab30-fixtures lab30 poc-runner) \
    || fail "无法启动 Lab30/poc-runner；请查看 docker compose 日志。"
  RUNNER_ID="$(cd "$ROOT_DIR" && docker compose --profile poc ps -q poc-runner)"
  [[ -n "$RUNNER_ID" ]] || fail "找不到 poc-runner 容器。"
  # The runner lives only on `internal` networks, where Docker does not publish ports.
  # The host can still reach the bridge address, so use it instead of weakening the
  # isolation with a published port.
  RUNNER_ADDR="$(docker inspect "$RUNNER_ID" --format '{{range $name, $net := .NetworkSettings.Networks}}{{if eq $name "vuln-audit_poc-control"}}{{$net.IPAddress}}{{end}}{{end}}')"
  [[ -n "$RUNNER_ADDR" ]] || RUNNER_ADDR="$(docker inspect "$RUNNER_ID" --format '{{range $net := .NetworkSettings.Networks}}{{$net.IPAddress}} {{end}}' | awk '{print $1}')"
  [[ -n "$RUNNER_ADDR" ]] || fail "无法解析 poc-runner 的内部地址。"
  for attempt in $(seq 1 240); do
    probe_url "http://$RUNNER_ADDR:8080/healthz" && break
    if (( attempt == 240 )); then
      (cd "$ROOT_DIR" && docker compose --profile poc ps) >&2 || true
      fail "等待 POC runner 就绪超时（$RUNNER_ADDR:8080）。"
    fi
    sleep 0.5
  done
  # Real environment variables win over .env, so the host-run backend reaches the
  # runner's private Compose address.
  export POC_RUNNER_URL="http://$RUNNER_ADDR:8080"
  export POC_ENABLED=1
fi

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
if [[ "$POC" == true ]]; then
  printf '  POC：已连接 %s（Lab30 + poc-runner 保持运行）\n' "$POC_RUNNER_URL"
  printf '       停止靶场：docker compose --profile poc down\n'
else
  printf '  POC：未启用（需要自动验证时使用 ./scripts/start.sh --poc）\n'
fi
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
