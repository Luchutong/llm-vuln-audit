#!/usr/bin/env bash
# Bootstrap the evidence-collection environment inside the Ubuntu 20.04 VM.
# Usage: bash /tmp/vm_bootstrap.sh <stage>
#   stages: uv | python | backend | node | envfile | start | status
set -uo pipefail

REPO="/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main"
export PATH="$HOME/.local/bin:$PATH"
export UV_INDEX_URL="https://pypi.tuna.tsinghua.edu.cn/simple"
export npm_config_registry="https://registry.npmmirror.com"

stage="${1:-status}"
cd "$REPO" || { echo "REPO_MISSING: $REPO"; exit 1; }

case "$stage" in
uv)
  echo "== install uv =="
  if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
  fi
  export PATH="$HOME/.local/bin:$PATH"
  uv --version || { echo "UV_INSTALL_FAILED"; exit 1; }
  ;;
python)
  echo "== install CPython 3.12 via uv =="
  uv python install 3.12 2>&1 | tail -5
  uv python list 2>&1 | grep -m2 "3.12" || true
  ;;
backend)
  echo "== uv sync (frozen) =="
  uv sync --project backend --frozen --extra poc-claude 2>&1 | tail -12
  echo "== import smoke test =="
  cd backend && uv run --frozen python -c "import audit.app, fastapi, tree_sitter; print('imports OK')" 2>&1 | tail -3
  ;;
node)
  echo "== install Node 22 from npmmirror =="
  export PATH="$HOME/opt/node/bin:$PATH"
  if command -v node >/dev/null 2>&1; then node -v; else
    NODE_VER="${NODE_VERSION:-v22.23.4}"
    fname="node-${NODE_VER}-linux-x64.tar.xz"
    url="https://registry.npmmirror.com/-/binary/node/${NODE_VER}/${fname}"
    echo "downloading $url"
    mkdir -p "$HOME/opt"
    curl -# -L -o /tmp/node.tar.xz "$url" || exit 1
    ls -l /tmp/node.tar.xz
    rm -rf "$HOME/opt/${fname%.tar.xz}"
    tar -xJf /tmp/node.tar.xz -C "$HOME/opt" || exit 1
    ln -sfn "$HOME/opt/${fname%.tar.xz}" "$HOME/opt/node"
    export PATH="$HOME/opt/node/bin:$PATH"
    node -v; npm -v
    grep -q 'opt/node/bin' "$HOME/.bashrc" || echo 'export PATH="$HOME/opt/node/bin:$PATH"' >> "$HOME/.bashrc"
  fi
  echo "== npm ci =="
  cd frontend && npm ci --no-audit --no-fund 2>&1 | tail -8
  ;;
envfile)
  if [ -f .env ]; then echo ".env exists"; else cp .env.example .env; echo ".env created from example"; fi
  grep -c . .env
  ;;
start)
  export PATH="$HOME/opt/node/bin:$HOME/.local/bin:$PATH"
  mkdir -p .run data
  echo "== stop old =="
  pkill -f "uvicorn audit.app:app" 2>/dev/null || true
  pkill -f "vite" 2>/dev/null || true
  sleep 1
  echo "== start backend =="
  cd backend
  setsid nohup uv run --frozen uvicorn audit.app:app --host 0.0.0.0 --port 8899 > ../.run/backend.log 2>&1 &
  cd ..
  echo "== start frontend =="
  cd frontend
  setsid nohup env VITE_API_TARGET=http://127.0.0.1:8899 ./node_modules/.bin/vite --host 0.0.0.0 --port 5173 > ../.run/frontend.log 2>&1 &
  cd ..
  sleep 10
  echo "== smoke =="
  curl -s -o /dev/null -w "backend /api/config -> %{http_code}\n" --max-time 5 http://127.0.0.1:8899/api/config
  curl -s -o /dev/null -w "frontend / -> %{http_code}\n" --max-time 5 http://127.0.0.1:5173/
  ;;
status)
  echo "== processes =="
  pgrep -af "uvicorn audit.app:app" | head -3
  pgrep -af "vite" | head -3
  echo "== ports =="
  (ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null) | grep -E ':(8899|5173)' || echo "no listeners"
  echo "== config =="
  curl -s --max-time 5 http://127.0.0.1:8899/api/config | head -c 600; echo
  echo "== logs tail =="
  tail -5 .run/backend.log 2>/dev/null; tail -5 .run/frontend.log 2>/dev/null
  ;;
*)
  echo "unknown stage: $stage"; exit 2;;
esac
