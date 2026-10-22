#!/usr/bin/env bash
# One-shot bootstrap for a bare Linux host (Debian/Ubuntu assumed for apt hints).
#
# Idempotent: re-running skips finished steps.  After it finishes you have a built
# frontend, a synced backend venv (.venv) and a scaffolded .env -- start the stack
# with ./scripts/start.sh (dev) or docker compose up -d --build (prod/lab).
#
# Usage: ./scripts/setup_linux.sh [--with-frontend]
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
WITH_FRONTEND=false
[[ "${1:-}" == "--with-frontend" ]] && WITH_FRONTEND=true

cd "$ROOT_DIR"

say() { printf '\n\033[1;34m[setup]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[setup] 失败：%s\033[0m\n' "$*" >&2; exit 1; }

# --- 0. 可执行位 ---------------------------------------------------------------------
chmod +x scripts/*.sh scripts/*.py 2>/dev/null || true

# --- 1. 系统依赖 ---------------------------------------------------------------------
command -v python3 >/dev/null 2>&1 || die "未找到 python3，请先安装（Ubuntu: sudo apt install python3 python3-venv python3-pip）"
PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
python3 - "$PY_VER" <<'PY' || die "项目要求 Python >= 3.12（当前 $PY_VER）。Ubuntu 22.04 可用 deadsnakes：sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt install python3.12 python3.12-venv"
import sys
sys.exit(0 if tuple(int(x) for x in sys.argv[1].split(".")) >= (3, 12) else 1)
PY
say "Python $PY_VER 满足要求"

if ! command -v uv >/dev/null 2>&1; then
  say "安装 uv（Python 包管理器）"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

# --- 2. 后端依赖（uv 按 uv.lock 锁定版本） --------------------------------------------
say "同步后端依赖（uv sync，按 uv.lock 冻结）"
(cd backend && uv sync --frozen --dev)

# --- 3. 前端（可选；Docker 路径不需要本机 Node） ----------------------------------------
if $WITH_FRONTEND; then
  command -v npm >/dev/null 2>&1 || die "未找到 npm，请先安装 Node 20+（或改用 Docker 路径，镜像内自带构建）"
  say "安装并构建前端"
  (cd frontend && npm ci --no-audit --no-fund && npm run build)
else
  say "跳过前端（需要时加 --with-frontend，或改用 Docker 路径）"
fi

# --- 4. .env 引导 ---------------------------------------------------------------------
if [[ ! -f .env ]]; then
  cp .env.example .env
  say "已从 .env.example 生成 .env —— 必须填写 LLM_MODEL / LLM_BASE_URL / LLM_API_KEY"
  say "本地一次性 POC 令牌可这样生成：openssl rand -hex 32"
else
  say ".env 已存在，跳过"
fi

# --- 5. 自检 ---------------------------------------------------------------------------
say "后端可导入性自检"
(cd backend && .venv/bin/python -c "import audit.app; print('audit.app OK')")

say "全部就绪。下一步："
echo "  开发栈:     ./scripts/start.sh            # 后端 8899 + 前端 5173"
echo "  容器栈:     docker compose up -d --build  # 需先在 .env 填好 LLM_*"
echo "  注册场景:   python3 scripts/register_scenarios.py http://127.0.0.1:8899"
echo "  数据集核对: python3 scripts/verify_lab30_dataset.py <靶场源码.zip> datasets/lab30-shop/ground_truth.json"
