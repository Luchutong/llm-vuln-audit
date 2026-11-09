#!/usr/bin/env bash
# 把模型凭据写进虚拟机上的 .env 并重启后端，使其 /api/config 变为 configured=true。
#
# 用法：
#   bash scripts/vm_set_model.sh <LLM_MODEL> <LLM_BASE_URL> <LLM_API_KEY>
#
# 说明：
#   - 凭据只写入 VM 的 .env（AUDIT_DATA_DIR 同目录），不回显到终端日志；
#   - 重启后调用 /api/config 校验，只有 configured=true 才算成功；
#   - 若 .env 已有同名键则原地替换，不会重复追加。
set -euo pipefail

MODEL="${1:-}"
BASE_URL="${2:-}"
API_KEY="${3:-}"

if [ -z "$MODEL" ] || [ -z "$BASE_URL" ] || [ -z "$API_KEY" ]; then
  echo "usage: bash scripts/vm_set_model.sh <LLM_MODEL> <LLM_BASE_URL> <LLM_API_KEY>" >&2
  exit 2
fi

REPO_LOCAL="${REPO_LOCAL:-$(pwd)}"
VM_REPO="/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main"
TMP_LOCAL="$(mktemp -d)"
trap 'rm -rf "$TMP_LOCAL"' EXIT

# 1) 凭据文件（只在本地临时目录生成，随后推送到 VM /tmp）
cat > "$TMP_LOCAL/llm_vars.env" <<EOF
LLM_MODEL=$MODEL
LLM_BASE_URL=$BASE_URL
LLM_API_KEY=$API_KEY
EOF

# 2) 合并脚本：按 key 覆盖写入 .env，保留其余配置
cat > "$TMP_LOCAL/merge_env.py" <<'PY'
import pathlib
import sys

vars_path, env_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
pairs = {}
for line in vars_path.read_text(encoding="utf-8").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        pairs[key.strip()] = value

existing = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
out, seen = [], set()
for line in existing:
    key = line.split("=", 1)[0] if "=" in line else None
    if key in pairs:
        out.append(f"{key}={pairs[key]}")
        seen.add(key)
    else:
        out.append(line)
for key, value in pairs.items():
    if key not in seen:
        out.append(f"{key}={value}")

env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
print("merged keys:", ", ".join(sorted(pairs)))
PY

cd "$REPO_LOCAL"
MSYS_NO_PATHCONV=1 python scripts/vm_ssh.py write "$TMP_LOCAL/llm_vars.env" /tmp/llm_vars.env
MSYS_NO_PATHCONV=1 python scripts/vm_ssh.py write "$TMP_LOCAL/merge_env.py" /tmp/merge_env.py

# 3) 合并 .env，然后重启后端使配置生效
MSYS_NO_PATHCONV=1 python scripts/vm_ssh.py run "cd '$VM_REPO' && ls -la .env 2>/dev/null; python3 /tmp/merge_env.py /tmp/llm_vars.env .env && grep -c '^LLM_' .env" 120

MSYS_NO_PATHCONV=1 python scripts/vm_ssh.py run "cd '$VM_REPO' && pkill -f 'uvicorn audit.app' 2>/dev/null; sleep 2; mkdir -p .run data; setsid nohup /home/zsh/.local/bin/uv run --project backend --frozen --extra poc-claude uvicorn audit.app:app --host 0.0.0.0 --port 8899 > .run/backend.log 2>&1 < /dev/null & sleep 12; echo restarted" 180

# 4) 校验：只打印脱敏后的状态
MSYS_NO_PATHCONV=1 python scripts/vm_ssh.py run "curl -s -m 8 http://127.0.0.1:8899/api/config" 60
