#!/bin/bash
# 在虚拟机上以脱离会话的方式拉起后端(8899)与前端(5173)。
set -u
export PATH="$HOME/opt/node/bin:$HOME/.local/bin:$PATH"
REPO="/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main"
cd "$REPO" || exit 1

pkill -f "uvicorn audit.app:app" 2>/dev/null || true
pkill -f "node_modules/.bin/vite" 2>/dev/null || true
sleep 1

cd "$REPO/backend" || exit 1
setsid nohup .venv/bin/python -m uvicorn audit.app:app --host 0.0.0.0 --port 8899 \
    > /tmp/be.log 2>&1 < /dev/null &

cd "$REPO/frontend" || exit 1
setsid nohup env VITE_API_TARGET=http://127.0.0.1:8899 ./node_modules/.bin/vite --host 0.0.0.0 --port 5173 \
    > /tmp/fe.log 2>&1 < /dev/null &

sleep 16
echo "== listeners =="
ss -ltn 2>/dev/null | grep -E ':(8899|5173)' || echo no_listeners
echo "== health =="
curl -s -o /dev/null -w "backend=%{http_code}\n" --max-time 6 http://127.0.0.1:8899/api/config
curl -s -o /dev/null -w "frontend=%{http_code}\n" --max-time 6 http://127.0.0.1:5173/
echo "== backend log =="
tail -8 /tmp/be.log 2>/dev/null
echo "== frontend log =="
tail -5 /tmp/fe.log 2>/dev/null
