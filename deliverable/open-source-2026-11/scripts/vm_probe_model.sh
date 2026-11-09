#!/usr/bin/env bash
# 在虚拟机内用 .env 的凭据做一次最小模型调用，确认 Key 有效、地址正确、有额度。
# 不打印任何密钥内容。
cd '/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main' || exit 1
set -a; . ./.env; set +a

code=$(curl -s -o /tmp/probe.json -w '%{http_code}' --max-time 40 \
  "$LLM_BASE_URL/chat/completions" \
  -H "Authorization: Bearer $LLM_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"'"$LLM_MODEL"'","messages":[{"role":"user","content":"ping"}],"max_tokens":4}')

echo "HTTP $code"
python3 - <<'PY'
import json, pathlib
p = pathlib.Path('/tmp/probe.json')
raw = p.read_text(errors='replace')
try:
    d = json.loads(raw)
except Exception:
    print('非 JSON 响应:', raw[:200])
    raise SystemExit
if 'error' in d:
    print('ERROR:', str(d['error'].get('message', ''))[:180])
else:
    print('OK model=', d.get('model'), '| usage=', d.get('usage'))
PY
