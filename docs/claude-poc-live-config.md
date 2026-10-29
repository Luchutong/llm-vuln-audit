# Claude Code SDK／DeepSeek 本机接入配置

日期：2026-10-28。用户明确选择复用本机 Claude Code 的 DeepSeek 配置，通过 Claude Code SDK 运行 POC。此前的离线准备记录保留为当时状态；本文记录本次配置。

## 生效配置

| 项目 | 配置 |
|---|---|
| POC 运行层 | `claude_sdk` |
| 真实模型提供商／模型 | DeepSeek／`deepseek-flash` |
| Anthropic 兼容上游 | `https://api.deepseek.com/anthropic` |
| SDK 唯一模型出口 | `http://127.0.0.1:8899/api/internal/poc-gateway` |
| 网关 | `POC_CLAUDE_GATEWAY_ENABLED=1` |
| SDK／CLI | `0.2.174`／`2.1.310` |
| 隔离目录 | `.run/claude-poc-workspace`，权限 `0700` |
| 阶段请求上限 | execute 40／conclude 3；按 run／epoch 累计，宿主总预算及首次开立值仍有效 |

DeepSeek 官方说明其 Anthropic 兼容基址包含 `/anthropic`，支持使用真实 DeepSeek 模型名与 `x-api-key` 认证。来源：[DeepSeek Anthropic API 文档](https://api-docs.deepseek.com/guides/anthropic_api/)。本次使用真实模型名，不使用 Claude 模型别名映射。

凭据从本机 `~/.claude/settings.json` 的既有配置复制到项目 `.env`，只由宿主网关读取；没有写入本文、命令输出或 SDK 子进程配置。`.env` 权限收紧为 `0600`，并继续由 Git 忽略。原配置及重启前应用日志保存在 `.run/backups/` 的私有备份目录中；备份位置索引为 `.run/claude-poc-config-backup-path`。

Planner／Worker 继续使用原有 `LLM_*` 配置。Lab30 与 runner 沿用正在运行的连接，现有本机 runner 地址已保存到 `.env`，后续普通应用重启也可复用；本次不执行 Compose、不重置靶场、不创建审计或 Prompt 实验。重启前已检查两类任务均无活动项。

## 核验范围

- 现有凭据请求 DeepSeek `GET /models` 返回 **200**，列表包含 `deepseek-flash`。
- 显式加载项目 `.env` 后，离线配置诊断全部通过，`ready_for_live=true`。
- 本项目的前后端已重启，网关健康接口返回 **200／ready=true**；应用配置确认 `runtime=claude_sdk`、POC 已启用且 runner 已配置，前端返回 **200**。
- 重启前后审计记录均为 **10 条**，重启后无活动审计；已有 3 个取消的 Prompt 实验保持原状态。
- 生成请求数为 **0**，没有执行真实 POC。模型工具调用、结构化结论与证据门禁仍需单条真实试跑验收；配置就绪不代表这些能力已通过。

诊断脚本默认只读进程环境。需要核对 `.env` 时，在仓库根目录显式加载：

```bash
backend/.venv/bin/python - <<'PY'
import runpy, sys
from pathlib import Path
sys.path.insert(0, str(Path('backend').resolve()))
from audit.config import load_env_file
load_env_file(Path('.env').resolve())
raise SystemExit(runpy.run_path('scripts/check_claude_poc.py')['main'](['--require-ready']))
PY
```

上述命令仅输出版本及配置条件，不输出凭据、不创建运行。实际服务的网关状态可通过 `GET /api/internal/poc-gateway/health` 查看，该接口也不请求模型。
