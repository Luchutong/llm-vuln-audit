# Claude POC SDK 离线准备记录

日期：2026-10-28。本记录证明安装、宿主适配与离线门禁准备，不代表真实模型或真实靶场端到端验收。本次 **真实模型请求 0、真实 runner 调用 0**，没有读取 `.env` 或秘密，没有打开项目的 `data/audit.db`。

## 当前状态

| 项目 | 已核验状态 |
|---|---|
| 默认模型运行层 | `legacy`；没有切换生产默认值 |
| SDK | `claude-agent-sdk==0.2.174`，已在 `backend/.venv` 安装；`pyproject.toml` 的 `poc-claude` extra 与 `uv.lock` 固定版本 |
| SDK wheel 内 CLI | 仅以 `--version` 核验，输出 `2.1.310 (Claude Code)`；没有启动 CLI query |
| HTTP 网关 | 已实现并挂载 `/api/internal/poc-gateway`，默认 `POC_CLAUDE_GATEWAY_ENABLED=0` |
| 启用所需配置 | 上游地址/宿主凭据、Claude 模型 ID、SDK 可达网关地址与隔离工作目录仍需用户配置；本次未配置实际服务 |
| 动态能力 | 阶段签发并撤销，绑定 run/epoch/stage/model/context/finding/TTL；能力只保留哈希，重启失效 |
| 请求计费 | 一次事务扣请求 quota、run responses、存在时的 workflow POC responses，并写 `poc_gateway_request`；SDK 最终用量不再扣请求数 |
| 提示与错误处理 | `verbatim_prompts=True` 防止 CLI 本地展开/命令分派，要求 CLI 至少 `2.1.248`；SDK 原始异常正文不持久化 |
| 离线诊断 | `scripts/check_claude_poc.py` 只读当前进程配置与包元数据；CLI 仅 `--version`，不加载 `.env`、不打开数据库、不联系上游 |

默认 40 次 execute 与 3 次 conclude 均为 `(run, epoch, stage)` 整轮累计额度，不是每条 finding 的额度。conclude 的整个 epoch 预算还包含修正请求；多 finding 的真实验收前应由用户明确配置 3..16 范围内的结论额度，并同时保证 run/workflow 总额足够。本次没有扩大配额或改变固定键。

## 离线验收

最终完整回归（2026-10-28）：

| 检查 | 结果 |
|---|---|
| 全部后端测试 | **1955 passed, 1 warning，46.08s**；警告来自刻意构造重复文件名的 ZIP 测试 |
| 前端 `npm test` | **99 passed** |
| 前端 `npm run build` | 通过；仍有现有的构建产物体积提示 |
| SDK 兼容与准备回归 | **42 passed**，含真实 SDK `ResultError` 在错误终态后的匹配与失败关闭 |
| `uv lock --check --project backend` | 通过，SDK 依赖锁一致 |
| `bash -n scripts/start.sh`、`git diff --check` | 通过 |
| 独立配置诊断 | SDK **0.2.174**、bundled CLI **2.1.310**；`model_requests=0` |

最终后端命令为 `backend/.venv/bin/python -m pytest backend/tests -q --basetemp=<独立临时目录>`。本机磁盘同步写入阻塞后，将最终完整回归的临时目录放在 `/dev/shm`，结束后删除，仅用于临时数据；这不是持久化性能测试。新增测试未使用真实上游、现有审计库或 Lab30。配置诊断未加载实际 `.env`；清空环境核验输出 `ready_for_live=false`，不据此推断现有服务已配置什么。

预算与执行回归执行命令（在 `backend`）：

```bash
.venv/bin/pytest -q \
  tests/test_poc_gateway_budget.py \
  tests/test_discovery_workflow.py \
  tests/test_execution_stability.py \
  tests/test_timed_comparison_api.py \
  tests/test_claude_poc_runtime.py::test_store_quota_is_durable_and_per_stage
```

记录结果：**88 passed in 23.35s**。全部使用临时 SQLite、模拟时钟或模拟调用。覆盖跨连接并发准入、SDK/native 共享原有预算、epoch/阶段/暂停/取消/截止门禁、准入事件失败整笔回滚、历史无 limits 的如实处理、恢复后不续领 run/workflow 配额，以及最后一个已获准响应仍能发布。

该结果包含共享结论额度的新规则：global 或 workflow 只剩 4 次、conclude 尚余 3 次时，并发 execute 仅获准 1 次；随后 execute 返回局部 `quota_exhausted` 和 `conclusion_reserved=true`，不写全局停止原因，3 次 conclude 仍可准入。只剩结论额度时不启动实验，已用结论额度也不会重复保留。原 native/legacy 准入计费规则保持。

相关离线测试资产：

| 文件 | 验证方法与边界 |
|---|---|
| `backend/tests/test_claude_poc_runtime.py` | FakeSDK 验证两个阶段、工具撤回、证据引用、结构化结论与无旧循环回退 |
| `backend/tests/test_claude_poc_sdk_compat.py` | 已安装的真实 SDK 创建 options/MCP，并使用内存自定义 transport 运行 SDK 控制协议；不启动真实 CLI、不联系模型 |
| `backend/tests/test_poc_model_gateway.py` | ASGI + `httpx.MockTransport` + 临时 SQLite 验证 HTTP JSON/SSE、动态能力、固定上游认证、重试和 `count_tokens` |
| `backend/tests/test_claude_poc_preparation.py` | 真实进程环境过滤、前置 readiness、宿主剩余预算、工具准入，以及适配器→HTTP 网关→临时 SQLite 的模拟上游整链路 |
| `backend/tests/test_poc_gateway_budget.py` | 临时 SQLite 验证请求额度与 run/workflow 的原子计费、原子准入日志和拒绝门禁 |
| `backend/tests/test_claude_poc_diagnostic.py` | 模拟配置及 CLI 版本探测，验证诊断不输出秘密、不读取 `.env` 或打开审计数据库 |

真实 SDK 的内存协议测试与真实 HTTP 网关的模拟上游测试分别验证了对应边界；两者不能合并解读为「真实 CLI 已通过真实上游」。

本机配置诊断可从仓库根目录运行：

```bash
backend/.venv/bin/python scripts/check_claude_poc.py
backend/.venv/bin/python scripts/check_claude_poc.py --require-ready
```

脚本仅检查当前已导出的配置，不自动读取 `.env`。`--require-ready` 在任一配置条件不满足时退出 1。即使输出 `ready_for_live: true`，仍保持 `model_requests: 0` 和 `live_connectivity_checked: false`，不代表真实上游验收通过。

## 启用前仍需完成

部署设置与事件解释见 [运行文档](poc-runtime.md)。`/health` 的 `ready=true` 只表示本机配置完整，不证明上游能接受该模型、SSE 或结构化输出。

真实验收需由用户另行显式启动，记录所选上游/模型、SDK/CLI 版本、run/epoch、实际 `poc_gateway_request` 次数、tokens/费用（未知即未知）、阶段停止原因、原始作业证据与结论发布状态。还需验证真实 CLI 的取消退出、非持久化选项、宿主/容器环境和 managed policy。完成前保留 `legacy` 默认与关闭的网关；不能根据本记录把离线模拟结果当成模型效果或真实付费验收。
