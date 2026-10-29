# POC 模型运行层：Claude Agent SDK adapter

本文说明 `POC_RUNTIME=claude_sdk` 的部署方式与边界。默认值仍是 `legacy`：SDK 路径必须先在目标机器上完成能力核验，再用显式配置启用。

2026-10-28 已完成 SDK 安装和离线准备：锁定的 `claude-agent-sdk==0.2.174` 可导入，其 wheel 内 CLI 为 `2.1.310`。仓库已提供实际 HTTP 网关；网关默认关闭，上游地址/凭据、模型和隔离工作目录仍待部署方配置。本次准备 **真实模型调用为 0**。验收范围与未验证项见 [准备记录](claude-poc-preparation.md)。

相关代码：

| 文件 | 职责 |
|---|---|
| `backend/audit/poc_tool_service.py` | runner 工具、身份前提、作业表、产物与原文证据视图。**没有**模型循环。 |
| `backend/audit/runtimes/claude_poc.py` | 唯一的 SDK adapter：readiness、两个固定阶段、请求网关、证据 ID、结论校验。 |
| `backend/audit/poc.py` | 宿主侧编排：何时验证、准备靶场、选择 runtime、持久化结论。 |
| `backend/audit/poc_model_gateway.py` | Anthropic HTTP/SSE 网关、动态能力令牌、固定上游与请求准入。 |
| `backend/audit/poc_store.py` / `backend/audit/execution_state.py` | 同一事务中的阶段额度、run/workflow 计费、真实准入日志与运行门禁。 |
| `backend/audit/runtimes/claude_cli.py` | 启动已核验 CLI 前清理继承环境，隔离真实上游凭据与替代出口。 |

## 1. 职责边界

| SDK 管理 | 宿主管理 |
|---|---|
| 模型请求、工具选择、上下文压缩、会话内停止 | run/finding/revision/epoch 所有权、取消与迟到写入门禁 |
| MCP 工具调用与结构化输出格式 | 靶场租约、上下文、身份与角色前提 |
| SDK 用量与运行事件 | 作业原子预约、幂等提交、原作业查询、真实执行事实 |
| JSON Schema 形状校验 | 正常/攻击原文证据、XSS 浏览器证据、最终发布门禁 |

`PocToolService.call` 是工具契约的唯一实现；SDK 的 MCP 注册只是传输层。作业表是事实来源，adapter 不复制 `jobs/scripts/observations/state_changes`。

## 2. 启用前的能力核验

`ClaudeCodePocRuntime.readiness()` 会在每个 attempt 开始时检查，并把结果写入 `poc_runtime_readiness` 事件。任一项不满足，该 attempt 以 `unavailable` 结束，**不会**回退到旧循环：

| reason | 条件 |
|---|---|
| `sdk_missing` | `import claude_agent_sdk` 失败 |
| `sdk_version_mismatch` | 设置了 `POC_CLAUDE_SDK_VERSION` 且实际版本不符 |
| `model_unconfigured` | `POC_CLAUDE_MODEL` 为空 |
| `gateway_unconfigured` | `POC_CLAUDE_GATEWAY_URL` 不是 http(s) 地址 |
| `workspace_unconfigured` / `workspace_missing` / `workspace_not_isolated` | 隔离任务目录缺失、不存在或位于项目根目录/含 `.git` |
| `cli_missing` / `cli_unavailable` | `claude --version` 不可执行 |
| `cli_version_mismatch` | 设置了 `POC_CLAUDE_CLI_VERSION` 且实际版本不符 |
| `cli_verbatim_unsupported` | CLI 低于 `2.1.248` 或版本无法识别，不能保证支持 verbatim prompts |
| `gateway_service_missing` | 宿主未挂载受控网关服务 |
| `disabled` / `upstream_not_configured` / `invalid_upstream_configuration` | 网关未启用、缺少上游配置或配置无效 |

核验顺序建议：

```bash
# 检查本机包、wheel 内 CLI 和当前进程已导出的配置；不创建 Store，不请求模型
backend/.venv/bin/python scripts/check_claude_poc.py
# 同样离线；本机配置检查未全通过时返回退出码 1
backend/.venv/bin/python scripts/check_claude_poc.py --require-ready
```

诊断脚本不加载 `.env`、不打开审计数据库、不请求健康接口或上游；唯一的子进程命令是已安装 wheel 内 CLI 的 `--version`，使用清理后的环境。JSON 只包含版本、各配置项是否满足和 `model_requests: 0`，不打印地址、模型名、工作目录或凭据。`ready_for_live` 仅表示本机配置检查通过，`live_connectivity_checked` 始终为 `false`。

上面的命令从仓库根目录运行。依赖由 `backend/pyproject.toml` 的 `poc-claude` extra 和 `backend/uv.lock` 固定；重新安装可在 `backend` 执行 `uv sync --locked --extra poc-claude --extra dev`。启动脚本默认安装基础依赖，使用 SDK 时需保留该 extra，避免后续普通 `uv sync` 移除它。

即使 readiness 通过，也不代表已做真实付费验收。本次只运行版本核验与离线测试。生产服务启动后可能恢复队列中已授权的运行，因此不要把启动审计服务当成纯只读的 SDK 核验命令。

### 部署配置

| 设置 | 用途与默认行为 |
|---|---|
| `POC_RUNTIME=legacy` | 默认继续使用旧循环；选择 SDK 必须显式设为 `claude_sdk` |
| `POC_CLAUDE_GATEWAY_ENABLED=0` | 内置 HTTP 网关默认关闭；启用时设为 `1` |
| `POC_CLAUDE_GATEWAY_URL` | SDK 可达的本服务网关地址，如 `http://127.0.0.1:8899/api/internal/poc-gateway`；容器内按实际网络调整 |
| `POC_CLAUDE_UPSTREAM_URL` | 宿主访问的 Anthropic 协议上游基址；网关在其后拼接 `/v1/messages`，不能使用 OpenAI chat/completions 地址 |
| `POC_CLAUDE_UPSTREAM_API_KEY` | 仅宿主网关持有的上游凭据，不传给 SDK 子进程 |
| `POC_CLAUDE_MODEL` | 上游实际支持的模型 ID，与能力绑定的模型必须一致；兼容提供商保留真实模型名 |
| `POC_CLAUDE_WORKSPACE` | 独立任务工作目录，不能是项目根目录或带 `.git` 的目录 |
| `POC_CLAUDE_SDK_VERSION=0.2.174` / `POC_CLAUDE_CLI_VERSION=2.1.310` | 本次核验版本；配置后 readiness 会拒绝不符版本 |

生产 `StorePocRequestGateway` 在阶段开始时动态签发能力，绑定 run/epoch/stage/model/context/finding 和到期时间，阶段退出时撤销；无需手工设置固定 `POC_CLAUDE_CAPABILITY_TOKEN`。能力只保留哈希，进程重启后失效，额度与真实准入记录仍保存在 SQLite。`GET /api/internal/poc-gateway/health` 只返回就绪状态，不请求上游，也不证明上游协议可用。

2026-10-28 已按用户选择配置本机 DeepSeek 上游；运行层为 `claude_sdk`，真实模型为 `deepseek-flash`。本机配置与生效核验见 [真实接入配置记录](claude-poc-live-config.md)，该记录不代替真实 POC 试跑验收。

## 3. 两个固定阶段

1. **实验阶段**（`execute`）：`tools=[]` + 仅本项目的 MCP server（`strict_mcp_config=True`），`allowed_tools` 列出全部 POC 工具，`permission_mode="dontAsk"`。系统提示词由 `execute_instructions()` 显式提供，不依赖 Claude Code 的默认提示。
2. **结论阶段**（`conclude`）：`mcp_servers={}`、不注册任何工具、无 `allowed_tools`，用 `output_format={"type": "json_schema", ...}` 获取结构化结论。执行阶段之后任何工具调用都会被 `call_tool` 拒绝并记录 `poc_runtime_tool_withdrawn`。

两个阶段都设置 `verbatim_prompts=True`，防止待验证源码/证据中的 `@path` 等文本被 CLI 当成本地文件展开或命令分派。readiness 要求 CLI 至少 `2.1.248`；本次核验的 `2.1.310` 满足该下限。此项与工具撤回、独立工作目录和网关门禁分别生效，不代替部署隔离。

只读取最终 `ResultMessage.structured_output`；中间工具输入、自由文本和实验阶段的输出都不会成为候选结论。`subtype != "success"` 即使带了 structured output 也按格式失败处理。

结论候选还要经过现有 `host_check`（作业可用性、同一 context、身份前提、原文片段属于对应通道、XSS 浏览器证据）。`host_check` 降级后最多给一次语义修正；修正在同一阶段额度内。

## 4. 硬配额

- 实验开始**之前**先为结论阶段开立额度（默认 3 次真实请求），再开立实验额度（默认 40）。
- 新建 `review_policy=batch-v1` 运行使用宿主生成的 `(run_id, execution_epoch, finding/ledger revision, stage)` 额度，独立保存每条当前结论的执行与发布预算；同一版本重新开立不重置、不加额。旧运行仍保留 `(run_id, execution_epoch, stage)` 的共享口径，不改历史记录。
- 首次开立还会取宿主为当前 attempt 下发的 `max_responses` 上限：先留出结论额度，再限制实验额度；`max_seconds` 同样取配置与宿主剩余时间的较小值。因此环境中写的 40/3 不保证本轮实际开立 40/3，应以 `poc_runtime_quota_opened` 和 SQLite 的实际额度为准。
- 新政策的 conclude=3 是**每条当前结论的发布上限**，包含格式/语义修正；开立仍受宿主单次 allowance 限制，并继续扣减原有 run/workflow 总预算，不意味着每条都能获得配置值 40+3。旧政策的 conclude=3 仍是整个 epoch 的共享上限。
- 每次生成请求在一个 SQLite 写事务中校验 epoch、运行状态、POC 阶段、截止及额度，然后同时递增 `poc_request_quota.used`、`run_execution_state.responses_used`、存在时的 `workflow.used.poc`，并写一条 `poc_gateway_request`。任一写入失败全部回滚；SDK 重试、上下文压缩、格式/语义修正均重新准入。
- run/workflow 剩余额度优先于配置的阶段请求上限；不存在历史 run limits 时不虚构默认上限，仍执行已开立的请求额度。
- 额度耗尽后返回 `quota_exhausted` 并把该阶段标记为最终拒绝（`quota_refused`），SDK 必须停止而不是收到可重试的 429。
- 阶段剩余额度不足 1 次时，不启动实验，返回 `deferred`（`quota_deferred`）。
- 宿主在认领和重置靶场前检查共享预算和对应版本额度；SDK 延期不计已处理、不启动下一次空复核，转入有界终审。相关调度、逐项整合及报告冻结见 [闭环交付说明](review-closure-and-report-freeze.md)。
- 实验阶段的局部额度拒绝保留结论额度，结论可基于已完成作业收束；`usage.execute_reason` 记录 `quota_exhausted`。暂停/取消、失效 epoch、整次预算或 POC workflow 预算拒绝会停止本次验证，不能借结论阶段绕过门禁。
- 开立结论阶段额度不绕过共享预算；execute 准入还需为尚未使用的 conclude 额度留出 run/workflow responses。其他 runtime 的消费、真实耗时与取消仍可能使后续结论无法执行。最后一个已获准响应可发布，后续被拒绝的请求不扣请求数。

约束：`max_turns` 只是附加上限，不能代替请求配额；`max_budget_usd` 是 SDK 客户端估算，同样不是硬上限。

内置网关已经挂载到 `/api/internal/poc-gateway`，支持 `POST /v1/messages` 的 JSON/SSE 和 `POST /v1/messages/count_tokens`。仅 Messages 生成请求计入推理额度，token 计数仍需有效能力。健康检查不消费推理额度。模型不匹配、无效/过期能力、非法请求体在转发前拒绝。

网关只向固定上游转发，使用宿主凭据替换客户端认证，不接受客户端指定的 run/stage/context 作为准入依据，不跟随重定向，并限制请求/响应大小与耗时。额度拒绝使用不可重试的 HTTP 400；真实上游返回的重试状态若引发 SDK 重试，每次重试仍重新准入。协议行为已用 ASGI、MockTransport 和临时 SQLite 验证，尚未用真实上游验证。

## 5. 证据引用 ID

结论阶段只看到宿主展示过的片段（与旧版 `_conclusion_jobs` 相同的渲染、24KiB 预算和省略标记）。每个片段得到一个 `ev-<16 hex>` 形式的 `evidence_ref_id`，绑定 context、job、channel、字符区间和内容哈希。

- 模型返回 `normal_refs` / `attack_refs` 里的 ID；宿主解析回真实片段并生成 `PocEvidenceReference`，模型不抄原文。
- 未展示、失败/超时作业、身份前提未核实或其他 context 的作业不会有 ID，引用会触发 `evidence_ref_rejected` 或 `host_check_rejected`。
- 格式修正最多一次，语义修正最多一次；仍不通过则 `conclusion_rejected`，保留原作业，不重新开放实验工具。

## 6. 环境与落盘

- `ANTHROPIC_BASE_URL` 指向受控网关；SDK 的 `ANTHROPIC_AUTH_TOKEN` 只包含阶段动态能力，不含真实上游凭据。CLI 启动包装器清理继承的上游 key、自定义认证头和替代云出口。
- `CLAUDE_CONFIG_DIR` 指向隔离任务目录下的 `.claude`；`setting_sources=[]`、`no-session-persistence`、`CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`，默认不落盘、不 resume。
- 宿主事件只桥接公开进度、工具调用与结果、停止原因、用量，不保存 thinking/reasoning 或 SDK 消息正文。`no-session-persistence` 等禁用选项已设置；真实 CLI 的完整落盘行为仍需部署验收。
- SDK 原始异常正文不写入宿主事件；SDK 崩溃记录异常类型与固定错误描述，避免诊断文本带入提示、上游凭据或响应正文。
- `setting_sources=[]` 不屏蔽全局配置与组织 managed policy；隔离依赖独立进程/容器与空目录，不能靠提示词或该选项保证。

## 7. 事件

| kind | 含义 |
|---|---|
| `poc_runtime_readiness` | 每个 attempt 开始的核验结果（含 reason/model/gateway/sdk/cli 版本） |
| `poc_runtime_unavailable` | attempt 因环境不满足而结束 |
| `poc_runtime_deferred` | 额度不足以执行并收束，未启动实验 |
| `poc_runtime_quota_opened` / `poc_runtime_quota_refused` | 阶段额度开立 / 某次请求被拒绝 |
| `poc_gateway_request` | 真实生成请求获准；与 quota、run/workflow response 扣费同一事务持久化，含准入序号 |
| `poc_runtime_stage` / `poc_runtime_stage_finished` | 阶段开始与结束 |
| `poc_runtime_stage_stopped` / `poc_runtime_stage_failed` / `poc_runtime_cancelled` | 停止原因 |
| `poc_runtime_usage` | 该阶段 usage、费用估算、turns、subtype、provider/model |
| `poc_runtime_conclusion_rejected` | 结论候选被拒绝及原因（格式/引用/host_check） |
| `poc_runtime_conclusion` | 最终结论状态与证据引用数量 |
| `poc_runtime_tool_withdrawn` | 结论阶段出现工具调用 |

用量未知时记 `null`，不写 0。`poc_runtime_usage` 根据一个 SDK query 的最终 `ResultMessage` 汇总 tokens/费用/turns；修正可能让同阶段有多个 query，流在最终结果前取消时用量可能缺失。它不再增加 response 请求数，真实计次以 `poc_gateway_request` 和持久计数为准。验证记录里 `usage.runtime` 冻结 runtime、model、去凭据 gateway、SDK/CLI 版本与限制；`usage.execute_reason` 记录实验阶段是否被截断。

## 8. 取消与回退

- pause/cancel 立即关闭新的 HTTP 准入；adapter 即使没有收到 SDK 消息也会轮询停止标志、截止时间及可信的网关拒绝原因，取消读取任务并在其所有者任务中 `aclose()`，随后撤销阶段能力。静默 transport 的关闭已做离线验证。
- 取消不等于 runner 作业终止：已提交的作业只能按原 ID 查询，不自动重交，也不自动 reset。
- 一个 attempt 只属于一个 runtime；adapter 内没有 catch-all 回退。需要旧循环时，把 `POC_RUNTIME` 设回 `legacy`（或让运行请求声明 `runtime: legacy`），新建 attempt。
- 回退不改写旧运行：历史记录按各自冻结的 `poc_runtime` 解释。

## 9. 迁移记录：新路径没有第二套运行栈

- **没有第二个消息循环。** SDK 拥有模型往返、工具选择与上下文；本仓库不创建 `Execution`，也不重放历史。`_StageToolExecution` 给工具事件编号，并调用原有宿主工具预算准入，不另建计费账本。
- **请求与用量各有来源。** `poc_gateway_request` 是唯一真实请求准入记录；最终 `ResultMessage` 只用于 tokens/费用汇总，不追加 response 计次。SDK 路径不产生旧循环的 `model_request`/`model_response`。
- **没有第二张作业表。** `PocToolService.jobs` 是唯一事实来源；MCP 注册只是传输层。正常完成的调用产生 `tool_call`/`tool_result`，取消时按已持久化的开始与作业事实解释。
- **每次 attempt 冻结**：`poc_snapshot.poc.runtime`、`policy.runtime`，以及验证记录里的 `agent.usage.runtime`（model、去凭据的 gateway、SDK/CLI 版本、各阶段额度与费用上限）。旧记录按各自冻结值解释，切换默认值不改写历史。

切换与回退：

1. 完成第 2 节的核验，在部署环境设置 `POC_RUNTIME=claude_sdk` 与 `POC_CLAUDE_*`，新建 attempt。
2. 回退时把 `POC_RUNTIME` 设回 `legacy`（或让新运行请求声明 `runtime: legacy`）；已执行副作用的 attempt 不切换重跑，已提交作业只能按原 ID 查询。
3. 旧循环仍保留在仓库中，作为回退路径与旧记录解析入口。只有在第 10 节的条件全部实测、且默认 runtime 已切换并稳定后，才移除旧 POC 模型循环的生产启动路径。

## 10. 已验证范围与剩余集成条件

离线已验证真实 SDK 的 options/MCP/结构化 `ResultMessage` 接口（自定义 transport，不启动 CLI query）、静默流停止、HTTP JSON/SSE、重试重新准入、token 计数不扣推理额度、跨连接并发预算、原子日志失败回滚及迟到写入门禁。CLI 仅做版本及帮助信息检查。完整证据见 [准备记录](claude-poc-preparation.md)。

SDK 可能先返回错误 `ResultMessage`，再因 CLI 非零退出抛出 `ResultError`。宿主只在两者类型、子类型及终止原因一致时使用已收到的错误终态分类：实验阶段达到轮次或费用上限后，仍可使用保留的结论额度。缺少终态、成功终态后异常或不匹配异常均终止验证，不发布确定性结论；异常原文不写入事件。

真实模型与 runner 调用仍为 0；以下条件尚未实测，完成前默认值保持 `legacy`、网关保持关闭：

- 用户选定上游和模型的 Anthropic 请求/SSE/结构化输出兼容性。
- 真实 CLI 进程上的 quota 拒绝、静默取消、子进程退出与实际用量报告。
- 实际容器/主机中的网络隔离、managed policy、凭据继承清理和完整落盘行为。
- 真实靶场身份、作业、证据引用及最终结论发布的整体验证。

## 11. 真实试运行清单（由用户显式启动）

以下步骤会真实调用模型并可能产生副作用，仓库不会自动执行。每一步的结果写入迁移记录；任一步不符就先停止，不进入下一步。

1. **核验**：`readiness` 事件中 `ready=true`，`sdk_version`/`cli_version`/`model`/`gateway` 与冻结值一致；`poc_request_quota` 中目标 `(run, epoch)` 没有历史占用。
2. **单条试跑**：新建一个只含少量 finding 的运行，`runtime` 由服务端设为 `claude_sdk`（请求只能降级）。记录 run id、`execution_epoch`、冻结的 `poc_snapshot.policy.runtime`。
3. **事件对照**：每个 attempt 有 `poc_runtime_readiness`；真实获准生成请求各有一条 `poc_gateway_request`。已取得最终结果的 SDK query 有 `poc_runtime_usage`；不应出现旧循环的 `model_request`/`model_response`。工具事件按实际完成情况核对，取消中的调用可能仅留下已开始事实。
4. **配额对照**：各阶段 `used` 分别不超过开立值，合计与 run/workflow 的相应增量一致；每条 `poc_gateway_request` 对应一次准入。未知 SDK 用量不补 0。局部 quota 拒绝后实验停止，整次/阶段预算拒绝后不再新建结论请求。
5. **结论对照**：`status` 为 `verified` 的条目必须能解析回该 context 的可用作业；`host_check` 降级与 `conclusion_rejected` 的原因可在事件中定位。
6. **记录**：commit SHA、SDK/CLI 版本、模型与网关主机（不含凭据）、请求次数、费用估算（未知即未知）、阶段停止原因、结论数量与状态。
7. **回退**：如果试跑未达到第 10 节的验收标准，把 `POC_RUNTIME` 设回 `legacy`，新建 attempt；已执行副作用的 attempt 不切换重跑。

单条试跑通过后，才把默认 runtime 的切换纳入发布变更；旧循环的移除另做一次提交，并保留旧记录解析。
