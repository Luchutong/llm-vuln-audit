# POC SDK 生成策略与真实进度

实施日期：2026-10-30。适用于 `POC_RUNTIME=claude_sdk` 的新建运行；历史运行缺少冻结字段时保持原有行为。不改写历史运行、冻结报告或 Prompt 实验预算。

本文对应 [poc-verification-convergence-plan.md](poc-verification-convergence-plan.md) §8。持久会话队列见 [poc-session-queue.md](poc-session-queue.md)，SDK 部署边界见 [poc-runtime.md](poc-runtime.md)，离线验收结果与部署步骤见 [poc-convergence-acceptance.md](poc-convergence-acceptance.md)。

## 1. 生成参数是冻结配置，不是 UI 声明

审计自己的 `AgentPolicy.max_tokens` 传不到 SDK 子进程。因此 SDK 运行冻结独立的 `poc_policy.sdk_generation`：

| 字段 | 默认 | 环境变量 | 说明 |
|---|---|---|---|
| `output_policy` | `bounded-v1` | `POC_SDK_OUTPUT_POLICY` | `bounded-v1` 设置输出上限；`provider_default` 保持已安装 SDK/CLI 原行为。 |
| `execute_output_tokens` | 4096 | `POC_SDK_EXECUTE_OUTPUT_TOKENS`（256–65536） | 实验阶段的单次输出上限。 |
| `publish_output_tokens` | 1024 | `POC_SDK_PUBLISH_OUTPUT_TOKENS`（128–65536） | 结论阶段的单次输出上限。 |
| `thinking` | `disabled` | `POC_SDK_THINKING`（`disabled`/`provider_default`） | `disabled` 显式关闭思考；`provider_default` 不发送该选项。 |

数值是同模型小样本评估的起点，不是性能保证。`POC_SDK_*` 的取值在进程启动时严格解析，非法值直接失败；运行期以冻结快照为准，`policy_from_snapshot()` 不会用当前默认值替换历史运行的配置。

### 1.1 适配实际 SDK 能力

- `bounded-v1` 通过安装的 CLI 环境变量 `CLAUDE_CODE_MAX_OUTPUT_TOKENS` 传递当前阶段的输出上限；`provider_default` 不设置该变量。
- `thinking=disabled` 通过 SDK 的 `thinking={"type":"disabled"}` 选项传递。若已安装 SDK 的 `ClaudeAgentOptions` 没有该字段，就绪检查返回 `sdk_thinking_unsupported` 并拒绝启动该 attempt；不会静默删字段、改模型或回退。
- 冻结块无法解析（版本、策略名、数值范围）时抛错，attempt 以运行期配置错误结束，而不是换一套生成策略继续跑。

### 1.2 网关独立核验

宿主签发的网关能力令牌携带本阶段的 `max_output_tokens` 与 `thinking`；网关在转发前检查真实请求体：

| 情况 | 结果 |
|---|---|
| `max_tokens` 缺失或不是正整数 | 拒绝，`poc_gateway_output_cap_missing`，记录 `output_cap_missing` 诊断。 |
| `max_tokens` 超过冻结上限 | 拒绝，`poc_gateway_output_cap_exceeded`，记录 `output_cap_exceeded`。 |
| 冻结 `thinking=disabled` 但请求体包含其他 thinking 类型 | 拒绝，`poc_gateway_thinking_rejected`，记录 `thinking_rejected`。 |
| 冻结 `provider_default`（未启用核验） | 不检查、不记录，等同历史运行。 |

网关只持久化白名单元数据（阶段、错误码、HTTP 状态、provider 错误类型/代码、时间），不保存请求正文、响应正文或凭据。`generation_for_capability()` 暴露的是网关实际观察到的事实，运行事件读取它，而不是复述配置。

### 1.3 截断与超时

- `finish_reason=length` 等截断仍按不完整结果处理：不拼接补造 JSON 或脚本，不把截断输出当成完整结论。
- 不恢复旧的固定 60/180 秒强制截断；连接超时、流空闲超时、阶段窗口和整次运行截止仍有效。
- 本次没有更换真实模型，也没有发出计费调用；真实配置差异需要用户显式启动对照。

## 2. 真实进度：五类事实分开记录

| 类别 | 记录位置 | 内容 |
|---|---|---|
| 宿主存活 | `poc_queue_heartbeat` | 最近心跳、当前项耗时、软提醒是否超时。只说明宿主进程仍在运行。 |
| 模型请求 | `poc_gateway_stream` | 请求开始、首事件时间、最近流事件、事件类型计数、结束/断流及累计等待。 |
| 模型生成 | `poc_queue_progress` | 文本、thinking、工具参数的字符数与事件数；只存元数据，不存思考或输出正文。 |
| 实验成果 | 作业与检查点事件 | 已完成作业、观测、检查点、重复/补证、最近业务进展时间。 |
| 正式结论 | 发布事件与验证记录 | 是否发布、结论状态、引用与正式复核状态。 |

### 2.1 网关流事件

`poc_gateway_stream` 有两种状态：

- `progress`：限频发出，每 5 秒最多一次、整条流最多 120 次；只有出现 `ping`/`message_stop` 之外的帧才允许发出。
- `end`：流结束或中断时发出。成功结束时 `completed=true`；断流时带 `code`。

载荷只包含 `state`、`stage`、`finding_id`、`context_id`、`execution_epoch`、`elapsed_seconds`、`received_bytes`、`events_received`、`content_events`、`event_types`、`usage`（仅数字 token 计数）、`completed`，以及可选的 `first_event_seconds`、`code`。

HTTP 200 只表示响应头已到达；`ping`/keepalive 与 `message_stop` 不计入 `content_events`，也不单独触发进度事件。首事件时间、字节数与事件类型是判断“正在生成”还是“连接空转”的依据。

### 2.2 队列进度事件

`poc_queue_progress` 在生成过程中最多每秒更新一次，包含：

- `model_wait_seconds`：等待本次模型响应的时长；
- `since_last_experiment_seconds`：距上次实际业务进展的时长；
- `public_output_chars`、`thinking_chars`、`tool_arg_chars`：仅计数；
- `response_events`：已收到的 SDK 消息数；
- `observations`、`jobs`：已完成实验与作业数；
- `published` 与 `unpublished_reason`：是否已发布；未发布时给出宿主判定原因（流中断、尚无已完成作业、尚未读取证据、尚未调用发布等）。

## 3. 同一统计对象：JSON、Markdown、页面

服务端在 `execution_summary.poc_statistics` 输出唯一对象（`version="poc-statistics-v1"`），三个消费方读取同一份数据：

| 消费方 | 位置 |
|---|---|
| JSON | 运行详情、报告导出 `run.execution_summary.poc_statistics` |
| Markdown | 报告“### POC 统计”小节 |
| 页面 | 执行状态面板的 `PocStatisticsFacts` |

对象分为 `host`、`model`、`generation`、`experiments`、`conclusion`、`recovery`、`continuation`、`unfinished` 八块：实验耗时、模型等待、已执行/已发布数、重复/补证次数、恢复消耗及未完成原因都在其中。

`continuation` 把沿用结果（`inherited`）与本轮新增（`current_status`、`retested`）分开：继承的 verified 不被报告成本轮成果。POC 关闭或历史运行没有该对象时不输出空表，避免把“未测量”读成“为零”。

### 3.1 前端

- 心跳与模型进度分别合并：新心跳不再替换 `poc_queue_progress`，两者以不同标题同时显示。
- 执行页至少显示“等待本次模型响应 N 秒”“距上次实验 M 秒”“已有 N 个观测，尚未发布及原因”。
- 心跳行明确写明“心跳只说明宿主仍在运行，不代表模型有新进展”。
- 失败、中断后仍可直接查看已有作业、检查点和未完成项。

## 4. 离线验收

使用模拟 SDK、模拟上游、临时 SQLite 与全部拦截的浏览器 API；未连接真实模型、未产生计费调用、未启动新审计、未重置靶场。

- 后端定向回归：`test_poc_model_gateway.py`、`test_claude_poc_runtime.py`、`test_claude_poc_queue.py`、`test_poc_store.py`、`test_recent_closure_repair.py`、`test_report_poc_statistics.py` 共 159 passed。范围更大的 22 文件定向回归 476 passed，后端全量 2182 passed / 2 failed（失败原因见验收记录），逐项数字与命令见 [poc-convergence-acceptance.md](poc-convergence-acceptance.md)。
- 覆盖：冻结配置写入 SDK 环境与选项；SDK 缺少 thinking 字段时就绪失败；网关对 `max_tokens` 缺失/超限、thinking 非 `disabled` 的拒绝；`provider_default` 不核验也不记录；流元数据的限频、首事件、usage、断流原因；ping-only 流不发进度；队列 `poc_queue_progress` 与心跳分离；统计对象的五类事实、沿用/本轮拆分与 POC 关闭时缺省；报告、JSON 与页面读取同一对象。
- 前端 `npm test`：111 passed；`npm run build` 通过（保留已有 chunk 大小提示）。

真实 SDK 的模型输出上限、thinking 兼容性、成本与吞吐需要用户显式启动验收；上述离线结果不替代真实结论验证。
