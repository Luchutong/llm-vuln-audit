# 上下文控制

## 为什么需要它

阶段内审计由 CodeAgent 驱动：每一步都重放本阶段全部 ActionStep 的模型输出与工具结果，
历史只增不减。旧实现只有一个硬闸门——请求序列化后超过 `history_bytes`（原 192KiB）
就直接以 `context_limit` 结束阶段，事件里没有触发时的字节数、阈值或消息构成。
运行 `57df26c8` 的一个任务就是这样在 12 次请求后终止，而当时仍在预算内。

现在的做法是：**先尝试保持在窗口内，再谈终止**。终止仍然是诚实的失败，不是静默截断。

## 预算模型

所有上限都在 `AgentPolicy`（`backend/audit/runtime.py`）上平铺，字段默认值在模块导入时
从环境变量计算（`backend/audit/context_config.py`）。非法值让进程启动失败，而不是静默回退，
否则 `/api/config` 会显示一个实际并未执行的数字。

| 变量 | 默认 | 范围 | 含义 |
|---|---:|---|---|
| `AUDIT_HISTORY_BYTES` | 393216（384KiB） | 64KiB..2MiB | 单次请求序列化后的 UTF-8 字节上限 |
| `AUDIT_HISTORY_SUMMARY` | 1 | 布尔 | 是否允许 LLM 摘要压缩 |
| `AUDIT_HISTORY_SUMMARY_BYTES` | 4096 | 512B..16KiB | 摘要消息本身的上限 |
| `AUDIT_HISTORY_SUMMARY_INPUT_BYTES` | 49152 | 8KiB..128KiB | 送去摘要的旧历史先裁剪到的大小 |
| `AUDIT_HISTORY_SUMMARY_MAX_TOKENS` | 1536 | 256..8192 | 摘要请求的输出上限（禁用思维链） |
| `AUDIT_HISTORY_SUMMARY_RESPONSES` | 2 | 0..8 | 每个阶段允许的摘要请求数 |
| `AUDIT_HISTORY_SUMMARY_RUN_RESPONSES` | 8 | 0..64 | 整次运行允许的摘要请求数 |
| `AUDIT_HISTORY_ACTION_BYTES` | 2048 | 256B..8KiB | 确定性裁剪时旧动作保留的头部 |
| `AUDIT_HISTORY_OBSERVATION_BYTES` | 1024 | 128B..8KiB | 确定性裁剪时旧观察保留的头部 |
| `AUDIT_PLANNER_PINNED_BYTES` | 16384 | 8KiB..64KiB | Planner 保护骨架的常态上限 |
| `AUDIT_PLANNER_PINNED_HARD_BYTES` | 32768 | 16KiB..64KiB | 保护骨架装不下时的一次放宽 |
| `AUDIT_SOURCE_BYTES` / `AUDIT_TOOL_BYTES` / `AUDIT_CODE_OUTPUT_BYTES` | 64KiB / 16KiB / 24KiB | — | 单次读取、工具结果与代码打印的上限 |
| `AUDIT_PLANNER_MAX_TOKENS` / `AUDIT_WORKER_MAX_TOKENS` / `AUDIT_RECON_MAX_TOKENS` / `AUDIT_POC_MAX_TOKENS` | 8192 / 4096 / 2048 / 4096 | — | 单次响应的输出上限 |

字段还有几个刻意不做成环境变量的参数：`history_trigger_ratio=0.85`（达到上限 85% 才启动
摘要，避免每步都尝试）、`history_target_ratio=0.60`（压缩后的目标水位）、`history_keep_steps=4`
（最近 4 个 ActionStep 组原样保留）。它们属于算法形状，不是部署参数；需要时改代码并补测试。

**字节不等于 token。** 中文 UTF-8 约 3 字节/字，384KiB 可以对应十万级 token。上线前先用一次
小运行核对 `model_response.input_tokens` 与 `model_request.request_bytes` 的比例；若模型窗口不足，
provider 会先返回 `model_error`，而不是宿主 `context_limit`。此时只调 `AUDIT_HISTORY_BYTES`，
不改压缩逻辑。切回 64K 级窗口的模型时必须把它调到 128KiB 以下。

## 压缩如何工作

1. 请求仍低于 `history_bytes × 0.85` 时不做任何事，零开销。
2. 超过触发水位后，按 assistant 消息切分 ActionStep 组，保留 system/任务前缀与最近
   `history_keep_steps` 组，把更旧的组交给摘要。
3. 摘要按「前缀覆盖」缓存：覆盖当前切点的摘要直接复用，不花请求；又有组滑出保留窗口时，
   只把新增组确定性裁剪后附在旧摘要之后；只有压缩后仍高于目标水位且配额未用完时，才再做一次
   增量摘要。因此不会因为每一步多一个 ActionStep 就重复发起摘要请求。
4. 摘要请求是**真实的** provider 请求：计入 phase attempts、`run_limits.responses`，
   并在事件里带 `purpose="history_summary"`；每个阶段最多 `history_summary_responses` 次，
   整次运行按持久化事件计数，最多 `history_summary_run_responses` 次。失败也计入——
   它确实消耗了预算。
5. 摘要失败、被截断、为空、超限或预算不足时，进入确定性降级：旧 observation 与 assistant
   动作按固定字节裁剪，仍超则从最旧组开始整组替换为「已省略历史步骤 k..n」标记，
   **始终保留前缀与最近步骤**。
6. 只有压缩后仍超过 `history_bytes` 才抛 `context_limit`，事件带 `source`、`request_bytes`、
   `history_bytes`、`top_messages`，可以直接判断「差一点」还是「结构性超限」。

压缩只作用于「本次请求的消息副本」，不修改 smolagents 的 memory；阶段边界的 `reset=True`
语义不变。结构化发布只有两条消息，没有旧组可压缩：它若本身超限，直接报 `context_limit`，
避免压缩器对两条消息无能为力却静默失败。

## 证据边界

摘要**永远不是源码证据**：

- `code_agent.yaml` 与 `code_agent_poc.yaml` 都写明「较早步骤可能被宿主替换为摘要；摘要不是
  源码证据，不能作为 evidence 或 primary_location 的依据，也不能代替实际读取」。
- `task_publish` 仍只重放 `SourceLedger` 与宿主证据清单，不重放 transcript；证据校验、行号
  门禁、POC 门禁都没有放宽。
- 摘要覆盖掉的是「已读过的过程」，不是「已读的源码账本」：工具仍在，模型需要时可以重新读取。

## 可观测性

- `model_request`：`purpose`、`request_bytes`、`history_bytes`、`used_ratio`、`message_count`、
  `compact {cached, groups, summary_bytes, dropped_groups}`。
- `context_summarized`：`before_bytes`、`after_bytes`、`summary_bytes`、`cached`。
- `context_summary_failed`：`reason`、`before_bytes`。
- `context_limit`：`source ∈ {history_bytes, source_ledger}` 与对应字节诊断；Planner 保护骨架
  失败仍是带 `source="planner_pinned"` 的 `planner_context_error`。
- `planner_pinned_expanded`：保护骨架从常态上限放宽到硬上限时记录，附各字段字节数。
- 运行摘要 `execution_summary.context`：`peak_request_bytes`、`history_bytes`、`summary_requests`、
  `summary_bytes`、`compactions`、`dropped_groups`、`limit_hits`、`sources`、`phases`。
  每个阶段写自己的 `Execution` 汇总，存储层按字段取较大值合并，后一个阶段不会把整次运行的
  峰值改小。
- 前端：执行状态卡展示「上下文峰值 / 上限、触发压缩、摘要请求、达到上限」；
  Timeline 展示三类上下文事件；导出的 Markdown 报告含「上下文控制」小节（每阶段峰值与占比）。

## 调参

- 模型窗口够大、想让审计少花摘要请求：提高 `AUDIT_HISTORY_BYTES`，或把
  `AUDIT_HISTORY_SUMMARY` 设为 0（只保留确定性裁剪，不花响应）。
- 运行频繁出现 `context_limit(source="history_bytes")`：说明压缩后仍超限。先看事件里的
  `top_messages` 判断是否某一条观察体积异常（例如一次性打印整个文件），再决定是调高上限
  还是限制工具输出；不要只把上限调大来「消掉」错误。
- `context_limit(source="source_ledger")` 是另一类：已读源码账本达到 `source_bytes` 上限，
  与模型窗口无关，调 `AUDIT_HISTORY_BYTES` 没有作用。
- 小预算运行（比如 24 responses）可能被摘要请求挤占；摘要额度不足时自动降级，不会失败。
  需要完整保留探索过程时，把 `history_summary_responses`（代码内）或响应预算调大。

## 相关测试

- `backend/tests/test_context_budget.py`：触发水位、保留窗口、缓存复用、失败降级、
  摘要请求不递归且不夺走发布额度。
- `backend/tests/test_context_config.py`：环境变量解析、范围夹取、非法值 fail-fast。
- `backend/tests/test_code_model.py`：`context_limit` 事件字段与摘要集成。
- `backend/tests/test_report_context.py`、`backend/tests/test_execution_stability.py`：
  报告小节与跨阶段合并。
- `frontend/tests/trace.test.mjs`、`frontend/tests/execution.test.mjs`：事件摘要与状态卡文案。
