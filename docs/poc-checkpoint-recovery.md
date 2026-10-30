# POC 检查点、受控继续与断流回收

实施日期：2026-10-30。对应 `docs/poc-verification-convergence-plan.md` 第 6、7 节与第 9 节第 3 步。只作用于新建运行；不改写历史运行、冻结报告、源码归档、30 项真值与评分锚点。

## 冻结与兼容

新运行在创建时冻结 `poc_policy.progress_policy="bounded-evidence-v1"` 及实际参数（`progress_params`：`checkpoint_experiments`、`continues`、`item_warning_seconds`、`recovery_seconds`、`recovery_requests`、`cleanup_seconds`，以及源码读取上限）。运行快照与 `/api/config` 只在字段存在时展示，缺字段的历史运行继续使用原有逐项政策，不推断、不回填。

已在运行／暂停的任务不热切换；换项、重连、暂停恢复或进程重启都不会重置时钟或累计用量——队列窗口在运行时对象创建时固定为 `min(运行剩余, 阶段剩余)`，检查点与继续只读取它，从不延长。

## 宿主状态机

每个队列项在宿主侧只有一个状态，模型只能通过工具推进：

```
experiment ──完成 checkpoint_experiments 个作业/重复实验/额度临近/发布窗口/耗时提醒/断流──► checkpoint
     ▲                                                                                      │
     └──────────────────── continue_verification（有界小批，至多 continues 次）───────────────┘
checkpoint ──publish_verification──► published（实验工具永久收回）
```

- `checkpoint` 状态是只读的：`read_verification_source`、`read_verification_diagnostics`、`get_verification_evidence`、`get_verification_tasks`、`publish_verification` 与补读源码仍可用；`run_poc`、`http_observe`、`browser_check`、`target_prepare` 一律返回 `checkpoint_readonly`。
- 检查点只登记事实：完成作业的 ID、类型、身份、状态、HTTP 状态码／脚本退出码／浏览器对话框计数、独立诊断是否可用，以及当前可引用的 `evidence_ref_id` 与宿主可见缺口。`interpretation.provided` 恒为 `false`——角色划分、根因与影响必须由模型引用证据后给出。
- 进入检查点时把“已展示的证据表”固定为本项唯一可引用的集合：未在检查点中出现的 ID 之后也不能发布。

## 检查点触发

| 原因 | 条件 |
| --- | --- |
| `duplicate_experiment` | 与已执行作业完全相同的请求／脚本（同一上下文、身份、方法、路径、正文、内容类型或脚本字节）且本批未声明继续。返回 `duplicate_of` 指向原作业。 |
| `experiments` | 自上一个检查点以来已完成 `checkpoint_experiments` 个作业。 |
| `job_limit_near` | 剩余作业额度 ≤ 1，保留最后一个给明确的补证。 |
| `publish_window` | 到达本项实验截止（见下），不再启动新副作用。 |
| `item_warning` | 单项耗时与无业务进展都达到 `item_warning_seconds`；仅提醒，不判失败。 |
| `stream_error` | SDK 流中断或终局缺失；先保存检查点再做只读回收。 |

不同身份或真正不同的脚本不是重复实验（指纹包含身份、上下文与脚本 SHA-256），不会被误合并。

## 受控继续

`continue_verification` 的参数是严格模型：`checkpoint_id`、`hypothesis`、`basis`、`next_experiment`、`expected_result`（各字段有长度下限，禁止额外字段）。宿主不评判措辞，只记录在检查点之后，便于后来区分“新判别方向”与“解锁重试”。

以下任一条件不满足即拒绝：当前确实处于检查点；`checkpoint_id` 是当前检查点（旧的/未知的不能解锁）；检查点绑定仍等于当前 `finding_id/revision/context_id`；`continues` 未用完；距实验截止仍 > 5 秒；剩余请求 ≥ 1 且工具 ≥ 3；作业额度 > 1；`hypothesis + next_experiment` 规范化后未使用过。

通过后只做三件事：置回 `experiment`、允许一小批实验、在完成 `checkpoint_experiments` 个作业后再次检查。它不赠送请求、作业、时间或身份，也不会重置队列时钟。

## 时间与请求预留

阶段截止 `workflow.stage_remaining_seconds = 剩余时间 − review_reserved_seconds`（仅非终审阶段），`workflow_view` 与执行准入检查使用同一公式；`host-queue-v1` 没有保留轮次，但同样保留终审秒数，POC 阶段因此必然早于整体截止。工作树只改这两处计算，历史运行仍按各自持久化的冻结值解释。

项内实验截止：

```
experiment_deadline = queue_deadline − min(recovery_seconds, 窗口×10%) − min(cleanup_seconds, 窗口×5%)
```

默认最多 60 秒恢复、10 秒清理，全部来自原额度，不按项累加。持续队列不为单项另开请求上限，执行阶段是整批共享的一个 run/epoch/queue 关卡，所以上一项未用的请求余额天然留给下一项；恢复则使用持久化的 `conclude` 阶段，第一次打开者固定上限，重开不刷新。

## 断流与只读回收

发生 `sdk_api_error`、`stream_connection_error` 或 `missing_result_message` 时：

1. 先写 `poc_runtime_error`（含流事件数、公开输出字符数、已知作业数）、`poc_queue_checkpoint`（原因 `stream_error`）并保留全部作业与观测；不把断流当作反证。
2. 只有 SDK 传输确认关闭（`async with` 正常退出）后才尝试回收；未知作业（`submission_unresolved`）、剩余窗口 < 5 秒、没有可用额度或无法打开 `conclude` 阶段时，只发 `poc_queue_recovery_skipped`，本项保持未决。
3. 回收只开 `conclude` 阶段，最多 `min(recovery_requests, 阶段余额, conclude_requests)` 次请求、共享同一 60 秒窗口；`mcp_servers={}`、`allowed_tools=[]`，没有目标租约，不能执行任何脚本／HTTP／浏览器动作。
4. 回收结论仍走原有 `EvidenceRefTable`、`evidence_errors`、`host_check` 与发布事务，身份、上下文、版本门禁不变；失败时保留原错误与本项未决，不补造结论。
5. 已经提交的发布不会被回收覆盖：若断流发生在发布之后，回收直接返回已提交结论且不发送任何请求。
6. 原错误与回收成本分开记录：`poc_queue_recovery_started`（请求数、秒数、检查点）、`poc_queue_recovery_published`、`poc_queue_recovery_failed`、`poc_queue_recovery_skipped`，用量里另存 `progress.recovery` 与 `progress.stream_error`。

队列 actor 的清理仍是撤销能力→取消并等待自身任务→超时报 `poc_runtime_cleanup_failed`；回收在同一个 actor 任务内完成，不跨任务关闭会话。回收结束后 `_query_failed` 为真，`verify_standing` 以 `sdk_session_stopped` 结束本批，剩余项不重放、改走显式复测。

## 事件与用量

新增事件：`poc_queue_checkpoint`、`poc_queue_continued`、`poc_queue_experiment_refused`（仅重复实验）、`poc_queue_recovery_started`、`poc_queue_recovery_skipped`、`poc_queue_recovery_published`、`poc_queue_recovery_failed`；`poc_queue_heartbeat` 增记 `progress_state/checkpoint_id/checkpoint_reason`。

每次发布与最终用量附带 `progress`：`policy`、`state`、`experiments`、`counts`（作业、源码补读、诊断读取、证据表读取）、最近 3 个检查点、最近 2 次继续、`recovery`、`stream_error`。事件与用量都不落 Cookie、密码、登录响应原文或模型思考正文。

## 边界

- 不提高 `max_jobs`，不恢复旧的 60／180 秒强制截断，不把未决改成 `verified` 或 `rejected`。
- 检查点不替代发布门禁：截断输出、HTTP 200、`exit_code=0` 仍不是结论。
- 本阶段没有启动真实模型、真实靶场或重启服务；真实队列表现、成本与吞吐仍需用户显式启动验收。

## 离线验收

使用模拟 SDK、内存网关、临时 SQLite 与假 runner 客户端：

- `backend/tests/test_claude_poc_queue.py`：27 passed（新增 9 项），覆盖两项完成进入检查点、重复实验不能无限解锁、未知/旧检查点拒绝、绑定变化拒绝、继续小批结束再次检查、不同身份不误合并、2109 个流事件后中断仍保留作业、只读回收无 MCP/工具、回收失败保留未决、发布后断流不被覆盖、`unresolved_job` 与 `no_time` 不启动回收、回收请求同时受 `recovery_requests` 与 `conclude_requests` 约束、用量 `progress` 字段。
- 定向回归（队列、SDK 适配、发现流程、宿主队列、诊断、源码、验证、工具服务、队列存储）：204 passed。
- 后端全量：2152 passed，2 failed；两项失败都在 `backend/tests/test_full_audit_creation.py`，由本工作树早先未提交的 `schemas.py` 默认值改动引起（`coverage_review` 缺省预算 512、`orchestration_policy` 缺省 `host-queue-v1`），与本阶段改动无关，也未在本阶段修改该测试。
- 前端未在本阶段改动；`poc_queue_*` 之外的新事件在现有日志视图中按原始事件展示，前端合并与统计留待第 4 步。
