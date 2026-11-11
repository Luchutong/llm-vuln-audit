# 原记录收尾与中断恢复

用户要求在 `3b50dbaf45955d989aacf47162e47967` 上补齐缺口并完成，不另开全量审计，不追加模型、工具或时间预算。

## 暂停原因

暂停时累计为 **187/284 次请求、136/5075 次工具调用、4610.724/10110 秒**。源码覆盖缺口为零、任务无 active/blocked，但有 21 条 required 与 10 条 advisory 方向未结算。许多已完成任务没有绑定这些方向的 ID，因而不能作为该方向的合法逐项结果；重复派发读过的文件既耗预算，也没有推进这个账本，最后触发全量探索无进展暂停。不能仅据此归因为重启，且并非预算耗尽。

另外存在 5 条所选 POC 未决：4 条 SDK 失败、1 条中断。原有 per-revision claim 防重复机制会拒绝再次自动执行，单纯 resume 不能补齐它们。

## 修复与接续

- 已完成源码覆盖的收尾任务必须绑定未决 `direction_ids`，模型 schema、预校验与数据库提交均约束；不能换名重复挖掘。
- 在静止暂停检查点，将缺逐项结果的 30 条方向明确绑定到 10 个有界取证任务。另一条已有完整结果直接留给复核。只修改读取范围及工作归属，不自动赋予漏洞或安全结论。清单幂等，旧尝试、发现、父报告、复核错误额度、用量和上限保持。
- 实测这些任务大多正常返回；其中订单方向被拒，原因是把未读的 partner/portal.php:4-6 作为连续区间。补齐全文并使用既有一次有界重开；另一项只核对冻结范围内 remember-me 假设及其两条衍生线索。原失败记录保留。
- 订单最后的拒收进一步暴露接口遗漏：宿主要求每项排除的反证命中该方向原始 `paths`，但 Worker 收到的 assigned_directions 未内联这些路径。已补全 paths、unknown_paths 与 no_evidence 的反证合同；schema 对 no_evidence 要求完整 disproof，对方向 ID 使用当前分派集合，拒收反馈包含具体要求路径。使用最后一次既有重开后订单项通过，全部源码任务完成，进入整合复核。
- 提供静止检查点的人工 Planner 修复入口，仍走原有任务和重开校验；该入口不调用模型、不允许并发草稿或执行中租约。
- POC 的定向重试需明确请求 ID 与发现 ID；只允许当前版本的未确定终态，要求原上下文关闭、所有已提交作业有终态事实，拒绝未知作业、未完成作业或确定结论。保留旧作业／验证，通过事件保存原 claim，原额度与消耗不变。每个 finding 仅允许一次这种显式定向重试。

## 验证

相关回归先后 69、27、50、14 项通过（有交集）。原记录 SQLite backup 的两轮隔离回放验证了具体方向绑定、源码完整交付、原始账本保持及 5 条定向 POC 可重新领取。应用数据保存在：

- [方向清单回放](validation/closure-checkpoint-replay-2026-11-11.json)
- [方向清单应用](validation/closure-checkpoint-applied-2026-11-11.json)
- [收尾交接回放](validation/closure-final-handoff-replay-2026-11-11.json)
- [收尾交接应用](validation/closure-final-handoff-applied-2026-11-11.json)

收尾交接时累计 **212/284 次请求**，仅使用剩余 72 次；最终结果以实际完成检查和导出为准，不能把未决强行改成完成。

方向合同补充回归：97 项中 96 项通过，唯一失败为错误标签增加 ID 后破坏旧标签格式；已保持原标签并单独追加 ID，随后相关 51 项全部通过。原标签兼容且方向路径始终可见；没有放宽原始证据校验。

## 人工补齐最后范围判断

整合复核后剩 4 条方向：旧 SQL 方向已有合法 supported 结果；maintenance/jobs→host_check 的排除只引用 require 行，需要补完整函数与调用链；订单金额方向及其衍生线索仍要求证明未提供的外部结算/cron 实现。

按用户要求由 Codex 亲自核读冻结源码：完整读取 bootstrap、DispatchJob、maintenance/jobs 及 host_check 调用方；检索全冻结文本的 orders、unit_price、checkout、refund、cron，再核读所有真实读写点、脚本与部署入口。得出的有限结论是：

- maintenance/jobs 到 host_check 的路径在冻结实现不可达；不影响其各自已有的对象注入／授权缺陷。
- 订单金额入库与库存影响保留；现有订单详情、列表与合作方结算摘要仅展示金额，钱包与用户报表没有使用 orders.total 扣款；不宣称部署外代码不存在或安全，也不扩大实际资金损失。
- SQL 方向引用已有直接搜索注入与 nickname 二次注入两条独立根因，不混入 profile 页面的 XSS。

人工结果明确记录 `assessment_source=operator`、审查者与真实源码读取区间，仍调用原 `resolve_task_attempt` 和反证校验；不伪装为模型产出。增加 **22 次真实源码读取工具计数、0 次模型请求**，上限不变。两个人工取证任务均完成，最后 3 条方向留待独立复核。见[人工回放](validation/operator-closure-replay-2026-11-11.json)、[实际应用](validation/operator-closure-applied-2026-11-11.json)。

同时补上跨进程恢复保护：暂停中仍有 running 源码任务时禁止 resume，避免人工或其它进程取证期间并发领取；修复收尾 schema 将方向汇总 dict 当 list 的一次内部异常。相关回归最终 **50 项通过**，另有人工取证及合同测试 **22 项通过**（有交集）。人工交接时累计 233/284 次模型请求，剩余 51 次用于定向 POC 与终审。

实际接续后两轮独立整合均通过，开放方向、覆盖缺口、阻塞任务全部归零。宿主于事件 `89499` 按真实 `met` 静态条件进入 POC，累计 235/284 次请求，剩余 49 次用于后续阶段。

## 最后一条 POC 证据与闭环结果

POC 阶段选中的 31 条中，`6ea737d111da4451a1c0cbab2c63aa92`（members.php `q` 注入）在早期准入失败后停在 `attempt=running` 且无作业，属于“已选中、未验证”而非模型结论。按用户要求由人工用真实 runner 作业补齐，不重开审计：

- 尝试 `8bcf3955…` 先经可审计事件释放回 `claimed`（原因 `admission_failed_without_jobs`），再以 `operator` 身份执行作业 `5bca6c029e9148fcbd3b9e30be055dac`。
- 同一会话对照：`q=alice` 仅返回 alice；`q=' OR 1=1 -- ` 返回 alice、bob、operator、admin，`exit_code=0`，`SQL_STRUCTURE_CHANGED_CONFIRMED`。lab30 种子账号在执行前已核实为干净状态，故未执行复位（`reset_performed=false`）。
- 记录 `source='operator'` 验证 `b9a479ce0a054a29aa015a892bc98455`，finding 与 ledger 转为 verified/confirmed；尝试完成；上下文 `operator-d080e73f…` 关闭后 `active=0`、`pending_jobs=0`。计入 **4 次工具调用、0 次模型请求**，证据见[operator-member-poc-2026-11-11.json](validation/operator-member-poc-2026-11-11.json)。

补齐后以 `POST /api/runs/{id}/budget` 将 1 次未用的 POC 响应转入 review（`request_id=close-manual-poc-20261111`，总量仍为 284，未新增预算）并从 `stage_budget_exhausted` 暂停恢复。终审批次此后连续完成 `review_batch_completed`，事件 `03:02:07Z` 发出 `run_completed`，`goal_status=met`。

最终状态（2026-11-11T03:01:58Z 完成）：

- 运行 `completed`，`stop_reason=goal_met`；预算分段 `discovery 174/174`、`poc 80/80`、`review 22/30`，合计 **276/284 次请求**、234 次工具、活跃 6497 秒。
- 终审：42 个 completed 批次、215 条终审事项，决策为 `resolve 128`、`accept 59`、`needs_evidence 20`、`skip 8`；待终审 0。
- 源码覆盖 61/61（读取+带理由跳过均为 61），必做方向结算 78/78，阻塞任务 0。
- POC：31 条选中全部有终态；`poc_agent` 28 verified + 12 inconclusive，人工 3 verified；成员注入补入后为 `C-19`，终审“动态确认/复核确认/已接受”。
- 终审报告已由宿主生成（约 300KB，`final-review/v2`）：原始记录 34、有效记录 31、规范结论 31、已接受漏洞 31，报告头标注“审计完整性：完成”。

本次闭环只补齐证据与恢复暂停，未修改 lab30 业务源码、ground truth、`scoring_anchors_v2.json`、历史运行或既有结论。
