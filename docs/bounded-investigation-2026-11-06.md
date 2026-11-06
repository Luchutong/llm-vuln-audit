# 真实运行后的有界调查优化

本次针对 `038b8ffeb5bd476fb0a2c8864eab3e60` 的实际轨迹优化调查调度与提交合同，新增独立的 `task.investigation_policy=bounded-v1`。新宿主队列运行在启用 Worker 取证策略时默认冻结此版本；显式 `legacy`、未包含此字段的历史记录及原冻结报告保持原语义。它与 `role_policy=worker-evidence-v2` 的根因/操作证据合同分别版本化。

## 观察依据

原始运行在账户余额不足的 HTTP 402 后以 `inconclusive/model_unavailable` 结束，没有完成独立终审。87 条仍有效的原始主张离线评分为 TP=29、FN=1、D=51、U=7、FP=58；正式接受集为空。不能将 29 个命中写成终审通过 29/30。

主要问题是已有进展的记账与实际取证脱节，而不只是模型额度不足：

| 实际观察 | 本次处理 |
| --- | --- |
| `orders-wallet-idor-logic` 执行 17 次、产生 26 条主张；同一坐标改写摘要或前提，仍被记为新增结论 | 宿主根据已通过提交校验的不可变 attempt 中的漏洞类型、主定位坐标计算新颖性，忽略调用方提交的文本指纹；不因此合并或删除漏洞 |
| 并发候选多次声明缺少真实隔离级别、事务配置，却继续自动领取并重报旧漏洞 | pending 候选显式声明 `blocked_on`，保存已有成果后暂停该任务并交接给 Planner；未决项仍计入完整性缺口 |
| 已有漏洞或同一候选在 observation 中复述后，再生成全局 advisory | 观察显式引用候选或 finding；宿主核对归属与根因处的真实读取凭据，避免再次生成待办 |
| supported 方向缺少实际 finding ID、no_evidence 混入 finding ID、required 被误作 triage | 每个方向的审查输入及提交参考提供实际 Worker 结果、有效 finding 和字段规则；required triage 在模型提交阶段即拒绝 |
| `preconditions` 被复制成台账中的数组；正向事实观察被当成无风险结论而缺反证 | 新 finding 明确要求字符串；关联正向观察不再要求排除反证，未关联的 `follow_up=false` 仍须反证 |
| 唯一漏检的维护入口身份判断只出现在笼统观察中，没有保存候选 | Worker 合同要求具体可疑边界进入候选检查点，即使本批 finding 条数已满；宿主不按关键词或基准答案自动升格漏洞 |

完整运行依据见 [原始监视报告](lab30-live-worker-evidence-v2-2026-11-06.md)。生产实现不依赖本表中的任务名称、项目路径或基准答案。

## 调查进展与暂停

一次有效提交新增实际读取区间、首次出现的类型/主定位坐标，或首次结算此前 pending 的稳定候选，才获得调查进展。不同措辞、CVSS 或前提不是新坐标。相同坐标可能仍有不同漏洞，全部主张继续保存并交独立审查；此处只限制调查配额。

连续两次有效提交没有上述进展，且任务还要自动继续时，任务转为 `blocked`，记录 `investigation_pause.code=no_investigation_progress` 与 `worker_investigation_paused` 事件。新增实际证据可清零连续停滞计数，已有失败预算不会恢复。非法输出和供应商失败继续使用原重试/失败预算，不冒充一次有效停滞提交。

源码、运行前提或外部环境缺失时，Worker 可提交：

```json
{
  "candidate_id": "concurrent-update",
  "status": "pending",
  "hypothesis": "更新是否在同一事务中仍需真实连接配置。",
  "primary_location": {"path": "demo/wallet.php", "line": 8},
  "evidence": [{"path": "demo/wallet.php", "start_line": 8, "end_line": 8}],
  "missing_context": ["实际连接的事务隔离级别和事务开关不在源码快照内。"],
  "next_step": "取得连接配置，核对更新和余额检查是否属于同一事务。",
  "blocked_on": "runtime"
}
```

`blocked_on` 为 `source|runtime|environment`，只允许用于 pending，并且必须有具体 `missing_context` 和 `next_step`。宿主先保存同批有效 finding 与候选，再停止自动领取。Planner 取得所需事实后可明确重开；若无法取得，保留未决，不通过取消、延后或 no_evidence 隐藏它。任务暂停不等于整个运行完成，也不代表该风险已被排除。

## 观察关联和方向参考

每条观察最多选择一个归属：`candidate_id` 为本任务已有或本次提交的候选，`finding_index` 为本批零起始索引，`finding_id` 为本运行仍有效且未撤回、判重或拒绝的 finding。其 `evidence` 必须实际读取并覆盖归属对象的主定位。伪造 ID、越界索引、多个归属、引用不覆盖根因都会拒绝。

有效关联观察仍完整保存在 attempt，但不另建全局线索；候选的 pending 状态、发现的独立审查要求保持原样。未关联观察继续按已有规则进入线索账本，不做自然语言分类或静默丢弃；未关联 `follow_up=false` 仍要求实际源码反证。关联某条发现不意味着排除其它风险，Worker 必须为独立问题另存候选。

审查方向时，`payload.resolution_context` 列出同一方向 ID 的 Worker 结果及当前可引用的 finding 坐标、证据。`host_reference_contract.items[].direction_resolution` 同步提供参考；`list_directions` 使用简短 ID 导航，以免重复主张挤占页面。路径交集只说明可供阅读，不证明风险已被覆盖。

supported 需要独立核对实际 finding 并提交 `finding_ids`；no_evidence 的 `finding_ids` 必须为空并引用 Worker 反证；缺少匹配的实际方向结果则保持未决。终审线索专轮不再建议 Planner 以 no_evidence 或范围排除清空已知源码线索。

两种 Worker 提交路径均附带 [完整 schema 和合成示例](worker-investigation-bounded-v1.schema.json)，`demo/` 路径不会授予实际读取凭据。

## 验证与实际效果边界

新增回归使用临时 SQLite、实际源码读取区间和受控模型，覆盖重复坐标、伪造进展指纹、外部阻塞、候选保留/重开、观察归属、错误引用、方向参考与结算、API 版本冻结，以及两条真实 Worker 提交路径的一次纠正。

最终后端 **2384 项通过**（含新增 24 项），前端 **128 项通过**，构建通过。后端分四个独立 pytest 进程执行，期间生产代码与测试代码哈希保持不变；保留一条既有重复 ZIP 条目告警。原始监视工件 8 项哈希一致，归档 7 项哈希及原 22/30 评分回放一致。尝试上限恰好为 2 时也会保存具体暂停原因；完整 schema 与实际发布工厂一致。

真实记录的只读回放：

```bash
backend/.venv/bin/python scripts/replay_investigation_progress.py \
  --db .run/lab30-live-v2-20261106-103858/trial/01-optimized/audit.db \
  --out docs/validation/bounded-investigation-live-replay-2026-11-06.json
```

80 次原始 attempt、104 条原始主张均纳入回放。订单/钱包任务在第 2、3 次提交均没有新读取、根因坐标或候选结算；新判定在第 3 次触发暂停。该脚本对原始输出作反事实分类，不能推算暂停后模型会如何规划，也不能宣称实际从 17 次降至 3 次、节省特定 token 或取得新得分。原始数据库哈希保持不变。

本次没有新模型请求或 POC 作业；账户 HTTP 402 问题仍需恢复模型额度。格式截断、主张因果错误、误报和最终 30/30 的效果仍需新的全量运行验证。完整回归、历史归档哈希及原始监视工件核对结果记录在 [验证清单](validation/bounded-investigation-2026-11-06.json)，逐次回放见 [真实记录回放](validation/bounded-investigation-live-replay-2026-11-06.json)。
