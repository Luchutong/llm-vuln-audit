# 首次真实整合批次失败：调查与修复

## 运行事实

最近真实运行：`3c9d05c25f8c49dda1de4dfa90240c1e`，北京时间 **2026-10-29 00:11:12–00:12:32**，约 80 秒。

| 项目 | 记录 |
|---|---|
| 状态 | failed |
| 失败原因 | `ValueError: 重复结论引用必须属于本运行的另一条当前结论` |
| 请求 | 25 / 256；静态阶段 25 / 180，POC 与 review 均为 0 |
| 工具 | 36 次调用及 36 条返回 |
| Worker | 2 个任务完成，合计 3 个尝试 |
| 已保存候选 | 5 条，其中两条 catalog SQL 注入是待处置的重复候选 |
| 源码读取 | 33 / 69 个文件；读取不等于审计完成 |
| Planner | 第一轮完成；第二轮生成批次决策后，在落库时抛出异常 |
| 批次 | integration `0684cc57462e4410933a079f5454b409`，1 个方向、5 个候选，整个事务回滚 |

这次没有进入 POC 阶段，也没有耗尽预算或发生上下文超限。初期代码动作的格式及解释器错误经过恢复，未导致此次终止。

## 根因

### 发布和落库使用了不同的校验

发布前 `validate_batch()` 只要求 duplicate 带有非空 `duplicate_of`，没有检查引用目标是否为本运行另一条当前规范结论。事务中才使用规范结论 `item_id` 检索目标，失败后抛出 ValueError。协调器没有将这类拒绝归入有限纠错，导致整个运行失败。

批次项 ID 通常是台账 ID，`payload.finding_id` 则是单次运行记录 ID；同一提示还包含旧 updates 合同和单次发现的重复候选 ID，容易混用。例如本批次两条 SQL 记录：

| 单次发现 ID | 规范结论 item_id |
|---|---|
| `d423a19496134fbda9e943bd2f654f51` | `7aea4d43f4f84ccfb0e44481cc81ed6a` |
| `3d3fd9060d844792ac1147cb2a543c9e` | `8debae5d87fd4214ae3f767e062b4426` |

旧日志没有保存逐项处置 JSON，无法确定模型实际提交的是 finding_id、自引用还是其他无效目标。能够确定的是：引用检查被遗漏在发布门禁之外，并且同类 ID 混用可以复现相同异常。修复覆盖上述分支，不猜测原始响应。

### 异常中断了报告收尾

终态事务已保存完整输入与源码证据，但 finally 再次 await 失败的 body 时重新抛出原异常，后续 materialize 没有执行。因此冻结表有输入、没有已保存的报告输出，第二轮草稿还停留在 planning。

## 修改

1. 发布门禁与事务共用 `Store.validate_review_decisions()`，检查精确输入版本、重复目标和方向结算依据。事务中仍重新校验，防止检查后输入变化。
2. 批次项本身仍严格使用 item_id / revision。`duplicate_of` 优先使用规范 item_id；仅在当前运行唯一匹配时，兼容映射当前 finding_id。映射留有结构化事件，不做相似标题或模糊 ID 猜测。
3. 拒绝未知、历史、自指、歧义、方向 ID，以及同批次互相判重或指向同时撤回的主结论。允许引用之前批次已保留的当前主结论。
4. 无效引用在 JSON 发布阶段进入现有纠错预算；实际落库时的 ValueError 关闭本轮失败草稿、保留用量并回滚业务变更，按现有无进展上限停止，不再直接击穿运行。
5. 修正批次发布提示，明确 item_id 与 finding_id 的不同，不再同时要求提交被本批次禁止的 verification_reviews / direction_updates。结构化事件保存批次 ID、各项决定、目标与理由，不保存代码块外推理正文。
6. 即使等待失败 body 再次抛出异常，finally 仍执行冻结报告渲染，并保留原错误。终态事务将尚未提交的 planning 草稿标为失败，不伪造已完成决策。

## 本轮产物恢复

对原失败批次做只读回放：6 项校验通过，SQL 重复引用准确映射为对应规范 item_id；SQLite 写入数为 0。

通过现有 report GET 接口从原冻结输入生成并保存缺失的报告输出：HTTP 200，`releasable_partial`，原始及规范候选均为 5，accepted=0、pending=5。恢复前后运行状态、候选内容及冻结 input_hash 均一致。没有补做整合决定，没有重启旧运行，没有修改失败原因或扩充已接受漏洞数量。

## 定向验收

使用临时 SQLite 与模拟模型覆盖普通整合、独立终审、别名兼容、非法引用、循环与撤回、跨批次引用、真实 JSON 发布有限纠错、落库拒绝保留用量、异常退出草稿回收及三个格式的报告冻结。

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_review_batch_recovery.py \
  backend/tests/test_review_closure.py \
  backend/tests/test_planner_publication_recovery.py \
  backend/tests/test_report_final_endpoints.py -q
```

结果：**35 passed in 2.70s**；Python 编译检查及 `git diff --check` 通过。未运行后端全量回归；本次没有前端代码变更。

本次不启动新模型请求、不重置 Lab30、不更改历史冻结输入。服务需加载修复后的代码，新运行才能使用新的发布门禁与异常收尾。
