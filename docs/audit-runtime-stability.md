# 审计执行稳定性修复说明

基线：`main@f6a8346`。本次实现保留源码快照、项目归组、台账与原始历史；不重跑已取消的真实审计，不修改 CVSS 3.1 评价口径。

## 交付行为

| 原故障 | 修复后的行为 |
| --- | --- |
| 穷尽条件拒绝 `met` 后协程退出，运行仍为 `running` | 收束拒绝可继续修复规划；同一阻塞原因最多修复一次，随后 `inconclusive`。正常返回却未终结触发退出保护。 |
| worker 配置 24，实际被隐藏裁剪到 8 | 移除裁剪，探索和判定共享真实单次额度，为提交和两次纠正预留额度。 |
| 各 agent 各自计数，整次审计消耗失真 | 所有角色经 SQLite 事务准入，共享持久计数；失败、缓存和重复工具均计数，SDK 隐式重试关闭。 |
| 暂停恢复与旧执行结果存在竞争 | 恢复等待执行静止，领取原子增加代次；旧代次工具回调、发现、任务、台账与验证写入被拒绝。 |
| 无适配目标仍逐发现写“不适用” | 新任务自动验证默认关闭。不可用仅记一次运行级说明，不创建逐发现验证。 |
| JSON 重复或固定调查复用时变成中文说明 | 返回原 JSON 结构，复用原因进入事件元数据；动态任务结果和覆盖每次读取最新事实。 |
| 格式/解释器错误反复纠正 | 分类记录，连续纠正最多两次；成功动作结束本轮纠正，消耗不重置。未放宽解释器、证据和范围限制。 |
| 模型报告遗漏已有发现，把阻塞写成安全 | 终结时读取持久化事实，宿主独立生成完整阶段报告；16 条运行发现按既有台账身份汇总为 6 组的合成回归通过。 |

公共接口见 [API 契约](api-contract.md)。新建任务显式提交 `snapshot_id`、`budgets`、`run_limits`、`poc_mode` 与 `task`。`require_poc` 只要求脚本。

## 存储及兼容

- Store 初始化增量创建 `run_execution_state` 和 `poc_attempts`，不重建旧表，不从旧事件推算或追扣预算。
- `run_execution_state` 保存冻结总额、尝试数、活跃时间、代次、业务版本、阶段、POC 决策、停止原因及宿主摘要。任务/发现/台账/验证变动更新业务版本，普通日志不更新。
- 终态、目标、Planner、剩余任务、阶段事实与终结事件同事务提交；取消和迟到成功不能相互覆盖。
- 删除审计在同一事务中清理两个新表及既有关联表；删除失败回滚保留完整记录。暂停尚未静止时返回冲突。
- 旧任务没有总预算时返回 `null`；恢复不追扣旧消耗。旧 POC 策略读取时标记 legacy，并按任务书映射，旧原始记录不重写。
- 新 `required` 任务不能用只有 `verified` 字样、缺少来源/结论版本/目标归属的历史记录达成目标。
- 新 Markdown 以宿主阶段事实渲染；原模型叙述、验证及事件仍可追溯。没有模型叙述或没有剩余模型额度也能下载报告。

## 自动化验收对应关系

所有新增测试使用临时 SQLite、假模型、假 runner 或模拟 HTTP，没有调用真实模型或 runner。

| 任务书用例 | 自动化覆盖 |
| --- | --- |
| A01–A04 | `test_execution_stability.py`：真实拒绝 met 分支、阻塞前沿、异常返回保护、取消/完成竞争 |
| A05 | 同文件的恢复代次及迟到写入测试；`test_run_pause.py`：在途提交、快速恢复拒绝、静止后继续 |
| A06–A07 | `test_agent_stability.py`：超过 8 次、探索预留；既有 `test_agent_runtime.py` 的低预算与零工具判定 |
| A08–A11 | `test_execution_stability.py`：并发最后一个额度、单一扣数、三类总预算、无工具事件的独立截止监控、暂停时间排除 |
| A09 | 同上及 `test_code_model.py`：失败/纠正计数、客户端禁隐式重试 |
| A12–A14 | `test_agent_stability.py`、`test_planner_pins.py`、`test_toolkit.py`：JSON 重复/错误/截断/复用、动态读取、解释器错误、参数失败、有界纠正 |
| A15 | `test_agent_stability.py` 和 `test_planner_situation.py`：大态势、关键阻塞、合法 JSON |
| A16–A17 | `test_poc_readiness.py`、`test_poc_agent.py`、`test_poc_store.py` 及创建 required 返回 409 用例 |
| A18–A19 | `test_poc_store.py`：持久占位、已知旧 job 查询、未知提交不重试、旧代次/修订/目标、有效 verified 不被未决覆盖 |
| A20–A22 | `test_execution_stability.py`：16→6 分组、模型遗漏拒绝、blocked 引用拒绝、零额度宿主报告 |
| A23–A24 | `test_record_deletion.py`、删除回滚与旧任务 null 限额；旧模式映射及既有 API 投影测试 |
| A25 | `ui_execution_smoke.py` 和 `ui_sources_smoke.py`：取消过期 readiness、切换快照、复制任务、刷新和导航 |

`scripts/ui_execution_smoke.py` 新增 32 项验收：三种 POC 模式、required 检查错误和创建时的 409、复制限额但不复制消耗、关闭模式取消过期请求、无终结 SSE 时 5 秒内轮询得到终态并排空超过 2000 条末尾事件、宿主报告、深浅主题与 1440/1024/768/390px 布局。

现有浏览器模拟回归覆盖暂停、继续、取消、日志、报告下载、源码库/工作台、漏洞台账/详情和运行/ZIP 删除。

## 复现命令

验收结果（2026-10-23）：后端全量 **682 passed**；前端 **58 passed**；生产构建通过；浏览器 **64 + 76 + 25 + 32 = 197** 项通过。后端仅有既有的重复 ZIP 条目夹具警告；浏览器请求失败场景使用模拟 503 验证异常状态。

```bash
cd backend
uv run --extra dev --frozen pytest tests/ -q
cd ../frontend
npm test
npm run build
cd ..
CHROME_BIN=/path/to/chrome uv run --with playwright python scripts/ui_execution_smoke.py http://127.0.0.1:5173 --screenshots .run/screenshots-execution
CHROME_BIN=/path/to/chrome uv run --with playwright python scripts/ui_smoke.py http://127.0.0.1:5173 --mock
CHROME_BIN=/path/to/chrome uv run --with playwright python scripts/ui_sources_smoke.py http://127.0.0.1:5173
CHROME_BIN=/path/to/chrome uv run --with playwright python scripts/ui_records_smoke.py http://127.0.0.1:5173
```

## 截图

完整 24 张深浅主题与四宽度截图位于 [screenshots/runtime](screenshots/runtime)。以下为关键状态：

- [桌面深色：整次预算耗尽](screenshots/runtime/execution-result-dark-1440.png)
- [桌面浅色：阶段报告](screenshots/runtime/phase-report-light-1440.png)
- [移动浅色：高级预算](screenshots/runtime/budget-options-light-390.png)
- [移动深色：阶段报告](screenshots/runtime/phase-report-dark-390.png)

## 实际边界

- runner 尚无幂等提交协议。存在旧 job ID 时先查询原作业；提交结果未知时保留未完成，不盲目重提。不宣称崩溃后“恰好执行一次”。
- Python 解释器线程不能被立即杀死；通过代次和终态门禁阻止迟到业务写入。已发送的外部请求不能保证撤销。
- 继续沿用服务重启后的 `interrupted` 语义，不新增跨重启自动续跑，不提供 Lab30 部署或新目标适配器。
- 本次回归使用合成故障状态和受控模型；没有付费重跑原先已取消的真实任务。
