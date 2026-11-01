# 运行页展示精简：交付与验收

基线：`main@7a467bd`。验收日期：2026-10-31。

本次保留对话形式，只调整运行页及其详情抽屉中的共享展示。没有修改创建请求、路由、后端、数据库、预算或验证规则，没有启动真实审计、模型请求或 POC 实验。

## 交付行为

- 页头只显示两行以内的任务标题、所属源码包、状态及主要操作。删除、停止和基于任务新建放入“更多”。任务目标默认三行；验收条件、冻结策略与原任务关系可展开。
- 对话内的紧凑摘要显示源码审计、POC 验证、最终复核三个阶段，优先采用服务端工作流；当前任务、并发任务展开、运行时间和实际进度集中展示。不计算推测性的完成百分比。
- 连续普通操作按执行上下文、任务、Worker、漏洞及修订、身份和时间边界折叠。只有存在同次执行的恢复证据才折叠错误；模型自行声称“已更正”不算恢复依据。操作参数、源码、HTTP 观测与诊断仍可原处展开或在完整日志读取。
- 结束结果与报告共用终审事实类型、标签和缓存，区分规范结论、终审接受、待终审及存疑或排除。待审或覆盖未完成时，不显示审计完成；成功工具调用不表示验证通过。
- 终审缺失时标注历史或宿主阶段回退，不推算接受数量；特定旧版 `409` 与普通读取错误分开处理。失败可重试，未知数字显示“暂无数据”。页面切换取消失去订阅者的请求，过期响应不能覆盖当前任务。
- 预算、上下文、SDK 配置、评分、覆盖、原始 JSON、运行 ID、ZIP SHA-256 和来源入口保留在审计详情。ZIP 元数据只在打开详情时读取，不读取源码正文。
- 展开内容、键盘焦点和历史阅读位置在实时更新时保留。暂停等待静止与已暂停不同，暂停不会出现结束结果卡。

主要实现：`RunView.tsx`、`ExecutionStatus.tsx` 的紧凑模式、`ActivityStream.tsx` 与 `activitySummary.ts`、共享 `runPresentation.ts`、`finalReview.ts` / `finalReviewCache.ts` / `useFinalReview.ts`。

## 自动化结果

全部浏览器脚本拦截 `/api/**`，使用内存模拟数据；包括模拟的暂停、恢复、取消、继续任务和删除请求。

| 检查 | 结果 |
| --- | --- |
| `cd frontend && npm test` | 125 项通过，含原有 111 项与新增展示、分组、历史兼容和缓存用例 |
| `cd frontend && npm run build` | 通过；Vite 仍提示现有主包超过 500 kB |
| `scripts/ui_run_presentation_smoke.py` | 21 项通过：阶段、并发、等待与观测、全部终态、终审缓存、缺字段、失败重试、快速切换、键盘操作 |
| `scripts/ui_smoke.py --mock` | 64 项通过：暂停、恢复、取消、长日志、工具详情、历史加载、末尾事件读取、焦点与阅读位置 |
| `scripts/ui_host_queue_smoke.py` | 47 项通过：宿主队列、继续审计、冻结终审、预算详情与报告下载 |
| `scripts/ui_execution_smoke.py` | 32 项通过：POC 模式、预算耗尽、轮询收尾及阶段报告 |
| `scripts/ui_agent_stability_smoke.py` | 26 项通过：错误恢复、失败脚本、HTTP 观测、身份和验证详情 |
| `scripts/ui_sources_smoke.py` | 87 项通过：源码工作台、ZIP、全局台账、漏洞详情、历史策略及异常切换 |
| `scripts/ui_records_smoke.py` | 25 项通过：审计及 ZIP 删除、并发冲突、取消确认及焦点恢复 |
| `git diff --check` | 通过 |

共 7 组、302 项浏览器检查。深浅主题均覆盖 1440、1024、768、390px，未发现横向溢出。源码验收脚本中原有的 256 次默认额度和旧策略文案断言，已同步至基线现有的 512 次全量默认额度及宿主调度文案；创建逻辑未改动。

复现（项目根目录，前端已在本地启动）：

```bash
export CHROME_BIN=/home/luchitong/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome
uv run --with playwright python scripts/ui_run_presentation_smoke.py \
  http://127.0.0.1:5173 --screenshots /tmp/run-presentation
uv run --with playwright python scripts/ui_smoke.py http://127.0.0.1:5173 --mock
uv run --with playwright python scripts/ui_host_queue_smoke.py http://127.0.0.1:5173
uv run --with playwright python scripts/ui_execution_smoke.py http://127.0.0.1:5173
uv run --with playwright python scripts/ui_agent_stability_smoke.py http://127.0.0.1:5173
uv run --with playwright python scripts/ui_sources_smoke.py http://127.0.0.1:5173
uv run --with playwright python scripts/ui_records_smoke.py http://127.0.0.1:5173
```

`CHROME_BIN` 可按本机 Chromium 安装路径调整。本次验证覆盖展示和交互，不评价真实模型或 runner 的执行质量。

## 截图

前后对照采用相同的宿主队列模拟数据。修改前来自基线版本，修改后来自本次工作树；终审有待审项，因此修改后明确显示“审计未完成”。

| 场景 | 修改前 | 修改后 |
| --- | --- | --- |
| 深色 · 1440px | [查看](images/run-presentation/before-dark-1440.png) | [查看](images/run-presentation/after-dark-1440.png) |
| 浅色 · 1440px | [查看](images/run-presentation/before-light-1440.png) | [查看](images/run-presentation/after-light-1440.png) |
| 深色 · 390px | [查看](images/run-presentation/before-dark-390.png) | [查看](images/run-presentation/after-dark-390.png) |
| 浅色 · 390px | [查看](images/run-presentation/before-light-390.png) | [查看](images/run-presentation/after-light-390.png) |

| 当前展示 | 桌面 | 移动端 |
| --- | --- | --- |
| 运行中 · 深色 | [查看](images/run-presentation/running-dark-1440.png) | [查看](images/run-presentation/running-dark-390.png) |
| 运行中 · 浅色 | [查看](images/run-presentation/running-light-1440.png) | [查看](images/run-presentation/running-light-390.png) |
| 结束结果 · 深色 | [查看](images/run-presentation/result-dark-1440.png) | [查看](images/run-presentation/result-dark-390.png) |
| 结束结果 · 浅色 | [查看](images/run-presentation/result-light-1440.png) | [查看](images/run-presentation/result-light-390.png) |
