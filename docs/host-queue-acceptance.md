# 宿主调度与统一终审离线验收记录

日期：2026-10-29。对象为当前工作树的 `host-queue-v1` 实现。验收没有加载真实模型请求、没有启动真实审计、没有重置或写入现有 Lab30。

## 结果

| 检查 | 实际结果 |
|---|---|
| 受影响后端定向回归，24 个测试文件 | **449 passed**，18.78 秒 |
| 前端 `npm test` | **101 passed** |
| 前端 `npm run build` | 通过；保留 Vite 的单个 JS chunk 超过 500 kB 提示 |
| Playwright 被拦截 API 检查 | **15 组通过** |
| 深浅主题布局 | 1440 / 1024 / 768 / 390px 均无页面横向溢出 |
| 冻结报告布局 | 1440 / 1024 / 768 / 390px 均通过 |
| 日志、JSON 与证据 ZIP 下载 | 模拟接口与浏览器下载通过 |
| 复制历史任务与恢复新默认 | 保留旧预算、旧政策和固定配额；显式重置后使用新默认 |
| `git diff --check` | 通过 |

这是定向离线验收，不是后端全量矩阵，也不是真实 Lab30 检出率、模型成本或 SDK 上游质量验收。

## 回放覆盖

`backend/tests/test_host_queue.py` 使用共享临时源码夹具和 SQLite：

- 29 个原始记录、23 个规范实体、6 个 verified；超过旧 24 回合上限后，23 个实体都获得显式终审决策。
- 37 个含中英文长观测对象，按实际字节打包；单项超长诚实 needs_evidence。
- 自动预留满足 `3B+6W`，时间阈值为 `60*(B+2W+1)`；不创建第二本消费账本。
- 并发重算和扣费保持总额度；固定配额不足不扩额，暂停恢复不刷新计数；已准入请求不被预留阈值充当第二硬截止。
- advisory 不阻止收束；明确采纳后必须有同方向 ID 的 Worker 判读与真实源码读取，再由 Planner 结算；Worker 不能降级义务。
- pending / deferred 整合不阻塞无关派工，同版本不无限重复重试。
- 首次 Planner 一次 JSON，无默认探索；缺少具体上下文时才聚焦补查。
- 同次 confirmed 与 final 处置原子提交；旧版本、未知验证 ID、存疑却 accept、非法项及事务插入后异常全部回滚。
- 复核输出不改变被审事实指纹；撤回一个规范实体不会复活其旧来源记录。
- 协调器直接完成源码取证、统一终审和冻结，不机械 retain 或添加独立动态复核轮次。

其余回归覆盖已有证据门禁、旧工作流、覆盖收束、取消、暂停、POC 作业和 SDK 配额、冻结后导出一致性、旧 manifest 兼容及九试次时限。新 manifest 的工作流和调度政策均显式冻结；隔离执行不会采用普通全量审计的新高预算覆盖实验预算。

## 复验命令

在仓库根目录恢复锁定的开发依赖：

```bash
uv sync --locked --project backend --extra dev --extra poc-claude
```

后端定向检查：

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_host_queue.py \
  backend/tests/test_goal_tasks.py \
  backend/tests/test_coverage_review_policy.py \
  backend/tests/test_discovery_workflow.py \
  backend/tests/test_workflow_limits.py \
  backend/tests/test_workflow_review_boundaries.py \
  backend/tests/test_execution_stability.py \
  backend/tests/test_run_pause.py \
  backend/tests/test_review_closure.py \
  backend/tests/test_review_batch_recovery.py \
  backend/tests/test_planner_publication_recovery.py \
  backend/tests/test_final_review_bundle.py \
  backend/tests/test_report_final_endpoints.py \
  backend/tests/test_timed_comparison_api.py \
  backend/tests/test_timed_comparison_runner.py \
  backend/tests/test_comparison_trial.py \
  backend/tests/test_full_comparison.py \
  backend/tests/test_remaining_work_lifecycle_review.py \
  backend/tests/test_planner_situation.py \
  backend/tests/test_planner_verification_context.py \
  backend/tests/test_verification_review.py \
  backend/tests/test_poc_store.py \
  backend/tests/test_poc_gateway_budget.py \
  backend/tests/test_claude_poc_runtime.py -q
```

前端：

```bash
cd frontend
npm test
npm run build
```

浏览器：先将 `frontend/dist` 作为静态目录在闲置的本地端口提供，然后运行下面脚本。所有 `/api` 请求在内存中响应，不连接审计服务。

```bash
uv run --isolated --with playwright python scripts/ui_host_queue_smoke.py \
  http://127.0.0.1:5187 --screenshots /tmp/vuln-host-queue-ui
```

如 Chromium 不在 Playwright 默认位置，通过 `CHROME_BIN` 指向本机已有 Chromium。截图是临时验收产物，不写入源码或现有运行档案。

## 交付边界

本次保留工作树原有 AutoCVE 复用、POC SDK、批次和报告冻结基础，补齐其新宿主政策闭环；不替换 Worker 或 POC runtime。原有部署配置和测试交付产物保持原状，不把真实历史记录写成新的模拟成绩。

部署生效需要重启到此代码版本；本次没有自动重启服务或恢复旧运行。真实验收由用户另行启动，采用同一源码、模型和 Worker 策略，比较覆盖、重复率、规划占比、终审完成率和单位有效产出成本。总预算增加的影响必须与架构调整分别解释。
