# 候选整合、独立终审与报告冻结交付说明

## 修复针对的问题

最近运行 `9deac8fc…` 中，Worker 任务已完成，但其宿主方向仍大量处于 pending / assigned；Planner 继续围绕剩余方向派发。任务完成、方向结算、动态复核、最终报告接受原先没有形成完整的生产调用链。

同时，SDK 首条验证开立的 execute / conclude 额度按整个运行 epoch 共享，后续 finding 不断延期；这些延期又被算作处理过的批次，触发无成果的复核。已有终审批次辅助函数没有实际接入调度；报告下载重新读取可变发现，无法保证同一历史报告的内容稳定。

本次沿用现有 Worker、Planner、Store 与 SDK：不创建第二套模型循环、任务账本或作业表，不增加冻结的请求、工具或时间总预算。

## 新运行的闭环

新建任务冻结 `task_spec.review_policy=batch-v1`。已有运行缺少该字段或显式为 legacy 时沿用旧调度；不替旧运行追加模型调用、补造终审或改写成绩。

1. **Worker 按稳定方向 ID 交回结果。** 每个领取方向必须在 `direction_results` 中恰好处置一次，说明 supported / no_evidence / needs_evidence 及依据。引用既有方向 ID 或原文的剩余工作不会生成另一个方向。完成判断不再被同一条已结算方向的重复文字拖住；宿主方向仍需 Planner 结算。
2. **候选逐项整合。** Worker 波次结束后，宿主先领取已完成任务的方向和当前候选，建立 integration 批次。Planner 必须对精确输入集合逐项提交 retain / needs_evidence / contested / duplicate / withdraw；方向使用 resolve / needs_evidence / skip。未补证方向可解除旧任务归属、保留为待办，不能静默消失。整合批次未提交前不自由扩展任务图。
3. **有成果才执行动态复核。** SDK 对新政策运行按台账当前版本隔离阶段额度，第一次开立后不能刷新。所有真实上游请求继续原子扣减运行和 POC 阶段总额。额度检查前移至认领、重置和创建验证上下文之前；延期不计 processed，不触发空复核。当前版本的真实动态验证复核仍沿用原门禁。
4. **独立终审批次。** 静态与 POC 阶段结束后，宿主为每个当前规范结论建立 final 批次，提供类型、CVSS、定位、根因、源码原文、验证观测和正式复核。Planner 只能逐项 accept / needs_evidence / contested / duplicate / withdraw，不派发新审计任务、不执行新 POC。全量审计及普通目标审计均接入该阶段。
5. **终态冻结并渲染。** 终态事务保存完整报告输入，包括运行、任务、计划、当前及历史发现、评分、验证、复核、批次、源码证据及附件。确定性渲染后一次保存事实包、Markdown、JSON、ZIP；页面与下载复用同一版本，不再回查当前发现改写旧报告。

## 批次、接受与预算边界

- 每批最多 8 项，包含原始源码的输入按 UTF-8 字节限制在约 32 KiB；超长项明确标注无法完整审阅，只能 needs_evidence。原有 Planner 态势的 16 KiB 限制保留。
- 输入内容摘要与每项 revision 一起持久化；遗漏项、重复提交项、旧批次、旧版本和其他执行代次均拒绝，整个决策事务回滚。输入变化则旧待审批次标为 stale，重新领取。
- integration 的 retain 只是保留候选。新政策中，动态 verified 或普通 confirmed 复核不能替代独立终审；没有同版本 final 决策时保持 pending。
- 静态源码充分的候选可以由 final 批次接受，报告注明依据为静态终审；不改变动态 verification_status。缺少源码、动态反证、未裁定冲突，或 verified 尚未正式复核时，不能直接 accept。
- 重复、撤回保留原始记录和批次理由；不按同文件、同类型自动合并不同根因。处置一个当前记录后出现的新当前版本，需要重新整合、终审。
- 对 discovery_first 运行，为独立终审保护 review 请求配额的一半；动态复核的单轮请求上限也裁到该预留之外，不能只检查开轮时的余额。全部调用仍受原有全局、阶段、轮次和截止门禁约束。
- 预算或轮次不足时，未审项保留 pending，批次可保留未完成。宿主发布限制明确的阶段报告，不追加模型总结、不把部分完成说成完成终审。

## 持久化与导出

`review_store.py` 在现有 SQLite 增量创建 `audit_review_batches`、`audit_review_items` 和 `frozen_run_reports`。无需人工改库；运行删除时按外键归属清理。

终态事务内冻结输入和宿主读取的源码、附件字节；文件不可读时冻结“不可用”及原因，不在之后的下载中补成可用。报告输入有完整 SHA-256；渲染输出首次保存后由数据库触发器拒绝改写。并发下载采用首次保存生效，三个导出格式复用各自已保存字节。渲染故障可从已冻结输入重试，不重新审计。

`/api/runs/{id}/final-review` 和原 `/report?format=markdown|json|zip` 接口保持兼容。报告页显示候选整合与独立终审批次、逐项处置数量、已接受／待审数量和冻结状态；切换运行取消旧请求，终态变化重新取回冻结结果。

历史运行不回填冻结表，继续提供原报告方式；其展示不会被伪装为经过新批次终审。

## 验证与使用

只进行临时 SQLite、模拟模型和模拟网关的定向检查，覆盖：

- 精确批次集合、过期版本及事务拒绝；完成方向经过批次结算。
- 静态接受与动态状态分离；动态 confirmed 不能替代独立终审。
- 普通目标和 discovery_first 协调器完成“规划 → 整合 → 独立终审 → 冻结”。
- 不同 finding 版本的 SDK 额度独立，但共享运行计数；额度耗尽时不重置或接触靶场。
- 冻结后修改发现不改变 Markdown / JSON / ZIP；渲染不再读取当前源码；数据库拒绝修改输入和已保存输出。

定向检查命令：

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_review_closure.py \
  backend/tests/test_poc_model_gateway_app.py \
  backend/tests/test_report_final_endpoints.py -q
cd frontend
npm test
npm run build
```

验收结果：上述后端定向检查 **14 passed**，前端 **99 passed**，`npm run build` 通过；Python 编译检查及 `git diff --check` 通过。

本次没有启动真实模型调用或 Lab30 审计，没有重置当前靶场；没有做后端全量回归。重启服务后，新建运行采用新政策，历史运行和原始测试产物保留。真实审计效果需要由后续实际运行验证。
