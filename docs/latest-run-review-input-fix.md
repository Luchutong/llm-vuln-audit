# 最近运行的终审输入与 POC 异常恢复修复

日期：2026-10-29。调查对象：`36ebfa11df644740b40c6924edeff19f`。

## 处理范围

本次修复终审输入失真、超长事实无法补读、漏洞类型丢失、同定位候选缺少判读、SDK 上游失败后无法利用已保存作业，以及终态原因误报。保留宿主队列、Worker、Claude SDK、现有消费账本及不可变报告；不增加模型总预算。

最近运行并非因旧 24 回合限制或 512 次请求耗尽停止。它形成 63 条原始记录、38 个规范实体，最终 33 项接受、5 项需补证。这些数量是运行结论统计，不是与官方真值比较的真实命中数。本次不改写该运行、冻结报告或实验成绩。

## 1. 终审输入与按需补读

- 完整保留结论正文、正常／攻击观测、两侧原文引用、身份前提、观测到的状态变化及作业状态。
- 批次中的作业仅投影 ID、上下文、身份、前提、执行结果元数据及完整记录哈希。大段 stdout/body 不与两侧引用重复注入；完整作业仍通过 `read_verification` 与既有下载入口读取。
- 删除“只允许四个源码引用”的门槛。逐一读取全部引用；超过单个读取窗口的范围按连续原始行拆分。实际缺失、越界、无法读取仍阻止接受。
- 单个对象超出传输容量时，保留可用内联事实，超长字段改为 `paged_fields` 清单：字段名、JSON 字符长度及 SHA-256。通过 Planner 只读工具 `read_review_input(item_id, field, offset, limit)` 分页补齐，不再整体清空证据。
- 宿主在现有批次 `items` JSON 中记录、合并读取区间。分页按 Unicode 字符偏移，单页最多 1024 字符。字段原文、条目版本、批次、执行代次和对照候选均须匹配；客户端伪造读取标记、漏页或旧版本不能放行。
- 所有分段字段完整读取后，才解除“输入未完整提供”的门禁。读取不改变被审事实指纹或批次 `input_hash`。真实缺证与尚未读取分段字段是不同状态。
- 含分段字段的批次使用同一个有限读取／发布循环，沿用每批至多三次响应的预留，不另起探索层。暂停后停止接收新读取动作。
- 已经正式处置的 needs_evidence 不会自动无限重审；本修复提供的是作出处置前的补读路径。预算不足或真实证据不足仍诚实保留待补证。

只读回放历史冻结输入，两个受影响验证的观测投影变为：

| 验证 ID | 原 agent JSON 字节 | 新观测投影字节 | 两侧观测原文 |
|---|---:|---:|---|
| `a8f2c98d91ff4b8a9101b903b995d834` | 40,255 | 22,487 | 完整保留 |
| `f84123f75ffa4c1abeed3fc6d1eef0cd` | 31,700 | 17,076 | 完整保留 |

这里比较的是验证数据的投影大小，不是整个批次大小；加入结论、源码及对照候选后仍按实际容量打包，超长字段走分段读取。回放只使用 SQLite `mode=ro` 与纯函数，没有重算或保存旧运行处置。

## 2. 类型、对照候选与静态接受

规范类型优先使用显式 `vulnerability_type`，只有历史记录缺字段才回退 `category`。显式 unknown／other 保持原值，不由 `task_goal:v2:…` 覆盖。

同类型、同主定位的跨台账条目成为 `comparison_candidates`，用于比较根因、危险操作和攻击前提；坐标本身不触发合并，不降低原有自动判重门槛。上述历史输入可识别出 7 对需要对照的候选，涉及 11 个规范实体；不能据此认定这 7 对都重复。

终审接受时，宿主要求对仍保留的对照项显式填写 `distinct_from`，并在处置理由说明根因、操作或前提差异。同一缺陷应使用 duplicate 并保留主结论及全部来源。评分不同、POC 状态不同不构成不同根因。终审提示同时明确：充分静态证据可以接受，不能单因没有 POC 而拒绝一项、同时接受同根因的另一静态项。

对照处置进入冻结 JSON 和 Markdown 附录。新合同保存 `input_policy=paged-facts-v1`；质量校验会阻止缺少该合同要求的对照判读却已接受的报告被当作合格交付。旧合同不追加这项新门禁。语义是否正确仍需人工或模型根据源码判断，宿主不把显式填写字段等同于漏洞真实成立。

## 3. POC SDK 异常恢复

当 SDK 流已经结束、`is_error=true` 且 `terminal_reason=api_error`，若当前上下文存在成功完成的作业，则允许进入已预留的只读结论阶段；不重新提交作业或脚本。没有作业事实时不额外消耗结论额度。成功作业本身不产生 verified，正常／攻击引用、上下文、身份和 XSS 浏览器门禁继续执行。

取消、全局／阶段配额拒绝，以及 SDK 清理未确认完成不走这个恢复分支。结论阶段仍受原三次请求、剩余时间和统一配额约束。SDK 清理超时记录原始停止类别与清理失败，保留作业和未决状态；不启动下一阶段。

错误信息优先显示 `api_error` 等实际终止类别，避免显示“SDK 报告错误（success）”。已有成功作业但结论阶段未完成时保存 `conclusion_error`，前端及报告显示“已有成功作业，验证结论阶段未完成”，不冒充确定的未触发或全部作业执行失败。这项改动不解决上游 API 的服务故障，只提供有界恢复和准确诊断。

## 4. 终态原因

新宿主工作流在收束时根据最终事实生成原因：

- `final_review_incomplete`：仍有对象没有完成终审。
- `final_review_needs_evidence`：终审已经完成，但有结论仍需补证。
- `final_review_contested`：终审后存在存疑或排除项。
- `audit_partial` 或真实的上游停止类别：保留其他未完成方向和运行限制。

阶段切换的“进入终审”不再被直接用作最终停止文案，也不再把已完成但需补证的终审统一标为 `invalid_output_limit`。全局取消和硬预算终止仍保留既有处理。

## 离线验收

- 受影响后端定向回归：327 项通过，覆盖下列 14 个测试文件；新增用例全部使用模拟模型、临时 SQLite 与临时源码。
- 前端 `npm test`：103 项通过。
- 前端 `npm run build`：通过；现有 Vite 大 chunk 提示保留。
- 浏览器拦截 API 验收：15 组通过；深浅主题及 1440／1024／768／390px、日志、冻结报告和下载均回归。截图位于 `/tmp/vuln-review-repair-ui`。
- 新增覆盖：六个引用、跨窗口读取、超长字段补读后发布、伪造／遗漏读取区间、旧版本、暂停、重复保留来源、独立根因对照、冻结报告质量门禁、SDK api_error 有界恢复、伪造引用仍拒绝及执行／结论状态区分。

```bash
cd /home/luchitong/work/vuln-audit/backend
uv sync --locked --extra dev --extra poc-claude
.venv/bin/python -m pytest \
  tests/test_host_queue.py tests/test_review_closure.py \
  tests/test_review_batch_recovery.py tests/test_review_input_repair.py \
  tests/test_final_review_bundle.py tests/test_claude_poc_runtime.py \
  tests/test_claude_poc_sdk_compat.py tests/test_poc_agent.py \
  tests/test_poc_http_contract.py tests/test_poc_durable_facts.py \
  tests/test_planner_verification_context.py tests/test_toolkit.py \
  tests/test_goal_tasks.py tests/test_workflow_review_boundaries.py -q
```

本次没有启动真实模型、真实审计或重置 Lab30；未重启现有服务。实际效果应在后端加载本次代码后，使用新运行验证；历史冻结报告保持原有字节。
