# 最近全量审计运行诊断

检查日期：2026-11-10，时间使用 Asia/Shanghai。运行 `7150ee45e16a49ad935ed62ab194be99`，源码 `lab30-shop-1.0.0-source.zip`，代码提交 `fa23b0d`。

本次仅检查只读 SQLite、已冻结事实包、事件和 runner 的 GET 健康接口。没有调用模型、执行 POC、恢复运行、重启服务或修改生产记录。[结构化证据](validation/latest-full-run-diagnosis-2026-11-10.json)保存统计、关键事件 ID、版本复算及冻结哈希。

## 实际结果

- 11:47 开始，12:21 结束，状态 `inconclusive`。活跃时间约 34 分 42 秒。
- 使用 212/512 次模型请求、168/4096 次工具；结束时仍剩约 25 分 18 秒与 300 次模型请求。
- 23 条原始漏洞记录，没有 duplicate 处置记录。冻结报告显示 18 条 accepted、5 条 pending；报告可交付部分成果，不能作为完整终审报告。
- 56/61 个文件有读取记录，1 个 SVG 被显式跳过，另有 4 个未处理路径。28 个任务中 21 个完成、2 个 blocked、5 个最终 cancelled。
- 23 条候选全部未做动态验证，实际 POC 作业为 0。

停止原因 `final_review_needs_evidence` 不能完整解释本次问题：5 个 pending 中有 4 个已经存在同版本终审 accept，被报告接续代码漏掉。

## 1. 已确认的终审版本计算不一致

`backend/audit/review_store.py:427` 为有 Worker 佐证的审查项计算：

```text
review_revision = fingerprint({base: finding_fact_revision(...), worker_references: refs})
```

但 `attach_final_decisions` 在同文件第 863 行仅计算 `finding_fact_revision(...)`，没有纳入 `worker_references`。因此队列、提交表认为终审完成，报告接续时却把相同决定当作版本不匹配而丢弃。

| 被漏接的结论 | Worker 佐证数 | 终审表的决定 | 冻结报告 |
| --- | ---: | --- | --- |
| support/download.php 路径穿越 | 1 | accept | pending |
| catalog/greeting.php 反射型 XSS | 1 | accept | pending |
| wallet/withdraw.php 提现竞态 | 4 | accept | pending |
| catalog/index.php SQL 注入 | 1 | accept | pending |

逐项只读复算证明：这四项的基础签名均不匹配已提交版本，加入现有佐证后全部精确匹配。在内存中按原有 `planner_final_batch` 来源接回既有决定，得到 **22 accepted / 1 pending**，没有新增或修改任何语义判决。这是诊断投影，原冻结报告仍保持 18/5。

应统一领取、提交、决定接续及报告冻结使用的事实版本函数，并增加“先提交短引用，再完成终审并冻结报告”的整条回归。历史记录修复应保留原冻结工件，生成有来源说明的派生结果，不能直接改写旧报告或把未执行 POC 标成已验证。

## 2. POC 在健康检查失败后没有执行

本轮模式为 `auto`，运行时 POC 阶段在 12:13:11 进入，12:13:21 记录 `runner_unhealthy`（事件 78604），12:13:24 即转入 review。23 条候选均 deferred，SDK 验证、正常/攻击对照及 POC 作业没有实际运行。

检查时本机 `127.0.0.1:18089/healthz` 返回正常，公开客户端和使用后端同配置的 `PocRunnerClient.health()` 均成功，约 0.1 秒，runner 版本为 3.2.0。因此不能认定容器从未启动，也不能认定仍持续故障。

`backend/audit/poc_readiness.py:130` 把 HTTP 拒绝、连接异常、超时等统一归为 `runner_unhealthy`，当时的具体异常类型没有写入运行事件，无法从现存日志追溯该次失败的精确原因。当前健康成功也不代表 SDK、模型网关和动态实验已经复测通过。

源码阶段提前停止的原因是给 POC 与终审保留窗口：当时 POC 窗口 1260 秒、终审窗口 780 秒。但 POC 不可用后，流程直接进入终审，没有重新处理上游未完成任务，最终剩余大量预算。因此仅增加整次预算不能解决这一问题。应在预留及切换前核对可用性，记录脱敏异常分类并做有界重试，按实际剩余工作分配时间。

## 3. 模型动作协议与候选身份仍消耗大量纠错

| 错误 | 次数 | 影响 |
| --- | ---: | --- |
| 探索输出没有可解析代码块 | 48 | 47 次为非空且 `finish_reason=stop`，另 1 次达到输出上限，不能全部解释成截断 |
| Python 动作超过 8192 字节／80 行 | 8 | 动作执行前被拒绝，限制本身有效 |
| 单动作工具调用过多 | 1 | 被 8 次上限拒绝 |
| 最终 JSON 截断 | 2 | 两次均达到 4096 输出 token 上限 |
| Worker 结构化发布被拒 | 14 | 数据流根因引用、候选归属及位置约束不满足 |
| Planner 发布被拒 | 7 | 已结算任务重定义、重开额度、方向引用等不满足合同 |

另有 1 次工具超时、1 次无效 Python。没有模型供应商重试或模型请求超时事件，也没有触及上下文硬上限。

**71/212 次请求用于纠正，占 33.5%**，消耗 1,508,578 输入 token 与 86,277 输出 token。事件只保存格式诊断，不保存模型原文，所以目前不能进一步确认每个非代码输出究竟是裸 JSON、散文还是其它围栏格式。

`wallet-orders-logic` 的 5 次任务尝试中出现 11 次发布拒绝：原候选锚定在钱包表单，后续却反复尝试用同一个 `candidate_id` 更换根因位置；另有 primary_location 未与 root_cause 证据对齐的问题。失败跨尝试反复出现，重开后最终仍 blocked。另一个 `wallet-debit-catalog` 已发布有效佐证，但保留的订单候选被判为外部依赖而 blocked；后续窄任务成功返回了价格篡改发现，父任务的旧 pending 候选并未同步闭合。

修复重点应是：分离探索小动作与最终大对象；为初始假设锚点到真实根因提供显式、可追溯的候选更替协议；在子任务补齐相同问题后结算父候选；对相同候选、相同版本及相同错误跨尝试累计额度。不能通过静默移动根因或放宽证据校验解决。

## 4. Planner 提示/schema 与实际策略许可不一致

第 11 回合（事件 78509）的模型发布已通过前置校验，提交事务却报：

```text
triage is only available for advisory leads in exhaustive-v1
```

本轮实际上是 `exploration_policy=legacy`。提交时 `backend/audit/exhaustive.py:94` 禁止该 triage，但此前模型接口仍暴露了相应动作，前置验证没有拦截，导致整份事务回滚。

应按当前策略与阶段从 schema 中收回不可用动作，并让模型前置校验和提交事务复用同一许可判定。

## 5. 全量目标没有启用穷尽策略

冻结参数实际为：

```text
completion_policy = coverage_review
focus_scope = targeted
risk_coverage_policy = off
exploration_policy = legacy
poc_mode = auto
require_poc = false
```

源码可读范围是完整快照，也已关闭历史结论继承；但这不等于启用了全量穷尽策略。自然语言目标写“全量”不会自动改变上述开关。`frontend/src/taskDraft.ts:44` 的穷尽选项才会同时设置 `exhaustive-v1`、`focus_scope=all` 与 `bounded-v2` 风险覆盖。

本轮仍有 16 条 advisory 方向未升级为必做，2 个 blocked 任务未解除，5 个未执行任务在最终停止时被取消。4 个未处理路径是：

- `lab30-shop/bin/lab`
- `lab30-shop/bin/package.py`
- `lab30-shop/docker/php.ini`
- `lab30-shop/fixtures/server.py`

这些限制应作为不完整覆盖展示，不能用提示词里的“全量”声称策略已经穷尽。

## 6. 剩余一条会话固定判读仍需针对性复核

会话固定是唯一明确由终审决定 `needs_evidence` 的项。它的理由把 `SameSite=Lax` 对跨站 POST 的约束用作额外的利用前提缺口；但已展示源码通过 GET `sid` 设置会话，认证后只写 `user_id`，没有换发 SID。

[OWASP 的会话固定说明](https://community.owasp.org/attacks/Session_fixation)明确列出 URL 中携带会话 ID、诱导用户访问并随后登录的路径。结合本轮源码，审查者可能把会话固定过度限定为跨站 POST 登录场景，应按真实 GET 投递及认证链重新核对。这是独立判读建议，不能直接据此修改原决定或声称动态已确认。

## 缓存与后续修复顺序

本轮缓存统计数据覆盖 212/212，均来自真实响应：

| 环节 | 响应数 | 输入 token 命中率 |
| --- | ---: | ---: |
| Worker | 182 | 86.56% |
| Planner | 13 | 57.73% |
| 独立审查 | 17 | 9.24% |
| 整轮 | 212 | 80.56% |

合计输入 4,529,753 token，缓存读取 3,649,152 token，输出 198,245 token。去重增量协议实际被使用 5 次，当前 23 条记录没有 duplicate 事件；因此这轮最突出的开销是纠错及阶段合同，而不是大量重复 finding。

建议先修复终审决定接续和 POC 健康/阶段衔接，再处理 Worker 纠错与候选身份、Planner 动作许可，最后继续优化 Planner／终审的缓存前缀。修复报告接续不会自动补齐动态验证或未完成覆盖，也不能把缓存命中率当成流程成功率。
