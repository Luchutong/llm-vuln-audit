# 全量探索优化实施与验收

2026-11-05，按 [22/30 诊断方案](lab30-22-to-30-analysis.md) 实施。冻结的 `2969bcf2` 仍是历史对照，不能将新策略回填到旧运行。

## 已实现的行为

| 方案要求 | 新行为 | 验证入口 |
| --- | --- | --- |
| 全量结束前分流具体线索 | 显式 `exploration_policy=exhaustive-v1`；未分流 advisory 纳入未决计数。可派工、关联真实发现、源码排除、范围排除或保留阻塞，不把全部建议直接变成必做漏洞 | `test_exhaustive_exploration.py`；宿主方向账本 |
| 复核观察中的其他风险 | 将有 worker 读取凭据的观察登记为调查线索；模型独立分流，不能自动创建漏洞。最多 256 条线索，超限计为缺口 | 同上；`source_kind=observation`、`omitted_leads` |
| 防止“已有结论”掩盖漏报 | covered 必须引用本运行有效 finding 和相关主定位；保存结论指纹。结论改版或失效后重新待审 | 同上；`triage.finding_refs` |
| 独立危险操作与正确去重 | 冻结 `worker-exhaustive-v1` 策略；注入/代码执行义务标为 supported 时，必须引用对应操作主定位的真实 finding。同一包含行的 LFI/RFI 提交独立比较，不自动改分类或合并 | `review_store.py`；新策略绑定事件；独立终审比较 |
| 扩充风险信号 | `bounded-v2` 增加动态调用、快速散列使用、诊断信息、Cookie/Header 身份输入、SQL 状态变更来源及 XML/动态包含候选。基于 PHP 语法节点，注释或字符串中的函数名不触发调用信号 | 合成源码测试；冻结 `risk_obligation_set` |
| 避免只读文件头就结清操作 | v2 义务记录 `operation_read`；发现阶段结束前，必做而未读的操作需要继续派工；最终支持/排除仍由独立审查判断 | 风险义务与实际 seen 区间 |
| 显式评分验收 | `--score-target lab30-30-v1` 要求 TP=30、FN/D/U/FP=0；旧成绩的 completed 或 failed_checks 为空不再替代检出验收 | `test_lab30_score_acceptance.py`；离线 22/30 输入返回失败 |
| 可供用户选择 | 高级设置新增“全量风险探索”。启用时选全部风险、完整覆盖复核和扩展信号；切换定向范围或快速模式会关闭全量探索。新策略身份和正文哈希由后端冻结 | 前端单元测试、API 创建测试、浏览器检查 |

标准/定向审计和没有新版本字段的历史运行维持原策略。旧语法索引缺少 v2 信号时，新任务可从哈希校验的源字节建立内存投影，不重写旧快照或历史项目图。

这些信号是调查候选，不能将每次 MD5 使用当成口令漏洞，或把客户端输入本身当成授权绕过。CSRF 仍需核实 Cookie/浏览器前提；没有真实动态观测不能标为 confirmed。完整性与漏洞检出分别判定。

## 使用

在页面的“高级执行设置”开启“全量风险探索”，检查本次硬预算后新建任务。

已有本地后端与专用 Lab30/runner 时，可按原闭环脚本运行：

```bash
python3 scripts/run_lab30_e2e.py \
  --zip llm-vuln-audit-feat-lab30-shop/llm-vuln-audit-feat-lab30-shop/lab30-shop-1.0.0-source.zip \
  --closure --exhaustive --score-target lab30-30-v1 \
  --out /tmp/lab30-exhaustive/score.json
```

该命令会调用真实模型、复位专用靶场并执行 POC。源码、答案和评分锚点沿用原哈希；评分标准只交给结束后的评估器，不传入审计目标。`--follow` 不允许将新策略升级到已有冻结任务。

独立静态试验使用新的输出目录与 SQLite，不写主数据库；默认 POC off：

```bash
uv run --project backend --frozen --extra poc-claude python \
  scripts/live_lab30_optimization.py \
  --source llm-vuln-audit-feat-lab30-shop/llm-vuln-audit-feat-lab30-shop/lab30-shop-1.0.0-source.zip \
  --output /tmp/lab30-optimization-experiment \
  --profiles baseline optimized --repeats 3 --poc-mode off
```

每个试次默认上限为 2048 请求、16384 工具、10800 秒，与原闭环上限一致；默认只跑一组对照，命令中的 repeats=3 才进行三组。顺序交错，每次 fresh；有效低分保留，不自动替换。`triage` 和 `signals` 可用于分步对照。此处 baseline 表示当前代码关闭新策略的控制组，不冒充原 2026-10-30 可执行版本。

manifest 在调用模型前记录源码/宿主代码哈希、策略、预算和评分目标。审计结束后才读取答案，分别评分全部仍主张的发现和独立终审接受的发现。只有后者达标且运行和完整性均完成，才通过本试次验收；运行期间宿主代码变化也会使该次固定版本验收失败。

off 模式只证明静态流程，不替代带真实 POC 的闭环。隔离数据库包含完整审计原文，仅保存在权限受限的本地目录，不随源码发布。

## 当前验证状态

- 针对性后端：最初 95 项通过；增加真实 API 创建和溢出门禁后继续回归。
- 前端：126 项通过，生产构建通过；浏览器 48 项检查通过，包含新开关、定向范围切换及深浅主题/多尺寸原流程。
- 完整后端复验：2287 项通过，1 条既有重复 ZIP 条目告警；三个旧策略数量断言已经修正。独立评分验收用例随后扩展到 12 项并通过。
- 实际 Lab30 源码生成 88 个 v2 有界风险义务，omitted=0；旧的 v1 诊断仍为 52。义务数量不代表漏洞数。
- 归档 7 项哈希与 22/30 评分重放通过；原冻结输入哈希仍为 `1c48ce503c8af9140bbce4025b742bbbf27145e02ea80606fa636813f97ff940`。
- 首轮新全量静态实测 `7d0ddccab40d4c30a031300dd04501db`：inconclusive，491 请求、359 工具、约 5943 秒。独立终审接受 TP=27、FN=3、D=0、U/FP=3、F1=0.90；全部仍主张的候选则为 TP=28、D=25、U=8，不能拿原始候选替代最终成绩。详见 [首轮完整结果摘要](validation/lab30-optimization-attempt1.json)。
- 第二轮实测 `4fa3bcd01b064690a02066f838983581`：inconclusive，326 请求、309 工具、约 2859 秒后以 `exploration_incomplete` 收束。独立终审接受 TP=26、FN=4、D=0、U/FP=4、F1=0.8667；未检出 09（数据库诊断信息泄露）、23（会员查询跨文件 SQL 注入）、24（主机巡检跨文件命令注入）、27（任务导入反序列化链）。详见 [第二轮完整结果摘要](validation/lab30-optimization-attempt2.json)。
- 第三轮实测 `29b9298e127e44fea887969971f98576`：inconclusive，399 请求、492 工具、约 4733 秒后以 `final_review_needs_evidence` 收束。全部仍主张候选为 TP=30、FN=0（30 个真值均已被发现），但独立终审接受 TP=28、FN=2、D=0、U/FP=3、F1=0.9180；未接受 18（维护接口信任请求头认证绕过，规范结论主定位漂移到第 4 行）和 28（会员报表二次 SQL 注入，终审要求未读取的 nickname 写入路径）。详见 [第三轮完整结果摘要](validation/lab30-optimization-attempt3.json)。
- 第四轮实测 `b6d0095f76174eacac905967018f39b2`：inconclusive，711 请求、730 工具，10802 秒用满 `seconds` 预算。全部仍主张候选 TP=30、FN=0；独立终审接受 TP=28、FN=2（21 会话固定、23 跨文件 SQL 注入）、U/FP=1（注册 CSRF 误报）、F1=0.9492。真值 21/23 的 finding 已创建但规范项在预算耗尽时仍待审；终审 95 分钟只处理了 80 个批次（56 个仅 1 项），88 条风险义务剩 44 条、256 条线索剩 90 条未结算。详见 [第四轮完整结果摘要](validation/lab30-optimization-attempt4.json)。

首轮保留为失败对照：观察线索到达 256 项上限并遗漏 1 项，233 项仍未结算；风险终审缺少实际 finding_id 导航而连续被拒。宿主以 host_review_contract_stall 提前收束，全部原文和用量保留。

第二轮保留为失败对照，并暴露三个具体缺陷：

- 严格路径校验把“采纳线索但漏写 source_refs”的整份计划拒绝；连续三次拒绝后宿主按无进展停止挖掘（49 个任务、130 条线索未结算），真实发现没有机会被派工复核。
- 终审前 drain 只展示 4 条线索，且没有要求分流的专用指令；Planner 在整个 review 阶段一次都没有调用 `list_directions`，一轮未变化后 drain 即退出。
- worker 已把 09/23/24/27 写进 `remaining_work`，但这三个任务的 `remaining_work` 不对应已分派方向，attempt 1 后即 completed；后续复核任务没有建立，`member_lookup.php`、`host_check.php`、`dispatch_job.php` 从未被读取。

第三轮针对上述缺陷修改（不回写前两轮结果）：

- 采纳线索时，宿主把线索点名的缺失路径自动追加到 `source_refs`（容量满则追加 `scope_paths`）并记录 sanitize 事件，不再拒绝整份计划；worker 仍须直接读取线索本体。
- 终审前 drain 每轮向 Planner 固定列出 12 条未结算观察线索（含 `review_evidence`），并附“只提交 `direction_updates` triage、逐条结算”的专用指令；循环按未结算数下降推进，未变化才停止。
- 新增 `_lead_drain_page` 与回归用例，锁定线索展示不受摘要 4 条上限约束。

第三轮代码修改后完整后端回归：2297 项通过（1 条既有重复 ZIP 条目告警）。

第三轮保留为失败对照，已把缺口定位到终审与规范结论选取，而不是发现覆盖率：

- 采纳线索自动补路径时 sanitize 载荷包含 `set`，第 33/34 轮触发 `TypeError: Object of type set is not JSON serializable`；现改为 `sorted(named)`，并新增回归。
- 文本线索没有 observation 的 `review_evidence`，终审前 drain 用 Planner 导航充数被整体拒绝；`_lead_drain_page` 现从 `planner_task_attempts.seen` 附加 worker 实际读过的区间，未读路径保持为空并要求 triage 为 `blocked`；drain 允许连续两轮无进展后再退出。
- 认证/授权绕过的主定位规则改为“被绕过、可伪造的身份/角色判断所在行”，不再一律锚在敏感状态变更行；IDOR 则锚在缺少对象归属约束的查询/读取行。这样维护接口的授权判断与项目台账中的规范结论锚点保持一致。
- `include`/`require` sink 被误报为 `path_traversal` 时，分类校验按实际 sink 归一为 `lfi`（远程 URL 包含保持原分类），避免同一行被拆成两个结论。
- `comparison_candidates` 增加同一主定位的路径穿越/LFI 家族比对，以及同入口相邻认证/对象授权变体比对；只在授权类之间、且一方证据覆盖另一方主定位时提名，仍由终审裁定是否重复。
- 终审批次为 finding 附加 `related_claims`：宿主按共享数据库表、稀有标识符和同文件选择相邻结论及其证据源码，供二次注入等来源/写入路径核对；它不是本项 sink 证据，不能替代本项证据。
- 终审指示明确：分类不同不等于独立结论；入口要求全局管理员/运营角色时缺少对象过滤不单独接受为 IDOR；二次注入有运行内写入路径旁证时应接受并写明来源链。

第四轮在第三轮缺口上继续修改（仍不回写旧结果）：

- 修复 `_excerpt_text`：`read_source` 返回编号行 `lines`，而此前只复制 `text`，导致 `related_claims` 证据全空；现在按行拼接并保留区间路径，新增回归用例。
- 终审线索结算专轮不再对“无 worker 读取证据”的线索一律 `blocked`（blocked 不结算，会永久阻止全量收束）：未点名已知路径、或点名路径从未被读过的线索改为显式 `out_of_scope` 范围限制并结算；分流的 `out_of_scope` 只有在证据可用时才强制引用 worker 读取区间，编造区间仍整体拒绝。
- 文本线索在捕获时保存 worker 实际读取区间为 `review_evidence`，发现阶段 `list_directions` 与终审 drain 使用同一证据，不再依赖 Planner 导航。
- `supported` 风险义务允许“同一利用链的落点”作为旁证：命令注入/代码执行义务可由链根因结论支持，但该结论 evidence 必须实际覆盖本项操作行，且 `dangerous_operation/propagation/summary` 明确写出本项文件；SQL 注入仍要求对应操作行，两处无关 sink 仍不能合报。
- 终审结束后，若发现阶段留下的只是无进展式 `inconclusive`，且终审批次、逐项处置与继续验证均无待审项，宿主尝试以 `met` 复核自己的收束条件（方向、风险义务、覆盖、有效结论、目标关联）；任一条不满足则回退 `inconclusive`。终态仍由 `finalize_goal` 的宿主校验决定，不采用发现阶段的中间建议。

第四轮代码修改后针对性回归通过；完整后端回归 2306 项通过（1 条既有重复 ZIP 条目告警）。

第五轮在第四轮缺口上继续修改（不回写旧结果）：

- 终审批次软上限由 32768 提高到 49152 字节（仅宿主队列模式）：单条 finding 的 payload 约 12–20KB，旧上限使 80 个终审批次中 56 个只能放 1 项，轮次延迟耗尽 wall-clock；提高后同一批次可容纳 2–3 条 finding 或 4–6 条风险义务，单项 32000 字节的界与处置合同不变。
- 终审提示补充 CSRF 边界：只有已认证受害者的既有会话可被跨站改变状态时才成立；注册、登录等未认证入口，或 SameSite=Lax/Strict 阻止跨站携带 Cookie 时，缺失令牌不得以“缺陷本身成立”接受，应 withdraw 或 contested。
- 第四轮实测暴露的待审压力（末两轮因 `focus.relation` 枚举与 paged_fields 未读被拒）仍由既有拆分/重试逻辑处理，不放松“读取完整绑定源码后才能结算风险义务”的门槛。
