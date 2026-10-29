# 最近运行：POC 作业事实、跨文件终审与报告修复

日期：2026-10-29。调查运行：`b8f423a9f54e48cd98aec6d6e217a353`。

## 运行事实与原因

本次运行北京时间 13:39:20–14:33:35，共约 54 分 14 秒，终态为部分完成。模型请求使用 187／528 次，工具调用使用 222／4096 次；不是旧 24 回合上限或全局请求耗尽。记录中的显式预算按原样解释，本修复不改默认总预算。

| 指标 | 已保存事实 |
|---|---:|
| 已完成任务 | 22 |
| 必做方向 | 9，均已结算 |
| 后续建议 | 32，不阻止收束 |
| 原始记录／有效候选／规范实体 | 31／29／23 |
| 自动验证 | 12 次：10 verified、2 inconclusive |
| 正式动态复核 | 10 confirmed |
| 终审 | 21 接受、1 需补证、1 存疑 |

21 项接受包含 10 项动态验证结论及 11 项静态接受结论，不代表官方真值中的 21 个命中。23 个实体均已获得处置；停止原因 `final_review_needs_evidence` 真实反映补证限制。源码原始读取数为 60／69；范围内覆盖复核的独立分母为 61，59 读取、2 跳过，二者不能混用。

前一轮终审输入修复已生效：9 个终审批次均未超过 32KiB，没有整体丢弃输入；本轮问题集中在以下环节。

1. **失败 POC 的作业事实未进入必读输入。** 两个失败尝试保存了成功作业，却没有发布正常／攻击侧结论。小批次不触发原有超长输入读取分支，Planner 仅看空观测字段便可能判为“没有 HTTP 观测”。LFI 尝试实际保存 7 个成功作业；价格篡改尝试保存 7 个作业，其中 5 个成功、2 个被 runner 路径规则拒绝。
2. **同链路跨文件结论缺少对照。** 会话固定的登录入口／公共初始化代码，以及反序列化的入口／魔术方法，主定位不同，原有同坐标比较无法发现这种关联。是否同一根因仍须语义判读，不能自动合并。
3. **报告格式门禁误报。** JWT 示例中的 `base64url({'sub':1,'role':'admin'})` 是结论中实际书写的示例，被误认成宿主泄漏 Python 对象表示。历史报告唯一失败检查为 `no_dict_repr`。
4. **SDK 清理与结论阶段衔接不合理。** 本机 SDK 的原生 CLI 清理可能耗时约 20 秒，原 2 秒清理等待容易将已保存实验事实的尝试直接判为清理失败；另一个尝试的结论被拒时，日志未保存具体引用错误。
5. **SDK 配额有隐藏旧限制。** SDK 配置虽允许执行阶段 40 次请求，单次尝试却仍可能受旧 `max_steps=8` 派生的 8＋3 上限约束。

## 修复合同

### 作业事实与终审补读

- 统一计算 `fact_availability`：区分保存的作业、满足执行和身份前提检查的作业、已发布的两侧观测，以及结论是否中断。
- 对结论未完整发布但有成功作业的当前版本，终审批次强制列出 `payload.verification_job_facts` 分页清单，即使整个批次很小也必须读取。旧记录没有失败原因、或状态不确定且两侧为空时，同样适用。
- 通过已有 `read_review_input` 读取完整原文，使用宿主保存的读取区间和版本校验。未读完整不能直接接受、排除或标为补证；预算不足则保持待审，不补造结论。
- 读取阶段仅开放既有只读工具，不启动新模型角色、脚本或 POC。保持批次容量、纠错次数、全局预算和证据门禁。
- 冻结 JSON 与 Markdown 同时展示保存的作业数量、作业 ID、结论发布状态及执行／结论结束原因。保存的作业 ID 单独列示，不自动加入支撑确定性结论的作业引用。

### 跨文件对照

- 同一规范漏洞类型下，除同主定位外，源码引用实际覆盖对方主定位时也进入对照。仅共同引用公共工具、且没有覆盖彼此主定位，不足以关联。
- 同组候选优先在原有容量内放进同批；超出容量时分批，并给后续批次提供已完成的同版本处置。
- 接受相互关联且仍保留的结论，必须明确 `distinct_from` 并解释根因或前提差异；同一缺陷使用 duplicate，保留来源历史。不扩大自动合并范围。
- 新处置保存 `input_policy=paged-facts-v2`。旧 `paged-facts-v1` 报告只执行原有同坐标合同，不追溯追加新门禁。

### SDK、runner 与前端

- 停止阶段后立即关闭新动作并撤销网关能力。非取消场景允许 SDK 在**原尝试截止时间内**获得最多 25 秒清理等待；取消／全局停止最多 2 秒。未确认清理完成仍阻止后续阶段，不绕过租约和预算。
- 只有确认执行阶段已经结束，才允许进入预留结论阶段；不重交副作用作业。清理失败保存 `sdk_cleanup_timeout` 和原始停止原因。
- 结论拒绝事件保存拟提交状态、宿主降级状态、具体证据错误、作业 ID 和上下文；不持久化额外模型推理正文。前端展示这些诊断。
- 新 SDK 运行冻结 `sdk_requests` 的版本及执行／结论额度，与旧 CodeAgent 的 `max_steps` 分开。默认 40＋3，仍受现有 POC 阶段、全局请求与时间上限约束。旧运行缺字段时继续原来的上限，暂停恢复不升级。
- runner HTTP 白名单支持 `/orders/` 下的 Lab30 订单操作，仍拒绝外部 URL、目录穿越和不受支持路径。
- 前端将源码 Agent 执行限制与 SDK 阶段额度分别展示。

### 报告质量

格式检查允许可追溯到结论、源码或审查正文的字典样式示例，也允许代码片段；未知来源的宿主对象表示仍报错。渲染器遇到真实字典／数组使用 JSON 序列化，避免产生 Python repr。该规则只修复格式识别，不证明结论语义正确。

新报告标记渲染器版本 `final-report/v2`，模板哈希包含版本；已有冻结报告仍保留原来的版本、哈希和内容。

## 验收记录

自动验收全部使用模拟模型、临时数据库和临时源码；最新运行只用 SQLite `mode=ro` 读取及纯函数回放。

- 后端直接受影响的 27 个测试文件：521 项通过，用时 61.04 秒。
- 报告渲染器版本标记调整后，再执行相关 3 个测试文件：37 项通过（属于上述范围的子集，不重复累计）。
- 前端 `npm test`：105 项通过。
- 前端 `npm run build`：通过，保留现有大 chunk 提示。
- 浏览器模拟验收：16 组通过，覆盖深浅主题及 1440／1024／768／390px、日志、报告下载、SDK 配额展示和历史配置复制。截图位于 `/tmp/vuln-closure-facts-repair-ui`。
- 只读回放能识别会话固定、反序列化两组跨文件关联；不据此自动判定重复。
- 同一历史报告的离线格式检查不再误报 JWT 示例，质量检查结果由 `review_required` 变为 `releasable_partial`；这只是离线检查结果，未写回数据库。原冻结输入、事实包和 Markdown 的 SHA-256 在回放前后保持不变。

定向测试涵盖：小批次也强制补读、缺少历史原因、只读补读后发布、跨文件引用与无关公共依赖、关联候选分批处置、旧合同兼容、SDK 清理超过两秒后继续结论、清理未结束时阻断、原始拒绝原因、冻结配额和旧运行上限、订单路径限制，以及报告中未发布结论与保存作业事实的区分。

```bash
cd /home/luchitong/work/vuln-audit/backend
uv sync --locked --extra dev --extra poc-claude
.venv/bin/python -m pytest \
  tests/test_recent_closure_repair.py tests/test_host_queue.py \
  tests/test_review_closure.py tests/test_review_batch_recovery.py \
  tests/test_review_input_repair.py tests/test_final_review_bundle.py \
  tests/test_report_final_endpoints.py tests/test_claude_poc_runtime.py \
  tests/test_claude_poc_sdk_compat.py tests/test_claude_poc_preparation.py \
  tests/test_poc_agent.py tests/test_poc_http_contract.py \
  tests/test_poc_durable_facts.py tests/test_poc_runner_http.py \
  tests/test_poc_runner_contexts.py tests/test_poc_runner_client.py \
  tests/test_poc_verification.py tests/test_poc_evidence_publication.py \
  tests/test_poc_gateway_budget.py tests/test_poc_model_gateway.py \
  tests/test_poc_model_gateway_app.py tests/test_planner_verification_context.py \
  tests/test_toolkit.py tests/test_goal_tasks.py tests/test_workflow_review_boundaries.py \
  tests/test_workflow_limits.py tests/test_discovery_workflow.py -q
```

## 生效边界

本次未调用真实模型、启动真实审计、重置商城或改写历史报告；未重启用户服务。后端和前端需加载新代码，runner 需重新构建／加载新的路径规则，之后由用户启动新的真实验收。新合同不能自动修正旧运行已冻结的语义处置，也不保证上游模型一定完成结论发布。
