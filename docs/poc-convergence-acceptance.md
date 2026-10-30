# POC 验证收敛：离线验收记录与部署说明

日期：2026-10-30。对应 [poc-verification-convergence-plan.md](poc-verification-convergence-plan.md) §8、§9 第 5 项和 §10。代码为相对 `524c9ee` 的工作树（48 个修改文件 + 28 个新增文件，含本阶段之前的收敛交付，均未提交）。本次验收**没有真实模型调用、没有计费请求、没有启动真实审计、没有写入或重置 Lab30**；浏览器检查全部使用内存中拦截的 API。

生成策略与五类进度的设计说明见 [poc-generation-policy.md](poc-generation-policy.md)，持久会话队列见 [poc-session-queue.md](poc-session-queue.md)，SDK 部署边界见 [poc-runtime.md](poc-runtime.md)。

## 1. 实际结果

| 检查 | 实际结果 |
|---|---|
| 后端定向回归，22 个测试文件 | **476 passed**，45.82 秒，0 failed / 0 skipped |
| 后端全量 `backend/tests` | **2182 passed，2 failed**，81.68 秒（详见 §2） |
| 新增/相关的 5 个测试文件（统计、回放、网关、队列、诊断） | **115 passed**，34.84 秒 |
| 前端 `npm test` | **111 pass**，0 fail / 0 cancelled / 0 skipped / 0 todo，310.99 毫秒 |
| 前端 `npm run build` | 通过（2.59 秒）；保留 Vite 的“单 chunk 609.77 kB 超过 500 kB”提示 |
| 浏览器 `scripts/ui_smoke.py --mock` | **64 checks passed** |
| 浏览器 `scripts/ui_execution_smoke.py` | **32 checks passed** |
| 浏览器 `scripts/ui_host_queue_smoke.py` | **47 checks passed** |
| 深浅主题 × 1440/1024/768/390px | 上述 143 项中覆盖，无页面横向溢出 |
| 脱敏回放 CLI（`--check`） | 退出码 0；7 条去重观测，结论 `inconclusive` |

浏览器一次性运行合计 **143 checks**，全部通过；命令与前置条件见 §7。

## 2. 两条未通过的后端测试（如实披露）

全量套件中以下两条失败，失败源于既有提交 `f31c1db`（宿主队列调度与动态终审预算预留）改变了创建期配额语义，而这两个测试断言未随该提交更新。本次工作树对 `backend/audit/app.py` 和 `backend/audit/schemas.py` 的改动不触及这两处判断（`git diff HEAD` 中相关 hunk 无变化），因此它们不是本轮收敛改动引入的。

| 测试 | 断言 | 实际 |
|---|---|---|
| `test_full_audit_creation.py::test_explicit_full_coverage_freezes_consistent_criteria_and_goal`（第 61 行） | `workflow["limits"] == {"discovery": 244, "poc": 0, "review": 12}` | `{"discovery": 488, "poc": 0, "review": 24}` |
| `test_full_audit_creation.py::test_a_poc_quota_is_released_when_this_server_cannot_run_poc`（第 211 行） | `task_spec["workflow_limits"]["poc"] == 0` | `60` |

原因：

- 第一条：`f31c1db` 为 `completion_policy="coverage_review"` 引入了 `FULL_RUN_LIMITS`（512/4096/3600）默认档，派生配额随之变为 488/0/24；测试仍按旧默认 256 的派生值断言。
- 第二条：`f31c1db` 在 `create_audit_run` 中为 `host-queue-v1` 增加例外——“显式固定配额即使自动验证不可用也保持冻结”；`coverage_review` 默认就是 `host-queue-v1`，于是显式 `poc: 60` 不再被释放为 0。

这两处是需要语义负责人裁定的取舍（改测试还是改行为），本轮按既有约束不静默修改：既未改测试期望，也未改生产语义。在裁定前，后端全量套件的通过基线应记为 **2182/2184**，不得写成“全部通过”。

## 3. LFI 脱敏回放

工具：`scripts/replay_lfi_evidence.py`（`lfi-replay-v1`）。夹具：`backend/tests/fixtures/lfi-replay-lab30.json`，来源运行 `7c890bb7eca354dba6bb46e8f43f5e3b`，只保留结构（路径、状态码、正文长度、页脚、标题、允许列出的诊断事实）；正文、会话、cookie、上游地址不进入夹具。数据库只读打开，工具不读取 ground truth、评分锚点或答案目录。

| 请求 | 状态 | 字符 | 相对基线 | 结构差异 |
|---|---|---|---|---|
| `/content/page.php?page=home`（基线） | 200 | 1381 | — | — |
| `../../../account/index` | 200 | 1242 | −139 | `shorter_body` |
| `../../public/auth/login.php` | 200 | 1242 | −139 | `shorter_body` |
| `../../public/account/index` | 200 | 1052 | −329 | `shorter_body`、`footer_missing` |
| `../../public/account/index`（另一路径形态） | 200 | 1070 | −311 | `shorter_body`、`footer_missing` |

- 服务端诊断：`diagnostics_not_recorded`（该运行没有记录作业级诊断）。
- 上表只列基线与越权请求；同一夹具另含 `/content/page.php`（1381，无 `page` 参数）和 `?page=shipping`（1330）两条正常页面观测，不参与差异分类，因此去重观测共 7 条。
- 证据缺口：`diagnostics_not_recorded`、`sanitized_replay_has_no_body_content`、`no_correlated_server_error`。
- 影响判定：`response_difference`；`arbitrary_file_read=false`、`remote_code_execution=false`。
- 结论：`inconclusive`（`basis=difference_only`）。

即：已观察到的只是同端点三种请求形态的响应差异，其中两条提前结束；回放不把它升级为任意文件读取或代码执行。若将来运行记录了与该请求关联（`include_related`）的服务端错误，回放会给出 `interruption.explained=true` 作为中断解释，但影响判定仍停留在 `response_difference`，结论仍为 `inconclusive`。诊断“不可用”只会记为缺口，不会被当作“没有出错”的证据。

## 4. 已离线通过的项目

§8 生成与反馈：

- `sdk_generation` 冻结块：`output_policy`（`bounded-v1`/`provider_default`）、执行 4096、发布 1024、`thinking`（`disabled`/`provider_default`）；`POC_SDK_*` 非法值在选定 `claude_sdk` 运行时启动失败，不静默夹取。
- SDK 适配：`bounded-v1` 经 `CLAUDE_CODE_MAX_OUTPUT_TOKENS` 传递上限；`disabled` 经 `thinking={"type":"disabled"}`；SDK 缺该字段时就绪检查报 `sdk_thinking_unsupported` 而非删字段。
- 网关独立核验：`poc_gateway_output_cap_missing`、`poc_gateway_output_cap_exceeded`、`poc_gateway_thinking_rejected` 三种拒绝；`poc_gateway_request` 只存白名单元数据。
- 截断（`finish_reason=length`）仍按不完整结果处理；不恢复固定 60/180 秒强制截断。
- 五类事实分开记录：`poc_queue_heartbeat`（宿主存活）、`poc_gateway_stream`（模型请求）、`poc_queue_progress`（模型生成元数据）、作业/检查点事件（实验成果）、发布事件（正式结论）；进度事件限频 5 秒/次、每条流最多 120 次，ping/`message_stop` 不计进度。
- `poc-statistics-v1` 单一统计对象由页面 `PocStatisticsFacts`、报告 `### POC 统计` 小节和 JSON 导出三处消费；JSON 导出与页面读同一对象（`test_report_poc_statistics.py` 断言 `poc_statistics` 原样导出）。
- 前端分别合并心跳与模型进度；“心跳不代表模型有进展”“4 次结束，其中中断 1 次”“沿用 3 项（不构成本轮成果）”等文案由前端测试与浏览器检查覆盖。

§9/§10 回放与检查：

- 回放工具的结构化、脱敏、篡改拒绝、关联诊断、诊断不可用、CLI 契约共 7 项测试通过。
- 报告与页面消费同一统计对象、历史运行缺少字段时不新增小节。
- 浏览器：日志、阶段报告、失败详情、报告 JSON 下载、深浅主题、四种宽度均通过（API 全部模拟）。

## 5. 仍需真实环境验证的项目

本次未做，也不得据此宣称的结果：

1. **真实上游生成参数**：`ark-code-latest`（或实际部署模型）是否接受 4096/1024 与 `thinking=disabled`，网关实际观察到的 `max_tokens`/`thinking` 是否与冻结值一致。现有证据全部来自 ASGI、MockTransport 与临时 SQLite。
2. **已安装 SDK/CLI 的实际选项支持**：`claude-agent-sdk==0.2.174` / CLI `2.1.310` 在真实 `ClaudeAgentOptions` 上是否具备 `thinking` 字段，需要在目标机运行 `scripts/check_claude_poc.py --require-ready` 确认。
3. **真实 SSE 流元数据**：首事件时间、事件类型计数、断流与结束事件在真实延迟和真实 ping 节奏下的取值。
4. **关联诊断**：启用 `compose.diagnostics.yaml` + `SHOP_DIAGNOSTICS_TOKEN` 后，Lab30 是否会为被包含文件产生带 `X-Verification-Request-Id` 的诊断；本次运行没有记录到任何诊断。
5. **真实断流恢复**：2109 个持续事件后的连接中断、只读恢复与迟到写入拒绝，只在模拟流上验证。
6. **持久会话队列的真实行为**：真实 SDK 的检查点、有界继续、暂停/取消下的事件时序。
7. **真实费用与 token 计量**：SDK 用量、网关请求账本与提供商账单是否一致。
8. **真实 Lab30 闭环**：run 状态、覆盖复核、POC 计数（`authentication_failed`、`state_changed`）、TP/F1/D 评分。这些属于用户另行启动的真实对照，绝不能沿用旧版本通过数字。
9. **真实后端下的浏览器表现**：本次浏览器检查全部使用拦截 API，未连接运行中的审计服务。
10. **Lab30 复位与 runner 重启**：未执行；`reset_between_findings` 的端到端效果仍需真实环境确认。

## 6. 部署说明

本次改动不改变默认运行路径，也没有数据库迁移：`sdk_generation` 随运行冻结进既有的 `poc_policy` JSON，事件仍写入既有 `events` 表，统计对象挂在 `execution_summary.poc_statistics`。

### 6.1 生效条件

- 默认 `POC_RUNTIME=legacy`，SDK 路径仍需显式设为 `claude_sdk`。本次没有切换默认运行时。
- `POC_SDK_*` 只在 `POC_RUNTIME=claude_sdk` 时解析；四项缺省即 `bounded-v1` / 4096 / 1024 / `disabled`。选择 SDK 运行时时，非法值会让进程启动失败，这是有意的 fail-fast。
- 要保留部署前的 SDK 行为（不限制输出、不干预 thinking），同时设置：

  ```bash
  POC_SDK_OUTPUT_POLICY=provider_default
  POC_SDK_THINKING=provider_default
  ```

- 运行中的运行、暂停中的运行不会被热切换：它们的 `poc_policy.sdk_generation` 在创建时已冻结；历史运行没有该字段时按 `provider_default` 解释。
- 关联诊断是可选项：`SHOP_DIAGNOSTICS_TOKEN` 留空即不启用；启用需要 `docker compose -f compose.yaml -f compose.diagnostics.yaml --profile poc up -d`。启用不会追溯修改既有靶场或既有运行。

### 6.2 部署步骤

1. 部署到此代码版本，重启审计服务（本次没有自动重启，也没有恢复旧运行）。SDK 用户需保留 `poc-claude` extra：`uv sync --locked --project backend --extra dev --extra poc-claude`。
2. 配置环境后先跑就绪检查，它不加载 `.env`、不打开数据库、不发模型请求：

   ```bash
   backend/.venv/bin/python scripts/check_claude_poc.py --require-ready
   ```

   若返回 `sdk_thinking_unsupported`，说明已安装 SDK 不支持该选项：改用 `POC_SDK_THINKING=provider_default` 或升级 SDK；不要删字段后假装已关闭 thinking。
3. 核对服务端实际生效的配置（只含开关与冻结值，不含凭据）：

   ```bash
   curl -s http://127.0.0.1:8899/api/config | python3 -c '
import json,sys
c=json.load(sys.stdin)
print(c["poc"]["runtime"], c["poc"].get("sdk_generation"))'
   ```

4. 新建一次小运行观察 `poc_gateway_stream` / `poc_queue_progress` 事件与 `execution_summary.poc_statistics`；确认网关没有 `output_cap_missing` / `output_cap_exceeded` / `thinking_rejected` 诊断后，再放开真实运行。
5. 回滚：改动 `POC_SDK_*` 环境变量并重启即可；已冻结运行不受影响，无需回写数据库。

### 6.3 回放工具的使用

只读打开数据库，按运行导出脱敏观测，或对已导出的夹具复核：

```bash
python scripts/replay_lfi_evidence.py --db data/audit.db --run-id <run-id> \
  --endpoint /content/page.php --export /tmp/lfi-observations.json
python scripts/replay_lfi_evidence.py --fixture /tmp/lfi-observations.json \
  --markdown-out /tmp/lfi-replay.md --check
```

`--check` 在缺少基线/差异观测、影响被升级、结论不再是 `inconclusive` 或夹具含敏感字段时以非零退出。

## 7. 复验命令

后端定向回归（22 个文件，本次 476 passed）：

```bash
backend/.venv/bin/python -m pytest \
  backend/tests/test_context_budget.py backend/tests/test_context_config.py \
  backend/tests/test_code_model.py backend/tests/test_agent_runtime.py \
  backend/tests/test_planner_situation.py backend/tests/test_execution_stability.py \
  backend/tests/test_coverage_review_policy.py backend/tests/test_worker_publication_recovery.py \
  backend/tests/test_planner_publication_recovery.py backend/tests/test_poc_runner_contexts.py \
  backend/tests/test_poc_runner_client.py backend/tests/test_poc_verification.py \
  backend/tests/test_poc_agent.py backend/tests/test_lab30_e2e_script.py \
  backend/tests/test_replay_lfi_evidence.py backend/tests/test_report_poc_statistics.py \
  backend/tests/test_claude_poc_queue.py backend/tests/test_poc_model_gateway.py \
  backend/tests/test_poc_diagnostics.py backend/tests/test_poc_source.py \
  backend/tests/test_run_continuations.py backend/tests/test_host_queue.py \
  -q --basetemp=/dev/shm/va-pytest -p no:cacheprovider
```

后端全量（本次 2182 passed / 2 failed，见 §2）：

```bash
backend/.venv/bin/python -m pytest backend/tests -q \
  --basetemp=/dev/shm/va-pytest -p no:cacheprovider
```

前端与浏览器（API 全部在内存中模拟，不连接审计服务）：

```bash
cd frontend && npm test && npm run build && cd ..
export CHROME_BIN=$HOME/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome
uv run --with playwright python scripts/ui_smoke.py --mock http://127.0.0.1:5173
uv run --with playwright python scripts/ui_execution_smoke.py http://127.0.0.1:5173
uv run --with playwright python scripts/ui_host_queue_smoke.py http://127.0.0.1:5173
```

浏览器脚本要求本地 `vite` 开发服务器已在 `127.0.0.1:5173` 提供 `frontend`；截图输出目录可选（`--screenshots`），属于临时产物，不写入源码或运行档案。

## 8. 交付边界

- 本记录只覆盖离线矩阵（定向、全量、前端、浏览器模拟、回放），不等于真实 Lab30 检出率、模型成本或 SDK 上游质量验收。
- 未改动历史运行、冻结报告、ground truth、`scoring_anchors_v2.json` 或 Prompt 实验预算；未删除既有失败记录。
- 两条失败测试保留原状并在此记录，供语义负责人裁定；不以修改测试通过数的方式收尾。
- 真实对照（同模型、同初始状态、同预算）与 Lab30 复位由用户另行启动。
