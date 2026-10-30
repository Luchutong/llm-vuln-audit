# lab30 闭环运行记录

一次真实全量审计的现场记录：环境、命令、版本、结果与已知偏差。本文只记录事实，
不改写历史运行，也不修改 lab30 的业务源码、ground truth 或评分锚点。

## 目的

验证 `vuln-audit` 在 lab30「拾光商城」上能完整闭环：
Planner 派发 → Worker 取证 → findings → POC 自动验证 → 覆盖复核 → v2 评分 → 报告。
验收口径是**流程与检出同时达标**（见文末「验收判据」）。

## 环境

| 项 | 值 |
|---|---|
| 目标 | lab30「拾光商城」，PHP 8.4 / Apache / MariaDB，30 个植入漏洞 |
| 靶场地址 | `http://127.0.0.1:18882`（compose 服务 `lab30`） |
| POC runner | `http://127.0.0.1:18089`（compose 服务 `poc-runner-dev`），版本 3.1.1 |
| 后端 | `./scripts/start.sh --poc`，`http://127.0.0.1:8899` |
| 模型 | `ark-code-latest`（沿用，未切换 provider） |
| 审计输入 | `data/imports/lab30-shop-1.0.0-source.zip` |
| 评分 | `--protocol lab30-v2`（`scripts/run_lab30_e2e.py` 默认） |

compose 服务（`--profile poc`）：`lab30`、`lab30-db`、`lab30-fixtures`、`poc-runner`、`poc-runner-dev`。

## 历史运行对照（未修改）

| run id | 状态 | 时长 | 关键失败 |
|---|---|---:|---|
| `abbc2616170c4952817aa005f4a13fce` | `failed` | 596s | 单次 429（`RequestBurstTooFast`）被当成致命错误；POC mode = `off`；TP 11/30、F1 45.8% |
| `57df26c83d6d4f27b9c91a183dc04efa` | `inconclusive` | 529s | `unresolved_blockers`：任务撞 `context_limit`；覆盖复核未记录 |
| `deliverable/lab30-validation-2026-10-26/` | 归档最佳 | — | 26 TP、F1 0.9286、5 条 confirmed；模型为 `deepseek-chat`，且因 Planner 态势上限失败 |

这两次运行保持原状态，作为本轮修复的对照。

## 历史污染：复位前的只读证据

本轮修复前，live lab30 的种子账号已被历史 POC **持久改写**，而 runner 仍按种子角色校验。
复位（`reset_shop()`）会 `DELETE FROM events` 并重置 `users`，下面的现场会永久消失，
因此先在此留证。以下全部为只读查询（PHP CLI 读库、runner 容器内列目录），没有写入。

### 账号（复位前，2026-10-27 约 13:20–13:24 之后的现场）

```
id  username  role      balance     tier
1   alice     admin     999999.00   gold
2   bob       customer  100.00      standard
3   operator  admin     999999.00   gold
4   admin     admin     100.00      gold
```

种子期望（`poc_runner/runner.py` `SEED_ACCOUNTS`）：alice/bob = `customer/100.00/standard`、
operator = `operator/100.00/standard`、admin = `admin/100.00/standard`。只有 bob 仍是种子态。

### 业务事件（`events` 表）

| id | 时间（UTC） | 用户 | 动作 | 字段 |
|---:|---|---|---|---|
| 14 | 2026-10-23 14:33:09 | 1 alice | `update_profile` | `csrf, role, balance, tier` |
| 33 | 2026-10-27 13:20:43 | 3 operator | `update_profile` | `csrf, display_name, nickname, email, homepage, role, balance, tier` |
| 40 | 2026-10-27 13:21:24 | 4 admin | `redeem_membership` | — |

`account/update.php` 把 POST 的 `role/balance/tier` 直接拼进 `UPDATE users`（题目本身的
mass-assignment 漏洞），`account/redeem.php` 会把 tier 改成 gold。两者都是合法 POC，
但会让种子账号永久偏离种子态：alice 在 10-23 被改，operator 在 10-27 13:20 被改，
admin 在 13:21 兑换会员，与上表一一对应。

### runner 作业目录（容器内 `/tmp/poc-runner/jobs`）

| 目录 | 写入时间（UTC） | 字节 | 内容要点 |
|---|---:|---:|---|
| `cee031f804874e699747968dac7e0412` | 2026-10-27T13:20:43Z | 2028 | 登录后 POST `/account/update.php`，写 `role=admin, balance=999999, tier=gold` |
| `ed160e93519a4eaa82c3b998b58d09f7` | 2026-10-27T13:21:06Z | 236 | `poc.php`：`md5('240610708')` 与 `md5('wrong-code')` 的弱类型比较自检 |
| `9f04b63117d34223a3e66d5bfcc061bb` | 2026-10-27T13:21:15Z | 1285 | 登录后 GET `/account/redeem.php`，再以 `wrong-code` 提交 |
| `388e9f23044c4d5181a08f28534e384b` | 2026-10-27T13:21:24Z | 1898 | 登录后先 GET 再以 `token=240610708`、`token=0` 两次 POST `/account/redeem.php` |

脚本中不含密码本身（读取 `LAB30_USER` / `LAB30_PASSWORD` 环境变量），此处也不记录任何凭据。

### 这条现场如何变成「认证问题」

- runner 的 `_account_snapshot()` 在角色不符时返回 `identity_or_role_mismatch`；
  alice、operator 被改成 `admin` 后，任何以普通会员为前提的 POC 准备都会失败。
- `PocVerifier.verify_finding()` 曾硬编码 `identity="alice"`，且不检查 `prepared["ok"]`，
  于是一条准备失败只作为 precondition 交给模型，模型只能用 bob/operator/admin 继续。
- runner 另有进程级 `_account_baselines`：按身份记录**第一次**成功快照，之后任何字段变化都判成
  `target_state_changed_manual_reset_required`，且不随 lab30 复位而清除，只能重启 runner。

修复后：每条 finding 前复位种子、身份按 alice→bob 选择、角色不符是硬门禁而字段漂移只作观测、
`authentication_failed` 单独计数并可被闭环判据检查。

### 修复前的动态复现（同一 runner 进程、同一脏现场）

在重启 runner 之前，直接用 runner 的 HTTP 接口复现了两个成因（新建 context → prepare →
关闭 context，不写业务数据）：

```bash
TOKEN=$(sed -n 's/^POC_RUNNER_TOKEN=//p' .env)
curl -sS -X POST http://127.0.0.1:18089/v1/verification-contexts \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target":"lab30","run_id":"auth-repro","finding_id":"auth-repro"}'
curl -sS -X POST http://127.0.0.1:18089/v1/targets/lab30/prepare \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"context_id":"<ctx>","identity":"alice"}'
```

`alice`（成因一：种子账号被 POC 改写）：

```json
{"ok":false,"identity":"alice","authenticated":false,
 "precondition":{"ok":false,"identity":"alice","expected_role":"customer",
  "actual":{"id":1,"username":"alice","role":"admin","balance":"999999.00","tier":"gold",
            "nickname":"alice","homepage":"#"},
  "reason":"identity_or_role_mismatch","expected_state":{}}}
```

`admin`（成因二：进程级基线记录了兑换前的 tier）：

```json
{"ok":false,"identity":"admin","authenticated":false,
 "precondition":{"ok":false,"identity":"admin","expected_role":"admin",
  "actual":{"id":4,"username":"admin","role":"admin","balance":"100.00","tier":"gold",
            "nickname":"admin","homepage":"#"},
  "reason":"target_state_changed_manual_reset_required","expected_state":{},
  "state_changes":[{"field":"tier","before":"standard","after":"gold"}]}}
```

两次准备都返回 `ok=false`，说明即使身份与角色本身正确，进程级基线也会把后续每条 finding
的准备判成失败——只复位数据库不够，必须同时改语义。

## 复位

（复位在本文件「历史污染」小节写定后执行；命令与结果见下。）

```bash
./scripts/reset_lab30.sh
docker compose --profile poc restart poc-runner poc-runner-dev
```

复位已执行（种子断言通过），runner 以 3.1.1 重启。复位后在同一 live 靶场上复验了修复语义
（新建 context → prepare → 关闭，不写业务数据）：

| 检查 | 结果 |
|---|---|
| alice / bob / operator / admin 依次 prepare | 四个身份全部 `ok:true` |
| 以 bob 只改 nickname，再 prepare | `ok:true` + `state_drift`（不再 `target_state_changed_manual_reset_required`） |
| `expected_state={"balance":100}` 对实际 `"100.00"` | 通过（数值按 Decimal 比较） |
| `GET /v1/verification-contexts/{id}` | 返回 `pending_jobs`，可用于复位前等待 context 关闭 |

## 上下文压缩动态复现（128KiB，未改默认值）

为了不靠「等它自然超限」来验证压缩器，用环境变量把上限定到 128KiB 跑一次小规模全量审计
（`poc_mode=off`，responses 40、tools 160、seconds 1200）：

```bash
AUDIT_HISTORY_BYTES=131072 AUDIT_HISTORY_SUMMARY=1 ./scripts/start.sh --skip-install --poc
python3 /tmp/mini_context_run.py   # 上传源码 zip → max_planner_rounds 6、max_total_attempts 6、coverage_review
```

run id `7e1b9899f51c4c2bbd5b22d416e990ad`，结果（只读取事件）：

| 指标 | 值 |
|---|---|
| `context_summarized` | 2 条（`116411 → 114319`，摘要 1198 字节；`113769 → 111870`，摘要 1702 字节） |
| `context_limit` | 0 条 |
| `model_request` | 55 条，均带 `request_bytes / history_bytes / used_ratio / message_count` |
| `purpose="history_summary"` 请求 | 2 条（3803、4089 字节，各 1 条消息） |
| 带 `compact` 的 `model_request` | **0 条** |

前四项符合通过标准；最后一项暴露了一个真实缺陷：**摘要请求本身占一个响应**，两次摘要都花掉了
阶段最后一个响应，压缩后的请求没有发出去，所以「压缩生效」只体现在摘要事件里，没有一次请求
真正带着摘要发出去。修复方式是压缩器在发起摘要前先确认「摘要 + 它要压缩的请求」都还在预算内
（阶段与运行两级）；只剩一个响应时直接确定性裁剪，并记一条
`context_summary_failed(reason="budget")`。离线回归见
`backend/tests/test_context_budget.py::test_a_summary_is_never_bought_with_the_phase_last_response`
与 `backend/tests/test_code_model.py::test_a_summary_is_never_bought_with_the_phase_last_response`
（后者用真实闸门验证「有两个响应时摘要会被买下，压缩后的请求带 `compact` 遥测」）。

另一次尝试用 64KiB（允许的最小值）时，第一个请求就是 92,775 字节——Planner 提示词本身已经超过
上限、prefix 只有 2 条消息无可压缩，直接 `context_limit(source="history_bytes")`。这说明 64KiB
不是「保守值」，新模型起步用 128KiB。复现完成后已把后端恢复为默认 384KiB 再跑闭环。

## 闭环运行

| 项 | 值 |
|---|---|
| commit | `569a77bdd4648b8a77b4cc166096e4af9779de45` |
| run id | `7f00e97c923049fc97126660fc336eea` |
| 命令 | `run_lab30_e2e.py --base http://127.0.0.1:8899 --zip data/imports/lab30-shop-1.0.0-source.zip --closure --out datasets/lab30-shop/score_all_v2.json` |
| 状态 | `inconclusive`，stop code `unresolved_blockers`（"一次修复规划后阻塞原因仍未改变"） |
| 时长 | 1341s（上限 5400s） |
| 用量 | responses 134 / 1024，tools 259 / 8192 |
| 事件 | 1490 条 |

闭环档配置：POC `auto`、`completion_policy=coverage_review`、`baseline_policy=fresh`、
`max_rounds=32`、`max_total_attempts=96`、`max_workers=2`。开跑前与结束后各复位一次，
两次种子断言均通过（4 账号、偏差 0）。

产物：`datasets/lab30-shop/closure_7f00e97c.json`、`score_all_v2.json`、
`report_7f00e97c.md`。

## 验收判据

| 判据 | 要求 | 实际 | 结论 |
|---|---|---|---|
| run 状态 | 非 `failed`，`inconclusive` 须有明确 stop_reason | `inconclusive` / `unresolved_blockers` | 通过 |
| 覆盖复核已记录 | `coverage_review_recorded` 存在 | 1 条（第 2 轮，2 个 skip） | 通过 |
| 覆盖收束 | `pending_total == 0` | **7**（read 52/61，reviewed 54/61） | **未通过** |
| POC 作业 | `jobs > 0` 且至少 1 条 confirmed | **0 / 0** | **未通过** |
| POC 认证 | `authentication_failed == 0` | 0（无作业，判据空转） | 通过（无意义） |
| 复位 | `reset_between_findings`、`seed_verified` | 均为 true，post_run_reset true | 通过 |
| 上下文 | `history_limit_hits == 0`，峰值有记录 | 0；峰值 142,769 字节（36.3%） | 通过 |
| 摘要 | `summary_requests` 可为 0，须说明 | 0（整轮未接近 384KiB 触发水位） | 通过 |
| 检出 | TP ≥ 26、F1 ≥ 0.9286、D ≤ 2 | **TP 16、F1 0.421、D 29** | **未通过** |
| 报告 | 非空 Markdown | `report_7f00e97c.md` | 通过 |

v2 评分：TP 16、D 29、U 1、FN 14，precision 0.348、recall 0.533、F1 0.421。
46 条 finding 中 29 条是同一评分位置上的重复表述，1 条落在任何 truth 位置之外。
未命中的 14 条真值：02 greeting 反射 XSS、03 ping 命令注入、06 template-preview RFI、
07 formula 动态调用、09 database 信息泄露、10 密码 MD5、11 messages 存储型 XSS、
12 url-preview SSRF、18 maintenance 头信任、19 create.php 金额篡改、20 withdraw 竞争条件、
21 会话固定、24 batch-check 跨文件命令注入、26 partner JWT。

## 已知偏差

本轮闭环没有走完，原因按阻断顺序记录（未修改 lab30 源码、ground truth 或评分锚点）：

1. **去重二档实际未合并（D=29）**：`classify_run_duplicate()` 的精确层要求证据区间、前提、
   POC、CVSS 全一致；二档 `(类型, 路径, 行, normalise_sink(dangerous_operation))` 的
   `normalise_sink` 只做 NFKC/大小写/空白归一，等于要求危险操作的描述**逐字相同**。
   同一 sink 被不同 worker 换句话描述就合并不了，例如 `ops/template-render.php:3` 的 5 条
   分别是「动态代码执行 eval」「eval() on attacker-supplied expression」
   「第3行 eval 执行客户端表达式」「eval() 执行客户端表达式」「eval 动态执行客户端可控字符串」。
   本轮 `finding_duplicate` 0 条、`finding_duplicate_candidate` 28 条，46 条 finding 只对应
   18 个不同的 `(类型, 路径, 行)` 主张（17 个不同位置，全部落在真值位置上，覆盖 16 个 truth）。
   宿主把候选线索交给 Planner，但 Planner 没有「确认重复」的工具，最终 disposition 全部停留在 `open`。
2. **覆盖复核被 blocker guard 截断（pending 7）**：第 3、4 轮把剩余未读路径派成新方向后，
   6 个任务以「当前结果已保存，但剩余方向未结算」阻塞；reconcile loop 里的 blocker guard
   （`_blocker_progress_signature` 未变即 `inconclusive`）先于覆盖复核判定，于是最后 7 条
   待复核路径（`bin/lab`、`bin/package.py`、`compose.yaml`、`docker/*`、`fixtures/server.py`）
   没有机会被显式 skip。这些是非业务文件，第 2 轮对 `assets/app.js`、`assets/products.svg`
   的 skip 已经证明这条路径可行。
3. **第 4 轮 Planner 决策被判无效**：`planner_round_failed` 的拒绝原因是
   「任务 sql-injection-dataflow 已经处于 blocked，不能重新定义已派发或已结算任务」。
   Planner 想重开/缩小受阻方向，宿主只接受「新任务」，连续 3 次无效后该回合失败。
4. **POC 一次都没有启动**：`verify_standing()` 位于 reconcile loop 的收束分支
   （blocker guard 与覆盖复核之后），本轮在 blocker guard 就结束了，从未到达收束边界。
   因此 `poc.jobs==0`，认证与复位类判据虽然都是 0/true，但没有实际检验。
5. **上下文没有触发压缩**：峰值 142,769 字节，只有 384KiB 的 36.3%，整轮 0 次摘要、
   0 次 `context_limit`。这是预算放宽后的预期结果，不是压缩器失效；压缩路径的证据见上一节。
6. **退出码**：脚本本身在 `failed_checks` 非空时 `return 1`，本次通过 `| tee` 管道运行，
   管道退出码取自 `tee`，所以终止状态看起来是 0；判定以 `closure_7f00e97c.json` 的
   `failed_checks` 为准。

## 闭环运行（第二轮：调度与去重修复后）

本轮验证 `37dcee0` 的四处修复（先 POC 与覆盖复核、后阻塞停滞判定；原子缩小并重开
blocked 任务；二档去重按 `sink_similarity`；POC 在统一终态入口也执行）。lab30 业务源码、
ground truth、评分锚点、模型与预算均未改动。

| 项 | 值 |
|---|---|
| commit | `37dcee0ec9d082f387419f5e32871ec5a3304cc6` |
| run id | `1287aed9e8cb4ed28ed7fcc8bd8cb91b` |
| 时间 | 2026-10-27 16:55:09Z – 18:05:01Z（脚本计量 4064.7s，上限 5400s） |
| 状态 | `inconclusive`，stop code `unresolved_blockers`（第 7 轮修复规划失败后阻塞原因未变） |
| 用量 | responses 531 / 1024，tools 715 / 8192 |
| 事件 | 4835 条 |
| 复位 | 开跑前与结束后各一次，均为 4 个账号、偏差 0；POC 每条 finding 前复位 48 次，失败 0 |

产物：`datasets/lab30-shop/closure_1287aed9.json`、`score_all_v2.json`（被 `.gitignore`
覆盖）、`report_1287aed9.md`（192,722 字节）。

### 验收判据（第二轮）

| 判据 | 要求 | 实际 | 结论 |
|---|---|---|---|
| run 状态 | 非 `failed`，`inconclusive` 须有明确 stop_reason | `inconclusive` / `unresolved_blockers` | 通过 |
| 覆盖复核已记录 | `coverage_review_recorded` 存在 | 2 条（`assets/products.svg`、`fixtures/server.py` skip） | 通过 |
| 覆盖收束 | `pending_total == 0` | **0**（total 61，read 60，reviewed 61） | 通过 |
| POC 作业 | `jobs > 0` 且至少 1 条 confirmed | **220 / 21**（48 条验证记录） | 通过 |
| POC 认证 | `authentication_failed == 0` | 0（`state_mismatch` 1，`auth_events` 0） | 通过 |
| 复位 | `reset_between_findings`、`seed_verified` | 均为 true，`reset_failures` 0，`post_run_reset` true | 通过 |
| 上下文 | `history_limit_hits == 0`，峰值有记录，无 `planner_context_error` | 0；峰值 144,019 / 393,216 字节（36.63%）；摘要 0 | 通过 |
| 检出 | TP ≥ 26、F1 ≥ 0.9286、D ≤ 2 | **TP 18、F1 0.4615、D 28** | **未通过** |
| 报告 | 非空 Markdown | 192,722 字节 | 通过 |

v2 评分：TP 18、D 28、U 2、FN 12，precision 0.375、recall 0.6、F1 0.4615。本轮共创建
52 条 finding，宿主按新二档规则标记 4 条 `duplicate`，评分器对剩余 48 条主张做
一对一匹配。

POC 明细（`poc_verification_recorded`）：confirmed 21、uncertain 25、rejected 2；
执行状态 success 23、`other_error` 15、`not_triggered` 9、`state_mismatch` 1。
认证失败 0，说明复位 + 身份不变量让 POC 第一次在真实闭环里跑起来，且没有回退到
用错误身份硬试。

与上一轮的对照（同一靶场、同一模型）：

| 指标 | `7f00e97c` | `1287aed9` |
|---|---:|---:|
| 覆盖 pending | 7 | **0** |
| POC jobs / confirmed | 0 / 0 | **220 / 21** |
| TP | 16 | 18 |
| D | 29 | 28 |
| U | 1 | 2 |
| FN | 14 | 12 |
| F1 | 0.421 | 0.4615 |

### 检出缺口

流程第一次完整收束，但检出仍低于计划中的目标，原因按证据记录：

1. **二档去重只合并了 4 / 28 个候选**：48 条有效主张仍对应 23 个不同的
   `(类型, 路径, 行)`，其中 16 个分组有多条主张（共 25 条额外主张）。例如
   `content/page.php:3` 6 条只判重 1 条、`ops/maintenance.php:3` 4 条判重 1 条、
   `account/backup.php:5` 3 条判重 0 条、`orders/detail.php:3` 3 条判重 0 条。
   阈值与唯一候选规则本身按预期工作（歧义时不合并），缺口在于 `sink_similarity`
   对中文换述仍偏严：`include 动态路径` 与 `include 动态文件路径` 这类表述的
   Jaccard 达不到 0.6。
2. **12 条未命中真值**：02 greeting 反射 XSS、06 template-preview RFI、07 formula
   动态调用、09 database 信息泄露、10 密码 MD5、12 url-preview SSRF、13 xml-import
   XXE、14 settings CSRF、17 users Cookie 授权绕过、21 会话固定、28 report 二次
   SQL 注入、29 template-render 表达式执行。
3. **其中 7 条集中在一个 blocked 任务**：`cli-tooling-and-packaging` 第 6/6 次尝试后
   以 blocked 结束，它的 `remaining_work` 明确列着
   `ops/formula.php`、`ops/database.php`、`ops/url-preview.php`、`ops/xml-import.php`、
   `ops/template-preview.php`、`ops/template-render.php`、`ops/report.php`——正好覆盖
   06/07/09/12/13/28/29。它的多次尝试以 `budget`（单阶段响应额度）与 `no_progress`
   停止，而全局只用了 531/1024 个响应。
4. **另外 4 条是“读到了但没主张”**：`greeting.php`、`register.php`、`settings.php`、
   `bootstrap.php` 分别被 56 / 123 / 170 / 527 条事件引用（覆盖与任务里反复出现），
   但没有任何 finding 落在这些 truth 位置。这是检出/分类层的缺口，不是覆盖记账问题。
5. **收束仍由 blocker guard 触发**：第 7 轮 `planner_round_failed`（`invalid_output`）
   的原因是 `public-entry-input-flow` 第三次重开超过上限 2；随后 blocker guard 以
   `unresolved_blockers` 收束。此时覆盖复核与 POC 已经完成，正是本轮修复期望的顺序。
6. **脚本的通过口径只含流程项**：`closure_problems()` 检查 `failed`、覆盖、POC 作业、
   认证、复位、历史超限与评分退出码，不含 TP/F1/D 阈值。因此打印
   `闭环验收通过 · TP=18 · F1=0.4615` 只表示**流程闭环**；检出是否达标必须同时看
   `closure_1287aed9.json` 的 `score` 字段和上表「检出」行。

下一轮的杠杆按影响排序：单任务剩余方向的尝试/响应额度（第 3 条，直接覆盖 7 条
FN）、二档去重的中文表述归一（第 1 条，直接压低 D）、以及 4 条读到未主张的分类
复核（第 4 条）。这些都不需要改 lab30 源码、真值或评分锚点。


## 闭环运行（第三轮：POC 直跑与调度振荡修复后）

本轮验证三处修复：
1. **POC 直跑**：审计产出的 POC 脚本由宿主在模型规划前直接执行（`poc_stored_poc_executed`），
   单条 finding 的 POC 墙钟时间从 60–166s 降到 16–37s；
2. **worker 起跑闸门自锁**：`execute_slot` 不再把自己当作 `additional_workers=1` 传入
   `refresh_review_reserve`，消除了 1311 条 `workflow_budget_reallocated` 与 244 条
   `host_retry` 的振荡；
3. **checkpoint 续跑不重跑 POC**：同一 finding 的已存 POC 在一个 runtime 内只执行一次。

lab30 业务源码、ground truth、评分锚点、模型与预算均未改动。

| 项 | 值 |
|---|---|
| commit | `524c9ee118fd73c295b5a7ab45b1cbd619cdff85` |
| run id | `17fc2e83ab1342a089583b548e45daa0` |
| 时间 | 2026-10-30 11:08:09Z – 11:43:10Z（脚本计量 1987.5s，上限 10800s） |
| 状态 | `inconclusive`，stop code `final_review_incomplete`（22 项未完成终审） |
| 用量 | responses 266 / 2048，tools 299 / 16384 |
| 事件 | 3597 条 |
| 复位 | 开跑前与结束后各一次，4 个账号偏差 0；每条 finding 前复位 28 次，失败 0 |

产物：`datasets/lab30-shop/closure_17fc2e83.json`、`score_all_v2.json`（另存
`score_17fc2e83.json`）、`report_17fc2e83.md`。

### 验收判据（第三轮）

| 判据 | 要求 | 实际 | 结论 |
|---|---|---|---|
| run 状态 | 非 `failed`，`inconclusive` 须有明确 stop_reason | `inconclusive` / `final_review_incomplete` | 通过 |
| 覆盖收束 | `pending_total == 0` | **0**（total 61，read 61，reviewed 61） | 通过 |
| POC 作业 | `jobs > 0` 且至少 1 条 confirmed | **50 / 28 条记录**（confirmed 27，uncertain 1） | 通过 |
| POC 认证 | `authentication_failed == 0` | 0（`state_mismatch` 0） | 通过 |
| 复位 | `reset_between_findings`、`seed_verified` | 均为 true，`reset_failures` 0，`post_run_reset` true | 通过 |
| 上下文 | `history_limit_hits == 0`，峰值有记录 | 0；峰值 131,980 / 393,216 字节（33.56%）；摘要 0 | 通过 |
| 检出 | TP ≥ 26、F1 ≥ 0.9286、D ≤ 2 | **TP 23、F1 0.7302、D 8** | **未通过** |
| 报告 | 非空 Markdown | 已写入 `report_17fc2e83.md` | 通过 |

v2 评分：TP 23、D 8、U 2、FN 7，precision 0.697、recall 0.767、F1 0.7302；
33 条 finding 对应 30 条真值，CVSS 基础分平均绝对误差 1.3261。

### 为什么终审没走完（事实，不是推测）

最终审查阶段只处理了 6 条结论就被中断。事件 `55035`–`55078` 显示：

- 第 17、18 轮都领取同一批次 `7f49062d…`（2 条会话固定类结论）；
- 第 17 轮三次尝试依次被拒：先因“动态已验证结论尚缺同版本正式观测复核”，
  再两次因 `verification_reviews.N.rationale_summary: Field required`；
- 第 18 轮补上了 `rationale_summary`，随后两次被
  `accept 前须判读 comparison_candidates` 拒绝；
- 第 18 轮失败后 `run_final_batches` 的 `final_stalls >= 2` 直接结束整个终审，
  留下 22 项未处置，尽管终审额度还剩 30 个 responses（40 中已用 10）。

也就是说，模型在逐轮逼近批次契约（每轮都在修上一个错误），而宿主的“连续 2 轮
失败即放弃”把这种进展也当成了停滞。这是一个框架侧的不合理旧约束，而不是证据
不足或预算不足。

### 对应修复

- `backend/audit/worker.py`：新增 `final_review_stall()`，终审停滞按
  **拒绝原因** 计数——同一冻结批次被同一理由连续拒绝 3 次（`planner_decision_retries+1`）
  才停止；拒绝理由变化视为进展，允许下一轮。批次完成即以 0 重置。
- `backend/audit/review_store.py`：`accept` 未判读 `comparison_candidates` 的拒绝
  现在直接列出仍保留的对照 `item_id`，并指明写进哪一项的 `distinct_from`；
  原报错只复述规则，模型连续两次以空 `distinct_from` 重新提交。
- 回归：`backend/tests/test_final_review_stall.py`（停滞计数）、
  `backend/tests/test_review_closure.py::test_a_changed_final_rejection_earns_another_round`
  （同一批次先两次不同理由被拒、第三次发布成功，批次必须结清）、
  `backend/tests/test_review_input_repair.py`（拒绝信息必须点名对照项）。

## 闭环运行（第四轮：终审停滞修复验证与覆盖复核暴露的新墙）

第四轮在第三轮三处修复之上，只新增了终审停滞计数的改动，用来验证终审能否走完。
结果：**终审确实走完了**（13、14 轮结清全部 final 批次，`review_batches_pending` 为空），
但源码挖掘阶段在覆盖复核处撞上了另一面墙，覆盖停在 46/61。

| 项 | 值 |
|---|---|
| commit | `524c9ee118fd73c295b5a7ab45b1cbd619cdff85`（与本轮修复前的代码一致） |
| run id | `a93ba654480d4520a805959e28cf4332` |
| 时间 | 2026-10-30 11:52:54Z – 12:16:53Z（脚本计量 1433.9s，上限 10800s） |
| 状态 | `inconclusive`，stop code `audit_partial` |
| 用量 | responses 154 / 2048，tools 152 / 16384 |
| 事件 | 2234 条 |
| 复位 | 开跑前与结束后各一次，每条 finding 前复位 20 次，失败 0，种子验证通过 |

产物：`datasets/lab30-shop/closure_a93ba654.json`、`report_a93ba654.md`。
（`score_all_v2.json` 已被本轮覆盖。）

### 验收判据（第四轮）

| 判据 | 要求 | 实际 | 结论 |
|---|---|---|---|
| run 状态 | 非 `failed` | `inconclusive` | 通过 |
| 覆盖收束 | `pending_total == 0` | **15**（total 61，read 46） | **未通过** |
| POC 作业 | `jobs > 0` 且至少 1 条 confirmed | 34 / 20 条记录（confirmed 18，uncertain 2） | 通过 |
| POC 认证 | `authentication_failed == 0` | 0（`state_mismatch` 0） | 通过 |
| 复位 | `reset_between_findings`、`seed_verified` | 均为 true，`post_run_reset` true | 通过 |
| 上下文 | `history_limit_hits == 0` | 0；峰值 150,232 / 393,216 字节（38.21%）；摘要 0 | 通过 |
| 终审 | 全部 final 批次结清 | 13、14 轮完成，`review_batches_pending` 空 | 通过 |
| 检出 | TP ≥ 26、F1 ≥ 0.9286、D ≤ 2 | TP 18、F1 0.72、D 1 | 未通过 |
| 报告 | 非空 Markdown | 已写入 `report_a93ba654.md` | 通过 |

v2 评分：TP 18、D 1、U 1、FN 12，precision 0.90、recall 0.60、F1 0.72；
20 条 finding，CVSS 基础分平均绝对误差 1.2000。检出下降与覆盖下降同向：
少读了 15 个第一方入口，finding 数从 33 降到 20，precision 上升而 recall 下降。

### 覆盖复核为什么停在 15（事件链，不是推测）

第 4、5、6 轮各自以同一条提交拒绝结束：

```
planner_commit_rejected
  未知源码路径不能直接升级为必做方向，请明确修正范围后再采纳
```

随后宿主按“覆盖缺口签名连续不变”结束 discovery，留下 15 个未读路径。
被拒的方向是 `dir_06bfef369c97d661810937dc739658b7`，文本为：

> lab30-shop/app/public/ops/users.php Cookie 授权绕过、report.php/member_lookup.php SQLi、support/download.php 路径穿越待成条

它的 `unknown_paths` 是 `["report.php/member_lookup.php"]`。冻结源码里两个文件其实都存在
（`ops/report.php`、`src/member_lookup.php`）——那是模型在散文里用斜杠把**两个文件名**
连成了一个 token，而宿主的路径识别正则把整个 token 当成一条路径。于是：

1. 一个真实、可执行的方向被标成 `requirement: advisory` + `unknown_paths`；
2. `direction_updates.assign` 对这类方向一律拒绝，而 `direction_updates` 没有“修正路径”的动作，
   模型无论如何都走不通；
3. 拒绝信息只重复规则，不说是哪个方向、哪些名字、接下来能做什么；
4. 覆盖缺口停滞计数只看 `pending_paths`，模型换了错误也照样算停滞。

这是框架侧缺陷：识别错误 + 不可能被满足的门禁 + 不可执行的拒绝信息 + 不区分进展的停滞计数。

### 对应修复（第五轮验证用）

- `backend/audit/directions.py`：新增 `unknown_source_names()`，把匹配到的 token 按 `/`
  拆段后再对冻结路径求解，只有所有段都解不出才算未知。`report.php/member_lookup.php`
  因此不再被当作未知路径。
- `backend/audit/directions.py`：未知路径拒绝现在点名方向 ID 与具体文件名，并给出两条
  可执行出路（`skip` 说明该路径不在冻结源码内，或 `resolve` 引用同一 `direction_id` 的取证）；
  同一方向被多个任务领取的拒绝也点名两个任务键。
- `backend/audit/worker.py`：覆盖复核停滞签名改为 `(pending_paths, 本轮失败原因)`，
  与终审停滞同一语义——同一缺口背后换了拒绝理由视为进展，允许一轮；`last_planner_failure`
  改为每轮开头重置，只表示本轮失败。
- `backend/audit/worker.py` / `review_store.py`：`finish_goal` 支持 `code`，
  覆盖复核结束、阻塞未解除、尝试耗尽分别落 `coverage_incomplete` / `blocker_unresolved` /
  `attempts_exhausted`；`review_terminal_reason` 为这些代码给出具体诊断，不再一律
  `audit_partial`（第四轮的 `audit_partial` 就是这样丢掉了真实原因）。
- 回归：`tests/test_host_queue.py::test_a_worker_naming_two_files_in_prose_does_not_make_a_direction_unassignable`、
  `::test_an_unknown_path_refusal_names_the_names_and_the_allowed_actions`、
  `tests/test_coverage_review_policy.py::test_changed_coverage_round_errors_earn_another_review_round`、
  `tests/test_review_input_repair.py::test_a_coverage_stop_keeps_its_own_diagnosis`。

## 闭环运行（第五轮：覆盖复核修复验证与一次网络瞬断）

第五轮验证第四轮末尾的四项修复。覆盖复核这条链**第一次真正走通**：缺口从 61 降到 1，
`coverage_review_recorded` 在第 3、5、6 轮各落一次，第四轮无论如何都分派不出去的方向
`dir_e8afb3c2ccfa2fc9ba76c97f35c9da1e` 在 12:29:43Z 被正常 `assign` 给
`ops-report-secondorder`，12:31:42Z 以二阶 SQLi 证据 `resolve`。但运行在 592s 时因
模型连接错误收束，POC 阶段没有开始。

| 项 | 值 |
|---|---|
| run id | `64bd9c5074334ab687a01e18229b7b5e` |
| 代码版本 | 工作树的 `directions/worker/review_store` 修复（未提交），commit 记 `524c9ee1` |
| 时间 | 2026-10-30 12:25:41Z – 12:35:33Z（脚本计量 592.9s，上限 10800s） |
| 状态 | `inconclusive`，stop code `model_unavailable` |
| 用量 | responses 95 / 2048，tools 147 / 16384 |
| 事件 | 1079 条 |
| 复位 | 开跑前与结束后各一次，种子 4 个账号偏差 0；POC 阶段未开始，逐条复位 0 次 |

产物：`datasets/lab30-shop/closure_64bd9c50.json`、`report_64bd9c50.md`。

### 验收判据（第五轮）

| 判据 | 要求 | 实际 | 结论 |
|---|---|---|---|
| run 状态 | 非 `failed` | `inconclusive`（`model_unavailable`） | 通过但非目标态 |
| 覆盖收束 | `pending_total == 0` | **1**（total 61，read 55，reviewed 60） | **未通过** |
| POC 作业 | `jobs > 0` 且至少 1 条 confirmed | 0（discovery 未收束，POC 阶段未进入） | **未通过** |
| 上下文 | `history_limit_hits == 0` | 0；峰值 136,634 / 393,216 字节（34.75%）；摘要 0 | 通过 |
| 检出 | TP ≥ 26、F1 ≥ 0.9286、D ≤ 2 | TP 22、F1 0.7586、D 5 | 未通过 |
| 报告 | 非空 Markdown | 已写入 `report_64bd9c50.md` | 通过 |

v2 评分：TP 22、D 5、U 1、FN 8，precision 0.7857、recall 0.7333、F1 0.7586，
finding 28 条。相对第四轮（TP 18、F1 0.72）召回上升、精度下降，重复项从 1 升到 5。

### 覆盖复核修复有效（事件链）

```
12:25:41  coverage_review_requested  pending_total 61
12:29:27  coverage_review_requested  pending_total 10
12:29:43  coverage_review_recorded   skip: assets/products.svg（静态资源）
12:29:43  audit_directions_updated   assign dir_e8af… → ops-report-secondorder
12:31:42  audit_directions_updated   resolve dir_e8af…（update.php 写入 → report.php 拼接的二阶注入）
12:31:42  coverage_review_requested  pending_total 5
12:32:05  coverage_review_recorded   skip: app.js / package.py / compose.yaml / docker/php.ini
12:34:00  coverage_review_requested  pending_total 1（fixtures/server.py）
```

第四轮被路径识别误判挡住的 `dir_06bfef…` 类方向在本轮没有再出现拒绝；
`planner_round_failed` 全程 0 次。剩下的 1 个缺口是 `lab30-shop/fixtures/server.py`
（靶场自带的测试夹具），第 6 轮已把它送进复核，但该轮尚未结束运行就终止了。

### 终止原因：连接错误没有被当成瞬时故障

```
12:34:55  planner_task_host_retry  content-page-traversal  host_failures 1
12:35:00  planner_task_host_retry  fixtures-server-coverage  host_failures 1
12:35:33  planner_task_host_retry  content-page-traversal  host_failures 2
12:35:34  run_inconclusive  model_unavailable
          "模型连续失败 3 次（worker）：ModelCallFailed: APIConnectionError: Connection error."
```

三次失败都是 `APIConnectionError`（走本机代理访问 `api.deepseek.com` 时的连接层错误），
彼此间隔 38 秒，期间 12:34:51 还有一次任务成功结算。事件里没有任何 `provider_retry`：
`AuditCodeModel._retry_wait()` 只把带状态码的 408/409/425/429/5xx 与 `request_timeout`
视为可重试，而连接错误没有状态码，于是**第一次尝试失败就直接进入熔断计数**。计数按设计
在成功结算时归零，三次连续耗尽就把运行按 `model_unavailable` 收束——这条规则本身没错，
错的是连接错误从未获得重试机会。

### 对应修复

- `backend/audit/codemodel.py`：新增 `_CONNECTION_ERRORS`（`APIConnectionError`、httpx 的
  `ConnectError/ReadError/RemoteProtocolError/…`、内建的 `ConnectionResetError` 等）。
  `failure()` 把其中没有状态码的错误也标注为 `ModelCallFailed("model_error")`（此前会作为
  “非预期异常”逃逸），`_retry_wait()` 则对“无状态码且 cause 是连接错误”返回退避时长，
  与 429 走同一条有界重试路径（`transient_retries=3`、指数退避、计入预算、发 `provider_retry`）。
- 回归：`tests/test_code_model.py::test_a_connection_error_without_a_status_is_retried`、
  `::test_an_unreachable_endpoint_still_exhausts_its_retries`。
- 定向回归：`test_code_model.py`、`test_structured_output.py`、`test_worker_runtime.py`、
  `test_worker_publication_recovery.py`、`test_execution_stability.py`、
  `test_coverage_review_policy.py` 共 129 项全部通过。

## 闭环运行（第六轮：首次完整流程闭环与终审配额/拒绝信息修复）

第六轮是第一次把整条链走到评分：覆盖复核 61/61 收束、POC 阶段实际执行并产出 32 条
confirmed、终审批处理建好并跑了 21/22 个批次、v2 评分落盘。停留在终审最后一批：
9 项结论未完成处置，运行以 `final_review_incomplete` 收束。本轮暴露的两个宿主缺陷
（配额困在已结束阶段、拒绝信息逐项披露）已在第七轮前修复。

| 项 | 值 |
|---|---|
| run id | `68240a4b547f4839ac18520429177c5a` |
| 代码版本 | commit `524c9ee1`（第五轮网络错误重试修复） |
| 时间 | 2026-10-30 12:46:44Z – 13:44:35Z（脚本计量 3469.2s，上限 10800s） |
| 模型 | deepseek-flash |
| 整次上限 / 阶段配额 | 2048 / 16384 / 10800；derived `1440 / 512 / 96` |
| 状态 | `inconclusive`，stop code `final_review_incomplete`（9 项） |
| 用量 | responses 368 / 2048，tools 374 / 16384 |
| 事件 | 4623 条 |
| 复位 | 开跑前与结束后各一次，种子 4 个账号偏差 0；POC 逐条复位 33 次 |

产物：`datasets/lab30-shop/closure_68240a4b.json`、`report_68240a4b.md`、
`score_all_v2.json`。

### 验收判据（第六轮）

| 判据 | 要求 | 实际 | 结论 |
|---|---|---|---|
| run 状态 | 非 `failed` | `inconclusive`（`final_review_incomplete`） | 通过但非目标态 |
| 覆盖收束 | `pending_total == 0` | **0**（total 61，read 58，reviewed 61） | 通过 |
| POC 作业 | `jobs > 0` 且至少 1 条 confirmed | 52 / **32 confirmed**，1 uncertain，复位 33 次，认证失败 0 | 通过 |
| 上下文 | `history_limit_hits == 0` | 0；峰值 147,212 / 393,216 字节（37.44%）；摘要 0 | 通过 |
| 检出 | TP ≥ 26、F1 ≥ 0.9286、D ≤ 2 | TP 27、D 10、U 0、FN 3、F1 0.8060 | TP 通过，F1/D 未通过 |
| 报告 | 非空 Markdown | 已写入 `report_68240a4b.md`（262 KB） | 通过 |
| `failed_checks` | 为空 | `[]` | 通过 |

### 终审为什么停在最后一批

13:34:07 进入 review 阶段时 review 配额只剩 51 条，13:44:00 最后一次重新分配后也只有
75 条；同一时刻 POC 阶段已花 138 / 1809，仍握着 1809 条未用配额。终审每轮消耗 3 条
（1 次发布 + 2 次纠正），75 条只够 25 轮，而 22 个批次中最后一个 2 项批次连续 27 轮
失败。失败文本在四类拒绝之间来回跳：

```
13:39:58 planner_round_failed ... accept 前须判读 comparison_candidates：… 须把 X 写入 item_id=A 的 distinct_from
13:40:19 planner_round_failed ... accept 前须判读 comparison_candidates：… 须把 Y 写入 item_id=B 的 distinct_from
13:41:27 planner_round_failed ... verification_reviews.0.rationale_summary: Field required；…verification_reviews.1…
13:41:55 planner_round_failed ... accept 前须判读 comparison_candidates：…
```

模型每轮修好被点名的一项，下一次拒绝才点名另一项，两个 item 交替消耗纠正额度，
直到整轮失败；插件在 failure 变化时允许继续，于是一个 2 项批次被反复重试了 27 轮。
配额侧同理：`refresh_review_reserve` 只能按当前 review 配额重新切分，
`set_workflow_stage("review")` 从不回收已结束 POC 阶段的剩余配额。

### 对应修复（第七轮前）

- `backend/audit/review_store.py::validate_review_decisions`：先收集**全部** item 的
  对照要求（`problems`），一次性抛出以“本批次逐项要求：…”结尾的拒绝，不再逐项披露。
- `backend/audit/execution_state.py`：新增 `Store.release_poc_quota(run_id)`，
  把 POC 阶段未花的 responses 转给 review，并累加 `transferred`；显式配额
  （`source == "explicit"`）不参与。`worker.py::run_final_batches` 进入终审批处理前调用。
  刻意**不**放在 POC→review 的每次切换上：discovery 之后 POC/review 会交替多轮，
  提前回收会让 POC 阶段在 `remaining.poc >= 4` 的判定处饿死（`test_each_two_nonverified_results_still_receive_a_planner_review` 回归）。
- 历史/缺失字段：`transferred` 用 `value.get("transferred", 0)` 读取，旧运行状态不因新字段失败。
- 回归：`test_finished_poc_quota_moves_to_the_final_review`、
  `test_same_anchor_acceptance_requires_an_explicit_comparison`（断言一次拒绝列出两项）。
- 定向回归：`test_discovery_workflow / test_review_closure / test_workflow_review_boundaries /
  test_host_queue / test_review_input_repair / test_coverage_review_policy` 共 79 项通过。

## 闭环运行（第七轮：终审完整收束，首次 `completed`）

第七轮验证第六轮末尾的两项修复（终审配对拒绝一次列全、POC→review 配额回收）。
运行以 `goal_met` 正常完成：覆盖 61/61、POC 24 条 confirmed 且认证失败 0、
终审 22 个批次全部处置（D=0）、`failed_checks` 为空。检出 TP 22 / FN 8 / F1 0.830，
低于归档基准（TP 26 / F1 0.9286），差距来自漏检而非流程。

| 项 | 值 |
|---|---|
| run id | `2969bcf204cd43b5baf2683cbb0e841d` |
| 代码版本 | 工作树（第五/六轮修复，commit 记 `524c9ee1`） |
| 时间 | 2026-10-30 13:58:07Z – 14:45:26Z（脚本计量 2832.1s，上限 10800s） |
| 模型 | deepseek-flash |
| 整次上限 / 阶段配额 | 2048 / 16384 / 10800；derived `1440 / 512 / 96` |
| 状态 | **`completed`**，stop `goal_met` |
| 用量 | responses 254 / 2048，tools 270 / 16384 |
| 事件 | 3212 条 |
| 复位 | 开跑前与结束后各一次，种子 4 个账号偏差 0；POC 逐条复位 25 次 |

产物：`datasets/lab30-shop/closure_2969bcf2.json`、`report_2969bcf2.md`（207 KB）、
`score_all_v2.json`。

### 验收判据（第七轮）

| 判据 | 要求 | 实际 | 结论 |
|---|---|---|---|
| run 状态 | 非 `failed`，首选 `completed` | `completed`（`goal_met`） | **通过** |
| 覆盖收束 | `pending_total == 0` | **0**（total 61，read 59，reviewed 61） | **通过** |
| POC 作业 | `jobs > 0` 且至少 1 条 confirmed | 47 / **24 confirmed**（1 uncertain），复位 25 次，认证失败 0 | **通过** |
| 上下文 | `history_limit_hits == 0` | 0；峰值 150,895 / 393,216 字节（38.37%）；摘要 0 | **通过** |
| 终审 | 全部批次处置，无 pending | D=0，U=1，`failed_checks == []` | **通过** |
| 检出 | TP ≥ 26、F1 ≥ 0.9286 | TP 22、FN 8、precision 0.9565、F1 0.8302 | 未通过 |
| 报告 | 非空 Markdown | `report_2969bcf2.md` | **通过** |

### 配额回收在真实运行中生效

第六轮结束时 POC 阶段握着 1809 条未用配额、终审只有 75 条；第七轮在终审批处理入口
回收后，运行末尾的冻结状态为：

```
stage=review source=derived
limits   discovery 105 / poc 120 / review 1823
used     discovery 105 / poc 120 / review  29
transferred 3209
```

即 POC 阶段的 120 条全部花完，未花完的配额（含 discovery→poc 转移的 1416 条）在
终审前一次性转入 review，终审只用了 29 条就完成全部批次。终审期间仍有 4 次
`planner_round_failed`（`rationale_summary` 缺字段、观测版本不符等），但失败文本每次
都在变化，按“changed rejection earns another round”继续，最终全部结算。
`run_final_batches` 之后 `status == completed`，不再出现 `final_review_incomplete`。

### 检出差距（相对归档 26 TP / F1 0.9286）

| truth | 类型 | 漏检原因 | 第六轮是否覆盖到该路径 |
|---|---|---|---|
| 07 | 动态函数调用代码执行（`ops/formula.php`） | 未读/未报 | 是 |
| 09 | 异常与堆栈信息泄露（`ops/database.php`） | 未读/未报 | 否 |
| 10 | MD5 存储密码（`auth/register.php`、`src/setup.php`） | 未读/未报 | 是 |
| 14 | CSRF（`account/settings.php`） | 未读/未报 | 否 |
| 17 | 信任角色 Cookie 越权（`ops/users.php`） | 有相关 finding，但判为 no_related_candidate | 是 |
| 18 | 信任请求头认证绕过（`ops/maintenance.php`） | 未读/未报 | 是 |
| 23 | 跨文件 SQLi（`ops/members.php`、`src/member_lookup.php`） | 未读/未报 | 是 |
| 24 | 跨文件命令注入（`ops/batch-check.php`、`src/host_check.php`） | 报在 `ops/ping.php:2`，锚点与 truth 不符 | 是 |

第七轮 discovery 在 14:09 就收束（105 responses、33 个路径），第六轮同模型在同一策略下
跑了 164 responses、41 个路径并命中 TP 27。两次差异不是预算（都有 1400+ 未用）而是
Planner 探索深度：`coverage_review` 只要求“每条 first-party 路径被读过或被理由跳过”，
不要求按漏洞类逐一取证，因此同一模型会出现 22–27 TP 的波动。这条判定属于既有完成策略，
不在本轮擅自改动；是否切换深一些的模型或调整发现粒度，留给后续决策。
