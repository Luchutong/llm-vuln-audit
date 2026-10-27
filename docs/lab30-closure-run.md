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

