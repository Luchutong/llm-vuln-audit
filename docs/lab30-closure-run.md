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

## 复位

（复位在本文件「历史污染」小节写定后执行；命令与结果见下。）

```bash
./scripts/reset_lab30.sh
docker compose --profile poc restart poc-runner poc-runner-dev
```

## 闭环运行

（待填：commit SHA、run id、命令、时长、状态）

## 验收判据

（待填：coverage、POC 计数、上下文峰值、v2 分数）

## 已知偏差

（待填）
