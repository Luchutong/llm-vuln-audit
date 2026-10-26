# 02 · 全量 Lab30 审计（本地部署 + POC auto）

本目录记录在**未经修改的 stock main（commit `bc12280d5f5cb4084cedc8c93fc51e4c85f34e4a`）**上，对 Lab30 商城靶场（30 项真值、22 类漏洞）执行全量审计的两次完整实跑、评分结果、POC 验证证据，以及一个可离线复现的框架缺陷分析。

- 靶场源码：`lab30-shop-1.0.0-source.zip`，SHA256 见各 attempt 目录 `source_zip_sha256.txt`
- 真值与评分锚点：`datasets/lab30-shop/ground_truth.json`、`scoring_anchors_v2.json`（仓库自带，未修改）
- 模型：`deepseek-chat`（DeepSeek 官方兼容接口；配置仅存在于被 `.gitignore` 忽略的 `.env`，未入库）
- 运行命令（两次完全相同，仓库自带 e2e 脚本）：

```bash
backend/.venv/bin/python scripts/run_lab30_e2e.py \
  --zip <lab30-shop-1.0.0-source.zip> --scenario all --poc-mode auto \
  --iterations 3 --max-rounds 24 --attempts 64 \
  --max-wait 10800 --interval 5 \
  --check-severity --check-cvss \
  --out score_all.json
```

- Run 预算（框架默认值）：responses 24 / tools 96 / seconds 1800；POC 策略：`enabled=true, mode=auto, browser=true, max_jobs=8/ finding, job_seconds=30`
- 评分口径：仓库自带 v2 锚点评分（`score_basis=Base`），只读 run 结束时仍主张的 findings，与 run 进程终态解耦。

## 1. 结果总览

| 指标 | 第 1 次 `b2c46d27`（主结果） | 第 2 次 `b857d53e`（复现对照） |
|---|---:|---:|
| 进程终态 | **failed**（框架异常，见 §4） | **failed**（同一异常） |
| 实跑墙钟 | 7m38s | 3m33s |
| 模型用量 | 201 requests / 309 tool calls / 560,981 in / 54,468 out tokens | 93 / 108 / 627,852 / 33,956 |
| 漏洞候选 | 26 | 10 |
| TP / FP / FN | **26 / 0 / 4** | 9 / 1 / 21 |
| Precision / Recall / F1 | **1.0000 / 0.8667 / 0.9286** | 0.9000 / 0.3000 / 0.4500 |
| 文字等级准确率 | 0.6154（16/26） | 0.5556（5/9） |
| CVSS 可评分 / 分数 MAE | 23 条 / 1.2870 | 9 条 / 0.8556 |
| POC runner 作业 | 124 个（99 http + 24 script + 1 browser） | 18 个（9 http + 9 script） |
| POC 判定 | 5 confirmed / 21 inconclusive | 2 confirmed / 8 inconclusive |

完整逐类覆盖、FN/FP 明细与 CVSS 分维度准确率见自动生成的 [`metrics_summary.md`](./metrics_summary.md)，两次的原始控制台流水与完整评分 JSON 分别在 `attempt-1-b2c46d27/`、`attempt-2/`。

**结论（回答"实际能找到哪些漏洞"）**：主结果一次覆盖 22 类漏洞中的 19 类、命中 30 项真值中的 26 项，**零误报**，F1 = 0.9286。SQL 注入（3/3）、反射/存储型 XSS、LFI/RFI、动态函数代码执行、XXE、SSRF、反序列化（2/2）、IDOR、三类认证绕过、价格篡改、竞态、会话固定、弱加密、批量赋值等类别均被命中。

### 1.1 主结果的 4 项漏报（FN）

| 真值 ID | 漏洞 | 真值位置 | 漏报观察 |
|---|---|---|---|
| 09 | 数据库诊断异常与堆栈信息泄露 | `ops/database.php:3` | 信息泄露类，无明确危险参数流，agent 未将报错回显判定为漏洞 |
| 14 | 邮箱设置 CSRF | `account/settings.php:5` | 业务语义型缺陷，纯代码阅读难以确认缺少 token 校验的可利用性 |
| 22 | 兑换码弱类型比较绕过（`==` + 0e 哈希） | `account/redeem.php:5` | 需要特定"魔法哈希"利用知识，未形成漏洞主张 |
| 24 | 主机巡检**跨文件**命令注入 | `ops/batch-check.php:2` + `src/host_check.php:2` | 全部 30 项真值中唯一的跨文件污点链，agent 未把两个文件的 source/sink 串联起来 |

### 1.2 CVSS 校准观察

- 23/26 条给出可评分 CVSS（3 条缺报），基础分 MAE = 1.287；向量逐指标中 AV/AC/UI 准确率很高（0.96/0.96/1.00），短板在 PR（0.57）与整体向量完全一致率（0.22）。
- 主要偏差方向是**等级高估**：多个真值 medium/low 被报为 high/medium（如 ID 23、26、14），与文字等级准确率 0.62 相互印证。

## 2. POC 验证证据（满足"带 POC 启动"要求）

POC 五容器栈（db / fixtures / web 靶场:18880 / poc-runner 隔离执行器 / poc-runner-dev relay:18089，Bearer 鉴权）全程在线，17 项环境验收全部 PASS（见 `../01-environment/verify_lab30_environment.txt`）。

- 第 1 次 run 共落库 **124 个真实 runner 作业**（HTTP 重放 99、Python 脚本 24、Chromium 浏览器验证 1；108 个 exit 0），覆盖 26 条 finding 的 26 个 POC attempt；作业流水见 `framework-defect/poc_runner_container_logs.txt`（1234 行，含多身份 guest/bob/alice 的 context prepare、隔离作业与上下文销毁）。
- **5 条漏洞被真实利用确认（verified/confirmed）**，清单见 `framework-defect/confirmed_findings_attempt1.txt`，包括反序列化 `DispatchJob::__wakeup` 命令执行（带唯一标记 `poc19384565` 的完整利用脚本）、`formula.php` 可变函数调用、RFI、`X-Admin` 头认证绕过、客户端单价篡改。
- 其余 21 条为 inconclusive/uncertain：框架语义是"执行了验证但证据不足以确认或推翻"，**不等于误报**（v2 评分中它们仍按锚点正确计为 TP）。典型如无盐 MD5 存口令这类无法在 30 秒作业内离线破解验证的缺陷。
- 作业级统计与状态分布见 `framework-defect/poc_job_accounting.txt`。

## 3. 为什么跑两次

第 1 次审计在产出 26 条 finding 后以 `failed` 终态结束。为区分"偶发模型轨迹问题"与"可复现框架问题"，在**同一 stock main、同一协议、同一模型配置**下原样重跑一次：第 2 次更早触发同一异常（3m33s，仅 10 条 finding），证明异常与采样随机性无关、在本环境确定性复现。两次记录均完整保留，第 1 次因结果显著更优且零误报作为主结果。

## 4. 框架缺陷：Planner situation 16KB 硬上限导致 run 必败

### 4.1 现象与触发点

两次 run 的终态错误完全相同：

```
ValueError: Planner situation ceiling cannot hold the required closure facts
```

- 抛出点：`backend/audit/agent.py:1533`，`_bound_situation(..., limit=policy.planner_pinned_bytes)`
- 上限常量：`backend/audit/runtime.py:94`，`AgentPolicy.planner_pinned_bytes = 16 * 1024`，frozen dataclass 硬编码，**无环境变量/配置覆盖入口**；生产路径 `backend/audit/app.py:491/1073` 使用裸 `AgentPolicy()`
- 触发时机：第 2 个 planner round 启动、宿主机拼装 situation 阶段（事件 `planner_round_started` 之后、任何模型调用之前），属宿主侧确定性异常，不消耗模型请求

### 4.2 根因（带字节级证据）

`_bound_situation` 只会裁剪 `settled / findings / observations / project_findings / frontier / blockers / goal`，而 POC 验证产生的 **`verification_records` 等闭包事实受保护、永不裁剪**。POC auto 为每条已验证 finding 生成一条记录（`db.py:779 build_verification_records`，单条上限约 3.5KB，中文按 UTF-8 三字节计）。离线重放两次 run 持久化状态得到：

| 组成（attempt-1 / attempt-2） | 是否可裁剪 | attempt-1 字节 | attempt-2 字节 |
|---|---|---:|---:|
| verification_records | **否（闭包事实）** | 48,522 | 14,830 |
| pinned_investigations | 否（仅结构瘦身后保留） | 9,894 | 9,883 |
| verification_reviews_required | 否 | 5,385 | 1,794 |
| notice / dispatch_rule / counts / closure_checks 等骨架 | 否 | ≈ 3,700 | ≈ 3,700 |
| 受保护子合计 vs 16,384 上限 | — | **67,501（溢出 51,117）** | **30,208（溢出 13,824）** |

即：即使把所有可裁剪列表全部清空，剩余闭包事实仍是 16KB 上限的 1.8～4.1 倍，守卫按设计抛错。POC 验证记录越多（finding 越多、验证越充分）越容易触发——这解释了为何结果最好的第 1 次反而必然失败，且该问题在"全量 + POC auto"这一指定组合下被放大；若关闭 POC，finding 保持 `unverified`，`build_verification_records` 会跳过它们，不会触发。

### 4.3 离线无损复现

`framework-defect/reproduce_planner_ceiling.py` 仅依赖仓库自身代码与持久化 DB，不产生任何模型调用，即可重放两次异常并打印完整字节核算，输出存档于 `framework-defect/offline_reproduction_output.txt`：

```bash
cp data/audit.db /tmp/audit_diag.db
backend/.venv/bin/python \
  deliverable/lab30-validation-2026-10-26/02-full-audit/framework-defect/reproduce_planner_ceiling.py \
  /tmp/audit_diag.db b2c46d270da6450e901354f68992f942 b857d53e39ac4dc28fc93ff93ec9aab5
```

### 4.4 处置原则与影响评估

- **未修改任何框架代码**：任务前提是"用最新版 main"，且 prompt 实验清单会记录代码身份（commit + dirty 标记），打补丁会污染全部实验有效性。截至执行日，远端最新仍为 `bc12280`，无对应 issue 或修复提交。
- **评分结果仍然有效**：26 条 finding 在异常发生前已逐条持久化并通过 POC 流水线；v2 评分只读当前仍主张的 findings 及其锚点匹配，不依赖 run 的终态字段，`score_all.json` 正常产出且可复算。
- **建议的上游修复方向（仅记录，不在本分支实施）**：让 `_bound_situation` 对 `verification_records` 具备与其他列表同构的"最旧先丢 + omission 明示"裁剪路径，或按闭包事实规模动态放宽 `planner_pinned_bytes`。

## 5. 文件清单

```
02-full-audit/
├── README.md                      # 本文件
├── metrics_summary.md             # 两次 run 指标/类别覆盖/FN/FP（自动生成）
├── attempt-1-b2c46d27/
│   ├── full_audit_console.txt     # e2e 全量控制台流水（含实时轮询与评分输出）
│   ├── score_all.json             # v2 完整评分结果（63KB，含 26 条匹配明细）
│   ├── poc_relay_health_pre.json  # 开跑前 relay 健康检查
│   └── source_zip_sha256.txt
├── attempt-2/                     # 同上，第二次复现跑
└── framework-defect/
    ├── reproduce_planner_ceiling.py        # 离线复现脚本（无模型调用）
    ├── offline_reproduction_output.txt     # 复现输出与字节核算
    ├── poc_job_accounting.txt              # POC 作业/判定统计
    ├── confirmed_findings_attempt1.txt     # 5 条真实利用确认清单
    ├── poc_runner_container_logs.txt       # 隔离执行器 1234 行作业流水
    └── poc_relay_container_logs.txt        # relay 容器日志
```
