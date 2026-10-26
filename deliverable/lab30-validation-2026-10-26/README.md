# Lab30 验证交付包（2026-10-26/27）

本交付包对应导师布置的两项测试：**① 全量 lab30 测试（本地部署、带 POC 启动、看实际能找到哪些漏洞）**；
**② prompt 横向比对实验（固定约 2 小时墙钟）**。全部工作基于仓库最新主线
`main@bc12280d5f5cb4084cedc8c93fc51e4c85f34e4a` 完成，框架代码零修改，交付物全部位于本目录，
提交在独立分支 `test/lab30-full-audit-and-prompt-comparison`（未触碰 main）。

## 1. 要求对照

| 导师要求 | 落实情况 | 证据位置 |
|---|---|---|
| 用最新版 main | 起始基线 `bc12280`（执行时远端 HEAD，已核对无更新提交/相关 issue）；本分支对 `backend/ frontend/ scripts/` 及 Docker 文件**零差异**，仅新增本文档树 | `git diff --stat bc12280 HEAD`；实验冻结清单 `03-prompt-comparison/frozen/manifest.json`（dirty=false，含全部代码文件 SHA256） |
| 本地部署 | WSL2 Ubuntu-20.04：uv + CPython 3.12 后端、Node 22/Vite 前端、Docker Compose 五容器 POC 栈，17 项环境验收全 PASS | [`01-environment/`](./01-environment/)、[`DEPLOYMENT_NOTES.md`](./DEPLOYMENT_NOTES.md) |
| 带 POC 启动 | `COMPOSE_PROFILES=poc`、POC_ENABLED=1；靶场:18880、runner relay:18089 Bearer 鉴权；全量审计以 `--poc-mode auto` 实跑，落库 124 个真实验证作业、5 条漏洞利用确认 | [`02-full-audit/`](./02-full-audit/)（§2 与 `framework-defect/` 容器日志） |
| 全量 lab30，看找到哪些漏洞 | 两次完整实跑；主结果命中 26/30 项真值、覆盖 22 类中的 19 类、**零误报**，F1=0.9286 | [`02-full-audit/README.md`](./02-full-audit/README.md)、`metrics_summary.md`、两个 attempt 目录 |
| prompt 横向比对，约 2h | 框架内置 lab30-full-v2 协议，3 策略 × 3 轮 = 9 试次全部 valid，协议墙 7200s、实测 3748s（62.5 分钟），零补跑 | [`03-prompt-comparison/`](./03-prompt-comparison/)（官方 `report.md/json/zip`） |
| 保留运行记录 | 控制台流水、轮询流水、评分 JSON、容器日志、API 快照、冻结清单、离线复现脚本全部归档；运行态数据库 `data/audit.db` 保留于本地（按 `.gitignore` 不入库） | 本目录全部文件 |

## 2. 结论摘要

### 2.1 全量审计（POC auto，单试次 1800s 预算）

| 指标 | 主结果 run `b2c46d27` | 对照 run `b857d53e` |
|---|---:|---:|
| TP / FP / FN | **26 / 0 / 4** | 9 / 1 / 21 |
| Precision / Recall / F1 | **1.000 / 0.867 / 0.9286** | 0.900 / 0.300 / 0.4500 |
| POC 作业 / confirmed | 124（99 http+24 script+1 browser）/ **5 条利用确认** | 18 / 2 |
| CVSS 分数 MAE（可评分项） | 1.287（23/26） | 0.856（9/9） |

- 强项：SQL 注入 3/3、认证绕过 3/3、反序列化 2/2，XSS/LFI/RFI/XXE/SSRF/IDOR/竞态/价格篡改/批量赋值等均命中。
- 稳定短板：**CSRF（真值 14）两跑均漏**；信息泄露（09）、弱类型魔法哈希（22）、唯一跨文件污点链（24）在主结果中漏报。
- 两次 run 进程终态均为 failed，但根因是**框架确定性缺陷而非模型能力问题**：`agent.py:1533` 的 planner situation 16KB 硬上限不裁剪 POC 闭包事实（`verification_records`），在"全量 + POC auto"组合下必被撑爆。已用持久化 DB 离线无模型调用复现两次异常（受保护事实分别 67.5KB / 30.2KB），脚本与输出见 `02-full-audit/framework-defect/`。**未打补丁**：修改框架会破坏 stock main 前提与实验代码身份；v2 评分只读持久化 findings、与进程终态解耦，故评分结果有效。

### 2.2 Prompt 横向比对（POC 关、每试次 720s，n=3）

| 策略 | F1（均值±SD） | Precision | Recall | 请求 | tokens | CVSS MAE |
|---|---:|---:|---:|---:|---:|---:|
| W0 基础审计（基线） | **77.5% ± 6.2%** | 72.0% | **84.4%** | 90 | 1.79M | 1.345 |
| W1 证据与防护 | 73.5% ± 8.1%（Δ−4.0pp） | 67.2% | 82.2% | 107 | 2.12M | **1.224** |
| W2 跨文件与业务前提 | 67.3% ± 18.4%（Δ−10.2pp） | **83.1%** | 64.4% | 75 | 1.50M | 1.103 |

- 三策略差距均未超出样本波动，框架报告明确不宣称统计显著；W2 走向"高精确、低召回、高方差"，W1 多花 19% 请求换来更好的 CVSS 覆盖率而非检出率。
- 共性盲区与全量审计一致：**CSRF（真值 14）9 试次 0/9**，MD5 弱加密（10）W1/W2 全程未报。
- 总消耗 817 请求 / 2048 工具调用 / 16,223,436 tokens；9 试次均 `goal_met` 自然收口。POC 关闭使 planner 闭包不含验证记录，9 试次无一触发 2.1 的 16KB 缺陷，两条任务线的根因分析互相印证。

## 3. 目录地图

```
lab30-validation-2026-10-26/
├── README.md                 # 本文件
├── DEPLOYMENT_NOTES.md       # 部署全过程（含 Docker 镜像源绕行等环境问题与解法）
├── 01-environment/           # 工具链版本、镜像 digest、compose 状态、17 项验收、pip freeze、API 配置
├── 02-full-audit/
│   ├── README.md             # 全量审计主文档（结果、FN 明细、POC 证据、框架缺陷分析）
│   ├── metrics_summary.md    # 由 score_all.json 自动生成的指标汇总
│   ├── attempt-1-b2c46d27/   # 主结果：控制台流水、63KB 完整评分、POC 健康快照、ZIP 哈希
│   ├── attempt-2/            # 复现对照（同名四件）
│   └── framework-defect/     # 离线复现脚本、复现输出、作业统计、confirmed 清单、双容器日志
└── 03-prompt-comparison/
    ├── README.md             # 实验解读文档
    ├── report.md / .json / .zip   # 框架官方报告（Markdown / 全量 JSON / 三张 CSV）
    ├── summary.json / final_state.json / state_latest.json
    ├── create_request.json / create_response.json / poll_progress.txt
    └── frozen/manifest.json  # 冻结契约（策略与代码哈希、预算、时间政策）
```

## 4. 复现与核查入口

- 部署复现：按 `DEPLOYMENT_NOTES.md` 准备 `.env`（含模型密钥，**不入库**），`docker compose --profile poc up -d` 后启动后端（需 `POC_RUNNER_URL=http://127.0.0.1:18089`）与前端。
- 全量命令与实验创建请求体分别见 `02-full-audit/README.md` §开头与 `03-prompt-comparison/create_request.json`；框架在实验启动时强校验靶场 ZIP、真值、锚点与全部代码文件哈希，任一漂移即拒绝执行。
- 本地运行态（gitignored）：`data/audit.db`（两次 run 与全部 POC 作业）、`data/prompt-experiments/61e957070de54c0a/`（9 试次冻结资产与逐试次记录），可经 `GET /api/runs`、`GET /api/prompt-experiments/{id}` 实时回读。
- 缺陷离线复现：`python 02-full-audit/framework-defect/reproduce_planner_ceiling.py <db副本> b2c46d27… b857d53e…`，无需任何模型调用。

## 5. 合规与边界说明

- 模型密钥、POC runner token 等仅存于本机 `.env`（chmod 600，命中 `.gitignore`），交付物与 git 历史中不含任何密钥；入库前已用守卫脚本核查无 `.env/data/.run/node_modules/.venv` 混入。
- 所有数字均来自框架自身评分产物或持久化数据库的现算结果，无手工誊写、无人工修正；评分 JSON、容器日志等原始证据与汇总文档一并归档可交叉核对。
- 本报告结论仅描述 Lab30 单一靶场、deepseek-chat 单一模型在本次环境下的表现，不外推到其他靶场或模型。
