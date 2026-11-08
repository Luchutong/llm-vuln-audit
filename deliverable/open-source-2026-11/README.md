# 成员 B 交付物总览（平台与审计截图 + 数据表）

> **执行年月**：2026-11（目录 `open-source-2026-11`）
> **负责人**：成员 B（3.6 平台界面 + 5.4.3 Prompt 实验 + 第 6 章证据链 + 9.4 审计成果 + D-B01～D-B04）
> **分支**：`feat/part-b-screens-data`（基于 `main`，未直接提交主干）
> **运行环境**：Ubuntu 20.04 虚拟机，FastAPI 后端 `:8899` + Vite 前端 `:5173`，模型 `deepseek-chat`（`https://api.deepseek.com/v1`），SQLite `backend/data/audit.db`

---

## 1. 交付清单

### 1.1 十一张主图（S-B01 – S-B11，`screens/report-set/`）

| 编号 | 文件 | 报告位置 | 关键内容 |
| --- | --- | --- | --- |
| S-B01 | `S-B01_3.1_总体架构.png` | 3.1 | 五模块链路（预处理 → 提示词工程 → LLM 推理 → POC 验证 → 校验降噪）与四类存储对象，分层完整 |
| S-B02 | `S-B02_3.6_源码包库与内容哈希.png` | 3.6 | 项目 `lab30-src`、ZIP 快照下拉（56 个文件）、ZIP SHA-256 全长 `b5c67194…6331f46` |
| S-B03 | `S-B03_3.6_项目工作台.png` | 3.6 | 审计目标文本、验收条件、审计模式（全量覆盖复核）、预算 512 请求 / 4096 工具 / 3600 秒 |
| S-B04 | `S-B04_3.6_执行详情_任务图与覆盖.png` | 3.6 | run `08860008` 审计详情：Planner 16/16 回合、阶段配额（81/152、0/0、5/8）、覆盖 `files_total 56 / files_read 51` |
| S-B05 | `S-B05_3.6_漏洞发现_类型CVSS验证状态.png` | 3.6 | 候选类型（SQLi / 命令注入 / 反序列化）、CVSS（7.5、8.8、7.1、5.4）、验证状态（未验证 / 验证通过） |
| S-B06 | `S-B06_3.6_模型档案.png` | 3.6 | 模型 `deepseek-chat`、Base URL `https://api.deepseek.com/v1`、凭据来源「环境变量」、无明文 Key |
| S-B07 | `S-B07_3.6_报告下载_三种入口.png` | 3.6 | Markdown / JSON / 证据包 三个下载入口，报告验收条件与终审事实包 |
| S-B08 | `S-B08_5.4.3_Prompt实验对比.png` | 5.4.3 | 实验 `c4b1374b9aae4707`（`lab30-full-v2`，9/9 完成）：W0/W1/W2 的 P/R/F1 与 ΔF1 |
| S-B09 | `S-B09_6_Worker结论_证据链.png` | 第 6 章 | 漏洞类型、文件行号 `app/src/host_check.php:2-2`、CVSS 3.1 向量、来源任务 |
| S-B10 | `S-B10_9.4_审计运行中_覆盖与预算.png` | 9.4 | run `a403cb8c` 运行中：预算 44/96 工具 84/288 秒 339.2/1500，分支推进与候选累积 |
| S-B11 | `S-B11_9.4_审计成果指标_评分JSON.png` | 9.4 | run id、TP 19 / FP 1 / FN 11、P 0.9500 / R 0.6333 / F1 0.7600、类别覆盖 15/22（实例 19/30） |

### 1.2 三张补充图（不占主图号）

| 文件 | 说明 |
| --- | --- |
| `S-B08a_5.4.3_Prompt实验_实验元信息与图表.png` | 实验页顶部：已完成 9/9、模型与冻结时间、P/R/F1 柱状图、相对基线 ΔF1（+0.5 / −4.1 个百分点） |
| `S-B08b_5.4.3_Prompt实验_逐轮记录.png` | 9 个试次逐轮明细（运行状态、TP/D/U/FP/FN、P/R/F1、停止原因） |
| `S-B10b_9.4_审计运行中_任务图与阶段配额.png` | run `a403cb8c` 的「审计详情 → 项目与任务图」：阶段配额、冻结范围 56 个可读文件、停止原因 JSON |

`screens/` 根目录另有同批次原始分辨率大图（`S-B01`、`S-B02b`、`S-B04a/b`、`S-B05c`、`S-B10c`、`S-B12`、`S-B15`、`S-B16`），`screens/real-run/` 保留两轮真实审计（`fb54bc3c`、`08860008`）的原始存档，逐图索引见 `screens/INDEX.md`。

### 1.3 四项数据（`data/`）

| 编号 | 文件 | 报告位置 | 内容 |
| --- | --- | --- | --- |
| **D-B01** | `D-B01_P20_九试次明细与三策略汇总.md` | 5.4.3 / 10.1 | 九试次逐次明细 + 三策略 mean±SD + 显著性口径 + 与 10-26 归档的口径差异 |
| **D-B02** | `D-B02_P3_代码规模统计_cloc.md` | 3.x | cloc 1.82 分目录 / 分语言 / 三种口径 |
| **D-B03** | `D-B03_P4_测试资产统计.md` | 3.x / 第 8 章 | 后端 2,268 项、前端 125 项，通过率、失败归因、采集日期 |
| **D-B04** | `D-B04_P18_审计成果量化指标.md` | 9.4 | TP/FP/FN、P/R/F1、类别覆盖、CVSS 质量、成本、真值溯源 |

`data/P20_九试次明细.md`、`P3_代码规模统计.md`、`P4_测试资产统计.md` 为 **2026-11-07 旧版**，文件头已标注「已被取代」，仅保留作口径对照。

---

## 2. 关键数字速查

| 项 | 数值 | 来源 |
| --- | --- | --- |
| 三策略 F1（W0 / W1 / W2） | **61.77% / 62.23% / 57.70%** | 实验 `c4b1374b9aae4707`，n=3 |
| ΔF1（相对 W0） | **+0.46 pp / −4.07 pp** | 同上 |
| 实验总消耗 | 514 请求、777 工具、886.6 万已知 tokens、76 分 12 秒 | 同上 |
| 代码规模（cloc 有效代码行） | **331 文件 / 75,848 行**（全语言 353 / 83,769） | cloc 1.82 |
| 测试资产 | 后端 **2,268 项 / 通过 2,265 / 失败 3**；前端 **125 / 125** | pytest + node:test，2026-11-08 |
| 审计成果（run `a403cb8c`） | **TP 19 / FP 1 / FN 11，P 0.9500 / R 0.6333 / F1 0.7600** | `scripts/score_dataset.py --protocol lab30-v2` |
| 类别覆盖 | **15/22 类 = 68.2%**（实例 19/30） | 同上 |
| CVSS 质量 | 基础分 MAE **1.1421**，向量完全一致率 **31.6%** | 同上 |

---

## 3. 采集方法（透明说明）

- **真实服务**：全部页面截图来自虚拟机内真实运行的 FastAPI + Vite 服务，即真实数据库 `audit.db` 中的真实 run，不是离线夹具、不是手绘、没有手填数字。
- **真实模型**：审计与实验均由真实 `deepseek-chat`（DeepSeek 兼容接口）驱动，`run fb54bc3c`、`run 08860008`、`run a403cb8c` 与实验 `c4b1374b9aae4707` 的 `/api/runs/{id}`、`/api/prompt-experiments/{id}` 均可查到对应记录与消耗。
- **真实截图**：Playwright 驱动本机真实 Chrome（2× DPR、强制浅色主题）访问上述服务渲染页面，非图像合成。
- **真实评分**：S-B11 与 D-B04 的指标由仓库自带 `scripts/score_dataset.py` 对冻结真值集（`datasets/lab30-shop/ground_truth.json`，30 项 / 22 类）现场计算后导出，原始 JSON 随交付。
- **已剔除的假图**：早期无 API Key 阶段曾用仓库自带 `scripts/ui_fixtures.py`（MockAPI 夹具）渲染 13 张结构图，**已全部作废并移入本地 `_deprecated-fixture/`，不纳入本仓库**。本目录内不存在任何夹具渲染产物。

---

## 4. 必须在报告里如实标注的四点

1. **审计终态是 `inconclusive`，不是 `completed`**：run `a403cb8c` 在 11/20 回合、源码覆盖 100% 时因发现阶段配额（78/78）收口，未完成方向保留在阶段报告中。
2. **`poc_mode=off`，验证覆盖率 0%**：虚拟机无 Docker，未启用隔离靶场自动验证，20 条结论的验证状态均为「未验证」。只能写「静态证据完整、待隔离环境复现」，**不能写「已复现」**。
3. **S-B08 的 W1 提升不显著、W2 低于基线**：n=3，轮间标准差 8–15 个百分点，只能写「方向一致但不显著」；W2 的 −4.1 个百分点属负面结果，不得隐去。
4. **S-B10 / S-B11 / D-B04 的审计对象是项目内置 `lab30-src` 快照**，不是成员 C 冻结的第三方仓库（phpMyFAQ 4.1.1）。待 C 的 `ZIP + sha256 + 真值集冻结日期` 到位后，用同一脚本对该快照重跑一次即可替换这三项。

另有两处口径提醒（详见 `data/README.md` §三）：D-B01 与 D-B04 的 F1 不可直接比较（预算不同）；D-B01 的 tokens 是**已知下限**（9 个试次 `token_usage_complete` 均为 `false`）。

---

## 5. 目录结构

```text
deliverable/open-source-2026-11/
├── README.md                      # 本文件
├── data/                          # 4 项数据交付物（D-B01～D-B04）
│   ├── D-B01_P20_九试次明细与三策略汇总.md
│   ├── D-B02_P3_代码规模统计_cloc.md
│   ├── D-B03_P4_测试资产统计.md
│   ├── D-B04_P18_审计成果量化指标.md
│   ├── README.md                  # 数据总览、跨表一致性提醒、复算入口
│   └── P20_ / P3_ / P4_（旧版，已标注「已被取代」）
└── screens/                       # 11 张主图 + 3 张补充图
    ├── INDEX.md                   # 逐图索引：报告位置、画面要点、来源性质
    ├── report-set/                # 按报告图号命名的交付集（S-B01～S-B11）
    │   ├── README.md              # 逐号对照 + 图注模板 + 复现命令
    │   └── *.png
    ├── real-run/                  # 两轮真实审计的原始截图存档
    └── *.png                      # 同批次原始分辨率大图
```

---

## 6. 复算入口

```bash
# --- 数据类 ---
# D-B01：九试次（读取实验存档）
python -c "import json;e=json.load(open('.run/exp_c4b1374b9aae4707.json'));print(len(e['trials']))"

# D-B02：代码规模
cloc backend frontend/src labs/lab30 poc_runner \
  --exclude-dir=node_modules,.venv,__pycache__,dist,.pytest_cache,data,coverage,htmlcov

# D-B03：测试资产
bash scripts/_run_tests.sh

# D-B04：评分重算（服务需在线）
backend/.venv/bin/python scripts/score_dataset.py --protocol lab30-v2 \
  --api http://127.0.0.1:8899 --run a403cb8c9efd48cfbba31337c5129842 \
  --out /tmp/score_a403cb8c.json

# --- 截图类 ---
python scripts/vm_gap_shots.py preflight                  # 服务/快照/策略/模型就绪检查
python scripts/vm_gap_shots.py b04-shoot <run_id>         # S-B04（审计详情·项目与任务图）
python scripts/vm_gap_shots.py b08-start                  # S-B08 实验（3 策略 × 3 轮 × 720 秒）
python scripts/vm_gap_shots.py b08-shoot <experiment_id>  # S-B08 截图
python scripts/vm_gap_shots.py b10-start                  # S-B10 审计发起
python scripts/vm_gap_shots.py b10-shoot <run_id>         # S-B10 运行中截图
python scripts/vm_gap_shots.py b11 <run_id>               # S-B11 评分导出 + 截图
bash   scripts/vm_start_services.sh                       # 虚拟机服务拉起（8899 / 5173）
```

> 复算依赖 `.run/` 下的原始存档（实验 JSON 2.4 MB、评分 JSON），该目录按 `.gitignore` 不入库，需按上表命令重新生成。
