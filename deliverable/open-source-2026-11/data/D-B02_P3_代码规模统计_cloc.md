# D-B02（P3）代码规模统计（cloc 口径）

> 对应报告：第 3 章项目概况 / 3.x 工程规模
> **采集工具：`cloc` 1.82**（Ubuntu 20.04 apt 包），非自写脚本，命令与原始 JSON 见文末
> 采集日期：2026-11-08　|　采集环境：虚拟机 `192.168.239.128`，仓库 `/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main`
> 统计口径：**代码行 = 去空行、去注释后的有效行**（cloc `code` 字段）；文件数 = cloc `nFiles`
> 排除目录：`node_modules`、`.venv`、`__pycache__`、`dist`、`.pytest_cache`、`data`、`coverage`、`htmlcov`

## 1. 口径先声明（避免与旧表混淆）

本表与 `P3_代码规模统计.md`（2026-11-07 版）**口径不同，数值不可互换**：

| 口径 | 含义 | 四目录合计 |
| --- | --- | ---: |
| 物理行（旧表） | 含空行、含注释，`wc -l` 口径 | 94,694 行 / 334 文件 |
| **cloc 代码行（本表）** | 去空行、去注释，仅有效代码 | **75,848 行** / 331 文件（纯源码） |
| cloc 全语言（本表） | 上述 + JSON/YAML/Markdown 等 | 83,769 行 / 353 文件 |

报告正文统一使用 **cloc 代码行**；若需引用物理行，须在脚注写明"含空行与注释"。

## 2. 分目录统计（cloc 全语言）

| 目录 | 文件数 | 空行 | 注释行 | **代码行** | 主要构成 |
| --- | ---: | ---: | ---: | ---: | --- |
| `backend/`（排除 `backend/data`） | 223 | 9,817 | 7,996 | **70,819** | Python 210 个（63,218 行）、JSON 夹具 4 个（7,339 行）、YAML/Markdown/TOML 9 个（262 行） |
| `frontend/src/` | 60 | 406 | 373 | **10,757** | TypeScript/TSX 52 个（9,353 行）、CSS 8 个（1,404 行） |
| `labs/lab30/` | 64 | 41 | 21 | **764** | PHP 53 个（414 行）、Python 2 个（106 行）、YAML 1 个（72 行）、SVG 1 个（58 行）、Markdown 1 个（48 行）、JS 1 个（23 行）、Shell 2 个（25 行）、INI 2 个（14 行）、CSS 1 个（4 行） |
| `poc_runner/` | 6 | 237 | 153 | **1,429** | Python 4 个（1,326 行）、Markdown 1 个（74 行）、Dockerfile 1 个（29 行） |
| **合计** | **353** | **10,501** | **8,543** | **83,769** | — |

## 3. 分语言统计（四目录合计）

| 语言 | 文件数 | 空行 | 注释行 | 代码行 | 占比（按代码行） |
| --- | ---: | ---: | ---: | ---: | ---: |
| Python | 216 | 9,971 | 8,075 | 64,650 | 77.2% |
| TypeScript/TSX | 52 | 393 | 365 | 9,353 | 11.2% |
| JSON（测试夹具与知识库清单） | 4 | 0 | 0 | 7,339 | 8.8% |
| CSS | 9 | 13 | 8 | 1,408 | 1.7% |
| PHP | 53 | 5 | 16 | 414 | 0.5% |
| YAML | 4 | 39 | 62 | 235 | 0.3% |
| Markdown | 7 | 68 | 0 | 192 | 0.2% |
| SVG | 1 | 0 | 0 | 58 | 0.07% |
| TOML | 1 | 4 | 4 | 29 | 0.03% |
| Dockerfile | 1 | 8 | 10 | 29 | 0.03% |
| JavaScript | 1 | 0 | 0 | 23 | 0.03% |
| Shell（bash + sh） | 2 | 0 | 0 | 25 | 0.03% |
| INI | 2 | 0 | 3 | 14 | 0.02% |
| **合计** | **353** | **10,501** | **8,543** | **83,769** | 100% |

## 4. 三种规模口径（按需引用）

| 口径 | 文件数 | 代码行 | 说明 |
| --- | ---: | ---: | --- |
| **纯源码**（Python + TS + CSS + PHP + JS） | **331** | **75,848** | 报告正文推荐值，不含任何配置与数据 |
| cloc 全语言（上述 + JSON/YAML/MD/TOML/Docker/SVG/Shell/INI） | 353 | 83,769 | 含 4 个测试夹具 JSON（7,339 行） |
| 再加前端测试脚本（`frontend/tests/*.mjs`） | 365 | 85,316 | cloc 1.82 不识别 `.mjs`，该 12 个文件 1,547 行由 `wc -l` 补计 |

### 4.1 `frontend/` 整目录（对齐任务书的路径写法）

若按任务书写"`frontend/`"，排除 `node_modules/`、`dist/` 后为 **65 个文件 / 13,347 行**：

| 组成 | 文件数 | 代码行 |
| --- | ---: | ---: |
| `frontend/src/` | 60 | 10,757 |
| `frontend/vite.config.ts` | 1 | 约 12 |
| `frontend/index.html` | 1 | 5 |
| `frontend/*.json`（package/tsconfig 等） | 3 | 2,573 |
| **小计** | **65** | **13,347** |

与 `frontend/src` 相差 2,590 行，全部来自配置与 JSON，**不含业务代码**。报告若写"前端 1.1 万行"指 `src`；若写"1.3 万行"须说明含配置文件。

## 5. 两处必须解释的"异常值"

**其一：`labs/lab30/` 只有 764 行代码。** 该目录是刻意精简的漏洞靶场——53 个 PHP 文件平均 7.8 行，绝大多数是"路由桩 + 单行调用"，把逻辑收敛到 `src/` 辅助函数里。靶场的设计目标是**漏洞密度**而非代码体量，30 项真值分布在 69 个源文件中，平均每个文件 0.43 个漏洞。评审若质疑"靶场太小"，正确的回应是给漏洞密度与真值覆盖率，而不是代码行数。

**其二：JSON 占 7,339 行。** 4 个文件分别是 `backend/tests/fixtures/cvss31_reference_2592.json`（CVSS 3.1 评分参照表）、`recent_capability_runs.json`、`lfi-replay-lab30.json`、`audit/reuse/autocve/knowledge/manifest.json`。它们是**评测夹具与知识库索引**，不是业务逻辑，故单列而不并入"纯源码"。

## 6. 复核方式

```bash
# 安装（虚拟机已装，版本 1.82）
sudo apt-get install -y cloc

# 四目录主口径（本表第 2、3 节）
cd "/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main"
cloc backend frontend/src labs/lab30 poc_runner \
  --exclude-dir=node_modules,.venv,__pycache__,dist,.pytest_cache,data,coverage,htmlcov

# frontend 整目录（本表 4.1 节）
cloc frontend --exclude-dir=node_modules,dist,.vite,coverage

# 前端测试脚本（cloc 不识别 .mjs，单独计数）
ls frontend/tests/*.mjs | wc -l && cat frontend/tests/*.mjs | wc -l
```

原始 JSON 保存在虚拟机 `/tmp/c2.json`（本次运行产物）；如需长期留档，执行：

```bash
cloc backend frontend/src labs/lab30 poc_runner \
  --exclude-dir=node_modules,.venv,__pycache__,dist,.pytest_cache,data \
  --json --quiet > deliverable/open-source-2026-11/data/cloc-20261108.json
```

## 7. 引用建议

- 报告 3.x 写："工程规模 **7.6 万行有效代码**（cloc 口径，331 个源文件），其中后端 Python 6.5 万行、前端 TypeScript/CSS 1.1 万行、靶场 PHP 414 行"；
- 不要写"9.5 万行"——那是含空行与注释的物理行，与 cloc 差 19%，评审复算会对不上；
- 表格入报告时保留"采集工具 + 采集日期 + 排除目录"三要素，满足证据可追溯要求。
