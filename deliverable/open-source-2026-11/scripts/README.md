# 采集与复算脚本（归档副本）

> 本目录是成员 B 交付过程中**实际执行**的脚本归档，用于复核截图与数据表的生成链路。
> 其中 `render_architecture.py`、`render_report_prompts.py`、`score_dataset.py` 与仓库 `scripts/` 下同名文件一致；其余 17 个为本次采集新增。

## 1. 运行依赖

| 依赖 | 版本 / 说明 |
| --- | --- |
| Python | 3.11（`backend/.venv`） |
| paramiko | SSH 驱动虚拟机（`vm_ssh.py`） |
| Playwright + 本机 Chrome | 截图（不下载 Playwright 自带浏览器） |
| cloc | 1.82（D-B02） |
| 虚拟机 | Ubuntu 20.04，后端 `:8899`、前端 `:5173`，仓库路径 `/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main` |

## 2. 清单

| 脚本 | 类别 | 作用 |
| --- | --- | --- |
| `vm_ssh.py` | 环境编排 | paramiko SSH 封装：probe / run / push / pull，其余脚本的基础传输层 |
| `vm_bootstrap.sh` | 环境编排 | VM 内依赖引导（uv / python / backend / node / envfile / start / status 分阶段） |
| `vm_start_services.sh` | 环境编排 | 以脱离 SSH 会话的方式拉起后端 :8899 与前端 :5173 |
| `vm_set_model.sh` | 环境编排 | 把模型凭据写入 VM 的 .env 并重启后端，校验 /api/config configured=true |
| `vm_probe_model.sh` | 环境编排 | VM 内最小模型调用（ping），验证 Key / Base URL / 额度，不打印密钥 |
| `vm_tests.sh` | 环境编排 | VM 内采集 D-B03 证据（后端 pytest + 前端 node:test） |
| `vm_real_run.py` | 环境编排 | 发起真实审计 run 并轮询/截图，明确不使用离线夹具 |
| `vm_shot.py` | 截图采集 | 单页截图早期版本（Playwright 驱动本机 Chrome，强制浅色、2× DPR） |
| `vm_shot_pages.py` | 截图采集 | 多页面批量截图（MockAPI 夹具方案，仅作方法对照，产物已作废） |
| `vm_gap_shots.py` | 截图采集 | 本轮截图编排器：preflight / b04 / b08-start|watch|shoot / b10-start|shoot / b11 |
| `_cloc_report.py` | 数据统计 | cloc 汇总口径（分语言 + 指定排除目录），产出 D-B02 主表 |
| `_cloc_each.py` | 数据统计 | 分目录单独 cloc 统计（backend / frontend/src / labs/lab30 / poc_runner / frontend） |
| `_parse_cloc.py` | 数据统计 | 解析 cloc JSON 输出为可粘贴的 Markdown 表 |
| `_run_tests.sh` | 数据统计 | 本地后端 / 前端测试资产采集，产出 D-B03 计数 |
| `gen_p20_trial_table.py` | 数据统计 | 读取实验存档生成 D-B01 九试次明细 + 三策略汇总 + 类别覆盖附录 |
| `gen_p3_loc.py` | 数据统计 | 按目录统计物理行数，产出 P3 工程规模表 |
| `score_dataset.py` | 数据统计 | 按源码位置匹配真值集评分，输出 TP/FP/FN、P/R/F1、类别覆盖、CVSS 质量（D-B04 / S-B11） |
| `render_architecture.py` | 图表渲染 | 由代码生成总体架构图（docs/architecture.svg），对应 S-B01 |
| `render_deployment_view.py` | 图表渲染 | 生成部署视图，对应 S-B01b |
| `render_report_prompts.py` | 图表渲染 | 渲染报告中的 Prompt 全文，校验与 backend/audit/prompts.py 一致 |

## 3. 归档差异（脱敏）

公开归档只做了两处与运行版本不同的处理，脚本逻辑未改动：

| 文件 | 原值 | 归档值 |
| --- | --- | --- |
| `vm_ssh.py` | `VM_PASS (<已移除>)` | `VM_PASS（环境变量注入）` |
| `vm_ssh.py` | `PASS = os.environ.get("VM_PASS", "<已移除>")` | `PASS = os.environ.get("VM_PASS", "")  # 归档副本已脱敏` |
| `vm_set_model.sh` | `REPO_LOCAL="<本机绝对路径>` | `REPO_LOCAL="${REPO_LOCAL:-$(pwd)}"` |
| `vm_gap_shots.py` | `VM_PASS = os.environ.get("VM_PASS", "<已移除>")` | `VM_PASS = os.environ.get("VM_PASS", "")  # 归档副本已` |

环境变量注入方式：

```bash
export VM_HOST=192.168.239.128 VM_USER=zsh VM_PASS='<你的实验机口令>'
```

## 4. 典型调用顺序

```bash
# 环境就绪
bash scripts/vm_bootstrap.sh all
bash scripts/vm_set_model.sh deepseek-chat https://api.deepseek.com/v1 "$LLM_API_KEY"
bash scripts/vm_probe_model.sh
bash scripts/vm_start_services.sh

# 截图（真实运行）
python scripts/vm_gap_shots.py preflight
python scripts/vm_gap_shots.py b08-start && python scripts/vm_gap_shots.py b08-watch
python scripts/vm_gap_shots.py b08-shoot c4b1374b9aae4707
python scripts/vm_gap_shots.py b10-start && python scripts/vm_gap_shots.py b10-shoot <run_id>
python scripts/vm_gap_shots.py b11 <run_id>

# 数据
python scripts/gen_p20_trial_table.py            # D-B01
python scripts/_cloc_report.py                   # D-B02
bash   scripts/_run_tests.sh                     # D-B03
backend/.venv/bin/python scripts/score_dataset.py --protocol lab30-v2 --run <run_id>  # D-B04
```

> 说明：`vm_shot_pages.py` 是早期的 MockAPI 夹具方案，其 13 张产物已作废（见总览 README §3），保留脚本仅为方法对照，**不在任何交付图中使用**。
