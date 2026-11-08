# 成员 B 数据类交付物（D-B01 ~ D-B04）

> 生成日期：2026-11-08　|　对应任务书：成员 B 数据类 4 项
> 全部数字来自本轮实测：实验 `c4b1374b9aae4707`、审计 run `a403cb8c9efd48cfbba31337c5129842`、cloc 1.82、pytest/node:test 实跑

## 一、文件对照

| 编号 | 报告位置 | 文件 | 内容 | 数据来源 | 采集日期 |
| --- | --- | --- | --- | --- | --- |
| **D-B01** | 5.4.3 / 10.1（表 P20） | `D-B01_P20_九试次明细与三策略汇总.md` | 九试次逐次明细 + 三策略 mean±SD 汇总 + 显著性口径 + 与旧归档的口径差异 | 实验 `c4b1374b9aae4707` 的 9 个 trial `score` 字段 | 2026-11-08 |
| **D-B02** | 3.x（表 P3） | `D-B02_P3_代码规模统计_cloc.md` | cloc 分目录 / 分语言 / 三种口径 | `cloc` 1.82 实跑 | 2026-11-08 |
| **D-B03** | 3.x / 第 8 章（表 P4） | `D-B03_P4_测试资产统计.md` | 后端 2,268 项、前端 125 项，通过率与失败归因 | pytest + node:test 实跑 | 2026-11-08 |
| **D-B04** | 9.4（表 P18） | `D-B04_P18_审计成果量化指标.md` | TP/FP/FN、P/R/F1、类别覆盖、CVSS 质量、成本、真值溯源 | 评分 JSON `score_a403cb8c....json` | 2026-11-08 |

## 二、四份表的核心数字（供快速核对）

| 表 | 关键值 |
| --- | --- |
| D-B01 | W0 / W1 / W2 的 F1 = **61.77% / 62.23% / 57.70%**；ΔF1 相对基线 **+0.46 pp / −4.07 pp**；9 试次共 514 请求、777 工具、886.6 万已知 tokens、76 分 12 秒 |
| D-B02 | 纯源码 **331 文件 / 75,848 行**；cloc 全语言 353 / 83,769；含前端测试脚本 365 / 85,316 |
| D-B03 | 后端 **2,268 项 / 通过 2,265 / 失败 3（环境缺失）**，99.87%；前端 **125 / 125**，100% |
| D-B04 | **TP 19 / FP 1 / FN 11，P 0.9500 / R 0.6333 / F1 0.7600**；类别 15/22；CVSS MAE 1.14、向量 31.6% |

## 三、三条跨表一致性提醒（写报告时最容易翻车的地方）

**1. D-B01 与 D-B04 的 F1 不能直接比较。**
D-B01 每试次预算 24 请求 / 96 工具 / 720 秒；D-B04 的 run 预算 96 / 288 / 1500 秒，实耗 85 请求。前者 F1 61.77%（W0），后者 76.00%，差异主要来自预算而非策略优劣。并列展示时必须标注"实验预算不同"。

**2. D-B02 不要写"9.5 万行"。**
94,694 是含空行与注释的**物理行**（旧口径）；cloc 有效代码行是 75,848。两者差约 19%，评审复算会对不上。报告统一用 cloc 口径，并在表下注明"去空行、去注释"。

**3. D-B01 的 tokens 是下限。**
9 个试次的 `token_usage_complete` 均为 `false`，只有 `known_*` 字段有值。写"886.6 万 tokens"必须同句补"（已知部分）"。

## 四、四份表各自的"不可省略"标注

| 表 | 必须保留的如实标注 |
| --- | --- |
| D-B01 | W1 提升不显著（0.46 pp < SD 7.96）；W2 低于基线 4.07 pp；与 10-26 归档口径不同不可混比 |
| D-B02 | `labs/lab30` 仅 764 行是"薄路由靶场"的设计使然；JSON 7,339 行是评测夹具不算业务代码 |
| D-B03 | 3 项失败因虚拟机无 Docker / Claude CLI，属环境受限；耗时受负载影响不可作性能指标；未采集行覆盖率 |
| D-B04 | 终态 `inconclusive`；`poc_mode=off` 故验证覆盖率 0%、不能写"已复现"；审计对象是内置 lab30 快照不是第三方仓库；CVSS 向量准确率仅 31.6% |

## 五、复算入口

```bash
# D-B01：实验九试次（宿主机直连虚拟机 8899）
python - <<'PY'
import json
e = json.load(open('.run/exp_c4b1374b9aae4707.json', encoding='utf-8'))
for t in sorted(e['trials'], key=lambda x: (x['prompt_id'], x['round_index'])):
    s = t['attempts'][-1]['score']
    print(t['run_id'][:8], t['prompt_id'], t['round_index'], s['TP'], s['FP'], s['FN'],
          round(s['precision'],4), round(s['recall'],4), round(s['f1'],4))
PY

# D-B02：cloc（虚拟机内执行，cloc 已安装 1.82）
cd "/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main"
cloc backend frontend/src labs/lab30 poc_runner \
  --exclude-dir=node_modules,.venv,__pycache__,dist,.pytest_cache,data,coverage,htmlcov

# D-B03：测试（虚拟机内执行）
bash scripts/_run_tests.sh

# D-B04：评分重算（虚拟机内执行，服务需在线）
backend/.venv/bin/python scripts/score_dataset.py \
  --protocol lab30-v2 --api http://127.0.0.1:8899 \
  --run a403cb8c9efd48cfbba31337c5129842 --out /tmp/score_a403cb8c.json
```

## 六、原始存档位置

| 文件 | 位置 | 说明 |
| --- | --- | --- |
| 实验原始 JSON（2.4 MB） | `.run/exp_c4b1374b9aae4707.json` | 含 9 个 trial 的完整 score / matches / attempts |
| 评分原始 JSON | `.run/score_a403cb8c9efd48cfbba31337c5129842.json` | 含 truth_results / class_coverage / cvss_evaluation |
| pytest 日志 | 虚拟机 `.run/pytest_20261108.log` | `3 failed, 2265 passed in 273.42s` |
| 前端测试日志 | 虚拟机 `.run/npmtest_20261108.log` | TAP，`# pass 125 / # fail 0` |
| cloc 原始 JSON | 虚拟机 `/tmp/c2.json` | 四目录全语言明细 |

## 七、旧版文件的处理

目录内 `P20_九试次明细.md`、`P3_代码规模统计.md`、`P4_测试资产统计.md` 为 **2026-11-07 版**，已在文件头标注"已被取代"。保留原因：D-B01 的旧表记录了 10-26 归档实验（`legacy_unit_v1` 策略、场景子集），报告若需做"新旧口径对照"仍可引用，但**主表必须用 D-B01~D-B04 这四份**。
