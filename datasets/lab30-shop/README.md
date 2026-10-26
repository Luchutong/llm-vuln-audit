# 拾光商城 Lab30 Shop 漏洞数据集

本目录将靶场的 30 项官方答案与源码位置、入口和数据流关联，用于比较审计结果。评级采用 **CVSS v3.1 Base Score**；检出率与评级准确率分别统计。

正式多版本完整审计使用 [lab30-v2 评分锚点与核验说明](SCORING_V2.md)。
`--protocol lab30-v2` 同时核对根因和主定位，并使用稳定最大一对一匹配；默认 CLI 保留下述旧协议，不重算历史成绩。

## 数据来源与版本

- `ground_truth.json` 的 `provenance` 固定上游 [feat/lab30-shop / 30364ec 的 answers.json](https://github.com/Luchutong/llm-vuln-audit/blob/30364ecd8f1c7c8c10e3f2e66107dfc38ecd1434/answers/answers.json)、答案文件 SHA-256 及源码 ZIP SHA-256。
- 绑定源码包的 SHA-256 为 `67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c`，本次评分更新没有修改源码包。
- 官方主评分为 `cvss.base_score`，基础向量为 `cvss.base_vector`，完整 22 项向量为 `cvss.vector`。数据集保留全部 22 项原始指标及评分假设；详细的权重、分项及逐项依据见固定版本的官方答案。
- `temporal_assessed=false`、`environmental_assessed=false` 表示时序及环境指标未独立评估。其按 X 默认值派生的分数不参与基础分比较，也不代表验证成功。
- 根目录旧交付副本中的文字等级属于历史版本；评价默认读取本目录固定的 CVSS 3.1 数据，不能回退到该副本的旧等级。

## 每项字段

| 字段 | 含义 |
| --- | --- |
| `id` | 官方编号 01–30 |
| `title`、`type`、`class` | 可读标题、官方漏洞类型与粗粒度机器类别 |
| `scenario` | `sqli` / `xss_r` / `command_injection`；其余为 `null` |
| `cvss` | CVSS 3.1 基础分、基础及完整向量、22 项指标，以及未独立评估的派生分数 |
| `assessment`、`description`、`impact` | 上游静态源码评估的假设、边界、漏洞描述与影响 |
| `severity`、`severity_cn` | 从基础分派生的兼容文字标签，不是旧版主观评级 |
| `location` | sink 位置：`path` + 从 1 开始的 `line` |
| `entry_point` | 路由、方法、参数、源码入口与登录要求 |
| `exploitation_path` | `input → propagation → sink` 数据流补充 |
| `evidence` | `path:start-end` 引用数组 |
| `preconditions` | 官方评分的触发前提，不能将其他漏洞或公开教学口令串入基础评分 |
| `attack_input`、`normal_input`、`expected_result`、`remediation` | 既有测试线索、预期差异及修复建议，不表示已执行 POC |

CVSS 定性等级按 [FIRST CVSS v3.1 规范](https://www.first.org/cvss/v3.1/specification-document#Qualitative-Severity-Rating-Scale) 派生：

| 基础分 | 英文标签 | 中文标签 |
| --- | --- | --- |
| 0.0 | `none` | 无 |
| 0.1–3.9 | `low` | 低 |
| 4.0–6.9 | `medium` | 中 |
| 7.0–8.9 | `high` | 高 |
| 9.0–10.0 | `critical` | 极高 |

当前分布：`high` 9、`medium` 17、`low` 3、`none` 1。编号 08 的开放重定向基础分为 0.0，仍是应检出的真值，继续参与 TP/FN 与召回率计算；不能因其没有可支持的 CVSS 基础影响而删除该条目。

## 分场景子集

| scenario | 编号 | 说明 |
| --- | --- | --- |
| `sqli` | 01, 23, 28 | 直连、跨文件、二次 SQL 注入 |
| `xss_r` | 02, 25 | 反射型 XSS、HTML 属性注入型 XSS |
| `command_injection` | 03, 24 | 直连、跨文件命令注入 |

其余 23 项用于全量评分。存储型 XSS、反序列化对象链等不因文字中出现 XSS 或命令执行而自动加入上述场景。

## 使用评价脚本

无需启动靶场或模型；脚本使用 Python 标准库及相邻的 `scripts/cvss31.py`。

```bash
# 评价真实 JSON 导出，同时核对文字评级和可用的 CVSS 分数/向量
python3 scripts/score_dataset.py --findings run.json \
  --check-severity --check-cvss --out /tmp/lab30-score.json

# 读取运行 API，只评价 SQL 注入场景
python3 scripts/score_dataset.py --api http://127.0.0.1:8899 --run <run_id> \
  --scenario sqli --check-severity --check-cvss --out /tmp/lab30-sqli.json

# 也接受新版官方 answers.json 数组，不要求其含旧 severity 字段
python3 scripts/score_dataset.py --truth /path/to/answers.json --findings run.json \
  --check-severity --check-cvss --out /tmp/official-score.json

# 核对源码行、归档哈希、CVSS 分数与向量的一致性
python3 scripts/verify_lab30_dataset.py /path/to/source.zip datasets/lab30-shop/ground_truth.json
```

`--findings` 接受发现数组、含 `findings` 的运行导出或含 `results` 的发现导出。兼容 worker 的 `kind`、运行 API 的 `finding_kind`、历史固定类别，以及文本或结构化源码证据。排查记录和撤回、重复、被替代的结论不进入当前漏洞评价。

### 检出评价

按完整路径组件忽略 ZIP 顶层前缀，再按证据行窗口与真值行的交集进行一对一匹配。一条发现最多命中一条真值，重复报出计作 FP。场景过滤仅缩小真值范围，范围外的发现仍计为 FP。

输出保留 `TP/FP/FN`、`precision/recall/f1`、`matches/missed/false_positives`；无命中时 F1 为 0.0。无预测时 precision 为 `null`，评级或数值不一致不会改变源码检出的 TP/FP/FN。

### 评级与 CVSS 评价

- `--check-severity`：将审计结果的文字等级与 **CVSS 基础分派生的等级**比较，输出 `severity_evaluation`。旧自定义真值没有 CVSS 时仍可比较其文字等级，但明确标为 `legacy severity`。
- `--check-cvss`：读取发现中的 `cvss` 对象，比较 `base_score`，也可从合法的 `base_vector` 或完整 `vector` 计算基础分。输出数值完全一致率、平均绝对误差 MAE、基础向量一致率及 AV/AC/PR/UI/S/C/I/A 逐项一致率。
- 完整向量中的时序和环境指标会校验取值，但不替代 Base Score。不混入 CVSS 3.0 或 4.0；向量顺序不影响比较，分数与向量互相冲突时标为无效。
- 当前审计结果通常只提供 `severity`，不能据此猜出一个 CVSS 数字。未提供数值/向量的命中标为 `missing_reported`，非法版本或数据标为 `invalid_reported`；均不作为 0 分，也不进入 MAE 分母。
- 一致率和 MAE 的分母仅为可比较的命中；报告同时提供 `compared`、`missing_truth`、`missing_reported`、`invalid_reported`，应一起阅读，不能把少量完整评分的一致率当作全部发现的覆盖率。
- 同一数值可能来自不同基础指标。报告分别列出分数与向量是否一致，不能以分数一致代替向量一致。

发现中的数值评分示例（可省略 `base_score`，由向量计算）：

```json
{
  "cvss": {
    "version": "3.1",
    "base_score": 7.5,
    "base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
  }
}
```

基础分计算遵循 FIRST 的向上保留一位小数（Roundup），包含 Appendix A 的浮点误差处理。本实现已与 `cvss==3.6` 独立对照全部 2,592 种基础指标组合。

运行时组件已使用相同CVSS计算器；其待评分状态按缺失处理。`cvss_evaluation.scoring_coverage` 为可比较基础分的命中数/全部命中数，与MAE分母同时报告，详情见 [运行时CVSS组件](../../docs/cvss31.md)。
