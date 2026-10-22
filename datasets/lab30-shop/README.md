# 拾光商城 Lab30 Shop 漏洞数据集

本目录是从靶场 `llm-vuln-audit-feat-lab30-shop`（拾光商城 Lab30 Shop 1.0.0）提取的**漏洞真值数据集**，用于对审计 agent 的产出做评分，进而比较不同 prompt / 分场景约束的好坏。

## 文件

- `ground_truth.json` —— 30 项漏洞真值（与靶场官方 `answers/answers.json` 的 30 项一一对应，并逐行核对了 `app/public/**/*.php` 与 `app/src/*.php` 源码补齐了数据流与入口信息）。

## 每项字段说明

| 字段 | 含义 | 对应 agent 产出 |
| --- | --- | --- |
| `id` | 编号（01–30，对齐 answers.json） | — |
| `title` | 漏洞标题 | `TaskFinding.title` |
| `type` | **漏洞类型**（中文） | `TaskFinding.summary` 的语义 |
| `class` | **漏洞类别**（机器可读粗粒度，如 `sqli`/`xss_r`/`ssrf`/`idor`…） | 用于分组/统计 |
| `scenario` | 映射到 agent 分场景 taxonomy（`sqli`/`xss_r`/`command_injection`），其余为 `null` | `TaskSpec.scenario` |
| `cwe` | CWE 编号 | — |
| `severity` | **漏洞等级**（英文，与 agent `Severity` 的 `low/medium/high/critical` 对齐） | `TaskFinding.severity` |
| `severity_cn` | **漏洞等级**（中文：极高/高/中/低） | — |
| `location` | **漏洞源码位置**：sink 所在 `path` + 1 基 `line` | `TaskFinding.evidence` 的 `path:line` |
| `entry_point` | **漏洞路口**：外部输入进入应用的入口（路由/方法/参数/文件/行号/是否需登录） | `TaskFinding.input_source` |
| `exploitation_path` | **利用路径**：`input → propagation → sink` 完整数据流 | `TaskFinding.propagation` / `dangerous_operation` |
| `evidence` | 供评分脚本直接匹配的 `path:start-end` 数组（对齐 `TaskFinding.evidence` 格式） | `TaskFinding.evidence` |
| `preconditions` | 触发前提（角色、会话、配置、并发、跨文件二次触发等） | `TaskFinding.preconditions` |
| `attack_input` | 触发 payload 示例 | `PocSpec.attack_input` |
| `normal_input` | 对照组正常输入 | `PocSpec.normal_input` |
| `expected_result` | 攻击与对照的可观测差异 | `PocSpec.expected_result` |
| `remediation` | 修复建议 | `TaskFinding.remediation` |

## 等级映射

靶场中文等级 → 数据集英文等级（对齐 agent `Severity`）：

| 中文 | 英文 |
| --- | --- |
| 极高 | `critical` |
| 高 | `high` |
| 中 | `medium` |
| 低 | `low` |

分布：`critical` 6、`high` 16、`medium` 8。

## 分场景（scenario）子集

审计 agent 的分场景 taxonomy 只有三类，数据集用 `scenario` 字段标出可落入这三类的真值：

| scenario | 编号 | 说明 |
| --- | --- | --- |
| `sqli` | 01, 23, 28 | 直连 SQL 注入、跨文件 SQL 注入、二次 SQL 注入 |
| `xss_r` | 02, 25 | 反射型 XSS、HTML 属性注入型反射 XSS |
| `command_injection` | 03, 24 | 直连命令注入、跨文件命令注入 |

其余 23 项（路径遍历、LFI/RFI、SSRF、XXE、CSRF、IDOR、反序列化、认证绕过、竞争条件、会话固定、批量赋值等）属于更广的漏洞类型，`scenario` 为 `null`，用于**全量评分**（不局限于三类 taxonomy）。

## 评分脚本如何用这份数据集

评分时把 agent 的每条 `TaskFinding`（`backend/audit/schemas.py`）与真值做匹配，建议规则：

1. **按场景过滤真值**：跑 `sqli` 场景时只取 `scenario == "sqli"` 的真值作为“应找到的漏洞全集”。
2. **文件匹配**：`finding.evidence`（`path:start-end`）中的 `path` 与真值 `location[].path` 相同，且行区间与真值 `location[].line` 有交集，视为命中同一处源码位置。
3. **类别/等级校验**：可进一步要求 `finding.severity` 与真值 `severity` 一致，`title`/`summary` 语义与真值 `type` 一致，以区分“位置对但类型错”的情况。
4. **计算指标**：对每个场景（或全量）计算
   - TP：真值被 agent 命中
   - FP：agent 报出但无对应真值（或位置/类型不匹配）
   - FN：真值未被 agent 报出
   - `precision = TP/(TP+FP)`、`recall = TP/(TP+FN)`、`F1 = 2PR/(P+R)`

> 匹配粒度建议以**源码位置（文件 + 行）**为主键，因为同一文件/同一行只对应一个真值漏洞，可稳定计算 precision/recall；`class`/`severity` 作为二次校验。

## 生成依据

- 真值清单：`llm-vuln-audit-feat-lab30-shop/llm-vuln-audit-feat-lab30-shop/answers/answers.json`（30 项，含 `locations[{path,line}]`、`type`、`severity`）。
- 源码核对：`app/public/{catalog,ops,auth,account,orders,partner,support,wallet,content}/**/*.php` 与 `app/src/*.php`，逐一确认入口参数、传播链与 sink 行号。
