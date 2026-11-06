# Lab30 冻结成绩 22/30：漏检诊断与后续优化方案

分析日期：2026-11-05。基线：`2969bcf204cd43b5baf2683cbb0e841d`。

**优先修复发现阶段的结算粒度与未决线索准入。8 个漏检点的关键源码行全部已经进入 worker 的读取凭据；主要损失发生在读取之后。** 其中 5 项停留在可选后续方向，2 项被记录为观察，1 项与另一处独立危险操作合报。单纯增大预算、换模型或提高文件覆盖率，没有直接解决这些断点。

本次新增的是只读诊断脚本、证据摘要和实施方案，没有修改审计行为或取得新的模型成绩。冻结源码、真值、评分锚点、23 条交付发现和历史报告均保持原样。

## 基线与证据可信度

重放 `scripts/reproduce_release.py`，7 个归档资产哈希全部通过，结果仍为 TP=22、FN=8、FP=1、D=0、U=1、precision=0.9565、recall=0.7333、F1=0.8302。

| 维度 | 冻结事实 | 对优化的含义 |
| --- | --- | --- |
| 全局消耗 | 254/2048 请求，270/16384 工具，2832/10800 秒 | 未触及全局上限 |
| discovery | 105 请求后结束 | 继续探索仍有预算，但必须改变调度准入 |
| 文件覆盖 | reviewed 61/61、read 59、pending 0 | 文件覆盖不能证明漏洞方向已结算 |
| worker | 19 项任务、20 次尝试 | 少量宽任务承担多个独立漏洞方向 |
| 方向账本 | 8 个 required 已 resolved；28 个 advisory 仍 pending | 完成门禁没有包含这些可选线索 |
| 上下文 | 峰值 150895/393216 字节，超限 0 | 本轮召回损失没有上下文超限证据 |
| 动态验证 | 47 作业、24 confirmed、1 uncertain | 验证数量和检出数量是不同口径 |

诊断直接读取 `frozen_run_reports.input_json` 内的 `tasks.attempt_history.seen`、任务结果与方向，不依赖可能继续变动的项目台账。冻结输入哈希为 `1c48ce503c8af9140bbce4025b742bbbf27145e02ea80606fa636813f97ff940`，脚本核对正文哈希后才分析。

历史记录 [lab30-closure-run.md](lab30-closure-run.md) 使用的“未读/未报”需要进一步细分：这 8 项均有关键行的读取凭据。读取凭据只说明源码行曾呈现给 worker，不证明对应风险已经完整分析。

## 8 个缺口逐项解释

下表路径省略归档根 `lab30-shop/`。完整读取任务、方向 ID、原始观察和评分诊断见 [机器可读证据](validation/lab30-gap-analysis-2026-11-05.json)。

| 真值 | 根因与定位 | 冻结轨迹中的实际断点 | 应采取的动作 |
| --- | --- | --- | --- |
| 07 | 动态函数调用；`app/public/ops/formula.php:3` | `ops-and-cli` 已读该行，明确提出 `$func` 可调用危险函数；方向 `dir_39311cbb1618e232d39dd66309d8e862` 仍是 pending/advisory | 为动态调用分配独立取证任务，核实函数名和实参控制、角色门禁及禁用函数配置 |
| 09 | 异常/堆栈泄露；`app/public/ops/database.php:3–4` | 已读；观察“database.php 输出异常堆栈”明确写出经 `h()` 编码仍暴露堆栈、路径与连接信息，却没有发现或后续方向 | 复核观察的风险性质；用正常数据源与异常分支作对照，核实实际泄露内容及访问前提 |
| 10 | MD5 口令存储；`app/public/auth/register.php:8`、`app/src/setup.php:17` | 两个锚点都已读；观察提及“以 MD5 存密码”，局部任务却围绕会话、批量赋值和 CLI 可达性结算 | 单独追踪口令输入→散列→数据库存储→登录比较，不因 SQL 参数化或 CLI 守卫排除口令风险 |
| 14 | 邮箱修改 CSRF；`app/public/account/settings.php:5` | 该行被 4 个任务读过；`account-object-authz` 称其“属已存结论范围”，实际没有对应发现；方向 `dir_23beb9e3381c7f561db548226f530653` 仍 pending/advisory | 核对真实发现 ID，独立检查请求来源防护、会话 Cookie 和浏览器成立条件 |
| 17 | 角色 Cookie 授权绕过；`app/public/ops/users.php:2` | `account-mass-assign` 已读并提出伪造 Cookie 方向；`dir_0426c7b739326a1be2d5e8edab55dc65` 未派发 | 普通用户、不覆盖角色与覆盖角色作对照；按认证前真实身份判定授权边界 |
| 18 | 请求头认证绕过；`app/public/ops/maintenance.php:3` | `ops-and-cli` 已读并说明未登录也仅凭 `X-Admin` 授权；`dir_5118407668344f3ba4ee1cd2f83e6972` 未派发 | 独立验证匿名请求的正常拒绝与伪造头后的敏感操作/状态读取 |
| 23 | 跨文件 SQLi；`app/src/member_lookup.php:3` | `sql-data-layer` 已读并明确指出拼接；`dir_f48161cc01979dea85ed891ae171f997` 未派发；operator/admin 门禁被留作待评估前提 | 追踪 `ops/members.php`→`member_lookup()`→`query()`；权限要求写入前提，不因存在登录门禁就排除注入 |
| 24 | 跨文件命令注入；`app/src/host_check.php:2` | 已读且进入交付发现的 evidence，但与 `ops/ping.php:2` 合成一条，primary_location 只指向后者；另一个 worker 将其当作同根因观察 | 分开审计两个独立 `shell_exec` 调用点；为 helper sink 发布独立结论，不能只移动原结论锚点 |

24 不是缺少行号证据：冻结发现 `7d557370dabe4a41ba0c681deb30a0a1` 的摘要及 evidence 同时覆盖 `ping.php`、`batch-check.php`、`host_check.php`。但前者自己调用 `shell_exec`，后者经另一个函数中的独立调用执行，修复其中一处不能修复另一处。v2 一条 finding 只能匹配一个真值；把 primary_location 改到 helper 会失去 03，必须先由源码确认独立根因，再拆分并各自复核。

14 还存在需要诚实验证的环境前提：`bootstrap.php:16` 设置 `SameSite=Lax`。不能把带会话的脚本请求或手工伪造 Origin 当成浏览器跨站请求成功的证据。应明确攻击页和目标的 origin/site、Cookie 实际携带情况及数据变更；如果需要攻击者控制同站不同源内容等额外条件，应写入前提。源码风险、基准命中与动态 confirmed 分开记录。

## 建议实施顺序

### P0：让全量审计结算已有的具体风险线索

相关实现：[directions.py](../backend/audit/directions.py)、[review_store.py](../backend/audit/review_store.py)、[worker.py](../backend/audit/worker.py)。

当前 `DirectionStoreMixin._capture_worker_directions_tx()` 在宿主队列模式下先将 worker 返回的后续方向登记为 advisory；`audit_direction_summary()` 的必做未决计数只包含 required。Planner 未选择的方向可以随运行完成一起留下。本轮五个漏报方向正好落在这里。

建议增加**显式、版本化的全量探索策略**：discovery 收束前必须对冻结目标相关、指向真实源码的具体 advisory 线索完成一次独立分流。分流允许：派发独立任务；关联实际已存在的发现及其版本；以源码依据排除；声明目标无关；保留缺失前提。尚未作出判断的目标相关线索阻止完整收束。

不要将全部 advisory 无条件升格为必做。28 条中也有重复或已覆盖的线索；保留稳定 ID、去重关联、分页完整计数、全局预算及无进展上限。方向文本写着“已有结论”不能代替真实 finding ID 与根因一致性检查。本轮 14 尤其需要这个约束。

预期直接作用于 07/14/17/18/23；这是待验证的收益范围，不能据此宣称已经获得 27 TP。

### P0：在结束前复核观察与局部排除结论

相关实现：[agent.py](../backend/audit/agent.py)、[review_store.py](../backend/audit/review_store.py)、[worker_strategies.py](../backend/audit/worker_strategies.py)。

为显式全量任务增加有界复核：检查已保存观察中是否存在尚未结算的目标风险，以及某种防护是否只排除了局部问题。SQL 参数化不证明口令散列安全，HTML 编码不证明信息保密，身份验证不证明角色授权正确。复核只能提出候选或新方向，不能由关键词直接把观察改成漏洞。

先复核原始源码再发布新 finding，继续沿用证据、CVSS、验证和终审合同。优先覆盖本轮已在观察中明确表达的 09、10。当前 W1/W2 v2 已包含口令、诊断信息与根因定位建议，但冻结运行的 `worker_strategy={}`；不能把已有策略文本误认为当时已经绑定。正式接入生产入口需要另行冻结策略身份，公开 `CreateRunRequest` 目前不接受随意增加 `worker_strategy` 字段。

### P0：按独立危险操作组织发现与去重

相关实现：[worker_strategies.py](../backend/audit/worker_strategies.py)、[project_findings.py](../backend/audit/project_findings.py)、[final_review.py](../backend/audit/final_review.py)。

现有 `validate_primary_location()` 能确认主定位读过且被 evidence 覆盖，但不会发现“一条结论包含两个独立 sink”。应在候选整合时核对根因位置、输入传播、防护和修复边界。不同文件中的独立危险调用不要因类型相同、命令文字相同或攻击效果相同就合报；同一个缺陷的不同入口或同一公共 sink 的多个调用者也不要机械拆报。

本轮 24 先做小范围回放：检查结论是否分别对应 `ping.php:2` 和 `host_check.php:2`，并确认原 03 仍然存在。

### P1：扩充风险信号，但先验证覆盖缺口

相关实现：[risk_coverage.py](../backend/audit/risk_coverage.py)、[schemas.py](../backend/audit/schemas.py)、[app.py](../backend/audit/app.py)。

当前 `risk_coverage_policy` 默认 off，`focus_scope` 默认 targeted；第七轮没有这两个冻结字段。新任务可以显式设置 `focus_scope=all` 与 `risk_coverage_policy=bounded-v1`，但这还不足以解决全部漏报。

将当前 `freeze()` 作用于原冻结项目图并假设全量范围，得到 52 个义务、omitted=0：

| 漏检项 | 当前义务在锚点的匹配 | 限制 |
| --- | --- | --- |
| 07 | 无 | 索引已有 `$func` 调用，SINKS 没有动态调用规则 |
| 09 | query / sqli | 这不是异常信息泄露义务，不能算已覆盖该风险 |
| 10 | 无 | 没有口令散列语义 |
| 14 | 无 | 没有敏感写入与请求来源防护维度 |
| 17、18 | 无 | 没有 Cookie/Header→授权决策语义 |
| 23 | query / sqli | 有对应敏感操作信号，仍需输入传播证据 |
| 24 | shell_exec / command_injection | 有对应操作信号，仍需独立结论与正确定位 |

因此，当前义务对缺失风险直接相关的锚点覆盖只有 23、24 两项。后续增加动态调用、口令散列、诊断输出、客户端身份断言及敏感状态变更的**候选信号**；不能仅补一个函数名列表就宣称覆盖授权/CSRF，也不能把 md5 的每次使用判成口令缺陷。

继续冻结有界集合、实际读取操作和防护上下文、独立判断相关性与 supported/no_evidence/not_applicable。新增策略只用于新任务，不回填历史运行。

### P1：处理额外预测并明确评分验收

冻结的额外预测为 `template-preview.php:3` 的 LFI；同一位置另有一条 RFI 已命中 06。这里不是 RFI 漏检。该 include 同时接受本地路径，不能为了分数把真实行为直接称为误报。应由独立复核判断是否属于同一未限制 include 根因，在规范结论中完整描述本地/远程能力，并保留全部原始记录；不能全局把 LFI 映射为 RFI。

现有 `scripts/run_lab30_e2e.py::closure_problems()` 没有 TP/FN/F1 门槛，因此 `failed_checks=[]` 不能证明检出达标。应为实验增加单独、显式冻结的评分验收；评分在审计结束后执行，真值与锚点不得进入 Planner/worker/POC 上下文。

## 后续实验如何判断有效

1. **结构回放**：验证五个具体 advisory 线索必须进入独立分流；09/10 只能经重新取证成为候选；24 的两个独立 sink 保留各自结论。测试还需覆盖真实无证据、未知路径、重复线索、定向任务不被扩大及预算耗尽保留未决。
2. **受控全量审计**：以当前代码为控制组，同模型、同源码 ZIP、同预算与 fresh 基线，逐步加入方向分流、观察复核、独立 sink 与新增风险义务。先验证同模型能否补齐缺口，再单独比较模型，避免一次改变所有变量。第六轮同为 deepseek-flash，离线重算为 TP=27、D=10、FN=3，漏 09/14/24；说明五个探索方向曾经能被发现，但不代表终审质量或 30/30 已成立。
3. **指标**：同时记录原 22 项是否回退、8 个缺口各自是否产生独立有效结论、required/advisory 分流、观察复核、D/U/FP、真实终审状态、请求/秒数和动态实验前提。不要只看文件覆盖或 completed。
4. **通过门槛**：新运行结束后，原始固定 `lab30-v2` 评分 TP=30、FN=0；目标为 D=0、U=0、FP=0，并且新增结论具有同版本独立终审。动态 confirmed 另报，不将静态接受算成动态成功。至少 3 次完整运行保留全部有效低分，报告最小值和均值；单次 30/30 只证明单次达到。

30/30 是后续实测目标。尤其 14 的浏览器前提和额外 LFI 的根因归并都需要独立判断，不能通过修改答案、放宽锚点或伪造验证达成。

“复测未决 POC”与“仅补终审”只处理已有发现，不能凭空补出 8 个漏报。即使使用 audit 继续模式，当前实现也只是重开 blocked/running 任务，不会自动将这五个 pending/advisory 全部升级或重新生成风险义务。验证新发现策略应创建新任务，保留父运行作为对照。

## 本次复现命令与验证

在仓库根目录执行，均不请求模型、不执行 POC、不修改数据库：

```bash
python3 scripts/reproduce_release.py --out /tmp/lab30-frozen-score.json
python3 scripts/analyze_lab30_gaps.py \
  --db data/audit.db \
  --out /tmp/lab30-gap-analysis.json
```

没有本地审计数据库时，省略 `--db` 仍可得到归档漏检与证据定位诊断，读取历史明确显示未知。该脚本不会创建缺失的数据库，拒绝覆盖指定数据库及其 WAL/SHM、冻结资产或复现清单。

本次已验证：归档分数及 7 项哈希一致；冻结输入哈希一致；8 项均有 worker 读取凭据；五项 pending/advisory 对应 07/14/17/18/23；方向计数为 28 advisory pending＋8 required resolved；当前信号探针为 52 项，只有 09/23/24 的锚点有调用信号，其中 09 的风险族不对应缺失根因。无数据库模式及错误输出路径也分别检查。
