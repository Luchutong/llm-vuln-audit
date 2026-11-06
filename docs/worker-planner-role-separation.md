# Worker 取证与 Planner 调度的角色分离

2026-11-06，接续 [五轮迭代查证](lab30-five-iterations-autocve-review.md)。本次完善现有执行器，不引入 AutoCVE FindingAgent、第二套运行时、数据库或成本账本。

## 冻结策略与职责

初版角色合同为 `worker-evidence-v1`；针对后续中断运行的定位冲突，新增默认 `worker-evidence-v2`，显式区分 root_cause 与 sink。旧 v1 与显式 legacy 仍可用于对照；字段缺失的历史运行保持旧语义。新全量审计绑定 `worker-exhaustive-v2`，历史策略文本保留供追溯。详见 [中断运行的证据合同优化](interrupted-audit-evidence-contract-2026-11-06.md)。

| 角色 | 负责 | 不能越过的边界 |
| --- | --- | --- |
| Planner | 目标、范围、优先级、依赖、派工与补证安排 | 不得凭自由文本排除具体源码风险；不得通过调度更新直接撤回/判重发现 |
| Worker | 当前工作项的候选跟进、跨文件证据链、防护核对及具体反证 | 不能决定整个项目安全或完成；不能自标动态 verified |
| 独立审查调用 | 当前冻结小批的根因比较、接受、拒绝、补证与同版本观测复核 | 不得派工、扩范围或改写原始 worker 证据；缺事实保持未决 |
| 宿主 | 读取凭据、引用/版本/所有权校验、事务、预算和完成门禁 | 不根据一句自然语言自动认定漏洞或安全 |

审查复用现有模型驱动，但采用独立受限调用和 Reviewer 合同，不另建调度框架。`role_contract_bound` 事件记录角色、策略与合同哈希。

## 借鉴到 Worker 的方法

借鉴的是候选状态、证据束和明确发布检查点的思路，代码为本项目独立实现，不复制或导入上游运行时，也不采用其“只报告高危”的筛选。

- **证据链**：每条新 finding 的 `dataflow` 包含实际读过的 input 与 sink 节点。v1 要求 sink 覆盖主定位；v2 允许独立 root_cause 节点覆盖主定位，保留真实下游 sink。证据不足的假设先保留为候选，不能为了补全字段编造链路。
- **候选检查点**：`candidate_updates` 使用任务内稳定 ID 和源码位置，状态为 pending/supported/excluded。pending 写明缺口和下一步；supported 绑定本次实际提交的同主定位 finding；excluded 附带源码反证。
- **持续调查**：宿主将候选存入现有任务结果的 `candidate_journal`，保留来源 attempt。下一轮漏写候选不会删除它；pending 继续留在当前任务，仍受原尝试、请求、工具、时间与全局预算约束。
- **完成门禁**：Planner 不能取消或延后有 pending 候选的任务。完整性检查扫描所有任务中的 pending，即使任务被外部改成终态，也不能将候选隐藏为完成。
- **有界与防重复**：每任务至多 16 项候选；宿主不会将候选账本自动转成全局方向，Worker 合同也要求避免重复提交同义 remaining_work。已发布发现和终态判断仍保留在不可变尝试历史中，候选账本不是第二份漏洞台账。
- **排除也要证据**：`direction_results.no_evidence`、`observation.follow_up=false` 和 excluded 候选都需 `disproof={basis,rationale,evidence}`。basis 限于有效防护、不可达或不适用；引用必须来自该次 Worker 实际读取区间。不同风险的语义仍由独立审查核对，结构校验不冒充正确性证明。

CSRF 指导同步纠正：登录CSRF可能发生于未认证入口；缺 token 或 SameSite 值不能单独决定接受或排除。报告实际条件与缺失前提，不虚构浏览器攻击观测。

## Planner 的可执行权限

新策略通过模型发布校验和数据库事务校验约束，作用于实际状态迁移，不是只修改角色称呼：

1. Planner 的 `triage no_evidence` 被拒绝。它应派给 Worker；取得该方向同 ID 的取证结果后，引用实际任务/发现结算。
2. 全量范围内的已知源码不能因未读、没有 finding、预算不足或进入终审而 out_of_scope/skip，也不能通过 `coverage_review skip` 绕过读取。当前快照外的线索可以记录明确范围限制；范围内未完成项继续阻止完整收束。
3. covered 仍需当前有效 finding，且引用的 Worker 读取范围覆盖实际根因行，同文件的任意片段不够。
4. 调度更新的 retract/duplicate/project_updates 被拒绝，争议通过受限审查批次处理。审查者仍可拒绝误报；不会自动接受 Worker 的所有主张。
5. 不再在新策略的终审入口运行“必须清空全部 advisory、却禁止派工”的线索 drain。发现阶段没有解决的线索作为覆盖缺口保留，不能以范围排除制造完成。

Worker 的 no_evidence 方向必须能回到对应 immutable attempt 的真实反证。任务完成、读过同文件或 Planner 摘要不能替代该凭据。原始判断、后续反证和审查处置分别持久化。

## 兼容和验证边界

没有数据库迁移，也不回填旧策略、旧发现或旧报告。显式 legacy 和无版本字段的历史队列仍接受原合同；新策略仅支持宿主队列。

本轮验证覆盖：中英文错误覆盖声明不能绕过门禁、已知未读路径仍是缺口、未知路径保留范围限制、伪造/错文件反证被拒、候选跨尝试保留及正常结束、根因位置不能悄悄换掉、input→sink 必须读过、模型在原发布纠错额度内改为调查，以及新旧 API 策略冻结。

完整后端用例分四个独立 pytest 进程执行，**2330 项通过**，保留一条既有重复 ZIP 条目告警；运行期间生产代码与测试代码哈希不变。编译、实验脚本帮助入口与 `git diff --check` 通过。归档 7 项哈希及原 TP=22/FN=8/D=0/U=1/FP=1 的评分重放一致。详见 [验证记录](validation/worker-planner-roles-2026-11-06.json)。

`scripts/live_lab30_optimization.py` 的 baseline/triage/signals 显式冻结 legacy；roles 仅启用新角色策略，optimized 同时启用角色、探索和风险信号策略。manifest 同时记录请求与宿主实际冻结的 task，避免新默认值污染对照。后续可用 `--profiles baseline roles optimized` 比较；本轮没有运行这些真实模型试次。

离线回归和原冻结成绩重放不能证明新模型召回提升。本次不发布新的 30/30 成绩；需要后续固定代码、模型、源码和预算的真实试次检验。

后续真实运行暴露的逐行读取凭据与落盘校验不一致问题，已补充修复和故障隔离，见 [全量审计落盘失败修复](full-audit-failure-2026-11-06.md)。
