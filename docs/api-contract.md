# API 契约

所有 HTTP API 使用 `/api` 前缀，响应为 JSON（文件上传、下载、SSE 和 `204` 空响应除外）。错误响应形如 `{ "detail": "..." }` 或 `{ "detail": {"code":"...","message":"..."} }`；时间均为 ISO 8601 UTC；ID 为字符串。

## 主流程

### 上传不可变源码快照

`POST /snapshots` 使用 `multipart/form-data`，字段名为 `file`，接受完整项目 ZIP。服务保存原始归档、文件哈希和原始行号，并把整包冻结成不可变快照：PHP 文件另建 tree-sitter 语法索引，其它语言的文本文件按纯文本行索引，二进制文件只登记大小。

支持 `.php`、`.php3`–`.php8`、`.phps`、`.inc`、`.phtml`，也识别含 `<?php` 或 `<?=` 标记的无扩展名和框架专用源码文件。第三方依赖与生成目录进入快照，并带 `dependency_tree=true` 元数据，供导航与默认搜索过滤使用；这不是排除判定。ZIP 路径穿越、符号链接、加密条目、归档超限或累计解压超限会被拒绝；单个条目超限、压缩比超限或条目总数超出预算时按确定顺序跳过，并记入 `warnings` / `skipped_files`。

- `GET /snapshots` → 摘要列表。
- `GET /snapshots/{id}` → 完整 `Snapshot`。
- `GET /snapshots/{id}/source?path=&start=1&end=200` → 原始源码行。

`Snapshot`：

```text
{id,name,created_at,archive_sha256,source,immutable:true,schema_version:2,
 content_key,project_id,target_profile,
 stats:{text_files,binary_files,php_files,dependency_tree_files,languages,skipped_count},
 files:[{path,sha256,size,line_count,kind,language,is_php,dependency_tree,
         excluded,exclude_reason,parse_errors}],
 units:[{id,file_path,start_line,end_line,symbol,kind,priority,slice_index,slice_count,...}],
 warnings:[],skipped_files:[{path,reason}],excluded_count}
```

`kind` 为 `text` 或 `binary`；`excluded` / `exclude_reason` 保留历史含义（`dependency_tree or not is_php`），不再决定可读性。二进制文件可以被导航列出，但读取会返回缺失上下文而不是内容。`skipped_files` 与 `excluded_files` 都是前 200 条加计数。

`content_key` 是项目身份：由快照内全部 `kind="text"` 文件的「路径 + 文件 sha256」按路径排序后计算，`.zip` 的重新打包、条目顺序或二进制文件变化都不会改变它。`POST /snapshots` 的响应还带 `project`（项目记录）、`project_reused`（内容键已存在）与 `snapshot_reused`（同一归档字节已导入过，此时不会重新解压）。

### 项目

- `GET /projects` → 项目列表：`{id,name,content_key,target_profile,created_at,updated_at,snapshot_count,run_count,latest_snapshot_id,latest_run_id,finding_counts:{total,open,verified,rejected,withdrawn,unverified}}`。
- `GET /projects/{id}` → 项目详情（含 `snapshots`、`runs`、`findings`）；`?include_findings=false` 省略完整台账，供源码包工作台按页加载漏洞，默认兼容原响应。
- `GET /projects/{id}/findings` → 项目台账（跨运行的漏洞结论，见下）。
- `GET /projects/{id}/runs` → 属于该项目的运行摘要。

`target_profile` 为 `lab30` 或 `unknown`；同一应用根下同时出现商城登录、会员、钱包、运营模板、合作服务及初始化文件时才识别为 `lab30`。自动验证只覆盖此靶场，其他源码仍可静态审计。

### 漏洞台账列表与详情

- `GET /project-findings` → `{items,total,offset,limit}`，全局与包内漏洞列表共用；`project_id` 可选，指定不存在的项目返回 `404`。
- 筛选参数为 `q`（标题、摘要、文件路径、项目名的字面子串，最多 200 字符）、`severity`（`critical/high/medium/low/unknown`）、`verification_status`（既有七种验证状态）、`disposition`。未指定处置时排除 `retracted/duplicate/superseded`；`disposition=all` 包含历史处置，其余值精确匹配（支持 `open/retracted/duplicate/superseded/contested`）。
- `offset` 默认 `0`，`limit` 默认 `25`、最大 `100`；按 `updated_at DESC, id DESC` 稳定排序。`total` 是所有筛选条件之后、分页之前的数量。未知筛选值、负 offset 或越界 limit 返回 `422`。

列表每行是当前项目台账的摘要：`{id,project_id,project_name,fingerprint,title,severity,summary,file_path,symbol,category,finding_kind,validation_state,disposition,disposition_reason,verification_status,verification_verdict,revision,origin_run_id,origin_finding_id,last_run_id,last_finding_id,discovered_at,updated_at,origin_run,last_run}`。不携带 POC、证据正文或验证历史。`origin_run` / `last_run` 是 `{id,snapshot_id,snapshot_name,status,created_at}`，对应首次发现及最近更新结论的实际运行；历史运行缺失时为 `null`。

`GET /project-findings/{id}` 返回：

```text
{finding:完整当前台账,project:Project,origin_run,last_run,
 history:[{run_id,run_finding_id,relation,revision,created_at,snapshot_id,snapshot_name,run_status}],
 verifications:Verification[],current_verification:Verification|null,
 poc_finding_id:string|null,poc_download_path:string|null}
```

`finding` 保留证据、漏洞链、POC、修复建议、处置和修订历史。源码引用按 `last_run.snapshot_id` 读取，不能使用项目最新上传快照代替实际审计来源。`history` 按关联时间倒序保留创建、重发现、更正、沿用、撤回及恢复关系，同一运行可有多条关系。`verifications` 包含整个台账及其关联运行发现上的记录（兼容早期人工记录），每条附真实 `run_id`；首次来源不等于当前结论。

`current_verification` 按台账 `latest_verification_id` 与当前修订匹配：重发现可以沿用早期运行的有效验证；台账状态为 `stale` 时始终为 `null`，早期记录仅作为历史展示，不能计为当前已验证。当前 POC 与最近运行发现一致时，`poc_download_path` 为带 `/api` 前缀的原有 `/api/findings/{poc_finding_id}/poc`；没有匹配的下载来源时两字段为 `null`，内联台账 POC 仍可阅读。台账 ID 不存在返回 `404`。这些端点只读，不改变审计、归组或台账写入语义。

### CVSS 3.1 基础评级与人工修订

运行发现及项目台账返回 `cvss`（有效基础分、标准向量、八项指标或null）、`cvss_assessment`（状态、来源、独立评分版本、结论版本、依据和实际快照）及 `legacy_severity`。有效 severity 由宿主计算：none/low/medium/high/critical，未评分为unknown。漏洞分类不依赖评分是否完成，0.0与未知保持独立。

新增 `POST /project-findings/{id}/cvss/preview`、`PUT /project-findings/{id}/cvss` 及 `GET /project-findings/{id}/cvss-history`，前两者接受八项 `metrics`、修订原因 `reason`、`expected_revision`、`expected_assessment_revision`；版本冲突409，指标或依据无效422，对象不存在404。人工评分修改项目台账，不覆盖历史任务或纯调分时的POC验证。列表 severity 支持none，新增cvss_status筛选与URL恢复。完整契约和迁移步骤见 [CVSS组件说明](cvss31.md)。

### 创建目标审计

`POST /runs`：

```json
{
  "snapshot_id": "...",
  "budgets": {"responses": 24, "tools": 96, "seconds": 1800},
  "run_limits": {"responses": 256, "tools": 2048, "seconds": 1800},
  "poc_mode": "off",
  "task": {
    "objective": "确认未认证管理路由及其源码证据",
    "success_criteria": "每条结论给出原始行号、路由和中间件判断；否则说明未决原因",
    "max_iterations": 3,
    "max_total_attempts": 64,
    "max_planner_rounds": 24,
    "max_workers": 2,
    "stop_on_achieved": true,
    "require_poc": false
  }
}
```

`project_id` 与 `snapshot_id` 恰好给一个：给 `snapshot_id` 时运行继承该快照所属项目；给 `project_id` 时使用该项目最新的快照。两者都给或都不给返回 `422`。项目式运行在创建时冻结 `project_id`、`project_mode="project"`、项目台账基线（`project_baseline`，不含已撤回结论）与 `poc_policy`（不含 runner token），并发出 `project_findings_baseline_frozen`。

请求体没有范围字段：快照中的所有可读文本文件都是审计范围（`Run.scope_mode="snapshot"`，`Run.scope` 为空）。`CreateRunRequest` 使用 `extra="forbid"`，携带历史 `scope` 字段的旧客户端会得到 `422 extra_forbidden` —— 这是有意的破坏性变更，请改为不发送该字段。请求只接受 `task` 模式，不能携带历史 `prompt_id`。任务文本、预算和**项目图**会在创建时冻结；项目图记录全部可读文本文件、符号、静态 include、调用点、模块聚合、高置信入口候选和未解析静态根，二进制文件另列 `binary_files`。入口候选与未解析根都只用于导航，不能作为发现证据或运行时路由事实。

`TaskSpec`：

```text
{objective,success_criteria,max_iterations:1..8,max_total_attempts:1..512,
 max_planner_rounds:1..128,max_workers:1..4,stop_on_achieved,require_poc}
```

`max_total_attempts` 默认 64、`max_planner_rounds` 默认 24。`budgets` 保留单次 Planner/worker 执行含义，默认 `{responses:24,tools:96,seconds:1800}`，上限 `{responses:256,tools:2048,seconds:14400}`。探索与判定共用单次额度，预留最终提交和最多两次纠正，不突破硬上限。

`run_limits` 是 Planner、侦察、worker、POC 共用的整次累计限额：默认 `{responses:256,tools:2048,seconds:1800}`，最小 `{responses:1,tools:0,seconds:30}`，最大 `{responses:4096,tools:32768,seconds:14400}`。缺省采用默认；非整数、布尔数值、越界及未知字段返回 `422`。失败请求、显式重试、重复工具、缓存命中及工具失败均计入；门禁拒绝不扣费，最终提交和纯进度不消耗工具额度。SDK 隐式重试关闭。暂停恢复保留消耗；排队和静止暂停时间不计时，并发执行不累加墙钟。整次耗尽自动以 `inconclusive` 结束，使用宿主事实生成阶段报告，不另请求模型。历史运行 `run_limits=null`，不猜算旧消耗或套入新默认。

`require_poc` 仅要求漏洞发现附带可复核脚本，不控制动态执行。`poc_mode` 为 `off|auto|required`，新任务缺省 `off`；基于旧任务新建也默认 `off`。

- `off`：不检查 runner 健康、不启动 POC Agent、不 prepare/reset、不提交实验；仍可要求脚本。
- `auto`：配置、源码类型及 runner 健康均满足才验证，否则保留静态审计；未执行原因只写运行级说明，不产生逐发现“不适用”记录。
- `required`：创建前作新鲜只读检查，环境不满足返回 `409`，不创建运行；收束须有至少一条同源码、当前版本、同目标的有效动态验证，且穷尽约束仍独立成立。执行中环境失效以 `inconclusive` 收束。

历史冻结策略无 `mode` 时：`require_poc=true → required`；否则 `enabled=true → auto`；其余 `off`，并标记 legacy。`POC_ENABLED` 是服务端能力开关；`POC_REQUIRED` 不覆盖新任务选择。安全观察不计为漏洞，blocked、未知或未读方向不得当作安全。

`GET /poc/readiness?snapshot_id=...` 返回 `{available,reason,message,checked_at,capabilities:{supported_targets:["lab30"],browser,...}}`。原因枚举为 `ready/disabled/unsupported_target/runner_unconfigured/runner_unhealthy`。检查只读配置、目标适配和健康，不 prepare/reset/提交作业；总超时 5 秒，成功缓存 15 秒、失败 5 秒，同配置并发合并。无快照返回 `404`。`required` 创建失败结构：

```json
{"detail":{"code":"poc_not_ready","reason":"runner_unconfigured","message":"自动验证执行器尚未配置。","checked_at":"<UTC>"}}
```

`GET /config` 保留 `budget_limits.defaults`，新增 `run_budget_limits:{defaults,min,max}`；`poc` 提供服务端能力、支持类型及 runner 是否已配置，不包含内部地址或凭据。

`Run.execution_summary` 包含 `policy_version,phase,run_limits,run_usage,run_remaining,active_executions,stop_reason,blocked_task_ids,poc,final_summary_available`。额度对象为 `{responses,tools,seconds}`，剩余不小于零；`active_executions` 每项含 invocation、角色、任务、阶段、实际单次额度和消耗。停止原因至少区分 `goal_met/run_budget_exhausted/planner_round_limit/worker_attempt_limit/unresolved_blockers/invalid_output_limit/environment_unavailable/worker_exit_without_terminal/user_cancelled/interrupted`；预算耗尽附 `dimension`。历史没有总限额时 `run_limits/run_remaining=null`。

终结事务同时保存 run、goal、Planner、剩余任务、终结事件及 `Run.final_summary`。宿主摘要包含状态/完成性、停止原因、原始与有效发现数、按台账 ID 分组数、逐发现修订/证据/验证、任务状态、覆盖、预算和限制；没有模型叙述也可下载完整阶段报告。新 Markdown 报告以该事实快照渲染；旧模型内容保留在原始事件及 JSON 追溯记录中。模型报告引用采用 `finding_refs:[{finding_id,revision}]` 和 `no_evidence_task_ids`，遗漏、外部 ID、过期修订及受阻“安全”引用会被拒绝，任务图仍可提交。

- `GET /runs` → 运行摘要（含 `project_id`、`project_name`、`project_mode`、`poc_policy`）。
- `GET /runs/{id}` → `{run,goal,planner,project,project_findings,carried_findings,report_narrative,verification_summary,verification_jobs,project_map,plans,tasks,observations,investigations,findings,source_observations,metrics}`。`findings` 为漏洞候选，`source_observations` 为独立的排查记录。`project_findings` 是实时项目台账的有界投影（排除已撤回结论，最多 200 条），本次冻结基线保存在 `run.project_baseline`；`carried_findings` 是本次没有重新取证、以沿用关系挂到本次运行的开放结论。`report_narrative` 是 Planner 在收束复核回合提交的 `{summary,conclusion,limitations,finding_refs,no_evidence_task_ids}`（没有则为 `null`）。`verification_summary` 按状态计数，`verification_jobs` 是 runner 作业摘要。Planner 运行的 `units` 与 `work_items` 为兼容字段且始终为空。`project_map` 在这里是**有界投影**（`stats`、入口候选、模块聚合、`binary_files`、`limitations` 等；不含 `files`/`symbols`/`includes`/`calls` 全量数组），以免整包快照让每次轮询变成数 MB JSON。`investigations` 是固定调查的无正文投影（见下）。
- `GET /runs/{id}/project-map` → 完整冻结项目图，供导出与深挖使用。注意 `architecture.modules[]` 的目录键是 `directory`：该数组里的每一项都是**目录**，而这份投影里其它叫 `path` 的字段都是文件。存储的完整项目图保留原始键名，`GET /runs/{id}` 与 `GET /runs/{id}/project-overview` 使用 `directory`。
- `GET /runs/{id}/project-overview` → Planner 首轮看到的那份有界概览。
- `POST /runs/{id}/cancel` → 取消排队、运行中或已暂停的任务。
- `POST /runs/{id}/pause` → 在下一个协作边界停下，保留前沿。
- `POST /runs/{id}/resume` → 继续一个已暂停的运行。

目标任务的 `Run.status` 可能是 `pending`、`running`、`paused`、`completed`、`unreachable`、`inconclusive`、`cancelled`、`interrupted` 或 `failed`。`unreachable` 只在动态前沿的所有证据方向结算且无受阻项时产生；缺失源码、模型/预算失败、共享尝试上限、Planner 回合耗尽、取消和中断不会被转换为“不可达”。

### 删除与清理记录

- `DELETE /runs/{id}` → `{run_id,status_before,deleted:{表名:删除行数}}`。`pending`、`running` 或暂停尚未静止返回 `409`，其余状态可删除，**包含已静止的 `paused`**；删除已暂停任务会失去继续执行的前沿。不存在的任务返回 `404`。
- `POST /runs/cleanup` 接受 `{}`（全局）或 `{"project_id":"..."}`（指定项目），返回 `{deleted_runs,runs:[上述删除结果]}`。自动跳过 `pending`、`running` 和尚未静止的执行，已静止的暂停任务同样在清理范围内。
- `DELETE /snapshots/{id}` → `204`。任何审计引用该快照时返回 `409`，不存在时返回 `404`。删除数据库中的快照及关联真值记录，不删除磁盘上的归档或源码文件。
- `DELETE /prompts/{id}` → `204`。内置提示词及被任一审计引用的提示词返回 `409`，不存在时返回 `404`；草稿列表沿用 `GET /prompts`，包含 `builtin` 标识。

审计删除会清理该运行的发现、验证、执行轨迹与关联记录，保留源码项目和跨运行的 `project_findings` 台账；因此被删任务的来源链接、验证或工件可能不可用。删除 ZIP 也保留项目及累计台账。运行和 ZIP 删除后，项目对应的计数与最新记录指针会按剩余记录重算，没有剩余记录时指针为 `null`。这些操作无法从界面撤销，前端提交前明确确认范围与影响，成功后刷新列表和统计，并在当前审计被删时返回源码包工作台。

### 暂停与继续

`paused` 不是终态：暂停只把运行停在回合边界，不放弃任何已完成的工作。已经领取的 worker 尝试与正在进行的 Planner 回合允许跑完并提交——一个被切断的模型调用会留下没有结果的尝试记录，而那正是继续时无法接上的状态——之后 `status` 变为 `paused`，`finished_at` 保持为空，探针事件为 `run_paused`。

- 只有 `pending` 或 `running` 可以暂停，其余状态返回 `409`；不存在的运行返回 `404`。暂停请求本身先记 `run_pause_requested`。
- `resume` 只接受 `paused`，其余返回 `409`。仅在原执行已静止时把状态放回 `pending`；尚在途时返回 `409`，前端显示等待静止。新领取原子递增 claim_epoch，旧代次不能写入业务事实，由既有的领取逻辑自然接管：前沿（任务、会话、`current_round`）原样续跑，`started_at` 保留首次开始的时间，不会重复产生 `run_started` / `planner_session_started`。目标的 `task_goals` 或会话已经结算（非 `open`）时无法继续，返回 `409`。
- `cancel` 对 `paused` 同样有效，直接结算为 `cancelled`：暂停是为了停下来看，如果必须先继续才能丢弃，那就是个陷阱。
- 服务重启会把 `paused` 扫成 `interrupted`（`error` 写明是暂停期间重启），**不支持跨重启继续**：暂停意图只在内存里。

## Planner、动态任务图与多 worker

`Goal` 保存一个运行的目标状态。一个运行只有一个主 `PlannerSession`；Planner 在序列化回合中基于冻结项目图和已持久化 worker 摘要生成或更新 `PlannerTask`。任务是跨文件证据方向，不是一个文件或语法切片。

```text
Goal {id,run_id,objective,success_criteria,status,attempts,max_iterations,max_total_attempts,...}
PlannerSession {run_id,session_id,current_round,max_rounds,current_revision,status,terminal_state,...}
PlannerPlan {id,round_no,revision,basis_summary,next_action,task_snapshot,updates,usage,...}
PlannerTask {id,task_key,title,objective,acceptance_criteria,context_spec,dependencies,
             priority,state,attempts,max_attempts,claimed_by,result,error,attempt_history:PlannerTaskAttempt[]}
PlannerTaskAttempt {task_id,attempt,worker_id,outcome,state,result,usage,seen,error,created_at}
```

Planner 不能直接声明源码发现：它只能提供任务目标、依据摘要、文件/符号阅读指令和依赖。它的工具面是**全量只读**的：`get_project_map` / `search_project_map`（冻结索引）、`list_tree` / `find_files` / `file_summary`（布局与符号大纲）、`read_source` / `search_code`（原始源码行与文本检索）、`get_coverage`（覆盖统计）、`get_task_results`（完整任务史与已有结论）、`get_investigation`（某条固定调查的全文）、`investigate_project`（内置侦察子 agent）。这些工具受运行冻结范围约束，越界返回 `context_missing`；未知工具名会被显式拒绝；参数不符合工具签名（例如多给一个没声明的开关）会退回模型纠正一次，而不是把该回合的探索阶段直接判死——这一类纠正请求与其它请求一样计入预算。**Planner 的读记录只用于节流与「已读过什么」，不进 `validate_evidence` 或任何 finding 证据路径**——与侦察子 agent 一致；证据永远只来自 worker 的台账。Planner 也不再有一个“无工具决策阶段”：结构化决策阶段保留同一套工具，只是提示词要求它现在提交 `PlannerDecision`。工具只在一种情况下会被收回——决策阶段的确认额度（`policy.decision_confirmations`）用尽，宿主发 `planner_tools_withdrawn` 并要求单独提交决策，见下文。

`investigate_project` 返回布局、入口候选、数据存储、安全边界和首批阅读目标，这些是导航线索而不是证据，且它有自己的响应/工具/墙钟预算。worker 通过原子租约领取已就绪任务，并先装载受范围约束的多文件上下文；已完成依赖的摘要会作为未验证线索交接给后续任务。worker 还可以检索同一运行中其他 worker 的受限持久化轨迹（工具参数/结果预览和依据摘要），但这些内容不是证据，任何 finding 仍须由该 worker 实际读取的源码行号支撑。`continue` 只会重试同一动态任务；`blocked` 会使整体结论保留为 `inconclusive`。每次工具调用都受运行冻结的审计范围限制：`scope_mode="snapshot"` 的运行可以读取快照内任何可读文本文件（含依赖目录与其它语言），二进制文件与快照外路径仍被拒绝。

目标任务 worker 提供 `list_tree` / `find_files` 定位其冻结范围内的可读文件，再使用 `read_source` / `search_code` / `get_context` 获取源码证据。目录和文件名查询计入工具预算，但不登记为已读源码。导航与同行轨迹的成功返回值保持纯 JSON，可用 `json.loads(...)` 解析，不追加文本预算提示；剩余额度由既有执行状态记录。源码中的运行时输出目录不一定存在于上传包，Planner 的 `scope_paths` 只能引用快照中实际存在的文件或目录。缺失的部署配置应记录为 `missing_context`，不得猜测其存在或检查服务器主机文件系统。

### 每轮态势与「允许派 0 个任务」

Planner 每回合在提示词里收到宿主**预取**的「本轮态势」：目标状态、`ready`/`running` 的前沿任务、**全部**已结算任务与已有结论（含 `validation_state`、`verdict`、`disposition`、`revision`、`derived_from` 与证据路径）、覆盖统计，以及已固定调查的清单。预取而不是等模型自己调工具，是因为每回合重建的 Planner 没有跨回合记忆，这正是它重复派发同一方向的直接原因；这一块与覆盖统计一起作为 `planner_situational_prepared` 事件持久化。

规则的硬底线只有一条：**目标未达成且前沿为空（无 `ready`/`running` 任务）时，本轮必须产出至少一个任务；否则本轮允许派出 0 个任务。** 前沿非空时的空计划是合法的——强制它每轮造活干，才是重复派发的推手。除此之外，新提议的阅读范围与某条「已结算且结论仍 `open`」的任务高度重合（文件集合 Jaccard ≥ 0.8）时会被拒绝并提示两条出口：结论有误就走 `updates` 的 `reopen` / `retract`，确是新方向就指出原任务未覆盖的文件。这是廉价护栏而非主机制：防重复主要靠前沿状态机（只有 `ready` 会被领取）与每轮态势。

### 固定调查（pinned investigations）

Planner 与侦察的每次调查，宿主都把答案固定在 `planner_investigations` 里：**一次写入，正文不再改写**，只有处置列（`status` / `superseded_by` / `reason` / `revision`）可变。同一话题再次被问到时直接返回原记录（`planner_investigation_reused`，附 `pinned_round` 与 `revision`），不会重新执行模型或子 agent。**只有 `investigate_project` 有 `revise=true`**：它的答案是子 agent 生成的，可能确实错了，重做时旧行标为 `superseded` 并记下接替它的新记录，新行 `revision+1` 追加写入，事件为 `planner_investigation_superseded`。导航与检索类工具**没有** `revise`，也不接受这个参数：它们读的是冻结快照，同一组参数不可能得出不同的字节，想让答案不同就得换参数。部分唯一索引保证同一话题同时只有一条 `active`，所以“被更正过”是一个可读的事实，而不是一次静默覆写。固定的内容是侦察简报全文与导航/检索结果；`read_source` 只记区间（`files_read`），正文永不入库。

`GET /runs/{id}` 的 `investigations` 是它的**无正文投影**：

```text
{total, by_status:{active,superseded,retracted}, notice,
 recent:[{id,round_no,revision,kind,tool,topic,topic_key,args,payload:null,
          payload_bytes,files_read,usage,status,reason,superseded_by,created_at}]}
```

`recent` 有界（最近 12 条）。正文只在 `get_investigation` 里按话题取，所以运行响应不会随着调查量增长。

宿主每回合为 Planner 计算一段**覆盖统计**（`{files_total,files_read,files_with_findings,coverage_ratio,read_paths,unread_hot_modules,dependency_tree_total,dependency_tree_read,notice}`），随提示词一起给出，并作为 `planner_coverage_prepared` 事件持久化。它由已持久化的 worker `seen` 读记录与冻结项目图算出，不是安全结论，也不能作为 finding 证据；分母是可读文本文件总数。`GET /runs/{id}` 的 `observations` 会把每回合的覆盖统计与侦察简报（或侦察失败/跳过的原因）一并返回，供界面与报告复核。报告的「覆盖统计、固定调查与侦察简报」一章渲染的正是这两者，并明确写出边界：它们是导航线索。

目标发现使用通用结构，不强制伪造漏洞链：

```text
TaskFinding {title,kind="source_observation",summary,evidence,
 severity?,input_source?,propagation?,dangerous_operation?,protection?,
 preconditions?,poc?,remediation?}
```

`kind` 可为 `source_observation`、`data_flow`、`security_boundary`、`vulnerability` 或任务定义的其他短名称。同一动态任务可提交多条独立引用的发现；每条引用都要在快照内且已被该 worker 实际读取。

### 结论的三个正交轴：证据、自动验证、处置

一条发现占据 `(run_id, unit_id, category)` 一个槽位，三个轴彼此独立：

- `validation_state`：引用是否核实得了（`candidate` / `invalid_evidence`）。
- `verification_status`：隔离靶场是否复现（`verified` / `rejected` / `inconclusive` / `not_applicable` / `environment_unavailable` / `unverified` / `stale`），附 `verification_verdict`（`confirmed` / `rejected` / `uncertain`）。它只由 POC Agent 在收束边界写入，HTTP 没有人工回填入口。
- `disposition`：本次运行是否仍然主张它（`open` / `superseded` / `retracted` / `duplicate`；`contested` 仅为历史值），附 `disposition_reason`、`disposition_by`、`disposition_at`。

重跑同一方向**不会替换行**：槽位被复用，`id`、`created_at` 与挂在该 `id` 上的自动验证记录全部保留，只有内容列被更新，旧文本快照进 `superseded_summary` 并把 `revision` 加一。物理替换行会让 `id` 变化、让验证记录成为孤儿，所以它被明确取消。`revision` 是这条槽位第几次给出结论，`superseded_summary` 是它此前说过的内容（有上限），`derived_from_finding_id` 记录它是从哪条结论派生/重复而来。内容发生实质变化时，旧验证状态置为 `stale`——之前复现的是旧结论。

Planner 可以更正已有结论：`updates` 的 `reopen` 把一条已结算任务放回 `ready`（`planner_task_reopened`，原 `planner_task_attempts` 行全部保留，新尝试只追加 `attempt=N+1`），`retract` / `duplicate` 把某条结论的处置标为撤回或重复。**软删除一律保留行**：撤回只是换处置并记下理由，行、证据、存档版本与验证记录都还在——把撤回的结论从结果里删掉，会让「本次没有发现」和「本次把发现撤回了」看起来一模一样。

**自动验证的 `rejected` 不是删除。** 宿主不会用验证结果改写 `disposition`；Planner 在复核回合可以据此撤回，若没有撤回，该结论也不会支撑 `met`，报告将其列入「自动验证未通过」并留下 `planner_kept_rejected_finding` 记录。历史 `findings.verdict` 字段只读保留，不再参与处置判定。

### 项目台账

同一条漏洞跨运行只有一行，存在 `project_findings`：`fingerprint` 由「文件路径 + 符号 + 危险操作」的规范化哈希决定，措辞漂移时只在同一 `(file_path, symbol)` 候选里按危险操作 token 的唯一 Jaccard ≥ 0.6 合并。台账行记录 `revision`、`verification_status/verdict`、`latest_verification_id` 与 `origin_run_id/origin_finding_id`；`project_finding_runs` 记录 `rediscovered` / `corrected` / `carried` / `withdrawn` / `restored` 关系。已撤回的台账行不会因为再次发现自动恢复，Planner 必须显式 `reopen`。

## 执行轨迹

`GET /runs/{id}/events?after=0` 是持久化 SSE。服务先将事件写入 SQLite，再推送；客户端应使用 `Last-Event-ID` 或 `after` 续传并以事件 ID 去重。`GET /runs/{id}/event-log?after=0` 返回 JSON 回放。

Planner 任务事件包括：

```text
planner_run_queued, planner_session_started,
planner_round_started, planner_assessment, planner_round_committed,
planner_context_prepared, planner_task_started, planner_task_requeued,
planner_task_completed, planner_task_exhausted, planner_task_blocked,
planner_task_reopened, planner_task_settled,
planner_dependency_handoff_prepared,
planner_overview_prepared, planner_coverage_prepared, planner_situational_prepared,
planner_exploration_stopped, planner_decision_sanitized, planner_tools_withdrawn, planner_round_failed,
planner_investigation_pinned, planner_investigation_reused, planner_investigation_superseded,
recon_started, recon_phase, recon_brief_prepared, recon_terminal, recon_skipped,
finding_superseded, finding_retracted, finding_duplicate, finding_contested,
finding_disposition_changed,
project_findings_baseline_frozen, project_finding_created, project_finding_rediscovered,
project_finding_corrected, project_finding_retracted, project_finding_duplicate,
project_finding_reopened, project_finding_disposition_changed, project_finding_update_rejected,
project_finding_merge_failed, carried_findings_recorded,
poc_agent_phase, poc_verification_started, poc_job_started, poc_job_finished,
poc_http_observed, poc_verification_recorded, poc_verification_skipped, poc_verification_unavailable,
report_narrative_committed, planner_kept_rejected_finding,
run_pause_requested, run_paused, run_resumed,
audit_progress, agent_code, tool_call, tool_result, task_assessment, model_retry,
run_completed, goal_unreachable, goal_inconclusive
```

Planner 事件带 `plan_id`、`session_id`、`role=planner`；侦察事件带 `role=recon` 与同一 `plan_id`，其工具事件复用 `tool_call` / `tool_result` 但 `call_id` 前缀为 `recon-tool-`（Planner 是 `planner-tool-`），因此不会与 Planner 的工具跨度合并。POC 验证事件带 `role=poc`、`finding_id`、`project_finding_id`；`poc_job_started` / `poc_job_finished` 另带 `job_id`、`language`、`exit_code`、`status`、`duration_ms` 与 `truncated`，`poc_verification_recorded` 带 `verification_id`、`status`、`verdict`、`jobs`、`artifacts`。worker 事件带 `task_id`、`task_key`、`worker_id`、`attempt`、`role=worker`。`tool_call` 和 `tool_result` 使用同一 `call_id` / `span_id` 配对，结果携带状态、受限预览、已读范围、用量和 `duration_ms`。`task_assessment` 包含 `outcome`、`summary`、`rationale`、`next_focus`、`missing_context` 和经解析的源码引用。

模型请求、代码动作、进展和工具事件另带 `agent_invocation_id` 与 `request_index`，标识具体执行实例及模型请求序号；`request_index` 不表示 worker 的任务尝试次数。配对时应结合运行、角色、执行实例、阶段、任务与尝试上下文，不能仅凭 `call_id` 合并不同 Planner 回合或并行 worker。

控制工具 `report_progress(message)` 在同一代码动作的源码工具调用前发布一句公开进展，持久化为 `audit_progress`，载荷包含 `message`、`phase` 与上述执行归属。每次模型响应最多保存一条，最多 280 字符、1024 UTF-8 字节；空白与重复内容不落库。它不增加模型请求或源码工具次数，仍受阶段关闭与墙钟预算限制，不属于漏洞证据，也不采集供应商隐藏推理。没有进展事件的旧记录只展示其原有摘要和实际工具操作。

`planner_coverage_prepared` 带 `round` 与 `coverage`；`planner_situational_prepared` 带 `round`、`counts`（前沿/已结算/结论/固定调查）与 `frontier` / `settled` / `finding_ids` / `omitted`，说明那一回合的 Planner 究竟被告知了什么——「它重复派发了一个已结算方向」与「宿主从没告诉它那个方向已结算」在没有这个事件时长得一样。`recon_brief_prepared` 带 `round`、`question`、`brief`（含由宿主填充的 `files_examined` 与 `reads`）；`recon_terminal` 带 `reason`（`completed`、`timeout`、`invalid_output`、`model_error`、`internal_error`、`cancelled`）——侦察失败只会让该回合没有简报，不会中断 Planner 回合或整个运行。侦察请求不计入 `planner_agent_terminal.usage`。

`planner_exploration_stopped` 的 `reason` 说明探索阶段为什么结束（`budget`、`timeout`、`request_timeout`、`no_progress`、`invalid_output`），而**探索结束本身不是回合失败**：随后照常进入决策阶段（`agent_phase.phase=planner_decision`），工具仍然可用，但只在一个确认额度内可用——`policy.decision_confirmations`（默认 2）次模型请求。这个额度是**从探索用掉的地方往下数的一小片**，不是回合的剩余预算：一次真实运行连续三个回合把每一个请求都花在「再列一次目录」上，从没产出回合唯一必须产出的那个决策。额度用尽后宿主收回工具并发 `planner_tools_withdrawn`（带 `reason`、`error`、`usage`），回合进入 `planner_publish` 阶段：无工具、一个 prompt、只要求结构化决策。因此「一个回合以决策收尾」是宿主的结构属性，而不是对模型自觉停手的期望。`planner_explore` 阶段的 `response_limit` 与 `planner_prepare` 的 `reserved_responses` 一起说明这份预留：`1 + policy.output_corrections + policy.decision_confirmations`。重复调用的「无进展」刹车只作用于探索阶段（`policy.repeated_calls`，默认 2）——它拦的是「没有新信息还硬转」；决策阶段里模型回头确认一条已有结论再提交决策是合法动作，那里的边界是确认额度，而重问同一查询由固定调查直接回答、不再重新执行。

`planner_decision_sanitized` 带 `round`、`field`、`task_key`、`before`、`after`、`reason`：建议性字段（越界的行号窗口、超限的 `priority`、过长的 `query_hints`）会被宿主裁掉并留痕，而不是拒掉整轮决策。只有安全与图不变式仍然硬拒——`source_refs` 引用了冻结图里不存在的**文件**、`scope_paths` 写了图里既不是文件也不是目录的路径、依赖不存在或成环、已结算任务被重新定义、以及前沿为空时的空计划。`scope_paths` 按契约可以写**目录**（例如 `architecture.modules[].directory` 给出的模块目录）：它是一个方向的覆盖范围而不是待读的行区间，所以宿主接受图覆盖的目录、按图的拼写归一后接受（`./src`、`src/` 与 `src` 是同一个），并在重复守卫里把它展开成其下的文件。`planner_round_failed` 带 `plan_id`、`round`、`revision`、`terminal_reason` 与 `error`：一个回合没能产出可用决策时，它被如实记录为一个失败草稿，**但运行不会就此结束**——宿主会先重试该回合，再用持久化前沿兜底。

`model_retry` 带 `phase`、`corrections` 和 `reason`——`reason` 是宿主的输出校验器拒绝上一次结构化输出的原文（例如某个任务引用了超出文件行数的区间）。一个执行阶段允许的纠正次数由 `policy.output_corrections` 决定（默认 2；`GET /config` 的 `agent_policy` 里可见），用尽后该阶段以 `invalid_output` 终止，所以这是判断回合为何失败的唯一线索；用尽时最后一次拒绝原因会并入 `planner_agent_terminal` / `task_agent_terminal` 的 `error`。预算耗尽与输出不合规是两回事，前者标为 `budget`。

`rationale` 是模型生成的、可审计的简短依据摘要，必须关联展示过的源码事实；不是模型内部思维链。系统不会保存或返回 provider thinking delta、隐藏推理或 API 密钥。

### 代码动作与解释器边界

每次模型请求产出的是**一段 Python 代码**（`<code>…</code>` 栅栏，或在代码块里调用 `final_answer(...)` 结束本阶段），而不是一串工具参数 JSON：一段代码可以在循环里连调多次只读工具、把中间结果留在变量里、只 `print` 出它真正要看的那几行。因此**一次请求换一串动作**——一条 `agent_code` 之后跟着多条共用同一 `call_id` / `span_id` 配对的 `tool_call` / `tool_result`，是这套机制的常态而不是异常。宿主的闸门没有移动：预算、墙钟、暂停/取消与历史体积仍然在**每次模型请求之前的同一个点上**检查，阶段名、`responses` / `tool_calls` / `model_attempts` / `corrections` 的语义与默认值一字未改。

`agent_code` 带 `phase`、`step`、`code`、`code_bytes`、`truncated`、`logs`、`is_final`、`error` 和 `usage`。`code` 是被执行的代码本身（按 `policy.code_bytes` 截断，默认 4 KiB；`truncated` 标记是否截断，`code_bytes` 是截断前的 UTF-8 字节数）。`logs` 是这一步 `print` 出来的内容，由解释器按 `policy.code_output_bytes` 截断（默认 24 KiB）——事件里存的就是模型当时读到的那一份，不再二次裁剪，避免留下一个与模型所见不同的版本。`is_final` 标记这一步是否以终局结束本阶段。`error` 是这一步失败的**原因**（截断到 400 字符），而不是解释器报错原文：解释器会把整段代码抄进自己的消息里（`Code execution failed at line '<整段代码>' due to: …`），照抄进事件的话，400 字符的预算会留下代码的回声、扔掉后面的原因——一次真实运行交了一份 5.9 KB 的决策、被拒，40 条 `agent_code` 里没有一条看得出为什么。所以事件取那句话**底下**的真正异常并保留类名（`OutputRejected: …` 是宿主拒绝终局、`NameError: …` 是模型自己的代码、`ExecutionTimeoutError: …` 是解释器的超时），两种情况仍然分得清。**代码是动作，不是隐藏推理**，所以它照 `tool_call` 的先例持久化并展示；代码块之外的散文只留在内存里，不进事件、不进库——「模型的内部思维链不会被保存或展示」继续成立。

**阶段边界不继承记忆**：一个阶段是有界的一段上下文，不是上一阶段的续篇。进入决策阶段与收尾阶段（`planner_decision` / `planner_publish`）前，宿主会清空循环的记忆，因为这些阶段的 prompt 已经带着它们需要的全部态势（项目概览、情境块、覆盖统计，以及把探索阶段问过的内容原样回放的固定调查）——继承上一阶段的观察只会让请求白白顶到 `policy.history_bytes`（默认 192 KiB）上限。一次真实运行正是这样死的：第一次收尾请求已经 ~170 KB，而被拒绝的决策唯一允许的那次纠正，在发出之前就被历史上限拒掉了。跨边界保留下来的是**解释器里的变量**（探索阶段建好的表正是决策阶段据以判断的东西），以及每个阶段照常重建的阶段名、工具表与闸门。

执行器的边界（进程内 `LocalPythonExecutor`，`additional_authorized_imports=["json"]`）：在库自带的基础模块（`re`、`math`、`collections`、`itertools`、`datetime`、`statistics`、`time`、`random`、`queue`、`stat`、`unicodedata`）之外，仅增加 JSON 数据解析；CodeAgent 和解释器使用同一授权列表。`os`、`sys`、`subprocess`、`socket`、`pathlib`、`io`、`shutil`、`multiprocessing`、`pty`、`builtins` 仍在解释器自己的危险清单里，连名字都取不到；`eval` / `exec` / `compile` / `globals` / `locals` / `__import__` 同样被禁，dunder 属性被拒。另有操作数上限（`1e7`）、`while` 迭代上限（`1e6`）与打印上限兜住跑飞的一步。

**官方定性照抄在这里**：smolagents 自己写着 `LocalPythonExecutor`「is not a security sandbox: for isolated execution of untrusted code, use a remote executor」。本工具接受这一定性，因为它执行的是**模型写出的、只被授权调用宿主只读工具**的代码，而不是上传快照里的任何代码：沙箱里没有任何能读文件、发网络请求或起进程的能力，所有实际读取都必须经由宿主工具，并照旧受范围校验、pin、去重、读账本与 `budgets["tools"]` 约束。上传快照里的代码从不执行；POC 也不在应用进程内运行，而是由隔离的 `poc-runner` 容器对着本地 Lab30 执行（见 `poc_runner/README.md`）。另一条诚实的边界：解释器的墙钟上限由线程池实现，**杀不掉已经跑飞的线程**，它限制的是宿主愿意等多久（`policy.code_seconds`，默认 30s），所以取消时的等待上限是「一次请求 + 最多一个代码块的等待」，而不是「一次请求」。

终局校验仍在宿主这一侧：`final_answer(...)` 的载荷按当前阶段的结构（`PlannerDecision` / `GoalAssessment` / 本单元的三类结论）校验，不通过时**不结束阶段**，而是把拒绝理由作为一条 Observation 还给模型，让它在同一个循环里改正。这次拒绝照旧算一次纠正：`policy.output_corrections`（默认 2）的额度、`model_retry` 事件与「用尽后以 `invalid_output` 终止」的语义一字不变。

一个行为变化：**worker 工具的参数错误**。旧实现里工具以 JSON schema 注册（`@agent.tool(sequential=True, retries=0)`），参数不符合 schema 就不再重试，直接结束当前读单元；现在工具就是 Python 函数，参数写错由解释器抛出的异常变成那一步的 Observation，模型看到错误后在同一循环里改正，读单元继续。这是变好了——一次笔误不再作废整个单元——但轨迹确实与旧记录不同：这类错误表现为一条带 `error` 的 `agent_code`，而不再以 `unit_incomplete` 收场。

## 发现、自动验证与导出

- `GET /findings/{id}` → 发现、只读的自动验证记录与历史人工记录（`source="poc_agent"` / `"legacy_human"`）。
- `GET /findings/{id}/poc` → 原样下载已存 POC；没有 POC 时返回 404。
- `GET /runs/{id}/report?format=markdown|json|zip` → 审计报告、原始结果或证据包。

验证记录由 POC Agent 在收束边界写入，没有 HTTP 提交入口。`Verification` 形如：

```text
{id,finding_id,source:"poc_agent"|"legacy_human",status,verdict,summary,
 execution_status?,environment?,command?,normal_observation?,attack_observation?,
 original_script?,modified_script?,target:{kind,base_url,security,authenticated},
 agent:{model,phases,jobs,usage},artifacts:[{name,sha256,size}],created_at}
```

`status` 与 `verification_status` 同一取值集合；`rejected` 表示隔离靶场执行成功但未能复现，静态源码证据仍保留。历史人工记录只作审计轨迹，不再决定当前结论。证据包包含自动验证产物，以及每份验证的 `<verification-id>-runner-manifest.json`（目标、限额、job id、退出码、产物哈希）。

Planner 目标任务的统计 `truth_status=planner_goal_not_comparable`、`evaluation=null`，进度字段表示动态任务前沿的结算状态，不会套用固定三类漏洞的 TP/FP/FN/TN 或 Recall 矩阵。

## 配置与多厂商模型档案

模型连接由可选择的档案表示。服务启动时，环境变量形成一个 `credential_source="environment"` 的只读初始档案，并会在后续启动时按当前环境变量刷新其名称、模型和 Base URL。该档案可被选择，但不能通过档案 API 编辑或删除。界面新建的档案使用 `credential_source="stored"`，每个档案独立保存 `label`、`model`、`base_url` 和 API Key。

`GET /config` 返回当前选中档案的非密钥状态、档案列表、预算、worker、模型健康状态和版本。顶层 `model` 与 `base_url` 对应当前选中档案，`selected_profile_id` 对应其 ID。所有返回的 Base URL 都会移除 URL 用户信息、查询参数和片段；环境变量中用于兼容端点的原始地址只保留在服务进程内。

```text
ModelProfile {id,label,model,base_url,credential_source:"environment"|"stored",
              api_key_configured,ordinal,created_at,updated_at,selected}
Config {model,base_url,configured,thinking,missing,selected_profile_id,
        model_profiles:ModelProfile[],budgets,budget_limits,run_budget_limits,poc,agent_policy,worker,
        model_health,version}
```

响应中的档案不包含 `api_key` 或 `api_key_secret`。浏览器只能获知 `api_key_configured` 等非密钥状态；已提交的 API Key 不会在后续响应中返回，也不会进入快照、事件、报告或证据包。

- `POST /config/profiles` → 新建独立档案，返回完整 `Config`，状态码 `201`。
- `PUT /config/profiles/{profile_id}` → 更新独立档案，返回完整 `Config`。
- `POST /config/profiles/{profile_id}/select` → 选择档案，返回完整 `Config`。
- `DELETE /config/profiles/{profile_id}` → 删除未选中的独立档案，状态码 `204`。
- `POST /config/check` → 对当前选中档案发送最小真实模型请求，返回 `{ok,model?,latency_ms?,reply?,error?}`。

新建请求体为：

```json
{
  "label": "供应商 A · 日常审计",
  "model": "chat-model",
  "base_url": "https://provider.example/v1",
  "api_key": "..."
}
```

更新请求同样需要 `label`、`model` 和 `base_url`；`api_key` 可省略。省略 `api_key` 会保留已有的加密密钥，提供空字符串会清除它。`base_url` 必须是不含凭据、空白、查询参数或片段的绝对 `http(s)` 地址，端口也必须有效。

独立档案的 API Key 会在写入前加密；密文保存在 `AUDIT_DATA_DIR/audit.db`，解密所需的本地密钥文件为 `AUDIT_DATA_DIR/.model-config.key`。备份、迁移或恢复已保存档案时必须同时保留这两个文件；缺少密钥文件时，已保存的 API Key 无法恢复。

只要存在 `pending`、`running` 或 `paused` 的审计，`POST /config/profiles`、`PUT /config/profiles/{profile_id}`、选择和删除操作都会返回 `409`，以阻止审计运行期间改变档案。环境变量档案的编辑或删除也会返回 `409`；删除当前选中档案同样会返回 `409`。不存在的档案返回 `404`，请求字段校验失败返回 `422`。

创建审计时，`Run` 额外冻结并返回非密钥的 `model_profile`：`{profile_id,model,base_url}`。其中 `base_url` 同样是公开净化值。worker 按冻结的 `profile_id` 找回该档案的连接凭据；若历史档案已删除，运行记录仍可展示快照，但不会改用当前选中档案继续执行。


## Lab30 实测修复的增量契约（2026-10-27）

- TaskSpec新增可选 `completion_policy: goal | coverage_review`，缺省goal；新正式对比及全源码E2E使用coverage_review。
- PlannerDecision新增 `coverage_review: [{path, action: skip, reason}]`。只有冻结文件路径及具体理由可接受，收束还受完整任务队列和待复核集合约束。
- `run.execution_summary.coverage_review` 提供版本、完整计数、pending_paths、read_paths、skips和complete；旧运行无该字段。
- 评分新增解释性 `missed_diagnostics` 和重复主张统计，正式TP/D/U不变；汇总新增共同CVSS配对差、独立审计/生命周期耗时及执行诊断。
- CSV ZIP保留原3表，新增cvss_common.csv和execution_diagnostics.csv。旧字段及历史成绩保留。
- runner HTTP/浏览器请求新增可选host job_id，共享幂等查询；健康能力新增idempotent_http_jobs/idempotent_browser_jobs，旧runner需升级，静态审计继续。

详见[实测修复交付](lab30-validation-repairs.md)。
