# API 契约

所有 HTTP API 使用 `/api` 前缀，响应为 JSON（文件上传、下载和 SSE 除外）。错误响应形如 `{ "detail": "..." }`；时间均为 ISO 8601 UTC；ID 为字符串。

## 主流程

### 上传不可变源码快照

`POST /snapshots` 使用 `multipart/form-data`，字段名为 `file`，接受 PHP 项目 ZIP。服务保存原始归档、文件哈希和原始行号，并建立 tree-sitter PHP 索引。

支持 `.php`、`.php3`–`.php8`、`.phps`、`.inc`、`.phtml`，也识别含 `<?php` 或 `<?=` 标记的无扩展名和框架专用源码文件。默认将 `vendor`、构建产物和其他非 PHP 文件标记为排除项；ZIP 路径穿越、符号链接、加密条目、压缩炸弹和超限内容会被拒绝。

- `GET /snapshots` → 摘要列表。
- `GET /snapshots/{id}` → 完整 `Snapshot`。
- `GET /snapshots/{id}/source?path=&start=1&end=200` → 原始源码行。

`Snapshot`：

```text
{id,name,created_at,archive_sha256,source,immutable:true,
 files:[{path,sha256,size,line_count,is_php,excluded,exclude_reason,parse_errors}],
 units:[{id,file_path,start_line,end_line,symbol,kind,priority,slice_index,slice_count,...}],
 warnings:[]}
```

### 创建目标审计

`POST /runs`：

```json
{
  "snapshot_id": "...",
  "scope": ["src/auth.php", "public/index.php"],
  "budgets": {"responses": 8, "tools": 16, "seconds": 300},
  "task": {
    "objective": "确认未认证管理路由及其源码证据",
    "success_criteria": "每条结论给出原始行号、路由和中间件判断；否则说明未决原因",
    "max_iterations": 3,
    "max_total_attempts": 24,
    "max_workers": 2,
    "stop_on_achieved": true,
    "require_poc": false
  }
}
```

`scope` 在目标任务中可省略，服务会冻结所有默认项目 PHP 文件；前端默认显式发送该范围。`vendor`、构建产物等目录中的 PHP 源码默认不选，但可在 `scope` 中显式加入；非 PHP 文件不能加入范围。目标任务不能携带 `prompt_id`。`scope`、任务文本、预算和队列顺序都在创建时冻结。目标文本中出现的文件路径和代码标识会影响工作项顺序，固定 SQL/XSS/命令执行优先级不会进入目标任务。

`TaskSpec`：

```text
{objective,success_criteria,max_iterations:1..8,max_total_attempts:1..128,
 max_workers:1..4,stop_on_achieved,require_poc}
```

`require_poc=false` 适用于源码事实、架构、配置和边界审计。设为 `true` 时，每条 `achieved` 发现都必须带可人工复核的 POC；服务不会执行 POC。

旧的固定 Prompt 审计仍可通过 `{snapshot_id,scope,prompt_id}` 创建，用于读取历史实验记录；默认工作台不展示该入口。

- `GET /runs` → 运行摘要。
- `GET /runs/{id}` → `{run,units,goals,work_items,findings,metrics,attributions}`。
- `POST /runs/{id}/cancel` → 取消待运行或运行中任务。

目标任务的 `Run.status` 可能是 `pending`、`running`、`completed`、`unreachable`、`inconclusive`、`cancelled`、`interrupted` 或 `failed`。`unreachable` 只在所有工作项正常结束或耗尽次数、且无受阻项时产生；缺失源码、模型/预算失败、取消和中断不会被转换为“不可达”。

## 多 worker 队列与结果

`Goal` 保存一个运行的目标状态。`TaskWorkItem` 保存一个冻结源码单元的工作状态，`TaskWorkAttempt` 追加保存每一轮：

```text
Goal {id,run_id,objective,success_criteria,status,attempts,max_iterations,max_total_attempts,...}
TaskWorkItem {id,goal_id,unit_id,summary,focus,priority,state,attempt,max_attempts,
              claimed_by,result,error,attempt_history:TaskWorkAttempt[]}
TaskWorkAttempt {work_id,attempt,worker_id,outcome,state,result,usage,seen,error,created_at}
```

worker 通过原子租约领取工作项。`achieved`、已验证的发现、工作项结算和目标状态在一个 SQLite 事务中提交。`continue` 只会重试同一工作项；`blocked` 会使最终状态成为 `inconclusive`。每次工具调用都受运行冻结的 `scope` 限制，不能读取范围外文件。

目标发现使用通用结构，不强制伪造漏洞链：

```text
TaskFinding {title,kind="source_observation",summary,evidence,
 severity?,input_source?,propagation?,dangerous_operation?,protection?,
 preconditions?,poc?,remediation?}
```

`kind` 可为 `source_observation`、`data_flow`、`security_boundary`、`vulnerability` 或任务定义的其他短名称。同一工作项可提交多条独立引用的发现；每条引用都要在快照内且已被该 worker 实际读取。

## 执行轨迹

`GET /runs/{id}/events?after=0` 是持久化 SSE。服务先将事件写入 SQLite，再推送；客户端应使用 `Last-Event-ID` 或 `after` 续传并以事件 ID 去重。`GET /runs/{id}/event-log?after=0` 返回 JSON 回放。

目标任务事件包括：

```text
task_coordinator_started, task_plan_created,
task_work_started, task_work_requeued, task_work_completed,
tool_call, tool_result, task_assessment,
task_goal_met, goal_unreachable, goal_inconclusive
```

所有 worker 工具事件带 `work_id`、`worker_id`、`attempt`。`tool_call` 和 `tool_result` 使用同一 `call_id` / `span_id` 配对，结果携带状态、受限预览、已读范围、用量和 `duration_ms`。`task_assessment` 包含 `outcome`、`summary`、`rationale`、`next_focus`、`missing_context` 和经解析的源码引用。

`rationale` 是模型生成的、可审计的简短依据摘要，必须关联展示过的源码事实；不是模型内部思维链。系统不会保存或返回 provider thinking delta、隐藏推理或 API 密钥。

## 发现、人工复核与导出

- `GET /findings/{id}` → 发现及人工复核记录。
- `GET /findings/{id}/poc` → 原样下载已存 POC；没有 POC 时返回 404。
- `POST /findings/{id}/verifications` → `multipart/form-data`，字段 `record`（JSON）和可选 `files`。带 POC 的漏洞发现确认或排除需要成功执行、环境、命令和对照观测；确认还需要附件。没有 POC 的通用源码发现可用人工复核说明确认或排除，无需伪造攻击执行记录；证据校验未通过的源码结论不能被确认。
- `GET /runs/{id}/report?format=markdown|json|zip` → 审计报告、原始结果或证据包。

自定义目标任务的统计 `truth_status=goal_task_not_comparable`、`evaluation=null`，不会套用固定三类漏洞的 TP/FP/FN/TN 或 Recall 矩阵。

## 配置

- `GET /config` → 不含密钥的模型与预算状态。
- `POST /config/check` → 发送最小真实模型请求以确认连接。

模型密钥仅由服务端环境变量读取，不下发浏览器、不写入快照、事件、报告或证据包。
