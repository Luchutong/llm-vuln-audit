# poc-runner

隔离的 POC 执行服务：审计应用通过 HTTP 请求它，由它在本地 Lab30 靶场中运行模型产出的
POC 脚本，并把有界输出、退出码和产物清单回传。审计应用自身不安装 PHP、不执行任何脚本，
也不持有 Docker socket。

## 它做什么

| 接口 | 作用 |
|---|---|
| `GET /healthz` | 无需令牌；返回服务版本、目标与 `php`/`python`/浏览器能力 |
| `POST /v1/verification-contexts` | 绑定 `target/run_id/finding_id`，独占靶场；可由宿主提供 `context_id` 幂等重试创建 |
| `DELETE /v1/verification-contexts/{id}` | 停止接收新动作；已有动作结束后释放靶场 |
| `GET /v1/verification-contexts/{id}` | 只读查询上下文状态与未完成作业数；未知上下文返回404（视为已关闭） |
| `POST /v1/targets/lab30/prepare` | 根据 `context_id/identity` 登录，核对 `/account/me.php`，不重置数据 |
| `GET /v1/targets/lab30/status` | 可达性、认证状态、登录会员 |
| `POST /v1/jobs` | 在白名单语言（`php`/`python`）中执行一段脚本 |
| `GET /v1/jobs/{id}` | 作业状态与有界 stdout/stderr |
| `GET /v1/jobs/{id}/artifacts/{name}` | 取回脚本写出的产物（单文件 ≤1 MiB，总计 ≤5 MiB） |
| `POST /v1/http` | 对 Lab30 白名单路径发起 GET/POST 观测 |
| `POST /v1/browser/check` | Chromium 加载白名单路径，返回标题、对话框、console error 与截图 |

除 `/healthz` 外都需要 `Authorization: Bearer $POC_RUNNER_TOKEN`。

所有 prepare/status/作业/HTTP/浏览器调用均要求有效的 `context_id`，没有上下文的旧客户端会被拒绝。
`identity` 可选 `guest/alice/bob/operator/admin`，默认 Alice；每个上下文、每个身份使用独立 Cookie。
`/v1/browser/check` 复用对应上下文和身份的登录会话：cookie 按目标 URL 注入 Chromium，
因此能直接打开需要登录的 Lab30 漏洞页面并捕获 `alert`。会话 cookie 只存在于 runner
内存，既不会返回给模型，也不会写入作业目录。

会员必须匹配已配置用户名及固定角色（Alice、Bob 为 `customer`），访客必须在会员接口得到401。
角色不符是授权前提，始终返回 `identity_or_role_mismatch`。余额、tier、昵称、主页等变化只作为
本次上下文内的 `state_drift` 观测返回，不阻断后续实验；只有显式 `expected_state` 不符才返回
`required_account_state_mismatch`。`id` 按整数比较，`balance` 按十进制数比较（`100`、`100.0`、
`"100.00"` 等价），其余字段按字符串精确比较。同一上下文只能追加断言，不能改写或清空既有断言。
每个动作前重查身份及账号前提，结束后返回 `precondition/postcondition/state_changes`。
前提不符返回 `precondition_failed`，不执行脚本或发送实验请求。靶场数据不会因会话隔离而复原；
需要从种子开始时由宿主在上下文之间执行 `scripts/reset_lab30.sh`（runner 自己从不重置靶场）。
缓存会话在会员接口返回 401 时会重新登录一次并重试；主动登出（Cookie 已清空）不会触发重登。

脚本环境中的 `LAB30_USER/LAB30_PASSWORD/LAB30_IDENTITY` 仅对应选定身份，不继承宿主凭据。
Alice 沿用 `LAB30_USER/LAB30_PASSWORD`；其他身份分别使用 `LAB30_BOB_*`、`LAB30_OPERATOR_*`、`LAB30_ADMIN_*`。

脚本提交可提供稳定 `job_id`，作业在执行前登记为 `running`，重复同一请求只返回原作业。
宿主请求超时应通过 `GET /v1/jobs/{id}` 查询，不重新执行。HTTP、浏览器同样登记作业，HTTP 状态码与作业执行状态分别保留。
关闭尚未知晓的宿主上下文 ID 会持久保存取消标记，阻止超时创建请求迟到后重新占用靶场；取消标记保留24小时。
正常退出及超时均清理整个作业进程组，防止后台子进程跨实验继续修改靶场。
无法确认进程组结束时，作业保留 `unresolved`、`process_confirmed_stopped=false`，靶场租约不会释放。

runner 进程重启后，租约日志中未关闭的上下文标为 `unresolved`，旧上下文及新实验均不能执行。
应先确认旧进程及子进程结束，再人工重新创建 runner 容器以重建 `/tmp`，并重置或核实商城；不得只重提交丢失的作业。
健康接口的 `capabilities.verification_contexts=true` 用于宿主检查版本兼容性。

## 限额

- 脚本 ≤32 KiB；stdout ≤64 KiB；stderr ≤32 KiB；单作业 ≤120 秒（默认 30 秒）。
- 子进程设置 CPU/地址空间/文件大小/句柄 rlimits，超时按进程组 `SIGKILL`。
- 全局并发 2；作业目录 900 秒后回收。
- 容器：只读根文件系统、`/tmp` tmpfs、`cap_drop: ALL`、`no-new-privileges`、
  非 root `10002`、内存/CPU/PID 上限、无发布端口、无宿主机挂载、无外网路由。

## 威胁模型（如实说明）

这些措施缩小攻击面，**不是数学意义上的沙箱**。如果模型产出的脚本能利用容器运行时或
内核漏洞逃逸，本服务无法阻止；因此它只允许在一次性、本地、已授权且不承载其它数据的
Docker 主机上运行，并且不应与审计数据或模型凭据放在同一信任域之外。

runner 只连接 `poc-target`（Lab30）与 `poc-control`（审计应用）两个 `internal` 网络，
其中没有任何一条通往公网。脚本环境里的代理变量被显式清空，避免把「目标内执行」变成
一次外连尝试。

## 本地构建与手工验证

```bash
cd ..
cp .env.example .env   # 填写 LLM_*、POC_RUNNER_TOKEN、LAB30_DB_* 密码
docker compose --profile poc up --build -d lab30-db lab30-fixtures lab30 poc-runner
docker compose exec app python - <<'PY'
import urllib.request, json, os
request = urllib.request.Request(
    "http://poc-runner:8080/healthz", headers={"Accept": "application/json"}
)
print(json.load(urllib.request.urlopen(request, timeout=5)))
PY
```

`healthz` 的 `ok` 为 `true` 才表示令牌已配置。浏览器不可用时返回
`capabilities.browser=false`，XSS 类结论只能记为 `inconclusive`。`POC_BROWSER` 是
**构建参数**：修改后需要 `docker compose --profile poc build poc-runner` 重新构建镜像，
只改 `.env` 再 `up` 不会替换已有的浏览器层。

完整构建、数据重置和真实浏览器验收见 [Lab30 环境说明](../docs/lab30-environment.md)。
