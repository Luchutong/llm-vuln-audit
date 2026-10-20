# poc-runner

隔离的 POC 执行服务：审计应用通过 HTTP 请求它，由它在本地 DVWA 靶场中运行模型产出的
POC 脚本，并把有界输出、退出码和产物清单回传。审计应用自身不安装 PHP、不执行任何脚本，
也不持有 Docker socket。

## 它做什么

| 接口 | 作用 |
|---|---|
| `GET /healthz` | 无需令牌；返回服务版本、Qt 环境与 `php`/`python`/浏览器能力 |
| `POST /v1/targets/dvwa/prepare` | 等待靶场、登录、重置数据库、设置安全级别，会话 cookie 只留在 runner 内存 |
| `GET /v1/targets/dvwa/status` | 可达性、认证状态、当前安全级别 |
| `POST /v1/jobs` | 在白名单语言（`php`/`python`）中执行一段脚本 |
| `GET /v1/jobs/{id}` | 作业状态与有界 stdout/stderr |
| `GET /v1/jobs/{id}/artifacts/{name}` | 取回脚本写出的产物（单文件 ≤1 MiB，总计 ≤5 MiB） |
| `POST /v1/http` | 对 DVWA 白名单路径发起 GET/POST 观测 |
| `POST /v1/browser/check` | Chromium 加载白名单路径，返回标题、对话框、console error 与截图 |

除 `/healthz` 外都需要 `Authorization: Bearer $POC_RUNNER_TOKEN`。

`/v1/browser/check` 复用 `prepare` 建立的登录会话：cookie 按目标 URL 注入 Chromium，
因此能直接打开需要登录的 DVWA 漏洞页面并捕获 `alert`。会话 cookie 只存在于 runner
内存，既不会返回给模型，也不会写入作业目录。

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

runner 只连接 `poc-target`（DVWA）与 `poc-control`（审计应用）两个 `internal` 网络，
其中没有任何一条通往公网。脚本环境里的代理变量被显式清空，避免把「目标内执行」变成
一次外连尝试。

## 本地构建与手工验证

```bash
cd ..
cp .env.example .env   # 填写 LLM_*、POC_RUNNER_TOKEN、DVWA_DB_* 密码
docker compose --profile poc up --build -d dvwa-db dvwa poc-runner
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
