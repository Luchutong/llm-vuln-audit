# Lab30 商城自动验证环境

自动验证只支持 Lab30 拾光商城。审计仍可接受任意源码 ZIP，其他源码的 POC 状态为不适用。旧靶场的历史审计与附件继续保留，旧目标名不能再提交到 runner 执行。

## 构建与启动

仓库的 `labs/lab30` 来自已准备好的 `lab30-shop-1.0.0-source.zip`，原包 SHA-256 为 `67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c`。商城实现与原包一致，答案不在构建上下文中。PHP、MariaDB 和合作服务基础镜像沿用原包固定 digest。

本地开发：

```bash
./scripts/start.sh --poc
```

完整容器部署：

```bash
docker compose --profile poc up --build -d --remove-orphans
```

`poc` profile 启动 `lab30-db`、`lab30-fixtures`、`lab30` 和 `poc-runner`。`--remove-orphans` 停止本 Compose 项目已移除的旧服务，不删除数据卷。构建与启动不再拉取或启动旧靶场镜像。旧 `POC_TARGET` 环境变量不改变新任务的 Lab30 目标。

- 商城：`http://127.0.0.1:18880`；端口通过 `LAB30_PORT` 设置。
- runner 访问：`http://lab30`，只在内部网络中访问商城。
- 宿主开发通过 `poc-runner-dev` 的 `127.0.0.1:18089` 转发访问 runner（`POC_RUNNER_DEV_PORT` 可改端口）。转发服务复用 runner 的 Python 基础镜像在本地构建，无额外软件依赖；健康检查实际穿透至 runner。runner 的令牌认证与内部网络保持不变。
- 合作服务以 `fixtures` 为网络别名，保留原源码的本地合作内容和内部库存服务。
- 数据库仅与商城共享内部网络；runner 不连接数据库、不挂载审计库、无模型凭据，也不发布端口。
- `LAB30_DB_PASSWORD` 与 `LAB30_DB_ROOT_PASSWORD` 设置商城数据库凭据；原有数据卷更换密码需按数据库运维流程操作。
- runner 的 `LAB30_USER/LAB30_PASSWORD` 默认普通会员 `alice/Alice123!`；商城原始数据还提供 bob、operator 和 admin 角色。

关闭 POC 环境时清空 `COMPOSE_PROFILES`，或启动时省略 `--poc`。只有构建镜像不会创建运行服务。

若启动时出现 `proxyconnect ... 127.0.0.1:7890 ... connection refused`，表示 Docker daemon 配置的代理未运行。新转发服务不再依赖 `alpine/socat`；已有 Python 基础镜像时可直接本地构建。缺失基础镜像或其它构建依赖时，仍需恢复 Docker 的镜像网络或代理。若已有另一套商城占用 18880，可用 `LAB30_PORT=18882 ./scripts/start.sh --poc` 为本项目选择其他端口。

## 识别、登录与证据

上传源码按同一应用根下的登录、会员、钱包、运营模板、合作服务和初始化文件联合识别，不依靠 ZIP 名称。完整源码包和 app 子目录源码包都能识别。已有源码库在服务启动时更新识别元数据，保留项目 ID、ZIP ID、最近活动顺序和历史审计。

runner 先获取绑定审计任务与发现的独占验证上下文，准备阶段检查商城 `health.php` 的 `ok`，再 POST `/auth/login.php`，最后通过 `/account/me.php` 核对实际账号及角色。访客不登录，会员接口必须返回401。登录失败、角色或必要账号前提不符时不宣布准备完成。

- HTTP 观测和 Chromium 使用对应验证上下文及身份的独立会话，支持访客、Alice、Bob、运营员和管理员；并发审计不会同时占用同一靶场。
- 独立 Python/PHP 脚本从子进程环境读取 `LAB30_URL/LAB30_USER/LAB30_PASSWORD`，自行建立会话；原始认证信息不会写入脚本。
- 登录表单只有用户名与密码；业务表单可能要求名为 `csrf` 的字段，Agent 按源码及真实表单取值。
- 未登录会员页可能返回401；HTTP 观测保留首个响应，不跟随重定向。
- 源码 `app/public` 映射到 Web 根；内部 `app/src` 文件不作为可直接访问的 HTTP 入口。
- XSS 需 Chromium 实际执行结果；HTTP 反射和脚本退出成功都不能直接表示验证成功。

准备阶段只刷新会话，不自动重置商城；需要恢复初始数据时，在审计间隙执行下面命令。该命令会清空商城业务数据与会话，但不改动审计库：

```bash
docker compose --profile poc exec lab30 php /var/www/shop/bin/reset.php
```

每条实验前后保存身份、角色及账号变化，观测到的持久状态污染会阻断后续实验。准备接口可明确余额等账号字段断言；
会话隔离不代表数据库和文件已复原。runner 进程重启遗留的上下文保持未决，确认旧作业结束后需人工重新创建 runner，
再重置或核实商城。新的宿主要求 runner 健康接口提供 `verification_contexts` 能力，升级时应重新构建 runner。

## 环境验收

对一次性测试栈执行以下检查；它会创建 POC 作业并访问测试页面，不调用模型、不写审计记录：

```bash
docker compose --profile poc exec -T poc-runner python - < scripts/verify_lab30_environment.py
```

检查包括旧目标拒绝、真实会员登录、HTTP 会话、重定向、Python/PHP 脚本环境、浏览器会话、XSS 对照和截图证据。

完整审计评测使用：

```bash
cd backend
uv run python ../scripts/run_lab30_e2e.py --zip /path/lab30-shop-1.0.0-source.zip --poc-mode auto
```

这会调用模型并产生审计任务；仅环境验收时无需执行。`--poc-mode required` 要求可用环境与有效验证；脚本按运行终态结束轮询，并输出 CVSS 3.1 对比结果。
