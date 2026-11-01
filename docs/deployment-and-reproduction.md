# 部署与结果复现

从仓库完整克隆即可部署应用、Lab30 与隔离 runner；源码 ZIP、靶场代码、固定依赖、评分真值及脱敏归档输入均在 Git 中。模型 API 和个人审计数据库由部署方提供。以下命令均从仓库根目录执行。

## 1. 获取代码与前置条件

```bash
git clone --branch main https://github.com/Luchutong/llm-vuln-audit.git
cd llm-vuln-audit
git rev-parse HEAD
cp .env.example .env
```

本地开发需要 Linux/Bash、`setsid`、Python 3.12+、uv 和 Node.js 22.18+（测试依赖 Node 原生 TypeScript 支持）。本次使用 uv 0.11.22、Node 24.16.0。容器部署需要 Docker Engine、Compose v2 和 BuildKit；本次在 Linux x86_64 上验证。首次构建需能下载 Python/npm 依赖、基础镜像和 Chromium，runner 构建较大。其他架构需自行核验 SDK 内置 CLI 和浏览器。

仓库无需 Git LFS 或子模块，也无需从其他分支取靶场。首次可先不填写任何模型密钥，验证应用启动与离线评分。`.env`、`data/`、`.run/` 均不随 Git 发布；`.run` 也不进入 Docker 构建上下文。

## 2. 最小 Docker 部署

```bash
# 只启动应用，不启动靶场或 runner，不调用模型。
COMPOSE_PROFILES= docker compose up --build -d app
curl --fail http://127.0.0.1:8899/api/config
curl --fail http://127.0.0.1:8899/api/projects
```

访问 <http://127.0.0.1:8899>。默认自动导入内置 Lab30 ZIP，源码包库应有一个项目；尚无审计任务属正常。`LAB30_SEED=0` 可以保留空库。端口占用时使用 `AUDIT_PORT=8900`，容器内仍为 8899。

`audit-data` 卷保存数据库、源码快照及密钥文件。升级使用 `git pull --ff-only` 后 `docker compose up --build -d app`；先备份数据卷，不使用 `down -v` 清理有价值的数据。`docker compose down` 停止服务并保留卷。

## 3. Lab30、登录与 runner

在 `.env` 中把 `POC_RUNNER_TOKEN` 改为随机值（如 `openssl rand -hex 32` 的输出），填写本机 Lab30 数据库口令。示例帐号是教学靶场种子，不用于其他系统。

```bash
docker compose --profile poc up --build -d
docker compose --profile poc ps
curl --fail http://127.0.0.1:18880/health.php
# 在 runner 内验证 HTTP、脚本、浏览器、身份隔离及幂等作业；不请求模型。
docker compose --profile poc exec -T poc-runner python - \
  < scripts/verify_lab30_environment.py
```

环境验收脚本会创建少量受控实验作业；请用于新建的专用靶场。成功时最后显示 `PASS ... real Lab30 environment checks; no model or audit records`。

商城地址 <http://127.0.0.1:18880>，登录入口 `/auth/login.php`。初始身份为 `alice / Alice123!`、`bob / Bob123!`、`operator / Ops123!`、`admin / Admin123!`。runner 使用对应独立会话，受保护操作必须先准备相应身份；普通用户登录成功不表示具备 operator/admin 权限。密码配置应与靶场种子一致，修改 runner 环境变量不会自动修改数据库用户。

新任务默认 `poc_mode=off`，启动 runner 不会替用户开启验证。`require_poc` 只要求附带脚本；`auto` 表示环境可用才执行；`required` 表示至少一条当前有效动态验证才能支撑目标达成，穷尽与终审约束仍独立执行。

### 复位边界

Lab30 是可修改业务状态的靶场。需要清理现场时，先确保没有验证在执行，再从宿主运行 `./scripts/reset_lab30.sh`；此命令会重置业务数据、帐号、会话和运行文件。

本地 `./scripts/start.sh --poc` 自动设置逐漏洞复位命令。完整 Compose 应用不持有 Docker socket 或 Docker CLI，不能在 app 内调用该宿主复位脚本；默认 `POC_RESET_BETWEEN_FINDINGS=0`。需要严格逐项复位的完整闭环实验请使用本地后端模式，或另行提供受控的外部复位服务，不能声称两种部署的复位能力完全相同。

## 4. 本地开发

```bash
./scripts/start.sh
# 需要靶场与自动逐项复位支持时：./scripts/start.sh --poc
```

脚本按 `backend/uv.lock` 和 `frontend/package-lock.json` 安装依赖，安装 SDK extra，但不会隐式开启 SDK 或自动验证。前端 <http://127.0.0.1:5173>、后端 <http://127.0.0.1:8899>。用 `Ctrl+C` 停止前后端；日志在 `.run`。`--poc` 启动的容器可用 `docker compose --profile poc down` 单独停止。

手动启动请保持后端进程的工作目录为仓库根目录，避免相对 `AUDIT_DATA_DIR=./data` 变成另一个数据库：

```bash
uv sync --project backend --frozen --extra poc-claude --extra dev
uv run --project backend --frozen --extra poc-claude uvicorn audit.app:app --host 127.0.0.1 --port 8899
# 在另一个终端
cd frontend
npm ci
npm run dev
```

## 5. Claude SDK POC（可选）

默认 `POC_RUNTIME=legacy`。复现 SDK 验证路径必须在 `.env` 中显式配置：

```dotenv
POC_RUNTIME=claude_sdk
POC_ENABLED=1
POC_CLAUDE_GATEWAY_ENABLED=1
POC_CLAUDE_MODEL=<提供商实际支持的模型 ID>
POC_CLAUDE_UPSTREAM_URL=<Anthropic Messages 协议根地址>
POC_CLAUDE_UPSTREAM_API_KEY=<自己的密钥>
```

源码审计的 `LLM_*` 使用 OpenAI 兼容协议；SDK 的上述上游使用 Anthropic Messages 协议，不能将 chat/completions 地址直接填入。安装的 SDK 为 0.2.174，内置 CLI 为 2.1.310。Compose 已传入 SDK/生成/上下文配置，并固定容器内网关为 `http://127.0.0.1:8899/api/internal/poc-gateway`、工作目录为 `/tmp/audit-poc-workspace`；主机端口变化不影响它们。

本地后端另需先创建仓库外的空目录并设置 `POC_CLAUDE_WORKSPACE`，以及与后端实际端口一致的 `POC_CLAUDE_GATEWAY_URL`。修改环境后重启服务，新任务才会冻结新策略。

```bash
# Compose：检查实际容器依赖和配置，不请求模型。
docker compose exec -T app python /app/scripts/check_claude_poc.py --require-ready
```

本地 `backend/.venv/bin/python scripts/check_claude_poc.py --require-ready` 只检查当前进程已导出的变量，**不加载 `.env`**。`ready_for_live=true` 仅证明本机配置检查通过；不证明真实上游可达、协议完全兼容或漏洞已证实。详细边界见 [POC 运行层](poc-runtime.md)。

## 6. 确定性复现：不需要 API、Docker 或历史数据库

```bash
python3 scripts/reproduce_release.py --out /tmp/lab30-score.json
```

脚本核对 7 份归档资产的 SHA-256、30 项 CVSS 3.1 真值与 43 处定位，然后用正式 `lab30-v2` 协议重算历史冻结的 23 条规范结论。预期 TP=22、D=0、U=1、FN=8、P=0.9565、R=0.7333、F1=0.8302。输入为脱敏的真实历史结论，不把官方答案当作模型发现。

归档材料位于 [2026-10-30 闭环交付](../deliverable/lab30-closure-2026-10-30/README.md)。最近一次“整体未决但已有证实漏洞”的故障与验收见 [未决修复记录](latest-pending-review-fixes.md)，可用下面的模拟测试重现收束与报告行为：

```bash
uv run --project backend --frozen --extra dev --extra poc-claude \
  pytest backend/tests/test_partial_review_delivery.py backend/tests/test_report_delivery.py -q
```

这些模拟结果验证框架行为，不应作为真实漏洞检出成绩。归档评分重算不会重放原来的 47 次 runner 作业。私人数据库、全部历史事件与模型密钥未发布，其他机器不会自动出现原机的历史运行页面。

## 7. 重新执行真实审计

填写自己的 `LLM_MODEL / LLM_BASE_URL / LLM_API_KEY`，重启应用，在“源码包库”选择内置 ZIP，创建独立任务。需要复现动态验证则先通过第 3、5 节验收，在新建页选择 `auto` 或 `required`。运行结束后分别下载“审计报告”“漏洞报告”和各条单独漏洞报告；整体未决时，终审已经接受的漏洞仍可导出，待终审不会冒充接受。

需要历史严格闭环配置时，使用本地 `--poc` 后端并显式运行：

```bash
uv run --project backend --frozen --extra poc-claude python scripts/run_lab30_e2e.py \
  --base http://127.0.0.1:8899 \
  --zip llm-vuln-audit-feat-lab30-shop/llm-vuln-audit-feat-lab30-shop/lab30-shop-1.0.0-source.zip \
  --scenario all --closure --out /tmp/lab30-new-score.json
```

此命令真实消费模型额度，并对专用靶场执行复位，可能运行数小时。先阅读脚本冻结的预算及 [闭环配置](lab30-closure-run.md)。模型版本、提供商实现、预算、策略、目标初始状态和随机输出都会影响结果；新运行不保证复现同样数量或文字。请保存本次提交号、源码哈希、冻结配置及导出，勿用旧评分代替本次结果。

## 8. 回归、备份与排错

```bash
uv run --project backend --frozen --extra dev --extra poc-claude pytest backend/tests/ -q
cd frontend
npm ci
npm test
npm run build
```

UI 模拟验收另需 Playwright/Chromium，可在前端开发服务启动后运行 `uv run --with playwright python scripts/ui_run_presentation_smoke.py http://127.0.0.1:5173` 与 `scripts/ui_report_delivery_smoke.py`；脚本使用模拟 API，不启动真实审计。

备份完整 `AUDIT_DATA_DIR`（含隐藏文件），尤其 `audit.db` 与用于模型档案解密的密钥文件；数据库单文件不足以恢复模型凭据。备份前停止应用，恢复前保留原副本。Docker 使用命名卷，`.env` 需独立保存，不能提交 Git。不同部署要使用不同 Compose project name、端口和数据卷。

常见问题：前端可用但无法开始审计时检查模型档案；POC 未执行时先看任务模式和 `/api/poc/readiness?snapshot_id=...`；SDK 不可用时看离线诊断及运行 readiness 事件；登录失败时检查对应角色的种子状态；环境检查通过但模型失败时检查真实上游协议和额度。不要通过反复暂停、继续绕过运行总预算，也不要把 HTTP 200 或脚本退出码 0 当成漏洞成立。
