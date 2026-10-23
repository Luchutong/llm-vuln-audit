# Linux 迁移指南

整套系统（审计应用、场景 Prompt 工具链、数据集与评分脚本、POC 靶场）均以 Linux 为目标运行环境。本指南给出从 Windows 检出到 Linux 服务器/WSL2 的两条迁移路径，以及迁移时已处理/需注意的事项。

## 路径 A：Docker Compose（推荐，无需装 Python/Node）

镜像为多阶段构建（node:22-alpine 构建前端 → python:3.12-slim + uv 锁定后端依赖），`scripts/` 与 `datasets/` 已随镜像内置。

```bash
# 1. 迁移代码（整个目录打包即可，.dockerignore 会挡住垃圾）
scp -r llm-vuln-audit-main/ user@server:/opt/   # 或 git clone

# 2. 配置
cd /opt/llm-vuln-audit-main
cp .env.example .env
# 必填：LLM_MODEL / LLM_BASE_URL / LLM_API_KEY
# 可选：COMPOSE_PROFILES=poc 启用本地 Lab30 靶场 + 隔离 poc-runner
#       POC_RUNNER_TOKEN=$(openssl rand -hex 32)

# 3. 构建并启动
docker compose up -d --build
docker compose logs -f app        # 等待 healthcheck 通过

# 4. 注册分场景 Prompt（宿主机即可，无需进容器）
python3 scripts/register_scenarios.py http://127.0.0.1:8899
#   无宿主机 Python 时：docker compose exec app python /app/scripts/register_scenarios.py http://127.0.0.1:8899

# 5. 数据集核对 + 评分（--out 指到可写目录）
python3 scripts/verify_lab30_dataset.py <靶场源码.zip> datasets/lab30-shop/ground_truth.json
python3 scripts/score_dataset.py --api http://127.0.0.1:8899 --run <run_id> --check-severity --check-cvss --out /tmp/score.json
```

要点：

- 评价以 CVSS 3.1 基础分为准；文字评级按基础分区间校验，未提供数值评分或向量时明确标为缺失。不会从 `severity` 猜分，也不将未独立评估的时序、环境分数作为主评分。字段与输出见 [数据集说明](../datasets/lab30-shop/README.md)。
- 数据持久化在 named volume `audit-data`；`AUDIT_PORT` 可改端口（默认只绑 127.0.0.1，对外暴露请自行加反代/改端口绑定）。
- 模型端点在宿主机时，容器内可用 `http://host.docker.internal:<port>`（compose 已配置 host-gateway）。
- `COMPOSE_PROFILES=poc` 时会额外启动 Lab30 + MariaDB + poc-runner；三个内部网络互相隔离，runner 无外网、无宿主挂载。

## 路径 B：裸机 venv（开发/调试）

要求：Python ≥ 3.12、curl；前端构建另需 Node 20+。

```bash
./scripts/setup_linux.sh --with-frontend   # 幂等：CRLF 自检 + uv sync + 前端构建 + .env 引导 + 导入自检
./scripts/start.sh                          # 后端 127.0.0.1:8899 + 前端 5173
```

`start.sh` 本身就是 Linux 实现（/proc、ss、uv sync），并支持 `--poc`（用 compose 拉起靶场）与 `--skip-install`。

## 迁移检查清单（Windows → Linux）

| 检查项 | 状态 | 说明 |
|--------|------|------|
| 脚本换行符 | ✅ 已核查 | 全仓 `.sh/.py/.yaml/.toml/.ts` 无 CRLF；`setup_linux.sh` 内置自检，发现即转 LF |
| 可执行位 | ✅ 已处理 | Windows 文件系统不带 +x；`setup_linux.sh` 会 `chmod +x scripts/*`；用 git 迁移时确认 `git update-index --chmod=+x` |
| Windows-only 代码 | ✅ 无残留 | `scripts/start.sh` 负责本地服务及 Lab30 Compose 环境；`poc_runner` 的 `resource` 模块在 Linux 容器内运行，其测试在非 Linux 上按平台跳过，Linux 上正常执行 |
| 镜像内容 | ✅ 已补齐 | Dockerfile application 阶段新增 `COPY scripts/` 与 `COPY datasets/`（只读）；容器内评分请用 `--out` 指到可写目录（未指定且目录只读时脚本自动退回当前工作目录） |
| 依赖锁定 | ✅ | 后端走 `uv sync --frozen`（uv.lock），前端走 `npm ci`（package-lock.json） |
| 数据与密钥 | ⚠️ 需人工 | `.env` 不入库不入镜像（.dockerignore 已挡）；密钥只在目标机的 `.env` 里填；`data/` 目录不建议从 Windows 拷贝（容器用 named volume 更干净） |

## WSL2 说明（在本 Windows 机器上跑 Linux）

本机当前状态：Docker 未安装；WSL 被安全策略拦截。如需在本机跑 Linux 环境和安全中心解除 `wsl.exe` 拦截后：

```powershell
wsl --install -d Ubuntu-24.04
```

进入 WSL 后按路径 A（Docker Desktop WSL2 后端）或路径 B 操作，目录建议放在 WSL 文件系统内（`~/`）而非 `/mnt/c/`，后者 I/O 慢一个数量级且权限位不生效。

## 已知的非迁移项

- `docs/` 截图、`deliverable/` 报告、根目录的实验 docx 与 Linux 运行无关，无需迁移。
- `frontend/.npm-cache`、`backend/.venv` 属于本机构建产物，迁移时不要拷贝（`.dockerignore` 已排除；裸机路径由 `setup_linux.sh` 重新生成）。
