# Lab30 本地部署与网络绕行记录（2026-10-26）

> 本文记录在受限网络环境中还原仓库标准 POC 部署的完整过程，保证他人可在同样环境下复现。
> 所有命令均在 WSL2（Ubuntu-20.04，用户属 `docker` 组，无 root/sudo）内执行。

## 1. 基线与分支

- 远端仓库：`git@github.com:Luchutong/llm-vuln-audit.git`
- 基线提交：`main` 分支 `bc12280d5f5cb4084cedc8c93fc51e4c85f34e4a`
  （`fix(prompt): bound comparison budgets and restore live feedback`）
- 工作分支：`test/lab30-full-audit-and-prompt-comparison`，全部实验产物只提交到该分支。
- 靶场源码 ZIP 的 SHA-256 与 `docs/lab30-environment.md` 记录一致：
  `67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c`

## 2. 工具链（用户态安装，无需 sudo）

| 组件 | 版本 | 安装方式 |
| --- | --- | --- |
| CPython（uv 托管） | 3.12.15 | `uv python install 3.12` |
| uv | 0.13.5 | astral 官方脚本，装于 `~/.local/bin` |
| Node.js | v22.20.0（满足前端 ≥22.18） | npmmirror 官方 tarbar 解压到 `~/.local/node` |
| Docker Compose 插件 | v5.6.1 | GitHub release 二进制 → `~/.docker/cli-plugins` |
| Docker Buildx 插件 | v0.23.0 | `download.docker.com` 的 `docker-buildx-plugin` deb，`ar x` 解包后取二进制（无需 root） |
| Docker Engine | 26.1.3（宿主既有，dockerd 内置 BuildKit v0.13.2） | 系统自带 |

后端依赖：`uv sync --locked`（61 个包，锁定文件未改动）。
前端依赖：`npm install`（registry 指向 npmmirror；npm 对 `package-lock.json` 的无害改写已 `git checkout` 还原，提交中不含锁文件漂移）。

## 3. 受限网络与镜像获取

本机 Docker Hub（`registry-1.docker.io`）直连超时，且 dockerd 预置的三个 registry mirror
（含 `hub-mirror.c.163.com`）域名已失效、DNS 无法解析；无 sudo 权限修改 `/etc/docker/daemon.json`。
采用以下绕行，**基础镜像内容与仓库 Dockerfile 中 digest 锁定的镜像逐字节一致**：

1. 通过可达的 `docker.m.daocloud.io` 显式前缀拉取四个基础镜像，再 `docker tag` 回仓库引用的本地名称：
   - `mariadb:11.4@sha256:250e1609…`（327 MB）
   - `php:8.4-apache-bookworm@sha256:e653ff90…`（511 MB）
   - `python:3.12-slim-bookworm@sha256:34386ef0…`（131 MB）
   - `python:3.12-slim-bookworm` 浮动标签（124 MB，relay 使用）
2. BuildKit 前端镜像 `docker/dockerfile:1` 同样经 daocloud 预拉取并打本地标签，
   消除 `poc_runner/Dockerfile` 首行 `# syntax=docker/dockerfile:1` 的外网依赖。
3. BuildKit 在 digest 元数据阶段仍强制查询失效 mirror。最终由 `docker compose up`
   的标准 BuildKit 流程完成全部镜像构建（基础层全部命中本地内容寻址存储，
   仅执行 Dockerfile 内的 apt/pip/Playwright 步骤，deb.debian.org、pypi.org、
   cdn.playwright.dev 在容器网络内均可达）。运行中的 `poc-runner` 容器即该规范流程产物，
   未使用任何临时改写的 Dockerfile；过程中产生的临时 `*.Dockerfile.local` 已全部删除，
   `git status` 干净。

## 4. 服务拓扑与端口

`COMPOSE_PROFILES=poc` 下五个容器（见 `01-environment/compose_ps.txt`）：

| 容器 | 镜像 | 作用 | 宿主可达性 |
| --- | --- | --- | --- |
| lab30-db | vuln-audit-lab30-db:1.0.0 | MariaDB 11.4 | 仅内部网络 |
| lab30-fixtures | vuln-audit-lab30-fixtures:1.0.0 | 测试夹具服务（8080/8082） | 仅内部网络 |
| lab30 | vuln-audit-lab30-web:1.0.0 | Lab30 商城（PHP/Apache） | 127.0.0.1:18880 |
| poc-runner | vuln-audit-poc-runner:latest | 隔离 POC 执行器（Python/PHP/Chromium），无发布端口 | 仅内部网络 |
| poc-runner-dev | vuln-audit-poc-relay:local | Bearer 令牌中继 | 127.0.0.1:18089 |

宿主机进程：

- 后端 uvicorn：`127.0.0.1:8899`，环境变量 `POC_ENABLED=1`、
  `POC_RUNNER_URL=http://127.0.0.1:18089`；
- 前端 Vite dev server：`127.0.0.1:5173`，`VITE_API_TARGET` 指向上者。

## 5. 验收结论

`scripts/verify_lab30_environment.py` 经 `docker compose exec poc-runner` 执行，
**17 项检查全部 PASS**（完整输出见 `01-environment/verify_lab30_environment.txt`），
覆盖：目标白名单、隔离 verification context 互斥、成员/operator 登录、HTTP 首跳重定向观测、
Python/PHP 隔离作业、Chromium 会话复用与真实 XSS 弹窗判别及截图存证、guest 会话隔离、
作业幂等重放、context 关闭释放。

## 6. 保密与提交边界

- `.env`（含随机 `POC_RUNNER_TOKEN` 与 LLM 密钥）被 `.gitignore` 忽略，**不入库**；
- `data/`、`.run/`、`*.log`、`datasets/**/score_*.json`、`.venv`、`node_modules` 均不入库；
- 入库的运行记录统一放在本 `deliverable/` 目录，日志使用 `.txt/.md/.json` 命名。
