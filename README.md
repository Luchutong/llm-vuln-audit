# PHP 源码目标审计工作台

这是一个面向受控环境的 PHP 白盒审计工具：**上传任意 PHP 源码 ZIP → 定义审计目标与验收条件 → 多 worker 审计 → 导出可复核结果**。

主流程不要求 DVWA、预设 Prompt 或固定漏洞类别。目标可以是漏洞路径、鉴权规则、敏感配置、危险依赖、路由覆盖、数据流或任意能由源码证据验证的事实。每次运行都会冻结源码快照、范围、目标、预算和工作队列；工具调用、源码引用、worker 尝试和模型给出的审计依据摘要均会持久化，刷新页面或重启服务后仍可回放。

模型的内部思维链不会被保存或展示。界面中的“审计依据摘要”是模型产出的、受源码行号约束的结论说明，结合工具轨迹与证据引用供人工复核。

## 快速开始

### 本地开发（一键启动）

```bash
cd /home/luchitong/work/vuln-audit
cp .env.example .env       # 配置 LLM_MODEL / LLM_BASE_URL / LLM_API_KEY
./scripts/start.sh
```

脚本会同步 Python 与 Node 依赖，并启动：

- 前端：<http://127.0.0.1:5173>
- 后端 API：<http://127.0.0.1:8899>

按 `Ctrl+C` 会同时停止两个进程，日志保存在 `.run/backend.log` 与 `.run/frontend.log`。依赖已安装时可使用 `./scripts/start.sh --skip-install`；端口冲突时可使用 `AUDIT_PORT=8900 WEB_PORT=5174 ./scripts/start.sh`。

也可以分别启动：

```bash
# 终端 1
cd backend
uv sync
uv run uvicorn audit.app:app --host 127.0.0.1 --port 8899

# 终端 2
cd frontend
npm install
VITE_API_TARGET=http://127.0.0.1:8899 npm run dev
```

### Docker Compose

默认 Compose 只启动通用审计应用，不挂载示例源码或靶机：

```bash
cp .env.example .env
# 填写 LLM_MODEL / LLM_BASE_URL / LLM_API_KEY
docker compose up --build
```

审计应用位于 <http://127.0.0.1:8899>。若端口已占用，可使用 `AUDIT_PORT=8900 docker compose up --build`。

### 环境变量

| 变量 | 说明 |
| --- | --- |
| `LLM_MODEL` | OpenAI 兼容模型名 |
| `LLM_BASE_URL` | OpenAI 兼容服务 API 根地址 |
| `LLM_API_KEY` | 仅由服务端读取，不返回浏览器、不写入数据库或报告 |
| `LLM_THINKING` | 默认 `disabled`；不采集或展示模型隐藏推理内容 |
| `AUDIT_DATA_DIR` | 数据目录，默认 `./data`（SQLite、不可变快照与证据） |
| `AUDIT_PORT` / `WEB_PORT` | 本地一键启动或 Compose 的监听端口 |

`AUDIT_MODEL` / `AUDIT_BASE_URL` / `AUDIT_API_KEY` 和 `OPENAI_*` 也可作为兼容别名。

## 使用流程

1. 在“审计任务”上传 PHP 源码 ZIP。导入器保留原始字节和哈希，并索引 `.php`、`.php3`–`.php8`、`.phps`、`.inc`、`.phtml` 文件；带 PHP 开始标记（含短标签）的无扩展名和框架专用文件也会被识别。它拒绝路径穿越、符号链接、加密条目和超限归档。
2. 选择待审计文件；默认选中 ZIP 中的项目 PHP 文件。第三方依赖与生成目录里的 PHP 文件会显式列为可选项，按需勾选后同样会冻结进本次范围；非 PHP 文件不会进入审计范围。
3. 填写任务目标和验收条件。例如：
   - “追踪上传入口到文件写入操作，确认是否存在未经路径规范化的可达写入路径。”
   - “列出所有无需认证即可访问的管理路由，并给出路由定义与中间件证据。”
   - “确认会话 cookie 的 `Secure`、`HttpOnly` 和 `SameSite` 配置来源。”
4. 设置每个工作项的最大轮次、任务总尝试上限、并发 worker 数，以及是否要求 POC。源码事实、配置或架构目标可关闭 POC；漏洞任务可要求 POC 作为达成条件。
5. 开始审计。协调器将冻结范围拆成共享工作队列，worker 原子领取不同源码单元。目标中出现的代码标识、文件名或路径会影响队列顺序；固定 SQL/XSS/命令执行启发式不会用于目标任务。
6. 在“执行详情”查看按工作项、worker 和轮次展开的工具调用、工具结果、源码已读范围、审计依据摘要、下一步与终止原因。结果页给出已达成、不可达或未决状态及经行号校验的发现；可下载 Markdown、JSON 和证据包。

一个工作项只能报告 `achieved`、`continue`、`no_evidence` 或 `blocked`。单个 worker 的“未发现”不会结束任务。只有全部可执行工作项正常完成或耗尽次数，且不存在上下文/模型/预算受阻项时，协调器才会把任务标为“不可达”；否则标为“未决”。

## 审计结果与执行详情

每项目标任务保存：

- 不可变 ZIP 哈希、选定范围、任务目标、验收条件、预算和队列顺序；
- 每个 worker 的领取记录、轮次、用量、已读源码行号、结构化结论和错误；
- 每次只读工具调用的参数、状态、受限预览与关联调用 ID；
- 模型生成的审计依据摘要、缺失上下文和下一步建议；
- 经过源码边界与已读范围校验的发现、可选 POC，以及 POC 验证或源码人工复核记录。

工具与结果先落 SQLite，再经 SSE 推送。因此实时页面只是视图，数据库事件才是审计记录的来源。工具调用和模型摘要均为可审查输出；不会保存提供商的 thinking delta、完整隐藏推理或密钥。

## 可选 DVWA 演示

DVWA 仅保留为课程演示和人工 POC 验证的可选 profile，不是默认审计对象：

```bash
python3 scripts/prepare_dvwa.py
# 与通用应用一起启动演示靶机和数据库
docker compose --profile demo up --build
```

演示靶机位于 <http://127.0.0.1:4280>。完成初始设置后，可上传 `demo/dvwa-source.zip` 并像任意项目一样定义目标任务。历史的 P0/P1/P2、真值集和三类漏洞流程仍在 API 与示例脚本中保留，用于重现实验记录，但不会出现在默认工作台流程中。

## 验证与开发检查

```bash
cd backend
uv sync --extra dev
uv run pytest tests/ -q

cd ../frontend
npm run build
```

以下脚本用于真实服务上的附加检查：

```bash
scripts/sse_reconnect.py http://127.0.0.1:8899 <run-id>
scripts/ui_smoke.py      http://127.0.0.1:5173 <run-id>
```

`ui_smoke.py` 需要 Playwright 和 Chromium，可先运行 `python -m playwright install chromium`。

## 设计边界

- 审计只读取上传快照中的源码；不会执行上传代码、POC 或外部网络请求。
- tree-sitter 用于建立 PHP 语法索引和稳定切片，不是完整的跨项目污点分析。动态加载、运行时配置和缺失依赖会作为未决上下文记录。
- POC 是模型产生的静态审计工件，必须由人工在授权环境中验证；带 POC 的确认与排除保留执行状态、环境、对照观测和附件。没有 POC 的源码结论通过书面人工复核确认或驳回，且只有通过源码证据校验的结论能够被确认。
- 固定漏洞实验、Prompt 轮次和 DVWA 工件是历史兼容层，不用于衡量任意上传项目的覆盖率或召回率。

## 目录结构

```text
backend/audit/        FastAPI、快照导入、目标协调器、worker、证据与报告
frontend/src/         React 工作台（任务创建、执行详情、结果与报告）
scripts/start.sh      本地前后端一键启动
docs/                 API 契约与报告说明
demo/dvwa/            可选的课程演示靶机
```
