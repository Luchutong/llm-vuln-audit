# PHP 源码目标审计工作台

这是一个面向受控环境的 PHP 白盒审计工具：**上传任意 PHP 源码 ZIP → 定义审计目标与验收条件 → 主 Planner 建立项目级任务图 → 多 worker 审计 → 导出可复核结果**。

主流程不要求 DVWA、预设 Prompt 或固定漏洞类别。目标可以是漏洞路径、鉴权规则、敏感配置、危险依赖、路由覆盖、数据流或任意能由源码证据验证的事实。每次运行都会冻结源码快照、范围、目标、预算和项目图；主 Planner 根据项目图与 worker 反馈动态维护跨文件任务图，而不是把每个文件或切片直接派给 agent。Planner 回合、任务依赖、工具调用、源码引用、worker 尝试和审计依据摘要都会持久化，刷新页面或重启服务后仍可回放。

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
| `DEEPSEEK_API_KEY` | DeepSeek 官方 API key 别名；单独设置时默认使用 `deepseek-flash` 和 `https://api.deepseek.com` |
| `LLM_THINKING` | 默认 `disabled`；不采集或展示模型隐藏推理内容 |
| `AUDIT_DATA_DIR` | 数据目录，默认 `./data`（SQLite、不可变快照与证据） |
| `AUDIT_PORT` / `WEB_PORT` | 本地一键启动或 Compose 的监听端口 |

`AUDIT_MODEL` / `AUDIT_BASE_URL` / `AUDIT_API_KEY` 和 `OPENAI_*` 也可作为兼容别名。`LLM_MODEL`、`LLM_BASE_URL` 与 `LLM_API_KEY` 优先于 DeepSeek 默认值；DeepSeek 官方模型和 API 地址以[官方文档](https://api-docs.deepseek.com/)为准。

## 使用流程

1. 在“审计任务”上传 PHP 源码 ZIP。导入器保留原始字节和哈希，并索引 `.php`、`.php3`–`.php8`、`.phps`、`.inc`、`.phtml` 文件；带 PHP 开始标记（含短标签）的无扩展名和框架专用文件也会被识别。它拒绝路径穿越、符号链接、加密条目和超限归档。
2. 选择待审计文件；默认选中 ZIP 中的项目 PHP 文件。第三方依赖与生成目录里的 PHP 文件会显式列为可选项，按需勾选后同样会冻结进本次范围；非 PHP 文件不会进入审计范围。
3. 填写任务目标和验收条件。例如：
   - “追踪上传入口到文件写入操作，确认是否存在未经路径规范化的可达写入路径。”
   - “列出所有无需认证即可访问的管理路由，并给出路由定义与中间件证据。”
   - “确认会话 cookie 的 `Secure`、`HttpOnly` 和 `SameSite` 配置来源。”
4. 设置每个动态任务的最大尝试、全局 worker 尝试上限、Planner 回合上限、并发 worker 数，以及是否要求 POC。源码事实、配置或架构目标可关闭 POC；漏洞任务可要求 POC 作为达成条件。
5. 开始审计。主 Planner 首轮获得紧凑的项目结构概览（模块、静态 include 图、高置信入口、引导文件与未解析关系统计），再按需检索具体路径、符号或调用点并创建少量跨文件、可依赖的审计方向。高置信入口与未解析静态根分开记录；后者不会被当成路由或作为 worker 的默认起点。worker 通过原子租约领取已就绪任务，并从多个源码窗口开始审计；其结果会成为下一轮 Planner 的输入。依赖任务会把已持久化的结论摘要交接给后续 worker；worker 还可检索其他 worker 的受限工具轨迹作为线索，但仍必须自行读取源码才能引用为证据。固定 SQL/XSS/命令执行启发式不会用于目标任务。
6. 在“项目与任务图”和“执行轨迹”查看 Planner 回合、动态任务依赖、worker、工具调用、工具结果、源码已读范围、审计依据摘要、下一步与终止原因。结果页给出已达成、不可达或未决状态及经行号校验的发现；可下载 Markdown、JSON 和证据包。

一个动态任务只能报告 `achieved`、`continue`、`no_evidence` 或 `blocked`。单个 worker 的“未发现”不会结束整个审计。只有 Planner 已穷尽已知证据方向、所有动态任务已结算、且不存在上下文或执行受阻项时，宿主才会接受“不可达”；共享尝试或 Planner 回合耗尽一律保留为“未决”。

## 审计结果与执行详情

每项目标任务保存：

- 不可变 ZIP 哈希、选定范围、任务目标、验收条件、预算和冻结项目图；
- 每个 Planner 回合的依据摘要、任务图版本、动态任务、依赖和更新记录；
- 每个 worker 的动态任务领取记录、尝试、用量、已读源码行号、结构化结论和错误；
- 依赖任务的摘要交接，以及可检索的受限同行工具轨迹和依据摘要；
- 每次只读工具调用的参数、状态、受限预览与关联调用 ID；
- 模型生成的审计依据摘要、缺失上下文和下一步建议；
- 经过源码边界与已读范围校验的发现、可选 POC，以及 POC 验证或源码人工复核记录。

工具与结果先落 SQLite，再经 SSE 推送。因此实时页面只是视图，数据库事件才是审计记录的来源。执行轨迹展示工具调用和模型给出的源码依据摘要，不展示或持久化提供商 thinking delta、完整隐藏推理或密钥。

## 可选 DVWA 演示

DVWA 仅保留为课程演示和人工 POC 验证的可选 profile，不是默认审计对象：

```bash
python3 scripts/prepare_dvwa.py
# 与通用应用一起启动演示靶机和数据库
docker compose --profile demo up --build
```

演示靶机位于 <http://127.0.0.1:4280>。完成初始设置后，可上传 `demo/dvwa-source.zip` 并像任意项目一样定义目标任务。历史 P0/P1/P2、真值集和三类漏洞记录仅作为兼容数据与课程实验示例保留，不属于默认工作台流程。

课程实验需要时，可通过独立脚本与 `/api/prompt-runs`、`/api/experiments` 兼容接口复现固定 Prompt 轮次；这些入口不参与默认目标审计。`scripts/seed_truths.py` 中的源码核验标签和 `scripts/verify_rounds.py` 也仅服务于该课程示例。其配对指标只适用于同条件且有充分独立真值的轮次，不代表任意项目的覆盖率或召回率。

### Mutillidae 困难样例（静态源码基准）

为减少 DVWA 单文件、低/高安全级别对照过于直观造成的天花板效应，可额外准备 [OWASP Mutillidae II](https://github.com/webpwnized/mutillidae) 的 DNS Lookup 与 Echo 页面。样例包含安全级别分支、客户端校验与服务端输入处理差异，并将同一请求数据用于命令调用和 HTML 输出；预置 6 组文件×类别源码核验标签。来源固定为 Mutillidae commit `126a1fdb4ff977f87e980d018f0def477afc3d5d`，压缩包仅包含这两个页面和上游 `LICENSE`，是静态审计样例而非可运行靶场。真值标签依据源码独立核验，尚需在隔离的 Mutillidae 实例中完成人工 POC 验证后，才可作为完整课程实验结论。

这两个样例主要考察 P0/P1 的输入—危险操作证据链与防护判断，以及 P2 的触发前提和结论边界；它们不包含真正的跨文件数据流，因此不能单独验证 P2 的跨文件分析优势。若要评价该项，还需再加入跨文件调用样例。

```bash
# 固定版本生成小型源码包
uv run --project backend python scripts/prepare_mutillidae.py
# 上传并记录输出的 snapshot id
uv run --project backend python scripts/demo_upload.py http://127.0.0.1:8899 demo/mutillidae-benchmark.zip
# 将 Mutillidae 的源码核验标签写入该快照
uv run --project backend python scripts/seed_truths.py http://127.0.0.1:8899 SNAPSHOT_ID --benchmark mutillidae
# 对完全相同的 Mutillidae 范围顺序运行 P0/P1/P2 并比较
uv run --project backend python scripts/prompt_rounds.py http://127.0.0.1:8899 SNAPSHOT_ID --benchmark mutillidae --responses 24 --tools 32 --seconds 600
```

比较结果仍可能没有提升；两页样例只能检验这些具体场景，不能证明 Prompt 对一般 PHP 项目有泛化提升。

### Mutillidae 跨文件数据流样例

另有一个独立的 `mutillidae-crossfile` 基准：唯一计分入口为 `src/user-info.php`，相关快照还包含入口路由、SQLQueryHandler、MySQLHandler 与 HTML 编码实现。它要求从请求参数跨文件追踪到 SQL 执行，并区分安全级别下的转义分支；同一入口还包含未编码的 HTML 回显。范围×类别共 3 个真值样本（SQL 注入、反射型 XSS、命令注入阴性），样本很少，结果仅用于探索，不足以支持一般性或统计显著性结论。标签经源码链核验，尚未在隔离靶场实际执行 POC。

```bash
# 固定版本生成含 helper 源码的静态审计包
uv run --project backend python scripts/prepare_mutillidae.py --benchmark mutillidae-crossfile
# 上传时只把 user-info.php 作为计分/调度范围；ZIP 中的 helper 供跨文件读取
uv run --project backend python scripts/demo_upload.py http://127.0.0.1:8899 demo/mutillidae-crossfile-benchmark.zip src/user-info.php
uv run --project backend python scripts/seed_truths.py http://127.0.0.1:8899 SNAPSHOT_ID --benchmark mutillidae-crossfile
uv run --project backend python scripts/prompt_rounds.py http://127.0.0.1:8899 SNAPSHOT_ID --benchmark mutillidae-crossfile --responses 24 --tools 32 --seconds 600
```

### Mutillidae 多入口跨文件样例（小规模）

为避免只用一个入口得出过强结论，`mutillidae-multiflow` 固定审计 3 个入口：`user-info.php`（请求参数→账户查询→SQL/HTML）、`register.php`（注册字段→SQLQueryHandler 插入→数据库）和 `browser-info.php`（HTTP 请求头→ClientInformationHandler→HTML）。真值按每个入口的 SQL 注入、反射型 XSS、命令注入三类标注，共 9 个文件×类别标签；随 ZIP 只附带路由、必要 handler、编码器及 CSRF helper，不包含整个 Mutillidae 项目。多个入口仍共享 SQLQueryHandler、MySQLHandler 等 helper，因此这些标签不是统计上完全独立的样本，只适合作为小规模探索对照。

```bash
uv run --project backend python scripts/prepare_mutillidae.py --benchmark mutillidae-multiflow
uv run --project backend python scripts/demo_upload.py http://127.0.0.1:8899 demo/mutillidae-multiflow-benchmark.zip src/user-info.php src/register.php src/browser-info.php
uv run --project backend python scripts/seed_truths.py http://127.0.0.1:8899 SNAPSHOT_ID --benchmark mutillidae-multiflow
uv run --project backend python scripts/prompt_rounds.py http://127.0.0.1:8899 SNAPSHOT_ID --benchmark mutillidae-multiflow --responses 24 --tools 32 --seconds 600
```

为进行透明的提示词消融对照，内置 `P0-lite`、`P1-lite` 是单独的最低要求简化基线：它们保留四段式任务结构、三类漏洞结论、行号、候选 POC 与修复建议，但不要求严格证据链或正常输入对照。两者标记为 `custom`，不会进入原 P0→P1→P2 优化轮次报表，也不覆盖历史运行。可按明确 ID 在同一快照和范围上单独运行配对比较：

```powershell
uv run --project backend python scripts/prompt_rounds.py http://127.0.0.1:8899 SNAPSHOT_ID P0-lite P1-lite --benchmark mutillidae-multiflow --responses 24 --tools 32 --seconds 600
```

该消融对照应单独报告，不能与原 P0/P1/P2 运行混为同一优化序列，也不能预设其必然产生更差结果。

这组样例只覆盖固定版本的三个代码路径；真值为源码核验，仍需在授权隔离靶场完成人工 POC 验证，不能据此宣称对一般 PHP 项目有泛化提升。

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
- tree-sitter 用于建立 PHP 语法索引、项目图和稳定源码窗口，不是完整的跨项目污点分析。动态加载、运行时配置和缺失依赖会作为未决上下文记录。
- POC 是模型产生的静态审计工件，必须由人工在授权环境中验证；带 POC 的确认与排除保留执行状态、环境、对照观测和附件。没有 POC 的源码结论通过书面人工复核确认或驳回，且只有通过源码证据校验的结论能够被确认。
- 固定漏洞实验、P0/P1/P2 Prompt 轮次、真值集和 DVWA 工件仅作为历史兼容数据与课程示例，不属于默认工作台流程，也不用于衡量任意上传项目的覆盖率或召回率。

## 目录结构

```text
backend/audit/        FastAPI、快照导入、目标协调器、worker、证据与报告
frontend/src/         React 工作台（任务创建、执行详情、结果与报告）
scripts/start.sh      本地前后端一键启动
docs/                 API 契约与报告说明
demo/dvwa/            可选的课程演示靶机
```
