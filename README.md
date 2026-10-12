# PHP 白盒审计最小 Demo

一个可复现、可追溯的 PHP 白盒审计实验闭环：**源码准备 → LLM 审计 → POC 生成 → 人工验证 → 复盘与提示词优化**。

审计对象是 DVWA 2.5（固定提交 `a96943dc1f52f390ee5df72144660636c4b7dd06`）的六个示例文件；审计的是同一份源码构建出来的靶机，所以每条候选都能对着真实运行的目标验证。

## 快速开始

### Docker Compose（推荐）

```bash
python3 scripts/prepare_dvwa.py  # 需要 Git；下载固定提交源码，生成上传 ZIP 与哈希清单
cp .env.example .env      # 填 LLM_MODEL / LLM_BASE_URL / LLM_API_KEY
docker compose up --build
```

* 审计应用 <http://127.0.0.1:8787>
* 演示靶机 DVWA <http://127.0.0.1:4280>

8787 被别的服务占用时（本机就跑着另一个项目），用 `AUDIT_PORT=8790 docker compose up --build` 换端口，其余不变。

首次启动后需要初始化 DVWA：打开 <http://127.0.0.1:4280/setup.php>，点击 **Create / Reset Database**，然后用 `admin` / `password` 登录，把 **DVWA Security** 设为 `low`。

### 本地开发

```bash
# 后端（Python 3.12 + uv）
cd backend
uv sync
uv run uvicorn audit.app:app --host 127.0.0.1 --port 8787

# 前端（另开一个终端）
cd frontend
npm install
VITE_API_TARGET=http://127.0.0.1:8787 npm run dev
```

后端启动时读取 `backend/.env`、项目根目录 `.env` 或进程环境变量。前端开发服务器默认把 `/api` 代理到 `127.0.0.1:8787`，可用 `VITE_API_TARGET` 改指别处。

### 环境变量

| 变量 | 说明 |
| --- | --- |
| `LLM_MODEL` | 模型名，例如 `ark-code-latest` |
| `LLM_BASE_URL` | OpenAI 兼容服务的 API 根地址 |
| `LLM_API_KEY` | API Key，**只从服务端环境变量读取**，不下发到浏览器、不写入数据库或报告 |
| `LLM_THINKING` | `disabled`（默认）显式关闭思维链输出，避免推理内容占满响应预算 |
| `AUDIT_DATA_DIR` | 数据目录，默认 `./data`（SQLite 库 + 快照） |

`AUDIT_MODEL` / `AUDIT_BASE_URL` / `AUDIT_API_KEY` 以及 `OPENAI_*` 是可用的别名，便于复用别处已有的配置。

## 演示步骤

1. **导入源码**：在「审计任务」页上传 `demo/dvwa-source.zip`。该压缩包与 `demo/dvwa` 目录逐字节一致（227 个文件全部哈希相同），也就是靶机镜像构建用的那份源码。
2. **选择范围**：点「选取 DVWA 六个演示样本」，勾选 sqli / xss_r / exec 的 `low.php` 与 `impossible.php`，得到 6 个审计单元。
3. **开始审计**：默认预算为每个单元 8 次模型响应、16 次工具调用、300 秒。运行开始后队列冻结。
4. **看过程**：「审计过程」页是持久化过的事件时间线，包含每一次工具调用；刷新或重启服务后内容不变。
5. **验证候选**：「发现与验证」页下载 POC，对着 <http://127.0.0.1:4280> 实际运行，上传日志或截图并记录结论。反射型 XSS 必须提交浏览器执行证据。演示中这四个候选的 POC 都**无法按原样跑通**：脚本里写死的地址端口、会话 cookie 名、以及对靶机默认安全级别的假设各有出入（本部署 `default_security_level` 是 `impossible`，登录后必须显式切到 `low`）。按课程流程先做「脚本预处理（适配环境）」再运行，适配内容与问题归因写进验证记录，会随导出进入报告 6.3。
6. **出报告**：「实验报告」页录入真值集与失败归因，然后导出 Markdown / JSON / 证据包（`/api/runs/{id}/report?format=`）。已导出的那份在 `deliverable/`，报告第 3 章是系统总体架构（架构图、数据流向、技术栈、代码结构与模块映射、当前实现状态），第 4 章是五个模块各自的设计依据与输入输出。

命令行等价入口：

```bash
python scripts/demo_upload.py  http://127.0.0.1:8787 demo/dvwa-source.zip   # 导入快照
python scripts/seed_truths.py http://127.0.0.1:8787 <snapshot-id>          # 录入真值集
python scripts/demo_run.py    http://127.0.0.1:8787 <snapshot-id> P2       # 跑完整流程
python scripts/demo_run.py    http://127.0.0.1:8787 --follow <run-id>      # 跟随已有运行
python scripts/demo_trace.py  <snapshot-id> sqli/source/low.php P2 8 16    # 单单元逐轮追踪
```

### 自检脚本

这几个脚本用来验证「跑通了」而不是「看起来跑通了」，都在真实服务上执行：

```bash
cd backend && uv sync --extra dev && uv run pytest tests/ -q   # 单元测试（快照导入、生命周期）

# 以下需要后端在跑，且有一个已产生候选的运行
scripts/sse_reconnect.py http://127.0.0.1:8787 <run-id>   # 事件流推送与断线续传（有无重复/有无空洞）
scripts/verify_gate.py   http://127.0.0.1:8787 <run-id>   # 人工验证闸门（执行失败不得判排除、XSS 需浏览器证据）
scripts/ui_smoke.py      http://127.0.0.1:5173 <run-id>   # 用真实数据打开每个标签页并检查控制台报错
scripts/verify_rounds.py http://127.0.0.1:8787            # 两轮优化对比：Markdown 与 result.json 是否一致
```

`ui_smoke.py` 需要 Playwright 与 chromium，未纳入后端依赖；安装后执行 `python -m playwright install chromium`。可通过 `CHROME_BIN` 指定已有浏览器。`sse_reconnect.py` / `verify_gate.py` 只用 httpx。

## 设计要点

**只有三个只读工具**：`read_source`、`search_code`、`get_context`。重复调用同一参数的组合会被拒绝并回注预算提示——小模型在查不到事实时会反复发起同一次搜索，而不是下结论。

**预算是收尾的触发器，不是失败的终点**。探索阶段耗尽响应/工具/时间预算后不会直接判该单元失败，而是进入**无工具的收尾阶段**：隐藏全部工具，把已经读到的代码原文回放给模型，按类别分次强制作答，收尾阶段有独立的墙钟预算（`SETTLE_SECONDS=420`）、按次调用的上限（`SETTLE_CALL_SECONDS=200`）与按请求超时（`SETTLE_REQUEST_SECONDS=90`）。收尾成功则该单元带 `exploration_incomplete`（`timeout` / `budget` / `error`）标记，报告 6.1 节单列一张表说明「模型还想继续读」，并明确它**仍计入统计**（结论是模型自己下的，引用行号逐条核验过）：把「还想继续读」当成「没有依据」，等于每次预算截断都抹掉一个已经成立的观察。真的没有依据时应答 `insufficient_context`，那一类才单列且不进混淆矩阵。

**预算耗尽、解析失败、缺上下文都不算阴性**。未完成的单元单独列出，绝不参与"没有漏洞"的判断。单元完成了、但就某一类明确答 `insufficient_context`（看到的代码不足以判断）时同样单列：记为漏报等于把模型的诚实当失误，记作真阴则等于凭空记一次正确否定，两种都会让 Precision 与 Recall 同时失真。

**证据在入库前校验**：引用的行号必须落在当前快照内，且必须是模型本次实际读过的范围（`seen`，相邻或重叠的多次读取会先合并）。不合规的引用逐条剔除并记录原因；**只有全部引用都无法核实时**，这条候选才降级为 `invalid_evidence` 单独列出——只要还有一条能核对就保留，否则一次真实发现会变成漏报。界面上两者分开显示。

**统计口径分两种**。没有独立核验的真值集时，只报告候选数、人工结论、审计覆盖率与验证覆盖率，**召回率 / 漏报数 / 真阴数标记为"不可计算"而不是 0**——没有基准就没有漏报可言。录入真值集后才计算 TP/FP/FN/TN、精确率、召回率与 F1。

**POC 执行错误不会自动变成误报**。执行状态与人工结论是两个字段；`not_triggered`、`syntax_error`、`connection_failed`、`environment_mismatch` 都保留原样。执行未成功时不能判为「排除」。

**审计的代码就是运行的代码**。`scripts/prepare_dvwa.py` 校验固定提交的源码，并生成 ZIP 和逐文件哈希清单 `demo/dvwa-manifest.json`。已导出演示报告使用的归档 SHA256 为 `90f29031d48f187c7e8a332c5bf768aad0820326ee91b6f7d0df4055b7edf8df`；新生成归档的 ZIP 元数据可能不同，源码逐文件哈希保持一致。Compose 中 DVWA 用 `pull_policy: build` 从同一份 `demo/dvwa` 构建。

`.env`、本地数据库、依赖目录、构建产物和下载的 DVWA 源码均不提交到仓库；环境变量配置仅提供不含密钥的 `.env.example`。

## 目录结构

```
backend/audit/        FastAPI 应用与审计 worker
  source.py           快照导入、tree-sitter PHP 索引、AuditUnit 切片
  agent.py            PydanticAI agent、三个工具、预算收尾
  prompts.py          四段式提示词 P0/P1/P2
  evidence.py         证据范围校验
  worker.py           队列消费、失败与未完成处理
  report.py           Markdown / JSON / 证据包导出
frontend/src/         React + TS + Tailwind 工作台（四个标签页）
scripts/              命令行入口与排查脚本
demo/dvwa/            DVWA 源码（固定提交）
docs/                接口约定与报告目录
deliverable/          已导出的实验报告（report.md / report.json / evidence.zip）
```

## 已知限制

* DVWA 六个样本只用于检验流程是否走得通，**不能据此声称对未知 PHP 项目的检测能力**。
* 切片只按函数/方法/顶层脚本在语句边界切分，不做完整污点分析；跨文件的传播依赖 agent 主动读取，读不到就是 `insufficient_context`，不猜。
* 演示用的模型（阿里云 Ark 计划端点）不会主动终止探索，因此多数单元会耗尽预算进入收尾阶段。这是该端点的行为，不是审计逻辑的要求。收尾阶段还会**间歇性地**触顶：含 POC 脚本的 XSS 类别作答超过 `SETTLE_REQUEST_SECONDS=90` 单次请求上限，重试两次即触顶 `SETTLE_CALL_SECONDS=200`，该单元整体记为未完成——P0、P1 两轮都发生在 `xss_r/source/low.php` 上，P2 的同一单元则通过了，所以这是端点延迟而非审计逻辑的确定性结果。报告第 5 章会点名列出发生这种情况的单元，4.2.1 的「可判定样本」列会说明这如何缩小了 Precision/Recall 的分母。
* 快照一旦导入不可变；重跑同一快照会创建新的运行记录，不会覆盖历史结果。
