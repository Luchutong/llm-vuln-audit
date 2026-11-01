# main 部署完整性验收

本次实现基线：`5b1fd0299e4c92f194c28150a7d027e2d14a418b`。验收使用该提交的全新本地克隆，不复用原项目 `.env`、数据库、虚拟环境或 `node_modules`；依赖下载和 Docker 构建允许复用机器缓存。最终文档提交与该基线的业务代码一致。

## 结果

| 检查 | 实际结果 |
| --- | --- |
| uv 冻结依赖安装 | `uv sync --project backend --frozen --extra dev --extra poc-claude` 成功 |
| npm 冻结依赖安装 | `npm ci` 成功 |
| 后端全量测试 | **2,268 passed**，128 秒 |
| 前端测试 | **125 passed** |
| 前端构建 | 成功；保留既有 bundle 大于 500 kB 的提示 |
| 干净克隆 Docker 构建 | 成功，已安装 SDK extra |
| 独立 Compose 部署 | app、Lab30、数据库、fixtures、runner、开发转发六服务全部健康 |
| 生产前端/API | 首页、`/api/config`、`/api/projects`、`/api/runs` 正常 |
| 初次导入及持久化 | 1 个项目、1 个快照；应用重启后保留且不重复导入 |
| Lab30 真实环境验收 | **17 passed**：会员登录、独立脚本登录、PHP、Chromium 会话、guest/operator 隔离、XSS 正常/攻击差异、上下文互斥、幂等作业及释放 |
| SDK 本机配置验收 | SDK **0.2.174**、CLI **2.1.310**；非 root UID 10001 可写独立工作目录，启动包装器可执行 |
| Compose 配置隔离 | app 接收 SDK 配置；runner 不接收 LLM/Anthropic 上游配置及凭据 |
| 运行页浏览器验收 | **21 passed**，模拟 API |
| 报告页浏览器验收 | **23 passed**，模拟 API |
| 深浅主题和宽度 | dark/light，1440、1024、768、390 px，无页面横向溢出 |
| 归档评分重算 | 校验 7 份资产、30 项真值、43 处定位，重算 TP22/D0/U1/FN8、F1 **0.8301886792452831** |
| 入口文档链接 | README、部署指南、闭环交付 README 的相对链接均存在并已跟踪 |
| 提交内容检查 | 新提交未含本机 `.env` 密钥；无大于 20 MB 的新增文件；本机数据及 `.run` 未入库 |

后端唯一 warning 来自专门构造重复 ZIP 文件名的拒绝测试，不是依赖安装失败。SDK 的配置检查使用不可访问的本机占位上游，明确 `live_connectivity_checked=false`，不据此宣称真实上游可用。

## 隔离与使用方式

容器验收使用独立 Compose project `vuln-audit-release-check`、独立数据卷及镜像标签，应用端口 18999、商城 19880、runner 转发 19089。原项目服务、历史审计与靶场未被重启或复位。本轮调用真实模型 **0 次**；17 项环境检查确实在新靶场创建了受控实验作业，不能写成“无 runner 执行”。

复现命令详见 [部署与结果复现](deployment-and-reproduction.md)。主要检查入口：

```bash
python3 scripts/reproduce_release.py --out /tmp/lab30-score.json
uv run --project backend --frozen --extra dev --extra poc-claude pytest backend/tests/ -q
docker compose --profile poc exec -T poc-runner python - < scripts/verify_lab30_environment.py
```

## 修复的交付缺口

- Docker 镜像原先缺少 Claude SDK extra，现与本地启动脚本一致安装固定版本。
- Compose 原先遗漏 SDK、生成策略和上下文配置，现显式传入；容器内部网关端口和隔离目录不再误用主机配置。
- Docker 构建上下文排除 `.run`，避免发送本地报告和运行日志。
- 本地启动改用 `npm ci`；文档补齐依赖版本与从仓库根目录启动后端的要求。
- 文档纠正 `require_poc`、`poc_mode` 和运行级环境门禁语义。
- 原历史评分文件被忽略规则排除，现新增已跟踪的脱敏冻结发现、评分明细、资产哈希清单与零服务重算脚本。
- 历史汇报页的本地 ZIP 路径改为仓库内实际路径，并区分离线重算与付费重新审计。

## 结论与边界

其他人可从完整 main 克隆按文档部署应用和靶场、验证登录及 runner、重算归档成绩，并运行框架与页面回归。真实审计需自己的模型凭据，输出受模型版本、策略、预算和随机性影响，不承诺与归档逐字同分。

私人数据库、完整原始审计事件和模型连接凭据不发布；克隆后不会自动恢复原机历史运行页面。`docs/validation` 中已有的真实 API 验收摘要是历史记录，引用的本机临时输出并非公共原始数据包。

完整 Docker app 不持有 Docker socket/CLI，不具备宿主脚本逐漏洞复位能力。严格闭环实验使用文档中的本地 `--poc` 后端路径；其他 CPU 架构、外部模型提供商和真实完整全量审计不在本轮新验收范围。
