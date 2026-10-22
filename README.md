# 拾光商城 · Lab30 Shop 1.0.0

基于 `multi-prompt-comparison` 分支的 `fcfd5b0283110cc5bb6e201ae5524804136e3659`，将原 30 个独立 PHP 练习改造为可部署的中文商城与运营后台。保留原编号及主要漏洞类型，使用共享业务数据、真实页面、登录和持久化操作。

本目录交付源码 ZIP 与独立答案。源码包可直接用于源码审计，也包含完整的 Docker Compose 部署配置。应用是本地练习用的漏洞版，默认仅监听宿主回环地址。

## 文件

| 文件 | 内容 |
| --- | --- |
| [lab30-shop-1.0.0-source.zip](lab30-shop-1.0.0-source.zip) | 完整应用源码、静态资源、Compose、初始化及重置脚本、应用说明；不含答案、POC、检查脚本或运行数据 |
| [answers/answers.json](answers/answers.json) | 30 条结构化答案，包含描述、影响、评分前提和完整 CVSS v3.1 指标 |
| [answers/answers.md](answers/answers.md) | 同一份答案的可读清单 |
| [SHA256SUMS](SHA256SUMS) | 本目录源码包及两份答案的 SHA-256 校验值 |

答案中的路径相对于解压后的 `lab30-shop/` 根目录，行号对应本版本源码。新版答案以 **CVSS v3.1 数值评分**替代原有文字危害等级，源码 ZIP 保持 1.0.0 原始字节及校验值。

## CVSS v3.1 评分与集成

- 每项保留 8 个基础、3 个时序、11 个环境指标，共 **22 项**。原始值、继承后的有效值、数值权重、取值依据与完整向量均写入答案。
- `cvss.base_score` 是主评分；`cvss.base_vector` 可供标准解析器集成，`cvss.vector` 显式包含全部指标。数组及 `id`、`locations`、`type` 保持，原 `severity` 字段移除。
- `cvss.sub_scores` 保留 ISS、Impact、Exploitability 及环境分项；分数由 FIRST 官方计算器实现计算，并用 `cvss==3.6` 独立复算。最终分数遵循 CVSS v3.1 Roundup，向上保留一位小数。
- 未独立评估的时序和环境指标明确记为 `X`，并记录默认系数或基础值继承关系；派生时序分、环境分不代表已经开展真实环境评估。
- 评分基于逐项静态代码分析，普通会员和后台角色分别保留权限前提；不把其他题目、公开教学口令或未证实的漏洞链加算进去。完整假设与边界见 [answers/answers.md](answers/answers.md)。
- 本次只更新独立答案及评分说明，不向源码 ZIP 添加答案或评测工具。答案仍不包含 POC、攻击脚本或漏洞验证报告。

规范参考：[FIRST CVSS v3.1 规范](https://www.first.org/cvss/v3.1/specification-document)、[使用指南](https://www.first.org/cvss/v3.1/user-guide)和[官方计算器](https://www.first.org/cvss/calculator/3.1)。

## 部署

需要 Docker Engine、Docker Compose v2 和 unzip。首次构建需要下载基础镜像与 Debian 软件包。

在仓库根目录执行：

```bash
sha256sum -c SHA256SUMS
unzip lab30-shop-1.0.0-source.zip -d "$HOME/lab30-workspace"
cd "$HOME/lab30-workspace/lab30-shop"
bin/lab up
bin/lab status
```

默认地址：

- 商城与运营后台：<http://127.0.0.1:18880>
- 合作内容服务：<http://127.0.0.1:18881>
- 健康检查：<http://127.0.0.1:18880/health.php>

技术栈为 PHP 8.4 / Apache、MariaDB 11.4 和独立辅助服务。前端使用本地 CSS、JavaScript 与 SVG，无 Node.js 构建依赖。数据库不映射宿主端口，业务数据使用本项目的独立命名卷。

端口可通过 `SHOP_PORT`、`HELPER_PORT` 配置。后续管理命令应保持同一组环境变量，例如：

```bash
SHOP_PORT=19880 HELPER_PORT=19881 bin/lab up
SHOP_PORT=19880 HELPER_PORT=19881 bin/lab status
```

构建需要代理时可设置 `SHOP_BUILD_HTTP_PROXY` 和 `SHOP_BUILD_HTTPS_PROXY`；这些变量仅用于构建。Docker 下载基础镜像所用的代理由本机 Docker 配置管理。更多说明见解压后的 `README.md`。

## 初始账号与正常业务

| 用户名 | 密码 | 身份 |
| --- | --- | --- |
| alice | Alice123! | 普通会员 |
| bob | Bob123! | 普通会员 |
| operator | Ops123! | 运营员 |
| admin | Admin123! | 管理员 |

每个账号初始余额为 100 元；Alice、Bob 各有私有订单。初始数据包含 4 个商品、2 条客服留言和 1 个运营任务。

商城支持注册、登录、商品检索与详情、下单、订单查看、钱包提现、资料与邮箱修改、会员服务、客服留言和文档下载。管理员、运营员登录后可见运营导航，提供会员查询、任务、报表、内容工具和操作记录。人员管理与合作方结算工作台限管理员。

页面按业务组织，不展示题号、漏洞类别或答案提示。桌面使用侧栏和分区布局，移动端使用横向导航及纵向卡片。

## 停止与重置

在解压后的商城目录执行：

```bash
bin/lab logs       # 查看最近日志
bin/lab reset      # 恢复全部初始业务数据、运行文件与会话
bin/lab down       # 停止并删除本项目容器，保留数据卷
bin/lab up         # 再次启动，保留已有业务数据
```

Compose 项目名为 `lab30-shop`。重置会暂停 Web 写入，恢复账号、商品、订单、余额、留言、任务、操作记录及文件，注销会话并重启辅助服务；可重复执行，仅操作该项目的数据。

镜像使用复制的应用源码，不挂载宿主源码目录、Docker socket、审计数据库或模型凭据。应用运行数据不进入源码包。

## 源码审计与版本说明

将本目录的源码 ZIP 上传至审计平台项目库即可，答案保持独立。此版本补齐统一业务应用与持久化数据，使用 PHP 8.4 支持的模板表达式实现替代旧版 PHP 语法。源码包内的 `VERSION` 和 `app/VERSION` 均为 `1.0.0`。

本分支独立分发靶场源码 ZIP、答案及使用说明。导入项目库与创建审计任务是独立操作。

若需要在本地重新生成发布包，将本目录 `answers/` 中的两份文件复制到解压后商城目录同级的 `lab30-shop-answers/`，再执行 `bin/lab package`；产物写入同级 `lab30-shop-releases/1.0.0/`。

## 已完成检查

- 52 个 PHP 文件通过语法检查，独立容器部署与健康检查通过。
- 注册登录、检索下单、订单查看、资料与邮箱修改、钱包提现、客服留言及后台正常操作检查通过。
- 25 个页面在 1440、1024、768、390px 下检查通过，未发现整页横向溢出。
- 连续两次重置、数据库中断及恢复反馈检查通过。
- 源码包内应用文件与运行镜像逐文件一致；30 条答案的 39 处源码引用已核对。

按本次交付范围，未进行漏洞验证，未提供 POC、攻击脚本或漏洞验证报告。上述检查仅代表部署、界面和正常业务可用性。
