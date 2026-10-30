# 源码审计阶段报告（64bd9c50）

> 报告类型：阶段报告；发布状态：可发布（阶段报告）
> 事实包 final-review/v1 · 渲染器 final-report/v2 · 策略 audit-runtime-3
> 运行 `64bd9c5074334ab687a01e18229b7b5e` · 快照 `586b79b41f8e4f59be80f2a9b548902b` · 源码哈希 `67fd87e9ae771d10…` · 输入哈希 `e42ce475c66c7860e96c3758ba147c166d4565c00752466f17f8e90bffce83b6`
> 本报告由宿主从冻结事实包确定性生成；数量、位置、验证状态与评分均不由模型填写。

## 1. 执行与终审摘要

- 运行：`64bd9c5074334ab687a01e18229b7b5e`；状态：inconclusive；停止原因：model_unavailable；模型连续失败 3 次（worker）：ModelCallFailed: APIConnectionError: Connection error.
- 审计完整性：未完成，本报告为阶段报告
- 报告类型：stage；发布状态：可发布（阶段报告）

- 原始记录：31
- 有效记录：28
- 规范结论：25
- 已接受漏洞：0
- 待终审：25
- 存疑或排除：0

“已接受漏洞”以当前版本的正式终审处置为准：静态证据充分可接受；动态已验证结论还须完成同版本观测复核。其余结论逐条保留，不会因为缺少终审额度而从报告中消失。

| 完成维度 | 已完成 | 分母 | 说明 |
|---|---:|---:|---|
| 源码覆盖（读取） | 55 | 61 | 已读只表示宿主记录过读取 |
| 源码覆盖（读取+带理由跳过） | 60 | 61 | 跳过不是安全结论 |
| 必做方向结算 | 6 | 9 | 未决 3 个 |
| 动态验证完成 | 0 | 25 | 待验证 25 条 |
| 正式复核 | 0 | 25 | 复核存疑或未复核不计入已接受 |
| 源码覆盖（仍待复核） | 1 | 61 | 未读且未跳过 1 个 |

- 发布门禁未通过：review_batch_complete

**仍需终审的结论**

- C-01 catalog/index.php 中 GET q 直接拼接进 LIKE 查询导致 SQL 注入：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-02 用户口令以无盐 md5 存储与校验，泄露后可被快速破解：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-03 登录页接受 GET sid 且关闭 use_strict_mode，攻击者可预置会话 ID 实施会话固定：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-04 ops/jobs.php 反序列化 DispatchJob 触发 __wakeup 中 shell_exec 任意命令执行：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-05 partner/portal.php 信任客户端 JWT payload 中 role，普通用户可伪造 admin 读取全部订单结算：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-06 ops/batch-check.php 将未过滤的 GET host 传入 host_check() 并拼入 shell_exec 命令（独立命令注入入口）：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-07 在线留言消息体未转义直接输出导致存储型 XSS：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-08 catalog/greeting.php 的 name 参数未转义直接输出造成反射型 XSS：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-09 wallet/withdraw.php 先读后写余额且无事务/行锁，可并发竞态超额提现：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-10 orders/detail.php 缺少归属校验，任意登录用户可读取他人订单详情（IDOR）：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-11 密码使用无盐 MD5 存储与校验，弱哈希可被离线快速破解：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-12 下单接口信任客户端单价，可用任意价格购买商品：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-13 ops/members.php 经 member_lookup() 拼接 GET q 造成 SQL 注入：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-14 ops/xml-import.php 以 LIBXML_NOENT|LIBXML_DTDLOAD 解析用户提交 XML 导致 XXE 文件读取/SSRF：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-15 template-preview.php 对用户可控 template 参数直接 include，导致本地/远程文件包含与代码执行：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-16 account/update.php 批量赋值允许普通用户改写 role/tier/balance 自升管理员：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-17 登录认证成功后不轮换会话 ID，配合 GET sid 预置导致会话固定：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-18 ops/users.php 用客户端 Cookie role 判断管理员，普通登录用户可越权读取全部用户：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-19 ops/ping.php 将 GET host 直接拼入 shell_exec 导致命令注入：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-20 ops/maintenance.php 仅凭客户端 X-Admin 请求头放行，未登录即可向 jobs 表写入任务：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-21 template-render.php 对 {{}} 内容执行 eval 导致任意 PHP 代码执行：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-22 ops/report.php:3 二阶 SQL 注入：用户可控 nickname 经数据库回读后拼接进查询：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-23 ops/url-preview.php 对 GET url 无协议/主机限制并回显响应，形成全回显 SSRF：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-24 support/download.php 未校验 file 参数导致目录穿越任意文件读取：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-25 Operator-controlled PHP function name passed to dynamic call in ops/formula.php enables arbitrary PHP function invocation：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

## 2. 范围和方法

- 项目：39211162aa984b25b60228c194b531ae；快照：`586b79b41f8e4f59be80f2a9b548902b`
- 源码包哈希（archive sha256）：`67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c`
- 事实包：final-review/v1；渲染器：final-report/v2；模板哈希：`bae25eb461e0811b`
- 输入哈希：`e42ce475c66c7860e96c3758ba147c166d4565c00752466f17f8e90bffce83b6`；冻结时间：2026-10-30T12:35:33.962290+00:00；生成时间：2026-10-30T12:35:33.962290+00:00
- 模型配置：deepseek-flash；策略版本：audit-runtime-3

本次报告只使用宿主记录的冻结事实：源码引用由服务器从快照读取并核对哈希，动态验证取自隔离 runner 的作业记录，正式复核按 finding revision 与 verification id 精确引用。模型的结论陈述与修复建议以“结论陈述”标注，不作为证据；未执行、环境失败与验证不确定都不解释为误报。

| 预算 | 上限 | 实际使用 | 剩余 |
|---|---:|---:|---:|
| 模型响应 | 2048 | 95 | 1953 |
| 工具调用 | 16384 | 147 | 16237 |
| 秒 | 10800 | 592.856 | 10207.144 |

- 上下文：峰值请求 136634 字节 / 上限 393216 字节；摘要请求 0 次；硬上限命中 0 次。

| 阶段 | 请求配额 | 已用 |
|---|---:|---:|
| 源码挖掘 | 1512 | 95 |
| POC 验证 | 512 | 0 |
| 统一终审 | 24 | 0 |
- 调度政策：host-queue-v1；配额：自动分配。
- 待终审 28 项，预计 6 批；当前预留 24 次请求、540 秒；按实际批次容量与 Worker 调整，不增加整次额度。
- POC 执行：。

## 3. 规范漏洞清单

| 编号 | 标题 | 类型 | 评分 | 位置 | 静态判读 | 动态验证 | 正式终审 | 处置 |
|---|---|---|---|---|---|---|---|---|
| C-01 | catalog/index.php 中 GET q 直接拼接进 LIKE 查询导致 SQL 注入 | sqli | CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:… | lab30-shop/app/public/catalog/index.php:4 | 缺上下文（1 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-02 | 用户口令以无盐 md5 存储与校验，泄露后可被快速破解 | weak_crypto | CVSS 3.1 Base 7.4 (high) · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/src/setup.php:17 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-03 | 登录页接受 GET sid 且关闭 use_strict_mode，攻击者可预置会话 ID 实施会话固定 | session_fixation | CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/… | lab30-shop/app/public/auth/login.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-04 | ops/jobs.php 反序列化 DispatchJob 触发 __wakeup 中 shell_exec 任意命令执… | insecure_deserialization | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/jobs.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-05 | partner/portal.php 信任客户端 JWT payload 中 role，普通用户可伪造 admin 读取… | auth_bypass | CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:… | lab30-shop/app/public/partner/portal.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-06 | ops/batch-check.php 将未过滤的 GET host 传入 host_check() 并拼入 shell… | command_injection | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/src/host_check.php:2 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-07 | 在线留言消息体未转义直接输出导致存储型 XSS | xss_s | CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/… | lab30-shop/app/public/support/messages.php:5 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-08 | catalog/greeting.php 的 name 参数未转义直接输出造成反射型 XSS | xss_r | CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/… | lab30-shop/app/public/catalog/greeting.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-09 | wallet/withdraw.php 先读后写余额且无事务/行锁，可并发竞态超额提现 | race_condition | CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/wallet/withdraw.php:7 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-10 | orders/detail.php 缺少归属校验，任意登录用户可读取他人订单详情（IDOR） | idor | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/orders/detail.php:2 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-11 | 密码使用无盐 MD5 存储与校验，弱哈希可被离线快速破解 | weak_crypto | CVSS 3.1 Base 5.9 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/auth/register.php:8 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-12 | 下单接口信任客户端单价，可用任意价格购买商品 | price_manipulation | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/orders/create.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-13 | ops/members.php 经 member_lookup() 拼接 GET q 造成 SQL 注入 | sqli | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/src/member_lookup.php:3 | 缺上下文（1 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-14 | ops/xml-import.php 以 LIBXML_NOENT&#124;LIBXML_DTDLOAD 解析用户提交… | xxe | CVSS 3.1 Base 5.7 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/… | lab30-shop/app/public/ops/xml-import.php:3 | 缺上下文（2 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-15 | template-preview.php 对用户可控 template 参数直接 include，导致本地/远程文件包含… | lfi | CVSS 3.1 Base 8.3 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/template-preview.php:3 | 缺上下文（1 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-16 | account/update.php 批量赋值允许普通用户改写 role/tier/balance 自升管理员 | mass_assignment | CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/account/update.php:5 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-17 | 登录认证成功后不轮换会话 ID，配合 GET sid 预置导致会话固定 | session_fixation | CVSS 3.1 Base 5.9 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/… | lab30-shop/app/public/auth/login.php:8 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-18 | ops/users.php 用客户端 Cookie role 判断管理员，普通登录用户可越权读取全部用户 | auth_bypass | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/ops/users.php:2 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-19 | ops/ping.php 将 GET host 直接拼入 shell_exec 导致命令注入 | command_injection | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/ping.php:2 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-20 | ops/maintenance.php 仅凭客户端 X-Admin 请求头放行，未登录即可向 jobs 表写入任务 | auth_bypass | CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/… | lab30-shop/app/public/ops/maintenance.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-21 | template-render.php 对 {{}} 内容执行 eval 导致任意 PHP 代码执行 | code_execution | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/template-render.php:3 | 缺上下文（1 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-22 | ops/report.php:3 二阶 SQL 注入：用户可控 nickname 经数据库回读后拼接进查询 | sqli | CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:L/… | lab30-shop/app/public/ops/report.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-23 | ops/url-preview.php 对 GET url 无协议/主机限制并回显响应，形成全回显 SSRF | ssrf | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/ops/url-preview.php:3 | 缺上下文（2 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-24 | support/download.php 未校验 file 参数导致目录穿越任意文件读取 | path_traversal | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/support/download.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-25 | Operator-controlled PHP function name passed to dynamic call… | code_execution | CVSS 3.1 Base 6.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/… | lab30-shop/app/public/ops/formula.php:3 | 缺上下文（2 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |

## 4. 逐条漏洞详单

### C-01 catalog/index.php 中 GET q 直接拼接进 LIKE 查询导致 SQL 注入

- 当前版本：finding `e5982d0c8d8848f4ac3e10adc18cb7fb` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/catalog/index.php:4`；文件：`lab30-shop/app/public/catalog/index.php`
- 证据引用：`2ee6bd3796c99bfe` lab30-shop/app/public/catalog/index.php:2-4；`85b2e45ff4e8d0eb` lab30-shop/app/src/bootstrap.php:4-8
- 根因类别：task_goal:v2:37cd06068445afbc084c:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

catalog/index.php:3 从 $_GET['q'] 取值后未处理，第 4 行直接拼入 LIKE '%...%' 并用 db()->query() 执行。ATTR_EMULATE_PREPARES=false 只对 prepare 生效，此处为 query 直连，可闭合引号 UNION 读取 users 表。页面无 require_user，匿名可触发。

- 攻击前身份与适用前提：匿名可访问 /catalog/index.php
- 入口 → 传播 → 危险操作/状态变更：$_GET['q'] → catalog/index.php:3 $term=(string)$_GET['q'] -> :4 拼接 SQL LIKE '%$term%' -> db()->query() → PDO::query() 执行外部可控 SQL
- 防护与边界：无；h() 仅用于输出，未用于 SQL
- 静态判读：缺上下文（1 项）；缺失上下文：nickname 二阶注入路径未执行验证
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 prepare+execute 绑定参数。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/catalog/index.php:2-4`（sha256 `e85bd1c2fa6a4b78…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';
    3  $term=(string)($_GET['q']??'');
    4  $products=db()->query("SELECT id,name,description,price,stock,color FROM products WHERE name LIKE '%".$term."%' ORDER BY id")->fetchAll();
```

`lab30-shop/app/src/bootstrap.php:4-8`（sha256 `2050819d093be02b…`）

```php
    4  function db(): PDO {
    5      static $pdo;
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    7      return $pdo;
    8  }
```

### C-02 用户口令以无盐 md5 存储与校验，泄露后可被快速破解

- 当前版本：finding `18d4dc711491403082341e53a66a370c` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/setup.php:17`；文件：`lab30-shop/app/src/setup.php`
- 证据引用：`80b30b229093e94e` lab30-shop/app/src/setup.php:16-17；`850e65d55415065d` lab30-shop/app/public/auth/register.php:8-8；`f7b097d7ada046e5` lab30-shop/app/public/auth/login.php:7-7
- 根因类别：task_goal:v2:5a6875d0f22e8f4457da:1（规范类型 weak_crypto）

**结论陈述（模型产出，不是证据）**

setup.php 第17行用 md5($u[2]) 写入 users.password_md5；register.php 第8行同样用 md5($password) 存入；login.php 第7行以 hash_equals 比对 md5 值。口令哈希无盐、无迭代、非 password_hash/argon2，一旦哈希经其他途径泄露即可用彩虹表或 GPU 快速还原，导致账户接管。

- 攻击前身份与适用前提：攻击者获取到 password_md5 哈希值
- 入口 → 传播 → 危险操作/状态变更：注册/登录提交的口令及数据库 password_md5 列 → $_POST['password'] -> md5() -> 写入/比对 password_md5 → 使用 md5 作为口令存储与校验算法
- 防护与边界：hash_equals 仅防时序，算法本身无盐无慢哈希
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 7.4 (high) · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 password_hash 与 password_verify 并迁移存量哈希。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/src/setup.php:16-17`（sha256 `53e7dc7286d7d370…`）

```php
   16      $q=$pdo->prepare('INSERT INTO users(id,username,password_md5,display_name,email,role,balance,tier,nickname) VALUES(?,?,?,?,?,?,100,?,?)');
   17      foreach ([[1,'alice','Alice123!','林晓','alice@shop.local','customer'],[2,'bob','Bob123!','陈远','bob@shop.local','customer'],[3,'operator','Ops123!','运营同事','ops@shop.local','operator'],[4,'admin','Admin123!','系统管理员','admin@shop.local','admin']] as $u) $q->execute([$u[0],$u[1],md5($u[2]),$u[3],$u[4],$u[5],'standard',$u[1]]);
```

`lab30-shop/app/public/auth/register.php:8-8`（sha256 `99166a0288be7b1e…`）

```php
    8      try {$q->execute([$name,md5($password),$name,(string)($_POST['email']??''),'customer','standard',$name]); $notice='注册成功，现在可以登录。';} catch(PDOException $e) {fail_request('该用户名已注册。',409);}
```

`lab30-shop/app/public/auth/login.php:7-7`（sha256 `b9be43ddb2233156…`）

```php
    7      if ($row && hash_equals($row['password_md5'],md5((string)($_POST['password']??'')))) {
```

### C-03 登录页接受 GET sid 且关闭 use_strict_mode，攻击者可预置会话 ID 实施会话固定

- 当前版本：finding `c9a4c3d0f72547d79f39a1832af765e4` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/login.php:3`；文件：`lab30-shop/app/public/auth/login.php`
- 证据引用：`5f912f7499e51381` lab30-shop/app/public/auth/login.php:3-9；`9f3b2a689fae3c12` lab30-shop/app/src/bootstrap.php:11-19
- 根因类别：task_goal:v2:ef96a2ba79785a7e1350:1（规范类型 session_fixation）

**结论陈述（模型产出，不是证据）**

login.php 第3行将 $_GET['sid'] 直接传给 start_session()；bootstrap.php 第17行在正则通过时调用 session_id($sid)，第13行显式设置 session.use_strict_mode=0，使服务端接受攻击者未初始化的 SID。第8行登录成功后只写 $_SESSION['user_id'] 且未调用 session_regenerate_id(true)，攻击者预先把自己的 SID 链接发给受害者，受害者登录后该 SID 即为已认证会话，攻击者凭同一 SID 冒充受害者。

- 攻击前身份与适用前提：受害者点击攻击者构造的 /auth/login.php?sid=... 链接并在同一浏览器完成登录
- 入口 → 传播 → 危险操作/状态变更：URL 查询参数 sid（$_GET['sid']） → $_GET['sid'] -> start_session($sid) -> session_id($sid) -> session_start()；登录成功后同一 SID 写入 user_id 且未 regenerate → session_id() 接受外部可控会话标识并 session_start()，认证后不轮换会话 ID
- 防护与边界：仅正则 /^[a-zA-Z0-9,-]{16,64}$/ 约束字符集；use_strict_mode=0 关闭拒绝未初始化 SID 的保护；无 session_regenerate_id
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：移除 sid 外部注入；启用 session.use_strict_mode=1；登录成功后 session_regenerate_id(true) 并更新 cookie。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/auth/login.php:3-9`（sha256 `b9be43ddb2233156…`）

```php
    3  start_session(isset($_GET['sid']) ? (string)$_GET['sid'] : null);
    4  $error='';
    5  if ($_SERVER['REQUEST_METHOD']==='POST') {
    6      $q=db()->prepare('SELECT id,password_md5 FROM users WHERE username=?'); $q->execute([$_POST['username']??'']); $row=$q->fetch();
    7      if ($row && hash_equals($row['password_md5'],md5((string)($_POST['password']??'')))) {
    8          $_SESSION['user_id']=(int)$row['id']; event_log('login');
    9          header('Location: /'); exit;
```

`lab30-shop/app/src/bootstrap.php:11-19`（sha256 `2050819d093be02b…`）

```php
   11  function start_session(?string $sid = null): void {
   12      if (session_status() === PHP_SESSION_ACTIVE) return;
   13      ini_set('session.use_strict_mode', '0');
   14      session_save_path(data_dir() . '/sessions');
   15      session_name('SHOPSESSID');
   16      session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'path' => '/']);
   17      if ($sid !== null && preg_match('/^[a-zA-Z0-9,-]{16,64}$/D', $sid)) session_id($sid);
   18      session_start();
   19  }
```

### C-04 ops/jobs.php 反序列化 DispatchJob 触发 __wakeup 中 shell_exec 任意命令执行

- 当前版本：finding `e620cbf200e14b73a5f2c0da407134e6` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/jobs.php:3`；文件：`lab30-shop/app/public/ops/jobs.php`
- 证据引用：`bc71d05290d8c856` lab30-shop/app/public/ops/jobs.php:2-3；`e030edd4e1bdfc70` lab30-shop/app/src/dispatch_job.php:2-4；`063c928d2d7c3b2e` lab30-shop/app/src/bootstrap.php:33-40
- 根因类别：task_goal:v2:cba187f46ca0a982c4f8:1（规范类型 insecure_deserialization）

**结论陈述（模型产出，不是证据）**

jobs.php 第3行对 POST job 做 base64_decode 后直接 unserialize，且在 instanceof DispatchJob 检查之前完成反序列化；dispatch_job.php 第3-4行公有 $command 属性与 __wakeup 中 shell_exec($this->command) 构成反序列化即命令执行。入口由 bootstrap require_user(['operator','admin']) 与 check_csrf 保护，登录操作员可提交恶意序列化对象获得任意命令执行。

- 攻击前身份与适用前提：拥有 operator 或 admin 角色账号；能获取当前会话 CSRF token（页面 csrf_field 即提供）
- 入口 → 传播 → 危险操作/状态变更：POST 参数 job（base64 编码的序列化 DispatchJob 对象，$command 可控） → base64_decode($_POST['job']) → unserialize($raw) → 触发 DispatchJob::__wakeup → shell_exec($this->command) → shell_exec 执行攻击者可控命令字符串
- 防护与边界：require_user 仅校验登录与角色；check_csrf 校验令牌；二者均为访问前提，未限制反序列化对象属性或命令内容。
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：移除对不可信输入的 unserialize，改用 JSON 或白名单结构；如必须序列化，应使用 allowed_classes 限制类，并对命令参数做白名单校验，禁止 shell_exec 拼接外部输入。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/jobs.php:2-3`（sha256 `0f7550fa7f16bd4a…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/dispatch_job.php';$u=require_user(['operator','admin']);$notice='';$output='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$raw=base64_decode((string)($_POST['job']??''),true);if($raw===false)fail_request('任务格式不正确。');ob_start();$job=unserialize($raw);$output=(string)ob_get_clean();if(!$job instanceof DispatchJob)fail_request('不是有效的任务文件。');db()->prepare("INSERT INTO jobs(user_id,title,status,details) VALUES(?,?,'completed',?)")->execute([$u['id'],'导入巡检任务',$output]);$notice='任务已导入并执行。';}
```

`lab30-shop/app/src/dispatch_job.php:2-4`（sha256 `e8234b971fe75d85…`）

```php
    2  class DispatchJob {
    3      public string $command = 'printf inventory-ready';
    4      public function __wakeup(): void { echo (string)shell_exec($this->command); }
```

`lab30-shop/app/src/bootstrap.php:33-40`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
   38  function csrf_token(): string { start_session(); return $_SESSION['csrf'] ??= bin2hex(random_bytes(24)); }
   39  function csrf_field(): string { return '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'; }
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

### C-05 partner/portal.php 信任客户端 JWT payload 中 role，普通用户可伪造 admin 读取全部订单结算

- 当前版本：finding `58fecd8c25ca42348047bc8ab4cfab17` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/partner/portal.php:3`；文件：`lab30-shop/app/public/partner/portal.php`
- 证据引用：`bce6927d778989fd` lab30-shop/app/public/partner/portal.php:2-5；`550f5e4c71ae4d33` lab30-shop/app/public/partner/token.php:3-6
- 根因类别：task_goal:v2:7594dbd1ab4457e80dbc:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

portal.php 从 POST token 或 Cookie partner_token 取 JWT，仅 base64 解码第二段并断言 payload['role']==='admin'，完全没有验证第三段签名；该 token 由 /partner/token.php 用 settings.generation 作 HMAC 密钥签发，但校验端不验签，因此攻击者可用任意 header.payload.signature 把 role 设为 admin，绕过管理员限制读取全部 orders 的 order_no 与 total。

- 攻击前身份与适用前提：无需登录，仅需构造 base64 JWT；可带上任意第三段
- 入口 → 传播 → 危险操作/状态变更：POST 参数 token 或 Cookie partner_token → portal.php:2 explode 取 parts[1] base64_decode json_decode -> portal.php:3 判断 role==='admin' -> portal.php:4 查询全部订单 -> 输出 → 无验签的 JWT 角色判定后读取全表 orders
- 防护与边界：无签名校验、无 require_user 角色校验；require_user 未传入角色
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：服务端校验 JWT 签名（HMAC/非对称）与声明，role 必须来自服务端会话或数据库而非 token；portal.php 应调用 require_user(['admin'])。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/partner/portal.php:2-5`（sha256 `e1267edb0f9df936…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$token=(string)($_POST['token']??$_COOKIE['partner_token']??'');$parts=explode('.',$token);$payload=count($parts)===3?json_decode((string)base64_decode(strtr($parts[1],'-_','+/')),true):null;
    3  if(!is_array($payload)||($payload['role']??'')!=='admin')fail_request('此合作方功能仅向管理员开放。',403);
    4  $rows=db()->query('SELECT order_no,total FROM orders ORDER BY id')->fetchAll();
    5  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['role'=>'admin','settlements'=>$rows]);
```

`lab30-shop/app/public/partner/token.php:3-6`（sha256 `391948b46efce76c…`）

```php
    3  function b64url(string $s):string{return rtrim(strtr(base64_encode($s),'+/','-_'),'=');}
    4  $header=b64url(json_encode(['alg'=>'HS256','typ'=>'JWT']));$payload=b64url(json_encode(['sub'=>$u['id'],'role'=>$u['role'],'name'=>$u['username']]));$key=db()->query("SELECT value FROM settings WHERE `key`='generation'")->fetchColumn();$token=$header.'.'.$payload.'.'.b64url(hash_hmac('sha256',$header.'.'.$payload,$key,true));
    5  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['token'=>$token]);
    6  page('合作方服务凭证',function()use($token){echo '<section class="panel"><h2>访问合作方工作台</h2><p>凭证代表当前账户的合作方身份。合作方结算工作台仅对管理员开放。</p><textarea readonly aria-label="合作方凭证">'.h($token).'</textarea><form action="/partner/portal.php" method="post"><input type="hidden" name="token" value="'.h($token).'"><button>进入合作方工作台</button></form></section>';},'账户与会员');
```

### C-06 ops/batch-check.php 将未过滤的 GET host 传入 host_check() 并拼入 shell_exec 命令（独立命令注入入口）

- 当前版本：finding `fcfe4dfec8264ad290950e36a85c0d95` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/host_check.php:2`；文件：`lab30-shop/app/public/ops/batch-check.php`
- 证据引用：`a41ee4811beeaf1b` lab30-shop/app/public/ops/batch-check.php:1-3；`65fc5323ae7c9b98` lab30-shop/app/src/host_check.php:1-2；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10
- 根因类别：task_goal:v2:48ea583584e3b4cb4b49:1（规范类型 command_injection）

**结论陈述（模型产出，不是证据）**

batch-check.php 仅 require_user(['operator','admin']) 做角色校验，随后直接把 $_GET['host'] 强转为字符串并作为唯一实参调用 host_check($host)。host_check() 的实现为 shell_exec('ping -c 1 -W 1 ' . $host)，没有任何 escapeshellarg/escapeshellcmd、白名单或字符过滤，因此 host 参数中的 ; &#124; & $() 反引号 换行等 shell 元字符都会被 /bin/sh 解释执行。执行结果被 page() 回显在 <pre> 中（h() 转义只影响 HTML 显示，不影响已经在服务端执行的命令），形成可回显的命令注入。这是与 ping.php 不同的独立文件、独立入口，虽然共享同一 host_check 语义，但 batch-check 通过 require src/host_check.php 引入该函数，其危险操作定位在 host_check.php:2，且 batch-check.php:2 是独立的用户输入到调用的传递点，属于可独立报告的入口。

- 攻击前身份与适用前提：攻击者需要持有 operator 或 admin 角色账号并已登录（require_user 强制）。GET 请求即可触发，无需 CSRF 令牌。
- 入口 → 传播 → 危险操作/状态变更：HTTP GET 参数 host（/ops/batch-check.php?host=...） → batch-check.php:2 $_GET['host'] → (string) 强转 → host_check($host) → host_check.php:2 shell_exec('ping -c 1 -W 1 ' . $host) → 返回值 $output → batch-check.php:3 输出到 <pre> → host_check.php:2 shell_exec 拼接未转义的 shell 命令片段
- 防护与边界：仅 require_user(['operator','admin']) 做身份/角色校验；无 CSRF（GET 只读操作不涉及状态变更）；无 escapeshellarg、escapeshellcmd、白名单或正则过滤。h() 仅转义 HTML 输出，不阻止命令执行。
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 escapeshellarg($host) 或改用 proc_open 传入参数数组；对 host 做严格白名单（域名/IP 正则）校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/batch-check.php:1-3`（sha256 `5f76332e7ad1b33a…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/host_check.php';require_user(['operator','admin']);$host=(string)($_GET['host']??'');$output=$host!==''?host_check($host):'';
    3  page('主机巡检',function()use($host,$output){echo '<section class="panel"><form method="get">';form_input('host','巡检主机',$host?:'127.0.0.1');echo '<button>委托巡检</button></form><pre>'.h($output).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/host_check.php:1-2`（sha256 `c3a868155c2d335e…`）

```php
    1  <?php
    2  function host_check(string $host): string { return (string)shell_exec('ping -c 1 -W 1 ' . $host); }
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

`lab30-shop/app/src/bootstrap.php:10-10`（sha256 `2050819d093be02b…`）

```php
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

### C-07 在线留言消息体未转义直接输出导致存储型 XSS

- 当前版本：finding `d7c784100b914abaaf2efc21676cd458` revision 1（项目版本 19）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/messages.php:5`；文件：`lab30-shop/app/public/support/messages.php`
- 证据引用：`2ba1a6f9578aa5c7` lab30-shop/app/public/support/messages.php:2-5；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:9e69c271e6e775ad42e7:1（规范类型 xss_s）

**结论陈述（模型产出，不是证据）**

第3行仅校验留言长度与空值后将原始 $_POST['message'] 用参数化 INSERT 入库；第4行读取全部留言；第5行在 HTML 文本上下文中直接输出 $row['message']，而同处 display_name 与 created_at 均调用 h() 转义（bootstrap.php:10 定义 h()=htmlspecialchars ENT_QUOTES），说明消息体被明确遗漏转义。攻击者提交 <script> 或事件处理器标签的留言后，任何用户访问在线留言页即执行脚本，形成存储型 XSS。

- 攻击前身份与适用前提：攻击者持有已登录账户（require_user），受害者访问 /support/messages.php
- 入口 → 传播 → 危险操作/状态变更：$_POST['message']（登录用户提交） → messages.php:3 存入 messages.message → messages.php:4 SELECT m.* → messages.php:5 echo 入 HTML 文本节点 → 未编码输出用户可控 HTML 到页面 body
- 防护与边界：无：h() 可用于同处其他字段但 message 未调用；提交端无 strip_tags/编码
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：输出时使用 h($row['message'])；如需保留换行可用 nl2br(h($row['message']))。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/support/messages.php:2-5`（sha256 `a6866f07b4de32f3…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();
    3  if($_SERVER['REQUEST_METHOD']==='POST') {check_csrf();$message=(string)($_POST['message']??'');if($message===''||strlen($message)>5000)fail_request('留言需为 1–5000 字节。');db()->prepare('INSERT INTO messages(user_id,message) VALUES(?,?)')->execute([$u['id'],$message]);event_log('leave_message');header('Location: /support/messages.php',true,303);exit;}
    4  $rows=db()->query('SELECT m.*,u.display_name FROM messages m JOIN users u ON u.id=m.user_id ORDER BY m.id DESC')->fetchAll();
    5  page('在线留言',function()use($rows){echo '<section class="panel"><h2>和我们聊聊</h2><form method="post">'.csrf_field().'<label>你的留言<textarea name="message" required></textarea></label><button>提交留言</button></form></section><div class="messages">';foreach($rows as$row)echo '<article class="panel"><strong>'.h($row['display_name']).'</strong><time>'.h($row['created_at']).'</time><div class="message-body">'.$row['message'].'</div></article>';echo '</div>';},'客服与帮助');
```

`lab30-shop/app/src/bootstrap.php:10-10`（sha256 `2050819d093be02b…`）

```php
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-08 catalog/greeting.php 的 name 参数未转义直接输出造成反射型 XSS

- 当前版本：finding `f216d637e0bc4222b1b02b6691c60c2d` revision 1（项目版本 17）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/catalog/greeting.php:3`；文件：`lab30-shop/app/public/catalog/greeting.php`
- 证据引用：`c57a3bf6bb6b01db` lab30-shop/app/public/catalog/greeting.php:2-3；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10
- 根因类别：task_goal:v2:67b304025b340a91601b:1（规范类型 xss_r）

**结论陈述（模型产出，不是证据）**

第2行 $name=(string)($_GET['name']??'拾光的朋友') 直接来自请求，第3行以 '<h2>你好，'.$name.'</h2>' 拼接输出，未调用 bootstrap.php:10 定义的 h()。攻击者可用 </h2><script>... 或 <img src=x onerror=...> 注入并执行脚本，属反射型 XSS。

- 攻击前身份与适用前提：受害者点击 /catalog/greeting.php?name=<payload> 链接
- 入口 → 传播 → 危险操作/状态变更：HTTP GET 参数 name → greeting.php:2 $_GET['name'] -> $name -> 第3行 echo 字符串拼接 -> HTML 输出 → echo 未转义的用户输入进入 HTML 文本/标签上下文
- 防护与边界：无：h() 存在但未被调用，页面无 CSRF/输入过滤
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：输出时使用 h($name)（htmlspecialchars, ENT_QUOTES, UTF-8），或改用 form_input 已有的转义方式渲染。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/catalog/greeting.php:2-3`（sha256 `8e6db315fdfc32cf…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$name=(string)($_GET['name']??'拾光的朋友');
    3  page('到店欢迎',function()use($name){echo '<section class="panel"><h2>你好，'.$name.'</h2><p>愿今天也有值得期待的小事。</p><form method="get">';form_input('name','你的称呼');echo '<button>生成欢迎信息</button></form></section>';},'商品目录');
```

`lab30-shop/app/src/bootstrap.php:10-10`（sha256 `2050819d093be02b…`）

```php
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

### C-09 wallet/withdraw.php 先读后写余额且无事务/行锁，可并发竞态超额提现

- 当前版本：finding `851fc104fa3f48efb27bc791df3b42fd` revision 1（项目版本 25）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/wallet/withdraw.php:7`；文件：`lab30-shop/app/public/wallet/withdraw.php`
- 证据引用：`713c1c83b1f33981` lab30-shop/app/public/wallet/withdraw.php:2-11；`85b2e45ff4e8d0eb` lab30-shop/app/src/bootstrap.php:4-8
- 根因类别：task_goal:v2:e8e882de9684bb0004d5:1（规范类型 race_condition）

**结论陈述（模型产出，不是证据）**

withdraw.php 先 SELECT balance 校验 $balance<$amount，然后 usleep(350000) 延迟，再执行 UPDATE users SET balance=? 使用旧读出的 $balance-$amount 覆盖写入，并单独 INSERT withdrawals。整个流程没有事务、没有 SELECT ... FOR UPDATE、也没有 UPDATE ... WHERE balance>=? 的条件更新。并发提交多笔请求时都通过余额校验，均以同一旧余额计算扣减，产生超出实际余额的多笔提现记录（TOCTOU）。

- 攻击前身份与适用前提：持有账号与 CSRF 令牌，余额>0，可并发发送多请求
- 入口 → 传播 → 危险操作/状态变更：$_POST['amount'] → $amount -> SELECT balance -> 余额校验 -> usleep -> UPDATE users SET balance=$balance-$amount → 用陈旧读值覆盖扣减余额并写入提现记录
- 防护与边界：session_write_close() 仅释放会话锁，不保护数据库；无事务与行级锁
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：在事务中使用 SELECT ... FOR UPDATE 或 UPDATE users SET balance=balance-? WHERE id=? AND balance>=? 并检查 rowCount，扣减与插入提现记录同一事务提交。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/wallet/withdraw.php:2-11`（sha256 `e3e73271e379b085…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();require_post();check_csrf();$amount=filter_var($_POST['amount']??null,FILTER_VALIDATE_FLOAT);if($amount===false||$amount<=0||$amount>10000)fail_request('提现金额不正确。');
    3  $id=(int)$u['id'];session_write_close();
    4  $q=db()->prepare('SELECT balance FROM users WHERE id=?');$q->execute([$id]);$balance=(float)$q->fetchColumn();
    5  if($balance<$amount)fail_request('账户余额不足，请调整提现金额。',409);
    6  usleep(350000);
    7  $q=db()->prepare('UPDATE users SET balance=? WHERE id=?');$q->execute([$balance-$amount,$id]);
    8  $q=db()->prepare('INSERT INTO withdrawals(user_id,amount) VALUES(?,?)');$q->execute([$id,$amount]);
    9  $receipt=(int)db()->lastInsertId();
   10  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['status'=>'paid','amount'=>$amount,'balance'=>$balance-$amount,'receipt_id'=>$receipt]);
   11  header('Location: /wallet/index.php?receipt='.$receipt,true,303);exit;
```

`lab30-shop/app/src/bootstrap.php:4-8`（sha256 `2050819d093be02b…`）

```php
    4  function db(): PDO {
    5      static $pdo;
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    7      return $pdo;
    8  }
```

### C-10 orders/detail.php 缺少归属校验，任意登录用户可读取他人订单详情（IDOR）

- 当前版本：finding `9cee2ab3ba5c43afba0da65dc549d07a` revision 1（项目版本 31）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/detail.php:2`；文件：`lab30-shop/app/public/orders/detail.php`
- 证据引用：`171ea369e07c383b` lab30-shop/app/public/orders/detail.php:1-4；`490c7d72eb514d6b` lab30-shop/app/public/orders/index.php:2-2；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:a62f3b1950f10395aa84:1（规范类型 idor）

**结论陈述（模型产出，不是证据）**

detail.php 仅调用 require_user() 建立身份，随后执行 SELECT ... FROM orders o ... WHERE o.id=? 并以 $_GET['id'] 作为唯一条件，没有 o.user_id=当前用户 的约束。订单详情中显示订单号、购买人 username、数量、实付金额与配送备注 private_note，并在 Accept: application/json 时把整行 json_response 输出。因此任何已登录用户遍历 id 即可读取他人订单（水平越权）。对比 orders/index.php 使用 user_id=? 过滤，说明该站点的归属模型是订单属于用户。

- 攻击前身份与适用前提：已登录任意普通用户，知道或枚举订单 id
- 入口 → 传播 → 危险操作/状态变更：$_GET['id'] → $_GET['id'] -> $q->execute([$_GET['id']]) -> $o 整行 -> page() 渲染 / JSON 响应 → 按主键读取订单并返回 order_no/username/quantity/total/private_note 等他人数据
- 防护与边界：仅有 require_user() 登录检查，无 user_id 归属过滤
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：在查询中追加 AND o.user_id=?，用当前会话用户 id 作为条件。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/orders/detail.php:1-4`（sha256 `be69aa78cecffcfd…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();$q=db()->prepare('SELECT o.*,u.username,p.name FROM orders o JOIN users u ON u.id=o.user_id LEFT JOIN products p ON p.id=o.product_id WHERE o.id=?');$q->execute([$_GET['id']??0]);$o=$q->fetch();if(!$o)fail_request('订单不存在。',404);
    3  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response($o);
    4  page('订单详情',function()use($o){echo '<section class="panel"><span class="badge">等待配送</span><h2>'.h($o['order_no']).'</h2><dl>';foreach(['商品'=>$o['name'],'购买人'=>$o['username'],'数量'=>$o['quantity'],'实付金额'=>'¥'.$o['total'],'配送备注'=>$o['private_note']]as$k=>$v)echo '<dt>'.h($k).'</dt><dd>'.h($v).'</dd>';echo '</dl><a class="button secondary" href="/orders/index.php">返回订单中心</a></section>';},'订单中心');
```

`lab30-shop/app/public/orders/index.php:2-2`（sha256 `633f73e04b427bba…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$q=db()->prepare('SELECT o.*,p.name FROM orders o LEFT JOIN products p ON p.id=o.product_id WHERE user_id=? ORDER BY o.id DESC');$q->execute([$u['id']]);$orders=$q->fetchAll();
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-11 密码使用无盐 MD5 存储与校验，弱哈希可被离线快速破解

- 当前版本：finding `ed3c30976efd40ac9390545a10a929a0` revision 1（项目版本 7）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/register.php:8`；文件：`lab30-shop/app/public/auth/register.php`
- 证据引用：`97325d351d8189c3` lab30-shop/app/public/auth/register.php:7-8；`1d3eb2d6e3bdc9fc` lab30-shop/app/public/auth/login.php:6-7；`f86e0ebf4243b153` lab30-shop/app/src/setup.php:7-7；`80b30b229093e94e` lab30-shop/app/src/setup.php:16-17
- 根因类别：task_goal:v2:fc8039939cea9e778a48:1（规范类型 weak_crypto）

**结论陈述（模型产出，不是证据）**

register.php 第 8 行以 md5($password) 无盐写入 users.password_md5（列宽 CHAR(32)，setup.php 第 7 行），login.php 第 7 行同样以 md5($_POST['password']) 与库中值做 hash_equals 比较。未使用 password_hash/password_verify，也无每用户盐与迭代。一旦数据库或备份泄露（项目存在 /account/backup.php 等情形），攻击者可用 GPU/彩虹表对 32 位无盐 MD5 高速爆破得到明文口令，并可跨用户复用已知口令表，属于可操作的弱口令存储缺陷。

- 攻击前身份与适用前提：攻击者获得 password_md5 摘要（数据库泄露、备份下载、SQL 注入等），或需离线校验猜测口令
- 入口 → 传播 → 危险操作/状态变更：注册/登录提交的 password 字段（$_POST['password']） → $_POST['password'] -> md5() -> INSERT/SELECT users.password_md5 -> hash_equals 比较 → 以无盐 MD5 作为口令派生并持久化/比对
- 防护与边界：仅有 hash_equals 做恒定时间比较，不提供抗爆破能力；无盐、无迭代、无 KDF
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.9 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 password_hash(PASSWORD_DEFAULT/ARGON2ID) 存储，登录用 password_verify，并对历史 md5 摘要做迁移（登录成功时重哈希）；数据库列长扩展到 255。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/auth/register.php:7-8`（sha256 `99166a0288be7b1e…`）

```php
    7      $q=db()->prepare('INSERT INTO users(username,password_md5,display_name,email,role,balance,tier,nickname) VALUES(?,?,?,?,?,100,?,?)');
    8      try {$q->execute([$name,md5($password),$name,(string)($_POST['email']??''),'customer','standard',$name]); $notice='注册成功，现在可以登录。';} catch(PDOException $e) {fail_request('该用户名已注册。',409);}
```

`lab30-shop/app/public/auth/login.php:6-7`（sha256 `b9be43ddb2233156…`）

```php
    6      $q=db()->prepare('SELECT id,password_md5 FROM users WHERE username=?'); $q->execute([$_POST['username']??'']); $row=$q->fetch();
    7      if ($row && hash_equals($row['password_md5'],md5((string)($_POST['password']??'')))) {
```

`lab30-shop/app/src/setup.php:7-7`（sha256 `53e7dc7286d7d370…`）

```php
    7      $pdo->exec("CREATE TABLE IF NOT EXISTS users(id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(60) UNIQUE NOT NULL, password_md5 CHAR(32) NOT NULL, display_name VARCHAR(100) NOT NULL, email VARCHAR(200) NOT NULL, role VARCHAR(24) NOT NULL DEFAULT 'customer', balance DECIMAL(12,2) NOT NULL DEFAULT 100, tier VARCHAR(30) NOT NULL DEFAULT 'standard', nickname VARCHAR(200) NOT NULL, homepage VARCHAR(500) NOT NULL DEFAULT '#')");
```

`lab30-shop/app/src/setup.php:16-17`（sha256 `53e7dc7286d7d370…`）

```php
   16      $q=$pdo->prepare('INSERT INTO users(id,username,password_md5,display_name,email,role,balance,tier,nickname) VALUES(?,?,?,?,?,?,100,?,?)');
   17      foreach ([[1,'alice','Alice123!','林晓','alice@shop.local','customer'],[2,'bob','Bob123!','陈远','bob@shop.local','customer'],[3,'operator','Ops123!','运营同事','ops@shop.local','operator'],[4,'admin','Admin123!','系统管理员','admin@shop.local','admin']] as $u) $q->execute([$u[0],$u[1],md5($u[2]),$u[3],$u[4],$u[5],'standard',$u[1]]);
```

### C-12 下单接口信任客户端单价，可用任意价格购买商品

- 当前版本：finding `eebdf3bdd27943f0ae034182eccf9867` revision 1（项目版本 31）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/create.php:3`；文件：`lab30-shop/app/public/orders/create.php`
- 证据引用：`e4ba0faa7c0831b2` lab30-shop/app/public/orders/create.php:3-7；`4a3783191c50b225` lab30-shop/app/src/setup.php:8-9
- 根因类别：task_goal:v2:8aedf5cb6b787fecff95:1（规范类型 price_manipulation）

**结论陈述（模型产出，不是证据）**

orders/create.php 从 $_POST['price'] 读取单价，仅做 FILTER_VALIDATE_FLOAT 与非负校验，未与服务端 products.price 比对；total=round($price*$quantity,2)，并把该 price 写入 orders.unit_price、total 写入 orders.total。setup.php 显示 products.price 是权威价格列，orders 独立存 unit_price/total，故攻击者提交任意低价（含 0）即可成交。

- 攻击前身份与适用前提：攻击者持有效账号与 CSRF 令牌，商品有库存
- 入口 → 传播 → 危险操作/状态变更：已登录用户 POST /orders/create.php 的 price、quantity、product_id 与 csrf → $_POST['price'] -> FILTER_VALIDATE_FLOAT -> $total=round($price*$quantity,2) -> INSERT orders(unit_price,total) → INSERT INTO orders 持久化客户端单价与据此计算的成交总额
- 防护与边界：仅 csrf、FILTER_VALIDATE_FLOAT 与非负检查；无服务端价格比对，products.price 从未参与计算
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：服务端从 products 表读取价格计算 total，忽略客户端 price 字段。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/orders/create.php:3-7`（sha256 `41e73625d7e04c58…`）

```php
    3  $q=db()->prepare('SELECT * FROM products WHERE id=?');$q->execute([$_POST['product_id']??0]);$p=$q->fetch();$quantity=filter_var($_POST['quantity']??0,FILTER_VALIDATE_INT);$price=filter_var($_POST['price']??null,FILTER_VALIDATE_FLOAT);
    4  if(!$p||!$quantity||$quantity<1||$quantity>20||$price===false||$price<0)fail_request('商品、数量或价格不正确。');
    5  $total=round($price*$quantity,2);$pdo=db();$pdo->beginTransaction();
    6  $q=$pdo->prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?');$q->execute([$quantity,$p['id'],$quantity]);if(!$q->rowCount()){$pdo->rollBack();fail_request('商品库存不足。',409);}
    7  $q=$pdo->prepare('INSERT INTO orders(order_no,user_id,product_id,quantity,unit_price,total,private_note) VALUES(?,?,?,?,?,?,?)');$q->execute(['SG-'.bin2hex(random_bytes(5)),$u['id'],$p['id'],$quantity,$price,$total,'会员订单，等待发货']);$id=(int)$pdo->lastInsertId();$pdo->commit();event_log('create_order',['order_id'=>$id,'total'=>$total]);header('Location: /orders/detail.php?id='.$id, true,303);
```

`lab30-shop/app/src/setup.php:8-9`（sha256 `53e7dc7286d7d370…`）

```php
    8      $pdo->exec("CREATE TABLE IF NOT EXISTS products(id INT PRIMARY KEY, name VARCHAR(100), description TEXT, price DECIMAL(12,2), stock INT, color VARCHAR(20))");
    9      $pdo->exec("CREATE TABLE IF NOT EXISTS orders(id INT PRIMARY KEY AUTO_INCREMENT, order_no VARCHAR(60), user_id INT, product_id INT, quantity INT, unit_price DECIMAL(12,2), total DECIMAL(12,2), private_note TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
```

### C-13 ops/members.php 经 member_lookup() 拼接 GET q 造成 SQL 注入

- 当前版本：finding `a4ecdd1dd83b482e955bd517ed03e711` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/member_lookup.php:3`；文件：`lab30-shop/app/src/member_lookup.php`
- 证据引用：`4d2f2da581629f05` lab30-shop/app/src/member_lookup.php:1-4；`12d724d86e16c5f7` lab30-shop/app/public/ops/members.php:1-4；`85b2e45ff4e8d0eb` lab30-shop/app/src/bootstrap.php:4-8
- 根因类别：task_goal:v2:a86109b3b819758a3350:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

src/member_lookup.php:3 将 $term 直接拼入 username LIKE '%...%' 并 db()->query() 执行；调用方 ops/members.php:2 原样传入 $_GET['q']。仅有 require_user(['operator','admin']) 角色校验，未做参数化，operator/admin 账号可注入读取 users 表含 password_md5。

- 攻击前身份与适用前提：持有 operator 或 admin 角色账号
- 入口 → 传播 → 危险操作/状态变更：$_GET['q'] via ops/members.php → ops/members.php:2 $term=(string)$_GET['q'] -> member_lookup($term) -> member_lookup.php:3 拼接 -> db()->query() → PDO::query() 执行外部可控 SQL
- 防护与边界：仅角色校验，无参数化或转义
- 静态判读：缺上下文（1 项）；缺失上下文：nickname 二阶注入路径未执行验证
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 prepare+execute，绑定 '%'.$term.'%'。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/src/member_lookup.php:1-4`（sha256 `eb704332329d4530…`）

```php
    1  <?php
    2  function member_lookup(string $term): array {
    3      return db()->query("SELECT id,username,email,role FROM users WHERE username LIKE '%" . $term . "%'")->fetchAll();
    4  }
```

`lab30-shop/app/public/ops/members.php:1-4`（sha256 `aef140c3800b9cf1…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/member_lookup.php';require_user(['operator','admin']);$term=(string)($_GET['q']??'alice');$rows=member_lookup($term);
    3  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['members'=>$rows]);
    4  page('会员查询',function()use($rows,$term){echo '<section class="panel"><form method="get">';form_input('q','会员名',$term);echo '<button>查询会员</button></form><table><thead><tr><th>编号</th><th>用户名</th><th>邮箱</th><th>角色</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['id']).'</td><td>'.h($r['username']).'</td><td>'.h($r['email']).'</td><td>'.h($r['role']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:4-8`（sha256 `2050819d093be02b…`）

```php
    4  function db(): PDO {
    5      static $pdo;
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    7      return $pdo;
    8  }
```

### C-14 ops/xml-import.php 以 LIBXML_NOENT|LIBXML_DTDLOAD 解析用户提交 XML 导致 XXE 文件读取/SSRF

- 当前版本：finding `8628b52760e64dc698105b43241aa1ad` revision 1（项目版本 27）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/xml-import.php:3`；文件：`lab30-shop/app/public/ops/xml-import.php`
- 证据引用：`c7321e7900aae64d` lab30-shop/app/public/ops/xml-import.php:2-4；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:255610836a7d43b72dcc:1（规范类型 xxe）

**结论陈述（模型产出，不是证据）**

第2行 require_user(['operator','admin']) 仅做角色校验；第3行在 POST 分支中 check_csrf 后取 $_POST['xml'] 直接传入 simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT&#124;LIBXML_DTDLOAD)。LIBXML_NOENT 使外部实体被展开、LIBXML_DTDLOAD 允许加载外部 DTD，攻击者可定义 file:// 或 http:// 实体，读取结果通过 $doc->title 在第4行回显。

- 攻击前身份与适用前提：持有 operator 或 admin 角色会话并携带有效 CSRF token 提交 POST
- 入口 → 传播 → 危险操作/状态变更：POST 参数 xml → $_POST['xml'] -> $xml -> simplexml_load_string(..., LIBXML_NOENT&#124;LIBXML_DTDLOAD) -> $doc->title -> $output -> h($output) → simplexml_load_string 在 LIBXML_NOENT&#124;LIBXML_DTDLOAD 下解析不可信 XML，展开外部实体
- 防护与边界：require_user 角色校验与 check_csrf；未见 LIBXML_NONET 或禁用 DTD/外部实体
- 静态判读：缺上下文（2 项）；缺失上下文：未读取 ops/template-render.php 与 ops/batch-check.php 源码；未读取 support/download.php 源码
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.7 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：解析时移除 LIBXML_NOENT&#124;LIBXML_DTDLOAD，使用 LIBXML_NONET，并禁用 DTD/外部实体（PHP 8 中默认已禁用实体替换，仍应显式加 LIBXML_NONET）。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/xml-import.php:2-4`（sha256 `3c23a76b1047f734…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$output='';$xml='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$xml=(string)($_POST['xml']??'');libxml_use_internal_errors(true);$doc=simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT|LIBXML_DTDLOAD);if(!$doc)fail_request('XML 格式不正确。');$output=(string)$doc->title;}
    4  page('合作方配置导入',function()use($output,$xml){echo '<section class="panel"><form method="post">'.csrf_field().'<label>XML 配置<textarea name="xml" required>'.h($xml?:'<config><title>春日上新</title></config>').'</textarea></label><button>导入配置</button></form><h2>导入结果</h2><pre>'.h($output).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-15 template-preview.php 对用户可控 template 参数直接 include，导致本地/远程文件包含与代码执行

- 当前版本：finding `78bf29e16faf42beb7950d11ba08c7b2` revision 1（项目版本 8）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-preview.php:3`；文件：`lab30-shop/app/public/ops/template-preview.php`
- 证据引用：`3fa8e49da1b5abbd` lab30-shop/app/public/ops/template-preview.php:2-3；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:9af2cbebba33aa7f20fe:1（规范类型 lfi）

**结论陈述（模型产出，不是证据）**

第2行从 $_GET['template'] 获取字符串，第3行直接 include $template。除 require_user(['operator','admin']) 角色检查外，无路径规范化、无 basename、无协议白名单。攻击者可用 php://filter/convert.base64-encode/resource=... 读取服务器任意可读文件；若 allow_url_include=On 且可控制远程资源，则可执行攻击者提供的 PHP 代码。

- 攻击前身份与适用前提：operator 或 admin 已登录会话；远程代码执行还需 allow_url_include=On 与可控远程 URL
- 入口 → 传播 → 危险操作/状态变更：$_GET['template'] → $template -> include $template → include 动态路径
- 防护与边界：仅 require_user 角色校验；无路径/协议限制
- 静态判读：缺上下文（1 项）；缺失上下文：服务器 PHP 配置（allow_url_include、open_basedir、disable_functions）未在已读源码中出现
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.3 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改为服务端白名单模板 ID 映射到固定路径；对路径做 realpath 并限制在模板目录；禁用远程包含。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/template-preview.php:2-3`（sha256 `107da46e9b067ce0…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$template=(string)($_GET['template']??'');
    3  page('远程模板预览',function()use($template){echo '<section class="panel"><form method="get">';form_input('template','模板地址',$template?:'http://fixtures:8080/templates/season.php');echo '<button>加载模板</button></form></section><section class="panel" id="remote-template">';if($template!=='')include $template;echo '</section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-16 account/update.php 批量赋值允许普通用户改写 role/tier/balance 自升管理员

- 当前版本：finding `698950dd0a814514956705b587c6c125` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/update.php:5`；文件：`lab30-shop/app/public/account/update.php`
- 证据引用：`e22c7db798ad872d` lab30-shop/app/public/account/update.php:2-7；`063c928d2d7c3b2e` lab30-shop/app/src/bootstrap.php:33-40
- 根因类别：task_goal:v2:82230886fbe1b411a692:1（规范类型 mass_assignment）

**结论陈述（模型产出，不是证据）**

update.php 在 POST 处理中把 $_POST 的键与固定列名白名单 ['display_name','email','role','balance','tier','nickname','homepage'] 比较，命中即加入 UPDATE 语句，随后以当前会话用户 id 作为 WHERE 条件执行。攻击者只需登录并从同一表单取 CSRF token，即可在保存资料请求中追加 role=admin 或 balance=999999、tier=gold，自升管理员并篡改余额/会员等级。表单不渲染 role/balance 字段，但服务端未限制，属于服务端缺失字段授权。

- 攻击前身份与适用前提：已登录任意普通用户，可获取自己会话的 CSRF token
- 入口 → 传播 → 危险操作/状态变更：POST 参数 role/balance/tier → update.php:4 列白名单 -> update.php:5 循环$_POST 构造 set/values -> update.php:6 prepare('UPDATE users SET ... WHERE id=?') 执行 → UPDATE users SET role/balance/tier ... WHERE id=当前用户
- 防护与边界：仅有 check_csrf 与登录校验，无角色字段级授权；白名单本身包含敏感列
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用显式字段白名单（仅 display_name/nickname/email/homepage），绝不从请求键推导 SQL 列；role/balance/tier 只允许管理员接口修改。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/update.php:2-7`（sha256 `b8227f19c05d0cd3…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$notice='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
    7      if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response($u);
```

`lab30-shop/app/src/bootstrap.php:33-40`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
   38  function csrf_token(): string { start_session(); return $_SESSION['csrf'] ??= bin2hex(random_bytes(24)); }
   39  function csrf_field(): string { return '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'; }
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

### C-17 登录认证成功后不轮换会话 ID，配合 GET sid 预置导致会话固定

- 当前版本：finding `df2050fbceae4f4480f7ae84c69b3c94` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/login.php:8`；文件：`lab30-shop/app/public/auth/login.php`
- 证据引用：`368b0f4121e7e402` lab30-shop/app/public/auth/login.php:3-3；`ab93e1f02607847c` lab30-shop/app/public/auth/login.php:5-9；`9f3b2a689fae3c12` lab30-shop/app/src/bootstrap.php:11-19
- 根因类别：task_goal:v2:497a8a7bfe415aae666f:1（规范类型 session_fixation）

**结论陈述（模型产出，不是证据）**

login.php 第 3 行把攻击者可控的 $_GET['sid'] 传给 start_session()，bootstrap.php 第 13 行显式设置 session.use_strict_mode=0，第 17 行对符合正则的 sid 调用 session_id($sid)，第 18 行使会话激活；登录成功后第 8 行仅写入 $_SESSION['user_id'] 并跳转，全流程无 session_regenerate_id，也未销毁旧会话数据。攻击者可将已知会话 ID 交给受害者（例如 /auth/login.php?sid=AAA...），受害者在同一浏览器完成登录后该 ID 即成为已认证会话，攻击者无需口令即可复用。与已记录结论差异：本条主定位在认证成功的身份写入行，强调缺少认证后 ID 轮换这一根因操作。

- 攻击前身份与适用前提：受害者点击构造的 ?sid= 链接并在同一浏览器登录；会话文件存放在共享 data_dir 下
- 入口 → 传播 → 危险操作/状态变更：GET 参数 sid（及 URL 传播） → $_GET['sid'] -> start_session($sid) -> session_id() -> session_start() -> 登录成功写入 $_SESSION['user_id'] → 使用外部指定会话标识且认证后不调用 session_regenerate_id()
- 防护与边界：sid 有 ^[a-zA-Z0-9,-]{16,64}$ 白名单正则，但白名单并不阻止攻击者选取合法格式的自有 ID；strict_mode 被关闭，Cookie 仅设 httponly/samesite
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.9 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：删除通过 GET 传入 sid 的调用，恢复 session.use_strict_mode=1；在登录成功处调用 session_regenerate_id(true) 后再写入 user_id。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/auth/login.php:3-3`（sha256 `b9be43ddb2233156…`）

```php
    3  start_session(isset($_GET['sid']) ? (string)$_GET['sid'] : null);
```

`lab30-shop/app/public/auth/login.php:5-9`（sha256 `b9be43ddb2233156…`）

```php
    5  if ($_SERVER['REQUEST_METHOD']==='POST') {
    6      $q=db()->prepare('SELECT id,password_md5 FROM users WHERE username=?'); $q->execute([$_POST['username']??'']); $row=$q->fetch();
    7      if ($row && hash_equals($row['password_md5'],md5((string)($_POST['password']??'')))) {
    8          $_SESSION['user_id']=(int)$row['id']; event_log('login');
    9          header('Location: /'); exit;
```

`lab30-shop/app/src/bootstrap.php:11-19`（sha256 `2050819d093be02b…`）

```php
   11  function start_session(?string $sid = null): void {
   12      if (session_status() === PHP_SESSION_ACTIVE) return;
   13      ini_set('session.use_strict_mode', '0');
   14      session_save_path(data_dir() . '/sessions');
   15      session_name('SHOPSESSID');
   16      session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'path' => '/']);
   17      if ($sid !== null && preg_match('/^[a-zA-Z0-9,-]{16,64}$/D', $sid)) session_id($sid);
   18      session_start();
   19  }
```

### C-18 ops/users.php 用客户端 Cookie role 判断管理员，普通登录用户可越权读取全部用户

- 当前版本：finding `4aee3676ac784ef08dd9e83754dfe454` revision 1（项目版本 26）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/users.php:2`；文件：`lab30-shop/app/public/ops/users.php`
- 证据引用：`0ad2a840edc3f2e0` lab30-shop/app/public/ops/users.php:1-5；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:af527b80a186eaef4755:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

users.php 第2行先调用无角色参数的 require_user()，只校验“已登录”；随后 $role=(string)($_COOKIE['role']??$u['role']) 优先取客户端 Cookie，再用 $role!=='admin' 判断。Cookie 由客户端完全控制，普通用户设置 role=admin 即通过，第3行查询、第4/5行输出全站用户 id、username、email、role，形成越权与用户信息泄露。

- 攻击前身份与适用前提：拥有任意普通账号并登录（通过 require_user 登录校验）；请求附加 Cookie role=admin
- 入口 → 传播 → 危险操作/状态变更：HTTP Cookie role（攻击者可控），任意已注册普通账号 → $_COOKIE['role'] ?? $u['role'] -> 第2行 $role!=='admin' -> 第3行 db()->query('SELECT id,username,email,role FROM users ...') -> 第4/5行输出 → db()->query('SELECT id,username,email,role FROM users ORDER BY id') 全量读取用户表并输出
- 防护与边界：require_user() 未传角色列表，bootstrap.php:35 仅在 $roles 非空时校验角色；第2行角色取自 Cookie 而非 $u['role']
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：删除对 $_COOKIE['role'] 的信任，改用 require_user(['admin']) 使用服务端会话角色。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/users.php:1-5`（sha256 `3c5e879d945650ba…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$role=(string)($_COOKIE['role']??$u['role']);if($role!=='admin')fail_request('人员管理需要管理员权限。',403);
    3  $rows=db()->query('SELECT id,username,email,role FROM users ORDER BY id')->fetchAll();
    4  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['access'=>'admin','users'=>$rows]);
    5  page('人员与权限管理',function()use($rows){echo '<section class="panel"><span class="badge">管理员工作区</span><h2>账户权限清单</h2><table><thead><tr><th>用户名</th><th>邮箱</th><th>角色</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['username']).'</td><td>'.h($r['email']).'</td><td>'.h($r['role']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-19 ops/ping.php 将 GET host 直接拼入 shell_exec 导致命令注入

- 当前版本：finding `62e0619b91234d9287ecd100662ac2b2` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/ping.php:2`；文件：`lab30-shop/app/public/ops/ping.php`
- 证据引用：`61f200eb89320676` lab30-shop/app/public/ops/ping.php:1-3；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:36d0afdb5c41b41894b0:1（规范类型 command_injection）

**结论陈述（模型产出，不是证据）**

ping.php 在 require_user(['operator','admin']) 之后取 $_GET['host'] 原样拼接进 'ping -c 1 -W 1 '.$host 交给 shell_exec，无 escapeshellarg/白名单/字符过滤。operator 账户即可注入 ; id 之类命令，输出通过 h($output) 回显在页面 <pre> 中，可直接读取命令执行结果。

- 攻击前身份与适用前提：获得 operator 或 admin 会话（攻击者自注册不可得该角色，需已有运营账号）
- 入口 → 传播 → 危险操作/状态变更：HTTP GET 参数 host → $_GET['host'] -> $host -> shell_exec('ping -c 1 -W 1 '.$host) -> $output -> h($output) 输出 → shell_exec 执行 ping 命令行，未做参数转义
- 防护与边界：仅 require_user 角色校验，无命令参数转义或输入白名单
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 escapeshellarg($host) 或改为纯 PHP 校验的 IP/主机白名单，禁用 shell 调用。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/ping.php:1-3`（sha256 `c15517950afe0794…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$host=(string)($_GET['host']??'');$output=$host!==''?(string)shell_exec('ping -c 1 -W 1 '.$host):'';
    3  page('网络诊断',function()use($host,$output){echo '<section class="panel"><form method="get">';form_input('host','主机地址',$host?:'127.0.0.1');echo '<button>开始诊断</button></form><pre id="diagnostic-output">'.h($output).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-20 ops/maintenance.php 仅凭客户端 X-Admin 请求头放行，未登录即可向 jobs 表写入任务

- 当前版本：finding `d8de220a7c0d45c28ba9210b7db5e3d4` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/maintenance.php:3`；文件：`lab30-shop/app/public/ops/maintenance.php`
- 证据引用：`4e2faa355e456c2e` lab30-shop/app/public/ops/maintenance.php:1-5；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:0aac9d440e37cf333c34:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

maintenance.php 第3行以 $_SERVER['HTTP_X_ADMIN']==='1' 作为唯一授权条件，未调用 require_user()/user()，没有任何服务端身份或角色校验。X-Admin 是任意 HTTP 客户端可自由设置的请求头，任何未认证访问者添加 X-Admin: 1 即可进入第4行 POST 分支，执行 INSERT INTO jobs(user_id,title,status,details) VALUES(4,?,'queued','维护接口发起')，以固定 user_id=4 的系统身份创建后台任务，且可无限重复提交。

- 攻击前身份与适用前提：无需登录；仅需访问 /ops/maintenance.php 并携带 X-Admin: 1
- 入口 → 传播 → 危险操作/状态变更：HTTP 请求头 X-Admin（攻击者完全可控）与 POST 方法 → $_SERVER['HTTP_X_ADMIN'] -> 第3行 if 判断 -> REQUEST_METHOD==='POST' -> 第4行 db()->prepare(...)->execute() 写入 jobs 表 → db()->prepare("INSERT INTO jobs(...) VALUES(4,?,'queued',...)")->execute() 以系统账号身份创建后台任务
- 防护与边界：无有效保护：鉴权完全依赖客户端头，未使用会话/角色/服务端共享密钥；bootstrap.php:33-37 的 require_user() 未被调用
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：删除对 X-Admin 头的信任，改用服务端共享密钥/HMAC 签名或 require_user(['admin']) 做服务端校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/maintenance.php:1-5`（sha256 `b96aecd7df7c5fa4…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';
    3  if(($_SERVER['HTTP_X_ADMIN']??'')!=='1')fail_request('内部维护接口需要有效的服务身份。',403);
    4  if($_SERVER['REQUEST_METHOD']==='POST'){db()->prepare("INSERT INTO jobs(user_id,title,status,details) VALUES(4,?,'queued','维护接口发起')")->execute(['系统对账']);json_response(['accepted'=>true,'job_id'=>(int)db()->lastInsertId()]);}
    5  json_response(['service'=>'settlement-maintenance','authorized'=>true]);
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-21 template-render.php 对 {{}} 内容执行 eval 导致任意 PHP 代码执行

- 当前版本：finding `d675bbff03ed47d8b3a7030670698e59` revision 1（项目版本 25）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-render.php:3`；文件：`lab30-shop/app/public/ops/template-render.php`
- 证据引用：`1c35861d605a775f` lab30-shop/app/public/ops/template-render.php:2-3；`415907ec6bf2f739` lab30-shop/app/src/bootstrap.php:40-40
- 根因类别：task_goal:v2:2889e90694bbdfca552d:1（规范类型 code_execution）

**结论陈述（模型产出，不是证据）**

第2行取 $_POST['template']。第3行在 POST 方法且 check_csrf() 通过后，用 preg_replace_callback 匹配 {{...}}，将捕获内容拼进 'return '.$m[1].';' 交给 eval 执行。任何通过正则的内容（如 system('id') 或 file_get_contents）都会作为 PHP 语句执行，无表达式白名单或沙箱。check_csrf 只是防跨站伪造，不限制已登录运营者执行任意代码。

- 攻击前身份与适用前提：operator/admin 登录会话；POST 请求携带与会话 csrf token 匹配的 csrf 字段
- 入口 → 传播 → 危险操作/状态变更：$_POST['template'] → $template -> preg_replace_callback 捕获 -> eval('return '.$m[1].';') → eval 动态代码执行
- 防护与边界：require_user 角色校验 + check_csrf()
- 静态判读：缺上下文（1 项）；缺失上下文：服务器 PHP 配置（allow_url_include、open_basedir、disable_functions）未在已读源码中出现
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：禁止 eval，改用受限表达式解析器或预定义变量替换白名单。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/template-render.php:2-3`（sha256 `357da9e9959275d8…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$template=(string)($_POST['template']??'');$result='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$result=preg_replace_callback('/\{\{(.*?)\}\}/s',function($m){return (string)eval('return '.$m[1].';');},$template);}
```

`lab30-shop/app/src/bootstrap.php:40-40`（sha256 `2050819d093be02b…`）

```php
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

### C-22 ops/report.php:3 二阶 SQL 注入：用户可控 nickname 经数据库回读后拼接进查询

- 当前版本：finding `700feba487aa40418d41463dd10462c4` revision 1（项目版本 16）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/report.php:3`；文件：`lab30-shop/app/public/account/update.php`
- 证据引用：`ec18381d7af73d0f` lab30-shop/app/public/account/update.php:4-6；`667c91ac7c21aa66` lab30-shop/app/public/ops/report.php:2-3
- 根因类别：task_goal:v2:d5e9f62dab57097336f5:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

update.php:4-6 仅对列名做白名单校验，$_POST['nickname'] 的值以 (string) 强制转换后作为参数写入 users 表，没有任何字符转义或格式校验。ops/report.php:2 用预处理按 user_id 取回 nickname，第 3 行却用 "... WHERE nickname='".$nickname."'" 拼接后交给 db()->query() 执行，库内攻击者控制的值重新进入 SQL 文本，形成二阶注入。注入可闭合引号后用 UNION 读取任意表或通过布尔/报错差异盲注，影响同一数据库内任意数据。

- 攻击前身份与适用前提：攻击者任意可注册普通账号并拥有有效 CSRF token 完成资料更新；随后具备 operator 或 admin 角色的账号访问 /ops/report.php?user_id=<攻击者id>（报表页需运营权限）
- 入口 → 传播 → 危险操作/状态变更：POST /account/update.php 的 nickname 字段（任意登录用户可控） → $_POST['nickname'] -> UPDATE users SET nickname=? -> users.nickname -> report.php:2 SELECT nickname WHERE id=? -> $nickname -> report.php:3 字符串拼接 -> db()->query() → db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'") 未参数化执行
- 防护与边界：写入端仅有列名 in_array 白名单，值未过滤；读取端仅第 2 行使用占位符，第 3 行拼接无转义；PDO::EMULATE_PREPARES=false 不影响拼接语句
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：report.php:3 改为预处理占位符绑定 $nickname；update.php 对 nickname 增加长度与字符白名单校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/update.php:4-6`（sha256 `b8227f19c05d0cd3…`）

```php
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
```

`lab30-shop/app/public/ops/report.php:2-3`（sha256 `90d7d60d44815374…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user(['operator','admin']);$id=(int)($_GET['user_id']??1);$q=db()->prepare('SELECT nickname FROM users WHERE id=?');$q->execute([$id]);$nickname=$q->fetchColumn();if($nickname===false)fail_request('会员不存在。',404);
    3  $rows=db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'")->fetchAll();
```

### C-23 ops/url-preview.php 对 GET url 无协议/主机限制并回显响应，形成全回显 SSRF

- 当前版本：finding `72571ec3e8ea4c5aab726bd1d32e803c` revision 1（项目版本 25）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/url-preview.php:3`；文件：`lab30-shop/app/public/ops/url-preview.php`
- 证据引用：`17e1cacfb5189678` lab30-shop/app/public/ops/url-preview.php:2-4；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:bd0c2f643d2ddf02f108:1（规范类型 ssrf）

**结论陈述（模型产出，不是证据）**

第2行从 $_GET['url'] 取值后仅判断非空，第3行用 stream_context_create 只设置 timeout 与 follow_location=0，未限制 scheme 或目标主机，直接 @file_get_contents($url,false,$context,0,65536) 以服务端身份请求任意 URL；第4行把返回内容经 h() 输出到页面，攻击者可读取内网 HTTP 服务响应。require_user(['operator','admin']) 只校验运营/管理员角色，不构成对目标地址的防护。

- 攻击前身份与适用前提：持有 operator 或 admin 角色会话；请求 /ops/url-preview.php?url=<目标地址>
- 入口 → 传播 → 危险操作/状态变更：GET 参数 url → $_GET['url'] -> $url -> file_get_contents($url,false,$context,0,65536) -> $output -> h($output) 输出 → file_get_contents 以服务端身份请求任意 URL 并回显内容
- 防护与边界：仅 require_user(['operator','admin']) 角色校验与 @ 错误抑制、超时 4 秒、禁止跟随跳转；无 scheme/内网地址白名单或过滤
- 静态判读：缺上下文（2 项）；缺失上下文：未读取 ops/template-render.php 与 ops/batch-check.php 源码；未读取 support/download.php 源码
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：限制 scheme 为 http/https，解析主机并拒绝环回/私有/链路本地地址，禁用 file://、gopher://、dict:// 等；使用 allowlist 或服务端 egress 过滤。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/url-preview.php:2-4`（sha256 `e495938b10c455c6…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$url=(string)($_GET['url']??'');$output='';
    3  if($url!==''){$context=stream_context_create(['http'=>['timeout'=>4,'follow_location'=>0]]);$value=@file_get_contents($url,false,$context,0,65536);$output=$value===false?'暂时无法获取该地址。':$value;}
    4  page('链接预览',function()use($url,$output){echo '<section class="panel"><form method="get">';form_input('url','内容地址',$url?:'http://fixtures:8080/catalog-info');echo '<button>读取预览</button></form><pre>'.h($output).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-24 support/download.php 未校验 file 参数导致目录穿越任意文件读取

- 当前版本：finding `57cf09156cf044bdb01ade2bb62472d6` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/download.php:3`；文件：`lab30-shop/app/public/support/download.php`
- 证据引用：`8bf814169e217985` lab30-shop/app/public/support/download.php:1-4；`f5faf41dff9a5a91` lab30-shop/app/src/bootstrap.php:9-9；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:9c4c992aa7829d74267d:1（规范类型 path_traversal）

**结论陈述（模型产出，不是证据）**

download.php 取 $_GET['file'] 直接拼接到 data_dir().'/docs/' 后交给 file_get_contents 输出，只有 is_file 检查，没有 basename、realpath 或前缀校验，因此 ../ 序列可穿越到 docs 目录之外读取服务器上任意可读文件（如 /var/lib/shop/sessions 下的会话文件、配置文件）。

- 攻击前身份与适用前提：任意已登录用户（require_user 无角色限制）
- 入口 → 传播 → 危险操作/状态变更：HTTP GET 参数 file → $_GET['file'] -> $path = data_dir().'/docs/'.$_GET['file'] -> is_file($path) -> file_get_contents($path) -> echo → file_get_contents 读取攻击者指定路径并回显
- 防护与边界：仅 is_file 存在性检查，无路径规范化/前缀白名单
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 basename($file) 或 realpath 后校验结果仍位于 data_dir()/docs 前缀内，并限制扩展名。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/support/download.php:1-4`（sha256 `71f0558eeb4ebb6c…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();
    3  if(isset($_GET['file'])){$path=data_dir().'/docs/'.(string)$_GET['file'];if(!is_file($path))fail_request('文档不存在。',404);header('Content-Type: text/plain; charset=utf-8');echo file_get_contents($path);exit;}
    4  page('帮助文档',function(){echo '<section class="panel"><h2>常用服务文档</h2><ul><li><a href="?file=shipping.txt">配送说明</a></li><li><a href="?file=returns.txt">售后说明</a></li></ul><form method="get">';form_input('file','文档文件名','shipping.txt');echo '<button>查看文档</button></form></section>';},'客服与帮助');
```

`lab30-shop/app/src/bootstrap.php:9-9`（sha256 `2050819d093be02b…`）

```php
    9  function data_dir(): string { return getenv('SHOP_DATA_DIR') ?: '/var/lib/shop'; }
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-25 Operator-controlled PHP function name passed to dynamic call in ops/formula.php enables arbitrary PHP function invocation

- 当前版本：finding `c8457162af18469b99170691ab9d29d0` revision 1（项目版本 11）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/formula.php:3`；文件：`lab30-shop/app/public/ops/formula.php`
- 证据引用：`f3b7c0b40a3232d5` lab30-shop/app/public/ops/formula.php:1-4；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36；`86b74a4529a1394f` lab30-shop/app/public/ops/index.php:3-3
- 根因类别：task_goal:v2:94a2ee7f24d6be912718:1（规范类型 code_execution）

**结论陈述（模型产出，不是证据）**

ops/formula.php line 3 reads $_GET['func'], casts it to string, and invokes it as an arbitrary PHP function with $_GET['arg'] as the single string argument, storing the return value. There is no allowlist, mapping table, or signature check, so any function name the requester supplies (for example a filesystem, environment, or code-evaluation helper) is called. Access requires an operator or admin session (line 2), but within that role the callable set is fully attacker-chosen. Result output is h()-escaped, so this is function/code invocation rather than reflected XSS.

- 攻击前身份与适用前提：Authenticated session with role operator or admin; GET request with func/arg parameters
- 入口 → 传播 → 危险操作/状态变更：$_GET['func'] (function name) and $_GET['arg'] (string argument) → $_GET['func'] -> (string) cast -> $func -> $func((string)$_GET['arg']) at formula.php:3 -> return value -> $result -> h($result) output at formula.php:4 → Dynamic PHP function invocation $func($arg) where $func is fully controlled by the request
- 防护与边界：Only require_user(['operator','admin']) authentication/role gate; no allowlist or callable whitelist on the function name, only output escaping
- 静态判读：缺上下文（2 项）；缺失上下文：/auth/login.php field names and response for the POC login step were not read.；Actual filesystem layout under APP_ROOT/resources/views and the data dir for page.php traversal resolution were not enumerated.
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：Replace the arbitrary callable dispatch with an explicit allowlist/map of supported formula operations (for example ['upper'=>'strtoupper', ...]) and reject any func value not in that map; never invoke a request-supplied string as a PHP function.

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/formula.php:1-4`（sha256 `686f39f31996a5d3…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$result='';
    3  if(isset($_GET['func'])){$func=(string)$_GET['func'];$result=(string)$func((string)($_GET['arg']??''));}
    4  page('运营公式计算',function()use($result){echo '<section class="panel"><p>选择函数并提交文本进行试算。</p><form method="get">';form_input('func','函数名称','strtoupper');form_input('arg','输入值','spring-sale');echo '<button>执行计算</button></form><pre>'.h($result).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:10-10`（sha256 `2050819d093be02b…`）

```php
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

`lab30-shop/app/public/ops/index.php:3-3`（sha256 `3e08442a501932a5…`）

```php
    3  page('运营工作台',function(){echo '<section class="panel"><h2>业务协作，井然有序</h2><p>管理会员与任务，检查基础服务，维护商城内容。</p></section><div class="cards">';foreach([['members.php','会员查询','检索会员联系信息。'],['users.php','人员管理','查看后台用户与权限。'],['ping.php','网络诊断','检查服务的基础连通性。'],['batch-check.php','主机巡检','委托公共巡检服务检测主机。'],['formula.php','公式计算','试算运营数据与规则。'],['database.php','数据库诊断','检查数据源连接。'],['url-preview.php','链接预览','获取外部内容的文本预览。'],['xml-import.php','配置导入','导入合作方 XML 配置。'],['template-preview.php','远程模板','预览合作方页面模板。'],['template-render.php','内容排版','按表达式渲染营销内容。'],['jobs.php','任务中心','导入与查看运营任务。'],['report.php','会员报表','根据已保存昵称生成报表。'],['maintenance.php','维护接口','查看内部维护服务。'],['audit-log.php','操作记录','查看业务操作流水。']]as$c)echo '<a class="feature-card" href="/ops/'.$c[0].'"><h3>'.$c[1].' ↗</h3><p>'.$c[2].'</p></a>';echo '</div>';},'运营工作台');
```

## 5. 实际验证和终审理由

本次运行没有动态验证或正式复核记录；相关结论均标注为未验证/未复核。

## 6. 覆盖与未决项

| 独立分母 | 总数 | 已结算 | 未决/待办 | 闭环 |
|---|---:|---:|---:|---|
| 文件覆盖 | 61 | 读取 55；读取+跳过 60 | 1 | 否 |
| 必做方向 | 9 | 已决 6；跳过 0 | 3 | 否 |
| 动态验证 | 25 | 已验证 0；已复核记录 0 | 待验证 25；待复核 0 | — |
| 正式终审 | 25 | 已接受 0 | 待终审 25；存疑 0 | — |

**带理由跳过的文件**

- `lab30-shop/app/public/assets/app.js`：纯前端静态脚本，不含服务端输入处理或危险操作 sink，不属于本目标的服务端漏洞证据面。
- `lab30-shop/app/public/assets/products.svg`：静态 SVG 资源，无服务端脚本或动态输入处理，不属于可被外部输入触发的服务端漏洞面。
- `lab30-shop/bin/package.py`：打包脚本，不暴露于运行时外部输入；其生成的部署目录不在冻结快照内，无法作为源码审计对象。
- `lab30-shop/compose.yaml`：容器编排配置，仅部署参数，无可被外部请求触发的漏洞路径；其缺失的 php.ini 配置已写入 missing_context 供 worker 参考。
- `lab30-shop/docker/php.ini`：PHP 运行时配置，非第一方业务源码；其 allow_url_include/open_basedir 取值影响 LFI/RFI 可利用性判断，但通过 missing_context 说明而非作为代码审计任务。

**后续建议（不阻止本次收束）**

- `dir_b3a3dfa4f0660e39afc7ed15271edafa`：lab30-shop/app/public/auth/continue.php:3 的 header('Location: '.(string)$_GET['next']) 未做白名单校验，存在登录后开放重定向，需单独作为 open_redirect 方向取证
- `dir_ee4663c32887b4ebf274e3ca4324946d`：lab30-shop/app/public/account/backup.php 是否导出 users.password_md5 摘要，影响弱哈希的实际可达泄露面
- `dir_033f963e75bc8a7aeb25f5cf62e41309`：检查 report.php 注入是否可结合堆叠语句写入或其他 secondary sink
- `dir_41f3755ab9884c8273c8560db3315c96`：检查 account/update.php 批量赋值 role/balance 的独立影响（已有候选，勿重复）
- `dir_b585fd8af47bae082a0dc5556c0922b1`：lab30-shop/app/public/ops/xml-import.php：本方向要求的 XXE 输入控制尚未读取源码，需读取该文件确认 XML 解析函数、LIBXML_NOENT/外部实体处理及响应回显。
- `dir_4fb5ca3c8e61d23d2009fd23659bea89`：审查 template-render.php 是否还有其它调用方传递 template 参数
- `dir_c377bf15539f99c5048f585233932d10`：确认部署配置 allow_url_include 与 open_basedir 是否在快照中（未读取到 php.ini/docker 配置），以精确化 RFI 可利用性
- `dir_a26fe028520670f77ad6d608a8edb4be`：审计 ops/template-render.php 与 ops/batch-check.php 的独立 sink（模板渲染代码执行、host_check 拼接），需实际读取源码取证
- `dir_97a0e4d084852f00985b377ca956bcab`：核查 support/download.php 是否存在路径穿越/IDOR（已在导航中提示，尚未读取）
- `dir_596ab3ff1038c25262a13fd95ec939d7`：Confirm the login flow parameters in /auth/login.php to validate the PoC credential fields.

**补证与未决动作**

- `06dfba1e2ffb494391c75370589162fc` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（catalog/index.php 中 GET q 直接拼接进 LIKE 查询导致 SQL 注入）
- `0727def603f44c6db0ae464cc8a1c479` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（用户口令以无盐 md5 存储与校验，泄露后可被快速破解）
- `0c40d00aa77d40bfa437f51a0df8f5f9` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（登录页接受 GET sid 且关闭 use_strict_mode，攻击者可预置会话 ID 实施会话固定）
- `1cf676ca0204434a822388c238446109` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/jobs.php 反序列化 DispatchJob 触发 __wakeup 中 shell_exec 任意命令执行）
- `22ae6596fa074b659f5346e9397b4fdb` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（partner/portal.php 信任客户端 JWT payload 中 role，普通用户可伪造 admin 读取全部订单结算）
- `2d1fd2cf375c4021b16960c5c52b852d` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/batch-check.php 将未过滤的 GET host 传入 host_check() 并拼入 shell_exec 命令（独立命令注入入口））
- `35cb594a16274ac79907a659717056d0` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（在线留言消息体未转义直接输出导致存储型 XSS）
- `3d7bcd8666c149e884a6533f109c96f2` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（catalog/greeting.php 的 name 参数未转义直接输出造成反射型 XSS）
- `494423ddc5fb4859bd074dca9235a8c5` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（wallet/withdraw.php 先读后写余额且无事务/行锁，可并发竞态超额提现）
- `4e35ce72f856430faf590095346c382a` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（orders/detail.php 缺少归属校验，任意登录用户可读取他人订单详情（IDOR））
- `527d01def9cc47ad87f8bdfc2422f2ba` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（密码使用无盐 MD5 存储与校验，弱哈希可被离线快速破解）
- `5a1f8b8736b246b9ae6d081c49f50198` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（下单接口信任客户端单价，可用任意价格购买商品）
- `6b0b017641d0406d855bb367b891b665` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/members.php 经 member_lookup() 拼接 GET q 造成 SQL 注入）
- `7905401b64084de6956b3ecd7b67e0a9` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/xml-import.php 以 LIBXML_NOENT&#124;LIBXML_DTDLOAD 解析用户提交 XML 导致 XXE 文件读取/SSR…）
- `84652dd95a814ae4b7d93fcd84a65de5` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（template-preview.php 对用户可控 template 参数直接 include，导致本地/远程文件包含与代码执行）
- `876ff6c2cacc4d85ba72c837f3c02521` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（account/update.php 批量赋值允许普通用户改写 role/tier/balance 自升管理员）
- `90141c1dad64463cad9833f3baed79bb` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（登录认证成功后不轮换会话 ID，配合 GET sid 预置导致会话固定）
- `9a66a667a5f046388568cfa10ff63cfe` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/users.php 用客户端 Cookie role 判断管理员，普通登录用户可越权读取全部用户）
- `ad05ccb8c7044994b5fe7ce097bdedf9` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/ping.php 将 GET host 直接拼入 shell_exec 导致命令注入）
- `bb47d5090ced4674b6fe3697351b98df` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/maintenance.php 仅凭客户端 X-Admin 请求头放行，未登录即可向 jobs 表写入任务）
- `bfd1580e14754964a21945d15907d435` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（template-render.php 对 {{}} 内容执行 eval 导致任意 PHP 代码执行）
- `c69fbc2e3f51448ba5c70f09c96bcb39` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/report.php:3 二阶 SQL 注入：用户可控 nickname 经数据库回读后拼接进查询）
- `c75a2af277c24086a450dc46dad72708` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/url-preview.php 对 GET url 无协议/主机限制并回显响应，形成全回显 SSRF）
- `da23d3ddf5774fadaee969fc13972acd` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（support/download.php 未校验 file 参数导致目录穿越任意文件读取）
- `fd7b2de1f92542ed9e05b5d2de82edc1` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（Operator-controlled PHP function name passed to dynamic call in ops/formula.php …）
- 3 项：逐个结算未决方向：读取、给出证据或明确 skip 理由。
- 1 项：读取或带理由复核未覆盖文件。

**限制**

- 受阻、未执行、未读取的方向均不代表安全。
- 本次运行未同时满足完成状态、覆盖闭环与验证闭环，本报告为阶段报告。
- 仍有 25 条规范结论未获得正式确认，不计入已接受漏洞。
- 3 个审计方向尚未结算。

## 7. 附录与证据索引

**历史版本与来源记录**

| 规范结论 | finding | revision | 处置 | 验证 | 当前 |
|---|---|---:|---|---|---|
| `494423ddc5fb4859bd074dca9235a8c5` | `75af79d3371b4d3ea4009ac61cafd35f` | 1 | open | unverified | 否 |
| `494423ddc5fb4859bd074dca9235a8c5` | `851fc104fa3f48efb27bc791df3b42fd` | 1 | open | unverified | 是 |
| `7905401b64084de6956b3ecd7b67e0a9` | `70cdadf0b2af4a8793aca66e7565bb8b` | 1 | open | unverified | 否 |
| `7905401b64084de6956b3ecd7b67e0a9` | `8628b52760e64dc698105b43241aa1ad` | 1 | open | unverified | 是 |
| `c75a2af277c24086a450dc46dad72708` | `687c1c005bab41999223eb588d53ad9d` | 1 | open | unverified | 否 |
| `c75a2af277c24086a450dc46dad72708` | `72571ec3e8ea4c5aab726bd1d32e803c` | 1 | open | unverified | 是 |

**撤回、重复或替代记录**

- `e45eb55e7ed3450187294161666dbf89`（revision 1）：duplicate——catalog/index.php 搜索参数 q 直接拼接进 SQL 查询导致 SQL 注入
- `12f1e2fc34ee4a70a4efdd1b5b40df1e`（revision 1）：duplicate——ops/template-preview.php 将 $_GET['template'] 直接 include 导致本地/远程文件包含与代码执行
- `e3bfca61c5834659930530276e6f749f`（revision 1）：duplicate——ops/template-render.php 将 $_POST['template'] 的 {{}} 内容直接 eval 导致任意 PHP 代码执行

**关联链路对照（位置或引用关联不代表重复）**

- `0727def603f44c6db0ae464cc8a1c479` ↔ `527d01def9cc47ad87f8bdfc2422f2ba`：仍需对照判读；尚未明确判读是否具有不同根因。
- `0c40d00aa77d40bfa437f51a0df8f5f9` ↔ `90141c1dad64463cad9833f3baed79bb`：仍需对照判读；尚未明确判读是否具有不同根因。

**任务记录**

| 任务 | 标题 | 状态 | 错误 |
|---|---|---|---|
| `33a2a777748548a3b7910c0e265a7cdc` | bootstrap 与数据库访问层的 SQL 注入排查 | completed | — |
| `e9629609cf6d4e40896aebbfa9f9ee20` | 账户模块的鉴权边界与 IDOR | completed | — |
| `07cc6176d3c947abb4b25d9885673860` | catalog 与模板层的反射/存储型 XSS | completed | — |
| `d1512531d59a42bf839e12f42eeb8db5` | wallet 与 orders 的业务逻辑与重放风险 | completed | — |
| `d2b267e7bafb472e87fb34f42649b700` | support 与 ops 入口的注入与文件风险 | completed | — |
| `9598d05e897a45ae8f2d7c92c36bf246` | auth 登录/注册/会话流程的认证与会话安全 | completed | — |
| `ec9e074bdc324988bb9221a9bbe85d62` | CLI 脚本与初始化逻辑的输入面 | completed | — |
| `4c69c53d1a854e4dafd5350ed0daeee9` | ops/report.php 二阶 SQL 注入与 account/update.php 写入链 | completed | — |
| `a197fbe555ee483f9655019cf83c22de` | ops/url-preview.php SSRF 输入控制与 URL 校验 | completed | — |
| `4dfe2631777146f6ab88ecd2c3a306ad` | ops/xml-import.php XML 解析与 XXE | completed | — |
| `eb49e576f4b34bc59082d0dfef0e6b77` | support/messages.php 存储型 XSS 与输出上下文 | completed | — |
| `31325f0dc8bb4546aa36d4c5e34573bb` | ops/jobs.php 反序列化链与 DispatchJob 命令执行 | completed | — |
| `394ef372daaf441898a7561e8a105432` | ops/template-preview.php LFI/RFI 与 template-render.php eval 代码执行 | completed | — |
| `97391c2cc4cf45a292c6e1407535c0fd` | orders 与 wallet 的下单定价、IDOR 与提现逻辑 | completed | — |
| `a4398a98cede4832b29c10d550ee6ed0` | ops 管理入口的鉴权边界（X-Admin 头伪造与越权） | completed | — |
| `0e0ba8864ccb4345865b28b967c666c2` | ops/template-preview.php 路径遍历与 template-render.php 动态执行可利用性 | completed | — |
| `b5e5c5752b2a4613bc5b4fa1654be86e` | ops/url-preview.php SSRF、xml-import.php XXE、ping.php 命令注入的独立取证 | completed | — |
| `f6f1814a9caa490f9e82f21c6eda8779` | ops/batch-check.php→host_check.php 独立命令注入入口 | completed | — |
| `5a868c2be89a4029a1498e721c22e2a0` | content/page.php include 路径穿越与可执行文件落点核查 | cancelled | 模型连续失败 3 次（worker）：ModelCallFailed: APIConnectionError: Connection error. |
| `2878d022400849d891268c8250d3fe2b` | 未读第一方文件：content/page.php 与 ops/formula.php 的输入处理 | completed | — |
| `81e62e4cac5747248a0d8d0662779db9` | 覆盖缺口 lab30-shop/fixtures/server.py 的读取与定位 | blocked | 模型连续失败 3 次（worker）：ModelCallFailed: APIConnectionError: Connection error. |

- 用量：上限 响应 2048；工具 16384；秒 10800；实际 响应 95；工具 147；秒 592.856；剩余 响应 1953；工具 16237；秒 10207.144

**证据索引（服务器读取）**

| evidence_id | 路径 | 范围 | 文件哈希 | 可用 |
|---|---|---|---|---|
| `2ee6bd3796c99bfe` | lab30-shop/app/public/catalog/index.php | 2-4 | `e85bd1c2fa6a4b78` | 是 |
| `85b2e45ff4e8d0eb` | lab30-shop/app/src/bootstrap.php | 4-8 | `2050819d093be02b` | 是 |
| `80b30b229093e94e` | lab30-shop/app/src/setup.php | 16-17 | `53e7dc7286d7d370` | 是 |
| `850e65d55415065d` | lab30-shop/app/public/auth/register.php | 8-8 | `99166a0288be7b1e` | 是 |
| `f7b097d7ada046e5` | lab30-shop/app/public/auth/login.php | 7-7 | `b9be43ddb2233156` | 是 |
| `5f912f7499e51381` | lab30-shop/app/public/auth/login.php | 3-9 | `b9be43ddb2233156` | 是 |
| `9f3b2a689fae3c12` | lab30-shop/app/src/bootstrap.php | 11-19 | `2050819d093be02b` | 是 |
| `bc71d05290d8c856` | lab30-shop/app/public/ops/jobs.php | 2-3 | `0f7550fa7f16bd4a` | 是 |
| `e030edd4e1bdfc70` | lab30-shop/app/src/dispatch_job.php | 2-4 | `e8234b971fe75d85` | 是 |
| `063c928d2d7c3b2e` | lab30-shop/app/src/bootstrap.php | 33-40 | `2050819d093be02b` | 是 |
| `bce6927d778989fd` | lab30-shop/app/public/partner/portal.php | 2-5 | `e1267edb0f9df936` | 是 |
| `550f5e4c71ae4d33` | lab30-shop/app/public/partner/token.php | 3-6 | `391948b46efce76c` | 是 |
| `a41ee4811beeaf1b` | lab30-shop/app/public/ops/batch-check.php | 1-3 | `5f76332e7ad1b33a` | 是 |
| `65fc5323ae7c9b98` | lab30-shop/app/src/host_check.php | 1-2 | `c3a868155c2d335e` | 是 |
| `78224482780bf94a` | lab30-shop/app/src/bootstrap.php | 33-37 | `2050819d093be02b` | 是 |
| `5220b9ce518719f6` | lab30-shop/app/src/bootstrap.php | 10-10 | `2050819d093be02b` | 是 |
| `2ba1a6f9578aa5c7` | lab30-shop/app/public/support/messages.php | 2-5 | `a6866f07b4de32f3` | 是 |
| `c57a3bf6bb6b01db` | lab30-shop/app/public/catalog/greeting.php | 2-3 | `8e6db315fdfc32cf` | 是 |
| `713c1c83b1f33981` | lab30-shop/app/public/wallet/withdraw.php | 2-11 | `e3e73271e379b085` | 是 |
| `171ea369e07c383b` | lab30-shop/app/public/orders/detail.php | 1-4 | `be69aa78cecffcfd` | 是 |
| `490c7d72eb514d6b` | lab30-shop/app/public/orders/index.php | 2-2 | `633f73e04b427bba` | 是 |
| `97325d351d8189c3` | lab30-shop/app/public/auth/register.php | 7-8 | `99166a0288be7b1e` | 是 |
| `1d3eb2d6e3bdc9fc` | lab30-shop/app/public/auth/login.php | 6-7 | `b9be43ddb2233156` | 是 |
| `f86e0ebf4243b153` | lab30-shop/app/src/setup.php | 7-7 | `53e7dc7286d7d370` | 是 |
| `e4ba0faa7c0831b2` | lab30-shop/app/public/orders/create.php | 3-7 | `41e73625d7e04c58` | 是 |
| `4a3783191c50b225` | lab30-shop/app/src/setup.php | 8-9 | `53e7dc7286d7d370` | 是 |
| `4d2f2da581629f05` | lab30-shop/app/src/member_lookup.php | 1-4 | `eb704332329d4530` | 是 |
| `12d724d86e16c5f7` | lab30-shop/app/public/ops/members.php | 1-4 | `aef140c3800b9cf1` | 是 |
| `c7321e7900aae64d` | lab30-shop/app/public/ops/xml-import.php | 2-4 | `3c23a76b1047f734` | 是 |
| `3fa8e49da1b5abbd` | lab30-shop/app/public/ops/template-preview.php | 2-3 | `107da46e9b067ce0` | 是 |
| `e22c7db798ad872d` | lab30-shop/app/public/account/update.php | 2-7 | `b8227f19c05d0cd3` | 是 |
| `368b0f4121e7e402` | lab30-shop/app/public/auth/login.php | 3-3 | `b9be43ddb2233156` | 是 |
| `ab93e1f02607847c` | lab30-shop/app/public/auth/login.php | 5-9 | `b9be43ddb2233156` | 是 |
| `0ad2a840edc3f2e0` | lab30-shop/app/public/ops/users.php | 1-5 | `3c5e879d945650ba` | 是 |
| `61f200eb89320676` | lab30-shop/app/public/ops/ping.php | 1-3 | `c15517950afe0794` | 是 |
| `4e2faa355e456c2e` | lab30-shop/app/public/ops/maintenance.php | 1-5 | `b96aecd7df7c5fa4` | 是 |
| `1c35861d605a775f` | lab30-shop/app/public/ops/template-render.php | 2-3 | `357da9e9959275d8` | 是 |
| `415907ec6bf2f739` | lab30-shop/app/src/bootstrap.php | 40-40 | `2050819d093be02b` | 是 |
| `ec18381d7af73d0f` | lab30-shop/app/public/account/update.php | 4-6 | `b8227f19c05d0cd3` | 是 |
| `667c91ac7c21aa66` | lab30-shop/app/public/ops/report.php | 2-3 | `90d7d60d44815374` | 是 |
| `17e1cacfb5189678` | lab30-shop/app/public/ops/url-preview.php | 2-4 | `e495938b10c455c6` | 是 |
| `8bf814169e217985` | lab30-shop/app/public/support/download.php | 1-4 | `71f0558eeb4ebb6c` | 是 |
| `f5faf41dff9a5a91` | lab30-shop/app/src/bootstrap.php | 9-9 | `2050819d093be02b` | 是 |
| `f3b7c0b40a3232d5` | lab30-shop/app/public/ops/formula.php | 1-4 | `686f39f31996a5d3` | 是 |
| `6220461f4c36cb1a` | lab30-shop/app/src/bootstrap.php | 33-36 | `2050819d093be02b` | 是 |
| `86b74a4529a1394f` | lab30-shop/app/public/ops/index.php | 3-3 | `3e08442a501932a5` | 是 |

**附件与机器可读清单**

- Markdown：本报告（由事实包确定性生成）。
- JSON：result.json（含本事实包与质量结果）
- 证据包：evidence/（POC 脚本、runner 产物、runner manifest）
- 源码：源码片段由宿主从冻结快照读取，见 source_evidence
- 事实包 ID：`e42ce475c66c7860e96c3758ba147c166d4565c00752466f17f8e90bffce83b6`；页面、Markdown、JSON 与证据包共用同一份事实。
