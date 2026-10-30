# 源码审计阶段报告（17fc2e83）

> 报告类型：阶段报告；发布状态：可发布（阶段报告）
> 事实包 final-review/v1 · 渲染器 final-report/v2 · 策略 audit-runtime-3
> 运行 `17fc2e83ab1342a089583b548e45daa0` · 快照 `586b79b41f8e4f59be80f2a9b548902b` · 源码哈希 `67fd87e9ae771d10…` · 输入哈希 `0b7c8bb1bfbc17edb3f1280b49bb5e4f8207818e6d9c5e7742e2cde812feb9a0`
> 本报告由宿主从冻结事实包确定性生成；数量、位置、验证状态与评分均不由模型填写。

## 1. 执行与终审摘要

- 运行：`17fc2e83ab1342a089583b548e45daa0`；状态：inconclusive；停止原因：final_review_incomplete；审计已结束，仍有 22 项未完成终审；已保存事实和阶段报告。
- 审计完整性：未完成，本报告为阶段报告
- 报告类型：stage；发布状态：可发布（阶段报告）

- 原始记录：41
- 有效记录：33
- 规范结论：28
- 已接受漏洞：6
- 待终审：22
- 存疑或排除：0

“已接受漏洞”以当前版本的正式终审处置为准：静态证据充分可接受；动态已验证结论还须完成同版本观测复核。其余结论逐条保留，不会因为缺少终审额度而从报告中消失。

| 完成维度 | 已完成 | 分母 | 说明 |
|---|---:|---:|---|
| 源码覆盖（读取） | 61 | 61 | 已读只表示宿主记录过读取 |
| 源码覆盖（读取+带理由跳过） | 61 | 61 | 跳过不是安全结论 |
| 必做方向结算 | 11 | 11 | 未决 0 个 |
| 动态验证完成 | 48 | 28 | 待验证 0 条 |
| 正式复核 | 6 | 28 | 复核存疑或未复核不计入已接受 |
| 源码覆盖（仍待复核） | 0 | 61 | 未读且未跳过 0 个 |

- 发布门禁未通过：review_batch_complete

**已接受漏洞**

- C-01 session.use_strict_mode 关闭，未初始化会话ID被接受存在会话固定风险（lab30-shop/docker/php.ini:7）
- C-02 partner/portal.php 不校验合作方令牌 HMAC 签名，伪造 admin 角色 payload 即可越权读取全部订单（lab30-shop/app/public/partner/portal.php:3）
- C-03 远程模板预览 template 参数直接 include（RFI/LFI）（lab30-shop/app/public/ops/template-preview.php:3）
- C-04 account/backup.php 对用户备份 unserialize 后直接写入 tier，可自行升级金卡会员权益（lab30-shop/app/public/account/backup.php:5）
- C-05 support/messages 留言内容未转义回显导致存储型 XSS（lab30-shop/app/public/support/messages.php:5）
- C-06 catalog/greeting.php 的 name 参数未编码直接输出到 HTML 文本，导致反射型 XSS（lab30-shop/app/public/catalog/greeting.php:3）

**仍需终审的结论**

- C-07 login.php 接受 GET sid 且 strict_mode 关闭导致会话固定：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-08 钱包提现为无锁读改写余额导致并发超额提现（竞态/重复支付）：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-09 orders/detail.php 按请求 id 读取任意订单，未校验 user_id 归属导致 IDOR：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-10 运营主机巡检 host 参数未转义拼接进 shell_exec（命令注入 RCE）：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-11 登录页接受 URL 参数 sid 作为会话 ID，存在会话固定：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-12 orders/create.php 订单单价取自请求参数 price，可按任意低价下单：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-13 continue.php 直接使用 GET next 作为跳转地址，存在开放重定向：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-14 account/update.php 批量赋值允许普通用户自改 role 与 balance：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-15 content/page.php 的 page 参数未经白名单直接拼接进 include 路径，导致本地文件包含：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-16 support/download.php 的 file 参数未做路径校验，登录用户可遍历读取 data_dir 下任意文件（含 sessions）：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-17 account/settings.php 邮箱更新缺少 CSRF 校验，可跨站改写绑定邮箱：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-18 运营网络诊断 host 参数未转义拼接进 shell_exec（命令注入 RCE）：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-19 ops/users.php 信任客户端 $_COOKIE['role'] 绕过管理员鉴权：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-20 ops/members.php 会员查询参数经 member_lookup 拼接进 SQL 造成 SQL 注入：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-21 catalog 搜索参数 q 直接拼接进 SQL LIKE 查询导致反射型 SQL 注入：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-22 ops/jobs.php 对 POST job 直接 unserialize，DispatchJob::__wakeup 触发 shell_exec 命令执行：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-23 ops/template-render.php 将 POST 模板双花括号内容直接拼接进 eval（代码执行）：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-24 ops/report.php 用 nickname 字符串拼接 query 的二阶 SQL 注入：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-25 资料维护接口批量赋值允许普通用户自改 role/balance/tier 提权：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-26 登录页以 GET sid 设置会话 ID 且登录后不轮换，构成会话固定：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-27 ops/formula.php 通过 GET func 变量函数调用任意 PHP 函数（code_execution）：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-28 php.ini 开启 allow_url_include，为 LFI 升级为远程代码包含提供条件：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

## 2. 范围和方法

- 项目：39211162aa984b25b60228c194b531ae；快照：`586b79b41f8e4f59be80f2a9b548902b`
- 源码包哈希（archive sha256）：`67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c`
- 事实包：final-review/v1；渲染器：final-report/v2；模板哈希：`bae25eb461e0811b`
- 输入哈希：`0b7c8bb1bfbc17edb3f1280b49bb5e4f8207818e6d9c5e7742e2cde812feb9a0`；冻结时间：2026-10-30T11:43:09.260948+00:00；生成时间：2026-10-30T11:43:09.260948+00:00
- 模型配置：deepseek-flash；策略版本：audit-runtime-3

本次报告只使用宿主记录的冻结事实：源码引用由服务器从快照读取并核对哈希，动态验证取自隔离 runner 的作业记录，正式复核按 finding revision 与 verification id 精确引用。模型的结论陈述与修复建议以“结论陈述”标注，不作为证据；未执行、环境失败与验证不确定都不解释为误报。

| 预算 | 上限 | 实际使用 | 剩余 |
|---|---:|---:|---:|
| 模型响应 | 2048 | 266 | 1782 |
| 工具调用 | 16384 | 299 | 16085 |
| 秒 | 10800 | 1987.524 | 8812.476 |

- 上下文：峰值请求 131980 字节 / 上限 393216 字节；摘要请求 0 次；硬上限命中 0 次。

| 阶段 | 请求配额 | 已用 |
|---|---:|---:|
| 源码挖掘 | 128 | 128 |
| POC 验证 | 1880 | 128 |
| 统一终审 | 40 | 10 |
- 调度政策：host-queue-v1；配额：自动分配。
- 待终审 22 项，预计 11 批；当前预留 33 次请求、720 秒；按实际批次容量与 Worker 调整，不增加整次额度。
- POC 执行：。

## 3. 规范漏洞清单

| 编号 | 标题 | 类型 | 评分 | 位置 | 静态判读 | 动态验证 | 正式终审 | 处置 |
|---|---|---|---|---|---|---|---|---|
| C-01 | session.use_strict_mode 关闭，未初始化会话ID被接受存在会话固定风险 | session_fixation | CVSS 3.1 待评分 | lab30-shop/docker/php.ini:7 | 缺上下文（3 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-02 | partner/portal.php 不校验合作方令牌 HMAC 签名，伪造 admin 角色 payload 即可越权… | auth_bypass | CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:… | lab30-shop/app/public/partner/portal.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-03 | 远程模板预览 template 参数直接 include（RFI/LFI） | rfi | CVSS 3.1 Base 9.9 (critical) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:… | lab30-shop/app/public/ops/template-preview.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-04 | account/backup.php 对用户备份 unserialize 后直接写入 tier，可自行升级金卡会员权益 | insecure_deserialization | CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/… | lab30-shop/app/public/account/backup.php:5 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-05 | support/messages 留言内容未转义回显导致存储型 XSS | xss_s | CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/… | lab30-shop/app/public/support/messages.php:5 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-06 | catalog/greeting.php 的 name 参数未编码直接输出到 HTML 文本，导致反射型 XSS | xss_r | CVSS 3.1 Base 6.1 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/… | lab30-shop/app/public/catalog/greeting.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-07 | login.php 接受 GET sid 且 strict_mode 关闭导致会话固定 | session_fixation | CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/… | lab30-shop/app/src/bootstrap.php:17 | 缺上下文（2 项） | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-08 | 钱包提现为无锁读改写余额导致并发超额提现（竞态/重复支付） | race_condition | CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/wallet/withdraw.php:7 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-09 | orders/detail.php 按请求 id 读取任意订单，未校验 user_id 归属导致 IDOR | idor | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/orders/detail.php:2 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-10 | 运营主机巡检 host 参数未转义拼接进 shell_exec（命令注入 RCE） | command_injection | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/src/host_check.php:2 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-11 | 登录页接受 URL 参数 sid 作为会话 ID，存在会话固定 | session_fixation | CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/… | lab30-shop/app/public/auth/login.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-12 | orders/create.php 订单单价取自请求参数 price，可按任意低价下单 | price_manipulation | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/orders/create.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-13 | continue.php 直接使用 GET next 作为跳转地址，存在开放重定向 | open_redirect | CVSS 3.1 Base 3.5 (low) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N | lab30-shop/app/public/auth/continue.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-14 | account/update.php 批量赋值允许普通用户自改 role 与 balance | mass_assignment | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/account/update.php:5 | 缺上下文（2 项） | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-15 | content/page.php 的 page 参数未经白名单直接拼接进 include 路径，导致本地文件包含 | lfi | CVSS 3.1 待评分 | lab30-shop/app/public/content/page.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-16 | support/download.php 的 file 参数未做路径校验，登录用户可遍历读取 data_dir 下任意文… | path_traversal | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/support/download.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-17 | account/settings.php 邮箱更新缺少 CSRF 校验，可跨站改写绑定邮箱 | csrf | CVSS 3.1 Base 3.1 (low) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N | lab30-shop/app/public/account/settings.php:5 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-18 | 运营网络诊断 host 参数未转义拼接进 shell_exec（命令注入 RCE） | command_injection | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/ping.php:2 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-19 | ops/users.php 信任客户端 $_COOKIE['role'] 绕过管理员鉴权 | auth_bypass | CVSS 3.1 Base 7.7 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:… | lab30-shop/app/public/ops/users.php:2 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-20 | ops/members.php 会员查询参数经 member_lookup 拼接进 SQL 造成 SQL 注入 | sqli | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/src/member_lookup.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-21 | catalog 搜索参数 q 直接拼接进 SQL LIKE 查询导致反射型 SQL 注入 | sqli | CVSS 3.1 Base 8.2 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:… | lab30-shop/app/public/catalog/index.php:4 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-22 | ops/jobs.php 对 POST job 直接 unserialize，DispatchJob::__wakeup… | insecure_deserialization | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/jobs.php:3 | 缺上下文（1 项） | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-23 | ops/template-render.php 将 POST 模板双花括号内容直接拼接进 eval（代码执行） | code_execution | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/template-render.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-24 | ops/report.php 用 nickname 字符串拼接 query 的二阶 SQL 注入 | sqli | CVSS 3.1 Base 5.9 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/… | lab30-shop/app/public/ops/report.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-25 | 资料维护接口批量赋值允许普通用户自改 role/balance/tier 提权 | mass_assignment | CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/account/update.php:4 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-26 | 登录页以 GET sid 设置会话 ID 且登录后不轮换，构成会话固定 | session_fixation | CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/… | lab30-shop/app/src/bootstrap.php:17 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-27 | ops/formula.php 通过 GET func 变量函数调用任意 PHP 函数（code_execution） | code_execution | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/formula.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-28 | php.ini 开启 allow_url_include，为 LFI 升级为远程代码包含提供条件 | rfi | CVSS 3.1 待评分 | lab30-shop/docker/php.ini:3 | 缺上下文（3 项） | 不确定（不确定） | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |

## 4. 逐条漏洞详单

### C-01 session.use_strict_mode 关闭，未初始化会话ID被接受存在会话固定风险

- 当前版本：finding `ea7837d9c8a646d4939112604172020a` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/docker/php.ini:7`；文件：`lab30-shop/docker/php.ini`
- 证据引用：`6022c7c16ca21753` lab30-shop/docker/php.ini:7-7；`6583999657214637` lab30-shop/docker/php.ini:8-8
- 根因类别：task_goal:v2:895096fcfe147ae8356a:1（规范类型 session_fixation）

**结论陈述（模型产出，不是证据）**

php.ini 第7行设置 session.use_strict_mode = 0，PHP 将接受未由服务端初始化的会话ID，削弱会话固定防护。攻击者可预设会话ID诱导受害者使用，若登录流程未重新生成会话ID，则可能劫持会话。是否可实际利用依赖未在本切片出现的登录/会话初始代码。

- 攻击前身份与适用前提：登录/认证流程未显式调用 session_regenerate_id
- 入口 → 传播 → 危险操作/状态变更：HTTP Cookie 中的 PHPSESSID → 未记录 → 接受攻击者指定的会话ID并沿用
- 防护与边界：session.save_path 位于 /var/lib/shop/sessions 且仅 www-data 可写(entrypoint.sh:3-4)，但未阻止未初始化ID接受
- 静态判读：缺上下文（3 项）；缺失上下文：lab30-shop/content/page.php 等实际 include/require 入口源码，用于确认 allow_url_include=On 能否被实际利用（RFI）；登录/认证与会话初始化代码，用于确认 session.use_strict_mode=0 是否可在无 session_regenerate_id 情况下被利用；bin/setup.php 内容，用于确认初始化时是否设置默认口令或弱凭据
- 动态验证：动态确认（verification `e22a4a838b364e1cb1487d15318b2c8e`）
- 正式终审：独立批次 70177978894041688de90370003471e5；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧观测（作业 e138e01caf0c45bbb7cb1d076a1e385a，身份 alice）：向量A——GET /auth/login.php?sid=fixedsida1b2c3d4e5f60718 返回 200 并下发 Set-Cookie SHOPSESSID=fixedsida1b2c3d4e5f60718（接受了攻击者指定的未初始化 ID）；登录前 /account/me.php 401；alice 在该 SID 下 POST 登录后 302→200 且未再下发 Set-Cookie（未重新生成 ID）；随后以同一 SID（无凭据）请求 /account/me.php 得 200 {"id":1,"username":"alice",...,"balance":"100.00"}。向量B——不带 ?sid、仅伪造 Cookie SHOPSESSID=cookiejar0f1e2d3c4b5a6978：GET / 200 且无 Set-Cookie（PHP 直接沿用该未初始化 ID），登录后仍无 Set-Cookie，/account/me.php 返回 200 alice 数据。对照：从未参与登录的 SID 请求 /account/me.php 返回 401 {"error":"请先登录后使用此功能。"}。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：设置 session.use_strict_mode = 1，并在认证成功后调用 session_regenerate_id(true)。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/docker/php.ini:7-7`（sha256 `b65de9007c7f42b3…`）

```
    7  session.use_strict_mode = 0
```

`lab30-shop/docker/php.ini:8-8`（sha256 `b65de9007c7f42b3…`）

```
    8  session.save_path = /var/lib/shop/sessions
```

### C-02 partner/portal.php 不校验合作方令牌 HMAC 签名，伪造 admin 角色 payload 即可越权读取全部订单

- 当前版本：finding `d014a86b046242429f9da520b13b06b4` revision 1（项目版本 20）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/partner/portal.php:3`；文件：`lab30-shop/app/public/partner/portal.php`
- 证据引用：`343d5e3158080141` lab30-shop/app/public/partner/portal.php:2-6；`e857c8df6419c587` lab30-shop/app/public/partner/token.php:2-6；`40ae2a25513665c3` lab30-shop/app/src/setup.php:27-27；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:87d9a20ff3a017182093:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

portal.php 第 2 行从 $_POST['token'] 或 $_COOKIE['partner_token'] 取得令牌，取 explode('.') 第二段做 base64/strtr 解码后 json_decode，未验证签名。第 3 行仅判断 payload['role']==='admin'，未调用 hash_hmac/hash_equals，也未验证 header alg 或与 token.php 签发一致。攻击者构造 header.payload.signature 形式的任意令牌（payload 含 role=admin，签名段随意）即可通过检查，第 4-6 行随即输出 orders 全表订单号与金额（含所有用户订单）。require_user 未被调用，匿名即可利用。

- 攻击前身份与适用前提：无，匿名网络请求即可；能访问 /partner/portal.php
- 入口 → 传播 → 危险操作/状态变更：HTTP POST 参数 token 或 Cookie partner_token（攻击者完全可控，无需登录） → portal.php:2 取 token→explode 第二段→base64_decode→json_decode 得 $payload→第 3 行仅检查 role==='admin'→第 4 行 SELECT 全表 orders→第 5/6 行输出 → portal.php:4 db()->query('SELECT order_no,total FROM orders ORDER BY id') 全表读取并在第 5-6 行返回
- 防护与边界：无：签名从未校验，未使用 hash_equals，未 require_user；仅前端 HTML 隐藏可见
- 静态判读：证据已记录
- 动态验证：动态确认（verification `9554fcf40efc4c1984d25eb46257f4dc`）
- 正式终审：独立批次 70177978894041688de90370003471e5；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

匿名（无 CookieJar、无登录）POST /partner/portal.php?token=<header>.<{"sub":999,"role":"admin"}>.forgedsig（Accept: application/json）：status=200，返回 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}，得 2 条订单，其中 SG-1002 属于 bob（INCLUDES_BOB_ORDER True），即跨用户读取全表订单。签名段 "forgedsig" 从未被校验即可通过。对照：匿名无令牌 403；alice 经 /partner/token.php 正常签发的真实令牌（payload sub=1, role=customer）匿名携带时 403；伪造 role=customer 的令牌同样 403 —— 结果只由 payload.role 决定。

- 评分依据：CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：portal.php 必须重算 header.payload 的 HMAC-SHA256 并与第三段用 hash_equals 比较，校验失败即拒绝；拒绝未知 alg；将密钥放入服务端配置而非 DB 明文 settings 表；并补充 require_user 服务端身份校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/partner/portal.php:2-6`（sha256 `e1267edb0f9df936…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$token=(string)($_POST['token']??$_COOKIE['partner_token']??'');$parts=explode('.',$token);$payload=count($parts)===3?json_decode((string)base64_decode(strtr($parts[1],'-_','+/')),true):null;
    3  if(!is_array($payload)||($payload['role']??'')!=='admin')fail_request('此合作方功能仅向管理员开放。',403);
    4  $rows=db()->query('SELECT order_no,total FROM orders ORDER BY id')->fetchAll();
    5  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['role'=>'admin','settlements'=>$rows]);
    6  page('合作方结算工作台',function()use($rows){echo '<section class="panel"><h2>结算摘要</h2><table><thead><tr><th>订单</th><th>金额</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['order_no']).'</td><td>¥'.h($r['total']).'</td></tr>';echo '</tbody></table></section>';});
```

`lab30-shop/app/public/partner/token.php:2-6`（sha256 `391948b46efce76c…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();
    3  function b64url(string $s):string{return rtrim(strtr(base64_encode($s),'+/','-_'),'=');}
    4  $header=b64url(json_encode(['alg'=>'HS256','typ'=>'JWT']));$payload=b64url(json_encode(['sub'=>$u['id'],'role'=>$u['role'],'name'=>$u['username']]));$key=db()->query("SELECT value FROM settings WHERE `key`='generation'")->fetchColumn();$token=$header.'.'.$payload.'.'.b64url(hash_hmac('sha256',$header.'.'.$payload,$key,true));
    5  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['token'=>$token]);
    6  page('合作方服务凭证',function()use($token){echo '<section class="panel"><h2>访问合作方工作台</h2><p>凭证代表当前账户的合作方身份。合作方结算工作台仅对管理员开放。</p><textarea readonly aria-label="合作方凭证">'.h($token).'</textarea><form action="/partner/portal.php" method="post"><input type="hidden" name="token" value="'.h($token).'"><button>进入合作方工作台</button></form></section>';},'账户与会员');
```

`lab30-shop/app/src/setup.php:27-27`（sha256 `53e7dc7286d7d370…`）

```php
   27      $pdo->prepare('INSERT INTO settings(`key`,value) VALUES(?,?)')->execute(['generation',bin2hex(random_bytes(12))]);
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-03 远程模板预览 template 参数直接 include（RFI/LFI）

- 当前版本：finding `e31a73469c3246d6a6d58e07189ffede` revision 1（项目版本 14）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-preview.php:3`；文件：`lab30-shop/app/public/ops/template-preview.php`
- 证据引用：`5d596a817dad3c10` lab30-shop/app/public/ops/template-preview.php:1-3；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:2d9ae373e8457588e937:1（规范类型 rfi）

**结论陈述（模型产出，不是证据）**

template-preview.php 第 2 行读取 $_GET['template']，第 3 行在 page 回调内 if($template!=='')include $template; 直接包含用户可控路径，无白名单、无 realpath 前缀校验，可造成本地文件包含及（若 allow_url_include 开启）远程文件包含执行代码。

- 攻击前身份与适用前提：攻击者持 operator/admin 会话；RFI 需 allow_url_include=On
- 入口 → 传播 → 危险操作/状态变更：GET 参数 template → $_GET['template'] -> $template -> include $template → include 文件包含/远程包含
- 防护与边界：仅身份校验，无路径白名单或规范化
- 静态判读：证据已记录
- 动态验证：动态确认（verification `fd944e41b1924f5d86ecd4b8595e66ba`）
- 正式终审：独立批次 70177978894041688de90370003471e5；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 operator 会话：template=/etc/passwd 时 #remote-template 区输出 root:x:0:0:root:/root:/bin/bash、daemon:x:1:1… 等系统账户行，证明可包含任意本地文件；template=data://text/plain;base64,<base64 of <?php echo 'XMARKRFI'.(6*7); ?>> 时输出 XMARKRFI42（“42”由包含的 PHP 代码求值产生，未出现在请求参数中），证明可包含远程/流并执行其中 PHP 代码，构成 RFI/RCE。

- 评分依据：CVSS 3.1 Base 9.9 (critical) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：将模板限定在固定目录并用 realpath 前缀校验/白名单映射，禁止直接 include 用户输入。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/template-preview.php:1-3`（sha256 `107da46e9b067ce0…`）

```php
    1  <?php
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

### C-04 account/backup.php 对用户备份 unserialize 后直接写入 tier，可自行升级金卡会员权益

- 当前版本：finding `612f04ef75cc4f6a8e700e1a7e431e09` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/backup.php:5`；文件：`lab30-shop/app/public/account/backup.php`
- 证据引用：`f15ec397a921596f` lab30-shop/app/public/account/backup.php:2-6；`9d0d13b19a80b9a2` lab30-shop/app/src/backup.php:2-5；`addf5b6a130c589e` lab30-shop/app/public/account/index.php:3-3；`ea671862691bb582` lab30-shop/app/public/account/redeem.php:5-5
- 根因类别：task_goal:v2:ba624b122b81eabc582d:1（规范类型 insecure_deserialization）

**结论陈述（模型产出，不是证据）**

backup.php:4 从 $_POST['backup'] 读取并经 base64_decode，:5 直接 unserialize($raw)，仅用 instanceof MemberBackup 校验类型，未使用 allowed_classes 白名单；:6 把 $restored->tier 与 $restored->displayName 直接写入 UPDATE users SET tier=?,display_name=?。任何已登录用户都能构造合法 MemberBackup 序列化对象把 tier 设为 'gold'，服务端持久保存，绕过 redeem.php:5 的兑换码校验即可获得金卡会员（account/index.php:3 显示 tier==='gold' 即金卡权益）。MemberBackup 仅有公共字符串属性、无魔术方法，故不构成 gadget 链，但客户端可写 tier 本身已违反业务字段白名单。

- 攻击前身份与适用前提：需要任意有效登录会话及页面 CSRF token；无需 operator/admin 角色。
- 入口 → 传播 → 危险操作/状态变更：POST 参数 backup（base64 编码序列化数据），任意已登录用户可提交 → base64_decode($_POST['backup']) -> unserialize -> instanceof MemberBackup -> $restored->tier/displayName -> UPDATE users SET tier=?,display_name=? → unserialize() 处理用户可控数据并将其属性写入 users.tier 字段
- 防护与边界：仅有 require_user() 登录校验、check_csrf() 与 instanceof MemberBackup 类型判断；无 allowed_classes、无字段白名单、tier 取值不受限。
- 静态判读：证据已记录
- 动态验证：动态确认（verification `4f8036e58fa04f2db14eefa4318f9f66`）
- 正式终审：独立批次 ba363ce181db4839868388f1ea3b04ab；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧：同一 alice 会话提交 base64('O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:5:"alice";}')，status=200 且页面提示“会员备份已恢复”；随后 GET /account/index.php 返回 badge=gold、member-benefit=“金卡会员：享受专属折扣与优先服务”。此前先提交 tier=standard 的对照备份，账户页显示 badge=standard、“普通会员：日常积分与会员活动”——两次提交流程相同，仅序列化对象内 tier 值不同，结果由客户端控制的 tier 决定；宿主审计作业 fdbb0380d7f84fadb02750cb011e07b2 也记录 pre/post tier 由 standard 变为 gold 的 state_changes。

- 评分依据：CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 JSON 并显式校验字段；unserialize 时传 allowed_classes 白名单；tier 不接受客户端输入，只允许恢复 displayName 等非敏感字段。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/backup.php:2-6`（sha256 `017e1703cdf0ff0c…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/backup.php';$u=require_user();$obj=new MemberBackup();$obj->tier=$u['tier'];$obj->displayName=$u['display_name'];$export=base64_encode(serialize($obj));$notice='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$raw=base64_decode((string)($_POST['backup']??''),true);if($raw===false)fail_request('备份格式不正确。');
    5      $restored=unserialize($raw);if(!$restored instanceof MemberBackup)fail_request('不是有效的会员备份。');
    6      db()->prepare('UPDATE users SET tier=?,display_name=? WHERE id=?')->execute([$restored->tier,$restored->displayName,$u['id']]);event_log('restore_member_backup');$notice='会员备份已恢复。';
```

`lab30-shop/app/src/backup.php:2-5`（sha256 `571459cc8b0f6e8e…`）

```php
    2  class MemberBackup {
    3      public string $tier = 'standard';
    4      public string $displayName = '会员';
    5  }
```

`lab30-shop/app/public/account/index.php:3-3`（sha256 `1d22c7bc280b30b0…`）

```php
    3  page('账户与会员',function()use($u){echo '<section class="panel"><span class="badge">'.h($u['tier']).'</span><h2>'.h($u['display_name']).'</h2><p>'.h($u['email']).'</p><dl><dt>用户名</dt><dd>'.h($u['username']).'</dd><dt>会员权益</dt><dd id="member-benefit">'.($u['tier']==='gold'?'金卡会员：享受专属折扣与优先服务':'普通会员：日常积分与会员活动').'</dd></dl></section><div class="cards">';foreach([['/account/profile.php','个人主页','预览你的个人链接'],['/account/settings.php','邮箱设置','维护常用联系方式'],['/account/update.php','资料维护','更新会员信息'],['/account/backup.php','会员备份','导出或恢复会员偏好'],['/account/redeem.php','权益兑换','使用活动兑换码'],['/partner/token.php','合作方服务','领取合作方访问凭证'],['/auth/continue.php','继续访问','选择登录后的目的页面']]as$c)echo '<a class="feature-card" href="'.$c[0].'"><h3>'.$c[1].' ↗</h3><p>'.$c[2].'</p></a>';echo '</div>';},'账户与会员');
```

`lab30-shop/app/public/account/redeem.php:5-5`（sha256 `28b3dc4534cca985…`）

```php
    5      if(md5((string)($_POST['token']??''))==$secret_hash){db()->prepare("UPDATE users SET tier='gold' WHERE id=?")->execute([$u['id']]);event_log('redeem_membership');$notice='兑换成功，已升级金卡会员。';$accepted=true;}
```

### C-05 support/messages 留言内容未转义回显导致存储型 XSS

- 当前版本：finding `4907961ff981463a817be4589ab79728` revision 1（项目版本 17）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/messages.php:5`；文件：`lab30-shop/app/public/support/messages.php`
- 证据引用：`4287a6e3dca83484` lab30-shop/app/public/support/messages.php:3-5；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10
- 根因类别：task_goal:v2:2423c5d5e3216d6762cd:1（规范类型 xss_s）

**结论陈述（模型产出，不是证据）**

messages.php 第 3 行将 POST 的 message（仅校验非空且≤5000 字节）参数化写入 messages 表；第 4-5 行查询后把 $row['message'] 直接拼入 <div class="message-body"> 输出，未调用 h()。同一 foreach 中 display_name 与 created_at 均用 h()，唯独 message 缺失转义，形成存储型 XSS。

- 攻击前身份与适用前提：攻击者持有任意有效登录会话；受害者浏览 /support/messages.php
- 入口 → 传播 → 危险操作/状态变更：POST 参数 message → 第 3 行 INSERT INTO messages ⇒ 第 4 行 SELECT m.* ⇒ 第 5 行 $row['message'] 拼接输出 → 将数据库内容未编码写入 HTML 响应
- 防护与边界：h() 存在于 bootstrap.php:10 且在同行其他字段使用，但 message 字段遗漏
- 静态判读：证据已记录
- 动态验证：动态确认（verification `afac2901d61f495c95fb0299a58e2b77`）
- 正式终审：独立批次 ba363ce181db4839868388f1ea3b04ab；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

alice 经支持页表单提交 message=<script>alert("XSS_MARK_9f2")</script> 后，服务端存储并在后续 GET /support/messages.php 的原始 HTML 中输出 '<div class="message-body"><script>alert("XSS_MARK_9f2")</script></div>'（未转义）。随后 alice 会话的 Chromium 加载 /support/messages.php，记录到弹窗 "XSS_MARK_9f2"（dialogs 一项、console_errors 为空），证明存储的脚本在受害者浏览器真实执行。

- 评分依据：CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：输出时对 $row['message'] 使用 h()，如 '<div class="message-body">'.h($row['message']).'</div>'，或采用允许列表的富文本清洗。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/support/messages.php:3-5`（sha256 `a6866f07b4de32f3…`）

```php
    3  if($_SERVER['REQUEST_METHOD']==='POST') {check_csrf();$message=(string)($_POST['message']??'');if($message===''||strlen($message)>5000)fail_request('留言需为 1–5000 字节。');db()->prepare('INSERT INTO messages(user_id,message) VALUES(?,?)')->execute([$u['id'],$message]);event_log('leave_message');header('Location: /support/messages.php',true,303);exit;}
    4  $rows=db()->query('SELECT m.*,u.display_name FROM messages m JOIN users u ON u.id=m.user_id ORDER BY m.id DESC')->fetchAll();
    5  page('在线留言',function()use($rows){echo '<section class="panel"><h2>和我们聊聊</h2><form method="post">'.csrf_field().'<label>你的留言<textarea name="message" required></textarea></label><button>提交留言</button></form></section><div class="messages">';foreach($rows as$row)echo '<article class="panel"><strong>'.h($row['display_name']).'</strong><time>'.h($row['created_at']).'</time><div class="message-body">'.$row['message'].'</div></article>';echo '</div>';},'客服与帮助');
```

`lab30-shop/app/src/bootstrap.php:10-10`（sha256 `2050819d093be02b…`）

```php
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

### C-06 catalog/greeting.php 的 name 参数未编码直接输出到 HTML 文本，导致反射型 XSS

- 当前版本：finding `e601764eee0f47658ae43fd8fb51f742` revision 1（项目版本 16）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/catalog/greeting.php:3`；文件：`lab30-shop/app/public/catalog/greeting.php`
- 证据引用：`c57a3bf6bb6b01db` lab30-shop/app/public/catalog/greeting.php:2-3；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10
- 根因类别：task_goal:v2:b2e9967b20ef1a41ba97:1（规范类型 xss_r）

**结论陈述（模型产出，不是证据）**

greeting.php:2 取 $_GET['name']，greeting.php:3 在 <h2> 中以 '你好，'.$name.'</h2>' 拼接后 echo，未调用 bootstrap.php:10 定义的 h()；同页 form_input 的 value 已用 h()，说明此处遗漏。攻击者用 name=<script>alert(1)</script> 即可在受害者浏览器执行脚本。

- 攻击前身份与适用前提：诱导受害者访问构造 URL
- 入口 → 传播 → 危险操作/状态变更：GET 参数 name（/catalog/greeting.php?name=...），无需登录 → greeting.php:2 $_GET['name'] -> $name -> greeting.php:3 拼接 -> echo 到 <h2> 文本上下文 → echo 未编码用户输入到 HTML 响应
- 防护与边界：无：未调用 h()（htmlspecialchars ENT_QUOTES）
- 静态判读：证据已记录
- 动态验证：动态确认（verification `4120c592946c4c548d36e66e4dd3877a`）
- 正式终审：独立批次 ba363ce181db4839868388f1ea3b04ab；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 Chromium 会话加载 /catalog/greeting.php?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E，页面返回标题“到店欢迎 · 拾光商城”，记录到 1 个弹窗且内容为 "1"（alert 实际执行）；同时 body_text 只剩“你好，”，说明 <script>alert(1)</script> 作为标签被解析而非当作文本显示。即 name 参数未编码直接进入 <h2> 文本上下文并在浏览器执行。

- 评分依据：CVSS 3.1 Base 6.1 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：输出改为 echo '<h2>你好，'.h($name).'</h2>'。

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

### C-07 login.php 接受 GET sid 且 strict_mode 关闭导致会话固定

- 当前版本：finding `b7699087edaa49fca6629be5298d4218` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/bootstrap.php:17`；文件：`lab30-shop/app/src/bootstrap.php`
- 证据引用：`9f3b2a689fae3c12` lab30-shop/app/src/bootstrap.php:11-19；`5f912f7499e51381` lab30-shop/app/public/auth/login.php:3-9
- 根因类别：task_goal:v2:e70901e195d6eec35db2:1（规范类型 session_fixation）

**结论陈述（模型产出，不是证据）**

start_session 显式 ini_set session.use_strict_mode=0，且当传入 sid 符合正则时直接 session_id($sid) 后 session_start；login.php:3 把 $_GET['sid'] 原样交给 start_session，且登录成功后未调用 session_regenerate_id。攻击者可预设合法 SID 构造登录链接，受害者登录后会话 ID 不变，攻击者复用同一 ID 获得其会话。

- 攻击前身份与适用前提：攻击者能投递带 sid 的链接且受害者完成登录
- 入口 → 传播 → 危险操作/状态变更：GET 参数 sid → $_GET['sid'] -> start_session($sid) -> preg_match 校验 -> session_id($sid) -> session_start() 无 regenerate → session_id 被外部指定并沿用为已认证会话
- 防护与边界：正则限制字符集与长度、httponly/SameSite=Lax，但 strict_mode 关闭且无 session_regenerate_id
- 静态判读：缺上下文（2 项）；缺失上下文：SHOP_DATA_DIR / 容器编排或 .env 部署配置未包含在快照中，无法确认 session_save_path 与 vault 目录是否位于 Web 可访问路径；HTTPS 强制与 secure cookie 配置未在源码中体现，无法据此判断会话传输保护
- 动态验证：动态确认（verification `170b82091ccf48b4831b9a390dc622c1`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：启用 session.use_strict_mode=1，登录成功后 session_regenerate_id(true)，并移除对请求传入 sid 的支持。

**源码片段（宿主从冻结快照读取）**

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

### C-08 钱包提现为无锁读改写余额导致并发超额提现（竞态/重复支付）

- 当前版本：finding `81dc9ba2b5764d7681cb0051685fe57b` revision 1（项目版本 22）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/wallet/withdraw.php:7`；文件：`lab30-shop/app/public/wallet/withdraw.php`
- 证据引用：`8e89065a153544f6` lab30-shop/app/public/wallet/withdraw.php:2-9；`063c928d2d7c3b2e` lab30-shop/app/src/bootstrap.php:33-40；`6cc4203c00ab810f` lab30-shop/app/public/wallet/index.php:2-4
- 根因类别：task_goal:v2:a3bdf2d733a4133e3b77:1（规范类型 race_condition）

**结论陈述（模型产出，不是证据）**

withdraw.php 先 SELECT balance 到 PHP 变量，随后 usleep(350000) 明确放大时间窗，再用 UPDATE users SET balance=? 写入计算后的常量余额，而不是 SET balance=balance-amount 的原子更新，也没有 SELECT ... FOR UPDATE、事务或幂等键。同一用户的多个并发提现请求可各自读到相同余额并通过 balance<amount 检查，最终都插入 withdrawals 记录并只把余额扣减一次，形成超出余额的提现。金额来自 $_POST['amount']，仅被 FILTER_VALIDATE_FLOAT 与 <=10000 校验，取值为客户端可控。要求已登录（require_user）且携带合法 CSRF 令牌（check_csrf），但注册用户可自行获取令牌并发起并发请求，防护不足以阻止竞态。

- 攻击前身份与适用前提：攻击者拥有普通注册账号并可自行取得 CSRF 令牌；需要并发发送多个提现请求（同一余额窗口内）
- 入口 → 传播 → 危险操作/状态变更：POST /wallet/withdraw.php 参数 amount（$_POST['amount']），由已登录用户提交 → withdraw.php:2 读取 amount -> :4 SELECT balance -> :5 余额比较检查 -> :6 usleep 放大窗口 -> :7 UPDATE balance=balance-amount 常量 -> :8 INSERT withdrawals → UPDATE users SET balance=? 非原子余额扣减及 INSERT INTO withdrawals 生成多笔提现记录
- 防护与边界：require_user 登录校验、require_post、check_csrf 与金额范围校验；缺少行锁/事务/原子减法/幂等，无法防止并发重复扣减
- 静态判读：证据已记录
- 动态验证：动态确认（verification `2ea22374d2de49d3b92b57d122d73561`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：在同一事务中 SELECT balance ... FOR UPDATE 或使用 UPDATE users SET balance=balance-? WHERE id=? AND balance>=? 并对影响行数判断，同时为提现请求引入幂等键/限流。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/wallet/withdraw.php:2-9`（sha256 `e3e73271e379b085…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();require_post();check_csrf();$amount=filter_var($_POST['amount']??null,FILTER_VALIDATE_FLOAT);if($amount===false||$amount<=0||$amount>10000)fail_request('提现金额不正确。');
    3  $id=(int)$u['id'];session_write_close();
    4  $q=db()->prepare('SELECT balance FROM users WHERE id=?');$q->execute([$id]);$balance=(float)$q->fetchColumn();
    5  if($balance<$amount)fail_request('账户余额不足，请调整提现金额。',409);
    6  usleep(350000);
    7  $q=db()->prepare('UPDATE users SET balance=? WHERE id=?');$q->execute([$balance-$amount,$id]);
    8  $q=db()->prepare('INSERT INTO withdrawals(user_id,amount) VALUES(?,?)');$q->execute([$id,$amount]);
    9  $receipt=(int)db()->lastInsertId();
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

`lab30-shop/app/public/wallet/index.php:2-4`（sha256 `76b24de3e20c34df…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$q=db()->prepare('SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC');$q->execute([$u['id']]);$rows=$q->fetchAll();
    3  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['balance'=>$u['balance'],'withdrawals'=>$rows,'withdrawn_total'=>array_sum(array_column($rows,'amount'))]);
    4  page('我的钱包',function()use($u,$rows){if(isset($_GET['receipt']))echo '<div class="notice" role="status">提现申请已完成，流水号 '.(int)$_GET['receipt'].'。最新余额及记录如下。</div>';echo '<div class="stats"><div><strong>¥'.h($u['balance']).'</strong><span>可用余额</span></div><div><strong>'.count($rows).'</strong><span>提现记录</span></div></div><section class="panel narrow"><h2>申请提现</h2><form action="/wallet/withdraw.php" method="post">'.csrf_field();form_input('amount','提现金额','10','number');echo '<button>确认提现</button></form></section><section class="panel"><h2>资金流水</h2><table><thead><tr><th>流水号</th><th>金额</th><th>时间</th></tr></thead><tbody>';foreach($rows as$row)echo '<tr><td>'.(int)$row['id'].'</td><td>¥'.h($row['amount']).'</td><td>'.h($row['created_at']).'</td></tr>';echo '</tbody></table></section>';},'我的钱包');
```

### C-09 orders/detail.php 按请求 id 读取任意订单，未校验 user_id 归属导致 IDOR

- 当前版本：finding `be7b150f8f9a4dd58b8e47b4678054fc` revision 1（项目版本 29）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/detail.php:2`；文件：`lab30-shop/app/public/orders/detail.php`
- 证据引用：`171ea369e07c383b` lab30-shop/app/public/orders/detail.php:1-4；`1b8e73c49d79d5d1` lab30-shop/app/public/orders/index.php:1-3；`a8463619606be720` lab30-shop/app/src/bootstrap.php:20-36
- 根因类别：task_goal:v2:7ddbaa5ca23a91e6a6bc:1（规范类型 idor）

**结论陈述（模型产出，不是证据）**

detail.php 只需 require_user() 登录，随后直接用 $_GET['id'] 作为唯一条件 SELECT o.* 并 JOIN users 取出购买人 username 与 private_note，未在任何位置比较 o.user_id 与当前会话用户；因此任意登录用户遍历自增 id 可读取他人订单号、商品、金额、数量与配送备注。Accept: application/json 时还会把整行数据 JSON 返回，放大泄露。对比 orders/index.php 第2行按 user_id=? 限定，说明列表页做了归属过滤而详情页遗漏。

- 攻击前身份与适用前提：攻击者持任意有效账号；目标订单 id 存在
- 入口 → 传播 → 危险操作/状态变更：GET 参数 id（/orders/detail.php?id=） → $_GET['id'] -> $q->execute([$_GET['id']??0])（无 user_id 条件）-> $o=$q->fetch() -> json_response($o) 或 page() 逐字段 h() 输出 → 跨用户读取订单记录（order_no、total、quantity、private_note、购买人 username）
- 防护与边界：仅 require_user() 认证；无归属/角色校验，SQL 用占位符只防注入不防越权
- 静态判读：证据已记录
- 动态验证：动态确认（verification `4997cbfbf6104bf99fef6fb55b06c2f2`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：在查询中加 AND o.user_id=? 并绑定当前用户 id（运营/管理员可单独授权），或在 fetch 后显式比较 $o['user_id']!==$u['id'] 时返回 403。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/orders/detail.php:1-4`（sha256 `be69aa78cecffcfd…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();$q=db()->prepare('SELECT o.*,u.username,p.name FROM orders o JOIN users u ON u.id=o.user_id LEFT JOIN products p ON p.id=o.product_id WHERE o.id=?');$q->execute([$_GET['id']??0]);$o=$q->fetch();if(!$o)fail_request('订单不存在。',404);
    3  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response($o);
    4  page('订单详情',function()use($o){echo '<section class="panel"><span class="badge">等待配送</span><h2>'.h($o['order_no']).'</h2><dl>';foreach(['商品'=>$o['name'],'购买人'=>$o['username'],'数量'=>$o['quantity'],'实付金额'=>'¥'.$o['total'],'配送备注'=>$o['private_note']]as$k=>$v)echo '<dt>'.h($k).'</dt><dd>'.h($v).'</dd>';echo '</dl><a class="button secondary" href="/orders/index.php">返回订单中心</a></section>';},'订单中心');
```

`lab30-shop/app/public/orders/index.php:1-3`（sha256 `633f73e04b427bba…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$q=db()->prepare('SELECT o.*,p.name FROM orders o LEFT JOIN products p ON p.id=o.product_id WHERE user_id=? ORDER BY o.id DESC');$q->execute([$u['id']]);$orders=$q->fetchAll();
    3  page('我的订单',function()use($orders){echo '<section class="panel"><table><thead><tr><th>订单号</th><th>商品</th><th>实付金额</th><th>详情</th></tr></thead><tbody>';foreach($orders as$o)echo '<tr><td>'.h($o['order_no']).'</td><td>'.h($o['name']).' × '.(int)$o['quantity'].'</td><td>¥'.h($o['total']).'</td><td><a href="/orders/detail.php?id='.(int)$o['id'].'">查看订单</a></td></tr>';echo '</tbody></table></section>';},'订单中心');
```

`lab30-shop/app/src/bootstrap.php:20-36`（sha256 `2050819d093be02b…`）

```php
   20  function user(): ?array {
   21      start_session();
   22      if (empty($_SESSION['user_id'])) return null;
   23      $q = db()->prepare('SELECT id,username,display_name,email,role,balance,tier,nickname,homepage FROM users WHERE id=?');
   24      $q->execute([$_SESSION['user_id']]); return $q->fetch() ?: null;
   25  }
   26  function json_response(mixed $value, int $status = 200): never {
   27      http_response_code($status); header('Content-Type: application/json; charset=utf-8'); echo json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); exit;
   28  }
   29  function fail_request(string $message, int $status = 400): never {
   30      if (str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json')) json_response(['error' => $message], $status);
   31      http_response_code($status); page('请求未完成', function() use ($message) { echo '<div class="notice error" role="alert">' . h($message) . '</div><div class="actions"><a class="button" href="/auth/login.php">前往登录</a><a class="button secondary" href="/">返回首页</a></div>'; }); exit;
   32  }
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-10 运营主机巡检 host 参数未转义拼接进 shell_exec（命令注入 RCE）

- 当前版本：finding `56e24bf0d1424385ab81cee10812cd99` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/host_check.php:2`；文件：`lab30-shop/app/public/ops/batch-check.php`
- 证据引用：`772dda483c0c1762` lab30-shop/app/public/ops/batch-check.php:2-2；`3469da4edb56bedd` lab30-shop/app/src/host_check.php:2-2；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36；`415907ec6bf2f739` lab30-shop/app/src/bootstrap.php:40-40
- 根因类别：task_goal:v2:fecdabbe0c2e86cc40ec:1（规范类型 command_injection）

**结论陈述（模型产出，不是证据）**

ops/batch-check.php 从 $_GET['host'] 读取任意字符串，直接传入 host_check()；host_check.php 用字符串拼接构造 'ping -c 1 -W 1 ' . $host 并交给 shell_exec 执行。全程无 escapeshellarg/escapeshellcmd、无白名单、无字符过滤，攻击者用 ';'、'&#124;'、'&&'、'$()' 可注入任意系统命令并以 Web 进程权限执行（RCE）。入口只做 require_user(['operator','admin']) 角色校验，且为 GET 请求未调用 check_csrf。

- 攻击前身份与适用前提：持有 operator 或 admin 有效会话
- 入口 → 传播 → 危险操作/状态变更：GET 参数 host（batch-check.php?host=...） → $_GET['host'] → $host（batch-check.php:2）→ host_check($host) → 'ping -c 1 -W 1 ' . $host → shell_exec（host_check.php:2） → shell_exec 系统命令执行
- 防护与边界：仅 require_user(['operator','admin']) 角色门禁；无 shell 参数转义或输入白名单；GET 请求不经过 check_csrf
- 静态判读：证据已记录
- 动态验证：动态确认（verification `395610502cf942dca52119a696a80d0d`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 escapeshellarg($host) 包裹参数，或采用参数数组形式的进程调用（如 proc_open/exec 传数组）并严格校验 host 为主机名白名单正则；对写/执行类接口同时施加 POST + CSRF 保护。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/batch-check.php:2-2`（sha256 `5f76332e7ad1b33a…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/host_check.php';require_user(['operator','admin']);$host=(string)($_GET['host']??'');$output=$host!==''?host_check($host):'';
```

`lab30-shop/app/src/host_check.php:2-2`（sha256 `c3a868155c2d335e…`）

```php
    2  function host_check(string $host): string { return (string)shell_exec('ping -c 1 -W 1 ' . $host); }
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

`lab30-shop/app/src/bootstrap.php:40-40`（sha256 `2050819d093be02b…`）

```php
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

### C-11 登录页接受 URL 参数 sid 作为会话 ID，存在会话固定

- 当前版本：finding `0be8523556144f559c4e0945954d27d8` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/login.php:3`；文件：`lab30-shop/app/public/auth/login.php`
- 证据引用：`5f912f7499e51381` lab30-shop/app/public/auth/login.php:3-9；`9f3b2a689fae3c12` lab30-shop/app/src/bootstrap.php:11-19
- 根因类别：task_goal:v2:f61e6acf923a76aa5fa2:1（规范类型 session_fixation）

**结论陈述（模型产出，不是证据）**

bootstrap.php 关闭了 session.use_strict_mode，start_session() 允许调用方传入任意合法格式 sid 并直接 session_id($sid)；login.php 第 3 行把 $_GET['sid'] 原样交给 start_session()，登录成功后只写入 $_SESSION['user_id'] 而不调用 session_regenerate_id()。因此攻击者可预设会话 ID 并把带 sid 的登录链接投递给受害者，受害者登录后攻击者凭同一会话 ID 即可复用其身份。

- 攻击前身份与适用前提：攻击者能诱导受害者点击带 sid 的登录 URL 并在该会话内登录
- 入口 → 传播 → 危险操作/状态变更：$_GET['sid'] → login.php:3 start_session($_GET['sid']) -> bootstrap.php:17 session_id($sid) -> session_start() -> login.php:8 $_SESSION['user_id'] 写入，未更换会话 ID → 以客户端提供的会话标识建立认证会话（session_id($sid) + 无 session_regenerate_id）
- 防护与边界：正则限制 sid 格式 [a-zA-Z0-9,-]{16,64}，但未阻止客户端指定会话 ID，且 use_strict_mode=0
- 静态判读：证据已记录
- 动态验证：动态确认（verification `5c86fa32ae8449de85de4b6758e7eb8f`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：删除 sid 参数入口，设置 session.use_strict_mode=1，并在认证成功后调用 session_regenerate_id(true)。

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

### C-12 orders/create.php 订单单价取自请求参数 price，可按任意低价下单

- 当前版本：finding `21c96a05f27f4dd8b3bd9cf51bfccf08` revision 1（项目版本 29）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/create.php:3`；文件：`lab30-shop/app/public/orders/create.php`
- 证据引用：`0665b79989f38035` lab30-shop/app/public/orders/create.php:1-7；`604a359fd6dacaf0` lab30-shop/app/src/bootstrap.php:38-45
- 根因类别：task_goal:v2:63ce2bea806ca5de929d:1（规范类型 price_manipulation）

**结论陈述（模型产出，不是证据）**

create.php 从 $_POST['price'] 读取单价并用 FILTER_VALIDATE_FLOAT 转换，仅校验 >=0，随后 $total=$price*$quantity 并以该 $price 写入 orders.unit_price/total；商品真实价格 $p['price'] 从未参与计算，因此攻击者可提交 price=0.01 以极低金额下单并正常扣减库存、产生订单。

- 攻击前身份与适用前提：攻击者持任意登录账号并能从正常页面取得 csrf 令牌
- 入口 → 传播 → 危险操作/状态变更：POST 参数 price、quantity、product_id 及 csrf（正常页面可取得） → $_POST['price'] -> filter_var(FILTER_VALIDATE_FLOAT) -> $total=round($price*$quantity,2) -> INSERT orders(unit_price,total) → 以攻击者指定单价落单，绕过商品定价
- 防护与边界：check_csrf 与库存 rowCount 校验仅防 CSRF/超卖，不校验价格来源
- 静态判读：证据已记录
- 动态验证：动态确认（verification `74dfa5e1e3b448d2904882f3830ed4cb`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：单价必须由服务端从 products 表读取（如 $p['price']），忽略请求中的 price 字段；金额由服务端计算并校验库存与最低价。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/orders/create.php:1-7`（sha256 `41e73625d7e04c58…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();require_post();check_csrf();
    3  $q=db()->prepare('SELECT * FROM products WHERE id=?');$q->execute([$_POST['product_id']??0]);$p=$q->fetch();$quantity=filter_var($_POST['quantity']??0,FILTER_VALIDATE_INT);$price=filter_var($_POST['price']??null,FILTER_VALIDATE_FLOAT);
    4  if(!$p||!$quantity||$quantity<1||$quantity>20||$price===false||$price<0)fail_request('商品、数量或价格不正确。');
    5  $total=round($price*$quantity,2);$pdo=db();$pdo->beginTransaction();
    6  $q=$pdo->prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?');$q->execute([$quantity,$p['id'],$quantity]);if(!$q->rowCount()){$pdo->rollBack();fail_request('商品库存不足。',409);}
    7  $q=$pdo->prepare('INSERT INTO orders(order_no,user_id,product_id,quantity,unit_price,total,private_note) VALUES(?,?,?,?,?,?,?)');$q->execute(['SG-'.bin2hex(random_bytes(5)),$u['id'],$p['id'],$quantity,$price,$total,'会员订单，等待发货']);$id=(int)$pdo->lastInsertId();$pdo->commit();event_log('create_order',['order_id'=>$id,'total'=>$total]);header('Location: /orders/detail.php?id='.$id, true,303);
```

`lab30-shop/app/src/bootstrap.php:38-45`（sha256 `2050819d093be02b…`）

```php
   38  function csrf_token(): string { start_session(); return $_SESSION['csrf'] ??= bin2hex(random_bytes(24)); }
   39  function csrf_field(): string { return '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'; }
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
   41  function event_log(string $action, array $data = []): void {
   42      $q = db()->prepare('INSERT INTO events(user_id,action,details) VALUES(?,?,?)');
   43      $q->execute([$_SESSION['user_id'] ?? null, $action, json_encode($data, JSON_UNESCAPED_UNICODE)]);
   44  }
   45  function require_post(): void { if ($_SERVER['REQUEST_METHOD'] !== 'POST') fail_request('此操作需要 POST 请求。', 405); }
```

### C-13 continue.php 直接使用 GET next 作为跳转地址，存在开放重定向

- 当前版本：finding `4280b2b06e4b474c88e7955305676084` revision 1（项目版本 22）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/continue.php:3`；文件：`lab30-shop/app/public/auth/continue.php`
- 证据引用：`a3a2825731fc4c1a` lab30-shop/app/public/auth/continue.php:2-4；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:41749629ebe830243f6c:1（规范类型 open_redirect）

**结论陈述（模型产出，不是证据）**

continue.php 第 2 行调用 require_user() 建立登录身份，第 3 行检测到 $_GET['next'] 后直接执行 header('Location: '.(string)$_GET['next'])，对目标地址无同源、白名单或绝对路径校验，任何已登录用户访问 /auth/continue.php?next=https://evil.example 都会被 302 到攻击者站点。

- 攻击前身份与适用前提：攻击者能诱导已登录用户访问带 next 的 continue.php 链接
- 入口 → 传播 → 危险操作/状态变更：$_GET['next'] → continue.php:3 读取 $_GET['next']，强制转 string 后拼接进 Location 响应头，无任何过滤 → header('Location: '.(string)$_GET['next']) 产生跨域跳转
- 防护与边界：仅有 require_user() 认证检查，没有对 next 做 host/协议/白名单校验
- 静态判读：证据已记录
- 动态验证：动态确认（verification `9aaaae7782954fa09bf9ffcf46ff8b03`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 3.5 (low) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：将 next 限制为站内相对路径或以服务器端白名单映射，拒绝含协议/主机或非 / 开头的值。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/auth/continue.php:2-4`（sha256 `50fde4a15e52af44…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();
    3  if(isset($_GET['next'])){header('Location: '.(string)$_GET['next']);exit;}
    4  page('继续访问',function(){echo '<section class="panel"><h2>选择下一站</h2><form method="get">';form_input('next','继续访问地址','/orders/index.php');echo '<button>继续</button></form></section>';});
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-14 account/update.php 批量赋值允许普通用户自改 role 与 balance

- 当前版本：finding `caa2109f7d1440e784380f3b601fc168` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/update.php:5`；文件：`lab30-shop/app/public/account/update.php`
- 证据引用：`f22eb45f82c6d948` lab30-shop/app/public/account/update.php:2-6；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:5c369f286e4f751e5b7c:1（规范类型 mass_assignment）

**结论陈述（模型产出，不是证据）**

account/update.php 的允许列数组包含 role、balance、tier，并遍历 $_POST 把任意匹配字段拼进 UPDATE users SET。require_user() 只校验登录，不校验字段来源，故任意 customer 可提交 role=admin 或 balance=999999 自提权、自增余额。check_csrf 只防跨站，不防本类越权。

- 攻击前身份与适用前提：任何已登录账户（如 customer）且能提供有效 csrf token
- 入口 → 传播 → 危险操作/状态变更：POST 参数 role、balance（表单实际只渲染 display_name/nickname/email/homepage，但服务端接受任意列名） → $_POST -> foreach 列白名单匹配 -> $set/$values -> UPDATE users SET `role`=? ... WHERE id=$u['id'] → UPDATE users SET role/balance 生效，改变当前账户角色与余额
- 防护与边界：有 check_csrf 与 require_user，但缺少敏感字段黑名单与角色变更授权
- 静态判读：缺上下文（2 项）；缺失上下文：SHOP_DATA_DIR / 容器编排或 .env 部署配置未包含在快照中，无法确认 session_save_path 与 vault 目录是否位于 Web 可访问路径；HTTPS 强制与 secure cookie 配置未在源码中体现，无法据此判断会话传输保护
- 动态验证：动态确认（verification `a728d34fc00040b4a3d47cb409a0daf1`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：把可写列收敛为 display_name/nickname/email/homepage；role/balance/tier 仅在管理员接口并做独立授权与审计。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/update.php:2-6`（sha256 `b8227f19c05d0cd3…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$notice='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-15 content/page.php 的 page 参数未经白名单直接拼接进 include 路径，导致本地文件包含

- 当前版本：finding `90a5c284ff9c4d80a6d1d7e01b5ac086` revision 1（项目版本 27）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/content/page.php:3`；文件：`lab30-shop/app/public/content/page.php`
- 证据引用：`be43fce581c2c052` lab30-shop/app/public/content/page.php:2-3
- 根因类别：task_goal:v2:f28ad72a70729e3f8a8e:1（规范类型 lfi）

**结论陈述（模型产出，不是证据）**

page.php 第 2 行取自 $_GET['page'] 并强制转字符串，第 3 行直接拼接到 include 语句 APP_ROOT.'/resources/views/'.$name.'.php'，无白名单、无 basename、无路径规范化。攻击者可用 ../ 序列穿越到任意 .php 文件并包含执行，读取或执行服务器端脚本。

- 攻击前身份与适用前提：内容中心 /content/page.php 可直接访问；目标文件以 .php 结尾
- 入口 → 传播 → 危险操作/状态变更：GET 参数 page → $_GET['page'] -> $name -> APP_ROOT.'/resources/views/'.$name.'.php' -> include → include 动态拼接文件路径
- 防护与边界：无白名单，未使用 basename 或路径规范化；仅强制字符串转换
- 静态判读：证据已记录
- 动态验证：动态确认（verification `795f5e0b4a0543efb4e1e8228cbd9ac8`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：将 page 参数与白名单映射（如 home/shipping），或使用 basename 且校验路径存在；禁止将用户输入拼接进 include。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/content/page.php:2-3`（sha256 `53c5997117f2d54c…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$name=(string)($_GET['page']??'home');
    3  page('内容中心',function()use($name){include APP_ROOT.'/resources/views/'.$name.'.php';echo '<section class="panel"><a href="?page=home">商城介绍</a> · <a href="?page=shipping">配送与售后</a></section>';},'内容中心');
```

### C-16 support/download.php 的 file 参数未做路径校验，登录用户可遍历读取 data_dir 下任意文件（含 sessions）

- 当前版本：finding `b60484437bb84f9da1529d79ec5b122a` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/download.php:3`；文件：`lab30-shop/app/public/support/download.php`
- 证据引用：`10c0c8123072e718` lab30-shop/app/public/support/download.php:2-3；`8d6a30203fcb8cca` lab30-shop/app/src/bootstrap.php:9-14；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:3b5bfd092e8bfaa47ace:1（规范类型 path_traversal）

**结论陈述（模型产出，不是证据）**

download.php 第 3 行把 $_GET['file'] 原样拼接到 data_dir().'/docs/' 后传给 file_get_contents，仅用 is_file 判断存在性，没有 basename、realpath 或目录前缀校验。攻击者（任意已登录用户，第 2 行 require_user）可提交 file=../sessions/<sid> 等值，越过 docs 目录读取 SHOP_DATA_DIR（默认 /var/lib/shop）下的其他文件，包括第 14 行设置的会话存储目录 sessions 中的会话文件，或任意 ../ 可达的绝对化路径。由于输入未拒绝 '..' 与 '/'，路径遍历成立；file_get_contents 对 php://filter 等包装器同样可用，但 is_file 对包装器可能返回 false，故以 ../ 遍历为确定路径。

- 攻击前身份与适用前提：攻击者持有任意有效登录会话
- 入口 → 传播 → 危险操作/状态变更：$_GET['file'] → $_GET['file'] -> (string) -> data_dir().'/docs/' 字符串拼接 -> $path -> is_file() -> file_get_contents($path) -> echo → file_get_contents 读取拼接路径并以 text/plain 输出文件内容
- 防护与边界：仅有 is_file() 存在性检查，无 basename/realpath/前缀白名单；require_user() 只校验登录不校验路径
- 静态判读：证据已记录
- 动态验证：动态确认（verification `425fed5d5e0040d88d95e771f115a980`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：对 file 参数使用 basename() 或白名单映射到具体文档；用 realpath() 规范化后校验结果必须位于 data_dir().'/docs/' 前缀内，拒绝包含 '..'、'/' 与包装器协议的输入。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/support/download.php:2-3`（sha256 `71f0558eeb4ebb6c…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();
    3  if(isset($_GET['file'])){$path=data_dir().'/docs/'.(string)$_GET['file'];if(!is_file($path))fail_request('文档不存在。',404);header('Content-Type: text/plain; charset=utf-8');echo file_get_contents($path);exit;}
```

`lab30-shop/app/src/bootstrap.php:9-14`（sha256 `2050819d093be02b…`）

```php
    9  function data_dir(): string { return getenv('SHOP_DATA_DIR') ?: '/var/lib/shop'; }
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
   11  function start_session(?string $sid = null): void {
   12      if (session_status() === PHP_SESSION_ACTIVE) return;
   13      ini_set('session.use_strict_mode', '0');
   14      session_save_path(data_dir() . '/sessions');
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-17 account/settings.php 邮箱更新缺少 CSRF 校验，可跨站改写绑定邮箱

- 当前版本：finding `192169b676e44fbcaf428676c0233436` revision 1（项目版本 11）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/settings.php:5`；文件：`lab30-shop/app/public/account/settings.php`
- 证据引用：`acc5953e7fe3994f` lab30-shop/app/public/account/settings.php:2-8；`4eba9252f833f919` lab30-shop/app/src/bootstrap.php:38-40；`06e77bb1ca712323` lab30-shop/app/src/bootstrap.php:16-16
- 根因类别：task_goal:v2:f267ece79c0056c881f9:1（规范类型 csrf）

**结论陈述（模型产出，不是证据）**

settings.php 第2行 require_user 建立会话身份后，第3行仅判断 POST，第4行校验 email 格式，第5行直接执行 UPDATE users SET email=? WHERE id=? 并写事件日志，全程未调用 bootstrap.php:40 的 check_csrf，表单第8行也未输出 csrf_field。攻击者页面可用自动提交表单让受害者浏览器向该接口 POST 任意 email，从而把账户邮箱改为攻击者地址；仅有的边界是会话 cookie SameSite=Lax（bootstrap.php:16），该设置使典型跨站 POST 不带 cookie，构成利用障碍但并非服务端校验。

- 攻击前身份与适用前提：受害者处于已登录状态且浏览器在跨站 POST 时发送会话 cookie（SameSite=Lax 实施环境下通常被浏览器拦截）
- 入口 → 传播 → 危险操作/状态变更：跨站页面自动提交的 POST 表单字段 $_POST['email'] → $_POST['email'] -> filter_var 校验 (settings.php:4) -> UPDATE users SET email=? WHERE id=$u['id'] (settings.php:5) → UPDATE users 修改当前用户绑定邮箱（账户找回/通知地址被替换）
- 防护与边界：无服务端 CSRF token 校验；仅 SameSite=Lax cookie 属浏览器侧缓解
- 静态判读：证据已记录
- 动态验证：动态确认（verification `e02edaf82f2f40fb96dabf07be468450`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 3.1 (low) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：在 POST 分支首行调用 check_csrf() 并在表单输出 csrf_field()，同时将 SameSite 设为 Strict 作为纵深防御。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/settings.php:2-8`（sha256 `f54949d62e46b9ca…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$notice='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      $email=(string)($_POST['email']??'');if(!filter_var($email,FILTER_VALIDATE_EMAIL))fail_request('请输入有效邮箱。');
    5      db()->prepare('UPDATE users SET email=? WHERE id=?')->execute([$email,$u['id']]);event_log('update_email',['email'=>$email]);$u['email']=$email;$notice='邮箱已更新。';
    6      if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['email'=>$email,'updated'=>true]);
    7  }
    8  page('邮箱设置',function()use($u,$notice){echo '<section class="panel narrow">';if($notice)echo '<div class="notice">'.h($notice).'</div>';echo '<form method="post">';form_input('email','常用邮箱',$u['email'],'email');echo '<button>保存邮箱</button></form></section>';},'账户与会员');
```

`lab30-shop/app/src/bootstrap.php:38-40`（sha256 `2050819d093be02b…`）

```php
   38  function csrf_token(): string { start_session(); return $_SESSION['csrf'] ??= bin2hex(random_bytes(24)); }
   39  function csrf_field(): string { return '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'; }
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

`lab30-shop/app/src/bootstrap.php:16-16`（sha256 `2050819d093be02b…`）

```php
   16      session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'path' => '/']);
```

### C-18 运营网络诊断 host 参数未转义拼接进 shell_exec（命令注入 RCE）

- 当前版本：finding `a43f7873a81749b48f256ab0fc41c778` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/ping.php:2`；文件：`lab30-shop/app/public/ops/ping.php`
- 证据引用：`61f200eb89320676` lab30-shop/app/public/ops/ping.php:1-3；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:6102603c14bab4170d65:1（规范类型 command_injection）

**结论陈述（模型产出，不是证据）**

ping.php 第 2 行把 $_GET['host'] 直接拼进 shell_exec 命令行，未使用 escapeshellarg/escapeshellcmd，操作者可用 ;、&#124;、$() 等注入任意命令。host 非空即执行。require_user 只做身份校验，不净化输入。

- 攻击前身份与适用前提：攻击者持有 operator 或 admin 会话
- 入口 → 传播 → 危险操作/状态变更：GET 参数 host → $_GET['host'] -> $host -> shell_exec('ping -c 1 -W 1 '.$host) → shell_exec 系统命令执行
- 防护与边界：仅 require_user(['operator','admin']) 身份限制；无输入净化
- 静态判读：证据已记录
- 动态验证：动态确认（verification `44be6903ba364aaaa79ce14526327b3e`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用白名单校验主机名/使用 escapeshellarg 并避免拼接；优先用专门网络库。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/ping.php:1-3`（sha256 `c15517950afe0794…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$host=(string)($_GET['host']??'');$output=$host!==''?(string)shell_exec('ping -c 1 -W 1 '.$host):'';
    3  page('网络诊断',function()use($host,$output){echo '<section class="panel"><form method="get">';form_input('host','主机地址',$host?:'127.0.0.1');echo '<button>开始诊断</button></form><pre id="diagnostic-output">'.h($output).'</pre></section>';},'运营工作台');
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

### C-19 ops/users.php 信任客户端 $_COOKIE['role'] 绕过管理员鉴权

- 当前版本：finding `d150482ca592418eb7a1f15fa9732730` revision 1（项目版本 25）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/users.php:2`；文件：`lab30-shop/app/public/ops/users.php`
- 证据引用：`d4000ad3e3500c5b` lab30-shop/app/public/ops/users.php:2-5；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37；`e7189d5aff3d503f` lab30-shop/app/public/ops/index.php:2-2
- 根因类别：task_goal:v2:04b902cf449b08078bab:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

ops/users.php 第 2 行以 $role=(string)($_COOKIE['role']??$u['role']) 读取客户端 cookie 覆盖服务端角色，仅做 $role!=='admin' 判断且不通过 require_user(['admin']) 做服务端校验；普通登录用户发送 Cookie: role=admin 即可通过第 3-5 行读取全部账户权限清单。对比 ops/index.php:2 与 bootstrap.php:33-37 使用服务端 $u['role'] 的严格校验，此路径缺失服务端授权。

- 攻击前身份与适用前提：攻击者拥有任意一个有效登录会话
- 入口 → 传播 → 危险操作/状态变更：Cookie 参数 role → 第 2 行读取 $_COOKIE['role'] ⇒ 覆盖 $u['role'] ⇒ 第 3 行查询全部用户 ⇒ 第 4-5 行输出 → 跨权限读取全部用户清单及邮箱
- 防护与边界：require_user(['admin']) 的服务端角色校验未使用；仅以客户端 cookie 值判断
- 静态判读：证据已记录
- 动态验证：动态确认（verification `fdd313376f5548439516baf94152cbc1`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 7.7 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：移除 $_COOKIE['role'] 读取，改用 require_user(['admin']) 依据服务端会话中的角色进行严格校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/users.php:2-5`（sha256 `3c5e879d945650ba…`）

```php
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

`lab30-shop/app/public/ops/index.php:2-2`（sha256 `3e08442a501932a5…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);
```

### C-20 ops/members.php 会员查询参数经 member_lookup 拼接进 SQL 造成 SQL 注入

- 当前版本：finding `36d7493a350d4e4eb864aa54056d018b` revision 1（项目版本 9）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/member_lookup.php:3`；文件：`lab30-shop/app/src/member_lookup.php`
- 证据引用：`4d2f2da581629f05` lab30-shop/app/src/member_lookup.php:1-4；`12d724d86e16c5f7` lab30-shop/app/public/ops/members.php:1-4；`85b2e45ff4e8d0eb` lab30-shop/app/src/bootstrap.php:4-8
- 根因类别：task_goal:v2:6b39e8c7a291f09ea733:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

ops/members.php 第 2 行取 $_GET['q'] 作为 $term 传入 member_lookup；member_lookup.php 第 3 行使用 db()->query("SELECT ... WHERE username LIKE '%" . $term . "%'")，将攻击者输入直接拼入 SQL，未使用预处理占位符。bootstrap.php 的 db() 虽支持预处理，但该调用未使用。运营/管理员身份可通过构造 q 参数闭合 LIKE 引号读取任意 users 数据。

- 攻击前身份与适用前提：拥有 operator 或 admin 角色的已登录会话，访问 /ops/members.php?q=...
- 入口 → 传播 → 危险操作/状态变更：$_GET['q'] (ops/members.php:2) → q -> $term -> member_lookup($term) -> 字符串拼接到 LIKE 子句 -> db()->query → db()->query 执行拼接后的 SELECT（member_lookup.php:3）
- 防护与边界：仅 require_user(['operator','admin']) 限制身份；无 SQL 参数化/转义
- 静态判读：证据已记录
- 动态验证：动态确认（verification `1f43a1c5b6de46ae97ab1986a4d3299e`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 db()->prepare('... WHERE username LIKE ?') 并以 '%'.$term.'%' 绑定；对 LIKE 通配符做转义。

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

### C-21 catalog 搜索参数 q 直接拼接进 SQL LIKE 查询导致反射型 SQL 注入

- 当前版本：finding `a8c11d900cdd412581e02828cea4b299` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/catalog/index.php:4`；文件：`lab30-shop/app/public/catalog/index.php`
- 证据引用：`b07638e22476de42` lab30-shop/app/public/catalog/index.php:3-5；`bd2a787730066498` lab30-shop/app/src/bootstrap.php:4-7
- 根因类别：task_goal:v2:87d9942f790d1fa2742c:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

index.php:3 从 $_GET['q'] 取搜索词仅做 (string) 转换，index.php:4 用字符串连接嵌入 "... WHERE name LIKE '%" . $term . "%' ORDER BY id" 后直接 db()->query()，无 prepare 占位符、无转义或白名单。单引号即可闭合字面量改写条件或 UNION 读取 users 表数据；页面把 $term 交给 h() 只影响回显，不缓解注入。

- 攻击前身份与适用前提：未认证直接请求目录页
- 入口 → 传播 → 危险操作/状态变更：GET 参数 q（/catalog/index.php?q=...），无需登录 → index.php:3 $_GET['q'] -> (string) -> index.php:4 字符串拼接 -> db()->query() 执行 → PDO::query() 执行拼接后的 SQL
- 防护与边界：无参数化、无转义；bootstrap.php:6 的 PDO 选项只作用于占位符
- 静态判读：证据已记录
- 动态验证：动态确认（verification `15c43b2a41b448d4bf4c692a7ea66827`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.2 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改为 prepare("SELECT ... WHERE name LIKE ? ORDER BY id") 并用 ['%'.$term.'%'] 绑定。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/catalog/index.php:3-5`（sha256 `e85bd1c2fa6a4b78…`）

```php
    3  $term=(string)($_GET['q']??'');
    4  $products=db()->query("SELECT id,name,description,price,stock,color FROM products WHERE name LIKE '%".$term."%' ORDER BY id")->fetchAll();
    5  page('本季好物',function()use($products,$term){echo '<form class="search-form" method="get"><input aria-label="搜索商品" name="q" placeholder="搜索你喜欢的好物" value="'.h($term).'"><button>搜索</button></form><p class="muted">共找到 <span id="result-count">'.count($products).'</span> 件商品</p><div class="products">';foreach($products as $p)echo '<article class="product"><div class="product-art '.h($p['color']).'"><svg viewBox="0 0 240 220" role="img" aria-label="'.h($p['name']).'"><use href="/assets/products.svg#product-'.(int)$p['id'].'"></use></svg></div><div class="product-copy"><small>拾光 · 日常系列</small><h2>'.h($p['name']).'</h2><p>'.h($p['description']).'</p><div class="row"><strong>¥'.h($p['price']).'</strong><a class="button secondary" href="/catalog/detail.php?id='.(int)$p['id'].'">查看商品 →</a></div></div></article>';echo '</div><a href="/catalog/greeting.php">查看到店欢迎信息</a>';},'商品目录');
```

`lab30-shop/app/src/bootstrap.php:4-7`（sha256 `2050819d093be02b…`）

```php
    4  function db(): PDO {
    5      static $pdo;
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    7      return $pdo;
```

### C-22 ops/jobs.php 对 POST job 直接 unserialize，DispatchJob::__wakeup 触发 shell_exec 命令执行

- 当前版本：finding `311b523024ac4f2e91f79a9cb320a7aa` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/jobs.php:3`；文件：`lab30-shop/app/public/ops/jobs.php`
- 证据引用：`bc71d05290d8c856` lab30-shop/app/public/ops/jobs.php:2-3；`e030edd4e1bdfc70` lab30-shop/app/src/dispatch_job.php:2-4；`063c928d2d7c3b2e` lab30-shop/app/src/bootstrap.php:33-40
- 根因类别：task_goal:v2:757483b4d7a7c991a08f:1（规范类型 insecure_deserialization）

**结论陈述（模型产出，不是证据）**

ops/jobs.php 第 3 行对 $_POST['job'] 做 base64_decode 后立即 unserialize，之后才 instanceof DispatchJob 校验；dispatch_job.php 第 4 行的 __wakeup 调用 shell_exec($this->command)，command 为攻击者可控制的 public 属性。因此在反序列化阶段即执行命令，类型与 CSRF/登录校验均不能阻止载荷中的命令。

- 攻击前身份与适用前提：攻击者持有 operator 或 admin 有效会话并获取 csrf token
- 入口 → 传播 → 危险操作/状态变更：$_POST['job']（base64 序列化对象） → base64_decode -> unserialize -> DispatchJob::__wakeup -> shell_exec($this->command) → shell_exec 系统命令执行
- 防护与边界：check_csrf 与 require_user(['operator','admin']) 仅控制需求入口；instanceof 校验在 unserialize 之后，无法阻止反序列化魔术方法执行
- 静态判读：缺上下文（1 项）；缺失上下文：未发现除 DispatchJob 外可用于 backup.php 的带危险魔术方法类；若其他快照文件（未读取）定义了 __destruct/__wakeup 反序列化链，backup.php 需重新评估，当前快照内未确认可用利用链。
- 动态验证：动态确认（verification `46372aed8c0d4cc684dba5fd03b40276`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：不要把用户可控的序列化数据交给 unserialize；改用 JSON 白名单字段解析，并为 DispatchJob 移除 __wakeup 中的命令执行或改名 class 以阻断对象链。

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

### C-23 ops/template-render.php 将 POST 模板双花括号内容直接拼接进 eval（代码执行）

- 当前版本：finding `d4fc477cfe8c4e90b2af4078847ac915` revision 1（项目版本 23）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-render.php:3`；文件：`lab30-shop/app/public/ops/template-render.php`
- 证据引用：`136d02a92a08ac98` lab30-shop/app/public/ops/template-render.php:1-4；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36；`415907ec6bf2f739` lab30-shop/app/src/bootstrap.php:40-40
- 根因类别：task_goal:v2:491b4c9ea0b74ce979d1:1（规范类型 code_execution）

**结论陈述（模型产出，不是证据）**

template-render.php 第2行将 $_POST['template'] 直接存入 $template；第3行在 POST 且通过 check_csrf 后，用 preg_replace_callback 对每个 {{...}} 内容 $m[1] 拼接成 'return '.$m[1].';' 并 eval。表达式内容未被过滤或白名单化，攻击者可注入任意 PHP 表达式/语句（如 system('id')、file_get_contents 等）实现代码执行与信息泄露。check_csrf 仅校验 CSRF token，不限制表达式内容。

- 攻击前身份与适用前提：攻击者持有 operator/admin 会话且携带页面 CSRF token
- 入口 → 传播 → 危险操作/状态变更：$_POST['template'] 中 {{ }} 内表达式 → $_POST['template'] -> preg_replace_callback 捕获 $m[1] -> eval('return '.$m[1].';') → eval 执行攻击者拼接的 PHP 代码
- 防护与边界：require_user 角色校验与 check_csrf token 校验，均不约束表达式
- 静态判读：证据已记录
- 动态验证：动态确认（verification `87f86b0925c7472f983ee5742445d033`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：不要用 eval 实现模板表达式；用受限的表达式解析器并只允许安全运算。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/template-render.php:1-4`（sha256 `357da9e9959275d8…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$template=(string)($_POST['template']??'');$result='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$result=preg_replace_callback('/\{\{(.*?)\}\}/s',function($m){return (string)eval('return '.$m[1].';');},$template);}
    4  page('营销内容排版',function()use($template,$result){echo '<section class="panel"><p>在双花括号内填写表达式，预览输出内容。</p><form method="post">'.csrf_field().'<label>模板<textarea name="template" required>'.h($template?:'本周精选，共 {{ 2 + 2 }} 款好物').'</textarea></label><button>生成预览</button></form><pre>'.h($result).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

`lab30-shop/app/src/bootstrap.php:40-40`（sha256 `2050819d093be02b…`）

```php
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

### C-24 ops/report.php 用 nickname 字符串拼接 query 的二阶 SQL 注入

- 当前版本：finding `b916387c142d4a35a759e43c51bfc611` revision 1（项目版本 15）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/report.php:3`；文件：`lab30-shop/app/public/ops/report.php`
- 证据引用：`667c91ac7c21aa66` lab30-shop/app/public/ops/report.php:2-3；`bd2a787730066498` lab30-shop/app/src/bootstrap.php:4-7
- 根因类别：task_goal:v2:8c0084c7a65d0d01a41b:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

report.php:2 以参数化 prepare 按 id 取 nickname，随后 report.php:3 将取出的 $nickname 以 "SELECT username,email,role FROM users WHERE nickname='" . $nickname . "'" 拼接后 db()->query 执行。若某用户的 nickname 被写入含单引号的注入载荷（如账户设置处可写 nickname），运营在报表中选择该 user_id 即触发二阶 SQL 注入。用户通过 user_id 选择注入源，nickname 为受污染的持久化数据。

- 攻击前身份与适用前提：存在可由攻击者控制 nickname 的写入路径（如账户设置），且运营在此页面选择对应 user_id。
- 入口 → 传播 → 危险操作/状态变更：$_GET['user_id'] 选择 users.id，间接使用攻击者之前写入的 nickname 值 → report.php:2 prepare/execute 取 $nickname -> report.php:3 字符串拼接进 WHERE nickname='...' -> db()->query() 执行 → db()->query("SELECT username,email,role FROM users WHERE nickname='" . $nickname . "'")
- 防护与边界：第一次查询使用了参数化，但第二次拼接查询未参数化/未转义 $nickname。
- 静态判读：证据已记录
- 动态验证：动态确认（verification `87ac020d13914e3c90945cbf16f37c88`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.9 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用参数化：db()->prepare('SELECT ... WHERE nickname=?')->execute([$nickname])。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/report.php:2-3`（sha256 `90d7d60d44815374…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user(['operator','admin']);$id=(int)($_GET['user_id']??1);$q=db()->prepare('SELECT nickname FROM users WHERE id=?');$q->execute([$id]);$nickname=$q->fetchColumn();if($nickname===false)fail_request('会员不存在。',404);
    3  $rows=db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'")->fetchAll();
```

`lab30-shop/app/src/bootstrap.php:4-7`（sha256 `2050819d093be02b…`）

```php
    4  function db(): PDO {
    5      static $pdo;
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    7      return $pdo;
```

### C-25 资料维护接口批量赋值允许普通用户自改 role/balance/tier 提权

- 当前版本：finding `b159a64c79e545e88e66862ee93c64c7` revision 1（项目版本 6）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/update.php:4`；文件：`lab30-shop/app/public/account/update.php`
- 证据引用：`f22eb45f82c6d948` lab30-shop/app/public/account/update.php:2-6；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36；`6700e4b97da566f5` lab30-shop/app/src/bootstrap.php:53-53
- 根因类别：task_goal:v2:ffb5c107c6eaa88493f7:1（规范类型 mass_assignment）

**结论陈述（模型产出，不是证据）**

update.php 把请求 POST 字段名与列白名单 ['display_name','email','role','balance','tier','nickname','homepage'] 做交集后直接拼进 UPDATE users，白名单包含 role、balance、tier 等敏感列。任一登录用户提交 role=admin 即可自提为管理员，或以 balance=999999 篡改余额；服务端没有任何字段级或角色校验（对比 settings.php 只更新 email）。

- 攻击前身份与适用前提：攻击者持有任意已登录会话并能读取自身 CSRF token
- 入口 → 传播 → 危险操作/状态变更：$_POST['role']、$_POST['balance']、$_POST['tier'] → require_user() 取得 $u 后进入 POST 分支 ; check_csrf() ; foreach($_POST) 与 $columns 交集生成 SET 子句与 $values ; db()->prepare('UPDATE users SET ...') 执行，WHERE id=$u['id'] → UPDATE users SET role=?,balance=? ... 写入敏感权限/资金列
- 防护与边界：仅有 CSRF 校验和列名白名单；白名单错误地包含 role/balance/tier，未限制普通用户可写字段
- 静态判读：证据已记录
- 动态验证：动态确认（verification `4ee6c93d2d3742298e145935dfce9ee4`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：把可写字段改为固定且最小的集合（display_name、nickname、email、homepage），role/balance/tier 只在管理员专用接口中变更并做角色校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/update.php:2-6`（sha256 `b8227f19c05d0cd3…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$notice='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

`lab30-shop/app/src/bootstrap.php:53-53`（sha256 `2050819d093be02b…`）

```php
   53      if (!$u || !in_array($u['role'], ['operator','admin'], true)) unset($nav['/ops/index.php']);
```

### C-26 登录页以 GET sid 设置会话 ID 且登录后不轮换，构成会话固定

- 当前版本：finding `8ee0b33f919c4f20b10c9ee7992796f4` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/bootstrap.php:17`；文件：`lab30-shop/app/public/auth/login.php`
- 证据引用：`368b0f4121e7e402` lab30-shop/app/public/auth/login.php:3-3；`8506476ecddd25f6` lab30-shop/app/public/auth/login.php:8-9；`96d4fc4a57e8be01` lab30-shop/app/src/bootstrap.php:13-18
- 根因类别：task_goal:v2:c82947ecb02d1c60d5ef:1（规范类型 session_fixation）

**结论陈述（模型产出，不是证据）**

login.php 第 3 行将 GET 参数 sid 传入 start_session；bootstrap.php 第 13 行把 session.use_strict_mode 设为 0，第 17 行在格式匹配后调用 session_id($sid)、第 18 行 session_start，使客户端提供的会话 ID 被接受。登录成功分支 login.php 第 8-9 行仅写入 $_SESSION['user_id'] 并重定向，未调用 session_regenerate_id。攻击者先获得一个已知会话 ID，诱导受害者以 ?sid= 打开登录页并登录；认证数据即写入攻击者已知的会话，攻击者复用该 ID 获得受害者身份。

- 攻击前身份与适用前提：攻击者能向受害者投递带已知 sid 的 /auth/login.php 链接，受害者在该页面完成登录；攻击者随后使用同一 sid 访问站点
- 入口 → 传播 → 危险操作/状态变更：GET 参数 sid → login.php:3 -> start_session($sid) -> bootstrap.php:17 session_id($sid) -> bootstrap.php:18 session_start；login.php:8 写入认证状态 → 以客户端指定的会话标识建立并沿用为已认证会话
- 防护与边界：第 17 行仅做正则格式校验（16-64 位字符），未验证会话由服务端生成；strict_mode 被显式关闭；登录后无 ID 轮换
- 静态判读：证据已记录
- 动态验证：动态确认（verification `3ec2b903eaab4afaa9e6250e2ff49749`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：登录成功后调用 session_regenerate_id(true)；启用 session.use_strict_mode=1；不要从 GET 接受外部会话 ID。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/auth/login.php:3-3`（sha256 `b9be43ddb2233156…`）

```php
    3  start_session(isset($_GET['sid']) ? (string)$_GET['sid'] : null);
```

`lab30-shop/app/public/auth/login.php:8-9`（sha256 `b9be43ddb2233156…`）

```php
    8          $_SESSION['user_id']=(int)$row['id']; event_log('login');
    9          header('Location: /'); exit;
```

`lab30-shop/app/src/bootstrap.php:13-18`（sha256 `2050819d093be02b…`）

```php
   13      ini_set('session.use_strict_mode', '0');
   14      session_save_path(data_dir() . '/sessions');
   15      session_name('SHOPSESSID');
   16      session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'path' => '/']);
   17      if ($sid !== null && preg_match('/^[a-zA-Z0-9,-]{16,64}$/D', $sid)) session_id($sid);
   18      session_start();
```

### C-27 ops/formula.php 通过 GET func 变量函数调用任意 PHP 函数（code_execution）

- 当前版本：finding `07fe40ddf2114282bdfd729f8a856379` revision 1（项目版本 10）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/formula.php:3`；文件：`lab30-shop/app/public/ops/formula.php`
- 证据引用：`f3b7c0b40a3232d5` lab30-shop/app/public/ops/formula.php:1-4；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:ea69a087b746192be635:1（规范类型 code_execution）

**结论陈述（模型产出，不是证据）**

formula.php 第3行当 isset($_GET['func']) 时取 (string)$_GET['func'] 存入 $func，然后直接执行 $func((string)($_GET['arg']??''))。没有任何白名单、function_exists 或禁用函数检查，攻击者可把 func 设为 system、passthru、file_get_contents 等任意可调用函数，argv 由 $_GET['arg'] 控制。第2行仅有 require_user(['operator','admin']) 身份校验，不限制函数名。

- 攻击前身份与适用前提：攻击者持有 operator 或 admin 角色会话
- 入口 → 传播 → 危险操作/状态变更：$_GET['func'] 与 $_GET['arg'] → $_GET['func'] -> (string)$func -> $func($_GET['arg']) 动态调用 → 变量函数 $func() 调用任意 PHP 函数
- 防护与边界：仅 require_user 角色校验；无函数白名单
- 静态判读：证据已记录
- 动态验证：动态确认（verification `3dcaf580e6704212b2744562d30cc928`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：用白名单映射允许的运算函数，拒绝任意字符串函数名。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/formula.php:1-4`（sha256 `686f39f31996a5d3…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$result='';
    3  if(isset($_GET['func'])){$func=(string)$_GET['func'];$result=(string)$func((string)($_GET['arg']??''));}
    4  page('运营公式计算',function()use($result){echo '<section class="panel"><p>选择函数并提交文本进行试算。</p><form method="get">';form_input('func','函数名称','strtoupper');form_input('arg','输入值','spring-sale');echo '<button>执行计算</button></form><pre>'.h($result).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-28 php.ini 开启 allow_url_include，为 LFI 升级为远程代码包含提供条件

- 当前版本：finding `127c478d14a64048b12521cde5a5587c` revision 1（项目版本 2）；CVSS 评分版本 1
- 位置：`lab30-shop/docker/php.ini:3`；文件：`lab30-shop/docker/php.ini`
- 证据引用：`09625de28ecabb6a` lab30-shop/docker/php.ini:2-3
- 根因类别：task_goal:v2:43b9a0f0002843703e94:1（规范类型 rfi）

**结论陈述（模型产出，不是证据）**

php.ini 第3行显式设置 allow_url_include = On，且第2行 allow_url_fopen = On，使 include/require 可加载远程 URL 内容。若应用存在用户可控的包含路径，即可将原本的本地文件包含升级为远程代码包含/执行。该配置本身是明确的危险运行时指令；具体可利用的包含点需结合 content/page.php 等入口确认。

- 攻击前身份与适用前提：需存在将攻击者输入拼入 include/require 的代码路径；当前切片未提供该包含点源码
- 入口 → 传播 → 危险操作/状态变更：潜在的用户可控 include 路径参数（具体入口未在本切片确认） → 未记录 → include/require 加载远程 URL 并解析为 PHP 代码
- 防护与边界：无；apache.conf AllowOverride None 阻止 .htaccess 覆盖，但未关闭 allow_url_include
- 静态判读：缺上下文（3 项）；缺失上下文：lab30-shop/content/page.php 等实际 include/require 入口源码，用于确认 allow_url_include=On 能否被实际利用（RFI）；登录/认证与会话初始化代码，用于确认 session.use_strict_mode=0 是否可在无 session_regenerate_id 情况下被利用；bin/setup.php 内容，用于确认初始化时是否设置默认口令或弱凭据
- 动态验证：不确定（不确定）（verification `da9c061c761b4ceb94448b4acd73ae60`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：在 php.ini 设置 allow_url_include = Off，并对包含路径使用白名单；禁用 allow_url_fopen 或对包含操作单独限制。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/docker/php.ini:2-3`（sha256 `b65de9007c7f42b3…`）

```
    2  allow_url_fopen = On
    3  allow_url_include = On
```

## 5. 实际验证和终审理由

### C-01 session.use_strict_mode 关闭，未初始化会话ID被接受存在会话固定风险

- verification `e22a4a838b364e1cb1487d15318b2c8e`（finding `ea7837d9c8a646d4939112604172020a` revision 1，context `3b657897c6a34240ba28434f52ec7c72`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常登录流程（无 ?sid、无预置 Cookie）行为对照：本作业中未使用预置 SID 的对照请求 /account/me.php 返回 401 {"error":"请先登录后使用此功能。"}，说明未登录会话不能访问会员接口；系统按默认流程登录时账户接口返回 200（A4 为预置 SID 但由真实凭据登录后的会员页）。会话机制在登录后确实返回会员数据，差异仅在于 SID 是否由攻击者预先指定。
  - 攻击侧观测：攻击侧观测（作业 e138e01caf0c45bbb7cb1d076a1e385a，身份 alice）：向量A——GET /auth/login.php?sid=fixedsida1b2c3d4e5f60718 返回 200 并下发 Set-Cookie SHOPSESSID=fixedsida1b2c3d4e5f60718（接受了攻击者指定的未初始化 ID）；登录前 /account/me.php 401；alice 在该 SID 下 POST 登录后 302→200 且未再下发 Set-Cookie（未重新生成 ID）；随后以同一 SID（无凭据）请求 /account/me.php 得 200 {"id":1,"username":"alice",...,"balance":"100.00"}。向量B——不带 ?sid、仅伪造 Cookie SHOPSESSID=cookiejar0f1e2d3c4b5a6978：GET / 200 且无 Set-Cookie（PHP 直接沿用该未初始化 ID），登录后仍无 Set-Cookie，/account/me.php 返回 200 alice 数据。对照：从未参与登录的 SID 请求 /account/me.php 返回 401 {"error":"请先登录后使用此功能。"}。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`e138e01caf0c45bbb7cb1d076a1e385a`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`e138e01caf0c45bbb7cb1d076a1e385a` script finished exit=0
  - 适配脚本：`e22a4a83-adapted-poc.php`（见证据包 evidence/）
  - 备注：证据引用 ev-8b5952bf6858b45e（作业 e138e01caf0c45bbb7cb1d076a1e385a stdout，含 A1-A5、B1-B3 与对照）。源码依据：bootstrap.php 第 13 行 ini_set('session.use_strict_mode','0')、第 17 行对传入 $sid 仅做字符集/长度正则后 session_id($sid)、第 18 行 session_start()；auth/login.php 第 3 行 start_session(isset($_GET['sid'])?(string)$_GET['sid']:null)，第 8 行登录成功仅 $_SESSION['user_id']=(int)$row['id'] 并 event_log('login')，没有 session_regenerate_id。快照 docker/php.ini 第 7 行 session.use_strict_mode=0、第 8 行 session.save_path=/var/lib/shop/sessions 与运行时行为一致。两向量均表现为：攻击者可预置/指定会话 ID，受害者登录后该 ID 被认证且未更换，攻击者以同一 ID 可直接读取受害者账户，构成会话固定。

- 正式复核 `43ebfe1c9e1646fa8f1bef65bf0db74a`：复核确认；引用 revision 1 / verification `e22a4a838b364e1cb1487d15318b2c8e`
  - 理由：正常观测中，显式、未初始化的 sid 下发 SHOPSESSID，登录前 me 为 401；攻击观测中，登录后无新 Set-Cookie，同一 SID 无凭据可读 alice 账户（向量A/B 均如此），从未参与登录的 SID 仍为 401。这逐一对应 php.ini:7 strict_mode=0 与登录不轮换的源码结论，动态确认会话固定成立。
  - 复核观测：正常侧 正常登录流程（无 ?sid、无预置 Cookie）行为对照：本作业中未使用预置 SID 的对照请求 /account/me.php 返回 401 {"error":"请先登录后使用此功能。"}，说明未登录会话不能访问会员接口；系统按默认流程登录时账户接口返回 200（A4 为预置 SID 但由真实凭据登录后的会员页）。会话机制在登录后确实返回会员数据，差异仅在于 SID 是否由攻击者预先指定。；攻击侧 攻击侧观测（作业 e138e01caf0c45bbb7cb1d076a1e385a，身份 alice）：向量A——GET /auth/login.php?sid=fixedsida1b2c3d4e5f60718 返回 200 并下发 Set-Cookie SHOPSESSID=fixedsida1b2c3d4e5f60718（接受了攻击者指定的未初始化 ID）；登录前 /account/me.php 401；alice 在该 SID 下 POST 登录后 302→200 且未再下发 Set-Cookie（未重新生成 ID）；随后以同一 SID（无凭据）请求 /account/me.php 得 200 {"id":1,"username":"alice",...,"balance":"100.00"}。向量B——不带 ?sid、仅伪造 Cookie SHOPSESSID=cookiejar0…

### C-02 partner/portal.php 不校验合作方令牌 HMAC 签名，伪造 admin 角色 payload 即可越权读取全部订单

- verification `9554fcf40efc4c1984d25eb46257f4dc`（finding `d014a86b046242429f9da520b13b06b4` revision 1，context `edae84a986c64a8fa18ca491d836cb7b`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：匿名 GET /partner/portal.php（Accept: application/json，不带 token）：status=403，正文 {"error":"此合作方功能仅向管理员开放。"}；匿名 POST 携带 alice 账号经 /partner/token.php 真实签发的令牌（payload {'sub': 1, 'role': 'customer', 'name': 'alice'}）：同样 403；匿名 POST 携带伪造的 role=customer 令牌：403。即合法/非管理员令牌被拒绝，说明拒绝理由来自 payload 中的 role 而非签名或身份。
  - 攻击侧观测：匿名（无 CookieJar、无登录）POST /partner/portal.php?token=<header>.<{"sub":999,"role":"admin"}>.forgedsig（Accept: application/json）：status=200，返回 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}，得 2 条订单，其中 SG-1002 属于 bob（INCLUDES_BOB_ORDER True），即跨用户读取全表订单。签名段 "forgedsig" 从未被校验即可通过。对照：匿名无令牌 403；alice 经 /partner/token.php 正常签发的真实令牌（payload sub=1, role=customer）匿名携带时 403；伪造 role=customer 的令牌同样 403 —— 结果只由 payload.role 决定。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`7ff0865b18ff46ad924ec83a1ba8ac83`；`7871fcc82aad4ba29a6cd8966006ade0`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`7871fcc82aad4ba29a6cd8966006ade0` script finished exit=0；`7ff0865b18ff46ad924ec83a1ba8ac83` script finished exit=0
  - 适配脚本：`9554fcf4-adapted-poc_partner_portal_forge.py`（见证据包 evidence/）
  - 备注：证据引用：ev-0ad63f02b31e5bf9（作业 7871fcc82aad4ba29a6cd8966006ade0 stdout：匿名无令牌 403、真实 customer 令牌 403、伪造 admin 令牌 200 且含 BOB 订单 SG-1002、伪造 customer 令牌 403）、ev-513c7df3ff1cb5b4（宿主审计作业 7ff0865b18ff46ad924ec83a1ba8ac83：role=customer 令牌 403 与伪造 admin 200 的相同对照）。源码 portal.php 第 2 行从 $_POST['token']/Cookie 取令牌、explode('.') 第二段 base64/strtr 解码 json_decode 为 $payload，全程无 hash_hmac/hash_equals；第 3 行仅判断 ($payload['role']??'')!=='admin'；第 4 行 db()->query('SELECT order_no,total FROM orders ORDER BY id') 全表读取；第 5 行以 JSON 返回。token.php 第 4 行确实用 settings.generation 做 HMAC-SHA256 签发（可作对照），但 portal 不验证该签名。portal.php…

- 正式复核 `9fe61a92138e480a93a6ac8cd77a9f63`：复核确认；引用 revision 1 / verification `9554fcf40efc4c1984d25eb46257f4dc`
  - 理由：正常侧：匿名无令牌、真实签发的 alice customer 令牌、伪造 customer 令牌均 403；攻击侧：匿名伪造 role=admin 签名为 forgedsig 的令牌返回 200，取得含 bob 的 SG-1002 全表订单。拒绝理由只由 payload.role 决定，未见签名校验，与 portal.php:2-4 源码一致，确认未校验签名导致匿名越权读取订单。
  - 复核观测：正常侧 匿名 GET /partner/portal.php（Accept: application/json，不带 token）：status=403，正文 {"error":"此合作方功能仅向管理员开放。"}；匿名 POST 携带 alice 账号经 /partner/token.php 真实签发的令牌（payload {'sub': 1, 'role': 'customer', 'name': 'alice'}）：同样 403；匿名 POST 携带伪造的 role=customer 令牌：403。即合法/非管理员令牌被拒绝，说明拒绝理由来自 payload 中的 role 而非签名或身份。；攻击侧 匿名（无 CookieJar、无登录）POST /partner/portal.php?token=<header>.<{"sub":999,"role":"admin"}>.forgedsig（Accept: application/json）：status=200，返回 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}，得 2 条订单，其中 SG-1002 属于 bob（INCLUDES_BOB_ORDER True），即跨用户读取全表订单。签名段 "forgedsig" 从未被校验即可通过。对照：匿名无令牌 403；alice 经 /partner/token.php 正常签发的真实令牌（payload sub…

### C-03 远程模板预览 template 参数直接 include（RFI/LFI）

- verification `fd944e41b1924f5d86ecd4b8595e66ba`（finding `e31a73469c3246d6a6d58e07189ffede` revision 1，context `40e88ace37784fe083f17d7c4439b195`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 登录后访问 /ops/template-preview.php（不带 template）返回 200，#remote-template 区为空；按页面默认地址 template=http://fixtures:8080/templates/season.php 时该区只渲染预期模板内容“<h2>合作方 · 秋日生活提案</h2><p>让生活慢下来，把好物带回家。</p>”，无系统文件或执行痕迹。
  - 攻击侧观测：同一 operator 会话：template=/etc/passwd 时 #remote-template 区输出 root:x:0:0:root:/root:/bin/bash、daemon:x:1:1… 等系统账户行，证明可包含任意本地文件；template=data://text/plain;base64,<base64 of <?php echo 'XMARKRFI'.(6*7); ?>> 时输出 XMARKRFI42（“42”由包含的 PHP 代码求值产生，未出现在请求参数中），证明可包含远程/流并执行其中 PHP 代码，构成 RFI/RCE。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`004e9c518cd443af97169d53549e187c`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`004e9c518cd443af97169d53549e187c` script finished exit=0
  - 适配脚本：`fd944e41-adapted-poc.php`（见证据包 evidence/）
  - 备注：作业 004e9c518cd443af97169d53549e187c 在 operator（id=3, role=operator）下执行，符合源码 template-preview.php:2 require_user(['operator','admin']) 的入口前提；未用特权身份证明普通会员越权。源码 applicability=match：template-preview.php:3 在 page 回调内 if($template!=='')include $template，无白名单/路径校验，与 LFI、data:// 代码执行观测一致。

- 正式复核 `79fefee4841b427488fe942294af5b9b`：复核确认；引用 revision 1 / verification `fd944e41b1924f5d86ecd4b8595e66ba`
  - 理由：正常侧：不带 template 时区域为空；用默认模板 URL 时只渲染合作方文案。攻击侧：operator 会话下 template=/etc/passwd 输出 root:x:0:0 等系统账户行；data:// 内嵌 PHP 输出 XMARKRFI42（42 未出现在参数中，由包含执行产生）。这与 template-preview.php:3 直接 include 用户输入的源码一致，确认 LFI 与 RFI/RCE。
  - 复核观测：正常侧 operator 登录后访问 /ops/template-preview.php（不带 template）返回 200，#remote-template 区为空；按页面默认地址 template=http://fixtures:8080/templates/season.php 时该区只渲染预期模板内容“<h2>合作方 · 秋日生活提案</h2><p>让生活慢下来，把好物带回家。</p>”，无系统文件或执行痕迹。；攻击侧 同一 operator 会话：template=/etc/passwd 时 #remote-template 区输出 root:x:0:0:root:/root:/bin/bash、daemon:x:1:1… 等系统账户行，证明可包含任意本地文件；template=data://text/plain;base64,<base64 of <?php echo 'XMARKRFI'.(6*7); ?>> 时输出 XMARKRFI42（“42”由包含的 PHP 代码求值产生，未出现在请求参数中），证明可包含远程/流并执行其中 PHP 代码，构成 RFI/RCE。

### C-04 account/backup.php 对用户备份 unserialize 后直接写入 tier，可自行升级金卡会员权益

- verification `4f8036e58fa04f2db14eefa4318f9f66`（finding `612f04ef75cc4f6a8e700e1a7e431e09` revision 1，context `3977e32cdf684ba5974aae3d08aa8f33`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice 登录后 GET /account/backup.php：status=200，表单含 csrf 字段，页面导出当前备份 base64（当时 tier 已因审计变为 gold）。提交合法结构的对照备份 tier=standard、displayName=alice：status=200，提示“会员备份已恢复”；随后 GET /account/index.php 显示 badge=standard、“普通会员：日常积分与会员活动”，即标准输入的恢复行为符合页面预期、未获得金卡。
  - 攻击侧观测：攻击侧：同一 alice 会话提交 base64('O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:5:"alice";}')，status=200 且页面提示“会员备份已恢复”；随后 GET /account/index.php 返回 badge=gold、member-benefit=“金卡会员：享受专属折扣与优先服务”。此前先提交 tier=standard 的对照备份，账户页显示 badge=standard、“普通会员：日常积分与会员活动”——两次提交流程相同，仅序列化对象内 tier 值不同，结果由客户端控制的 tier 决定；宿主审计作业 fdbb0380d7f84fadb02750cb011e07b2 也记录 pre/post tier 由 standard 变为 gold 的 state_changes。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`fdbb0380d7f84fadb02750cb011e07b2`；`4607a56b57f24e8eb3c410443e1f508d`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`4607a56b57f24e8eb3c410443e1f508d` script finished exit=0；`fdbb0380d7f84fadb02750cb011e07b2` script finished exit=0
  - 适配脚本：`4f8036e5-adapted-poc_backup_tier.py`（见证据包 evidence/）
  - 备注：证据引用 ev-b1d3f99468428281（作业 4607a56b57f24e8eb3c410443e1f508d stdout：backup 页 200 有 csrf，standard 对照后账户页 badge=standard/普通会员，gold 攻击后账户页 badge=gold/金卡会员）；ev-914c58748ce7d37d（宿主审计作业 fdbb0380d7f84fadb02750cb011e07b2 stdout：CONTROL/ATTACK 提交均 200，VERIFY 200 gold）。源码 account/backup.php 第 4 行 base64_decode($_POST['backup']) 后第 5 行直接 unserialize($raw)（无 allowed_classes 白名单），仅 instanceof MemberBackup 校验，第 6 行把 $restored->tier/$restored->displayName 写入 UPDATE users SET tier=?,display_name=?；src/backup.php MemberBackup 只有两个 public string 属性、无魔术方法，故此处是客户端可写业务字段（tier）而非 gadget RCE。account/index.php 第 3 行 …

- 正式复核 `1220a90f318441e48a9cab66a3bfcb3d`：复核确认；引用 revision 1 / verification `4f8036e58fa04f2db14eefa4318f9f66`
  - 理由：完整读取两侧观测：正常侧 alice 提交合法结构 tier=standard 的备份后提示“会员备份已恢复”，账户页显示 badge=standard、普通会员，说明正常恢复流程行为符合预期；攻击侧同一会话提交序列化 MemberBackup tier=gold，提示同样为恢复成功，随后账户页 badge=gold、金卡会员，作业 4607a56b57f24e8eb3c410443e1f508d 记录 tier standard→gold 的 state_drift。两组仅序列化对象内 tier 不同，结果表明服务端持久化了客户端控制的 tier，与 backup.php:4-6 无 allowed_classes/字段白名单的源码一致，确认该结论。
  - 复核观测：正常侧 alice 登录后 GET /account/backup.php：status=200，表单含 csrf 字段，页面导出当前备份 base64（当时 tier 已因审计变为 gold）。提交合法结构的对照备份 tier=standard、displayName=alice：status=200，提示“会员备份已恢复”；随后 GET /account/index.php 显示 badge=standard、“普通会员：日常积分与会员活动”，即标准输入的恢复行为符合页面预期、未获得金卡。；攻击侧 攻击侧：同一 alice 会话提交 base64('O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:5:"alice";}')，status=200 且页面提示“会员备份已恢复”；随后 GET /account/index.php 返回 badge=gold、member-benefit=“金卡会员：享受专属折扣与优先服务”。此前先提交 tier=standard 的对照备份，账户页显示 badge=standard、“普通会员：日常积分与会员活动”——两次提交流程相同，仅序列化对象内 tier 值不同，结果由客户端控制的 tier 决定；宿主审计作业 fdbb0380d7f84fadb02750cb011e07b2 也记录 pre/post tier 由 standard 变为 gold 的 state_…

### C-05 support/messages 留言内容未转义回显导致存储型 XSS

- verification `afac2901d61f495c95fb0299a58e2b77`（finding `4907961ff981463a817be4589ab79728` revision 1，context `6f093aa553fc472d9a7e733258fa2f1f`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：同一页面上的良性留言被当作纯文本显示：浏览器 body_text 包含“陈远 … 请问帆布包可以机洗吗？”与“林晓 … 包装很好，期待下次上新。”，均无弹窗；写入前 GET /support/messages.php 也不含攻击载荷（payload_already_present=False）。对照说明正常存储内容仅文本呈现，弹窗只由存储的 script 载荷产生。
  - 攻击侧观测：alice 经支持页表单提交 message=<script>alert("XSS_MARK_9f2")</script> 后，服务端存储并在后续 GET /support/messages.php 的原始 HTML 中输出 '<div class="message-body"><script>alert("XSS_MARK_9f2")</script></div>'（未转义）。随后 alice 会话的 Chromium 加载 /support/messages.php，记录到弹窗 "XSS_MARK_9f2"（dialogs 一项、console_errors 为空），证明存储的脚本在受害者浏览器真实执行。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`fbed87750da44d889f05902d3e7ffebe`；`3820a8fadcb3466998d9b79c185477c5`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`fbed87750da44d889f05902d3e7ffebe` script finished exit=0；`3820a8fadcb3466998d9b79c185477c5` browser finished exit=0
  - 产物：`afac2901d61f495c95fb0299a58e2b77-3820a8fadcb3466998d9b79c185477c5-screenshot.png`
  - 适配脚本：`afac2901-adapted-messages_xss_poc.py`（见证据包 evidence/）
  - 备注：阶段一作业 fbed87750da44d889f05902d3e7ffebe（alice）确认写入前页面不含载荷、POST 后原始 HTML 出现未转义的 script；阶段二作业 3820a8fadcb3466998d9b79c185477c5（alice 浏览器）记录到 dialogs=["XSS_MARK_9f2"]。仅用 HTML 反射不能证明执行，结论以浏览器弹窗为准。源码 applicability=match：messages.php:5 仅对 display_name/created_at 调用 h()，message 直接拼接输出；bootstrap.php:10 提供 h() 但此字段遗漏。

- 正式复核 `fe0052669ead4cde81f94f333d4b77fb`：复核确认；引用 revision 1 / verification `afac2901d61f495c95fb0299a58e2b77`
  - 理由：完整读取两侧观测：正常侧浏览器 body_text 中良性与本人留言均以纯文本呈现，无弹窗，写入前页面不含攻击载荷；攻击侧提交 <script>alert("XSS_MARK_9f2")</script> 后原始 HTML 中出现未转义的 <div class="message-body"><script>…</script></div>，同会话 Chromium 加载 /support/messages.php 记录到弹窗 "XSS_MARK_9f2" 且 console_errors 为空，browser_execution=true。与 messages.php:5 对 message 漏用 h() 的源码一致，确认存储型 XSS 成立。
  - 复核观测：正常侧 同一页面上的良性留言被当作纯文本显示：浏览器 body_text 包含“陈远 … 请问帆布包可以机洗吗？”与“林晓 … 包装很好，期待下次上新。”，均无弹窗；写入前 GET /support/messages.php 也不含攻击载荷（payload_already_present=False）。对照说明正常存储内容仅文本呈现，弹窗只由存储的 script 载荷产生。；攻击侧 alice 经支持页表单提交 message=<script>alert("XSS_MARK_9f2")</script> 后，服务端存储并在后续 GET /support/messages.php 的原始 HTML 中输出 '<div class="message-body"><script>alert("XSS_MARK_9f2")</script></div>'（未转义）。随后 alice 会话的 Chromium 加载 /support/messages.php，记录到弹窗 "XSS_MARK_9f2"（dialogs 一项、console_errors 为空），证明存储的脚本在受害者浏览器真实执行。

### C-06 catalog/greeting.php 的 name 参数未编码直接输出到 HTML 文本，导致反射型 XSS

- verification `4120c592946c4c548d36e66e4dd3877a`（finding `e601764eee0f47658ae43fd8fb51f742` revision 1，context `028125adce4a4e1cae901c19fbc616ff`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：Chromium（guest 会话）加载 /catalog/greeting.php?name=abc：标题“到店欢迎 · 拾光商城”，body_text 为“你好，abc”，dialogs 为空、console_errors 为空，说明正常输入仅被当作纯文本渲染。
  - 攻击侧观测：同一 Chromium 会话加载 /catalog/greeting.php?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E，页面返回标题“到店欢迎 · 拾光商城”，记录到 1 个弹窗且内容为 "1"（alert 实际执行）；同时 body_text 只剩“你好，”，说明 <script>alert(1)</script> 作为标签被解析而非当作文本显示。即 name 参数未编码直接进入 <h2> 文本上下文并在浏览器执行。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`5be8d02b06c24fe0b6fad5f419f514b7`；`6bf3c7ea2d0d4c0793eee56afbe65907`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`5be8d02b06c24fe0b6fad5f419f514b7` browser finished exit=0；`6bf3c7ea2d0d4c0793eee56afbe65907` browser finished exit=0
  - 产物：`4120c592946c4c548d36e66e4dd3877a-5be8d02b06c24fe0b6fad5f419f514b7-screenshot.png`；`4120c592946c4c548d36e66e4dd3877a-6bf3c7ea2d0d4c0793eee56afbe65907-screenshot.png`
  - 备注：对照作业均为 guest（未登录）浏览器作业：5be8d02b06c24fe0b6fad5f419f514b7 为正常侧，6bf3c7ea2d0d4c0793eee56afbe65907 为攻击侧，后者 dialogs=["1"]、console_errors=[]。源码 applicability=match：greeting.php:3 直接拼接 $name 到 '<h2>你好，'.$name.'</h2>' 且未调用 bootstrap.php:10 的 h()，而同页 form_input 会对 value 做 h()，与观测到的解析/执行行为一致。按规范，HTTP 反射本身不作为依据，本结论以浏览器弹窗为执行证据。

- 正式复核 `dc6685a93fe74f2aa6c90d5ba5bb523d`：复核确认；引用 revision 1 / verification `4120c592946c4c548d36e66e4dd3877a`
  - 理由：完整读取两侧观测：正常侧 guest 浏览器加载 /catalog/greeting.php?name=abc，body_text 为“你好，abc”，dialogs 与 console_errors 为空；攻击侧加载 name=%3Cscript%3Ealert(1)%3C%2Fscript%3E，记录到 1 个弹窗内容 "1"，body_text 在“你好，”后为空，表明 script 标签被解析执行而非文本化。与 greeting.php:2-3 未调用 h() 直接拼接输出的源码一致，确认反射型 XSS 成立。
  - 复核观测：正常侧 Chromium（guest 会话）加载 /catalog/greeting.php?name=abc：标题“到店欢迎 · 拾光商城”，body_text 为“你好，abc”，dialogs 为空、console_errors 为空，说明正常输入仅被当作纯文本渲染。；攻击侧 同一 Chromium 会话加载 /catalog/greeting.php?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E，页面返回标题“到店欢迎 · 拾光商城”，记录到 1 个弹窗且内容为 "1"（alert 实际执行）；同时 body_text 只剩“你好，”，说明 <script>alert(1)</script> 作为标签被解析而非当作文本显示。即 name 参数未编码直接进入 <h2> 文本上下文并在浏览器执行。

### C-07 login.php 接受 GET sid 且 strict_mode 关闭导致会话固定

- verification `170b82091ccf48b4831b9a390dc622c1`（finding `b7699087edaa49fca6629be5298d4218` revision 1，context `5bd368f98809496593d2d6ca1d45a423`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：匿名 GET /account/me.php 返回 401；不带 sid 的登录成功后 Cookie 为随机值 SHOPSESSID=ea3c5a5b6b550e33eb603572cbfe946f（不等于攻击者选定的 csfixedsid0123456789），该会话访问 /account/me.php 返回 200 与 alice 的 JSON。阴性对照：使用从未参与登录的 SHOPSESSID=csunusedsid0123456789 访问返回 401；在受害者登录之前用 SHOPSESSID=csfixedsid0123456789 访问同样返回 401，说明 200 只出现在该固定会话完成认证之后。
  - 攻击侧观测：攻击侧：受害者经 GET /auth/login.php?sid=csfixedsid0123456789 获得的 Set-Cookie 正是该预置值，POST 凭据后会话 jar 中 SHOPSESSID=csfixedsid0123456789，且服务器未更换 ID（无新的 Set-Cookie）；随后与受害者相互独立的客户端仅以 Cookie: SHOPSESSID=csfixedsid0123456789 请求 /account/me.php 返回 200 与 alice 完整身份 JSON。审计 POC 作业 689d5d96ee6e425fb65b7a189676713b 用另一随机固定 SID 亦得到相同结果（reuse fixed sid 返回 alice JSON），独立复现。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`689d5d96ee6e425fb65b7a189676713b`；`fb078ad87f9e4a44abcdffd8812abee9`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`fb078ad87f9e4a44abcdffd8812abee9` script finished exit=0；`689d5d96ee6e425fb65b7a189676713b` script finished exit=0
  - 适配脚本：`170b8209-adapted-session_fixation.php`（见证据包 evidence/）
  - 备注：主证据为作业 fb078ad87f9e4a44abcdffd8812abee9（alice，python）的单次 stdout，同时包含正常、两个阴性对照与攻击四组观测；作业 689d5d96ee6e425fb65b7a189676713b（PHP 审计 POC）作为另一 SID 的独立复现。源码 applicability=match：login.php:3 start_session($_GET['sid'])，bootstrap.php:13 use_strict_mode=0、:17 session_id($sid) 后 session_start()，login.php:8 仅写 user_id，无 session_regenerate_id。未使用特权身份，受影响会话仍为普通会员 alice。

### C-08 钱包提现为无锁读改写余额导致并发超额提现（竞态/重复支付）

- verification `2ea22374d2de49d3b92b57d122d73561`（finding `81dc9ba2b5764d7681cb0051685fe57b` revision 1，context `6c03e0a890a74caebbdc4c66d301b167`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：单次顺序提现的对照：wallet 基线 {"balance":"100.00","withdrawals":[],"withdrawn_total":0}；一次 POST /wallet/withdraw.php amount=1（合法 csrf）返回 {"status":"paid","amount":1,"balance":99,"receipt_id":1}，随后 wallet 为 balance=99.00、1 条记录、withdrawn_total=1，记录数与扣减金额一致（扣 1.00 记 1.00），说明正常路径下余额与流水保持平衡。
  - 攻击侧观测：在 alice 已认证的 6 个独立会话上，获取各自合法 csrf 后经线程屏障同时向 /wallet/withdraw.php 提交 amount=1。6 个请求全部 200 且返回 {"status":"paid",...}，receipt_id 为 2..7；每个响应中的 balance 都等于 98（都是从同一读到的余额 99 计算出的常量）。最终 /wallet/index.php 显示 balance=98.00、7 条 withdrawals 记录、withdrawn_total=7。即 7 笔提现被记为已支付，但余额只从 100.00 降到 98.00（仅扣减 2.00），多出的 5.00 未被扣减，属于超额提现/重复支付。宿主 postcondition 也记录 balance 100.00→98.00。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`a147ff9c2da0414eb8265ca9ade67438`；`39f1b8e0a64e4939a6e472fe0f153052`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`39f1b8e0a64e4939a6e472fe0f153052` script finished exit=0
  - 适配脚本：`2ea22374-adapted-poc_wallet_race.py`（见证据包 evidence/）
  - 备注：证据来自作业 39f1b8e0a64e4939a6e472fe0f153052 的单次 stdout，正常与攻击两阶段同脚本、同上下文、同一 alice 账号。审计原 POC（作业 a147ff9c2da0414eb8265ca9ade67438）因误在 JSON 响应中找 csrf 且工作线程未登录，仅得 403/401，未作为证据；本次改为 HTML 取 csrf、真正的已认证并发。源码 applicability=match：withdraw.php:3 session_write_close() 解除会话锁，:4 SELECT 余额、:6 usleep(350000)、:7 UPDATE balance=常量，与观测到的 6 个相同 balance=98 及仅一次扣减完全吻合。

### C-09 orders/detail.php 按请求 id 读取任意订单，未校验 user_id 归属导致 IDOR

- verification `4997cbfbf6104bf99fef6fb55b06c2f2`（finding `be7b150f8f9a4dd58b8e47b4678054fc` revision 1，context `e9e366ada78e4aeba60114177c356efb`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：登录为 alice（user_id=1）后请求 /orders/detail.php?id=1 返回 200，JSON 为本人订单 SG-1001（user_id=1、username "alice"、private_note "ALICE_PRIVATE_ORDER_delivery_morning"、total 129.00），页面/JSON 均属当前用户。
  - 攻击侧观测：同一 alice 会话请求 /orders/detail.php?id=2（Accept: application/json）返回 200 及属于 user_id=2（bob）的完整订单：order_no SG-1002、total 158.00、quantity 2、username "bob"、private_note "BOB_PRIVATE_ORDER_gift_for_family"。alice 自身 id=1，未做任何授权操作即跨用户读取了他人订单及配送备注，证明详情接口未校验归属。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`8e7b0bcf11ed4d30b56347ee4ae71ec2`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`8e7b0bcf11ed4d30b56347ee4ae71ec2` script finished exit=0
  - 适配脚本：`4997cbfb-adapted-idor_order_detail.py`（见证据包 evidence/）
  - 备注：作业 8e7b0bcf11ed4d30b56347ee4ae71ec2 在 alice 身份下同一次执行给出正常与攻击两侧；会话有效性由两次均返回订单 JSON（非 401）佐证。源码 applicability=match：orders/detail.php:2 仅 require_user()，查询条件只有 o.id=?，未绑定 user_id；对比 orders/index.php:2 明确 WHERE user_id=?，说明列表做了归属过滤而详情遗漏。private_note 与 username 均为详情页会渲染/JSON 返回的字段。

### C-10 运营主机巡检 host 参数未转义拼接进 shell_exec（命令注入 RCE）

- verification `395610502cf942dca52119a696a80d0d`（finding `56e24bf0d1424385ab81cee10812cd99` revision 1，context `34178520ba3442548ccc4165a4d50d58`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 登录后请求 /ops/batch-check.php?host=127.0.0.1 返回 200，<pre> 区仅显示 ping 的标准输出（1 packets transmitted, 1 received, 0% packet loss），无任何额外命令输出或标记；登录后 /account/me.php 确认为 operator 身份。
  - 攻击侧观测：同一 operator 会话将 host 改为 "127.0.0.1;echo INJX$((7*6))"，<pre> 区在 ping 统计后出现 INJX42（42 由 shell 求值，请求参数中并无 42）；再以 "127.0.0.1;id" 提交，输出出现 uid=33(www-data) gid=33(www-data) groups=33(www-data)。两次均 200，证明 /ops/batch-check.php 的 host 被拼接进 shell_exec 并以 Web 进程身份执行任意命令。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`f67515ecc268425c9c9f23262de6658c`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`f67515ecc268425c9c9f23262de6658c` script finished exit=0
  - 适配脚本：`39561050-adapted-poc_batch_check_cmd_injection.py`（见证据包 evidence/）
  - 备注：作业 f67515ecc268425c9c9f23262de6658c 在 operator（id=3, role=operator）下执行，符合 batch-check.php:2 require_user(['operator','admin']) 的入口前提，未用特权身份冒充普通会员结论。源码 applicability=match：batch-check.php:2 取 $_GET['host'] 后调用 host_check()，src/host_check.php:2 以 'ping -c 1 -W 1 '.$host 拼接并 shell_exec；页面回显 h($output) 仅做 HTML 转义，不影响注入。未观察到 CSRF 校验（GET 入口），与源码 :40 仅在 POST 流程使用的 check_csrf 一致。

### C-11 登录页接受 URL 参数 sid 作为会话 ID，存在会话固定

- verification `5c86fa32ae8449de85de4b6758e7eb8f`（finding `0be8523556144f559c4e0945954d27d8` revision 1，context `f2b1c4e918d546ecadaca7265b395063`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：不经过 sid 的常规路径：匿名 GET /account/me.php 返回 401；不带 sid 的登录成功后 Cookie 为随机值 SHOPSESSID=0e7e169b538ff98f85ec2aae83186c3c（不等于攻击者选定的 ID），该会话访问 /account/me.php 返回 alice 的 JSON。阴性对照：在受害者登录之前，单独用 Cookie SHOPSESSID=fixationsessionid12345 访问 /account/me.php 返回 401；使用从未参与登录的 SHOPSESSID=unusedsessionid00000 访问同样返回 401，说明 200 响应来自固定会话内被写入的认证状态，而非任意 Cookie 均可通过。
  - 攻击侧观测：受害者在带 sid 的登录入口（GET /auth/login.php?sid=fixationsessionid12345）拿到 Set-Cookie: SHOPSESSID=fixationsessionid12345，提交凭据后该会话成为 alice 的已认证会话。随后与受害者相互独立的客户端（无凭据、无登录流程）仅以 Cookie: SHOPSESSID=fixationsessionid12345 请求 /account/me.php，返回 200 与 alice 完整 JSON（id=1, username=alice, role=customer），说明会话 ID 完全由外部预先决定并被认证写入。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`5713e2ecadc4493e92b0d9ae30de2ec7`；`96828c3f1aae4edda245f45448fe3fbc`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`96828c3f1aae4edda245f45448fe3fbc` script finished exit=0
  - 适配脚本：`5c86fa32-adapted-poc_session_fixation.py`（见证据包 evidence/）
  - 备注：作业 96828c3f1aae4edda245f45448fe3fbc 一次执行同时给出正常、对照与攻击三组观测；先前的 5713e2ecadc4493e92b0d9ae30de2ec7 因未捕获 401 提前退出，无可用输出，未作为证据。源码 applicability=match：login.php:3 start_session($_GET['sid'])，bootstrap.php:13 use_strict_mode=0、:17 session_id($sid) 后 session_start()，login.php:8 仅写 user_id 未 session_regenerate_id()。受影响的固定会话仍指向 alice（role 未变），未做任何写操作。

### C-12 orders/create.php 订单单价取自请求参数 price，可按任意低价下单

- verification `74dfa5e1e3b448d2904882f3830ed4cb`（finding `21c96a05f27f4dd8b3bd9cf51bfccf08` revision 1，context `ecee72b3dad041b4bf149a8a0d10d359`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：/catalog/detail.php?id=1 展示单价 129.00；以 price=129.00、quantity=1 下单返回 303 到 /orders/detail.php?id=3，详情为 unit_price 129.00、total 129.00、商品“晨光手冲壶”、user_id=1，与商品标价一致，说明正常流程下服务端记录的是展示价格。
  - 攻击侧观测：同一 alice 会话对同一商品（product_id=1，quantity=1）提交 price=0.01，携带有效 csrf 后 /orders/create.php 返回 303 Location=/orders/detail.php?id=4，订单创建成功；详情返回 {"id":4,...,"unit_price":"0.01","total":"0.01",...,"name":"晨光手冲壶"}。即订单单价/实付完全采用请求参数，未使用商品真实价 129.00。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`506a1e002af148388b9df79bd11b45c8`；`6223f7df733c4dcdbc4e189d67f9d814`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`6223f7df733c4dcdbc4e189d67f9d814` script finished exit=0
  - 适配脚本：`74dfa5e1-adapted-price_tamper.py`（见证据包 evidence/）
  - 备注：作业 6223f7df733c4dcdbc4e189d67f9d814 在 alice 身份下完成正常/攻击对照；商品真实价 129.00 取自 /catalog/detail.php?id=1 页面展示值。审计原 POC（作业 506a1e002af148388b9df79bd11b45c8）因从 catalog 与 GET create.php 取 csrf 失败（405），未采用。源码 applicability=match：orders/create.php:3 从 $_POST['price'] 取价、:5 以 $price*$quantity 计算 total、:7 写入 unit_price/total；$p 仅用于库存与 product_id，商品真实价格从未参与。库存扣减未在本作业单独测量，结论仅聚焦以任意低价成功落单。

### C-13 continue.php 直接使用 GET next 作为跳转地址，存在开放重定向

- verification `9aaaae7782954fa09bf9ffcf46ff8b03`（finding `4280b2b06e4b474c88e7955305676084` revision 1，context `d8e3e2a536b049a8b30365387dfa18ed`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice 登录后 GET /auth/continue.php（无 next）：/orders/index.php 会话确认 200；页面返回 200，无 Location 头，含 name="next" 表单输入且默认值为 /orders/index.php。GET /auth/continue.php?next=%2Forders%2Findex.php：返回 302，Location=/orders/index.php，即正常站内相对跳转。
  - 攻击侧观测：同一 alice 会话请求 /auth/continue.php?next=https%3A%2F%2Fevil.example%2Fpoc-landing：status=302，Location 恰为 https://evil.example/poc-landing（matches=True）；再请求 next=//evil.example/second：status=302，Location=//evil.example/second。两者均无任何同源或白名单拦截，浏览器会跳转到外站。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`b4c3b39ac775457ea9d1b3be905c1d96`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`b4c3b39ac775457ea9d1b3be905c1d96` script finished exit=0
  - 适配脚本：`9aaaae77-adapted-poc.php`（见证据包 evidence/）
  - 备注：证据引用 ev-548b7e0e2c1c8cd1（作业 b4c3b39ac775457ea9d1b3be905c1d96 stdout，identity alice，precondition ok）。源码 continue.php 第 2 行 require_user() 仅做登录校验，第 3 行 isset($_GET['next']) 后直接 header('Location: '.(string)$_GET['next'])，第 4 行正常页面的表单默认值即为 /orders/index.php，与正常侧观测一致；bootstrap.php 第 33-36 行 require_user 只检查会话与角色，不涉及跳转目标校验。结论为已登录用户可被诱导跳转到任意外域（开放重定向），跨站钓鱼/凭据窃取前提是诱导用户点击带 next 的链接。

### C-14 account/update.php 批量赋值允许普通用户自改 role 与 balance

- verification `a728d34fc00040b4a3d47cb409a0daf1`（finding `caa2109f7d1440e784380f3b601fc168` revision 1，context `4331469eaddb4041ad47c75762c31f47`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：攻击前 /account/me.php 返回 alice 自身资料：role=customer、balance=100.00、tier=standard；页面表单仅渲染 display_name、nickname、email、homepage 四个字段（表单 value 仍为原值），服务端页面未展示 role/balance/tier 输入项，说明正常资料维护路径不涉及敏感列。
  - 攻击侧观测：alice 携带有效 csrf 提交 role=admin（请求中不含表单渲染的任何资料字段）后，/account/update.php 返回 200 与“资料已保存。”，且同一响应页面的侧边导航中出现了仅 operator/admin 可见的“运营工作台”（bootstrap.php:53 依据 $u['role'] 决定是否显示），说明字段已在同一请求内写入并生效。宿主 postcondition 独立记录 state_changes：role customer→admin（reason=identity_or_role_mismatch），确认数据库中的角色被提升为 admin。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`27edc20282fe4deeb5f0df023d575566`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`27edc20282fe4deeb5f0df023d575566` script finished exit=0
  - 适配脚本：`a728d34f-adapted-mass_assign_update.php`（见证据包 evidence/）
  - 备注：作业 27edc20282fe4deeb5f0df023d575566（PHP，alice）为宿主执行的原始 POC，exit_code=0 且 evidence_usable；其 postcondition 由宿主持久化核对得出 role customer→admin，作为服务端写入生效的独立佐证。源码 applicability=match：update.php:4 白名单含 role/balance/tier，:5 遍历 $_POST 拼接 SET，:6 执行 UPDATE。本轮仅提交 role=admin，未在本次上下文单独测量 balance/tier 改动；它们与 role 走完全相同的白名单与循环，源码层面同源。

### C-15 content/page.php 的 page 参数未经白名单直接拼接进 include 路径，导致本地文件包含

- verification `795f5e0b4a0543efb4e1e8228cbd9ac8`（finding `90a5c284ff9c4d80a6d1d7e01b5ac086` revision 1，context `5f1273741da04c17a017a2c197a1bbf9`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：guest 访问 /content/page.php?page=home：status=200，长度 1381，正文在内容中心标题后正常渲染 resources/views/home.php 的“为日常，选一点喜欢的东西”面板，再渲染 ?page=home / ?page=shipping 链接与 footer；page=shipping：200，长度 1330，渲染“配送与售后”面板。两者说明正常路径只包含 resources/views 下存在的视图文件，页面完整。
  - 攻击侧观测：同一 guest 会话请求 /content/page.php?page=../../src/bootstrap（解析为 APP_ROOT/src/bootstrap.php，位于 views 目录之外）：响应在 include 处中止——正文恰好在 <h1>内容中心</h1></div> 结束，没有后面的站内链接 section 与 footer；独立 http_observe 作业 1d53125495b2494c94c748e06163d8b3 得到相同截断正文（body 通道 1052 字符，止于同一位置）。对照 page=../../src/nonexistent_zz 与 page=../../../etc/passwd（不存在或非 .php）时 include 静默失败，页面继续渲染链接与 footer（1242 字节），说明截断只能由“目标文件被打开并执行”引起；bootstrap.php 第 3-4 行在重复包含时会触发常量/函数重定义致命错误，故渲染在此终止。攻击侧证明 page 参数穿越到 views 之外并执行了服务器端 PHP 文件。
  - 已保存作业事实：3 个；满足执行及前提检查的作业：3 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`2c32133ab1824d798ec1645bafaf6c34`；`b8bc19b535ee43f28d9a57027a5d8088`；`1d53125495b2494c94c748e06163d8b3`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`b8bc19b535ee43f28d9a57027a5d8088` script finished exit=0；`1d53125495b2494c94c748e06163d8b3` http finished exit=0；`2c32133ab1824d798ec1645bafaf6c34` script finished exit=0
  - 适配脚本：`795f5e0b-adapted-lfi_page_poc.py`（见证据包 evidence/）
  - 备注：证据引用：ev-968d9d2b3b76473d（作业 b8bc19b535ee43f28d9a57027a5d8088 stdout，含 home/shipping 正常页与 bootstrap/nonexistent/etc-passwd 对照的原始输出与长度）、ev-3d50166bf9fc209b（http 作业 1d53125495b2494c94c748e06163d8b3 的响应正文，止于 <h1>内容中心</h1></div>）、ev-c23874de1ed87d76（同作业响应头 content-type: text/html）。宿主先行作业 2c32133ab1824d798ec1645bafaf6c34 的 ev-ede57dbcab83809e 也显示 home 1381 / ../../src/bootstrap 1052 的长度差。源码 page.php 第 2 行 $name=(string)($_GET['page']??'home')，第 3 行 include APP_ROOT.'/resources/views/'.$name.'.php'，无白名单/basename/规范化。限制：本环境 display_errors 关闭，未观察到错误文本或目标文件内容回显，因此“任意文件读取/源码泄露”未被直接证明；已证明的是 out-of-views 的…

### C-16 support/download.php 的 file 参数未做路径校验，登录用户可遍历读取 data_dir 下任意文件（含 sessions）

- verification `425fed5d5e0040d88d95e771f115a980`（finding `b60484437bb84f9da1529d79ec5b122a` revision 1，context `c649572522494f9b9ec3d8adaaa4d054`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice 登录后（/orders/index.php 200）：GET /support/download.php?file=shipping.txt → 200，Content-Type text/plain，正文 '配送说明：工作日 48 小时内发货。'；file=returns.txt → 200 '售后说明：签收后七天内可申请退货。'；file=no_such_doc.txt → 404，正文为“文档不存在。”错误页。即正常仅能读取 data_dir/docs 下已存在文档，缺失文档被拒绝。
  - 攻击侧观测：同一 alice 会话 GET /support/download.php?file=../vault/internal.txt：status=200，text/plain，正文 'SHOP_INTERNAL_21f480e7a6167dfa9374a373'——该标记由 setup.php 生成并写入 data_dir/vault/internal.txt，从未在网页出现，证明读到了 docs 目录之外的文件。file=../vault/account.php 返回其 PHP 源码 '<?php echo "SHOP_INTERNAL_21f480e7a6167dfa9374a373";'（源码泄露）；file=../messages/readme.txt 返回 '客服文件区'；file=../sessions/sess_<当前sid> 返回 'user_id&#124;i:1;'，即会话存储目录文件。对照 file=no_such_doc.txt 仍为 404。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`81dfb1325d7a48768cee6b448f3d608d`；`acb5a93a99e448f284c414624411042a`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`acb5a93a99e448f284c414624411042a` script finished exit=0；`81dfb1325d7a48768cee6b448f3d608d` script finished exit=0
  - 适配脚本：`425fed5d-adapted-path_traversal_download.py`（见证据包 evidence/）
  - 备注：证据引用 ev-689c12abd20fa737（作业 acb5a93a99e448f284c414624411042a stdout）。正常侧 file=shipping.txt 200 '配送说明：工作日 48 小时内发货。'、returns.txt 200；对照 file=no_such_doc.txt 404，说明 is_file 检查仍在；攻击侧 ../vault/internal.txt、../vault/account.php、../messages/readme.txt、../sessions/sess_<sid> 均 200 并返回 docs 目录外内容。宿主审计作业 81dfb1325d7a48768cee6b448f3d608d（ev-e375a7bb497d0b69）的 file=../../VERSION 404 是因为该路径解析为 /var/lib/VERSION（不存在），并非遍历被拦截；在其基础上改用 data_dir 内 ../vault 与 ../sessions 目标才得到判别结果。源码 download.php 第 2 行 require_user() 仅要求登录，第 3 行 $path=data_dir().'/docs/'.$file，仅 is_file 判断后 file_get_contents 并 echo，无 basename/re…

### C-17 account/settings.php 邮箱更新缺少 CSRF 校验，可跨站改写绑定邮箱

- verification `e02edaf82f2f40fb96dabf07be468450`（finding `192169b676e44fbcaf428676c0233436` revision 1，context `de1b8c702b8c45e9a565b760cca7ca5d`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：GET /account/settings.php（alice 已登录，/account/me.php 200 确认身份）：SETTINGS page status=200，csrf_field_present=False；表单原文为 <form method="post"><label>常用邮箱<input name="email" type="email" value="attacker@example.org" required></label><button>保存邮箱</button></form>，只有 email 一个输入，没有任何隐藏 csrf 字段。
  - 攻击侧观测：同一 alice 会话（未重新登录、未携带任何 csrf 参数）直接 POST email=csrf_probe@lab.local：status=200，响应体 {"email":"csrf_probe@lab.local","updated":true}；随后 GET /account/me.php 显示 "email":"csrf_probe@lab.local"，证明写入生效。为恢复现场再次无 token POST email=alice@shop.local：status=200 {"email":"alice@shop.local","updated":true}，me.php 确认 email 恢复为 alice@shop.local。审计作业 ddbc3850940c4f718a7dfc30f01b6a28 在同上下文也已用无 token POST 把 email 改为 attacker@example.org，独立复现同一行为。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`ddbc3850940c4f718a7dfc30f01b6a28`；`50d44ddda68747dbbc5c619fe345051b`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`50d44ddda68747dbbc5c619fe345051b` script finished exit=0；`ddbc3850940c4f718a7dfc30f01b6a28` script finished exit=0
  - 适配脚本：`e02edaf8-adapted-csrf_settings_email.py`（见证据包 evidence/）
  - 备注：证据引用：ev-3ca6e852fc68cba5（作业 ddbc3850940c4f718a7dfc30f01b6a28 stdout，无 token POST 返回 {"email":"attacker@example.org","updated":true}）；ev-178adad6a661da69（作业 50d44ddda68747dbbc5c619fe345051b stdout，csrf_field_present=False、两次无 token POST 与 me.php 前后对照）。源码快照 account/settings.php：第 3 行判断 POST，第 4 行仅做邮箱格式校验，第 5 行 prepared UPDATE users SET email=? WHERE id=? 后 event_log，全程没有 check_csrf()；第 8 行表单仅 form_input('email',...)，无 csrf_field()。限制：SameSite=Lax 使跨站 POST 通常不携带会话 Cookie，故跨站实际可利用性受浏览器策略约束，本结论确定的是服务端缺少 CSRF 校验且无 token 请求即可改写邮箱。

### C-18 运营网络诊断 host 参数未转义拼接进 shell_exec（命令注入 RCE）

- verification `44be6903ba364aaaa79ce14526327b3e`（finding `a43f7873a81749b48f256ab0fc41c778` revision 1，context `a423ea840daa4a05be974d6f84500082`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 登录后请求 /ops/ping.php?host=127.0.0.1 返回 200，诊断区仅显示 ping 的标准输出（PING 127.0.0.1 ... 1 packets transmitted, 1 received, 0% packet loss），没有任何额外命令输出或标记。
  - 攻击侧观测：同一 operator 会话将 host 改为 "127.0.0.1;echo INJMARK$((6*7))" 后，诊断输出在 ping 结果之后出现 INJMARK42——"42" 由 shell 求值产生，不出现在输入中；再以 "127.0.0.1;id" 提交，输出出现 uid=33(www-data) gid=33(www-data) groups=33(www-data)。两条请求均 200，证明 host 被拼接进 shell_exec 并以 Web 服务器身份执行任意命令。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`b3e76e9e070b41fd89ac94f88c84c735`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`b3e76e9e070b41fd89ac94f88c84c735` script finished exit=0
  - 适配脚本：`44be6903-adapted-poc.php`（见证据包 evidence/）
  - 备注：作业 b3e76e9e070b41fd89ac94f88c84c735 在 operator（id=3, role=operator）下执行，身份与源码 ops/ping.php:2 require_user(['operator','admin']) 的入口前提一致，未用特权身份冒充普通会员结论。正常侧仅得到 ping 统计，不含任何命令输出。源码 applicability=match：ping.php:2 直接拼接 $host 到 'ping -c 1 -W 1 '.$host 并 shell_exec，无 escapeshellarg；回显处 h($output) 只做 HTML 转义，不影响命令执行。

### C-19 ops/users.php 信任客户端 $_COOKIE['role'] 绕过管理员鉴权

- verification `fdd313376f5548439516baf94152cbc1`（finding `d150482ca592418eb7a1f15fa9732730` revision 1，context `b778678283934b168a9da9cfc1e95662`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：对照：alice 登录后仅携带自身会话 Cookie（SHOPSESSID）请求 /ops/users.php 返回 403 {"error":"人员管理需要管理员权限。"}；附加 Cookie role=user 时同样 403。两者均未返回任何用户清单，说明正常会员身份无法访问该接口。
  - 攻击侧观测：同一 alice 会话（服务端角色 customer）在请求头附加 Cookie: role=admin 后访问 /ops/users.php（Accept: application/json）返回 200：{"access":"admin","users":[{"id":1,"username":"alice",...,"role":"customer"},{"id":2,...bob...},{"id":3,...operator...},{"id":4,"username":"admin","email":"admin@shop.local","role":"admin"}]}，即普通会员仅凭客户端 cookie 读取了全部账户权限清单（含管理员邮箱与角色）。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`e1e78da8db554d4291b3c4d04bd958fe`；`e50767d718a142d9b8c8a2f0a14122b8`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`e50767d718a142d9b8c8a2f0a14122b8` script finished exit=0
  - 适配脚本：`fdd31337-adapted-ops_role_cookie_poc.py`（见证据包 evidence/）
  - 备注：作业 e50767d718a142d9b8c8a2f0a14122b8 在 alice（id=1, role=customer）下完成对照；登录凭据来自 LAB30_USER/PASSWORD，Cookie 通过同一会话的 SHOPSESSID 加 role 值构造，未使用管理员身份。审计原 POC（e1e78da8db554d4291b3c4d04bd958fe）因登录页无 csrf 字段提前失败，未采用。源码 applicability=match：ops/users.php:2 用 $_COOKIE['role'] 覆盖 $u['role'] 并仅做字符串比较；对比 ops/index.php:2 与 bootstrap.php:33-36 的服务端角色校验。

### C-20 ops/members.php 会员查询参数经 member_lookup 拼接进 SQL 造成 SQL 注入

- verification `1f43a1c5b6de46ae97ab1986a4d3299e`（finding `36d7493a350d4e4eb864aa54056d018b` revision 1，context `5d728eb3b713417291cfdefceb590854`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：operator 请求 q=alice 返回 200，members 仅 [{"id":1,"username":"alice","email":"alice@shop.local","role":"customer"}]；q=zzz_no_such_user 返回 200 且 members 为空数组。两者都只按用户名匹配返回结果，未出现非库内合成行。
  - 攻击侧观测：同一 operator 会话请求 /ops/members.php?q=%' UNION SELECT 1,CONCAT('XMARK',6*7),'x@x','inj'-- -（Accept json）返回 200，members 除 4 个真实账户（alice/bob/operator/admin，含 admin@shop.local、role=admin）外，还出现由数据库求值生成的合成行 {"id":1,"username":"XMARK42","email":"x@x","role":"inj"}——XMARK42 中的 42 由 CONCAT(...,6*7) 计算，请求参数中并不存在，证明 q 被拼接进 SQL 并执行 UNION。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`bfb5ce22217d48caa65204f380414e94`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`bfb5ce22217d48caa65204f380414e94` script finished exit=0
  - 适配脚本：`1f43a1c5-adapted-poc.php`（见证据包 evidence/）
  - 备注：作业 bfb5ce22217d48caa65204f380414e94 在 operator（id=3, role=operator）下执行，符合 members.php:2 require_user(['operator','admin']) 的入口前提。源码 applicability=match：member_lookup.php:3 以 "SELECT id,username,email,role FROM users WHERE username LIKE '%".$term."%'" 字符串拼接后 db()->query；bootstrap.php:6 的 PDO 设置只对占位符生效，此处未使用 prepare。结论仅基于 UNION 求值行与真实行差异，未引用任何密码哈希。

### C-21 catalog 搜索参数 q 直接拼接进 SQL LIKE 查询导致反射型 SQL 注入

- verification `15c43b2a41b448d4bf4c692a7ea66827`（finding `a8c11d900cdd412581e02828cea4b299` revision 1，context `75a17369aaa24d8e821514794b6e6707`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常路径：GET /catalog/index.php 无搜索参数返回 200、result-count=4（4 件商品列表）；GET /catalog/index.php?q=a 返回 200、result-count=0，页面正常渲染搜索框；两者均为商品页，不含 users 表数据。
  - 攻击侧观测：未认证请求 /catalog/index.php?q=%' UNION SELECT 1,username,role,1,1,'x' FROM users-- - 返回 200，result-count 由正常搜索的 0/4 变为 8，页面额外渲染出 users 表行：<h2>alice</h2><p>customer</p>（name=username、description=role），说明注入点闭合了 LIKE 字面量并成功 UNION 读取 users 表。另一条 %' UNION SELECT 1,username,password_md5,1,1,'x' FROM users-- - 同样返回 200、count=8，表明任意 6 字段列均可被抽取（此处未引用哈希内容）。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`2b525cfa0a3f482b87e930761cb3a489`；`c4af891a21cf4f9e8bc59c32f4a74c48`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`c4af891a21cf4f9e8bc59c32f4a74c48` script finished exit=0
  - 适配脚本：`15c43b2a-adapted-sqli_catalog_index.py`（见证据包 evidence/）
  - 备注：作业 c4af891a21cf4f9e8bc59c32f4a74c48 以 guest（无需登录）执行，正常与攻击观测在同一脚本。说明：审计 POC 用的 password 列不存在，导致 503（作业 2b525cfa0a3f482b87e930761cb3a489，未采用）；本实验改用真实列名并补做列数匹配。另需注意 ' OR 1=2-- - 仍返回 4，是因为前缀 name LIKE '%' 恒真，故该 OR 对照不具判别力，结论只基于 UNION 抽取结果，未据此推断。源码 applicability=match：catalog/index.php:3 (string) 取值、:4 直接拼接进 db()->query()，bootstrap.php:6 的 PDO 属性只对占位符生效。

### C-22 ops/jobs.php 对 POST job 直接 unserialize，DispatchJob::__wakeup 触发 shell_exec 命令执行

- verification `46372aed8c0d4cc684dba5fd03b40276`（finding `311b523024ac4f2e91f79a9cb320a7aa` revision 1，context `539d33b4117f4e34bdf52aa3d4740439`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 身份登录后 GET /ops/jobs.php：status=200，页面含“导入任务”表单和 csrf 隐藏字段；textarea 预填示例 base64 解码为 O:11:"DispatchJob":1:{s:7:"command";s:22:"printf inventory-ready";}。原样提交（带 csrf）返回 status=200，<pre> 输出 'inventory-ready'，即默认 command 的正常执行结果。
  - 攻击侧观测：同一 operator 会话提交攻击载荷 base64(O:11:"DispatchJob":1:{s:7:"command";s:25:"echo JOBS_RCE_MARK_42; id";})：status=200，<pre> 输出 'JOBS_RCE_MARK_42\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n' —— command 可控并在 unserialize 阶段执行，返回命令真实输出。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`4d5c84ab84ba43c89e24ed96a390f14d`；`70595b9339f74498b43142a4a3228996`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`70595b9339f74498b43142a4a3228996` script finished exit=0
  - 适配脚本：`46372aed-adapted-jobs_deserialize_rce.py`（见证据包 evidence/）
  - 备注：证据引用 ev-c94b1ae4bc000fa8（作业 70595b9339f74498b43142a4a3228996 stdout）：operator 登录后 /ops/jobs.php 200 并含表单与 csrf；正常示例（textarea 默认值 base64 'O:11:"DispatchJob":1:{s:7:"command";s:22:"printf inventory-ready";}'）提交后 <pre> 输出 'inventory-ready'；攻击载荷提交后 <pre> 输出 'JOBS_RCE_MARK_42' 与 'uid=33(www-data) gid=33(www-data)'；无效 base64 对照返回 400 且无 <pre>，说明差异由反序列化对象内的 command 引起。源码 jobs.php 第 3 行 base64_decode 后直接 unserialize（instanceof 校验在其后），dispatch_job.php 第 4 行 __wakeup 中 shell_exec($this->command)，command 为 public 属性，与观测一致。宿主先行审计作业 4d5c84ab84ba43c89e24ed96a390f14d 因登录页无 csrf 字段在登录处失败（exit 1，未产生可用证据），本结论基于…

### C-23 ops/template-render.php 将 POST 模板双花括号内容直接拼接进 eval（代码执行）

- verification `87f86b0925c7472f983ee5742445d033`（finding `d4fc477cfe8c4e90b2af4078847ac915` revision 1，context `51097fc9d5824559aa002b52966dc2cc`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 正常提交默认类模板 {{ 2 + 2 }}，/ops/template-render.php 返回 200，<pre> 为 4，仅执行算术表达式，没有命令输出或系统信息。
  - 攻击侧观测：同一 operator 会话携带页面真实 csrf：template={{ 'XM'.(6*7) }} 的 <pre> 返回 XM42（42 由 eval 求值产生），template={{ system('id') }} 的响应正文开头及 <pre> 均出现 uid=33(www-data) gid=33(www-data) groups=33(www-data)。两次均 200，证明花括号内内容被拼进 eval('return ...;') 后以 Web 进程权限执行任意 PHP 表达式/系统命令。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`046e5e888c964b04a5f396eabda01f0a`；`82ee10ceae934e0985280150d84b1341`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`82ee10ceae934e0985280150d84b1341` script finished exit=0
  - 适配脚本：`87f86b09-adapted-template_eval_poc.py`（见证据包 evidence/）
  - 备注：作业 82ee10ceae934e0985280150d84b1341 在 operator（id=3, role=operator）下执行，符合 template-render.php:2 require_user(['operator','admin']) 的入口前提；审计 POC 作业 046e5e888c964b04a5f396eabda01f0a 以 alice 运行被 403 拒绝（未采用其数据，仅佐证角色门禁存在）。源码 applicability=match：template-render.php:3 preg_replace_callback('/\{\{(.*?)\}\}/s', ... eval('return '.$m[1].';'))，仅 check_csrf 校验令牌，无表达式过滤；pre 处 h($result) 只做 HTML 转义。

### C-24 ops/report.php 用 nickname 字符串拼接 query 的二阶 SQL 注入

- verification `87ac020d13914e3c90945cbf16f37c88`（finding `b916387c142d4a35a759e43c51bfc611` revision 1，context `04c1a7ba0caf4614b0dd62a244c94992`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：良性数据对照：operator 请求 /ops/report.php?user_id=2 得 saved_nickname='bob'、members 仅 [{"username":"bob","email":"bob@shop.local","role":"customer"}]；user_id=3 得 saved_nickname='operator'、members 仅 operator 一行。两例均只返回昵称完全匹配的单个用户，未出现全表读取。
  - 攻击侧观测：alice 的 nickname 被改为 "' OR '1'='1" 后，operator 访问 /ops/report.php?user_id=1（Accept: application/json）返回 saved_nickname="' OR '1'='1"，members 变为 4 条：alice、bob、operator、admin（含 admin@shop.local 与 role=admin）。同一请求的 SQL 条件本应为 nickname='<值>'，实际被闭合为 nickname='' OR '1'='1，从而返回全表，证明存储的 nickname 被二次拼接执行。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`2ff2f0996a7b4d9b85764ab7b1796362`；`ef334acb61fd423a8a0a4edc0200b448`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`2ff2f0996a7b4d9b85764ab7b1796362` script finished exit=0；`ef334acb61fd423a8a0a4edc0200b448` script finished exit=0
  - 适配脚本：`87ac020d-adapted-poc.php`（见证据包 evidence/）
  - 备注：两阶段作业：2ff2f0996a7b4d9b85764ab7b1796362（alice）通过合法账户资料表单写入 nickname 载荷，宿主记录 state_changes nickname alice→"' OR '1'='1"；ef334acb61fd423a8a0a4edc0200b448（operator）读取报表。operator 是 report.php:2 要求的 operator/admin 角色入口，未用于冒充普通会员。源码 applicability=match：report.php:2 参数化取 nickname，:3 以 WHERE nickname='".$nickname."' 拼接后 db()->query 执行，与良性/恶意 nickname 的结果差异一致。

### C-25 资料维护接口批量赋值允许普通用户自改 role/balance/tier 提权

- verification `4ee6c93d2d3742298e145935dfce9ee4`（finding `b159a64c79e545e88e66862ee93c64c7` revision 1，context `fff55afeb42d422a9f8a445fc00fb1b6`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：攻击前 GET /account/me.php 返回 {"id":1,"username":"alice",...,"role":"customer","balance":"100.00","tier":"standard",...}；页面表单只提供 display_name/nickname/email/homepage 四个字段，说明合法资料维护路径不涉及 role/balance。攻击 POST 返回 200 且页面呈现"资料已保存。"，与正常保存的响应形式一致，未出现 403 拒绝。
  - 攻击侧观测：携带真实 csrf 提交 csrf=<token>&role=admin&balance=999999 后，同一脚本再次 GET /account/me.php 返回 "role":"admin","balance":"999999.00"，即敏感列被写入。作业 postcondition 记录 alice 状态变化 balance 100.00→999999.00、role customer→admin，reason=identity_or_role_mismatch（宿主侧独立核实角色已改变）。响应体中 /ops/index.php 导航项也随之出现（bootstrap.php 第53行依据 role∈{operator,admin} 显示运营工作台），进一步说明提权真实生效。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`04c21d3cdf41425997dcea72b59c5b34`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`04c21d3cdf41425997dcea72b59c5b34` script finished exit=0
  - 适配脚本：`4ee6c93d-adapted-poc_mass_assignment.py`（见证据包 evidence/）
  - 备注：单一作业 04c21d3cdf41425997dcea72b59c5b34 的 stdout 同时包含正常侧基线（control me）与攻击侧结果（after），并与宿主 state_changes/postcondition 吻合。源码快照 applicability=match：update.php:4 白名单含 role/balance/tier，:5-6 直接拼接执行 UPDATE users；bootstrap.php:33-36 require_user 不带角色限制即返回当前用户。role=admin 的持久化改变会污染后续 alice 会话，本轮不再追加实验。

### C-26 登录页以 GET sid 设置会话 ID 且登录后不轮换，构成会话固定

- verification `3ec2b903eaab4afaa9e6250e2ff49749`（finding `8ee0b33f919c4f20b10c9ee7992796f4` revision 1，context `9e99aa53686643c58253c71973182457`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧对照（同一作业）：未参与登录的会话 SID 请求 /account/me.php 得到 401 {"error":"请先登录后使用此功能。"}，证明未认证会话不能访问会员接口；正常登录页 GET（不带 sid）返回 200 登录表单。差异仅在于 sid 是否由客户端预置：预置后同一机制即产生已认证会话，说明问题出在 ID 接受与不轮换，而非正常登录本身。
  - 攻击侧观测：当前上下文作业 77e9b7883386431d8d220a67280a4a30（身份 alice）复现：① GET /auth/login.php?sid=fixedsid5f4e3d2c1b0a9988 返回 200，Set-Cookie 直接下发攻击者指定的 SHOPSESSID=fixedsid5f4e3d2c1b0a9988（未由服务端生成）；② 登录前 /account/me.php 对该 SID 返回 401；③ alice 携带该 SID POST 登录得 302 Location: / 且 Set-Cookie 仍是同一 SID（登录后未轮换）；④ 之后 /account/me.php 返回 200 {"id":1,"username":"alice",...,"balance":"100.00"}；⑤ 以同一 SID、无任何凭据的独立请求同样返回 200 完整账户数据；⑥ 对照：从未用于登录的 SID 返回 401。说明攻击者预置的会话 ID 在受害者登录后被认证且可被攻击者复用。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`77e9b7883386431d8d220a67280a4a30`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`77e9b7883386431d8d220a67280a4a30` script finished exit=0
  - 适配脚本：`3ec2b903-adapted-poc.php`（见证据包 evidence/）
  - 备注：证据引用 ev-8ea07d041c86d3c3（作业 77e9b7883386431d8d220a67280a4a30 stdout，步骤 1-6）。源码 login.php 第 3 行 start_session(isset($_GET['sid'])?(string)$_GET['sid']:null)、第 8 行 $_SESSION['user_id']=(int)$row['id']、第 9 行 Location: / 后 exit，无 session_regenerate_id；bootstrap.php 第 13 行 ini_set('session.use_strict_mode','0')、第 17 行正则通过即 session_id($sid)、第 18 行 session_start。运行结果与源码一致：GET sid 被接受并下发，登录前后 SID 相同，跨请求复用可读取受害者账户。前提为攻击者能投递带已知 sid 的登录链接且受害者在该页登录——已通过真实凭据登录模拟；不涉及特权身份。

### C-27 ops/formula.php 通过 GET func 变量函数调用任意 PHP 函数（code_execution）

- verification `3dcaf580e6704212b2744562d30cc928`（finding `07fe40ddf2114282bdfd729f8a856379` revision 1，context `6f3355aa306a4ceda64497e1b1c1a691`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 正常使用页面默认能力 func=strtoupper&arg=spring-sale，返回 200 且 <pre> 显示 'SPRING-SALE'，即仅执行字符串大写转换，无命令输出或系统信息。
  - 攻击侧观测：同一 operator 会话：func=shell_exec&arg=id 的 <pre> 返回 "uid=33(www-data) gid=33(www-data) groups=33(www-data)"；func=system&arg=echo INJMARK$((6*7)) 的响应正文开头即为 "INJMARK42"（42 由 shell 求值，输入中不存在），证明 func 被作为 PHP 函数名调用且 arg 被当作 shell 命令执行，可在 Web 进程权限下运行任意命令/调用任意 PHP 函数。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`104d87c2c6c74f2eadf987020d890635`；`32766adaeb8149eb9260906ec9d13bb1`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`32766adaeb8149eb9260906ec9d13bb1` script finished exit=0
  - 适配脚本：`3dcaf580-adapted-formula_func_poc.py`（见证据包 evidence/）
  - 备注：作业 32766adaeb8149eb9260906ec9d13bb1 在 operator（id=3, role=operator）下执行，符合 formula.php:2 require_user(['operator','admin']) 的入口前提；审计 POC 作业 104d87c2c6c74f2eadf987020d890635 以 alice（customer）运行被 403 拒绝，佐证角色门禁存在但函数名无过滤。源码 applicability=match：formula.php:3 $func=(string)$_GET['func']; $result=(string)$func((string)($_GET['arg']??''))，无白名单/function_exists 检查；pre 处 h($result) 仅 HTML 转义。

### C-28 php.ini 开启 allow_url_include，为 LFI 升级为远程代码包含提供条件

- verification `da9c061c761b4ceb94448b4acd73ae60`（finding `127c478d14a64048b12521cde5a5587c` revision 1，context `23675f3471b944d7998aa824c997e062`，target lab30-shop-1.0.0）
  - 执行状态：执行完成，尚无确定结论；判定：不确定；来源：poc_agent
  - 正常侧观测：alice 会话下正常读取 /support/download.php?file=shipping.txt 返回文档（此前作业已确认 200 配送说明），路径遍历本身工作正常——同一机制下 /etc/passwd 可读（深度 4），说明 404 结果不是读取能力缺失，而是目标 ini 文件不存在于这些路径。
  - 攻击侧观测：动态侧可确认的是运行形态而无法确认该指令：经已登录 alice 的路径遍历，../../../../etc/passwd 可读（root:x:0:0...，证明遍历与读取确实生效）；进程为 apache2 -DFOREGROUND（/proc/1/cmdline），libphp.so 由 mod_php 加载，扩展目录 /usr/local/lib/php/extensions/no-debug-non-zts-20240924；/etc/apache2/sites-enabled/000-default.conf 的 DocumentRoot 为 /var/www/shop/public，但 php.ini 与 php 配置目录均无 PHPIniDir 线索。按此尝试读取部署 ini：/etc/php.ini、/usr/local/etc/php/php.ini、/usr/local/etc/php/conf.d/*.ini、/var/www/shop/docker/php.ini、/var/www/shop/php.ini 全部 404。因此无法读取运行时 allow_url_include 的实际取值；同时唯一已知的用户可控 include 点 content/page.php 把输入拼在 APP_ROOT.'/resources/views/' 之后，URL 无法处于路径开头，无法构造 RFI 请求。
  - 已保存作业事实：5 个；满足执行及前提检查的作业：5 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`2e431997e8ac48989e627212a1f61287`；`451cb41ea8384699a69659c9acf15bf2`；`5d0079af5e7145b5a1fa4f583d8df63f`；`4fa4ae638b744fae93c7c78efe9fafe5`；`ba5b6fffc10041ea98758898bffaa7e5`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`2e431997e8ac48989e627212a1f61287` script finished exit=0；`451cb41ea8384699a69659c9acf15bf2` script finished exit=0；`5d0079af5e7145b5a1fa4f583d8df63f` script finished exit=0；`4fa4ae638b744fae93c7c78efe9fafe5` script finished exit=0；`ba5b6fffc10041ea98758898bffaa7e5` script finished exit=0
  - 适配脚本：`da9c061c-adapted-poc.php`（见证据包 evidence/）
  - 备注：证据：ev-313b5156d049c53b（作业 2e431997e8ac48989e627212a1f61287：/etc/php.ini、/usr/local/etc/php/php.ini、conf.d 候选 404）；ev-bbb780d0df5227ea（作业 451cb41ea8384699a69659c9acf15bf2：深度探测，深度 4 读到 /etc/passwd，其余 ini 路径 404）；ev-2557456412660b7b（作业 5d0079af5e7145b5a1fa4f583d8df63f：apache2 -DFOREGROUND，environ 为空）；ev-77ec8bf9e0aa845c（作业 4fa4ae638b744fae93c7c78efe9fafe5：maps 显示 mod_php/libphp，mountinfo 无 php 配置挂载）；ev-ac4d22a9e63bf0f6（作业 ba5b6fffc10041ea98758898bffaa7e5：DocumentRoot=/var/www/shop/public，项目根 docker/php.ini 及 php.ini 均 404）。源码快照 docker/php.ini 第 2-3 行确为 allow_url_fopen=On、allow_url_include=On（appl…

## 6. 覆盖与未决项

| 独立分母 | 总数 | 已结算 | 未决/待办 | 闭环 |
|---|---:|---:|---:|---|
| 文件覆盖 | 61 | 读取 61；读取+跳过 61 | 0 | 是 |
| 必做方向 | 11 | 已决 11；跳过 0 | 0 | 是 |
| 动态验证 | 28 | 已验证 27；已复核记录 6 | 待验证 0；待复核 21 | — |
| 正式终审 | 28 | 已接受 6 | 待终审 22；存疑 0 | — |

**带理由跳过的文件**

- `lab30-shop/app/public/assets/products.svg`：静态 SVG 资源，不含服务端脚本；其内容由 content/page.php 与 assets/app.js 方向一并核对文件包含与输出上下文，若确认未被动态包含即无服务端执行面。

**后续建议（不阻止本次收束）**

- `dir_d1e17da66a8976cccb8420c147cb68a0`：读取 orders/create.php、account/redeem.php，检查价格/余额状态变更与重放防护
- `dir_e0eda37aa0a171bab8bc2a9134984447`：读取 ops/jobs.php、ops/maintenance.php、ops/database.php，检查 SQL 表名/排序拼接与命令执行
- `dir_e6a3979451d09671a691fcea9e7a3f5a`：lab30-shop/app/public/ops/database.php、maintenance.php、formula.php 等 ops 入口的 SQL 拼接与危险操作尚未读取
- `dir_ad9ecc44f0303b53475f3529f45315ea`：lab30-shop/app/public/account/settings.php 无 CSRF 校验的邮箱变更（可导致账户接管）需单独确认
- `dir_38849f8084d3ae74e5dba49a93a77ece`：ops/template-render.php:3 eval('return '.$m[1].';') 模板表达式代码执行，确认 POST 需 CSRF 令牌前提
- `dir_82ae7c1aae4a454a200d2c71277a5d7a`：ops/formula.php:3 动态函数调用 $func(...) 到任意全局函数（可间接触发系统命令/信息泄露），确认可达函数与后果
- `dir_aac4d7d206e89ddb1bf00a0c7882bf6f`：ops/url-preview.php:3 file_get_contents($url) 无协议/主机限制的 SSRF，确认内网可达性与响应回显
- `dir_ccfeed465ff507844d03f609cfd884ab`：support/download.php:3 data_dir().'/docs/'.$_GET['file'] 路径拼接，确认 ../ 路径遍历与 require_user() 无角色限制的可达性
- `dir_dff65951e21325262fea8769d9f3b072`：ops/xml-import.php:3 simplexml_load_string 使用 LIBXML_NOENT&#124;LIBXML_DTDLOAD，确认 XXE 文件读取/SSRF
- `dir_e79b56a4b90798fa4bbe4171fb0038b2`：ops/jobs.php:3 unserialize($raw) 于 DispatchJob 触发 __wakeup shell_exec（dispatch_job.php:4），确认反序列化 RCE 链
- `dir_dab82035111c7ab7f6d02057c9c02d0d`：审查 ops 目录其他入口（如 partner/portal.php、host_check.php 相关调用）是否存在同类 unserialize 外部输入与魔术方法链。
- `dir_1780f7c32a5b47bac3b45184b21191a9`：确认 template-render.php eval 在含引号/分号时 preg_replace_callback 提取边界与可执行表达式构造
- `dir_c09aaac814514aaf8b235d201a45db9b`：核对 formula.php 变量函数在 PHP 8 下可利用的具体危险函数（如 system/assert）与回显路径，补充完整利用请求
- `dir_d9ab88052b6e16f33e255de11b40e4ea`：template-preview.php include 的实际 RFI 运行前提（allow_url_include）与 LFI 落地路径未在源码中体现
- `dir_a9db474433dee0778d0d08b01e9cece4`：ops/database.php:3-4 异常/堆栈回显的信息泄露尚未作为独立 finding 提交（本轮达到 2 条 finding 上限），需后续提交为 info_disclosure。
- `dir_864f8c7c7c85e72babd31b0a5c6a7b91`：继续核对 ops/template-preview.php 与已有 RFI 结论的差异，确认是否还有新的文件包含/读取路径
- `dir_d0c4ba2560c64b529168848835c25758`：核实 php://filter 包装器在 is_file 下是否可用（需运行环境事实），以确认是否可绕过 http(s) 包装或对 is_file 无效路径的读取
- `dir_47697d671d158bc00d607a0985c2a42b`：核实 profile.php 第3行 href 输出是否形成可执行 open_redirect/xss（需协议过滤证据与浏览器上下文）
- `dir_062a7f5273b644f817914d15ae7b9a9d`：lab30-shop/app/public/account/backup.php:5 对用户输入 unserialize（不安全反序列化）
- `dir_1f550541f4979c8f836651e45e77fbcc`：lab30-shop/app/public/ops/template-render.php:3 对用户模板 eval 表达式（代码执行）
- `dir_3cb1c0d1a2b959c8f7b704440b6fb68e`：lab30-shop/app/public/ops/formula.php:3 变量函数 $func() 调用任意 PHP 函数（代码执行/信息泄露）
- `dir_4fdf66756717958a6238f66dd2139a77`：lab30-shop/app/public/support/download.php:3 docs/ 拼接 $_GET['file'] 路径穿越
- `dir_70c48f0d7f29441f72377f57c3c6beed`：lab30-shop/app/public/ops/xml-import.php:3 LIBXML_NOENT&#124;DTDLOAD 外部实体（XXE）
- `dir_b6d1ee54583b5e2afd453b8a397d5a73`：lab30-shop/app/public/ops/database.php:3 异常回显含 trace（信息泄露）
- `dir_d80a568d34381b17cc2df580b00eccd2`：lab30-shop/app/public/ops/url-preview.php:3 file_get_contents 任意 URL（SSRF）
- `dir_c96390f1ca048bd0152fa64c5b1deb2f`：data_dir 部署配置缺失，待补充部署事实后再判定 vault 目录是否可被 Web 直接读取
- `dir_d1fd4a6ade20d2330be15a9bfec9caa6`：account/backup.php:5 unserialize($_POST['backup']) 在 instanceOf 检查前即反序列化，可触发 dispatch_job.php:4 __wakeup 的 shell_exec（需普通登录会话与新漏洞结论，与已有 host_check 命令注入根因不同）
- `dir_fc1a59e4f0abad9f4de8683970d0ca34`：account/settings.php:3-6 邮箱更新未调用 check_csrf，需确认是否构成可利用 CSRF 写操作
- `dir_3f5b39904c9293234f94fd925a2fd58a`：审查 greeting.php 的 name 反射输出是否有其他上下文（如 URL/JS）未覆盖，已有 xss_r 结论需确认是否重复
- `dir_fe9f66a4c0978b42f8083a099f01e4eb`：审查 catalog/index.php:4 的 $term 拼接 LIKE 导致的 SQL 注入（q 参数），确认可注入语句与前置条件
- `dir_2af083a35b8c1ce298827b245f7be90c`：lab30-shop/app/public/support/download.php:3 路径穿越读取任意文件，待独立提交 finding 与 POC

**补证与未决动作**

- `43d592821aea48d2858efa93be41c43f` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 170b82091ccf48b4831b9a390dc622c1。（login.php 接受 GET sid 且 strict_mode 关闭导致会话固定）
- `494423ddc5fb4859bd074dca9235a8c5` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 2ea22374d2de49d3b92b57d122d73561。（钱包提现为无锁读改写余额导致并发超额提现（竞态/重复支付））
- `4e35ce72f856430faf590095346c382a` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 4997cbfbf6104bf99fef6fb55b06c2f2。（orders/detail.php 按请求 id 读取任意订单，未校验 user_id 归属导致 IDOR）
- `535647d0ed7347489babe46d74304070` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 395610502cf942dca52119a696a80d0d。（运营主机巡检 host 参数未转义拼接进 shell_exec（命令注入 RCE））
- `5720ae92f0e5471eac00a8fb77fb3fac` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 5c86fa32ae8449de85de4b6758e7eb8f。（登录页接受 URL 参数 sid 作为会话 ID，存在会话固定）
- `5a1f8b8736b246b9ae6d081c49f50198` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 74dfa5e1e3b448d2904882f3830ed4cb。（orders/create.php 订单单价取自请求参数 price，可按任意低价下单）
- `5c3db49dc8ce4eeab05208bd9757d432` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 9aaaae7782954fa09bf9ffcf46ff8b03。（continue.php 直接使用 GET next 作为跳转地址，存在开放重定向）
- `5e378654bba9469e88af2f96e98c9aee` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id a728d34fc00040b4a3d47cb409a0daf1。（account/update.php 批量赋值允许普通用户自改 role 与 balance）
- `5f8a819f26e14990a4204f0220c29672` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 795f5e0b4a0543efb4e1e8228cbd9ac8。（content/page.php 的 page 参数未经白名单直接拼接进 include 路径，导致本地文件包含）
- `6932a2d3e1de496c94b8f2b3c9c1a41e` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 425fed5d5e0040d88d95e771f115a980。（support/download.php 的 file 参数未做路径校验，登录用户可遍历读取 data_dir 下任意文件（含 sessions））
- `7ad3c684a4d54adb899e29e34e560d5e` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id e02edaf82f2f40fb96dabf07be468450。（account/settings.php 邮箱更新缺少 CSRF 校验，可跨站改写绑定邮箱）
- `7d12ad9359b14df7ada8996ac4d0bacc` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 44be6903ba364aaaa79ce14526327b3e。（运营网络诊断 host 参数未转义拼接进 shell_exec（命令注入 RCE））
- `9a66a667a5f046388568cfa10ff63cfe` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id fdd313376f5548439516baf94152cbc1。（ops/users.php 信任客户端 $_COOKIE['role'] 绕过管理员鉴权）
- `a4a6743f9b5649b4a1ef38011e51f504` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 1f43a1c5b6de46ae97ab1986a4d3299e。（ops/members.php 会员查询参数经 member_lookup 拼接进 SQL 造成 SQL 注入）
- `aa70f04ec65d42dd983c4b7d3638a182` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 15c43b2a41b448d4bf4c692a7ea66827。（catalog 搜索参数 q 直接拼接进 SQL LIKE 查询导致反射型 SQL 注入）
- `b693d5e8f0344d668b4f2194bf114f51` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 46372aed8c0d4cc684dba5fd03b40276。（ops/jobs.php 对 POST job 直接 unserialize，DispatchJob::__wakeup 触发 shell_exec 命令执行）
- `bfd1580e14754964a21945d15907d435` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 87f86b0925c7472f983ee5742445d033。（ops/template-render.php 将 POST 模板双花括号内容直接拼接进 eval（代码执行））
- `c69fbc2e3f51448ba5c70f09c96bcb39` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 87ac020d13914e3c90945cbf16f37c88。（ops/report.php 用 nickname 字符串拼接 query 的二阶 SQL 注入）
- `de178184d68144a694523b9093146aa0` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 4ee6c93d2d3742298e145935dfce9ee4。（资料维护接口批量赋值允许普通用户自改 role/balance/tier 提权）
- `ebf79804b7144f1599db2784de628db4` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 3ec2b903eaab4afaa9e6250e2ff49749。（登录页以 GET sid 设置会话 ID 且登录后不轮换，构成会话固定）
- `fd7b2de1f92542ed9e05b5d2de82edc1` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 3dcaf580e6704212b2744562d30cc928。（ops/formula.php 通过 GET func 变量函数调用任意 PHP 函数（code_execution））
- `fee35f9297b04da6a262edcbfa5eb9f9` 处理动态验证结论 inconclusive：补证、重试或撤回，并保留原记录。（php.ini 开启 allow_url_include，为 LFI 升级为远程代码包含提供条件）
- 21 项：对已验证结论完成正式复核；verified 不能替代终审。

**限制**

- 受阻、未执行、未读取的方向均不代表安全。
- 本次运行未同时满足完成状态、覆盖闭环与验证闭环，本报告为阶段报告。
- 仍有 22 条规范结论未获得正式确认，不计入已接受漏洞。

## 7. 附录与证据索引

**历史版本与来源记录**

| 规范结论 | finding | revision | 处置 | 验证 | 当前 |
|---|---|---:|---|---|---|
| `4e35ce72f856430faf590095346c382a` | `f6443234d9234ce2b19b7dfc29056e86` | 1 | open | unverified | 否 |
| `4e35ce72f856430faf590095346c382a` | `be7b150f8f9a4dd58b8e47b4678054fc` | 1 | open | verified | 是 |
| `5a1f8b8736b246b9ae6d081c49f50198` | `a498fc25608346dba9e18f7e737d2746` | 1 | open | unverified | 否 |
| `5a1f8b8736b246b9ae6d081c49f50198` | `21c96a05f27f4dd8b3bd9cf51bfccf08` | 1 | open | verified | 是 |
| `5f8a819f26e14990a4204f0220c29672` | `e48a1423f0ba469c819c3a99ef6ccbb0` | 1 | open | unverified | 否 |
| `5f8a819f26e14990a4204f0220c29672` | `30343c09d3bd42389b50f4b0f11693ac` | 1 | open | unverified | 否 |
| `5f8a819f26e14990a4204f0220c29672` | `90a5c284ff9c4d80a6d1d7e01b5ac086` | 1 | open | verified | 是 |
| `7ad3c684a4d54adb899e29e34e560d5e` | `4485b9ac03ba437d8eeda12a6085541f` | 1 | open | unverified | 否 |
| `7ad3c684a4d54adb899e29e34e560d5e` | `192169b676e44fbcaf428676c0233436` | 1 | open | verified | 是 |

**撤回、重复或替代记录**

- `60915ff8a140441f88a3636b30f2ef49`（revision 1）：duplicate——ops/members.php 与 member_lookup 的 LIKE 拼接 SQL 注入
- `02f4d13458674646a4e376388c463cd5`（revision 1）：duplicate——ops/batch-check.php 主机巡检参数经 host_check 拼入 shell_exec 造成命令注入
- `6fa34d3463d349eba7e53aeabde06bcc`（revision 1）：duplicate——ops/ping.php 主机参数注入系统命令（shell_exec）
- `266ec0bd61674249a9e7c89b316b22ac`（revision 1）：duplicate——ops/batch-check.php 经 host_check() 注入系统命令
- `3f4a5c525a7342e29766763ebbb152f9`（revision 1）：duplicate——account/backup.php 对 POST backup 先 unserialize 后类型检查
- `02850571e7e9491db51bc887c71adb47`（revision 1）：duplicate——ops/jobs.php 对 base64 解码的 $_POST['job'] 直接 unserialize，DispatchJob::__wakeup 触发 shell_exec 命令执行
- `b44c71f51aec4212b525d187ae4b8dbc`（revision 1）：duplicate——login.php 接受 GET sid 且关闭 session.use_strict_mode，可预置会话 ID 实施会话固定
- `722c0044bcac4c02a93ed33a3fe3ffc0`（revision 1）：duplicate——catalog 搜索参数 q 未过滤拼接进 LIKE 子句并经 PDO::query 执行（反射型 SQL 注入）

**关联链路对照（位置或引用关联不代表重复）**

- `43d592821aea48d2858efa93be41c43f` ↔ `5720ae92f0e5471eac00a8fb77fb3fac`：仍需对照判读；尚未明确判读是否具有不同根因。
- `43d592821aea48d2858efa93be41c43f` ↔ `ebf79804b7144f1599db2784de628db4`：仍需对照判读；尚未明确判读是否具有不同根因。
- `5720ae92f0e5471eac00a8fb77fb3fac` ↔ `ebf79804b7144f1599db2784de628db4`：仍需对照判读；尚未明确判读是否具有不同根因。
- `5e378654bba9469e88af2f96e98c9aee` ↔ `de178184d68144a694523b9093146aa0`：仍需对照判读；尚未明确判读是否具有不同根因。

**任务记录**

| 任务 | 标题 | 状态 | 错误 |
|---|---|---|---|
| `64fdd625cb46417fb1aab53a33383582` | 共享引导与数据层：db()/h()/session 封装及所有 DSN 与转义路径 | completed | — |
| `8de7d4b3632b4f709d79211bce774fc7` | 账户入口：认证、会话固定、弱比较、IDOR 与备份文件读取 | completed | — |
| `2012a996ec9d4669bcd44e2399075c70` | 钱包入口：客户端单价信任、提现竞态/重复支付、批量赋值改敏感字段 | completed | — |
| `860a18927a8b4c4a8adf2742c43b2720` | 运维高危面取证：动态函数调用、反序列化、eval 模板、SSRF、XXE、路径遍历 | completed | — |
| `8d1a92bc52a54432bfcacea9c344b94d` | 不安全反序列化利用链：account/backup.php 与 ops/jobs.php | completed | — |
| `7b9269a11ef744a1bc3b57b050121e41` | 运营端动态执行链：formula.php 变量函数、template-render.php eval、jobs.php 反序列化 | completed | — |
| `336ce3d48a1d457588148c3871c89ea5` | 部署与运行时配置：compose.yaml、apache.conf、php.ini、entrypoint.sh | completed | — |
| `e7a0054c94cc492c86ded261db20ba20` | 目录入口：SQL 注入（直连/跨文件）与反射/存储型 XSS 全链路 | completed | — |
| `a20b1969d6d44b42add28307df33855b` | 运维 SQL 注入：members、report、member_lookup、audit-log 参数化复核 | completed | — |
| `cc24476f89c24f4984f21905bafc6826` | 订单入口：越权/IDOR、状态篡改与 CSRF 缺失 | completed | — |
| `74ff2c8c14ec4d3699dff06ae97674d3` | 动态调用与模板表达式：ops/formula.php 变量函数与 ops/template-render.php eval | completed | — |
| `d1cd914e4f17431a97d82424e09cf785` | 合作方入口 partner/portal.php 与 partner/token.php 的鉴权与令牌边界 | completed | — |
| `70963dc0a852446fbbfed3ce131f4f34` | catalog/index.php 搜索词拼接 LIKE 的 SQL 注入 | completed | — |
| `b4579f26a6bd43a1a280af0fa6e5b0a9` | support/download.php 任意文件读取与 docs 目录越界 | completed | — |
| `6283fb35f52c4d70ae48bef07e7a1369` | 运维与支持入口：命令执行、文件操作、SSRF/XXE 与模板 eval | completed | — |
| `ae75bde78aba413cad4bb11ca8fbc9d0` | 存储型 XSS 与客户端角色信任：support/messages、ops/users 与展示模板 | completed | — |
| `d5f2afe9c8a14baab03897d6a5c92647` | 写操作鉴权与 CSRF 覆盖：account/settings.php、account/profile.php、account/update.php | completed | — |
| `d8359f6136e649268323c6ecbd590145` | 前台总入口 public/index.php 与 CLI bin/lab 的输入处理 | completed | — |
| `2e9dd6d0b5dc480092c7c67cec5e21eb` | account/backup.php 反序列化与批量赋值 | completed | — |
| `d47920e5776a4502a685d448c4dca973` | 未覆盖入口与脚本：app/bin 与前端资源、以及剩余第一方入口 | completed | — |
| `44d76c8887d744418aaa90236580791b` | 注册与登录会话边界：auth/register.php、auth/continue.php 与 login.php 会话处理 | completed | — |
| `abd09e3a3dc6401c8cddc477a6f85e50` | 会话固定与会话/CSRF 写入边界补查 | completed | — |
| `fe04e89200774bb2a29f6c74ce59d01f` | auth/login.php 与 auth/continue.php 的会话建立与固定 | completed | — |
| `19c0953f308249bcab07bb55e6209f86` | bootstrap/data 层收窄补查：db()、h()、csrf、会话与 data_dir 实现 | completed | — |
| `5c9c2543326146f5b140a4e12b187ed9` | 内容页与健康检查入口：content/page.php、health.php、assets/products.svg | completed | — |
| `23d59dcb9b094aca8a9624f4e4014968` | catalog 详情与 greeting 的 SQL 拼接与输出上下文 | completed | — |
| `e57a3d13701f432e9203902948a33fe6` | 订单与支持入口的越权与业务逻辑：orders/detail.php、orders/index.php、support 目录 | completed | — |

- 用量：上限 响应 2048；工具 16384；秒 10800；实际 响应 266；工具 299；秒 1987.524；剩余 响应 1782；工具 16085；秒 8812.476

**证据索引（服务器读取）**

| evidence_id | 路径 | 范围 | 文件哈希 | 可用 |
|---|---|---|---|---|
| `6022c7c16ca21753` | lab30-shop/docker/php.ini | 7-7 | `b65de9007c7f42b3` | 是 |
| `6583999657214637` | lab30-shop/docker/php.ini | 8-8 | `b65de9007c7f42b3` | 是 |
| `343d5e3158080141` | lab30-shop/app/public/partner/portal.php | 2-6 | `e1267edb0f9df936` | 是 |
| `e857c8df6419c587` | lab30-shop/app/public/partner/token.php | 2-6 | `391948b46efce76c` | 是 |
| `40ae2a25513665c3` | lab30-shop/app/src/setup.php | 27-27 | `53e7dc7286d7d370` | 是 |
| `78224482780bf94a` | lab30-shop/app/src/bootstrap.php | 33-37 | `2050819d093be02b` | 是 |
| `5d596a817dad3c10` | lab30-shop/app/public/ops/template-preview.php | 1-3 | `107da46e9b067ce0` | 是 |
| `f15ec397a921596f` | lab30-shop/app/public/account/backup.php | 2-6 | `017e1703cdf0ff0c` | 是 |
| `9d0d13b19a80b9a2` | lab30-shop/app/src/backup.php | 2-5 | `571459cc8b0f6e8e` | 是 |
| `addf5b6a130c589e` | lab30-shop/app/public/account/index.php | 3-3 | `1d22c7bc280b30b0` | 是 |
| `ea671862691bb582` | lab30-shop/app/public/account/redeem.php | 5-5 | `28b3dc4534cca985` | 是 |
| `4287a6e3dca83484` | lab30-shop/app/public/support/messages.php | 3-5 | `a6866f07b4de32f3` | 是 |
| `5220b9ce518719f6` | lab30-shop/app/src/bootstrap.php | 10-10 | `2050819d093be02b` | 是 |
| `c57a3bf6bb6b01db` | lab30-shop/app/public/catalog/greeting.php | 2-3 | `8e6db315fdfc32cf` | 是 |
| `9f3b2a689fae3c12` | lab30-shop/app/src/bootstrap.php | 11-19 | `2050819d093be02b` | 是 |
| `5f912f7499e51381` | lab30-shop/app/public/auth/login.php | 3-9 | `b9be43ddb2233156` | 是 |
| `8e89065a153544f6` | lab30-shop/app/public/wallet/withdraw.php | 2-9 | `e3e73271e379b085` | 是 |
| `063c928d2d7c3b2e` | lab30-shop/app/src/bootstrap.php | 33-40 | `2050819d093be02b` | 是 |
| `6cc4203c00ab810f` | lab30-shop/app/public/wallet/index.php | 2-4 | `76b24de3e20c34df` | 是 |
| `171ea369e07c383b` | lab30-shop/app/public/orders/detail.php | 1-4 | `be69aa78cecffcfd` | 是 |
| `1b8e73c49d79d5d1` | lab30-shop/app/public/orders/index.php | 1-3 | `633f73e04b427bba` | 是 |
| `a8463619606be720` | lab30-shop/app/src/bootstrap.php | 20-36 | `2050819d093be02b` | 是 |
| `772dda483c0c1762` | lab30-shop/app/public/ops/batch-check.php | 2-2 | `5f76332e7ad1b33a` | 是 |
| `3469da4edb56bedd` | lab30-shop/app/src/host_check.php | 2-2 | `c3a868155c2d335e` | 是 |
| `6220461f4c36cb1a` | lab30-shop/app/src/bootstrap.php | 33-36 | `2050819d093be02b` | 是 |
| `415907ec6bf2f739` | lab30-shop/app/src/bootstrap.php | 40-40 | `2050819d093be02b` | 是 |
| `0665b79989f38035` | lab30-shop/app/public/orders/create.php | 1-7 | `41e73625d7e04c58` | 是 |
| `604a359fd6dacaf0` | lab30-shop/app/src/bootstrap.php | 38-45 | `2050819d093be02b` | 是 |
| `a3a2825731fc4c1a` | lab30-shop/app/public/auth/continue.php | 2-4 | `50fde4a15e52af44` | 是 |
| `f22eb45f82c6d948` | lab30-shop/app/public/account/update.php | 2-6 | `b8227f19c05d0cd3` | 是 |
| `be43fce581c2c052` | lab30-shop/app/public/content/page.php | 2-3 | `53c5997117f2d54c` | 是 |
| `10c0c8123072e718` | lab30-shop/app/public/support/download.php | 2-3 | `71f0558eeb4ebb6c` | 是 |
| `8d6a30203fcb8cca` | lab30-shop/app/src/bootstrap.php | 9-14 | `2050819d093be02b` | 是 |
| `acc5953e7fe3994f` | lab30-shop/app/public/account/settings.php | 2-8 | `f54949d62e46b9ca` | 是 |
| `4eba9252f833f919` | lab30-shop/app/src/bootstrap.php | 38-40 | `2050819d093be02b` | 是 |
| `06e77bb1ca712323` | lab30-shop/app/src/bootstrap.php | 16-16 | `2050819d093be02b` | 是 |
| `61f200eb89320676` | lab30-shop/app/public/ops/ping.php | 1-3 | `c15517950afe0794` | 是 |
| `d4000ad3e3500c5b` | lab30-shop/app/public/ops/users.php | 2-5 | `3c5e879d945650ba` | 是 |
| `e7189d5aff3d503f` | lab30-shop/app/public/ops/index.php | 2-2 | `3e08442a501932a5` | 是 |
| `4d2f2da581629f05` | lab30-shop/app/src/member_lookup.php | 1-4 | `eb704332329d4530` | 是 |
| `12d724d86e16c5f7` | lab30-shop/app/public/ops/members.php | 1-4 | `aef140c3800b9cf1` | 是 |
| `85b2e45ff4e8d0eb` | lab30-shop/app/src/bootstrap.php | 4-8 | `2050819d093be02b` | 是 |
| `b07638e22476de42` | lab30-shop/app/public/catalog/index.php | 3-5 | `e85bd1c2fa6a4b78` | 是 |
| `bd2a787730066498` | lab30-shop/app/src/bootstrap.php | 4-7 | `2050819d093be02b` | 是 |
| `bc71d05290d8c856` | lab30-shop/app/public/ops/jobs.php | 2-3 | `0f7550fa7f16bd4a` | 是 |
| `e030edd4e1bdfc70` | lab30-shop/app/src/dispatch_job.php | 2-4 | `e8234b971fe75d85` | 是 |
| `136d02a92a08ac98` | lab30-shop/app/public/ops/template-render.php | 1-4 | `357da9e9959275d8` | 是 |
| `667c91ac7c21aa66` | lab30-shop/app/public/ops/report.php | 2-3 | `90d7d60d44815374` | 是 |
| `6700e4b97da566f5` | lab30-shop/app/src/bootstrap.php | 53-53 | `2050819d093be02b` | 是 |
| `368b0f4121e7e402` | lab30-shop/app/public/auth/login.php | 3-3 | `b9be43ddb2233156` | 是 |
| `8506476ecddd25f6` | lab30-shop/app/public/auth/login.php | 8-9 | `b9be43ddb2233156` | 是 |
| `96d4fc4a57e8be01` | lab30-shop/app/src/bootstrap.php | 13-18 | `2050819d093be02b` | 是 |
| `f3b7c0b40a3232d5` | lab30-shop/app/public/ops/formula.php | 1-4 | `686f39f31996a5d3` | 是 |
| `09625de28ecabb6a` | lab30-shop/docker/php.ini | 2-3 | `b65de9007c7f42b3` | 是 |

**附件与机器可读清单**

- Markdown：本报告（由事实包确定性生成）。
- JSON：result.json（含本事实包与质量结果）
- 证据包：evidence/（POC 脚本、runner 产物、runner manifest）
- 源码：源码片段由宿主从冻结快照读取，见 source_evidence
- 事实包 ID：`0b7c8bb1bfbc17edb3f1280b49bb5e4f8207818e6d9c5e7742e2cde812feb9a0`；页面、Markdown、JSON 与证据包共用同一份事实。
