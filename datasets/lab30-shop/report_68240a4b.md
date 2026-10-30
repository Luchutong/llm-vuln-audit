# 源码审计阶段报告（68240a4b）

> 报告类型：阶段报告；发布状态：可发布（阶段报告）
> 事实包 final-review/v1 · 渲染器 final-report/v2 · 策略 audit-runtime-3
> 运行 `68240a4b547f4839ac18520429177c5a` · 快照 `586b79b41f8e4f59be80f2a9b548902b` · 源码哈希 `67fd87e9ae771d10…` · 输入哈希 `23f929fcfdf3262628b35821772e4fe1a2a9d484fceac86fd69e5a4a94dd5df3`
> 本报告由宿主从冻结事实包确定性生成；数量、位置、验证状态与评分均不由模型填写。

## 1. 执行与终审摘要

- 运行：`68240a4b547f4839ac18520429177c5a`；状态：inconclusive；停止原因：final_review_incomplete；审计已结束，仍有 9 项未完成终审；已保存事实和阶段报告。
- 审计完整性：未完成，本报告为阶段报告
- 报告类型：stage；发布状态：可发布（阶段报告）

- 原始记录：49
- 有效记录：37
- 规范结论：29
- 已接受漏洞：20
- 待终审：9
- 存疑或排除：0

“已接受漏洞”以当前版本的正式终审处置为准：静态证据充分可接受；动态已验证结论还须完成同版本观测复核。其余结论逐条保留，不会因为缺少终审额度而从报告中消失。

| 完成维度 | 已完成 | 分母 | 说明 |
|---|---:|---:|---|
| 源码覆盖（读取） | 58 | 61 | 已读只表示宿主记录过读取 |
| 源码覆盖（读取+带理由跳过） | 61 | 61 | 跳过不是安全结论 |
| 必做方向结算 | 12 | 12 | 未决 0 个 |
| 动态验证完成 | 38 | 29 | 待验证 0 条 |
| 正式复核 | 20 | 29 | 复核存疑或未复核不计入已接受 |
| 源码覆盖（仍待复核） | 0 | 61 | 未读且未跳过 0 个 |

- 发布门禁未通过：review_batch_complete

**已接受漏洞**

- C-01 ops/maintenance.php 仅凭可伪造的 X-Admin 请求头授权，未认证即可触发维护任务写入（lab30-shop/app/public/ops/maintenance.php:3）
- C-02 ops/template-preview.php 将 GET template 直接 include，allow_url_include=On 时可远程包含执行代码（lab30-shop/app/public/ops/template-preview.php:3）
- C-03 support/messages.php 留言正文未编码输出的存储型 XSS（lab30-shop/app/public/support/messages.php:5）
- C-04 catalog/greeting.php 的 name 参数未经转义直接回显导致反射型 XSS（lab30-shop/app/public/catalog/greeting.php:3）
- C-05 运营会员查询 $_GET['q'] 拼接进 LIKE，跨文件 SQL 注入（lab30-shop/app/src/member_lookup.php:3）
- C-06 wallet/withdraw.php 余额读取与更新非原子，配合 usleep 与 session_write_close 可并发重复提现（lab30-shop/app/public/wallet/withdraw.php:7）
- C-07 订单详情接口按订单 id 查询未校验归属，任意登录用户可越权读取他人订单（lab30-shop/app/public/orders/detail.php:2）
- C-08 注册/登录使用无盐 md5 存储与校验口令（lab30-shop/app/public/auth/register.php:8）
- C-09 下单接口信任客户端 price 字段，单价与总价可被篡改为任意非负值（lab30-shop/app/public/orders/create.php:5）
- C-10 auth/continue.php next 参数未校验导致登录后开放重定向（lab30-shop/app/public/auth/continue.php:3）
- C-11 content/page.php 的 page 参数未经净化拼入 include，导致路径遍历与本地/远程文件包含（lab30-shop/app/public/content/page.php:3）
- C-12 商品搜索 q 参数拼接 SQL 导致注入（catalog/index.php）（lab30-shop/app/public/catalog/index.php:4）
- C-13 ops/xml-import.php 以 LIBXML_NOENT|LIBXML_DTDLOAD 解析请求 XML，导致 XXE 本地文件读取并回显（lab30-shop/app/public/ops/xml-import.php:3）
- C-14 account/profile.php 的 url 参数未经转义进入 href 属性导致反射型 XSS（lab30-shop/app/public/account/profile.php:3）
- C-15 account/update.php 批量赋值允许任意用户修改 role/balance/tier（lab30-shop/app/public/account/update.php:5）
- C-16 start_session 允许外部可控 SID 且未在登录后重生成，导致会话固定/劫持（lab30-shop/app/src/bootstrap.php:17）
- C-17 ops/users.php 以客户端 Cookie role 判定管理员，任意登录用户可冒充 admin 读取全部用户邮箱与角色（lab30-shop/app/public/ops/users.php:2）
- C-19 partner/portal.php 不校验 JWT 签名，任意匿名请求伪造 role=admin 即可读取全部用户订单（lab30-shop/app/public/partner/portal.php:3）
- C-23 运营网络诊断将 GET host 原样拼入 shell_exec 导致命令注入（lab30-shop/app/public/ops/ping.php:2）
- C-24 ops/jobs.php 反序列化用户提交的 DispatchJob 对象，__wakeup 中 shell_exec 导致代码执行（lab30-shop/app/src/dispatch_job.php:4）

**仍需终审的结论**

- C-18 support/download.php file 参数路径遍历读取任意文件：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-20 运营模板渲染将 POST 模板表达式直接 eval，导致任意 PHP 代码执行：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-21 运营链接预览将 GET url 原样传入 file_get_contents，导致 SSRF：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-22 account/backup.php 对用户提交的备份直接 unserialize 并写入任意 tier/display_name：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-25 account/redeem.php 使用 == 比较 md5 兑换码导致 0e 弱比较绕过升级会员：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-26 support/download.php file 参数未规范化导致 ../ 路径遍历任意文件读取：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-27 ops/report.php 将数据库昵称二次拼接进 SQL，低权用户可通过昵称注入：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-28 support/download.php file 参数未规范化拼接路径导致任意文件读取：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-29 ops/formula.php 将 GET func 直接作为函数名调用，可调用 system/exec 等实现任意命令执行：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

## 2. 范围和方法

- 项目：39211162aa984b25b60228c194b531ae；快照：`586b79b41f8e4f59be80f2a9b548902b`
- 源码包哈希（archive sha256）：`67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c`
- 事实包：final-review/v1；渲染器：final-report/v2；模板哈希：`bae25eb461e0811b`
- 输入哈希：`23f929fcfdf3262628b35821772e4fe1a2a9d484fceac86fd69e5a4a94dd5df3`；冻结时间：2026-10-30T13:44:33.750010+00:00；生成时间：2026-10-30T13:44:33.750010+00:00
- 模型配置：deepseek-flash；策略版本：audit-runtime-3

本次报告只使用宿主记录的冻结事实：源码引用由服务器从快照读取并核对哈希，动态验证取自隔离 runner 的作业记录，正式复核按 finding revision 与 verification id 精确引用。模型的结论陈述与修复建议以“结论陈述”标注，不作为证据；未执行、环境失败与验证不确定都不解释为误报。

| 预算 | 上限 | 实际使用 | 剩余 |
|---|---:|---:|---:|
| 模型响应 | 2048 | 368 | 1680 |
| 工具调用 | 16384 | 374 | 16010 |
| 秒 | 10800 | 3469.183 | 7330.817 |

- 上下文：峰值请求 147212 字节 / 上限 393216 字节；摘要请求 0 次；硬上限命中 0 次。

| 阶段 | 请求配额 | 已用 |
|---|---:|---:|
| 源码挖掘 | 164 | 164 |
| POC 验证 | 1809 | 138 |
| 统一终审 | 75 | 66 |
- 调度政策：host-queue-v1；配额：自动分配。
- 待终审 9 项，预计 4 批；当前预留 12 次请求、300 秒；按实际批次容量与 Worker 调整，不增加整次额度。
- POC 执行：。

## 3. 规范漏洞清单

| 编号 | 标题 | 类型 | 评分 | 位置 | 静态判读 | 动态验证 | 正式终审 | 处置 |
|---|---|---|---|---|---|---|---|---|
| C-01 | ops/maintenance.php 仅凭可伪造的 X-Admin 请求头授权，未认证即可触发维护任务写入 | auth_bypass | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/… | lab30-shop/app/public/ops/maintenance.php:3 | 缺上下文（1 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-02 | ops/template-preview.php 将 GET template 直接 include，allow_url… | rfi | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/template-preview.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-03 | support/messages.php 留言正文未编码输出的存储型 XSS | xss_s | CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/… | lab30-shop/app/public/support/messages.php:5 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-04 | catalog/greeting.php 的 name 参数未经转义直接回显导致反射型 XSS | xss_r | CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/… | lab30-shop/app/public/catalog/greeting.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-05 | 运营会员查询 $_GET['q'] 拼接进 LIKE，跨文件 SQL 注入 | sqli | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/src/member_lookup.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-06 | wallet/withdraw.php 余额读取与更新非原子，配合 usleep 与 session_write_clo… | race_condition | CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/wallet/withdraw.php:7 | 缺上下文（1 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-07 | 订单详情接口按订单 id 查询未校验归属，任意登录用户可越权读取他人订单 | idor | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/orders/detail.php:2 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-08 | 注册/登录使用无盐 md5 存储与校验口令 | weak_crypto | CVSS 3.1 Base 5.9 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/auth/register.php:8 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-09 | 下单接口信任客户端 price 字段，单价与总价可被篡改为任意非负值 | price_manipulation | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/orders/create.php:5 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-10 | auth/continue.php next 参数未校验导致登录后开放重定向 | open_redirect | CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/… | lab30-shop/app/public/auth/continue.php:3 | 缺上下文（1 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-11 | content/page.php 的 page 参数未经净化拼入 include，导致路径遍历与本地/远程文件包含 | lfi | CVSS 3.1 Base 9.4 (critical) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:… | lab30-shop/app/public/content/page.php:3 | 缺上下文（2 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-12 | 商品搜索 q 参数拼接 SQL 导致注入（catalog/index.php） | sqli | CVSS 3.1 Base 8.2 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:… | lab30-shop/app/public/catalog/index.php:4 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-13 | ops/xml-import.php 以 LIBXML_NOENT&#124;LIBXML_DTDLOAD 解析请求 X… | xxe | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/ops/xml-import.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-14 | account/profile.php 的 url 参数未经转义进入 href 属性导致反射型 XSS | xss_r | CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/… | lab30-shop/app/public/account/profile.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-15 | account/update.php 批量赋值允许任意用户修改 role/balance/tier | mass_assignment | CVSS 3.1 待评分 | lab30-shop/app/public/account/update.php:5 | 缺上下文（2 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-16 | start_session 允许外部可控 SID 且未在登录后重生成，导致会话固定/劫持 | session_fixation | CVSS 3.1 待评分 | lab30-shop/app/src/bootstrap.php:17 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-17 | ops/users.php 以客户端 Cookie role 判定管理员，任意登录用户可冒充 admin 读取全部用户邮… | auth_bypass | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/ops/users.php:2 | 缺上下文（1 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-18 | support/download.php file 参数路径遍历读取任意文件 | path_traversal | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/support/download.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-19 | partner/portal.php 不校验 JWT 签名，任意匿名请求伪造 role=admin 即可读取全部用户订单 | auth_bypass | CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:… | lab30-shop/app/public/partner/portal.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-20 | 运营模板渲染将 POST 模板表达式直接 eval，导致任意 PHP 代码执行 | code_execution | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/template-render.php:3 | 缺上下文（2 项） | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-21 | 运营链接预览将 GET url 原样传入 file_get_contents，导致 SSRF | ssrf | CVSS 3.1 Base 5.0 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/… | lab30-shop/app/public/ops/url-preview.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-22 | account/backup.php 对用户提交的备份直接 unserialize 并写入任意 tier/display… | insecure_deserialization | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/account/backup.php:5 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-23 | 运营网络诊断将 GET host 原样拼入 shell_exec 导致命令注入 | command_injection | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/ping.php:2 | 缺上下文（2 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-24 | ops/jobs.php 反序列化用户提交的 DispatchJob 对象，__wakeup 中 shell_exec … | insecure_deserialization | CVSS 3.1 待评分 | lab30-shop/app/src/dispatch_job.php:4 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-25 | account/redeem.php 使用 == 比较 md5 兑换码导致 0e 弱比较绕过升级会员 | weak_type_comparison | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/account/redeem.php:5 | 缺上下文（1 项） | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-26 | support/download.php file 参数未规范化导致 ../ 路径遍历任意文件读取 | path_traversal | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/support/download.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-27 | ops/report.php 将数据库昵称二次拼接进 SQL，低权用户可通过昵称注入 | sqli | CVSS 3.1 Base 4.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/… | lab30-shop/app/public/ops/report.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-28 | support/download.php file 参数未规范化拼接路径导致任意文件读取 | path_traversal | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/support/download.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-29 | ops/formula.php 将 GET func 直接作为函数名调用，可调用 system/exec 等实现任意命令… | code_execution | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/formula.php:3 | 证据已记录 | 动态确认 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |

## 4. 逐条漏洞详单

### C-01 ops/maintenance.php 仅凭可伪造的 X-Admin 请求头授权，未认证即可触发维护任务写入

- 当前版本：finding `bfc27a79c5a04c438b49cd5fc87f5519` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/maintenance.php:3`；文件：`lab30-shop/app/public/ops/maintenance.php`
- 证据引用：`4e2faa355e456c2e` lab30-shop/app/public/ops/maintenance.php:1-5；`9d62b8b1257e5f2a` lab30-shop/app/src/bootstrap.php:20-25；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:e461ef5e9988d8a29a98:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

maintenance.php 未调用 require_user，第 3 行仅判断 $_SERVER['HTTP_X_ADMIN']==='1'，该头由客户端任意设置，与服务端会话完全独立。满足后第 4 行 POST 分支执行 INSERT INTO jobs(user_id,title,status,details) VALUES(4,?,'queued','维护接口发起') 并返回 job_id，任何未认证访问者均可触发。

- 攻击前身份与适用前提：能访问 /ops/maintenance.php；发送 X-Admin: 1；POST 触发写库
- 入口 → 传播 → 危险操作/状态变更：请求头 X-Admin: 1 → maintenance.php:3 读取 HTTP_X_ADMIN -> 与 '1' 比较通过 -> 第4行 POST 时执行 INSERT jobs 并回显 job_id → 无认证写入 jobs 表（维护任务触发）
- 防护与边界：无：未绑定服务端会话，X-Admin 为客户端可控请求头
- 静态判读：缺上下文（1 项）；缺失上下文：jobs 表结构与 user_id=4 是否存在及维护任务的后续执行逻辑未在已读源码中体现
- 动态验证：动态确认（verification `0776b77b9c1949b59f02a2f7dddfeb87`）
- 正式终审：独立批次 bb1af304255840229be2a6ab238ba43c；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一未认证 guest 请求加 X-Admin: 1：GET 返回 200 {"service":"settlement-maintenance","authorized":true}；连续两次 POST 均返回 200 {"accepted":true,"job_id":302} 与 {"accepted":true,"job_id":303}。自增主键连续递增证明每次请求都实际执行了 INSERT INTO jobs 并写库，而非伪造或缓存响应；user_id=4 的硬编码插入未触发外键/约束错误。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：未提供

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/maintenance.php:1-5`（sha256 `b96aecd7df7c5fa4…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';
    3  if(($_SERVER['HTTP_X_ADMIN']??'')!=='1')fail_request('内部维护接口需要有效的服务身份。',403);
    4  if($_SERVER['REQUEST_METHOD']==='POST'){db()->prepare("INSERT INTO jobs(user_id,title,status,details) VALUES(4,?,'queued','维护接口发起')")->execute(['系统对账']);json_response(['accepted'=>true,'job_id'=>(int)db()->lastInsertId()]);}
    5  json_response(['service'=>'settlement-maintenance','authorized'=>true]);
```

`lab30-shop/app/src/bootstrap.php:20-25`（sha256 `2050819d093be02b…`）

```php
   20  function user(): ?array {
   21      start_session();
   22      if (empty($_SESSION['user_id'])) return null;
   23      $q = db()->prepare('SELECT id,username,display_name,email,role,balance,tier,nickname,homepage FROM users WHERE id=?');
   24      $q->execute([$_SESSION['user_id']]); return $q->fetch() ?: null;
   25  }
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-02 ops/template-preview.php 将 GET template 直接 include，allow_url_include=On 时可远程包含执行代码

- 当前版本：finding `0bb3ead0ddc24e6e944d1e0b0f5e3a76` revision 1（项目版本 16）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-preview.php:3`；文件：`lab30-shop/app/public/ops/template-preview.php`
- 证据引用：`3fa8e49da1b5abbd` lab30-shop/app/public/ops/template-preview.php:2-3；`09625de28ecabb6a` lab30-shop/docker/php.ini:2-3；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:74e57fa245bad6a7fdfb:1（规范类型 rfi）

**结论陈述（模型产出，不是证据）**

template-preview.php 取 $_GET['template'] 后 if($template!=='')include $template; 无路径规范化、无前缀校验、无白名单。由于 docker/php.ini 设置 allow_url_include=On，include 可接受 http:// 远程 URL，攻击者托管 PHP 文件即可远程代码执行；同样可 include 本地路径（LFI）读取/包含本地文件。

- 攻击前身份与适用前提：持有 operator 或 admin 角色的有效会话；远程包含需 allow_url_include=On（本快照 php.ini 已开启）
- 入口 → 传播 → 危险操作/状态变更：HTTP GET 参数 template → $_GET['template'] -> (string)$template -> include $template → include 语句包含请求可控路径/URL
- 防护与边界：仅 require_user(['operator','admin'])，无白名单、无 basename/realpath 校验
- 静态判读：证据已记录
- 动态验证：动态确认（verification `744fffb1e0a54226b18df6fe4b17908a`）
- 正式终审：独立批次 21d5fb0651c140ebaa499dcb779bb04e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 operator 会话请求 /ops/template-preview.php?template=/etc/passwd：HTTP 200，#remote-template 区域内原样输出本地文件内容 "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:...\nbin:x:2:2:...\nsys:x:3:3:..."（ATTACK passwd True），证明 include 接受任意本地路径并读取任意文件。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：禁止直接 include 请求值：改为固定模板目录白名单映射（如 ['season'=>'/templates/season.php']），用 realpath 校验前缀，并关闭 allow_url_include。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/template-preview.php:2-3`（sha256 `107da46e9b067ce0…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$template=(string)($_GET['template']??'');
    3  page('远程模板预览',function()use($template){echo '<section class="panel"><form method="get">';form_input('template','模板地址',$template?:'http://fixtures:8080/templates/season.php');echo '<button>加载模板</button></form></section><section class="panel" id="remote-template">';if($template!=='')include $template;echo '</section>';},'运营工作台');
```

`lab30-shop/docker/php.ini:2-3`（sha256 `b65de9007c7f42b3…`）

```
    2  allow_url_fopen = On
    3  allow_url_include = On
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-03 support/messages.php 留言正文未编码输出的存储型 XSS

- 当前版本：finding `bc93fb6a277d4739a06986e3c6154a0e` revision 1（项目版本 20）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/messages.php:5`；文件：`lab30-shop/app/public/support/messages.php`
- 证据引用：`4287a6e3dca83484` lab30-shop/app/public/support/messages.php:3-5；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10
- 根因类别：task_goal:v2:af3c55792fda1daa9790:1（规范类型 xss_s）

**结论陈述（模型产出，不是证据）**

第3行将 POST message 直接入库（仅长度校验，无 HTML 转义）；第5行输出列表时 display_name 与 created_at 用 h() 转义，但 $row['message'] 直接拼进 <div class="message-body">，形成存储型 XSS。攻击者提交含脚本的留言，任何访问留言页的用户浏览即执行。

- 攻击前身份与适用前提：攻击者为已登录用户并可提交留言；受害用户浏览 /support/messages.php
- 入口 → 传播 → 危险操作/状态变更：POST body 参数 message → $_POST['message'] -> INSERT INTO messages -> SELECT -> foreach 输出拼接 HTML → echo '<div class="message-body">'.$row['message'].'</div>'
- 防护与边界：其它字段使用 h()，message 字段无任何编码
- 静态判读：证据已记录
- 动态验证：动态确认（verification `be96a0e446da487e8b52167164bb8bf4`）
- 正式终审：独立批次 9ad9756b9a27418288ad9983d0da57af；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

alice 提交 message=<script>alert('XSS_BC93FB6A')</script> 后，留言列表 HTML 中直接出现 <div class="message-body"><script>alert('XSS_BC93FB6A')</script></div>（PAYLOAD_RAW_PRESENT True、PAYLOAD_ESCAPED_PRESENT False）。受害者 bob（独立会话、浏览自己的留言页）加载 /support/messages.php 时，浏览器实际弹出对话框，dialogs 记录为 XSS_BC93FB6A，页面正文还可见 alice 的普通留言文本。攻击脚本由服务端存储并在另一用户的浏览器中执行，构成存储型 XSS。

- 评分依据：CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：输出 message 时使用 h($row['message']) 转义，或在存储时统一编码。

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

### C-04 catalog/greeting.php 的 name 参数未经转义直接回显导致反射型 XSS

- 当前版本：finding `20966dec508f4d548b87236cef766951` revision 1（项目版本 18）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/catalog/greeting.php:3`；文件：`lab30-shop/app/public/catalog/greeting.php`
- 证据引用：`b06ddb554b7c114a` lab30-shop/app/public/catalog/greeting.php:1-3；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10；`ae2713ba84d306b9` lab30-shop/app/src/bootstrap.php:47-60
- 根因类别：task_goal:v2:33166578112e2fa11ba9:1（规范类型 xss_r）

**结论陈述（模型产出，不是证据）**

greeting.php 第2行从 $_GET['name'] 读取攻击者可控值，第3行在 page() 的 HTML 正文闭包中直接字符串拼接回显到 <h2> 内，未调用 bootstrap.php:10 定义的 h()。攻击者可传入 HTML/脚本载荷，在受害者浏览器中以站点同源执行脚本，导致会话或页面数据被读取、可发起同源操作。

- 攻击前身份与适用前提：无需登录，访问 /catalog/greeting.php?name=<payload>，受害者点击该链接
- 入口 → 传播 → 危险操作/状态变更：$_GET['name'] → $name=(string)($_GET['name']??'拾光的朋友') 传入 page() 回调闭包 use($name)，在 echo '<section...<h2>你好，'.$name.'</h2>' 处拼接输出 → HTML 正文中未编码回显用户输入
- 防护与边界：无：未使用 h()/htmlspecialchars，bootstrap 的 page() 仅转义标题与导航等固定字段，不处理闭包内输出
- 静态判读：证据已记录
- 动态验证：动态确认（verification `2fecb90fab3d495a8c2b0dbd0986e953`）
- 正式终审：独立批次 9ad9756b9a27418288ad9983d0da57af；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

job 65742a6f5a234a5e8671951eae75e07a：同一 guest 身份加载 /catalog/greeting.php?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E，dialogs 为 ["1"]（alert(1) 实际执行），body_text 中 h2 只剩「你好，」说明 <script> 被浏览器当作标签解析执行而非文本显示。

- 评分依据：CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 h($name) 输出，或在模板中统一采用自动转义；对 name 长度与字符集做限制。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/catalog/greeting.php:1-3`（sha256 `8e6db315fdfc32cf…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$name=(string)($_GET['name']??'拾光的朋友');
    3  page('到店欢迎',function()use($name){echo '<section class="panel"><h2>你好，'.$name.'</h2><p>愿今天也有值得期待的小事。</p><form method="get">';form_input('name','你的称呼');echo '<button>生成欢迎信息</button></form></section>';},'商品目录');
```

`lab30-shop/app/src/bootstrap.php:10-10`（sha256 `2050819d093be02b…`）

```php
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

`lab30-shop/app/src/bootstrap.php:47-60`（sha256 `2050819d093be02b…`）

```php
   47  function page(string $title, callable $body, string $section = ''): void {
   48      db();
   49      $u = user();
   50      header('Content-Type: text/html; charset=utf-8');
   51      echo '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>' . h($title) . ' · 拾光商城</title><meta name="theme-color" content="#1b573f"><link rel="stylesheet" href="/assets/app.css"><script src="/assets/app.js" defer></script></head><body><div class="shell"><aside><a class="brand" href="/"><span>拾</span><div>拾光商城<small>SHIGUANG COMMERCE</small></div></a><nav>';
   52      $nav = ['/' => '工作台', '/catalog/index.php' => '商品目录', '/orders/index.php' => '订单中心', '/wallet/index.php' => '我的钱包', '/account/index.php' => '账户与会员', '/support/index.php' => '客服与帮助', '/content/page.php' => '内容中心', '/ops/index.php' => '运营工作台'];
   53      if (!$u || !in_array($u['role'], ['operator','admin'], true)) unset($nav['/ops/index.php']);
   54      foreach ($nav as $url => $label) echo '<a ' . ($section === $label ? 'class="active" ' : '') . 'href="' . $url . '">' . $label . '</a>';
   55      echo '</nav><div class="side-bottom">本地演示商城<small>数据可通过重置命令恢复</small></div></aside><main><header class="topbar"><a class="mobile-brand" href="/">拾光商城</a><span>商城工作空间 / ' . h($title) . '</span><div>';
   56      if ($u) echo '<span>' . h($u['display_name']) . '</span><a href="/account/index.php">我的账户</a><a href="/auth/logout.php">退出</a>';
   57      else echo '<a href="/auth/login.php">登录</a><a href="/auth/register.php">注册</a>';
   58      echo '</div></header><div class="content"><div class="page-heading"><span class="eyebrow">SHIGUANG WORKSPACE</span><h1>' . h($title) . '</h1></div>';
   59      $body();
   60      echo '</div><footer>拾光商城 · 会员、订单与运营协作平台 <span>版本 ' . h(trim(file_get_contents(APP_ROOT . '/VERSION'))) . '</span></footer></main></div></body></html>';
```

### C-05 运营会员查询 $_GET['q'] 拼接进 LIKE，跨文件 SQL 注入

- 当前版本：finding `f9d93c1f0f134a948bfbfae9a4220822` revision 1（项目版本 3）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/member_lookup.php:3`；文件：`lab30-shop/app/public/ops/members.php`
- 证据引用：`12d724d86e16c5f7` lab30-shop/app/public/ops/members.php:1-4；`4d2f2da581629f05` lab30-shop/app/src/member_lookup.php:1-4；`85b2e45ff4e8d0eb` lab30-shop/app/src/bootstrap.php:4-8；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:403ac282e292cf41dd92:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

member_lookup() 在第3行把 $term 直接拼进 SQL 字符串；ops/members.php:2 将 $_GET['q'] 传入该函数，无任何过滤或参数化。攻击者以 operator/admin 登录后，可通过 q 注入 UNION 或布尔条件读取任意表。members.php:3 在 Accept: application/json 时直接返回查询结果，便于带外/直接取数。

- 攻击前身份与适用前提：攻击者需持有 operator 或 admin 会话；通过 /ops/members.php?q=... 访问，或加 Accept: application/json 获取 JSON 结果
- 入口 → 传播 → 危险操作/状态变更：$_GET['q']（ops/members.php:2） → members.php:2 $term=(string)($_GET['q']??'alice') -> member_lookup($term) -> member_lookup.php:3 字符串拼接 → db()->query("SELECT ... WHERE username LIKE '%" . $term . "%'")
- 防护与边界：无参数化、无转义；require_user 仅做角色校验，不处理 q
- 静态判读：证据已记录
- 动态验证：动态确认（verification `42e81052cb814bfea750043cb5264f04`）
- 正式终审：独立批次 9ad9756b9a27418288ad9983d0da57af；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 operator 会话请求 /ops/members.php?q=%25%27%20OR%20%271%27%3D%271%27%20--%20（Accept: application/json）：HTTP 200，members 返回 4 行——alice/customer、bob/customer、operator/operator、admin/admin，SQL 的 LIKE 条件被 OR 恒真条件与 -- 注释闭合，越权返回全部会员及角色。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改为参数化查询：$stmt=db()->prepare('SELECT id,username,email,role FROM users WHERE username LIKE ?'); $stmt->execute(['%'.$term.'%']); return $stmt->fetchAll();

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/members.php:1-4`（sha256 `aef140c3800b9cf1…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/member_lookup.php';require_user(['operator','admin']);$term=(string)($_GET['q']??'alice');$rows=member_lookup($term);
    3  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['members'=>$rows]);
    4  page('会员查询',function()use($rows,$term){echo '<section class="panel"><form method="get">';form_input('q','会员名',$term);echo '<button>查询会员</button></form><table><thead><tr><th>编号</th><th>用户名</th><th>邮箱</th><th>角色</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['id']).'</td><td>'.h($r['username']).'</td><td>'.h($r['email']).'</td><td>'.h($r['role']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
```

`lab30-shop/app/src/member_lookup.php:1-4`（sha256 `eb704332329d4530…`）

```php
    1  <?php
    2  function member_lookup(string $term): array {
    3      return db()->query("SELECT id,username,email,role FROM users WHERE username LIKE '%" . $term . "%'")->fetchAll();
    4  }
```

`lab30-shop/app/src/bootstrap.php:4-8`（sha256 `2050819d093be02b…`）

```php
    4  function db(): PDO {
    5      static $pdo;
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    7      return $pdo;
    8  }
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-06 wallet/withdraw.php 余额读取与更新非原子，配合 usleep 与 session_write_close 可并发重复提现

- 当前版本：finding `6292c426c920455d84e7b13975afafa8` revision 1（项目版本 27）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/wallet/withdraw.php:7`；文件：`lab30-shop/app/public/wallet/withdraw.php`
- 证据引用：`713c1c83b1f33981` lab30-shop/app/public/wallet/withdraw.php:2-11
- 根因类别：task_goal:v2:c223d9c70ecd82f4c614:1（规范类型 race_condition）

**结论陈述（模型产出，不是证据）**

withdraw.php 先 SELECT balance（第4行），在第6行 usleep(350000) 后才 UPDATE users SET balance=?（第7行），而第3行 session_write_close() 已释放会话锁，check_csrf 后窗口内多次并发 POST 都以同一旧余额通过第5行比较，各自写入 balance-amount 并 INSERT withdrawals，造成重复提现/余额被覆盖失真。

- 攻击前身份与适用前提：已登录用户，持有有效 csrf token，并发或快速重复提交多笔提现
- 入口 → 传播 → 危险操作/状态变更：POST amount（攻击者控制提现金额与并发次数） → amount -> 第4行读 balance -> 第5行比较 -> 第6行 sleep -> 第7行覆盖 balance -> 第8行插入 withdrawals → UPDATE users SET balance=? 与 INSERT INTO withdrawals 在同一过期余额快照下重复执行
- 防护与边界：第2行金额校验、第3行 session_write_close、check_csrf 只防伪造请求，未防并发；缺少事务/行锁/条件更新
- 静态判读：缺上下文（1 项）；缺失上下文：read_source 调用失败：FileNotFoundError: Source file does not exist in snapshot。先用 find_files 或 list_tree 核对快照实际路径；这只表示该路径缺失，不表示代码安全。
- 动态验证：动态确认（verification `d8ebc3c8b7c44603a41f50313505eb28`）
- 正式终审：独立批次 913c4cd4d7ea42efaab5142af6eb963f；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 alice 会话、同一 csrf，在余额 90.00 时以 Barrier 同时发起 6 个 POST /wallet/withdraw.php（amount=90，Accept: application/json）。6 个请求全部 status=200 且均返回 {"status":"paid","amount":90,"balance":0,"receipt_id":2..7}，耗时统一约 0.357s（正好落在源码 usleep(350000) 窗口内），即全部以同一过期余额快照通过第 5 行比较并各自落库。GET /wallet/index.php 显示可用余额 ¥0.00、提现记录 7 条，资金流水列出 6 笔 ¥90.00（流水号 2-7）加 1 笔 ¥10.00（流水号 1）。合计提现 550.00 元，而账户初始仅 100.00 元，实际只应成交 10 元那一笔；凭空多出 450.00 元的成功提现。

- 评分依据：CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：在事务中使用 SELECT ... FOR UPDATE 或原子条件更新 UPDATE users SET balance=balance-? WHERE id=? AND balance>=?，并检查影响行数；withdrawals 插入与被扣减同事务；去掉可放大窗口的 usleep。

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

### C-07 订单详情接口按订单 id 查询未校验归属，任意登录用户可越权读取他人订单

- 当前版本：finding `907de1688e454a18a57c6db4886f47e9` revision 1（项目版本 32）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/detail.php:2`；文件：`lab30-shop/app/public/orders/detail.php`
- 证据引用：`171ea369e07c383b` lab30-shop/app/public/orders/detail.php:1-4；`1b8e73c49d79d5d1` lab30-shop/app/public/orders/index.php:1-3；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37；`5f912f7499e51381` lab30-shop/app/public/auth/login.php:3-9
- 根因类别：task_goal:v2:38f0d54d799e0de18adf:1（规范类型 idor）

**结论陈述（模型产出，不是证据）**

orders/detail.php 只调用 require_user() 建立登录状态，未取当前用户 id 参与查询条件。第 2 行执行的 SQL 为 'SELECT o.*,u.username,p.name FROM orders o JOIN users u ON u.id=o.user_id LEFT JOIN products p ON p.id=o.product_id WHERE o.id=?'，唯一条件来自客户端 $_GET['id']，与当前会话用户无关，返回订单行后不比对 $o['user_id'] 与 $u['id']。第 4 行将 order_no、购买人 username、数量、实付金额 total、配送备注 private_note 输出到页面；第 3 行当请求头 Accept 包含 application/json 时用 json_response($o) 返回整个订单行。因此任意已登录用户只需递增 id 即可读取全站他人订单的订单号、金额与私密备注，构成水平越权（IDOR）。对比 orders/index.php 第 2 行使用 WHERE user_id=? 绑定 $u['id']，说明归属过滤在执行层可落实而此处缺失。

- 攻击前身份与适用前提：攻击者持任意有效普通用户账户（如自助注册）并已登录，可通过 GET /orders/detail.php?id=N 遍历订单 id；无需 CSRF token
- 入口 → 传播 → 危险操作/状态变更：$_GET['id']（订单自增 id，攻击者完全可控） → detail.php:2 $_GET['id'] -> $q->execute([...]) 按 o.id 查询 -> $o=$q->fetch() -> detail.php:4 渲染 order_no/username/total/private_note；或 detail.php:3 json_response($o) 输出整行 → 按客户端提供的主键读取他人订单记录并返回订单号、购买人、金额、私密备注
- 防护与边界：require_user() 仅校验登录（bootstrap.php:33-37 只在无会话时 401），未做对象归属或角色校验；SQL 使用占位符但条件不包含当前用户，prepare 无法阻止越权读取
- 静态判读：证据已记录
- 动态验证：动态确认（verification `df197aa7c03c491aaff6d68d26d4bfbd`）
- 正式终审：独立批次 1939f9a0952b4544b198bb5b0fa49fc0；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 alice 会话请求 GET /orders/detail.php?id=2（订单属于 user_id=2 的 bob）：JSON 模式返回 200 与 {"id":2,"order_no":"SG-1002","user_id":2,...,"total":"158.00","private_note":"BOB_PRIVATE_ORDER_gift_for_family","username":"bob"}；HTML 模式同样 200，页面渲染「等待配送 SG-1002 / 商品 山野帆布包 / 购买人 bob / 数量 2 / 实付金额 ¥158.00 / 配送备注 BOB_PRIVATE_ORDER_gift_for_family」。alice 的订单中心只列出自己的 SG-1001，却可通过修改 id 读取 bob 的订单号、金额与私密备注。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：在查询中加入归属条件 WHERE o.id=? AND o.user_id=? 并绑定 $u['id']（或读取后强制比对 $o['user_id'] !== $u['id'] 时返回 403/404），operator/admin 若需查看全部订单应走独立带角色校验的接口。

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

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
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

### C-08 注册/登录使用无盐 md5 存储与校验口令

- 当前版本：finding `10078f1ecd984a7982f4adba159aadde` revision 1（项目版本 8）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/register.php:8`；文件：`lab30-shop/app/public/auth/register.php`
- 证据引用：`9c57c102cf1e7731` lab30-shop/app/public/auth/register.php:6-8；`1d3eb2d6e3bdc9fc` lab30-shop/app/public/auth/login.php:6-7；`f86e0ebf4243b153` lab30-shop/app/src/setup.php:7-7
- 根因类别：task_goal:v2:66c0feec2e5166936c3d:1（规范类型 weak_crypto）

**结论陈述（模型产出，不是证据）**

register.php 以 md5($password) 写入 password_md5 列，login.php 用 hash_equals 比对 md5 摘要。使用无盐、快速哈希存储口令，数据库或哈希泄露后可用彩虹表/GPU 暴力快速还原明文；且长度仅校验 8 位，无强度约束。未使用 password_hash/password_verify。

- 攻击前身份与适用前提：需先取得 password_md5 哈希（数据库泄露或其他读取渠道）
- 入口 → 传播 → 危险操作/状态变更：注册/登录表单 password 参数 → $_POST['password'] -> md5() -> password_md5 列；登录时 md5() 与库中摘要 hash_equals 比较 → md5() 口令哈希存储
- 防护与边界：login 使用 hash_equals 防时序攻击，但哈希算法本身不安全
- 静态判读：证据已记录
- 动态验证：动态确认（verification `0cf388a8bf6442a3be8fddd9ac090728`）
- 正式终审：独立批次 c07c8b5c8c7a43e0a2f3b43020579bb5；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

通过运营侧 SQL 注入点（同一作业内，operator 会话，q 为 UNION 查询 users.password_md5）读取该新账号存储的口令摘要：row: id=5, username=wc26849953, email 字段=4e42bdc04f1fdc145c553a18ddf8e06d；本地计算 md5("PocPass123!")=4e42bdc04f1fdc145c553a18ddf8e06d，两者完全相等，HASH_IS_MD5_OF_PASSWORD True，长度 32 且非 $2 前缀。说明库中 password_md5 就是无盐、单轮 MD5(明文)，一旦摘要泄露即可用彩虹表/GPU 快速还原。

- 评分依据：CVSS 3.1 Base 5.9 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 password_hash($password, PASSWORD_DEFAULT) 存储，登录用 password_verify 校验，并对存量 md5 在下次登录时迁移。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/auth/register.php:6-8`（sha256 `99166a0288be7b1e…`）

```php
    6      if(!preg_match('/^[a-zA-Z][a-zA-Z0-9_]{2,39}$/D',$name)||strlen($password)<8) fail_request('用户名需为 3–40 位字母数字，密码至少 8 位。');
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

### C-09 下单接口信任客户端 price 字段，单价与总价可被篡改为任意非负值

- 当前版本：finding `9dc01b5fc875445496274debba22d73d` revision 1（项目版本 33）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/create.php:5`；文件：`lab30-shop/app/public/orders/create.php`
- 证据引用：`e4ba0faa7c0831b2` lab30-shop/app/public/orders/create.php:3-7；`dc0b10bf76499d4d` lab30-shop/app/public/catalog/detail.php:3-3；`3bf12e4330602249` lab30-shop/app/src/setup.php:9-9
- 根因类别：task_goal:v2:4b062e489e99bb1ad99b:1（规范类型 price_manipulation）

**结论陈述（模型产出，不是证据）**

orders/create.php 第 3 行从 $_POST['price'] 取值，仅用 FILTER_VALIDATE_FLOAT 与 $price<0 检查，第 5 行以 round($price*$quantity,2) 计算总额，第 7 行把该单价与总额原样 INSERT 进 orders 的 unit_price/total。商品真实价格来自 products 表（catalog/detail.php 第 3 行仅把价格作为隐藏表单字段回传），服务端从未用 $p['price'] 校验或替换客户端单价，因此攻击者可提交 0.01 之类的价格完成低价购买。库存扣减和事件日志都基于该被篡改金额。

- 攻击前身份与适用前提：任意已登录普通用户；需携带有效 CSRF token（可自行打开 /catalog/detail.php 获取）
- 入口 → 传播 → 危险操作/状态变更：POST /orders/create.php 的 price 与 quantity 参数 → create.php:3 $_POST['price'] -> filter_var FLOAT -> create.php:5 $total=round($price*$quantity,2) -> create.php:7 INSERT orders(unit_price,total) → 以客户端单价计算并持久化订单金额（orders.unit_price/total），同时扣减库存
- 防护与边界：仅 FILTER_VALIDATE_FLOAT 与 $price<0 下限检查，缺少与 products.price 的一致性校验或服务端重新取价
- 静态判读：证据已记录
- 动态验证：动态确认（verification `4923efcca7f2434398c12bdd0eae7cab`）
- 正式终审：独立批次 c07c8b5c8c7a43e0a2f3b43020579bb5；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 alice 会话、同一 csrf 与商品 id=1（真实单价 129.00），只把 price 改为 0.01、quantity=2 提交 /orders/create.php：返回 303 Location /orders/detail.php?id=7，订单详情显示「商品 晨光手冲壶、购买人 alice、数量 2、实付金额 ¥0.02」。即 2 件共 ¥258 的商品按 ¥0.02 成交，客户端单价被原样持久化并参与总额计算（0.01×2=0.02）。宿主先前同一会话的正常订单（id=3）与攻击订单（id=4）也均为 200 且攻击订单详情含 0.01。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：服务端用 $p['price'] 作为唯一单价来源，忽略客户端 price；如需支持促销价，使用服务端白名单/活动表校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/orders/create.php:3-7`（sha256 `41e73625d7e04c58…`）

```php
    3  $q=db()->prepare('SELECT * FROM products WHERE id=?');$q->execute([$_POST['product_id']??0]);$p=$q->fetch();$quantity=filter_var($_POST['quantity']??0,FILTER_VALIDATE_INT);$price=filter_var($_POST['price']??null,FILTER_VALIDATE_FLOAT);
    4  if(!$p||!$quantity||$quantity<1||$quantity>20||$price===false||$price<0)fail_request('商品、数量或价格不正确。');
    5  $total=round($price*$quantity,2);$pdo=db();$pdo->beginTransaction();
    6  $q=$pdo->prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?');$q->execute([$quantity,$p['id'],$quantity]);if(!$q->rowCount()){$pdo->rollBack();fail_request('商品库存不足。',409);}
    7  $q=$pdo->prepare('INSERT INTO orders(order_no,user_id,product_id,quantity,unit_price,total,private_note) VALUES(?,?,?,?,?,?,?)');$q->execute(['SG-'.bin2hex(random_bytes(5)),$u['id'],$p['id'],$quantity,$price,$total,'会员订单，等待发货']);$id=(int)$pdo->lastInsertId();$pdo->commit();event_log('create_order',['order_id'=>$id,'total'=>$total]);header('Location: /orders/detail.php?id='.$id, true,303);
```

`lab30-shop/app/public/catalog/detail.php:3-3`（sha256 `daccd22134a2224d…`）

```php
    3  page($p['name'],function()use($p){echo '<div class="product-detail"><div class="product-art '.h($p['color']).'"><svg viewBox="0 0 240 220" role="img" aria-label="'.h($p['name']).'"><use href="/assets/products.svg#product-'.(int)$p['id'].'"></use></svg></div><section class="panel"><h2>'.h($p['name']).'</h2><p>'.h($p['description']).'</p><h2>¥'.h($p['price']).'</h2><p class="muted">库存 '.(int)$p['stock'].' 件</p><form action="/orders/create.php" method="post"><input type="hidden" name="product_id" value="'.(int)$p['id'].'"><input type="hidden" name="price" value="'.h($p['price']).'">'.csrf_field();echo '<label>购买数量<input type="number" name="quantity" value="1" min="1" max="20" required></label>';echo '<button>立即购买</button></form></section></div>';},'商品目录');
```

`lab30-shop/app/src/setup.php:9-9`（sha256 `53e7dc7286d7d370…`）

```php
    9      $pdo->exec("CREATE TABLE IF NOT EXISTS orders(id INT PRIMARY KEY AUTO_INCREMENT, order_no VARCHAR(60), user_id INT, product_id INT, quantity INT, unit_price DECIMAL(12,2), total DECIMAL(12,2), private_note TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
```

### C-10 auth/continue.php next 参数未校验导致登录后开放重定向

- 当前版本：finding `60dbc457afba403b9467566a0d2b58c6` revision 1（项目版本 23）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/continue.php:3`；文件：`lab30-shop/app/public/auth/continue.php`
- 证据引用：`3d07985381125c49` lab30-shop/app/public/auth/continue.php:1-4；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:cb7c6d010ca4fba5f359:1（规范类型 open_redirect）

**结论陈述（模型产出，不是证据）**

continue.php 第2行仅调用 require_user 要求登录，第3行在收到 GET next 时直接执行 header('Location: '.(string)$_GET['next'])，没有任何主机、协议或路径白名单校验。攻击者可构造 /auth/continue.php?next=https://attacker.example/ 诱导已登录用户点击，浏览器被重定向到攻击者站点，可用于钓鱼或凭据诱导。

- 攻击前身份与适用前提：受害者已登录并访问 attacker 提供的 continue.php?next= 链接
- 入口 → 传播 → 危险操作/状态变更：GET 参数 next → $_GET['next'] -> (string) -> header('Location: ...') → header('Location: '.(string)$_GET['next']) 跳转到任意外部 URL
- 防护与边界：无白名单、无 URL 解析、无相对路径限制；require_user 只做登录校验
- 静态判读：缺上下文（1 项）；缺失上下文：未发现 reset_session/登录后 session_regenerate_id 调用；login.php:8 直接写入 user_id，配合 bootstrap.php:13-18 的 use_strict_mode=0 与 sid 采用，会话固定风险实为已存在的 candidate（start_session 处），本工作项未重复提交。
- 动态验证：动态确认（verification `aa926fda9c454659bf0b7678fdef333c`）
- 正式终审：独立批次 c07c8b5c8c7a43e0a2f3b43020579bb5；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

登录态下访问 /auth/continue.php?next=https://attacker.example/phish，服务端返回 302 且 Location: https://attacker.example/phish；再以协议相对形式 //attacker.example/phish 请求，Location 同样为 //attacker.example/phish。外部主机未被拒绝、未做白名单或 URL 解析校验，响应头原文直接回显攻击者控制的跳转目标，构成开放重定向。

- 评分依据：CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：仅允许相对路径或固定站点内白名单；解析 URL 拒绝外部主机与 //、javascript: 等协议。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/auth/continue.php:1-4`（sha256 `50fde4a15e52af44…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();
    3  if(isset($_GET['next'])){header('Location: '.(string)$_GET['next']);exit;}
    4  page('继续访问',function(){echo '<section class="panel"><h2>选择下一站</h2><form method="get">';form_input('next','继续访问地址','/orders/index.php');echo '<button>继续</button></form></section>';});
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-11 content/page.php 的 page 参数未经净化拼入 include，导致路径遍历与本地/远程文件包含

- 当前版本：finding `21722ca9ff6a4e6e829697ca77a80770` revision 1（项目版本 31）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/content/page.php:3`；文件：`lab30-shop/app/public/content/page.php`
- 证据引用：`173f24f6297d9164` lab30-shop/app/public/content/page.php:1-3；`440a0f38753d4516` lab30-shop/app/src/bootstrap.php:9-10；`fdf51798a6541ca7` lab30-shop/app/src/bootstrap.php:47-59；`0eb39a1944a68011` lab30-shop/app/src/setup.php:34-38；`60b3d11fb6b16011` lab30-shop/docker/php.ini:3-3
- 根因类别：task_goal:v2:5b0e359384ad3b738547:1（规范类型 lfi）

**结论陈述（模型产出，不是证据）**

page.php 第2行 $name=(string)($_GET['page']??'home')，第3行 include APP_ROOT.'/resources/views/'.$name.'.php'。前缀固定为 resources/views 目录、后缀固定 .php，但完全未过滤 ../、斜杠或协议，既无白名单也无 realpath/basename 校验，故可用 page=../vault/account 跳出 views 目录包含任意 .php；docker/php.ini 开启 allow_url_include，配合 allow_url_include=On 可通过 php:// 或 http:// 协议包装。setup.php:34-38 证明存在含可执行 PHP 的 vault/account.php 与 vault/internal.txt，前者可被包含执行，后者因强制追加 .php 只能通过协议包装或截断手段读取。公开访问，无需登录。

- 攻击前身份与适用前提：content/page.php 可公开访问；可包含目标路径存在（vault/account.php 由 setup.php 生成）；协议包装需 allow_url_include=On（配置已开启）
- 入口 → 传播 → 危险操作/状态变更：GET 参数 page（$_GET['page']），公开可访问 → page.php:2 赋值 $name -> page.php:3 闭包内 include APP_ROOT.'/resources/views/'.$name.'.php' → include 动态拼接的用户可控路径（本地/远程文件包含）
- 防护与边界：无：未使用 basename、realpath、白名单、str_replace('..')；仅固定前缀目录与 .php 后缀，可被 ../ 与协议包装绕过
- 静态判读：缺上下文（2 项）；缺失上下文：resources/views 目录下除 home.php、shipping.php 外的其他模板文件未在快照上下文中列出，无法完全枚举可被 page 参数直接包含的合法模板范围；未读取 docker/php.ini 完整内容（仅见 allow_url_include=On 一行），无法确认 allow_url_fopen 等协议包装相关配置是否全部允许
- 动态验证：动态确认（verification `dccfee757e234b03a3b16bf9f79c99c5`）
- 正式终审：独立批次 ca6a6875191748cb9964da890ff6924f；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

匿名 guest 请求 /content/page.php?page=../../../../lib/shop/vault/account（另 ../../../../../var/lib/shop/vault/account、../../../../../../var/lib/shop/vault/account 同样命中）：HTTP 200，页面中出现 vault/account.php 执行结果 SHOP_INTERNAL_9ee02d854bf1b6156e492647；逐级对照中前缀深度不足的路径（如 ../vault/account、../../../lib/shop/vault/account）marker=False，说明是穿越到 views 目录之外的 /var/lib/shop/vault/account.php 并被 include 执行，而非正常模板。

- 评分依据：CVSS 3.1 Base 9.4 (critical) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：将 page 参数映射到白名单键（如 home/shipping），或用 basename 过滤并 realpath 校验前缀属于 resources/views；关闭 allow_url_include。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/content/page.php:1-3`（sha256 `53c5997117f2d54c…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$name=(string)($_GET['page']??'home');
    3  page('内容中心',function()use($name){include APP_ROOT.'/resources/views/'.$name.'.php';echo '<section class="panel"><a href="?page=home">商城介绍</a> · <a href="?page=shipping">配送与售后</a></section>';},'内容中心');
```

`lab30-shop/app/src/bootstrap.php:9-10`（sha256 `2050819d093be02b…`）

```php
    9  function data_dir(): string { return getenv('SHOP_DATA_DIR') ?: '/var/lib/shop'; }
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

`lab30-shop/app/src/bootstrap.php:47-59`（sha256 `2050819d093be02b…`）

```php
   47  function page(string $title, callable $body, string $section = ''): void {
   48      db();
   49      $u = user();
   50      header('Content-Type: text/html; charset=utf-8');
   51      echo '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>' . h($title) . ' · 拾光商城</title><meta name="theme-color" content="#1b573f"><link rel="stylesheet" href="/assets/app.css"><script src="/assets/app.js" defer></script></head><body><div class="shell"><aside><a class="brand" href="/"><span>拾</span><div>拾光商城<small>SHIGUANG COMMERCE</small></div></a><nav>';
   52      $nav = ['/' => '工作台', '/catalog/index.php' => '商品目录', '/orders/index.php' => '订单中心', '/wallet/index.php' => '我的钱包', '/account/index.php' => '账户与会员', '/support/index.php' => '客服与帮助', '/content/page.php' => '内容中心', '/ops/index.php' => '运营工作台'];
   53      if (!$u || !in_array($u['role'], ['operator','admin'], true)) unset($nav['/ops/index.php']);
   54      foreach ($nav as $url => $label) echo '<a ' . ($section === $label ? 'class="active" ' : '') . 'href="' . $url . '">' . $label . '</a>';
   55      echo '</nav><div class="side-bottom">本地演示商城<small>数据可通过重置命令恢复</small></div></aside><main><header class="topbar"><a class="mobile-brand" href="/">拾光商城</a><span>商城工作空间 / ' . h($title) . '</span><div>';
   56      if ($u) echo '<span>' . h($u['display_name']) . '</span><a href="/account/index.php">我的账户</a><a href="/auth/logout.php">退出</a>';
   57      else echo '<a href="/auth/login.php">登录</a><a href="/auth/register.php">注册</a>';
   58      echo '</div></header><div class="content"><div class="page-heading"><span class="eyebrow">SHIGUANG WORKSPACE</span><h1>' . h($title) . '</h1></div>';
   59      $body();
```

`lab30-shop/app/src/setup.php:34-38`（sha256 `53e7dc7286d7d370…`）

```php
   34      file_put_contents("$root/vault/internal.txt",$marker . "\n");
   35      file_put_contents("$root/vault/account.php",'<?php echo "' . $marker . '";');
   36      file_put_contents("$root/docs/shipping.txt","配送说明：工作日 48 小时内发货。\n");
   37      file_put_contents("$root/docs/returns.txt","售后说明：签收后七天内可申请退货。\n");
   38      file_put_contents("$root/messages/readme.txt","客服文件区\n");
```

`lab30-shop/docker/php.ini:3-3`（sha256 `b65de9007c7f42b3…`）

```
    3  allow_url_include = On
```

### C-12 商品搜索 q 参数拼接 SQL 导致注入（catalog/index.php）

- 当前版本：finding `5c7ff87a89fa404281d1674556896450` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/catalog/index.php:4`；文件：`lab30-shop/app/public/catalog/index.php`
- 证据引用：`b07638e22476de42` lab30-shop/app/public/catalog/index.php:3-5；`85b2e45ff4e8d0eb` lab30-shop/app/src/bootstrap.php:4-8；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10
- 根因类别：task_goal:v2:45ccf157328295340868:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

index.php 第 3 行把 $_GET['q'] 转成字符串，第 4 行以 "... WHERE name LIKE '%".$term."%' ORDER BY id" 方式直接拼接进 db()->query()，未使用 prepare/占位符也未做任何转义，攻击者可通过 q 闭合引号注入任意 SQL（如 UNION 读取 users 表或布尔/时间盲注）。输出端第 5 行用 h() 转义，故不构成 XSS。

- 攻击前身份与适用前提：目录页无需登录即可访问，攻击者直接请求 /catalog/index.php?q=...
- 入口 → 传播 → 危险操作/状态变更：HTTP GET 参数 q（catalog/index.php 第 3 行 $_GET['q']） → $term -> 字符串拼接进 SQL -> db()->query() 直接执行（catalog/index.php:4） → PDO::query 执行含用户输入的 SELECT，返回集被渲染到目录页
- 防护与边界：无：未使用参数化查询，未调用 quote/转义；h() 只作用于输出非 SQL
- 静态判读：证据已记录
- 动态验证：动态确认（verification `2418fd4001d54bbbbb336d2c044fa96c`）
- 正式终审：独立批次 8170fc6ae59f4e75b5658e143d5b1fdd；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

guest 未登录直接请求 /catalog/index.php?q=%27%20UNION%20SELECT%20id,username,role,balance,tier,%27x%27%20FROM%20users--%20- 返回 200，页面从 4 件商品变为 8 条结果，新增 4 行来自 users 表：alice/customer/100.00、bob/customer/100.00、operator/operator/100.00、admin/admin/100.00（商品名位置显示 username，描述位置显示 role，价格位置显示 balance，库存位置显示 tier）。另一请求 q=拾光' 触发 503「服务暂时不可用」错误页，说明单引号直接改变了 SQL 结构。攻击行不可能由 products 表产生，证明 q 参数被拼接执行任意 SELECT。

- 评分依据：CVSS 3.1 Base 8.2 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用预处理：$st=db()->prepare('SELECT ... WHERE name LIKE ? ORDER BY id'); $st->execute(['%'.$term.'%']); 并对输入长度做限制。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/catalog/index.php:3-5`（sha256 `e85bd1c2fa6a4b78…`）

```php
    3  $term=(string)($_GET['q']??'');
    4  $products=db()->query("SELECT id,name,description,price,stock,color FROM products WHERE name LIKE '%".$term."%' ORDER BY id")->fetchAll();
    5  page('本季好物',function()use($products,$term){echo '<form class="search-form" method="get"><input aria-label="搜索商品" name="q" placeholder="搜索你喜欢的好物" value="'.h($term).'"><button>搜索</button></form><p class="muted">共找到 <span id="result-count">'.count($products).'</span> 件商品</p><div class="products">';foreach($products as $p)echo '<article class="product"><div class="product-art '.h($p['color']).'"><svg viewBox="0 0 240 220" role="img" aria-label="'.h($p['name']).'"><use href="/assets/products.svg#product-'.(int)$p['id'].'"></use></svg></div><div class="product-copy"><small>拾光 · 日常系列</small><h2>'.h($p['name']).'</h2><p>'.h($p['description']).'</p><div class="row"><strong>¥'.h($p['price']).'</strong><a class="button secondary" href="/catalog/detail.php?id='.(int)$p['id'].'">查看商品 →</a></div></div></article>';echo '</div><a href="/catalog/greeting.php">查看到店欢迎信息</a>';},'商品目录');
```

`lab30-shop/app/src/bootstrap.php:4-8`（sha256 `2050819d093be02b…`）

```php
    4  function db(): PDO {
    5      static $pdo;
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    7      return $pdo;
    8  }
```

`lab30-shop/app/src/bootstrap.php:10-10`（sha256 `2050819d093be02b…`）

```php
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

### C-13 ops/xml-import.php 以 LIBXML_NOENT|LIBXML_DTDLOAD 解析请求 XML，导致 XXE 本地文件读取并回显

- 当前版本：finding `f32557d8e70f4a51b5831f8018091349` revision 1（项目版本 29）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/xml-import.php:3`；文件：`lab30-shop/app/public/ops/xml-import.php`
- 证据引用：`3d3d06e15daa2cd1` lab30-shop/app/public/ops/xml-import.php:1-4；`063c928d2d7c3b2e` lab30-shop/app/src/bootstrap.php:33-40；`38c5cad78d49b7f3` lab30-shop/docker/php.ini:1-13；`f621b844d17a50c0` lab30-shop/docker/apache.conf:1-12
- 根因类别：task_goal:v2:ae1bde621fab335ac02a:1（规范类型 xxe）

**结论陈述（模型产出，不是证据）**

行 3 直接对 $_POST['xml'] 调用 simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT&#124;LIBXML_DTDLOAD)（行 3），并只以 libxml_use_internal_errors(true) 抑制错误；该选项组合会加载 DTD 并替换外部实体。行 4 将解析出的 $doc->title 写入 <pre>，因此攻击者在 title 元素内放置 &ext; 实体引用时，实体展开后的本地文件内容（如 file:///etc/passwd）会随响应返回。CSRF 校验与 operator/admin 角色校验（行 2-3、bootstrap:33-40）是访问前提，不是 XXE 的防护——没有任何实体/DTD 限制。

- 攻击前身份与适用前提：攻击者持有 operator 或 admin 角色会话；先 GET /ops/xml-import.php 取得 csrf token 后 POST xml 参数
- 入口 → 传播 → 危险操作/状态变更：HTTP POST 表单字段 xml（$_POST['xml']） → 行 3 把 $_POST['xml'] 直接传给 simplexml_load_string，启用 LIBXML_NOENT&#124;LIBXML_DTDLOAD；解析结果 $doc->title 在行 4 拼入页面 <pre> 输出 → 带 LIBXML_NOENT&#124;LIBXML_DTDLOAD 的 simplexml_load_string 外部实体解析，结果回显到 HTTP 响应
- 防护与边界：仅有 require_user(['operator','admin']) 角色校验（bootstrap:33-36）与 hash_equals CSRF 校验（bootstrap:40）；未禁用外部实体、未过滤 DOCTYPE/ENTITY，也没有 libxml_set_external_entity_loader 限制
- 静态判读：证据已记录
- 动态验证：动态确认（verification `d78f219e97ef46939c32dbcd0f610bc8`）
- 正式终审：独立批次 8170fc6ae59f4e75b5658e143d5b1fdd；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 operator 会话使用同一 CSRF token POST /ops/xml-import.php，xml 为 <?xml version="1.0"?><!DOCTYPE config [<!ENTITY ext SYSTEM "file:///etc/passwd">]><config><title>&ext;</title></config>。HTTP 200，响应 <pre> 中回显 /etc/passwd 内容：root:x:0:0:root:/root:/bin/bash、daemon:x:1:1、www-data:x:33:33 等多行，ATTACK_HAS_ROOT=True，证明外部实体被实际解析并读取了本地文件。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：调用 simplexml_load_string 时不要传 LIBXML_NOENT/LIBXML_DTDLOAD，并显式禁止 DOCTYPE：解析前用 preg_match('/<!DOCTYPE/i',$xml) 拒绝含 DTD 的输入，或改用 LIBXML_NONET 并设置 libxml_set_external_entity_loader 返回 null；仅在业务需要时使用安全解析器。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/xml-import.php:1-4`（sha256 `3c23a76b1047f734…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$output='';$xml='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$xml=(string)($_POST['xml']??'');libxml_use_internal_errors(true);$doc=simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT|LIBXML_DTDLOAD);if(!$doc)fail_request('XML 格式不正确。');$output=(string)$doc->title;}
    4  page('合作方配置导入',function()use($output,$xml){echo '<section class="panel"><form method="post">'.csrf_field().'<label>XML 配置<textarea name="xml" required>'.h($xml?:'<config><title>春日上新</title></config>').'</textarea></label><button>导入配置</button></form><h2>导入结果</h2><pre>'.h($output).'</pre></section>';},'运营工作台');
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

`lab30-shop/docker/php.ini:1-13`（sha256 `b65de9007c7f42b3…`）

```
    1  date.timezone = Asia/Shanghai
    2  allow_url_fopen = On
    3  allow_url_include = On
    4  display_errors = Off
    5  log_errors = On
    6  error_reporting = E_ALL & ~E_DEPRECATED
    7  session.use_strict_mode = 0
    8  session.save_path = /var/lib/shop/sessions
    9  memory_limit = 128M
   10  post_max_size = 2M
   11  max_execution_time = 15
   12  default_socket_timeout = 4
   13  expose_php = Off
```

`lab30-shop/docker/apache.conf:1-12`（sha256 `6a49914efde0e75b…`）

```
    1  ServerName localhost
    2  <VirtualHost *:80>
    3      ServerName localhost
    4      DocumentRoot /var/www/shop/public
    5      <Directory /var/www/shop/public>
    6          Options -Indexes +FollowSymLinks
    7          AllowOverride None
    8          Require all granted
    9      </Directory>
   10      ErrorLog /proc/self/fd/2
   11      CustomLog /proc/self/fd/1 combined
   12  </VirtualHost>
```

### C-14 account/profile.php 的 url 参数未经转义进入 href 属性导致反射型 XSS

- 当前版本：finding `3d2ab8abc1e5475fb4ee565ef1570c2f` revision 1（项目版本 25）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/profile.php:3`；文件：`lab30-shop/app/public/account/profile.php`
- 证据引用：`4d94f1acccb7284b` lab30-shop/app/public/account/profile.php:1-3；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10；`1b8b2b99a1a47fee` lab30-shop/app/src/bootstrap.php:46-46
- 根因类别：task_goal:v2:c23bb6b958acbe1046c1:1（规范类型 xss_r）

**结论陈述（模型产出，不是证据）**

profile.php 第2行用 $_GET['url'] 覆盖 homepage 值，第3行将其拼入 <a href="...">，未调用 h()。双引号属性可被 " 闭合注入 onmouseover 等事件处理器，或使用 javascript: 伪协议；同页 form_input 对 $url 已调用 h()（bootstrap.php:46），说明转义函数存在但漏用于 href 输出点，构成反射型 XSS。页面无 Location 或客户端跳转，open redirect 不成立。

- 攻击前身份与适用前提：攻击者或受害者需已登录（require_user），访问 /account/profile.php?url=<payload> 并诱导点击
- 入口 → 传播 → 危险操作/状态变更：$_GET['url'] → $url=(string)($_GET['url']??$u['homepage']) 经 use($url) 进入 page 闭包，echo '<a id="profile-link" href="'.$url.'">' 拼接输出 → 双引号 HTML 属性中未编码回显用户输入
- 防护与边界：不足：仅 form_input 内部对 value 做 h() 转义，href 属性拼接未使用 h()
- 静态判读：证据已记录
- 动态验证：动态确认（verification `21351765b9534950b924d68ee68564bc`）
- 正式终审：独立批次 9bb2daaee8364ec38a6dcecc9d3f90b1；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

job a80438c9adb541f6a1d8cf1734808199：alice 会话加载 /account/profile.php?url=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E，browser dialogs 为 ["1"]，即注入的 <img onerror> 在同源页面执行 alert(1)；同时出现 404 资源加载失败（即 img src=x 的请求），body_text 中链接处显示残片「">访问个人主页」，说明双引号已闭合 href 属性并注入新标签。

- 评分依据：CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：在 href 中输出时使用 h($url)；对链接协议做白名单校验（仅 http/https），避免 javascript: 伪协议。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/profile.php:1-3`（sha256 `6f2406bbf636de04…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$url=(string)($_GET['url']??$u['homepage']);
    3  page('个人主页预览',function()use($u,$url){echo '<section class="panel"><h2>'.h($u['display_name']).' 的主页</h2><p><a id="profile-link" href="'.$url.'">访问个人主页</a></p><form method="get">';form_input('url','主页链接',$url);echo '<button>预览链接</button></form></section>';},'账户与会员');
```

`lab30-shop/app/src/bootstrap.php:10-10`（sha256 `2050819d093be02b…`）

```php
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

`lab30-shop/app/src/bootstrap.php:46-46`（sha256 `2050819d093be02b…`）

```php
   46  function form_input(string $name, string $label, string $value = '', string $type = 'text'): void { echo '<label>' . h($label) . '<input name="' . h($name) . '" type="' . h($type) . '" value="' . h($value) . '" required></label>'; }
```

### C-15 account/update.php 批量赋值允许任意用户修改 role/balance/tier

- 当前版本：finding `15250777c73d43b88defa26f1d264b08` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/update.php:5`；文件：`lab30-shop/app/public/account/update.php`
- 证据引用：`d55d34fdd0ba1160` lab30-shop/app/public/account/update.php:3-6；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:d372105975b87c589f9d:1（规范类型 mass_assignment）

**结论陈述（模型产出，不是证据）**

update.php 第 4 行把 role、balance、tier 放入允许更新的列数组，第 5 行遍历 $_POST 中命中列名的字段直接构造 SET 子句，第 6 行以当前用户 id 执行 UPDATE users。服务端只按登录身份定位行，未校验字段是否允许普通用户修改，也未对角色/余额做服务端取值约束。任意已登录用户 POST role=admin 或 balance=999999 即完成提权与余额篡改，随后 wallet/withdraw 可用伪造余额提现。

- 攻击前身份与适用前提：已登录任意用户，携带有效 csrf token
- 入口 → 传播 → 危险操作/状态变更：POST 参数 role、balance、tier、display_name 等 → $_POST -> columns 白名单 -> $set/$values -> UPDATE users SET ... WHERE id=? → UPDATE users 修改 role/balance/tier 敏感列
- 防护与边界：check_csrf 仅防 CSRF；require_user 仅校验登录；列白名单反而包含敏感列
- 静态判读：缺上下文（2 项）；缺失上下文：src 中除 bootstrap.php/backup.php 外的类定义未读取，无法确认反序列化 gadget 链；数据库事务隔离级别与 users 表锁行为未确认（静态推断为可竞态）
- 动态验证：动态确认（verification `548bd73efc3648a59b12ed6b1faf4a98`）
- 正式终审：独立批次 9bb2daaee8364ec38a6dcecc9d3f90b1；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 alice 会话、同一 csrf，POST display_name=Alice Normal&role=admin&balance=999999&tier=vip，响应 200，正文 {"id":1,...,"role":"admin","balance":"999999.00","tier":"vip",...}。随后 GET /account/update.php 返回的导航中出现 /ops/index.php「运营工作台」链接（源码中仅 operator/admin 显示），表单显示名称变为 Alice Normal。宿主 postcondition 记录 state_changes：balance 100.00→999999.00、role customer→admin、tier standard→vip。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：服务端白名单限定为 display_name/nickname/email/homepage；role/balance/tier 只能由受控后台流程修改，并对值做类型与范围校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/update.php:3-6`（sha256 `b8227f19c05d0cd3…`）

```php
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

### C-16 start_session 允许外部可控 SID 且未在登录后重生成，导致会话固定/劫持

- 当前版本：finding `16ccd319c0254152a39799e78fa53c57` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/bootstrap.php:17`；文件：`lab30-shop/app/src/bootstrap.php`
- 证据引用：`9f3b2a689fae3c12` lab30-shop/app/src/bootstrap.php:11-19；`785adf202a6701b2` lab30-shop/app/src/bootstrap.php:22-24；`368b0f4121e7e402` lab30-shop/app/public/auth/login.php:3-3；`6e01b773a001a844` lab30-shop/app/public/auth/login.php:8-8
- 根因类别：task_goal:v2:24d0557214df1ab07c3b:1（规范类型 session_fixation）

**结论陈述（模型产出，不是证据）**

start_session 关闭 session.use_strict_mode，并仅用正则校验后直接把外部传入的 sid 作为 session_id 使用，登录成功后也未调用 session_regenerate_id。auth/login.php:3 将 $_GET['sid'] 传入，攻击者可预先构造一个合法 SID 链接，受害者登录后该 SID 绑定其 user_id，攻击者复用同一 SID 即成为该用户。

- 攻击前身份与适用前提：受害者访问包含 sid 的登录链接并以任意账户登录
- 入口 → 传播 → 危险操作/状态变更：$_GET['sid']（auth/login.php:3），登录表单最终确认身份 → GET sid -> start_session($sid) -> 正则通过 -> session_id($sid) -> session_start(); 登录成功 $_SESSION['user_id'] 写入但不换 SID → session_id 采用客户端可控值 + 登录后不重生成会话 ID
- 防护与边界：仅有 /^[a-zA-Z0-9,-]{16,64}$/D 格式校验，该约束不能防止攻击者选择自己的 SID；use_strict_mode=0 也允许未初始化 SID 被接受
- 静态判读：证据已记录
- 动态验证：动态确认（verification `7b0fdade72a04551aa9bc73325b3af7d`）
- 正式终审：独立批次 c05062015fce42fdb838e28f31a066d1；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击者预先选定 SID=attackerfixedsid123456。受害者打开 /auth/login.php?sid=attackerfixedsid123456，响应 200 并回写 Set-Cookie: SHOPSESSID=attackerfixedsid123456（客户端可控值被接受）；携带该链接 POST 登录后，受害者 Cookie 仍为 SHOPSESSID=attackerfixedsid123456（VICTIM_SID_EQUALS_FIXED True），登录成功写入 $_SESSION['user_id'] 但 SID 未重生成。随后一个从未登录、仅带 Cookie: SHOPSESSID=attackerfixedsid123456 的独立客户端 GET /account/index.php 返回 200，页面显示「林晓 / 用户名 alice / alice@shop.local」及退出链接，GET /wallet/index.php 返回 200 且显示可用余额 ¥100.00，构成对 alice 账户的完整会话劫持。对照：使用未参与登录的随机 SID attackercontrolsid98765 访问同页面返回 401「请求未完成」，说明攻击成功并非未认证绕过，而是该 SID 已绑定受害者身份。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：启用 session.use_strict_mode=1；不从未经认证的请求参数设置 session_id；在 auth/login.php 认证成功后调用 session_regenerate_id(true)。

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

`lab30-shop/app/src/bootstrap.php:22-24`（sha256 `2050819d093be02b…`）

```php
   22      if (empty($_SESSION['user_id'])) return null;
   23      $q = db()->prepare('SELECT id,username,display_name,email,role,balance,tier,nickname,homepage FROM users WHERE id=?');
   24      $q->execute([$_SESSION['user_id']]); return $q->fetch() ?: null;
```

`lab30-shop/app/public/auth/login.php:3-3`（sha256 `b9be43ddb2233156…`）

```php
    3  start_session(isset($_GET['sid']) ? (string)$_GET['sid'] : null);
```

`lab30-shop/app/public/auth/login.php:8-8`（sha256 `b9be43ddb2233156…`）

```php
    8          $_SESSION['user_id']=(int)$row['id']; event_log('login');
```

### C-17 ops/users.php 以客户端 Cookie role 判定管理员，任意登录用户可冒充 admin 读取全部用户邮箱与角色

- 当前版本：finding `ec6cdc0fe29741aebf7dc60ec5aab87a` revision 1（项目版本 28）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/users.php:2`；文件：`lab30-shop/app/public/ops/users.php`
- 证据引用：`0ad2a840edc3f2e0` lab30-shop/app/public/ops/users.php:1-5；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:2e59e173691b3883e027:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

users.php:2 先 require_user() 只校验登录，然后用 $role=(string)($_COOKIE['role']??$u['role']) 后再 if($role!=='admin') 判权。客户端 Cookie role 优先于服务端会话角色，任意已登录低权用户设置 Cookie role=admin 即可通过判定，第 3-5 行查询并回显 users 表全部 id/username/email/role。

- 攻击前身份与适用前提：攻击者持有任意有效账号会话；可设置 role Cookie
- 入口 → 传播 → 危险操作/状态变更：Cookie: role=admin → users.php:2 读取 $_COOKIE['role'] -> 覆盖 $u['role'] -> if($role!=='admin') 通过 -> 第3行全表查询 -> 第4/5行 JSON 或 HTML 回显 → 无授权的敏感数据读取（全部用户邮箱与角色）
- 防护与边界：require_user() 仅要求登录，未限制角色；真正的角色判断被客户端 Cookie 覆盖，服务端会话角色未用于此处授权。
- 静态判读：缺上下文（1 项）；缺失上下文：jobs 表结构与 user_id=4 是否存在及维护任务的后续执行逻辑未在已读源码中体现
- 动态验证：动态确认（verification `f8619f1605fb4d579754e4a3ae0bd224`）
- 正式终审：独立批次 c05062015fce42fdb838e28f31a066d1；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 alice 会话、同一请求头 Accept: application/json，仅额外加上客户端 Cookie "role=admin"：GET /ops/users.php 返回 HTTP 200，正文 {"access":"admin","users":[...]}，列出全部 4 个账号：alice/alice@shop.local/customer、bob/bob@shop.local/customer、operator/ops@shop.local/operator、admin/admin@shop.local/admin，说明仅凭客户端 Cookie 即通过管理员判定并越权读取全部用户邮箱与角色。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：未提供

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/users.php:1-5`（sha256 `3c5e879d945650ba…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$role=(string)($_COOKIE['role']??$u['role']);if($role!=='admin')fail_request('人员管理需要管理员权限。',403);
    3  $rows=db()->query('SELECT id,username,email,role FROM users ORDER BY id')->fetchAll();
    4  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['access'=>'admin','users'=>$rows]);
    5  page('人员与权限管理',function()use($rows){echo '<section class="panel"><span class="badge">管理员工作区</span><h2>账户权限清单</h2><table><thead><tr><th>用户名</th><th>邮箱</th><th>角色</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['username']).'</td><td>'.h($r['email']).'</td><td>'.h($r['role']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-18 support/download.php file 参数路径遍历读取任意文件

- 当前版本：finding `c4c8a046de93404aa739d4c080afe7f7` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/download.php:3`；文件：`lab30-shop/app/public/support/download.php`
- 证据引用：`10c0c8123072e718` lab30-shop/app/public/support/download.php:2-3；`f5faf41dff9a5a91` lab30-shop/app/src/bootstrap.php:9-9；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:69a8f4949fbb550f98cf:1（规范类型 path_traversal）

**结论陈述（模型产出，不是证据）**

文件参数 $_GET['file'] 经 (string) 强转后直接拼接到 data_dir().'/docs/' 前缀，仅用 is_file 判断存在，随后 file_get_contents 输出原始内容。无 realpath 规范化、无 ../ 过滤、无允许文件名白名单，攻击者构造 ../ 序列可读取 data_dir/docs 之外的进程可读文件（例如 SHOP_DATA_DIR/sessions 下的会话文件或其他应用文件）。前置仅为 require_user()（任意登录用户）。

- 攻击前身份与适用前提：攻击者为任意已登录用户；目标文件存在且 PHP 进程可读
- 入口 → 传播 → 危险操作/状态变更：GET 参数 file → $_GET['file'] -> (string) 拼接 data_dir().'/docs/' -> is_file($path) -> file_get_contents($path) 输出 → file_get_contents($path) 将任意可读文件内容回显给客户端
- 防护与边界：仅有 require_user() 登录检查与 is_file 存在性判断；无路径规范化、无 ../ 或前缀白名单校验
- 静态判读：证据已记录
- 动态验证：动态确认（verification `3570b96d07be4c8ca580d16149e33d57`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 basename() 限制为单文件名，或基于白名单映射允许的文档名，并在 realpath 后校验结果仍位于 data_dir()/docs 前缀内

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/support/download.php:2-3`（sha256 `71f0558eeb4ebb6c…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();
    3  if(isset($_GET['file'])){$path=data_dir().'/docs/'.(string)$_GET['file'];if(!is_file($path))fail_request('文档不存在。',404);header('Content-Type: text/plain; charset=utf-8');echo file_get_contents($path);exit;}
```

`lab30-shop/app/src/bootstrap.php:9-9`（sha256 `2050819d093be02b…`）

```php
    9  function data_dir(): string { return getenv('SHOP_DATA_DIR') ?: '/var/lib/shop'; }
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-19 partner/portal.php 不校验 JWT 签名，任意匿名请求伪造 role=admin 即可读取全部用户订单

- 当前版本：finding `471a1fc8e9554baea7baa6bd256b80b4` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/partner/portal.php:3`；文件：`lab30-shop/app/public/partner/portal.php`
- 证据引用：`343d5e3158080141` lab30-shop/app/public/partner/portal.php:2-6；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36；`10e301316be34133` lab30-shop/app/public/partner/token.php:2-4；`3bf12e4330602249` lab30-shop/app/src/setup.php:9-9
- 根因类别：task_goal:v2:0bacd9f20ff52488b4c6:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

portal.php 第2行从 $_POST['token'] 或 $_COOKIE['partner_token'] 取得令牌，按 '.' 分割后仅 base64 解码第二段并 json_decode，完全没有校验签名段，也没有调用 bootstrap.php 的 require_user()。第3行仅判断 payload['role']==='admin' 即放行，第4行执行 SELECT order_no,total FROM orders ORDER BY id 返回所有用户的订单。攻击者无需任何账号，用 base64url 编码 {"role":"admin"} 作为第二段、任意字符串作为第三段即可通过校验并以 JSON 或 HTML 页面拿到全量订单号与金额。token.php:2/4 显示正常令牌由登录用户 + 服务端 settings.generation 密钥 HMAC 签发，说明 portal 侧缺失的正是签名校验这一边界。

- 攻击前身份与适用前提：portal.php 可匿名访问；orders 表存在（setup.php:9 建表，默认含 alice/bob 订单）
- 入口 → 传播 → 危险操作/状态变更：HTTP POST 参数 token 或 Cookie partner_token（完全客户端可控） → portal.php:2 取 token → explode('.')[1] → base64_decode → json_decode 得到 payload → portal.php:3 判断 payload['role'] → portal.php:4 全表查询 orders → portal.php:5/6 返回订单号与金额 → 无签名校验的身份判断后执行跨用户 SELECT order_no,total FROM orders，并将结果返回给请求者
- 防护与边界：无有效防护：未调用 require_user()/user()，未校验 HMAC 签名段，未按 user_id 过滤查询；仅有一个可由客户端随意构造的 payload.role 字段比较
- 静态判读：证据已记录
- 动态验证：动态确认（verification `4780b834a9274d4ca880de9b22e1fd69`）
- 正式终审：独立批次 225354779d94490e92d956698f30f0ab；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一未登录请求 POST /partner/portal.php，携带自造三段式 token（header=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9，payload=base64url({"sub":1,"role":"admin","name":"x"})，第三段为任意串 "forged" 的 base64url 编码），返回 200 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}。签名段从未被校验，任意伪造 role=admin 的 payload 即可读取 alice 与 bob 的全部订单号与金额。

- 评分依据：CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：portal.php 必须先对令牌做 HMAC-SHA256 签名校验（与 token.php:4 相同的服务端 settings.generation 密钥，hash_equals 比较），并从令牌 sub 解析用户身份后按 user_id 过滤查询；或直接改用 require_user(['admin']) 的服务端会话鉴权。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/partner/portal.php:2-6`（sha256 `e1267edb0f9df936…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$token=(string)($_POST['token']??$_COOKIE['partner_token']??'');$parts=explode('.',$token);$payload=count($parts)===3?json_decode((string)base64_decode(strtr($parts[1],'-_','+/')),true):null;
    3  if(!is_array($payload)||($payload['role']??'')!=='admin')fail_request('此合作方功能仅向管理员开放。',403);
    4  $rows=db()->query('SELECT order_no,total FROM orders ORDER BY id')->fetchAll();
    5  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['role'=>'admin','settlements'=>$rows]);
    6  page('合作方结算工作台',function()use($rows){echo '<section class="panel"><h2>结算摘要</h2><table><thead><tr><th>订单</th><th>金额</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['order_no']).'</td><td>¥'.h($r['total']).'</td></tr>';echo '</tbody></table></section>';});
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

`lab30-shop/app/public/partner/token.php:2-4`（sha256 `391948b46efce76c…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();
    3  function b64url(string $s):string{return rtrim(strtr(base64_encode($s),'+/','-_'),'=');}
    4  $header=b64url(json_encode(['alg'=>'HS256','typ'=>'JWT']));$payload=b64url(json_encode(['sub'=>$u['id'],'role'=>$u['role'],'name'=>$u['username']]));$key=db()->query("SELECT value FROM settings WHERE `key`='generation'")->fetchColumn();$token=$header.'.'.$payload.'.'.b64url(hash_hmac('sha256',$header.'.'.$payload,$key,true));
```

`lab30-shop/app/src/setup.php:9-9`（sha256 `53e7dc7286d7d370…`）

```php
    9      $pdo->exec("CREATE TABLE IF NOT EXISTS orders(id INT PRIMARY KEY AUTO_INCREMENT, order_no VARCHAR(60), user_id INT, product_id INT, quantity INT, unit_price DECIMAL(12,2), total DECIMAL(12,2), private_note TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
```

### C-20 运营模板渲染将 POST 模板表达式直接 eval，导致任意 PHP 代码执行

- 当前版本：finding `02387c10d9d14176a68924c68bd9dc28` revision 1（项目版本 27）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-render.php:3`；文件：`lab30-shop/app/public/ops/template-render.php`
- 证据引用：`136d02a92a08ac98` lab30-shop/app/public/ops/template-render.php:1-4；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36；`415907ec6bf2f739` lab30-shop/app/src/bootstrap.php:40-40
- 根因类别：task_goal:v2:851fc3b5095a1a0f0593:1（规范类型 code_execution）

**结论陈述（模型产出，不是证据）**

第2行把 $_POST['template'] 原样赋给 $template；第3行 POST 时经 check_csrf 后，用 preg_replace_callback 匹配 /\{\{(.*?)\}\}/s 并把捕获组拼进 eval('return '.$m[1].';')。捕获内容完全由请求控制，eval 无白名单、无字符过滤或表达式沙箱，故 {{...}} 内可放任意 PHP 表达式/语句片段实现代码执行。角色限制仅要求 operator/admin，不构成安全边界。

- 攻击前身份与适用前提：攻击者需持有 operator 或 admin 账户会话，并取得有效 CSRF token（页面本身提供）
- 入口 → 传播 → 危险操作/状态变更：POST 参数 template → $_POST['template'] -> $template（第2行）-> preg_replace_callback 捕获 $m[1] -> eval('return '.$m[1].';')（第3行） → eval 动态执行请求可控的 PHP 代码
- 防护与边界：仅 require_user(['operator','admin']) 角色校验与 check_csrf；无表达式白名单/沙箱
- 静态判读：缺上下文（2 项）；缺失上下文：运行时 allow_url_include 与 open_basedir 配置未包含在快照中，影响远程包含是否默认成立；fixtures:8080 提供的模板内容及部署反代配置不在上传包内
- 动态验证：动态确认（verification `1b367bc3a6f24a0c96441de0062b1ecc`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：未提供

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

### C-21 运营链接预览将 GET url 原样传入 file_get_contents，导致 SSRF

- 当前版本：finding `9f3aed0469d34ff189b427fa127a9b7b` revision 1（项目版本 26）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/url-preview.php:3`；文件：`lab30-shop/app/public/ops/url-preview.php`
- 证据引用：`17e1cacfb5189678` lab30-shop/app/public/ops/url-preview.php:2-4；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:b51d6c54d9a066edaa9e:1（规范类型 ssrf）

**结论陈述（模型产出，不是证据）**

url-preview.php 第2行取 $_GET['url']，第3行仅用 stream_context_create 设置 timeout 与 follow_location=0，随后直接 @file_get_contents($url,false,$context,0,65536)。无 scheme 白名单、无主机/IP 黑名单、未过滤回环与内网地址，响应体以 h() 回显到 <pre>，可读取内网服务内容。require_user(['operator','admin']) 仅限制角色，不保护 URL 目标。

- 攻击前身份与适用前提：持有 operator 或 admin 有效会话并可访问 /ops/url-preview.php
- 入口 → 传播 → 危险操作/状态变更：HTTP GET 参数 url（$_GET['url']） → url-preview.php:2 取 $_GET['url'] -> 第3行 stream_context_create -> file_get_contents($url,...) -> $output 经 h() 输出到 <pre> → file_get_contents 对攻击者指定的完整 URL 发起服务端请求，回显最多 65536 字节响应体
- 防护与边界：仅 require_user 角色校验与 h() 输出转义；无 URL scheme/主机白名单或内网过滤
- 静态判读：证据已记录
- 动态验证：动态确认（verification `1d818e513b40451cb662e778fb5730da`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.0 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：对 url 施加严格白名单（仅 https + 允许主机列表），拒绝私有/回环/链路本地 IP 与非标准端口，禁用非 http(s) wrapper，必要时经受限出网代理。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/url-preview.php:2-4`（sha256 `e495938b10c455c6…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$url=(string)($_GET['url']??'');$output='';
    3  if($url!==''){$context=stream_context_create(['http'=>['timeout'=>4,'follow_location'=>0]]);$value=@file_get_contents($url,false,$context,0,65536);$output=$value===false?'暂时无法获取该地址。':$value;}
    4  page('链接预览',function()use($url,$output){echo '<section class="panel"><form method="get">';form_input('url','内容地址',$url?:'http://fixtures:8080/catalog-info');echo '<button>读取预览</button></form><pre>'.h($output).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-22 account/backup.php 对用户提交的备份直接 unserialize 并写入任意 tier/display_name

- 当前版本：finding `ada258387c284766a48e0d3b5ded75ab` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/backup.php:5`；文件：`lab30-shop/app/public/account/backup.php`
- 证据引用：`52a7b68bba8b1c1f` lab30-shop/app/public/account/backup.php:4-6；`9d0d13b19a80b9a2` lab30-shop/app/src/backup.php:2-5；`415907ec6bf2f739` lab30-shop/app/src/bootstrap.php:40-40
- 根因类别：task_goal:v2:cd65bd43b78688832f9f:1（规范类型 insecure_deserialization）

**结论陈述（模型产出，不是证据）**

POST 参数 backup 经 base64_decode 后未经 allowed_classes 白名单即传递给 unserialize()，返回对象仅做 instanceof MemberBackup 检查，随后把 $restored->tier 与 $restored->displayName 写入当前用户的 users 行。攻击者构造序列化 MemberBackup 对象即可将 tier 设为任意值（如 gold/admin），绕过正常的会员升级流程；结合站点其他可被加载的类，序列化对象注入还可扩展为更严重的利用。

- 攻击前身份与适用前提：任意已登录用户，携带有效 csrf token 提交特制 backup 值
- 入口 → 传播 → 危险操作/状态变更：POST 表单字段 backup（base64 编码的序列化字符串） → $_POST['backup'] -> base64_decode -> unserialize($raw) -> $restored->tier/$restored->displayName -> UPDATE users SET tier=?,display_name=? → unserialize() 处理不可信输入；随后 UPDATE users 写入 tier 敏感列
- 防护与边界：仅校验 CSRF 与 instanceof MemberBackup，未设置 allowed_classes，也未校验 tier 取值白名单
- 静态判读：证据已记录
- 动态验证：动态确认（verification `f381e2c7d0d840e1abd559dc363c19d3`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 unserialize($raw, ['allowed_classes'=>['MemberBackup']])，或改用 JSON 解析并对 tier 做白名单校验，禁止客户端指定 tier。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/backup.php:4-6`（sha256 `017e1703cdf0ff0c…`）

```php
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

`lab30-shop/app/src/bootstrap.php:40-40`（sha256 `2050819d093be02b…`）

```php
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

### C-23 运营网络诊断将 GET host 原样拼入 shell_exec 导致命令注入

- 当前版本：finding `d2677c773d34449d8e9a9a2a62ca6591` revision 1（项目版本 4）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/ping.php:2`；文件：`lab30-shop/app/public/ops/ping.php`
- 证据引用：`61f200eb89320676` lab30-shop/app/public/ops/ping.php:1-3；`65fc5323ae7c9b98` lab30-shop/app/src/host_check.php:1-2；`772dda483c0c1762` lab30-shop/app/public/ops/batch-check.php:2-2；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:81f9aaf41f719b2b6a5b:1（规范类型 command_injection）

**结论陈述（模型产出，不是证据）**

ops/ping.php 第 2 行取 $_GET['host'] 后直接拼接进 shell_exec('ping -c 1 -W 1 '.$host)，没有 escapeshellarg、字符白名单或 IP 校验；同一模式下 src/host_check.php 第 2 行同样原样拼接 host，被 ops/batch-check.php 第 2 行调用。任何持有 operator 或 admin 角色的登录用户可通过 host=127.0.0.1;id 之类载荷执行系统命令，命令输出在第 3 行 <pre> 中回显，形成回显型命令注入。鉴权仅要求 operator/admin 角色，不能阻断已登录低权限运营账号的利用。

- 攻击前身份与适用前提：持有 operator 或 admin 角色的有效会话；网络可访问 /ops/ping.php
- 入口 → 传播 → 危险操作/状态变更：$_GET['host']（ops/ping.php:2）以及 ops/batch-check.php:2 传入 host_check 的 $_GET['host'] → $_GET['host'] -> (string) -> shell_exec('ping -c 1 -W 1 '.$host) (ping.php:2)；batch-check.php:2 -> host_check($host) -> shell_exec 拼接 (host_check.php:2) → shell_exec 执行拼接后的系统命令，结果回显到页面
- 防护与边界：仅 require_user(['operator','admin']) 身份检查；无输入过滤、无 escapeshellarg、无白名单
- 静态判读：缺上下文（2 项）；缺失上下文：support/download.php 实际 data_dir 下 docs 目录结构与是否存在 ../ 可达敏感文件；未提供 SHOP_DATA_DIR 运行值；登录接口 auth/login.php 未读取，POC 登录流程按常规字段构造，需宿主环境确认字段名
- 动态验证：动态确认（verification `f67d451c812a4f8ab6f57d3a0c5bc32d`）
- 正式终审：独立批次 7d8017ebfe024177a73a06b74044084f；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 operator 会话，GET /ops/ping.php?host=127.0.0.1%3B%20echo%20CMDPROOF_9f3a71%3B%20id：响应 <pre> 在 ping 统计之后出现独立行 CMDPROOF_9f3a71，随后 uid=33(www-data) gid=33(www-data) groups=33(www-data)，证明 shell_exec 执行了注入的 echo 与 id。重复同一请求得到相同标记与 uid（非偶发）。对 /ops/batch-check.php?host=<同一载荷> 得到相同结果，确认 host_check()（src/host_check.php 第 2 行）同样存在注入。标记 CMDPROOF_9f3a71 只由本次注入命令产生，正常请求中未出现。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 escapeshellarg($host) 并对 host 做严格 IP/主机名白名单校验，或改用纯 PHP 的连通性检测，避免调用 shell。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/ping.php:1-3`（sha256 `c15517950afe0794…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$host=(string)($_GET['host']??'');$output=$host!==''?(string)shell_exec('ping -c 1 -W 1 '.$host):'';
    3  page('网络诊断',function()use($host,$output){echo '<section class="panel"><form method="get">';form_input('host','主机地址',$host?:'127.0.0.1');echo '<button>开始诊断</button></form><pre id="diagnostic-output">'.h($output).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/host_check.php:1-2`（sha256 `c3a868155c2d335e…`）

```php
    1  <?php
    2  function host_check(string $host): string { return (string)shell_exec('ping -c 1 -W 1 ' . $host); }
```

`lab30-shop/app/public/ops/batch-check.php:2-2`（sha256 `5f76332e7ad1b33a…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/host_check.php';require_user(['operator','admin']);$host=(string)($_GET['host']??'');$output=$host!==''?host_check($host):'';
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-24 ops/jobs.php 反序列化用户提交的 DispatchJob 对象，__wakeup 中 shell_exec 导致代码执行

- 当前版本：finding `aa6930e95bbf43b393fbb979036a4d05` revision 1（项目版本 4）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/dispatch_job.php:4`；文件：`lab30-shop/app/public/ops/jobs.php`
- 证据引用：`0ae7d306da24e8a8` lab30-shop/app/public/ops/jobs.php:2-4；`4a4dd3de59c1de26` lab30-shop/app/src/dispatch_job.php:1-5；`063c928d2d7c3b2e` lab30-shop/app/src/bootstrap.php:33-40
- 根因类别：task_goal:v2:ba105f1be6d2c53f39dd:1（规范类型 insecure_deserialization）

**结论陈述（模型产出，不是证据）**

ops/jobs.php 把 $_POST['job'] 做 base64_decode 后直接 unserialize，instanceof 检查在反序列化之后才执行；unserialize 时已实例化 DispatchJob 并调用 __wakeup，该方法将公有属性 $command 交给 shell_exec，因此提交 O:11:"DispatchJob":1:{s:7:"command";...} 即可执行任意系统命令，输出被 ob_get_clean 捕获并写入 jobs 表。

- 攻击前身份与适用前提：持有 operator 或 admin 账号，并能读取 /ops/jobs.php 页面中的 CSRF token
- 入口 → 传播 → 危险操作/状态变更：HTTP POST 参数 job（base64 编码的序列化 PHP 对象） → $_POST['job'] -> base64_decode -> unserialize -> DispatchJob::__wakeup -> shell_exec($this->command) -> ob_get_clean -> jobs.details → shell_exec($this->command) 位于 src/dispatch_job.php:4
- 防护与边界：仅 CSRF 校验与角色校验；unserialize 未设 allowed_classes 白名单，instanceof 检查无法阻止 __wakeup 已执行
- 静态判读：证据已记录
- 动态验证：动态确认（verification `871aa3c9f5354398b8194600852720fc`）
- 正式终审：独立批次 4bbd72d4a3774ca992efff709ee212e8；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一作业中攻击侧：POST job=base64('O:11:"DispatchJob":1:{s:7:"command";s:38:"id; uname; printf LAB30_DESER_aa6930e9";}')，HTTP 200，页面 notice「任务已导入并执行。」；输出区 <pre> 显示 "uid=33(www-data) gid=33(www-data) groups=33(www-data)\nLinux\nLAB30_DESER_aa6930e9"，唯一标记 LAB30_DESER_aa6930e9 与 id/uname 输出均由本次攻击命令产生，且该结果同时被写入 jobs.details（表格中可见同串）。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：不要对用户数据 unserialize；改用 JSON 并只接受任务类型枚举，移除 __wakeup 中的 shell_exec。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/jobs.php:2-4`（sha256 `0f7550fa7f16bd4a…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/dispatch_job.php';$u=require_user(['operator','admin']);$notice='';$output='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$raw=base64_decode((string)($_POST['job']??''),true);if($raw===false)fail_request('任务格式不正确。');ob_start();$job=unserialize($raw);$output=(string)ob_get_clean();if(!$job instanceof DispatchJob)fail_request('不是有效的任务文件。');db()->prepare("INSERT INTO jobs(user_id,title,status,details) VALUES(?,?,'completed',?)")->execute([$u['id'],'导入巡检任务',$output]);$notice='任务已导入并执行。';}
    4  $normal=new DispatchJob();$example=base64_encode(serialize($normal));$rows=db()->query('SELECT id,title,status,details FROM jobs ORDER BY id DESC LIMIT 20')->fetchAll();
```

`lab30-shop/app/src/dispatch_job.php:1-5`（sha256 `e8234b971fe75d85…`）

```php
    1  <?php
    2  class DispatchJob {
    3      public string $command = 'printf inventory-ready';
    4      public function __wakeup(): void { echo (string)shell_exec($this->command); }
    5  }
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

### C-25 account/redeem.php 使用 == 比较 md5 兑换码导致 0e 弱比较绕过升级会员

- 当前版本：finding `9a55b23d82814cd19b76510533209567` revision 1（项目版本 19）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/redeem.php:5`；文件：`lab30-shop/app/public/account/redeem.php`
- 证据引用：`a3d11f0b53761e11` lab30-shop/app/public/account/redeem.php:1-9
- 根因类别：task_goal:v2:020accd3bc8730f5e30a:1（规范类型 weak_type_comparison）

**结论陈述（模型产出，不是证据）**

redeem.php 第4行 secret_hash=md5('240610708') 得到 0e 开头的纯数字字符串，第5行使用 == 将 md5(用户 token) 与该哈希比较。PHP 中形如 0e... 的字符串在 == 下被当作数字 0，攻击者提交任一 md5 为 0e+纯数字形式的 token（如 'QNKCDZO'）即可使比较为真，绕过真实兑换码校验，执行 UPDATE users SET tier='gold' 将当前用户升级为金卡会员。

- 攻击前身份与适用前提：已登录用户，携带有效 csrf token 提交特制 token
- 入口 → 传播 → 危险操作/状态变更：POST 参数 token → $_POST['token'] -> md5() -> ==$secret_hash -> UPDATE users SET tier='gold' → UPDATE users SET tier='gold' WHERE id=$u['id']
- 防护与边界：check_csrf 仅防 CSRF，不防弱比较；未使用 hash_equals
- 静态判读：缺上下文（1 项）；缺失上下文：未发现 reset_session/登录后 session_regenerate_id 调用；login.php:8 直接写入 user_id，配合 bootstrap.php:13-18 的 use_strict_mode=0 与 sid 采用，会话固定风险实为已存在的 candidate（start_session 处），本工作项未重复提交。
- 动态验证：动态确认（verification `3b51d65072ae490297b0a8930b701a24`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 hash_equals($secret_hash, md5($token)) 做严格字符串比较，或改用 password_hash/password_verify；不要用 == 比较哈希。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/redeem.php:1-9`（sha256 `28b3dc4534cca985…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$notice='';$accepted=false;
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$secret_hash=md5('240610708');
    5      if(md5((string)($_POST['token']??''))==$secret_hash){db()->prepare("UPDATE users SET tier='gold' WHERE id=?")->execute([$u['id']]);event_log('redeem_membership');$notice='兑换成功，已升级金卡会员。';$accepted=true;}
    6      else{$notice='兑换码无效。';http_response_code(422);}
    7      if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['accepted'=>$accepted,'message'=>$notice],$accepted?200:422);
    8  }
    9  page('会员权益兑换',function()use($notice){echo '<section class="panel narrow"><h2>让日常多一点惊喜</h2><p>输入活动提供的会员兑换码。</p>';if($notice)echo '<div class="notice">'.h($notice).'</div>';echo '<form method="post">'.csrf_field();form_input('token','兑换码');echo '<button>兑换权益</button></form></section>';},'账户与会员');
```

### C-26 support/download.php file 参数未规范化导致 ../ 路径遍历任意文件读取

- 当前版本：finding `2ad14e06d6e84f8d866d0eec3d3fc0a5` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/download.php:3`；文件：`lab30-shop/app/public/support/download.php`
- 证据引用：`10c0c8123072e718` lab30-shop/app/public/support/download.php:2-3；`f5faf41dff9a5a91` lab30-shop/app/src/bootstrap.php:9-9；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:95621d239f8a7a68a7bf:1（规范类型 path_traversal）

**结论陈述（模型产出，不是证据）**

download.php:3 不存在 basename/realpath/白名单，$path=data_dir().'/docs/'.$_GET['file']，用户传 file=../../etc/passwd 时路径解析为 /var/lib/shop/docs/../../etc/passwd 即 /etc/passwd，is_file 通过后 file_get_contents 输出内容。前置仅需任意登录用户（require_user 无角色参数）。

- 攻击前身份与适用前提：攻击者为任意已登录用户；目标文件存在且 PHP 进程可读
- 入口 → 传播 → 危险操作/状态变更：$_GET['file'] → $_GET['file'] -> (string) -> data_dir().'/docs/'.$file -> is_file -> file_get_contents($path) -> echo 输出 → file_get_contents 读取并回显任意可读文件
- 防护与边界：仅 is_file 存在性检查，无路径规范化或白名单，不足以阻止 ../ 逃逸
- 静态判读：证据已记录
- 动态验证：动态确认（verification `b5e9d6a01bc341d6a2c34401ac3a8dc4`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：对 file 参数做 basename 或 realpath 前缀校验，只允许 data_dir()/docs 下的固定白名单文件名。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/support/download.php:2-3`（sha256 `71f0558eeb4ebb6c…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();
    3  if(isset($_GET['file'])){$path=data_dir().'/docs/'.(string)$_GET['file'];if(!is_file($path))fail_request('文档不存在。',404);header('Content-Type: text/plain; charset=utf-8');echo file_get_contents($path);exit;}
```

`lab30-shop/app/src/bootstrap.php:9-9`（sha256 `2050819d093be02b…`）

```php
    9  function data_dir(): string { return getenv('SHOP_DATA_DIR') ?: '/var/lib/shop'; }
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-27 ops/report.php 将数据库昵称二次拼接进 SQL，低权用户可通过昵称注入

- 当前版本：finding `478b720dcb6a455dac412d6b875c46d8` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/report.php:3`；文件：`lab30-shop/app/public/ops/report.php`
- 证据引用：`0245c9c62f5af52c` lab30-shop/app/public/ops/report.php:2-4；`ec18381d7af73d0f` lab30-shop/app/public/account/update.php:4-6；`f86e0ebf4243b153` lab30-shop/app/src/setup.php:7-7
- 根因类别：task_goal:v2:97d3dc479e34353b4831:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

report.php 先按 user_id 参数化取出 nickname（第2行），随后第3行把该 nickname 直接拼入 "SELECT username,email,role FROM users WHERE nickname='...'" 并执行。nickname 是普通用户可在 account/update.php 第5-6行自行提交写入的列（白名单包含 nickname，值以 (string) 原样入库，未过滤引号），因此任意登录用户（customer）可把自己的昵称设为 ' OR '1'='1 之类的载荷，再由运营账号打开 /ops/report.php?user_id=<该用户ID> 触发注入，读出全部用户名/邮箱/角色。

- 攻击前身份与适用前提：攻击者拥有任意注册账号并完成 CSRF 令牌的资料保存；受害 operator/admin 需以其 user_id 访问 report.php（GET 链接或诱导点击）
- 入口 → 传播 → 危险操作/状态变更：GET user_id 指向的 users.nickname，其值来自 /account/update.php 的 POST nickname → account/update.php:5-6 写入 users.nickname → report.php:2 参数化读取为 $nickname → report.php:3 字符串拼接 + db()->query 执行 → db()->query 执行含单引号的拼接 SQL，结果集经 report.php:4/5 回显
- 防护与边界：仅第2行参数化，第3行的二次查询完全没有占位符或转义；nickname 写入路径无字符过滤
- 静态判读：证据已记录
- 动态验证：动态确认（verification `5b2f038c08fa4b43ad1527f64f7ad1a9`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 4.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：第3行改用预处理语句 db()->prepare('SELECT username,email,role FROM users WHERE nickname=?')->execute([$nickname])，或直接以第2行查询一并取出所需列；nickname 写入路径增加长度与字符校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/report.php:2-4`（sha256 `90d7d60d44815374…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user(['operator','admin']);$id=(int)($_GET['user_id']??1);$q=db()->prepare('SELECT nickname FROM users WHERE id=?');$q->execute([$id]);$nickname=$q->fetchColumn();if($nickname===false)fail_request('会员不存在。',404);
    3  $rows=db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'")->fetchAll();
    4  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['saved_nickname'=>$nickname,'members'=>$rows]);
```

`lab30-shop/app/public/account/update.php:4-6`（sha256 `b8227f19c05d0cd3…`）

```php
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
```

`lab30-shop/app/src/setup.php:7-7`（sha256 `53e7dc7286d7d370…`）

```php
    7      $pdo->exec("CREATE TABLE IF NOT EXISTS users(id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(60) UNIQUE NOT NULL, password_md5 CHAR(32) NOT NULL, display_name VARCHAR(100) NOT NULL, email VARCHAR(200) NOT NULL, role VARCHAR(24) NOT NULL DEFAULT 'customer', balance DECIMAL(12,2) NOT NULL DEFAULT 100, tier VARCHAR(30) NOT NULL DEFAULT 'standard', nickname VARCHAR(200) NOT NULL, homepage VARCHAR(500) NOT NULL DEFAULT '#')");
```

### C-28 support/download.php file 参数未规范化拼接路径导致任意文件读取

- 当前版本：finding `2198eca455c84b6db9a639ac7a7210a3` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/download.php:3`；文件：`lab30-shop/app/public/support/download.php`
- 证据引用：`8bf814169e217985` lab30-shop/app/public/support/download.php:1-4；`17d72b54d2f463ef` lab30-shop/app/src/bootstrap.php:2-2；`f5faf41dff9a5a91` lab30-shop/app/src/bootstrap.php:9-9；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:7c056b8691b1b49467f9:1（规范类型 path_traversal）

**结论陈述（模型产出，不是证据）**

download.php 第 3 行将 (string)$_GET['file'] 直接拼接到 data_dir().'/docs/' 后作为路径传给 file_get_contents 并回显。代码仅在 is_file 失败时返回 404，没有 basename、realpath 或白名单约束，攻击者可提交 ../ 序列访问 docs 目录之外的任意可读文件。

- 攻击前身份与适用前提：已登录任意用户；目标文件存在且 PHP 进程可读
- 入口 → 传播 → 危险操作/状态变更：$_GET['file'] → $_GET['file'] -> (string) -> data_dir().'/docs/'.file -> is_file 检查 -> file_get_contents 回显 → file_get_contents($path) 内容写入响应
- 防护与边界：仅 is_file 存在性检查；无 basename/realpath/前缀校验/白名单
- 静态判读：证据已记录
- 动态验证：动态确认（verification `6de2225583b94b85b955a715320fcb7c`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 basename() 限制为单层文件名，或对解析后的 realpath 校验其位于 data_dir().'/docs/' 前缀内，并建议白名单允许的文档名。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/support/download.php:1-4`（sha256 `71f0558eeb4ebb6c…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();
    3  if(isset($_GET['file'])){$path=data_dir().'/docs/'.(string)$_GET['file'];if(!is_file($path))fail_request('文档不存在。',404);header('Content-Type: text/plain; charset=utf-8');echo file_get_contents($path);exit;}
    4  page('帮助文档',function(){echo '<section class="panel"><h2>常用服务文档</h2><ul><li><a href="?file=shipping.txt">配送说明</a></li><li><a href="?file=returns.txt">售后说明</a></li></ul><form method="get">';form_input('file','文档文件名','shipping.txt');echo '<button>查看文档</button></form></section>';},'客服与帮助');
```

`lab30-shop/app/src/bootstrap.php:2-2`（sha256 `2050819d093be02b…`）

```php
    2  declare(strict_types=1);
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

### C-29 ops/formula.php 将 GET func 直接作为函数名调用，可调用 system/exec 等实现任意命令执行

- 当前版本：finding `4679744af0c244798f7eea708317a445` revision 1（项目版本 13）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/formula.php:3`；文件：`lab30-shop/app/public/ops/formula.php`
- 证据引用：`5576c0baf3a49f09` lab30-shop/app/public/ops/formula.php:2-4；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37；`38c5cad78d49b7f3` lab30-shop/docker/php.ini:1-13；`156ea3e4adf6ec2a` lab30-shop/docker/web.Dockerfile:1-4
- 根因类别：task_goal:v2:4858948da6818e7824c8:1（规范类型 code_execution）

**结论陈述（模型产出，不是证据）**

formula.php 在 require_user(['operator','admin']) 之后，把 $_GET['func'] 强转为字符串并直接以 $func($_GET['arg']) 形式调用。PHP 变量函数调用对内置函数无白名单，攻击者传入 func=system 且 arg=id 即执行任意系统命令；也可用 passthru/shell_exec/file_get_contents 等读取文件或发起请求。页面表单里 form_input('func',...) 也直接展示该参数，说明服务端没有任何函数名白名单或过滤。

- 攻击前身份与适用前提：持有 operator 或 admin 角色的有效会话（登录 /auth/login.php）
- 入口 → 传播 → 危险操作/状态变更：HTTP GET 参数 func 与 arg → $_GET['func'] -> (string)$func -> $func((string)($_GET['arg'])) 变量函数调用 → 变量函数调用，可解析到 system/exec/passthru/shell_exec 等内置函数
- 防护与边界：仅 require_user(['operator','admin']) 角色校验，无函数白名单、无禁用函数配置（php.ini 未设置 disable_functions）
- 静态判读：证据已记录
- 动态验证：动态确认（verification `447dcc09be42456298fffc839a314c39`）
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改为白名单映射：$allowed=['strtoupper','strtolower','trim'...]; if(!in_array($func,$allowed,true)) fail_request(); 或使用 match 显式分发，禁止以请求参数直接作为函数名，并设置 disable_functions。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/formula.php:2-4`（sha256 `686f39f31996a5d3…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$result='';
    3  if(isset($_GET['func'])){$func=(string)$_GET['func'];$result=(string)$func((string)($_GET['arg']??''));}
    4  page('运营公式计算',function()use($result){echo '<section class="panel"><p>选择函数并提交文本进行试算。</p><form method="get">';form_input('func','函数名称','strtoupper');form_input('arg','输入值','spring-sale');echo '<button>执行计算</button></form><pre>'.h($result).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

`lab30-shop/docker/php.ini:1-13`（sha256 `b65de9007c7f42b3…`）

```
    1  date.timezone = Asia/Shanghai
    2  allow_url_fopen = On
    3  allow_url_include = On
    4  display_errors = Off
    5  log_errors = On
    6  error_reporting = E_ALL & ~E_DEPRECATED
    7  session.use_strict_mode = 0
    8  session.save_path = /var/lib/shop/sessions
    9  memory_limit = 128M
   10  post_max_size = 2M
   11  max_execution_time = 15
   12  default_socket_timeout = 4
   13  expose_php = Off
```

`lab30-shop/docker/web.Dockerfile:1-4`（sha256 `5cea6e16d48a9d49…`）

```
    1  FROM php:8.4-apache-bookworm@sha256:e653ff90d7f6e2e6f81eddb07c864f1eae224ccbf5143f82a44f25e2f110e320
    2  RUN apt-get update && apt-get install -y --no-install-recommends libxml2-dev libonig-dev iputils-ping \
    3      && docker-php-ext-install -j2 pdo_mysql mysqli simplexml mbstring \
    4      && rm -rf /var/lib/apt/lists/*
```

## 5. 实际验证和终审理由

### C-01 ops/maintenance.php 仅凭可伪造的 X-Admin 请求头授权，未认证即可触发维护任务写入

- verification `0776b77b9c1949b59f02a2f7dddfeb87`（finding `bfc27a79c5a04c438b49cd5fc87f5519` revision 1，context `a84509c8c0394e84898e8edfed6e5126`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：未认证 guest（无 Cookie、无会话）请求 /ops/maintenance.php：GET 返回 403 {"error":"内部维护接口需要有效的服务身份。"}；POST 同样返回 403 且无 job_id，说明缺少该请求头时接口拒绝访问、未发生写库。
  - 攻击侧观测：同一未认证 guest 请求加 X-Admin: 1：GET 返回 200 {"service":"settlement-maintenance","authorized":true}；连续两次 POST 均返回 200 {"accepted":true,"job_id":302} 与 {"accepted":true,"job_id":303}。自增主键连续递增证明每次请求都实际执行了 INSERT INTO jobs 并写库，而非伪造或缓存响应；user_id=4 的硬编码插入未触发外键/约束错误。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`8fe4eb20f18049858a6fb2cac410abdb`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`8fe4eb20f18049858a6fb2cac410abdb` script finished exit=0
  - 适配脚本：`0776b77b-adapted-poc.php`（见证据包 evidence/）
  - 备注：单作业 8fe4eb20f18049858a6fb2cac410abdb，guest 身份（无任何会话，前置/后置均为 role=guest、未认证）。正常侧与攻击侧唯一差异是客户端可伪造的 X-Admin 请求头；响应自增 job_id 连续递增（302→303）是写库的客观证据。未使用任何特权身份，符合“任何未认证访问者”前提。

- 正式复核 `8e3318ed458d42ec900256ba7f64abfc`：复核确认；引用 revision 1 / verification `0776b77b9c1949b59f02a2f7dddfeb87`
  - 理由：正常侧：未认证 guest 无头 GET/POST 均 403 {"error":"内部维护接口需要有效的服务身份。"}，无 job_id；攻击侧：同一 guest 会话加 X-Admin: 1 后 GET 200 authorized=true，两次 POST 分别返回 job_id 302、303 连续递增，证明每次请求均实际执行 maintenance.php:4 的 INSERT 并写库。会话前提（precondition 中 guest 与 alice 身份均校验 ok）与源码第 3 行仅比较请求头一致，未见反证，故确认。
  - 复核观测：正常侧 未认证 guest（无 Cookie、无会话）请求 /ops/maintenance.php：GET 返回 403 {"error":"内部维护接口需要有效的服务身份。"}；POST 同样返回 403 且无 job_id，说明缺少该请求头时接口拒绝访问、未发生写库。；攻击侧 同一未认证 guest 请求加 X-Admin: 1：GET 返回 200 {"service":"settlement-maintenance","authorized":true}；连续两次 POST 均返回 200 {"accepted":true,"job_id":302} 与 {"accepted":true,"job_id":303}。自增主键连续递增证明每次请求都实际执行了 INSERT INTO jobs 并写库，而非伪造或缓存响应；user_id=4 的硬编码插入未触发外键/约束错误。

### C-02 ops/template-preview.php 将 GET template 直接 include，allow_url_include=On 时可远程包含执行代码

- verification `744fffb1e0a54226b18df6fe4b17908a`（finding `0bb3ead0ddc24e6e944d1e0b0f5e3a76` revision 1，context `192fe80488b24728ba93a82a5a4f05e5`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 登录后 GET /ops/template-preview.php?template=http://fixtures:8080/templates/season.php：HTTP 200，页面 #remote-template 区域输出合作方模板内容「合作方 · 秋日生活提案 / 让生活慢下来，把好物带回家。」，说明服务端按请求值抓取并 include 了远程 URL 返回的内容；不带 template 的页面仅渲染表单（PAGE 200）。
  - 攻击侧观测：同一 operator 会话请求 /ops/template-preview.php?template=/etc/passwd：HTTP 200，#remote-template 区域内原样输出本地文件内容 "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:...\nbin:x:2:2:...\nsys:x:3:3:..."（ATTACK passwd True），证明 include 接受任意本地路径并读取任意文件。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`14dd132072114993bc90c97ab3916cbe`；`de8adc562184407bacabf02afd821f16`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`de8adc562184407bacabf02afd821f16` script finished exit=0
  - 适配脚本：`744fffb1-adapted-poc_template_preview_rfi.py`（见证据包 evidence/）
  - 备注：源码 applicability=match：template-preview.php:3 在 if($template!=='') 后直接 include $template，无白名单/realpath；docker/php.ini:2-3 开启 allow_url_fopen 与 allow_url_include=On。正常请求的 template 是 http:// URL，页面渲染出远程返回的合作方模板 HTML（合作方 · 秋日生活提案），说明服务端确实通过 include 抓取并包含远程 URL 内容，具备 RFI 条件（若远程文件为 PHP 代码则会被执行）；攻击请求把 template 换成本地 /etc/passwd，页面直接包含其内容，说明同一 include 点无任何路径限制。两侧同身份、同路由，唯一变量是 template 值。宿主审计作业 14dd132072114993bc90c97ab3916cbe 以 alice(customer) 身份请求得到 403（角色门禁），未作为漏洞证据；源码要求 operator/admin，故按前提使用 operator。

- 正式复核 `5043adba4fd64b6da1172065affde93f`：复核确认；引用 revision 1 / verification `744fffb1e0a54226b18df6fe4b17908a`
  - 理由：正常侧：operator 登录后 POST/GET /ops/template-preview.php 不带 template 时页面 200 仅渲染表单，#remote-template 区为空（PAGE status 200 ops_nav True form True）；template=http://fixtures:8080/templates/season.php 时该区输出合作方模板正文（NORMAL season_like True），说明服务端按请求 URL 抓取并 include。攻击侧：同一会话 template=/etc/passwd 返回 200 并原样输出 root:x:0:0:root:/root:/bin/bash、daemon:x:1:1:daemon:... 等账户行（ATTACK passwd True），证明 include 接受任意本地路径并读出文件内容，与源码 template-preview.php:3 include $template 且无白名单一致，动态确认任意文件包含。
  - 复核观测：正常侧 operator 登录后 GET /ops/template-preview.php?template=http://fixtures:8080/templates/season.php：HTTP 200，页面 #remote-template 区域输出合作方模板内容「合作方 · 秋日生活提案 / 让生活慢下来，把好物带回家。」，说明服务端按请求值抓取并 include 了远程 URL 返回的内容；不带 template 的页面仅渲染表单（PAGE 200）。；攻击侧 同一 operator 会话请求 /ops/template-preview.php?template=/etc/passwd：HTTP 200，#remote-template 区域内原样输出本地文件内容 "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:...\nbin:x:2:2:...\nsys:x:3:3:..."（ATTACK passwd True），证明 include 接受任意本地路径并读取任意文件。

### C-03 support/messages.php 留言正文未编码输出的存储型 XSS

- verification `be96a0e446da487e8b52167164bb8bf4`（finding `bc93fb6a277d4739a06986e3c6154a0e` revision 1，context `14a525a571ff43c0bab3f1688841a374`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：同一 alice 会话正常提交 message=NORMAL_MSG_bc93 hello normal text，返回 200 并回到 /support/messages.php；列表中原样显示该文本（NORMAL_TEXT_PRESENT True），未产生脚本或对话框。受害者 bob 的浏览器页面正文同样显示该普通留言为纯文本，整个页面仅弹出攻击载荷对应的一个对话框。
  - 攻击侧观测：alice 提交 message=<script>alert('XSS_BC93FB6A')</script> 后，留言列表 HTML 中直接出现 <div class="message-body"><script>alert('XSS_BC93FB6A')</script></div>（PAYLOAD_RAW_PRESENT True、PAYLOAD_ESCAPED_PRESENT False）。受害者 bob（独立会话、浏览自己的留言页）加载 /support/messages.php 时，浏览器实际弹出对话框，dialogs 记录为 XSS_BC93FB6A，页面正文还可见 alice 的普通留言文本。攻击脚本由服务端存储并在另一用户的浏览器中执行，构成存储型 XSS。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`9ff2146f647844ac9fb2f5db89b959c1`；`078e364e6ef947089f4e47ca3c92f57b`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`9ff2146f647844ac9fb2f5db89b959c1` script finished exit=0；`078e364e6ef947089f4e47ca3c92f57b` browser finished exit=0
  - 产物：`be96a0e446da487e8b52167164bb8bf4-078e364e6ef947089f4e47ca3c92f57b-screenshot.png`
  - 适配脚本：`be96a0e4-adapted-xss_messages.php`（见证据包 evidence/）
  - 备注：注入方为 alice（作业 9ff2146f647844ac9fb2f5db89b959c1），查看方为 bob（浏览器作业 078e364e6ef947089f4e47ca3c92f57b，dialogs=XSS_BC93FB6A，截图工件 078e...-screenshot.png），两侧会话相互独立，符合「任意访问留言页用户即执行」。普通留言 NORMAL_MSG_bc93 hello normal text 在同一页面仅以文本显示，未触发任何对话框。

- 正式复核 `a133ed97d57f4732ad95c65d85a648e2`：复核确认；引用 revision 1 / verification `be96a0e446da487e8b52167164bb8bf4`
  - 理由：正常侧：alice 提交 NORMAL_MSG_bc93 hello normal text 后 200 回到 /support/messages.php，列表原样显示纯文本（NORMAL_TEXT_PRESENT True），bob 页面同样只显示该文本、无弹窗。攻击侧：alice 提交 <script>alert('XSS_BC93FB6A')</script> 后，服务端返回的 HTML 中直接出现 <div class="message-body"><script>alert('XSS_BC93FB6A')</script></div>（RAW_PRESENT True、ESCAPED_PRESENT False），bob 独立会话加载留言页时浏览器实际弹出 XSS_BC93FB6A 对话框。两侧观测与源码 messages.php:3/5 未编码输出一致，存储型 XSS 复核确认。
  - 复核观测：正常侧 同一 alice 会话正常提交 message=NORMAL_MSG_bc93 hello normal text，返回 200 并回到 /support/messages.php；列表中原样显示该文本（NORMAL_TEXT_PRESENT True），未产生脚本或对话框。受害者 bob 的浏览器页面正文同样显示该普通留言为纯文本，整个页面仅弹出攻击载荷对应的一个对话框。；攻击侧 alice 提交 message=<script>alert('XSS_BC93FB6A')</script> 后，留言列表 HTML 中直接出现 <div class="message-body"><script>alert('XSS_BC93FB6A')</script></div>（PAYLOAD_RAW_PRESENT True、PAYLOAD_ESCAPED_PRESENT False）。受害者 bob（独立会话、浏览自己的留言页）加载 /support/messages.php 时，浏览器实际弹出对话框，dialogs 记录为 XSS_BC93FB6A，页面正文还可见 alice 的普通留言文本。攻击脚本由服务端存储并在另一用户的浏览器中执行，构成存储型 XSS。

### C-04 catalog/greeting.php 的 name 参数未经转义直接回显导致反射型 XSS

- verification `2fecb90fab3d495a8c2b0dbd0986e953`（finding `20966dec508f4d548b87236cef766951` revision 1，context `40570ab09a2f4fa399929138daa83b0e`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：job cde53066f2d348cf932aee64250f0b4e：guest 会话加载 /catalog/greeting.php?name=Alice，标题「到店欢迎 · 拾光商城」，body_text 含「你好，Alice」，dialogs=[]、console_errors=[]，无脚本执行。
  - 攻击侧观测：job 65742a6f5a234a5e8671951eae75e07a：同一 guest 身份加载 /catalog/greeting.php?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E，dialogs 为 ["1"]（alert(1) 实际执行），body_text 中 h2 只剩「你好，」说明 <script> 被浏览器当作标签解析执行而非文本显示。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`cde53066f2d348cf932aee64250f0b4e`；`65742a6f5a234a5e8671951eae75e07a`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`cde53066f2d348cf932aee64250f0b4e` browser finished exit=0；`65742a6f5a234a5e8671951eae75e07a` browser finished exit=0
  - 产物：`2fecb90fab3d495a8c2b0dbd0986e953-cde53066f2d348cf932aee64250f0b4e-screenshot.png`；`2fecb90fab3d495a8c2b0dbd0986e953-65742a6f5a234a5e8671951eae75e07a-screenshot.png`
  - 备注：源码快照 applicability=match。对照：两作业仅 name 值不同（Alice vs <script>alert(1)</script>），身份同为 guest，均返回同一页面；攻击侧唯一新增观测为 alert 弹窗及 DOM 中 script 标签消失。源码 greeding.php:3 的拼接位置在 page() 回调内，而 page() 只在 bootstrap.php:51/55/58 对固定字段与标题调用 h()，第59行直接执行 $body()，故闭包内输出不受转义保护，与运行时观测一致。截图工件已随作业保留。

- 正式复核 `587d303b9f484d1a834178e6bb18adbb`：复核确认；引用 revision 1 / verification `2fecb90fab3d495a8c2b0dbd0986e953`
  - 理由：正常侧：guest 访问 /catalog/greeting.php?name=Alice，body_text 含「你好，Alice」，dialogs=[]、console_errors=[]，无脚本执行。攻击侧：同一 guest 访问 name=<script>alert(1)</script>，dialogs 为 ["1"]（alert(1) 实际执行），h2 处脚本被当作标签解析而非文本。两侧观测与 greeting.php:2-3 未调用 h() 直接拼接的源码一致，反射型 XSS 复核确认。
  - 复核观测：正常侧 job cde53066f2d348cf932aee64250f0b4e：guest 会话加载 /catalog/greeting.php?name=Alice，标题「到店欢迎 · 拾光商城」，body_text 含「你好，Alice」，dialogs=[]、console_errors=[]，无脚本执行。；攻击侧 job 65742a6f5a234a5e8671951eae75e07a：同一 guest 身份加载 /catalog/greeting.php?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E，dialogs 为 ["1"]（alert(1) 实际执行），body_text 中 h2 只剩「你好，」说明 <script> 被浏览器当作标签解析执行而非文本显示。

### C-05 运营会员查询 $_GET['q'] 拼接进 LIKE，跨文件 SQL 注入

- verification `42e81052cb814bfea750043cb5264f04`（finding `f9d93c1f0f134a948bfbfae9a4220822` revision 1，context `8cd1df3ff0254497ab187e1e9e40ef1b`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 登录后请求 /ops/members.php?q=alice（Accept: application/json）：HTTP 200，members 仅 1 行，即 id=1 alice &#124; alice@shop.local &#124; customer，与 LIKE '%alice%' 的正常语义一致。
  - 攻击侧观测：同一 operator 会话请求 /ops/members.php?q=%25%27%20OR%20%271%27%3D%271%27%20--%20（Accept: application/json）：HTTP 200，members 返回 4 行——alice/customer、bob/customer、operator/operator、admin/admin，SQL 的 LIKE 条件被 OR 恒真条件与 -- 注释闭合，越权返回全部会员及角色。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`b082e2414b344f2ea422aef89a562451`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`b082e2414b344f2ea422aef89a562451` script finished exit=0
  - 适配脚本：`42e81052-adapted-poc.php`（见证据包 evidence/）
  - 备注：源码 applicability=match：members.php:2 读取 $_GET['q']（默认 alice）传入 member_lookup；member_lookup.php:3 用 db()->query("SELECT id,username,email,role FROM users WHERE username LIKE '%".$term."%'") 直接拼接，无参数化或转义；members.php:3 在 Accept: application/json 时直接返回查询结果。正常与攻击两侧同一 operator 会话、同一路由与请求头，唯一变量是 q 值，行数由 1 变为 4，差异只能由注入改变 SQL 条件解释。角色限制为源码要求，故按前提使用 operator 身份。

- 正式复核 `5cc4ebf694434742b0fc0190057de2f0`：复核确认；引用 revision 1 / verification `42e81052cb814bfea750043cb5264f04`
  - 理由：正常侧：operator 请求 /ops/members.php?q=alice（Accept: application/json）返回 1 行，即 id=1 alice &#124; alice@shop.local &#124; customer，符合 LIKE '%alice%' 语义。攻击侧：q=%' OR '1'='1' -- 返回 4 行（alice、bob、operator、admin 及角色/邮箱），说明 LIKE 条件被闭合注释绕过。观测与 member_lookup.php:3 字符串拼接 SQL、members.php:2 直传 q 的源码一致，跨文件 SQL 注入复核确认。
  - 复核观测：正常侧 operator 登录后请求 /ops/members.php?q=alice（Accept: application/json）：HTTP 200，members 仅 1 行，即 id=1 alice &#124; alice@shop.local &#124; customer，与 LIKE '%alice%' 的正常语义一致。；攻击侧 同一 operator 会话请求 /ops/members.php?q=%25%27%20OR%20%271%27%3D%271%27%20--%20（Accept: application/json）：HTTP 200，members 返回 4 行——alice/customer、bob/customer、operator/operator、admin/admin，SQL 的 LIKE 条件被 OR 恒真条件与 -- 注释闭合，越权返回全部会员及角色。

### C-06 wallet/withdraw.php 余额读取与更新非原子，配合 usleep 与 session_write_close 可并发重复提现

- verification `d8ebc3c8b7c44603a41f50313505eb28`（finding `6292c426c920455d84e7b13975afafa8` revision 1，context `7194ecd191ed45a983a283381303f4e2`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice 正常登录（余额 100.00），GET /wallet/index.php 显示可用余额 ¥100.00、提现记录 0，并从表单取得真实 48 位 csrf。单次正常 POST /wallet/withdraw.php amount=10 返回 200 正文 {"status":"paid","amount":10,"balance":90,"receipt_id":1}，余额按单笔正确扣减为 90.00。说明在无并发时该接口按预期只扣一次。
  - 攻击侧观测：同一 alice 会话、同一 csrf，在余额 90.00 时以 Barrier 同时发起 6 个 POST /wallet/withdraw.php（amount=90，Accept: application/json）。6 个请求全部 status=200 且均返回 {"status":"paid","amount":90,"balance":0,"receipt_id":2..7}，耗时统一约 0.357s（正好落在源码 usleep(350000) 窗口内），即全部以同一过期余额快照通过第 5 行比较并各自落库。GET /wallet/index.php 显示可用余额 ¥0.00、提现记录 7 条，资金流水列出 6 笔 ¥90.00（流水号 2-7）加 1 笔 ¥10.00（流水号 1）。合计提现 550.00 元，而账户初始仅 100.00 元，实际只应成交 10 元那一笔；凭空多出 450.00 元的成功提现。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`3fe485e111844c29a04310c69819a9dd`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`3fe485e111844c29a04310c69819a9dd` script finished exit=0
  - 适配脚本：`d8ebc3c8-adapted-poc.php`（见证据包 evidence/）
  - 备注：仅用 1 个作业 3fe485e111844c29a04310c69819a9dd（alice，exit 0），正常侧与并发攻击侧 stdout 连续保留，作业后宿主 postcondition 记录 balance 100.00→0.00。6 个并发请求使用同一会话 Cookie 但各自独立 opener，无 CookieJar 共享；源码第 3 行 session_write_close 与第 6 行 usleep(350000) 解释并发窗口成立。未额外提现或使用特权身份。

- 正式复核 `cf27025487b54d5196dd5bd6d640be93`：复核确认；引用 revision 1 / verification `d8ebc3c8b7c44603a41f50313505eb28`
  - 理由：正常侧观测：alice 登录后钱包显示余额 100.00、提现记录 0，取得 48 位 csrf，单次 POST amount=10 返回 {"status":"paid","amount":10,"balance":90,"receipt_id":1}，无并发时扣减正确。攻击侧观测：余额 90.00 时以 Barrier 同时发起 6 个 amount=90 的 POST，全部 200 且均返回 paid，receipt 2..7、balance 均为 0，耗时统一约 0.357s 正落在 usleep(350000) 窗口内；事后钱包显示余额 ¥0.00、7 条提现记录、流水含 6 笔 ¥90.00 加 1 笔 ¥10.00，合计 550 元，超本金 450 元。该观测与源码第 3 行 session_write_close 释放锁、第 4 行旧余额快照、第 6 行延时、第 7 行覆盖式 UPDATE、第 8 行流水插入的非原子链路完全吻合，竞态可被普通用户稳定利用，确认该 verified 结论。
  - 复核观测：正常侧 alice 正常登录（余额 100.00），GET /wallet/index.php 显示可用余额 ¥100.00、提现记录 0，并从表单取得真实 48 位 csrf。单次正常 POST /wallet/withdraw.php amount=10 返回 200 正文 {"status":"paid","amount":10,"balance":90,"receipt_id":1}，余额按单笔正确扣减为 90.00。说明在无并发时该接口按预期只扣一次。；攻击侧 同一 alice 会话、同一 csrf，在余额 90.00 时以 Barrier 同时发起 6 个 POST /wallet/withdraw.php（amount=90，Accept: application/json）。6 个请求全部 status=200 且均返回 {"status":"paid","amount":90,"balance":0,"receipt_id":2..7}，耗时统一约 0.357s（正好落在源码 usleep(350000) 窗口内），即全部以同一过期余额快照通过第 5 行比较并各自落库。GET /wallet/index.php 显示可用余额 ¥0.00、提现记录 7 条，资金流水列出 6 笔 ¥90.00（流水号 2-7）加 1 笔 ¥10.00（流水号 1）。合计提现 550.00 元，而账户初始仅 100.00 元，实际只应成交 10 元那一笔；凭空…

### C-07 订单详情接口按订单 id 查询未校验归属，任意登录用户可越权读取他人订单

- verification `df197aa7c03c491aaff6d68d26d4bfbd`（finding `907de1688e454a18a57c6db4886f47e9` revision 1，context `dc4b8719815c4938893c254a30546465`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice 登录后 GET /orders/index.php 返回 200，只列出自己的订单 SG-1001（晨光手冲壶 × 1，¥129.00），详情链接为 id=1；GET /orders/detail.php?id=1（Accept: application/json）返回 200 与 user_id=1、order_no=SG-1001、total=129.00、private_note=ALICE_PRIVATE_ORDER_delivery_morning，属于本人订单。
  - 攻击侧观测：同一 alice 会话请求 GET /orders/detail.php?id=2（订单属于 user_id=2 的 bob）：JSON 模式返回 200 与 {"id":2,"order_no":"SG-1002","user_id":2,...,"total":"158.00","private_note":"BOB_PRIVATE_ORDER_gift_for_family","username":"bob"}；HTML 模式同样 200，页面渲染「等待配送 SG-1002 / 商品 山野帆布包 / 购买人 bob / 数量 2 / 实付金额 ¥158.00 / 配送备注 BOB_PRIVATE_ORDER_gift_for_family」。alice 的订单中心只列出自己的 SG-1001，却可通过修改 id 读取 bob 的订单号、金额与私密备注。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`13862c583faf4fc791807ace47560db1`；`14ede60605324f669f3aff043c094a45`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`14ede60605324f669f3aff043c094a45` script finished exit=0；`13862c583faf4fc791807ace47560db1` script finished exit=0
  - 适配脚本：`df197aa7-adapted-idor_order_detail.py`（见证据包 evidence/）
  - 备注：攻击者与被越权数据分属不同用户：alice(id=1) 读取 bob(id=2) 的订单 2；订单归属由 JSON 的 user_id/username 字段与 setup.php 第 22 行 bob 的 SG-1002 记录共同确认。正常与攻击使用同一 alice 会话、同一路由，唯一差异是 id 参数。宿主预执行作业 13862c583faf4fc791807ace47560db1 与本次作业 14ede60605324f669f3aff043c094a45 结果一致（id=3..5 返回 404，说明只是库中无该订单而非有归属校验）。

- 正式复核 `c3bf41d81b104ce781f7b5c84e449143`：复核确认；引用 revision 1 / verification `df197aa7c03c491aaff6d68d26d4bfbd`
  - 理由：正常侧：alice 登录后 /orders/index.php 仅列出本人 SG-1001 与 id=1 详情链接，detail.php?id=1 返回 user_id=1 与本人 private_note，符合预期。攻击侧：同一会话 GET /orders/detail.php?id=2（属于 bob）返回 200，JSON 含 user_id=2、order_no=SG-1002、total=158.00、private_note=BOB_PRIVATE_ORDER_gift_for_family，HTML 页面亦渲染 bob 的订单号、金额与配送备注；id=3-5 返回 404 仅为种子数据不存在，不影响 id 遍历。两个作业均成功且无错误，与源码缺失归属校验的结论吻合，确认该 IDOR 成立。
  - 复核观测：正常侧 alice 登录后 GET /orders/index.php 返回 200，只列出自己的订单 SG-1001（晨光手冲壶 × 1，¥129.00），详情链接为 id=1；GET /orders/detail.php?id=1（Accept: application/json）返回 200 与 user_id=1、order_no=SG-1001、total=129.00、private_note=ALICE_PRIVATE_ORDER_delivery_morning，属于本人订单。；攻击侧 同一 alice 会话请求 GET /orders/detail.php?id=2（订单属于 user_id=2 的 bob）：JSON 模式返回 200 与 {"id":2,"order_no":"SG-1002","user_id":2,...,"total":"158.00","private_note":"BOB_PRIVATE_ORDER_gift_for_family","username":"bob"}；HTML 模式同样 200，页面渲染「等待配送 SG-1002 / 商品 山野帆布包 / 购买人 bob / 数量 2 / 实付金额 ¥158.00 / 配送备注 BOB_PRIVATE_ORDER_gift_for_family」。alice 的订单中心只列出自己的 SG-1001，却可通过修改 id 读取 bob 的订单号、金额与私密备注。

### C-08 注册/登录使用无盐 md5 存储与校验口令

- verification `0cf388a8bf6442a3be8fddd9ac090728`（finding `10078f1ecd984a7982f4adba159aadde` revision 1，context `9ef4825c8bd7434888e79997b2be3c10`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：匿名注册新账号 wc26849953（密码 PocPass123!，8 位以上）返回 200 且页面提示「注册成功」；随后用该用户名/明文密码登录返回 200、最终 URL 为 http://lab30/、页面含「退出」，说明注册与登录流程正常工作（登录校验与库中摘要一致）。
  - 攻击侧观测：通过运营侧 SQL 注入点（同一作业内，operator 会话，q 为 UNION 查询 users.password_md5）读取该新账号存储的口令摘要：row: id=5, username=wc26849953, email 字段=4e42bdc04f1fdc145c553a18ddf8e06d；本地计算 md5("PocPass123!")=4e42bdc04f1fdc145c553a18ddf8e06d，两者完全相等，HASH_IS_MD5_OF_PASSWORD True，长度 32 且非 $2 前缀。说明库中 password_md5 就是无盐、单轮 MD5(明文)，一旦摘要泄露即可用彩虹表/GPU 快速还原。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`57796f8752564e538de86da2075e1e8e`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`57796f8752564e538de86da2075e1e8e` script finished exit=0
  - 适配脚本：`0cf388a8-adapted-poc.php`（见证据包 evidence/）
  - 备注：源码 applicability=match：register.php:6 仅校验长度≥8（无强度约束），register.php:8 以 md5($password) 写入 password_md5；login.php:7 用 hash_equals($row['password_md5'], md5($_POST['password'])) 校验；setup.php:7 列定义 password_md5 CHAR(32)，setup.php:17 种子用户同样 md5。运行时以已知明文注册新账号 wc26849953（密码 PocPass123!），登录成功（final_url 为 /，页面含退出），再经既有 SQL 注入通道读取其存储摘要，结果与 md5(明文) 完全一致且为 32 位十六进制，直接证明无盐 MD5 存储。该读取通道为运营侧 /ops/members.php 的 LIKE 注入（另一独立发现），此处仅用于取得摘要以核对存储格式，不改变本发现的判定；攻击者无需该通道即可在数据库泄露场景下实施哈希破解。

- 正式复核 `2a321952232d47bfaf8ae11892f655c5`：复核确认；引用 revision 1 / verification `0cf388a8bf6442a3be8fddd9ac090728`
  - 理由：读取两侧全文：正常侧匿名注册 wc26849953 后登录成功（最终 URL http://lab30/、页面含退出），说明注册登录链路正常；攻击侧经运营 SQL 注入读出该账号库中摘要 4e42bdc04f1fdc145c553a18ddf8e06d，与 md5("PocPass123!") 完全相等、长度 32 且非 $2 前缀，正式确认无盐单轮 MD5 存储口令。
  - 复核观测：正常侧 匿名注册新账号 wc26849953（密码 PocPass123!，8 位以上）返回 200 且页面提示「注册成功」；随后用该用户名/明文密码登录返回 200、最终 URL 为 http://lab30/、页面含「退出」，说明注册与登录流程正常工作（登录校验与库中摘要一致）。；攻击侧 通过运营侧 SQL 注入点（同一作业内，operator 会话，q 为 UNION 查询 users.password_md5）读取该新账号存储的口令摘要：row: id=5, username=wc26849953, email 字段=4e42bdc04f1fdc145c553a18ddf8e06d；本地计算 md5("PocPass123!")=4e42bdc04f1fdc145c553a18ddf8e06d，两者完全相等，HASH_IS_MD5_OF_PASSWORD True，长度 32 且非 $2 前缀。说明库中 password_md5 就是无盐、单轮 MD5(明文)，一旦摘要泄露即可用彩虹表/GPU 快速还原。

### C-09 下单接口信任客户端 price 字段，单价与总价可被篡改为任意非负值

- verification `4923efcca7f2434398c12bdd0eae7cab`（finding `9dc01b5fc875445496274debba22d73d` revision 1，context `06865c77f43346cdb187c338052da455`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice 登录后 GET /catalog/detail.php?id=1 取得真实单价 129.00 与有效 csrf；按表单原值提交 product_id=1、quantity=1、price=129.00 返回 303 Location /orders/detail.php?id=6，订单详情显示「商品 晨光手冲壶、购买人 alice、数量 1、实付金额 ¥129.00」，与商品真实价格一致。
  - 攻击侧观测：同一 alice 会话、同一 csrf 与商品 id=1（真实单价 129.00），只把 price 改为 0.01、quantity=2 提交 /orders/create.php：返回 303 Location /orders/detail.php?id=7，订单详情显示「商品 晨光手冲壶、购买人 alice、数量 2、实付金额 ¥0.02」。即 2 件共 ¥258 的商品按 ¥0.02 成交，客户端单价被原样持久化并参与总额计算（0.01×2=0.02）。宿主先前同一会话的正常订单（id=3）与攻击订单（id=4）也均为 200 且攻击订单详情含 0.01。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`0c0fac686827432195ee2465a4230011`；`a3974c982c01436684673da9904de90b`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`a3974c982c01436684673da9904de90b` script finished exit=0；`0c0fac686827432195ee2465a4230011` script finished exit=0
  - 适配脚本：`4923efcc-adapted-price_manipulation_poc.py`（见证据包 evidence/）
  - 备注：正常与攻击订单都在同一 alice 会话、同一表单 csrf 下完成，唯一差异是客户端提交的 price。攻击侧由服务端订单详情页回显 ¥0.02（数据库 orders.unit_price/total 已按客户端值写入，源码第 7 行 INSERT 参数即 $price/$total）。注：两次下单也各扣减 1/2 件库存，属源码第 6 行行为，未影响金额结论。宿主预执行作业 0c0fac686827432195ee2465a4230011 独立复现了「detail contains 0.01: True」。未使用特权身份。

- 正式复核 `c8e0498894874eeaa241e777afaaab04`：复核确认；引用 revision 1 / verification `4923efcca7f2434398c12bdd0eae7cab`
  - 理由：读取两侧全文：正常侧同一 alice 会话按表单真实单价 129.00、数量 1 提交，订单详情实付 ¥129.00；攻击侧保持同一 csrf 与商品 id=1，仅改 price=0.01、quantity=2 提交即得订单详情实付 ¥0.02（商品原价合计 ¥258），客户端单价被原样持久化，确认单价篡改成立。
  - 复核观测：正常侧 alice 登录后 GET /catalog/detail.php?id=1 取得真实单价 129.00 与有效 csrf；按表单原值提交 product_id=1、quantity=1、price=129.00 返回 303 Location /orders/detail.php?id=6，订单详情显示「商品 晨光手冲壶、购买人 alice、数量 1、实付金额 ¥129.00」，与商品真实价格一致。；攻击侧 同一 alice 会话、同一 csrf 与商品 id=1（真实单价 129.00），只把 price 改为 0.01、quantity=2 提交 /orders/create.php：返回 303 Location /orders/detail.php?id=7，订单详情显示「商品 晨光手冲壶、购买人 alice、数量 2、实付金额 ¥0.02」。即 2 件共 ¥258 的商品按 ¥0.02 成交，客户端单价被原样持久化并参与总额计算（0.01×2=0.02）。宿主先前同一会话的正常订单（id=3）与攻击订单（id=4）也均为 200 且攻击订单详情含 0.01。

### C-10 auth/continue.php next 参数未校验导致登录后开放重定向

- verification `aa926fda9c454659bf0b7678fdef333c`（finding `60dbc457afba403b9467566a0d2b58c6` revision 1，context `eada2b0c95e84877868be8cf7a7232fa`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：以 alice 身份登录成功（LOGIN 200 http://lab30/）后访问 /auth/continue.php?next=/orders/index.php，服务端返回 302，Location 为同站相对路径 '/orders/index.php'，属于正常的站内跳转行为。
  - 攻击侧观测：登录态下访问 /auth/continue.php?next=https://attacker.example/phish，服务端返回 302 且 Location: https://attacker.example/phish；再以协议相对形式 //attacker.example/phish 请求，Location 同样为 //attacker.example/phish。外部主机未被拒绝、未做白名单或 URL 解析校验，响应头原文直接回显攻击者控制的跳转目标，构成开放重定向。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`e7a2146dccb34aba8b621c8de9b3aa2e`；`2841a88e13b04db5a0d1dead6609a7fa`
  - 结论结束原因：completed；执行阶段结束原因：sdk_api_error
  - 作业：`2841a88e13b04db5a0d1dead6609a7fa` script finished exit=0
  - 适配脚本：`aa926fda-adapted-poc.php`（见证据包 evidence/）
  - 备注：证据来自 job 2841a88e13b04db5a0d1dead6609a7fa 的 stdout 原文（ev-6e0af4a766be7336），包含正常相对路径与两种外部跳转（绝对 URL、协议相对 URL）的完整 STATUS/LOCATION 记录；另一 job e7a2146dccb34aba8b621c8de9b3aa2e 因脚本自身 HTTPError 异常退出且 evidence_usable=false，未作为结论依据。open_redirect 属服务端响应头缺陷，本次通过 HTTP 客户端实际请求获得带攻击者域名的 Location，未使用浏览器，故 browser_execution=false。

- 正式复核 `4d011c510db54e3a80e39ba173297292`：复核确认；引用 revision 1 / verification `aa926fda9c454659bf0b7678fdef333c`
  - 理由：读取两侧全文：正常侧登录后 next=/orders/index.php 返回 302 且 Location 为同站相对路径；攻击侧 next=https://attacker.example/phish 与 //attacker.example/phish 均在同一 302 响应中原样回显到 Location 头，未见白名单或协议过滤，确认开放重定向。
  - 复核观测：正常侧 以 alice 身份登录成功（LOGIN 200 http://lab30/）后访问 /auth/continue.php?next=/orders/index.php，服务端返回 302，Location 为同站相对路径 '/orders/index.php'，属于正常的站内跳转行为。；攻击侧 登录态下访问 /auth/continue.php?next=https://attacker.example/phish，服务端返回 302 且 Location: https://attacker.example/phish；再以协议相对形式 //attacker.example/phish 请求，Location 同样为 //attacker.example/phish。外部主机未被拒绝、未做白名单或 URL 解析校验，响应头原文直接回显攻击者控制的跳转目标，构成开放重定向。

### C-11 content/page.php 的 page 参数未经净化拼入 include，导致路径遍历与本地/远程文件包含

- verification `dccfee757e234b03a3b16bf9f79c99c5`（finding `21722ca9ff6a4e6e829697ca77a80770` revision 1，context `74bee7f35c164e2eb60693b447528c0f`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：guest 访问 /content/page.php?page=home：HTTP 200，<h1>内容中心</h1> 后输出正常模板「为日常，选一点喜欢的东西 / 从商品、服务到售后，拾光希望让每一份选择都更从容。」，正文不含 SHOP_INTERNAL_ 标记。
  - 攻击侧观测：匿名 guest 请求 /content/page.php?page=../../../../lib/shop/vault/account（另 ../../../../../var/lib/shop/vault/account、../../../../../../var/lib/shop/vault/account 同样命中）：HTTP 200，页面中出现 vault/account.php 执行结果 SHOP_INTERNAL_9ee02d854bf1b6156e492647；逐级对照中前缀深度不足的路径（如 ../vault/account、../../../lib/shop/vault/account）marker=False，说明是穿越到 views 目录之外的 /var/lib/shop/vault/account.php 并被 include 执行，而非正常模板。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`2d073e12e89948ecb72cc20a5930c083`；`5e86febbb6c742dd8836e691eafa447e`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`2d073e12e89948ecb72cc20a5930c083` script finished exit=0；`5e86febbb6c742dd8836e691eafa447e` script finished exit=0
  - 适配脚本：`dccfee75-adapted-lfi_page_poc.py`（见证据包 evidence/）
  - 备注：源码 applicability=match：content/page.php:2 直接取 $_GET['page']（默认 home），第3行闭包内 include APP_ROOT.'/resources/views/'.$name.'.php'，无 basename/realpath/白名单；setup.php:25-26,34-35 在 data_dir()/vault 下生成 internal.txt 与 account.php，account.php 内容为 <?php echo "<随机 marker>";。攻击侧回显的 SHOP_INTERNAL_9ee02d854bf1b6156e492647 正是该文件执行输出的内部 marker（随机、不可从公开模板获得）。注意：审计脚本建议的 page=../vault/account 未命中（该深度只到 app/resources/vault），实际命中的是 ../ 深度足以到达 /var/lib/shop 的路径，因此按运行时目录结构采用 ../../../../lib/shop/vault/account 等最小变体；这不改变漏洞性质。正常侧 page=home 仅输出内容中心首页文案，无 marker。guest 身份可访问，符合公开无需登录的前提。

- 正式复核 `2608fecdcfb44836ab8c9fc4423e2777`：复核确认；引用 revision 1 / verification `dccfee757e234b03a3b16bf9f79c99c5`
  - 理由：正常侧 page=home 返回 200 且输出正常模板文本、无内部 marker；攻击侧匿名 guest 用 ../../../../lib/shop/vault/account 等路径返回 200 并出现 setup.php 生成的 SHOP_INTERNAL_9ee02d854bf1b6156e492647，而 ../vault/account 等同前缀不足路径 marker=False，符合穿越出 views 目录并被 include 执行的判读，动态观测与源码结论一致。
  - 复核观测：正常侧 guest 访问 /content/page.php?page=home：HTTP 200，<h1>内容中心</h1> 后输出正常模板「为日常，选一点喜欢的东西 / 从商品、服务到售后，拾光希望让每一份选择都更从容。」，正文不含 SHOP_INTERNAL_ 标记。；攻击侧 匿名 guest 请求 /content/page.php?page=../../../../lib/shop/vault/account（另 ../../../../../var/lib/shop/vault/account、../../../../../../var/lib/shop/vault/account 同样命中）：HTTP 200，页面中出现 vault/account.php 执行结果 SHOP_INTERNAL_9ee02d854bf1b6156e492647；逐级对照中前缀深度不足的路径（如 ../vault/account、../../../lib/shop/vault/account）marker=False，说明是穿越到 views 目录之外的 /var/lib/shop/vault/account.php 并被 include 执行，而非正常模板。

### C-12 商品搜索 q 参数拼接 SQL 导致注入（catalog/index.php）

- verification `2418fd4001d54bbbbb336d2c044fa96c`（finding `5c7ff87a89fa404281d1674556896450` revision 1，context `eee9f9243d77454b8a6889d75cd9ec78`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：同一 guest 会话正常搜索：GET /catalog/index.php（无 q）返回 200，共找到 4 件商品（晨光手冲壶 ¥129.00、山野帆布包 ¥79.00、周末香氛蜡烛 ¥59.00、留白手账本 ¥39.00）；q=晨光 返回 200、共 1 件商品（晨光手冲壶，¥129.00）。正常结果只包含 products 表中的商品行，不含任何 users 数据。
  - 攻击侧观测：guest 未登录直接请求 /catalog/index.php?q=%27%20UNION%20SELECT%20id,username,role,balance,tier,%27x%27%20FROM%20users--%20- 返回 200，页面从 4 件商品变为 8 条结果，新增 4 行来自 users 表：alice/customer/100.00、bob/customer/100.00、operator/operator/100.00、admin/admin/100.00（商品名位置显示 username，描述位置显示 role，价格位置显示 balance，库存位置显示 tier）。另一请求 q=拾光' 触发 503「服务暂时不可用」错误页，说明单引号直接改变了 SQL 结构。攻击行不可能由 products 表产生，证明 q 参数被拼接执行任意 SELECT。
  - 已保存作业事实：3 个；满足执行及前提检查的作业：3 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`438a7904622c4b0f88bea9b72540576a`；`15f974faa05a459e9cde76f2f66b7da7`；`17962621cf304a82962505962cd03c43`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`15f974faa05a459e9cde76f2f66b7da7` script finished exit=0；`17962621cf304a82962505962cd03c43` script finished exit=0；`438a7904622c4b0f88bea9b72540576a` script finished exit=0
  - 适配脚本：`2418fd40-adapted-poc_sqli_catalog.py`（见证据包 evidence/）
  - 备注：商品目录无需登录，攻击均以 guest 直接发起。正常侧：无 q 时 4 件商品；q=晨光 时 1 件（晨光手冲壶 ¥129.00）。攻击侧：UNION 注入新增 4 行 users 数据并回显 role/balance。宿主预执行作业 438a7904622c4b0f88bea9b72540576a 的正常请求 200、攻击请求 503 与本结论一致（其攻击载荷因列名 password 不存在而报错，未作为攻击证据）。未修改任何数据。

- 正式复核 `79d3e334866d474ca7d0439f0d81ea27`：复核确认；引用 revision 1 / verification `2418fd4001d54bbbbb336d2c044fa96c`
  - 理由：读取两侧完整观测：guest 基线 GET /catalog/index.php 返回 200 且仅 4 件 products 商品，q=晨光 返回 1 件；攻击侧 q=' UNION SELECT id,username,role,balance,tier,'x' FROM users-- - 返回 200 且结果从 4 条变为 8 条，新增 4 行为 users 表的 alice/bob/operator/admin 及角色与余额，另一请求 q=拾光' 触发 503 数据库错误页。额外数据不可能来自 products 表，证明 q 参数被拼接执行任意 SELECT，与源码行 4 的字符串拼接一致。
  - 复核观测：正常侧 同一 guest 会话正常搜索：GET /catalog/index.php（无 q）返回 200，共找到 4 件商品（晨光手冲壶 ¥129.00、山野帆布包 ¥79.00、周末香氛蜡烛 ¥59.00、留白手账本 ¥39.00）；q=晨光 返回 200、共 1 件商品（晨光手冲壶，¥129.00）。正常结果只包含 products 表中的商品行，不含任何 users 数据。；攻击侧 guest 未登录直接请求 /catalog/index.php?q=%27%20UNION%20SELECT%20id,username,role,balance,tier,%27x%27%20FROM%20users--%20- 返回 200，页面从 4 件商品变为 8 条结果，新增 4 行来自 users 表：alice/customer/100.00、bob/customer/100.00、operator/operator/100.00、admin/admin/100.00（商品名位置显示 username，描述位置显示 role，价格位置显示 balance，库存位置显示 tier）。另一请求 q=拾光' 触发 503「服务暂时不可用」错误页，说明单引号直接改变了 SQL 结构。攻击行不可能由 products 表产生，证明 q 参数被拼接执行任意 SELECT。

### C-13 ops/xml-import.php 以 LIBXML_NOENT|LIBXML_DTDLOAD 解析请求 XML，导致 XXE 本地文件读取并回显

- verification `d78f219e97ef46939c32dbcd0f610bc8`（finding `f32557d8e70f4a51b5831f8018091349` revision 1，context `1cddc1ff37b14f589c92e2d899428a78`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 登录成功（LOGIN 200、页面含“退出”），GET /ops/xml-import.php 返回 200 并取到真实 csrf token；POST 正常 XML <config><title>normal-title</title></config>，HTTP 200，导入结果 <pre> 中仅为字面文本 normal-title。
  - 攻击侧观测：同一 operator 会话使用同一 CSRF token POST /ops/xml-import.php，xml 为 <?xml version="1.0"?><!DOCTYPE config [<!ENTITY ext SYSTEM "file:///etc/passwd">]><config><title>&ext;</title></config>。HTTP 200，响应 <pre> 中回显 /etc/passwd 内容：root:x:0:0:root:/root:/bin/bash、daemon:x:1:1、www-data:x:33:33 等多行，ATTACK_HAS_ROOT=True，证明外部实体被实际解析并读取了本地文件。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`cd0a2ab46fe54e279ac5dfa03784b486`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`cd0a2ab46fe54e279ac5dfa03784b486` script finished exit=0
  - 适配脚本：`d78f219e-adapted-xxe_xml_import.py`（见证据包 evidence/）
  - 备注：单作业 cd0a2ab46fe54e279ac5dfa03784b486，operator 身份（源码行 2 明确要求 operator/admin，前置/后置均为 operator 正常）。正常与攻击 XML 的唯一差异是 DOCTYPE 外部实体定义与 title 中的 &ext; 引用；正常输出为字面 normal-title，攻击输出为 /etc/passwd 行内容，差异直接归因于 LIBXML_NOENT&#124;LIBXML_DTDLOAD 启用的外部实体展开。未使用 admin 冒充，也未读取工作区内部标记。

- 正式复核 `9b2bd8cbe5f246d495f360ed6eceb0d7`：复核确认；引用 revision 1 / verification `d78f219e97ef46939c32dbcd0f610bc8`
  - 理由：读取两侧完整观测：operator 登录后取到真实 csrf，正常 XML <config><title>normal-title</title></config> 的 <pre> 仅显示 normal-title；攻击侧同一会话首次通过 CSRF 校验提交带 <!DOCTYPE ... <!ENTITY ext SYSTEM "file:///etc/passwd"> 且 title 引用 &ext; 的 XML，HTTP 200 且 <pre> 回显 root:x:0:0 至 www-data 等多行 /etc/passwd，ATTACK_HAS_ROOT=True，证明外部实体被加载并读取本地文件，与 xml-import.php:3 的 LIBXML_NOENT&#124;LIBXML_DTDLOAD 一致。
  - 复核观测：正常侧 operator 登录成功（LOGIN 200、页面含“退出”），GET /ops/xml-import.php 返回 200 并取到真实 csrf token；POST 正常 XML <config><title>normal-title</title></config>，HTTP 200，导入结果 <pre> 中仅为字面文本 normal-title。；攻击侧 同一 operator 会话使用同一 CSRF token POST /ops/xml-import.php，xml 为 <?xml version="1.0"?><!DOCTYPE config [<!ENTITY ext SYSTEM "file:///etc/passwd">]><config><title>&ext;</title></config>。HTTP 200，响应 <pre> 中回显 /etc/passwd 内容：root:x:0:0:root:/root:/bin/bash、daemon:x:1:1、www-data:x:33:33 等多行，ATTACK_HAS_ROOT=True，证明外部实体被实际解析并读取了本地文件。

### C-14 account/profile.php 的 url 参数未经转义进入 href 属性导致反射型 XSS

- verification `21351765b9534950b924d68ee68564bc`（finding `3d2ab8abc1e5475fb4ee565ef1570c2f` revision 1，context `0bcecb41c7f94585a1f979bc37a0cb71`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：job b0b6713cab5e48bfb0702e944f171d3e：alice 会话（页面显示林晓/退出）加载 /account/profile.php?url=https%3A%2F%2Fexample.com，标题「个人主页预览 · 拾光商城」，body_text 含「访问个人主页」，dialogs=[]、console_errors=[]，无脚本执行。
  - 攻击侧观测：job a80438c9adb541f6a1d8cf1734808199：alice 会话加载 /account/profile.php?url=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E，browser dialogs 为 ["1"]，即注入的 <img onerror> 在同源页面执行 alert(1)；同时出现 404 资源加载失败（即 img src=x 的请求），body_text 中链接处显示残片「">访问个人主页」，说明双引号已闭合 href 属性并注入新标签。
  - 已保存作业事实：3 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`0da35582eb5246e099a2e275aa2db770`；`b0b6713cab5e48bfb0702e944f171d3e`；`a80438c9adb541f6a1d8cf1734808199`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`b0b6713cab5e48bfb0702e944f171d3e` browser finished exit=0；`a80438c9adb541f6a1d8cf1734808199` browser finished exit=0
  - 产物：`21351765b9534950b924d68ee68564bc-b0b6713cab5e48bfb0702e944f171d3e-screenshot.png`；`21351765b9534950b924d68ee68564bc-a80438c9adb541f6a1d8cf1734808199-screenshot.png`
  - 备注：源码快照 applicability=match。profile.php:3 输出 '<a id="profile-link" href="'.$url.'">' 未调用 h()，而同页 form_input 内部对 value 调用 h()（bootstrap.php:46），page() 仅对标题/导航/显示名转义（bootstrap.php:51-58），第59行直接执行闭包，故 href 处的用户输入不受保护。对照仅 url 参数不同，身份同为 alice，正常侧无弹窗、攻击侧弹窗成立。审计脚本 job 0da35582eb5246e099a2e275aa2db770 只 GET 了登录页未提交凭据，返回 401，evidence_usable=false，不作为证据引用。

- 正式复核 `e4c9cee69a334b74a69f76e5e84b8101`：复核确认；引用 revision 1 / verification `21351765b9534950b924d68ee68564bc`
  - 理由：读取两侧观测：正常侧 b0b6713cab5e48bfb0702e944f171d3e 以 alice 会话加载 profile.php?url=https%3A%2F%2Fexample.com，标题正常、dialogs=[]、console_errors=[]，无脚本执行；攻击侧 a80438c9adb541f6a1d8cf1734808199 加载 url=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E，browser_execution=true 且 dialogs=["1"]，body_text 链接处残留「">访问个人主页」表明双引号已闭合 href 属性，同时 img src=x 触发 404 请求。与 profile.php:3 未调用 bootstrap.php:10 h() 的静态证据一致，反射型 XSS 判为 confirmed。
  - 复核观测：正常侧 job b0b6713cab5e48bfb0702e944f171d3e：alice 会话（页面显示林晓/退出）加载 /account/profile.php?url=https%3A%2F%2Fexample.com，标题「个人主页预览 · 拾光商城」，body_text 含「访问个人主页」，dialogs=[]、console_errors=[]，无脚本执行。；攻击侧 job a80438c9adb541f6a1d8cf1734808199：alice 会话加载 /account/profile.php?url=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E，browser dialogs 为 ["1"]，即注入的 <img onerror> 在同源页面执行 alert(1)；同时出现 404 资源加载失败（即 img src=x 的请求），body_text 中链接处显示残片「">访问个人主页」，说明双引号已闭合 href 属性并注入新标签。

### C-15 account/update.php 批量赋值允许任意用户修改 role/balance/tier

- verification `548bd73efc3648a59b12ed6b1faf4a98`（finding `15250777c73d43b88defa26f1d264b08` revision 1，context `376d830700c9451592e1ce0a654d0bd4`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice 正常登录后 GET /account/update.php 取得真实 csrf（48 位）；POST display_name=Alice Normal&nickname=alice&email=alice@example.com&homepage=# 并带 Accept: application/json，响应 200，正文 {"id":1,"username":"alice","display_name":"Alice Normal","email":"alice@example.com","role":"customer","balance":"100.00","tier":"standard",...}。角色、余额、等级均未被普通资料合法修改影响。
  - 攻击侧观测：同一 alice 会话、同一 csrf，POST display_name=Alice Normal&role=admin&balance=999999&tier=vip，响应 200，正文 {"id":1,...,"role":"admin","balance":"999999.00","tier":"vip",...}。随后 GET /account/update.php 返回的导航中出现 /ops/index.php「运营工作台」链接（源码中仅 operator/admin 显示），表单显示名称变为 Alice Normal。宿主 postcondition 记录 state_changes：balance 100.00→999999.00、role customer→admin、tier standard→vip。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`d03ac2c1e0934aed9e0a76d7126c5ba1`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`d03ac2c1e0934aed9e0a76d7126c5ba1` script finished exit=0
  - 适配脚本：`548bd73e-adapted-poc.php`（见证据包 evidence/）
  - 备注：仅使用 1 个作业 d03ac2c1e0934aed9e0a76d7126c5ba1（alice，exit 0），正常侧与攻击侧输出在同一 stdout 中顺序完整保留。未执行提现，未使用特权身份；提权结果由接口 JSON 回读、后续页面导航与宿主状态对比三方一致确认。

- 正式复核 `158a16de4e214e34b8d9b942da164d4b`：复核确认；引用 revision 1 / verification `548bd73efc3648a59b12ed6b1faf4a98`
  - 理由：读取两侧观测：正常侧 d03ac2c1e0934aed9e0a76d7126c5ba1 中 alice 取得真实 csrf 后仅提交 display_name/nickname/email/homepage，响应 JSON 中 role=customer、balance=100.00、tier=standard 未变；攻击侧同一会话同一 csrf 追加 role=admin&balance=999999&tier=vip，响应回读 role=admin、balance=999999.00、tier=vip，宿主 state_changes 记录三列 before/after，且页面导航出现原仅 operator/admin 可见的运营入口。与 update.php:4-6 列白名单含敏感列、仅按 id 更新的源码一致，批量赋值判为 confirmed。
  - 复核观测：正常侧 alice 正常登录后 GET /account/update.php 取得真实 csrf（48 位）；POST display_name=Alice Normal&nickname=alice&email=alice@example.com&homepage=# 并带 Accept: application/json，响应 200，正文 {"id":1,"username":"alice","display_name":"Alice Normal","email":"alice@example.com","role":"customer","balance":"100.00","tier":"standard",...}。角色、余额、等级均未被普通资料合法修改影响。；攻击侧 同一 alice 会话、同一 csrf，POST display_name=Alice Normal&role=admin&balance=999999&tier=vip，响应 200，正文 {"id":1,...,"role":"admin","balance":"999999.00","tier":"vip",...}。随后 GET /account/update.php 返回的导航中出现 /ops/index.php「运营工作台」链接（源码中仅 operator/admin 显示），表单显示名称变为 Alice Normal。宿主 postcondition 记录 state_changes：balance 100.00→999999.00、role customer→admin、tier standard→vip。

### C-16 start_session 允许外部可控 SID 且未在登录后重生成，导致会话固定/劫持

- verification `7b0fdade72a04551aa9bc73325b3af7d`（finding `16ccd319c0254152a39799e78fa53c57` revision 1，context `62f4e78abd594d7da639ce61a8cb0805`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：不带 sid 的正常登录：GET /auth/login.php 由服务端下发随机 32 位十六进制 SID（Set-Cookie: SHOPSESSID=100e1ce87e642eddd8992cbb1fddb3bf），POST 登录后 Cookie 仍为该服务端生成值。正常登录不使用攻击者预设值（NORMAL_SID_IS_FIXED False，长度 32）。
  - 攻击侧观测：攻击者预先选定 SID=attackerfixedsid123456。受害者打开 /auth/login.php?sid=attackerfixedsid123456，响应 200 并回写 Set-Cookie: SHOPSESSID=attackerfixedsid123456（客户端可控值被接受）；携带该链接 POST 登录后，受害者 Cookie 仍为 SHOPSESSID=attackerfixedsid123456（VICTIM_SID_EQUALS_FIXED True），登录成功写入 $_SESSION['user_id'] 但 SID 未重生成。随后一个从未登录、仅带 Cookie: SHOPSESSID=attackerfixedsid123456 的独立客户端 GET /account/index.php 返回 200，页面显示「林晓 / 用户名 alice / alice@shop.local」及退出链接，GET /wallet/index.php 返回 200 且显示可用余额 ¥100.00，构成对 alice 账户的完整会话劫持。对照：使用未参与登录的随机 SID attackercontrolsid98765 访问同页面返回 401「请求未完成」，说明攻击成功并非未认证绕过，而是该 SID 已绑定受害者身份。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`6c2ce65d8c654208b59e14e8ef485933`；`12359feba7a54130a9be0347f5d9a049`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`6c2ce65d8c654208b59e14e8ef485933` script finished exit=0；`12359feba7a54130a9be0347f5d9a049` script finished exit=0
  - 适配脚本：`7b0fdade-adapted-session_fixation_poc.py`（见证据包 evidence/）
  - 备注：作业 12359feba7a54130a9be0347f5d9a049（alice，exit 0，本上下文）给出完整对照；宿主预执行作业 6c2ce65d8c654208b59e14e8ef485933 的截断输出（ev-1074174f6f1b25b2）同样显示固定 SID 可访问账户页，与本实验一致。未使用特权身份，未修改任何业务数据，仅 GET 与登录。

- 正式复核 `6a97874f872e484a9baf56cc797334cf`：复核确认；引用 revision 1 / verification `7b0fdade72a04551aa9bc73325b3af7d`
  - 理由：正常侧：不带 sid 登录由服务端下发随机 32 位 SID，登录后 Cookie 不变，NORMAL_SID_IS_FIXED False。攻击侧：GET /auth/login.php?sid=attackerfixedsid123456 返回 Set-Cookie SHOPSESSID=attackerfixedsid123456，POST 登录后 VICTIM_SID_EQUALS_FIXED True，独立客户端仅携该 Cookie 访问 /account/index.php 得 alice 资料与退出链接、/wallet/index.php 得余额 ¥100.00；随机未登录 SID 返回 401。固定→劫持链路完整，与 bootstrap.php:13/17 与 auth/login.php:3/8 源码一致。
  - 复核观测：正常侧 不带 sid 的正常登录：GET /auth/login.php 由服务端下发随机 32 位十六进制 SID（Set-Cookie: SHOPSESSID=100e1ce87e642eddd8992cbb1fddb3bf），POST 登录后 Cookie 仍为该服务端生成值。正常登录不使用攻击者预设值（NORMAL_SID_IS_FIXED False，长度 32）。；攻击侧 攻击者预先选定 SID=attackerfixedsid123456。受害者打开 /auth/login.php?sid=attackerfixedsid123456，响应 200 并回写 Set-Cookie: SHOPSESSID=attackerfixedsid123456（客户端可控值被接受）；携带该链接 POST 登录后，受害者 Cookie 仍为 SHOPSESSID=attackerfixedsid123456（VICTIM_SID_EQUALS_FIXED True），登录成功写入 $_SESSION['user_id'] 但 SID 未重生成。随后一个从未登录、仅带 Cookie: SHOPSESSID=attackerfixedsid123456 的独立客户端 GET /account/index.php 返回 200，页面显示「林晓 / 用户名 alice / ali…

### C-17 ops/users.php 以客户端 Cookie role 判定管理员，任意登录用户可冒充 admin 读取全部用户邮箱与角色

- verification `f8619f1605fb4d579754e4a3ae0bd224`（finding `ec6cdc0fe29741aebf7dc60ec5aab87a` revision 1，context `180a4b2f68c84be298b5cd32f032ad13`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice（customer，会话检查 GET /account/index.php 返回 200 且已登录）请求 /ops/users.php，未设置 role Cookie：HTTP 403，正文 {"error":"人员管理需要管理员权限。"}，无任何用户数据返回。
  - 攻击侧观测：同一 alice 会话、同一请求头 Accept: application/json，仅额外加上客户端 Cookie "role=admin"：GET /ops/users.php 返回 HTTP 200，正文 {"access":"admin","users":[...]}，列出全部 4 个账号：alice/alice@shop.local/customer、bob/bob@shop.local/customer、operator/ops@shop.local/operator、admin/admin@shop.local/admin，说明仅凭客户端 Cookie 即通过管理员判定并越权读取全部用户邮箱与角色。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`221d60af3fa847268261972526b0e5bc`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`221d60af3fa847268261972526b0e5bc` script finished exit=0
  - 适配脚本：`f8619f16-adapted-poc.php`（见证据包 evidence/）
  - 备注：源码 applicability=match：users.php:2 先 require_user() 只校验登录，再 $role=(string)($_COOKIE['role']??$u['role'])，随后 if($role!=='admin') 才拒绝；bootstrap.php:33-36 的 require_user 未传 role 白名单，不校验角色。因此客户端 Cookie 覆盖服务端会话角色构成授权绕过。对照在同一作业、同一 alice 会话（服务端实际 role=customer，见作业 precondition）内完成，正常请求与攻击请求的唯一差异是新增 Cookie role=admin，服务端数据未发生改变。

- 正式复核 `22f08ba087e64d50937bec151f633093`：复核确认；引用 revision 1 / verification `f8619f1605fb4d579754e4a3ae0bd224`
  - 理由：正常侧：alice 会话请求 /ops/users.php 未设 role Cookie，HTTP 403 正文「人员管理需要管理员权限。」，无数据返回。攻击侧：同一 alice 会话、同一 Accept: application/json 仅增加 Cookie role=admin，返回 200 且 access=admin，列出全部 4 个账号的用户名/邮箱/角色。说明授权判定取自客户端 Cookie 而非会话角色，与 users.php:2 的 $_COOKIE['role'] 覆盖一致。
  - 复核观测：正常侧 alice（customer，会话检查 GET /account/index.php 返回 200 且已登录）请求 /ops/users.php，未设置 role Cookie：HTTP 403，正文 {"error":"人员管理需要管理员权限。"}，无任何用户数据返回。；攻击侧 同一 alice 会话、同一请求头 Accept: application/json，仅额外加上客户端 Cookie "role=admin"：GET /ops/users.php 返回 HTTP 200，正文 {"access":"admin","users":[...]}，列出全部 4 个账号：alice/alice@shop.local/customer、bob/bob@shop.local/customer、operator/ops@shop.local/operator、admin/admin@shop.local/admin，说明仅凭客户端 Cookie 即通过管理员判定并越权读取全部用户邮箱与角色。

### C-18 support/download.php file 参数路径遍历读取任意文件

- verification `3570b96d07be4c8ca580d16149e33d57`（finding `c4c8a046de93404aa739d4c080afe7f7` revision 1，context `8a3fa0591e844430957213d0ff8fdd50`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice 登录后（会话已建立）请求 /support/download.php?file=shipping.txt：HTTP 200，正文为「配送说明：工作日 48 小时内发货。」，即 docs 目录内的公开文档。
  - 攻击侧观测：同一 alice 会话请求 /support/download.php?file=../vault/internal.txt：HTTP 200，返回内部标记文件内容 'SHOP_INTERNAL_5124fbb3283ae91cea1f164c'（setup.php 在 data_dir/vault 生成的随机内部标记，非公开文档）；请求 file=../../../../etc/passwd：HTTP 200，返回 'root:x:0:0:root:/root:/bin/bash\ndaemon:...'，证明可穿越出 docs 目录读取进程可读的任意文件。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`8dbf346f09084e4c882754c409f22d7c`；`ca870db476d34731934fff2fde1986a0`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`ca870db476d34731934fff2fde1986a0` script finished exit=0
  - 适配脚本：`3570b96d-adapted-poc_path_traversal.py`（见证据包 evidence/）
  - 备注：源码 applicability=match：download.php:3 将 $_GET['file'] 直接拼接为 data_dir().'/docs/'.(string)$_GET['file']，仅 is_file 判断后 file_get_contents 并 text/plain 输出，无 realpath/前缀校验；bootstrap.php:9 data_dir 默认 /var/lib/shop，故 ../vault/internal.txt 解析为 /var/lib/shop/vault/internal.txt，../../../../etc/passwd 解析为 /etc/passwd。正常侧 shipping.txt 返回配送说明。审计脚本 job 8dbf346f09084e4c882754c409f22d7c 的 ../../../../VERSION 解析到 /VERSION（不存在）而 404，仅说明该路径深度未命中，不构成漏洞反证；本轮按运行时目录结构改用 ../vault/internal.txt 与 ../../../../etc/passwd 两个最小变体获得命中。前置仅要求登录，alice 为普通 customer 即满足。

### C-19 partner/portal.php 不校验 JWT 签名，任意匿名请求伪造 role=admin 即可读取全部用户订单

- verification `4780b834a9274d4ca880de9b22e1fd69`（finding `471a1fc8e9554baea7baa6bd256b80b4` revision 1，context `0f58d15fb67f49c0b40071b29ff6b6c6`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：未登录会话 POST /partner/portal.php，token 为空字符串（对照），返回 403 {"error":"此合作方功能仅向管理员开放。"}，未返回任何订单数据。
  - 攻击侧观测：同一未登录请求 POST /partner/portal.php，携带自造三段式 token（header=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9，payload=base64url({"sub":1,"role":"admin","name":"x"})，第三段为任意串 "forged" 的 base64url 编码），返回 200 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}。签名段从未被校验，任意伪造 role=admin 的 payload 即可读取 alice 与 bob 的全部订单号与金额。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`fd1e6e2468c74bacbbeb7ecf9a5da158`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`fd1e6e2468c74bacbbeb7ecf9a5da158` script finished exit=0
  - 适配脚本：`4780b834-adapted-poc_partner_portal_jwt_forge.py`（见证据包 evidence/）
  - 备注：单作业 fd1e6e2468c74bacbbeb7ecf9a5da158，未登录（无任何会话）。正常/攻击唯一差异是 token：空串与伪造 payload.role=admin 的三段式字符串；403/200 的差异直接证明授权取决于未签名 payload。setup.php:21-22 确认 SG-1001 属 alice、SG-1002 属 bob，攻击响应同时返回二者，构成跨用户数据泄露。未使用任何特权会话。

- 正式复核 `dacb50c7327c4056ac8ad5c899a519fe`：复核确认；引用 revision 1 / verification `4780b834a9274d4ca880de9b22e1fd69`
  - 理由：读取该验证记录全文：正常侧未登录、token 为空返回 403 且无数据；攻击侧自造未签名三段式 token（第三段任意串）把 payload.role 改为 admin，即返回 200 与 orders SG-1001(129.00)、SG-1002(158.00)，跨用户数据泄露。执行成功、precondition 正常，观测与 portal.php:3-4 仅凭客户端可控 payload 授权并全表查询的结论一致，确认。
  - 复核观测：正常侧 未登录会话 POST /partner/portal.php，token 为空字符串（对照），返回 403 {"error":"此合作方功能仅向管理员开放。"}，未返回任何订单数据。；攻击侧 同一未登录请求 POST /partner/portal.php，携带自造三段式 token（header=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9，payload=base64url({"sub":1,"role":"admin","name":"x"})，第三段为任意串 "forged" 的 base64url 编码），返回 200 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}。签名段从未被校验，任意伪造 role=admin 的 payload 即可读取 alice 与 bob 的全部订单号与金额。

### C-20 运营模板渲染将 POST 模板表达式直接 eval，导致任意 PHP 代码执行

- verification `1b367bc3a6f24a0c96441de0062b1ecc`（finding `02387c10d9d14176a68924c68bd9dc28` revision 1，context `2a6f689db31e44eba9354cf6f059723e`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 登录后 GET /ops/template-render.php 返回 200（含运营导航），取得真实 csrf。提交页面默认模板「本周精选，共 {{ 2 + 2 }} 款好物」：HTTP 200，<pre> 输出「本周精选，共 4 款好物」，仅做算术表达式求值，无命令执行痕迹。
  - 攻击侧观测：同一 operator 会话提交 template={{ system('id; uname; printf LAB30_EVAL_02387c10'); }}：HTTP 200，响应中检测到 uid=<数字>（ATTACK uid True），且 <pre> 中原样输出唯一标记 LAB30_EVAL_02387c10（system 返回的最后一行）；该标记只可能由被 eval 执行的命令产生。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`ec968127e35d402e9a3bface9d41a8b6`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`ec968127e35d402e9a3bface9d41a8b6` script finished exit=0
  - 适配脚本：`1b367bc3-adapted-poc.php`（见证据包 evidence/）
  - 备注：源码 applicability=match：template-render.php:2 把 $_POST['template'] 原样赋给 $template；第3行 POST 且通过 check_csrf 后，preg_replace_callback('/\{\{(.*?)\}\}/s') 把捕获组拼入 eval('return '.$m[1].';')，无白名单/沙箱。正常侧模板只用纯算术表达式，返回 4；攻击侧替换为调用 system() 的 PHP 表达式后执行了系统命令。两侧使用同一 operator 会话与同一 CSRF token，唯一变量是 template 值。角色限制为源码要求，故按前提使用 operator 身份。

### C-21 运营链接预览将 GET url 原样传入 file_get_contents，导致 SSRF

- verification `1d818e513b40451cb662e778fb5730da`（finding `9f3aed0469d34ff189b427fa127a9b7b` revision 1，context `c6fe7d8912e44ab598d14e6e198bd9ac`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 登录后请求 /ops/url-preview.php?url=http://fixtures:8080/catalog-info：HTTP 200，<pre> 返回「拾光合作方商品摘要：本季上新四款日常好物，工作日统一配送。」，即合作方服务正常内容。
  - 攻击侧观测：同一 operator 会话请求 /ops/url-preview.php?url=http://127.0.0.1:80/：HTTP 200，<pre>（经 h() 转义）内容为回环地址返回的商城首页 HTML，含 &lt;title&gt;让每一份日常，都值得期待 · 拾光商城&lt;/title&gt; 与 /assets/app.css、theme-color 等页面结构，ATTACK_LOOPBACK_HIT True。证明服务端按攻击者指定 URL 向回环/内网发起请求并回显响应正文，无目标地址限制。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`48b95fce27be460c84a7ee91affd30f9`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`48b95fce27be460c84a7ee91affd30f9` script finished exit=0
  - 适配脚本：`1d818e51-adapted-ssrf_url_preview.py`（见证据包 evidence/）
  - 备注：源码 applicability=match：url-preview.php:2 取 $_GET['url']，第3行仅用 stream_context_create(['http'=>['timeout'=>4,'follow_location'=>0]]) 后 @file_get_contents($url,false,$context,0,65536)，无 scheme/主机/IP 白名单；第4行把结果 h() 后放入 <pre>。正常与攻击两侧同一 operator 会话、同一路由，唯一变量是 url：正常指向 fixtures 合作方服务，攻击指向 127.0.0.1:80 回环服务，返回内容从合作方摘要变为商城自身首页 HTML，说明请求目标完全由请求方控制。角色限制为源码要求，故按前提使用 operator 身份。

### C-22 account/backup.php 对用户提交的备份直接 unserialize 并写入任意 tier/display_name

- verification `f381e2c7d0d840e1abd559dc363c19d3`（finding `ada258387c284766a48e0d3b5ded75ab` revision 1，context `f94997ceed734188b61d134148b3f14d`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice 登录后从 /account/backup.php 取得真实 csrf，提交空 backup：HTTP 400，JSON {"error":"不是有效的会员备份。"}，tier 保持 standard，无任何用户字段被写入。
  - 攻击侧观测：同一 alice 会话 POST backup=base64('O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:5:"poced";}') 与同一 csrf：HTTP 200，页面提示「会员备份已恢复。」，页头显示名称变为 poced；随后 GET /account/me.php 返回 {"id":1,"username":"alice","display_name":"poced",...,"tier":"gold",...}，服务端 postcondition 记录 alice.tier 由 standard 变为 gold。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`19840ef25cc64929a0cfc33296af4c95`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`19840ef25cc64929a0cfc33296af4c95` script finished exit=0
  - 适配脚本：`f381e2c7-adapted-poc_backup_unserialize.py`（见证据包 evidence/）
  - 备注：源码 applicability=match：backup.php:4 base64_decode 后第5行直接 unserialize($raw)（无 allowed_classes），仅 instanceof MemberBackup 检查，第6行把 $restored->tier / $restored->displayName 写入当前用户 users 行，未校验 tier 取值；backup.php.php 中 MemberBackup 仅含两个公有字符串属性（src/backup.php:2-5），故本例的可利用后果是客户端任意指定 tier/display_name 并持久化。正常/攻击两侧同一 alice 会话与 csrf，唯一变量是 backup 值，正常空值被 400 拒绝、攻击值被接受并改变数据库，对照成立。

### C-23 运营网络诊断将 GET host 原样拼入 shell_exec 导致命令注入

- verification `f67d451c812a4f8ab6f57d3a0c5bc32d`（finding `d2677c773d34449d8e9a9a2a62ca6591` revision 1，context `1ae865004d104541bb1ae3930917abbf`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 正常登录后 GET /ops/ping.php?host=127.0.0.1 返回 200，<pre> 中只有 ping 自身输出（PING 127.0.0.1 ... 1 packets transmitted, 1 received），无 CMDPROOF 标记、无 uid= 行。说明正常主机参数仅触发预期的 ping 命令。
  - 攻击侧观测：同一 operator 会话，GET /ops/ping.php?host=127.0.0.1%3B%20echo%20CMDPROOF_9f3a71%3B%20id：响应 <pre> 在 ping 统计之后出现独立行 CMDPROOF_9f3a71，随后 uid=33(www-data) gid=33(www-data) groups=33(www-data)，证明 shell_exec 执行了注入的 echo 与 id。重复同一请求得到相同标记与 uid（非偶发）。对 /ops/batch-check.php?host=<同一载荷> 得到相同结果，确认 host_check()（src/host_check.php 第 2 行）同样存在注入。标记 CMDPROOF_9f3a71 只由本次注入命令产生，正常请求中未出现。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`29a74cf38b2347c9bd7b259ed92c9c33`；`d593220a9750401884494cc192b539fc`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`d593220a9750401884494cc192b539fc` script finished exit=0
  - 适配脚本：`f67d451c-adapted-ping_rce.py`（见证据包 evidence/）
  - 备注：使用 operator 身份是源码明确要求：ops/ping.php 与 ops/batch-check.php 第 2 行均调用 require_user(['operator','admin'])。宿主先前以 alice（customer）执行同一 POC 返回 HTTP 403，说明该入口不对普通会员开放（该作业未成功、不作为证据）；本结论只主张 operator/admin 账号可 RCE。实验仅 GET 只读命令（echo/id），未修改数据，未使用 admin。

- 正式复核 `3f1ef1fa2a7a46f7b6e83fdbd0fd03ba`：复核确认；引用 revision 1 / verification `f67d451c812a4f8ab6f57d3a0c5bc32d`
  - 理由：operator 会话正常 /ops/ping.php?host=127.0.0.1 只含 ping 自身输出且无 CMDPROOF 与 uid 行；攻击载荷 127.0.0.1; echo CMDPROOF_9f3a71; id 后追加唯一标记与 uid=33(www-data)，重复请求结果一致，同一载荷对 batch-check 亦同样成功。源码 ping.php:2 使用 shell_exec('ping -c 1 -W 1 '.$host) 无转义，仅 require_user(['operator','admin'])，两侧观测与源码一致。
  - 复核观测：正常侧 operator 正常登录后 GET /ops/ping.php?host=127.0.0.1 返回 200，<pre> 中只有 ping 自身输出（PING 127.0.0.1 ... 1 packets transmitted, 1 received），无 CMDPROOF 标记、无 uid= 行。说明正常主机参数仅触发预期的 ping 命令。；攻击侧 同一 operator 会话，GET /ops/ping.php?host=127.0.0.1%3B%20echo%20CMDPROOF_9f3a71%3B%20id：响应 <pre> 在 ping 统计之后出现独立行 CMDPROOF_9f3a71，随后 uid=33(www-data) gid=33(www-data) groups=33(www-data)，证明 shell_exec 执行了注入的 echo 与 id。重复同一请求得到相同标记与 uid（非偶发）。对 /ops/batch-check.php?host=<同一载荷> 得到相同结果，确认 host_check()（src/host_check.php 第 2 行）同样存在注入。标记 CMDPROOF_9f3a71 只由本次注入命令产生，正常请求中未出现。

### C-24 ops/jobs.php 反序列化用户提交的 DispatchJob 对象，__wakeup 中 shell_exec 导致代码执行

- verification `871aa3c9f5354398b8194600852720fc`（finding `aa6930e95bbf43b393fbb979036a4d05` revision 1，context `b37ac70af89745639d0bbe3c0dd47e47`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 登录后 GET /ops/jobs.php 返回 200 并取得真实 csrf 与页面示例任务（base64 的 DispatchJob，command=printf inventory-ready）。提交该示例：HTTP 200，notice「任务已导入并执行」，输出区 <pre>inventory-ready</pre>，仅执行默认命令。
  - 攻击侧观测：同一作业中攻击侧：POST job=base64('O:11:"DispatchJob":1:{s:7:"command";s:38:"id; uname; printf LAB30_DESER_aa6930e9";}')，HTTP 200，页面 notice「任务已导入并执行。」；输出区 <pre> 显示 "uid=33(www-data) gid=33(www-data) groups=33(www-data)\nLinux\nLAB30_DESER_aa6930e9"，唯一标记 LAB30_DESER_aa6930e9 与 id/uname 输出均由本次攻击命令产生，且该结果同时被写入 jobs.details（表格中可见同串）。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`506420638ae44362a1eac8aece2a1af8`；`50367d1efccb49c6a27df28a4db5e2af`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`50367d1efccb49c6a27df28a4db5e2af` script finished exit=0
  - 适配脚本：`871aa3c9-adapted-poc_jobs_deserialization.py`（见证据包 evidence/）
  - 备注：源码 applicability=match：jobs.php:3 先 ob_start、再 unserialize(base64_decode($_POST['job']))，之后才做 instanceof 检查；dispatch_job.php:4 __wakeup 中 echo shell_exec($this->command)，命令输出被 ob_get_clean 收集后写入 jobs.details。因此攻击载荷执行发生在 instanceof 之前。正常/攻击两侧使用同一 operator 会话与同一 CSRF，唯一变量是 job 值。审计脚本 job 506420638ae44362a1eac8aece2a1af8 使用 alice(customer) 身份访问 /ops/jobs.php 被 403 拒绝（evidence_usable=false），仅证明角色门禁存在，未作为漏洞证据引用；源码本就要求 operator/admin，故本轮按源码前提使用 operator 身份。

- 正式复核 `3179b15dc4cb4d0aac3a0881420cb2f9`：复核确认；引用 revision 1 / verification `871aa3c9f5354398b8194600852720fc`
  - 理由：读取两侧完整观测：正常侧 operator 登录后取真实 csrf 与页面示例任务（command=printf inventory-ready），提交后返回 200、notice 成功，输出区仅 <pre>inventory-ready</pre>；攻击侧同一会话提交 base64 序列化的 O:11:"DispatchJob"，$command 为 "id; uname; printf LAB30_DESER_aa6930e9"，页面输出 uid=33(www-data) gid=33(www-data)、Linux 与唯一标记 LAB30_DESER_aa6930e9，且该串写入 jobs 表。正常/攻击差异明确由攻击载荷控制，确认 src/dispatch_job.php:4 的 shell_exec 执行任意命令。
  - 复核观测：正常侧 operator 登录后 GET /ops/jobs.php 返回 200 并取得真实 csrf 与页面示例任务（base64 的 DispatchJob，command=printf inventory-ready）。提交该示例：HTTP 200，notice「任务已导入并执行」，输出区 <pre>inventory-ready</pre>，仅执行默认命令。；攻击侧 同一作业中攻击侧：POST job=base64('O:11:"DispatchJob":1:{s:7:"command";s:38:"id; uname; printf LAB30_DESER_aa6930e9";}')，HTTP 200，页面 notice「任务已导入并执行。」；输出区 <pre> 显示 "uid=33(www-data) gid=33(www-data) groups=33(www-data)\nLinux\nLAB30_DESER_aa6930e9"，唯一标记 LAB30_DESER_aa6930e9 与 id/uname 输出均由本次攻击命令产生，且该结果同时被写入 jobs.details（表格中可见同串）。

### C-25 account/redeem.php 使用 == 比较 md5 兑换码导致 0e 弱比较绕过升级会员

- verification `3b51d65072ae490297b0a8930b701a24`（finding `9a55b23d82814cd19b76510533209567` revision 1，context `5ba93a2ca04a471bbe3a5ff4eae315ca`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice 已登录，GET /account/redeem.php 提取到真实 csrf 字段后，POST token=wrong-code&csrf=<真实值>：HTTP 422，页面 notice 为「兑换码无效。」，账户 tier 保持 standard。
  - 攻击侧观测：同一会话 POST token=QNKCDZO&csrf=<同一真实值>：HTTP 200，页面 notice 为「兑换成功，已升级金卡会员。」；作业 postcondition 中 alice 的 tier 由 standard 变为 gold，state_changes 记录 field=tier, before=standard, after=gold。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`afb7fe56be544769b18d0e767a276ae7`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`afb7fe56be544769b18d0e767a276ae7` script finished exit=0
  - 适配脚本：`3b51d650-adapted-redeem_0e_poc.py`（见证据包 evidence/）
  - 备注：源码窗口（applicability=match，snapshot lab30-shop-1.0.0-source.zip）显示 redeem.php:4 secret_hash=md5('240610708')，redeem.php:5 使用 == 比较 md5((string)$_POST['token'])；md5('240610708')=0e462097431906509019562988736854，QNKCDZO 的 md5=0e830400451993494058024219903391，两者在 PHP 8 的数字字符串比较中同为 0。正常/攻击两侧使用同一 csrf 与同一用户，唯一变量是 token 值，差异可归因于弱比较。check_csrf 正常触发（缺少 csrf 时不进入比较），不影响结论。

### C-26 support/download.php file 参数未规范化导致 ../ 路径遍历任意文件读取

- verification `b5e9d6a01bc341d6a2c34401ac3a8dc4`（finding `2ad14e06d6e84f8d866d0eec3d3fc0a5` revision 1，context `fdabe2a6725c48de92293d94892c221d`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：LOGIN 302；GET /support/download.php?file=shipping.txt 返回 HTTP 200，正文为 docs/shipping.txt 实际内容“配送说明：工作日 48 小时内发货。”，说明 alice 会话已生效且正常文档读取工作。
  - 攻击侧观测：同一 alice 会话 GET /support/download.php?file=../../../../etc/passwd 返回 HTTP 200，正文为 /etc/passwd 全文：root:x:0:0:root:/root:/bin/bash、daemon:x:1:1、www-data:x:33:33 等 17 个账户行，非文档目录内容，确认 ../ 路径逃逸读取了系统文件。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`3fddfd36d726471392e9268f9818aa0b`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`3fddfd36d726471392e9268f9818aa0b` script finished exit=0
  - 适配脚本：`b5e9d6a0-adapted-poc_path_traversal.php`（见证据包 evidence/）
  - 备注：仅一个作业 3fddfd36d726471392e9268f9818aa0b，正常侧与攻击侧在同一脚本内依次执行，前后置身份校验均为 alice/customer OK。正常侧返回固定文档文本、攻击侧返回 /etc/passwd 结构行，两者差异即为判别依据；未使用特权身份。

### C-27 ops/report.php 将数据库昵称二次拼接进 SQL，低权用户可通过昵称注入

- verification `5b2f038c08fa4b43ad1527f64f7ad1a9`（finding `478b720dcb6a455dac412d6b875c46d8` revision 1，context `0036edcb0a294f6cadc58ceb29a7d25f`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 请求 /ops/report.php?user_id=2（bob，昵称 'bob'）：HTTP 200 JSON，saved_nickname='bob'，members 仅 1 行 bob/bob@shop.local/customer，符合参数化取出的良性昵称匹配。
  - 攻击侧观测：operator 请求 /ops/report.php?user_id=1（alice，昵称已存为 x' OR '1'='1）：HTTP 200 JSON，saved_nickname 原样为 "x' OR '1'='1"，members 返回 4 行——alice/alice@shop.local/customer、bob/bob@shop.local/customer、operator/ops@shop.local/operator、admin/admin@shop.local/admin，SQL 条件被注入为恒真，越权读出全部用户及角色信息。
  - 已保存作业事实：3 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`1af4cb6f3f7147528b896b996c5ee581`；`9c2541f0d5c140d982a6eafc33251fb8`；`cf732bbea12d4c2cb327dd211959961e`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`9c2541f0d5c140d982a6eafc33251fb8` script finished exit=0；`cf732bbea12d4c2cb327dd211959961e` script finished exit=0
  - 适配脚本：`5b2f038c-adapted-sqli_secondorder_report.py`（见证据包 evidence/）
  - 备注：源码 applicability=match：account/update.php:4-6 的 nickname 在列白名单内且值以 (string) 原样入库；report.php:2 参数化取出 nickname，report.php:3 用 db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'") 直接拼接，无占位符或转义。正常对照使用 bob(user_id=2) 的良性昵称 'bob'，同一路由同一参数结构，返回 1 行；攻击使用 alice(user_id=1) 的注入昵称，返回全部 4 行，差异仅由存储值引起的 SQL 语义变化解释。审计脚本 job 1af4cb6f3f7147528b896b996c5ee581 因 /account/index.php 无 csrf 字段而在取 token 时失败（evidence_usable=false），未产生有效观测，不作为证据引用；本轮改用 /account/update.php 的表单取真实 csrf。

### C-28 support/download.php file 参数未规范化拼接路径导致任意文件读取

- verification `6de2225583b94b85b955a715320fcb7c`（finding `2198eca455c84b6db9a639ac7a7210a3` revision 1，context `9b1e18f21fd548bb9c8f801b134a45cf`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：alice 登录后会员会话确认生效（MEMBER_SESSION 200，/orders/index.php 未跳转登录）。GET /support/download.php?file=shipping.txt 返回 HTTP 200，正文为 docs/shipping.txt 实际内容“配送说明：工作日 48 小时内发货。”，正常读取限定文档。
  - 攻击侧观测：同一 alice 会话 GET /support/download.php?file=../../../../etc/passwd（../ 经 URL 编码提交），HTTP 200，正文为 /etc/passwd 内容：root:x:0:0:root:/root:/bin/bash、daemon:x:1:1、bin:x:2:2、www-data:x:33:33 等多行，ATTACK_HAS_ROOT=True。路径 /var/lib/shop/docs/ 向上四级逃逸至 /etc/passwd 被 is_file 通过后 file_get_contents 原样回显，读取到 docs 目录之外的系统文件。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`072aec8cca2b4ba1959ef72ec4d72f6a`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`072aec8cca2b4ba1959ef72ec4d72f6a` script finished exit=0
  - 适配脚本：`6de22255-adapted-poc.php`（见证据包 evidence/）
  - 备注：单作业 072aec8cca2b4ba1959ef72ec4d72f6a，alice（customer）身份，前置/后置校验均 OK，脚本先以 /orders/index.php 200 且未被重定向到登录页确认会话生效。正常侧返回 docs/shipping.txt 固定文本，攻击侧返回 /etc/passwd 结构行，差异仅来自 file 参数，直接对应 download.php:3 的路径拼接。未使用任何特权身份。

### C-29 ops/formula.php 将 GET func 直接作为函数名调用，可调用 system/exec 等实现任意命令执行

- verification `447dcc09be42456298fffc839a314c39`（finding `4679744af0c244798f7eea708317a445` revision 1，context `8576a767402d45c0b70cb4974507a7e9`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 正常登录后 /ops/index.php 返回 200；GET /ops/formula.php?func=strtoupper&arg=spring-sale 返回 200，<pre> 内容为 SPRING-SALE，页面无 FORMULAPROOF 标记、无 uid= 输出，说明合法内置函数调用按预期执行。
  - 攻击侧观测：同一 operator 会话，GET /ops/formula.php?func=system&arg=echo%20FORMULAPROOF_c7d2a4%3B%20id：响应 200，<pre> 中出现 uid=33(www-data) gid=33(www-data) groups=33(www-data)，页面正文含唯一标记 FORMULAPROOF_c7d2a4；重复同一请求结果一致。另以 func=passthru 传入同一命令，页面正文同样出现 FORMULAPROOF_c7d2a4_PT（passthru 直接输出，故 <pre> 为空但正文含标记），说明任意内置函数名都可被请求参数选中。标记仅由本次注入参数产生。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`bc9550da8d6f4cfca138dbf3f1ec6ab1`；`0a68d7117374465eb1b184e0c0236822`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`0a68d7117374465eb1b184e0c0236822` script finished exit=0；`bc9550da8d6f4cfca138dbf3f1ec6ab1` script finished exit=0
  - 适配脚本：`447dcc09-adapted-poc_formula_rce.py`（见证据包 evidence/）
  - 备注：operator 身份是源码明确要求：formula.php 第 2 行 require_user(['operator','admin'])。对照组：alice（customer）执行相同 POC 时正常与攻击请求均返回 HTTP 403（作业 bc9550da8d6f4cfca138dbf3f1ec6ab1），说明该入口不对普通会员开放；本结论仅主张 operator/admin 账号可实现代码执行，不冒充低权限越权。php.ini 未设置 disable_functions，与 system/passthru 可被调用一致。实验只执行 echo/id 只读命令，未改动数据。

## 6. 覆盖与未决项

| 独立分母 | 总数 | 已结算 | 未决/待办 | 闭环 |
|---|---:|---:|---:|---|
| 文件覆盖 | 61 | 读取 58；读取+跳过 61 | 0 | 是 |
| 必做方向 | 12 | 已决 12；跳过 0 | 0 | 是 |
| 动态验证 | 29 | 已验证 29；已复核记录 20 | 待验证 0；待复核 9 | — |
| 正式终审 | 29 | 已接受 20 | 待终审 9；存疑 0 | — |

**带理由跳过的文件**

- `lab30-shop/app/public/assets/products.svg`：静态 SVG 图片资源，不含服务端执行逻辑；无可控输入进入的处理分支
- `lab30-shop/bin/lab`：CLI 启动包装脚本，仅用于本地拉起服务，不接收外部 HTTP 输入
- `lab30-shop/bin/package.py`：打包辅助脚本，属构建期工具而非 Web 运行时代码，无外部可达入口
- `lab30-shop/compose.yaml`：本地容器编排配置，仅声明服务与端口，不含应用层输入处理逻辑

**后续建议（不阻止本次收束）**

- `dir_291d1546311985029686556e768f76d6`：lab30-shop/app/public/ops/maintenance.php、ops/template-render.php、ops/url-preview.php、ops/xml-import.php、catalog/greeting.php、content/page.php 等入口本批未读取，公共层之外的危险原语（模板、SSRF、XXE）仍待逐一取证。
- `dir_60fb06d2f603f4c548b319ecaa86a19d`：lab30-shop/app/public/auth/continue.php:3 直接把 $_GET['next'] 用于 Location 头，属开放重定向，需确认下游入口。
- `dir_71adec23925e5f4df2d29f9a4129f0e5`：lab30-shop/app/public/account/backup.php:5 对 POST backup 反序列化合 MemberBackup 并写 tier/display_name（backup.php:6），存在对象注入与属性覆盖方向，需按 mass_assignment/insecure_deserialization 细分。
- `dir_94d1c65cae9ef9b3b03e4afa1456cbfa`：lab30-shop/app/src/member_lookup.php:3 的 SQL 拼接（ops/members.php:2 的 $_GET['q']）需单独评估可利用性与注入回显。
- `dir_f06c344ea0e8684edf9aaf91a1692c2c`：lab30-shop/app/src/host_check.php:2 的 shell_exec('ping ... '.$host) 由 ops/batch-check.php:2 的 $_GET['host'] 驱动，属命令注入方向，需取证输出回显与过滤缺失。
- `dir_cf7af951be043990d6bf85be4bc8edf6`：ops/url-preview.php:3 file_get_contents 任意 URL 的 SSRF
- `dir_c845a045b41337bd5815901678abf8c7`：审计 orders/detail.php 的越权读取（IDOR）并把其作为独立发现补交
- `dir_3abe20d96885fec76bce16605ba97aa2`：lab30-shop/app/src/member_lookup.php:3 LIKE 拼接 SQL 注入（经 ops/members.php:2 q 参数）
- `dir_5e097524fd185913244e43afb6990e2e`：lab30-shop/app/public/ops/url-preview.php:3 file_get_contents 任意 URL SSRF
- `dir_6c38f8bda21a3bc116a97ff3d1b1d114`：lab30-shop/app/public/ops/xml-import.php:3 LIBXML_NOENT&#124;LIBXML_DTDLOAD 外部实体注入
- `dir_733b48c59b950c3b0a4d43c68be73ba8`：lab30-shop/app/public/ops/maintenance.php:3 仅凭 X-Admin 请求头的鉴权绕过
- `dir_aba6aa69842fa7a4244dac0f5035d87a`：lab30-shop/app/public/ops/template-preview.php:3 include 请求路径导致 LFI/RFI
- `dir_84f196bc82847649119652bbe93b84cc`：核对 resources/views 下其余模板（如 orders、account、ops 页面）是否存在对用户可控变量的未转义输出
- `dir_e37ac44e72b804ca168b46e745c403ba`：核对 ops/template-preview.php 与 template-render.php 的模板路径/内容来源是否构成 RFI 或代码执行
- `dir_40f14ac0f0476d107d4623cff4f818d0`：lab30-shop/app/public/wallet/index.php 余额/转账类接口的归属与状态校验
- `dir_f90d3cfda4911210835d18442f7f5e3d`：lab30-shop/app/public/ops/index.php（运营工作台）角色校验是否可被普通用户访问
- `dir_8e1f88b1eb21ae70b127ad3a6dd716b5`：审计 partner/portal.php 的 $_COOKIE['partner_token'] 是否可被跨站写入或长期重放，以及该 cookie 是否设置 HttpOnly/SameSite
- `dir_c4bd30320cf24beed98c263dfbc44674`：检查 settings 表中 generation 值是否会变化/泄露，从而影响 token.php 签名密钥的保密性
- `dir_a10acd886413c78e7df9f8fcf6a214ef`：复核 account/update.php 批量赋值（columns 含 role/balance/tier）是否可提升权限或改余额，与本 workitem 的 wallet 结算相互独立
- `dir_6ac8dbee42424d7e25360a67a3ff948c`：核对 data_dir() 默认 /var/lib/shop 下 sessions 目录可读性以确认穿越到会话文件的实际影响（需运行环境事实）
- `dir_3e1a18450e8aae4e81dc89d734bb536e`：lab30-shop/app/public/ops/url-preview.php:3 将请求可控 URL 直接交给 file_get_contents，需独立审计 SSRF
- `dir_1c4c26945c671cf09ca9bfd842e42baa`：核实 ops/members.php 经 src/member_lookup.php 的 SQL 注入是否已在其他工作项落库，未落库则单独提交
- `dir_4d5297ccae3d7d0047dad3b885b442eb`：lab30-shop/app/public/support/download.php 与 account/settings.php 的文件/跳转目标参数尚未审查
- `dir_594fb193838c0309921d630d6b74a51e`：lab30-shop/app/public/orders/detail.php:1-4 的 IDOR 已由本轮运行既有候选覆盖，未重复提交；如需可补充 POC（GET /orders/detail.php?id=N 遍历）
- `dir_a8c7452d72167791c65db3b0c94c37cc`：复核 wallet/withdraw.php receipt 拼接进 Location 是否存在头部注入或重定向滥用（第 11 行）。
- `dir_eb155d0aeee052525b7a153227e6592b`：lab30-shop/app/public/auth/login.php 登录流程是否存在 next/redirect 参数进入 Location 的开放重定向（当前仅读到第 9 行硬编码 '/'）。
- `dir_97afc06a50dc36299c40acd1d02efa36`：ops/xml-import.php、ops/url-preview.php、ops/maintenance.php、ops/jobs.php、ops/users.php、ops/members.php、ops/ping.php 的 sink 尚未在本工作项审查

**补证与未决动作**

- `afd22f5579844161aa011541f0ae8812` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 3570b96d07be4c8ca580d16149e33d57。（support/download.php file 参数路径遍历读取任意文件）
- `bfd1580e14754964a21945d15907d435` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 1b367bc3a6f24a0c96441de0062b1ecc。（运营模板渲染将 POST 模板表达式直接 eval，导致任意 PHP 代码执行）
- `c75a2af277c24086a450dc46dad72708` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 1d818e513b40451cb662e778fb5730da。（运营链接预览将 GET url 原样传入 file_get_contents，导致 SSRF）
- `c99a499ebe364ed8a8bea59c13a0b2ea` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id f381e2c7d0d840e1abd559dc363c19d3。（account/backup.php 对用户提交的备份直接 unserialize 并写入任意 tier/display_name）
- `e0cf553e9838411fa31a2455b8d0dd8d` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 3b51d65072ae490297b0a8930b701a24。（account/redeem.php 使用 == 比较 md5 兑换码导致 0e 弱比较绕过升级会员）
- `e7194a298f6f45aeba14f4373dd3e3d2` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id b5e9d6a01bc341d6a2c34401ac3a8dc4。（support/download.php file 参数未规范化导致 ../ 路径遍历任意文件读取）
- `ec09775dc7774d03a124cce24ae185b8` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 5b2f038c08fa4b43ad1527f64f7ad1a9。（ops/report.php 将数据库昵称二次拼接进 SQL，低权用户可通过昵称注入）
- `f70251f235c5413c8143059494c2b12c` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 6de2225583b94b85b955a715320fcb7c。（support/download.php file 参数未规范化拼接路径导致任意文件读取）
- `fd7b2de1f92542ed9e05b5d2de82edc1` 对当前结论版本执行正式复核（确认或存疑），复核记录须引用该 verification id 447dcc09be42456298fffc839a314c39。（ops/formula.php 将 GET func 直接作为函数名调用，可调用 system/exec 等实现任意命令执行）
- 9 项：对已验证结论完成正式复核；verified 不能替代终审。

**限制**

- 受阻、未执行、未读取的方向均不代表安全。
- 本次运行未同时满足完成状态、覆盖闭环与验证闭环，本报告为阶段报告。
- 仍有 9 条规范结论未获得正式确认，不计入已接受漏洞。

## 7. 附录与证据索引

**历史版本与来源记录**

| 规范结论 | finding | revision | 处置 | 验证 | 当前 |
|---|---|---:|---|---|---|
| `1d31c3b79a8040a3810985945c1f137e` | `5a97ed77f03942158995a504c75a02e9` | 1 | open | unverified | 否 |
| `1d31c3b79a8040a3810985945c1f137e` | `0bb3ead0ddc24e6e944d1e0b0f5e3a76` | 1 | open | verified | 是 |
| `494423ddc5fb4859bd074dca9235a8c5` | `72049850919747af8c8006374538bd2b` | 1 | open | unverified | 否 |
| `494423ddc5fb4859bd074dca9235a8c5` | `6292c426c920455d84e7b13975afafa8` | 1 | open | verified | 是 |
| `5a1f8b8736b246b9ae6d081c49f50198` | `22a43337feb141bdbb7ba309a90dc755` | 1 | open | unverified | 否 |
| `5a1f8b8736b246b9ae6d081c49f50198` | `9dc01b5fc875445496274debba22d73d` | 1 | open | verified | 是 |
| `5f8a819f26e14990a4204f0220c29672` | `9ee7ec981a354cfba23d153a7db2dc6a` | 1 | open | unverified | 否 |
| `5f8a819f26e14990a4204f0220c29672` | `02983c3f18214891b51523b36d8de53e` | 1 | open | unverified | 否 |
| `5f8a819f26e14990a4204f0220c29672` | `21722ca9ff6a4e6e829697ca77a80770` | 1 | open | verified | 是 |
| `7905401b64084de6956b3ecd7b67e0a9` | `ce6d65810a3245cd9069d33bb10ea238` | 1 | open | unverified | 否 |
| `7905401b64084de6956b3ecd7b67e0a9` | `f32557d8e70f4a51b5831f8018091349` | 1 | open | verified | 是 |
| `9a66a667a5f046388568cfa10ff63cfe` | `5c506cd7b9404ab1ae197b751c67b929` | 1 | open | unverified | 否 |
| `9a66a667a5f046388568cfa10ff63cfe` | `ec6cdc0fe29741aebf7dc60ec5aab87a` | 1 | open | verified | 是 |
| `fd7b2de1f92542ed9e05b5d2de82edc1` | `76c6bd3890b94333a322c022bbce0f78` | 1 | open | unverified | 否 |
| `fd7b2de1f92542ed9e05b5d2de82edc1` | `4679744af0c244798f7eea708317a445` | 1 | open | verified | 是 |

**撤回、重复或替代记录**

- `2eda6751731b4f92916d24b39c0fbf7c`（revision 1）：duplicate——ops/jobs.php 对用户提交数据反序列化触发 DispatchJob::__wakeup 系统命令执行
- `75e8267dd57f49489d2f9ff27f109f9c`（revision 1）：duplicate——support/download.php 文件参数路径遍历读取任意文件
- `2a728abad715464ab1eadaeb23bf8dcf`（revision 1）：duplicate——ops/batch-check.php 将 GET 参数 host 拼接进 shell_exec 导致命令注入
- `4c388dc6cf584cc4a5e61dda23d5d5fc`（revision 1）：duplicate——partner/portal.php 未校验 JWT 签名，伪造 role=admin 令牌即可读取全部订单
- `66e25abd11314dff8f859b9599cbe9bc`（revision 1）：duplicate——ops/jobs.php 对 POST job 直接 unserialize，DispatchJob::__wakeup 中 shell_exec 导致命令执行
- `81b56fed3e8f483eb85388beb5b82224`（revision 1）：duplicate——partner/portal.php 不校验 JWT 签名，伪造 role=admin 的 payload 即可读取全部用户订单号与金额
- `e4e1238432354da48fe5b5cf6786cdb7`（revision 1）：duplicate——ops/members.php 将 GET 参数 q 直接拼入 LIKE 查询导致 SQL 注入
- `1a737adb1a9e4d348bffb504efd68047`（revision 1）：duplicate——catalog/greeting.php 的 name 参数未经 h() 转义直接回显到 HTML，导致反射型 XSS
- `9267de620a104ee99e93a176bf328937`（revision 1）：duplicate——catalog/index.php 将 GET q 直接拼接进 LIKE 查询导致 SQL 注入
- `4a289c890c1e4e93a3faf463cf2f9f0a`（revision 1）：duplicate——ops/report.php 将数据库昵称二次拼接进 SQL 导致存储型二次注入
- `795a3e6ebfa5444c81890676944ae367`（revision 1）：duplicate——php.ini 开启 allow_url_include 放大了模板预览的远程文件包含
- `b544f989fe41423bb687361faceeea68`（revision 1）：duplicate——auth/continue.php next 参数直接进入 Location 响应头导致开放重定向

**关联链路对照（位置或引用关联不代表重复）**

- `afd22f5579844161aa011541f0ae8812` ↔ `e7194a298f6f45aeba14f4373dd3e3d2`：仍需对照判读；尚未明确判读是否具有不同根因。
- `afd22f5579844161aa011541f0ae8812` ↔ `f70251f235c5413c8143059494c2b12c`：仍需对照判读；尚未明确判读是否具有不同根因。
- `e7194a298f6f45aeba14f4373dd3e3d2` ↔ `f70251f235c5413c8143059494c2b12c`：仍需对照判读；尚未明确判读是否具有不同根因。

**任务记录**

| 任务 | 标题 | 状态 | 错误 |
|---|---|---|---|
| `aade3930fdd14e629bf4c47deb103bdf` | bootstrap 与 src 公共层的数据库、编码、会话与工具函数审计 | completed | — |
| `1a554ea215424e43ab598cdd3b38d195` | 账户与钱包入口的鉴权、IDOR 与业务逻辑审计 | completed | — |
| `6ff5b498164b4647b981d982ff57e7be` | support/download.php 文件参数路径遍历与 account/settings.php 跳转/写入门 | completed | — |
| `8d212326ad964b11a757e2c6d0fc6867` | ops/xml-import.php 的 XXE 外部实体与上传解析面取证 | completed | — |
| `44013a172d8c4a5f82c0f23d1aac9b60` | ops/jobs.php 反序列化与 dispatch_job.php __wakeup 命令执行链取证 | completed | — |
| `d250b081558b4b84a19aac3e3ba6430e` | ops/users.php Cookie 角色信任与 ops/maintenance.php X-Admin 头伪造的鉴权绕过取证 | completed | — |
| `77c4bf86961542ca9f3e7aba6264af5f` | 运营与支持入口的文件操作、命令执行与注入审计 | completed | — |
| `cd4be54e5014483db8cdb46364a18a3e` | 目录与订单入口的 SQL 注入、XSS、价格篡改审计 | completed | — |
| `567c5df1f19e49b8bde8bbb0a462bd49` | 运营入口已登记候选的定点取证：SQL 拼接、Cookie/请求头信任、XXE、SSRF、动态 include、反序列化链 | completed | — |
| `fb7f6fd4c3314de1b4b20048c8a885cb` | catalog/index.php 与 ops/report.php 的 where 条件字符串拼接注入取证 | completed | — |
| `f1ff4ea7d1574a668151cf0480de3588` | support 族存储型 XSS 与下载路径遍历取证 | completed | — |
| `0f2c3639dc10481da79091cd9627ff97` | content/page.php 动态包含/路径与输出注入取证 | completed | — |
| `931a07be72b9480cae2869a74810e279` | resources/views 模板对不可信数据的输出与包含链审计 | completed | — |
| `c59beae0073e405bb2716a88ad6a6848` | ops/xml-import.php 与 ops/members.php 的 XXE、SQL 拼接与输出注入取证 | completed | — |
| `b711f3a22e6242cb8e510e1444594d90` | docker/apache.conf 与 docker/entrypoint.sh 的部署面安全配置复核 | completed | — |
| `2a591c544b7c43d4843b7ce9fea2ce6f` | 订单详情越权（IDOR）独立取证 | completed | — |
| `57cbb8bd72774b7288f6a3a13a06d93b` | partner/portal.php 与 partner/token.php 的鉴权边界与令牌处理 | completed | — |
| `661902c1c968418ea287faf0f9e1f8fb` | ops/index.php 角色边界与 wallet 归属/状态校验结算 | completed | — |
| `d0fee6f455fd4bc6a0b83066afcd0d5c` | content/page.php LFI 与 catalog/greeting.php 反射型 XSS 的可利用性复核 | completed | — |
| `3d790ce51ce04d54b8a122c4f493a188` | 注册与登录会话路径：认证绕过、弱比较、会话固定与开放重定向 | completed | — |
| `199d0f3666304928a6edeca950df0737` | support/download.php 与 account/settings.php 的文件读取/跳转参数取证 | completed | — |
| `85c823909713454592263613986e37d3` | partner/portal.php 与 partner/token.php 的对象归属与令牌信任审计 | completed | — |
| `917cf4421e9f4f648ceb5d918a5e8a1f` | ops 模板渲染 eval 与动态 include 的代码执行/RFI 取证 | completed | — |
| `e3c411a7865048659ffd0821d2d7f968` | partner/token.php 与 partner/portal.php 的令牌签发、越权与 SSRF/注入取证 | completed | — |
| `02d65f6b09d7460687a3d182062ad48a` | src 辅助类与 CLI 脚本的 gadget 链、配置加载与敏感操作审计 | completed | — |
| `584417da36b34a3bb93e539a7c02a875` | member_lookup 跨文件 SQL 注入独立取证 | completed | — |
| `f58a8abab18549aebe5044e203b589f6` | catalog/greeting.php 与账户 profile 的反射 XSS/开放跳转取证 | completed | — |
| `5df5bb37c9224a7288fe630d97c7c3d8` | ops/url-preview.php 与 ping.php 的 SSRF/开放跳转取证 | completed | — |
| `b5a7ecf426ec4084af9d804b2e69a19f` | 订单创建/详情/列表的价格数量信任与 IDOR 审计 | completed | — |
| `44d0ec2409c143a9b03d2b47e59c82df` | account/settings.php 与 support/download.php 的文件与跳转目标参数审计 | completed | — |
| `5f3357a678de4b258f913fafdbc89205` | fixtures/server.py 辅助服务端的输入处理与暴露面复核 | completed | — |
| `e79e94b755f4439db7661197c4f9186b` | 账户域兑换、改密、更新与备份的越权/弱哈希/会话审计 | completed | — |
| `e7883aec2a4b49a79f621ed7e9476506` | ops 剩余解析/公式/数据库/审计入口的注入与执行面取证 | completed | — |

- 用量：上限 响应 2048；工具 16384；秒 10800；实际 响应 368；工具 374；秒 3469.183；剩余 响应 1680；工具 16010；秒 7330.817

**证据索引（服务器读取）**

| evidence_id | 路径 | 范围 | 文件哈希 | 可用 |
|---|---|---|---|---|
| `4e2faa355e456c2e` | lab30-shop/app/public/ops/maintenance.php | 1-5 | `b96aecd7df7c5fa4` | 是 |
| `9d62b8b1257e5f2a` | lab30-shop/app/src/bootstrap.php | 20-25 | `2050819d093be02b` | 是 |
| `6220461f4c36cb1a` | lab30-shop/app/src/bootstrap.php | 33-36 | `2050819d093be02b` | 是 |
| `3fa8e49da1b5abbd` | lab30-shop/app/public/ops/template-preview.php | 2-3 | `107da46e9b067ce0` | 是 |
| `09625de28ecabb6a` | lab30-shop/docker/php.ini | 2-3 | `b65de9007c7f42b3` | 是 |
| `78224482780bf94a` | lab30-shop/app/src/bootstrap.php | 33-37 | `2050819d093be02b` | 是 |
| `4287a6e3dca83484` | lab30-shop/app/public/support/messages.php | 3-5 | `a6866f07b4de32f3` | 是 |
| `5220b9ce518719f6` | lab30-shop/app/src/bootstrap.php | 10-10 | `2050819d093be02b` | 是 |
| `b06ddb554b7c114a` | lab30-shop/app/public/catalog/greeting.php | 1-3 | `8e6db315fdfc32cf` | 是 |
| `ae2713ba84d306b9` | lab30-shop/app/src/bootstrap.php | 47-60 | `2050819d093be02b` | 是 |
| `12d724d86e16c5f7` | lab30-shop/app/public/ops/members.php | 1-4 | `aef140c3800b9cf1` | 是 |
| `4d2f2da581629f05` | lab30-shop/app/src/member_lookup.php | 1-4 | `eb704332329d4530` | 是 |
| `85b2e45ff4e8d0eb` | lab30-shop/app/src/bootstrap.php | 4-8 | `2050819d093be02b` | 是 |
| `713c1c83b1f33981` | lab30-shop/app/public/wallet/withdraw.php | 2-11 | `e3e73271e379b085` | 是 |
| `171ea369e07c383b` | lab30-shop/app/public/orders/detail.php | 1-4 | `be69aa78cecffcfd` | 是 |
| `1b8e73c49d79d5d1` | lab30-shop/app/public/orders/index.php | 1-3 | `633f73e04b427bba` | 是 |
| `5f912f7499e51381` | lab30-shop/app/public/auth/login.php | 3-9 | `b9be43ddb2233156` | 是 |
| `9c57c102cf1e7731` | lab30-shop/app/public/auth/register.php | 6-8 | `99166a0288be7b1e` | 是 |
| `1d3eb2d6e3bdc9fc` | lab30-shop/app/public/auth/login.php | 6-7 | `b9be43ddb2233156` | 是 |
| `f86e0ebf4243b153` | lab30-shop/app/src/setup.php | 7-7 | `53e7dc7286d7d370` | 是 |
| `e4ba0faa7c0831b2` | lab30-shop/app/public/orders/create.php | 3-7 | `41e73625d7e04c58` | 是 |
| `dc0b10bf76499d4d` | lab30-shop/app/public/catalog/detail.php | 3-3 | `daccd22134a2224d` | 是 |
| `3bf12e4330602249` | lab30-shop/app/src/setup.php | 9-9 | `53e7dc7286d7d370` | 是 |
| `3d07985381125c49` | lab30-shop/app/public/auth/continue.php | 1-4 | `50fde4a15e52af44` | 是 |
| `173f24f6297d9164` | lab30-shop/app/public/content/page.php | 1-3 | `53c5997117f2d54c` | 是 |
| `440a0f38753d4516` | lab30-shop/app/src/bootstrap.php | 9-10 | `2050819d093be02b` | 是 |
| `fdf51798a6541ca7` | lab30-shop/app/src/bootstrap.php | 47-59 | `2050819d093be02b` | 是 |
| `0eb39a1944a68011` | lab30-shop/app/src/setup.php | 34-38 | `53e7dc7286d7d370` | 是 |
| `60b3d11fb6b16011` | lab30-shop/docker/php.ini | 3-3 | `b65de9007c7f42b3` | 是 |
| `b07638e22476de42` | lab30-shop/app/public/catalog/index.php | 3-5 | `e85bd1c2fa6a4b78` | 是 |
| `3d3d06e15daa2cd1` | lab30-shop/app/public/ops/xml-import.php | 1-4 | `3c23a76b1047f734` | 是 |
| `063c928d2d7c3b2e` | lab30-shop/app/src/bootstrap.php | 33-40 | `2050819d093be02b` | 是 |
| `38c5cad78d49b7f3` | lab30-shop/docker/php.ini | 1-13 | `b65de9007c7f42b3` | 是 |
| `f621b844d17a50c0` | lab30-shop/docker/apache.conf | 1-12 | `6a49914efde0e75b` | 是 |
| `4d94f1acccb7284b` | lab30-shop/app/public/account/profile.php | 1-3 | `6f2406bbf636de04` | 是 |
| `1b8b2b99a1a47fee` | lab30-shop/app/src/bootstrap.php | 46-46 | `2050819d093be02b` | 是 |
| `d55d34fdd0ba1160` | lab30-shop/app/public/account/update.php | 3-6 | `b8227f19c05d0cd3` | 是 |
| `9f3b2a689fae3c12` | lab30-shop/app/src/bootstrap.php | 11-19 | `2050819d093be02b` | 是 |
| `785adf202a6701b2` | lab30-shop/app/src/bootstrap.php | 22-24 | `2050819d093be02b` | 是 |
| `368b0f4121e7e402` | lab30-shop/app/public/auth/login.php | 3-3 | `b9be43ddb2233156` | 是 |
| `6e01b773a001a844` | lab30-shop/app/public/auth/login.php | 8-8 | `b9be43ddb2233156` | 是 |
| `0ad2a840edc3f2e0` | lab30-shop/app/public/ops/users.php | 1-5 | `3c5e879d945650ba` | 是 |
| `10c0c8123072e718` | lab30-shop/app/public/support/download.php | 2-3 | `71f0558eeb4ebb6c` | 是 |
| `f5faf41dff9a5a91` | lab30-shop/app/src/bootstrap.php | 9-9 | `2050819d093be02b` | 是 |
| `343d5e3158080141` | lab30-shop/app/public/partner/portal.php | 2-6 | `e1267edb0f9df936` | 是 |
| `10e301316be34133` | lab30-shop/app/public/partner/token.php | 2-4 | `391948b46efce76c` | 是 |
| `136d02a92a08ac98` | lab30-shop/app/public/ops/template-render.php | 1-4 | `357da9e9959275d8` | 是 |
| `415907ec6bf2f739` | lab30-shop/app/src/bootstrap.php | 40-40 | `2050819d093be02b` | 是 |
| `17e1cacfb5189678` | lab30-shop/app/public/ops/url-preview.php | 2-4 | `e495938b10c455c6` | 是 |
| `52a7b68bba8b1c1f` | lab30-shop/app/public/account/backup.php | 4-6 | `017e1703cdf0ff0c` | 是 |
| `9d0d13b19a80b9a2` | lab30-shop/app/src/backup.php | 2-5 | `571459cc8b0f6e8e` | 是 |
| `61f200eb89320676` | lab30-shop/app/public/ops/ping.php | 1-3 | `c15517950afe0794` | 是 |
| `65fc5323ae7c9b98` | lab30-shop/app/src/host_check.php | 1-2 | `c3a868155c2d335e` | 是 |
| `772dda483c0c1762` | lab30-shop/app/public/ops/batch-check.php | 2-2 | `5f76332e7ad1b33a` | 是 |
| `0ae7d306da24e8a8` | lab30-shop/app/public/ops/jobs.php | 2-4 | `0f7550fa7f16bd4a` | 是 |
| `4a4dd3de59c1de26` | lab30-shop/app/src/dispatch_job.php | 1-5 | `e8234b971fe75d85` | 是 |
| `a3d11f0b53761e11` | lab30-shop/app/public/account/redeem.php | 1-9 | `28b3dc4534cca985` | 是 |
| `0245c9c62f5af52c` | lab30-shop/app/public/ops/report.php | 2-4 | `90d7d60d44815374` | 是 |
| `ec18381d7af73d0f` | lab30-shop/app/public/account/update.php | 4-6 | `b8227f19c05d0cd3` | 是 |
| `8bf814169e217985` | lab30-shop/app/public/support/download.php | 1-4 | `71f0558eeb4ebb6c` | 是 |
| `17d72b54d2f463ef` | lab30-shop/app/src/bootstrap.php | 2-2 | `2050819d093be02b` | 是 |
| `5576c0baf3a49f09` | lab30-shop/app/public/ops/formula.php | 2-4 | `686f39f31996a5d3` | 是 |
| `156ea3e4adf6ec2a` | lab30-shop/docker/web.Dockerfile | 1-4 | `5cea6e16d48a9d49` | 是 |

**附件与机器可读清单**

- Markdown：本报告（由事实包确定性生成）。
- JSON：result.json（含本事实包与质量结果）
- 证据包：evidence/（POC 脚本、runner 产物、runner manifest）
- 源码：源码片段由宿主从冻结快照读取，见 source_evidence
- 事实包 ID：`23f929fcfdf3262628b35821772e4fe1a2a9d484fceac86fd69e5a4a94dd5df3`；页面、Markdown、JSON 与证据包共用同一份事实。
