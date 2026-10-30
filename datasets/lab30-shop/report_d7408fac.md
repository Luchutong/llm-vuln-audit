# 源码审计阶段报告（d7408fac）

> 报告类型：阶段报告；发布状态：可发布（阶段报告）
> 事实包 final-review/v1 · 渲染器 final-report/v2 · 策略 audit-runtime-3
> 运行 `d7408facaa2245be81c08c2ac3c715a2` · 快照 `586b79b41f8e4f59be80f2a9b548902b` · 源码哈希 `67fd87e9ae771d10…` · 输入哈希 `14129816449d9af6170ad08190d88cb178d710edd2c48f6d6e3f837913ca8fcd`
> 本报告由宿主从冻结事实包确定性生成；数量、位置、验证状态与评分均不由模型填写。

## 1. 执行与终审摘要

- 运行：`d7408facaa2245be81c08c2ac3c715a2`；状态：cancelled；停止原因：user_cancelled；用户取消审计
- 审计完整性：未完成，本报告为阶段报告
- 报告类型：stage；发布状态：可发布（阶段报告）

- 原始记录：36
- 有效记录：32
- 规范结论：31
- 已接受漏洞：0
- 待终审：31
- 存疑或排除：0

“已接受漏洞”以当前版本的正式终审处置为准：静态证据充分可接受；动态已验证结论还须完成同版本观测复核。其余结论逐条保留，不会因为缺少终审额度而从报告中消失。

| 完成维度 | 已完成 | 分母 | 说明 |
|---|---:|---:|---|
| 源码覆盖（读取） | 60 | 61 | 已读只表示宿主记录过读取 |
| 源码覆盖（读取+带理由跳过） | 61 | 61 | 跳过不是安全结论 |
| 必做方向结算 | 3 | 6 | 未决 3 个 |
| 动态验证完成 | 0 | 31 | 待验证 31 条 |
| 正式复核 | 0 | 31 | 复核存疑或未复核不计入已接受 |
| 源码覆盖（仍待复核） | 0 | 61 | 未读且未跳过 0 个 |

- 发布门禁未通过：review_batch_complete

**仍需终审的结论**

- C-01 登录会话未重新生成 ID 且允许 GET 指定 sid 导致会话固定：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-02 account/update.php 批量赋值可修改 role/balance/tier 敏感字段：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-03 account/update.php 批量赋值允许普通用户把 role 改为 admin、任意改写 balance：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-04 在线留言 message 入库后未转义输出导致存储型 XSS：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-05 greeting.php 未转义 GET name 输出的反射型 XSS：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-06 support/download.php file 参数路径遍历导致任意文件读取：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-07 wallet/withdraw.php 提现余额读-改-写无事务，usleep 放大并发窗口可重复提现：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-08 orders/detail.php 仅按 id 读取订单，无归属校验导致可越权查看他人订单（含私密备注）：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-09 订单创建采信客户端 price 计算总价（单价操纵）：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-10 auth/continue.php 未校验 next 参数导致开放重定向：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-11 content/page.php page 参数路径遍历导致本地文件包含：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-12 ops/report.php 将可写 nickname 直接拼接进 SQL，会员可注入读取其他账户数据：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-13 account/redeem.php 使用 == 比较 md5 导致弱类型绕过，可任意升级 gold 会员：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-14 XML 导入启用 LIBXML_NOENT|LIBXML_DTDLOAD，用户 XML 外部实体可读取本地文件：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-15 合作方结算工作台返回全部订单，无 partner/归属过滤：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-16 reset_shop() 硬编码默认账户口令并以 md5 存储密码：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-17 ops/users.php 仅凭客户端 role Cookie 判定管理员，任意登录会员可读取全量用户清单：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-18 ops/members.php 经 member_lookup 将 GET q 直接拼接进 LIKE 查询导致 SQL 注入：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-19 运营主机巡检把 host 参数直接拼接进 shell_exec 的 ping 命令，可注入任意系统命令：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-20 src/member_lookup.php 将 GET 参数拼接进 LIKE 查询导致 SQL 注入：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-21 reset_shop() 与 bin/setup.php 全表无 WHERE DELETE 且 CLI 包装缺失 SAPI 检查：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-22 template-render.php 对 {{ }} 内表达式直接 eval，运营模板可远程代码执行：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-23 ops/report.php 将库中 nickname 拼接进 SQL，形成存储型二次注入：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-24 运营 URL 预览将用户提供的地址直接交给 file_get_contents，可访问内网与元数据地址：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-25 维护接口仅凭可伪造的 X-Admin 请求头判定授权，且会话缺少该头即可匿名调用：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-26 运营后台 ping 主机参数未过滤直接进入 shell_exec，可执行任意系统命令：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-27 catalog 搜索参数 q 直接拼入 SQL 导致注入：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-28 合作方门户令牌仅 base64 解码 role 判断，签名不校验导致管理员鉴权绕过：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-29 ops/jobs.php 反序列化 POST 任务数据触发 DispatchJob::__wakeup 执行任意系统命令：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-30 account/backup.php 客户端可控反序列化恢复写入 tier，可自升级会员：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审
- C-31 ops/jobs.php 反序列化用户数据触发 DispatchJob::__wakeup 中 shell_exec 命令执行：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

## 2. 范围和方法

- 项目：39211162aa984b25b60228c194b531ae；快照：`586b79b41f8e4f59be80f2a9b548902b`
- 源码包哈希（archive sha256）：`67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c`
- 事实包：final-review/v1；渲染器：final-report/v2；模板哈希：`bae25eb461e0811b`
- 输入哈希：`14129816449d9af6170ad08190d88cb178d710edd2c48f6d6e3f837913ca8fcd`；冻结时间：2026-10-30T10:28:18.095046+00:00；生成时间：2026-10-30T10:28:18.095046+00:00
- 模型配置：deepseek-flash；策略版本：audit-runtime-3

本次报告只使用宿主记录的冻结事实：源码引用由服务器从快照读取并核对哈希，动态验证取自隔离 runner 的作业记录，正式复核按 finding revision 与 verification id 精确引用。模型的结论陈述与修复建议以“结论陈述”标注，不作为证据；未执行、环境失败与验证不确定都不解释为误报。

| 预算 | 上限 | 实际使用 | 剩余 |
|---|---:|---:|---:|
| 模型响应 | 2048 | 109 | 1939 |
| 工具调用 | 16384 | 191 | 16193 |
| 秒 | 10800 | 1050.513 | 9749.487000000001 |

- 上下文：峰值请求 141026 字节 / 上限 393216 字节；摘要请求 0 次；硬上限命中 0 次。

| 阶段 | 请求配额 | 已用 |
|---|---:|---:|
| 源码挖掘 | 103 | 103 |
| POC 验证 | 1924 | 6 |
| 统一终审 | 21 | 0 |
- 调度政策：host-queue-v1；配额：自动分配。
- 待终审 34 项，预计 7 批；当前预留 21 次请求、480 秒；按实际批次容量与 Worker 调整，不增加整次额度。
- POC 执行：。

## 3. 规范漏洞清单

| 编号 | 标题 | 类型 | 评分 | 位置 | 静态判读 | 动态验证 | 正式终审 | 处置 |
|---|---|---|---|---|---|---|---|---|
| C-01 | 登录会话未重新生成 ID 且允许 GET 指定 sid 导致会话固定 | session_fixation | CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:… | lab30-shop/app/public/auth/login.php:8 | 缺上下文（1 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-02 | account/update.php 批量赋值可修改 role/balance/tier 敏感字段 | mass_assignment | CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/account/update.php:4 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-03 | account/update.php 批量赋值允许普通用户把 role 改为 admin、任意改写 balance | mass_assignment | CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/account/update.php:4 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-04 | 在线留言 message 入库后未转义输出导致存储型 XSS | xss_s | CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/… | lab30-shop/app/public/support/messages.php:5 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-05 | greeting.php 未转义 GET name 输出的反射型 XSS | xss_r | CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/… | lab30-shop/app/public/catalog/greeting.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-06 | support/download.php file 参数路径遍历导致任意文件读取 | path_traversal | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/support/download.php:3 | 缺上下文（2 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-07 | wallet/withdraw.php 提现余额读-改-写无事务，usleep 放大并发窗口可重复提现 | race_condition | CVSS 3.1 Base 3.1 (low) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N | lab30-shop/app/public/wallet/withdraw.php:7 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-08 | orders/detail.php 仅按 id 读取订单，无归属校验导致可越权查看他人订单（含私密备注） | idor | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/orders/detail.php:2 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-09 | 订单创建采信客户端 price 计算总价（单价操纵） | price_manipulation | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/orders/create.php:5 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-10 | auth/continue.php 未校验 next 参数导致开放重定向 | open_redirect | CVSS 3.1 Base 3.5 (low) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N | lab30-shop/app/public/auth/continue.php:3 | 缺上下文（1 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-11 | content/page.php page 参数路径遍历导致本地文件包含 | lfi | CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/… | lab30-shop/app/public/content/page.php:3 | 缺上下文（2 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-12 | ops/report.php 将可写 nickname 直接拼接进 SQL，会员可注入读取其他账户数据 | sqli | CVSS 3.1 Base 5.7 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/… | lab30-shop/app/public/ops/report.php:3 | 缺上下文（1 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-13 | account/redeem.php 使用 == 比较 md5 导致弱类型绕过，可任意升级 gold 会员 | weak_type_comparison | CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/… | lab30-shop/app/public/account/redeem.php:5 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-14 | XML 导入启用 LIBXML_NOENT&#124;LIBXML_DTDLOAD，用户 XML 外部实体可读取本地文件 | xxe | CVSS 3.1 待评分 | lab30-shop/app/public/ops/xml-import.php:3 | 缺上下文（2 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-15 | 合作方结算工作台返回全部订单，无 partner/归属过滤 | idor | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/partner/portal.php:4 | 缺上下文（2 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-16 | reset_shop() 硬编码默认账户口令并以 md5 存储密码 | weak_crypto | CVSS 3.1 Base 7.3 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:… | lab30-shop/app/src/setup.php:17 | 缺上下文（3 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-17 | ops/users.php 仅凭客户端 role Cookie 判定管理员，任意登录会员可读取全量用户清单 | auth_bypass | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/ops/users.php:2 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-18 | ops/members.php 经 member_lookup 将 GET q 直接拼接进 LIKE 查询导致 SQL … | sqli | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/src/member_lookup.php:3 | 缺上下文（1 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-19 | 运营主机巡检把 host 参数直接拼接进 shell_exec 的 ping 命令，可注入任意系统命令 | command_injection | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/src/host_check.php:2 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-20 | src/member_lookup.php 将 GET 参数拼接进 LIKE 查询导致 SQL 注入 | sqli | CVSS 3.1 Base 8.3 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/src/member_lookup.php:3 | 缺上下文（2 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-21 | reset_shop() 与 bin/setup.php 全表无 WHERE DELETE 且 CLI 包装缺失 SAP… | other | CVSS 3.1 Base 7.4 (high) · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:… | lab30-shop/app/src/setup.php:15 | 缺上下文（3 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-22 | template-render.php 对 {{ }} 内表达式直接 eval，运营模板可远程代码执行 | code_execution | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/template-render.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-23 | ops/report.php 将库中 nickname 拼接进 SQL，形成存储型二次注入 | sqli | CVSS 3.1 Base 5.7 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/… | lab30-shop/app/public/ops/report.php:3 | 缺上下文（1 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-24 | 运营 URL 预览将用户提供的地址直接交给 file_get_contents，可访问内网与元数据地址 | ssrf | CVSS 3.1 待评分 | lab30-shop/app/public/ops/url-preview.php:3 | 缺上下文（2 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-25 | 维护接口仅凭可伪造的 X-Admin 请求头判定授权，且会话缺少该头即可匿名调用 | auth_bypass | CVSS 3.1 待评分 | lab30-shop/app/public/ops/maintenance.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-26 | 运营后台 ping 主机参数未过滤直接进入 shell_exec，可执行任意系统命令 | command_injection | CVSS 3.1 待评分 | lab30-shop/app/public/ops/ping.php:2 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-27 | catalog 搜索参数 q 直接拼入 SQL 导致注入 | sqli | CVSS 3.1 Base 9.4 (critical) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:… | lab30-shop/app/public/catalog/index.php:4 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-28 | 合作方门户令牌仅 base64 解码 role 判断，签名不校验导致管理员鉴权绕过 | auth_bypass | CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:… | lab30-shop/app/public/partner/portal.php:3 | 缺上下文（2 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-29 | ops/jobs.php 反序列化 POST 任务数据触发 DispatchJob::__wakeup 执行任意系统命令 | insecure_deserialization | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/jobs.php:3 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-30 | account/backup.php 客户端可控反序列化恢复写入 tier，可自升级会员 | insecure_deserialization | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/account/backup.php:5 | 证据已记录 | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |
| C-31 | ops/jobs.php 反序列化用户数据触发 DispatchJob::__wakeup 中 shell_exec 命… | insecure_deserialization | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/src/dispatch_job.php:4 | 缺上下文（2 项） | 未验证 | 未复核 | 待终审：当前版本尚未完成独立终审批次；动态复核不替代终审 |

## 4. 逐条漏洞详单

### C-01 登录会话未重新生成 ID 且允许 GET 指定 sid 导致会话固定

- 当前版本：finding `69bd458ebef04c9ea51a053f74035df3` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/login.php:8`；文件：`lab30-shop/app/src/bootstrap.php`
- 证据引用：`dbf3c25dae0af619` lab30-shop/app/src/bootstrap.php:11-18；`144e48ac712e16dc` lab30-shop/app/public/auth/login.php:3-8
- 根因类别：task_goal:v2:5159525698f33e58d628:1（规范类型 session_fixation）

**结论陈述（模型产出，不是证据）**

bootstrap 的 start_session 将 session.use_strict_mode 设为 0 并允许通过 GET sid 指定 session_id；login.php 第3行把 $_GET['sid'] 传入 start_session，登录成功第8行仅设置 $_SESSION['user_id'] 而未调用 session_regenerate_id()，预设的会话 ID 在认证后继续有效，攻击者可固定受害者会话后劫持。

- 攻击前身份与适用前提：受害者点击带有效 sid 的链接并完成登录
- 入口 → 传播 → 危险操作/状态变更：$_GET['sid'] → $_GET['sid'] -> start_session($sid) -> session_id($sid) -> session_start() -> 登录后赋值 $_SESSION['user_id'] → 认证成功后沿用攻击者可控的会话标识
- 防护与边界：sid 仅有正则字符集与长度限制（bootstrap:17），use_strict_mode 关闭，且登录处无 session_regenerate_id
- 静态判读：缺上下文（1 项）；缺失上下文：未读取 sessions 存储目录权限配置，无法确认同一 sid 攻击者是否可读取会话文件（会话固定仍需攻击者获知 sid 值并诱导受害者使用）
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：启用 session.use_strict_mode=1，移除对 GET sid 的信任；登录成功后调用 session_regenerate_id(true)。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/src/bootstrap.php:11-18`（sha256 `2050819d093be02b…`）

```php
   11  function start_session(?string $sid = null): void {
   12      if (session_status() === PHP_SESSION_ACTIVE) return;
   13      ini_set('session.use_strict_mode', '0');
   14      session_save_path(data_dir() . '/sessions');
   15      session_name('SHOPSESSID');
   16      session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'path' => '/']);
   17      if ($sid !== null && preg_match('/^[a-zA-Z0-9,-]{16,64}$/D', $sid)) session_id($sid);
   18      session_start();
```

`lab30-shop/app/public/auth/login.php:3-8`（sha256 `b9be43ddb2233156…`）

```php
    3  start_session(isset($_GET['sid']) ? (string)$_GET['sid'] : null);
    4  $error='';
    5  if ($_SERVER['REQUEST_METHOD']==='POST') {
    6      $q=db()->prepare('SELECT id,password_md5 FROM users WHERE username=?'); $q->execute([$_POST['username']??'']); $row=$q->fetch();
    7      if ($row && hash_equals($row['password_md5'],md5((string)($_POST['password']??'')))) {
    8          $_SESSION['user_id']=(int)$row['id']; event_log('login');
```

### C-02 account/update.php 批量赋值可修改 role/balance/tier 敏感字段

- 当前版本：finding `26e1f25384ff4580a0eace5fd242d04a` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/update.php:4`；文件：`lab30-shop/app/public/account/update.php`
- 证据引用：`fadde1b1e1006c27` lab30-shop/app/public/account/update.php:3-7；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:a2a5e35b227f58304cdd:1（规范类型 mass_assignment）

**结论陈述（模型产出，不是证据）**

update.php 的可更新列白名单包含 role、balance、tier，$_POST 中同名键被构造为 SET 片段，WHERE id 仅用当前登录用户 id；普通用户提交 role=admin、balance=999999、tier=gold 即可自升管理员与篡改余额，服务端没有任何字段级权限过滤。

- 攻击前身份与适用前提：拥有任意普通账号并取得自己会话的 csrf 令牌
- 入口 → 传播 → 危险操作/状态变更：POST 参数 role / balance / tier（普通登录用户） → $_POST 键名匹配 $columns（含 role/balance/tier）→ $set[]='`'.$key.'`=?' → UPDATE users SET ... WHERE id=$u['id'] → UPDATE users SET role=?/balance=?/tier=? 写入敏感列
- 防护与边界：check_csrf 仅防 CSRF；列白名单反向扩大了可写敏感字段，无角色/字段授权校验
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：从列白名单移除 role、balance、tier 等敏感列，仅允许用户可编辑字段，并在服务端强制字段级授权。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/update.php:3-7`（sha256 `b8227f19c05d0cd3…`）

```php
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
    7      if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response($u);
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-03 account/update.php 批量赋值允许普通用户把 role 改为 admin、任意改写 balance

- 当前版本：finding `2a31cc05a2c0443399c2c46c202d9a2f` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/update.php:4`；文件：`lab30-shop/app/public/account/update.php`
- 证据引用：`aecff877ea34a4a4` lab30-shop/app/public/account/update.php:1-9；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:c1a554840c086a3e9401:1（规范类型 mass_assignment）

**结论陈述（模型产出，不是证据）**

account/update.php 第4行把请求字段白名单设为包含 role、balance、tier 等敏感列，第5行遍历 $_POST 中所有命中白名单的键拼进 UPDATE 语句，第6行按当前用户 id 执行。服务端没有排除角色/余额列，因此普通登录用户提交 role=admin 或 balance=999999 即可自我提权与篡改余额；页面只渲染 display_name/nickname/email/homepage，但服务端仍接受隐藏字段（第9行表单仅四个字段）。

- 攻击前身份与适用前提：普通用户已登录并取得 csrf 令牌（可从任意页面 csrf_field 获取）
- 入口 → 传播 → 危险操作/状态变更：$_POST 任意字段名（含 role、balance、tier） → update.php:4 $columns 含 role/balance → 第5行 foreach($_POST) 命中即加入 $set/$values → 第6行 UPDATE users SET `role`=? ... WHERE id=当前用户 → 动态拼接的 UPDATE users 写入 role/balance 等授权与资金列
- 防护与边界：仅有 check_csrf() 与登录门槛，白名单反而显式包含敏感列，无角色限制
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：白名单移除 role/balance/tier 等敏感列，仅允许 display_name/nickname/email/homepage；角色与余额变更走独立的管理员接口并做权限校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/update.php:1-9`（sha256 `b8227f19c05d0cd3…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$notice='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
    7      if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response($u);
    8  }
    9  page('会员资料维护',function()use($u,$notice){echo '<section class="panel narrow">';if($notice)echo '<div class="notice">'.h($notice).'</div>';echo '<form method="post">'.csrf_field();form_input('display_name','显示名称',$u['display_name']);form_input('nickname','对外昵称',$u['nickname']);form_input('email','常用邮箱',$u['email'],'email');form_input('homepage','个人网站',$u['homepage']);echo '<button>保存资料</button></form></section>';},'账户与会员');
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-04 在线留言 message 入库后未转义输出导致存储型 XSS

- 当前版本：finding `2d93a21827de43d9b665b0bb897e5380` revision 1（项目版本 16）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/messages.php:5`；文件：`lab30-shop/app/public/support/messages.php`
- 证据引用：`4287a6e3dca83484` lab30-shop/app/public/support/messages.php:3-5；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10
- 根因类别：task_goal:v2:ccad9408a180e923d30c:1（规范类型 xss_s）

**结论陈述（模型产出，不是证据）**

messages.php:3 将 $_POST['message'] 仅做非空与长度校验后写入 messages 表；messages.php:4 取出全部留言，messages.php:5 用字符串拼接把 $row['message'] 放入 <div class="message-body">，同行的 display_name、created_at 都调用 h() 而 message 未调用。任一登录用户提交带事件属性的标签即可在访问留言页的用户（含运营/管理员）浏览器执行脚本。

- 攻击前身份与适用前提：攻击者持有任一有效账号并通过 check_csrf；受害者访问 /support/messages.php
- 入口 → 传播 → 危险操作/状态变更：POST /support/messages.php 的 message 参数（需登录） → $_POST['message'] -> INSERT INTO messages(message)（第3行）-> SELECT m.*（第4行）-> 第5行拼接输出 → echo '<div class="message-body">'.$row['message'].'</div>'
- 防护与边界：写入仅校验长度；h() 在 bootstrap.php:10 定义且同用途可用，但此处未调用
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：输出改为 h($row['message']) 或经白名单净化。

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

### C-05 greeting.php 未转义 GET name 输出的反射型 XSS

- 当前版本：finding `70a4f97f262f468a8c451b0bb97d8060` revision 1（项目版本 14）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/catalog/greeting.php:3`；文件：`lab30-shop/app/public/catalog/greeting.php`
- 证据引用：`c57a3bf6bb6b01db` lab30-shop/app/public/catalog/greeting.php:2-3；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10；`1b8b2b99a1a47fee` lab30-shop/app/src/bootstrap.php:46-46
- 根因类别：task_goal:v2:1973600ea3e539dd6e7b:1（规范类型 xss_r）

**结论陈述（模型产出，不是证据）**

greeting.php:2 直接读取 $_GET['name'] 到 $name（仅强制字符串），greeting.php:3 将 $name 拼入 <h2>你好，'.$name.'</h2> 未调用 h()；同一语句中的 form_input 内部对值做了 h()，说明编码函数存在但此处遗漏。无需登录即可利用 /catalog/greeting.php?name=<svg/onload=alert(1)> 执行脚本。

- 攻击前身份与适用前提：诱导受害者访问带载荷的链接
- 入口 → 传播 → 危险操作/状态变更：GET 参数 name → $_GET['name'] -> $name -> 第3行 '<h2>你好，'.$name.'</h2>' 直接 echo → echo '<h2>你好，'.$name.'</h2>'
- 防护与边界：无，h() 未调用
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：输出改为 h($name)。

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

`lab30-shop/app/src/bootstrap.php:46-46`（sha256 `2050819d093be02b…`）

```php
   46  function form_input(string $name, string $label, string $value = '', string $type = 'text'): void { echo '<label>' . h($label) . '<input name="' . h($name) . '" type="' . h($type) . '" value="' . h($value) . '" required></label>'; }
```

### C-06 support/download.php file 参数路径遍历导致任意文件读取

- 当前版本：finding `b947798745e143a1929c3f804f345e85` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/download.php:3`；文件：`lab30-shop/app/public/support/download.php`
- 证据引用：`8bf814169e217985` lab30-shop/app/public/support/download.php:1-4；`f5faf41dff9a5a91` lab30-shop/app/src/bootstrap.php:9-9；`35aab41df419ddcc` lab30-shop/app/src/bootstrap.php:33-35
- 根因类别：task_goal:v2:9142ed0719873f4a239e:1（规范类型 path_traversal）

**结论陈述（模型产出，不是证据）**

download.php 第 3 行把 $_GET['file'] 强制转字符串后拼接到 data_dir().'/docs/' 并直接 file_get_contents 回显；data_dir() 返回服务端目录（bootstrap.php:9）。没有任何规范化或 ../ 过滤，仅有 is_file 存在性判断，攻击者可用穿越序列读取 docs 目录之外的任意可读文件。

- 攻击前身份与适用前提：拥有任意有效登录会话；目标文件对 web 进程可读
- 入口 → 传播 → 危险操作/状态变更：$_GET['file'] → (string)$_GET['file'] → data_dir().'/docs/'.$file → $path → file_get_contents($path) → echo 输出 → file_get_contents 读取攻击者控制路径并回显
- 防护与边界：仅 require_user() 登录检查与 is_file 存在性检查；无 basename/realpath/白名单/.. 过滤
- 静态判读：缺上下文（2 项）；缺失上下文：resources/views 目录实际文件及 PHP include 对省略 .php 后缀的解析行为未在快照中确认；ops/url-preview.php 的 $url 赋值上游代码未完整读取
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：对 file 参数使用 basename() 并配合 realpath 校验目标必须位于 docs 目录内，或改用白名单映射文件名。

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

`lab30-shop/app/src/bootstrap.php:33-35`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
```

### C-07 wallet/withdraw.php 提现余额读-改-写无事务，usleep 放大并发窗口可重复提现

- 当前版本：finding `4e436dcb24744e319307607dd6c638e3` revision 1（项目版本 21）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/wallet/withdraw.php:7`；文件：`lab30-shop/app/public/wallet/withdraw.php`
- 证据引用：`713c1c83b1f33981` lab30-shop/app/public/wallet/withdraw.php:2-11；`bd7555c5a11365fe` lab30-shop/app/public/wallet/withdraw.php:4-8
- 根因类别：task_goal:v2:3d26aece95288638cd1f:1（规范类型 race_condition）

**结论陈述（模型产出，不是证据）**

withdraw.php 第4行读取 balance，第5行只在应用层比较余额是否足够，第6行 usleep(350000) 人为放大窗口，第7行用第4行读到的旧 balance 计算 balance-amount 写回，第8行插入提现记录；全程无事务、无 SELECT ... FOR UPDATE、无 WHERE balance>=? 条件更新。第3行 session_write_close 只释放会话锁，不能阻止多个并发 HTTP 请求同时通过第5行检查，从而以同一笔余额发起多次提现。

- 攻击前身份与适用前提：拥有任意普通账号，取得会话 csrf 令牌，能并发发送多个提现请求
- 入口 → 传播 → 危险操作/状态变更：$_POST['amount']（withdraw.php:2） → amount 经 filter_var 校验后，与 :4 读到的 balance 比较，:6 睡眠，:7 写回 balance-amount，:8 插入 withdrawals → UPDATE users SET balance=? 无并发保护地写回扣减结果（withdraw.php:7）
- 防护与边界：仅 PHP 层 !<amount 比较与单值上限；无数据库行锁、无事务、无原子条件更新
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 3.1 (low) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用事务加 SELECT ... FOR UPDATE 锁定用户行，或改为原子条件更新 UPDATE users SET balance=balance-? WHERE id=? AND balance>=? 并检查 affected rows，提现记录与扣减同事务提交；移除 usleep。

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

`lab30-shop/app/public/wallet/withdraw.php:4-8`（sha256 `e3e73271e379b085…`）

```php
    4  $q=db()->prepare('SELECT balance FROM users WHERE id=?');$q->execute([$id]);$balance=(float)$q->fetchColumn();
    5  if($balance<$amount)fail_request('账户余额不足，请调整提现金额。',409);
    6  usleep(350000);
    7  $q=db()->prepare('UPDATE users SET balance=? WHERE id=?');$q->execute([$balance-$amount,$id]);
    8  $q=db()->prepare('INSERT INTO withdrawals(user_id,amount) VALUES(?,?)');$q->execute([$id,$amount]);
```

### C-08 orders/detail.php 仅按 id 读取订单，无归属校验导致可越权查看他人订单（含私密备注）

- 当前版本：finding `0d65511a4c954f949d656af554f1f0a7` revision 1（项目版本 27）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/detail.php:2`；文件：`lab30-shop/app/public/orders/detail.php`
- 证据引用：`171ea369e07c383b` lab30-shop/app/public/orders/detail.php:1-4；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:c0a7b45e521a84378563:1（规范类型 idor）

**结论陈述（模型产出，不是证据）**

orders/detail.php 第2行只 require_user() 做登录判断，随后用 $_GET['id'] 直接查询 orders 并 JOIN users，WHERE 仅 o.id=?，未附加 o.user_id=当前用户；任意登录用户遍历 id 即可读取他人订单号、购买人用户名、数量、实付金额及 private_note（第2行 SELECT o.*，第4行输出 private_note），第3行在 Accept: application/json 时直接 json_response($o) 返回完整行，扩大泄露面。

- 攻击前身份与适用前提：攻击者拥有任意普通账号并登录；知晓或遍历订单自增 id
- 入口 → 传播 → 危险操作/状态变更：$_GET['id']（及 $_SERVER['HTTP_ACCEPT'] 决定 JSON 分支） → orders/detail.php:2 $q->execute([$_GET['id']??0]) 取回 $o → 第3行 json_response($o) 或第4行 page 输出 o.order_no/username/total/private_note → 无归属条件的订单读取与完整对象输出（含 private_note）
- 防护与边界：仅有 require_user() 登录门槛，查询条件未包含当前用户 id；对比 orders/index.php 使用 WHERE user_id=?，说明 detail 缺口属实现遗漏
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：查询加入 AND o.user_id=?（用当前会话用户 id），并仅在归属匹配时返回；JSON 分支同样复用该条件。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/orders/detail.php:1-4`（sha256 `be69aa78cecffcfd…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();$q=db()->prepare('SELECT o.*,u.username,p.name FROM orders o JOIN users u ON u.id=o.user_id LEFT JOIN products p ON p.id=o.product_id WHERE o.id=?');$q->execute([$_GET['id']??0]);$o=$q->fetch();if(!$o)fail_request('订单不存在。',404);
    3  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response($o);
    4  page('订单详情',function()use($o){echo '<section class="panel"><span class="badge">等待配送</span><h2>'.h($o['order_no']).'</h2><dl>';foreach(['商品'=>$o['name'],'购买人'=>$o['username'],'数量'=>$o['quantity'],'实付金额'=>'¥'.$o['total'],'配送备注'=>$o['private_note']]as$k=>$v)echo '<dt>'.h($k).'</dt><dd>'.h($v).'</dd>';echo '</dl><a class="button secondary" href="/orders/index.php">返回订单中心</a></section>';},'订单中心');
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-09 订单创建采信客户端 price 计算总价（单价操纵）

- 当前版本：finding `da2587fa06a44d5682a0fc44ff1667a5` revision 1（项目版本 26）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/create.php:5`；文件：`lab30-shop/app/public/orders/create.php`
- 证据引用：`e4ba0faa7c0831b2` lab30-shop/app/public/orders/create.php:3-7；`dc0b10bf76499d4d` lab30-shop/app/public/catalog/detail.php:3-3
- 根因类别：task_goal:v2:97d53850074b97260893:1（规范类型 price_manipulation）

**结论陈述（模型产出，不是证据）**

orders/create.php 第3行从 $_POST['price'] 读取价格并 FILTER_VALIDATE_FLOAT 校验，第4行仅校验非负，第5行用其计算 total，第7行把客户端 price 连同 total 写入 orders 表，从不使用数据库中 $p['price']。任何登录用户可提交 price=0.01 低价下单。

- 攻击前身份与适用前提：已登录用户，持有有效 CSRF token
- 入口 → 传播 → 危险操作/状态变更：$_POST['price']（detail.php 隐藏字段） → $_POST['price'] -> FILTER_VALIDATE_FLOAT -> $price -> $total=$price*$quantity -> INSERT orders(unit_price,total) → INSERT INTO orders 使用客户端价格作为实付金额
- 防护与边界：仅校验 price>=0，未与 products.price 对比
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：服务端使用 $p['price'] 计算 total，忽略客户端 price 字段

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

### C-10 auth/continue.php 未校验 next 参数导致开放重定向

- 当前版本：finding `c16ccad83cbb4a7ba9cde3ff9d3be309` revision 1（项目版本 20）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/continue.php:3`；文件：`lab30-shop/app/public/auth/continue.php`
- 证据引用：`3d07985381125c49` lab30-shop/app/public/auth/continue.php:1-4
- 根因类别：task_goal:v2:b53bce906bedf697fed9:1（规范类型 open_redirect）

**结论陈述（模型产出，不是证据）**

continue.php 第3行在 require_user() 后直接执行 header('Location: '.(string)$_GET['next'])，next 完全来自请求参数且无主机白名单或相对路径校验，登录用户点击 /auth/continue.php?next=https://evil.example 即被重定向到外部站点。

- 攻击前身份与适用前提：受害者已登录并点击攻击者构造的链接
- 入口 → 传播 → 危险操作/状态变更：$_GET['next'] → $_GET['next'] -> 字符串强制转换 -> header('Location: ...') -> exit → 未校验的 302 Location 跳转
- 防护与边界：仅有 require_user() 登录校验，无跳转目标校验
- 静态判读：缺上下文（1 项）；缺失上下文：未读取 sessions 存储目录权限配置，无法确认同一 sid 攻击者是否可读取会话文件（会话固定仍需攻击者获知 sid 值并诱导受害者使用）
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 3.5 (low) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：只允许站内相对路径，拒绝含 scheme/主机或以 // 开头的值，或改用白名单映射。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/auth/continue.php:1-4`（sha256 `50fde4a15e52af44…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();
    3  if(isset($_GET['next'])){header('Location: '.(string)$_GET['next']);exit;}
    4  page('继续访问',function(){echo '<section class="panel"><h2>选择下一站</h2><form method="get">';form_input('next','继续访问地址','/orders/index.php');echo '<button>继续</button></form></section>';});
```

### C-11 content/page.php page 参数路径遍历导致本地文件包含

- 当前版本：finding `e0ccf6637cf2457781f1f67b8db61915` revision 1（项目版本 24）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/content/page.php:3`；文件：`lab30-shop/app/public/content/page.php`
- 证据引用：`173f24f6297d9164` lab30-shop/app/public/content/page.php:1-3；`d4a92906b50eb717` lab30-shop/app/src/bootstrap.php:59-59
- 根因类别：task_goal:v2:4bb556c3ad1b3fb37185:1（规范类型 lfi）

**结论陈述（模型产出，不是证据）**

content/page.php 第 2 行取 $_GET['page'] 作为 $name，第 3 行直接拼接到 APP_ROOT.'/resources/views/'.$name.'.php' 并 include，无 basename/白名单/.. 过滤。bootstrap.php:59 由 page() 调用该闭包，使 include 可达。攻击者用 ../ 穿越包含任意本地 .php 文件或读取其内容，构成 LFI。

- 攻击前身份与适用前提：可访问 content/page.php；被包含文件在进程可达路径内（缺 .php 后缀可由 PHP 解析行为补足时需运行时确认）
- 入口 → 传播 → 危险操作/状态变更：$_GET['page'] → $_GET['page'] → $name → APP_ROOT.'/resources/views/'.$name.'.php' → include → include 执行攻击者控制路径的 PHP 文件
- 防护与边界：无白名单、无 basename、无 ../ 过滤；page() 不强制登录
- 静态判读：缺上下文（2 项）；缺失上下文：resources/views 目录实际文件及 PHP include 对省略 .php 后缀的解析行为未在快照中确认；ops/url-preview.php 的 $url 赋值上游代码未完整读取
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：对 page 参数使用白名单允许的视图名映射，禁止路径穿越字符，并在 include 前用 realpath 校验位于 views 目录内。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/content/page.php:1-3`（sha256 `53c5997117f2d54c…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$name=(string)($_GET['page']??'home');
    3  page('内容中心',function()use($name){include APP_ROOT.'/resources/views/'.$name.'.php';echo '<section class="panel"><a href="?page=home">商城介绍</a> · <a href="?page=shipping">配送与售后</a></section>';},'内容中心');
```

`lab30-shop/app/src/bootstrap.php:59-59`（sha256 `2050819d093be02b…`）

```php
   59      $body();
```

### C-12 ops/report.php 将可写 nickname 直接拼接进 SQL，会员可注入读取其他账户数据

- 当前版本：finding `9eb1485e526f4b14a141ae639791a7f4` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/report.php:3`；文件：`lab30-shop/app/public/ops/report.php`
- 证据引用：`27592a1d1945e010` lab30-shop/app/public/ops/report.php:2-5；`ec18381d7af73d0f` lab30-shop/app/public/account/update.php:4-6；`bd2a787730066498` lab30-shop/app/src/bootstrap.php:4-7
- 根因类别：task_goal:v2:b2a3098d0ec96f2670de:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

report.php:2 用占位符按 id 取出 nickname，report.php:3 将该 nickname 直接拼入 "SELECT username,email,role FROM users WHERE nickname='".$nickname."'" 并执行。nickname 由 account/update.php:4-6 写入，列在白名单内且对任意登录用户开放，值虽以参数化 UPDATE 存储但未过滤引号。攻击者设置 nickname 为带单引号的 payload 后，运营打开报表即触发注入；report.php:4 的 JSON 分支返回 members 数组，report.php:5 的 HTML 表格也逐行回显，故可读取跨行数据。

- 攻击前身份与适用前提：存在任意登录会员并将 nickname 写入恶意值；operator/admin 打开 /ops/report.php?user_id=<该会员>（或带 Accept: application/json）
- 入口 → 传播 → 危险操作/状态变更：account/update.php POST 参数 nickname（普通登录用户可控） → update.php:5 将 nickname 放入 users 表 -> report.php:2 按 user_id 读取 nickname -> report.php:3 字符串拼接进 db()->query 执行 → db()->query 执行拼接了用户数据的 SQL（无占位符、无转义）
- 防护与边界：首次查询使用预处理；但二次查询完全未使用参数绑定，也未使用引号转义或白名单校验，保护缺失。
- 静态判读：缺上下文（1 项）；缺失上下文：未读取 ops/members.php 与 ops/audit-log.php，无法确认其同类越权或注入问题
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.7 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：二次查询改用预处理占位符：$q=db()->prepare('SELECT username,email,role FROM users WHERE nickname=?');$q->execute([$nickname]);

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/report.php:2-5`（sha256 `90d7d60d44815374…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user(['operator','admin']);$id=(int)($_GET['user_id']??1);$q=db()->prepare('SELECT nickname FROM users WHERE id=?');$q->execute([$id]);$nickname=$q->fetchColumn();if($nickname===false)fail_request('会员不存在。',404);
    3  $rows=db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'")->fetchAll();
    4  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['saved_nickname'=>$nickname,'members'=>$rows]);
    5  page('会员运营报表',function()use($id,$rows){echo '<section class="panel"><form method="get">';form_input('user_id','会员编号',(string)$id,'number');echo '<button>生成报表</button></form><table><thead><tr><th>会员名</th><th>邮箱</th><th>角色</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['username']).'</td><td>'.h($r['email']).'</td><td>'.h($r['role']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
```

`lab30-shop/app/public/account/update.php:4-6`（sha256 `b8227f19c05d0cd3…`）

```php
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
```

`lab30-shop/app/src/bootstrap.php:4-7`（sha256 `2050819d093be02b…`）

```php
    4  function db(): PDO {
    5      static $pdo;
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    7      return $pdo;
```

### C-13 account/redeem.php 使用 == 比较 md5 导致弱类型绕过，可任意升级 gold 会员

- 当前版本：finding `deb89fac2a094add98153aee1a2ad3d1` revision 1（项目版本 2）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/redeem.php:5`；文件：`lab30-shop/app/public/account/redeem.php`
- 证据引用：`81e47fc9f94990a6` lab30-shop/app/public/account/redeem.php:3-6；`415907ec6bf2f739` lab30-shop/app/src/bootstrap.php:40-40
- 根因类别：task_goal:v2:75f3e862637a48ea709e:1（规范类型 weak_type_comparison）

**结论陈述（模型产出，不是证据）**

redeem.php:4 以 $secret_hash=md5('240610708') 得到 '0e462097431906509019562988736854'，第5行用 md5($POST['token'])==$secret_hash 松散比较。攻击者提交任意 md5 结果形如 0e+纯数字的字符串（如 'QNKCDZO'、'240610708' 本身）即被 PHP 解释为 0，与 secret 的 0e 数值相等，从而通过校验并将 tier 更新为 gold。

- 攻击前身份与适用前提：普通登录用户会话与 csrf 令牌
- 入口 → 传播 → 危险操作/状态变更：POST 参数 token → redeem.php:4-5 md5(token)=='0e...' 松散比较为真 -> redeem.php:5 UPDATE users SET tier='gold' → UPDATE users SET tier='gold' 提升会员等级
- 防护与边界：仅有 check_csrf()；比较使用 == 而非 hash_equals 或 ===，构成魔术哈希绕过
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 hash_equals($secret_hash, md5($token)) 或 ===，并用强随机兑换码存储哈希校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/redeem.php:3-6`（sha256 `28b3dc4534cca985…`）

```php
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$secret_hash=md5('240610708');
    5      if(md5((string)($_POST['token']??''))==$secret_hash){db()->prepare("UPDATE users SET tier='gold' WHERE id=?")->execute([$u['id']]);event_log('redeem_membership');$notice='兑换成功，已升级金卡会员。';$accepted=true;}
    6      else{$notice='兑换码无效。';http_response_code(422);}
```

`lab30-shop/app/src/bootstrap.php:40-40`（sha256 `2050819d093be02b…`）

```php
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

### C-14 XML 导入启用 LIBXML_NOENT|LIBXML_DTDLOAD，用户 XML 外部实体可读取本地文件

- 当前版本：finding `3ae09753a6774743a5a6c2a6bf509da1` revision 1（项目版本 24）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/xml-import.php:3`；文件：`lab30-shop/app/public/ops/xml-import.php`
- 证据引用：`c7321e7900aae64d` lab30-shop/app/public/ops/xml-import.php:2-4；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:9e71dd2d8814df1d8db5:1（规范类型 xxe）

**结论陈述（模型产出，不是证据）**

xml-import.php:3 在 POST 分支取 $_POST['xml']，调用 simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT&#124;LIBXML_DTDLOAD)。LIBXML_DTDLOAD 允许加载外部 DTD，LIBXML_NOENT 展开实体，随后第 3 行取 $doc->title、第 4 行 h($output) 回显，攻击者可用外部实体把本地文件内容带入 title 输出。仅 check_csrf 保护，无禁用外部实体的配置。

- 攻击前身份与适用前提：持有 operator/admin 会话并取得 CSRF 令牌（页面表单自带）
- 入口 → 传播 → 危险操作/状态变更：$_POST['xml'] → $_POST['xml'] -> simplexml_load_string(LIBXML_NOENT&#124;LIBXML_DTDLOAD) -> $doc->title -> h($output) → simplexml_load_string 解析用户 XML 并展开外部实体
- 防护与边界：check_csrf 防 CSRF，但对实体加载无效；require_user 仅为角色校验
- 静态判读：缺上下文（2 项）；缺失上下文：allow_url_include、open_basedir、allow_url_fopen 等 PHP 运行时配置不在快照内，影响 template-preview 远程包含与 url-preview file:// 的可利用性；应用主机到目标内网/元数据地址的网络可达性未验证
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 LIBXML_NONET 并在解析前禁用外部实体；或改用不加载 DTD/实体的安全解析配置

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

### C-15 合作方结算工作台返回全部订单，无 partner/归属过滤

- 当前版本：finding `7069c8d0ec064593a24ea0146679c88a` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/partner/portal.php:4`；文件：`lab30-shop/app/public/partner/portal.php`
- 证据引用：`684c79964506d05b` lab30-shop/app/public/partner/portal.php:4-6
- 根因类别：task_goal:v2:1ef7fbd446e240cd4c6e:1（规范类型 idor）

**结论陈述（模型产出，不是证据）**

portal.php 第4行 SELECT order_no,total FROM orders ORDER BY id，无 WHERE 关联当前合作方或用户；第5行 JSON 响应与第6行 HTML 表格均输出全部订单号与金额。无 partner 字段或归属过滤，任何通过检查者可读取所有订单。

- 攻击前身份与适用前提：通过 portal.php:3 的令牌检查（可伪造 admin 令牌）
- 入口 → 传播 → 危险操作/状态变更：token 授权后的数据查询 → portal.php:4 查询全部订单 → portal.php:5 json_response 或 portal.php:6 表格遍历输出 → 跨合作方读取全部订单编号与金额
- 防护与边界：无 WHERE partner_id/user_id 条件
- 静态判读：缺上下文（2 项）；缺失上下文：未读取 settings 表结构与 generation 密钥来源，无法确认签名算法实际密钥强度；但伪造路径不依赖该密钥；未读取 orders 表 schema 确认是否存在 partner_id/owner_id 字段，归属过滤缺失依据为查询无条件
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：按当前会话/令牌 sub 解析合作方或用户，查询加 WHERE partner_id=? 或 owner_id=? 限制；不返回全表。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/partner/portal.php:4-6`（sha256 `e1267edb0f9df936…`）

```php
    4  $rows=db()->query('SELECT order_no,total FROM orders ORDER BY id')->fetchAll();
    5  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['role'=>'admin','settlements'=>$rows]);
    6  page('合作方结算工作台',function()use($rows){echo '<section class="panel"><h2>结算摘要</h2><table><thead><tr><th>订单</th><th>金额</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['order_no']).'</td><td>¥'.h($r['total']).'</td></tr>';echo '</tbody></table></section>';});
```

### C-16 reset_shop() 硬编码默认账户口令并以 md5 存储密码

- 当前版本：finding `a4c5f4374437422ea1586e2d00ecd2d7` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/setup.php:17`；文件：`lab30-shop/app/src/setup.php`
- 证据引用：`f86e0ebf4243b153` lab30-shop/app/src/setup.php:7-7；`988f8601a466f0cd` lab30-shop/app/src/setup.php:16-16；`deecf20720274f28` lab30-shop/app/src/setup.php:17-17
- 根因类别：task_goal:v2:060df8a5b655fd0ccda6:1（规范类型 weak_crypto）

**结论陈述（模型产出，不是证据）**

reset_shop() 在初始化时插入 4 个固定用户名/固定口令账户（alice/Alice123!、bob/Bob123!、operator/Ops123!、admin/Admin123!），角色分别为 customer/operator/admin，并将口令经 md5() 后写入 password_md5 CHAR(32) 列。这同时构成公开默认凭据（含管理员）与弱哈希存储：无盐 md5 可被快速离线碰撞，且默认口令可直接用于登录。

- 攻击前身份与适用前提：执行一次 setup/reset 初始化（CLI 或 Web 触发的 reset_shop）
- 入口 → 传播 → 危险操作/状态变更：源码内硬编码的初始化数据（非请求输入） → reset_shop() -> prepare INSERT INTO users -> $q->execute([... md5($u[2]) ...]) → md5($u[2]) 写入 password_md5；固定明文口令 Admin123! 等
- 防护与边界：无盐 md5、无 pwd_hash/password_hash、无首次登录强制改密逻辑（本切片未见）
- 静态判读：缺上下文（3 项）；缺失上下文：app/src/bootstrap.php 内容（是否有全局 CLI 检查、db()/data_dir() 实现）；Web 服务器部署配置：bin 目录是否对外可达；应用登录/认证接口源码，未验证默认凭据的实际利用路径
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 7.3 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 password_hash()/password_verify()；避免硬编码口令，改为部署时随机生成或首次登录强制重置。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/src/setup.php:7-7`（sha256 `53e7dc7286d7d370…`）

```php
    7      $pdo->exec("CREATE TABLE IF NOT EXISTS users(id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(60) UNIQUE NOT NULL, password_md5 CHAR(32) NOT NULL, display_name VARCHAR(100) NOT NULL, email VARCHAR(200) NOT NULL, role VARCHAR(24) NOT NULL DEFAULT 'customer', balance DECIMAL(12,2) NOT NULL DEFAULT 100, tier VARCHAR(30) NOT NULL DEFAULT 'standard', nickname VARCHAR(200) NOT NULL, homepage VARCHAR(500) NOT NULL DEFAULT '#')");
```

`lab30-shop/app/src/setup.php:16-16`（sha256 `53e7dc7286d7d370…`）

```php
   16      $q=$pdo->prepare('INSERT INTO users(id,username,password_md5,display_name,email,role,balance,tier,nickname) VALUES(?,?,?,?,?,?,100,?,?)');
```

`lab30-shop/app/src/setup.php:17-17`（sha256 `53e7dc7286d7d370…`）

```php
   17      foreach ([[1,'alice','Alice123!','林晓','alice@shop.local','customer'],[2,'bob','Bob123!','陈远','bob@shop.local','customer'],[3,'operator','Ops123!','运营同事','ops@shop.local','operator'],[4,'admin','Admin123!','系统管理员','admin@shop.local','admin']] as $u) $q->execute([$u[0],$u[1],md5($u[2]),$u[3],$u[4],$u[5],'standard',$u[1]]);
```

### C-17 ops/users.php 仅凭客户端 role Cookie 判定管理员，任意登录会员可读取全量用户清单

- 当前版本：finding `701625d639a44036b6ad727be8239dc8` revision 1（项目版本 24）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/users.php:2`；文件：`lab30-shop/app/public/ops/users.php`
- 证据引用：`0ad2a840edc3f2e0` lab30-shop/app/public/ops/users.php:1-5；`b07251a036fc163b` lab30-shop/app/src/bootstrap.php:20-37
- 根因类别：task_goal:v2:4c85159cdb9e44e096f9:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

第 2 行使用 $_COOKIE['role'] 优先于服务端查出的 $u['role'] 做管理员判定，攻击者可设置 role=admin 绕过；第 3 行随后全量查询 users 表，第 4 行在 Accept: application/json 时经 json_response 输出 id/username/email/role。保护仅为一个可伪造的请求字段的字符串比较，未使用服务端会话角色。

- 攻击前身份与适用前提：攻击者持有任意有效登录会话（$_SESSION['user_id'] 存在），并设置 Cookie role=admin。
- 入口 → 传播 → 危险操作/状态变更：Cookie: role=admin（同时需任意有效 SHOPSESSID 会话） → $_COOKIE['role'] -> $role -> if($role!=='admin') -> 跳过 403 -> db()->query('SELECT id,username,email,role FROM users') -> json_response 或页面表格 → 管理员权限下全量读取 users 表并通过 json_response/页面泄露
- 防护与边界：仅有 $role!=='admin' 的字符串比较；role 取自客户端 Cookie，无签名/无服务端二次校验；require_user() 返回的 $u['role'] 被 Cookie 覆盖，未用于授权。
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：删除基于 $_COOKIE['role'] 的判定，改用 require_user(['admin']) 或基于 $u['role'] 的服务端校验；不要信任任何客户端角色字段。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/users.php:1-5`（sha256 `3c5e879d945650ba…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$role=(string)($_COOKIE['role']??$u['role']);if($role!=='admin')fail_request('人员管理需要管理员权限。',403);
    3  $rows=db()->query('SELECT id,username,email,role FROM users ORDER BY id')->fetchAll();
    4  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['access'=>'admin','users'=>$rows]);
    5  page('人员与权限管理',function()use($rows){echo '<section class="panel"><span class="badge">管理员工作区</span><h2>账户权限清单</h2><table><thead><tr><th>用户名</th><th>邮箱</th><th>角色</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['username']).'</td><td>'.h($r['email']).'</td><td>'.h($r['role']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:20-37`（sha256 `2050819d093be02b…`）

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
   37  }
```

### C-18 ops/members.php 经 member_lookup 将 GET q 直接拼接进 LIKE 查询导致 SQL 注入

- 当前版本：finding `2df8af0fe4604f49bce69de917fe6c8d` revision 1（项目版本 6）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/member_lookup.php:3`；文件：`lab30-shop/app/public/ops/members.php`
- 证据引用：`8a5062cc6924dcf6` lab30-shop/app/public/ops/members.php:2-3；`a61042430a79910b` lab30-shop/app/src/member_lookup.php:2-4；`8f16736f6656fa52` lab30-shop/app/src/bootstrap.php:6-6
- 根因类别：task_goal:v2:24019bd9e35ff87f1cde:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

members.php 第2行把 $_GET['q'] 原样传入 member_lookup；member_lookup.php 第3行用字符串拼接构造 LIKE '%...%' 并 db()->query() 执行，无绑定与转义，可注入 UNION 或布尔条件。

- 攻击前身份与适用前提：持有 operator 或 admin 会话访问 /ops/members.php?q=<payload>
- 入口 → 传播 → 危险操作/状态变更：GET 参数 q → members.php:2 $_GET['q'] -> member_lookup($term) -> member_lookup.php:3 拼接 -> query() 执行 -> members.php:4 输出 → db()->query("SELECT id,username,email,role FROM users WHERE username LIKE '%".$term."%'")
- 防护与边界：无 prepared statement、无转义；第3行直接 query()
- 静态判读：缺上下文（1 项）；缺失上下文：数据库账户 DB_USER 的权限范围（是否存在 FILE/写入等）未在源码中体现，无法判定超出数据读取的影响
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用预处理并对通配符转义：$q=db()->prepare('SELECT ... WHERE username LIKE ?'); $q->execute(['%'.$term.'%']);

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/members.php:2-3`（sha256 `aef140c3800b9cf1…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/member_lookup.php';require_user(['operator','admin']);$term=(string)($_GET['q']??'alice');$rows=member_lookup($term);
    3  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['members'=>$rows]);
```

`lab30-shop/app/src/member_lookup.php:2-4`（sha256 `eb704332329d4530…`）

```php
    2  function member_lookup(string $term): array {
    3      return db()->query("SELECT id,username,email,role FROM users WHERE username LIKE '%" . $term . "%'")->fetchAll();
    4  }
```

`lab30-shop/app/src/bootstrap.php:6-6`（sha256 `2050819d093be02b…`）

```php
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
```

### C-19 运营主机巡检把 host 参数直接拼接进 shell_exec 的 ping 命令，可注入任意系统命令

- 当前版本：finding `35d82e7c58314b08ac717870d7f66e82` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/host_check.php:2`；文件：`lab30-shop/app/public/ops/batch-check.php`
- 证据引用：`a41ee4811beeaf1b` lab30-shop/app/public/ops/batch-check.php:1-3；`65fc5323ae7c9b98` lab30-shop/app/src/host_check.php:1-2；`b07251a036fc163b` lab30-shop/app/src/bootstrap.php:20-37
- 根因类别：task_goal:v2:47209a4d7a0019e605e8:1（规范类型 command_injection）

**结论陈述（模型产出，不是证据）**

batch-check.php 第 2 行从 $_GET['host'] 取用户输入传入 host_check()；host_check.php 第 2 行以 'ping -c 1 -W 1 ' . $host 字符串拼接后交给 shell_exec，无 escapeshellarg、无字符白名单。结果在 batch-check.php 第 3 行用 h($output) 回显到 <pre>，命令输出可被攻击者读取。持有 operator/admin 会话者可用 ;、&&、$() 执行任意命令。

- 攻击前身份与适用前提：持有 operator 或 admin 角色有效会话
- 入口 → 传播 → 危险操作/状态变更：$_GET['host']（HTTP GET 参数 host） → batch-check.php:2 $_GET['host'] -> host_check($host) -> host_check.php:2 拼接 -> shell_exec -> batch-check.php:3 h($output) 回显 → shell_exec('ping -c 1 -W 1 ' . $host) 未转义参数
- 防护与边界：仅 require_user(['operator','admin']) 登录角色校验；无命令转义与白名单
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：用 escapeshellarg($host) 包裹参数或改用非 shell 实现，并对主机名做正则白名单校验。

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

`lab30-shop/app/src/bootstrap.php:20-37`（sha256 `2050819d093be02b…`）

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
   37  }
```

### C-20 src/member_lookup.php 将 GET 参数拼接进 LIKE 查询导致 SQL 注入

- 当前版本：finding `c9f5a9c5718147259885252586ede80d` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/member_lookup.php:3`；文件：`lab30-shop/app/src/member_lookup.php`
- 证据引用：`4d2f2da581629f05` lab30-shop/app/src/member_lookup.php:1-4；`d9d0420bc26ce2f1` lab30-shop/app/public/ops/members.php:2-4；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:aea04d315ec638476b50:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

member_lookup.php:3 使用 db()->query("SELECT ... WHERE username LIKE '%" . $term . "%'") 直接拼接 $term；ops/members.php:2 从 $_GET['q'] 取值并在 operator/admin 权限下传入，攻击者可通过单引号闭合 LIKE 字符串注入任意 SQL，返回数据经 JSON 或 HTML 输出（含其它用户邮箱、角色）。

- 攻击前身份与适用前提：攻击者持有 operator 或 admin 会话（或通过已报告的硬编码口令获得）
- 入口 → 传播 → 危险操作/状态变更：$_GET['q'] → members.php:2 $term=(string)$_GET['q'] -> member_lookup($term) -> member_lookup.php:3 拼接进 query → PDO::query 执行拼接后的 SQL
- 防护与边界：无参数化、无转义；require_user(['operator','admin']) 仅限制角色，不防注入
- 静态判读：缺上下文（2 项）；缺失上下文：bin 目录下其余脚本（如 bin/*.php 未全部展示）是否含调试输出泄露 DB 凭据/堆栈未完全核实；nginx 配置未在快照中出现（仅有 apache.conf），是否存在其他部署入口未确认
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.3 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 prepare + execute([$term]) 参数化查询

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/src/member_lookup.php:1-4`（sha256 `eb704332329d4530…`）

```php
    1  <?php
    2  function member_lookup(string $term): array {
    3      return db()->query("SELECT id,username,email,role FROM users WHERE username LIKE '%" . $term . "%'")->fetchAll();
    4  }
```

`lab30-shop/app/public/ops/members.php:2-4`（sha256 `aef140c3800b9cf1…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/member_lookup.php';require_user(['operator','admin']);$term=(string)($_GET['q']??'alice');$rows=member_lookup($term);
    3  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['members'=>$rows]);
    4  page('会员查询',function()use($rows,$term){echo '<section class="panel"><form method="get">';form_input('q','会员名',$term);echo '<button>查询会员</button></form><table><thead><tr><th>编号</th><th>用户名</th><th>邮箱</th><th>角色</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['id']).'</td><td>'.h($r['username']).'</td><td>'.h($r['email']).'</td><td>'.h($r['role']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-21 reset_shop() 与 bin/setup.php 全表无 WHERE DELETE 且 CLI 包装缺失 SAPI 检查

- 当前版本：finding `899091520fa44f50ac70a935a1054c38` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/setup.php:15`；文件：`lab30-shop/app/src/setup.php`
- 证据引用：`8414b38edcb46a0e` lab30-shop/app/src/setup.php:15-15；`6cf55daf689a603f` lab30-shop/app/src/setup.php:33-33；`13c50ae02f533745` lab30-shop/app/bin/setup.php:1-4；`770ccd6cdfe6a8af` lab30-shop/app/bin/reset.php:2-2
- 根因类别：task_goal:v2:257c07a50739bef2b4e7:1（规范类型 other）

**结论陈述（模型产出，不是证据）**

reset_shop() 在第 15 行对 withdrawals/messages/jobs/events/orders/products/users/settings 逐一执行 "DELETE FROM $table"，无任何 WHERE 或备份/确认；第 33 行还 unlink 数据目录下所有文件。reset.php 第 2 行以 PHP_SAPI!=='cli' 阻断 Web，但 bin/setup.php 第 1-4 行缺少同等检查，仅在 settings.generation 不存在时调用 reset_shop()。因此若 bin 目录被 Web 暴露且数据库未初始化（或 settings 中 generation 缺失），一次 HTTP 请求即可清空全部业务数据、删除数据文件并以默认弱凭据重建账户。

- 攻击前身份与适用前提：bin 目录经 Web 可访问；settings 表不存在或缺 generation 行；bootstrap.php 未额外限制 SAPI
- 入口 → 传播 → 危险操作/状态变更：HTTP 请求 bin/setup.php（无参数） → bin/setup.php:3 查询 generation 失败 -> $ready=false -> reset_shop() -> exec DELETE FROM 每表 -> 默认数据重建 → 无 WHERE 的 DELETE FROM；递归 unlink($file->getPathname())
- 防护与边界：reset.php 有 PHP_SAPI 检查；bin/setup.php 无；全局守卫是否在 bootstrap.php 存在未知（该文件未读到）
- 静态判读：缺上下文（3 项）；缺失上下文：app/src/bootstrap.php 内容（是否有全局 CLI 检查、db()/data_dir() 实现）；Web 服务器部署配置：bin 目录是否对外可达；应用登录/认证接口源码，未验证默认凭据的实际利用路径
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 7.4 (high) · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：在 bin/setup.php 顶部加入与 reset.php 相同的 PHP_SAPI!=='cli' 检查；重置删除改为按 generation/环境开关控制，禁止 Web 可达。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/src/setup.php:15-15`（sha256 `53e7dc7286d7d370…`）

```php
   15      foreach (['withdrawals','messages','jobs','events','orders','products','users','settings'] as $table) $pdo->exec("DELETE FROM $table");
```

`lab30-shop/app/src/setup.php:33-33`（sha256 `53e7dc7286d7d370…`）

```php
   33      foreach($it as $file) if($file->isFile()) unlink($file->getPathname());
```

`lab30-shop/app/bin/setup.php:1-4`（sha256 `1bbc4984e7432c96…`）

```php
    1  <?php
    2  require __DIR__ . '/../src/setup.php';
    3  try { $ready = db()->query("SELECT value FROM settings WHERE `key`='generation'")->fetchColumn(); } catch (Throwable $e) { $ready=false; }
    4  if (!$ready) { reset_shop(); echo "商城初始数据已建立。\n"; } else echo "使用已有商城数据。\n";
```

`lab30-shop/app/bin/reset.php:2-2`（sha256 `ed6e60a577f6d2d6…`）

```php
    2  if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
```

### C-22 template-render.php 对 {{ }} 内表达式直接 eval，运营模板可远程代码执行

- 当前版本：finding `60748d2dfd18404489f42de90fde3b3f` revision 1（项目版本 22）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-render.php:3`；文件：`lab30-shop/app/public/ops/template-render.php`
- 证据引用：`136d02a92a08ac98` lab30-shop/app/public/ops/template-render.php:1-4；`4eba9252f833f919` lab30-shop/app/src/bootstrap.php:38-40
- 根因类别：task_goal:v2:c1d6b1193d49b9a3fb92:1（规范类型 code_execution）

**结论陈述（模型产出，不是证据）**

第 2 行取 $_POST['template']，第 3 行 preg_replace_callback 匹配双花括号后把捕获组拼进 eval('return '.$m[1].';')。无表达式白名单、无沙箱。攻击者可提交 {{ system('id') }}、反引号或可变函数执行任意 PHP 代码；CSRF 令牌由页面表单下发，自身会话即可取得。

- 攻击前身份与适用前提：持有 operator/admin 会话并携带页面下发的 csrf 值
- 入口 → 传播 → 危险操作/状态变更：$_POST['template']（POST 参数 template） → template-render.php:2 $_POST['template'] -> preg_replace_callback 捕获组 -> eval('return '.$m[1].';') → eval 对用户可控表达式求值
- 防护与边界：仅 require_user(['operator','admin']) 与 check_csrf()；无求值限制
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：移除 eval，改用受限表达式解析或字段/函数白名单；必要时用不执行 PHP 的模板引擎并转义输出。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/template-render.php:1-4`（sha256 `357da9e9959275d8…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$template=(string)($_POST['template']??'');$result='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$result=preg_replace_callback('/\{\{(.*?)\}\}/s',function($m){return (string)eval('return '.$m[1].';');},$template);}
    4  page('营销内容排版',function()use($template,$result){echo '<section class="panel"><p>在双花括号内填写表达式，预览输出内容。</p><form method="post">'.csrf_field().'<label>模板<textarea name="template" required>'.h($template?:'本周精选，共 {{ 2 + 2 }} 款好物').'</textarea></label><button>生成预览</button></form><pre>'.h($result).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:38-40`（sha256 `2050819d093be02b…`）

```php
   38  function csrf_token(): string { start_session(); return $_SESSION['csrf'] ??= bin2hex(random_bytes(24)); }
   39  function csrf_field(): string { return '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'; }
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

### C-23 ops/report.php 将库中 nickname 拼接进 SQL，形成存储型二次注入

- 当前版本：finding `69643b21b36d458f80b3319bce6f31a5` revision 1（项目版本 14）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/report.php:3`；文件：`lab30-shop/app/public/ops/report.php`
- 证据引用：`27592a1d1945e010` lab30-shop/app/public/ops/report.php:2-5；`ec18381d7af73d0f` lab30-shop/app/public/account/update.php:4-6；`8f16736f6656fa52` lab30-shop/app/src/bootstrap.php:6-6
- 根因类别：task_goal:v2:f26209c6a85bf6c1b195:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

第2行用预处理按 user_id 取 nickname，第3行把该 nickname 直接拼进 SELECT ... WHERE nickname='...' 并 db()->query() 执行，既无占位符也无转义。nickname 可由任意登录会员经 account/update.php 写入，运营打开报表即触发注入。

- 攻击前身份与适用前提：存在可写 nickname 的会员账号；operator/admin 打开 /ops/report.php?user_id=<该会员>
- 入口 → 传播 → 危险操作/状态变更：users.nickname（普通会员经 account/update.php 写入），配合 GET user_id 选择目标会员 → account/update.php:5-6 写入 nickname -> report.php:2 预处理按 id 取回 nickname -> report.php:3 字符串拼接 -> db()->query() 执行 → db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'")
- 防护与边界：该查询完全无绑定参数与转义；同文件第2行虽有预处理但不覆盖第3行
- 静态判读：缺上下文（1 项）；缺失上下文：数据库账户 DB_USER 的权限范围（是否存在 FILE/写入等）未在源码中体现，无法判定超出数据读取的影响
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 5.7 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用预处理：$q=db()->prepare('SELECT username,email,role FROM users WHERE nickname=?'); $q->execute([$nickname]);

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/report.php:2-5`（sha256 `90d7d60d44815374…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user(['operator','admin']);$id=(int)($_GET['user_id']??1);$q=db()->prepare('SELECT nickname FROM users WHERE id=?');$q->execute([$id]);$nickname=$q->fetchColumn();if($nickname===false)fail_request('会员不存在。',404);
    3  $rows=db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'")->fetchAll();
    4  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['saved_nickname'=>$nickname,'members'=>$rows]);
    5  page('会员运营报表',function()use($id,$rows){echo '<section class="panel"><form method="get">';form_input('user_id','会员编号',(string)$id,'number');echo '<button>生成报表</button></form><table><thead><tr><th>会员名</th><th>邮箱</th><th>角色</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['username']).'</td><td>'.h($r['email']).'</td><td>'.h($r['role']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
```

`lab30-shop/app/public/account/update.php:4-6`（sha256 `b8227f19c05d0cd3…`）

```php
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
```

`lab30-shop/app/src/bootstrap.php:6-6`（sha256 `2050819d093be02b…`）

```php
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
```

### C-24 运营 URL 预览将用户提供的地址直接交给 file_get_contents，可访问内网与元数据地址

- 当前版本：finding `42ad003752b7411fa5a5dd99f4056277` revision 1（项目版本 22）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/url-preview.php:3`；文件：`lab30-shop/app/public/ops/url-preview.php`
- 证据引用：`17e1cacfb5189678` lab30-shop/app/public/ops/url-preview.php:2-4；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:db511eb0942a58e32e35:1（规范类型 ssrf）

**结论陈述（模型产出，不是证据）**

url-preview.php:2 从 $_GET['url'] 取用户输入，第 3 行以 stream_context_create 仅设置 timeout/follow_location，直接 file_get_contents($url) 抓取并回显（第 3-4 行 h($output) 输出）。没有协议白名单、主机/IP 黑名单或内网地址过滤，file_get_contents 支持 http/ftp/file 等封装器，可访问内部服务（如 fixtures、db、元数据 169.254.169.254）并把响应写回预览面板。

- 攻击前身份与适用前提：持有 operator 或 admin 的有效会话；目标内部服务可从应用主机访问
- 入口 → 传播 → 危险操作/状态变更：$_GET['url'] → $_GET['url'] -> (string) -> file_get_contents($url, false, $context) -> $output -> echo h($output) → file_get_contents 对外部/内网 URL 发起请求并回显完整响应
- 防护与边界：仅 require_user 角色校验；无 URL 协议/主机/IP 校验
- 静态判读：缺上下文（2 项）；缺失上下文：allow_url_include、open_basedir、allow_url_fopen 等 PHP 运行时配置不在快照内，影响 template-preview 远程包含与 url-preview file:// 的可利用性；应用主机到目标内网/元数据地址的网络可达性未验证
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：限定 http/https，解析并校验解析后的 IP 不在内网/回环/链路本地段，禁用重定向跟随，最好通过固定代理抓取

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

### C-25 维护接口仅凭可伪造的 X-Admin 请求头判定授权，且会话缺少该头即可匿名调用

- 当前版本：finding `b313db2a342b43bd92d7c7935472b558` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/maintenance.php:3`；文件：`lab30-shop/app/public/ops/maintenance.php`
- 证据引用：`4e2faa355e456c2e` lab30-shop/app/public/ops/maintenance.php:1-5；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:8d0f5cbbd56852a038a7:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

ops/maintenance.php 第2行仅 require bootstrap.php，未调用 require_user；第3行用 ($_SERVER['HTTP_X_ADMIN'] ?? '') !== '1' 作为唯一授权判断，攻击者自行发送 X-Admin: 1 头即可通过；通过后第4行以 POST 向 jobs 表写入队列任务并返回 job_id，构成未认证的管理操作。

- 攻击前身份与适用前提：无需登录，直接 POST /ops/maintenance.php 并携带 X-Admin: 1
- 入口 → 传播 → 危险操作/状态变更：HTTP 请求头 X-Admin，任意客户端可控制 → HTTP_X_ADMIN -> 与 '1' 比较 -> 直接进入 INSERT INTO jobs 分支 → 未认证写入 jobs 队列任务并返回 job_id
- 防护与边界：仅一个客户端可控请求头比较，无会话身份/角色校验
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改为基于服务端会话的身份校验，例如 require_user(['admin'])，并对内部服务令牌做密钥校验与来源限制。

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

### C-26 运营后台 ping 主机参数未过滤直接进入 shell_exec，可执行任意系统命令

- 当前版本：finding `a1b33b8e515d451d91cd025432414f84` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/ping.php:2`；文件：`lab30-shop/app/public/ops/ping.php`
- 证据引用：`61f200eb89320676` lab30-shop/app/public/ops/ping.php:1-3；`65fc5323ae7c9b98` lab30-shop/app/src/host_check.php:1-2；`a41ee4811beeaf1b` lab30-shop/app/public/ops/batch-check.php:1-3；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:fdc62ad125ecc3e365e3:1（规范类型 command_injection）

**结论陈述（模型产出，不是证据）**

ops/ping.php 第2行把 $_GET['host'] 直接拼进 shell_exec('ping -c 1 -W 1 '.$host)，无 escapeshellarg、无白名单校验；require_user(['operator','admin']) 仅要求 operator 角色。src/host_check.php:2 的 host_check 同样把入参拼接进 shell_exec，并被 ops/batch-check.php:2 以 $_GET['host'] 调用。两处均可用 ; 、&#124; 、$() 等分隔符注入任意命令，命令输出被原样回显到页面 pre 元素。

- 攻击前身份与适用前提：持有 operator 或 admin 角色会话（或通过 users.php 的 Cookie 角色绕过获取管理员视图）
- 入口 → 传播 → 危险操作/状态变更：GET 参数 host（ping.php、batch-check.php） → $_GET['host'] -> (string) -> shell_exec('ping -c 1 -W 1 '.$host) / host_check($host) -> shell_exec 拼接 → shell_exec 无参数转义执行系统命令
- 防护与边界：仅 require_user(['operator','admin']) 角色校验，无输入过滤与转义
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用白名单校验主机名/IP，或用 escapeshellarg 并且不使用 shell 拼接。

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

`lab30-shop/app/public/ops/batch-check.php:1-3`（sha256 `5f76332e7ad1b33a…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/host_check.php';require_user(['operator','admin']);$host=(string)($_GET['host']??'');$output=$host!==''?host_check($host):'';
    3  page('主机巡检',function()use($host,$output){echo '<section class="panel"><form method="get">';form_input('host','巡检主机',$host?:'127.0.0.1');echo '<button>委托巡检</button></form><pre>'.h($output).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-27 catalog 搜索参数 q 直接拼入 SQL 导致注入

- 当前版本：finding `b161374ed56f4cb6babc349d1016b36c` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/catalog/index.php:4`；文件：`lab30-shop/app/public/catalog/index.php`
- 证据引用：`9af2d828eb658d25` lab30-shop/app/public/catalog/index.php:3-4；`85b2e45ff4e8d0eb` lab30-shop/app/src/bootstrap.php:4-8
- 根因类别：task_goal:v2:bca5390d9034f9638dd6:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

catalog/index.php 第3行读取 $_GET['q']，第4行以字符串拼接方式构造 name LIKE '%...%' 并直接 query() 执行；未使用预处理绑定，也无转义。攻击者可闭合引号注入任意 SQL，读取/篡改数据库。

- 攻击前身份与适用前提：无需登录，公开 GET 请求
- 入口 → 传播 → 危险操作/状态变更：$_GET['q'] → $term=(string)$_GET['q'] -> 拼接进 SELECT ... WHERE name LIKE '%$term%' -> db()->query() → PDO::query 执行拼接后的 SQL 字符串
- 防护与边界：无：未使用 prepare/bindParam，也没有任何转义函数
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 9.4 (critical) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 PDO 预处理：prepare('...WHERE name LIKE ?')->execute(['%'.$term.'%'])

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/catalog/index.php:3-4`（sha256 `e85bd1c2fa6a4b78…`）

```php
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

### C-28 合作方门户令牌仅 base64 解码 role 判断，签名不校验导致管理员鉴权绕过

- 当前版本：finding `82cd8f6448204b0994ad0e85c38b8a5e` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/partner/portal.php:3`；文件：`lab30-shop/app/public/partner/portal.php`
- 证据引用：`300ee68a909ae488` lab30-shop/app/public/partner/portal.php:2-3；`ab54a1f06e186428` lab30-shop/app/public/partner/token.php:4-4；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:1dd7c0eb855e7e12d24a:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

portal.php 第2行从 POST token 或 cookie 取客户端令牌并 base64_decode 中段 json_decode；第3行仅检查 payload['role']==='admin'。token.php 第4行显示服务端令牌第三段为 HMAC 签名，但 portal.php 从不校验签名，也不调用 require_user。攻击者提交任意 header.payload.x（payload 含 role=admin）即可通过检查访问合作方工作台。

- 攻击前身份与适用前提：无需登录，仅需发送 POST token
- 入口 → 传播 → 危险操作/状态变更：POST 参数 token 或 Cookie partner_token → portal.php:2 取 token → explode('.') → base64_decode 中段 → json_decode → payload; portal.php:3 仅比较 payload['role']==='admin' → 通过伪造的 admin payload 授权访问合作方结算工作台
- 防护与边界：未执行 HMAC 校验，未比对签名，未使用服务端会话身份
- 静态判读：缺上下文（2 项）；缺失上下文：未读取 settings 表结构与 generation 密钥来源，无法确认签名算法实际密钥强度；但伪造路径不依赖该密钥；未读取 orders 表 schema 确认是否存在 partner_id/owner_id 字段，归属过滤缺失依据为查询无条件
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用服务端签名校验（hash_equals 校验 HMAC，检查 alg、sub 与数据库用户角色），或以服务端会话 require_user(['admin']) 作为授权来源，不接受客户端 base64 payload 的 role 字段。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/partner/portal.php:2-3`（sha256 `e1267edb0f9df936…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$token=(string)($_POST['token']??$_COOKIE['partner_token']??'');$parts=explode('.',$token);$payload=count($parts)===3?json_decode((string)base64_decode(strtr($parts[1],'-_','+/')),true):null;
    3  if(!is_array($payload)||($payload['role']??'')!=='admin')fail_request('此合作方功能仅向管理员开放。',403);
```

`lab30-shop/app/public/partner/token.php:4-4`（sha256 `391948b46efce76c…`）

```php
    4  $header=b64url(json_encode(['alg'=>'HS256','typ'=>'JWT']));$payload=b64url(json_encode(['sub'=>$u['id'],'role'=>$u['role'],'name'=>$u['username']]));$key=db()->query("SELECT value FROM settings WHERE `key`='generation'")->fetchColumn();$token=$header.'.'.$payload.'.'.b64url(hash_hmac('sha256',$header.'.'.$payload,$key,true));
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-29 ops/jobs.php 反序列化 POST 任务数据触发 DispatchJob::__wakeup 执行任意系统命令

- 当前版本：finding `957eee25e92b477991e263cae87eb633` revision 1（项目版本 3）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/jobs.php:3`；文件：`lab30-shop/app/public/ops/jobs.php`
- 证据引用：`906cb4c8c458a208` lab30-shop/app/public/ops/jobs.php:1-5；`4a4dd3de59c1de26` lab30-shop/app/src/dispatch_job.php:1-5；`063c928d2d7c3b2e` lab30-shop/app/src/bootstrap.php:33-40
- 根因类别：task_goal:v2:c3ff309385f1c4062250:1（规范类型 insecure_deserialization）

**结论陈述（模型产出，不是证据）**

ops/jobs.php:3 在 POST 分支中对 base64_decode($_POST['job']) 的结果直接 unserialize，且类型校验 instanceof DispatchJob 在反序列化之后才执行。DispatchJob 的 public $command 属性可被载荷控制，其 __wakeup（dispatch_job.php:4）在对象重建时无条件 echo shell_exec($this->command)。因此具备 operator/admin 会话并取得 CSRF 令牌的攻击者可提交特制 job 参数，在服务端反序列化阶段执行任意系统命令，再通过 ob_start/ob_get_clean 捕获输出并存入 jobs 表、回显于页面。

- 攻击前身份与适用前提：持有 operator 或 admin 角色有效会话；提交时携带有效 csrf 令牌（页面表单自带）
- 入口 → 传播 → 危险操作/状态变更：POST 参数 job（base64 编码的 PHP 序列化数据），页面表单由 jobs.php:5 提供 csrf 字段 → jobs.php:3 base64_decode -> unserialize -> DispatchJob 实例化触发 __wakeup -> dispatch_job.php:4 shell_exec($this->command) → shell_exec 执行攻击者控制的 command 字符串
- 防护与边界：require_user 仅校验 operator/admin 角色；check_csrf 校验令牌；instanceof DispatchJob 在反序列化之后，无法阻止 __wakeup 副作用；未使用 allowed_classes 白名单。
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：禁止对请求数据使用 unserialize；改用 JSON。若必须反序列化，使用 unserialize($raw, ['allowed_classes' => false]) 或严格白名单，并移除 DispatchJob 在 __wakeup/__destruct 中的命令执行逻辑。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/jobs.php:1-5`（sha256 `0f7550fa7f16bd4a…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/dispatch_job.php';$u=require_user(['operator','admin']);$notice='';$output='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$raw=base64_decode((string)($_POST['job']??''),true);if($raw===false)fail_request('任务格式不正确。');ob_start();$job=unserialize($raw);$output=(string)ob_get_clean();if(!$job instanceof DispatchJob)fail_request('不是有效的任务文件。');db()->prepare("INSERT INTO jobs(user_id,title,status,details) VALUES(?,?,'completed',?)")->execute([$u['id'],'导入巡检任务',$output]);$notice='任务已导入并执行。';}
    4  $normal=new DispatchJob();$example=base64_encode(serialize($normal));$rows=db()->query('SELECT id,title,status,details FROM jobs ORDER BY id DESC LIMIT 20')->fetchAll();
    5  page('运营任务中心',function()use($notice,$output,$example,$rows){echo '<section class="panel"><h2>导入任务</h2>';if($notice)echo '<div class="notice">'.h($notice).'</div>';echo '<form method="post">'.csrf_field().'<label>任务数据<textarea name="job" required>'.h($example).'</textarea></label><button>导入并执行</button></form><pre>'.h($output).'</pre></section><section class="panel"><h2>近期任务</h2><table><thead><tr><th>编号</th><th>任务</th><th>状态</th><th>结果</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.(int)$r['id'].'</td><td>'.h($r['title']).'</td><td>'.h($r['status']).'</td><td>'.h($r['details']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
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

### C-30 account/backup.php 客户端可控反序列化恢复写入 tier，可自升级会员

- 当前版本：finding `027a56c883554fbcb550e657cff80957` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/backup.php:5`；文件：`lab30-shop/app/public/account/backup.php`
- 证据引用：`f15ec397a921596f` lab30-shop/app/public/account/backup.php:2-6；`21beb708c8b508dc` lab30-shop/app/src/backup.php:1-5
- 根因类别：task_goal:v2:e5b1875ecf9a300b4769:1（规范类型 insecure_deserialization）

**结论陈述（模型产出，不是证据）**

backup.php 直接 unserialize 用户提交的 base64 数据，仅校验 instanceof MemberBackup，随后把 $restored->tier 与 displayName 写入 users。用户可自行构造 MemberBackup 序列化串把 tier 设为 gold，绕过兑换码升级逻辑。虽然类无魔术方法，仍是不可信反序列化并导致会员等级篡改。

- 攻击前身份与适用前提：普通登录账号，能获取 csrf 令牌
- 入口 → 传播 → 危险操作/状态变更：POST 参数 backup（base64 序列化串） → base64_decode → unserialize → $restored->tier/$restored->displayName → UPDATE users SET tier=?,display_name=? → unserialize 不可信数据并写入敏感列 tier
- 防护与边界：check_csrf 与 instanceof 校验，不限制 tier 取值，也不使用签名/HMAC
- 静态判读：证据已记录
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：不要反序列化客户端数据；改为 JSON 并对 tier 做白名单校验，或对备份加 HMAC 签名。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/backup.php:2-6`（sha256 `017e1703cdf0ff0c…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/backup.php';$u=require_user();$obj=new MemberBackup();$obj->tier=$u['tier'];$obj->displayName=$u['display_name'];$export=base64_encode(serialize($obj));$notice='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$raw=base64_decode((string)($_POST['backup']??''),true);if($raw===false)fail_request('备份格式不正确。');
    5      $restored=unserialize($raw);if(!$restored instanceof MemberBackup)fail_request('不是有效的会员备份。');
    6      db()->prepare('UPDATE users SET tier=?,display_name=? WHERE id=?')->execute([$restored->tier,$restored->displayName,$u['id']]);event_log('restore_member_backup');$notice='会员备份已恢复。';
```

`lab30-shop/app/src/backup.php:1-5`（sha256 `571459cc8b0f6e8e…`）

```php
    1  <?php
    2  class MemberBackup {
    3      public string $tier = 'standard';
    4      public string $displayName = '会员';
    5  }
```

### C-31 ops/jobs.php 反序列化用户数据触发 DispatchJob::__wakeup 中 shell_exec 命令执行

- 当前版本：finding `d2f13744c41c4e8a832c8e6c97f11fbe` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/dispatch_job.php:4`；文件：`lab30-shop/app/src/dispatch_job.php`
- 证据引用：`4a4dd3de59c1de26` lab30-shop/app/src/dispatch_job.php:1-5；`3a1faf58cc93de6f` lab30-shop/app/public/ops/jobs.php:2-5；`415907ec6bf2f739` lab30-shop/app/src/bootstrap.php:40-40
- 根因类别：task_goal:v2:410af732c344f2f25257:1（规范类型 insecure_deserialization）

**结论陈述（模型产出，不是证据）**

ops/jobs.php:3 对 $_POST['job'] 做 base64_decode 后 unserialize，PHP 在返回对象后即触发 DispatchJob::__wakeup()，而 dispatch_job.php:4 的 __wakeup 直接 shell_exec($this->command)。攻击者控制 command 属性即可执行任意系统命令，输出经 ob_start/ob_get_clean 回显并写入 jobs 表。check_csrf 与 instanceof 检查无法阻止（__wakeup 在类型判断前已执行）。

- 攻击前身份与适用前提：攻击者持有 operator/admin 会话及有效 CSRF token（登录页面自带）
- 入口 → 传播 → 危险操作/状态变更：$_POST['job']（base64 序列化的 DispatchJob） → jobs.php:3 base64_decode -> unserialize -> 实例化 DispatchJob -> __wakeup -> shell_exec($this->command) → shell_exec 执行攻击者控制的 command 字符串
- 防护与边界：check_csrf 防跨站但不防本人利用；unserialize 无 allowed_classes 限制；instanceof 检查发生在魔术方法执行之后
- 静态判读：缺上下文（2 项）；缺失上下文：bin 目录下其余脚本（如 bin/*.php 未全部展示）是否含调试输出泄露 DB 凭据/堆栈未完全核实；nginx 配置未在快照中出现（仅有 apache.conf），是否存在其他部署入口未确认
- 动态验证：未验证
- 正式终审：未复核；处置：待终审——当前版本尚未完成独立终审批次；动态复核不替代终审

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 unserialize($raw,['allowed_classes'=>['DispatchJob']]) 并从外部移除 command 可执行入口；或在 __wakeup 中禁止执行 shell

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/src/dispatch_job.php:1-5`（sha256 `e8234b971fe75d85…`）

```php
    1  <?php
    2  class DispatchJob {
    3      public string $command = 'printf inventory-ready';
    4      public function __wakeup(): void { echo (string)shell_exec($this->command); }
    5  }
```

`lab30-shop/app/public/ops/jobs.php:2-5`（sha256 `0f7550fa7f16bd4a…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/dispatch_job.php';$u=require_user(['operator','admin']);$notice='';$output='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$raw=base64_decode((string)($_POST['job']??''),true);if($raw===false)fail_request('任务格式不正确。');ob_start();$job=unserialize($raw);$output=(string)ob_get_clean();if(!$job instanceof DispatchJob)fail_request('不是有效的任务文件。');db()->prepare("INSERT INTO jobs(user_id,title,status,details) VALUES(?,?,'completed',?)")->execute([$u['id'],'导入巡检任务',$output]);$notice='任务已导入并执行。';}
    4  $normal=new DispatchJob();$example=base64_encode(serialize($normal));$rows=db()->query('SELECT id,title,status,details FROM jobs ORDER BY id DESC LIMIT 20')->fetchAll();
    5  page('运营任务中心',function()use($notice,$output,$example,$rows){echo '<section class="panel"><h2>导入任务</h2>';if($notice)echo '<div class="notice">'.h($notice).'</div>';echo '<form method="post">'.csrf_field().'<label>任务数据<textarea name="job" required>'.h($example).'</textarea></label><button>导入并执行</button></form><pre>'.h($output).'</pre></section><section class="panel"><h2>近期任务</h2><table><thead><tr><th>编号</th><th>任务</th><th>状态</th><th>结果</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.(int)$r['id'].'</td><td>'.h($r['title']).'</td><td>'.h($r['status']).'</td><td>'.h($r['details']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:40-40`（sha256 `2050819d093be02b…`）

```php
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

## 5. 实际验证和终审理由

本次运行没有动态验证或正式复核记录；相关结论均标注为未验证/未复核。

## 6. 覆盖与未决项

| 独立分母 | 总数 | 已结算 | 未决/待办 | 闭环 |
|---|---:|---:|---:|---|
| 文件覆盖 | 61 | 读取 60；读取+跳过 61 | 0 | 是 |
| 必做方向 | 6 | 已决 3；跳过 0 | 3 | 否 |
| 动态验证 | 31 | 已验证 0；已复核记录 0 | 待验证 31；待复核 0 | — |
| 正式终审 | 31 | 已接受 0 | 待终审 31；存疑 0 | — |

**带理由跳过的文件**

- `lab30-shop/app/public/assets/products.svg`：静态 SVG 图标资源，不含服务端代码或脚本执行逻辑，PHP 审计范围内无外部输入参与，跳过
- `lab30-shop/app/public/content/page.php`：本轮已由 file-sink-sweep 任务纳入 source_refs 显式读取，不单独跳过

**后续建议（不阻止本次收束）**

- `dir_01205b9c86fb85c0ad23377de9698606`：审查 wallet/withdraw.php 余额扣减的并发与余额校验
- `dir_370515d5aee608e36aeb428ecbac9a4d`：审查 lab30-shop/app/src/member_lookup.php 的 LIKE 拼接在 ops/members.php 中的可达性与权限
- `dir_38f158ce095d30169b2dd65f7bcd4db8`：审查 lab30-shop/app/public/account/update.php 的可写列列表（role/balance/tier）是否构成 mass_assignment
- `dir_5022eb77385dd6844181a7c2f53e6788`：审查 lab30-shop/app/public/ops/database.php probe 参数导致的 PDO 连接错误信息与堆栈回显
- `dir_31a229dc88cc9b5b3ed4962e28e76f43`：lab30-shop/app/public/auth/continue.php:3 未校验 $_GET['next'] 的开放重定向
- `dir_46621649f03745b54b0d2930faf5d261`：lab30-shop/app/public/auth/login.php:3,8 接受 $_GET['sid'] 且未 session_regenerate_id，导致会话固定
- `dir_97283146fe59d8f8cd2d273834b679bc`：lab30-shop/app/public/account/redeem.php:4-5 弱类型 == 与固定 md5('240610708')，可用 '0e...' 等魔术哈希绕过兑换码
- `dir_9af07ea10594710efd43400d67c96ac7`：lab30-shop/app/public/account/profile.php:2-3 $_GET['url'] 直接输出到 href，存在反射型 XSS/钓鱼跳转
- `dir_dac62e03ced0e3534648e0e26e90e2f1`：lab30-shop/app/public/wallet/withdraw.php:3-8 会话关闭后读余额、sleep 再写回，无事务/行锁，存在并发竞态超额提现
- `dir_057de973ad778b93a119f30f83423c91`：审查 lab30-shop/app/public/ops/members.php 的角色判定与数据返回边界（未读取）
- `dir_07dfe0dc6cbd4be393be8fc6a97bbbca`：审查 lab30-shop/app/public/ops/audit-log.php 的访问控制与日志字段回显（未读取）
- `dir_f5ebffcd57e079a0c71ee5652e488a46`：lab30-shop/app/public/ops/template-preview.php:3 与 url-preview.php:3 的外部 URL 访问/包含
- `dir_f0c1c952c37f29cd42473639e01b5aaa`：account/redeem.php:4-5 硬编码 md5 兑换码可在多次请求中反复兑换升级 tier，且 md5 弱比较；评估是否构成独立弱加密/逻辑缺陷（与已落库 mass_assignment 不同根因）。
- `dir_3169ce2fd4dd50fd66613a20cdf1e125`：确认 lab30-shop/app/public/ops/url-preview.php:3 的 file_get_contents($url) 是否可被用于读取 file:// 等本地协议（SSRF/任意文件读取），需读取 $url 来源及 bootstrap 保护
- `dir_e778172cdf58ddf868493c0e01967932`：核对 src/setup.php 其余行及 bin/setup.php 是否存在 request 数据流入 file_put_contents/unlink 的其它路径
- `dir_825df8d0255167c1df9bda8b060c8173`：lab30-shop/app/public/ops/template-preview.php:3 include $_GET['template'] 的 LFI/RFI 需单独 finding 与 POC
- `dir_86343ed5cf8c2b8b5a0d1a67f46ddc3f`：lab30-shop/app/public/ops/template-render.php:3 eval('return '.$m[1].';') 的代码执行需单独 finding 与 POC
- `dir_a7e860b5823fb552b0aa1746d81b6bf9`：lab30-shop/app/public/ops/formula.php:3 $func(...) 可变函数调用（潜在任意函数/命令执行）需单独 finding
- `dir_d7956c43109a870d3dc7e76225fa9561`：读取 bin/ 下剩余脚本确认是否有调试输出或凭据泄露
- `dir_f53ba472ae6305678094dac41eb1a607`：检查是否存在 .htaccess 或 Web 根目录映射排除 bin/ 部署配置（快照内未见）
- `dir_c631eb36915cfb294ebd03aa80af3cbe`：catalog/orders、wallet、content 及 src/setup.php、src/dispatch_job.php 的文件读写 sink 未审查
- `dir_d8b01d64e140b496d909ec50fb95eddd`：ops/report.php:3 昵称二次拼接 SQL 注入需独立验证并报告
- `dir_f6f2f545db230d25b9128dfbc03a83e2`：account/update.php:4-6 允许写 role/balance/tier 的 mass assignment 未审查
- `dir_600131dd61d17c1c8c4f7de30cd57aa4`：核对 account/update.php 中 nickname 之外的写入接口（如注册、其他资料页）是否也能控制 nickname，确认注入前置的唯一来源
- `dir_01fb1345b095f445995602de94f0f3ce`：lab30-shop/app/public/content/page.php:2-3 page 参数无白名单拼接 include，需评估 LFI/RFI 与路径穿越
- `dir_2d72a8bcbf96a677d1077653d8929531`：核对 lab30-shop/app/public/ops/jobs.php 中 $output 写入 jobs 表的 details 是否存在任务字段覆盖/伪造状态（title/status 固定为值，影响有限），仅在需要另立不同根因时推进。

**补证与未决动作**

- `034092c16b35416089a03e85c241ab0c` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（登录会话未重新生成 ID 且允许 GET 指定 sid 导致会话固定）
- `17c7e80426a441239fadb36161fdcd3e` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（account/update.php 批量赋值可修改 role/balance/tier 敏感字段）
- `2630675155c846f0bb5c771288849e29` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（account/update.php 批量赋值允许普通用户把 role 改为 admin、任意改写 balance）
- `35cb594a16274ac79907a659717056d0` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（在线留言 message 入库后未转义输出导致存储型 XSS）
- `3d7bcd8666c149e884a6533f109c96f2` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（greeting.php 未转义 GET name 输出的反射型 XSS）
- `432ad46cc5e446eb8aef2e12d31be658` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（support/download.php file 参数路径遍历导致任意文件读取）
- `494423ddc5fb4859bd074dca9235a8c5` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（wallet/withdraw.php 提现余额读-改-写无事务，usleep 放大并发窗口可重复提现）
- `4e35ce72f856430faf590095346c382a` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（orders/detail.php 仅按 id 读取订单，无归属校验导致可越权查看他人订单（含私密备注））
- `5a1f8b8736b246b9ae6d081c49f50198` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（订单创建采信客户端 price 计算总价（单价操纵））
- `5c3db49dc8ce4eeab05208bd9757d432` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（auth/continue.php 未校验 next 参数导致开放重定向）
- `5f8a819f26e14990a4204f0220c29672` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（content/page.php page 参数路径遍历导致本地文件包含）
- `64ffe33daa2b452c8853e0e6c95f9113` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/report.php 将可写 nickname 直接拼接进 SQL，会员可注入读取其他账户数据）
- `73deab1848874e1c8c81797a62eabbb5` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（account/redeem.php 使用 == 比较 md5 导致弱类型绕过，可任意升级 gold 会员）
- `7905401b64084de6956b3ecd7b67e0a9` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（XML 导入启用 LIBXML_NOENT&#124;LIBXML_DTDLOAD，用户 XML 外部实体可读取本地文件）
- `86936b0c6e3241559892558fc7f698c6` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（合作方结算工作台返回全部订单，无 partner/归属过滤）
- `86e1df9dc2c64034a4d933e4f5ad95c7` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（reset_shop() 硬编码默认账户口令并以 md5 存储密码）
- `9a66a667a5f046388568cfa10ff63cfe` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/users.php 仅凭客户端 role Cookie 判定管理员，任意登录会员可读取全量用户清单）
- `a61dde40538748f4829bb7ba5bb0d43c` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/members.php 经 member_lookup 将 GET q 直接拼接进 LIKE 查询导致 SQL 注入）
- `aa38495451ce46c386f5dee352b74d28` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（运营主机巡检把 host 参数直接拼接进 shell_exec 的 ping 命令，可注入任意系统命令）
- `ae1ddb6b223d4f27a7f419f19b5f474a` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（src/member_lookup.php 将 GET 参数拼接进 LIKE 查询导致 SQL 注入）
- `bd18783a63c5491a99608930ee5a9da1` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（reset_shop() 与 bin/setup.php 全表无 WHERE DELETE 且 CLI 包装缺失 SAPI 检查）
- `bfd1580e14754964a21945d15907d435` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（template-render.php 对 {{ }} 内表达式直接 eval，运营模板可远程代码执行）
- `c69fbc2e3f51448ba5c70f09c96bcb39` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/report.php 将库中 nickname 拼接进 SQL，形成存储型二次注入）
- `c75a2af277c24086a450dc46dad72708` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（运营 URL 预览将用户提供的地址直接交给 file_get_contents，可访问内网与元数据地址）
- `c7932f1c750e43f3b01b243fb3125188` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（维护接口仅凭可伪造的 X-Admin 请求头判定授权，且会话缺少该头即可匿名调用）
- `c8f9ed1e88e34aabbb130fb80d317aa4` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（运营后台 ping 主机参数未过滤直接进入 shell_exec，可执行任意系统命令）
- `d3a702c9bfe7496dafabc39bc6fbf306` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（catalog 搜索参数 q 直接拼入 SQL 导致注入）
- `df5b8e300b2346549580061f242d0327` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（合作方门户令牌仅 base64 解码 role 判断，签名不校验导致管理员鉴权绕过）
- `e0cdcefb074e4272a89b5409b00aeec2` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/jobs.php 反序列化 POST 任务数据触发 DispatchJob::__wakeup 执行任意系统命令）
- `e8398527a55a4915b179573f4ddfe0a0` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（account/backup.php 客户端可控反序列化恢复写入 tier，可自升级会员）
- `f17cc7445c19486c94a1d51d95c15061` 完成动态验证，或明确标注为仅静态支持并说明缺失的运行条件。（ops/jobs.php 反序列化用户数据触发 DispatchJob::__wakeup 中 shell_exec 命令执行）
- 3 项：逐个结算未决方向：读取、给出证据或明确 skip 理由。

**限制**

- 受阻、未执行、未读取的方向均不代表安全。
- 本次运行未同时满足完成状态、覆盖闭环与验证闭环，本报告为阶段报告。
- 仍有 31 条规范结论未获得正式确认，不计入已接受漏洞。
- 3 个审计方向尚未结算。

## 7. 附录与证据索引

**历史版本与来源记录**

| 规范结论 | finding | revision | 处置 | 验证 | 当前 |
|---|---|---:|---|---|---|
| `9a66a667a5f046388568cfa10ff63cfe` | `e25b7a0a48804e80a5002441c1f3e0bc` | 1 | open | unverified | 否 |
| `9a66a667a5f046388568cfa10ff63cfe` | `701625d639a44036b6ad727be8239dc8` | 1 | open | unverified | 是 |

**撤回、重复或替代记录**

- `4340c6d1899e4f79a95748754ce8d7d3`（revision 1）：duplicate——商品目录搜索 q 参数直接拼接进 SQL 查询
- `77c555ad2aa0461d91bfec8d43329ebb`（revision 1）：duplicate——运营报表昵称二次查询直接拼接 SQL（存储型正则注入）
- `84c1d472b82c4c5eb7ef97b266a8327b`（revision 1）：duplicate——support/download.php 的 file 参数路径遍历导致任意文件读取
- `f378ca5767cb48778a940629ce0f415e`（revision 1）：duplicate——account/update.php 字段白名单含 role/balance/tier，普通用户可批量赋值自升权限与篡改余额

**关联链路对照（位置或引用关联不代表重复）**

- `17c7e80426a441239fadb36161fdcd3e` ↔ `2630675155c846f0bb5c771288849e29`：仍需对照判读；尚未明确判读是否具有不同根因。
- `64ffe33daa2b452c8853e0e6c95f9113` ↔ `c69fbc2e3f51448ba5c70f09c96bcb39`：仍需对照判读；尚未明确判读是否具有不同根因。
- `a61dde40538748f4829bb7ba5bb0d43c` ↔ `ae1ddb6b223d4f27a7f419f19b5f474a`：仍需对照判读；尚未明确判读是否具有不同根因。
- `aa38495451ce46c386f5dee352b74d28` ↔ `c8f9ed1e88e34aabbb130fb80d317aa4`：仍需对照判读；尚未明确判读是否具有不同根因。
- `e0cdcefb074e4272a89b5409b00aeec2` ↔ `f17cc7445c19486c94a1d51d95c15061`：仍需对照判读；尚未明确判读是否具有不同根因。

**任务记录**

| 任务 | 标题 | 状态 | 错误 |
|---|---|---|---|
| `d3eef95532a04a128843d4ca239fd981` | 引导文件与数据库访问层：SQL 拼接与全局安全边界 | completed | — |
| `b712ba436dc540fd92f14e68079e6093` | 账户模块：登录会话、IDOR、重置码与钱包业务逻辑 | completed | — |
| `e6339746fa9146fa9dc78848bae70e27` | 商品目录与订单：SQL 注入、存储/反射 XSS 与客户端单价信任 | completed | — |
| `f6d7a48e31b94860ab5d3eb404c1008e` | 登录注册与会话边界：弱哈希、会话固定、开放重定向与客户端角色 | completed | — |
| `0b022c9bced24f3cb761b0788003b432` | 运营后台报表二次注入与基于 Cookie 角色的越权 | completed | — |
| `9b9dae9d414446e9b6e86764e381e2f2` | 客服与运维后台：鉴权绕过、命令执行与管理操作越权 | completed | — |
| `a237d0800648496ba4aa0c72b1fce5c9` | 钱包与兑换：业务逻辑、竞态与越权 | completed | — |
| `93909d0e955e4cbfb87162b60c6406dd` | 其余入口的文件读写 sink 与可控路径 | completed | — |
| `43134e6a52fb4e72a92e0c0a28911ed2` | shipping.php 与打包/夹具脚本的输入处理与敏感操作 | completed | — |
| `96ce9df8355b47bebb1e42e40cd0000d` | 合作方门户与令牌接口：鉴权绕过与 IDOR | completed | — |
| `731d0d92191d45cf8827cb2c86b7d8a2` | 备份与文件操作：路径遍历、任意文件读取与包含 | completed | — |
| `893f86eaff0045439b96aea5aacf00b6` | 运维侧预览与渲染接口：SSRF、模板注入与 XXE | completed | — |
| `a5e9c67a53564eac801e4bfd90c212dc` | account 接口批量赋值与会话/认证边界 | completed | — |
| `db6e9cf74cfd4446a813300b0aa5f34f` | ops 后台信任 Cookie role 的越权与角色边界 | completed | — |
| `91199cb8834c4772b03ea9cb4ec8529f` | 剩余 src 公共文件与部署配置：CLI 边界、分享数据库配置与文件写入 | completed | — |
| `0c2bfe9c6640482f81234db867eaa918` | 运营端高危 sink 复核：SSRF、XXE、模板求值、命令执行 | completed | — |
| `25bd4697260d4a568895d4c7cd380597` | CLI 初始化与重置脚本：默认凭据、弱哈希与危险删除 | completed | — |
| `23f67c22271c43b3bdbde2b954514716` | 客服消息与目录问候：存储型/反射型 XSS 与 SQL 拼接 | completed | — |
| `ccc00bc1ec4943cbac59fb62fb052fe3` | bin 目录其余脚本的 SAPI 检查与调试输出 | completed | — |
| `a9fe84978b1b4b40b39e443875056a64` | ops/report.php 与 member_lookup 的二次拼接 SQL 注入 | completed | — |
| `92e0b2e689bd459398fec7156b2949df` | 未覆盖视图与前端资源：home.php 输出转义与 app.js 数据注入 | completed | — |
| `716426da04e446248bc44c8145a8a2fd` | ops/jobs.php 反序列化对象注入到 dispatch_job 的命令执行链 | completed | — |
| `d4fe6a4d2564447f8ef579637ebbd155` | 认证、会话与 CSRF 边界：登录/继续/注册及状态变更接口 | completed | — |

- 用量：上限 响应 2048；工具 16384；秒 10800；实际 响应 109；工具 191；秒 1050.513；剩余 响应 1939；工具 16193；秒 9749.487000000001

**证据索引（服务器读取）**

| evidence_id | 路径 | 范围 | 文件哈希 | 可用 |
|---|---|---|---|---|
| `dbf3c25dae0af619` | lab30-shop/app/src/bootstrap.php | 11-18 | `2050819d093be02b` | 是 |
| `144e48ac712e16dc` | lab30-shop/app/public/auth/login.php | 3-8 | `b9be43ddb2233156` | 是 |
| `fadde1b1e1006c27` | lab30-shop/app/public/account/update.php | 3-7 | `b8227f19c05d0cd3` | 是 |
| `6220461f4c36cb1a` | lab30-shop/app/src/bootstrap.php | 33-36 | `2050819d093be02b` | 是 |
| `aecff877ea34a4a4` | lab30-shop/app/public/account/update.php | 1-9 | `b8227f19c05d0cd3` | 是 |
| `78224482780bf94a` | lab30-shop/app/src/bootstrap.php | 33-37 | `2050819d093be02b` | 是 |
| `4287a6e3dca83484` | lab30-shop/app/public/support/messages.php | 3-5 | `a6866f07b4de32f3` | 是 |
| `5220b9ce518719f6` | lab30-shop/app/src/bootstrap.php | 10-10 | `2050819d093be02b` | 是 |
| `c57a3bf6bb6b01db` | lab30-shop/app/public/catalog/greeting.php | 2-3 | `8e6db315fdfc32cf` | 是 |
| `1b8b2b99a1a47fee` | lab30-shop/app/src/bootstrap.php | 46-46 | `2050819d093be02b` | 是 |
| `8bf814169e217985` | lab30-shop/app/public/support/download.php | 1-4 | `71f0558eeb4ebb6c` | 是 |
| `f5faf41dff9a5a91` | lab30-shop/app/src/bootstrap.php | 9-9 | `2050819d093be02b` | 是 |
| `35aab41df419ddcc` | lab30-shop/app/src/bootstrap.php | 33-35 | `2050819d093be02b` | 是 |
| `713c1c83b1f33981` | lab30-shop/app/public/wallet/withdraw.php | 2-11 | `e3e73271e379b085` | 是 |
| `bd7555c5a11365fe` | lab30-shop/app/public/wallet/withdraw.php | 4-8 | `e3e73271e379b085` | 是 |
| `171ea369e07c383b` | lab30-shop/app/public/orders/detail.php | 1-4 | `be69aa78cecffcfd` | 是 |
| `e4ba0faa7c0831b2` | lab30-shop/app/public/orders/create.php | 3-7 | `41e73625d7e04c58` | 是 |
| `dc0b10bf76499d4d` | lab30-shop/app/public/catalog/detail.php | 3-3 | `daccd22134a2224d` | 是 |
| `3d07985381125c49` | lab30-shop/app/public/auth/continue.php | 1-4 | `50fde4a15e52af44` | 是 |
| `173f24f6297d9164` | lab30-shop/app/public/content/page.php | 1-3 | `53c5997117f2d54c` | 是 |
| `d4a92906b50eb717` | lab30-shop/app/src/bootstrap.php | 59-59 | `2050819d093be02b` | 是 |
| `27592a1d1945e010` | lab30-shop/app/public/ops/report.php | 2-5 | `90d7d60d44815374` | 是 |
| `ec18381d7af73d0f` | lab30-shop/app/public/account/update.php | 4-6 | `b8227f19c05d0cd3` | 是 |
| `bd2a787730066498` | lab30-shop/app/src/bootstrap.php | 4-7 | `2050819d093be02b` | 是 |
| `81e47fc9f94990a6` | lab30-shop/app/public/account/redeem.php | 3-6 | `28b3dc4534cca985` | 是 |
| `415907ec6bf2f739` | lab30-shop/app/src/bootstrap.php | 40-40 | `2050819d093be02b` | 是 |
| `c7321e7900aae64d` | lab30-shop/app/public/ops/xml-import.php | 2-4 | `3c23a76b1047f734` | 是 |
| `684c79964506d05b` | lab30-shop/app/public/partner/portal.php | 4-6 | `e1267edb0f9df936` | 是 |
| `f86e0ebf4243b153` | lab30-shop/app/src/setup.php | 7-7 | `53e7dc7286d7d370` | 是 |
| `988f8601a466f0cd` | lab30-shop/app/src/setup.php | 16-16 | `53e7dc7286d7d370` | 是 |
| `deecf20720274f28` | lab30-shop/app/src/setup.php | 17-17 | `53e7dc7286d7d370` | 是 |
| `0ad2a840edc3f2e0` | lab30-shop/app/public/ops/users.php | 1-5 | `3c5e879d945650ba` | 是 |
| `b07251a036fc163b` | lab30-shop/app/src/bootstrap.php | 20-37 | `2050819d093be02b` | 是 |
| `8a5062cc6924dcf6` | lab30-shop/app/public/ops/members.php | 2-3 | `aef140c3800b9cf1` | 是 |
| `a61042430a79910b` | lab30-shop/app/src/member_lookup.php | 2-4 | `eb704332329d4530` | 是 |
| `8f16736f6656fa52` | lab30-shop/app/src/bootstrap.php | 6-6 | `2050819d093be02b` | 是 |
| `a41ee4811beeaf1b` | lab30-shop/app/public/ops/batch-check.php | 1-3 | `5f76332e7ad1b33a` | 是 |
| `65fc5323ae7c9b98` | lab30-shop/app/src/host_check.php | 1-2 | `c3a868155c2d335e` | 是 |
| `4d2f2da581629f05` | lab30-shop/app/src/member_lookup.php | 1-4 | `eb704332329d4530` | 是 |
| `d9d0420bc26ce2f1` | lab30-shop/app/public/ops/members.php | 2-4 | `aef140c3800b9cf1` | 是 |
| `8414b38edcb46a0e` | lab30-shop/app/src/setup.php | 15-15 | `53e7dc7286d7d370` | 是 |
| `6cf55daf689a603f` | lab30-shop/app/src/setup.php | 33-33 | `53e7dc7286d7d370` | 是 |
| `13c50ae02f533745` | lab30-shop/app/bin/setup.php | 1-4 | `1bbc4984e7432c96` | 是 |
| `770ccd6cdfe6a8af` | lab30-shop/app/bin/reset.php | 2-2 | `ed6e60a577f6d2d6` | 是 |
| `136d02a92a08ac98` | lab30-shop/app/public/ops/template-render.php | 1-4 | `357da9e9959275d8` | 是 |
| `4eba9252f833f919` | lab30-shop/app/src/bootstrap.php | 38-40 | `2050819d093be02b` | 是 |
| `17e1cacfb5189678` | lab30-shop/app/public/ops/url-preview.php | 2-4 | `e495938b10c455c6` | 是 |
| `4e2faa355e456c2e` | lab30-shop/app/public/ops/maintenance.php | 1-5 | `b96aecd7df7c5fa4` | 是 |
| `61f200eb89320676` | lab30-shop/app/public/ops/ping.php | 1-3 | `c15517950afe0794` | 是 |
| `9af2d828eb658d25` | lab30-shop/app/public/catalog/index.php | 3-4 | `e85bd1c2fa6a4b78` | 是 |
| `85b2e45ff4e8d0eb` | lab30-shop/app/src/bootstrap.php | 4-8 | `2050819d093be02b` | 是 |
| `300ee68a909ae488` | lab30-shop/app/public/partner/portal.php | 2-3 | `e1267edb0f9df936` | 是 |
| `ab54a1f06e186428` | lab30-shop/app/public/partner/token.php | 4-4 | `391948b46efce76c` | 是 |
| `906cb4c8c458a208` | lab30-shop/app/public/ops/jobs.php | 1-5 | `0f7550fa7f16bd4a` | 是 |
| `4a4dd3de59c1de26` | lab30-shop/app/src/dispatch_job.php | 1-5 | `e8234b971fe75d85` | 是 |
| `063c928d2d7c3b2e` | lab30-shop/app/src/bootstrap.php | 33-40 | `2050819d093be02b` | 是 |
| `f15ec397a921596f` | lab30-shop/app/public/account/backup.php | 2-6 | `017e1703cdf0ff0c` | 是 |
| `21beb708c8b508dc` | lab30-shop/app/src/backup.php | 1-5 | `571459cc8b0f6e8e` | 是 |
| `3a1faf58cc93de6f` | lab30-shop/app/public/ops/jobs.php | 2-5 | `0f7550fa7f16bd4a` | 是 |

**附件与机器可读清单**

- Markdown：本报告（由事实包确定性生成）。
- JSON：result.json（含本事实包与质量结果）
- 证据包：evidence/（POC 脚本、runner 产物、runner manifest）
- 源码：源码片段由宿主从冻结快照读取，见 source_evidence
- 事实包 ID：`14129816449d9af6170ad08190d88cb178d710edd2c48f6d6e3f837913ca8fcd`；页面、Markdown、JSON 与证据包共用同一份事实。
