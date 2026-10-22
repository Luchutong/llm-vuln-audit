# Lab30 源码位置清单

位置相对于源码包中的 `lab30-shop/` 根目录。危害程度依据代码与业务影响评定，未进行漏洞验证。

| 编号 | 源码位置 | 漏洞类型 | 危害程度 |
| --- | --- | --- | --- |
| 01 | `app/public/catalog/index.php:4` | SQL 注入 | 高 |
| 02 | `app/public/catalog/greeting.php:3` | 反射型 XSS | 中 |
| 03 | `app/public/ops/ping.php:2` | 命令注入 | 极高 |
| 04 | `app/public/support/download.php:3` | 路径遍历与文件读取 | 高 |
| 05 | `app/public/content/page.php:3` | 本地文件包含 | 高 |
| 06 | `app/public/ops/template-preview.php:3` | 远程文件包含 | 极高 |
| 07 | `app/public/ops/formula.php:3` | 动态函数调用导致代码执行 | 极高 |
| 08 | `app/public/auth/continue.php:3` | 开放重定向 | 中 |
| 09 | `app/public/ops/database.php:3` | 异常及堆栈信息泄露 | 中 |
| 10 | `app/public/auth/register.php:8`<br>`app/src/setup.php:17` | 使用 MD5 存储密码 | 中 |
| 11 | `app/public/support/messages.php:5` | 存储型 XSS | 高 |
| 12 | `app/public/ops/url-preview.php:3` | 服务端请求伪造（SSRF） | 高 |
| 13 | `app/public/ops/xml-import.php:3` | XML 外部实体（XXE） | 高 |
| 14 | `app/public/account/settings.php:5` | 跨站请求伪造（CSRF） | 中 |
| 15 | `app/public/account/backup.php:5` | 不安全反序列化导致会员权益篡改 | 中 |
| 16 | `app/public/orders/detail.php:2` | 订单对象越权访问（IDOR） | 高 |
| 17 | `app/public/ops/users.php:2` | 信任客户端角色 Cookie 导致权限绕过 | 高 |
| 18 | `app/public/ops/maintenance.php:3` | 信任请求头导致认证绕过 | 高 |
| 19 | `app/public/orders/create.php:3`<br>`app/public/orders/create.php:5` | 信任客户端单价导致订单金额篡改 | 高 |
| 20 | `app/public/wallet/withdraw.php:3`<br>`app/public/wallet/withdraw.php:7` | 提现竞争条件与重复支付 | 高 |
| 21 | `app/src/bootstrap.php:13`<br>`app/public/auth/login.php:8` | 会话固定 | 高 |
| 22 | `app/public/account/redeem.php:5` | 弱类型比较导致兑换码绕过 | 中 |
| 23 | `app/public/ops/members.php:2`<br>`app/src/member_lookup.php:3` | 跨文件 SQL 注入 | 高 |
| 24 | `app/public/ops/batch-check.php:2`<br>`app/src/host_check.php:2` | 跨文件命令注入 | 极高 |
| 25 | `app/public/account/profile.php:3` | HTML 属性注入型 XSS | 中 |
| 26 | `app/public/partner/portal.php:2` | JWT 未校验签名导致身份伪造 | 高 |
| 27 | `app/public/ops/jobs.php:3`<br>`app/src/dispatch_job.php:4` | 反序列化对象链导致命令执行 | 极高 |
| 28 | `app/public/account/update.php:6`<br>`app/public/ops/report.php:3` | 二次 SQL 注入 | 高 |
| 29 | `app/public/ops/template-render.php:3` | 模板表达式执行（原 /e 场景的 PHP 8.4 等价实现） | 极高 |
| 30 | `app/public/account/update.php:4`<br>`app/public/account/update.php:6` | 批量赋值导致敏感字段修改 | 高 |
