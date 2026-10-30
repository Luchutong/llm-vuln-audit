# 源码审计阶段报告（a93ba654）

> 报告类型：阶段报告；发布状态：可发布（阶段报告）
> 事实包 final-review/v1 · 渲染器 final-report/v2 · 策略 audit-runtime-3
> 运行 `a93ba654480d4520a805959e28cf4332` · 快照 `586b79b41f8e4f59be80f2a9b548902b` · 源码哈希 `67fd87e9ae771d10…` · 输入哈希 `d040c84e1fe5f409c09692d4a1acd6da1a63a10e6598827fadec70f5ac6cae29`
> 本报告由宿主从冻结事实包确定性生成；数量、位置、验证状态与评分均不由模型填写。

## 1. 执行与终审摘要

- 运行：`a93ba654480d4520a805959e28cf4332`；状态：inconclusive；停止原因：audit_partial；审计与终审已结束，未完成的源码方向及运行限制保留在阶段报告中。
- 审计完整性：未完成，本报告为阶段报告
- 报告类型：stage；发布状态：可发布（阶段报告）

- 原始记录：20
- 有效记录：20
- 规范结论：20
- 已接受漏洞：20
- 待终审：0
- 存疑或排除：0

“已接受漏洞”以当前版本的正式终审处置为准：静态证据充分可接受；动态已验证结论还须完成同版本观测复核。其余结论逐条保留，不会因为缺少终审额度而从报告中消失。

| 完成维度 | 已完成 | 分母 | 说明 |
|---|---:|---:|---|
| 源码覆盖（读取） | 46 | 61 | 已读只表示宿主记录过读取 |
| 源码覆盖（读取+带理由跳过） | 46 | 61 | 跳过不是安全结论 |
| 必做方向结算 | 3 | 3 | 未决 0 个 |
| 动态验证完成 | 18 | 20 | 待验证 0 条 |
| 正式复核 | 20 | 20 | 复核存疑或未复核不计入已接受 |
| 源码覆盖（仍待复核） | 15 | 61 | 未读且未跳过 15 个 |

**已接受漏洞**

- C-01 partner/portal.php 仅 base64 解码 JWT payload 而不校验签名，任意用户伪造 role=admin 读取全部订单结算数据（lab30-shop/app/public/partner/portal.php:3）
- C-02 account/update.php 批量赋值允许普通用户将自身 role/balance/tier 写为任意值（自我提权）（lab30-shop/app/public/account/update.php:4）
- C-03 support/messages.php 留言内容未转义输出导致存储型 XSS（lab30-shop/app/public/support/messages.php:5）
- C-04 account/backup.php 在校验前对用户 base64 数据执行 unserialize，导致 PHP 对象注入（lab30-shop/app/public/account/backup.php:5）
- C-05 wallet/withdraw.php 提现余额校验与扣减非原子，可并发超额提现（lab30-shop/app/public/wallet/withdraw.php:7）
- C-06 orders/detail.php 按 id 直接读取订单且不校验 user_id，形成订单 IDOR（JSON 分支泄露备注）（lab30-shop/app/public/orders/detail.php:2）
- C-07 注册与登录使用无盐 md5 存储与校验口令（lab30-shop/app/public/auth/register.php:8）
- C-08 订单创建信任客户端提交的 price，导致商品实付金额被任意压低（lab30-shop/app/public/orders/create.php:7）
- C-09 content/page.php 将 $_GET['page'] 直接拼入 include 导致本地文件包含（lab30-shop/app/public/content/page.php:3）
- C-10 redeem.php 会员兑换使用 md5 弱类型比较，0e 魔术哈希绕过（lab30-shop/app/public/account/redeem.php:5）
- C-11 ops/xml-import.php 启用 LIBXML_NOENT|LIBXML_DTDLOAD 解析用户 XML，导致 XXE（lab30-shop/app/public/ops/xml-import.php:3）
- C-12 start_session() 关闭 strict_mode 且接受可控 sid，导致会话固定（lab30-shop/app/src/bootstrap.php:13）
- C-13 ops/template-preview.php 将 GET template 直接 include 导致本地文件包含（条件性远程包含）（lab30-shop/app/public/ops/template-preview.php:3）
- C-14 account/profile.php 将 url 参数与用户 homepage 未编码写入 href，造成反射型/存储型 XSS（lab30-shop/app/public/account/profile.php:3）
- C-15 商品目录搜索参数 q 直接拼接进 SQL 导致 SQL 注入（lab30-shop/app/public/catalog/index.php:4）
- C-16 support/download.php 用户可控 file 参数拼接路径导致路径遍历任意文件读取（lab30-shop/app/public/support/download.php:3）
- C-17 ops/template-render.php 对模板表达式 eval 导致任意 PHP 代码执行（lab30-shop/app/public/ops/template-render.php:3）
- C-18 ops/url-preview.php 将 GET url 直接传给 file_get_contents 导致 SSRF（lab30-shop/app/public/ops/url-preview.php:3）
- C-19 ops/ping.php 将 host 参数拼接进 shell_exec 导致命令注入（lab30-shop/app/public/ops/ping.php:2）
- C-20 reset_shop() 使用 MD5 存储硬编码初始口令（含 admin）（lab30-shop/app/src/setup.php:17）

## 2. 范围和方法

- 项目：39211162aa984b25b60228c194b531ae；快照：`586b79b41f8e4f59be80f2a9b548902b`
- 源码包哈希（archive sha256）：`67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c`
- 事实包：final-review/v1；渲染器：final-report/v2；模板哈希：`bae25eb461e0811b`
- 输入哈希：`d040c84e1fe5f409c09692d4a1acd6da1a63a10e6598827fadec70f5ac6cae29`；冻结时间：2026-10-30T12:16:48.371310+00:00；生成时间：2026-10-30T12:16:48.371310+00:00
- 模型配置：deepseek-flash；策略版本：audit-runtime-3

本次报告只使用宿主记录的冻结事实：源码引用由服务器从快照读取并核对哈希，动态验证取自隔离 runner 的作业记录，正式复核按 finding revision 与 verification id 精确引用。模型的结论陈述与修复建议以“结论陈述”标注，不作为证据；未执行、环境失败与验证不确定都不解释为误报。

| 预算 | 上限 | 实际使用 | 剩余 |
|---|---:|---:|---:|
| 模型响应 | 2048 | 154 | 1894 |
| 工具调用 | 16384 | 152 | 16232 |
| 秒 | 10800 | 1433.884 | 9366.116 |

- 上下文：峰值请求 150232 字节 / 上限 393216 字节；摘要请求 0 次；硬上限命中 0 次。

| 阶段 | 请求配额 | 已用 |
|---|---:|---:|
| 源码挖掘 | 58 | 58 |
| POC 验证 | 1966 | 85 |
| 统一终审 | 24 | 11 |
- 调度政策：host-queue-v1；配额：自动分配。
- 待终审 0 项，预计 0 批；当前预留 0 次请求、60 秒；按实际批次容量与 Worker 调整，不增加整次额度。
- POC 执行：。

## 3. 规范漏洞清单

| 编号 | 标题 | 类型 | 评分 | 位置 | 静态判读 | 动态验证 | 正式终审 | 处置 |
|---|---|---|---|---|---|---|---|---|
| C-01 | partner/portal.php 仅 base64 解码 JWT payload 而不校验签名，任意用户伪造 rol… | auth_bypass | CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:… | lab30-shop/app/public/partner/portal.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-02 | account/update.php 批量赋值允许普通用户将自身 role/balance/tier 写为任意值（自我提… | mass_assignment | CVSS 3.1 Base 9.6 (critical) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:… | lab30-shop/app/public/account/update.php:4 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-03 | support/messages.php 留言内容未转义输出导致存储型 XSS | xss_s | CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/… | lab30-shop/app/public/support/messages.php:5 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-04 | account/backup.php 在校验前对用户 base64 数据执行 unserialize，导致 PHP 对象… | insecure_deserialization | CVSS 3.1 待评分 | lab30-shop/app/public/account/backup.php:5 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-05 | wallet/withdraw.php 提现余额校验与扣减非原子，可并发超额提现 | race_condition | CVSS 3.1 待评分 | lab30-shop/app/public/wallet/withdraw.php:7 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-06 | orders/detail.php 按 id 直接读取订单且不校验 user_id，形成订单 IDOR（JSON 分支泄… | idor | CVSS 3.1 待评分 | lab30-shop/app/public/orders/detail.php:2 | 证据已记录 | 不确定（不确定） | 未复核 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-07 | 注册与登录使用无盐 md5 存储与校验口令 | weak_crypto | CVSS 3.1 Base 5.9 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/auth/register.php:8 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-08 | 订单创建信任客户端提交的 price，导致商品实付金额被任意压低 | price_manipulation | CVSS 3.1 待评分 | lab30-shop/app/public/orders/create.php:7 | 证据已记录 | 不确定（不确定） | 未复核 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-09 | content/page.php 将 $_GET['page'] 直接拼入 include 导致本地文件包含 | lfi | CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:… | lab30-shop/app/public/content/page.php:3 | 缺上下文（2 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-10 | redeem.php 会员兑换使用 md5 弱类型比较，0e 魔术哈希绕过 | weak_type_comparison | CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/… | lab30-shop/app/public/account/redeem.php:5 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-11 | ops/xml-import.php 启用 LIBXML_NOENT&#124;LIBXML_DTDLOAD 解析用户 … | xxe | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/ops/xml-import.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-12 | start_session() 关闭 strict_mode 且接受可控 sid，导致会话固定 | session_fixation | CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/… | lab30-shop/app/src/bootstrap.php:13 | 缺上下文（2 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-13 | ops/template-preview.php 将 GET template 直接 include 导致本地文件包含（… | lfi | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/ops/template-preview.php:3 | 缺上下文（2 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-14 | account/profile.php 将 url 参数与用户 homepage 未编码写入 href，造成反射型/存储… | xss_r | CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/… | lab30-shop/app/public/account/profile.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-15 | 商品目录搜索参数 q 直接拼接进 SQL 导致 SQL 注入 | sqli | CVSS 3.1 Base 8.6 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:… | lab30-shop/app/public/catalog/index.php:4 | 缺上下文（1 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-16 | support/download.php 用户可控 file 参数拼接路径导致路径遍历任意文件读取 | path_traversal | CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/… | lab30-shop/app/public/support/download.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-17 | ops/template-render.php 对模板表达式 eval 导致任意 PHP 代码执行 | code_execution | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/template-render.php:3 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-18 | ops/url-preview.php 将 GET url 直接传给 file_get_contents 导致 SSRF | ssrf | CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/… | lab30-shop/app/public/ops/url-preview.php:3 | 缺上下文（2 项） | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-19 | ops/ping.php 将 host 参数拼接进 shell_exec 导致命令注入 | command_injection | CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:… | lab30-shop/app/public/ops/ping.php:2 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |
| C-20 | reset_shop() 使用 MD5 存储硬编码初始口令（含 admin） | weak_crypto | CVSS 3.1 Base 9.4 (critical) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:… | lab30-shop/app/src/setup.php:17 | 证据已记录 | 动态确认 | 复核确认 | 已接受：独立终审批次接受源码结论；动态验证状态单独保留 |

## 4. 逐条漏洞详单

### C-01 partner/portal.php 仅 base64 解码 JWT payload 而不校验签名，任意用户伪造 role=admin 读取全部订单结算数据

- 当前版本：finding `2450f5eb14b94063bae1850f8e1b0af4` revision 1（项目版本 21）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/partner/portal.php:3`；文件：`lab30-shop/app/public/partner/portal.php`
- 证据引用：`7bea3967b6864d34` lab30-shop/app/public/partner/portal.php:1-6；`caef78d64c12c1c2` lab30-shop/app/public/partner/token.php:3-4；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:0621b9d234639dc18a59:1（规范类型 auth_bypass）

**结论陈述（模型产出，不是证据）**

portal.php 第2行从 $_POST['token'] 或 $_COOKIE['partner_token'] 取 token，用 explode('.') 分成3段后仅对第2段做 base64url 解码并 json_decode，完全未重算 HMAC、未比对第3段签名、也未校验 sub/角色来源。第3行只判断 $payload['role']==='admin' 就以管理员身份继续，第4行无任何归属/权限过滤地查询 orders 全表并输出订单号与金额（第5/6行）。攻击者无需任何账号即可自造 header.payload.sig 三段字符串，把 payload 设为 {"role":"admin"}，POST 到 /partner/portal.php 即越权读取全部订单结算数据；token.php 签发的真实签名在此处毫无作用，属于客户端可控 claims 的可伪造授权。

- 攻击前身份与适用前提：portal.php 可被公网访问；无需登录（脚本未调用 require_user）
- 入口 → 传播 → 危险操作/状态变更：HTTP POST 参数 token 或 Cookie partner_token，完全由客户端提供 → portal.php:2 $_POST['token']/$_COOKIE['partner_token'] -> explode('.') 取第2段 -> base64_decode -> json_decode 得到 $payload；:3 只比较 $payload['role'] -> :4 查询 orders 全表 -> :5/:6 输出 → 越权数据读取：db()->query('SELECT order_no,total FROM orders ORDER BY id')->fetchAll() 并原样返回
- 防护与边界：无。第2行未调用 hash_hmac、未 hash_equals 签名，header alg 未被检查，payload 的 sub/role 未与任何服务端会话绑定；第3行依客户端 JSON 的 role 字段做授权判定
- 静态判读：证据已记录
- 动态验证：动态确认（verification `bfdab048b1654fbaa217c7b2ffcc6a00`）
- 正式终审：独立批次 d056014f27e54aa4bac82e2bf32bd96b；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（job 1744831dacf8436eacf84bd6a8aee4a0）：构造三段 token = base64url({"alg":"HS256","typ":"JWT"}) + '.' + base64url({"sub":1,"role":"admin","name":"partner"}) + '.sig'（第三段为任意串，未做任何真实签名），POST /partner/portal.php 返回 200，JSON 为 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}，即无签名校验地取得全表订单结算数据。对照：token.php 签发的真实 token（payload 为 {"sub":1,"role":"customer","name":"alice"}，三部分完整）POST 后返回 403；伪造 role=user 也返回 403。此前审计作业 f005c810632d4d0eaac569e4f9e04937 两次 403 是其 token 构造只有 2 段/4 段导致 payload 解析失败（'xxx.e30.sig' 的第二段即 'e30'），并非漏洞不存在；修正为正确三段后攻击成立。

- 评分依据：CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：portal.php 必须校验 JWT 签名：使用服务端密钥重算 hash_hmac 并用 hash_equals 比对第3段，拒绝 alg 非预期值；同时把 sub 映射到服务端用户并核对实际 role，而非信任 payload 中的 role。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/partner/portal.php:1-6`（sha256 `e1267edb0f9df936…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$token=(string)($_POST['token']??$_COOKIE['partner_token']??'');$parts=explode('.',$token);$payload=count($parts)===3?json_decode((string)base64_decode(strtr($parts[1],'-_','+/')),true):null;
    3  if(!is_array($payload)||($payload['role']??'')!=='admin')fail_request('此合作方功能仅向管理员开放。',403);
    4  $rows=db()->query('SELECT order_no,total FROM orders ORDER BY id')->fetchAll();
    5  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['role'=>'admin','settlements'=>$rows]);
    6  page('合作方结算工作台',function()use($rows){echo '<section class="panel"><h2>结算摘要</h2><table><thead><tr><th>订单</th><th>金额</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['order_no']).'</td><td>¥'.h($r['total']).'</td></tr>';echo '</tbody></table></section>';});
```

`lab30-shop/app/public/partner/token.php:3-4`（sha256 `391948b46efce76c…`）

```php
    3  function b64url(string $s):string{return rtrim(strtr(base64_encode($s),'+/','-_'),'=');}
    4  $header=b64url(json_encode(['alg'=>'HS256','typ'=>'JWT']));$payload=b64url(json_encode(['sub'=>$u['id'],'role'=>$u['role'],'name'=>$u['username']]));$key=db()->query("SELECT value FROM settings WHERE `key`='generation'")->fetchColumn();$token=$header.'.'.$payload.'.'.b64url(hash_hmac('sha256',$header.'.'.$payload,$key,true));
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-02 account/update.php 批量赋值允许普通用户将自身 role/balance/tier 写为任意值（自我提权）

- 当前版本：finding `8d351dc371a74ee99ba7542713dde029` revision 1（项目版本 7）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/update.php:4`；文件：`lab30-shop/app/public/account/update.php`
- 证据引用：`fadde1b1e1006c27` lab30-shop/app/public/account/update.php:3-7；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37；`434b5d778ccdc04c` lab30-shop/app/public/account/index.php:1-3
- 根因类别：task_goal:v2:3ef310ec45df0c0d02e7:1（规范类型 mass_assignment）

**结论陈述（模型产出，不是证据）**

update.php 在 POST 处理中把 columns 白名单设为 ['display_name','email','role','balance','tier','nickname','homepage']，随后遍历 $_POST 中命中该白名单的键直接拼成 UPDATE users SET ... WHERE id=?，参数为当前会话用户 id。表单只渲染 display_name/nickname/email/homepage，但服务端并不限制提交字段，任何登录用户都可额外提交 role=admin、tier=gold、balance=999999，直接改写自身权限与余额列。require_user() 只验证登录，没有角色校验，也没有字段级授权。

- 攻击前身份与适用前提：攻击者拥有任意普通账户并通过登录取得会话，可获取页面 csrf 令牌
- 入口 → 传播 → 危险操作/状态变更：POST 请求体字段（role、tier、balance 等），攻击者只需具备普通登录账户 → $_POST 键值 -> in_array($key,$columns,true) 命中 -> $set/$values 拼接 -> UPDATE users SET `role`=?,`balance`=? ... WHERE id=$u['id'] → db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values) 动态写入权限/余额列
- 防护与边界：无有效防护：csrf 校验只防跨站伪造，columns 白名单本身包含敏感列，未按业务允许集合过滤，也未校验角色
- 静态判读：证据已记录
- 动态验证：动态确认（verification `fbf7eefa06404ce4a958e4a6fc339057`）
- 正式终审：独立批次 d056014f27e54aa4bac82e2bf32bd96b；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

同一脚本随后提交 csrf + display_name=pwned&role=admin&balance=999999&tier=gold，返回 200。宿主对作业 4608e524a20646eebe7ecfb7dc61c67c 的 postcondition 显示：alice 的 role 由 customer 变为 admin、balance 由 100.00 变为 999999.00、tier 由 standard 变为 gold，reason=identity_or_role_mismatch，state_changes 明确列出这三个字段的 before/after。即攻击侧越过了表单可见字段边界，直接改写权限与资金列。补充：脚本对 /ops/index.php 的字符串检查输出 'OPS 200 False'，仅说明页面正文未出现字面量 admin，不作为越权可见性证据；权限提升本身由数据库列变化与宿主前提判定证实。

- 评分依据：CVSS 3.1 Base 9.6 (critical) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：把可写字段限定为 display_name/nickname/email/homepage，显式拒绝 role/balance/tier；敏感列更新需单独接口并做角色校验。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/update.php:3-7`（sha256 `b8227f19c05d0cd3…`）

```php
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
    7      if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response($u);
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

`lab30-shop/app/public/account/index.php:1-3`（sha256 `1d22c7bc280b30b0…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();
    3  page('账户与会员',function()use($u){echo '<section class="panel"><span class="badge">'.h($u['tier']).'</span><h2>'.h($u['display_name']).'</h2><p>'.h($u['email']).'</p><dl><dt>用户名</dt><dd>'.h($u['username']).'</dd><dt>会员权益</dt><dd id="member-benefit">'.($u['tier']==='gold'?'金卡会员：享受专属折扣与优先服务':'普通会员：日常积分与会员活动').'</dd></dl></section><div class="cards">';foreach([['/account/profile.php','个人主页','预览你的个人链接'],['/account/settings.php','邮箱设置','维护常用联系方式'],['/account/update.php','资料维护','更新会员信息'],['/account/backup.php','会员备份','导出或恢复会员偏好'],['/account/redeem.php','权益兑换','使用活动兑换码'],['/partner/token.php','合作方服务','领取合作方访问凭证'],['/auth/continue.php','继续访问','选择登录后的目的页面']]as$c)echo '<a class="feature-card" href="'.$c[0].'"><h3>'.$c[1].' ↗</h3><p>'.$c[2].'</p></a>';echo '</div>';},'账户与会员');
```

### C-03 support/messages.php 留言内容未转义输出导致存储型 XSS

- 当前版本：finding `cd3a4d574a174fc2a17410c024d39300` revision 1（项目版本 18）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/messages.php:5`；文件：`lab30-shop/app/public/support/messages.php`
- 证据引用：`4287a6e3dca83484` lab30-shop/app/public/support/messages.php:3-5；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10
- 根因类别：task_goal:v2:e769a5ec1f92122078bc:1（规范类型 xss_s）

**结论陈述（模型产出，不是证据）**

messages.php 第 3 行将 POST message 原样插入数据库，第 5 行遍历时 display_name 与 created_at 均经 h() 转义，但 $row['message'] 直接拼入 <div class="message-body">，未转义，形成存储型 XSS。

- 攻击前身份与适用前提：攻击者登录且持有 CSRF token 提交留言
- 入口 → 传播 → 危险操作/状态变更：POST 参数 message → $_POST['message'] -> INSERT INTO messages -> SELECT -> $row['message'] -> 拼接进 HTML 输出 → 未转义的 HTML 输出 $row['message']
- 防护与边界：h() 仅用于 display_name/created_at，message 字段未使用；CSRF 与长度校验不防 XSS
- 静态判读：证据已记录
- 动态验证：动态确认（verification `479fa77d8fca449e80bc11fb319cfa07`）
- 正式终审：独立批次 ccfc459438644b5997fe28cf115ed79e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（job bba80ab0fd96458685961c83d0fd0d4e + browser job 889b6122d09345289b23cf51af25fa25，同一 alice 会话）：POST message=&lt;script&gt;alert('POC_XSS_9f21')&lt;/script&gt; 返回 200；响应 HTML 中 message-body 为 <div class="message-body"><script>alert('POC_XSS_9f21')</script></div>（RAW_SCRIPT_PRESENT True，ESCAPED_SCRIPT_PRESENT False），即未转义存储。随后 browser_check 以 alice 加载 /support/messages.php，宿主记录 dialogs=["POC_XSS_9f21"]，脚本在浏览器实际执行；对应留言在 body_text 中呈现为空条目（时间为 2026-10-30 12:11:35）。

- 评分依据：CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：输出时对 $row['message'] 使用 h()，或使用 nl2br(h(...)) 并保持 ENT_QUOTES。

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

### C-04 account/backup.php 在校验前对用户 base64 数据执行 unserialize，导致 PHP 对象注入

- 当前版本：finding `f9905b9698ff46aa9ef4e23f1c73ad48` revision 1（项目版本 2）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/backup.php:5`；文件：`lab30-shop/app/public/account/backup.php`
- 证据引用：`52a7b68bba8b1c1f` lab30-shop/app/public/account/backup.php:4-6；`9d0d13b19a80b9a2` lab30-shop/app/src/backup.php:2-5
- 根因类别：task_goal:v2:bd0ea6ea6960517634f4:1（规范类型 insecure_deserialization）

**结论陈述（模型产出，不是证据）**

第4行 base64_decode 用户 POST 的 backup，字段仅做 base64 合法性检查；第5行直接 unserialize 后才做 instanceof 判断，反序列化先于类型校验，未设置 allowed_classes。攻击者可提交任意类的序列化对象以触发魔术方法，或用 MemberBackup 之外的属性驱动第6行的 UPDATE。

- 攻击前身份与适用前提：登录用户并可获取 csrf 令牌
- 入口 → 传播 → 危险操作/状态变更：POST backup → base64_decode → unserialize → instanceof → UPDATE users SET tier,display_name → unserialize($raw)
- 防护与边界：仅事后 instanceof 检查，无 allowed_classes 白名单
- 静态判读：证据已记录
- 动态验证：动态确认（verification `e226eb97145e41cdab43413628ee72cf`）
- 正式终审：独立批次 ccfc459438644b5997fe28cf115ed79e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（同一 alice 会话，job 4528de3454a44a91b6f2f52c76f95260）：提交 base64(O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:8:"PWN_9f21";}) 返回 200 并提示「会员备份已恢复」；随后 /account/index.php 的 badge 与姓名由 (gold, pwned) 变为 (gold, PWN_9f21)，MARKER_VISIBLE True，即攻击者伪造的属性被 unserialize 还原并原样写入第6行的 UPDATE。辅助对照：提交 base64 的数组序列化 a:1:{s:3:"tier";s:4:"gold";} 返回 400「不是有效的会员备份」，说明用户可控序列化数据确实先进入 unserialize，随后才被 instanceof 拦截。审计作业 84685f8a71594ecebc2cd95becb6465b 的同类伪造负载亦使 alice tier 由 standard 变为 gold（宿主 state_changes）。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 unserialize($raw, ['allowed_classes'=>['MemberBackup']]) 或改用 JSON 结构并严格校验字段。

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

### C-05 wallet/withdraw.php 提现余额校验与扣减非原子，可并发超额提现

- 当前版本：finding `828f0388116b4678b4e0012243032ee2` revision 1（项目版本 23）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/wallet/withdraw.php:7`；文件：`lab30-shop/app/public/wallet/withdraw.php`
- 证据引用：`713c1c83b1f33981` lab30-shop/app/public/wallet/withdraw.php:2-11
- 根因类别：task_goal:v2:a9b1723d10cab28842dd:1（规范类型 race_condition）

**结论陈述（模型产出，不是证据）**

第4行读取余额、第5行比较、第7行以旧余额计算新余额写回，无事务行锁、无 WHERE balance>=? 条件更新；第3行 session_write_close 使并发请求互不阻塞，第6行 usleep(350000) 放大竞争窗口。多个并发请求读到同一旧余额均通过校验，余额被覆盖为同一值却生成多笔 withdrawals 记录，实现超额提现。

- 攻击前身份与适用前提：攻击者拥有普通账户并取得 csrf 令牌；并发发送多个提现请求
- 入口 → 传播 → 危险操作/状态变更：POST amount 与并发请求 → amount 校验 → SELECT balance → usleep → UPDATE users SET balance=旧值-amount → INSERT withdrawals → 基于过期读值写回 users.balance
- 防护与边界：仅校验金额范围与单次余额，无锁、无原子条件更新
- 静态判读：证据已记录
- 动态验证：动态确认（verification `9b0215f14cf74f3bbb61aaec7fd919ed`）
- 正式终审：独立批次 ccfc459438644b5997fe28cf115ed79e；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（同 job 11fc94d7584c44548ffc7b5a04ea1871）：在余额 80.00、记录 6 条（合计 60）时并发提交 4 个 amount=10 提现请求，4 个响应均为 200 且各自返回 {"status":"paid","amount":10,"balance":70,"receipt_id":7/8/9/10}（receipt 7,8,9,10 全部生成）。随后 /wallet/index.php（Accept: application/json）为 balance 70.00、count 10、withdrawn_total 100：新增 4 条提现记录共 40.00，但余额只从 80.00 减到 70.00（仅扣 10.00），即多提现 30.00，超额提现成立。宿主 postcondition 也记录 90.00→70.00。审计作业 e27db6dc8b414d3d81b09f21c7cc5f09 的 5 并发同型实验（全部 200）后 postcondition 余额 100.00→90.00，与上述非原子写回一致。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改为 UPDATE users SET balance=balance-? WHERE id=? AND balance>=? 并检查 rowCount，或事务内 SELECT ... FOR UPDATE。

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

### C-06 orders/detail.php 按 id 直接读取订单且不校验 user_id，形成订单 IDOR（JSON 分支泄露备注）

- 当前版本：finding `bc120a98aa3943b0aeb05fcff4c6ca64` revision 1（项目版本 30）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/detail.php:2`；文件：`lab30-shop/app/public/orders/detail.php`
- 证据引用：`2585399332002e26` lab30-shop/app/public/orders/detail.php:2-4；`5c7a19d86aca3057` lab30-shop/app/src/bootstrap.php:20-24；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:8e969f4faeb638897ae9:1（规范类型 idor）

**结论陈述（模型产出，不是证据）**

detail.php 第2行以 SELECT o.*,u.username,p.name FROM orders ... WHERE o.id=? 查询，仅 require_user() 判断已登录，WHERE 条件不含 o.user_id 或当前用户，任意登录用户可用连续订单 id 读取他人订单（含 private_note、购买人、金额）；第3行当 Accept 含 application/json 时直接 json_response($o)，把完整订单行返回，绕过页面层的 h() 转义。

- 攻击前身份与适用前提：攻击者持任一有效账号，目标订单 id 存在
- 入口 → 传播 → 危险操作/状态变更：GET 参数 id → $_GET['id'] -> $q->execute([...]) 查询 orders WHERE o.id=?（无 user_id 条件）-> $o -> 第3行 json_response($o) 或第4行页面输出 → 返回不属于当前用户的订单完整记录
- 防护与边界：仅有 require_user() 登录校验；无归属比较，无角色限制；JSON 分支完全原样输出订单行
- 静态判读：证据已记录
- 动态验证：不确定（不确定）（verification `acde04a0b9664d1b8eb85cc944d3e5b2`）
- 正式终审：独立批次 644cebc9df844573bfe08b560808cc94；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：查询条件追加 AND o.user_id=? 并绑定当前会话用户 id（管理员/运营读取他人订单需显式角色校验与审计）；JSON 分支只返回必要字段。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/orders/detail.php:2-4`（sha256 `be69aa78cecffcfd…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user();$q=db()->prepare('SELECT o.*,u.username,p.name FROM orders o JOIN users u ON u.id=o.user_id LEFT JOIN products p ON p.id=o.product_id WHERE o.id=?');$q->execute([$_GET['id']??0]);$o=$q->fetch();if(!$o)fail_request('订单不存在。',404);
    3  if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response($o);
    4  page('订单详情',function()use($o){echo '<section class="panel"><span class="badge">等待配送</span><h2>'.h($o['order_no']).'</h2><dl>';foreach(['商品'=>$o['name'],'购买人'=>$o['username'],'数量'=>$o['quantity'],'实付金额'=>'¥'.$o['total'],'配送备注'=>$o['private_note']]as$k=>$v)echo '<dt>'.h($k).'</dt><dd>'.h($v).'</dd>';echo '</dl><a class="button secondary" href="/orders/index.php">返回订单中心</a></section>';},'订单中心');
```

`lab30-shop/app/src/bootstrap.php:20-24`（sha256 `2050819d093be02b…`）

```php
   20  function user(): ?array {
   21      start_session();
   22      if (empty($_SESSION['user_id'])) return null;
   23      $q = db()->prepare('SELECT id,username,display_name,email,role,balance,tier,nickname,homepage FROM users WHERE id=?');
   24      $q->execute([$_SESSION['user_id']]); return $q->fetch() ?: null;
```

`lab30-shop/app/src/bootstrap.php:33-37`（sha256 `2050819d093be02b…`）

```php
   33  function require_user(array $roles = []): array {
   34      $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
   35      if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
   36      return $u;
   37  }
```

### C-07 注册与登录使用无盐 md5 存储与校验口令

- 当前版本：finding `a94a3b86a4874c2ea7ca50febea25973` revision 1（项目版本 6）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/auth/register.php:8`；文件：`lab30-shop/app/public/auth/register.php`
- 证据引用：`d75d9f6dcc3431a8` lab30-shop/app/public/auth/register.php:5-8；`61badbb513a28357` lab30-shop/app/public/auth/login.php:7-8
- 根因类别：task_goal:v2:2011f6b100229403a863:1（规范类型 weak_crypto）

**结论陈述（模型产出，不是证据）**

register.php 第 7-8 行把口令以 md5($password) 写入 users.password_md5，login.php 第 7 行同样以 md5 校验。md5 未加盐且为快速哈希，一旦数据库或哈希泄露可被彩虹表/GPU 暴力快速还原明文。

- 攻击前身份与适用前提：需先取得 password_md5 值才能离线破解
- 入口 → 传播 → 危险操作/状态变更：注册表单 $_POST['password'] → register.php:8 $q->execute([... md5($password) ...]) 写入 users.password_md5；login.php:7 hash_equals(row['password_md5'], md5($_POST['password'])) → md5() 无盐口令摘要存储与校验
- 防护与边界：仅长度 >=8 校验，无盐、无 password_hash 慢哈希
- 静态判读：证据已记录
- 动态验证：动态确认（verification `79deb349024548beb39fb3ff71f44bd0`）
- 正式终审：独立批次 644cebc9df844573bfe08b560808cc94；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

判别性观测（弱哈希的证据在存储/校验路径本身，而非某个越权请求）：以未登录（guest）身份在 /auth/register.php 新建账号 pocd470a9f5（REGISTER 200、SUCCESS_NOTICE True），注册源码 register.php:8 只写入 md5($password)。随后用同一明文口令登录成功（LOGIN_CORRECT 200 并跳离登录页），/account/index.php 200、含「退出」且显示该新用户名；而错误口令登录返回 401（LOGIN_WRONG 401，提示「账号或密码不正确」）。由于 login.php:7 唯一的判定是 hash_equals(password_md5, md5(输入))，登录成功即证明库中 password_md5 恰为 32 位 md5(明文)（本例 md5 计算值为 4e42bdc04f1fdc145c553a18ddf8e06d，LEN 32），未加盐、无慢哈希。

- 评分依据：CVSS 3.1 Base 5.9 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 password_hash(PASSWORD_DEFAULT) 存储、password_verify 校验并迁移旧哈希。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/auth/register.php:5-8`（sha256 `99166a0288be7b1e…`）

```php
    5      $name=(string)($_POST['username']??''); $password=(string)($_POST['password']??'');
    6      if(!preg_match('/^[a-zA-Z][a-zA-Z0-9_]{2,39}$/D',$name)||strlen($password)<8) fail_request('用户名需为 3–40 位字母数字，密码至少 8 位。');
    7      $q=db()->prepare('INSERT INTO users(username,password_md5,display_name,email,role,balance,tier,nickname) VALUES(?,?,?,?,?,100,?,?)');
    8      try {$q->execute([$name,md5($password),$name,(string)($_POST['email']??''),'customer','standard',$name]); $notice='注册成功，现在可以登录。';} catch(PDOException $e) {fail_request('该用户名已注册。',409);}
```

`lab30-shop/app/public/auth/login.php:7-8`（sha256 `b9be43ddb2233156…`）

```php
    7      if ($row && hash_equals($row['password_md5'],md5((string)($_POST['password']??'')))) {
    8          $_SESSION['user_id']=(int)$row['id']; event_log('login');
```

### C-08 订单创建信任客户端提交的 price，导致商品实付金额被任意压低

- 当前版本：finding `ee4a398ed1fc494fb97edf480a59daf7` revision 1（项目版本 30）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/orders/create.php:7`；文件：`lab30-shop/app/public/orders/create.php`
- 证据引用：`e4ba0faa7c0831b2` lab30-shop/app/public/orders/create.php:3-7；`063c928d2d7c3b2e` lab30-shop/app/src/bootstrap.php:33-40；`7a752056361b87ea` lab30-shop/app/public/catalog/index.php:4-5
- 根因类别：task_goal:v2:babb900bd07ada2ef86a:1（规范类型 price_manipulation）

**结论陈述（模型产出，不是证据）**

create.php 第3行从 $_POST['price'] 经 FILTER_VALIDATE_FLOAT 取值，第4行仅校验其为非负数字，没有使用第3行已查出的 $p['price'] 作为权威单价；第5行以 $price*$quantity 计算 total，第7行把客户端 $price 和 $total 直接写入 orders。任意已登录用户构造 POST 即可用 0.01 等价格下单并通过库存扣减，造成金额篡改和库存消耗。

- 攻击前身份与适用前提：攻击者拥有有效账号并取得自身会话 CSRF 令牌；商品存在且库存足够
- 入口 → 传播 → 危险操作/状态变更：POST 参数 price、quantity、product_id（CSRF 令牌可由正常登录会话获取） → $_POST['price'] -> filter_var(FILTER_VALIDATE_FLOAT) -> $price（第3行）-> $total=round($price*$quantity,2)（第5行）-> INSERT INTO orders(unit_price,total)（第7行） → 以客户端可控单价写订单并计算实付金额
- 防护与边界：仅 require_user、require_post、check_csrf；对 price 只做非负校验，未与 products.price 比对，属于业务完整性缺失防护
- 静态判读：证据已记录
- 动态验证：不确定（不确定）（verification `b470fcae64a94ee0af4d8d89bd063332`）
- 正式终审：独立批次 644cebc9df844573bfe08b560808cc94；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响**

未通过动态验证确认可执行；影响只以静态证据所支持的范围为准，不自动外推。

- 评分依据：CVSS 3.1 待评分；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：服务端只接受 product_id 与 quantity，单价与总额一律用 products 表中的 price 计算；可校验客户端提交价仅用于展示比对并拒绝不一致请求。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/orders/create.php:3-7`（sha256 `41e73625d7e04c58…`）

```php
    3  $q=db()->prepare('SELECT * FROM products WHERE id=?');$q->execute([$_POST['product_id']??0]);$p=$q->fetch();$quantity=filter_var($_POST['quantity']??0,FILTER_VALIDATE_INT);$price=filter_var($_POST['price']??null,FILTER_VALIDATE_FLOAT);
    4  if(!$p||!$quantity||$quantity<1||$quantity>20||$price===false||$price<0)fail_request('商品、数量或价格不正确。');
    5  $total=round($price*$quantity,2);$pdo=db();$pdo->beginTransaction();
    6  $q=$pdo->prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?');$q->execute([$quantity,$p['id'],$quantity]);if(!$q->rowCount()){$pdo->rollBack();fail_request('商品库存不足。',409);}
    7  $q=$pdo->prepare('INSERT INTO orders(order_no,user_id,product_id,quantity,unit_price,total,private_note) VALUES(?,?,?,?,?,?,?)');$q->execute(['SG-'.bin2hex(random_bytes(5)),$u['id'],$p['id'],$quantity,$price,$total,'会员订单，等待发货']);$id=(int)$pdo->lastInsertId();$pdo->commit();event_log('create_order',['order_id'=>$id,'total'=>$total]);header('Location: /orders/detail.php?id='.$id, true,303);
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

`lab30-shop/app/public/catalog/index.php:4-5`（sha256 `e85bd1c2fa6a4b78…`）

```php
    4  $products=db()->query("SELECT id,name,description,price,stock,color FROM products WHERE name LIKE '%".$term."%' ORDER BY id")->fetchAll();
    5  page('本季好物',function()use($products,$term){echo '<form class="search-form" method="get"><input aria-label="搜索商品" name="q" placeholder="搜索你喜欢的好物" value="'.h($term).'"><button>搜索</button></form><p class="muted">共找到 <span id="result-count">'.count($products).'</span> 件商品</p><div class="products">';foreach($products as $p)echo '<article class="product"><div class="product-art '.h($p['color']).'"><svg viewBox="0 0 240 220" role="img" aria-label="'.h($p['name']).'"><use href="/assets/products.svg#product-'.(int)$p['id'].'"></use></svg></div><div class="product-copy"><small>拾光 · 日常系列</small><h2>'.h($p['name']).'</h2><p>'.h($p['description']).'</p><div class="row"><strong>¥'.h($p['price']).'</strong><a class="button secondary" href="/catalog/detail.php?id='.(int)$p['id'].'">查看商品 →</a></div></div></article>';echo '</div><a href="/catalog/greeting.php">查看到店欢迎信息</a>';},'商品目录');
```

### C-09 content/page.php 将 $_GET['page'] 直接拼入 include 导致本地文件包含

- 当前版本：finding `540794db77534bd0a2a22518ea37375f` revision 1（项目版本 28）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/content/page.php:3`；文件：`lab30-shop/app/public/content/page.php`
- 证据引用：`173f24f6297d9164` lab30-shop/app/public/content/page.php:1-3；`87549aa1faa05190` lab30-shop/app/src/setup.php:30-38
- 根因类别：task_goal:v2:0a3bb2ce970708fa64f6:1（规范类型 lfi）

**结论陈述（模型产出，不是证据）**

content/page.php 第2行从 $_GET['page'] 读取路径片段（无白名单），第3行把 APP_ROOT.'/resources/views/'.$name.'.php' 直接传给 include。攻击者可用 ../ 穿越到 data_dir 下的任意 .php 文件（如 vault/account.php 由 setup.php:35 创建），PHP include 会执行其中的代码并输出内容；也可读取其他路径文件。未对 $name 做 basename 或白名单校验。

- 攻击前身份与适用前提：需知道目标文件相对路径，可先用 ../ 遍历或读取已知 data_dir 布局
- 入口 → 传播 → 危险操作/状态变更：$_GET['page'] → $name -> include APP_ROOT.'/resources/views/'.$name.'.php' → include 动态拼接路径
- 防护与边界：无白名单，无 realpath 前缀校验，无 basename
- 静态判读：缺上下文（2 项）；缺失上下文：PHP 运行时 allow_url_include 与 allow_url_fopen 的实际配置；autoload/类加载配置，确认 dispatch_job 等类的可达性
- 动态验证：动态确认（verification `11670586889c40c68ef8929b16497890`）
- 正式终审：独立批次 644d7ad7e7e2427cb3fa6205568539ef；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（同一 alice 会话，job 29208d3829ea4e0ea755721922dff94e）：GET /content/page.php?page=../×5+var/lib/shop/vault/account（URL 编码 %2E%2E%2F…）返回 200，响应正文出现 setup.php:35 写入 vault/account.php 的唯一内部标记 SHOP_INTERNAL_086a85109c3a034cd4b77920；深度 6-11 同样命中（多余 .. 截断到根目录后仍解析到 /var/lib/shop/vault/account.php），未出现 Warning/失败的 include 错误。说明 include APP_ROOT.'/resources/views/'.$name.'.php' 被 ../ 穿越到 data_dir 并执行了该 PHP 文件。

- 评分依据：CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：对 page 参数使用固定白名单映射，拒绝包含 / 或 . 的取值，必要时用 realpath 校验前缀。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/content/page.php:1-3`（sha256 `53c5997117f2d54c…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';$name=(string)($_GET['page']??'home');
    3  page('内容中心',function()use($name){include APP_ROOT.'/resources/views/'.$name.'.php';echo '<section class="panel"><a href="?page=home">商城介绍</a> · <a href="?page=shipping">配送与售后</a></section>';},'内容中心');
```

`lab30-shop/app/src/setup.php:30-38`（sha256 `53e7dc7286d7d370…`）

```php
   30      $root=data_dir();
   31      foreach (['sessions','vault','docs','messages','exports'] as $dir) { if (!is_dir("$root/$dir")) mkdir("$root/$dir",0770,true); }
   32      $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
   33      foreach($it as $file) if($file->isFile()) unlink($file->getPathname());
   34      file_put_contents("$root/vault/internal.txt",$marker . "\n");
   35      file_put_contents("$root/vault/account.php",'<?php echo "' . $marker . '";');
   36      file_put_contents("$root/docs/shipping.txt","配送说明：工作日 48 小时内发货。\n");
   37      file_put_contents("$root/docs/returns.txt","售后说明：签收后七天内可申请退货。\n");
   38      file_put_contents("$root/messages/readme.txt","客服文件区\n");
```

### C-10 redeem.php 会员兑换使用 md5 弱类型比较，0e 魔术哈希绕过

- 当前版本：finding `5d4e81d921a444bd9c462548c4881f44` revision 1（项目版本 3）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/redeem.php:5`；文件：`lab30-shop/app/public/account/redeem.php`
- 证据引用：`81e47fc9f94990a6` lab30-shop/app/public/account/redeem.php:3-6
- 根因类别：task_goal:v2:18b6989994e46d53ae88:1（规范类型 weak_type_comparison）

**结论陈述（模型产出，不是证据）**

redeem.php 第 4 行固定 $secret_hash=md5('240610708')（0e 开头纯数字）；第 5 行以 md5($_POST['token'])==$secret_hash 宽松比较，任何 md5 结果为 '0e'+纯数字的 token（如 240610708 或 QNKCDZO）都被解析为 0==0 通过，从而把任意登录用户升级为 gold 会员。

- 攻击前身份与适用前提：任意已登录用户并携带有效 CSRF token
- 入口 → 传播 → 危险操作/状态变更：POST 表单 $_POST['token'] → redeem.php:5 md5((string)$_POST['token'])==$secret_hash 为真 -> UPDATE users SET tier='gold' → 弱类型比较通过后执行 UPDATE users SET tier='gold'
- 防护与边界：仅 check_csrf()，使用 == 而非 hash_equals
- 静态判读：证据已记录
- 动态验证：动态确认（verification `537aa3a5147149d98cc7137c652bf9d4`）
- 正式终审：独立批次 644d7ad7e7e2427cb3fa6205568539ef；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

提交 md5 结果为 0e830400...391 的 token（QNKCDZO，与 240610708 的 0e462097...854 同为 0e 纯数字），返回 200 {"accepted":true,"message":"兑换成功，已升级金卡会员。"}，随后查询 tier 由 standard 变为 gold，状态变更由宿主记录确认。

- 评分依据：CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改用 hash_equals($secret_hash, md5(...)) 或随机化兑换码并严格比较（===）。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/redeem.php:3-6`（sha256 `28b3dc4534cca985…`）

```php
    3  if($_SERVER['REQUEST_METHOD']==='POST'){
    4      check_csrf();$secret_hash=md5('240610708');
    5      if(md5((string)($_POST['token']??''))==$secret_hash){db()->prepare("UPDATE users SET tier='gold' WHERE id=?")->execute([$u['id']]);event_log('redeem_membership');$notice='兑换成功，已升级金卡会员。';$accepted=true;}
    6      else{$notice='兑换码无效。';http_response_code(422);}
```

### C-11 ops/xml-import.php 启用 LIBXML_NOENT|LIBXML_DTDLOAD 解析用户 XML，导致 XXE

- 当前版本：finding `9302b8fb4eaf47c581953019bb3c7e84` revision 1（项目版本 25）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/xml-import.php:3`；文件：`lab30-shop/app/public/ops/xml-import.php`
- 证据引用：`c7321e7900aae64d` lab30-shop/app/public/ops/xml-import.php:2-4；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36；`415907ec6bf2f739` lab30-shop/app/src/bootstrap.php:40-40
- 根因类别：task_goal:v2:cf8511801817f9752cec:1（规范类型 xxe）

**结论陈述（模型产出，不是证据）**

xml-import.php 第 3 行把 POST 的 xml 字段直接交给 simplexml_load_string，并显式启用 LIBXML_NOENT（展开实体）与 LIBXML_DTDLOAD（加载外部 DTD）。攻击者可在 XML 中定义外部实体引用 file:// 或 http:// 资源，解析阶段读取到的内容会成为元素值，再经 (string)$doc->title 赋给 $output 并在第 4 行 <pre> 中回显（h() 只在输出时做 HTML 转义，不阻止解析期实体展开）。require_user 只校验 operator/admin 角色，check_csrf 依赖攻击者自身上下文可取 token，均不构成 XXE 防护。

- 攻击前身份与适用前提：持有 operator 或 admin 账号，POST /ops/xml-import.php 并携带 csrf token
- 入口 → 传播 → 危险操作/状态变更：POST 参数 xml → $_POST['xml'] -> simplexml_load_string($xml, ..., LIBXML_NOENT&#124;LIBXML_DTDLOAD) -> $doc->title -> $output -> h($output) 输出到 <pre> → simplexml_load_string 解析启用外部实体与外部 DTD
- 防护与边界：仅 require_user 角色检查与 check_csrf；未禁用 libxml_disable_entity_loader / 未移除 LIBXML_NOENT 与 LIBXML_DTDLOAD，也未设置 LIBXML_NONET；输出 h() 不阻止解析阶段读取
- 静态判读：证据已记录
- 动态验证：动态确认（verification `c9f87b3fbfcb4ecdb3352b480819c605`）
- 正式终审：独立批次 644d7ad7e7e2427cb3fa6205568539ef；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（同一 operator 会话、同一 csrf，job cd9c66eff7cf4ca5a5a388e76a59c07c）：提交 <!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> 的 XML 返回 200，<pre> 中出现 root:x:0:0:root:/root:/bin/bash、daemon:… 等 /etc/passwd 内容（ROOT_LINE True）；再提交实体指向 file:///var/lib/shop/vault/internal.txt 的 XML，返回 200 且 <pre> 中回显 SHOP_INTERNAL_19eeaf3f0a110b338bfb859a。外部实体在解析阶段被展开并随 $doc->title 输出，XXE 成立。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：调用 simplexml_load_string 时移除 LIBXML_NOENT 与 LIBXML_DTDLOAD，或显式加 LIBXML_NONET 并在解析前禁用外部实体（如 libxml_disable_entity_loader(true) / 使用 LIBXML_NOENT 之外的安全选项），对输入大小做限制。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/xml-import.php:2-4`（sha256 `3c23a76b1047f734…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$output='';$xml='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$xml=(string)($_POST['xml']??'');libxml_use_internal_errors(true);$doc=simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT|LIBXML_DTDLOAD);if(!$doc)fail_request('XML 格式不正确。');$output=(string)$doc->title;}
    4  page('合作方配置导入',function()use($output,$xml){echo '<section class="panel"><form method="post">'.csrf_field().'<label>XML 配置<textarea name="xml" required>'.h($xml?:'<config><title>春日上新</title></config>').'</textarea></label><button>导入配置</button></form><h2>导入结果</h2><pre>'.h($output).'</pre></section>';},'运营工作台');
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

### C-12 start_session() 关闭 strict_mode 且接受可控 sid，导致会话固定

- 当前版本：finding `0f8e892b8c784af69d7a05ec5929e26c` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/bootstrap.php:13`；文件：`lab30-shop/app/src/bootstrap.php`
- 证据引用：`9f3b2a689fae3c12` lab30-shop/app/src/bootstrap.php:11-19；`5f912f7499e51381` lab30-shop/app/public/auth/login.php:3-9
- 根因类别：task_goal:v2:a245d2e6c3dc5b376f48:1（规范类型 session_fixation）

**结论陈述（模型产出，不是证据）**

start_session() 将 session.use_strict_mode 设为 0（第13行），session_id() 的取值来自外部传入的 $sid 且仅做字符集/长度正则（第17行），随后 session_start()（第18行）会接受该未在服务端生成过的会话 ID。login.php 第3行把 $_GET['sid'] 直接传入 start_session()，第8行登录成功后写入 user_id 但没有 session_regenerate_id()。攻击者可先构造一个 sid 链接让受害者登录，之后用同一 sid 复用已认证会话。

- 攻击前身份与适用前提：攻击者需让受害者通过含 sid 的登录 URL 登录，或受害者直接访问带 sid 的请求
- 入口 → 传播 → 危险操作/状态变更：$_GET['sid']（login.php:3） → $_GET['sid'] -> start_session($sid) -> session_id($sid) -> session_start()；登录成功后 $_SESSION['user_id'] 写入该会话 → 以客户端可控 ID 建立会话并在其上写入认证状态
- 防护与边界：session_set_cookie_params 设置 HttpOnly 与 SameSite=Lax，但对固定 ID 无帮助；strict_mode 被显式关闭
- 静态判读：缺上下文（2 项）；缺失上下文：PHP 运行时 allow_url_include 与 allow_url_fopen 的实际配置；autoload/类加载配置，确认 dispatch_job 等类的可达性
- 动态验证：动态确认（verification `4c760aa252ad4eeaaecdde73288f87de`）
- 正式终审：独立批次 49b344472aea47ff95394c3a624c67a5；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（job 93331f4d752346cead78cb16dd8f0da1，模拟受害者通过带 sid 的登录链接登录）：GET /auth/login.php?sid=pocattacksid0123456789abcd 后 POST 同一 URL 登录，响应 Set-Cookie 的会话值与预置值完全一致（SESSION_EQUALS_CHOSEN_SID True，ATTACK_LOGIN_STATUS 200）。随后用全新 opener 仅以 Cookie: SHOPSESSID=pocattacksid0123456789abcd 请求 /account/index.php，返回 200（ATTACK_FRESH_SESSION_ACCOUNT_STATUS 200）、页面含 <dd>alice</dd>（ATTACK_IDENTITY_ALICE True）与「退出」（ATTACK_AUTH_MARKER True），即攻击者预置的会话 ID 在登录后成为已认证的 alice 会话并被第三方复用。对照：未登录时直接使用另一个固定 sid 请求同一页面返回 401（CONTROL_UNLOGGED_FIXED_SID_STATUS 401），说明该固定值本身并无既有权限，认证状态确由本次登录写入。审计作业 86eebadfaf794126b579c260980f6488 的独立复核同样以同一 sid 头访问 /orders/index.php 得到 200 并打印 SESSION_FIXATION_CONFIRMED。

- 评分依据：CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：开启 session.use_strict_mode=1，禁止从请求参数设置会话 ID，登录成功与权限提升后调用 session_regenerate_id(true)。

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

### C-13 ops/template-preview.php 将 GET template 直接 include 导致本地文件包含（条件性远程包含）

- 当前版本：finding `f0808b3f98f44b829055d315886c0122` revision 1（项目版本 7）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-preview.php:3`；文件：`lab30-shop/app/public/ops/template-preview.php`
- 证据引用：`5d596a817dad3c10` lab30-shop/app/public/ops/template-preview.php:1-3；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:76ce69c592a0c04ce35e:1（规范类型 lfi）

**结论陈述（模型产出，不是证据）**

template-preview.php 第2行把 GET 参数 template 强转为字符串，第3行在 page 回调中直接 `include $template;`，无白名单、无路径规范化、无前缀限制。operator/admin 登录者可指定任意本地路径读取/包含文件；若运行时 allow_url_include=On，还可包含远程 URL 形成 RFI。读取源码文件时 include 作为 PHP 执行而非原样回显，故实际影响以可执行/可解析的文件为主，本地泄露面取决于文件内容。

- 攻击前身份与适用前提：持有 operator 或 admin 登录会话，访问 /ops/template-preview.php?template=<路径>
- 入口 → 传播 → 危险操作/状态变更：GET 参数 template → $_GET['template'] -> (string) -> $template -> include $template → include 动态文件路径
- 防护与边界：require_user(['operator','admin']) 仅做角色鉴权，无输入过滤/路径限制
- 静态判读：缺上下文（2 项）；缺失上下文：allow_url_include 运行时配置值（决定 template-preview 的 RFI 可行性）；url-preview 可达网络拓扑与内网地址可访问性（影响 SSRF 实际影响面）
- 动态验证：动态确认（verification `88f598ea2bca4a009cec0778d91d6da9`）
- 正式终审：独立批次 49b344472aea47ff95394c3a624c67a5；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（同一 operator 会话，job 7da42ee42d13484c9d54973be920c30b）：GET /ops/template-preview.php?template=/var/lib/shop/vault/account.php 返回 200，#remote-template 段内输出 SHOP_INTERNAL_a786c48053383161e5b5e9b8（MARKER），即 include 命中了 data_dir 下的 PHP 文件并执行其代码；GET ...?template=/etc/passwd 返回 200，段内原样输出 root:x:0:0:root:/root:/bin/bash、daemon:… 等，证明可包含任意本地路径读取文件内容（PASSWD True）。另：默认模板 http://fixtures:8080/templates/season.php 被服务端成功取得并渲染出「合作方 · 秋日生活提案」，说明运行时允许 URL 包含（allow_url_include 生效），但未用外部攻击者控制的远端主机验证 RFI。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改为固定模板白名单映射到服务端已知文件名，禁止用户直接提供路径；移除动态 include。

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

### C-14 account/profile.php 将 url 参数与用户 homepage 未编码写入 href，造成反射型/存储型 XSS

- 当前版本：finding `879044f7ff9d474f8c428a8cb831efa9` revision 1（项目版本 24）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/account/profile.php:3`；文件：`lab30-shop/app/public/account/profile.php`
- 证据引用：`e1dc06d2f03a80eb` lab30-shop/app/public/account/profile.php:2-3；`ec18381d7af73d0f` lab30-shop/app/public/account/update.php:4-6；`5220b9ce518719f6` lab30-shop/app/src/bootstrap.php:10-10
- 根因类别：task_goal:v2:332fe278cedb77805928:1（规范类型 xss_r）

**结论陈述（模型产出，不是证据）**

profile.php 第 2 行取 $url = (string)($_GET['url'] ?? $u['homepage'])，第 3 行直接拼接 '<a id="profile-link" href="'.$url.'">'，未使用 h() 转义。攻击者可通过 ?url=javascript:... 或 " onmouseover=... 注入脚本；由于 update.php 允许写 homepage 且 profile.php 默认回读 homepage，同一段输出也构成存储型 XSS，受害者打开带链接的预览页即执行。页面其余输出（display_name）已转义，唯独该 href 未转义。

- 攻击前身份与适用前提：受害者点击携带 url 参数的链接（反射型）；或受害者打开攻击者个人主页（存储型，需攻击者能设置 homepage）
- 入口 → 传播 → 危险操作/状态变更：GET 参数 url，或 users.homepage（可通过 update.php 写入） → $_GET['url'] 或 $u['homepage'] -> $url -> 字符串拼接进 href 属性 -> 输出 HTML → echo '<a id="profile-link" href="'.$url.'">访问个人主页</a>'
- 防护与边界：无：同页其它变量使用 h()，但 $url 完全未编码，也未做协议白名单
- 静态判读：证据已记录
- 动态验证：动态确认（verification `545525e2ec8c4080802e9031dd61bfbd`）
- 正式终审：独立批次 49b344472aea47ff95394c3a624c67a5；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧 URL：/account/profile.php?url=javascript%3Aalert(1)。HTTP 侧脚本作业 f8c2776d00f94636ba563e0308955f20 输出 ATTACK 200 True，即未编码的 javascript:alert(1) 出现在响应中；httponly 反射本身不算执行。浏览器作业 78d6ff7ba9fc49a3b9c993c06d99d43c 以 alice 会话加载同一路径，执行 document.getElementById('profile-link').click() 后宿主记录 dialogs=["1"]，即 javascript: URL 在页面上下文实际执行并弹出 alert(1)；页面标题为「个人主页预览 · 拾光商城」，console_errors 为空，截图 78d6ff7ba9fc49a3b9c993c06d99d43c-screenshot.png 留存。同页其它值(display_name)walkthrough 使用 h() 转义，仅 href 原样拼接，说明根因即源码 profile.php:2-3 的缺失编码/协议校验。

- 评分依据：CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：对 href 使用 h($url) 编码，并对协议做 http/https 白名单校验；不要回显任意 URL。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/account/profile.php:2-3`（sha256 `6f2406bbf636de04…`）

```php
    2  require __DIR__.'/../../src/bootstrap.php';$u=require_user();$url=(string)($_GET['url']??$u['homepage']);
    3  page('个人主页预览',function()use($u,$url){echo '<section class="panel"><h2>'.h($u['display_name']).' 的主页</h2><p><a id="profile-link" href="'.$url.'">访问个人主页</a></p><form method="get">';form_input('url','主页链接',$url);echo '<button>预览链接</button></form></section>';},'账户与会员');
```

`lab30-shop/app/public/account/update.php:4-6`（sha256 `b8227f19c05d0cd3…`）

```php
    4      check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    5      foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    6      if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
```

`lab30-shop/app/src/bootstrap.php:10-10`（sha256 `2050819d093be02b…`）

```php
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

### C-15 商品目录搜索参数 q 直接拼接进 SQL 导致 SQL 注入

- 当前版本：finding `514c84a170d043b7943d923e0d29517e` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/catalog/index.php:4`；文件：`lab30-shop/app/public/catalog/index.php`
- 证据引用：`1a6cc98ec16c37fd` lab30-shop/app/public/catalog/index.php:1-5；`a5097aecd2398250` lab30-shop/app/src/bootstrap.php:4-10
- 根因类别：task_goal:v2:29a271005f51d481b187:1（规范类型 sqli）

**结论陈述（模型产出，不是证据）**

catalog/index.php 第 3 行把 $_GET['q'] 转为字符串，第 4 行以字符串拼接方式构造 SELECT ... WHERE name LIKE '%<q>%' 并交给 db()->query()。bootstrap db() 使用 PDO 但该调用不是 prepare/execute，q 未经任何转义或白名单，引号可闭合 LIKE 字符串，从而改变 WHERE 条件或插入 UNION。查询结果在第 5 行被渲染，因此可利用页面差异或注入列回显做数据读取。h() 仅在输出阶段转义，不影响 SQL 解析。

- 攻击前身份与适用前提：数据库可用，products 表存在（由查询语句本身推断部署时存在）；无需登录
- 入口 → 传播 → 危险操作/状态变更：GET 参数 q（$_GET['q']） → $_GET['q'] -> (string) 强转赋值 $term -> 字符串拼接进 SELECT 文本 -> db()->query(...) 执行 -> fetchAll 结果随页面输出 → db()->query() 执行含请求数据的 SQL 文本
- 防护与边界：无参数化查询；仅 (string) 强转与输出端 h() 转义，均不能阻断 SQL 语义注入
- 静态判读：缺上下文（1 项）；缺失上下文：orders/detail.php、订单写入端点与 catalog/detail.php 的源码未在本次快照中显示，无法对其 SQL 构造与归属校验下结论。
- 动态验证：动态确认（verification `c34b49674ee04bdca244e1b9083b7983`）
- 正式终审：独立批次 08996df4f8d0422db3ff317d5f750233；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（未携带任何会话 Cookie 的 GET，job 845b26c3e1ea40d39128d6b9fd7f62bd）：q=' OR '1'='1' -- （URL 编码）使 result-count 从正常的 0/1 变为 4，返回全部四个商品，条件恒真；进一步 q=%' UNION SELECT 777,value,'union-leak',0,0,'sand' FROM settings WHERE `key`='internal_marker' -- 返回 COUNT 5，商品名列表末尾出现注入行 'SHOP_INTERNAL_77bcb2d132cb8ded1f798513'（MARKER 命中），即通过 UNION 从 settings 表读出了服务端内部标记并渲染到页面。审计作业 6b82f341bf984a44ad6edf2c7a737729 的等价 payload 亦显示 normal_count=0 / attack_count=4（页面为未登录导航，含「登录」「注册」）。

- 评分依据：CVSS 3.1 Base 8.6 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：改为 $q = db()->prepare('SELECT ... WHERE name LIKE ? ORDER BY id'); $q->execute(['%' . $term . '%']);，并对 LIKE 通配符做转义（ESCAPE），禁止将请求数据拼接进 SQL 文本。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/catalog/index.php:1-5`（sha256 `e85bd1c2fa6a4b78…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';
    3  $term=(string)($_GET['q']??'');
    4  $products=db()->query("SELECT id,name,description,price,stock,color FROM products WHERE name LIKE '%".$term."%' ORDER BY id")->fetchAll();
    5  page('本季好物',function()use($products,$term){echo '<form class="search-form" method="get"><input aria-label="搜索商品" name="q" placeholder="搜索你喜欢的好物" value="'.h($term).'"><button>搜索</button></form><p class="muted">共找到 <span id="result-count">'.count($products).'</span> 件商品</p><div class="products">';foreach($products as $p)echo '<article class="product"><div class="product-art '.h($p['color']).'"><svg viewBox="0 0 240 220" role="img" aria-label="'.h($p['name']).'"><use href="/assets/products.svg#product-'.(int)$p['id'].'"></use></svg></div><div class="product-copy"><small>拾光 · 日常系列</small><h2>'.h($p['name']).'</h2><p>'.h($p['description']).'</p><div class="row"><strong>¥'.h($p['price']).'</strong><a class="button secondary" href="/catalog/detail.php?id='.(int)$p['id'].'">查看商品 →</a></div></div></article>';echo '</div><a href="/catalog/greeting.php">查看到店欢迎信息</a>';},'商品目录');
```

`lab30-shop/app/src/bootstrap.php:4-10`（sha256 `2050819d093be02b…`）

```php
    4  function db(): PDO {
    5      static $pdo;
    6      if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    7      return $pdo;
    8  }
    9  function data_dir(): string { return getenv('SHOP_DATA_DIR') ?: '/var/lib/shop'; }
   10  function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
```

### C-16 support/download.php 用户可控 file 参数拼接路径导致路径遍历任意文件读取

- 当前版本：finding `4969e168d8b0497a884adc3b295b2969` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/support/download.php:3`；文件：`lab30-shop/app/public/support/download.php`
- 证据引用：`10c0c8123072e718` lab30-shop/app/public/support/download.php:2-3；`f5faf41dff9a5a91` lab30-shop/app/src/bootstrap.php:9-9
- 根因类别：task_goal:v2:167afbbdc66fae9aa5bd:1（规范类型 path_traversal）

**结论陈述（模型产出，不是证据）**

download.php 第 3 行取 $_GET['file'] 直接追加到 data_dir().'/docs/' 后交给 is_file/file_get_contents，未使用 basename、realpath 或白名单限定，允许 ../../ 逃出 docs 目录读取任意可读文件。

- 攻击前身份与适用前提：攻击者拥有登录会话
- 入口 → 传播 → 危险操作/状态变更：GET 参数 file → $_GET['file'] -> (string) -> data_dir().'/docs/'.file -> is_file -> file_get_contents -> echo → file_get_contents($path) 并把内容输出到响应
- 防护与边界：仅 require_user() 登录检查与 is_file 存在性检查，无路径规范化或白名单
- 静态判读：证据已记录
- 动态验证：动态确认（verification `a480c33bb7574c82ae6c1abb406a951a`）
- 正式终审：独立批次 08996df4f8d0422db3ff317d5f750233；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（同一 alice 会话，job 4d0c0956aed041f68ec796b5515502d3）：file=../vault/internal.txt 返回 200 且正文为 SHOP_INTERNAL_42b45b976d56e902e3a20053，即路径逃出 docs 目录读到 data_dir/vault 下文件；file=../../../../etc/passwd 返回 200 且正文为 root:x:0:0:root:/root:/bin/bash、daemon:… 等系统文件内容（PASSWD True）。目录穿越与任意文件读取成立。

- 评分依据：CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 basename() 或 realpath 后校验前缀等于 data_dir().'/docs/'，并拒绝分隔符与 '..'；或改用固定白名单映射。

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

### C-17 ops/template-render.php 对模板表达式 eval 导致任意 PHP 代码执行

- 当前版本：finding `6ffea81f95e642cb9969bcc88369d326` revision 1（项目版本 24）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/template-render.php:3`；文件：`lab30-shop/app/public/ops/template-render.php`
- 证据引用：`136d02a92a08ac98` lab30-shop/app/public/ops/template-render.php:1-4；`415907ec6bf2f739` lab30-shop/app/src/bootstrap.php:40-40
- 根因类别：task_goal:v2:1c98348f04ece3e40447:1（规范类型 code_execution）

**结论陈述（模型产出，不是证据）**

ops/template-render.php 第3行用 preg_replace_callback 匹配 {{...}} 后把内容拼成 'return '.$m[1].';' 交给 eval。模板取自 $_POST['template']，check_csrf 只防伪造不限制内容；提交 {{ system('id') }} 即执行任意 PHP 代码。

- 攻击前身份与适用前提：持有 operator/admin 账号并携带有效 csrf 提交 POST
- 入口 → 传播 → 危险操作/状态变更：$_POST['template'] → $template=(string)($_POST['template']??'') -> preg_replace_callback -> eval('return '.$m[1].';') → eval 动态代码执行
- 防护与边界：仅 check_csrf 与角色校验，无表达式白名单或沙箱
- 静态判读：证据已记录
- 动态验证：动态确认（verification `451e38e003dd4b628b991d991abe75b9`）
- 正式终审：独立批次 f71a209425af4ef1acf1220e9dfac4f0；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（同一 operator 会话，job 612d8872155b408d97a0a1aaaac3f7e8）：POST template={{ system('id; echo LAB30_EVAL_MARK_9c2f41') }} 返回 200；响应在 HTML 之前直接输出了 uid=33(www-data) gid=33(www-data) groups=33(www-data)（ATTACK_UID_PRESENT True），<pre> 内容为 ['LAB30_EVAL_MARK_9c2f41']（ATTACK_MARKER_PRESENT True），该唯一标记仅由攻击模板产生。即 eval('return '.$m[1].';') 执行了任意 PHP 代码并以 Web 服务账户调用系统命令，代码执行成立。请求使用从表单页面实际取得的 csrf 令牌（FORM 200 csrf）。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：移除 eval，改用受限表达式解析器与白名单运算。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/template-render.php:1-4`（sha256 `357da9e9959275d8…`）

```php
    1  <?php
    2  require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$template=(string)($_POST['template']??'');$result='';
    3  if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$result=preg_replace_callback('/\{\{(.*?)\}\}/s',function($m){return (string)eval('return '.$m[1].';');},$template);}
    4  page('营销内容排版',function()use($template,$result){echo '<section class="panel"><p>在双花括号内填写表达式，预览输出内容。</p><form method="post">'.csrf_field().'<label>模板<textarea name="template" required>'.h($template?:'本周精选，共 {{ 2 + 2 }} 款好物').'</textarea></label><button>生成预览</button></form><pre>'.h($result).'</pre></section>';},'运营工作台');
```

`lab30-shop/app/src/bootstrap.php:40-40`（sha256 `2050819d093be02b…`）

```php
   40  function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
```

### C-18 ops/url-preview.php 将 GET url 直接传给 file_get_contents 导致 SSRF

- 当前版本：finding `f7763e4792fd477ca30e8b71b0563e8d` revision 1（项目版本 23）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/url-preview.php:3`；文件：`lab30-shop/app/public/ops/url-preview.php`
- 证据引用：`924ff7a637feffe5` lab30-shop/app/public/ops/url-preview.php:1-4；`6220461f4c36cb1a` lab30-shop/app/src/bootstrap.php:33-36
- 根因类别：task_goal:v2:d1bee9eb363714f16a9c:1（规范类型 ssrf）

**结论陈述（模型产出，不是证据）**

url-preview.php 第2行取 GET 参数 url，第3行在非空时直接 `@file_get_contents($url,false,$context,0,65536)`，上下文仅设置 timeout=4 和 follow_location=0，未限制协议、主机或内网地址，结果第4行经 h() 回显。operator/admin 登录者可让服务器请求任意 URL（含内网/localhost），读取响应前 64KB，形成 SSRF。

- 攻击前身份与适用前提：持有 operator 或 admin 登录会话，访问 /ops/url-preview.php?url=<目标>
- 入口 → 传播 → 危险操作/状态变更：GET 参数 url → $_GET['url'] -> (string) -> $url -> file_get_contents($url,...) -> $output -> h($output) 回显 → file_get_contents 抓取用户指定 URL
- 防护与边界：仅设置超时与不跟随重定向，无协议/主机/IP 白名单；@ 抑制错误但不阻断请求
- 静态判读：缺上下文（2 项）；缺失上下文：allow_url_include 运行时配置值（决定 template-preview 的 RFI 可行性）；url-preview 可达网络拓扑与内网地址可访问性（影响 SSRF 实际影响面）
- 动态验证：动态确认（verification `b0b52085e3d849b5933d7655adf23fe1`）
- 正式终审：独立批次 f71a209425af4ef1acf1220e9dfac4f0；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（同一 operator 会话，job da57f5487e4a47209e78a18a87bfe256）：url=http://127.0.0.1/ 与 url=http://localhost/ 均返回 200，<pre> 长度为 3493，内容为服务端自身的商城 HTML（h() 转义后呈 &lt;!doctype html&gt;…，含「拾光商城」），证明服务器向回环地址发起请求并回显响应；url=file:///var/lib/shop/vault/internal.txt 返回 200，<pre> 为 SHOP_INTERNAL_c3b5c4de0a252b4f532b471f，说明协议也未受限，可直接读取服务器本地文件。任意 URL 抓取（含内网/环回）与本地文件读取成立。

- 评分依据：CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：对 URL 做协议与主机白名单，解析后拒绝内网/环回地址，或改为代理到受控固定上游。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/public/ops/url-preview.php:1-4`（sha256 `e495938b10c455c6…`）

```php
    1  <?php
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

### C-19 ops/ping.php 将 host 参数拼接进 shell_exec 导致命令注入

- 当前版本：finding `2ca0b026800e417393d38ab57b1df807` revision 1（项目版本 3）；CVSS 评分版本 1
- 位置：`lab30-shop/app/public/ops/ping.php:2`；文件：`lab30-shop/app/public/ops/ping.php`
- 证据引用：`61f200eb89320676` lab30-shop/app/public/ops/ping.php:1-3；`65fc5323ae7c9b98` lab30-shop/app/src/host_check.php:1-2；`a41ee4811beeaf1b` lab30-shop/app/public/ops/batch-check.php:1-3；`78224482780bf94a` lab30-shop/app/src/bootstrap.php:33-37
- 根因类别：task_goal:v2:7a5382999ceee4a99bde:1（规范类型 command_injection）

**结论陈述（模型产出，不是证据）**

ops/ping.php 第2行取 $_GET['host'] 后未过滤直接拼接到 'ping -c 1 -W 1 '.$host 交给 shell_exec。operator/admin 登录用户提交 host=127.0.0.1;id 即可执行任意系统命令，输出经 h() 回显页面。相同 sink 亦在 host_check.php 第2行由 batch-check.php 复用。

- 攻击前身份与适用前提：持有 operator 或 admin 登录账号，GET /ops/ping.php
- 入口 → 传播 → 危险操作/状态变更：$_GET['host'] → $host=(string)($_GET['host']??'') -> 拼接 'ping -c 1 -W 1 '.$host -> shell_exec → shell_exec 执行拼接后的系统命令
- 防护与边界：仅 require_user(['operator','admin']) 角色校验，无 escapeshellarg/白名单
- 静态判读：证据已记录
- 动态验证：动态确认（verification `e8e0f6e58ab846f0988c1b3df492796c`）
- 正式终审：独立批次 f71a209425af4ef1acf1220e9dfac4f0；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

攻击侧（同一 operator 会话，同作业 d66d623addd1472ea794bf765cb2c88d）：GET /ops/ping.php?host=127.0.0.1%3Bid%3Becho%20LAB30_CI_MARK_7f3a91 返回 200，<pre id="diagnostic-output"> 中除正常 ping 统计外追加了 uid=33(www-data) gid=33(www-data) groups=33(www-data) 与仅由攻击请求产生的唯一标记 LAB30_CI_MARK_7f3a91，ATTACK_MARKER_PRESENT True、ATTACK_UID_PRESENT True。即拼接的 shell 命令在服务端以 www-data 身份执行，命令注入成立。

- 评分依据：CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 escapeshellarg 并校验主机名/IP，或改用 proc_open 数组参数、纯 PHP 连接探测。

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

### C-20 reset_shop() 使用 MD5 存储硬编码初始口令（含 admin）

- 当前版本：finding `e40ed71d3c3d4da8956c2c8d839da9c1` revision 1（项目版本 1）；CVSS 评分版本 1
- 位置：`lab30-shop/app/src/setup.php:17`；文件：`lab30-shop/app/src/setup.php`
- 证据引用：`f86e0ebf4243b153` lab30-shop/app/src/setup.php:7-7；`80b30b229093e94e` lab30-shop/app/src/setup.php:16-17
- 根因类别：task_goal:v2:c7e35bf44ffa3abb09df:1（规范类型 weak_crypto）

**结论陈述（模型产出，不是证据）**

src/setup.php 定义 users.password_md5 CHAR(32)，第 17 行以 md5($u[2]) 写入固定口令 Alice123!/Bob123!/Ops123!/Admin123!，初始账号角色包含 customer/operator/admin。MD5 无盐且快速，易被离线暴力破解；口令本身硬编码在源码中，可被任何读到源码或初始化库的人直接使用。

- 攻击前身份与适用前提：多用户环境或攻击者可读取源码/初始化库/执行 setup.php/reset.php 一次后数据库中存在这些账号
- 入口 → 传播 → 危险操作/状态变更：源码/初始化数据库中的硬编码初始口令 → reset_shop() -> INSERT INTO users -> 后续登录 → md5() 存储密码，硬编码 admin 口令
- 防护与边界：无盐、无慢哈希（无 password_hash），无强制改密
- 静态判读：证据已记录
- 动态验证：动态确认（verification `f0a1470ba714495082532e688b5d4643`）
- 正式终审：独立批次 4203d05ed35c46f28cf3ad570d217a65；处置：已接受——独立终审批次接受源码结论；动态验证状态单独保留

**实际影响（来自动态验证观测）**

判别性观测（不发送伪造请求，因为该弱点在凭据存储本身）：job 6e7f3420708446e6aff61c88756469b9 以宿主提供的 alice 密码计算 md5，结果与源码常量 Alice123! 的 md5 完全相等（MD5_MATCHES_HARDCODED_ALICE123 True，而与 Bob123! 不等）；job d2e63460da5a43a7825eb27adeb61030 以宿主提供的 admin 密码计算 md5，与源码常量 Admin123! 的 md5 完全相等（MD5_MATCHES_HARDCODED_ADMIN123 True），且该会话可直接以 admin 角色读取 /ops/users.php（USERS_ACCESS admin，返回 alice/bob/operator/admin 四个账号与角色）。结合 login.php:7 的 hash_equals($row['password_md5'], md5($_POST['password']))，登录成功即意味着库中 password_md5 恰为 md5(明文密码)，且明文密码与 setup.php:17 硬编码常量一致——即任何读到源码的人可直接得到 admin 账号的实时口令。

- 评分依据：CVSS 3.1 Base 9.4 (critical) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L；引擎 cvss31-base-1；适用结论版本 1
- 修复方案（结论陈述）：使用 password_hash()/password_verify()（bcrypt/argon2），移除硬编码口令，改为初始化时随机生成或强制首次登录改密，并加密盐值。

**源码片段（宿主从冻结快照读取）**

`lab30-shop/app/src/setup.php:7-7`（sha256 `53e7dc7286d7d370…`）

```php
    7      $pdo->exec("CREATE TABLE IF NOT EXISTS users(id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(60) UNIQUE NOT NULL, password_md5 CHAR(32) NOT NULL, display_name VARCHAR(100) NOT NULL, email VARCHAR(200) NOT NULL, role VARCHAR(24) NOT NULL DEFAULT 'customer', balance DECIMAL(12,2) NOT NULL DEFAULT 100, tier VARCHAR(30) NOT NULL DEFAULT 'standard', nickname VARCHAR(200) NOT NULL, homepage VARCHAR(500) NOT NULL DEFAULT '#')");
```

`lab30-shop/app/src/setup.php:16-17`（sha256 `53e7dc7286d7d370…`）

```php
   16      $q=$pdo->prepare('INSERT INTO users(id,username,password_md5,display_name,email,role,balance,tier,nickname) VALUES(?,?,?,?,?,?,100,?,?)');
   17      foreach ([[1,'alice','Alice123!','林晓','alice@shop.local','customer'],[2,'bob','Bob123!','陈远','bob@shop.local','customer'],[3,'operator','Ops123!','运营同事','ops@shop.local','operator'],[4,'admin','Admin123!','系统管理员','admin@shop.local','admin']] as $u) $q->execute([$u[0],$u[1],md5($u[2]),$u[3],$u[4],$u[5],'standard',$u[1]]);
```

## 5. 实际验证和终审理由

### C-01 partner/portal.php 仅 base64 解码 JWT payload 而不校验签名，任意用户伪造 role=admin 读取全部订单结算数据

- verification `bfdab048b1654fbaa217c7b2ffcc6a00`（finding `2450f5eb14b94063bae1850f8e1b0af4` revision 1，context `49bdfbefd1484a9d8efce151280e4ce0`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（job 1744831dacf8436eacf84bd6a8aee4a0）：以 alice 登录后 GET /partner/token.php（Accept: application/json）取得服务端签发的三段 token，其中 payload 解码为 {"sub":1,"role":"customer","name":"alice"}；将该真实 token POST 到 /partner/portal.php 返回 403「此合作方功能仅向管理员开放。」；伪造 payload 为 role=user 的 token 同样返回 403。
  - 攻击侧观测：攻击侧（job 1744831dacf8436eacf84bd6a8aee4a0）：构造三段 token = base64url({"alg":"HS256","typ":"JWT"}) + '.' + base64url({"sub":1,"role":"admin","name":"partner"}) + '.sig'（第三段为任意串，未做任何真实签名），POST /partner/portal.php 返回 200，JSON 为 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}，即无签名校验地取得全表订单结算数据。对照：token.php 签发的真实 token（payload 为 {"sub":1,"role":"customer","name":"alice"}，三部分完整）POST 后返回 403；伪造 role=user 也返回 403。此前审计作业 f005c810632d4d0eaac569e4f9e04937 两次 403 是其 token 构造只有 2 段/4 段导致 payload 解析失败（'xxx.e30.sig' 的第二段即 'e30'），并非漏洞不存在；修正为正确三段后攻击成立。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`f005c810632d4d0eaac569e4f9e04937`；`1744831dacf8436eacf84bd6a8aee4a0`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`1744831dacf8436eacf84bd6a8aee4a0` script finished exit=0；`f005c810632d4d0eaac569e4f9e04937` script finished exit=0
  - 适配脚本：`bfdab048-adapted-partner_jwt_forge.py`（见证据包 evidence/）
  - 备注：真实签名 token、伪造 user、伪造 admin 三组请求在同一作业内，仅 payload/签名不同；判定依据是响应角色与订单数组内容，而非状态码单独。伪造请求可由未登录者发出（portal.php 未调用 require_user，仅读取 POST token/Cookie）。未使用 admin 账号，因此不是以特权身份冒充普通会员。审计作业的 403 结果已解释为脚本构造缺陷。

- 正式复核 `b74ed32f6e2c484ba69f3dd34046da4e`：复核确认；引用 revision 1 / verification `bfdab048b1654fbaa217c7b2ffcc6a00`
  - 理由：正常侧（job 1744831dacf8436eacf84bd6a8aee4a0）：alice 登录后取得的服务端签发 token payload 为 {"sub":1,"role":"customer"}，POST 到 portal.php 返回 403，伪造 role=user 亦 403。攻击侧：自造三段 token（payload role=admin，第三段任意签名）POST 返回 200 并输出 orders 全表结算数据 SG-1001 129.00、SG-1002 158.00。两侧观测与 portal.php:2-6 缺乏签名校验、仅依赖客户端 claims 授权的根因一致，越权读取成立，确认该验证结论。
  - 复核观测：正常侧 正常侧（job 1744831dacf8436eacf84bd6a8aee4a0）：以 alice 登录后 GET /partner/token.php（Accept: application/json）取得服务端签发的三段 token，其中 payload 解码为 {"sub":1,"role":"customer","name":"alice"}；将该真实 token POST 到 /partner/portal.php 返回 403「此合作方功能仅向管理员开放。」；伪造 payload 为 role=user 的 token 同样返回 403。；攻击侧 攻击侧（job 1744831dacf8436eacf84bd6a8aee4a0）：构造三段 token = base64url({"alg":"HS256","typ":"JWT"}) + '.' + base64url({"sub":1,"role":"admin","name":"partner"}) + '.sig'（第三段为任意串，未做任何真实签名），POST /partner/portal.php 返回 200，JSON 为 {"role":"admin","settlements":[{"order_no":"SG-1001","total":"129.00"},{"order_no":"SG-1002","total":"158.00"}]}，即无签名校验地取得全表订单结算数据。对照：token.php 签发的真实 token（payload 为 {"sub":1,"rol…

### C-02 account/update.php 批量赋值允许普通用户将自身 role/balance/tier 写为任意值（自我提权）

- verification `fbf7eefa06404ce4a958e4a6fc339057`（finding `8d351dc371a74ee99ba7542713dde029` revision 1，context `624bff9370a34f7492ff90b7f6d2fc02`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：同一会话先 GET /account/update.php 取到真实 csrf 令牌(csrf True)，随后只提交表单可见字段 display_name=normalname(附带 role=user，与原值相同) 的正常请求返回 200，页面为「会员资料维护」，无报错；该阶段宿主前置状态为 role=customer、balance=100.00、tier=standard。
  - 攻击侧观测：同一脚本随后提交 csrf + display_name=pwned&role=admin&balance=999999&tier=gold，返回 200。宿主对作业 4608e524a20646eebe7ecfb7dc61c67c 的 postcondition 显示：alice 的 role 由 customer 变为 admin、balance 由 100.00 变为 999999.00、tier 由 standard 变为 gold，reason=identity_or_role_mismatch，state_changes 明确列出这三个字段的 before/after。即攻击侧越过了表单可见字段边界，直接改写权限与资金列。补充：脚本对 /ops/index.php 的字符串检查输出 'OPS 200 False'，仅说明页面正文未出现字面量 admin，不作为越权可见性证据；权限提升本身由数据库列变化与宿主前提判定证实。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`4608e524a20646eebe7ecfb7dc61c67c`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`4608e524a20646eebe7ecfb7dc61c67c` script finished exit=0
  - 适配脚本：`fbf7eefa-adapted-poc_mass_assignment.py`（见证据包 evidence/）
  - 备注：单一作业内完成正常/攻击对照：正常请求仅改显示名；攻击请求后宿主 postcondition 与 state_changes 记录 role/balance/tier 三项被改写。OPS 访问检查的字符串命中失败(False)，未作为影响证据；未重跑同一脚本以避免重复副作用，也未在 alice 已变为 admin 后追加依赖 customer 前提的实验。

- 正式复核 `f76a52e2741644e3abd5283360c31aa6`：复核确认；引用 revision 1 / verification `fbf7eefa06404ce4a958e4a6fc339057`
  - 理由：正常侧（job 4608e524a20646eebe7ecfb7dc61c67c）：同一会话取到真实 csrf 后仅提交可见字段返回 200，前置状态 role=customer、balance=100.00、tier=standard。攻击侧：额外提交 role=admin&balance=999999&tier=gold 返回 200，宿主 postcondition 记录三项字段自 customer/100.00/standard 变为 admin/999999.00/gold 并判 identity_or_role_mismatch。观测与 update.php:4-6 白名单含敏感列且入口无角色校验的根因一致，自我提权成立，确认该验证结论。
  - 复核观测：正常侧 同一会话先 GET /account/update.php 取到真实 csrf 令牌(csrf True)，随后只提交表单可见字段 display_name=normalname(附带 role=user，与原值相同) 的正常请求返回 200，页面为「会员资料维护」，无报错；该阶段宿主前置状态为 role=customer、balance=100.00、tier=standard。；攻击侧 同一脚本随后提交 csrf + display_name=pwned&role=admin&balance=999999&tier=gold，返回 200。宿主对作业 4608e524a20646eebe7ecfb7dc61c67c 的 postcondition 显示：alice 的 role 由 customer 变为 admin、balance 由 100.00 变为 999999.00、tier 由 standard 变为 gold，reason=identity_or_role_mismatch，state_changes 明确列出这三个字段的 before/after。即攻击侧越过了表单可见字段边界，直接改写权限与资金列。补充：脚本对 /ops/index.php 的字符串检查输出 'OPS 200 False'，仅说明页面正文未出现字面量 admin，不作为越权可见性证据；权…

### C-03 support/messages.php 留言内容未转义输出导致存储型 XSS

- verification `479fa77d8fca449e80bc11fb319cfa07`（finding `cd3a4d574a174fc2a17410c024d39300` revision 1，context `d32f8f94c2524077bc2c63b9c5d5bf01`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（job b42d9e1da57f4e34bb7fb6aeff194418 与 browser job fc32b411688c4f2f897d6203b8b11ca3）：alice 取真实 csrf 后提交普通留言「POC_NORMAL_MSG_9f21 请帮忙确认发货时间。」返回 200 并跳回留言页，页面原样显示该文本且不含任何 script 标签（NO_SCRIPT_TAGS_IN_PAGE True）。此时浏览器加载 /support/messages.php 的 dialogs 为空数组、console_errors 为空，页面正常显示该留言及预置留言。
  - 攻击侧观测：攻击侧（job bba80ab0fd96458685961c83d0fd0d4e + browser job 889b6122d09345289b23cf51af25fa25，同一 alice 会话）：POST message=&lt;script&gt;alert('POC_XSS_9f21')&lt;/script&gt; 返回 200；响应 HTML 中 message-body 为 <div class="message-body"><script>alert('POC_XSS_9f21')</script></div>（RAW_SCRIPT_PRESENT True，ESCAPED_SCRIPT_PRESENT False），即未转义存储。随后 browser_check 以 alice 加载 /support/messages.php，宿主记录 dialogs=["POC_XSS_9f21"]，脚本在浏览器实际执行；对应留言在 body_text 中呈现为空条目（时间为 2026-10-30 12:11:35）。
  - 已保存作业事实：4 个；满足执行及前提检查的作业：4 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`b42d9e1da57f4e34bb7fb6aeff194418`；`fc32b411688c4f2f897d6203b8b11ca3`；`bba80ab0fd96458685961c83d0fd0d4e`；`889b6122d09345289b23cf51af25fa25`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`bba80ab0fd96458685961c83d0fd0d4e` script finished exit=0；`889b6122d09345289b23cf51af25fa25` browser finished exit=0；`b42d9e1da57f4e34bb7fb6aeff194418` script finished exit=0；`fc32b411688c4f2f897d6203b8b11ca3` browser finished exit=0
  - 产物：`479fa77d8fca449e80bc11fb319cfa07-fc32b411688c4f2f897d6203b8b11ca3-screenshot.png`；`479fa77d8fca449e80bc11fb319cfa07-889b6122d09345289b23cf51af25fa25-screenshot.png`
  - 适配脚本：`479fa77d-adapted-poc.php`（见证据包 evidence/）
  - 备注：正常与攻击在同一 alice 会话内依次完成：先正常留言并做浏览器对照，再投递脚本留言并再次浏览器观测，页面内容仅多出攻击留言，归因清晰。攻击侧执行证据为 dialogs=["POC_XSS_9f21"]，HTTP 反射/原样标签仅作传播链路佐证。原始页面另含 setup 预置留言（陈远/林晓），未被触发。未验证跨用户浏览场景（数据库中存储内容对任何打开留言页的登录用户生效）。

- 正式复核 `059079d861bc41a2b90551689497e36a`：复核确认；引用 revision 1 / verification `479fa77d8fca449e80bc11fb319cfa07`
  - 理由：已完整读取该验证记录的 normal_observation 与 attack_observation：正常侧 alice 提交普通留言后返回 200、页面原样显示且 NO_SCRIPT_TAGS_IN_PAGE True、dialogs 与 console_errors 为空；攻击侧同一 alice 会话提交 <script>alert('POC_XSS_9f21')</script> 后响应含未转义标签（RAW_SCRIPT_PRESENT True、ESCAPED_SCRIPT_PRESENT False），浏览器加载留言页实际执行 dialogs=[POC_XSS_9f21]，与 messages.php:5 未对 $row['message'] 调用 h() 的静态证据一致，存储型 XSS 成立。
  - 复核观测：正常侧 正常侧（job b42d9e1da57f4e34bb7fb6aeff194418 与 browser job fc32b411688c4f2f897d6203b8b11ca3）：alice 取真实 csrf 后提交普通留言「POC_NORMAL_MSG_9f21 请帮忙确认发货时间。」返回 200 并跳回留言页，页面原样显示该文本且不含任何 script 标签（NO_SCRIPT_TAGS_IN_PAGE True）。此时浏览器加载 /support/messages.php 的 dialogs 为空数组、console_errors 为空，页面正常显示该留言及预置留言。；攻击侧 攻击侧（job bba80ab0fd96458685961c83d0fd0d4e + browser job 889b6122d09345289b23cf51af25fa25，同一 alice 会话）：POST message=&lt;script&gt;alert('POC_XSS_9f21')&lt;/script&gt; 返回 200；响应 HTML 中 message-body 为 <div class="message-body"><script>alert('POC_XSS_9f21')</script></div>（RAW_SCRIPT_PRESENT True，ESCAPED_SCRIPT_PRESENT False），即未转义存储。随后 browser_check 以 alice 加载 /support/messages.php，宿主记录 dialogs=["POC_XS…

### C-04 account/backup.php 在校验前对用户 base64 数据执行 unserialize，导致 PHP 对象注入

- verification `e226eb97145e41cdab43413628ee72cf`（finding `f9905b9698ff46aa9ef4e23f1c73ad48` revision 1，context `420259c8c00840428eee591ce1fe7df8`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（job 4528de3454a44a91b6f2f52c76f95260）：页面下发的合法备份解码后为 O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:5:"pwned";}（即当前账号自身状态，precondition 中 tier 已因先前审计作业为 gold）。原样提交该导出恢复返回 200 并提示「会员备份已恢复」（NORMAL_STATUS 200 NOTICE True），随后 /account/index.php 仍是 (gold, pwned)，与提交前完全一致，属页面自带的正常备份往返。
  - 攻击侧观测：攻击侧（同一 alice 会话，job 4528de3454a44a91b6f2f52c76f95260）：提交 base64(O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:8:"PWN_9f21";}) 返回 200 并提示「会员备份已恢复」；随后 /account/index.php 的 badge 与姓名由 (gold, pwned) 变为 (gold, PWN_9f21)，MARKER_VISIBLE True，即攻击者伪造的属性被 unserialize 还原并原样写入第6行的 UPDATE。辅助对照：提交 base64 的数组序列化 a:1:{s:3:"tier";s:4:"gold";} 返回 400「不是有效的会员备份」，说明用户可控序列化数据确实先进入 unserialize，随后才被 instanceof 拦截。审计作业 84685f8a71594ecebc2cd95becb6465b 的同类伪造负载亦使 alice tier 由 standard 变为 gold（宿主 state_changes）。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`84685f8a71594ecebc2cd95becb6465b`；`4528de3454a44a91b6f2f52c76f95260`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`4528de3454a44a91b6f2f52c76f95260` script finished exit=0；`84685f8a71594ecebc2cd95becb6465b` script finished exit=0
  - 适配脚本：`e226eb97-adapted-backup_unserialize.py`（见证据包 evidence/）
  - 备注：正常/攻击/非 MemberBackup 对照均在同一作业内，使用同一 csrf 与同一会话。已证部分：用户可控 base64 → unserialize（无可信 allowed_classes）→ instanceof 事后校验 → 属性驱动 UPDATE，攻击者可任意指定自身 tier/display_name。未证部分：未找到并触发任何带 __wakeup/__destruct 的应用类，因此「任意类实例化/魔术方法执行（gadget chain）」只有潜在可能，未计入结论。job 4528de3454a44a91b6f2f52c76f95260 的 precondition 已因审计作业使 tier=gold，属 state_drift，不是本次攻击造成。

- 正式复核 `6e09e518f32c476f901bbcb331268ea0`：复核确认；引用 revision 1 / verification `e226eb97145e41cdab43413628ee72cf`
  - 理由：已完整读取该验证记录的 normal_observation 与 attack_observation：正常侧提交页面自带备份解码为 O:12:"MemberBackup" 往返后账号状态 (gold, pwned) 不变；攻击侧提交伪造序列化对象后备份被接受、PWN_9f21 写库并在 /account/index.php 可见（MARKER_VISIBLE True），非 MemberBackup 数组返回 400 说明其已进入 unserialize 才被拦截；与 backup.php:5 先 unserialize 后 instanceof 的静态证据一致，不安全反序列化与属性篡改成立，结论已明确不宣称 gadget 链执行。
  - 复核观测：正常侧 正常侧（job 4528de3454a44a91b6f2f52c76f95260）：页面下发的合法备份解码后为 O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:5:"pwned";}（即当前账号自身状态，precondition 中 tier 已因先前审计作业为 gold）。原样提交该导出恢复返回 200 并提示「会员备份已恢复」（NORMAL_STATUS 200 NOTICE True），随后 /account/index.php 仍是 (gold, pwned)，与提交前完全一致，属页面自带的正常备份往返。；攻击侧 攻击侧（同一 alice 会话，job 4528de3454a44a91b6f2f52c76f95260）：提交 base64(O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:8:"PWN_9f21";}) 返回 200 并提示「会员备份已恢复」；随后 /account/index.php 的 badge 与姓名由 (gold, pwned) 变为 (gold, PWN_9f21)，MARKER_VISIBLE True，即攻击者伪造的属性被 unserialize 还原并原样写入第6行的 UPDATE。辅助对照：提交 base64 的数组序列化 a:1:{s:3:"tier";s:4:"gold";} 返回 400「不是有效的会员备份」，说明用户可控序列化数据确实先进入 unserialize，随后才被 …

### C-05 wallet/withdraw.php 提现余额校验与扣减非原子，可并发超额提现

- verification `9b0215f14cf74f3bbb61aaec7fd919ed`（finding `828f0388116b4678b4e0012243032ee2` revision 1，context `64e59543f4b24fe385ce405e7b717ad7`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（job 11fc94d7584c44548ffc7b5a04ea1871，同一 alice 会话）：BEFORE 为 balance 90.00、count 5、withdrawn_total 50；单个 POST /wallet/withdraw.php amount=10 返回 200 {"status":"paid","amount":10,"balance":80,"receipt_id":6}；随后读取 /wallet/index.php（Accept: application/json）为 balance 80.00、count 6、withdrawn_total 60，即单次请求恰好新增 1 条记录并扣减 10.00，行为正常。
  - 攻击侧观测：攻击侧（同 job 11fc94d7584c44548ffc7b5a04ea1871）：在余额 80.00、记录 6 条（合计 60）时并发提交 4 个 amount=10 提现请求，4 个响应均为 200 且各自返回 {"status":"paid","amount":10,"balance":70,"receipt_id":7/8/9/10}（receipt 7,8,9,10 全部生成）。随后 /wallet/index.php（Accept: application/json）为 balance 70.00、count 10、withdrawn_total 100：新增 4 条提现记录共 40.00，但余额只从 80.00 减到 70.00（仅扣 10.00），即多提现 30.00，超额提现成立。宿主 postcondition 也记录 90.00→70.00。审计作业 e27db6dc8b414d3d81b09f21c7cc5f09 的 5 并发同型实验（全部 200）后 postcondition 余额 100.00→90.00，与上述非原子写回一致。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`e27db6dc8b414d3d81b09f21c7cc5f09`；`11fc94d7584c44548ffc7b5a04ea1871`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`11fc94d7584c44548ffc7b5a04ea1871` script finished exit=0；`e27db6dc8b414d3d81b09f21c7cc5f09` script finished exit=0
  - 适配脚本：`9b0215f1-adapted-race_withdraw.py`（见证据包 evidence/）
  - 备注：正常与攻击对照在同一作业内完成，判定依据是 withdrawals 记录数与 withdrawn_total 相对余额变化，而不是状态码。BEFORE 的 90.00/5 条/50.00 是审计作业 5 并发后的残留状态，已在正常对照前作为旁证记录。金额与记录均来自应用自身 /wallet/index.php 的 JSON 输出。未验证并发数更大时能否超过可用余额上限；结论限于已观测的非原子读-改-写导致的多笔入账、单次扣款。

- 正式复核 `ea549ed019c64a049c14ba78bdfa4968`：复核确认；引用 revision 1 / verification `9b0215f14cf74f3bbb61aaec7fd919ed`
  - 理由：已完整读取该验证记录的 normal_observation 与 attack_observation：正常侧单次提现 10 后记录 +1、余额 90→80；攻击侧 4 个并发请求均 200 且生成 receipt 7/8/9/10，记录 6→10、withdrawn_total 60→100 而余额仅 80→70，多入账 30.00，宿主 postcondition 及独立 5 并发作业一致；与 withdraw.php:4-8 无锁读-改-写及 usleep 放大的静态证据吻合，并发超额提现成立。
  - 复核观测：正常侧 正常侧（job 11fc94d7584c44548ffc7b5a04ea1871，同一 alice 会话）：BEFORE 为 balance 90.00、count 5、withdrawn_total 50；单个 POST /wallet/withdraw.php amount=10 返回 200 {"status":"paid","amount":10,"balance":80,"receipt_id":6}；随后读取 /wallet/index.php（Accept: application/json）为 balance 80.00、count 6、withdrawn_total 60，即单次请求恰好新增 1 条记录并扣减 10.00，行为正常。；攻击侧 攻击侧（同 job 11fc94d7584c44548ffc7b5a04ea1871）：在余额 80.00、记录 6 条（合计 60）时并发提交 4 个 amount=10 提现请求，4 个响应均为 200 且各自返回 {"status":"paid","amount":10,"balance":70,"receipt_id":7/8/9/10}（receipt 7,8,9,10 全部生成）。随后 /wallet/index.php（Accept: application/json）为 balance 70.00、count 10、withdrawn_total 100：新增 4 条提现记录共 40.00，但余额只从 80.00 减到 70.00（仅扣 10.00），即多提现 30.00，超额提现成立。宿主 postcondition 也记录 90.00→70.00。审计作业 e27db6…

### C-06 orders/detail.php 按 id 直接读取订单且不校验 user_id，形成订单 IDOR（JSON 分支泄露备注）

- verification `acde04a0b9664d1b8eb85cc944d3e5b2`（finding `bc120a98aa3943b0aeb05fcff4c6ca64` revision 1，context `ba9dff1ec09c4abab2bbfee26aae2f31`，target lab30-shop-1.0.0）
  - 执行状态：执行失败；判定：不确定；来源：poc_agent
  - 正常侧观测：无有效正常侧观测。作业 d162c207ef9442329700a99a88b7387c 的 stdout 为空，stderr 为 AttributeError: 'NoneType' object has no attribute 'group'（在登录页解析 name="csrf" 时失败），exit_code=1；未完成登录，也未取得当前用户自身订单 id 的正常 JSON 返回。
  - 攻击侧观测：无有效攻击侧观测。作业 d162c207ef9442329700a99a88b7387c 在登录步骤之前即失败（exit_code=1，stderr AttributeError），未对 detail.php?id=1/2/3 发出任何 GET 请求，也没有可引用的 200 响应或 JSON 订单字段输出。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：0 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`d162c207ef9442329700a99a88b7387c`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`d162c207ef9442329700a99a88b7387c` script finished exit=1
  - 备注：静态依据（快照 586b79b41f8e4f59be80f2a9b548902b，applicability=match）：orders/detail.php L2 为 SELECT o.*,u.username,p.name FROM orders o JOIN users u ON u.id=o.user_id LEFT JOIN products p ON p.id=o.product_id WHERE o.id=?，仅 require_user() 登录校验，WHERE 不含 o.user_id 或当前用户 id，$o 不存在才返回 404；L3 当 Accept 含 application/json 时 json_response($o) 原样返回订单行（含 private_note、username、total 等），L4 HTML 分支仍输出这些字段。bootstrap.php L20-24 user() 按 $_SESSION['user_id'] 取当前用户，L33-37 require_user 仅判断登录与可选角色，未参与订单归属检查。以上为源码事实，尚缺本上下文动态对照。

### C-07 注册与登录使用无盐 md5 存储与校验口令

- verification `79deb349024548beb39fb3ff71f44bd0`（finding `a94a3b86a4874c2ea7ca50febea25973` revision 1，context `ca948f9a3c4d4af5aedd6788600acdd1`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：未登录即可访问 /auth/register.php 并成功注册新用户（REGISTER 200、SUCCESS_NOTICE True、无重名提示），随后用注册时的口令登录返回 200 并跳离登录页，/account/index.php 返回 200、页面含「退出」与用户名 pocd470a9f5，注册—登录正常流程可用；注册表单仅校验用户名格式与口令长度 ≥8（源码 register.php:6），无盐/无 password_hash。
  - 攻击侧观测：判别性观测（弱哈希的证据在存储/校验路径本身，而非某个越权请求）：以未登录（guest）身份在 /auth/register.php 新建账号 pocd470a9f5（REGISTER 200、SUCCESS_NOTICE True），注册源码 register.php:8 只写入 md5($password)。随后用同一明文口令登录成功（LOGIN_CORRECT 200 并跳离登录页），/account/index.php 200、含「退出」且显示该新用户名；而错误口令登录返回 401（LOGIN_WRONG 401，提示「账号或密码不正确」）。由于 login.php:7 唯一的判定是 hash_equals(password_md5, md5(输入))，登录成功即证明库中 password_md5 恰为 32 位 md5(明文)（本例 md5 计算值为 4e42bdc04f1fdc145c553a18ddf8e06d，LEN 32），未加盐、无慢哈希。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`a1682cecd77840619c5a95ed25217bf7`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`a1682cecd77840619c5a95ed25217bf7` script finished exit=0
  - 适配脚本：`79deb349-adapted-poc.php`（见证据包 evidence/）
  - 备注：未直接读取 users.password_md5 列（无授权读取接口，且未借助其他发现的漏洞取数）；md5 存储结论由 register.php:8 的写入方是唯一来源、login.php:7 的 md5 比较是唯一判定、以及新账号正确口令登录成功/错误口令 401 三点共同推出。未做离线破解速度基准；所用测试账号与口令为本次新建，不含真实用户口令。

- 正式复核 `f28b340d0d8e4c2bbf81910610a7bf70`：复核确认；引用 revision 1 / verification `79deb349024548beb39fb3ff71f44bd0`
  - 理由：已读取本次验证的 normal_observation 与 attack_observation：guest 注册新账号返回 200 且无重名提示，正确口令登录 200 并进入账户页显示用户名，错误口令 401，观测中 md5 结果为 32 位；与 register.php:8 写入 md5($password)、login.php:7 以 hash_equals 比对 md5 输入的唯一校验路径一致，无盐快速哈希成立。
  - 复核观测：正常侧 正常侧：未登录即可访问 /auth/register.php 并成功注册新用户（REGISTER 200、SUCCESS_NOTICE True、无重名提示），随后用注册时的口令登录返回 200 并跳离登录页，/account/index.php 返回 200、页面含「退出」与用户名 pocd470a9f5，注册—登录正常流程可用；注册表单仅校验用户名格式与口令长度 ≥8（源码 register.php:6），无盐/无 password_hash。；攻击侧 判别性观测（弱哈希的证据在存储/校验路径本身，而非某个越权请求）：以未登录（guest）身份在 /auth/register.php 新建账号 pocd470a9f5（REGISTER 200、SUCCESS_NOTICE True），注册源码 register.php:8 只写入 md5($password)。随后用同一明文口令登录成功（LOGIN_CORRECT 200 并跳离登录页），/account/index.php 200、含「退出」且显示该新用户名；而错误口令登录返回 401（LOGIN_WRONG 401，提示「账号或密码不正确」）。由于 login.php:7 唯一的判定是 hash_equals(password_md5, md5(输入))，登录成功即证明库中 password_md5 恰为 32 位 md5(明文)（本例 md5 计算值为 4e42bdc04f1fdc…

### C-08 订单创建信任客户端提交的 price，导致商品实付金额被任意压低

- verification `b470fcae64a94ee0af4d8d89bd063332`（finding `ee4a398ed1fc494fb97edf480a59daf7` revision 1，context `34d837058552489bbf6a832d1b76afbd`，target lab30-shop-1.0.0）
  - 执行状态：执行失败；判定：不确定；来源：poc_agent
  - 正常侧观测：无有效正常侧观测。作业 a6f2fb55386e42e0a5750c45a64616d7 的 stdout 为空，stderr 为 AttributeError: 'NoneType' object has no attribute 'group'（在登录页解析 csrf 时失败），exit_code=1；请求在登录、下单前终止，未取得任何正常价订单记录。
  - 攻击侧观测：无有效攻击侧观测。同一作业未发出 /orders/create.php 请求，未产生 price=0.01 的订单，也无订单中心或详情页的 unit_price/total 输出可引用。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：0 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`a6f2fb55386e42e0a5750c45a64616d7`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`a6f2fb55386e42e0a5750c45a64616d7` script finished exit=1
  - 备注：静态依据（快照 586b79b41f8e4f59be80f2a9b548902b，applicability=match）：orders/create.php L3 取 $_POST['price'] 为 $price，L4 仅校验非负，L5 total=round($price*$quantity,2)，L7 INSERT orders(unit_price,total) 写入该 $price/$total；bootstrap.php L38-40 显示 csrf_token/csrf_field/check_csrf 语义（表单令牌名 csrf），L33-37 require_user 仅校验登录。catalog/index.php L4-5 展示 products.price 作为权威价，但 create.php 未使用。以上为源码事实，尚缺当前上下文的动态对照观测。

### C-09 content/page.php 将 $_GET['page'] 直接拼入 include 导致本地文件包含

- verification `11670586889c40c68ef8929b16497890`（finding `540794db77534bd0a2a22518ea37375f` revision 1，context `7440d872986448b8909365a52d9fb18d`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（job 29208d3829ea4e0ea755721922dff94e）：登录后 GET /content/page.php?page=home 返回 200，页面为「内容中心」，正文不含 SHOP_INTERNAL_ 标记（NORMAL_STATUS 200 MARKER False）；深度 2-4 的非穿越值也返回 200 且无标记。审计作业 11473a3b08ec4012bdda427e004f5a3e 的 page=home 同样返回正常视图，无标记或错误。
  - 攻击侧观测：攻击侧（同一 alice 会话，job 29208d3829ea4e0ea755721922dff94e）：GET /content/page.php?page=../×5+var/lib/shop/vault/account（URL 编码 %2E%2E%2F…）返回 200，响应正文出现 setup.php:35 写入 vault/account.php 的唯一内部标记 SHOP_INTERNAL_086a85109c3a034cd4b77920；深度 6-11 同样命中（多余 .. 截断到根目录后仍解析到 /var/lib/shop/vault/account.php），未出现 Warning/失败的 include 错误。说明 include APP_ROOT.'/resources/views/'.$name.'.php' 被 ../ 穿越到 data_dir 并执行了该 PHP 文件。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`11473a3b08ec4012bdda427e004f5a3e`；`29208d3829ea4e0ea755721922dff94e`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`29208d3829ea4e0ea755721922dff94e` script finished exit=0；`11473a3b08ec4012bdda427e004f5a3e` script finished exit=0
  - 适配脚本：`11670586-adapted-lfi_page_poc.py`（见证据包 evidence/）
  - 备注：正常与攻击来自同一 alice 会话的两个请求；攻击证据为页面正文中的 SHOP_INTERNAL_ 唯一标记（来自 /var/lib/shop/vault/account.php），非状态码或常见字符串。审计作业 11473a3b08ec4012bdda427e004f5a3e 的 600 字截断输出两侧头部相同，未显示标记，不能单独支撑结论，仅作链路佐证；决定性观测来自后续深度扫描作业。未验证 php:// 包装器或读取非 PHP 文件。

- 正式复核 `b4bc4ad6b2a44953856e51f6a56cb52e`：复核确认；引用 revision 1 / verification `11670586889c40c68ef8929b16497890`
  - 理由：已完整读取该记录两侧观测：正常侧 page=home 返回 200 且 MARKER False，深度 2-4 亦无标记；攻击侧同一 alice 会话请求 page=../×5+var/lib/shop/vault/account 返回 200，正文出现 setup.php:35 生成的唯一标记 SHOP_INTERNAL_086a85109c3a034cd4b77920，深度 5-11 同样命中且无 include 错误，证明 ../ 穿越到 data_dir 并执行了该 PHP 文件，与 content/page.php:2-3 无白名单拼接 include 的静态依据一致。
  - 复核观测：正常侧 正常侧（job 29208d3829ea4e0ea755721922dff94e）：登录后 GET /content/page.php?page=home 返回 200，页面为「内容中心」，正文不含 SHOP_INTERNAL_ 标记（NORMAL_STATUS 200 MARKER False）；深度 2-4 的非穿越值也返回 200 且无标记。审计作业 11473a3b08ec4012bdda427e004f5a3e 的 page=home 同样返回正常视图，无标记或错误。；攻击侧 攻击侧（同一 alice 会话，job 29208d3829ea4e0ea755721922dff94e）：GET /content/page.php?page=../×5+var/lib/shop/vault/account（URL 编码 %2E%2E%2F…）返回 200，响应正文出现 setup.php:35 写入 vault/account.php 的唯一内部标记 SHOP_INTERNAL_086a85109c3a034cd4b77920；深度 6-11 同样命中（多余 .. 截断到根目录后仍解析到 /var/lib/shop/vault/account.php），未出现 Warning/失败的 include 错误。说明 include APP_ROOT.'/resources/views/'.$name.'.php' 被 ../ 穿越到 data_dir 并执行了该 PHP …

### C-10 redeem.php 会员兑换使用 md5 弱类型比较，0e 魔术哈希绕过

- verification `537aa3a5147149d98cc7137c652bf9d4`（finding `5d4e81d921a444bd9c462548c4881f44` revision 1，context `da19261e45b8487da9ede31893c57cc3`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：同一登录用户 alice 携带有效 CSRF 提交普通 token，返回 422 {"accepted":false,"message":"兑换码无效。"}，tier 保持 standard。
  - 攻击侧观测：提交 md5 结果为 0e830400...391 的 token（QNKCDZO，与 240610708 的 0e462097...854 同为 0e 纯数字），返回 200 {"accepted":true,"message":"兑换成功，已升级金卡会员。"}，随后查询 tier 由 standard 变为 gold，状态变更由宿主记录确认。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`6cc1954babad45d394e45a6c8e88e457`
  - 结论结束原因：completed；执行阶段结束原因：sdk_api_error
  - 作业：`6cc1954babad45d394e45a6c8e88e457` script finished exit=0
  - 适配脚本：`537aa3a5-adapted-poc.php`（见证据包 evidence/）
  - 备注：证据 stdout 同时包含两次 md5 计算值、普通 token 被拒与攻击 token 被接受及 tier 前后对比，构成对照。

- 正式复核 `7b23998b9c7e44749c818df59feca0f3`：复核确认；引用 revision 1 / verification `537aa3a5147149d98cc7137c652bf9d4`
  - 理由：已完整读取该记录两侧观测：正常侧普通 token 返回 422 且 tier 保持 standard；攻击侧 0e 魔术哈希 token（QNKCDZO，md5 为 0e830400…391）返回 200 accepted:true，宿主记录 tier 由 standard 变为 gold，确证 redeem.php:5 的 md5(...)==$secret_hash 宽松比较可被绕过，与源码行证据一致。
  - 复核观测：正常侧 同一登录用户 alice 携带有效 CSRF 提交普通 token，返回 422 {"accepted":false,"message":"兑换码无效。"}，tier 保持 standard。；攻击侧 提交 md5 结果为 0e830400...391 的 token（QNKCDZO，与 240610708 的 0e462097...854 同为 0e 纯数字），返回 200 {"accepted":true,"message":"兑换成功，已升级金卡会员。"}，随后查询 tier 由 standard 变为 gold，状态变更由宿主记录确认。

### C-11 ops/xml-import.php 启用 LIBXML_NOENT|LIBXML_DTDLOAD 解析用户 XML，导致 XXE

- verification `c9f87b3fbfcb4ecdb3352b480819c605`（finding `9302b8fb4eaf47c581953019bb3c7e84` revision 1，context `b8b3264de49e478bb2f0651d92b57341`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 身份（precondition 确认 id=3, role=operator）：登录后 GET /ops/xml-import.php 返回 200 并取到 csrf（CSRF True）。提交普通 XML &lt;config&gt;&lt;title&gt;阳光配置&lt;/title&gt;&lt;/config&gt; 返回 200，导入结果 <pre> 显示「阳光配置」，无文件内容。
  - 攻击侧观测：攻击侧（同一 operator 会话、同一 csrf，job cd9c66eff7cf4ca5a5a388e76a59c07c）：提交 <!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> 的 XML 返回 200，<pre> 中出现 root:x:0:0:root:/root:/bin/bash、daemon:… 等 /etc/passwd 内容（ROOT_LINE True）；再提交实体指向 file:///var/lib/shop/vault/internal.txt 的 XML，返回 200 且 <pre> 中回显 SHOP_INTERNAL_19eeaf3f0a110b338bfb859a。外部实体在解析阶段被展开并随 $doc->title 输出，XXE 成立。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`cd9c66eff7cf4ca5a5a388e76a59c07c`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`cd9c66eff7cf4ca5a5a388e76a59c07c` script finished exit=0
  - 适配脚本：`c9f87b3f-adapted-xxe_xml_import.php`（见证据包 evidence/）
  - 备注：正常/攻击两请求在同一 operator 会话内、使用同一 csrf；攻击后果为本地任意文件读取（/etc/passwd 与 data_dir 下的内部标记文件）。未测试 SSRF 类 http:// 实体（file:// 已足够证明实体展开），也未做盲注外带。入口按源码要求 operator/admin，本次使用 host 提供的 operator 身份，未用其证明普通会员越权。

- 正式复核 `626d88d3e6154b6385b50bd4dcaa23db`：复核确认；引用 revision 1 / verification `c9f87b3fbfcb4ecdb3352b480819c605`
  - 理由：已完整读取该记录两侧观测：正常侧普通 XML 回显「阳光配置」，无文件内容；攻击侧实体 SYSTEM "file:///etc/passwd" 使 <pre> 出现 root:x:0:0 等行，指向 vault/internal.txt 时回显 SHOP_INTERNAL_19eeaf3f0a110b338bfb859a，确证 xml-import.php:3 启用 LIBXML_NOENT&#124;LIBXML_DTDLOAD 造成外部实体展开与本地文件读取。
  - 复核观测：正常侧 operator 身份（precondition 确认 id=3, role=operator）：登录后 GET /ops/xml-import.php 返回 200 并取到 csrf（CSRF True）。提交普通 XML &lt;config&gt;&lt;title&gt;阳光配置&lt;/title&gt;&lt;/config&gt; 返回 200，导入结果 <pre> 显示「阳光配置」，无文件内容。；攻击侧 攻击侧（同一 operator 会话、同一 csrf，job cd9c66eff7cf4ca5a5a388e76a59c07c）：提交 <!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> 的 XML 返回 200，<pre> 中出现 root:x:0:0:root:/root:/bin/bash、daemon:… 等 /etc/passwd 内容（ROOT_LINE True）；再提交实体指向 file:///var/lib/shop/vault/internal.txt 的 XML，返回 200 且 <pre> 中回显 SHOP_INTERNAL_19eeaf3f0a110b338bfb859a。外部实体在解析阶段被展开并随 $doc->title 输出，XXE 成立。

### C-12 start_session() 关闭 strict_mode 且接受可控 sid，导致会话固定

- verification `4c760aa252ad4eeaaecdde73288f87de`（finding `0f8e892b8c784af69d7a05ec5929e26c` revision 1，context `2d95e0e9a231485c9d30ac25c4eae816`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（job 93331f4d752346cead78cb16dd8f0da1）：不带 sid 参数访问 /auth/login.php 并登录（NORMAL_LOGIN_STATUS 200），服务端下发的是自行生成的 32 位十六进制会话 ID（SERVER_SID_LEN 32），随后 /account/index.php 返回 200 且页面含 <dd>alice</dd> 与「退出」（NORMAL_ACCOUNT 200 True True），会话正常。对照组：用未经登录的固定 Cookie SHOPSESSID=pocfixedsid0123456789abcdef 请求 /account/index.php 得到 401 并给出「请先登录」（CONTROL_UNAUTH_MARKER True），说明服务端不会凭空赋予该固定 ID 认证状态。
  - 攻击侧观测：攻击侧（job 93331f4d752346cead78cb16dd8f0da1，模拟受害者通过带 sid 的登录链接登录）：GET /auth/login.php?sid=pocattacksid0123456789abcd 后 POST 同一 URL 登录，响应 Set-Cookie 的会话值与预置值完全一致（SESSION_EQUALS_CHOSEN_SID True，ATTACK_LOGIN_STATUS 200）。随后用全新 opener 仅以 Cookie: SHOPSESSID=pocattacksid0123456789abcd 请求 /account/index.php，返回 200（ATTACK_FRESH_SESSION_ACCOUNT_STATUS 200）、页面含 <dd>alice</dd>（ATTACK_IDENTITY_ALICE True）与「退出」（ATTACK_AUTH_MARKER True），即攻击者预置的会话 ID 在登录后成为已认证的 alice 会话并被第三方复用。对照：未登录时直接使用另一个固定 sid 请求同一页面返回 401（CONTROL_UNLOGGED_FIXED_SID_STATUS 401），说明该固定值本身并无既有权限，认证状态确由本次登录写入。审计作业 86eebadfaf794126b579c260980f6488 的独立复核同样以同一 sid 头访问 /orders/index.php 得到 200 并打印 SESSION_FIXATION_CONFIRMED。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`86eebadfaf794126b579c260980f6488`；`93331f4d752346cead78cb16dd8f0da1`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`93331f4d752346cead78cb16dd8f0da1` script finished exit=0；`86eebadfaf794126b579c260980f6488` script finished exit=0
  - 适配脚本：`4c760aa2-adapted-session_fixation_poc.py`（见证据包 evidence/）
  - 备注：正常、未登录固定 sid 对照、攻击三组观测在同一作业内完成，归因清晰。实验用 alice 的凭据扮演登录受害者的行为，属攻击模型中的受害者登录步骤，不是用特权身份冒充普通会员。结论仅指会话固定（攻击者可控 sid 在登录后保持并可复用）；未验证跨受害者的横向影响。凭据取自环境变量，未在输出中打印。

- 正式复核 `0f6c3b4d41c64f0c98afde1886b84bb0`：复核确认；引用 revision 1 / verification `4c760aa252ad4eeaaecdde73288f87de`
  - 理由：正常侧不带 sid 登录得到服务端生成的 32 位会话并能访问账户页，未登录固定 sid 请求返回 401；攻击侧以 sid=pocattacksid0123456789abcd 登录后返回值与原值一致，全新连接仅带该 Cookie 即取得 alice 账户页 200 与退出标记，独立作业亦复现 SESSION_FIXATION_CONFIRMED，与源码 bootstrap.php:13/17/18 及 login.php:3/8 完全一致。
  - 复核观测：正常侧 正常侧（job 93331f4d752346cead78cb16dd8f0da1）：不带 sid 参数访问 /auth/login.php 并登录（NORMAL_LOGIN_STATUS 200），服务端下发的是自行生成的 32 位十六进制会话 ID（SERVER_SID_LEN 32），随后 /account/index.php 返回 200 且页面含 <dd>alice</dd> 与「退出」（NORMAL_ACCOUNT 200 True True），会话正常。对照组：用未经登录的固定 Cookie SHOPSESSID=pocfixedsid0123456789abcdef 请求 /account/index.php 得到 401 并给出「请先登录」（CONTROL_UNAUTH_MARKER True），说明服务端不会凭空赋予该固定 ID 认证状态。；攻击侧 攻击侧（job 93331f4d752346cead78cb16dd8f0da1，模拟受害者通过带 sid 的登录链接登录）：GET /auth/login.php?sid=pocattacksid0123456789abcd 后 POST 同一 URL 登录，响应 Set-Cookie 的会话值与预置值完全一致（SESSION_EQUALS_CHOSEN_SID True，ATTACK_LOGIN_STATUS 200）。随后用全新 opener 仅以 Cookie: SHOPSESSID=pocattacksid0123456789abcd 请求 /account/index.php，返回 200（ATTACK_FRESH_SESSION_ACCOUNT_STATUS 200）、页面含 <dd>alice</dd>（ATTACK_IDENTITY_ALICE True）与「退出」（AT…

### C-13 ops/template-preview.php 将 GET template 直接 include 导致本地文件包含（条件性远程包含）

- verification `88f598ea2bca4a009cec0778d91d6da9`（finding `f0808b3f98f44b829055d315886c0122` revision 1，context `53a539b53b694c6ab8ab9bec3f7b0783`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（job 7da42ee42d13484c9d54973be920c30b）：operator 登录成功（LOGIN 200，已跳离登录页）；不带 template 参数访问 /ops/template-preview.php 返回 200，页面含 #remote-template 段但无包含内容（BASELINE 200）；使用页面默认的 http://fixtures:8080/templates/season.php 时返回 200，段内渲染出合作方模板内容「合作方 · 秋日生活提案 / 让生活慢下来，把好物带回家。」，属预期远程模板预览，无本地标记。
  - 攻击侧观测：攻击侧（同一 operator 会话，job 7da42ee42d13484c9d54973be920c30b）：GET /ops/template-preview.php?template=/var/lib/shop/vault/account.php 返回 200，#remote-template 段内输出 SHOP_INTERNAL_a786c48053383161e5b5e9b8（MARKER），即 include 命中了 data_dir 下的 PHP 文件并执行其代码；GET ...?template=/etc/passwd 返回 200，段内原样输出 root:x:0:0:root:/root:/bin/bash、daemon:… 等，证明可包含任意本地路径读取文件内容（PASSWD True）。另：默认模板 http://fixtures:8080/templates/season.php 被服务端成功取得并渲染出「合作方 · 秋日生活提案」，说明运行时允许 URL 包含（allow_url_include 生效），但未用外部攻击者控制的远端主机验证 RFI。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`7da42ee42d13484c9d54973be920c30b`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`7da42ee42d13484c9d54973be920c30b` script finished exit=0
  - 适配脚本：`88f598ea-adapted-poc.php`（见证据包 evidence/）
  - 备注：正常/攻击在同一 operator 会话内，同一端点仅 template 取值不同；判定依据是 #remote-template 段内的文件内容/唯一标记，而非状态码。未搭建攻击者控制的远端模板服务器，故 RFI 仅以 fixtures 正常模板加载为旁证（默认功能即远程包含），结论主体为本地任意文件包含/读取。入口的 operator/admin 要求来自源码 require_user(['operator','admin'])，未用其证明普通会员越权。

- 正式复核 `0233719fa3d44965bb0652c0a970f740`：复核确认；引用 revision 1 / verification `88f598ea2bca4a009cec0778d91d6da9`
  - 理由：正常侧默认 remote 模板正常渲染且无本地内容；攻击侧 template=/var/lib/shop/vault/account.php 在 #remote-template 段内输出 SHOP_INTERNAL 标记（本地 PHP 被执行），template=/etc/passwd 原样输出 root:x:0:0 等行，证明确为无过滤动态 include，与 template-preview.php:2-3 一致。RFI 仅证明 allow_url_include 生效，未用攻击者远端主机实测，故结论按 LFI 接受。
  - 复核观测：正常侧 正常侧（job 7da42ee42d13484c9d54973be920c30b）：operator 登录成功（LOGIN 200，已跳离登录页）；不带 template 参数访问 /ops/template-preview.php 返回 200，页面含 #remote-template 段但无包含内容（BASELINE 200）；使用页面默认的 http://fixtures:8080/templates/season.php 时返回 200，段内渲染出合作方模板内容「合作方 · 秋日生活提案 / 让生活慢下来，把好物带回家。」，属预期远程模板预览，无本地标记。；攻击侧 攻击侧（同一 operator 会话，job 7da42ee42d13484c9d54973be920c30b）：GET /ops/template-preview.php?template=/var/lib/shop/vault/account.php 返回 200，#remote-template 段内输出 SHOP_INTERNAL_a786c48053383161e5b5e9b8（MARKER），即 include 命中了 data_dir 下的 PHP 文件并执行其代码；GET ...?template=/etc/passwd 返回 200，段内原样输出 root:x:0:0:root:/root:/bin/bash、daemon:… 等，证明可包含任意本地路径读取文件内容（PASSWD True）。另：默认模板 http://fixtures:8080/templates/se…

### C-14 account/profile.php 将 url 参数与用户 homepage 未编码写入 href，造成反射型/存储型 XSS

- verification `545525e2ec8c4080802e9031dd61bfbd`（finding `879044f7ff9d474f8c428a8cb831efa9` revision 1，context `44f15efc6c6d4b1aa5412c7b40faddf9`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧：HTTP 脚本作业 f8c2776d00f94636ba563e0308955f20 请求 /account/profile.php?url=https%3A%2F%2Fexample.com%2F 返回 200，页面正常渲染、无报错。浏览器对照作业 7569c399f7ec404dbde5a8782e533243 对同一页面加载 /account/profile.php?url=%2Faccount%2Findex.php（相对地址，指向站内账户页），执行与攻击侧相同的 document.getElementById('profile-link').click()，宿主记录 dialogs 为空数组、console_errors 为空，页面标题「个人主页预览 · 拾光商城」，无任何脚本执行。
  - 攻击侧观测：攻击侧 URL：/account/profile.php?url=javascript%3Aalert(1)。HTTP 侧脚本作业 f8c2776d00f94636ba563e0308955f20 输出 ATTACK 200 True，即未编码的 javascript:alert(1) 出现在响应中；httponly 反射本身不算执行。浏览器作业 78d6ff7ba9fc49a3b9c993c06d99d43c 以 alice 会话加载同一路径，执行 document.getElementById('profile-link').click() 后宿主记录 dialogs=["1"]，即 javascript: URL 在页面上下文实际执行并弹出 alert(1)；页面标题为「个人主页预览 · 拾光商城」，console_errors 为空，截图 78d6ff7ba9fc49a3b9c993c06d99d43c-screenshot.png 留存。同页其它值(display_name)walkthrough 使用 h() 转义，仅 href 原样拼接，说明根因即源码 profile.php:2-3 的缺失编码/协议校验。
  - 已保存作业事实：3 个；满足执行及前提检查的作业：3 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`f8c2776d00f94636ba563e0308955f20`；`78d6ff7ba9fc49a3b9c993c06d99d43c`；`7569c399f7ec404dbde5a8782e533243`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`f8c2776d00f94636ba563e0308955f20` script finished exit=0；`78d6ff7ba9fc49a3b9c993c06d99d43c` browser finished exit=0；`7569c399f7ec404dbde5a8782e533243` browser finished exit=0
  - 产物：`545525e2ec8c4080802e9031dd61bfbd-78d6ff7ba9fc49a3b9c993c06d99d43c-screenshot.png`；`545525e2ec8c4080802e9031dd61bfbd-7569c399f7ec404dbde5a8782e533243-screenshot.png`
  - 适配脚本：`545525e2-adapted-poc_profile_xss.py`（见证据包 evidence/）
  - 备注：攻击侧执行证据来自浏览器作业 dialogs=["1"]；正常侧浏览器对照作业 7569c399f7ec404dbde5a8782e533243 使用同样点击脚本、url=相对路径 /account/index.php，dialogs 为空，无脚本执行。HTTP 反射(ATTACK 200 True)仅作传播链路佐证，未单独作为 XSS 成立依据。未做存储型(homepage)变体实验，结论限定为反射型；存储路径由 update.php 可写 homepage + profile.php 默认回读推断，未动态验证。

- 正式复核 `bbc096ed38bf4710adf2479d2c45a629`：复核确认；引用 revision 1 / verification `545525e2ec8c4080802e9031dd61bfbd`
  - 理由：正常侧相对地址对照页点击 profile-link 后 dialogs 为空、无 console 错误；攻击侧 url=javascript%3Aalert(1) 页面点击后宿主记录 dialogs=["1"]，脚本在页面上下文真实执行，且响应中未编码的 javascript: 原样出现，与 profile.php:2-3 未转义 href 拼接一致；存储型路径未验证，不作为本条依据。
  - 复核观测：正常侧 正常侧：HTTP 脚本作业 f8c2776d00f94636ba563e0308955f20 请求 /account/profile.php?url=https%3A%2F%2Fexample.com%2F 返回 200，页面正常渲染、无报错。浏览器对照作业 7569c399f7ec404dbde5a8782e533243 对同一页面加载 /account/profile.php?url=%2Faccount%2Findex.php（相对地址，指向站内账户页），执行与攻击侧相同的 document.getElementById('profile-link').click()，宿主记录 dialogs 为空数组、console_errors 为空，页面标题「个人主页预览 · 拾光商城」，无任何脚本执行。；攻击侧 攻击侧 URL：/account/profile.php?url=javascript%3Aalert(1)。HTTP 侧脚本作业 f8c2776d00f94636ba563e0308955f20 输出 ATTACK 200 True，即未编码的 javascript:alert(1) 出现在响应中；httponly 反射本身不算执行。浏览器作业 78d6ff7ba9fc49a3b9c993c06d99d43c 以 alice 会话加载同一路径，执行 document.getElementById('profile-link').click() 后宿主记录 dialogs=["1"]，即 javascript: URL 在页面上下文实际执行并弹出 alert(1)；页面标题为「个人主页预览 · 拾光商城」，console_errors 为空，截图 78d6ff7ba9fc49a3b9c99…

### C-15 商品目录搜索参数 q 直接拼接进 SQL 导致 SQL 注入

- verification `c34b49674ee04bdca244e1b9083b7983`（finding `514c84a170d043b7943d923e0d29517e` revision 1，context `691e2f8159bf47dd9012dd4e493dc6ad`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（同一未登录请求序列，job 845b26c3e1ea40d39128d6b9fd7f62bd）：q=手冲 返回 200、result-count 1，仅命中「晨光手冲壶」；q=zzz-no-such-item 返回 200、result-count 0、无商品；均无 SHOP_INTERNAL_ 标记，说明 q 作为 LIKE 子串按预期过滤。审计作业的 q=拾 同样返回 200、count 0，属正常（产品名不含「拾」）。
  - 攻击侧观测：攻击侧（未携带任何会话 Cookie 的 GET，job 845b26c3e1ea40d39128d6b9fd7f62bd）：q=' OR '1'='1' -- （URL 编码）使 result-count 从正常的 0/1 变为 4，返回全部四个商品，条件恒真；进一步 q=%' UNION SELECT 777,value,'union-leak',0,0,'sand' FROM settings WHERE `key`='internal_marker' -- 返回 COUNT 5，商品名列表末尾出现注入行 'SHOP_INTERNAL_77bcb2d132cb8ded1f798513'（MARKER 命中），即通过 UNION 从 settings 表读出了服务端内部标记并渲染到页面。审计作业 6b82f341bf984a44ad6edf2c7a737729 的等价 payload 亦显示 normal_count=0 / attack_count=4（页面为未登录导航，含「登录」「注册」）。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`6b82f341bf984a44ad6edf2c7a737729`；`845b26c3e1ea40d39128d6b9fd7f62bd`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`845b26c3e1ea40d39128d6b9fd7f62bd` script finished exit=0；`6b82f341bf984a44ad6edf2c7a737729` script finished exit=0
  - 适配脚本：`c34b4967-adapted-sqli_catalog_q.php`（见证据包 evidence/）
  - 备注：正常/攻击对照均无 Cookie、未登录，页面导航显示「登录/注册」，与源码 catalog/index.php 无 require_user 一致。判定依据是结果行数与行内容（含 UNION 注入行中的 SHOP_INTERNAL_ 标记），不是状态码。未提权、未写库；UNION 读取的是 settings 表既有内部标记，属只读数据泄露。结论限定于 catalog/index.php 的 q 参数。

- 正式复核 `7d1fb5db99cc4889a711d53dbcdc5ffe`：复核确认；引用 revision 1 / verification `c34b49674ee04bdca244e1b9083b7983`
  - 理由：正常侧 job 845b26c3e1ea40d39128d6b9fd7f62bd：q=手冲 计数 1 仅命中「晨光手冲壶」，q=zzz-no-such-item 计数 0，无 SHOP_INTERNAL_ 标记；攻击侧同作业 q=' OR '1'='1' -- 计数变为 4 返回全部商品，UNION 载荷使计数为 5 且商品名位置出现 settings.internal_marker 的 SHOP_INTERNAL_77bcb2d132cb8ded1f798513；作业 6b82f341bf984a44ad6edf2c7a737729 显示同样的 normal_count=0 / attack_count=4 对照。输入确实进入 SQL 解析并可跨表读数据，与 catalog/index.php:3-4 的拼接证据一致。
  - 复核观测：正常侧 正常侧（同一未登录请求序列，job 845b26c3e1ea40d39128d6b9fd7f62bd）：q=手冲 返回 200、result-count 1，仅命中「晨光手冲壶」；q=zzz-no-such-item 返回 200、result-count 0、无商品；均无 SHOP_INTERNAL_ 标记，说明 q 作为 LIKE 子串按预期过滤。审计作业的 q=拾 同样返回 200、count 0，属正常（产品名不含「拾」）。；攻击侧 攻击侧（未携带任何会话 Cookie 的 GET，job 845b26c3e1ea40d39128d6b9fd7f62bd）：q=' OR '1'='1' -- （URL 编码）使 result-count 从正常的 0/1 变为 4，返回全部四个商品，条件恒真；进一步 q=%' UNION SELECT 777,value,'union-leak',0,0,'sand' FROM settings WHERE `key`='internal_marker' -- 返回 COUNT 5，商品名列表末尾出现注入行 'SHOP_INTERNAL_77bcb2d132cb8ded1f798513'（MARKER 命中），即通过 UNION 从 settings 表读出了服务端内部标记并渲染到页面。审计作业 6b82f341bf984a44ad6edf2c7a737729 的等价 payload …

### C-16 support/download.php 用户可控 file 参数拼接路径导致路径遍历任意文件读取

- verification `a480c33bb7574c82ae6c1abb406a951a`（finding `4969e168d8b0497a884adc3b295b2969` revision 1，context `9914e3165bed4e2088900a90c8bde08a`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（job 4d0c0956aed041f68ec796b5515502d3）：alice 登录后 GET /support/download.php?file=shipping.txt 返回 200、text/plain，正文「配送说明：工作日 48 小时内发货。」；file=returns.txt 返回「售后说明：签收后七天内可申请退货。」，均限于 docs 目录内文件。
  - 攻击侧观测：攻击侧（同一 alice 会话，job 4d0c0956aed041f68ec796b5515502d3）：file=../vault/internal.txt 返回 200 且正文为 SHOP_INTERNAL_42b45b976d56e902e3a20053，即路径逃出 docs 目录读到 data_dir/vault 下文件；file=../../../../etc/passwd 返回 200 且正文为 root:x:0:0:root:/root:/bin/bash、daemon:… 等系统文件内容（PASSWD True）。目录穿越与任意文件读取成立。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`4d0c0956aed041f68ec796b5515502d3`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`4d0c0956aed041f68ec796b5515502d3` script finished exit=0
  - 适配脚本：`a480c33b-adapted-poc.php`（见证据包 evidence/）
  - 备注：五组请求在同一 alice 会话内，仅 file 取值不同；判定依据为响应正文内容（内部标记、/etc/passwd 行），Content-Type 均为 text/plain。未尝试写入或包含执行；结论限于读取。普通会员即可触发（require_user 仅要求登录）。

- 正式复核 `2eb7765d327b4250a940459c7f33c307`：复核确认；引用 revision 1 / verification `a480c33bb7574c82ae6c1abb406a951a`
  - 理由：正常侧 job 4d0c0956aed041f68ec796b5515502d3：alice 会话下 file=shipping.txt 返回「配送说明：工作日 48 小时内发货。」，file=returns.txt 返回「售后说明：签收后七天内可申请退货。」，均在 docs 目录内。攻击侧同一会话 file=../vault/internal.txt 返回 200 且正文为 SHOP_INTERNAL_42b45b976d56e902e3a20053，file=../../../../etc/passwd 返回 root:x:0:0 等系统用户行，证实路径逃逸与任意文件读取，与 download.php:3 缺少路径规范化/白名单的源码证据一致。
  - 复核观测：正常侧 正常侧（job 4d0c0956aed041f68ec796b5515502d3）：alice 登录后 GET /support/download.php?file=shipping.txt 返回 200、text/plain，正文「配送说明：工作日 48 小时内发货。」；file=returns.txt 返回「售后说明：签收后七天内可申请退货。」，均限于 docs 目录内文件。；攻击侧 攻击侧（同一 alice 会话，job 4d0c0956aed041f68ec796b5515502d3）：file=../vault/internal.txt 返回 200 且正文为 SHOP_INTERNAL_42b45b976d56e902e3a20053，即路径逃出 docs 目录读到 data_dir/vault 下文件；file=../../../../etc/passwd 返回 200 且正文为 root:x:0:0:root:/root:/bin/bash、daemon:… 等系统文件内容（PASSWD True）。目录穿越与任意文件读取成立。

### C-17 ops/template-render.php 对模板表达式 eval 导致任意 PHP 代码执行

- verification `451e38e003dd4b628b991d991abe75b9`（finding `6ffea81f95e642cb9969bcc88369d326` revision 1，context `c04305eee0fd45dba3fa3b96d4741595`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 身份（precondition 确认 id=3, role=operator）：登录后 OPS_SESSION 200 /ops/index.php 含「退出」「运营」；GET /ops/template-render.php 返回 200 并含 csrf 隐藏字段（FORM 200 csrf）。提交 template=共 {{ 2 + 2 }} 款 返回 200，<pre> 输出 ['共 4 款']，NORMAL_MARKER_PRESENT False，仅执行模板自身的算术表达式。
  - 攻击侧观测：攻击侧（同一 operator 会话，job 612d8872155b408d97a0a1aaaac3f7e8）：POST template={{ system('id; echo LAB30_EVAL_MARK_9c2f41') }} 返回 200；响应在 HTML 之前直接输出了 uid=33(www-data) gid=33(www-data) groups=33(www-data)（ATTACK_UID_PRESENT True），<pre> 内容为 ['LAB30_EVAL_MARK_9c2f41']（ATTACK_MARKER_PRESENT True），该唯一标记仅由攻击模板产生。即 eval('return '.$m[1].';') 执行了任意 PHP 代码并以 Web 服务账户调用系统命令，代码执行成立。请求使用从表单页面实际取得的 csrf 令牌（FORM 200 csrf）。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`3307791c95be4556a30fe7e0f6a9107a`；`612d8872155b408d97a0a1aaaac3f7e8`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`612d8872155b408d97a0a1aaaac3f7e8` script finished exit=0
  - 适配脚本：`451e38e0-adapted-poc_template_eval.py`（见证据包 evidence/）
  - 备注：正常/攻击均为同一 operator 会话内的 POST，输出取自同一页面 <pre> 与响应头段，归因清晰。此前宿主审计作业 3307791c95be4556a30fe7e0f6a9107a 以 alice(customer) 请求 GET /ops/template-render.php 得到 403，evidence_usable=false，未用于结论；入口的 operator/admin 要求以源码 require_user(['operator','admin']) 为依据。结论限于 template-render.php 的 eval，未扩展到其它模板功能。

- 正式复核 `aed7dac87b7747a48a6007cc93a8e99a`：复核确认；引用 revision 1 / verification `451e38e003dd4b628b991d991abe75b9`
  - 理由：已读取同版本完整正常/攻击观测：正常侧 operator 提交 template=共 {{ 2 + 2 }} 款 返回 <pre> ['共 4 款']、NORMAL_MARKER_PRESENT False；攻击侧同会话提交 {{ system('id; echo LAB30_EVAL_MARK_9c2f41') }} 返回 200，HTML 之前输出 uid=33(www-data) gid=33(www-data) groups=33(www-data)，唯一标记 LAB30_EVAL_MARK_9c2f41 出现在 <pre>，ATTACK_MARKER_PRESENT 与 ATTACK_UID_PRESENT 均为 True，且使用表单取得的 csrf。与源码 eval('return '.$m[1].';') 根因一致，确认。
  - 复核观测：正常侧 operator 身份（precondition 确认 id=3, role=operator）：登录后 OPS_SESSION 200 /ops/index.php 含「退出」「运营」；GET /ops/template-render.php 返回 200 并含 csrf 隐藏字段（FORM 200 csrf）。提交 template=共 {{ 2 + 2 }} 款 返回 200，<pre> 输出 ['共 4 款']，NORMAL_MARKER_PRESENT False，仅执行模板自身的算术表达式。；攻击侧 攻击侧（同一 operator 会话，job 612d8872155b408d97a0a1aaaac3f7e8）：POST template={{ system('id; echo LAB30_EVAL_MARK_9c2f41') }} 返回 200；响应在 HTML 之前直接输出了 uid=33(www-data) gid=33(www-data) groups=33(www-data)（ATTACK_UID_PRESENT True），<pre> 内容为 ['LAB30_EVAL_MARK_9c2f41']（ATTACK_MARKER_PRESENT True），该唯一标记仅由攻击模板产生。即 eval('return '.$m[1].';') 执行了任意 PHP 代码并以 Web 服务账户调用系统命令，代码执行成立。请求使用从表单页面实际取得的 csrf 令牌（FORM 200 cs…

### C-18 ops/url-preview.php 将 GET url 直接传给 file_get_contents 导致 SSRF

- verification `b0b52085e3d849b5933d7655adf23fe1`（finding `f7763e4792fd477ca30e8b71b0563e8d` revision 1，context `19cda01d7def4a13b035165c5827fc64`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（job da57f5487e4a47209e78a18a87bfe256）：operator 登录成功；GET /ops/url-preview.php?url=http://fixtures:8080/catalog-info（页面默认地址）返回 200，<pre> 为 29 字节的合作方摘要「拾光合作方商品摘要：本季上新四款日常好物，工作日统一配送。」，属预期外部内容预览。
  - 攻击侧观测：攻击侧（同一 operator 会话，job da57f5487e4a47209e78a18a87bfe256）：url=http://127.0.0.1/ 与 url=http://localhost/ 均返回 200，<pre> 长度为 3493，内容为服务端自身的商城 HTML（h() 转义后呈 &lt;!doctype html&gt;…，含「拾光商城」），证明服务器向回环地址发起请求并回显响应；url=file:///var/lib/shop/vault/internal.txt 返回 200，<pre> 为 SHOP_INTERNAL_c3b5c4de0a252b4f532b471f，说明协议也未受限，可直接读取服务器本地文件。任意 URL 抓取（含内网/环回）与本地文件读取成立。
  - 已保存作业事实：1 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`da57f5487e4a47209e78a18a87bfe256`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`da57f5487e4a47209e78a18a87bfe256` script finished exit=0
  - 适配脚本：`b0b52085-adapted-poc.php`（见证据包 evidence/）
  - 备注：四个请求在同一 operator 会话内，仅 url 参数不同；判定依据为 <pre> 中的响应内容（回环获取的商城页面、内部标记文件），不是状态码。未做端口扫描、未访问云元数据地址、未尝试非 HTTP 内网服务。入口按源码要求 operator/admin，未用其证明普通会员越权。

- 正式复核 `c5645e1519474990a380a340f264863c`：复核确认；引用 revision 1 / verification `b0b52085e3d849b5933d7655adf23fe1`
  - 理由：已读取同版本完整正常/攻击观测：正常侧 url=http://fixtures:8080/catalog-info 返回 29 字节预期合作方摘要；攻击侧 http://127.0.0.1/ 与 http://localhost/ 均 200 且回显 3493 字节服务端自身商城 HTML，file:///var/lib/shop/vault/internal.txt 回显 SHOP_INTERNAL_c3b5c4de0a252b4f532b471f。与 url-preview.php:2-3 将 GET url 直接传入 file_get_contents、无协议/主机限制的根因一致，确认（网络拓扑仅影响利用面）。
  - 复核观测：正常侧 正常侧（job da57f5487e4a47209e78a18a87bfe256）：operator 登录成功；GET /ops/url-preview.php?url=http://fixtures:8080/catalog-info（页面默认地址）返回 200，<pre> 为 29 字节的合作方摘要「拾光合作方商品摘要：本季上新四款日常好物，工作日统一配送。」，属预期外部内容预览。；攻击侧 攻击侧（同一 operator 会话，job da57f5487e4a47209e78a18a87bfe256）：url=http://127.0.0.1/ 与 url=http://localhost/ 均返回 200，<pre> 长度为 3493，内容为服务端自身的商城 HTML（h() 转义后呈 &lt;!doctype html&gt;…，含「拾光商城」），证明服务器向回环地址发起请求并回显响应；url=file:///var/lib/shop/vault/internal.txt 返回 200，<pre> 为 SHOP_INTERNAL_c3b5c4de0a252b4f532b471f，说明协议也未受限，可直接读取服务器本地文件。任意 URL 抓取（含内网/环回）与本地文件读取成立。

### C-19 ops/ping.php 将 host 参数拼接进 shell_exec 导致命令注入

- verification `e8e0f6e58ab846f0988c1b3df492796c`（finding `2ca0b026800e417393d38ab57b1df807` revision 1，context `1083196a4bfa4b31b323fc16ed0f9ce8`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：operator 身份（precondition 确认 id=3, role=operator）：登录后 OPS_SESSION 200 /ops/index.php 页面含「退出」「运营」，会话生效。GET /ops/ping.php?host=127.0.0.1 返回 200，<pre id="diagnostic-output"> 中仅为 ping 自身的输出（PING 127.0.0.1 … 1 packets transmitted, 1 received, 0% packet loss），未出现 uid/标记，NORMAL_MARKER_PRESENT False。
  - 攻击侧观测：攻击侧（同一 operator 会话，同作业 d66d623addd1472ea794bf765cb2c88d）：GET /ops/ping.php?host=127.0.0.1%3Bid%3Becho%20LAB30_CI_MARK_7f3a91 返回 200，<pre id="diagnostic-output"> 中除正常 ping 统计外追加了 uid=33(www-data) gid=33(www-data) groups=33(www-data) 与仅由攻击请求产生的唯一标记 LAB30_CI_MARK_7f3a91，ATTACK_MARKER_PRESENT True、ATTACK_UID_PRESENT True。即拼接的 shell 命令在服务端以 www-data 身份执行，命令注入成立。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：1 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`e038f1191f5d43f3a8f4e11be5aac61f`；`d66d623addd1472ea794bf765cb2c88d`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`d66d623addd1472ea794bf765cb2c88d` script finished exit=0
  - 适配脚本：`e8e0f6e5-adapted-poc_ping_rce.py`（见证据包 evidence/）
  - 备注：正常/攻击为同一 operator 会话内的两个 GET，输出取自页面 <pre id="diagnostic-output">，归因清晰。入口按源码要求 operator/admin；本次未用普通会员身份做动态对照，权限门槛以源码 require_user(['operator','admin']) 为依据。结论限定于 ping.php 的 shell_exec 注入；host_check.php / batch-check.php 的同一 sink 仅由源码确认，未另做动态实验。

- 正式复核 `5b377132712949ba9f8f986d84b4a5de`：复核确认；引用 revision 1 / verification `e8e0f6e58ab846f0988c1b3df492796c`
  - 理由：已读取同版本完整正常/攻击观测：正常侧 host=127.0.0.1 仅返回 ping 统计（1 packets transmitted, 1 received），NORMAL_MARKER_PRESENT False；攻击侧 host=127.0.0.1;id;echo LAB30_CI_MARK_7f3a91 在同页 <pre id="diagnostic-output"> 追加 uid=33(www-data) 与唯一标记 LAB30_CI_MARK_7f3a91，ATTACK_MARKER_PRESENT/ATTACK_UID_PRESENT 均 True。与 ping.php:2 拼接 shell_exec 及 host_check.php:2 复用同一 sink 的根因一致，确认。
  - 复核观测：正常侧 operator 身份（precondition 确认 id=3, role=operator）：登录后 OPS_SESSION 200 /ops/index.php 页面含「退出」「运营」，会话生效。GET /ops/ping.php?host=127.0.0.1 返回 200，<pre id="diagnostic-output"> 中仅为 ping 自身的输出（PING 127.0.0.1 … 1 packets transmitted, 1 received, 0% packet loss），未出现 uid/标记，NORMAL_MARKER_PRESENT False。；攻击侧 攻击侧（同一 operator 会话，同作业 d66d623addd1472ea794bf765cb2c88d）：GET /ops/ping.php?host=127.0.0.1%3Bid%3Becho%20LAB30_CI_MARK_7f3a91 返回 200，<pre id="diagnostic-output"> 中除正常 ping 统计外追加了 uid=33(www-data) gid=33(www-data) groups=33(www-data) 与仅由攻击请求产生的唯一标记 LAB30_CI_MARK_7f3a91，ATTACK_MARKER_PRESENT True、ATTACK_UID_PRESENT True。即拼接的 shell 命令在服务端以 www-data 身份执行，命令注入成立。

### C-20 reset_shop() 使用 MD5 存储硬编码初始口令（含 admin）

- verification `f0a1470ba714495082532e688b5d4643`（finding `e40ed71d3c3d4da8956c2c8d839da9c1` revision 1，context `23eb7ea8a081480ca58eef0c6b5279af`，target lab30-shop-1.0.0）
  - 执行状态：执行完成；判定：confirmed；来源：poc_agent
  - 正常侧观测：正常侧（job 6e7f3420708446e6aff61c88756469b9，alice/customer）：用宿主提供的账号口令走 /auth/login.php 正常登录返回 200 并跳离登录页，/account/index.php 返回 200、含「退出」与 <dd>alice</dd>，认证流程本身工作正常；该口令的 md5 为 32 位十六进制（MD5_HEX_LEN 32），符合 password_md5 CHAR(32) 的存储形态。
  - 攻击侧观测：判别性观测（不发送伪造请求，因为该弱点在凭据存储本身）：job 6e7f3420708446e6aff61c88756469b9 以宿主提供的 alice 密码计算 md5，结果与源码常量 Alice123! 的 md5 完全相等（MD5_MATCHES_HARDCODED_ALICE123 True，而与 Bob123! 不等）；job d2e63460da5a43a7825eb27adeb61030 以宿主提供的 admin 密码计算 md5，与源码常量 Admin123! 的 md5 完全相等（MD5_MATCHES_HARDCODED_ADMIN123 True），且该会话可直接以 admin 角色读取 /ops/users.php（USERS_ACCESS admin，返回 alice/bob/operator/admin 四个账号与角色）。结合 login.php:7 的 hash_equals($row['password_md5'], md5($_POST['password']))，登录成功即意味着库中 password_md5 恰为 md5(明文密码)，且明文密码与 setup.php:17 硬编码常量一致——即任何读到源码的人可直接得到 admin 账号的实时口令。
  - 已保存作业事实：2 个；满足执行及前提检查的作业：2 个。作业完成不等同于漏洞成立。
  - 已观测作业 ID：`6e7f3420708446e6aff61c88756469b9`；`d2e63460da5a43a7825eb27adeb61030`
  - 结论结束原因：completed；执行阶段结束原因：未记录
  - 作业：`6e7f3420708446e6aff61c88756469b9` script finished exit=0；`d2e63460da5a43a7825eb27adeb61030` script finished exit=0
  - 适配脚本：`f0a1470b-adapted-poc.php`（见证据包 evidence/）
  - 备注：两个作业均为成功作业并带身份前提（alice=customer、admin=admin）。脚本只在内存中比较 md5，未打印明文密码；未使用任何猜测口令登录。admin 身份仅用于核对该账号的凭据是否等于源码常量，不用于证明普通会员越权。未直接读取数据库列；md5 存储由 login.php:7 的 md5 比较逻辑 + 登录成功推断，源码 applicability=match。离线暴力破解速度未做基准测试。

- 正式复核 `79a196e2a89842dbb239565f1dd39e19`：复核确认；引用 revision 1 / verification `f0a1470ba714495082532e688b5d4643`
  - 理由：已完整读取同版本正常/攻击两侧原文。正常侧 job 6e7f3420708446e6aff61c88756469b9：alice 正常登录 200 并跳离登录页、/account/index.php 含认证标记与用户 alice，其口令 md5 为 32 位十六进制且等于 md5(Alice123!) 而不等于 md5(Bob123!)。攻击侧 job d2e63460da5a43a7825eb27adeb61030：admin 口令 md5 等于 md5(Admin123!)，admin 会话以 admin 角色读取 /ops/users.php 得到 alice/bob/operator/admin 全量账号与角色。结合 setup.php:7 的 password_md5 CHAR(32) 与 :17 md5($u[2]) 硬编码写入、login.php:7 hash_equals 比较，确认库中存储为无盐 MD5 且源码常量即真实生效口令（含管理员），无强制改密机制。
  - 复核观测：正常侧 正常侧（job 6e7f3420708446e6aff61c88756469b9，alice/customer）：用宿主提供的账号口令走 /auth/login.php 正常登录返回 200 并跳离登录页，/account/index.php 返回 200、含「退出」与 <dd>alice</dd>，认证流程本身工作正常；该口令的 md5 为 32 位十六进制（MD5_HEX_LEN 32），符合 password_md5 CHAR(32) 的存储形态。；攻击侧 判别性观测（不发送伪造请求，因为该弱点在凭据存储本身）：job 6e7f3420708446e6aff61c88756469b9 以宿主提供的 alice 密码计算 md5，结果与源码常量 Alice123! 的 md5 完全相等（MD5_MATCHES_HARDCODED_ALICE123 True，而与 Bob123! 不等）；job d2e63460da5a43a7825eb27adeb61030 以宿主提供的 admin 密码计算 md5，与源码常量 Admin123! 的 md5 完全相等（MD5_MATCHES_HARDCODED_ADMIN123 True），且该会话可直接以 admin 角色读取 /ops/users.php（USERS_ACCESS admin，返回 alice/bob/operator/admin 四个账号与角色）。结合 login.php:7 的 ha…

## 6. 覆盖与未决项

| 独立分母 | 总数 | 已结算 | 未决/待办 | 闭环 |
|---|---:|---:|---:|---|
| 文件覆盖 | 61 | 读取 46；读取+跳过 46 | 15 | 否 |
| 必做方向 | 3 | 已决 3；跳过 0 | 0 | 是 |
| 动态验证 | 20 | 已验证 18；已复核记录 18 | 待验证 0；待复核 0 | — |
| 正式终审 | 20 | 已接受 20 | 待终审 0；存疑 0 | — |

**后续建议（不阻止本次收束）**

- `dir_ff99b8b70b87b5ade9e68c5c25d79faa`：审查 ops/formula.php:3 的动态函数调用 $func(...) 是否可通过可控函数名（如 system、assert 等）达成代码/命令执行，或受 PHP 配置限制；需要确认可调用函数范围与参数传递。
- `dir_8088a3ad9e4c8c57aa433373945d47f7`：确认 messages 表是否存在私密字段与按 id 读取的单一消息接口，判断是否另有 IDOR
- `dir_9214c85b1d6740c8f0e3e9dcd96eea1d`：审查 data_dir() 下 sessions 目录是否可被 download.php 路径遍历读取导致会话劫持
- `dir_f30de9eaa8955077d64313fa40001d71`：核实 lab30-shop/app/public/auth/continue.php:3 的 next 开放重定向可利用性
- `dir_3df0b484fb1dbe44fd7f67e894310409`：核实 account/backup.php 的 unserialize 是否能通过 dispatch_job.php 等 gadget 在 instanceof 检查前触发代码执行（需确认类自动加载路径）
- `dir_06bfef369c97d661810937dc739658b7`：lab30-shop/app/public/ops/users.php Cookie 授权绕过、report.php/member_lookup.php SQLi、support/download.php 路径穿越待成条
- `dir_82ab73b457b6cb32f58bf99fc7405433`：lab30-shop/app/public/ops/jobs.php + src/dispatch_job.php unserialize RCE 待单独成条
- `dir_33d20c9c173a2396005b62e96b88e413`：lab30-shop/app/public/account/redeem.php:5 弱类型 md5 切换比较可构造的绕过输入
- `dir_3dee62574e357396324d764e1ebabbb1`：lab30-shop/app/public/auth/login.php:3 会话固定与 md5 口令的实际可利用性需动态确认
- `dir_a2626bbb2cd978f1a957db7b64a2181c`：lab30-shop/app/public/account/backup.php:5 unserialize 是否存在可链式利用的对象注入
- `dir_d299ccf7ed8b10c48e74fd10c7887bba`：lab30-shop/app/public/partner/portal.php:2-5 JWT 未验签致鉴权绕过，待独立确认
- `dir_f04d7f7640c063a2224778df38f1b0fe`：lab30-shop/app/public/content/page.php 与 ops/url-preview.php 的 SSRF/开放重定向方向待审
- `dir_807467174353dd7c685f6ec80169e01f`：未读取订单创建/写入脚本（如 orders/create.php 或 wallet 支付处）：需检查订单号、备注等字段入库后是否在其它页面二次拼接进 SQL（二次注入方向）。
- `dir_b92bebb271ca942beeacfba05b93d31f`：未读取 lab30-shop/app/public/orders/detail.php：需核对订单详情是否仅按 id 读取而未校验 user_id（IDOR 方向）。
- `dir_d7ab64c497970a5a44a5a1dcbdabd6bf`：未读取商品详情 catalog/detail.php：检查其 id 参数拼接与输出编码（反射型 XSS / SQL 注入方向）。

**补证与未决动作**

- 15 项：读取或带理由复核未覆盖文件。

**限制**

- 受阻、未执行、未读取的方向均不代表安全。
- 本次运行未同时满足完成状态、覆盖闭环与验证闭环，本报告为阶段报告。

## 7. 附录与证据索引

**任务记录**

| 任务 | 标题 | 状态 | 错误 |
|---|---|---|---|
| `dc3eb03ab75740929891f16e9e03a2a4` | 合作伙伴门户 JWT 鉴权绕过与令牌签发逻辑 | completed | — |
| `692abdde5bc145f084690f675b365165` | 运维模板预览/渲染与 URL 预览的 LFI/RFI/SSRF 与代码执行 | completed | — |
| `2c274e4504c2439a919e4f680dd5426a` | 运维脚本：XML 导入 XXE、ping/批处理命令注入与 database 面板 | completed | — |
| `3cebcb07ad3a4d76b1f0664ed9712e0b` | 客服支持：文件下载路径遍历与消息存储型 XSS/越权 | completed | — |
| `2a977d7fba774da088c3ef327da7e91c` | 注册与会话：弱口令哈希、注册批量赋值与会话固定补查 | completed | — |
| `033fb9e312644e1099589837a96a5d5b` | 订单创建与详情：客户端单价信任、订单归属 IDOR 与入库二次注入 | completed | — |
| `2b40e018b4eb4f91a58597267d6f68dc` | 引导与共享库：数据库封装、转义、会话与包含 | completed | — |
| `3a615c749f0b4dfe822936ac3bd27984` | 运维与支持：命令执行、SSRF、XXE 与信息泄露 | completed | — |
| `9465b6ece44e423197f0a1408696148a` | 账户入口：认证/会话、资料更新与批量赋值 | completed | — |
| `9fba47d02a3d42af86894b7a4c7ebfd5` | 钱包与兑换：业务逻辑、竞态、备份文件读取 | completed | — |
| `d33102f35e8f4971a034a6e14da5edb9` | 目录与订单：SQL 拼接、二次注入与输出编码 | completed | — |
| `eff8312017ea482ba5109ffb95432d11` | bin 脚本：初始化与重置中的输入处理与危险操作 | completed | — |

- 用量：上限 响应 2048；工具 16384；秒 10800；实际 响应 154；工具 152；秒 1433.884；剩余 响应 1894；工具 16232；秒 9366.116

**证据索引（服务器读取）**

| evidence_id | 路径 | 范围 | 文件哈希 | 可用 |
|---|---|---|---|---|
| `7bea3967b6864d34` | lab30-shop/app/public/partner/portal.php | 1-6 | `e1267edb0f9df936` | 是 |
| `caef78d64c12c1c2` | lab30-shop/app/public/partner/token.php | 3-4 | `391948b46efce76c` | 是 |
| `78224482780bf94a` | lab30-shop/app/src/bootstrap.php | 33-37 | `2050819d093be02b` | 是 |
| `fadde1b1e1006c27` | lab30-shop/app/public/account/update.php | 3-7 | `b8227f19c05d0cd3` | 是 |
| `434b5d778ccdc04c` | lab30-shop/app/public/account/index.php | 1-3 | `1d22c7bc280b30b0` | 是 |
| `4287a6e3dca83484` | lab30-shop/app/public/support/messages.php | 3-5 | `a6866f07b4de32f3` | 是 |
| `5220b9ce518719f6` | lab30-shop/app/src/bootstrap.php | 10-10 | `2050819d093be02b` | 是 |
| `52a7b68bba8b1c1f` | lab30-shop/app/public/account/backup.php | 4-6 | `017e1703cdf0ff0c` | 是 |
| `9d0d13b19a80b9a2` | lab30-shop/app/src/backup.php | 2-5 | `571459cc8b0f6e8e` | 是 |
| `713c1c83b1f33981` | lab30-shop/app/public/wallet/withdraw.php | 2-11 | `e3e73271e379b085` | 是 |
| `2585399332002e26` | lab30-shop/app/public/orders/detail.php | 2-4 | `be69aa78cecffcfd` | 是 |
| `5c7a19d86aca3057` | lab30-shop/app/src/bootstrap.php | 20-24 | `2050819d093be02b` | 是 |
| `d75d9f6dcc3431a8` | lab30-shop/app/public/auth/register.php | 5-8 | `99166a0288be7b1e` | 是 |
| `61badbb513a28357` | lab30-shop/app/public/auth/login.php | 7-8 | `b9be43ddb2233156` | 是 |
| `e4ba0faa7c0831b2` | lab30-shop/app/public/orders/create.php | 3-7 | `41e73625d7e04c58` | 是 |
| `063c928d2d7c3b2e` | lab30-shop/app/src/bootstrap.php | 33-40 | `2050819d093be02b` | 是 |
| `7a752056361b87ea` | lab30-shop/app/public/catalog/index.php | 4-5 | `e85bd1c2fa6a4b78` | 是 |
| `173f24f6297d9164` | lab30-shop/app/public/content/page.php | 1-3 | `53c5997117f2d54c` | 是 |
| `87549aa1faa05190` | lab30-shop/app/src/setup.php | 30-38 | `53e7dc7286d7d370` | 是 |
| `81e47fc9f94990a6` | lab30-shop/app/public/account/redeem.php | 3-6 | `28b3dc4534cca985` | 是 |
| `c7321e7900aae64d` | lab30-shop/app/public/ops/xml-import.php | 2-4 | `3c23a76b1047f734` | 是 |
| `6220461f4c36cb1a` | lab30-shop/app/src/bootstrap.php | 33-36 | `2050819d093be02b` | 是 |
| `415907ec6bf2f739` | lab30-shop/app/src/bootstrap.php | 40-40 | `2050819d093be02b` | 是 |
| `9f3b2a689fae3c12` | lab30-shop/app/src/bootstrap.php | 11-19 | `2050819d093be02b` | 是 |
| `5f912f7499e51381` | lab30-shop/app/public/auth/login.php | 3-9 | `b9be43ddb2233156` | 是 |
| `5d596a817dad3c10` | lab30-shop/app/public/ops/template-preview.php | 1-3 | `107da46e9b067ce0` | 是 |
| `e1dc06d2f03a80eb` | lab30-shop/app/public/account/profile.php | 2-3 | `6f2406bbf636de04` | 是 |
| `ec18381d7af73d0f` | lab30-shop/app/public/account/update.php | 4-6 | `b8227f19c05d0cd3` | 是 |
| `1a6cc98ec16c37fd` | lab30-shop/app/public/catalog/index.php | 1-5 | `e85bd1c2fa6a4b78` | 是 |
| `a5097aecd2398250` | lab30-shop/app/src/bootstrap.php | 4-10 | `2050819d093be02b` | 是 |
| `10c0c8123072e718` | lab30-shop/app/public/support/download.php | 2-3 | `71f0558eeb4ebb6c` | 是 |
| `f5faf41dff9a5a91` | lab30-shop/app/src/bootstrap.php | 9-9 | `2050819d093be02b` | 是 |
| `136d02a92a08ac98` | lab30-shop/app/public/ops/template-render.php | 1-4 | `357da9e9959275d8` | 是 |
| `924ff7a637feffe5` | lab30-shop/app/public/ops/url-preview.php | 1-4 | `e495938b10c455c6` | 是 |
| `61f200eb89320676` | lab30-shop/app/public/ops/ping.php | 1-3 | `c15517950afe0794` | 是 |
| `65fc5323ae7c9b98` | lab30-shop/app/src/host_check.php | 1-2 | `c3a868155c2d335e` | 是 |
| `a41ee4811beeaf1b` | lab30-shop/app/public/ops/batch-check.php | 1-3 | `5f76332e7ad1b33a` | 是 |
| `f86e0ebf4243b153` | lab30-shop/app/src/setup.php | 7-7 | `53e7dc7286d7d370` | 是 |
| `80b30b229093e94e` | lab30-shop/app/src/setup.php | 16-17 | `53e7dc7286d7d370` | 是 |

**附件与机器可读清单**

- Markdown：本报告（由事实包确定性生成）。
- JSON：result.json（含本事实包与质量结果）
- 证据包：evidence/（POC 脚本、runner 产物、runner manifest）
- 源码：源码片段由宿主从冻结快照读取，见 source_evidence
- 事实包 ID：`d040c84e1fe5f409c09692d4a1acd6da1a63a10e6598827fadec70f5ac6cae29`；页面、Markdown、JSON 与证据包共用同一份事实。
